//! Mesh algorithm similar to that used by esp-mesh. A tree is created and nodes connect to the neighbor closest to the root.

mod node_data;
mod packet;

pub use packet::{Packet, PacketHeader};

use crate::{
    connect_to_other_node, consts,
    util::{SelectEither, UnwrapExt},
    Mutex,
};
use core::{borrow::Borrow, future::Future, marker::PhantomData};
use either::Either;
use embassy_net::{
    tcp::{TcpReader, TcpSocket},
    IpEndpoint, IpListenEndpoint,
};
use embassy_sync::{
    blocking_mutex::raw::CriticalSectionRawMutex,
    channel::{Channel, Receiver, Sender},
    pubsub::{DynPublisher, DynSubscriber},
    signal::Signal,
};
use embassy_time::{Duration, Instant, TimeoutError, Timer, WithTimeout};
use embedded_io_async::{Read, Write};
use esp_hal::xtensa_lx::mutex::Mutex as _;
use esp_wifi::wifi::{Configuration, PromiscuousPkt, Sniffer, StaList, WifiController, WifiEvent};
use heapless::FnvIndexMap;
use ieee80211::{
    common::CapabilitiesInformation,
    element_chain,
    elements::{SSIDElement, VendorSpecificElement},
    mac_parser::MACAddress,
    mgmt_frame::BeaconFrame,
};
use node_data::{NodeData, NodeDataBeaconMsg, NodeTable};
use scroll::{ctx::SizeWith, Pread, Pwrite};
use stack_dst::Value;

error_set::error_set! {
    SendToParentErr = {
        #[display("no parent")]
        NoParent,
    } || PacketSendErr || PacketNewErr;
    SendToChildErr = {
        #[display("child missing")]
        NoChild
    } || PacketSendErr || PacketNewErr;
    PacketSendErr = {
        #[display("{source:?}")]
        Tcp {
            source: embassy_net::tcp::Error
        },
        // #[display("{source:?}")]
        // ScrollErr {
        //     source: scroll::Error,
        // },
    };
    PacketNewErr = {
        /// Too much data for one packet.
        #[display("data too large for one packet")]
        TooBig,
    };
    /// Errors related to messages received.
    InvalidMsg = {
        /// Protocol version of msg doesn't match.
        Version { version: Version },
    };
}

pub type Version = u8;
pub type Level = u8;

pub type OneShotRx<T> = Receiver<'static, CriticalSectionRawMutex, T, 1>;
pub type OneShotTx<T> = Sender<'static, CriticalSectionRawMutex, T, 1>;
pub type OneShotChannel<T> = Channel<CriticalSectionRawMutex, T, 1>;

/// Implement the [`scroll`] traits using [`zerocopy`]
macro_rules! impl_scroll_with_zerocopy {
    ($ty:ident) => {
        impl scroll::ctx::TryIntoCtx for $ty {
            type Error = scroll::Error;

            fn try_into_ctx(self, dst: &mut [u8], _ctx: ()) -> Result<usize, Self::Error> {
                use zerocopy::IntoBytes;
                let bytes = self.as_bytes();
                let offset = &mut 0;
                dst.gwrite(bytes, offset)?;
                Ok(*offset)
            }
        }
        impl scroll::ctx::TryFromCtx<'_> for $ty {
            type Error = scroll::Error;

            fn try_from_ctx(from: &[u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
                use zerocopy::FromBytes;
                Ok((
                    Self::read_from_prefix(from)
                        .map_err(|_| scroll::Error::TooBig {
                            size: size_of::<Self>(),
                            len: from.len(),
                        })?
                        .0,
                    size_of::<Self>(),
                ))
            }
        }
        impl scroll::ctx::MeasureWith<()> for $ty {
            fn measure_with(&self, _: &()) -> usize {
                size_of::<Self>()
            }
        }
        impl scroll::ctx::SizeWith<()> for $ty {
            fn size_with(_: &()) -> usize {
                size_of::<Self>()
            }
        }
    };
}
pub(crate) use impl_scroll_with_zerocopy;

/// Relative position in the mesh tree.
#[derive(Debug, Default, Clone)]
pub enum TreePos {
    /// Have to go up the tree to reach the node.
    Up,
    /// Have to go down the tree through the given child to reach the node.
    Down(MACAddress),
    /// Not connected to this node.
    #[default]
    Disconnected,
}

/// Send the given data, which fits in one packet, to the current parent.
pub async fn send_to_parent(
    data: &[u8],
    socket: &mut TcpSocket<'_>,
) -> Result<(), SendToParentErr> {
    let pkt = Packet::new(
        STATE
            .borrow()
            .lock(|table| table.parent)
            .ok_or(SendToParentErr::NoParent)?,
        data,
    )?;
    pkt.send(socket).await?;
    Ok(())
}

/* TODO
/// Send the given data packet to the given child.
pub async fn send_to_child() -> Result<(), SendToChildErr> {
    todo!()
} */

/// Accept connections on the socket and forward all [`Packet`]s received.
#[embassy_executor::task(pool_size = consts::MAX_NODES)]
pub async fn accept_sta_and_forward(
    rx_socket: &'static mut TcpSocket<'static>,
    ap_mac: MACAddress,
    ap_tx_socket: &'static mut TcpSocket<'static>,
    sta_tx_socket: &'static mut TcpSocket<'static>,
) {
    loop {
        rx_socket.close();
        err!(rx_socket.flush().await);
        match rx_socket
            .accept(IpListenEndpoint {
                addr: None,
                port: 8000,
            })
            .await
        {
            Ok(()) => (),
            e @ Err(_) => {
                err!(e);
                log::warn!(
                    "state: {}, local: {:?}, remote: {:?}",
                    rx_socket.state(),
                    rx_socket.local_endpoint(),
                    rx_socket.remote_endpoint()
                );
                continue;
            }
        };

        let (mut rx, _tx) = rx_socket.split();
        match forward::<core::convert::Infallible>(
            &mut rx,
            ap_mac,
            ap_tx_socket,
            sta_tx_socket,
            async |bytes| {
                // TODO receive data for this node.
                esp_println::dbg!(bytes);
                Ok(())
            },
        )
        .await
        {
            Ok(()) => (),
            Err(e) => match e {},
        };
    }
}

/// Close down socket forcefully.
pub async fn socket_force_closed(socket: &mut TcpSocket<'_>) {
    socket.close();
    err!(socket.flush().await);
    socket.abort();
    err!(socket.flush().await);
}

/// Connects using either ap (to child) or sta (to parent) interface to the node on the way to the given mac.
/// Disconnects from previous if needed to connect to new.
async fn next_hop_socket<'a>(
    address: MACAddress,
    ap_tx_socket: &'a mut TcpSocket<'static>,
    sta_tx_socket: &'a mut TcpSocket<'static>,
) -> &'a mut TcpSocket<'static> {
    // Resolve next-hop.
    let Some(dest) = STATE.borrow().lock(|table| {
        table
            .map
            .iter()
            .find(|x| *x.0 == address)
            .map(|x| (x.0.clone(), x.1.clone()))
    }) else {
        todo!("forward mac {address} dest missing");
    };
    // The ip depends on the node and the socket depends on if using sta (connected to parent) or ap (connected to children) interface.
    let (ip, tx_socket) = match dest.1.postion {
        TreePos::Up => (consts::AP_CIDR.address().into_address(), sta_tx_socket),
        TreePos::Down(child_mac) => (
            consts::sta_cidr_from_mac(child_mac)
                .address()
                .into_address(),
            ap_tx_socket,
        ),
        TreePos::Disconnected => todo!("forward to an inaccessible node"),
    };

    // Connect to next-hop if not already connected.
    if tx_socket.remote_endpoint() != Some(IpEndpoint::new(ip, consts::PORT)) {
        // Disconnect old.
        if tx_socket.remote_endpoint().is_some() {
            socket_force_closed(tx_socket).await;
        }
        // Connect new.
        err!(
            tx_socket.connect(IpEndpoint::new(ip, consts::PORT)).await,
            "connect to next hop"
        );
    }
    tx_socket
}

/// Forward all [`Packet`]s received from `rx` to `tx_other` or `tx_me` based on destination.
/// Sockets may not be closed when this returns.
pub async fn forward<E>(
    rx: &mut TcpReader<'_>,
    ap_mac: MACAddress,
    ap_tx_socket: &mut TcpSocket<'static>,
    sta_tx_socket: &mut TcpSocket<'static>,
    mut tx_me: impl async FnMut(&[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let mut buf = [0u8; {
        Packet::max_size() // or smaller, but no need for bigger
    }];

    'packet: loop {
        // Forward header.
        match rx
            .read_exact(&mut buf[..PacketHeader::size_with(&())])
            .await
        {
            Ok(()) => (),
            Err(e) => {
                // If no data comes while expecting a header it is fine. Nothing needs to be fixed.
                match e {
                    embedded_io_async::ReadExactError::UnexpectedEof => break 'packet Ok(()),
                    embedded_io_async::ReadExactError::Other(e) => {
                        log::trace!("{e:?} waiting for header");
                        break 'packet Ok(());
                    }
                }
            }
        }
        let header = buf.pread::<PacketHeader>(0).todo();
        let mut bytes_left = header.len();
        let to_me = header.destination() == ap_mac;
        // Forward header and choose correct socket if the data is not for this node.
        let mut tx_socket = if to_me {
            None
        } else {
            // Connect to next hop socket and disconnect from previous if needed.
            let tx_socket =
                next_hop_socket(header.destination(), ap_tx_socket, sta_tx_socket).await;
            // Send data to next-hop.
            err!(
                tx_socket
                    .write_all(&buf[..PacketHeader::size_with(&())])
                    .await,
                "next hop failed write"
            );
            Some(tx_socket)
        };

        // Forward data.
        loop {
            let to_read = buf.len().min(bytes_left);
            match rx.read_exact(&mut buf[..to_read]).await {
                Ok(()) => (),
                // TODO: Disconnect while expecting more data. This will result in lost data.
                // At the very least, should probably send `bytes_left` filler to resync the forwarded data.
                // Better would be to use framing (e.g. COBS).
                e @ Err(_) => e.todo_msg("missing rest of data"),
            };
            match &mut tx_socket {
                // Send data to next-hop.
                Some(tx_socket) => {
                    err!(
                        tx_socket.write_all(&buf[..to_read]).await,
                        "next hop failed write"
                    );
                }
                // Sending to self
                None => tx_me(&buf[..to_read]).await?,
            }
            bytes_left -= to_read;
            if bytes_left == 0 {
                break;
            }
        }
    }
}

/// Stored in a static because the sniffer callback is unfortunately a `fn` not a `Fn` and can't store runtime state.
static STATE: Mutex<NodeTable> = Mutex::new(NodeTable {
    pending_parent: None,
    parent: None,
    map: FnvIndexMap::new(),
});

/// [`MACAddress`] for next parent node to connect to.
/// Stored in a static because the sniffer callback is unfortunately a `fn` not a `Fn` and can't store runtime state.
static NEXT_PARENT: Signal<CriticalSectionRawMutex, MACAddress> = Signal::new();

/// Callback which updates mesh network tree state when called as part of the [`Sniffer`] callback
pub fn sniffer_callback(pkt: &PromiscuousPkt) {
    // Return quick helps since this is called and blocks every packet.
    // Ignore non-beacon frames.
    let Ok(beacon) = ieee80211::match_frames!(pkt.data, beacon = BeaconFrame => { beacon }) else {
        return;
    };
    // Ignore non-matching SSID.
    if beacon.ssid() != Some(consts::SSID) {
        return;
    }
    // Ignore from denylist.
    if consts::DENYLIST_MACS.contains(&beacon.header.bssid.0) {
        return;
    }

    for field in beacon
        .elements
        .get_matching_elements::<VendorSpecificElement>()
    {
        let Some(payload) = field.get_payload_if_prefix_matches(consts::ESPRESSIF_OUI) else {
            log::debug!("unmatched beacon field: {:?}", field);
            continue;
        };
        let Ok(data) = payload.pread::<NodeDataBeaconMsg>(0) else {
            log::warn!("bad beacon field? {:?}", field);
            continue;
        };

        let candidate_parent = beacon.header.bssid;

        // Apply new message to state.
        let (me_level, new_node_level, current_parent, pending_parent) =
            STATE.borrow().lock(|table| {
                (|| match table.map.entry(candidate_parent) {
                    heapless::Entry::Occupied(mut occupied_entry) => {
                        occupied_entry.get_mut().update_with_msg(data)
                    }
                    heapless::Entry::Vacant(vacant_entry) => {
                        vacant_entry.insert(NodeData::from_first_msg(data)?).todo();
                        Ok(())
                    }
                })()
                .todo();

                (
                    table.level(),
                    table.map[&candidate_parent].level,
                    table.parent,
                    table.pending_parent,
                )
            });

        // Now that the message has updated the table, can send for handling in [`handle_new_msgs`]
        // Only handle if not root.
        if consts::TREE_LEVEL != Some(0) {
            // me_level > 0 since not this is not run by root node.
            assert_ne!(me_level, 0, "Shouldn't be the root");
            let parent_level = me_level - 1;
            // Switch to candidate node if closer to root than current parent.
            let closer_than_parent = new_node_level < parent_level;
            // TODO(perf): optimize by picking a new pending parent even if already have a pending parent if better than previous pending parent.
            // If we do this, have to fix logic in connection handler to avoid overwriting with `None` unconditionally.
            let already_connecting = pending_parent.is_some();
            // Don't connect to the current parent again.
            let is_current_parent = Some(candidate_parent) == current_parent;

            if !already_connecting && closer_than_parent && !is_current_parent {
                STATE
                    .borrow()
                    .lock(|table| table.pending_parent = Some(candidate_parent));
                NEXT_PARENT.signal(candidate_parent);
            }
        }

        // Found the element we care about. Stop looking through elements.
        break;
    }
}

/// Periodic transmit of beacon with custom vendor data.
#[embassy_executor::task]
pub async fn beacon_vendor_tx(mut sniffer: Sniffer, source_mac: MACAddress) {
    log::info!("sending vendor-beacons");

    // Buffer for beacon body
    let mut beacon = [0u8; 256];
    loop {
        let data: NodeDataBeaconMsg = STATE.borrow().lock(|table| table.beacon_msg());
        let length = beacon
            .pwrite(
                BeaconFrame {
                    header: ieee80211::mgmt_frame::ManagementFrameHeader {
                        transmitter_address: source_mac,
                        bssid: source_mac,
                        receiver_address: MACAddress([0xff; 6]), // multicast to all
                        ..Default::default()
                    },
                    body: ieee80211::mgmt_frame::body::BeaconLikeBody {
                        timestamp: 0,
                        beacon_interval: 100,
                        capabilities_info: CapabilitiesInformation::new().with_is_ess(true), // is ess = is AP
                        elements: element_chain! {
                            SSIDElement::new(consts::SSID).unwrap(),
                            VendorSpecificElement::new_prefixed(
                                // Vender specific OUI is first 3 bytes. Rest is payload concatenated.
                                consts::ESPRESSIF_OUI,
                                data,
                            )
                        },
                        _phantom: PhantomData,
                    },
                },
                0,
            )
            .unwrap();

        // Send raw frame using wifi-stack's sequence number.
        // Will give an `ESP_ERR_INVALID_ARG` if sending for most configurations if `use_internal_seq_num` != true when wi-fi is initialized.
        // See <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/wifi.html#side-effects-to-avoid-in-different-scenarios>
        log::trace!("beacon tx");
        if let Err(e) = sniffer.send_raw_frame(false, &beacon[0..length], true) {
            log::error!("Failed to send beacon: {e:?}")
        }
        log::trace!("beacon tx'ed");

        Timer::after_millis(100).await;
    }
}

// Max size in units of `u64` for the values of [`ControllerMsg`]
// 1 usize goes to the metadata and the rest is for the actual size.
const DYN_FIXED_SIZE: usize = 37;
/// Commands/Messages (like in the actor model) for the controller
pub struct ControllerCommand(
    // Can't make this `FnOnce` without nightly since it would have to move out the dyn FnOnce to call.
    // `std::Box` is special and gets to do this but 3rd party types like `Value` here don't.
    // Read as "A closure with a maximum size which returns a future a maximum size"
    pub  Value<
        dyn for<'a> FnMut(
            &'a mut esp_wifi::wifi::Configuration,
            &'a mut WifiController<'static>,
        ) -> Value<
            dyn Future<Output = ()> + 'a,
            stack_dst::buffers::ConstArrayBuf<u64, DYN_FIXED_SIZE>,
        >,
        stack_dst::buffers::ConstArrayBuf<u64, DYN_FIXED_SIZE>,
    >,
);
/// Create a new command for the controller to execute.
/// Works by taking a fixed size closure that returns a fixed size future and polling the result to completion.
/// # Panics
/// If this panics the future or closure is too large. Either increase [`DYN_FIXED_SIZE`] or make the future/closure smaller.
/// # Example
/// Use like
/// ```ignore
/// controller_msg!(config, controller, { log::info!("{:?}{:?}", controller.get_capabilities(), config.as_ap_conf_ref()) })
/// ```
macro_rules! controller_command {
    ($config:ident, $controller:ident, $e:expr) => {
        ControllerCommand(
            Value::new(
                for<'a> move |$config: &'a mut Configuration,
                              $controller: &'a mut WifiController<'static>|
                              -> Value<dyn Future<Output = ()> + 'a, stack_dst::buffers::ConstArrayBuf<u64, DYN_FIXED_SIZE>> {
                        Value::new(async move { $e })
                    .unwrap_or_else(|e| panic!("future: {} >= {}", size_of_val(&e), size_of::<u64>() * DYN_FIXED_SIZE))
                },
            )
            .unwrap_or_else(|e| panic!("closure: {} >= {}", size_of_val(&e), size_of::<u64>() * DYN_FIXED_SIZE))
        )
    };
}

#[derive(Debug, Clone, Copy)]
pub enum ConnectionChange {
    Connect,
    Disconnect,
}
/// `controller` has to be managed exclusively by this task so events and actions be simultaneously awaited. See "actor model".
/// Can send commands for what to do next from many other tasks using the channel for `rx`.
#[embassy_executor::task]
pub async fn controller_task(
    mut config: Configuration,
    mut controller: WifiController<'static>,
    rx: Receiver<'static, CriticalSectionRawMutex, ControllerCommand, 10>,
    sta_disconnected_tx: DynPublisher<'static, (Instant, MACAddress)>,
    ap_sta_connected_tx: DynPublisher<'static, (Instant, MACAddress, ConnectionChange)>,
) {
    let mut prev_connected = StaList::default();
    loop {
        // Wait for an event from the controller or a message to do something with the controller.
        let res = rx
            .receive()
            .select(controller.wait_for_events(
                WifiEvent::StaDisconnected
                    | WifiEvent::ApStaconnected
                    | WifiEvent::ApStadisconnected,
                false,
            ))
            .await;

        match res {
            Either::Left(mut cmd) => cmd.0(&mut config, &mut controller).await,
            Either::Right(event) => {
                if event.contains(WifiEvent::StaDisconnected) {
                    sta_disconnected_tx.publish_immediate((
                        Instant::now(),
                        MACAddress(
                            controller
                                .get_configuration()
                                .unwrap()
                                .as_client_conf_ref()
                                .unwrap()
                                .bssid
                                .expect("connected to a bssid"),
                        ),
                    ));
                }
                if event.contains(WifiEvent::ApStaconnected) {
                    let list = esp_wifi::wifi::StaList::get_sta_list().unwrap();
                    let instant = Instant::now();
                    for sta in list.0.iter().filter(|sta| !prev_connected.0.contains(sta)) {
                        ap_sta_connected_tx.publish_immediate((
                            instant,
                            sta.0.mac.into(),
                            ConnectionChange::Connect,
                        ));
                    }
                    prev_connected = list;
                }
                if event.contains(WifiEvent::ApStadisconnected) {
                    let list = esp_wifi::wifi::StaList::get_sta_list().unwrap();
                    let instant = Instant::now();
                    for sta in prev_connected.0.iter().filter(|sta| !list.0.contains(sta)) {
                        ap_sta_connected_tx.publish_immediate((
                            instant,
                            sta.0.mac.into(),
                            ConnectionChange::Disconnect,
                        ));
                    }
                    prev_connected = list;
                }
                // TODO other events.
            }
        }
    }
}

/// Connects to new parent nodes if a better one is found. Doesn't do anything if this node is root.
#[embassy_executor::task]
pub async fn connect_to_next_parent(
    // Send new commands to controller task
    controller_tx: Sender<'static, CriticalSectionRawMutex, ControllerCommand, 10>,
    // Publisher for new sta_disconnected events.
    mut sta_disconnected_rx: DynSubscriber<'static, (Instant, MACAddress)>,
) {
    // Don't run if root.
    if consts::TREE_LEVEL == Some(0) {
        return;
    }

    // Last time connected to parent.
    let mut last_connected = Instant::now();
    loop {
        match NEXT_PARENT
            .wait()
            .select(async {
                // Handle disconnects in this function so we only mark ourselves as disconnected when not connected or trying to connect.
                loop {
                    let disconnect_event = sta_disconnected_rx.next_message_pure().await;
                    // Only care about the event if disconnected since last connect.
                    if disconnect_event
                        .0
                        .checked_duration_since(last_connected)
                        .is_some()
                    {
                        break;
                    };
                }
            })
            .await
        {
            Either::Left(next_parent) => {
                log::info!("connecting: mac={next_parent}");
                /// Send/receive results from commands sent to controller task.
                static ONESHOT: OneShotChannel<
                    Result<Result<Instant, esp_wifi::wifi::WifiError>, TimeoutError>,
                > = OneShotChannel::new();
                let command = controller_command!(config, controller, {
                    // Either fail to connect or return when connection succeeded
                    let connection_result =
                        connect_to_other_node(config, controller, next_parent, 1)
                            .with_timeout(Duration::from_secs(60))
                            .await
                            .map(|x| x.map(|_| Instant::now()));
                    ONESHOT.send(connection_result).await;
                });
                controller_tx.send(command).await;
                let res = ONESHOT.receive().await;

                match res {
                    Ok(Ok(instant)) => {
                        last_connected = instant;

                        let parent_level = STATE.borrow().lock(|table| {
                            // Set new parent now that connected.
                            table.parent = Some(next_parent);
                            // The new parent can be reached by going up (to the parent).
                            // The old parent is probably still connected, and isn't below this node so it stays `Up` until further notice.
                            table.map[&next_parent].postion = TreePos::Up;

                            // Unset pending now that it is set.
                            // TODO(perf): If optimization where a new pending parent is picked even while connecting, then this can't be unconditional set `None`.
                            table.pending_parent = None;

                            table.map[&next_parent].level
                        });
                        if res.is_ok() {
                            log::info!("connected: mac={next_parent}; level={parent_level}")
                        }
                    }
                    Ok(Err(e)) => {
                        STATE.borrow().lock(|table| {
                            table.mark_me_disconnected();
                            // Even on connection fail clear the pending parent so search can find new parent.
                            // TODO(perf): If optimization where a new pending parent is picked even while connecting, then this can't be unconditional set `None`.
                            table.pending_parent = None;
                        });
                        log::warn!("failed connect: mac={next_parent}: {e:?}")
                    }
                    Err(e) => {
                        STATE.borrow().lock(|table| {
                            table.mark_me_disconnected();
                            // Even on connection fail clear the pending parent so search can find new parent.
                            // TODO(perf): If optimization where a new pending parent is picked even while connecting, then this can't be unconditional set `None`.
                            table.pending_parent = None;
                        });
                        log::warn!("failed connect: mac={next_parent}: {e:?}")
                    }
                }
            }
            Either::Right(_) => {
                STATE.borrow().lock(|table| table.mark_me_disconnected());
                log::warn!("STA disconnected");
            }
        }
    }
}
