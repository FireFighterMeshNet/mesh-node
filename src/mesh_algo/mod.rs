//! Mesh algorithm similar to that used by esp-mesh. A tree is created and nodes connect to the neighbor closest to the root.

pub mod device;
mod macros;
mod node_data;
mod packet;
mod propagate_neighbors;

pub use packet::{Packet, PacketHeader};
#[allow(unused_imports)]
pub use propagate_neighbors::{propagate_neighbors, PropagateNeighborMsg};

use crate::{connect_to_other_node, consts, util::UnwrapExt};
use core::{cell::RefCell, marker::PhantomData};
use critical_section::Mutex;
use embassy_net::{
    tcp::{TcpReader, TcpSocket},
    IpEndpoint, IpListenEndpoint,
};
use embassy_sync::{
    blocking_mutex::raw::CriticalSectionRawMutex,
    channel::{Channel as ChannelRaw, Receiver, Sender},
    pubsub::PubSubChannel as PubSubChannelRaw,
    signal::Signal as SignalRaw,
};
use embassy_time::{Duration, Timer, WithTimeout};
use embedded_io_async::{Read, Write};
use esp_wifi::wifi::{self, event::EventExt, PromiscuousPkt, Sniffer, WifiController};
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
        /// The selected next hop isn't available.
        NextHopMissing
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

pub type Channel<T, const N: usize> = ChannelRaw<CriticalSectionRawMutex, T, N>;
pub type OneShotRx<T> = Receiver<'static, CriticalSectionRawMutex, T, 1>;
pub type OneShotTx<T> = Sender<'static, CriticalSectionRawMutex, T, 1>;
pub type OneShotChannel<T> = Channel<T, 1>;
pub type AsyncMutex<T> = embassy_sync::mutex::Mutex<CriticalSectionRawMutex, T>;
pub type Signal<T> = SignalRaw<CriticalSectionRawMutex, T>;
pub type PubSubChannel<T, const CAP: usize, const SUBS: usize, const PUBS: usize> =
    PubSubChannelRaw<CriticalSectionRawMutex, T, CAP, SUBS, PUBS>;

/// Relative position in the mesh tree.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
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
    ap_tx_socket: &mut TcpSocket<'static>,
    sta_tx_socket: &mut TcpSocket<'static>,
) -> Result<(), SendToParentErr> {
    let pkt = Packet::new(
        critical_section::with(|cs| STATE.borrow_ref_mut(cs).parent)
            .ok_or(SendToParentErr::NoParent)?,
        data,
    )?;
    pkt.send(ap_tx_socket, sta_tx_socket).await?;
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
) -> ! {
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
                log::info!("[{}:{}] bytes = {:?}", file!(), line!(), bytes);
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
/// # Return
/// If the selected socket was input as `None` the output will be `None`.
async fn next_hop_socket<'a>(
    address: MACAddress,
    ap_tx_socket: impl Into<Option<&'a mut TcpSocket<'static>>>,
    sta_tx_socket: impl Into<Option<&'a mut TcpSocket<'static>>>,
) -> Option<&'a mut TcpSocket<'static>> {
    let ap_tx_socket: Option<&mut TcpSocket<'static>> = ap_tx_socket.into();
    let sta_tx_socket: Option<&mut TcpSocket<'static>> = sta_tx_socket.into();
    // TODO: broadcast address should broadcast to all children and parent.

    // Resolve next-hop.
    let pos = critical_section::with(|cs| {
        let table = &mut *STATE.borrow_ref_mut(cs);
        if let Some(dest) = table
            .map
            .iter()
            .find(|x| esp_println::dbg!(*x.0) == esp_println::dbg!(address))
            .map(|x| x.1.clone())
        {
            return esp_println::dbg!(dest.postion);
        }

        // If the addressed node isn't known to this node, hopefully a higher node does know it.
        if table.parent.is_none() {
            log::warn!("next-hop mac {address} missing and no parent");
        }
        TreePos::Disconnected
    });
    // The ip depends on the node and the socket depends on if using sta (connected to parent) or ap (connected to children) interface.
    let (ip, tx_socket) = match pos {
        TreePos::Up | TreePos::Disconnected => {
            (consts::AP_CIDR.address().into_address(), sta_tx_socket)
        }
        TreePos::Down(child_mac) => (
            consts::sta_cidr_from_mac(child_mac)
                .address()
                .into_address(),
            ap_tx_socket,
        ),
    };
    let tx_socket = tx_socket?;

    // Connect to next-hop if not already connected.
    if tx_socket.remote_endpoint() != Some(IpEndpoint::new(ip, consts::DATA_PORT)) {
        // Disconnect old.
        if tx_socket.remote_endpoint().is_some() {
            socket_force_closed(tx_socket).await;
        }
        // Connect new.
        err!(
            tx_socket
                .connect(IpEndpoint::new(ip, consts::DATA_PORT))
                .await,
            "connect to next hop"
        );
    }
    Some(tx_socket)
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
    // Make sure if `Packet`'s length type is not `u8` this doesn't overflow flash.
    const MAX_SIZE: usize = 1024;
    // buffer can be `Packet::max_size()` or smaller, but no need for bigger
    let mut buf = [0u8; {
        if Packet::max_size() < MAX_SIZE {
            Packet::max_size()
        } else {
            MAX_SIZE
        }
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
        let header = buf.pread::<PacketHeader>(0).unwrap();
        let mut bytes_left = header.len();
        let to_me = header.destination() == ap_mac;
        // Forward header and choose correct socket if the data is not for this node.
        let mut tx_socket = if to_me {
            None
        } else {
            // Connect to next hop socket and disconnect from previous if needed.
            let tx_socket = next_hop_socket(
                header.destination(),
                &mut *ap_tx_socket,
                &mut *sta_tx_socket,
            )
            .await
            .unwrap();
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
                e @ Err(_) => e.todo_msg("incomplete packet: data missing"),
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
static STATE: Mutex<RefCell<NodeTable>> = Mutex::new(RefCell::new(NodeTable {
    pending_parent: None,
    parent: None,
    map: FnvIndexMap::new(),
}));

/// [`MACAddress`] for next parent node to connect to.
/// Stored in a static because the sniffer callback is unfortunately a `fn` not a `Fn` and can't store runtime state.
static NEXT_PARENT: Signal<MACAddress> = Signal::new();

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
            critical_section::with(|cs| {
                let table = &mut *STATE.borrow_ref_mut(cs);

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
                critical_section::with(|cs| {
                    STATE.borrow_ref_mut(cs).pending_parent = Some(candidate_parent)
                });
                NEXT_PARENT.signal(candidate_parent);
            }
        }

        // Found the element we care about. Stop looking through elements.
        break;
    }
}

/// Periodic transmit of beacon with custom vendor data.
#[embassy_executor::task]
pub async fn beacon_vendor_tx(mut sniffer: Sniffer, source_mac: MACAddress) -> ! {
    log::info!("sending vendor-beacons");

    // Buffer for beacon body
    let mut beacon = [0u8; 256];
    loop {
        let data: NodeDataBeaconMsg =
            critical_section::with(|cs| STATE.borrow_ref_mut(cs).beacon_msg());
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

/// Connects to new parent nodes if a better one is found.
#[embassy_executor::task]
pub async fn connect_to_next_parent(controller: &'static AsyncMutex<WifiController<'static>>) -> ! {
    // Make sure to update state on disconnects.
    wifi::event::StaDisconnected::update_handler(|cs, event| {
        STATE.borrow_ref_mut(cs).mark_me_disconnected();
        log::warn!("STA disconnected: {}", MACAddress(event.0.bssid));
    });

    // Keep connecting to `NEXT_PARENT` whenever a new one is identified.
    loop {
        let next_parent = NEXT_PARENT.wait().await;
        log::info!("connecting: mac={next_parent}");

        let res = connect_to_other_node(&mut *controller.lock().await, next_parent, 1)
            .with_timeout(Duration::from_secs(60))
            .await;

        match res {
            Ok(Ok(())) => {
                let parent_level = critical_section::with(|cs| {
                    let table = &mut *STATE.borrow_ref_mut(cs);

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
                // TODO: send neighbor table to parent.
            }
            Ok(Err(e)) => {
                critical_section::with(|cs| {
                    let table = &mut *STATE.borrow_ref_mut(cs);

                    table.mark_me_disconnected();
                    // Even on connection fail clear the pending parent so search can find new parent.
                    // TODO(perf): If optimization where a new pending parent is picked even while connecting, then this can't be unconditional set `None`.
                    table.pending_parent = None;
                });
                log::warn!("failed connect: mac={next_parent}: {e:?}")
            }
            Err(e) => {
                critical_section::with(|cs| {
                    let table = &mut *STATE.borrow_ref_mut(cs);

                    table.mark_me_disconnected();
                    // Even on connection fail clear the pending parent so search can find new parent.
                    // TODO(perf): If optimization where a new pending parent is picked even while connecting, then this can't be unconditional set `None`.
                    table.pending_parent = None;
                });
                log::warn!("failed connect: mac={next_parent}: {e:?}")
            }
        }
    }
}
