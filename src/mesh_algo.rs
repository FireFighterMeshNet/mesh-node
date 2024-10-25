//! Mesh algorithm similar to that used by esp-mesh. A tree is created and nodes connect to the neighbor closest to the root.

use crate::{
    connect_to_other_node, consts,
    util::{SelectEither, UnwrapExt},
    Mutex,
};
use core::{borrow::Borrow, future::Future, marker::PhantomData};
use either::Either;
use embassy_sync::{
    blocking_mutex::raw::CriticalSectionRawMutex,
    channel::{Channel, Receiver, Sender},
    pubsub::{DynPublisher, DynSubscriber},
    signal::Signal,
};
use embassy_time::{Duration, Instant, TimeoutError, Timer, WithTimeout};
use esp_hal::xtensa_lx::mutex::Mutex as _;
use esp_wifi::wifi::{Configuration, PromiscuousPkt, Sniffer, WifiController, WifiEvent};
use heapless::FnvIndexMap;
use ieee80211::{
    common::CapabilitiesInformation,
    element_chain,
    elements::{SSIDElement, VendorSpecificElement},
    mac_parser::MACAddress,
    mgmt_frame::BeaconFrame,
};
use scroll::{Pread, Pwrite};
use stack_dst::Value;

pub type Version = u8;
pub type Level = u8;

pub type OneShotRx<T> = Receiver<'static, CriticalSectionRawMutex, T, 1>;
pub type OneShotTx<T> = Sender<'static, CriticalSectionRawMutex, T, 1>;
pub type OneShotChannel<T> = Channel<CriticalSectionRawMutex, T, 1>;

/// Errors related to messages received.
#[derive(Debug, Clone)]
pub enum InvalidMsg {
    /// Protocol version of msg doesn't match.
    Version(Version),
}

/// Relative position in the mesh tree.
#[derive(Debug, Default, Clone)]
pub enum TreePos {
    /// Above this node in tree.
    Ancestor,
    /// Below this node in tree.
    Descendant,
    /// Same level in tree.
    Sibling,
    /// Descendant of sibling. `esp-mesh` doesn't track these nodes, but we have so few we can.
    SiblingDescendant,
    /// Not connected to this node.
    #[default]
    Disconnected,
}

/// Value of data for a single node.
#[derive(Default, Debug, Clone)]
pub struct NodeData {
    postion: TreePos,
    /// Version of this protocol the node is running.
    version: Version,
    /// Distance from root. Root is 0. Root's children is 1, etc.
    level: Level,
}
impl NodeData {
    pub const fn new_disconnected() -> Self {
        NodeData {
            postion: TreePos::Disconnected,
            version: consts::PROT_VERSION,
            level: u8::MAX,
        }
    }
    /// Create a new [`NodeData`] from the first msg received from a node.
    pub fn from_first_msg(msg: NodeDataBeaconMsg) -> Result<Self, InvalidMsg> {
        if msg.version != consts::PROT_VERSION {
            return Err(InvalidMsg::Version(msg.version));
        }
        Ok(Self {
            postion: TreePos::Disconnected,
            version: msg.version,
            level: msg.level,
        })
    }
    /// Update an existing [`NodeData`] with a more recent [`NodeDataBeaconMsg`]
    pub fn update_with_msg(&mut self, msg: NodeDataBeaconMsg) -> Result<(), InvalidMsg> {
        if msg.version != consts::PROT_VERSION {
            return Err(InvalidMsg::Version(msg.version));
        }
        self.version = msg.version;
        self.level = msg.level;
        Ok(())
    }
}

/// Beacon message per node.
#[derive(Debug, Clone)]
pub struct NodeDataBeaconMsg {
    version: Version,
    level: Level,
}
impl scroll::ctx::TryIntoCtx for NodeDataBeaconMsg {
    type Error = scroll::Error;

    fn try_into_ctx(self, dst: &mut [u8], _ctx: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        dst.gwrite_with(self.version, offset, scroll::NETWORK)?;
        dst.gwrite_with(self.level, offset, scroll::NETWORK)?;

        Ok(*offset)
    }
}
impl scroll::ctx::TryFromCtx<'_> for NodeDataBeaconMsg {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let version = from.gread_with(offset, scroll::NETWORK)?;
        let level = from.gread_with(offset, scroll::NETWORK)?;

        Ok((Self { version, level }, *offset))
    }
}
impl scroll::ctx::MeasureWith<()> for NodeDataBeaconMsg {
    fn measure_with(&self, _: &()) -> usize {
        size_of::<Self>()
    }
}
impl From<&NodeData> for NodeDataBeaconMsg {
    fn from(value: &NodeData) -> Self {
        Self {
            version: value.version,
            level: value.level,
        }
    }
}

/// Table of all mesh info.
#[derive(Debug, Clone)]
pub struct NodeTable {
    /// [`MacAddress`] of parent currently being connected to.
    /// Should only be [`Some`] while connecting.
    /// Prevents trashing when multiple nodes are simultaneously better than current parent.
    pub pending_parent: Option<MACAddress>,
    /// Parent if connected.
    pub parent: Option<MACAddress>,
    /// The data for other nodes.
    // `FnvIndexMap` has to be a power of two in size.
    pub map: FnvIndexMap<MACAddress, NodeData, { consts::MAX_NODES.next_power_of_two() }>,
}
impl NodeTable {
    /// Saturates at the furthest level from the root if self is disconnected.
    // This enables the level of `self` to dynamically change as the parent's level changes.
    pub fn level(&self) -> Level {
        if let Some(level) = consts::TREE_LEVEL {
            level
        } else if let Some(parent) = self.parent {
            self.map[&parent].level + 1
        } else {
            Level::MAX
        }
    }
    /// The message sent in beacons to other nodes.
    pub fn beacon_msg(&self) -> NodeDataBeaconMsg {
        NodeDataBeaconMsg {
            version: consts::PROT_VERSION,
            level: self.level(),
        }
    }
    /// Mark self as disconnected from the tree. Doesn't actually disconnect.
    pub fn mark_me_disconnected(&mut self) {
        self.parent = None;
    }
}

/// Stored in a static because the sniffer callback is unfortunately a `fn` not a `Fn` and can't store runtime state.
static STATE: Mutex<NodeTable> = Mutex::new(NodeTable {
    pending_parent: None,
    parent: None,
    map: FnvIndexMap::new(),
});

/// [`MacAddress`] for next parent node to connect to.
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
    // Buffer for beacon body
    let mut beacon = [0u8; 256];
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
    log::info!("sending vendor-beacons");

    loop {
        // Send raw frame using wifi-stack's sequence number.
        // Will give an `ESP_ERR_INVALID_ARG` if sending for most configurations if `use_internal_seq_num` != true when wi-fi is initialized.
        // See <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/wifi.html#side-effects-to-avoid-in-different-scenarios>
        if let Err(e) = sniffer.send_raw_frame(false, &beacon[0..length], true) {
            log::error!("Failed to send beacon: {e:?}")
        }

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
/// `controller` has to be managed exclusively by this task so events and actions be simultaneously awaited. See "actor model".
/// Can send commands for what to do next from many other tasks using the channel for `rx`.
#[embassy_executor::task]
pub async fn controller_task(
    mut config: Configuration,
    mut controller: WifiController<'static>,
    rx: Receiver<'static, CriticalSectionRawMutex, ControllerCommand, 10>,
    sta_disconnected_rx: DynPublisher<'static, (Instant, MACAddress)>,
) {
    loop {
        // Wait for an event from the controller or a message to do something with the controller.
        let res = rx
            .receive()
            .select(controller.wait_for_events(
                WifiEvent::StaDisconnected | WifiEvent::ApStaconnected,
                false,
            ))
            .await;

        match res {
            Either::Left(mut msg) => msg.0(&mut config, &mut controller).await,
            Either::Right(event) => {
                if event.contains(WifiEvent::StaDisconnected) {
                    sta_disconnected_rx.publish_immediate((
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

                            // Unset pending level now that it is set.
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
