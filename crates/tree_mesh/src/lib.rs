//! Mesh algorithm similar to that used by esp-mesh. A tree is created and nodes connect to the neighbor closest to the root.
#![no_std]
#![feature(impl_trait_in_assoc_type)] // needed for embassy's tasks on nightly for perfect sizing with generic `static`s
#![feature(closure_lifetime_binder)] // for<'a> |&'a| syntax
#![feature(async_closure)] // not needed in 1.85

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "alloc")]
#[macro_use]
#[allow(unused_imports)]
extern crate alloc;

pub mod consts;
pub mod device;
mod error;
pub mod macros;
pub mod node_data;
pub mod packet;
mod propagate_neighbors;
pub mod simulator;

#[cfg(test)]
mod tests;

pub use packet::{Packet, PacketHeader};

use common::{err, UnwrapExt};
use core::{cell::RefCell, marker::PhantomData};
use critical_section::Mutex;
use embassy_net::{tcp::TcpSocket, IpAddress, IpEndpoint};
use embassy_sync::{
    blocking_mutex::raw::CriticalSectionRawMutex,
    channel::{Channel as ChannelRaw, Receiver, Sender},
    pubsub::PubSubChannel as PubSubChannelRaw,
    signal::Signal as SignalRaw,
};
use embassy_time::{Duration, Timer, WithTimeout};
use embedded_io_async::{Read, Write};
use heapless::FnvIndexMap;
use ieee80211::{
    common::CapabilitiesInformation,
    element_chain,
    elements::{SSIDElement, VendorSpecificElement},
    mac_parser::MACAddress,
    mgmt_frame::BeaconFrame,
};
use node_data::{NodeData, NodeDataBeaconMsg, NodeTable};
use scroll::{Pread, Pwrite};
use simulator::*;

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

/// Close and flush, then abort socket.
pub async fn socket_force_closed(socket: &mut TcpSocket<'_>) {
    socket.close();
    err!(socket.flush().await);
    socket.abort();
    err!(socket.flush().await);
}

fn resolve_next_hop(address: MACAddress) -> TreePos {
    // Resolve next-hop.
    critical_section::with(|cs| {
        let table = &mut *STATE.borrow_ref_mut(cs);
        if let Some(dest) = table
            .map
            .iter()
            .find(|x| *x.0 == address)
            .map(|x| x.1.clone())
        {
            return dest.postion;
        }

        // If the addressed node isn't known to this node, hopefully a higher node does know it.
        if table.parent.is_none() {
            log::warn!("next-hop mac {address} missing and no parent");
        }
        TreePos::Disconnected
    })
}

/// All MACs to send to given the cause of the flood came from `rx_from`
fn resolve_flood(rx_from: MACAddress) -> impl Iterator<Item = MACAddress> {
    critical_section::with(|cs| {
        let table = &mut *STATE.borrow_ref_mut(cs);
        table
            .map
            .iter()
            .filter(|x| *x.0 != rx_from) // don't flood loop.
            .flat_map(|x| match x.1.postion {
                // Nodes which are 1 level further and accessible by children are direct children.
                TreePos::Down(child) if x.1.level == table.level() + 1 => Some(child),
                _ => None,
            })
            // There is one parent
            .chain(table.parent)
            .collect::<heapless::Vec<_, { consts::MAX_NODES.next_power_of_two() }>>()
            .into_iter()
    })
}

fn next_hop_select_ap_sta<T>(address: MACAddress, ap: T, sta: T) -> (IpAddress, T) {
    let pos = resolve_next_hop(address);

    // The ip depends on the node and the socket depends on if using sta (connected to parent) or ap (connected to children) interface.
    match pos {
        TreePos::Up | TreePos::Disconnected => (consts::AP_CIDR.address().into(), sta),
        TreePos::Down(child_mac) => (consts::sta_cidr_from_mac(child_mac).address().into(), ap),
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
pub fn sniffer_callback<S: IO>(data: &[u8]) {
    // Return quick helps since this is called and blocks every packet.
    // Ignore non-beacon frames.
    let Ok(beacon) = ieee80211::match_frames!(data, beacon = BeaconFrame => { beacon }) else {
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
        let Some(payload) = field.get_payload_if_prefix_matches(&S::OUI) else {
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
pub(crate) async fn beacon_vendor_tx<S: IO>(mut sniffer: S::Sniffer, source_mac: MACAddress) -> ! {
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
                                &S::OUI,
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
        if let Err(e) = sniffer.send_raw_frame(&beacon[0..length]) {
            log::error!("Failed to send beacon: {e:?}")
        }
        log::trace!("beacon tx'ed");

        Timer::after_millis(100).await;
    }
}

/// Connects to new parent nodes if a better one is found.
pub(crate) async fn connect_to_next_parent<S: IO>(
    controller: &'static AsyncMutex<S::Controller>,
) -> ! {
    // Make sure to update state on disconnects.
    S::StaDisconnected::update_handler(|event| {
        critical_section::with(|cs| STATE.borrow_ref_mut(cs).mark_me_disconnected());
        log::warn!("STA disconnected: {}", event.mac());
    });

    // Keep connecting to `NEXT_PARENT` whenever a new one is identified.
    loop {
        let next_parent = NEXT_PARENT.wait().await;
        log::info!("connecting: mac={next_parent}");

        let res = S::connect_to_other_node(&mut *controller.lock().await, next_parent, 1)
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

/// Run all background tasks needed for the tree mesh
pub async fn run<S: IO>(
    sniffer: S::Sniffer,
    controller: &'static AsyncMutex<S::Controller>,
    ap_rx_socket: &'static mut TcpSocket<'static>,
    sta_tx_socket: &'static mut TcpSocket<'static>,
    ap_mac: MACAddress,
) -> ! {
    use embassy_futures::join::join;
    let future1 = beacon_vendor_tx::<S>(sniffer, ap_mac);
    let future2 = connect_to_next_parent::<S>(controller);
    let future3 = propagate_neighbors::propagate_neighbors::<S>(ap_rx_socket, sta_tx_socket);
    // Make sure to balance (binary tree) as more futures are added.
    let res = join(future1, join(future2, future3)).await;
    res.0
}
