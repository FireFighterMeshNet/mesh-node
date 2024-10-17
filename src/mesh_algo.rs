//! Mesh algorithm similar to that used by esp-mesh. A tree is created and nodes connect to the neighbor closest to the root.

use crate::{consts, util::UnwrapTodo, Mutex};
use core::{borrow::Borrow, marker::PhantomData};
use embassy_time::Timer;
use esp_hal::xtensa_lx::mutex::Mutex as _;
use esp_wifi::wifi::{PromiscuousPkt, Sniffer};
use heapless::FnvIndexMap;
use ieee80211::{
    common::CapabilitiesInformation,
    element_chain,
    elements::{SSIDElement, VendorSpecificElement},
    mac_parser::MACAddress,
    mgmt_frame::BeaconFrame,
};
use scroll::{Pread, Pwrite};

pub type Version = u8;
pub type Level = u8;

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
    /// Data for this node.
    pub me: NodeData,
    /// The data for other nodes.
    // `FnvIndexMap` has to be a power of two in size.
    pub map: FnvIndexMap<MACAddress, NodeData, { consts::MAX_NODES.next_power_of_two() }>,
}

static STATE: Mutex<NodeTable> = Mutex::new(NodeTable {
    me: {
        let mut out = NodeData::new_disconnected();
        if let Some(level) = consts::TREE_LEVEL {
            out.level = level;
        }
        out
    },
    map: FnvIndexMap::new(),
});

/// Updates mesh networks tree state. Expected to be called as part of the [`Sniffer`]
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

        // Apply new messages to state.
        STATE
            .borrow()
            .lock(|table| match table.map.entry(beacon.header.bssid) {
                heapless::Entry::Occupied(mut occupied_entry) => {
                    occupied_entry.get_mut().update_with_msg(data)
                }
                heapless::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(NodeData::from_first_msg(data)?).todo();
                    Ok(())
                }
            })
            .todo();

        // Found the message we care about. Stop looking through elements.
        break;
    }
}

/// Periodic transmit of beacon with custom vendor data.
#[embassy_executor::task]
pub async fn beacon_vendor_tx(mut sniffer: Sniffer, source_mac: MACAddress) {
    // Buffer for beacon body
    let mut beacon = [0u8; 256];
    let data: NodeDataBeaconMsg = STATE.borrow().lock(|table| table.me.borrow().into());
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
