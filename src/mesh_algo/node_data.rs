use super::*;

/// Value of data for a single node.
#[derive(Default, Debug, Clone)]
pub struct NodeData {
    pub postion: TreePos,
    /// Version of this protocol the node is running.
    pub version: Version,
    /// Distance from root. Root is 0. Root's children is 1, etc.
    pub level: Level,
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
            return Err(InvalidMsg::Version {
                version: msg.version,
            });
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
            return Err(InvalidMsg::Version {
                version: msg.version,
            });
        }
        self.version = msg.version;
        self.level = msg.level;
        Ok(())
    }
}

/// Beacon message per node.
#[derive(Debug, Clone)]
pub struct NodeDataBeaconMsg {
    pub version: Version,
    pub level: Level,
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
    /// [`MACAddress`] of parent currently being connected to.
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
            // While the node only connects to parents closer to the root and defaults to MAX,
            // it is possible the connected parent which used to be closer to root disconnects and become Level::MAX,
            // in which case we saturate instead of wrapping.
            self.map[&parent].level.saturating_add(1)
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
