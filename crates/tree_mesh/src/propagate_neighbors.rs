use super::*;
use core::ops::ControlFlow;
use embassy_futures::join::join;
use simulator::IO;
use zerocopy::IntoBytes;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    zerocopy::TryFromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(u8)]
#[allow(non_camel_case_types)] // silence zerocopy error
pub enum PropagateNeighborMsg {
    Connect([u8; 6]),
    Disconnect([u8; 6]),
}
impl PropagateNeighborMsg {
    fn mac(self) -> [u8; 6] {
        match self {
            Self::Connect(mac) | Self::Disconnect(mac) => mac,
        }
    }
}

/// Serialized child connection events so we don't have an ABA issue (node connects, disconnects, connects should end connected).
static MAC_CHANGE_TO_TX: Channel<PropagateNeighborMsg, { consts::MAX_NODES * 2 }> = Channel::new();

/// Messages that were received out-of-order and have to be handled later.
type ChildThatSent = MACAddress;
static REQUEUED: Channel<(PropagateNeighborMsg, ChildThatSent), { consts::MAX_NODES * 2 }> =
    Channel::new();

/// If the given message received from the given `child` is out-of-order;
fn message_out_of_order(
    table: &mut NodeTable,
    msg: PropagateNeighborMsg,
    child: MACAddress,
) -> bool {
    table
        .map
        .get(&MACAddress(msg.mac()))
        .and_then(|x| match x.postion {
            // If the descendant is connected to a child, only that child can
            // claim ownership. It is an out-of-order message if received by a different child.
            TreePos::Down(macaddress) if macaddress != child => Some(()),
            _ => None,
        })
        .is_some()
}

/// Update with the given message received from the given child.
async fn update_from_msg(msg: PropagateNeighborMsg, child: MACAddress) {
    let (mac, new_pos) = match msg {
        PropagateNeighborMsg::Connect(mac) => (mac, TreePos::Down(child)),
        PropagateNeighborMsg::Disconnect(mac) => (mac, TreePos::Disconnected),
    };
    if critical_section::with(|cs| {
        let table = &mut *STATE.borrow_ref_mut(cs);
        log::trace!(
            "update neighbor start: {:?}\nmsg: {:?}, child: {}",
            table,
            msg,
            child
        );

        // Check that `child` can be the ancestor of the given node
        // and if not, add update message to back of queue instead of processing.
        // This way if the tree transition is:
        /*
          A       A
         B C  -> B C
        D           D
         */
        // and get C connect and then B disconnect, C's connect will go to back of queue, B disconnect will be processed first and then C's
        // What if D goes B C B and A gets both B's messages before C's?
        // Then C's message will stay queued until next disconnect msg from `B` and `C`'s messages will cancel out.
        // TODO: This has unbounded overhead because sequence can be B dis, C con, C dis, C con, C dis, ..., B con
        // with a received message order of all B's messages before any of C's.
        // This can be changed to fixed overhead of max 1 msg per node by cancelling con-dis pairs in the queue instead of queueing a second.
        if message_out_of_order(table, msg, child) {
            // Replace `todo_msg` with `unwrap` after above todo is fixed.
            log::trace!("message out of order",);
            REQUEUED.try_send((msg, child)).todo_msg("no space left");
            return ControlFlow::Break(());
        }

        let child_level = table.map[&child].level;
        match table.map.entry(MACAddress(mac)) {
            heapless::Entry::Occupied(mut occupied_entry) => {
                occupied_entry.get_mut().postion = new_pos;
            }
            heapless::Entry::Vacant(vacant_entry) => {
                let mut new_node = NodeData::from_first_msg(NodeDataBeaconMsg {
                    version: consts::PROT_VERSION,
                    // TODO this might be wrong if multiple hops away from child
                    level: child_level + 1,
                })
                .unwrap();
                new_node.postion = new_pos;
                vacant_entry.insert(new_node).todo();
            }
        }
        log::trace!(
            "update neighbor end: {:?}\nmsg: {:?}, child: {}",
            table,
            msg,
            child
        );
        ControlFlow::Continue(())
    })
    .is_break()
    {
        return;
    }
    // Add to list of things to tx
    MAC_CHANGE_TO_TX.send(msg).await
}

/// Drain requeued until the next message is out-of-order again.
async fn drain_requeued() {
    // Note: Don't lock `REQUEUED` and critical section at the same time to avoid thinking about deadlocks.
    while let Ok((msg, child)) = REQUEUED.try_receive() {
        if critical_section::with(|cs| {
            message_out_of_order(&mut *STATE.borrow_ref_mut(cs), msg, child)
        }) {
            REQUEUED.try_send((msg, child)).unwrap();
            break;
        } else {
            update_from_msg(msg, child).await;
        }
    }
}

/// Handle receiving propagate neighbor messages.
async fn rx_propagate_neighbors(ap_rx_socket: &'static mut TcpSocket<'static>) -> ! {
    let mut buf = [0u8; size_of::<PropagateNeighborMsg>()];

    // Accept connection, handle neighbor changes, wait for client to disconnect.
    loop {
        err!(ap_rx_socket.accept(consts::CONTROL_PORT).await);
        let remote = ap_rx_socket
            .remote_endpoint()
            .expect("should have remote after accept");
        ap_rx_socket.close(); // not going to write to child.
        err!(ap_rx_socket.flush().await);
        match ap_rx_socket.read_exact(&mut buf).await {
            Ok(()) => {
                let msg: Result<PropagateNeighborMsg, _> = zerocopy::try_transmute!(buf);
                match msg {
                    Ok(msg) => {
                        update_from_msg(
                            msg,
                            consts::mac_from_sta_addr(
                                #[allow(unreachable_patterns)]
                                match remote.addr {
                                    embassy_net::IpAddress::Ipv6(address) => address,
                                    _ => unreachable!(),
                                },
                            ),
                        )
                        .await;
                        drain_requeued().await;
                    }
                    Err(e) => todo!("invalid PropagateNeighborMsg: {e:?}"),
                }
            }
            Err(e) => match e {
                // other side also done.
                embedded_io_async::ReadExactError::UnexpectedEof => continue,
                embedded_io_async::ReadExactError::Other(e) => err!(Err::<(), _>(e)),
            },
        }
    }
}

/// Send propagate neighbor messages.
async fn tx_propagate_neighbors(sta_tx_socket: &'static mut TcpSocket<'static>) -> ! {
    // Connect to parent, send queued updates, disconnect.
    loop {
        sta_tx_socket.close();
        err!(sta_tx_socket.flush().await);
        // Wait for updates.
        MAC_CHANGE_TO_TX.ready_to_receive().await;

        // Don't connect to parent if there is none, but empty queue of events.
        if critical_section::with(|cs| STATE.borrow_ref_mut(cs).parent.is_none()) {
            while let Ok(_) = MAC_CHANGE_TO_TX.try_receive() {}
            continue;
        }

        match sta_tx_socket
            .connect(IpEndpoint::new(
                consts::AP_CIDR.address().into(),
                consts::CONTROL_PORT,
            ))
            .await
        {
            Ok(()) => (),
            e @ Err(_) => {
                err!(e);
                continue;
            }
        }

        // If disconnected from parent don't need to tell parent about different events,
        // they already know we disconnected therefore all our children too.
        // TODO: When we connect to a new parent we will send our currently connected list.
        while let Ok(msg) = MAC_CHANGE_TO_TX.try_receive() {
            err!(sta_tx_socket.write_all(msg.as_bytes()).await);
        }
    }
}

/// Send and receive multi-hop neighbor updates.
/// Tell parent what children have connected and handle the same messages from children.
pub(crate) async fn propagate_neighbors<S: IO>(
    ap_rx_socket: &'static mut TcpSocket<'static>,
    sta_tx_socket: &'static mut TcpSocket<'static>,
) -> ! {
    S::ApStadisconnected::update_handler(|event| {
        let ap_mac = S::sta_mac_to_ap(event.mac());
        MAC_CHANGE_TO_TX
            .try_send(PropagateNeighborMsg::Disconnect(ap_mac.0))
            .todo_msg("too many new macs");
        critical_section::with(|cs| {
            let table = &mut *STATE.borrow_ref_mut(cs);
            // For each node that was reached through the disconnected node, disconnect it.
            for val in table.map.values_mut() {
                if val.postion == TreePos::Down(ap_mac) {
                    *val = NodeData::new_disconnected();
                }
            }
        })
    });
    S::ApStaconnected::update_handler(|event| {
        let ap_mac = S::sta_mac_to_ap(event.mac());
        critical_section::with(|cs| {
            let table = &mut *STATE.borrow_ref_mut(cs);
            table.map.insert(
                ap_mac,
                NodeData {
                    postion: TreePos::Down(ap_mac),
                    version: consts::PROT_VERSION,
                    level: table.level(),
                },
            )
        })
        .todo();

        MAC_CHANGE_TO_TX
            .try_send(PropagateNeighborMsg::Connect(ap_mac.0))
            .todo_msg("too many new macs");
    });

    join(
        rx_propagate_neighbors(ap_rx_socket),
        tx_propagate_neighbors(sta_tx_socket),
    )
    .await
    .0;
}
