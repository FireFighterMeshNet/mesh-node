//! Mesh overlay device.
//!
//! This device creates an "overlay" network which can be used to access different nodes in the mesh as though they are directly connected to this node. It does this by sending, receiving, and forwarding wrapped packets on an "underlay" network where nodes organize themselves into a tree-like connectivity and each node may not be directly accessible to each other.
//!
//! To use the mesh, the [`embassy_net`] types such as [`embassy_net::tcp::TcpSocket`] or [`embassy_net::udp::UdpSocket`], should be created with the device returned by [`new`].
//!
//! For example:
//! ```no_run
//! # use ieee80211::mac_parser::MACAddress;
//! # use embassy_net::{udp::UdpSocket, tcp::TcpSocket};
//! // Construct the mesh device.
//! const MTU: usize = 1492; // With MTU of 1492 bytes
//! const N_RX: usize = 3; // Max 3 buffered packets received (for bursts).
//! const N_TX: usize = 3; // Max 3 buffered packets transmitted (for bursts).
//! let state: &mut embassy_net_driver_channel::State::<MTU, N_RX, N_TX>;
//! let address: embassy_net::driver::HardwareAddress;
//! let ap_mac: MACAddress;
//! let ap_socket: UdpSocket;
//! let sta_socket: UdpSocket;
//! # state = common::make_static!(const
//! #             embassy_net_driver_channel::State::<MTU, N_RX, N_TX>,
//! #             embassy_net_driver_channel::State::new()
//! #         );
//! # ap_mac = MACAddress::default();
//! # address = embassy_net::driver::HardwareAddress::Ethernet(ap_mac.0);
//! # ap_socket = unimplemented!();
//! # sta_socket = unimplemented!();
//! let (mesh_device, mesh_device_runner) = tree_mesh::device::new(
//!     state,
//!     address,
//!     ap_mac,
//!     ap_socket,
//!     sta_socket,
//! );
//!
//! // Create an embassy network stack on the mesh device.
//! let stack_resources: &mut embassy_net::StackResources::<1>;
//! let rng: u64;
//! let config: embassy_net::Config;
//! # rng = 0;
//! # stack_resources = common::make_static!(const embassy_net::StackResources::<1>, embassy_net::StackResources::new());
//! # config = embassy_net::Config::ipv6_static(embassy_net::StaticConfigV6 {
//! #             address: tree_mesh::consts::sta_cidr_from_mac(ap_mac),
//! #             gateway: None,
//! #             dns_servers: Default::default(),
//! #         });
//! let (mesh_stack, mesh_stack_runner) = embassy_net::new(
//!     mesh_device,
//!     config,
//!     stack_resources,
//!     rng,
//! );
//!
//! // Create a new socket on that network stack.
//! let rx_buf: &mut [u8; {2usize.pow(12)}];
//! # rx_buf = common::make_static!(const [u8; 2usize.pow(12)], [0; 2usize.pow(12)]);
//! let tx_buf: &mut [u8; {2usize.pow(12)}];
//! # tx_buf = common::make_static!(const [u8; 2usize.pow(12)], [0; 2usize.pow(12)]);
//! let mesh_tcp_socket = TcpSocket::new(mesh_stack, rx_buf, tx_buf);
//! ```
//!

pub use embassy_net_driver_channel as ch;

use crate::{next_hop_select_ap_sta, packet::PacketLen, resolve_flood, Packet, PacketHeader};
use ch::{Device, State};
use common::err;
use embassy_futures::select::{select, Either};
use embassy_net::{driver, udp::UdpSocket, EthernetAddress, IpEndpoint, IpListenEndpoint};
use ieee80211::mac_parser::MACAddress;
use log::trace;
use scroll::{ctx::MeasureWith, Pwrite};
use smoltcp::wire::EthernetFrame;
use zerocopy::{FromBytes, IntoBytes, SizeError};

/// Construct the mesh device and the runner which must be polled for the device to progress.
pub fn new<'d, const MTU: usize, const N_RX: usize, const N_TX: usize>(
    state: &'d mut State<MTU, N_RX, N_TX>,
    hardware_address: driver::HardwareAddress,
    ap_mac: MACAddress,
    ap_socket: UdpSocket<'d>,
    sta_socket: UdpSocket<'d>,
) -> (Device<'d, MTU>, MeshRunner<'d, MTU>) {
    let (runner, device) = ch::new(state, hardware_address);
    (
        device,
        MeshRunner::new(runner, ap_mac, ap_socket, sta_socket),
    )
}

/// [`MeshRunner::run`] must be polled (or `await`ed) to progress the mesh device.
pub struct MeshRunner<'a, const MTU: usize> {
    pub runner: ch::Runner<'a, MTU>,
    pub ap_mac: MACAddress,
    pub ap_socket: UdpSocket<'a>,
    pub sta_socket: UdpSocket<'a>,
    rx_staging_buf: Packet<[u8; MTU]>,
}
impl<'d, const MTU: usize> MeshRunner<'d, MTU> {
    pub fn new(
        runner: ch::Runner<'d, MTU>,
        ap_mac: MACAddress,
        ap_socket: UdpSocket<'d>,
        sta_socket: UdpSocket<'d>,
    ) -> Self {
        const {
            assert!(
                MTU <= PacketLen::MAX_VALUE.get() as usize,
                "MTU of the mesh must be <= the max size of a `Packet` but is greater.",
            )
        }
        let me = Self {
            runner,
            ap_mac,
            ap_socket,
            sta_socket,
            rx_staging_buf: Packet::new(Default::default(), [0; MTU]).unwrap(),
        };
        assert!(
            me.ap_socket.payload_recv_capacity() >= MTU + size_of::<PacketHeader>(),
            "buffer provided to MeshRunner too small for MTU + PacketHeader"
        );
        assert!(
            me.ap_socket.payload_recv_capacity() >= MTU + size_of::<PacketHeader>(),
            "buffer provided to MeshRunner smaller than MTU + PacketHeader"
        );
        assert!(
            me.sta_socket.payload_send_capacity() >= MTU + size_of::<PacketHeader>(),
            "buffer provided to MeshRunner smaller than MTU + PacketHeader"
        );
        assert!(
            me.sta_socket.payload_recv_capacity() >= MTU + size_of::<PacketHeader>(),
            "buffer provided to MeshRunner smaller than MTU + PacketHeader"
        );
        me
    }
    pub async fn run(mut self) -> ! {
        let (_state, mut rx, mut tx) = self.runner.split();
        self.ap_socket
            .bind(IpListenEndpoint {
                addr: None,
                port: crate::consts::DATA_PORT,
            })
            .unwrap();
        self.sta_socket
            .bind(IpListenEndpoint {
                addr: None,
                port: crate::consts::DATA_PORT,
            })
            .unwrap();
        loop {
            match select(
                async {
                    // Wait until there is space to rx into overlay driver if necessary.
                    let rx_buf = rx.rx_buf().await;
                    // Wait until there is a rxed packet from underlay network.
                    let ap_or_sta = select(
                        self.ap_socket.wait_recv_ready(),
                        self.sta_socket.wait_recv_ready(),
                    )
                    .await;
                    (rx_buf, ap_or_sta)
                },
                // Wait until there is a packet to forward through underlay network.
                tx.tx_buf(),
            )
            .await
            {
                Either::First((rx_buf, ap_or_sta)) => {
                    trace!("mesh rx buf");
                    let ready_socket = match ap_or_sta {
                        Either::First(()) => &mut self.ap_socket,
                        Either::Second(()) => &mut self.sta_socket,
                    };
                    let rx_staging = self.rx_staging_buf.as_mut_bytes();
                    let (len, meta) = match ready_socket.recv_from(rx_staging).await {
                        Ok(x) => x,
                        e @ Err(_) => {
                            err!(e, "received forward msg longer than MTU");
                            continue;
                        }
                    };
                    // Get the wrapped packet.
                    let pkt = match <Packet<[u8]>>::ref_from_bytes(&rx_staging[..len])
                        .map_err(|e| SizeError::from(e))
                    {
                        Ok(pkt) => pkt,
                        e @ Err(_) => {
                            err!(e, "rxed packet size error");
                            continue;
                        }
                    };
                    // Either deliver to overlay or forward on underlay network again depending on final destination.
                    let to_me = pkt.header.destination() == self.ap_mac;
                    // Flooding on non-unicast is always valid even if inefficient.
                    // In other words this doesn't optimize multicast groups.
                    let flood = !EthernetAddress(pkt.header.destination().0).is_unicast();

                    // TODO: make function
                    macro_rules! send_to_next_hop {
                        ($address:expr, $extra_ignore:expr) => {{
                            // Get which socket to use.
                            let (ip, socket) = next_hop_select_ap_sta(
                                $address,
                                &mut self.ap_socket,
                                &mut self.sta_socket,
                            );

                            if $extra_ignore.into_iter().all(|x| x.addr != ip) {
                                // Send data to the next hop.
                                trace!("sending to next hop {:?}", ip);
                                err!(
                                    socket
                                        .send_to(
                                            &pkt.as_bytes(),
                                            IpEndpoint {
                                                addr: ip,
                                                port: crate::consts::DATA_PORT,
                                            },
                                        )
                                        .await
                                );
                            } else {
                                trace!("not sending to next hop, ip resolved to an ignored address")
                            }
                        }};
                    }

                    if to_me {
                        rx_buf[..pkt.data.len()].copy_from_slice(&pkt.data);
                        rx.rx_done(pkt.data.len());
                    } else if flood {
                        trace!("flood from: {}", meta.endpoint);
                        let embassy_net::IpAddress::Ipv6(rx_from) = meta.endpoint.addr else {
                            err!(Err::<(), _>("non ipv6 udp received"));
                            continue;
                        };

                        for node in resolve_flood(crate::consts::mac_from_sta_addr(rx_from)) {
                            trace!("flood forward to: {}", MACAddress(node.0));
                            send_to_next_hop!(node, Some(meta.endpoint))
                        }
                        rx_buf[..pkt.data.len()].copy_from_slice(&pkt.data);
                        rx.rx_done(pkt.data.len());
                    } else {
                        send_to_next_hop!(pkt.header.destination(), None::<IpEndpoint>);
                    }
                }
                Either::Second(tx_buf) => {
                    trace!("mesh tx buf");
                    let frame = EthernetFrame::new_unchecked(&tx_buf);
                    let dst = frame.dst_addr();
                    // The mac used by the overlay network matches the actual final destination mac of the underlay network.
                    let pkt = Packet::new(dst.0.into(), tx_buf).unwrap();

                    // TODO: make function
                    macro_rules! send_to_next_hop {
                        ($address:expr) => {{
                            // Get which socket to use.
                            let (ip, socket) = next_hop_select_ap_sta(
                                $address,
                                &mut self.ap_socket,
                                &mut self.sta_socket,
                            );
                            // Send data to the next hop.
                            // TODO if the size is too large does this await forever (buffer never getting large enough)?
                            // TODO pr: yep, need to submit pr to embassy-net
                            err!(
                                socket
                                    .send_to_with(
                                        pkt.measure_with(&()),
                                        IpEndpoint {
                                            addr: ip,
                                            port: crate::consts::DATA_PORT,
                                        },
                                        |buf| buf.pwrite(&pkt, 0),
                                    )
                                    .await
                            );
                        }};
                    }

                    // Flooding on non-unicast is always valid even if inefficient.
                    // In other words this doesn't optimize multicast groups.
                    let flood = !dst.is_unicast();
                    if flood {
                        trace!("flood from self");
                        for node in resolve_flood(self.ap_mac) {
                            trace!("flood from self to: {}", MACAddress(node.0));
                            send_to_next_hop!(node)
                        }
                    } else {
                        trace!("adding new packet to underlay network");
                        send_to_next_hop!(pkt.destination());
                    }
                    tx.tx_done();
                }
            }
        }
    }
}
