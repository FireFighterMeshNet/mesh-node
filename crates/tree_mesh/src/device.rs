//! Mesh overlay device.

use crate::{next_hop_select_ap_sta, resolve_flood, Packet};
use common::err;
use embassy_futures::select::{select, Either};
use embassy_net::{udp::UdpSocket, EthernetAddress, IpEndpoint, IpListenEndpoint};
pub use embassy_net_driver_channel as ch;
use ieee80211::mac_parser::MACAddress;
use log::trace;
use scroll::{ctx::MeasureWith, Pwrite};
use smoltcp::wire::EthernetFrame;
use zerocopy::{FromBytes, IntoBytes, SizeError};

pub struct MeshRunner<'a, const MTU: usize> {
    pub runner: ch::Runner<'a, MTU>,
    pub ap_mac: MACAddress,
    pub ap_socket: UdpSocket<'a>,
    pub sta_socket: UdpSocket<'a>,
}
impl<'d, const MTU: usize> MeshRunner<'d, MTU> {
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
                    let (len, meta) = match ready_socket.recv_from(rx_buf).await {
                        Ok(x) => x,
                        e @ Err(_) => {
                            err!(e, "received forward msg longer than MTU");
                            continue;
                        }
                    };
                    // Get the wrapped packet.
                    let pkt = match <Packet<[u8]>>::ref_from_bytes(&rx_buf[..len])
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
                        ($address:expr) => {{
                            // Get which socket to use.
                            let (ip, socket) = next_hop_select_ap_sta(
                                $address,
                                &mut self.ap_socket,
                                &mut self.sta_socket,
                            );
                            // Send data to the next hop.
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
                            socket.flush().await;
                        }};
                    }

                    if to_me {
                        let data_range = pkt.data_range();
                        rx_buf.copy_within(data_range, 0);
                        rx.rx_done(len);
                    } else if flood {
                        trace!("flood from: {}", meta.endpoint);
                        let embassy_net::IpAddress::Ipv6(rx_from) = meta.endpoint.addr else {
                            err!(Err::<(), _>("non ipv6 udp received"));
                            continue;
                        };

                        for node in resolve_flood(crate::consts::mac_from_sta_addr(rx_from)) {
                            trace!("flood forward to: {}", MACAddress(node.0));
                            send_to_next_hop!(node)
                        }
                        let data_range = pkt.data_range();
                        rx_buf.copy_within(data_range, 0);
                        rx.rx_done(len);
                    } else {
                        send_to_next_hop!(pkt.header.destination());
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
                            socket.flush().await;
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
                        send_to_next_hop!(pkt.destination());
                    }
                    tx.tx_done();
                }
            }
        }
    }
}
