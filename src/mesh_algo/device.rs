use embassy_net::driver::{Driver, RxToken as RxTokenEmbassy, TxToken as TxTokenEmbassy};
use smoltcp::{phy::ChecksumCapabilities, wire::EthernetRepr};

pub struct RxToken<T>(T);
impl<T: RxTokenEmbassy> RxTokenEmbassy for RxToken<T> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.0.consume(|buf| {
            let res = f(buf);
            let frame = smoltcp::wire::EthernetFrame::new_unchecked(&*buf);
            let frame = EthernetRepr::parse(&frame).unwrap();
            esp_println::dbg!(frame);
            res
        })
    }
}
pub struct TxToken<T>(T);
impl<T: TxTokenEmbassy> TxTokenEmbassy for TxToken<T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.0.consume(len, |buf| {
            let res = f(buf);
            let frame = smoltcp::wire::EthernetFrame::new_unchecked(&*buf);
            let payload = frame.payload();
            let frame = EthernetRepr::parse(&frame).unwrap();
            match frame.ethertype {
                smoltcp::wire::EthernetProtocol::Ipv6 => {
                    let ipv6 = smoltcp::wire::Ipv6Packet::new_unchecked(&*payload);
                    let payload = ipv6.payload();
                    let ipv6 = smoltcp::wire::Ipv6Repr::parse(&ipv6).unwrap();
                    esp_println::dbg!(ipv6);
                    match ipv6.next_header {
                        smoltcp::wire::IpProtocol::Tcp => {
                            let tcp = smoltcp::wire::TcpPacket::new_unchecked(payload);
                            let payload = tcp.payload();
                            let tcp = smoltcp::wire::TcpRepr::parse(
                                &tcp,
                                &ipv6.src_addr.into_address(),
                                &ipv6.dst_addr.into_address(),
                                &ChecksumCapabilities::default(),
                            )
                            .unwrap();
                            esp_println::dbg!(tcp, payload);
                        }
                        _ => (),
                    }
                }
                _ => (),
            }
            esp_println::dbg!(frame);
            res
        })
    }
}

/// A device which enables running an overlay network over an unreliable mesh network.
pub struct MeshDevice<D> {
    inner: D,
}
impl<D> MeshDevice<D> {
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
    pub fn into_inner(self) -> D {
        self.inner
    }
}
impl<D: Driver> Driver for MeshDevice<D> {
    type RxToken<'a> = RxToken<D::RxToken<'a>> where Self: 'a;

    type TxToken<'a> = TxToken<D::TxToken<'a>> where Self: 'a;

    fn receive(
        &mut self,
        cx: &mut core::task::Context,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inner.receive(cx).map(|x| (RxToken(x.0), TxToken(x.1)))
    }

    fn transmit(&mut self, cx: &mut core::task::Context) -> Option<Self::TxToken<'_>> {
        self.inner.transmit(cx).map(|x| TxToken(x))
    }

    fn link_state(&mut self, cx: &mut core::task::Context) -> embassy_net::driver::LinkState {
        self.inner.link_state(cx)
    }

    fn capabilities(&self) -> embassy_net::driver::Capabilities {
        self.inner.capabilities()
    }

    fn hardware_address(&self) -> embassy_net::driver::HardwareAddress {
        // TODO: should this return `HardwareAddress::Ip` and disable neighbor discovery?
        // Then extract the mac from the given ip and construct a new mac packet for the next hop?
        // Or should it read the ip, calculate next mac, replace-in-place, and deliver to `inner` for next-hop transmission?
        // In the second case, ARP broadcasts would have to forward throughout the whole tree
        // and it would be possible to assign an ip to the overlayer with dhcp regularly.
        let address = self.inner.hardware_address();
        assert!(
            !matches!(address, embassy_net::driver::HardwareAddress::Ip),
            "can't overlay an ip network driver"
        );
        address
    }
}
