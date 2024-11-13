use super::*;
use zerocopy::IntoBytes;

pub type PacketLen = u8;
#[derive(
    Debug,
    Clone,
    Copy,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct PacketHeader {
    destination: [u8; 6],
    len: PacketLen,
}
impl PacketHeader {
    pub fn new(destination: MACAddress, len: usize) -> Result<Self, PacketNewErr> {
        Ok(Self {
            destination: destination.0,
            len: len.try_into().map_err(|_| PacketNewErr::TooBig)?,
        })
    }
    pub fn len(&self) -> usize {
        self.len.into()
    }
    pub fn destination(&self) -> MACAddress {
        MACAddress(self.destination)
    }
    pub fn set_destination(&mut self, destination: MACAddress) {
        self.destination = destination.0;
    }
}
macros::impl_scroll_with_zerocopy!(PacketHeader);

#[derive(Debug, Clone)]
pub struct Packet<'a> {
    pub header: PacketHeader,
    pub data: &'a [u8],
}
impl scroll::ctx::TryIntoCtx for &Packet<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, dst: &mut [u8], _ctx: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        dst.gwrite(self.header, offset)?;
        dst.gwrite(self.data, offset)?;

        Ok(*offset)
    }
}
impl<'a> scroll::ctx::TryFromCtx<'a> for Packet<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let header: PacketHeader = from.gread(offset)?;
        let data = from.gread_with(offset, header.len())?;

        Ok((Self { header, data }, *offset))
    }
}
impl scroll::ctx::MeasureWith<()> for Packet<'_> {
    fn measure_with(&self, _: &()) -> usize {
        size_of::<PacketHeader>() + self.data.len()
    }
}
impl<'a> Packet<'a> {
    pub fn new(destination: MACAddress, data: &'a [u8]) -> Result<Self, PacketNewErr> {
        Ok(Self {
            header: PacketHeader::new(destination, data.len())?,
            data,
        })
    }
    pub fn data(&self) -> &[u8] {
        self.data
    }
    pub fn destination(&self) -> MACAddress {
        self.header.destination()
    }
    pub fn set_destination(&mut self, destination: MACAddress) {
        self.header.set_destination(destination);
    }

    /// Maximum size of a single packet.
    pub const fn max_size() -> usize {
        size_of::<PacketHeader>() + PacketLen::MAX as usize
    }

    pub async fn send(&self, socket: &mut TcpSocket<'_>) -> Result<(), PacketSendErr> {
        socket
            .write_all(self.header.as_bytes())
            .await
            .map_err(|e| PacketSendErr::Tcp { source: e })?;
        socket
            .write_all(self.data)
            .await
            .map_err(|e| PacketSendErr::Tcp { source: e })?;

        Ok(())
    }
}
