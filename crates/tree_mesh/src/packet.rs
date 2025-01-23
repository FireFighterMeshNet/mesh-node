use super::*;
use zerocopy::{network_endian::U16, IntoBytes};

pub type PacketLen = U16;
#[derive(
    Debug,
    Default,
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
    pub fn new(destination: MACAddress, len: usize) -> Result<Self, error::PacketNewErr> {
        Ok(Self {
            destination: destination.0,
            len: len.try_into().map_err(|_| error::PacketNewErr::TooBig)?,
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

#[derive(
    Debug,
    Clone,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Packet<T: AsRef<[u8]> + ?Sized> {
    pub header: PacketHeader,
    pub data: T,
}
impl<T: AsRef<[u8]>> scroll::ctx::TryIntoCtx for &Packet<T> {
    type Error = scroll::Error;

    fn try_into_ctx(self, dst: &mut [u8], _ctx: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        dst.gwrite(self.header, offset)?;
        dst.gwrite(self.data.as_ref(), offset)?;

        Ok(*offset)
    }
}
impl<'a> scroll::ctx::TryFromCtx<'a> for Packet<&'a [u8]> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let header: PacketHeader = from.gread(offset)?;
        let data = from.gread_with(offset, header.len())?;

        Ok((Self { header, data }, *offset))
    }
}
impl<T: AsRef<[u8]>> scroll::ctx::MeasureWith<()> for Packet<T> {
    fn measure_with(&self, _: &()) -> usize {
        size_of::<PacketHeader>() + self.data.as_ref().len()
    }
}
impl Packet<&[u8]> {
    /// Maximum size of a single packet.
    pub const fn max_size() -> usize {
        size_of::<PacketHeader>() + PacketLen::MAX_VALUE.get() as usize
    }
}
impl<T: AsRef<[u8]> + ?Sized> Packet<T> {
    pub fn new(destination: MACAddress, data: T) -> Result<Self, error::PacketNewErr>
    where
        T: Sized,
    {
        Ok(Self {
            header: PacketHeader::new(destination, data.as_ref().len())?,
            data,
        })
    }
    pub fn data(&self) -> &T {
        &self.data
    }
    /// The range of a [`[u8]`] that backs the [`Packet`] containing the data field.
    /// Useful for [`<[u8]>::copy_within()`]
    pub fn data_range(&self) -> impl core::ops::RangeBounds<usize> {
        size_of::<PacketHeader>()..
    }
    pub fn destination(&self) -> MACAddress {
        self.header.destination()
    }
    pub fn set_destination(&mut self, destination: MACAddress) {
        self.header.set_destination(destination);
    }

    pub async fn send<'a>(
        &self,
        ap_tx_socket: impl Into<Option<&'a mut TcpSocket<'static>>>,
        sta_tx_socket: impl Into<Option<&'a mut TcpSocket<'static>>>,
    ) -> Result<(), error::PacketSendErr> {
        let dest = self.header.destination();

        let socket = next_hop_socket_connected(dest, ap_tx_socket, sta_tx_socket)
            .await
            .ok_or(error::PacketSendErr::NextHopMissing)?;

        socket
            .write_all(self.header.as_bytes())
            .await
            .map_err(|e| error::PacketSendErr::Tcp { source: e })?;
        socket
            .write_all(self.data.as_ref())
            .await
            .map_err(|e| error::PacketSendErr::Tcp { source: e })?;

        Ok(())
    }
}
impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    // Don't give `&mut T` so if `T` is a `Vec` or similar it can't change its size and make the header inconsistent.
    pub fn data_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}
