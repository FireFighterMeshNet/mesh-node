use super::*;

pub type PacketLen = u8;
#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub destination: MACAddress,
    pub len: PacketLen,
}
impl PacketHeader {
    /// Length of packet as `usize`
    pub fn len(&self) -> usize {
        self.len.into()
    }
}
impl scroll::ctx::TryIntoCtx for &PacketHeader {
    type Error = scroll::Error;

    fn try_into_ctx(self, dst: &mut [u8], _: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        dst.gwrite(self.destination, offset)?;
        dst.gwrite_with::<PacketLen>(self.len, offset, scroll::NETWORK)?;

        Ok(*offset)
    }
}
impl scroll::ctx::TryFromCtx<'_> for PacketHeader {
    type Error = scroll::Error;

    fn try_from_ctx(from: &[u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let destination = from.gread(offset)?;
        let len = from.gread_with::<PacketLen>(offset, scroll::NETWORK)?;

        Ok((Self { destination, len }, *offset))
    }
}
impl SizeWith for PacketHeader {
    fn size_with(_: &()) -> usize {
        size_of::<MACAddress>() + size_of::<PacketLen>()
    }
}
impl scroll::ctx::MeasureWith<()> for PacketHeader {
    fn measure_with(&self, ctx: &()) -> usize {
        Self::size_with(ctx)
    }
}

#[derive(Debug, Clone)]
pub struct Packet<'a> {
    pub destination: MACAddress,
    pub data: &'a [u8],
}
impl scroll::ctx::TryIntoCtx for &Packet<'_> {
    type Error = scroll::Error;

    fn try_into_ctx(self, dst: &mut [u8], _ctx: ()) -> Result<usize, Self::Error> {
        let offset = &mut 0;

        dst.gwrite(self.destination, offset)?;
        dst.gwrite_with::<PacketLen>(
            self.data
                .len()
                .try_into()
                .expect("PacketLen::MAX < usize::MAX"),
            offset,
            scroll::NETWORK,
        )?;
        dst.gwrite(self.data, offset)?;

        Ok(*offset)
    }
}
impl<'a> scroll::ctx::TryFromCtx<'a> for Packet<'a> {
    type Error = scroll::Error;

    fn try_from_ctx(from: &'a [u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
        let offset = &mut 0;

        let destination = from.gread(offset)?;
        let len = from.gread_with::<PacketLen>(offset, scroll::NETWORK)? as usize;
        let data = from.gread_with(offset, len)?;

        Ok((Self { destination, data }, *offset))
    }
}
impl scroll::ctx::MeasureWith<()> for Packet<'_> {
    fn measure_with(&self, _: &()) -> usize {
        size_of::<PacketHeader>() + self.data.len()
    }
}
impl<'a> Packet<'a> {
    /// Maximum size of a single packet.
    pub const fn max_size() -> usize {
        size_of::<PacketHeader>() + PacketLen::MAX as usize
    }
    pub fn new(destination: MACAddress, data: &'a [u8]) -> Result<Self, PacketNewErr> {
        if data.len() > PacketLen::MAX.into() {
            return Err(PacketNewErr::TooBig);
        }
        Ok(Self { destination, data })
    }
    pub async fn send(&self, socket: &mut TcpSocket<'_>) -> Result<(), PacketSendErr> {
        let mut done = false;
        loop {
            // If too big to ever send, then give up.
            if self.measure_with(&()) > socket.send_capacity() {
                return Err(PacketSendErr::TooBig);
            }
            socket
                .write_with(|buf| match buf.pwrite(self, 0) {
                    Ok(len) => {
                        done = true;
                        (len, ())
                    }
                    Err(scroll::Error::TooBig { .. }) => (0, ()),
                    Err(scroll::Error::BadInput { .. } | scroll::Error::BadOffset(..)) => {
                        unreachable!()
                    }
                })
                .await
                .map_err(|e| PacketSendErr::Tcp { source: e })?;
            if done {
                break;
            }
            log::debug!("yield");
            // No way to wait until tcp stack has x space available, so yield and loop
            futures_lite::future::yield_now().await;
        }
        Ok(())
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
    pub fn destination(&self) -> MACAddress {
        self.destination
    }
    pub fn destination_mut(&mut self) -> &mut MACAddress {
        &mut self.destination
    }
}
