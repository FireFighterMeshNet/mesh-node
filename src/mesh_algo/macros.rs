/// Implement the [`scroll`] traits using [`zerocopy`]
macro_rules! impl_scroll_with_zerocopy {
    ($ty:ident) => {
        impl scroll::ctx::TryIntoCtx for $ty {
            type Error = scroll::Error;

            fn try_into_ctx(self, dst: &mut [u8], _ctx: ()) -> Result<usize, Self::Error> {
                use zerocopy::IntoBytes;
                let bytes = self.as_bytes();
                let offset = &mut 0;
                dst.gwrite(bytes, offset)?;
                Ok(*offset)
            }
        }
        impl scroll::ctx::TryFromCtx<'_> for $ty {
            type Error = scroll::Error;

            fn try_from_ctx(from: &[u8], _ctx: ()) -> Result<(Self, usize), Self::Error> {
                use zerocopy::FromBytes;
                Ok((
                    Self::read_from_prefix(from)
                        .map_err(|_| scroll::Error::TooBig {
                            size: size_of::<Self>(),
                            len: from.len(),
                        })?
                        .0,
                    size_of::<Self>(),
                ))
            }
        }
        impl scroll::ctx::MeasureWith<()> for $ty {
            fn measure_with(&self, _: &()) -> usize {
                size_of::<Self>()
            }
        }
        impl scroll::ctx::SizeWith<()> for $ty {
            fn size_with(_: &()) -> usize {
                size_of::<Self>()
            }
        }
    };
}
pub(super) use impl_scroll_with_zerocopy;
