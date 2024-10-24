use core::future::{Future, IntoFuture};
use either::Either;
use futures_lite::FutureExt;

// See <https://github.com/embassy-rs/static-cell/issues/16>
/// Convert a `T` to a `&'static mut T`.
///
/// The macro declares a `static StaticCell` and then initializes it when run, returning the `&'static mut`.
/// Therefore, each instance can only be run once. Next runs will panic. The `static` can additionally be
/// decorated with attributes, such as `#[link_section]`, `#[used]`, et al.
///
/// # Examples
///
/// ```
/// # fn main() {
/// let x: &'static mut u32 = make_static!(u32, 42);
///
/// // This attribute instructs the linker to allocate it in the external RAM's BSS segment.
/// // This specific example is for ESP32S3 with PSRAM support.
/// let buf = make_static!([u8; 4096], [0u8; 4096], #[link_section = ".ext_ram.bss.buf"]);
///
/// // Multiple attributes can be supplied.
/// let s = make_static!(usize, 0usize, #[used] #[export_name = "exported_symbol_name"]);
/// # }
/// ```
#[macro_export]
macro_rules! make_static {
    ($t:ty, $val:expr) => ($crate::make_static!($t, $val,));
    ($t:ty, $val:expr, $(#[$m:meta])*) => {{
        $(#[$m])*
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        STATIC_CELL.init_with(|| $val)
    }};
}

/// Log error with [`core::fmt::Debug`] impl or [`core::fmt::Display`] if called with leading `%`
macro_rules! err {
    ($e:expr) => {
        if let Err(e) = $e {
            log::error!("[{}:{}] {e:?}", file!(), line!())
        }
    };
    (%$e:expr) => {
        if let Err(e) = $e {
            log::error!("[{}:{}] {e}", file!(), line!())
        }
    };
}

/// Extra `unwrap`-like methods
pub trait UnwrapExt {
    type T;
    /// `unwrap` indicating this is prototype code. Should be removed from final product.
    fn todo(self) -> Self::T;
    /// `unwrap` indicating this is prototype code. Allows a message. Should be removed from final product.
    fn todo_msg(self, msg: &str) -> Self::T;
    /// Indicates an assertion that should be true but isn't worth crashing over.
    fn unwrap_or_log(self, msg: impl core::fmt::Display);
}
impl<T> UnwrapExt for Option<T> {
    type T = T;

    fn todo(self) -> Self::T {
        self.unwrap_or_else(|| todo!())
    }
    fn todo_msg(self, msg: &str) -> Self::T {
        self.unwrap_or_else(|| todo!("{msg}"))
    }
    /// Unwrap type or log as error.
    fn unwrap_or_log(self, msg: impl core::fmt::Display) {
        if self.is_none() {
            log::error!("{msg}")
        }
    }
}
impl<T, E> UnwrapExt for Result<T, E> {
    type T = T;

    fn todo(self) -> Self::T {
        self.unwrap_or_else(|_| todo!())
    }
    fn todo_msg(self, msg: &str) -> Self::T {
        self.unwrap_or_else(|_| todo!("{msg}"))
    }
    fn unwrap_or_log(self, msg: impl core::fmt::Display) {
        if self.is_err() {
            log::error!("{msg}")
        }
    }
}

/// Extension trait to race heterogeneous futures.
pub trait SelectEither {
    /// Select Either the result of the first future (Left) or the result of the second future (Right), whichever is ready first.
    #[allow(async_fn_in_trait)]
    async fn select<T1, T2>(self, fut2: impl IntoFuture<Output = T2>) -> Either<T1, T2>
    where
        Self: Future<Output = T1> + Sized,
    {
        async { Either::Left(self.await) }
            .or(async { Either::Right(fut2.await) })
            .await
    }
}
impl<F: Future> SelectEither for F {}
