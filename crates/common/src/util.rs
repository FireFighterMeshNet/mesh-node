use core::{future::Future, pin::Pin};

// See <https://github.com/embassy-rs/static-cell/issues/16>
/// Convert a `T` to a `&'static mut T`.
///
/// The macro declares a `static StaticCell` and then initializes it when run, returning the `&'static mut`.
/// Therefore, each instance can only be run once. Next runs will panic. The `static` can additionally be
/// decorated with attributes, such as `#[link_section]`, `#[used]`, et al.
///
/// If prefixed with `const` then uses a `static ConstStaticCell` to initialize the value at compile time to guarantee no runtime initialization cost and not intialized on the stack.
///
/// # Examples
///
/// ```
/// # fn main() {
/// let x: &'static mut u32 = make_static!(u32, 42);
///
/// // This attribute instructs the linker to allocate it in the external RAM's BSS segment.
/// // This specific example is for ESP32S3 with PSRAM support.
/// let buf = make_static!(#[link_section = ".ext_ram.bss.buf"] [u8; 4096], [0u8; 4096]);
///
/// // Multiple attributes can be supplied.
/// let s = make_static!(#[used] #[export_name = "exported_symbol_name"] usize, 0usize);
///
/// // Better to prefix with `const` when possible to avoid initializing on stack and copying to final destination.
/// let s = make_static!(const #[used] #[export_name = "exported_symbol_name"] usize, 0usize);
/// # }
/// ```
#[macro_export]
macro_rules! make_static {
    ($(#[$m:meta])* $t:ty, $val:expr $(,)?) => {{
        $(#[$m])*
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        STATIC_CELL.init_with(|| $val)
    }};
    (const $(#[$m:meta])* $t:ty, $val:expr $(,)?) => {{
        $(#[$m])*
        static STATIC_CELL: static_cell::ConstStaticCell<$t> = static_cell::ConstStaticCell::new($val);
        STATIC_CELL.take()
    }};
}

/// Log error with [`core::fmt::Debug`] impl or [`core::fmt::Display`] if called with leading `%`
#[macro_export]
macro_rules! err {
    ($e:expr) => {
        if let Err(e) = $e {
            log::error!("[{}:{}] {e:?}", file!(), line!())
        }
    };
    ($e:expr, $s:expr) => {
        if let Err(e) = $e {
            let s = $s;
            log::error!("[{}:{}] - {s}: {e:?}", file!(), line!())
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

#[derive(Debug, Clone, Copy, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct LogFut<'a, F> {
    fut: F,
    msg: &'a str,
}
impl<'a, F: Future> LogFut<'a, F> {
    fn inner(self: Pin<&mut Self>) -> Pin<&mut F> {
        // This is okay because `field` is pinned when `self` is.
        unsafe { self.map_unchecked_mut(|s| &mut s.fut) }
    }
    pub fn into_parts(self) -> (F, &'a str) {
        (self.fut, self.msg)
    }
}
impl<'a, F: Future> Future for LogFut<'a, F> {
    type Output = F::Output;
    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        log::trace!("polled '{}'", self.msg);
        self.inner().poll(cx)
    }
}
pub trait LogFutExt: Future + Sized {
    fn inspect(self, msg: &str) -> LogFut<Self> {
        LogFut { fut: self, msg }
    }
}
impl<F: Future> LogFutExt for F {}
