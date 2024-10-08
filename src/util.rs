// See <https://github.com/embassy-rs/static-cell/issues/16>
#[macro_export]
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
macro_rules! make_static {
    ($t:ty, $val:expr) => ($crate::make_static!($t, $val,));
    ($t:ty, $val:expr, $(#[$m:meta])*) => {{
        $(#[$m])*
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        STATIC_CELL.init_with(|| $val)
    }};
}

/// Log error with [`Debug`] impl or [`Display`] if called with leading `%`
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

/// Prototyping unwraps that should be handled when the design is done.
pub trait UnwrapTodo {
    type T;
    fn todo(self) -> Self::T;
    fn todo_msg(self, msg: &str) -> Self::T;
}
impl<T> UnwrapTodo for Option<T> {
    type T = T;

    fn todo(self) -> Self::T {
        self.unwrap_or_else(|| todo!())
    }
    fn todo_msg(self, msg: &str) -> Self::T {
        self.unwrap_or_else(|| todo!("{msg}"))
    }
}
impl<T, E> UnwrapTodo for Result<T, E> {
    type T = T;

    fn todo(self) -> Self::T {
        self.unwrap_or_else(|_| todo!())
    }
    fn todo_msg(self, msg: &str) -> Self::T {
        self.unwrap_or_else(|_| todo!("{msg}"))
    }
}
