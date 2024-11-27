#![cfg_attr(not(feature = "build"), no_std)]

#[cfg(feature = "build")]
pub mod build;

mod util;

pub use util::*;
