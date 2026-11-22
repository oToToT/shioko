//! shioko: a minimal TLS-terminating reverse proxy. The library is the
//! whole of it; the binary (src/main.rs) starts it, and the fuzz targets
//! (fuzz/) drive its parts.

#![cfg_attr(test, allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic))]

/// Records a step of spec/Server.tla in `--features record` builds; in
/// other builds it is nothing at all.
macro_rules! record {
    ($($what:tt)*) => {
        #[cfg(feature = "record")]
        crate::record::step(&format!($($what)*));
    };
}

pub mod config;
pub mod crypto;
pub mod http;
pub mod log;
pub mod net;
pub mod pem;
#[cfg(feature = "record")]
pub mod record;
pub mod server;
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod signals;
pub mod stream;
pub mod tls;
