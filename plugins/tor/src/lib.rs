//! Sends the browser's traffic through a local Tor daemon (work in progress).

mod config;
pub mod forwarder;
mod socks;

pub use config::{ControlAuth, Isolation, TorConfig};
pub use forwarder::{Forwarder, IsolationToken, Limits};

/// Runs a future to completion on a small runtime, for the unit tests.
#[cfg(test)]
pub(crate) fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(future)
}
