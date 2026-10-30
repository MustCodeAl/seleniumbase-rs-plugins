//! The checks the plugin makes before the browser starts: something answers as
//! a SOCKS5 proxy where Tor's SocksPort should be and, when a control port is
//! configured, Tor says that it finished bootstrapping.
//!
//! The checks never request a connection through Tor, so they send no traffic
//! to the network. They fail closed: an error here means the browser is not
//! started.

use std::net::SocketAddr;

use seleniumbase_rs_plugin::{PluginError, Result};

use std::time::Duration;

use tokio::net::TcpStream;

use crate::config::TorConfig;
use crate::{control, socks};

/// The message when nothing listens on the SocksPort.
#[must_use]
pub fn no_listener_message(address: SocketAddr) -> String {
    format!(
        "tor: no SOCKS listener at {address}; start a local Tor daemon (sbrs never installs or \
         starts Tor)"
    )
}

/// Checks Tor as `config` describes it. A password for the control port is
/// read from the process environment.
///
/// # Errors
///
/// [`PluginError::Other`] with a message for the user when nothing answers as
/// a SOCKS5 proxy at `socks`, or, with `require_bootstrapped` and a control
/// port, when the control port cannot be used or Tor has not finished
/// bootstrapping.
pub async fn check(config: &TorConfig) -> Result<()> {
    check_with(config, &|name| std::env::var(name).ok()).await
}

/// [`check`] with the environment given as a function, so that a test does not
/// have to change the process's.
///
/// # Errors
///
/// As [`check`].
pub async fn check_with(
    config: &TorConfig,
    env: &(dyn Fn(&str) -> Option<String> + Sync),
) -> Result<()> {
    probe_socks(config.socks).await?;
    if !config.require_bootstrapped {
        return Ok(());
    }
    // `require_bootstrapped` needs the control port; without one there is
    // nothing more to ask.
    let (Some(control), Some(auth)) = (config.control, config.control_auth.as_ref()) else {
        return Ok(());
    };
    let bootstrap = control::bootstrap_status(control, auth, env)
        .await
        .map_err(|why| PluginError::other(format!("tor: {why}")))?;
    if bootstrap.progress < 100 {
        let summary = if bootstrap.summary.is_empty() {
            String::new()
        } else {
            format!(": {}", bootstrap.summary)
        };
        return Err(PluginError::other(format!(
            "tor: the Tor daemon is still bootstrapping ({}%, {}{summary}); wait until it \
             reports 100% or set `require_bootstrapped = false`",
            bootstrap.progress, bootstrap.tag
        )));
    }
    Ok(())
}

/// How long to wait for the SocksPort to accept a connection and answer.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Connects to `address` and checks that it answers as a SOCKS5 proxy. No
/// request is made, so no traffic leaves the machine.
async fn probe_socks(address: SocketAddr) -> Result<()> {
    let connected = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(address)).await;
    let Ok(Ok(mut stream)) = connected else {
        return Err(PluginError::other(no_listener_message(address)));
    };
    let not_socks = |why: String| {
        PluginError::other(format!(
            "tor: something listens at {address}, but it does not answer as a SOCKS5 proxy \
                 ({why}); `socks` must be Tor's SocksPort, not its control port or an HTTP proxy"
        ))
    };
    match tokio::time::timeout(PROBE_TIMEOUT, socks::probe(&mut stream)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(not_socks(error.to_string())),
        Err(_) => Err(not_socks(format!(
            "no answer within {} seconds",
            PROBE_TIMEOUT.as_secs()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_names_the_address_and_says_that_sbrs_never_starts_tor() {
        assert_eq!(
            no_listener_message("127.0.0.1:9050".parse().unwrap()),
            "tor: no SOCKS listener at 127.0.0.1:9050; start a local Tor daemon (sbrs never \
             installs or starts Tor)"
        );
    }
}
