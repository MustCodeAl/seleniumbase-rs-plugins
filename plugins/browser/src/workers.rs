//! `wait_for_workers`: waiting until the service workers of the extensions the
//! plugin loaded are running.
//!
//! The wait asks the host (`BrowserHandle::extension_workers`) and sleeps on
//! the clock the plugin set provides (`BrowserHandle::clock`), because a hook
//! like `on_browser` gets neither a task context nor a runtime.

use std::path::Path;
use std::time::Duration;

use seleniumbase_rs_plugin::{
    BrowserHandle, Clock, ExtensionWorker, LoadedExtension, PluginError, Result,
};

use crate::source::Worker;

/// How often the wait asks the host.
pub(crate) const POLL: Duration = Duration::from_millis(250);

/// How much longer than the wait the set may let `on_browser` run, so that the
/// plugin's own message, and not the bare time-out of the hook, ends a wait.
pub(crate) const HOOK_HEADROOM: Duration = Duration::from_secs(5);

/// An extension to wait for: the id the host gave it and the path the user
/// wrote for it.
struct Wanted<'a> {
    id: String,
    label: &'a Path,
}

/// The error of the option, with `what` as the reason.
fn refuse(what: impl std::fmt::Display) -> PluginError {
    PluginError::other(format!("browser: `wait_for_workers`: {what}"))
}

/// Waits until each of `workers` has a running service worker, for at most
/// `seconds`. An empty list is nothing to wait for.
///
/// # Errors
///
/// An error naming `wait_for_workers` when the host cannot list workers, did
/// not report an id for one of the extensions, gives the plugin no clock, or
/// when a worker is still missing after `seconds`.
pub(crate) async fn wait(
    browser: &dyn BrowserHandle,
    workers: &[Worker],
    seconds: u64,
) -> Result<()> {
    if workers.is_empty() {
        return Ok(());
    }
    let first = match browser.extension_workers().await {
        Err(PluginError::NotSupported(_)) => {
            return Err(refuse(
                "needs a host that reports extension service workers; this host does not",
            ));
        }
        other => other?,
    };
    let wanted = identify(&browser.extensions(), workers)?;
    let clock = browser
        .clock()
        .ok_or_else(|| refuse("needs a clock the host did not provide"))?;

    let mut missing = Vec::new();
    let waiting = poll(browser, &clock, &wanted, first, &mut missing);
    match clock.timeout(Duration::from_secs(seconds), waiting).await {
        Ok(result) => result,
        Err(PluginError::Timeout(_)) => Err(refuse(format!(
            "no service worker for {} after {seconds} s",
            describe(&wanted, &missing)
        ))),
        Err(other) => Err(other),
    }
}

/// Asks the host again and again until nothing is missing. `missing` holds the
/// indexes into `wanted` that the last answer left out.
async fn poll(
    browser: &dyn BrowserHandle,
    clock: &Clock,
    wanted: &[Wanted<'_>],
    mut snapshot: Vec<ExtensionWorker>,
    missing: &mut Vec<usize>,
) -> Result<()> {
    loop {
        *missing = absent(wanted, &snapshot);
        if missing.is_empty() {
            return Ok(());
        }
        clock.sleep(POLL).await;
        snapshot = browser.extension_workers().await?;
    }
}

/// The indexes of the extensions in `wanted` that have no worker in `running`.
fn absent(wanted: &[Wanted<'_>], running: &[ExtensionWorker]) -> Vec<usize> {
    wanted
        .iter()
        .enumerate()
        .filter(|(_, extension)| running.iter().all(|worker| worker.id != extension.id))
        .map(|(index, _)| index)
        .collect()
}

/// The ids the host gave the extensions of `workers`, found by their folders.
fn identify<'a>(loaded: &[LoadedExtension], workers: &'a [Worker]) -> Result<Vec<Wanted<'a>>> {
    workers
        .iter()
        .map(|worker| {
            let id = loaded
                .iter()
                .find(|extension| same_folder(&extension.path, &worker.folder))
                .map(|extension| extension.id.clone())
                .ok_or_else(|| {
                    refuse(format!(
                        "the host did not report an id for the extension `{}`, so its service worker cannot be awaited",
                        worker.label.display()
                    ))
                })?;
            Ok(Wanted {
                id,
                label: &worker.label,
            })
        })
        .collect()
}

/// Whether two paths name the same folder: equal, or equal once resolved.
fn same_folder(reported: &Path, ours: &Path) -> bool {
    reported == ours
        || matches!(
            (std::fs::canonicalize(reported), std::fs::canonicalize(ours)),
            (Ok(a), Ok(b)) if a == b
        )
}

/// The extensions at `missing`, for the message.
fn describe(wanted: &[Wanted<'_>], missing: &[usize]) -> String {
    missing
        .iter()
        .filter_map(|&index| wanted.get(index))
        .map(|extension| format!("extension {} ({})", extension.id, extension.label.display()))
        .collect::<Vec<_>>()
        .join(", ")
}
