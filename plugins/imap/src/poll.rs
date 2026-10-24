//! The wait: look at a source of mail again and again until a message
//! matches or the time is up.

use std::collections::HashSet;
use std::time::Duration;

use seleniumbase_rs_plugin::{Clock, PluginError, Result, async_trait};

use crate::mail::{Found, Mail, Query};

/// The most messages one look fetches (the newest ones).
pub const MAX_BATCH: usize = 25;

/// A message as the server delivers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawMail {
    /// The id the source knows it by (the IMAP UID); a message is looked at once.
    pub id: u32,
    /// The message, as RFC 5322 text.
    pub bytes: Vec<u8>,
}

/// Where messages come from. The plugin reads an IMAP mailbox; tests give it a
/// list.
#[async_trait]
pub trait MailSource: Send {
    /// Messages sent no earlier than about `since_secs` (seconds since the Unix
    /// epoch) whose id is not in `seen`: at most [`MAX_BATCH`], newest first.
    ///
    /// # Errors
    ///
    /// If the source could not be read.
    async fn fetch_new(&mut self, since_secs: u64, seen: &HashSet<u32>) -> Result<Vec<RawMail>>;
}

fn not_found(query: &Query, timeout: Duration) -> PluginError {
    PluginError::other(format!(
        "imap: no email ({}) arrived within {}s",
        query.describe(),
        timeout.as_secs()
    ))
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Looks at `source` every `poll` until a message matches `query`, newest
/// first, or `timeout` has passed. Every message is read once.
///
/// # Errors
///
/// The source's error, or a [`PluginError`] saying that nothing matched in
/// time.
pub async fn wait_for(
    source: &mut dyn MailSource,
    query: &Query,
    clock: &Clock,
    poll: Duration,
    timeout: Duration,
) -> Result<Found> {
    let deadline = clock.now_ms().saturating_add(millis(timeout));
    let mut seen = HashSet::new();
    loop {
        let now_ms = clock.now_ms();
        let left = deadline.saturating_sub(now_ms);
        if left == 0 {
            return Err(not_found(query, timeout));
        }
        let now_secs = now_ms / 1000;
        let since = now_secs.saturating_sub(query.since_secs);
        let batch = clock
            .timeout(Duration::from_millis(left), source.fetch_new(since, &seen))
            .await
            .map_err(|_| not_found(query, timeout))??;
        for raw in batch {
            seen.insert(raw.id);
            if let Some(found) =
                Mail::parse(&raw.bytes).and_then(|mail| query.matches(&mail, now_secs))
            {
                return Ok(found);
            }
        }
        let left = deadline.saturating_sub(clock.now_ms());
        if left == 0 {
            return Err(not_found(query, timeout));
        }
        clock.sleep(poll.min(Duration::from_millis(left))).await;
    }
}
