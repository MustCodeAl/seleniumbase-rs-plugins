//! Time for plugins: the [`Timer`] a host provides and the [`Clock`] built on it.
//!
//! The API crate has no runtime. seleniumbase-rs gives the set a timer that
//! sleeps on tokio ([`PluginSet::with_timer`](crate::PluginSet::with_timer));
//! tests give it a manual one that moves when the test says so
//! (`ManualTimer` in `seleniumbase-rs-plugin-testing`).

use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{PluginError, Result};

/// A source of sleeps, so the API crate needs no async runtime.
pub trait Timer: Send + Sync {
    /// A future that finishes after `duration`, counted from this call.
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    /// Milliseconds since the Unix epoch. The default reads the system clock;
    /// a test timer returns its own time.
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// What a task uses for sleeping, time limits and the current time.
///
/// ```
/// use std::sync::Arc;
/// use std::time::Duration;
/// use seleniumbase_rs_plugin::{Clock, PluginError};
/// use seleniumbase_rs_plugin_testing::{block_on, ManualTimer};
///
/// let timer = Arc::new(ManualTimer::new());
/// let clock = Clock::new(timer.clone());
/// // The future never finishes; the timer is moved past the limit.
/// let waiting = clock.timeout(Duration::from_secs(5), std::future::pending::<()>());
/// timer.advance(Duration::from_secs(6));
/// assert!(matches!(block_on(waiting), Err(PluginError::Timeout(_))));
/// ```
#[derive(Clone)]
pub struct Clock {
    timer: Arc<dyn Timer>,
}

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Clock").finish_non_exhaustive()
    }
}

impl Clock {
    /// A clock over `timer`.
    #[must_use]
    pub fn new(timer: Arc<dyn Timer>) -> Self {
        Self { timer }
    }

    /// Waits for `duration`.
    pub async fn sleep(&self, duration: Duration) {
        self.timer.sleep(duration).await;
    }

    /// Runs `future`, giving up after `duration`. The time starts when this is
    /// called, not when the result is first polled.
    ///
    /// # Errors
    ///
    /// The returned future gives [`PluginError::Timeout`] if the time ran out
    /// first; `future` is dropped then.
    pub fn timeout<F: Future>(
        &self,
        duration: Duration,
        future: F,
    ) -> impl Future<Output = Result<F::Output>> {
        let mut future = Box::pin(future);
        let mut sleep = self.timer.sleep(duration);
        poll_fn(move |cx| {
            if let Poll::Ready(value) = future.as_mut().poll(cx) {
                return Poll::Ready(Ok(value));
            }
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(PluginError::Timeout(duration)));
            }
            Poll::Pending
        })
    }

    /// Milliseconds since the Unix epoch, by the timer's clock.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.timer.now_ms()
    }
}
