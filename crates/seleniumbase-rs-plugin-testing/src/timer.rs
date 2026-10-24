//! A timer that moves when a test says so.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Waker};
use std::time::Duration;

use seleniumbase_rs_plugin::Timer;

/// The time [`ManualTimer::now_ms`](Timer::now_ms) starts from: 2026-01-01.
const START_MS: u64 = 1_767_225_600_000;

#[derive(Debug, Default)]
struct State {
    now: Duration,
    wakers: Vec<Waker>,
}

/// A [`Timer`] whose time stands still until [`advance`](Self::advance) moves
/// it, so a test checks a time limit without waiting for it.
///
/// ```
/// use std::time::Duration;
/// use seleniumbase_rs_plugin::Timer;
/// use seleniumbase_rs_plugin_testing::{block_on, ManualTimer};
///
/// let timer = ManualTimer::new();
/// let sleep = timer.sleep(Duration::from_secs(10));
/// timer.advance(Duration::from_secs(10));
/// block_on(sleep);
/// assert_eq!(timer.elapsed(), Duration::from_secs(10));
/// ```
#[derive(Clone, Debug, Default)]
pub struct ManualTimer {
    state: Arc<Mutex<State>>,
}

impl ManualTimer {
    /// A timer at time zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Moves time forward and wakes every sleep that is due.
    pub fn advance(&self, by: Duration) {
        let wakers = {
            let mut state = self.state();
            state.now += by;
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// How far time has been moved.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.state().now
    }
}

impl Timer for ManualTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let deadline = self.state().now + duration;
        let state = Arc::clone(&self.state);
        Box::pin(poll_fn(move |cx| {
            let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
            if state.now >= deadline {
                Poll::Ready(())
            } else {
                state.wakers.push(cx.waker().clone());
                Poll::Pending
            }
        }))
    }

    fn now_ms(&self) -> u64 {
        START_MS + u64::try_from(self.state().now.as_millis()).unwrap_or(u64::MAX)
    }
}
