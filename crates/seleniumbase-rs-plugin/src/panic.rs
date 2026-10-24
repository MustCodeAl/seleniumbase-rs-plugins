//! Panic capture for plugin hooks.
//!
//! A plugin is foreign code: a bug in one hook must not unwind through the
//! host. [`catch`] polls a hook's future inside `catch_unwind`, so a panic
//! becomes a value the set turns into [`PluginError::Panicked`](crate::PluginError::Panicked).
//! It needs no dependency: the future is pinned on the caller's stack.
//!
//! This relies on unwinding. A host built with `panic = "abort"` still stops
//! at a panic, as any Rust program does.

use std::future::{Future, poll_fn};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::pin;
use std::task::Poll;

/// Runs `future` to completion, or returns `Err(())` if polling it panicked.
///
/// The future is dropped as soon as it panics and is never polled again. The
/// panic message goes where the process's panic hook sends it (standard error
/// by default); it is not part of the result.
pub(crate) async fn catch<F: Future>(future: F) -> Result<F::Output, ()> {
    let mut future = pin!(future);
    poll_fn(move |cx| {
        match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(payload) => {
                // A payload whose destructor panics must not escape either.
                let _ = catch_unwind(AssertUnwindSafe(|| drop(payload)));
                Poll::Ready(Err(()))
            }
        }
    })
    .await
}
