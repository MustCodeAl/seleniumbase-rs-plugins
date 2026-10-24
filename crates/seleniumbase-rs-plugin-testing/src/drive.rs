//! Helpers that drive a [`PluginSet`] the way the host does, and a sink that
//! keeps what a task records.

use std::sync::{Mutex, PoisonError};

use seleniumbase_rs_plugin::{
    PluginError, PluginSet, RequestDecision, RequestView, ResponseView, Result, Sink,
};
use serde_json::Value;

use crate::block_on;

/// Asks `set` what happens to `request`, as the host does for a request it
/// paused: see [`PluginSet::on_request`].
#[must_use]
pub fn drive_request(set: &PluginSet, request: RequestView) -> RequestDecision {
    block_on(set.on_request(&request))
}

/// Gives `response` to `set`, as the host does: see [`PluginSet::on_response`].
/// Returns the errors the plugins' hooks gave.
#[must_use]
pub fn drive_response(set: &PluginSet, response: ResponseView<'_>) -> Vec<PluginError> {
    block_on(set.on_response(&response))
}

/// A [`Sink`] that keeps every line a task records.
#[derive(Debug, Default)]
pub struct VecSink {
    lines: Mutex<Vec<Value>>,
}

impl VecSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// What was recorded, in order.
    #[must_use]
    pub fn lines(&self) -> Vec<Value> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Sink for VecSink {
    fn record(&self, line: &Value) -> Result<()> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line.clone());
        Ok(())
    }
}
