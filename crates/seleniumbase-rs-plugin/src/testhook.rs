//! Test hooks: a plugin learns when a test starts and ends and may fail it.
//!
//! The runner calls [`PluginSet::on_test_start`] and [`PluginSet::on_test_end`]
//! around each test, while the test's page is still open. Both reach only
//! plugins that hold [`Capability::TestHooks`].

use crate::{Capability, PageHandle, PluginError, PluginSet};

/// A test, as the runner names it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct TestInfo {
    /// The test's name, such as `checkout::pays_with_a_card`.
    pub name: String,
    /// The source file, when the runner knows it.
    pub file: Option<String>,
}

impl TestInfo {
    /// A test called `name`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            file: None,
        }
    }

    /// Sets the source file.
    #[must_use]
    pub fn file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }
}

/// How a test ended before the plugins had their say.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TestOutcome {
    /// It passed.
    Passed,
    /// It failed; the message says how.
    Failed(String),
    /// It did not run.
    Skipped,
}

/// What a plugin makes of a finished test.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TestVerdict {
    /// Leave the result as it is.
    Keep,
    /// Fail the test with this message, even if it passed.
    Fail(String),
}

impl PluginSet {
    /// Tells every plugin that holds [`Capability::TestHooks`] a test starts.
    /// Every plugin runs even when one fails; the failures are returned for the
    /// caller to log.
    pub async fn on_test_start(&self, test: &TestInfo) -> Vec<PluginError> {
        let mut failures = Vec::new();
        for entry in self.holding(&Capability::TestHooks) {
            if let Err(error) = self
                .run_hook(entry, "on_test_start", entry.plugin.on_test_start(test))
                .await
            {
                failures.push(error);
            }
        }
        failures
    }

    /// Asks every plugin that holds [`Capability::TestHooks`] what it makes of a
    /// finished test, while its `page` is still open. The messages of the
    /// plugins that return [`TestVerdict::Fail`] are joined with `"; "`, in
    /// run order, into one [`TestVerdict::Fail`]; otherwise the verdict is
    /// [`TestVerdict::Keep`]. A plugin that errors does not change the verdict:
    /// its error is returned with the verdict for the caller to log.
    pub async fn on_test_end(
        &self,
        test: &TestInfo,
        outcome: &TestOutcome,
        page: Option<&dyn PageHandle>,
    ) -> (TestVerdict, Vec<PluginError>) {
        let mut messages = Vec::new();
        let mut failures = Vec::new();
        for entry in self.holding(&Capability::TestHooks) {
            match self
                .run_hook(
                    entry,
                    "on_test_end",
                    entry.plugin.on_test_end(test, outcome, page),
                )
                .await
            {
                Ok(TestVerdict::Keep) => {}
                Ok(TestVerdict::Fail(message)) => messages.push(message),
                Err(error) => failures.push(error),
            }
        }
        let verdict = if messages.is_empty() {
            TestVerdict::Keep
        } else {
            TestVerdict::Fail(messages.join("; "))
        };
        (verdict, failures)
    }
}
