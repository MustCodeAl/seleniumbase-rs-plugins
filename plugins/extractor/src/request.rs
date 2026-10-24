//! What a caller asks for: one [`Request`] per page, and the input of the task.

use std::collections::BTreeMap;
use std::time::Duration;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::schema::{FieldSpec, Schema, Source};

/// The most pages one task run accepts.
pub const MAX_JOBS: usize = 10_000;

/// The longest pause between two pages, in milliseconds.
pub const MAX_DELAY_MS: u64 = 60_000;

fn bad(why: impl std::fmt::Display) -> PluginError {
    PluginError::Config(format!("extractor: {why}"))
}

/// One page to read and what to take from it.
///
/// With no `select`, no `schema` and none of `text`, `links`, `tables` and
/// `meta`, the extractor discovers the structure of the page by itself.
///
/// ```
/// use seleniumbase_rs_plugin_extractor::Request;
///
/// let request: Request = serde_json::from_value(serde_json::json!({
///     "url": "https://example.com/shop",
///     "item": ".card",
///     "select": {
///         "title": "h3",
///         "price": { "selector": ".price", "type": "money", "required": true },
///         "link": { "selector": "a", "attr": "href", "type": "url" },
///     },
///     "links": true,
/// }))?;
/// assert_eq!(request.select.len(), 3);
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Request {
    /// The address to open first; without it the page is read where it is.
    pub url: Option<String>,
    /// Fields by name: a selector, or `{selector, attr, type, required, all}`.
    pub select: BTreeMap<String, FieldSpec>,
    /// A selector for the repeated element the `select` selectors are
    /// relative to; without it the record is the whole document.
    pub item: Option<String>,
    /// A schema found earlier (by discovery), to apply as it is.
    pub schema: Option<Schema>,
    /// Whether to discover the structure. The default is yes when nothing
    /// else says what to read.
    pub discover: Option<bool>,
    /// With `discover`, which kind of structure to prefer.
    pub source: Option<Source>,
    /// Also return the visible text of the page.
    pub text: bool,
    /// Also return its `http(s)` links.
    pub links: bool,
    /// Also return its tables, as headers and rows.
    pub tables: bool,
    /// Also return its title, description, Open Graph and canonical data.
    pub meta: bool,
}

/// What to do about the records of a page.
pub(crate) enum Plan {
    /// Read with this schema.
    Given(Schema),
    /// Find a schema first, preferring this kind.
    Discover(Option<Source>),
    /// No records, only the page parts.
    Nothing,
}

impl Request {
    pub(crate) fn plan(&self, max_fields: usize) -> Result<Plan> {
        if let Some(schema) = &self.schema {
            schema.validate(max_fields)?;
            return Ok(Plan::Given(schema.clone()));
        }
        if !self.select.is_empty() {
            return Ok(Plan::Given(Schema::selectors(
                self.item.clone(),
                &self.select,
                max_fields,
            )?));
        }
        if self.item.is_some() {
            return Err(bad("`item` needs a `select` map"));
        }
        let wants_page = self.text || self.links || self.tables || self.meta;
        Ok(match self.discover {
            Some(true) => Plan::Discover(self.source),
            Some(false) => Plan::Nothing,
            None if wants_page => Plan::Nothing,
            None => Plan::Discover(self.source),
        })
    }

    /// The page parts to read, for the page script.
    pub(crate) fn parts(&self) -> Value {
        json!({
            "text": self.text,
            "links": self.links,
            "tables": self.tables,
            "meta": self.meta,
        })
    }

    /// Checks the address, if there is one.
    pub(crate) fn check_url(&self) -> Result<()> {
        let Some(url) = &self.url else {
            return Ok(());
        };
        let lower = url.to_ascii_lowercase();
        let web = lower.starts_with("http://") || lower.starts_with("https://");
        let authority = url
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split(['/', '?', '#']).next())
            .unwrap_or_default();
        if !web || authority.is_empty() || url.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(bad(format!("`{url}` is not an http or https address")));
        }
        if authority.contains('@') {
            return Err(bad(format!(
                "`{url}` carries credentials, which are not accepted"
            )));
        }
        Ok(())
    }
}

/// The input of the task: `urls` read the same way (`extract`), or `jobs`,
/// each a [`Request`] of its own.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TaskInput {
    urls: Vec<String>,
    jobs: Vec<Request>,
    extract: Request,
    delay_ms: u64,
}

impl TaskInput {
    pub(crate) fn parse(input: &Value) -> Result<Self> {
        let parsed: Self = serde_json::from_value(input.clone())
            .map_err(|error| bad(format!("bad task input: {error}")))?;
        let given = !parsed.urls.is_empty() || !parsed.jobs.is_empty();
        if !given {
            return Err(bad(
                "the task input needs `urls` (with an optional `extract`) or `jobs`",
            ));
        }
        if !parsed.urls.is_empty() && !parsed.jobs.is_empty() {
            return Err(bad("give `urls` or `jobs`, not both"));
        }
        if parsed.urls.len().max(parsed.jobs.len()) > MAX_JOBS {
            return Err(bad(format!("too many pages (at most {MAX_JOBS})")));
        }
        if parsed.delay_ms > MAX_DELAY_MS {
            return Err(bad(format!("`delay_ms` is at most {MAX_DELAY_MS}")));
        }
        Ok(parsed)
    }

    pub(crate) fn delay(&self) -> Duration {
        Duration::from_millis(self.delay_ms)
    }

    /// One request per page.
    pub(crate) fn requests(&self) -> Vec<Request> {
        if self.jobs.is_empty() {
            self.urls
                .iter()
                .map(|url| Request {
                    url: Some(url.clone()),
                    ..self.extract.clone()
                })
                .collect()
        } else {
            self.jobs.clone()
        }
    }
}
