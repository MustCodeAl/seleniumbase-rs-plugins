//! Reads structured data off the pages a browser opens: text, links, tables,
//! the fields of a repeated card or a JSON-LD block, or whatever a map of CSS
//! selectors names. The result is JSON, one record per card or row, typed
//! (`text`, `number`, `money`, `date`, `url`) and checked: a field that is
//! missing or does not fit its type becomes an entry in `problems`, not an
//! error.
//!
//! It reads the page the user's browser loaded. It makes no request of its
//! own, and the page script is pure: it walks at most `max_nodes` nodes, writes
//! nothing, and treats page content as data that is never run.
//!
//! ```
//! use seleniumbase_rs_plugin::PluginSet;
//! use seleniumbase_rs_plugin_extractor::{Extractor, ExtractorConfig};
//!
//! let extractor = Extractor::new(ExtractorConfig::default())?;
//! let plugins = PluginSet::strict().with(extractor)?;
//! assert_eq!(plugins.names(), ["extractor"]);
//! assert_eq!(plugins.task_names(), ["extractor"]);
//! # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
//! ```
//!
//! # Finding structure
//!
//! [`Extractor::discover`] looks, in this order, for
//!
//! 1. JSON-LD blocks, one candidate per `@type`; the fields are the dotted
//!    paths of its scalar properties (`offers.price`), and a `price` is paired
//!    with the `priceCurrency` next to it, so it types as `money`;
//! 2. tables with a header row, one field per column;
//! 3. up to three groups of at least `min_repeats` sibling elements of the
//!    same shape (a card list), with the fields that are present in at least
//!    half of the sampled cards. Field names come from `itemprop`,
//!    `data-field`, `aria-label`, the first class name or the tag.
//!
//! Each candidate becomes a [`Schema`]: a source, an item selector, and fields
//! with a selector (or path), a type guessed from up to five samples and
//! whether every item had it. [`Schema::json_schema`] describes the records.
//! A schema can be written by hand, or kept from an earlier run and given back
//! as `schema`.
//!
//! # Not covered
//!
//! `auto_save` (writing every page's records as an artifact) waits for an
//! artifact API in the plugin host: the plugin declares no `artifacts.write`.
//! Microdata, `<label>` and header-less layouts are not anchors yet; those
//! pages fall back to the structural signature, or to a `select` map.

mod request;
mod schema;
mod values;

use seleniumbase_rs_plugin::{
    BrowserHandle, Capability, Category, Configurable, JobRunner, Metadata, PageHandle, Plugin,
    PluginError, Requirements, Result, Task, TaskContext, async_trait, config::options,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub use request::{MAX_DELAY_MS, MAX_JOBS, Request};
pub use schema::{
    DetailedField, Extraction, Field, FieldSpec, FieldType, MAX_NAME_LEN, MAX_PROBLEMS,
    MAX_SELECTOR_LEN, Problem, Schema, Source, extract_values,
};

use request::{Plan, TaskInput};

/// The name the plugin is enabled by.
const NAME: &str = "extractor";

/// The page script: reads the document in one of two modes.
const DOM_JS: &str = include_str!("dom.js");

/// What the extractor reads and how much of it.
///
/// ```
/// use seleniumbase_rs_plugin_extractor::ExtractorConfig;
///
/// let config = ExtractorConfig { min_repeats: 5, ..ExtractorConfig::default() };
/// assert_eq!(config.max_nodes, 20_000);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractorConfig {
    /// How many sibling elements of one shape make a list of cards (2 to 1000).
    pub min_repeats: u32,
    /// The most nodes the page script walks (100 to 1,000,000); past it the
    /// result says `truncated`.
    pub max_nodes: u32,
    /// The most fields in a schema (1 to 256).
    pub max_fields: usize,
    /// The most records per page (1 to 100,000).
    pub max_records: usize,
    /// The most characters of page text returned (at most 10,000,000).
    pub max_text_chars: usize,
    /// The most links returned (at most 100,000).
    pub max_links: usize,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            min_repeats: 3,
            max_nodes: 20_000,
            max_fields: 64,
            max_records: 1000,
            max_text_chars: 100_000,
            max_links: 1000,
        }
    }
}

impl ExtractorConfig {
    fn check(&self) -> Result<()> {
        let range = |option: &str, ok: bool, range: &str| {
            if ok {
                Ok(())
            } else {
                Err(PluginError::Config(format!(
                    "extractor: `{option}` must be {range}"
                )))
            }
        };
        range(
            "min_repeats",
            (2..=1000).contains(&self.min_repeats),
            "2 to 1000",
        )?;
        range(
            "max_nodes",
            (100..=1_000_000).contains(&self.max_nodes),
            "100 to 1000000",
        )?;
        range(
            "max_fields",
            (1..=256).contains(&self.max_fields),
            "1 to 256",
        )?;
        range(
            "max_records",
            (1..=100_000).contains(&self.max_records),
            "1 to 100000",
        )?;
        range(
            "max_text_chars",
            self.max_text_chars <= 10_000_000,
            "at most 10000000",
        )?;
        range("max_links", self.max_links <= 100_000, "at most 100000")
    }
}

/// The extractor plugin. See the [crate documentation](crate).
#[derive(Clone, Debug)]
pub struct Extractor {
    config: ExtractorConfig,
}

/// What the page script answered, as far as the extractor needs it.
struct Reply {
    records: Value,
    errors: Vec<String>,
    page: Map<String, Value>,
    truncated: bool,
}

fn unexpected(reply: &Value) -> PluginError {
    let shown: String = reply.to_string().chars().take(200).collect();
    PluginError::other(format!(
        "extractor: unexpected reply from the page: {shown}"
    ))
}

impl Extractor {
    /// Builds the plugin from `config`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] for a limit out of range.
    pub fn new(config: ExtractorConfig) -> Result<Self> {
        config.check()?;
        Ok(Self { config })
    }

    /// The options the plugin was built with.
    #[must_use]
    pub fn config(&self) -> &ExtractorConfig {
        &self.config
    }

    /// The JSON Schema of the records of `schema`: see [`Schema::json_schema`].
    #[must_use]
    pub fn json_schema(schema: &Schema) -> Value {
        schema.json_schema()
    }

    /// Types the raw records a page gave: see [`extract_values`].
    #[must_use]
    pub fn extract_values(schema: &Schema, raw: &Value) -> Extraction {
        extract_values(schema, raw)
    }

    /// The expression that runs the page script in `mode`. Everything the
    /// script is given travels as one JSON literal.
    fn script(&self, mode: &str, schema: Option<&Schema>, parts: &Value) -> String {
        let request = json!({
            "mode": mode,
            "schema": schema,
            "page": parts,
            "limits": {
                "max_nodes": self.config.max_nodes,
                "min_repeats": self.config.min_repeats,
                "max_fields": self.config.max_fields,
                "max_records": self.config.max_records,
                "max_text": self.config.max_text_chars,
                "max_links": self.config.max_links,
            },
        });
        format!("({DOM_JS})({request})")
    }

    /// Looks for structure in the page: the schemas found, the best first
    /// (JSON-LD, then tables, then repeated elements), and whether the page
    /// was bigger than `max_nodes`.
    async fn find(&self, page: &dyn PageHandle) -> Result<(Vec<Schema>, bool)> {
        let reply = page
            .evaluate(&self.script("discover", None, &Value::Null))
            .await?;
        let candidates = reply
            .get("candidates")
            .and_then(Value::as_array)
            .ok_or_else(|| unexpected(&reply))?;
        let schemas = candidates
            .iter()
            .filter_map(|candidate| Schema::from_candidate(candidate, self.config.max_fields))
            .collect();
        let truncated = reply.get("truncated").and_then(Value::as_bool) == Some(true);
        Ok((schemas, truncated))
    }

    /// Finds the structure of the page the plugin is in: the schemas found,
    /// the best first.
    ///
    /// # Errors
    ///
    /// If the page cannot be evaluated or answers something else.
    pub async fn discover(&self, page: &dyn PageHandle) -> Result<Vec<Schema>> {
        Ok(self.find(page).await?.0)
    }

    /// Reads the page with `schema` (when there is one) and the page parts.
    async fn read(
        &self,
        page: &dyn PageHandle,
        schema: Option<&Schema>,
        parts: &Value,
    ) -> Result<Reply> {
        let reply = page
            .evaluate(&self.script("extract", schema, parts))
            .await?;
        let object = reply.as_object().ok_or_else(|| unexpected(&reply))?;
        let list = |key: &str| object.get(key).cloned().unwrap_or(Value::Null);
        Ok(Reply {
            records: list("records"),
            errors: list("errors")
                .as_array()
                .map(|errors| {
                    errors
                        .iter()
                        .filter_map(|e| e.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            page: list("page").as_object().cloned().unwrap_or_default(),
            truncated: object.get("truncated").and_then(Value::as_bool) == Some(true),
        })
    }

    /// Reads the records of the page the plugin is in with `schema`.
    ///
    /// # Errors
    ///
    /// If the page cannot be evaluated or answers something else. Values that
    /// do not fit are [`Problem`]s of the result, not errors.
    pub async fn extract(&self, page: &dyn PageHandle, schema: &Schema) -> Result<Extraction> {
        schema.validate(self.config.max_fields)?;
        let reply = self.read(page, Some(schema), &Value::Null).await?;
        let mut extraction = extract_values(schema, &reply.records);
        for error in reply.errors {
            extraction.note(0, "", error);
        }
        Ok(extraction)
    }

    /// Does one [`Request`] in `page`.
    async fn run_request(&self, page: &dyn PageHandle, request: &Request) -> Result<Value> {
        request.check_url()?;
        let plan = request.plan(self.config.max_fields)?;
        if let Some(url) = &request.url {
            page.navigate(url).await?;
        }
        let mut notes = Vec::new();
        let schema = match plan {
            Plan::Given(schema) => Some(schema),
            Plan::Nothing => None,
            Plan::Discover(prefer) => {
                let (found, _) = self.find(page).await?;
                let chosen = prefer
                    .and_then(|source| found.iter().find(|s| s.source == source))
                    .or_else(|| found.first())
                    .cloned();
                if chosen.is_none() {
                    notes.push("no structure found on the page".to_owned());
                }
                chosen
            }
        };
        let reply = self.read(page, schema.as_ref(), &request.parts()).await?;
        let mut extraction = match &schema {
            Some(schema) => extract_values(schema, &reply.records),
            None => Extraction::default(),
        };
        for note in notes.into_iter().chain(reply.errors) {
            extraction.note(0, "", note);
        }

        let mut out = Map::new();
        for key in ["url", "title"] {
            if let Some(value) = reply.page.get(key) {
                out.insert(key.to_owned(), value.clone());
            }
        }
        for key in ["text", "links", "tables", "meta"] {
            if let Some(value) = reply.page.get(key) {
                out.insert(key.to_owned(), value.clone());
            }
        }
        if let Some(schema) = &schema {
            out.insert("schema".into(), json!(schema));
        }
        out.insert("records".into(), Value::Array(extraction.records));
        out.insert("problems".into(), json!(extraction.problems));
        if extraction.more_problems > 0 {
            out.insert("more_problems".into(), json!(extraction.more_problems));
        }
        if reply.truncated {
            out.insert("truncated".into(), Value::Bool(true));
        }
        Ok(Value::Object(out))
    }
}

#[async_trait]
impl Plugin for Extractor {
    fn name(&self) -> &str {
        NAME
    }

    fn requirements(&self) -> Requirements {
        Requirements::CHROMIUM_ONLY
    }

    fn metadata(&self) -> Metadata {
        Self::describe()
    }

    fn task(&self) -> Option<&dyn Task> {
        Some(self)
    }

    fn job_runner(&self) -> Option<&dyn JobRunner> {
        Some(self)
    }
}

#[async_trait]
impl JobRunner for Extractor {
    /// Runs a [`Request`] in `page`, which the caller opened: it opens
    /// `url` if there is one, reads the page and answers `{url, title,
    /// schema, records, problems}` and the parts asked for (`text`, `links`,
    /// `tables`, `meta`).
    async fn run_job(&self, page: &dyn PageHandle, job: &Value) -> Result<Value> {
        let request: Request = serde_json::from_value(job.clone())
            .map_err(|error| PluginError::Config(format!("extractor: bad job: {error}")))?;
        self.run_request(page, &request).await
    }
}

#[async_trait]
impl Task for Extractor {
    /// Reads `{"urls": [...], "extract": {...}}` or `{"jobs": [...]}` one page
    /// after the other in one tab; `delay_ms` (default 0) pauses between pages.
    ///
    /// Each page records one line to the sink: the answer of
    /// [`run_job`](JobRunner::run_job) with its `index`, or `{index, url,
    /// error}`. A page that fails does not stop the others; a missing
    /// capability does. The summary is `{total, ok, failed, records}`.
    async fn run(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let input = TaskInput::parse(cx.input)?;
        let requests = input.requests();
        for request in &requests {
            request.check_url()?;
        }
        let browser = cx.plugins.guarded_browser(NAME, cx.browser)?;
        let page = browser.new_page(None).await?;
        let (mut ok, mut failed, mut records) = (0_u64, 0_u64, 0_u64);
        let mut outcome = Ok(());
        for (index, request) in requests.iter().enumerate() {
            if index > 0 && !input.delay().is_zero() {
                cx.clock.sleep(input.delay()).await;
            }
            let line = match self.run_request(&*page, request).await {
                Ok(mut answer) => {
                    ok += 1;
                    records += answer["records"].as_array().map_or(0, |r| r.len() as u64);
                    answer["index"] = json!(index);
                    answer
                }
                Err(error @ PluginError::Capability { .. }) => {
                    outcome = Err(error);
                    break;
                }
                Err(error) => {
                    failed += 1;
                    json!({ "index": index, "url": request.url, "error": error.to_string() })
                }
            };
            if let Err(error) = cx.sink.record(&line) {
                outcome = Err(error);
                break;
            }
        }
        // The tab is ours: close it whatever happened.
        let _ = page.close().await;
        outcome?;
        Ok(json!({
            "total": requests.len(),
            "ok": ok,
            "failed": failed,
            "records": records,
        }))
    }
}

impl Configurable for Extractor {
    const NAME: &'static str = NAME;

    fn describe() -> Metadata {
        Metadata::new(Category::Core)
            .version(env!("CARGO_PKG_VERSION"))
            .summary("Finds structured data on a page (JSON-LD, tables, cards, selectors) and extracts it as JSON")
            .capabilities([
                Capability::PageEvaluate,
                Capability::PageNavigate,
                Capability::Task,
            ])
    }

    /// Options: see [`ExtractorConfig`].
    fn configure(value: &Value) -> Result<Self> {
        Self::new(options(NAME, value)?)
    }
}
