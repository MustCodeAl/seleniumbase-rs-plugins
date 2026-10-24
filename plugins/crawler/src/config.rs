//! The options of the crawler, and the checks that make a bad one an error at
//! start-up instead of a surprise halfway through a crawl.

use std::path::PathBuf;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::{Deserialize, Serialize};

use crate::url::WebUrl;

/// The largest `max_pages` accepted.
pub const MAX_PAGES_LIMIT: usize = 50_000;

/// The largest `max_depth` accepted.
pub const MAX_DEPTH_LIMIT: u32 = 100;

/// The longest `delay_ms` accepted: one minute.
pub const MAX_DELAY_MS: u64 = 60_000;

/// The most links read from one page.
pub const MAX_LINKS_LIMIT: usize = 100_000;

/// The most start addresses, `scope.hosts` entries, globs and `must_reach`
/// entries each option may hold.
pub const MAX_LIST: usize = 1_000;

/// Which addresses a crawl may visit, besides the `include` and `exclude`
/// patterns.
///
/// In a config file this is `"same-origin"`, `"same-site"` or
/// `{ hosts = ["example.com"] }`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// The scheme, host and port of one of the start addresses.
    #[default]
    SameOrigin,
    /// The host of a start address and its subdomains, any scheme and port.
    /// The registrable part of a host is a rule of thumb (`example.co.uk` is
    /// one site), not the public-suffix list.
    SameSite,
    /// These hosts and their subdomains.
    Hosts(Vec<String>),
}

/// What a crawl must find for the test to pass.
///
/// ```
/// use seleniumbase_rs_plugin_crawler::Expect;
///
/// let expect = Expect::default();
/// assert_eq!(expect.max_status, 399);
/// assert!(expect.must_reach.is_empty());
/// assert!(!expect.no_console_errors);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Expect {
    /// The highest status a page may have; a page above it is a broken link.
    /// The default, 399, makes every 4xx and 5xx page broken (Python
    /// SeleniumBase only counts 404). A page that fails to load counts as 404,
    /// as in Python.
    pub max_status: u16,
    /// Addresses the crawl must reach. One that it did not load, or that loaded
    /// as a broken page, is `unreached`.
    pub must_reach: Vec<String>,
    /// Whether an error in the browser console (an uncaught exception, a
    /// failed resource) fails the test.
    pub no_console_errors: bool,
}

impl Default for Expect {
    fn default() -> Self {
        Self {
            max_status: 399,
            must_reach: Vec::new(),
            no_console_errors: false,
        }
    }
}

/// What the crawler does, as a program or a config file states it.
///
/// ```
/// use seleniumbase_rs_plugin_crawler::{CrawlerConfig, Scope};
///
/// let config: CrawlerConfig = serde_json::from_value(serde_json::json!({
///     "start": ["https://example.com/"],
///     "scope": { "hosts": ["example.com", "docs.example.org"] },
///     "exclude": ["/logout*", "*?print=1"],
///     "max_depth": 2,
///     "expect": { "no_console_errors": true },
/// }))?;
/// assert_eq!(config.max_pages, 500);
/// assert_eq!(config.delay_ms, 1000);
/// assert!(config.respect_robots);
/// assert!(matches!(config.scope, Scope::Hosts(_)));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CrawlerConfig {
    /// Where the crawl starts. The task input may give `start` instead.
    pub start: Vec<String>,
    /// Which hosts the crawl may visit.
    pub scope: Scope,
    /// Patterns a followed link must match, if there are any. `*` matches any
    /// run of characters, `?` one character. A pattern that starts with `/`
    /// is matched against the path and query, any other against the whole
    /// address. They apply to links the crawl finds, not to the start
    /// addresses.
    pub include: Vec<String>,
    /// Patterns of links not to follow, matched like `include`.
    pub exclude: Vec<String>,
    /// How many links deep the crawl goes; the start addresses are depth 0
    /// (at most 100).
    pub max_depth: u32,
    /// The most pages loaded (1 to 50,000).
    pub max_pages: usize,
    /// The pause between two navigations, in milliseconds (at most 60,000).
    /// A `Crawl-delay` in robots.txt can make it longer.
    pub delay_ms: u64,
    /// Whether robots.txt is read and obeyed. Turn it off only for a site you
    /// own or may test.
    pub respect_robots: bool,
    /// The most links read from one page (1 to 100,000).
    pub max_links: usize,
    /// A JSON file that keeps the crawl so it can be resumed.
    pub state_file: Option<PathBuf>,
    /// What the crawl must find.
    pub expect: Expect,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            start: Vec::new(),
            scope: Scope::SameOrigin,
            include: Vec::new(),
            exclude: Vec::new(),
            max_depth: 3,
            max_pages: 500,
            delay_ms: 1000,
            respect_robots: true,
            max_links: 1000,
            state_file: None,
            expect: Expect::default(),
        }
    }
}

fn bad(why: impl std::fmt::Display) -> PluginError {
    PluginError::Config(format!("crawler: {why}"))
}

impl CrawlerConfig {
    /// Checks every option.
    pub(crate) fn check(&self) -> Result<()> {
        check_list("start", self.start.len())?;
        for url in &self.start {
            check_address("start", url)?;
        }
        if let Scope::Hosts(hosts) = &self.scope {
            check_list("scope.hosts", hosts.len())?;
            if hosts.is_empty() {
                return Err(bad("`scope.hosts` needs at least one host"));
            }
            for host in hosts {
                check_host(host)?;
            }
        }
        for (option, globs) in [("include", &self.include), ("exclude", &self.exclude)] {
            check_list(option, globs.len())?;
            for glob in globs {
                check_glob(option, glob)?;
            }
        }
        if self.max_depth > MAX_DEPTH_LIMIT {
            return Err(bad(format!("`max_depth` is at most {MAX_DEPTH_LIMIT}")));
        }
        if !(1..=MAX_PAGES_LIMIT).contains(&self.max_pages) {
            return Err(bad(format!("`max_pages` must be 1 to {MAX_PAGES_LIMIT}")));
        }
        if self.delay_ms > MAX_DELAY_MS {
            return Err(bad(format!("`delay_ms` is at most {MAX_DELAY_MS}")));
        }
        if !(1..=MAX_LINKS_LIMIT).contains(&self.max_links) {
            return Err(bad(format!("`max_links` must be 1 to {MAX_LINKS_LIMIT}")));
        }
        if let Some(path) = &self.state_file
            && path.file_name().is_none()
        {
            return Err(bad(format!(
                "`state_file` `{}` is not a file name",
                path.display()
            )));
        }
        if !(100..=599).contains(&self.expect.max_status) {
            return Err(bad("`expect.max_status` must be 100 to 599"));
        }
        check_list("expect.must_reach", self.expect.must_reach.len())?;
        for url in &self.expect.must_reach {
            check_address("expect.must_reach", url)?;
        }
        Ok(())
    }
}

fn check_list(option: &str, len: usize) -> Result<()> {
    if len > MAX_LIST {
        return Err(bad(format!("`{option}` holds at most {MAX_LIST} entries")));
    }
    Ok(())
}

/// An address must be a plain `http` or `https` address.
pub(crate) fn check_address(option: &str, url: &str) -> Result<()> {
    if WebUrl::parse(url).is_none() {
        return Err(bad(format!(
            "`{url}` in `{option}` is not an http or https address"
        )));
    }
    Ok(())
}

/// A host is a name or an address without scheme, port or path.
fn check_host(host: &str) -> Result<()> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !ok {
        return Err(bad(format!(
            "bad host `{host}` in `scope.hosts` (a name such as `example.com`, with no scheme, port or path)"
        )));
    }
    Ok(())
}

/// A glob is bad when it is empty or holds whitespace or a control character:
/// no address does, so it could never match.
fn check_glob(option: &str, glob: &str) -> Result<()> {
    if glob.is_empty() || glob.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad(format!("bad glob `{glob}` in `{option}`")));
    }
    Ok(())
}
