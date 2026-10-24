//! The crawl itself: a breadth-first walk over the links of a site, one tab,
//! one navigation at a time.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use seleniumbase_rs_plugin::{BrowserHandle, PageHandle, PluginError, Result, TaskContext};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::CrawlerConfig;
use crate::report::{Broken, JsError, Report};
use crate::robots::{AGENT, Robots};
use crate::scope::Matcher;
use crate::state::{self, Loaded, StateFile};
use crate::url::normalise;
use crate::{Crawler, Finished, NAME, bad};

/// The most links between pages a crawl keeps; past it `edges` stops growing.
pub const MAX_EDGES: usize = 200_000;

/// The most addresses a crawl queues, loaded or waiting; past it `truncated`
/// is set. It is separate from `max_pages` so a crawl stopped by the page limit
/// keeps its queue and can be resumed with a higher limit.
pub const MAX_QUEUE: usize = 200_000;

/// The most start addresses a run accepts.
const MAX_STARTS: usize = 1000;

/// The page script: reads the title, the status and the links of the page.
const PAGE_JS: &str = include_str!("page.js");

/// The robots.txt script: reads the text of the document the tab is on.
const ROBOTS_JS: &str = include_str!("robots.js");

/// The state file is written at least every this many pages.
const SAVE_EVERY: usize = 25;

/// The input of the task: `{"start": [...], "resume": true}`.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct TaskInput {
    /// Start addresses; without them the `start` option is used.
    pub(crate) start: Vec<String>,
    /// Whether to go on from the state file, when there is one that fits.
    pub(crate) resume: bool,
}

impl Default for TaskInput {
    fn default() -> Self {
        Self {
            start: Vec::new(),
            resume: true,
        }
    }
}

impl TaskInput {
    pub(crate) fn parse(input: &Value) -> Result<Self> {
        if input.is_null() {
            return Ok(Self::default());
        }
        serde_json::from_value(input.clone())
            .map_err(|error| bad(format!("bad task input: {error}")))
    }
}

/// One address waiting to be loaded.
#[derive(Clone, Debug)]
pub(crate) struct Item {
    url: String,
    depth: u32,
    from: Option<String>,
}

/// The state of a crawl.
#[derive(Debug, Default)]
pub(crate) struct Crawl {
    frontier: VecDeque<Item>,
    /// Everything ever queued, loaded or blocked: the dedup set.
    queued: HashSet<String>,
    /// What was loaded, in order, with the addresses pages ended up on.
    visited: Vec<String>,
    blocked: Vec<String>,
    /// Addresses a page ended up on after a redirect: not loaded again.
    landed: HashSet<String>,

    edges: Vec<(String, String)>,
    broken: Vec<Broken>,
    pages: usize,
    truncated: bool,
}

impl Crawl {
    /// A crawl that starts at `starts`.
    pub(crate) fn fresh(starts: &[String]) -> Self {
        let mut crawl = Self::default();
        for url in starts {
            if crawl.queued.insert(url.clone()) {
                crawl.frontier.push_back(Item {
                    url: url.clone(),
                    depth: 0,
                    from: None,
                });
            }
        }
        crawl
    }

    /// A crawl that goes on from `state`.
    pub(crate) fn resume(state: StateFile) -> Self {
        let mut crawl = Self {
            pages: state.pages,
            edges: state.edges,
            broken: state.broken,
            blocked: state.blocked,
            ..Self::default()
        };
        crawl.queued.extend(state.visited.iter().cloned());
        crawl.queued.extend(crawl.blocked.iter().cloned());
        crawl.visited = state.visited;
        for (url, depth) in state.frontier {
            if crawl.queued.insert(url.clone()) {
                crawl.frontier.push_back(Item {
                    url,
                    depth,
                    from: None,
                });
            }
        }
        crawl
    }

    /// The crawl as a state file for options that hash to `hash`.
    pub(crate) fn to_state(&self, hash: &str) -> StateFile {
        StateFile {
            version: state::VERSION,
            config_hash: hash.to_owned(),
            visited: self.visited.clone(),
            frontier: self
                .frontier
                .iter()
                .map(|item| (item.url.clone(), item.depth))
                .collect(),
            edges: self.edges.clone(),
            broken: self.broken.clone(),
            pages: self.pages,
            blocked: self.blocked.clone(),
        }
    }

    /// Queues the links of the page `page` (at `depth`) that the crawl may
    /// follow, and returns how many were new.
    pub(crate) fn follow(
        &mut self,
        matcher: &Matcher,
        config: &CrawlerConfig,
        page: &str,
        depth: u32,
        links: &[String],
    ) -> usize {
        let mut queued = 0;
        let mut seen_here = HashSet::new();
        for raw in links {
            let Some(url) = normalise(raw) else { continue };
            if url == page || !seen_here.insert(url.clone()) {
                continue;
            }
            if !matcher.host_allows(&url) || !matcher.path_allows(&url) {
                continue;
            }
            if self.edges.len() < MAX_EDGES {
                self.edges.push((page.to_owned(), url.clone()));
            }
            if depth >= config.max_depth || self.queued.contains(&url) {
                continue;
            }
            if self.queued.len() >= MAX_QUEUE {
                self.truncated = true;
                continue;
            }
            self.queued.insert(url.clone());
            self.frontier.push_back(Item {
                url,
                depth: depth + 1,
                from: Some(page.to_owned()),
            });
            queued += 1;
        }
        queued
    }

    /// Remembers that a page ended up on `url`, so a link to it is not loaded
    /// again.
    fn landed_on(&mut self, url: &str) {
        self.queued.insert(url.to_owned());
        self.landed.insert(url.to_owned());

        self.visited.push(url.to_owned());
    }

    /// The report of the crawl so far.
    pub(crate) fn report(
        &self,
        config: &CrawlerConfig,
        js_errors: Vec<JsError>,
        js_errors_total: usize,
    ) -> Report {
        let broken_urls: HashSet<&str> = self.broken.iter().map(|b| b.url.as_str()).collect();
        let reached: HashSet<&str> = self
            .visited
            .iter()
            .map(String::as_str)
            .filter(|url| !broken_urls.contains(url))
            .collect();
        let mut unreached: Vec<String> = Vec::new();
        for url in &config.expect.must_reach {
            if let Some(normal) = normalise(url)
                && !reached.contains(normal.as_str())
                && !unreached.contains(&normal)
            {
                unreached.push(normal);
            }
        }
        Report {
            pages: self.pages,
            edges: self.edges.clone(),
            broken: self.broken.clone(),
            js_errors,
            js_errors_total,
            unreached,
            robots_blocked: self.blocked.len(),
            truncated: self.truncated,
            no_console_errors: config.expect.no_console_errors,
        }
    }
}

/// What the page script found.
struct Landed {
    url: String,
    title: String,
    status: Option<u16>,
    links: Vec<String>,
    nofollow: bool,
}

/// How one visit went.
enum Visit {
    Page(Box<Landed>),
    /// The page was not read. `broken` says whether that counts as a broken
    /// link (the navigation failed) or not (a plugin cancelled it, or the
    /// page could not be read).
    Failed {
        error: String,
        broken: bool,
    },
}

fn read_landed(reply: &Value) -> Option<Landed> {
    let object = reply.as_object()?;
    let url = object.get("url")?.as_str()?.to_owned();
    let title: String = object
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .chars()
        .take(500)
        .collect();
    let status = object
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|s| u16::try_from(s).ok())
        .filter(|s| (100..=599).contains(s));
    let links = object
        .get("links")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|link| link.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Some(Landed {
        url,
        title,
        status,
        links,
        nofollow: object.get("nofollow").and_then(Value::as_bool) == Some(true),
    })
}

fn shown(value: &Value) -> String {
    value.to_string().chars().take(200).collect()
}

impl Crawler {
    /// The start addresses of this run, normalised and without duplicates.
    fn starts(&self, input: &TaskInput) -> Result<Vec<String>> {
        let given = if input.start.is_empty() {
            &self.config.start
        } else {
            &input.start
        };
        if given.is_empty() {
            return Err(bad(
                "give `start` addresses in the options or in the task input",
            ));
        }
        if given.len() > MAX_STARTS {
            return Err(bad(format!(
                "too many start addresses (at most {MAX_STARTS})"
            )));
        }
        let mut starts: Vec<String> = Vec::new();
        for url in given {
            let normal = normalise(url)
                .ok_or_else(|| bad(format!("`{url}` is not an http or https address")))?;
            if !starts.contains(&normal) {
                starts.push(normal);
            }
        }
        Ok(starts)
    }

    /// The task: crawls from the start addresses and returns the report.
    pub(crate) async fn crawl(&self, cx: &TaskContext<'_>) -> Result<Value> {
        let input = TaskInput::parse(cx.input)?;
        let starts = self.starts(&input)?;
        let matcher = Arc::new(Matcher::new(&self.config, &starts));
        for start in &starts {
            if !matcher.host_allows(start) {
                return Err(bad(format!(
                    "the start address `{start}` is outside the crawl scope"
                )));
            }
        }
        let hash = state::config_hash(&json!({
            "start": starts,
            "scope": self.config.scope,
            "include": self.config.include,
            "exclude": self.config.exclude,
            "max_depth": self.config.max_depth,
            "respect_robots": self.config.respect_robots,
        }));
        let _run = self.begin(&matcher)?;

        let mut ignored = None;
        let mut resumed = None;
        if let Some(path) = &self.config.state_file
            && input.resume
        {
            match state::load(path, &hash)? {
                Loaded::Resume(state) => resumed = Some(Crawl::resume(state)),
                Loaded::Other(why) => ignored = Some(why),
                Loaded::Missing => {}
            }
        }
        let did_resume = resumed.is_some();
        let mut crawl = resumed.unwrap_or_else(|| Crawl::fresh(&starts));
        // A state file that cannot be written is found out now, not after an hour.
        self.save(&crawl, &hash)?;

        let browser = cx.plugins.guarded_browser(NAME, cx.browser)?;
        let page = browser.new_page(None).await?;
        let walked = self.walk(&*page, cx, &matcher, &mut crawl, &hash).await;
        // The tab is ours: close it whatever happened.
        let _ = page.close().await;
        let saved = self.save(&crawl, &hash);
        walked?;
        saved?;

        let (js_errors, js_total) = {
            let live = self.live();
            (live.js_errors.clone(), live.js_total)
        };
        let report = crawl.report(&self.config, js_errors, js_total);
        let mut summary = report.to_json();
        summary["resumed"] = json!(did_resume);
        if let Some(why) = ignored {
            summary["state_ignored"] = json!(format!("the state file was ignored: {why}"));
        }
        *self.finished() = Some(Finished {
            report,
            judged: false,
        });
        Ok(summary)
    }

    fn save(&self, crawl: &Crawl, hash: &str) -> Result<()> {
        match &self.config.state_file {
            Some(path) => state::save(path, &crawl.to_state(hash)),
            None => Ok(()),
        }
    }

    /// Waits `delay` unless this is the first navigation.
    async fn pause(&self, cx: &TaskContext<'_>, navigations: &mut usize, delay: Duration) {
        if *navigations > 0 && !delay.is_zero() {
            cx.clock.sleep(delay).await;
        }
        *navigations += 1;
    }

    /// Takes the frontier address by address until it is empty or the page
    /// limit is reached.
    async fn walk(
        &self,
        page: &dyn PageHandle,
        cx: &TaskContext<'_>,
        matcher: &Matcher,
        crawl: &mut Crawl,
        hash: &str,
    ) -> Result<()> {
        let config = &self.config;
        let base_delay = Duration::from_millis(config.delay_ms);
        let mut robots: std::collections::HashMap<String, Robots> =
            std::collections::HashMap::new();
        let mut navigations = 0_usize;
        let mut unsaved = 0_usize;
        while let Some(item) = crawl.frontier.pop_front() {
            if crawl.landed.contains(&item.url) {
                continue;
            }

            if crawl.pages >= config.max_pages {
                crawl.frontier.push_front(item);
                crawl.truncated = true;
                break;
            }
            let Some(parsed) = crate::url::WebUrl::parse(&item.url) else {
                continue;
            };
            let mut delay = base_delay;
            if config.respect_robots {
                let origin = parsed.origin();
                if !robots.contains_key(&origin) {
                    self.pause(cx, &mut navigations, delay).await;
                    let rules = self.fetch_robots(page, &origin).await?;
                    robots.insert(origin.clone(), rules);
                }
                let rules = &robots[&origin];
                if let Some(extra) = rules.crawl_delay() {
                    delay = delay.max(extra);
                }
                if !rules.allows(&parsed.path_and_query()) {
                    crawl.blocked.push(item.url.clone());
                    cx.sink.record(&json!({
                        "url": item.url,
                        "depth": item.depth,
                        "from": item.from,
                        "skipped": "robots.txt",
                    }))?;
                    continue;
                }
            }
            self.pause(cx, &mut navigations, delay).await;

            let index = crawl.pages;
            crawl.pages += 1;
            crawl.visited.push(item.url.clone());
            self.set_current(Some(&item.url));
            let line = match self.visit(page, &item).await? {
                Visit::Failed { error, broken } => {
                    if broken {
                        crawl.broken.push(Broken {
                            url: item.url.clone(),
                            from: item.from.clone(),
                            status: 404,
                        });
                    }
                    json!({
                        "index": index,
                        "url": item.url,
                        "depth": item.depth,
                        "from": item.from,
                        "error": error,
                    })
                }
                Visit::Page(landed) => self.landed(crawl, matcher, &item, index, *landed),
            };
            cx.sink.record(&line)?;

            if config.state_file.is_some() {
                unsaved += 1;
                if unsaved >= SAVE_EVERY.max(crawl.pages / 20) {
                    self.save(crawl, hash)?;
                    unsaved = 0;
                }
            }
        }
        Ok(())
    }

    /// Opens `item` and reads the page. Only a missing capability is an `Err`.
    async fn visit(&self, page: &dyn PageHandle, item: &Item) -> Result<Visit> {
        match page.navigate(&item.url).await {
            Ok(()) => {}
            Err(error @ PluginError::Capability { .. }) => return Err(error),
            Err(error @ PluginError::NavigationCancelled { .. }) => {
                return Ok(Visit::Failed {
                    error: error.to_string(),
                    broken: false,
                });
            }
            // A page that cannot be opened counts as a 404, as in Python.
            Err(error) => {
                return Ok(Visit::Failed {
                    error: error.to_string(),
                    broken: true,
                });
            }
        }
        let script = format!(
            "({PAGE_JS})({})",
            json!({ "max_links": self.config.max_links })
        );
        let reply = match page.evaluate(&script).await {
            Ok(reply) => reply,
            Err(error @ PluginError::Capability { .. }) => return Err(error),
            Err(error) => {
                return Ok(Visit::Failed {
                    error: error.to_string(),
                    broken: false,
                });
            }
        };
        Ok(match read_landed(&reply) {
            Some(landed) if landed.url.starts_with("chrome-error:") => Visit::Failed {
                error: "the page did not load".to_owned(),
                broken: true,
            },
            Some(landed) => Visit::Page(Box::new(landed)),
            None => Visit::Failed {
                error: format!("unexpected reply from the page: {}", shown(&reply)),
                broken: false,
            },
        })
    }

    /// Takes in a page that was read: records its problems, queues its links,
    /// and returns the line for the sink.
    fn landed(
        &self,
        crawl: &mut Crawl,
        matcher: &Matcher,
        item: &Item,
        index: usize,
        landed: Landed,
    ) -> Value {
        let final_url = normalise(&landed.url).unwrap_or_else(|| item.url.clone());
        let status = landed.status.or_else(|| self.recorded_status(&final_url));
        if final_url != item.url {
            crawl.landed_on(&final_url);
        }
        let mut line = json!({
            "index": index,
            "url": item.url,
            "depth": item.depth,
            "from": item.from,
            "status": status,
            "title": landed.title,
            "links": landed.links.len(),
        });
        let mut queued = 0;
        if !matcher.host_allows(&final_url) {
            line["error"] = json!(format!(
                "redirected to {final_url}, which is outside the crawl scope"
            ));
        } else if landed.nofollow && self.config.respect_robots {
            line["nofollow"] = json!(true);
        } else {
            queued = crawl.follow(matcher, &self.config, &final_url, item.depth, &landed.links);
        }
        line["queued"] = json!(queued);
        if final_url != item.url {
            line["final_url"] = json!(final_url);
        }
        if let Some(status) = status
            && status > self.config.expect.max_status
        {
            crawl.broken.push(Broken {
                url: item.url.clone(),
                from: item.from.clone(),
                status,
            });
        }
        line
    }

    /// Reads robots.txt of `origin` by opening it in the tab, as any visitor
    /// would, so the proxy and privacy plugins apply to it too. A 4xx answer
    /// means no rules; a 5xx answer or no answer means the site is closed.
    async fn fetch_robots(&self, page: &dyn PageHandle, origin: &str) -> Result<Robots> {
        let url = format!("{origin}/robots.txt");
        self.set_current(Some(&url));
        match page.navigate(&url).await {
            Ok(()) => {}
            Err(error @ PluginError::Capability { .. }) => return Err(error),
            Err(_) => return Ok(Robots::disallow_all()),
        }
        let reply = match page.evaluate(&format!("({ROBOTS_JS})()")).await {
            Ok(reply) => reply,
            Err(error @ PluginError::Capability { .. }) => return Err(error),
            Err(_) => return Ok(Robots::disallow_all()),
        };
        let status = reply.get("status").and_then(Value::as_u64);
        let text = reply
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default();
        Ok(match status {
            Some(500..=599) => Robots::disallow_all(),
            Some(400..=499) => Robots::allow_all(),
            _ => Robots::parse(text, AGENT),
        })
    }
}
