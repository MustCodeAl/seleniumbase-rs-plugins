//! What a crawl found, and how it is judged.
//!
//! The wording of [`Report::summary`] is the wording of Python SeleniumBase's
//! `assert_no_404_errors` (`Broken link detected:` / `Broken links detected:`,
//! the addresses sorted, one per line), so a test that fails in one language
//! reads the same in the other.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The most console errors a report keeps; `js_errors_total` counts them all.
pub const MAX_JS_ERRORS: usize = 200;

/// A page that did not load, or loaded with a status above `expect.max_status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Broken {
    /// The address that was visited.
    pub url: String,
    /// The page that linked to it; `None` for a start address.
    pub from: Option<String>,
    /// Its HTTP status. A page that failed to load is 404, as in Python.
    pub status: u16,
}

/// One error the browser console showed during the crawl.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JsError {
    /// The page the crawl was on, when it knew.
    pub page: Option<String>,
    /// The message.
    pub message: String,
}

/// The result of a crawl.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// How many pages were visited.
    pub pages: usize,
    /// The links between visited or queued pages as `(from, to)`, at most
    /// [`MAX_EDGES`](crate::MAX_EDGES).
    pub edges: Vec<(String, String)>,
    /// The broken pages.
    pub broken: Vec<Broken>,
    /// The console errors, at most [`MAX_JS_ERRORS`].
    pub js_errors: Vec<JsError>,
    /// How many console errors there were in all.
    pub js_errors_total: usize,
    /// The `expect.must_reach` addresses the crawl did not load.
    pub unreached: Vec<String>,
    /// How many pages `robots.txt` kept the crawl away from.
    pub robots_blocked: usize,
    /// Whether the page limit stopped the crawl with pages left.
    pub truncated: bool,
    /// Whether console errors fail the report (`expect.no_console_errors`).
    pub no_console_errors: bool,
}

impl Report {
    /// Whether the crawl found nothing to fail on: it loaded a page, no broken page, every
    /// `must_reach` address reached, and no console error when
    /// `no_console_errors` is set.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.pages > 0
            && self.broken.is_empty()
            && self.unreached.is_empty()
            && !(self.no_console_errors && self.js_errors_total > 0)
    }

    /// The message of a failed test, or a line saying nothing was wrong.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut sections = Vec::new();
        let broken: BTreeSet<&str> = self.broken.iter().map(|b| b.url.as_str()).collect();
        if !broken.is_empty() {
            let heading = if broken.len() == 1 {
                "Broken link detected:"
            } else {
                "Broken links detected:"
            };
            sections.push(format!(
                "{heading}\n{}",
                broken.into_iter().collect::<Vec<_>>().join("\n")
            ));
        }
        if !self.unreached.is_empty() {
            let mut unreached: Vec<&str> = self.unreached.iter().map(String::as_str).collect();
            unreached.sort_unstable();
            let heading = if unreached.len() == 1 {
                "Page not reached:"
            } else {
                "Pages not reached:"
            };
            sections.push(format!("{heading}\n{}", unreached.join("\n")));
        }
        if self.no_console_errors && self.js_errors_total > 0 {
            let mut lines: Vec<String> = self
                .js_errors
                .iter()
                .take(10)
                .map(|e| match &e.page {
                    Some(page) => format!("{page}: {}", e.message),
                    None => e.message.clone(),
                })
                .collect();
            if self.js_errors_total > lines.len() {
                lines.push(format!(
                    "... and {} more",
                    self.js_errors_total - lines.len()
                ));
            }
            sections.push(format!("JavaScript errors detected:\n{}", lines.join("\n")));
        }
        if sections.is_empty() && self.pages == 0 {
            let why = if self.robots_blocked > 0 {
                " (robots.txt keeps the crawl away)"
            } else {
                ""
            };
            return format!("No page was crawled{why}");
        }

        if sections.is_empty() {
            let s = if self.pages == 1 { "" } else { "s" };
            return format!("Crawled {} page{s}: no broken links", self.pages);
        }
        sections.join("\n")
    }

    /// The report as the task returns it: counts for `pages` and `edges`, the
    /// lists in full, `passed` and `summary`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "pages": self.pages,
            "edges": self.edges.len(),
            "broken": self.broken,
            "js_errors": self.js_errors,
            "js_errors_total": self.js_errors_total,
            "unreached": self.unreached,
            "robots_blocked": self.robots_blocked,
            "truncated": self.truncated,
            "passed": self.passed(),
            "summary": self.summary(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broken(url: &str, status: u16) -> Broken {
        Broken {
            url: url.into(),
            from: Some("https://a.test/".into()),
            status,
        }
    }

    #[test]
    fn a_clean_report_passes_and_says_so() {
        let report = Report {
            pages: 3,
            ..Report::default()
        };
        assert!(report.passed());
        assert_eq!(report.summary(), "Crawled 3 pages: no broken links");
        let one = Report {
            pages: 1,
            ..Report::default()
        };
        assert_eq!(one.summary(), "Crawled 1 page: no broken links");
    }

    #[test]
    fn a_crawl_that_loaded_no_page_does_not_pass() {
        let nothing = Report::default();
        assert!(!nothing.passed());
        assert_eq!(nothing.summary(), "No page was crawled");
        let closed = Report {
            robots_blocked: 1,
            ..Report::default()
        };
        assert!(!closed.passed());
        assert_eq!(
            closed.summary(),
            "No page was crawled (robots.txt keeps the crawl away)"
        );
    }

    #[test]

    fn a_broken_link_fails_with_the_python_wording() {
        let report = Report {
            pages: 2,
            broken: vec![broken("https://a.test/missing", 404)],
            ..Report::default()
        };
        assert!(!report.passed());
        assert_eq!(
            report.summary(),
            "Broken link detected:\nhttps://a.test/missing"
        );
    }

    #[test]
    fn several_broken_links_are_sorted_and_listed_once() {
        let report = Report {
            broken: vec![
                broken("https://a.test/z", 404),
                broken("https://a.test/a", 500),
                broken("https://a.test/z", 404),
            ],
            ..Report::default()
        };
        assert_eq!(
            report.summary(),
            "Broken links detected:\nhttps://a.test/a\nhttps://a.test/z"
        );
    }

    #[test]
    fn an_unreached_must_reach_address_fails() {
        let report = Report {
            unreached: vec!["https://a.test/pricing".into()],
            ..Report::default()
        };
        assert!(!report.passed());
        assert_eq!(
            report.summary(),
            "Page not reached:\nhttps://a.test/pricing"
        );
        let two = Report {
            unreached: vec!["https://a.test/b".into(), "https://a.test/a".into()],
            ..Report::default()
        };
        assert_eq!(
            two.summary(),
            "Pages not reached:\nhttps://a.test/a\nhttps://a.test/b"
        );
    }

    #[test]
    fn console_errors_fail_only_when_asked_to() {
        let mut report = Report {
            pages: 1,
            js_errors: vec![JsError {
                page: Some("https://a.test/".into()),
                message: "Uncaught TypeError: x is undefined".into(),
            }],
            js_errors_total: 1,
            ..Report::default()
        };
        assert!(report.passed(), "errors are only recorded by default");
        report.no_console_errors = true;
        assert!(!report.passed());
        assert_eq!(
            report.summary(),
            "JavaScript errors detected:\nhttps://a.test/: Uncaught TypeError: x is undefined"
        );
    }

    #[test]
    fn console_errors_are_cut_to_ten_lines_and_the_rest_counted() {
        let report = Report {
            js_errors: (0..12)
                .map(|n| JsError {
                    page: None,
                    message: format!("error {n}"),
                })
                .collect(),
            js_errors_total: 15,
            no_console_errors: true,
            ..Report::default()
        };
        let summary = report.summary();
        assert!(summary.contains("error 9"));
        assert!(!summary.contains("error 10"));
        assert!(summary.ends_with("... and 5 more"), "{summary}");
    }

    #[test]
    fn sections_follow_each_other_and_the_json_carries_everything() {
        let report = Report {
            pages: 4,
            edges: vec![("a".into(), "b".into())],
            broken: vec![broken("https://a.test/x", 404)],
            unreached: vec!["https://a.test/y".into()],
            robots_blocked: 2,
            truncated: true,
            ..Report::default()
        };
        assert_eq!(
            report.summary(),
            "Broken link detected:\nhttps://a.test/x\nPage not reached:\nhttps://a.test/y"
        );
        let json = report.to_json();
        assert_eq!(json["pages"], 4);
        assert_eq!(json["edges"], 1);
        assert_eq!(json["broken"][0]["status"], 404);
        assert_eq!(json["broken"][0]["from"], "https://a.test/");
        assert_eq!(json["robots_blocked"], 2);
        assert_eq!(json["truncated"], true);
        assert_eq!(json["passed"], false);
    }
}
