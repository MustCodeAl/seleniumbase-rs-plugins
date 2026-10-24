//! Which addresses a crawl may visit.
//!
//! Two questions, asked at two places. [`Matcher::host_allows`] is about where
//! the crawl may go at all: the `before_navigate` hook asks it of every
//! navigation while a crawl runs. [`Matcher::path_allows`] is about which of
//! the links on those hosts the crawl follows: the `include` and `exclude`
//! patterns, asked only of links the crawl finds.

use std::collections::BTreeSet;

use crate::config::{CrawlerConfig, Scope};
use crate::url::{WebUrl, glob_match, site};

/// The scope of one crawl, built from the options and the start addresses.
#[derive(Clone, Debug)]
pub(crate) struct Matcher {
    scope: Scope,
    origins: BTreeSet<String>,
    sites: BTreeSet<String>,
    hosts: Vec<String>,
    include: Vec<String>,
    exclude: Vec<String>,
}

impl Matcher {
    /// `starts` are normalised start addresses.
    pub(crate) fn new(config: &CrawlerConfig, starts: &[String]) -> Self {
        let parsed: Vec<WebUrl> = starts.iter().filter_map(|s| WebUrl::parse(s)).collect();
        let hosts = match &config.scope {
            Scope::Hosts(hosts) => hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
            _ => Vec::new(),
        };
        Self {
            scope: config.scope.clone(),
            origins: parsed.iter().map(WebUrl::origin).collect(),
            sites: parsed.iter().map(|u| site(&u.host)).collect(),
            hosts,
            include: config.include.clone(),
            exclude: config.exclude.clone(),
        }
    }

    /// Whether the crawl may go to `url` at all.
    pub(crate) fn host_allows(&self, url: &str) -> bool {
        let Some(parsed) = WebUrl::parse(url) else {
            return false;
        };
        match &self.scope {
            Scope::SameOrigin => self.origins.contains(&parsed.origin()),
            Scope::SameSite => self.sites.contains(&site(&parsed.host)),
            Scope::Hosts(_) => self.hosts.iter().any(|host| {
                parsed.host == *host
                    || parsed
                        .host
                        .strip_suffix(host.as_str())
                        .is_some_and(|rest| rest.ends_with('.'))
            }),
        }
    }

    /// Whether a link to `url` is followed: it matches `include` (when there
    /// are patterns) and no `exclude` pattern.
    pub(crate) fn path_allows(&self, url: &str) -> bool {
        let Some(parsed) = WebUrl::parse(url) else {
            return false;
        };
        let whole = parsed.normalised();
        let local = parsed.path_and_query();
        let hit = |pattern: &String| {
            if pattern.starts_with('/') {
                glob_match(pattern, &local)
            } else {
                glob_match(pattern, &whole)
            }
        };
        (self.include.is_empty() || self.include.iter().any(hit)) && !self.exclude.iter().any(hit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(config: serde_json::Value, starts: &[&str]) -> Matcher {
        let config: CrawlerConfig = serde_json::from_value(config).unwrap();
        let starts: Vec<String> = starts
            .iter()
            .map(|s| crate::url::normalise(s).unwrap())
            .collect();
        Matcher::new(&config, &starts)
    }

    #[test]
    fn same_origin_scope_table() {
        let m = matcher(
            serde_json::json!({}),
            &["https://a.test/", "http://b.test:8080/x"],
        );
        for (url, want) in [
            ("https://a.test/deep/page?x=1", true),
            ("http://b.test:8080/other", true),
            ("http://a.test/", false),
            ("https://www.a.test/", false),
            ("https://a.test:8443/", false),
            ("http://b.test/", false),
            ("https://evil.test/", false),
            ("mailto:x@a.test", false),
            ("javascript:void(0)", false),
            ("ftp://a.test/", false),
        ] {
            assert_eq!(m.host_allows(url), want, "{url}");
        }
    }

    #[test]
    fn same_site_scope_table() {
        let m = matcher(
            serde_json::json!({ "scope": "same-site" }),
            &["https://www.example.com/"],
        );
        for (url, want) in [
            ("https://example.com/", true),
            ("http://blog.example.com:8080/x", true),
            ("https://a.b.example.com/", true),
            ("https://example.org/", false),
            ("https://notexample.com/", false),
            ("https://example.com.evil.test/", false),
        ] {
            assert_eq!(m.host_allows(url), want, "{url}");
        }
    }

    #[test]
    fn hosts_scope_matches_the_host_and_its_subdomains_only() {
        let m = matcher(
            serde_json::json!({ "scope": { "hosts": ["Example.com", "docs.test"] } }),
            &["https://example.com/"],
        );
        for (url, want) in [
            ("https://example.com/", true),
            ("http://api.example.com:81/", true),
            ("https://docs.test/a", true),
            ("https://x.docs.test/a", true),
            ("https://test/", false),
            ("https://badexample.com/", false),
            ("https://example.com.evil.test/", false),
        ] {
            assert_eq!(m.host_allows(url), want, "{url}");
        }
    }

    #[test]
    fn include_and_exclude_globs_apply_to_the_path_or_the_whole_address() {
        let m = matcher(
            serde_json::json!({
                "include": ["/docs/*", "https://a.test/blog/*"],
                "exclude": ["*?print=1", "/docs/old/*"],
            }),
            &["https://a.test/"],
        );
        for (url, want) in [
            ("https://a.test/docs/intro", true),
            ("https://a.test/blog/post-1", true),
            ("https://a.test/about", false),
            ("https://a.test/docs/old/page", false),
            ("https://a.test/docs/intro?print=1", false),
            ("https://a.test/docs/intro?lang=de", true),
        ] {
            assert_eq!(m.path_allows(url), want, "{url}");
        }
    }

    #[test]
    fn no_include_patterns_means_everything_is_followed() {
        let m = matcher(
            serde_json::json!({ "exclude": ["/logout*"] }),
            &["https://a.test/"],
        );
        assert!(m.path_allows("https://a.test/anything"));
        assert!(!m.path_allows("https://a.test/logout"));
        assert!(!m.path_allows("https://a.test/logout?next=/"));
    }
}
