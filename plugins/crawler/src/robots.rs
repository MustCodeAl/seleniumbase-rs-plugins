//! robots.txt, read the way RFC 9309 asks: the group for our name, else the
//! group for `*`; of the rules that match, the longest wins and `Allow` wins a
//! tie; `*` and a trailing `$` work in a rule.

use std::time::Duration;

/// The product token the crawler answers to in a `User-agent` line, besides `*`.
pub(crate) const AGENT: &str = "sbrs";

/// The longest `Crawl-delay` honoured.
const MAX_CRAWL_DELAY: Duration = Duration::from_secs(60);

/// Most rules read from one file; the rest are ignored.
const MAX_RULES: usize = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Rule {
    allow: bool,
    pattern: String,
}

/// The rules that apply to the crawler on one site.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Robots {
    rules: Vec<Rule>,
    delay: Option<f64>,
    disallow_all: bool,
}

#[derive(Default)]
struct Group {
    agents: Vec<String>,
    rules: Vec<Rule>,
    delay: Option<f64>,
}

impl Robots {
    /// No restrictions: the file is missing (a 4xx answer) or empty.
    pub(crate) fn allow_all() -> Self {
        Self::default()
    }

    /// Everything is off limits: the file could not be fetched (a 5xx answer
    /// or no answer), so the site is treated as closed, as RFC 9309 says.
    pub(crate) fn disallow_all() -> Self {
        Self {
            disallow_all: true,
            ..Self::default()
        }
    }

    /// Reads the file `text` for the crawler named `agent`.
    pub(crate) fn parse(text: &str, agent: &str) -> Self {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut groups: Vec<Group> = Vec::new();
        let mut collecting = false;
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or_default().trim();
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
            match key.as_str() {
                "user-agent" => {
                    if !collecting || groups.is_empty() {
                        groups.push(Group::default());
                    }
                    collecting = true;
                    if let Some(group) = groups.last_mut() {
                        group.agents.push(value.to_ascii_lowercase());
                    }
                }
                "allow" | "disallow" | "crawl-delay" => {
                    collecting = false;
                    let Some(group) = groups.last_mut() else {
                        continue;
                    };
                    if key == "crawl-delay" {
                        if let Ok(seconds) = value.parse::<f64>()
                            && seconds.is_finite()
                            && seconds > 0.0
                        {
                            group.delay = Some(seconds);
                        }
                    } else if !value.is_empty() && group.rules.len() < MAX_RULES {
                        group.rules.push(Rule {
                            allow: key == "allow",
                            pattern: value.to_owned(),
                        });
                    }
                }
                _ => collecting = false,
            }
        }
        let agent = agent.to_ascii_lowercase();
        let mut chosen: Vec<&Group> = groups
            .iter()
            .filter(|g| g.agents.contains(&agent))
            .collect();
        if chosen.is_empty() {
            chosen = groups
                .iter()
                .filter(|g| g.agents.iter().any(|a| a == "*"))
                .collect();
        }
        Self {
            rules: chosen.iter().flat_map(|g| g.rules.clone()).collect(),
            delay: chosen.iter().filter_map(|g| g.delay).reduce(f64::max),
            disallow_all: false,
        }
    }

    /// Whether the crawler may fetch the path (with its query) `target`.
    pub(crate) fn allows(&self, target: &str) -> bool {
        if self.disallow_all {
            return target == "/robots.txt";
        }
        if target == "/robots.txt" {
            return true;
        }
        let mut best: Option<(usize, bool)> = None;
        for rule in &self.rules {
            if rule_matches(&rule.pattern, target) {
                let length = rule.pattern.len();
                best = match best {
                    Some((len, allow)) if len > length || (len == length && allow) => best,
                    _ => Some((length, rule.allow)),
                };
            }
        }
        best.is_none_or(|(_, allow)| allow)
    }

    /// The `Crawl-delay` of the group, at most a minute.
    pub(crate) fn crawl_delay(&self) -> Option<Duration> {
        self.delay
            .map(|seconds| Duration::from_secs_f64(seconds).min(MAX_CRAWL_DELAY))
    }
}

/// Whether `pattern` (with `*` and a trailing `$`) matches the start of
/// `path`, or all of it when anchored by `$`.
fn rule_matches(pattern: &str, path: &str) -> bool {
    let (pattern, anchored) = match pattern.strip_suffix('$') {
        Some(rest) => (rest, true),
        None => (pattern, false),
    };
    let parts: Vec<&str> = pattern.split('*').collect();
    let count = parts.len();
    if !path.starts_with(parts[0]) {
        return false;
    }
    let mut position = parts[0].len();
    if count == 1 {
        return !anchored || path.len() == position;
    }
    for part in &parts[1..count - 1] {
        match path.get(position..).and_then(|rest| rest.find(part)) {
            Some(at) => position += at + part.len(),
            None => return false,
        }
    }
    let tail = parts[count - 1];
    if anchored {
        path.len() >= position + tail.len() && path.ends_with(tail)
    } else {
        path.get(position..).is_some_and(|rest| rest.contains(tail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn robots(text: &str) -> Robots {
        Robots::parse(text, AGENT)
    }

    #[test]
    fn an_empty_or_missing_file_allows_everything() {
        for rules in [
            robots(""),
            Robots::allow_all(),
            robots("# only a comment\n"),
        ] {
            assert!(rules.allows("/anything?x=1"));
            assert_eq!(rules.crawl_delay(), None);
        }
    }

    #[test]
    fn disallow_blocks_a_prefix_and_an_empty_disallow_blocks_nothing() {
        let rules = robots("User-agent: *\nDisallow: /private\nDisallow:\n");
        assert!(!rules.allows("/private"));
        assert!(!rules.allows("/private/area?x=1"));
        assert!(!rules.allows("/privately"));
        assert!(rules.allows("/public"));
        assert!(robots("User-agent: *\nDisallow:\n").allows("/x"));
    }

    #[test]
    fn the_longest_rule_wins_and_allow_wins_a_tie() {
        let rules = robots(
            "User-agent: *\nDisallow: /docs\nAllow: /docs/public\nDisallow: /docs/public/secret\n\
             Disallow: /tie\nAllow: /tie\n",
        );
        assert!(!rules.allows("/docs/intro"));
        assert!(rules.allows("/docs/public/page"));
        assert!(!rules.allows("/docs/public/secret/x"));
        assert!(rules.allows("/tie"));
    }

    #[test]
    fn wildcards_and_end_anchors() {
        let rules = robots(
            "User-agent: *\nDisallow: /*.pdf$\nDisallow: /a*/tmp\nDisallow: /*?session=\nAllow: /\n",
        );
        assert!(!rules.allows("/files/report.pdf"));
        assert!(rules.allows("/files/report.pdf?download=1"));
        assert!(rules.allows("/files/report.pdfx"));
        assert!(!rules.allows("/abc/tmp"));
        assert!(rules.allows("/b/tmp"));
        assert!(!rules.allows("/page?session=42"));
        assert!(rules.allows("/page?x=1"));
    }

    #[test]
    fn our_own_group_beats_the_star_group_and_groups_with_our_name_merge() {
        let text = "User-agent: *\nDisallow: /\n\n\
                    User-agent: Googlebot\nDisallow: /g\n\n\
                    User-agent: SBRS\nDisallow: /one\n\n\
                    User-agent: other\nUser-agent: sbrs\nDisallow: /two\n";
        let rules = robots(text);
        assert!(rules.allows("/open"));
        assert!(!rules.allows("/one"));
        assert!(!rules.allows("/two"));
        // Without a group of our own the star group applies.
        let star = robots("User-agent: googlebot\nDisallow: /g\n\nUser-agent: *\nDisallow: /x\n");
        assert!(!star.allows("/x"));
        assert!(star.allows("/g"));
    }

    #[test]
    fn consecutive_user_agent_lines_share_one_group_and_comments_are_ignored() {
        let rules = robots(
            "\u{feff}User-agent: a # first\nUser-agent: *\n# note\nDisallow: /x # trailing\nBogus line\n",
        );
        assert!(!rules.allows("/x"));
        assert!(rules.allows("/y"));
    }

    #[test]
    fn rules_before_any_user_agent_are_ignored() {
        let rules = robots("Disallow: /\nUser-agent: *\nDisallow: /z\n");
        assert!(rules.allows("/a"));
        assert!(!rules.allows("/z"));
    }

    #[test]
    fn crawl_delay_is_read_and_capped() {
        let rules = robots("User-agent: *\nCrawl-delay: 2.5\n");
        assert_eq!(rules.crawl_delay(), Some(Duration::from_millis(2500)));
        let long = robots("User-agent: *\nCrawl-delay: 3600\n");
        assert_eq!(long.crawl_delay(), Some(MAX_CRAWL_DELAY));
        for text in [
            "User-agent: *\nCrawl-delay: soon\n",
            "User-agent: *\nCrawl-delay: -1\n",
        ] {
            assert_eq!(robots(text).crawl_delay(), None);
        }
    }

    #[test]
    fn an_unreachable_file_closes_the_site_but_not_robots_txt_itself() {
        let rules = Robots::disallow_all();
        assert!(!rules.allows("/"));
        assert!(!rules.allows("/page"));
        assert!(rules.allows("/robots.txt"));
        // robots.txt is always allowed, whatever the file says.
        assert!(robots("User-agent: *\nDisallow: /\n").allows("/robots.txt"));
    }
}
