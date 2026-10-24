//! Web addresses as the crawler needs them: parsed, normalised, compared.
//!
//! The browser resolves every link before the crawler sees it, so this module
//! only reads absolute `http` and `https` addresses. Two addresses that name
//! the same page by different spellings normalise to one string, which is what
//! the crawler deduplicates on.

use std::net::Ipv4Addr;

/// The longest address the crawler accepts; longer links are ignored.
pub(crate) const MAX_URL_LEN: usize = 4096;

/// A parsed `http` or `https` address, in normal form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WebUrl {
    https: bool,
    /// Lower-case host, with the brackets of an IPv6 literal.
    pub(crate) host: String,
    port: u16,
    path: String,
    query: Option<String>,
}

impl WebUrl {
    /// Reads `url`. `None` unless it is an `http` or `https` address with a
    /// host, no credentials, no space and no control character. The fragment
    /// is dropped.
    pub(crate) fn parse(url: &str) -> Option<Self> {
        if url.is_empty()
            || url.len() > MAX_URL_LEN
            || url.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return None;
        }
        let (https, rest) = if let Some(rest) = strip_scheme(url, "https://") {
            (true, rest)
        } else if let Some(rest) = strip_scheme(url, "http://") {
            (false, rest)
        } else {
            return None;
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.is_empty() || authority.contains('@') {
            return None;
        }
        let (host, port) = split_host_port(authority, if https { 443 } else { 80 })?;
        let tail = tail.split('#').next().unwrap_or_default();
        let (path, query) = match tail.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (tail, None),
        };
        Some(Self {
            https,
            host,
            port,
            path: upper_escapes(&clean_path(path)),
            query: query.filter(|q| !q.is_empty()).map(upper_escapes),
        })
    }

    fn default_port(&self) -> u16 {
        if self.https { 443 } else { 80 }
    }

    /// `scheme://host[:port]`, without a trailing slash.
    pub(crate) fn origin(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        if self.port == self.default_port() {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }

    /// The path and the query, as a robots.txt rule or a `/path` glob sees them.
    pub(crate) fn path_and_query(&self) -> String {
        match &self.query {
            Some(query) => format!("{}?{query}", self.path),
            None => self.path.clone(),
        }
    }

    /// The normal form: lower-case scheme and host, no default port, no
    /// fragment, dot segments resolved, an empty path as `/`, an empty query
    /// dropped, percent escapes in upper case.
    pub(crate) fn normalised(&self) -> String {
        format!("{}{}", self.origin(), self.path_and_query())
    }
}

/// The normal form of `url`, or `None` if it is not a plain web address.
pub(crate) fn normalise(url: &str) -> Option<String> {
    WebUrl::parse(url).map(|parsed| parsed.normalised())
}

fn strip_scheme<'a>(url: &'a str, scheme: &str) -> Option<&'a str> {
    let head = url.get(..scheme.len())?;
    head.eq_ignore_ascii_case(scheme)
        .then(|| &url[scheme.len()..])
}

fn split_host_port(authority: &str, default: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        if host.is_empty() {
            return None;
        }
        let after = &rest[close + 1..];
        let port = if after.is_empty() {
            default
        } else {
            after.strip_prefix(':')?.parse().ok()?
        };
        return Some((format!("[{}]", host.to_ascii_lowercase()), port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, "")) => (host, default),
        Some((host, port)) => (host, port.parse().ok()?),
        None => (authority, default),
    };
    if host.is_empty() || host.contains([':', '[', ']']) {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

/// Resolves `.` and `..` segments. The path starts with `/` or is empty.
fn clean_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len() - 1;
    let mut out: Vec<&str> = Vec::new();
    for (index, segment) in segments.iter().enumerate().skip(1) {
        match *segment {
            "." => {
                if index == last {
                    out.push("");
                }
            }
            ".." => {
                out.pop();
                if index == last {
                    out.push("");
                }
            }
            other => out.push(other),
        }
    }
    format!("/{}", out.join("/"))
}

/// Writes the hex digits of every `%xx` escape in upper case.
fn upper_escapes(text: &str) -> String {
    let mut bytes = text.as_bytes().to_vec();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == b'%'
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            bytes[index + 1] = bytes[index + 1].to_ascii_uppercase();
            bytes[index + 2] = bytes[index + 2].to_ascii_uppercase();
            index += 3;
        } else {
            index += 1;
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|_| text.to_owned())
}

/// The registrable part of `host`, by a rule of thumb: the last two labels, or
/// the last three when the top-level label has two letters and the one before
/// it at most three (`example.co.uk`). There is no public-suffix list, so a
/// few hosts are put in the wrong site; use `scope = { hosts = [..] }` when it
/// matters.
pub(crate) fn site(host: &str) -> String {
    if host.starts_with('[') || host.parse::<Ipv4Addr>().is_ok() {
        return host.to_owned();
    }
    let labels: Vec<&str> = host.split('.').collect();
    let count = labels.len();
    if count <= 2 {
        return host.to_owned();
    }
    let take = if labels[count - 1].len() == 2 && labels[count - 2].len() <= 3 {
        3
    } else {
        2
    };
    labels[count - take..].join(".")
}

/// Whether `text` matches `pattern`, where `*` stands for any run of
/// characters (also none) and `?` for exactly one.
pub(crate) fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let mut star: Option<usize> = None;
    let mut mark = 0;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_table() {
        for (input, want) in [
            ("HTTP://Example.COM", "http://example.com/"),
            ("https://example.com:443/a", "https://example.com/a"),
            ("http://example.com:80/", "http://example.com/"),
            ("http://example.com:8080/x", "http://example.com:8080/x"),
            ("https://example.com/a#frag", "https://example.com/a"),
            ("https://example.com/a?", "https://example.com/a"),
            (
                "https://example.com/a?b=1&c=2#x",
                "https://example.com/a?b=1&c=2",
            ),
            ("https://example.com?q=1", "https://example.com/?q=1"),
            ("https://example.com/a/./b/../c", "https://example.com/a/c"),
            ("https://example.com/a/b/..", "https://example.com/a/"),
            ("https://example.com/a/.", "https://example.com/a/"),
            ("https://example.com/../a", "https://example.com/a"),
            (
                "https://example.com/caf%c3%a9",
                "https://example.com/caf%C3%A9",
            ),
            ("https://example.com/a%2", "https://example.com/a%2"),
            ("https://[::1]:8443/x", "https://[::1]:8443/x"),
            ("http://[::1]/", "http://[::1]/"),
            ("http://127.0.0.1:3000", "http://127.0.0.1:3000/"),
        ] {
            assert_eq!(normalise(input).as_deref(), Some(want), "{input}");
        }
    }

    #[test]
    fn what_is_not_a_plain_web_address_does_not_parse() {
        for input in [
            "",
            "file:///etc/passwd",
            "mailto:a@b.c",
            "javascript:alert(1)",
            "data:text/html,x",
            "ftp://example.com/",
            "//example.com/a",
            "/relative",
            "https://",
            "https:///a",
            "https://user:pw@example.com/",
            "https://example.com/a b",
            "https://example.com:notaport/",
            "https://example.com:99999/",
            "https://exa:mple.com/",
            "https://[]/",
            "https://[::1/",
        ] {
            assert!(WebUrl::parse(input).is_none(), "{input}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_URL_LEN));
        assert!(WebUrl::parse(&long).is_none());
    }

    #[test]
    fn spellings_of_one_page_normalise_to_one_string() {
        let spellings = [
            "https://Example.com/a/b",
            "https://example.com:443/a/b#top",
            "https://example.com/a/./b",
            "https://example.com/x/../a/b",
        ];
        let first = normalise(spellings[0]).unwrap();
        assert!(spellings.iter().all(|s| normalise(s).unwrap() == first));
    }

    #[test]
    fn origin_and_path_and_query_split_the_address() {
        let parsed = WebUrl::parse("https://Example.com:8443/a/b?x=1#f").unwrap();
        assert_eq!(parsed.origin(), "https://example.com:8443");
        assert_eq!(parsed.path_and_query(), "/a/b?x=1");
        assert_eq!(parsed.host, "example.com");
        let plain = WebUrl::parse("http://example.com").unwrap();
        assert_eq!(plain.origin(), "http://example.com");
        assert_eq!(plain.path_and_query(), "/");
    }

    #[test]
    fn site_is_the_registrable_part_by_rule_of_thumb() {
        for (host, want) in [
            ("example.com", "example.com"),
            ("www.example.com", "example.com"),
            ("a.b.example.com", "example.com"),
            ("www.example.co.uk", "example.co.uk"),
            ("blog.example.de", "example.de"),
            ("localhost", "localhost"),
            ("127.0.0.1", "127.0.0.1"),
            ("[::1]", "[::1]"),
        ] {
            assert_eq!(site(host), want, "{host}");
        }
    }

    #[test]
    fn glob_star_and_question_mark() {
        assert!(glob_match("https://a.test/*", "https://a.test/x/y"));
        assert!(glob_match("*/login*", "https://a.test/login?next=/"));
        assert!(glob_match("/p?ge", "/page"));
        assert!(!glob_match("/p?ge", "/pge"));
        assert!(!glob_match("/admin/*", "/administrator"));
        assert!(glob_match("*", ""));
        assert!(glob_match("a*b*c", "aXXbYYc"));
        assert!(!glob_match("a*b*c", "aXXbYY"));
    }
}
