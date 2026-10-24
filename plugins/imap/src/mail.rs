//! Messages: what a task asks for, how a message is read, and how a one-time
//! code or a link is found in it.

use mail_parser::MessageParser;
use seleniumbase_rs_plugin::{PluginError, Result};
use serde::Deserialize;
use serde_json::{Value, json};

/// The default for `since_secs`: ten minutes.
pub const DEFAULT_SINCE_SECS: u64 = 600;

/// The largest `since_secs` accepted: thirty days.
pub const MAX_SINCE_SECS: u64 = 30 * 86_400;

/// The most bytes of the body that go into the `text` of an answer.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;

/// The longest `from` or `subject_contains`.
const MAX_FILTER_CHARS: usize = 256;

/// What to pull out of the message that matched.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Extract {
    /// A one-time code; a message without one does not match.
    Code,
    /// A link; a message without one does not match.
    Link,
    /// Both, when present; a message with neither does not match.
    #[default]
    Both,
}

/// The task's input: which email to wait for.
///
/// ```
/// use seleniumbase_rs_plugin_imap::{Extract, Query};
///
/// let query = Query::parse(&serde_json::json!({
///     "from": "no-reply@example.com",
///     "extract": "code",
/// }))?;
/// assert_eq!(query.since_secs, 600);
/// assert_eq!(query.extract, Extract::Code);
/// # Ok::<(), seleniumbase_rs_plugin::PluginError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Query {
    /// Part of the sender (name or address), without regard to case.
    pub from: Option<String>,
    /// Part of the subject, without regard to case.
    pub subject_contains: Option<String>,
    /// Only messages sent in the last this many seconds.
    pub since_secs: u64,
    /// What to extract.
    pub extract: Extract,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            from: None,
            subject_contains: None,
            since_secs: DEFAULT_SINCE_SECS,
            extract: Extract::Both,
        }
    }
}

impl Query {
    /// Reads the task input (`null` means no filters).
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] for an unknown field, an empty or overlong
    /// filter, or a `since_secs` out of range.
    pub fn parse(input: &Value) -> Result<Self> {
        if input.is_null() {
            return Ok(Self::default());
        }
        let query: Self = serde_json::from_value(input.clone())
            .map_err(|error| PluginError::Config(format!("imap: bad task input: {error}")))?;
        for (name, value) in [
            ("from", &query.from),
            ("subject_contains", &query.subject_contains),
        ] {
            if let Some(text) = value
                && (text.trim().is_empty() || text.chars().count() > MAX_FILTER_CHARS)
            {
                return Err(PluginError::Config(format!(
                    "imap: `{name}` must be 1 to {MAX_FILTER_CHARS} characters"
                )));
            }
        }
        if !(1..=MAX_SINCE_SECS).contains(&query.since_secs) {
            return Err(PluginError::Config(format!(
                "imap: `since_secs` must be between 1 and {MAX_SINCE_SECS}"
            )));
        }
        Ok(query)
    }

    /// The filters in words, for an error.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(from) = &self.from {
            parts.push(format!("from `{from}`"));
        }
        if let Some(subject) = &self.subject_contains {
            parts.push(format!("with a subject containing `{subject}`"));
        }
        parts.push(format!("sent in the last {}s", self.since_secs));
        parts.join(", ")
    }

    /// The answer for `mail` if it is what was asked for, judged at
    /// `now_secs` (seconds since the Unix epoch).
    #[must_use]
    pub fn matches(&self, mail: &Mail, now_secs: u64) -> Option<Found> {
        if let Some(wanted) = &self.from {
            let sender = format!(
                "{} <{}>",
                mail.from_name.as_deref().unwrap_or_default(),
                mail.from_address.as_deref().unwrap_or_default()
            );
            if !contains_ignore_case(&sender, wanted) {
                return None;
            }
        }
        if let Some(wanted) = &self.subject_contains
            && !contains_ignore_case(&mail.subject, wanted)
        {
            return None;
        }
        if let Some(sent) = mail.timestamp {
            let now = i64::try_from(now_secs).unwrap_or(i64::MAX);
            let window = i64::try_from(self.since_secs).unwrap_or(i64::MAX);
            if sent < now.saturating_sub(window) {
                return None;
            }
        }
        let code = match self.extract {
            Extract::Code | Extract::Both => mail.code(),
            Extract::Link => None,
        };
        let link = match self.extract {
            Extract::Link | Extract::Both => mail.link(),
            Extract::Code => None,
        };
        let found = match self.extract {
            Extract::Code => code.is_some(),
            Extract::Link => link.is_some(),
            Extract::Both => code.is_some() || link.is_some(),
        };
        found.then(|| Found {
            from: mail.sender(),
            subject: mail.subject.clone(),
            date: mail.date.clone(),
            code,
            link,
            text: cut(&mail.text, MAX_TEXT_BYTES),
        })
    }
}

fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// At most `max` bytes of `text`, ending on a character boundary.
fn cut(text: &str, max: usize) -> String {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// A message, as far as the plugin reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mail {
    /// The display name of the sender.
    pub from_name: Option<String>,
    /// The address of the sender.
    pub from_address: Option<String>,
    /// The subject, decoded.
    pub subject: String,
    /// The `Date` header as RFC 3339.
    pub date: Option<String>,
    /// The `Date` header as seconds since the Unix epoch.
    pub timestamp: Option<i64>,
    /// The text of the message: the plain part, else the HTML part as text.
    pub text: String,
    /// The HTML part, if there is one.
    pub html: Option<String>,
}

impl Mail {
    /// Reads a raw message; `None` if it cannot be read as one.
    #[must_use]
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let message = MessageParser::default().parse(raw)?;
        let sender = message.from().and_then(|from| from.first());
        let date = message.date();
        Some(Self {
            from_name: sender.and_then(|s| s.name()).map(str::to_owned),
            from_address: sender.and_then(|s| s.address()).map(str::to_owned),
            subject: message.subject().unwrap_or_default().to_owned(),
            date: date.map(|d| d.to_rfc3339()),
            timestamp: date.map(|d| d.to_timestamp()),
            text: message
                .body_text(0)
                .map(|text| text.into_owned())
                .unwrap_or_default(),
            html: message.body_html(0).map(|html| html.into_owned()),
        })
    }

    /// The sender as one string: the address, else the name.
    #[must_use]
    pub fn sender(&self) -> Option<String> {
        self.from_address.clone().or_else(|| self.from_name.clone())
    }

    /// The first one-time code: in the subject, else in the text.
    #[must_use]
    pub fn code(&self) -> Option<String> {
        find_code(&[&self.subject, &self.text])
    }

    /// The first `http(s)` link: in the text part, else in the HTML part.
    #[must_use]
    pub fn link(&self) -> Option<String> {
        find_link(&self.text).or_else(|| {
            self.html
                .as_deref()
                .and_then(|html| find_href(html).or_else(|| find_link(html)))
        })
    }
}

/// What the wait found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// The sender's address (or name).
    pub from: Option<String>,
    /// The subject.
    pub subject: String,
    /// The `Date` header as RFC 3339.
    pub date: Option<String>,
    /// The one-time code, if asked for and found.
    pub code: Option<String>,
    /// The link, if asked for and found.
    pub link: Option<String>,
    /// The start of the text (at most [`MAX_TEXT_BYTES`]).
    pub text: String,
}

impl Found {
    /// The line the task records: `{"from", "subject", "date", "code"?,
    /// "link"?, "text"}`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut line = json!({
            "from": self.from,
            "subject": self.subject,
            "date": self.date,
            "text": self.text,
        });
        if let Some(object) = line.as_object_mut() {
            if let Some(code) = &self.code {
                object.insert("code".into(), json!(code));
            }
            if let Some(link) = &self.link {
                object.insert("link".into(), json!(link));
            }
        }
        line
    }
}

// ---- one-time codes -----------------------------------------------------------

/// Words that, close to a number, mark it as the code.
const KEYWORDS: [&str; 9] = [
    "code",
    "otp",
    "pin",
    "passcode",
    "password",
    "verification",
    "verify",
    "token",
    "security",
];

/// The first one-time code of 4 to 8 digits in `texts`, searched in order.
///
/// A number close to a word such as "code" or "verification" comes before
/// any other. Digits that are part of a longer number, a date, a time, a
/// price, an address or a word are not codes, and neither are the digits of
/// a link. A code written as two groups of three (`123 456`) is joined.
///
/// ```
/// use seleniumbase_rs_plugin_imap::find_code;
///
/// assert_eq!(find_code(&["Your code is 482910, valid until 10:30"]).as_deref(), Some("482910"));
/// assert_eq!(find_code(&["Use 739 204 to sign in"]).as_deref(), Some("739204"));
/// assert_eq!(find_code(&["Order 2026-10-24 shipped"]), None);
/// ```
#[must_use]
pub fn find_code(texts: &[&str]) -> Option<String> {
    let all: Vec<(String, Option<usize>)> = texts
        .iter()
        .flat_map(|text| code_candidates(text))
        .collect();
    // The number closest to a keyword; the first of those equally close.
    all.iter()
        .filter(|(_, distance)| distance.is_some())
        .min_by_key(|(_, distance)| *distance)
        .or_else(|| all.first())
        .map(|(code, _)| code.clone())
}

fn code_candidates(text: &str) -> Vec<(String, Option<usize>)> {
    let chars: Vec<char> = without_urls(text).chars().collect();
    let digit_at = |i: usize| chars.get(i).is_some_and(char::is_ascii_digit);
    let mut found = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while digit_at(i) {
            i += 1;
        }
        let mut end = i;
        let mut len = end - start;
        // "123 456": a code written in two groups.
        if len == 3
            && chars.get(end) == Some(&' ')
            && (end + 1..end + 4).all(digit_at)
            && !digit_at(end + 4)
        {
            end += 4;
            len = 6;
            i = end;
        }
        if !(4..=8).contains(&len) || glued_before(&chars, start) || glued_after(&chars, end) {
            continue;
        }
        let code: String = chars[start..end]
            .iter()
            .filter(|c| c.is_ascii_digit())
            .collect();
        found.push((code, keyword_distance(&chars, start, end)));
    }
    found
}

/// Whether what comes before the digits makes them part of something else.
fn glued_before(chars: &[char], start: usize) -> bool {
    match start.checked_sub(1).map(|j| chars[j]) {
        None => false,
        Some(c) if c.is_alphabetic() => true,
        Some('$' | '#') => true,
        Some('.' | ',' | '-' | '/' | ':' | '+') => start >= 2 && chars[start - 2].is_ascii_digit(),
        Some(_) => false,
    }
}

/// Whether what comes after the digits makes them part of something else.
fn glued_after(chars: &[char], end: usize) -> bool {
    match chars.get(end) {
        None => false,
        Some(c) if c.is_alphabetic() || *c == '%' => true,
        Some('.' | ',' | '-' | '/' | ':') => chars.get(end + 1).is_some_and(char::is_ascii_digit),
        Some(_) => false,
    }
}

fn keyword_distance(chars: &[char], start: usize, end: usize) -> Option<usize> {
    let before: String = chars[start.saturating_sub(60)..start]
        .iter()
        .collect::<String>()
        .to_lowercase();
    let after: String = chars[end..chars.len().min(end + 40)]
        .iter()
        .collect::<String>()
        .to_lowercase();
    KEYWORDS
        .iter()
        .flat_map(|word| {
            let back = before
                .rfind(word)
                .map(|pos| before.len() - (pos + word.len()));
            back.into_iter().chain(after.find(word))
        })
        .min()
}

/// `text` with every `http(s)` link replaced by a space.
fn without_urls(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(pos) = next_url(&lower, at) {
        out.push_str(&text[at..pos]);
        out.push(' ');
        at = text[pos..]
            .find(char::is_whitespace)
            .map_or(text.len(), |n| pos + n);
    }
    out.push_str(&text[at..]);
    out
}

/// Where the next `http://` or `https://` starts in `lower`, from `from`.
fn next_url(lower: &str, from: usize) -> Option<usize> {
    let rest = &lower[from..];
    rest.find("http://")
        .into_iter()
        .chain(rest.find("https://"))
        .min()
        .map(|n| from + n)
}

// ---- links --------------------------------------------------------------------

/// The first `http(s)` link in `text`, without the punctuation that ends a
/// sentence.
///
/// ```
/// use seleniumbase_rs_plugin_imap::find_link;
///
/// assert_eq!(
///     find_link("Confirm: https://example.com/c?t=1&u=2.").as_deref(),
///     Some("https://example.com/c?t=1&u=2"),
/// );
/// assert_eq!(find_link("no link here"), None);
/// ```
#[must_use]
pub fn find_link(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = next_url(&lower, from) {
        let end = text[pos..]
            .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '\''))
            .map_or(text.len(), |n| pos + n);
        let url = text[pos..end].trim_end_matches(|c: char| {
            matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}')
        });
        if url
            .split_once("://")
            .is_some_and(|(_, rest)| !rest.is_empty())
        {
            return Some(url.to_owned());
        }
        from = end.max(pos + 1);
    }
    None
}

/// The first `href` of an HTML document that is an `http(s)` address.
fn find_href(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let mut from = 0;
    while let Some(n) = lower[from..].find("href=") {
        let at = from + n + "href=".len();
        from = at;
        let rest = &html[at..];
        let value = match rest.chars().next() {
            Some(quote @ ('"' | '\'')) => rest[1..].split(quote).next().unwrap_or_default(),
            _ => rest
                .split(|c: char| c.is_whitespace() || c == '>')
                .next()
                .unwrap_or_default(),
        };
        let value = value.trim().replace("&amp;", "&");
        let scheme = value.to_ascii_lowercase();
        if scheme.starts_with("http://") || scheme.starts_with("https://") {
            return Some(value);
        }
    }
    None
}

// ---- dates --------------------------------------------------------------------

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// A day in the form IMAP's `SINCE` takes (`24-Oct-2026`), in UTC.
///
/// ```
/// use seleniumbase_rs_plugin_imap::imap_date;
///
/// assert_eq!(imap_date(0), "1-Jan-1970");
/// assert_eq!(imap_date(1_767_225_600), "1-Jan-2026");
/// ```
#[must_use]
pub fn imap_date(epoch_secs: u64) -> String {
    let (year, month, day) = civil_from_days(i64::try_from(epoch_secs / 86_400).unwrap_or(0));
    format!("{day}-{}-{year}", MONTHS[month - 1])
}

/// The proleptic Gregorian date of a day count since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, usize, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, usize::try_from(month).unwrap_or(1), day)
}
