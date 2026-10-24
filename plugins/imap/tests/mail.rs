//! Reading messages, matching them and waiting for one: no server.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use seleniumbase_rs_plugin::{Clock, PluginError, Result, Timer, async_trait};
use seleniumbase_rs_plugin_imap::{
    Extract, Mail, MailSource, Query, RawMail, find_code, find_link, imap_date, wait_for,
};
use seleniumbase_rs_plugin_testing::block_on;
use serde_json::{Value, json};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn mail(name: &str) -> Mail {
    Mail::parse(&fixture(name)).unwrap()
}

fn sent(mail: &Mail) -> u64 {
    u64::try_from(mail.timestamp.unwrap()).unwrap()
}

// ---- reading and extracting ---------------------------------------------------

#[test]
fn a_plain_message_gives_its_code_and_link() {
    let mail = mail("plain.eml");
    assert_eq!(mail.from_address.as_deref(), Some("no-reply@example.com"));
    assert_eq!(mail.from_name.as_deref(), Some("Example Service"));
    assert_eq!(mail.subject, "Verify your email address");
    assert!(
        mail.date
            .as_deref()
            .unwrap()
            .starts_with("2026-10-24T10:00:00")
    );
    // The date, the time and the price in the body are not codes; the year in
    // the footer comes after the real one.
    assert_eq!(mail.code().as_deref(), Some("482910"));
    // The full stop that ends the sentence is not part of the link.
    assert_eq!(
        mail.link().as_deref(),
        Some("https://example.com/verify?token=abc123&x=1")
    );
}

#[test]
fn an_html_only_message_is_read_as_text_and_its_href_is_the_link() {
    let mail = mail("html_only.eml");
    assert!(mail.html.is_some());
    assert!(mail.text.contains("Confirm your email"));
    assert_eq!(mail.code().as_deref(), Some("739204"));
    assert_eq!(
        mail.link().as_deref(),
        Some("https://app.example.org/confirm?a=1&b=2")
    );
}

#[test]
fn a_multipart_message_prefers_its_text_part() {
    let mail = mail("multipart.eml");
    assert_eq!(mail.code().as_deref(), Some("1234"));
    assert_eq!(
        mail.link().as_deref(),
        Some("https://plain.example.com/a?x=1")
    );
}

#[test]
fn a_code_in_the_subject_comes_before_the_year_in_the_body() {
    let mail = mail("subject_code.eml");
    assert_eq!(mail.code().as_deref(), Some("635127"));
    assert_eq!(mail.link(), None);
}

#[test]
fn numbers_that_are_not_codes_are_skipped() {
    for text in [
        "Order 2026-10-24 at 10:30",
        "Total $1,234.56",
        "Rated 4.5 stars",
        "Reference ABC12345",
        "12345678901 is too long",
        "Sale: 123456% off",
        "visit https://x.example/v/123456 now",
        "call 555-0100",
    ] {
        assert_eq!(find_code(&[text]), None, "{text}");
    }
}

#[test]
fn codes_in_other_shapes_are_found() {
    assert_eq!(find_code(&["Code: G-123456"]).as_deref(), Some("123456"));
    assert_eq!(find_code(&["Your PIN is 4829."]).as_deref(), Some("4829"));
    assert_eq!(find_code(&["Use 739 204 now"]).as_deref(), Some("739204"));
    assert_eq!(find_code(&["(98765432)"]).as_deref(), Some("98765432"));
    // A number next to a word like "code" wins over an earlier one.
    assert_eq!(
        find_code(&["Copyright 2026. Your verification code is 998877."]).as_deref(),
        Some("998877")
    );
    // The first text is searched first.
    assert_eq!(find_code(&["111111", "222222"]).as_deref(), Some("111111"));
}

#[test]
fn links_are_cut_where_they_end() {
    assert_eq!(
        find_link("see <https://a.example/x>").as_deref(),
        Some("https://a.example/x")
    );
    assert_eq!(
        find_link("(see https://a.example/x).").as_deref(),
        Some("https://a.example/x")
    );
    assert_eq!(
        find_link("HTTPS://A.EXAMPLE/X now").as_deref(),
        Some("HTTPS://A.EXAMPLE/X")
    );
    assert_eq!(find_link("mailto:a@b.example and http:// alone"), None);
}

#[test]
fn imap_dates_are_days_in_utc() {
    assert_eq!(imap_date(0), "1-Jan-1970");
    assert_eq!(imap_date(1_767_225_600), "1-Jan-2026");
    assert_eq!(imap_date(1_709_164_800), "29-Feb-2024");
    assert_eq!(imap_date(1_792_836_000), "24-Oct-2026");
}

// ---- matching -----------------------------------------------------------------

#[test]
fn from_and_subject_filters_ignore_case() {
    let mail = mail("plain.eml");
    let now = sent(&mail) + 60;
    let by = |from: Option<&str>, subject: Option<&str>| Query {
        from: from.map(Into::into),
        subject_contains: subject.map(Into::into),
        ..Query::default()
    };
    assert!(
        by(Some("NO-REPLY@EXAMPLE"), None)
            .matches(&mail, now)
            .is_some()
    );
    assert!(
        by(Some("example service"), None)
            .matches(&mail, now)
            .is_some()
    );
    assert!(
        by(Some("other.example"), None)
            .matches(&mail, now)
            .is_none()
    );
    assert!(by(None, Some("VERIFY YOUR")).matches(&mail, now).is_some());
    assert!(by(None, Some("welcome")).matches(&mail, now).is_none());
}

#[test]
fn only_messages_inside_the_window_match() {
    let mail = mail("plain.eml");
    let query = Query::default();
    assert!(query.matches(&mail, sent(&mail) + 599).is_some());
    assert!(query.matches(&mail, sent(&mail) + 601).is_none());
}

#[test]
fn extract_decides_what_must_be_there() {
    let plain = mail("plain.eml");
    let now = sent(&plain) + 1;
    let only = |extract| Query {
        extract,
        ..Query::default()
    };

    let code = only(Extract::Code).matches(&plain, now).unwrap();
    assert_eq!(code.code.as_deref(), Some("482910"));
    assert_eq!(code.link, None);
    let line = code.to_json();
    assert_eq!(line["code"], "482910");
    assert!(line.get("link").is_none());
    assert_eq!(line["from"], "no-reply@example.com");
    assert_eq!(line["subject"], "Verify your email address");
    assert!(line["date"].as_str().unwrap().starts_with("2026-10-24"));
    assert!(line["text"].as_str().unwrap().contains("verification code"));

    let link = only(Extract::Link).matches(&plain, now).unwrap();
    assert_eq!(link.code, None);
    assert!(link.to_json().get("code").is_none());

    let both = only(Extract::Both).matches(&plain, now).unwrap();
    assert!(both.code.is_some() && both.link.is_some());

    // A message without the thing asked for is not the one being waited for.
    let link_only =
        Mail::parse(b"From: a@b.example\nSubject: Hi\n\nVisit https://x.example/y\n").unwrap();
    assert!(only(Extract::Code).matches(&link_only, now).is_none());
    assert!(only(Extract::Link).matches(&link_only, now).is_some());
    assert!(only(Extract::Both).matches(&link_only, now).is_some());
    let neither = Mail::parse(b"From: a@b.example\nSubject: Hi\n\nNothing to see.\n").unwrap();
    assert!(only(Extract::Both).matches(&neither, now).is_none());
}

#[test]
fn the_task_input_is_checked() {
    assert_eq!(Query::parse(&Value::Null).unwrap(), Query::default());
    assert_eq!(Query::parse(&json!({})).unwrap(), Query::default());
    let query = Query::parse(&json!({ "from": "a", "since_secs": 30, "extract": "link" })).unwrap();
    assert_eq!(query.since_secs, 30);
    assert_eq!(query.extract, Extract::Link);
    for (input, needle) in [
        (json!({ "form": "a" }), "unknown field"),
        (json!({ "since_secs": 0 }), "since_secs"),
        (json!({ "since_secs": 99_999_999 }), "since_secs"),
        (json!({ "extract": "sms" }), "sms"),
        (json!({ "from": "  " }), "`from`"),
        (json!({ "subject_contains": "" }), "`subject_contains`"),
    ] {
        match Query::parse(&input) {
            Err(PluginError::Config(message)) => {
                assert!(message.starts_with("imap: "), "{message}");
                assert!(message.contains(needle), "{message}");
            }
            other => panic!("expected a configuration error for {input}, got {other:?}"),
        }
    }
}

// ---- waiting ------------------------------------------------------------------

/// A clock that moves only when something sleeps.
struct Virtual(Arc<AtomicU64>);

impl Timer for Virtual {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let now = Arc::clone(&self.0);
        Box::pin(async move {
            now.fetch_add(
                u64::try_from(duration.as_millis()).unwrap(),
                Ordering::SeqCst,
            );
        })
    }

    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A source that answers each look from a list, and remembers what it was told.
struct Script {
    answers: Vec<Vec<RawMail>>,
    seen_per_look: Vec<HashSet<u32>>,
}

impl Script {
    fn new(answers: Vec<Vec<RawMail>>) -> Self {
        Self {
            answers,
            seen_per_look: Vec::new(),
        }
    }
}

#[async_trait]
impl MailSource for Script {
    async fn fetch_new(&mut self, _since: u64, seen: &HashSet<u32>) -> Result<Vec<RawMail>> {
        let look = self.seen_per_look.len();
        self.seen_per_look.push(seen.clone());
        Ok(self.answers.get(look).cloned().unwrap_or_default())
    }
}

fn raw(id: u32, name: &str) -> RawMail {
    RawMail {
        id,
        bytes: fixture(name),
    }
}

fn clock_at(start_ms: u64) -> (Clock, Arc<AtomicU64>) {
    let now = Arc::new(AtomicU64::new(start_ms));
    (Clock::new(Arc::new(Virtual(Arc::clone(&now)))), now)
}

#[test]
fn the_wait_looks_again_until_a_message_matches() {
    let start_ms = (sent(&mail("plain.eml")) + 60) * 1000;
    let (clock, now) = clock_at(start_ms);
    let mut source = Script::new(vec![
        vec![],
        vec![raw(5, "html_only.eml")],
        vec![raw(6, "plain.eml"), raw(5, "html_only.eml")],
    ]);
    let query = Query {
        subject_contains: Some("verify your email".into()),
        extract: Extract::Code,
        ..Query::default()
    };
    let found = block_on(wait_for(
        &mut source,
        &query,
        &clock,
        Duration::from_secs(5),
        Duration::from_secs(60),
    ))
    .unwrap();
    assert_eq!(found.code.as_deref(), Some("482910"));
    assert_eq!(source.seen_per_look.len(), 3);
    // The message that did not match is not offered again.
    assert!(source.seen_per_look[2].contains(&5));
    assert!(source.seen_per_look[0].is_empty());
    assert_eq!(now.load(Ordering::SeqCst) - start_ms, 10_000);
}

#[test]
fn the_wait_gives_up_at_the_timeout_and_says_what_it_waited_for() {
    let start_ms = (sent(&mail("plain.eml")) + 60) * 1000;
    let (clock, now) = clock_at(start_ms);
    let mut source = Script::new(Vec::new());
    let query = Query {
        from: Some("bank".into()),
        ..Query::default()
    };
    let error = block_on(wait_for(
        &mut source,
        &query,
        &clock,
        Duration::from_secs(5),
        Duration::from_secs(12),
    ))
    .unwrap_err()
    .to_string();
    assert!(error.contains("imap: no email"), "{error}");
    assert!(error.contains("from `bank`"), "{error}");
    assert!(error.contains("12s"), "{error}");
    // Looks at 0 s, 5 s and 10 s; then the last 2 s are slept and time is up.
    assert_eq!(source.seen_per_look.len(), 3);
    assert_eq!(now.load(Ordering::SeqCst) - start_ms, 12_000);
}

#[test]
fn a_message_outside_the_window_is_skipped_not_returned() {
    // The clock is a day after the message was sent.
    let start_ms = (sent(&mail("plain.eml")) + 86_400) * 1000;
    let (clock, _) = clock_at(start_ms);
    let mut source = Script::new(vec![vec![raw(1, "plain.eml")]]);
    let result = block_on(wait_for(
        &mut source,
        &Query::default(),
        &clock,
        Duration::from_secs(5),
        Duration::from_secs(5),
    ));
    assert!(result.is_err());
}
