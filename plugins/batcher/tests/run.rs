//! The batcher's task against the plugin API's fakes: no browser.

mod support;

use std::time::Duration;

use seleniumbase_rs_plugin::{
    Capability, CapabilitySet, Configurable, ContextSettings, NoPrompt, Plugin, PluginError,
    PluginSet, TaskContext,
};
use seleniumbase_rs_plugin_fetcher::Fetcher;
use seleniumbase_rs_plugin_testing::{Call, RecordingBrowser};
use serde_json::{Value, json};
use support::{Mode, Plain, Rig, Worker, batcher, indexes, jobs, poll_once, set_with};

fn config_error(result: Result<Value, PluginError>) -> String {
    match result {
        Err(PluginError::Config(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

// ---- concurrency, chunks, order ------------------------------------------------

#[test]
fn ten_jobs_at_concurrency_two_write_ten_records_and_never_hold_more_than_two_tabs() {
    let worker = Worker::new("worker", Mode::Echo);
    let set = set_with(json!({ "runner": "worker" }), &[&worker]);
    let rig = Rig::new();
    let summary = rig.run(&set, &jobs(10, 3)).unwrap();
    assert_eq!(
        summary,
        json!({ "total": 10, "ok": 10, "failed": 0, "skipped": 0, "retried": 0, "chunks": 1 })
    );

    let lines = rig.sink.lines();
    assert_eq!(lines.len(), 10);
    let mut seen = indexes(&lines);
    seen.sort_unstable();
    assert_eq!(seen, (0..10).collect::<Vec<_>>());
    for line in &lines {
        assert_eq!(line["chunk"], 0);
        assert_eq!(line["outcome"]["status"], "ok");
        assert_eq!(line["outcome"]["attempts"], 1);
        assert_eq!(line["outcome"]["result"]["echo"], line["job"]);
    }

    assert_eq!(rig.browser.max_live_pages(), 2);
    assert!(rig.browser.max_live_contexts() <= 2);
    assert_eq!(rig.browser.max_live_contexts(), 1);
    assert_eq!(rig.browser.pages_made(), 10);
    assert_eq!(rig.browser.live_pages(), 0);
    assert_eq!(rig.browser.live_contexts(), 0);
    assert_eq!(worker.total(), 10);
}

#[test]
fn the_number_of_tabs_at_work_follows_concurrency_and_the_number_of_jobs() {
    for (width, count, expected) in [(1, 6, 1), (3, 12, 3), (4, 12, 4), (8, 3, 3), (32, 40, 32)] {
        let worker = Worker::new("worker", Mode::Echo);
        let set = set_with(
            json!({ "runner": "worker", "concurrency": width, "chunk_size": 100 }),
            &[&worker],
        );
        let rig = Rig::new();
        rig.run(&set, &jobs(count, 4)).unwrap();
        assert_eq!(
            rig.browser.max_live_pages(),
            expected,
            "concurrency {width}, {count} jobs"
        );
        assert_eq!(rig.sink.lines().len() as u64, count);
        assert_eq!(rig.browser.live_pages(), 0);
    }
}

#[test]
fn a_chunk_is_a_context_of_its_own_and_chunks_run_one_after_the_other() {
    let worker = Worker::new("worker", Mode::Echo);
    let set = set_with(
        json!({ "runner": "worker", "chunk_size": 3, "ordered": true }),
        &[&worker],
    );
    let rig = Rig::new();
    let summary = rig.run(&set, &jobs(7, 2)).unwrap();
    assert_eq!(summary["chunks"], 3);
    assert_eq!(rig.browser.contexts_made(), 3);
    assert_eq!(rig.browser.max_live_contexts(), 1);
    assert_eq!(rig.browser.live_contexts(), 0);

    let lines = rig.sink.lines();
    let chunks: Vec<u64> = lines.iter().map(|l| l["chunk"].as_u64().unwrap()).collect();
    assert_eq!(chunks, [0, 0, 0, 1, 1, 1, 2]);
    assert_eq!(indexes(&lines), [0, 1, 2, 3, 4, 5, 6]);

    let contexts = rig.browser.contexts();
    let sizes: Vec<usize> = contexts.iter().map(|c| c.pages().len()).collect();
    assert_eq!(sizes, [3, 3, 1]);
    assert!(contexts.iter().all(|c| c.disposed()));
    // A context is made with no proxy of its own: privacy plugins set theirs
    // in `before_context`.
    let made = rig
        .browser
        .calls()
        .into_iter()
        .filter(|call| matches!(call, Call::NewContext(_)))
        .count();
    assert_eq!(made, 3);
    assert!(
        contexts
            .iter()
            .all(|c| *c.settings() == ContextSettings::new())
    );
}

#[test]
fn records_come_in_the_order_the_jobs_finish_unless_ordered_asks_for_the_input_order() {
    let input = json!({ "jobs": [
        { "n": 0, "yields": 6 }, { "n": 1, "yields": 0 }, { "n": 2, "yields": 0 },
    ]});
    for (ordered, expected) in [(false, vec![1, 2, 0]), (true, vec![0, 1, 2])] {
        let worker = Worker::new("worker", Mode::Echo);
        let set = set_with(
            json!({ "runner": "worker", "concurrency": 2, "ordered": ordered }),
            &[&worker],
        );
        let rig = Rig::new();
        rig.run(&set, &input).unwrap();
        assert_eq!(indexes(&rig.sink.lines()), expected, "ordered = {ordered}");
    }
}

// ---- retries, denials, limits ------------------------------------------------------

#[test]
fn a_failing_job_is_tried_again_up_to_retries_and_the_record_says_how_often() {
    let input = jobs(1, 0);
    for (retries, ok, attempts) in [(2, true, 3), (1, false, 2), (0, false, 1)] {
        let worker = Worker::new("worker", Mode::FailTimes(2));
        let set = set_with(
            json!({ "runner": "worker", "retries": retries, "backoff_ms": 0 }),
            &[&worker],
        );
        let rig = Rig::new();
        let summary = rig.run(&set, &input).unwrap();
        let line = &rig.sink.lines()[0];
        assert_eq!(line["outcome"]["attempts"], attempts, "retries {retries}");
        assert_eq!(worker.total(), attempts as usize);
        assert_eq!(summary["retried"], attempts - 1);
        if ok {
            assert_eq!(line["outcome"]["status"], "ok");
            assert_eq!(line["outcome"]["result"]["tries"], 3);
            assert_eq!(summary["ok"], 1);
        } else {
            assert_eq!(line["outcome"]["status"], "failed");
            assert!(
                line["outcome"]["error"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("ERR_CONNECTION_RESET (try {attempts})")),
                "{line}"
            );
            assert!(line["outcome"].get("denied").is_none());
            assert_eq!(summary["failed"], 1);
        }
        // Every try had a tab of its own, and every tab was closed.
        assert_eq!(rig.browser.pages_made(), attempts as usize);
        assert_eq!(rig.browser.live_pages(), 0);
    }
}

#[test]
fn a_job_a_plugin_denied_is_never_tried_again() {
    for (mode, text) in [
        (Mode::Cancelled, "cancelled by plugin policy"),
        (Mode::Blocked, "ERR_BLOCKED_BY_CLIENT"),
    ] {
        let worker = Worker::new("worker", Mode::Echo);
        let denying = Worker::new("denier", mode);
        let set = set_with(
            json!({ "runner": "denier", "retries": 3, "backoff_ms": 0 }),
            &[&worker, &denying],
        );
        let rig = Rig::new();
        let summary = rig.run(&set, &jobs(2, 0)).unwrap();
        assert_eq!(denying.total(), 2, "{text}: one try for each job");
        let lines = rig.sink.lines();
        for line in &lines {
            assert_eq!(line["outcome"]["status"], "failed");
            assert_eq!(line["outcome"]["attempts"], 1);
            assert_eq!(line["outcome"]["denied"], true);
            assert!(line["outcome"]["error"].as_str().unwrap().contains(text));
        }
        assert_eq!(summary["failed"], 2);
        assert_eq!(summary["retried"], 0);
    }
}

#[test]
fn a_bad_job_is_a_failed_line_and_is_not_tried_again() {
    let set = PluginSet::strict()
        .with(batcher(json!({ "retries": 3, "backoff_ms": 0 })))
        .unwrap();
    let rig = Rig::new();
    let input = json!({ "jobs": [
        { "url": "ftp://a.test/" }, { "link": "https://a.test/" }, { "url": "https://a.test/ok" },
    ]});
    let summary = rig.run(&set, &input).unwrap();
    assert_eq!(summary["failed"], 2);
    assert_eq!(summary["ok"], 1);
    assert_eq!(summary["retried"], 0);
    let mut lines = rig.sink.lines();
    lines.sort_by_key(|l| l["index"].as_u64());
    assert!(
        lines[0]["outcome"]["error"]
            .as_str()
            .unwrap()
            .contains("not an http or https")
    );
    assert!(
        lines[1]["outcome"]["error"]
            .as_str()
            .unwrap()
            .contains("bad job")
    );
    assert_eq!(lines[2]["outcome"]["status"], "ok");
    assert!(lines.iter().all(|l| l["outcome"]["attempts"] == 1));
    assert_eq!(rig.browser.live_pages(), 0);
}

#[test]
fn a_missing_capability_ends_the_run_and_still_closes_the_context_and_its_tabs() {
    let worker = Worker::new("worker", Mode::Capability);
    let set = set_with(json!({ "runner": "worker", "retries": 3 }), &[&worker]);
    let rig = Rig::new();
    let error = rig.run(&set, &jobs(6, 1)).unwrap_err();
    assert!(
        matches!(&error, PluginError::Capability { capability, .. } if capability == "page.navigate"),
        "{error:?}"
    );
    assert!(rig.sink.lines().is_empty());
    assert_eq!(rig.browser.live_contexts(), 0);
    assert_eq!(rig.browser.live_pages(), 0);
    assert!(rig.browser.contexts()[0].disposed());
}

#[test]
fn the_pause_before_a_retry_doubles_by_the_clock() {
    let worker = Worker::new("worker", Mode::FailTimes(9));
    let set = set_with(
        json!({ "runner": "worker", "retries": 3, "backoff_ms": 100, "concurrency": 1 }),
        &[&worker],
    );
    let rig = Rig::new();
    let input = jobs(1, 0);
    let cx = TaskContext::new(&rig.browser, &input, &rig.sink, &set, &rig.clock, &NoPrompt);
    let mut run = Box::pin(set.task("batcher").unwrap().run(&cx));

    assert!(poll_once(&mut run).is_pending());
    assert_eq!(worker.total(), 1, "first try, then a pause of 100 ms");
    rig.timer.advance(Duration::from_millis(99));
    assert!(poll_once(&mut run).is_pending());
    assert_eq!(worker.total(), 1);
    rig.timer.advance(Duration::from_millis(1));
    assert!(poll_once(&mut run).is_pending());
    assert_eq!(worker.total(), 2, "second try, then 200 ms");
    rig.timer.advance(Duration::from_millis(199));
    assert!(poll_once(&mut run).is_pending());
    assert_eq!(worker.total(), 2);
    rig.timer.advance(Duration::from_millis(1));
    assert!(poll_once(&mut run).is_pending());
    assert_eq!(worker.total(), 3, "third try, then 400 ms");
    rig.timer.advance(Duration::from_millis(400));
    let summary = match poll_once(&mut run) {
        std::task::Poll::Ready(summary) => summary.unwrap(),
        std::task::Poll::Pending => panic!("the fourth try is the last"),
    };
    assert_eq!(worker.total(), 4);
    assert_eq!(summary["failed"], 1);
    assert_eq!(summary["retried"], 3);
}

#[test]
fn a_job_that_never_answers_is_cut_off_at_the_time_limit_and_its_tab_is_closed() {
    for (retries, attempts) in [(0_u8, 1_u64), (1, 2)] {
        let worker = Worker::new("worker", Mode::Stuck);
        let set = set_with(
            json!({ "runner": "worker", "job_timeout_secs": 5, "retries": retries, "backoff_ms": 0 }),
            &[&worker],
        );
        let rig = Rig::new();
        let input = jobs(1, 0);
        let cx = TaskContext::new(&rig.browser, &input, &rig.sink, &set, &rig.clock, &NoPrompt);
        let mut run = Box::pin(set.task("batcher").unwrap().run(&cx));

        assert!(poll_once(&mut run).is_pending());
        assert_eq!(rig.browser.live_pages(), 1);
        rig.timer.advance(Duration::from_secs(4));
        assert!(poll_once(&mut run).is_pending(), "one second left");
        let mut finished = None;
        for _ in 0..attempts {
            rig.timer.advance(Duration::from_secs(5));
            if let std::task::Poll::Ready(summary) = poll_once(&mut run) {
                finished = Some(summary.unwrap());
            }
        }
        let summary = finished.expect("the run ended");
        assert_eq!(summary["failed"], 1);
        assert_eq!(summary["retried"], attempts - 1);
        let line = &rig.sink.lines()[0];
        assert_eq!(line["outcome"]["attempts"], attempts);
        assert_eq!(line["outcome"]["error"], "timed out after 5s");
        assert_eq!(rig.browser.live_pages(), 0);
        let pages = rig.browser.contexts()[0].pages();
        assert_eq!(pages.len() as u64, attempts);
        assert!(pages.iter().all(|page| page.calls().contains(&Call::Close)));
    }
}

#[test]
fn a_run_with_more_jobs_than_max_jobs_or_a_bad_input_opens_no_context() {
    let worker = Worker::new("worker", Mode::Echo);
    let set = set_with(json!({ "runner": "worker", "max_jobs": 3 }), &[&worker]);
    let cases = [
        (jobs(4, 0), "batcher: too many jobs"),
        (json!({}), "needs `jobs`"),
        (Value::Null, "needs `jobs`"),
        (json!({ "jobs": [] }), "empty"),
        (json!({ "jobs": "a.test" }), "bad task input"),
        (json!({ "jobs": [1], "urls": ["a"] }), "bad task input"),
    ];
    for (input, expected) in cases {
        let rig = Rig::new();
        let message = config_error(rig.run(&set, &input));
        assert!(message.contains(expected), "{input}: {message}");
        assert_eq!(rig.browser.contexts_made(), 0);
        assert!(rig.sink.lines().is_empty());
    }
    // Exactly max_jobs is fine.
    Rig::new().run(&set, &jobs(3, 0)).unwrap();
}

#[test]
fn a_browser_that_cannot_make_a_context_fails_the_run_before_any_job() {
    let worker = Worker::new("worker", Mode::Echo);
    let set = set_with(json!({ "runner": "worker" }), &[&worker]);
    let rig = Rig::with_browser(
        RecordingBrowser::new()
            .with_contexts()
            .failing("new_context"),
    );
    let error = rig.run(&set, &jobs(3, 0)).unwrap_err();
    assert!(error.to_string().contains("new_context failed"), "{error}");
    assert_eq!(worker.total(), 0);
    assert!(rig.sink.lines().is_empty());
    // A browser that offers no contexts at all says so.
    let plain = Rig::with_browser(RecordingBrowser::new());
    let error = plain.run(&set, &jobs(1, 0)).unwrap_err();
    assert!(matches!(error, PluginError::NotSupported(_)), "{error:?}");
}

// ---- runners -------------------------------------------------------------------------

#[test]
fn the_open_runner_opens_each_address_and_records_its_title_and_url() {
    let set = PluginSet::strict()
        .with(batcher(json!({ "ordered": true })))
        .unwrap();
    let rig = Rig::new();
    let input =
        json!({ "jobs": [{ "url": "https://a.test/1" }, { "url": "https://b.test/2?q=1" }] });
    let summary = rig.run(&set, &input).unwrap();
    assert_eq!(summary["ok"], 2);
    let lines = rig.sink.lines();
    assert_eq!(
        lines[0]["outcome"]["result"],
        json!({ "title": "", "url": "https://a.test/1" })
    );
    assert_eq!(
        lines[1]["outcome"]["result"],
        json!({ "title": "", "url": "https://b.test/2?q=1" })
    );
    let mut opened = Vec::new();
    for page in rig.browser.contexts()[0].pages() {
        match page.calls().as_slice() {
            [
                Call::Navigate(url),
                Call::Evaluate(script),
                Call::Url,
                Call::Close,
            ] => {
                assert_eq!(script, "document.title");
                opened.push(url.clone());
            }
            other => panic!("unexpected calls: {other:?}"),
        }
    }
    opened.sort();
    assert_eq!(opened, ["https://a.test/1", "https://b.test/2?q=1"]);
}

#[test]
fn a_runner_by_name_is_found_in_the_set_or_the_run_does_not_start() {
    let rig = Rig::new();
    let alone = PluginSet::strict()
        .with(batcher(json!({ "runner": "ghost" })))
        .unwrap();
    let message = config_error(rig.run(&alone, &jobs(1, 0)));
    assert!(message.contains("runner `ghost`"), "{message}");

    let set = PluginSet::strict()
        .with(batcher(json!({ "runner": "plain" })))
        .unwrap()
        .with(Plain)
        .unwrap();
    let message = config_error(rig.run(&set, &jobs(1, 0)));
    assert!(
        message.contains("runner `plain`") && message.contains("offers no job runner"),
        "{message}"
    );
    assert_eq!(rig.browser.contexts_made(), 0);
}

#[test]
fn the_runner_of_another_plugin_gets_the_tab_with_that_plugins_capabilities_only() {
    let worker = Worker::new("worker", Mode::Evaluate);
    // With everything the worker declares the job runs.
    let set = set_with(json!({ "runner": "worker" }), &[&worker]);
    let rig = Rig::new();
    rig.run(&set, &jobs(1, 0)).unwrap();
    assert_eq!(
        rig.sink.lines()[0]["outcome"]["result"],
        json!({ "value": null })
    );

    // Without `page.evaluate` its tab refuses the script, and the run stops.
    let mut grants = CapabilitySet::new();
    grants.insert(Capability::PageNavigate);
    let set = PluginSet::strict()
        .with(batcher(json!({ "runner": "worker" })))
        .unwrap()
        .with_grants_shared(worker.clone() as std::sync::Arc<dyn Plugin>, grants)
        .unwrap();
    let rig = Rig::new();
    let error = rig.run(&set, &jobs(1, 0)).unwrap_err();
    assert!(
        matches!(&error, PluginError::Capability { plugin, capability, .. }
            if plugin == "worker" && capability == "page.evaluate"),
        "{error:?}"
    );
    assert_eq!(rig.browser.live_pages(), 0);
    assert_eq!(rig.browser.live_contexts(), 0);
}

#[test]
fn the_fetcher_is_reached_by_name_and_its_tab_visits_the_site_first() {
    let fetcher = Fetcher::configure(&Value::Null).unwrap();
    let set = PluginSet::strict()
        .with(batcher(json!({ "runner": "fetcher", "retries": 0 })))
        .unwrap()
        .with(fetcher)
        .unwrap();
    assert!(set.job_runner("fetcher").is_ok());
    let rig = Rig::new();
    let input = json!({ "jobs": [{ "url": "https://a.test/api/1" }] });
    let summary = rig.run(&set, &input).unwrap();
    // The fake tab has no page to answer the fetch: the fetcher's own error
    // comes back as the record.
    assert_eq!(summary["failed"], 1);
    let error = rig.sink.lines()[0]["outcome"]["error"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        error.contains("fetcher: unexpected reply from the page"),
        "{error}"
    );
    let calls = rig.browser.contexts()[0].pages()[0].calls();
    assert_eq!(calls[0], Call::Navigate("https://a.test/".into()));
    assert!(matches!(&calls[1], Call::Evaluate(script) if script.contains("https://a.test/api/1")));
    assert_eq!(calls[2], Call::Close);
}

#[test]
fn warm_up_visits_the_site_of_a_job_when_asked_and_not_otherwise() {
    let cases = [
        // (options, expected navigations)
        (json!({ "runner": "worker" }), vec![]),
        (
            json!({ "runner": "worker", "warm_up": true }),
            vec!["https://a.test/"],
        ),
        (json!({ "runner": "worker", "warm_up": false }), vec![]),
    ];
    for (options, expected) in cases {
        let worker = Worker::new("worker", Mode::Echo);
        let set = set_with(options.clone(), &[&worker]);
        let rig = Rig::new();
        rig.run(
            &set,
            &json!({ "jobs": [{ "n": 0, "url": "https://A.test/page?x=1" }] }),
        )
        .unwrap();
        let navigations: Vec<String> = rig.browser.contexts()[0].pages()[0]
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Navigate(url) => Some(url),
                _ => None,
            })
            .collect();
        assert_eq!(navigations, expected, "{options}");
    }
    // A job whose address cannot be visited fails that job, not the run.
    let worker = Worker::new("worker", Mode::Echo);
    let set = set_with(json!({ "runner": "worker", "warm_up": true }), &[&worker]);
    let rig = Rig::new();
    let summary = rig
        .run(
            &set,
            &json!({ "jobs": [{ "n": 0, "url": "file:///etc/hosts" }, { "n": 1 }] }),
        )
        .unwrap();
    assert_eq!(
        (summary["failed"].as_u64(), summary["ok"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(worker.total(), 1);
}

#[test]
fn the_task_is_found_by_name_and_does_nothing_until_it_is_polled() {
    let worker = Worker::new("worker", Mode::Echo);
    let set = set_with(json!({ "runner": "worker" }), &[&worker]);
    assert_eq!(set.task_names(), ["batcher"]);
    let rig = Rig::new();
    let input = jobs(2, 0);
    let cx = TaskContext::new(&rig.browser, &input, &rig.sink, &set, &rig.clock, &NoPrompt);
    drop(set.task("batcher").unwrap().run(&cx));
    assert_eq!(rig.browser.contexts_made(), 0);
    assert_eq!(worker.total(), 0);
}
