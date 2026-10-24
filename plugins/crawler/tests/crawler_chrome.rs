//! The crawler against a small local site in a real headless Chrome. Every test
//! is `#[ignore]`d: they need Chrome and start one headless process per page.
//!
//! The plugin API has no browser of its own, so a small `PageHandle` here
//! remembers the address it was told to go to, and `evaluate` has headless
//! Chrome load that address from a fixture server (`--dump-dom`). The server
//! appends the expression the crawler wants evaluated to the page, so it runs
//! in the real page with its real address, status and links, and the answer is
//! read back out of the dumped page. The crawler code under test is the real
//! one; the fixture server is a `std::net::TcpListener`.
//!
//! Run them alone:
//!
//! ```text
//! cargo test -p seleniumbase-rs-plugin-crawler --test crawler_chrome -- --ignored --test-threads=1
//! ```
//!
//! `SB_TEST_CHROME` names the browser binary; otherwise Google Chrome on macOS,
//! then `google-chrome` and `chromium` on the path.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use seleniumbase_rs_plugin::{
    BrowserFamily, BrowserHandle, Clock, Configurable, Engine, NoPrompt, PageHandle, PluginError,
    PluginSet, Result, TaskContext, TestInfo, TestOutcome, TestVerdict, async_trait,
};
use seleniumbase_rs_plugin_crawler::Crawler;
use seleniumbase_rs_plugin_testing::{ManualTimer, VecSink, block_on};
use serde_json::{Value, json};

static RUNS: AtomicUsize = AtomicUsize::new(0);

fn chrome() -> PathBuf {
    if let Some(path) = std::env::var_os("SB_TEST_CHROME") {
        return PathBuf::from(path);
    }
    let mac = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if mac.exists() {
        return mac.to_path_buf();
    }
    PathBuf::from(if which("google-chrome") {
        "google-chrome"
    } else {
        "chromium"
    })
}

fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).exists()))
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", "\u{a0}")
        .replace("&amp;", "&")
}

// ---- the fixture server ----------------------------------------------------

type Expression = Arc<Mutex<Option<String>>>;

struct Server {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Server {
    /// Serves what `router` answers for a path: a status and the body of the
    /// page. A request while `expression` is set gets a script that evaluates
    /// it and writes the JSON answer into the page.
    fn start(
        expression: Expression,
        router: impl Fn(&str) -> Option<(u16, String)> + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free local port");
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                handle(stream, &router, &log, &expression);
            }
        });
        Self { port, requests }
    }

    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// The paths requested, each once, in the order they first came. Chrome
    /// asks for the root of a site once more on every start, so a path is not
    /// counted twice.
    fn pages(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for path in self.requests() {
            if !seen.contains(&path) {
                seen.push(path);
            }
        }
        seen
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn handle(
    mut stream: TcpStream,
    router: &impl Fn(&str) -> Option<(u16, String)>,
    log: &Mutex<Vec<String>>,
    expression: &Expression,
) {
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(clone);
    let mut first = String::new();
    if reader.read_line(&mut first).is_err() {
        return;
    }
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break,
            Ok(_) => {}
        }
    }
    let path = first.split_whitespace().nth(1).unwrap_or("/").to_owned();
    let (status, body) = if path == "/favicon.ico" {
        (404, String::new())
    } else {
        log.lock().unwrap().push(path.clone());
        let (status, inner) = router(&path).unwrap_or((404, "<h1>Not found</h1>".to_owned()));
        let injected = expression
            .lock()
            .unwrap()
            .as_deref()
            .map(inject)
            .unwrap_or_default();
        (
            status,
            format!(
                "<!doctype html><html><head><meta charset=\"utf-8\"><title>Fixture {path}</title>\
                 </head><body>{inner}{injected}</body></html>"
            ),
        )
    };
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn inject(expression: &str) -> String {
    format!(
        "<pre id=\"sbrs-out\"></pre><script>(function () {{\
           var out = document.getElementById('sbrs-out');\
           try {{ Promise.resolve({expression}).then(\
             function (v) {{ out.textContent = JSON.stringify(v); }},\
             function (e) {{ out.textContent = JSON.stringify({{ error: String(e) }}); }});\
           }} catch (e) {{ out.textContent = JSON.stringify({{ error: String(e) }}); }}\
         }})();</script>"
    )
}

// ---- the tab ---------------------------------------------------------------------

/// Evaluates `expression` in the page at `url`, in headless Chrome.
fn run_in_chrome(
    url: &str,
    expression: &Expression,
    script: &str,
) -> std::result::Result<Value, String> {
    let dir = std::env::temp_dir().join(format!(
        "sbrs-crawler-{}-{}",
        std::process::id(),
        RUNS.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    *expression.lock().unwrap() = Some(script.to_owned());
    let output = Command::new(chrome())
        .args([
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--no-first-run",
            "--disable-extensions",
            "--disable-background-networking",
        ])
        .arg(format!("--user-data-dir={}", dir.join("profile").display()))
        .arg("--dump-dom")
        .arg(url)
        .output();
    *expression.lock().unwrap() = None;
    let output = output.map_err(|e| format!("could not start Chrome: {e}"))?;
    let dumped = String::from_utf8_lossy(&output.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&dir);
    let open = "<pre id=\"sbrs-out\">";
    let start = dumped.find(open).ok_or_else(|| {
        format!(
            "no answer in the dumped page of {url}: {}",
            &dumped[..dumped.len().min(300)]
        )
    })? + open.len();
    let end = dumped[start..]
        .find("</pre>")
        .ok_or("unterminated answer")?
        + start;
    let text = unescape(&dumped[start..end]);
    if text.is_empty() {
        return Err("the page script gave no answer".into());
    }
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("{e}: {text}"))?;
    match value.get("error") {
        Some(error) if value.as_object().is_some_and(|o| o.len() == 1) => Err(error.to_string()),
        _ => Ok(value),
    }
}

#[derive(Clone)]
struct ChromeTab {
    expression: Expression,
    current: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl PageHandle for ChromeTab {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }

    async fn send(&self, _method: &str, _params: Value) -> Result<Value> {
        Ok(Value::Null)
    }

    async fn add_init_script(&self, _source: &str) -> Result<()> {
        Ok(())
    }

    async fn evaluate(&self, expression: &str) -> Result<Value> {
        let url = self
            .current
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| PluginError::other("evaluate before navigate"))?;
        run_in_chrome(&url, &self.expression, expression)
            .map_err(|why| PluginError::other(format!("chrome: {why}")))
    }

    async fn navigate(&self, url: &str) -> Result<()> {
        *self.current.lock().unwrap() = Some(url.to_owned());
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

struct ChromeBrowser {
    tab: ChromeTab,
}

#[async_trait]
impl BrowserHandle for ChromeBrowser {
    fn engine(&self) -> Engine {
        Engine::Cdp
    }

    fn family(&self) -> BrowserFamily {
        BrowserFamily::Chromium
    }

    async fn new_page<'a>(&'a self, _url: Option<&str>) -> Result<Box<dyn PageHandle + 'a>> {
        Ok(Box::new(self.tab.clone()))
    }

    async fn send(&self, _method: &str, _params: Value) -> Result<Value> {
        Ok(Value::Null)
    }
}

// ---- the site ------------------------------------------------------------------

/// The local site: a home page with a planted broken link, a link that
/// robots.txt forbids, and a link to another origin.
fn site(outside: String) -> impl Fn(&str) -> Option<(u16, String)> + Send + 'static {
    move |path| match path {
        "/" => Some((
            200,
            format!(
                "<h1>Home</h1><a href=\"/a\">a</a> <a href=\"/missing\">gone</a> \
                 <a href=\"/private/x\">private</a> <a href=\"{outside}/outside\">elsewhere</a> \
                 <a href=\"mailto:someone@example.test\">mail</a>"
            ),
        )),
        "/a" => Some((
            200,
            "<h1>A</h1><a href=\"/\">home</a> <a href=\"/a/deep#section\">deep</a>".to_owned(),
        )),
        "/a/deep" => Some((200, "<h1>Deep</h1>".to_owned())),
        "/missing" => Some((404, "<h1>Gone</h1>".to_owned())),
        "/private/x" => Some((200, "<h1>Private</h1>".to_owned())),
        "/robots.txt" => Some((
            200,
            "<pre>User-agent: *\nDisallow: /private\n</pre>".to_owned(),
        )),
        _ => None,
    }
}

#[test]
#[ignore = "needs Chrome"]
fn a_local_site_with_a_broken_link_fails_the_test_with_the_summary_and_never_leaves_its_origin() {
    let expression: Expression = Arc::default();
    let other = Server::start(Arc::clone(&expression), |_| {
        Some((200, "<h1>Outside</h1>".to_owned()))
    });
    let main = Server::start(Arc::clone(&expression), site(other.base()));

    let crawler = Crawler::configure(&json!({
        "start": [format!("{}/", main.base())],
        "delay_ms": 0,
        "max_depth": 3,
    }))
    .unwrap();
    let set = PluginSet::strict().with(crawler).unwrap();
    let browser = ChromeBrowser {
        tab: ChromeTab {
            expression,
            current: Arc::default(),
        },
    };
    let sink = VecSink::new();
    let clock = Clock::new(Arc::new(ManualTimer::new()));
    let input = json!({});
    let cx = TaskContext::new(&browser, &input, &sink, &set, &clock, &NoPrompt);
    let summary = block_on(set.task("crawler").unwrap().run(&cx)).unwrap();

    let base = main.base();
    assert_eq!(
        main.pages(),
        ["/robots.txt", "/", "/a", "/missing", "/a/deep"],
        "{summary}"
    );
    assert!(
        other.requests().is_empty(),
        "the other origin was visited: {:?}",
        other.requests()
    );
    assert_eq!(summary["pages"], 4);
    assert_eq!(summary["robots_blocked"], 1);
    assert_eq!(summary["passed"], false);
    assert_eq!(
        summary["broken"],
        json!([{ "url": format!("{base}/missing"), "from": format!("{base}/"), "status": 404 }])
    );
    assert_eq!(
        summary["summary"],
        format!("Broken link detected:\n{base}/missing")
    );

    let lines = sink.lines();
    assert_eq!(lines[0]["title"], "Fixture /");
    assert_eq!(lines[0]["status"], 200);
    assert_eq!(
        lines[0]["links"], 4,
        "mailto: is not a link the crawler reads"
    );
    assert!(lines.iter().any(|l| l["skipped"] == "robots.txt"));

    let (verdict, failures) = block_on(set.on_test_end(
        &TestInfo::new("crawl the fixture"),
        &TestOutcome::Passed,
        None,
    ));
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(
        verdict,
        TestVerdict::Fail(format!("Broken link detected:\n{base}/missing"))
    );
}
