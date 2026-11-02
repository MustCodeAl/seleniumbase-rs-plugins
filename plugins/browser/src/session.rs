//! Saved sessions: the cookies of a browser kept in a file, so that a later
//! browser starts signed in.
//!
//! The file holds credentials. Nothing here puts a cookie value into an error,
//! a log line or a `Debug` output.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use seleniumbase_rs_plugin::{BrowserHandle, PluginError, Result};
use serde_json::{Map, Value, json};

use crate::config::{DEFAULT_SESSION_DIR, SessionConfig};

/// The format of the session files this plugin writes and reads.
const FORMAT_VERSION: u64 = 1;

/// A session file larger than this is not read, and one that would be larger
/// is not written.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// The most cookies a session file may hold.
const MAX_COOKIES: usize = 5000;

/// The values of `sameSite`, `priority` and `sourceScheme` the protocol has.
const SAME_SITE: &[&str] = &["Strict", "Lax", "None"];
const PRIORITY: &[&str] = &["Low", "Medium", "High"];
const SOURCE_SCHEME: &[&str] = &["Unset", "NonSecure", "Secure"];

/// The fields of a cookie object.
type Fields = Map<String, Value>;

/// One cookie, with the fields the plugin keeps (the ones `Network.CookieParam`
/// takes) and no others. The value is a credential, so `Debug` shows nothing.
#[derive(Clone, PartialEq)]
pub(crate) struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    /// Seconds since the Unix epoch; `None` for a session cookie.
    expires: Option<f64>,
    http_only: bool,
    secure: bool,
    same_site: Option<&'static str>,
    priority: Option<&'static str>,
    source_scheme: Option<&'static str>,
    source_port: Option<i64>,
    partition_key: Option<Value>,
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cookie").finish_non_exhaustive()
    }
}

/// A text field that must be there.
fn required_text(fields: &Fields, field: &str) -> std::result::Result<String, String> {
    match fields.get(field) {
        Some(Value::String(text)) => Ok(text.clone()),
        _ => Err(format!("`{field}` is missing or is not text")),
    }
}

/// A true-or-false field; missing means false.
fn flag(fields: &Fields, field: &str) -> std::result::Result<bool, String> {
    match fields.get(field) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(on)) => Ok(*on),
        _ => Err(format!("`{field}` is not true or false")),
    }
}

/// A field that is one of `allowed`. `lenient` drops a value that is not
/// (what a browser reports may know more than this plugin); otherwise it is
/// an error. The error never repeats the value.
fn choice(
    fields: &Fields,
    field: &str,
    allowed: &[&'static str],
    lenient: bool,
) -> std::result::Result<Option<&'static str>, String> {
    match fields.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => {
            match allowed
                .iter()
                .copied()
                .find(|known| *known == text.as_str())
            {
                Some(known) => Ok(Some(known)),
                None if lenient => Ok(None),
                None => Err(format!("`{field}` is not a value this plugin knows")),
            }
        }
        Some(_) if lenient => Ok(None),
        Some(_) => Err(format!("`{field}` is not text")),
    }
}

/// `expires`: a positive time, or none for a session cookie (the browser says
/// `-1` for those).
fn expiry(fields: &Fields) -> std::result::Result<Option<f64>, String> {
    match fields.get("expires") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(time)) => Ok(time
            .as_f64()
            .filter(|seconds| seconds.is_finite() && *seconds > 0.0)),
        Some(_) => Err("`expires` is not a number".to_owned()),
    }
}

/// `sourcePort`: -1 (unspecified) or a port number.
fn source_port(fields: &Fields, lenient: bool) -> std::result::Result<Option<i64>, String> {
    match fields.get("sourcePort") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(port)) => match port.as_i64() {
            Some(port) if port == -1 || (1..=65535).contains(&port) => Ok(Some(port)),
            _ if lenient => Ok(None),
            _ => Err("`sourcePort` is not a port number".to_owned()),
        },
        Some(_) if lenient => Ok(None),
        Some(_) => Err("`sourcePort` is not a number".to_owned()),
    }
}

/// `partitionKey`: older browsers say a text, newer ones an object of which
/// only `topLevelSite` and `hasCrossSiteAncestor` are kept.
fn partition_key(fields: &Fields, lenient: bool) -> std::result::Result<Option<Value>, String> {
    match fields.get("partitionKey") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(site)) => Ok(Some(Value::String(site.clone()))),
        Some(Value::Object(object)) => match object.get("topLevelSite") {
            Some(Value::String(site)) => {
                let mut key = Map::new();
                key.insert("topLevelSite".to_owned(), Value::String(site.clone()));
                if let Some(Value::Bool(cross)) = object.get("hasCrossSiteAncestor") {
                    key.insert("hasCrossSiteAncestor".to_owned(), Value::Bool(*cross));
                }
                Ok(Some(Value::Object(key)))
            }
            _ if lenient => Ok(None),
            _ => Err("`partitionKey` has no `topLevelSite`".to_owned()),
        },
        Some(_) if lenient => Ok(None),
        Some(_) => Err("`partitionKey` is not text or an object".to_owned()),
    }
}

impl Cookie {
    /// Reads one cookie. `lenient` is for what a browser reports: optional
    /// fields with a value this plugin does not know are dropped. A session
    /// file is read strictly. The error names a field and never a value.
    fn parse(cookie: &Value, lenient: bool) -> std::result::Result<Self, String> {
        let Some(fields) = cookie.as_object() else {
            return Err("it is not an object".to_owned());
        };
        let domain = required_text(fields, "domain")?;
        if domain.is_empty() {
            return Err("`domain` is empty".to_owned());
        }
        let path = required_text(fields, "path")?;
        if !path.starts_with('/') {
            return Err("`path` does not start with `/`".to_owned());
        }
        Ok(Self {
            name: required_text(fields, "name")?,
            value: required_text(fields, "value")?,
            domain,
            path,
            expires: expiry(fields)?,
            http_only: flag(fields, "httpOnly")?,
            secure: flag(fields, "secure")?,
            same_site: choice(fields, "sameSite", SAME_SITE, lenient)?,
            priority: choice(fields, "priority", PRIORITY, lenient)?,
            source_scheme: choice(fields, "sourceScheme", SOURCE_SCHEME, lenient)?,
            source_port: source_port(fields, lenient)?,
            partition_key: partition_key(fields, lenient)?,
        })
    }

    /// The cookie as `Network.CookieParam` and the session file have it: the
    /// kept fields only.
    fn to_value(&self) -> Value {
        let mut fields = Map::new();
        fields.insert("name".to_owned(), json!(self.name));
        fields.insert("value".to_owned(), json!(self.value));
        fields.insert("domain".to_owned(), json!(self.domain));
        fields.insert("path".to_owned(), json!(self.path));
        if let Some(expires) = self.expires {
            fields.insert("expires".to_owned(), json!(expires));
        }
        fields.insert("httpOnly".to_owned(), json!(self.http_only));
        fields.insert("secure".to_owned(), json!(self.secure));
        for (field, value) in [
            ("sameSite", self.same_site),
            ("priority", self.priority),
            ("sourceScheme", self.source_scheme),
        ] {
            if let Some(value) = value {
                fields.insert(field.to_owned(), json!(value));
            }
        }
        if let Some(port) = self.source_port {
            fields.insert("sourcePort".to_owned(), json!(port));
        }
        if let Some(key) = &self.partition_key {
            fields.insert("partitionKey".to_owned(), key.clone());
        }
        Value::Object(fields)
    }

    /// Whether the cookie had expired at `now` (seconds since the epoch).
    fn expired(&self, now: f64) -> bool {
        self.expires.is_some_and(|expires| expires <= now)
    }
}

/// Seconds since the Unix epoch.
fn unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

/// The cookies of a session file's `bytes`. The error continues the sentence
/// "the file ..." and holds no value of the file: `serde_json` quotes the
/// value it did not like, so only the line and column of a syntax error are
/// kept.
fn parse_file(bytes: &[u8]) -> std::result::Result<Vec<Cookie>, String> {
    let file: Value = serde_json::from_slice(bytes).map_err(|error| {
        format!(
            "is not valid JSON (line {}, column {})",
            error.line(),
            error.column()
        )
    })?;
    let Some(object) = file.as_object() else {
        return Err("is not a JSON object".to_owned());
    };
    match object.get("version").and_then(Value::as_u64) {
        Some(FORMAT_VERSION) => {}
        Some(other) => {
            return Err(format!(
                "has version {other}, and only version {FORMAT_VERSION} is known"
            ));
        }
        None => return Err("has no numeric `version`".to_owned()),
    }
    let Some(list) = object.get("cookies").and_then(Value::as_array) else {
        return Err("has no `cookies` list".to_owned());
    };
    if list.len() > MAX_COOKIES {
        return Err(format!(
            "holds {} cookies, more than the {MAX_COOKIES} a session file may keep",
            list.len()
        ));
    }
    list.iter()
        .enumerate()
        .map(|(index, cookie)| {
            Cookie::parse(cookie, false)
                .map_err(|what| format!("has an error in cookies[{index}]: {what}"))
        })
        .collect()
}

/// The text of a session file with these cookies.
fn file_bytes(cookies: &[Cookie]) -> std::result::Result<Vec<u8>, String> {
    if cookies.len() > MAX_COOKIES {
        return Err(format!(
            "the browser holds {} cookies, more than the {MAX_COOKIES} a session file may keep; nothing was saved",
            cookies.len()
        ));
    }
    let saved_at_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis()),
    )
    .unwrap_or(u64::MAX);
    let file = json!({
        "version": FORMAT_VERSION,
        "saved_at_ms": saved_at_ms,
        "cookies": cookies.iter().map(Cookie::to_value).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec_pretty(&file)
        .map_err(|_| "the cookies cannot be written as JSON".to_owned())?;
    if u64::try_from(bytes.len()).is_ok_and(|size| size > MAX_FILE_BYTES) {
        return Err("the session file would be larger than 8 MiB; nothing was saved".to_owned());
    }
    Ok(bytes)
}

/// Makes `dir`, and the folders above it that are missing, readable by the
/// owner only.
#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(_dir: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "saving a session needs Unix file permissions",
    ))
}

/// Writes a new file that only its owner can read, failing if `path` exists.
#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(_path: &Path, _bytes: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "saving a session needs Unix file permissions",
    ))
}

/// Removes every value of `cookies` from `message`, as it is and as JSON would
/// write it, for the text of an error the browser sent back.
fn redact(message: &str, cookies: &[Cookie]) -> String {
    let mut text = message.to_owned();
    for cookie in cookies.iter().filter(|cookie| !cookie.value.is_empty()) {
        text = text.replace(&cookie.value, "[a cookie value]");
        let escaped = serde_json::to_string(&cookie.value).unwrap_or_default();
        if let Some(inner) = escaped
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .filter(|inner| !inner.is_empty() && *inner != cookie.value)
        {
            text = text.replace(inner, "[a cookie value]");
        }
    }
    text
}

/// Where one saved session lives: `<dir>/<name>.json`.
#[derive(Clone, Debug)]
pub(crate) struct Store {
    name: String,
    dir: PathBuf,
    file: PathBuf,
}

impl Store {
    /// The store the options name, or `None` without `session`. A relative
    /// folder is made absolute against the working directory now, so a later
    /// change of the directory does not move the session.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] if the working directory is unknown.
    pub(crate) fn from_config(config: &SessionConfig) -> Result<Option<Self>> {
        let Some(name) = &config.session else {
            return Ok(None);
        };
        let given = config
            .session_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SESSION_DIR));
        let dir = if given.is_absolute() {
            given
        } else {
            std::env::current_dir()
                .map_err(|error| {
                    PluginError::Config(format!(
                        "browser: `session_dir` cannot be made absolute, the working directory is unknown: {error}"
                    ))
                })?
                .join(given)
        };
        let file = dir.join(format!("{name}.json"));
        // The name was checked; this makes sure the file is inside the folder.
        if file.parent() != Some(dir.as_path()) {
            return Err(PluginError::Config(
                "browser: `session` does not name a file in `session_dir`".to_owned(),
            ));
        }
        Ok(Some(Self {
            name: name.clone(),
            dir,
            file,
        }))
    }

    /// The session's name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The folder the file lives in.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// The session file.
    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    /// An error of the option, with `what` as the reason.
    fn problem(&self, what: impl fmt::Display) -> PluginError {
        PluginError::other(format!("browser: `session` `{}`: {what}", self.name))
    }

    /// Refuses a symbolic link and anything that is not a regular file.
    fn check_kind(&self, meta: &fs::Metadata) -> Result<()> {
        if meta.file_type().is_symlink() {
            Err(self.problem(format!(
                "{} is a symbolic link, which is not followed",
                self.file.display()
            )))
        } else if !meta.is_file() {
            Err(self.problem(format!("{} is not a regular file", self.file.display())))
        } else {
            Ok(())
        }
    }

    /// Refuses a target that is a symbolic link or not a regular file; a
    /// target that does not exist is fine.
    fn check_target(&self) -> Result<()> {
        match fs::symlink_metadata(&self.file) {
            Ok(meta) => self.check_kind(&meta),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(self.problem(format!(
                "{} cannot be looked at: {error}",
                self.file.display()
            ))),
        }
    }

    /// A name for a temporary file in the session folder that no other file,
    /// browser or process has.
    fn temp_path(&self) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        self.dir.join(format!(
            ".{}.json.{}-{serial}.tmp",
            self.name,
            std::process::id()
        ))
    }

    /// The cookies to put back: the unexpired ones. `None` when the session
    /// was never saved.
    ///
    /// # Errors
    ///
    /// An error naming `session` for a file that is a symbolic link, not a
    /// regular file, larger than 8 MiB, corrupt, of another version, or with
    /// more than 5000 cookies. It never holds a value of the file.
    pub(crate) fn load(&self) -> Result<Option<Vec<Cookie>>> {
        let file = self.file.display();
        let meta = match fs::symlink_metadata(&self.file) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(self.problem(format!("{file} cannot be read: {error}")));
            }
        };
        self.check_kind(&meta)?;
        let too_big = || self.problem(format!("{file} is larger than 8 MiB"));
        if meta.len() > MAX_FILE_BYTES {
            return Err(too_big());
        }
        let mut bytes = Vec::new();
        fs::File::open(&self.file)
            .and_then(|handle| handle.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|error| self.problem(format!("{file} cannot be read: {error}")))?;
        if u64::try_from(bytes.len()).is_ok_and(|size| size > MAX_FILE_BYTES) {
            return Err(too_big());
        }
        let cookies = parse_file(&bytes).map_err(|what| self.problem(format!("{file} {what}")))?;
        let now = unix_seconds();
        Ok(Some(
            cookies
                .into_iter()
                .filter(|cookie| !cookie.expired(now))
                .collect(),
        ))
    }

    /// Writes the session: a temporary file in the same folder, created with
    /// mode 0600, then renamed over the file. A folder the call makes is
    /// created with mode 0700. A symbolic link or a folder at the file's place
    /// is refused, and a failure leaves the old file and no temporary file.
    ///
    /// # Errors
    ///
    /// An error naming `session`.
    pub(crate) fn save(&self, cookies: &[Cookie]) -> Result<()> {
        let bytes = file_bytes(cookies).map_err(|what| self.problem(what))?;
        create_private_dir(&self.dir).map_err(|error| {
            self.problem(format!(
                "the folder {} cannot be made or used: {error}",
                self.dir.display()
            ))
        })?;
        self.check_target()?;
        let temp = self.temp_path();
        let written =
            write_private_file(&temp, &bytes).and_then(|()| fs::rename(&temp, &self.file));
        if let Err(error) = written {
            // Best effort: the temporary file is ours, and the error is the news.
            let _ = fs::remove_file(&temp);
            return Err(self.problem(format!(
                "{} cannot be written: {error}",
                self.file.display()
            )));
        }
        Ok(())
    }

    /// Makes the folder if it is missing and writes and removes a temporary
    /// file in it, so that a session that cannot be saved is found out at
    /// launch and not when the browser closes.
    ///
    /// # Errors
    ///
    /// An error naming `session` and `save_on_close`.
    pub(crate) fn check_writable(&self) -> Result<()> {
        let probe = self.temp_path();
        create_private_dir(&self.dir)
            .and_then(|()| write_private_file(&probe, b""))
            .and_then(|()| fs::remove_file(&probe))
            .map_err(|error| {
                // Best effort again.
                let _ = fs::remove_file(&probe);
                self.problem(format!(
                    "cannot be saved: the folder {} cannot be written ({error}), and `save_on_close` and `interactive` need to write there",
                    self.dir.display()
                ))
            })?;
        self.check_target()
    }
}

/// Puts the cookies of the saved session back into the browser. A session
/// that was never saved, or holds nothing unexpired, sends nothing.
///
/// # Errors
///
/// An error naming `session`: from the file (see [`Store::load`]), or when the
/// browser refuses the cookies, with their values removed from its message.
pub(crate) async fn restore(browser: &dyn BrowserHandle, store: &Store) -> Result<()> {
    let Some(cookies) = store.load()? else {
        return Ok(());
    };
    if cookies.is_empty() {
        return Ok(());
    }
    let params = json!({ "cookies": cookies.iter().map(Cookie::to_value).collect::<Vec<_>>() });
    browser
        .send("Storage.setCookies", params)
        .await
        .map(drop)
        .map_err(|error| {
            store.problem(format!(
                "the browser refused `Storage.setCookies` for {} cookies: {}",
                cookies.len(),
                redact(&error.to_string(), &cookies)
            ))
        })
}

/// Saves the browser's cookies (its default context) as the session. Gives
/// the number of cookies saved.
///
/// # Errors
///
/// An error naming `session`: the browser cannot give its cookies, answers
/// something else, holds more than 5000, or the file cannot be written.
pub(crate) async fn save(browser: &dyn BrowserHandle, store: &Store) -> Result<usize> {
    let reply = browser
        .send("Storage.getCookies", json!({}))
        .await
        .map_err(|error| store.problem(format!("cannot read the browser's cookies: {error}")))?;
    let Some(list) = reply.get("cookies").and_then(Value::as_array) else {
        return Err(
            store.problem("the browser's answer to `Storage.getCookies` has no cookie list")
        );
    };
    if list.len() > MAX_COOKIES {
        return Err(store.problem(format!(
            "the browser holds {} cookies, more than the {MAX_COOKIES} a session file may keep; nothing was saved",
            list.len()
        )));
    }
    let cookies = list
        .iter()
        .enumerate()
        .map(|(index, cookie)| {
            Cookie::parse(cookie, true)
                .map_err(|what| store.problem(format!("the browser's cookies[{index}]: {what}")))
        })
        .collect::<Result<Vec<_>>>()?;
    store.save(&cookies)?;
    Ok(cookies.len())
}

/// The longest session name.
const MAX_NAME_LEN: usize = 64;

/// Whether `name` is a session name: one to 64 letters, digits, `.`, `_` or
/// `-`, starting with a letter or a digit. Such a name is one path component,
/// holds no separator and no NUL, and does not start with a dot.
pub(crate) fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.len() <= MAX_NAME_LEN
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-value-0042";

    fn cookie_with(extra: Value) -> Value {
        let mut cookie = json!({ "name": "sid", "value": SECRET, "domain": "a.test", "path": "/" });
        for (field, value) in extra.as_object().expect("an object") {
            cookie[field.as_str()] = value.clone();
        }
        cookie
    }

    #[test]
    fn a_cookie_shows_nothing_in_debug() {
        let cookie = Cookie::parse(&cookie_with(json!({})), false).expect("a good cookie");
        let shown = format!("{cookie:?} {:?}", vec![cookie.clone()]);
        assert!(!shown.contains(SECRET), "{shown}");
        assert!(!shown.contains("sid"), "{shown}");
    }

    #[test]
    fn names_are_one_safe_path_component() {
        let long = "x".repeat(65);
        for bad in [
            "", ".a", "-a", "_a", "a/b", "a\\b", "..", "a b", "a\0b", "é", &long,
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        for good in ["a", "A9", "a.b", "a_b", "a-b", "a..b", &"x".repeat(64)] {
            assert!(valid_name(good), "{good:?}");
        }
    }

    #[test]
    fn a_session_cookie_has_no_expiry_whatever_the_browser_calls_it() {
        for expires in [json!(-1), json!(0), json!(null)] {
            let cookie = Cookie::parse(&cookie_with(json!({ "expires": expires })), false)
                .expect("a good cookie");
            assert!(cookie.to_value().get("expires").is_none());
        }
        let cookie = Cookie::parse(&cookie_with(json!({ "expires": 5.5 })), false).expect("good");
        assert_eq!(cookie.to_value()["expires"], json!(5.5));
        assert!(cookie.expired(5.5) && cookie.expired(6.0) && !cookie.expired(5.0));
    }

    #[test]
    fn a_value_this_plugin_does_not_know_is_an_error_to_read_and_dropped_from_a_browser() {
        let odd =
            cookie_with(json!({ "sameSite": "Sometimes", "sourcePort": 0, "partitionKey": 3 }));
        let strict = Cookie::parse(&odd, false).expect_err("a session file is read strictly");
        assert!(
            strict.contains("sameSite") && !strict.contains("Sometimes"),
            "{strict}"
        );
        let lenient = Cookie::parse(&odd, true).expect("a browser may know more");
        let kept = lenient.to_value();
        for field in ["sameSite", "sourcePort", "partitionKey"] {
            assert!(kept.get(field).is_none(), "{field}");
        }
    }

    #[test]
    fn redacting_removes_a_value_as_it_is_and_as_json_writes_it() {
        let tricky = "q\"u\\ote";
        let cookie = Cookie::parse(
            &json!({ "name": "n", "value": tricky, "domain": "a.test", "path": "/" }),
            false,
        )
        .expect("a good cookie");
        let message = format!(
            "bad {tricky} and {}",
            serde_json::to_string(tricky).expect("json")
        );
        let shown = redact(&message, &[cookie]);
        assert!(!shown.contains(tricky), "{shown}");
        assert!(!shown.contains("u\\\\ote"), "{shown}");
        assert!(shown.starts_with("bad "), "{shown}");
    }

    #[test]
    fn the_file_is_always_inside_its_folder() {
        for name in ["a", "a.json", "a..b", "x-y_z.1"] {
            let config = SessionConfig::new()
                .with_session(name)
                .with_session_dir("/tmp/sessions/");
            let store = Store::from_config(&config)
                .expect("a store")
                .expect("a session");
            assert_eq!(store.file().parent(), Some(store.dir()));
            assert_eq!(store.name(), name);
        }
        assert!(
            Store::from_config(&SessionConfig::new())
                .expect("no error")
                .is_none()
        );
    }
}
