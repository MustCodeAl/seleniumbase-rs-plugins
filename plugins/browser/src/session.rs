//! Containerized persistent session storage: cookies, per-origin Web Storage
//! (`localStorage` and `sessionStorage`), open tab URLs, container identity
//! metadata, and TTL expiry.
//!
//! Files are written atomically with owner-only (`0600`) permissions on Unix.
//! Cookie values and storage values are credentials and are never printed in
//! errors, logs, or `Debug` output.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use seleniumbase_rs_plugin::{BrowserHandle, PluginError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::config::{DEFAULT_SESSION_DIR, SessionConfig};

/// Legacy v1 format (cookies only); still read seamlessly for upgrades.
const LEGACY_FORMAT_VERSION: u64 = 1;
/// Container v2 format: cookies + storage + open tabs + identity + TTL.
const FORMAT_VERSION: u64 = 2;

const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_COOKIES: usize = 5_000;
const MAX_TABS: usize = 32;
const MAX_ORIGINS: usize = 128;

const SAME_SITE: &[&str] = &["Strict", "Lax", "None"];
const PRIORITY: &[&str] = &["Low", "Medium", "High"];
const SOURCE_SCHEME: &[&str] = &["Unset", "NonSecure", "Secure"];

type Fields = Map<String, Value>;

/// Validates a container/session name (`1..=64` ASCII alnum/`.`/`_`/`-`, starting with alnum).
pub(crate) fn check_name(name: &str) -> std::result::Result<(), String> {
    if name.is_empty() || name.len() > 64 {
        return Err("`session` must be 1 to 64 characters".to_owned());
    }
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err("`session` is empty".to_owned());
    };
    if !first.is_ascii_alphanumeric() {
        return Err("`session` must start with an ASCII letter or digit".to_owned());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(
            "`session` may only contain ASCII letters, digits, `.`, `_`, or `-`".to_owned(),
        );
    }
    Ok(())
}

/// Persisted identity metadata bound to a container.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerIdentity {
    /// ISO 3166-1 alpha-2 country code.
    pub country: Option<String>,
    /// BCP 47 locale tag.
    pub locale: Option<String>,
    /// IANA timezone name.
    pub timezone: Option<String>,
    /// Geolocation `[latitude, longitude]`.
    pub geolocation: Option<[f64; 2]>,
    /// User-Agent string override.
    pub user_agent: Option<String>,
    /// Index of the sticky proxy last bound to this container.
    pub proxy_index: Option<usize>,
}

/// Persisted Web Storage entries for a single origin (`https://example.com`).
/// Values are credentials and omitted from `Debug`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OriginStorage {
    /// `window.localStorage` key/value pairs.
    pub local_storage: BTreeMap<String, String>,
    /// `window.sessionStorage` key/value pairs.
    pub session_storage: BTreeMap<String, String>,
}

impl fmt::Debug for OriginStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginStorage")
            .field("local_keys", &self.local_storage.len())
            .field("session_keys", &self.session_storage.len())
            .finish()
    }
}

/// One browser cookie keeping `Network.CookieParam` fields only.
#[derive(Clone, PartialEq)]
pub(crate) struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
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

/// Full containerized session snapshot persisted to disk.
#[derive(Clone, Default)]
pub(crate) struct ContainerSnapshot {
    pub(crate) saved_at_ms: u64,
    pub(crate) expires_at_ms: Option<u64>,
    pub(crate) cookies: Vec<Cookie>,
    pub(crate) storage: BTreeMap<String, OriginStorage>,
    pub(crate) tabs: Vec<String>,
    pub(crate) identity: ContainerIdentity,
}

impl fmt::Debug for ContainerSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainerSnapshot")
            .field("saved_at_ms", &self.saved_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("cookies", &self.cookies.len())
            .field("storage_origins", &self.storage.len())
            .field("tabs", &self.tabs.len())
            .field("identity", &self.identity)
            .finish()
    }
}

impl ContainerSnapshot {
    /// Returns whether this snapshot has passed its TTL (`expires_at_ms`) or `ttl_secs`.
    pub(crate) fn is_expired(&self, now_ms: u64, ttl_secs: Option<u64>) -> bool {
        if let Some(exp) = self.expires_at_ms
            && now_ms >= exp
        {
            return true;
        }
        if let Some(ttl) = ttl_secs
            && self.saved_at_ms > 0
        {
            let deadline = self.saved_at_ms.saturating_add(ttl.saturating_mul(1_000));
            if now_ms >= deadline {
                return true;
            }
        }
        false
    }

    /// Generates an init script that hydrates `localStorage` and `sessionStorage`
    /// for matching origins before any page script runs.
    pub(crate) fn storage_init_script(&self) -> Option<String> {
        if self.storage.is_empty() {
            return None;
        }
        let payload = serde_json::to_string(&self.storage).ok()?;
        Some(format!(
            "(() => {{\
               try {{\
                 const map = {payload};\
                 const entry = map[window.location.origin];\
                 if (!entry) return;\
                 if (entry.local_storage) {{\
                   for (const [k, v] of Object.entries(entry.local_storage)) {{\
                     if (window.localStorage.getItem(k) === null) window.localStorage.setItem(k, v);\
                   }}\
                 }}\
                 if (entry.session_storage) {{\
                   for (const [k, v] of Object.entries(entry.session_storage)) {{\
                     if (window.sessionStorage.getItem(k) === null) window.sessionStorage.setItem(k, v);\
                   }}\
                 }}\
               }} catch (_) {{}}\
             }})();"
        ))
    }
}

fn required_text(fields: &Fields, field: &str) -> std::result::Result<String, String> {
    match fields.get(field) {
        Some(Value::String(text)) => Ok(text.clone()),
        _ => Err(format!("`{field}` is missing or is not text")),
    }
}

fn flag(fields: &Fields, field: &str) -> std::result::Result<bool, String> {
    match fields.get(field) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(on)) => Ok(*on),
        _ => Err(format!("`{field}` is not true or false")),
    }
}

fn choice(
    fields: &Fields,
    field: &str,
    allowed: &[&'static str],
    lenient: bool,
) -> std::result::Result<Option<&'static str>, String> {
    match fields.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => match allowed.iter().copied().find(|k| *k == text.as_str()) {
            Some(known) => Ok(Some(known)),
            None if lenient => Ok(None),
            None => Err(format!("`{field}` is not a value this plugin knows")),
        },
        Some(_) if lenient => Ok(None),
        Some(_) => Err(format!("`{field}` is not text")),
    }
}

fn expiry(fields: &Fields) -> std::result::Result<Option<f64>, String> {
    match fields.get("expires") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(time)) => Ok(time
            .as_f64()
            .filter(|seconds| seconds.is_finite() && *seconds > 0.0)),
        Some(_) => Err("`expires` is not a number".to_owned()),
    }
}

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

    fn expired(&self, now: f64) -> bool {
        self.expires.is_some_and(|expires| expires <= now)
    }
}

pub(crate) fn unix_millis() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(u64::MAX)
}

fn unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

pub(crate) fn is_http_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    (lower.starts_with("http://") || lower.starts_with("https://"))
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn parse_file(bytes: &[u8]) -> std::result::Result<ContainerSnapshot, String> {
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
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| "has no numeric `version`".to_owned())?;
    if version != LEGACY_FORMAT_VERSION && version != FORMAT_VERSION {
        return Err(format!(
            "has version {version}, and only versions {LEGACY_FORMAT_VERSION} or {FORMAT_VERSION} are supported"
        ));
    }
    let Some(list) = object.get("cookies").and_then(Value::as_array) else {
        return Err("has no `cookies` list".to_owned());
    };
    if list.len() > MAX_COOKIES {
        return Err(format!(
            "holds {} cookies, exceeding the {MAX_COOKIES} limit",
            list.len()
        ));
    }
    let cookies = list
        .iter()
        .enumerate()
        .map(|(index, cookie)| {
            Cookie::parse(cookie, false)
                .map_err(|what| format!("has an error in cookies[{index}]: {what}"))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let saved_at_ms = object
        .get("saved_at_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let expires_at_ms = object.get("expires_at_ms").and_then(Value::as_u64);

    let storage = match object.get("storage") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(val) => {
            let map: BTreeMap<String, OriginStorage> = serde_json::from_value(val.clone())
                .map_err(|_| "has an invalid `storage` map".to_owned())?;
            if map.len() > MAX_ORIGINS {
                return Err(format!("exceeds {MAX_ORIGINS} stored origins"));
            }
            map
        }
    };

    let tabs = match object.get("tabs") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .filter(|url| is_http_url(url))
            .take(MAX_TABS)
            .map(str::to_owned)
            .collect(),
        Some(_) => return Err("has a non-array `tabs` field".to_owned()),
    };

    let identity = match object.get("identity") {
        None | Some(Value::Null) => ContainerIdentity::default(),
        Some(val) => serde_json::from_value(val.clone())
            .map_err(|_| "has an invalid `identity` object".to_owned())?,
    };

    Ok(ContainerSnapshot {
        saved_at_ms,
        expires_at_ms,
        cookies,
        storage,
        tabs,
        identity,
    })
}

fn file_bytes(snapshot: &ContainerSnapshot) -> std::result::Result<Vec<u8>, String> {
    if snapshot.cookies.len() > MAX_COOKIES {
        return Err(format!(
            "the browser holds {} cookies, exceeding the {MAX_COOKIES} limit; nothing was saved",
            snapshot.cookies.len()
        ));
    }
    let file = json!({
        "version": FORMAT_VERSION,
        "saved_at_ms": snapshot.saved_at_ms,
        "expires_at_ms": snapshot.expires_at_ms,
        "cookies": snapshot.cookies.iter().map(Cookie::to_value).collect::<Vec<_>>(),
        "storage": snapshot.storage,
        "tabs": snapshot.tabs,
        "identity": snapshot.identity,
    });
    let bytes = serde_json::to_vec_pretty(&file)
        .map_err(|_| "the container snapshot cannot be serialized as JSON".to_owned())?;
    if u64::try_from(bytes.len()).is_ok_and(|size| size > MAX_FILE_BYTES) {
        return Err("the container file would exceed 8 MiB; nothing was saved".to_owned());
    }
    Ok(bytes)
}

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
        "saving a container needs Unix file permissions",
    ))
}

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
        "saving a container needs Unix file permissions",
    ))
}

/// Persistent container store rooted at `<session_dir>/<name>.json`.
#[derive(Clone, Debug)]
pub(crate) struct Store {
    name: String,
    dir: PathBuf,
    file: PathBuf,
}

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

impl Store {
    pub(crate) fn from_config(config: &SessionConfig) -> Result<Option<Self>> {
        let Some(ref name) = config.session else {
            return Ok(None);
        };
        let raw_dir = config
            .session_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SESSION_DIR));
        let dir = if raw_dir.is_absolute() {
            raw_dir
        } else {
            std::env::current_dir()
                .map_err(|e| PluginError::Config(format!("browser: current_dir unavailable: {e}")))?
                .join(raw_dir)
        };
        let file = dir.join(format!("{name}.json"));
        Ok(Some(Self {
            name: name.clone(),
            dir,
            file,
        }))
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn file(&self) -> &Path {
        &self.file
    }

    pub(crate) fn check_writable(&self) -> Result<()> {
        if !self.dir.exists() {
            create_private_dir(&self.dir).map_err(|error| {
                PluginError::other(format!(
                    "browser: cannot create session_dir `{}`: {error}",
                    self.dir.display()
                ))
            })?;
        }
        Ok(())
    }

    pub(crate) fn load(&self, ttl_secs: Option<u64>) -> Result<Option<ContainerSnapshot>> {
        let mut file = match fs::File::open(&self.file) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(PluginError::other(format!(
                    "browser: cannot read container `{}`: {e}",
                    self.file.display()
                )));
            }
        };
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                PluginError::other(format!(
                    "browser: cannot read container `{}`: {e}",
                    self.file.display()
                ))
            })?;
        if u64::try_from(bytes.len()).is_ok_and(|size| size > MAX_FILE_BYTES) {
            return Err(PluginError::other(format!(
                "browser: container `{}` exceeds 8 MiB",
                self.file.display()
            )));
        }
        let snapshot = parse_file(&bytes).map_err(|why| {
            PluginError::other(format!(
                "browser: container `{}` {why}",
                self.file.display()
            ))
        })?;
        if snapshot.is_expired(unix_millis(), ttl_secs) {
            return Ok(None);
        }
        Ok(Some(snapshot))
    }

    pub(crate) fn write(&self, snapshot: &ContainerSnapshot) -> Result<()> {
        self.check_writable()?;
        let bytes =
            file_bytes(snapshot).map_err(|why| PluginError::other(format!("browser: {why}")))?;
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let temp = self
            .dir
            .join(format!(".{}.{}.{seq}.tmp", self.name, std::process::id()));
        if let Err(error) = write_private_file(&temp, &bytes) {
            let _ = fs::remove_file(&temp);
            return Err(PluginError::other(format!(
                "browser: cannot write container `{}`: {error}",
                self.file.display()
            )));
        }
        if let Err(error) = fs::rename(&temp, &self.file) {
            let _ = fs::remove_file(&temp);
            return Err(PluginError::other(format!(
                "browser: cannot persist container `{}`: {error}",
                self.file.display()
            )));
        }
        Ok(())
    }
}

/// Restores non-expired cookies into the browser via `Storage.setCookies`.
pub(crate) async fn restore_cookies(
    browser: &dyn BrowserHandle,
    cookies: &[Cookie],
) -> Result<usize> {
    let now = unix_seconds();
    let live: Vec<Value> = cookies
        .iter()
        .filter(|c| !c.expired(now))
        .map(Cookie::to_value)
        .collect();
    if live.is_empty() {
        return Ok(0);
    }
    let count = live.len();
    browser
        .send("Storage.setCookies", json!({ "cookies": live }))
        .await?;
    Ok(count)
}

/// Reads all live cookies from the browser via `Storage.getCookies`.
pub(crate) async fn capture_cookies(browser: &dyn BrowserHandle) -> Result<Vec<Cookie>> {
    let response = browser.send("Storage.getCookies", json!({})).await?;
    let Some(list) = response.get("cookies").and_then(Value::as_array) else {
        return Err(PluginError::other(
            "browser: `Storage.getCookies` did not return a `cookies` array",
        ));
    };
    let mut out = Vec::with_capacity(list.len());
    for (idx, item) in list.iter().enumerate() {
        let cookie = Cookie::parse(item, true).map_err(|why| {
            PluginError::other(format!(
                "browser: `Storage.getCookies` cookies[{idx}]: {why}"
            ))
        })?;
        out.push(cookie);
    }
    Ok(out)
}

/// Summary returned after saving a container snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SaveSummary {
    /// Container name.
    pub session: String,
    /// Number of cookies persisted.
    pub cookies: usize,
    /// Number of origins with persisted Web Storage.
    pub storage_origins: usize,
    /// Number of open tab URLs persisted.
    pub tabs: usize,
}
