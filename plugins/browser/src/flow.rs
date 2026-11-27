//! Dynamic SPA flow and extraction runner executed inside a persistent
//! `browser` container via `sbrs plugin run browser`.
//!
//! Supports multi-step workflows across pages and tabs without reconnecting:
//! `goto`, `new_tab`, `wait_for`, `click`, `type`, `scroll`, `extract`, `save`.

use std::time::Duration;

use seleniumbase_rs_plugin::{BrowserHandle, PageHandle, PluginError, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::session::{OriginStorage, is_http_url};

/// Maximum steps allowed in a single flow call.
const MAX_STEPS: usize = 100;

/// Default selector wait timeout in milliseconds.
const DEFAULT_WAIT_MS: u64 = 10_000;

/// Input payload for `sbrs plugin run browser` when `interactive` is false.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FlowInput {
    /// Optional starting URL opened before running `steps`.
    pub(crate) url: Option<String>,
    /// Ordered interaction and extraction steps executed without reconnecting.
    pub(crate) steps: Vec<FlowStep>,
    /// Optional shortcut selectors to extract after `steps` finish (`{ name: css_selector }`).
    pub(crate) extract: std::collections::BTreeMap<String, String>,
    /// Whether to save the container snapshot after the flow completes.
    pub(crate) save: bool,
}

/// One action inside a persistent browser container flow.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(crate) enum FlowStep {
    /// Navigate the active tab to `url`.
    Goto { url: String },
    /// Open a new tab inside the same persistent session (keeping existing tabs alive).
    NewTab { url: Option<String> },
    /// Wait for a dynamic SPA selector to appear in the DOM.
    WaitFor {
        selector: String,
        timeout_ms: Option<u64>,
    },
    /// Click the first element matching `selector`.
    Click { selector: String },
    /// Type `text` into the element matching `selector`.
    Type { selector: String, text: String },
    /// Scroll the page by `dx`, `dy` pixels.
    Scroll {
        #[serde(default)]
        dx: i32,
        dy: i32,
    },
    /// Extract text (or `attr` / `html`) from the first element matching `selector`.
    Extract {
        name: String,
        selector: String,
        attr: Option<String>,
        #[serde(default)]
        html: bool,
    },
}

fn validate_url(url: &str) -> Result<()> {
    if !is_http_url(url) {
        return Err(PluginError::other(
            "browser: flow URL must start with http:// or https:// without spaces or control characters",
        ));
    }
    Ok(())
}

/// Reads `localStorage` and `sessionStorage` from the active page's origin.
pub(crate) async fn snapshot_page_storage(
    page: &dyn PageHandle,
) -> Result<Option<(String, OriginStorage)>> {
    let js = r#"(() => {
        try {
            const origin = window.location.origin;
            if (!origin || origin === 'null' || (!origin.startsWith('http://') && !origin.startsWith('https://'))) {
                return null;
            }
            const local_storage = {};
            for (let i = 0; i < window.localStorage.length; i++) {
                const k = window.localStorage.key(i);
                if (k !== null) local_storage[k] = window.localStorage.getItem(k) ?? '';
            }
            const session_storage = {};
            for (let i = 0; i < window.sessionStorage.length; i++) {
                const k = window.sessionStorage.key(i);
                if (k !== null) session_storage[k] = window.sessionStorage.getItem(k) ?? '';
            }
            return { origin, local_storage, session_storage };
        } catch (_) {
            return null;
        }
    })()"#;
    let value = page.evaluate(js).await?;
    if value.is_null() {
        return Ok(None);
    }
    let Some(obj) = value.as_object() else {
        return Ok(None);
    };
    let Some(origin) = obj.get("origin").and_then(Value::as_str) else {
        return Ok(None);
    };
    let local_storage = obj
        .get("local_storage")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let session_storage = obj
        .get("session_storage")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Ok(Some((
        origin.to_owned(),
        OriginStorage {
            local_storage,
            session_storage,
        },
    )))
}

async fn wait_for_selector(
    browser: &dyn BrowserHandle,
    page: &dyn PageHandle,
    selector: &str,
    timeout_ms: u64,
) -> Result<()> {
    let sel = serde_json::to_string(selector)
        .map_err(|_| PluginError::other("browser: invalid selector"))?;
    let expr = format!("Boolean(document.querySelector({sel}))");
    let attempts = (timeout_ms / 150).max(1);
    for _ in 0..attempts {
        if page.evaluate(&expr).await? == Value::Bool(true) {
            return Ok(());
        }
        if let Some(clock) = browser.clock() {
            clock.sleep(Duration::from_millis(150)).await;
        } else {
            break;
        }
    }
    Err(PluginError::other(format!(
        "browser: timed out waiting for selector `{selector}`"
    )))
}

async fn extract_one(
    page: &dyn PageHandle,
    selector: &str,
    attr: Option<&str>,
    html: bool,
) -> Result<Value> {
    let sel = serde_json::to_string(selector)
        .map_err(|_| PluginError::other("browser: invalid selector"))?;
    let expr = if let Some(attr_name) = attr {
        let attr_lit = serde_json::to_string(attr_name)
            .map_err(|_| PluginError::other("browser: invalid attribute name"))?;
        format!(
            "(() => {{ const el = document.querySelector({sel}); return el ? el.getAttribute({attr_lit}) : null; }})()"
        )
    } else if html {
        format!(
            "(() => {{ const el = document.querySelector({sel}); return el ? el.innerHTML : null; }})()"
        )
    } else {
        format!(
            "(() => {{ const el = document.querySelector({sel}); return el ? (el.innerText ?? el.textContent ?? '') : null; }})()"
        )
    };
    page.evaluate(&expr).await
}

/// Executes a multi-step SPA workflow across pages/tabs inside the running browser.
pub(crate) async fn execute(
    browser: &dyn BrowserHandle,
    input: &Value,
) -> Result<(
    serde_json::Map<String, Value>,
    Vec<String>,
    Vec<(String, OriginStorage)>,
    bool,
)> {
    let flow: FlowInput = if input.is_null() {
        FlowInput::default()
    } else {
        serde_json::from_value(input.clone())
            .map_err(|e| PluginError::Config(format!("browser: invalid flow input: {e}")))?
    };
    if flow.steps.len() > MAX_STEPS {
        return Err(PluginError::Config(format!(
            "browser: flow exceeds {MAX_STEPS} steps"
        )));
    }
    if let Some(ref u) = flow.url {
        validate_url(u)?;
    }

    let mut page = browser.new_page(flow.url.as_deref()).await?;
    let mut visited_urls: Vec<String> = Vec::new();
    let mut captured_storage: Vec<(String, OriginStorage)> = Vec::new();
    let mut extracted = serde_json::Map::new();

    if let Some(ref u) = flow.url {
        visited_urls.push(u.clone());
    }

    for step in &flow.steps {
        match step {
            FlowStep::Goto { url } => {
                validate_url(url)?;
                page.navigate(url).await?;
                visited_urls.push(url.clone());
            }
            FlowStep::NewTab { url } => {
                if let Some(u) = url {
                    validate_url(u)?;
                }
                if let Ok(Some(pair)) = snapshot_page_storage(&*page).await {
                    captured_storage.push(pair);
                }
                page = browser.new_page(url.as_deref()).await?;
                if let Some(u) = url {
                    visited_urls.push(u.clone());
                }
            }
            FlowStep::WaitFor {
                selector,
                timeout_ms,
            } => {
                wait_for_selector(
                    browser,
                    &*page,
                    selector,
                    timeout_ms.unwrap_or(DEFAULT_WAIT_MS),
                )
                .await?;
            }
            FlowStep::Click { selector } => {
                let sel = serde_json::to_string(selector)
                    .map_err(|_| PluginError::other("browser: invalid selector"))?;
                let res = page
                    .evaluate(&format!(
                        "(() => {{ const el = document.querySelector({sel}); if (!el) return false; el.click(); return true; }})()"
                    ))
                    .await?;
                if res != Value::Bool(true) {
                    return Err(PluginError::other(format!(
                        "browser: click target `{selector}` not found"
                    )));
                }
            }
            FlowStep::Type { selector, text } => {
                let sel = serde_json::to_string(selector)
                    .map_err(|_| PluginError::other("browser: invalid selector"))?;
                let txt = serde_json::to_string(text)
                    .map_err(|_| PluginError::other("browser: invalid text"))?;
                let res = page
                    .evaluate(&format!(
                        "(() => {{ const el = document.querySelector({sel}); if (!el) return false; el.focus(); el.value = {txt}; el.dispatchEvent(new Event('input', {{ bubbles: true }})); el.dispatchEvent(new Event('change', {{ bubbles: true }})); return true; }})()"
                    ))
                    .await?;
                if res != Value::Bool(true) {
                    return Err(PluginError::other(format!(
                        "browser: type target `{selector}` not found"
                    )));
                }
            }
            FlowStep::Scroll { dx, dy } => {
                page.evaluate(&format!("window.scrollBy({dx}, {dy}); true"))
                    .await?;
            }
            FlowStep::Extract {
                name,
                selector,
                attr,
                html,
            } => {
                let val = extract_one(&*page, selector, attr.as_deref(), *html).await?;
                extracted.insert(name.clone(), val);
            }
        }
    }

    for (name, selector) in &flow.extract {
        let val = extract_one(&*page, selector, None, false).await?;
        extracted.insert(name.clone(), val);
    }

    if let Ok(Some(pair)) = snapshot_page_storage(&*page).await {
        captured_storage.push(pair);
    }
    if let Ok(current) = page.url().await
        && is_http_url(&current)
        && !visited_urls.contains(&current)
    {
        visited_urls.push(current);
    }

    Ok((extracted, visited_urls, captured_storage, flow.save))
}
