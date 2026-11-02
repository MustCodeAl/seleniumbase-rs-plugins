//! The input of the `interactive` task: where the browser's first tab goes.

use std::fmt::Display;

use seleniumbase_rs_plugin::{PluginError, Result};
use serde_json::Value;

/// The error of the option, with `what` as the reason. It never repeats the
/// address, which may hold a token.
fn refuse(what: impl Display) -> PluginError {
    PluginError::other(format!("browser: `interactive`: {what}"))
}

/// Whether `text` starts with `prefix`, whatever the case of the letters.
fn starts_with_ignore_case(text: &str, prefix: &str) -> bool {
    text.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// The address the task opens: the `url` of the input, if it has one. The
/// input is nothing or an object; only `http` and `https` addresses are
/// opened, and none gives a blank tab.
///
/// # Errors
///
/// An error naming `interactive` for any other input or address.
pub(crate) fn start_url(input: &Value) -> Result<Option<&str>> {
    let url = match input {
        Value::Null => return Ok(None),
        Value::Object(fields) => match fields.get("url") {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::String(url)) => url.as_str(),
            Some(_) => return Err(refuse("the input's `url` must be text")),
        },
        _ => {
            return Err(refuse(
                "the input must be an object with an optional `url`, or nothing",
            ));
        }
    };
    let scheme_len = if starts_with_ignore_case(url, "https://") {
        "https://".len()
    } else if starts_with_ignore_case(url, "http://") {
        "http://".len()
    } else {
        return Err(refuse(
            "the input's `url` must start with http:// or https://",
        ));
    };
    let rest = &url[scheme_len..];
    if rest.is_empty()
        || rest.starts_with('/')
        || rest.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(refuse(
            "the input's `url` needs a host and may hold no spaces or control characters",
        ));
    }
    Ok(Some(url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nothing_and_an_object_without_an_address_give_a_blank_tab() {
        for input in [Value::Null, json!({}), json!({ "url": null })] {
            assert_eq!(start_url(&input).expect("no address"), None);
        }
    }

    #[test]
    fn the_address_is_returned_as_given() {
        for url in [
            "http://a.test/",
            "HTTPS://A.TEST/x?y=1#z",
            "https://a.test:8443",
        ] {
            let input = json!({ "url": url });
            assert_eq!(start_url(&input).expect("an address"), Some(url));
        }
    }

    #[test]
    fn other_inputs_and_addresses_are_refused_without_repeating_them() {
        for input in [
            json!({ "url": "file:///etc/passwd?token=hunter2" }),
            json!({ "url": "https://a b.test/?token=hunter2" }),
            json!({ "url": "https:///?token=hunter2" }),
            json!({ "url": "https://" }),
            json!({ "url": 7 }),
            json!("https://a.test/?token=hunter2"),
            json!([1]),
        ] {
            let text = start_url(&input).expect_err("refused").to_string();
            assert!(text.contains("`interactive`"), "{text}");
            assert!(!text.contains("hunter2"), "{text}");
        }
    }
}
