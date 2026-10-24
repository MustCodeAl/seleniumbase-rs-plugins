//! Shared by the extractor's test files.

use serde_json::Value;

/// A validator for the subset of JSON Schema that `Schema::json_schema` emits:
/// `type`, `properties`, `required`, `additionalProperties: false`, `items`,
/// `anyOf` and the two `pattern`s. It is a test aid, not a general validator.
#[must_use]
pub fn valid(schema: &Value, value: &Value) -> bool {
    if let Some(any) = schema.get("anyOf").and_then(Value::as_array) {
        return any.iter().any(|option| valid(option, value));
    }
    if let Some(declared) = schema.get("type") {
        let names: Vec<&str> = match declared {
            Value::String(name) => vec![name.as_str()],
            Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let fits = names.iter().any(|name| match *name {
            "string" => value.is_string(),
            "number" => value.is_number(),
            "null" => value.is_null(),
            "object" => value.is_object(),
            "array" => value.is_array(),
            _ => false,
        });
        if !fits {
            return false;
        }
    }
    if let (Some(pattern), Some(text)) = (
        schema.get("pattern").and_then(Value::as_str),
        value.as_str(),
    ) {
        let ok = match pattern {
            "^https?://" => text.starts_with("http://") || text.starts_with("https://"),
            "^[0-9]{4}-[0-9]{2}-[0-9]{2}" => {
                let b = text.as_bytes();
                b.len() >= 10
                    && b[..4].iter().all(u8::is_ascii_digit)
                    && b[4] == b'-'
                    && b[5..7].iter().all(u8::is_ascii_digit)
                    && b[7] == b'-'
                    && b[8..10].iter().all(u8::is_ascii_digit)
            }
            other => panic!("the test validator does not know the pattern {other}"),
        };
        if !ok {
            return false;
        }
    }
    if let Some(object) = value.as_object() {
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (key, sub) in properties {
                if object.get(key).is_some_and(|inner| !valid(sub, inner)) {
                    return false;
                }
            }
            if schema.get("additionalProperties") == Some(&Value::Bool(false))
                && object.keys().any(|key| !properties.contains_key(key))
            {
                return false;
            }
        }
        if let Some(required) = schema.get("required").and_then(Value::as_array)
            && required
                .iter()
                .filter_map(Value::as_str)
                .any(|key| !object.contains_key(key))
        {
            return false;
        }
    }
    if let (Some(items), Some(list)) = (schema.get("items"), value.as_array())
        && !list.iter().all(|item| valid(items, item))
    {
        return false;
    }
    true
}
