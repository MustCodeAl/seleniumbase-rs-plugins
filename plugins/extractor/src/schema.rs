//! The shape of a record: [`Schema`] and its [`Field`]s, the JSON Schema that
//! describes the records, and the step that types what the page gave.

use std::collections::{BTreeMap, BTreeSet};

use seleniumbase_rs_plugin::{PluginError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::values::{convert, infer_type};

/// The longest field name.
pub const MAX_NAME_LEN: usize = 64;

/// The longest selector or path.
pub const MAX_SELECTOR_LEN: usize = 500;

/// The most problems an [`Extraction`] lists; the rest are counted.
pub const MAX_PROBLEMS: usize = 200;

/// What a field holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    /// Text, whitespace collapsed.
    #[default]
    Text,
    /// A number: `1,234.56`, `1.234,56`, `12%`.
    Number,
    /// An amount with its currency: `{"amount": 19.99, "currency": "USD"}`.
    Money,
    /// An ISO 8601 date, with or without a time.
    Date,
    /// An `http` or `https` address.
    Url,
}

/// Where a schema was found, which says how its fields are read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// A JSON-LD block: `item` is the `@type`, a field has a dotted `path`.
    JsonLd,
    /// A table: `item` selects its rows, `skip` is the header row.
    Table,
    /// Repeated elements of the same shape: `item` selects them.
    Repeat,
    /// Selectors given by the caller.
    Selectors,
}

/// One value of a record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    /// The key in the record.
    pub name: String,
    /// A CSS selector, relative to the item (or the document), for every
    /// source except JSON-LD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// An attribute to read instead of the text, such as `href`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attr: Option<String>,
    /// A dotted path into the JSON-LD object, such as `offers.price`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// What the field holds.
    #[serde(rename = "type", default)]
    pub kind: FieldType,
    /// Whether every record must have it.
    #[serde(default)]
    pub required: bool,
    /// Whether it is a list of every match instead of the first.
    #[serde(default)]
    pub all: bool,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// How to find the records on a page and what each one holds.
///
/// ```
/// use seleniumbase_rs_plugin_extractor::{Schema, Source};
///
/// let schema: Schema = serde_json::from_value(serde_json::json!({
///     "source": "repeat",
///     "item": ".card",
///     "fields": [
///         { "name": "title", "selector": "h3" },
///         { "name": "price", "selector": ".price", "type": "money", "required": true },
///     ],
/// }))?;
/// assert_eq!(schema.source, Source::Repeat);
/// assert_eq!(schema.json_schema()["required"], serde_json::json!(["title", "price"]));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schema {
    /// Where it was found.
    pub source: Source,
    /// The records: a selector (tables and repeated elements), a `@type`
    /// (JSON-LD), or nothing for one record from the whole document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<String>,
    /// How many of the first matches of `item` to leave out (a table's header).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skip: usize,
    /// What a record holds.
    pub fields: Vec<Field>,
}

/// A field as a caller writes it in a `select` map: a selector, or more.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum FieldSpec {
    /// Just a selector; the text of the first match.
    Selector(String),
    /// A selector with the rest.
    Detailed(DetailedField),
}

/// The long form of a [`FieldSpec`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetailedField {
    /// A CSS selector.
    pub selector: String,
    /// An attribute to read instead of the text.
    #[serde(default)]
    pub attr: Option<String>,
    /// What the field holds.
    #[serde(rename = "type", default)]
    pub kind: FieldType,
    /// Whether every record must have it.
    #[serde(default)]
    pub required: bool,
    /// Whether it is a list of every match.
    #[serde(default)]
    pub all: bool,
}

fn bad(why: impl std::fmt::Display) -> PluginError {
    PluginError::Config(format!("extractor: {why}"))
}

impl Schema {
    /// A schema from selectors the caller wrote, `item` being the selector of
    /// the repeated element, if any.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] if there are no fields or a field is wrong.
    pub fn selectors(
        item: Option<String>,
        select: &BTreeMap<String, FieldSpec>,
        max_fields: usize,
    ) -> Result<Self> {
        let fields = select
            .iter()
            .map(|(name, spec)| match spec {
                FieldSpec::Selector(selector) => Field {
                    name: name.clone(),
                    selector: Some(selector.clone()),
                    attr: None,
                    path: None,
                    kind: FieldType::Text,
                    required: false,
                    all: false,
                },
                FieldSpec::Detailed(long) => Field {
                    name: name.clone(),
                    selector: Some(long.selector.clone()),
                    attr: long.attr.clone(),
                    path: None,
                    kind: long.kind,
                    required: long.required,
                    all: long.all,
                },
            })
            .collect();
        let schema = Self {
            source: Source::Selectors,
            item,
            skip: 0,
            fields,
        };
        schema.validate(max_fields)?;
        Ok(schema)
    }

    /// Checks a schema, including one that came from a caller or a page.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] naming the first thing wrong.
    pub fn validate(&self, max_fields: usize) -> Result<()> {
        if self.fields.is_empty() {
            return Err(bad("a schema needs at least one field"));
        }
        if self.fields.len() > max_fields {
            return Err(bad(format!("a schema has at most {max_fields} fields")));
        }
        if matches!(self.source, Source::Table | Source::Repeat) && self.item.is_none() {
            return Err(bad("a table or repeat schema needs an `item` selector"));
        }
        if let Some(item) = &self.item {
            check_text("item", item, MAX_SELECTOR_LEN)?;
        }
        let mut names = BTreeSet::new();
        for field in &self.fields {
            check_text("field name", &field.name, MAX_NAME_LEN)?;
            if !names.insert(field.name.as_str()) {
                return Err(bad(format!("field `{}` appears twice", field.name)));
            }
            let place = if self.source == Source::JsonLd {
                field.path.as_deref()
            } else {
                field.selector.as_deref()
            };
            let what = if self.source == Source::JsonLd {
                "a `path`"
            } else {
                "a `selector`"
            };
            let place = place.ok_or_else(|| bad(format!("field `{}` needs {what}", field.name)))?;
            check_text("selector or path", place, MAX_SELECTOR_LEN)?;
            if let Some(attr) = &field.attr {
                let plain = !attr.is_empty()
                    && attr.len() <= 64
                    && attr
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b':');
                if !plain {
                    return Err(bad(format!("`{attr}` is not an attribute name")));
                }
            }
        }
        Ok(())
    }

    /// Builds a schema from a candidate the page script found, typing each
    /// field from its samples. `None` if the candidate is not well formed or
    /// does not pass [`validate`](Self::validate).
    pub(crate) fn from_candidate(candidate: &Value, max_fields: usize) -> Option<Self> {
        let source = match candidate.get("source")?.as_str()? {
            "json-ld" => Source::JsonLd,
            "table" => Source::Table,
            "repeat" => Source::Repeat,
            _ => return None,
        };
        let fields = candidate
            .get("fields")?
            .as_array()?
            .iter()
            .map(|raw| {
                let text = |key: &str| raw.get(key).and_then(Value::as_str).map(str::to_owned);
                let samples: Vec<String> = raw
                    .get("samples")
                    .and_then(Value::as_array)
                    .map(|list| {
                        list.iter()
                            .filter_map(|s| s.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default();
                let present = raw.get("present").and_then(Value::as_u64)?;
                let total = raw.get("total").and_then(Value::as_u64)?;
                Some(Field {
                    name: text("name")?,
                    selector: text("selector"),
                    attr: text("attr"),
                    path: text("path"),
                    kind: infer_type(&samples),
                    required: total > 0 && present >= total,
                    all: false,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let schema = Self {
            source,
            item: candidate
                .get("item")
                .and_then(Value::as_str)
                .map(str::to_owned),
            skip: usize::try_from(candidate.get("skip").and_then(Value::as_u64).unwrap_or(0))
                .ok()?,
            fields,
        };
        schema.validate(max_fields).ok()?;
        Some(schema)
    }

    /// A JSON Schema (draft 2020-12) that every record of this schema obeys:
    /// each field is always present, `null` when it is missing and not
    /// `required`, and a list for `all`.
    #[must_use]
    pub fn json_schema(&self) -> Value {
        let mut properties = Map::new();
        for field in &self.fields {
            let one = match field.kind {
                FieldType::Text => json!({ "type": "string" }),
                FieldType::Number => json!({ "type": "number" }),
                FieldType::Money => json!({
                    "type": "object",
                    "properties": {
                        "amount": { "type": "number" },
                        "currency": { "type": ["string", "null"] },
                    },
                    "required": ["amount", "currency"],
                    "additionalProperties": false,
                }),
                FieldType::Date => {
                    json!({ "type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}" })
                }
                FieldType::Url => json!({ "type": "string", "pattern": "^https?://" }),
            };
            let shaped = if field.all {
                json!({ "type": "array", "items": one })
            } else if field.required {
                one
            } else {
                json!({ "anyOf": [one, { "type": "null" }] })
            };
            properties.insert(field.name.clone(), shaped);
        }
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": properties,
            "required": self.fields.iter().map(|f| f.name.clone()).collect::<Vec<_>>(),
            "additionalProperties": false,
        })
    }
}

fn check_text(what: &str, text: &str, longest: usize) -> Result<()> {
    if text.is_empty() || text.len() > longest || text.chars().any(char::is_control) {
        return Err(bad(format!(
            "{what} must be 1 to {longest} characters without control characters"
        )));
    }
    Ok(())
}

/// Something wrong with one value, or with the extraction as a whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// The index of the record; `0` for a problem of the whole extraction.
    pub record: usize,
    /// The field; empty for a problem of the whole extraction.
    pub field: String,
    /// What is wrong.
    pub problem: String,
}

/// The records of a page, typed, and what was wrong with them. A missing
/// required field or a value that does not fit its type is a [`Problem`]; the
/// value is `null` and the extraction goes on.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Extraction {
    /// One object per record.
    pub records: Vec<Value>,
    /// What was wrong, at most [`MAX_PROBLEMS`] of it.
    pub problems: Vec<Problem>,
    /// How many more problems there were.
    pub more_problems: usize,
}

impl Extraction {
    pub(crate) fn note(&mut self, record: usize, field: &str, problem: impl Into<String>) {
        if self.problems.len() < MAX_PROBLEMS {
            self.problems.push(Problem {
                record,
                field: field.to_owned(),
                problem: problem.into(),
            });
        } else {
            self.more_problems += 1;
        }
    }
}

/// The text of a raw cell, whitespace collapsed; empty for no value.
fn text_of(cell: &Value) -> String {
    let raw = match cell {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    };
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Types the raw records the page gave: `raw` is a list of objects with one
/// text (or list of texts) per field, as the page script reads them.
///
/// ```
/// use seleniumbase_rs_plugin_extractor::{extract_values, Schema};
///
/// let schema: Schema = serde_json::from_value(serde_json::json!({
///     "source": "selectors",
///     "fields": [{ "name": "price", "selector": ".p", "type": "money", "required": true }],
/// }))?;
/// let found = extract_values(&schema, &serde_json::json!([{ "price": "$19.99" }, { "price": null }]));
/// assert_eq!(found.records[0]["price"]["amount"], 19.99);
/// assert_eq!(found.problems[0].problem, "missing required field");
/// # Ok::<(), serde_json::Error>(())
/// ```
#[must_use]
pub fn extract_values(schema: &Schema, raw: &Value) -> Extraction {
    let mut out = Extraction::default();
    let Some(rows) = raw.as_array() else {
        out.note(0, "", "the page gave no list of records");
        return out;
    };
    for (index, row) in rows.iter().enumerate() {
        let mut record = Map::new();
        for field in &schema.fields {
            let cell = row.get(&field.name).unwrap_or(&Value::Null);
            let value = if field.all {
                let items: Vec<&Value> = match cell {
                    Value::Array(list) => list.iter().collect(),
                    Value::Null => Vec::new(),
                    other => vec![other],
                };
                let mut typed = Vec::new();
                for item in items {
                    let text = text_of(item);
                    if text.is_empty() {
                        continue;
                    }
                    match convert(field.kind, &text) {
                        Ok(value) => typed.push(value),
                        Err(why) => out.note(index, &field.name, why),
                    }
                }
                if typed.is_empty() && field.required {
                    out.note(index, &field.name, "missing required field");
                }
                Value::Array(typed)
            } else {
                let text = text_of(cell);
                if text.is_empty() {
                    if field.required {
                        out.note(index, &field.name, "missing required field");
                    }
                    Value::Null
                } else {
                    convert(field.kind, &text).unwrap_or_else(|why| {
                        out.note(index, &field.name, why);
                        Value::Null
                    })
                }
            };
            record.insert(field.name.clone(), value);
        }
        out.records.push(Value::Object(record));
    }
    out
}
