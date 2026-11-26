//! Provider-agnostic AI extraction prompt builder and JSON response parser.
//!
//! This module does not bundle an HTTP client or lock into a single LLM vendor.
//! Callers build a structured [`AiExtractionPrompt`] from a [`Schema`] (or raw
//! JSON Schema) and page content, send the messages to any model provider, and
//! pass the raw text reply to [`parse_ai_response`] or [`parse_ai_records`].

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ExtractError;
use crate::schema::Schema;

/// A provider-agnostic prompt pair ready to send to any chat/completion API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiExtractionPrompt {
    /// System instructions constraining the model to strict JSON output.
    pub system: String,
    /// User message containing the target JSON Schema and source page content.
    pub user: String,
    /// JSON Schema describing the expected extraction payload.
    pub json_schema: Value,
}

/// Builder for [`AiExtractionPrompt`].
#[derive(Clone, Debug, Default)]
pub struct AiPromptBuilder {
    json_schema: Option<Value>,
    content: String,
    instructions: Option<String>,
    max_content_chars: Option<usize>,
    expect_array: bool,
}

impl AiPromptBuilder {
    /// Creates a new empty prompt builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the extraction target from a discovered or hand-written [`Schema`].
    #[must_use]
    pub fn schema(mut self, schema: &Schema) -> Self {
        self.json_schema = Some(schema.json_schema());
        self.expect_array = true;
        self
    }

    /// Sets the extraction target from an arbitrary JSON Schema object.
    #[must_use]
    pub fn json_schema(mut self, schema: Value) -> Self {
        self.json_schema = Some(schema);
        self
    }

    /// Sets the source page content (for example Markdown from [`crate::html::html_to_markdown`]).
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Adds optional domain-specific extraction instructions.
    #[must_use]
    pub fn instructions(mut self, instructions: impl Into<String>) -> Self {
        self.instructions = Some(instructions.into());
        self
    }

    /// Caps the source content length in Unicode scalar values.
    #[must_use]
    pub const fn max_content_chars(mut self, limit: usize) -> Self {
        self.max_content_chars = Some(limit);
        self
    }

    /// Requests a JSON array of records rather than a single JSON object.
    #[must_use]
    pub const fn expect_array(mut self, expect_array: bool) -> Self {
        self.expect_array = expect_array;
        self
    }

    /// Validates inputs and builds the [`AiExtractionPrompt`].
    ///
    /// # Errors
    ///
    /// Returns [`ExtractError::InvalidInput`] if the content is empty or no schema was provided.
    pub fn build(self) -> Result<AiExtractionPrompt, ExtractError> {
        let trimmed = self.content.trim();
        if trimmed.is_empty() {
            return Err(ExtractError::InvalidInput(
                "AI extraction content must not be empty".to_owned(),
            ));
        }
        let json_schema = self.json_schema.ok_or_else(|| {
            ExtractError::InvalidInput("AI extraction requires a schema or json_schema".to_owned())
        })?;

        let content = match self.max_content_chars {
            Some(limit) if trimmed.chars().count() > limit => {
                trimmed.chars().take(limit).collect::<String>()
            }
            _ => trimmed.to_owned(),
        };

        let shape = if self.expect_array {
            "a JSON array of objects"
        } else {
            "a single JSON object"
        };

        let system = format!(
            "You are a precise structured data extractor. Return ONLY valid JSON ({shape}) \
             matching the provided JSON Schema. Do not include commentary or markdown fences. \
             Use null for missing optional fields."
        );

        let schema_str = serde_json::to_string_pretty(&json_schema)?;
        let mut user = String::new();
        if let Some(extra) = self.instructions.as_deref().map(str::trim)
            && !extra.is_empty()
        {
            user.push_str("Instructions:\n");
            user.push_str(extra);
            user.push_str("\n\n");
        }
        user.push_str("Target JSON Schema:\n");
        user.push_str(&schema_str);
        user.push_str("\n\nSource Content:\n");
        user.push_str(&content);

        Ok(AiExtractionPrompt {
            system,
            user,
            json_schema,
        })
    }
}

/// Strips optional markdown code fences (such as ```` ```json ... ``` ````) and parses JSON.
///
/// # Errors
///
/// Returns [`ExtractError::InvalidInput`] if the response is empty, or [`ExtractError::Json`]
/// if the extracted payload is not valid JSON.
pub fn parse_ai_response(raw: &str) -> Result<Value, ExtractError> {
    let cleaned = strip_code_fences(raw);
    if cleaned.is_empty() {
        return Err(ExtractError::InvalidInput(
            "AI response was empty".to_owned(),
        ));
    }
    serde_json::from_str(cleaned).map_err(ExtractError::from)
}

/// Parses an AI response into a list of JSON record objects.
///
/// Accepts either a top-level JSON array, an object wrapping `"records": [...]`,
/// or a single JSON object (returned as a one-element `Vec`).
///
/// # Errors
///
/// Returns [`ExtractError::InvalidInput`] if the parsed value is neither an object
/// nor an array of objects, or [`ExtractError::Json`] on malformed JSON.
pub fn parse_ai_records(raw: &str) -> Result<Vec<Value>, ExtractError> {
    let value = parse_ai_response(raw)?;
    match value {
        Value::Array(items) => {
            if items.iter().all(Value::is_object) {
                Ok(items)
            } else {
                Err(ExtractError::InvalidInput(
                    "AI response array must contain JSON objects".to_owned(),
                ))
            }
        }
        Value::Object(mut map) => {
            if let Some(Value::Array(items)) = map.remove("records")
                && items.iter().all(Value::is_object)
            {
                return Ok(items);
            }
            Ok(vec![Value::Object(map)])
        }
        other => Err(ExtractError::InvalidInput(format!(
            "expected JSON object or array of objects, got {}",
            json_type_name(&other)
        ))),
    }
}

/// Builds a minimal JSON Schema object from a list of `(field_name, json_type)` pairs.
#[must_use]
pub fn object_schema(fields: &[(&str, &str)]) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::with_capacity(fields.len());
    for (name, ty) in fields {
        properties.insert((*name).to_owned(), json!({ "type": ty }));
        required.push(Value::String((*name).to_owned()));
    }
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

fn strip_code_fences(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```") {
        let after_lang = rest.find('\n').map_or(rest, |idx| &rest[idx + 1..]);
        if let Some(body) = after_lang.strip_suffix("```") {
            return body.trim();
        }
        return after_lang.trim();
    }
    trimmed
}

const fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
