//! Tool-calling interface for LangChain agents using seleniumbase-rs.

use crate::error::{LangChainError, Result};
use seleniumbase_rs_plugin_extractor::html::html_to_markdown;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[cfg(feature = "plugin")]
use seleniumbase_rs_plugin::PageHandle;

/// Actions supported by the [`SeleniumBaseTool`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ToolAction {
    /// Navigates the browser to the specified URL.
    Navigate {
        /// Target URL to navigate to.
        url: String,
    },
    /// Clicks on an element identified by CSS selector.
    Click {
        /// CSS selector of the element to click.
        selector: String,
    },
    /// Types text into an input or textarea element identified by CSS selector.
    TypeText {
        /// CSS selector of the target input element.
        selector: String,
        /// The text string to type.
        text: String,
    },
    /// Extracts the page (or a scoped element) as clean LLM-friendly Markdown.
    ExtractMarkdown {
        /// Optional CSS selector to scope markdown extraction.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
    },
}

/// Raw input payload accepted by the tool from LLM tool-calling invocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInput {
    /// The action name (`"navigate"`, `"click"`, `"type_text"`, or `"extract_markdown"`).
    pub action: String,
    /// Destination URL for `"navigate"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Target selector for `"click"`, `"type_text"`, or optional for `"extract_markdown"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// Text to enter for `"type_text"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl ToolInput {
    /// Converts a raw [`ToolInput`] into a typed [`ToolAction`].
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError::InvalidInput`] if required fields for the action are missing.
    pub fn into_action(self) -> Result<ToolAction> {
        match self.action.to_ascii_lowercase().as_str() {
            "navigate" | "open" | "goto" => {
                let url = self.url.ok_or_else(|| {
                    LangChainError::InvalidInput("missing 'url' for 'navigate' action".into())
                })?;
                Ok(ToolAction::Navigate { url })
            }
            "click" => {
                let selector = self.selector.ok_or_else(|| {
                    LangChainError::InvalidInput("missing 'selector' for 'click' action".into())
                })?;
                Ok(ToolAction::Click { selector })
            }
            "type_text" | "type" | "send_keys" | "fill" => {
                let selector = self.selector.ok_or_else(|| {
                    LangChainError::InvalidInput("missing 'selector' for 'type_text' action".into())
                })?;
                let text = self.text.ok_or_else(|| {
                    LangChainError::InvalidInput("missing 'text' for 'type_text' action".into())
                })?;
                Ok(ToolAction::TypeText { selector, text })
            }
            "extract_markdown" | "extract" | "to_markdown" => Ok(ToolAction::ExtractMarkdown {
                selector: self.selector,
            }),
            other => Err(LangChainError::InvalidInput(format!(
                "unrecognized tool action: '{other}'. Expected 'navigate', 'click', 'type_text', or 'extract_markdown'"
            ))),
        }
    }
}

impl From<ToolAction> for ToolInput {
    fn from(action: ToolAction) -> Self {
        match action {
            ToolAction::Navigate { url } => Self {
                action: "navigate".into(),
                url: Some(url),
                selector: None,
                text: None,
            },
            ToolAction::Click { selector } => Self {
                action: "click".into(),
                url: None,
                selector: Some(selector),
                text: None,
            },
            ToolAction::TypeText { selector, text } => Self {
                action: "type_text".into(),
                url: None,
                selector: Some(selector),
                text: Some(text),
            },
            ToolAction::ExtractMarkdown { selector } => Self {
                action: "extract_markdown".into(),
                url: None,
                selector,
                text: None,
            },
        }
    }
}

/// The result returned from executing a [`SeleniumBaseTool`] action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolOutput {
    /// Whether the action succeeded.
    pub success: bool,
    /// Result payload or summary on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Error description on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ToolOutput {
    /// Creates a successful tool execution output.
    #[must_use]
    pub fn success(result: impl Into<String>) -> Self {
        Self {
            success: true,
            result: Some(result.into()),
            error: None,
        }
    }

    /// Creates a failed tool execution output.
    #[must_use]
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            result: None,
            error: Some(error.into()),
        }
    }

    /// Converts output to a JSON [`Value`].
    #[must_use]
    pub fn to_json_value(&self) -> Value {
        json!(self)
    }

    /// Serializes output to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// LangChain agent tool for browser automation and content extraction.
///
/// Implements standard OpenAI / LangChain function-calling JSON schema
/// and executes `navigate`, `click`, `type_text`, and `extract_markdown` commands.
///
/// # Examples
///
/// ```
/// use seleniumbase_rs_plugin_langchain::{SeleniumBaseTool, ToolAction};
///
/// let tool = SeleniumBaseTool::new();
/// assert_eq!(tool.name(), "seleniumbase");
///
/// let schema = tool.schema();
/// assert_eq!(schema["type"], "object");
/// assert!(schema["properties"]["action"]["enum"]
///     .as_array()
///     .unwrap()
///     .contains(&serde_json::json!("navigate")));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeleniumBaseTool {
    name: String,
    description: String,
}

impl Default for SeleniumBaseTool {
    fn default() -> Self {
        Self {
            name: "seleniumbase".to_string(),
            description: "Web automation tool for navigating web pages, clicking elements, typing text, and extracting clean markdown content.".to_string(),
        }
    }
}

impl SeleniumBaseTool {
    /// Creates a new `SeleniumBaseTool` with default name and description.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Customizes the tool name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Customizes the tool description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Returns the tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the tool description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Generates the standard JSON Schema describing tool input parameters.
    #[must_use]
    pub fn schema(&self) -> Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "SeleniumBaseToolInput",
            "type": "object",
            "description": "Input parameters for SeleniumBase browser automation",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["navigate", "click", "type_text", "extract_markdown"],
                    "description": "The browser action to execute: 'navigate' to visit a URL, 'click' to click an element, 'type_text' to enter text into an input field, 'extract_markdown' to convert HTML to Markdown."
                },
                "url": {
                    "type": "string",
                    "description": "The destination URL (required when action is 'navigate')."
                },
                "selector": {
                    "type": "string",
                    "description": "CSS selector of the target element (required for 'click' and 'type_text', optional for 'extract_markdown')."
                },
                "text": {
                    "type": "string",
                    "description": "Text to type into the element (required when action is 'type_text')."
                }
            },
            "required": ["action"]
        })
    }

    /// Returns the full OpenAI / LangChain function-calling tool definition object.
    #[must_use]
    pub fn tool_definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.schema()
            }
        })
    }

    /// Executes a [`ToolAction`] against a [`PageHandle`].
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if page communication fails or script evaluation fails.
    #[cfg(feature = "plugin")]
    pub async fn execute(&self, action: ToolAction, page: &dyn PageHandle) -> Result<ToolOutput> {
        match action {
            ToolAction::Navigate { url } => {
                page.navigate(&url).await.map_err(|e| {
                    LangChainError::Page(format!("navigation to {url} failed: {e}"))
                })?;
                Ok(ToolOutput::success(format!("Navigated to {url}")))
            }
            ToolAction::Click { selector } => {
                let sel_escaped = serde_json::to_string(&selector)?;
                let script = format!(
                    r#"(() => {{
                        const el = document.querySelector({sel_escaped});
                        if (!el) {{
                            return {{ success: false, error: "Element not found" }};
                        }}
                        el.scrollIntoView({{ block: 'center', inline: 'center' }});
                        el.click();
                        return {{ success: true }};
                    }})()"#
                );

                let reply = page
                    .evaluate(&script)
                    .await
                    .map_err(|e| LangChainError::Page(format!("click evaluation failed: {e}")))?;

                if reply
                    .get("success")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    Ok(ToolOutput::success(format!(
                        "Successfully clicked element '{selector}'"
                    )))
                } else {
                    let err = reply
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("Element not found");
                    Ok(ToolOutput::failure(format!(
                        "Failed to click '{selector}': {err}"
                    )))
                }
            }
            ToolAction::TypeText { selector, text } => {
                let sel_escaped = serde_json::to_string(&selector)?;
                let text_escaped = serde_json::to_string(&text)?;
                let script = format!(
                    r#"(() => {{
                        const el = document.querySelector({sel_escaped});
                        if (!el) {{
                            return {{ success: false, error: "Element not found" }};
                        }}
                        el.scrollIntoView({{ block: 'center', inline: 'center' }});
                        el.focus();
                        el.value = {text_escaped};
                        el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        return {{ success: true }};
                    }})()"#
                );

                let reply = page.evaluate(&script).await.map_err(|e| {
                    LangChainError::Page(format!("type_text evaluation failed: {e}"))
                })?;

                if reply
                    .get("success")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    Ok(ToolOutput::success(format!(
                        "Successfully typed text into element '{selector}'"
                    )))
                } else {
                    let err = reply
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("Element not found");
                    Ok(ToolOutput::failure(format!(
                        "Failed to type into '{selector}': {err}"
                    )))
                }
            }
            ToolAction::ExtractMarkdown { selector } => {
                let script = if let Some(sel) = &selector {
                    let sel_escaped = serde_json::to_string(sel)?;
                    format!(
                        r#"(() => {{
                            const el = document.querySelector({sel_escaped});
                            if (!el) {{
                                return {{ success: false, error: "Element not found" }};
                            }}
                            return {{ success: true, html: el.outerHTML }};
                        }})()"#
                    )
                } else {
                    r#"(() => {
                        return { success: true, html: document.documentElement.outerHTML };
                    })()"#
                        .to_string()
                };

                let reply = page.evaluate(&script).await.map_err(|e| {
                    LangChainError::Page(format!("extract_markdown evaluation failed: {e}"))
                })?;

                if reply
                    .get("success")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    let html = reply
                        .get("html")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let md = html_to_markdown(html);
                    Ok(ToolOutput::success(md))
                } else {
                    let err = reply
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("Element not found");
                    let sel_name = selector.as_deref().unwrap_or("page");
                    Ok(ToolOutput::failure(format!(
                        "Failed to extract markdown from '{sel_name}': {err}"
                    )))
                }
            }
        }
    }

    /// Parses and executes a raw [`ToolInput`] against a [`PageHandle`].
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if input validation or action execution fails.
    #[cfg(feature = "plugin")]
    pub async fn execute_input(
        &self,
        input: ToolInput,
        page: &dyn PageHandle,
    ) -> Result<ToolOutput> {
        let action = input.into_action()?;
        self.execute(action, page).await
    }

    /// Parses JSON arguments into an action and executes them against a [`PageHandle`].
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if JSON parsing or execution fails.
    #[cfg(feature = "plugin")]
    pub async fn execute_json(&self, args: &Value, page: &dyn PageHandle) -> Result<ToolOutput> {
        let action: ToolAction = serde_json::from_value(args.clone()).or_else(|_| {
            let input: ToolInput = serde_json::from_value(args.clone())?;
            input.into_action()
        })?;
        self.execute(action, page).await
    }

    /// Parses a JSON string argument, executes the action, and returns a JSON string response.
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if deserialization, execution, or serialization fails.
    #[cfg(feature = "plugin")]
    pub async fn execute_raw(&self, json_str: &str, page: &dyn PageHandle) -> Result<String> {
        let val: Value = serde_json::from_str(json_str)?;
        let output = self.execute_json(&val, page).await?;
        let output_str = serde_json::to_string(&output)?;
        Ok(output_str)
    }

    /// Executes a [`ToolAction`] directly on a [`seleniumbase_rs::BaseCase`] session.
    ///
    /// # Errors
    ///
    /// Returns [`LangChainError`] if the underlying browser action fails.
    pub async fn execute_base_case(
        &self,
        action: ToolAction,
        sb: &mut seleniumbase_rs::BaseCase,
    ) -> Result<ToolOutput> {
        match action {
            ToolAction::Navigate { url } => {
                sb.open(&url).await?;
                Ok(ToolOutput::success(format!("Navigated to {url}")))
            }
            ToolAction::Click { selector } => {
                sb.click(selector.as_str()).await?;
                Ok(ToolOutput::success(format!(
                    "Successfully clicked element '{selector}'"
                )))
            }
            ToolAction::TypeText { selector, text } => {
                sb.type_text(selector.as_str(), &text).await?;
                Ok(ToolOutput::success(format!(
                    "Successfully typed text into element '{selector}'"
                )))
            }
            ToolAction::ExtractMarkdown { selector: _ } => {
                let html = sb.page_source().await?;
                let md = html_to_markdown(&html);
                Ok(ToolOutput::success(md))
            }
        }
    }
}
