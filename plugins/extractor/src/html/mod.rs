//! Pure offline HTML extraction helpers (Markdown, metadata, JSON-LD, tables, forms).

pub mod form;
pub mod json_ld;
pub mod markdown;
pub mod metadata;
pub mod table;

pub use form::FormData;
pub use json_ld::{extract_json_ld, extract_json_ld_raw};
pub use markdown::{MarkdownOptions, html_to_markdown, html_to_markdown_with};
pub use metadata::PageMetadata;
pub use table::TableData;
