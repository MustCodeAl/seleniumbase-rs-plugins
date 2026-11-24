//! Sitemap XML parsing and URL discovery for crawlers.
//!
//! Provides [`parse_sitemap_urls`] to extract target `<loc>` URLs from standard
//! XML sitemaps and sitemap index files without heavy external XML libraries.

/// Extracts all `<loc>` URLs from an XML sitemap or sitemap index string.
///
/// # Examples
///
/// ```
/// use seleniumbase_rs_plugin_crawler::sitemap::parse_sitemap_urls;
///
/// let xml = r#"
///     <?xml version="1.0" encoding="UTF-8"?>
///     <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
///         <url><loc>https://example.com/page1</loc></url>
///         <url><loc>https://example.com/page2</loc></url>
///     </urlset>
/// "#;
///
/// let urls = parse_sitemap_urls(xml);
/// assert_eq!(urls.len(), 2);
/// assert_eq!(urls[0], "https://example.com/page1");
/// assert_eq!(urls[1], "https://example.com/page2");
/// ```
#[must_use]
pub fn parse_sitemap_urls(xml_text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut remaining = xml_text;

    while let Some(start_loc) = remaining.find("<loc>") {
        let after_loc = &remaining[start_loc + 5..];
        if let Some(end_loc) = after_loc.find("</loc>") {
            let url = after_loc[..end_loc].trim();
            if !url.is_empty() {
                urls.push(url.to_string());
            }
            remaining = &after_loc[end_loc + 6..];
        } else {
            break;
        }
    }

    urls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_loc_urls() {
        let sitemap = r#"
            <urlset>
                <url><loc>https://shop.com/item/1</loc><lastmod>2026-01-01</lastmod></url>
                <url><loc>https://shop.com/item/2</loc></url>
            </urlset>
        "#;
        let urls = parse_sitemap_urls(sitemap);
        assert_eq!(
            urls,
            vec!["https://shop.com/item/1", "https://shop.com/item/2"]
        );
    }
}
