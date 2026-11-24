//! Sitemap XML parsing and URL discovery for crawlers.
//!
//! Re-exports sitemap XML parsing from core [`seleniumbase_rs::crawler::sitemap`].

pub use seleniumbase_rs::crawler::sitemap::parse_sitemap_urls;

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
