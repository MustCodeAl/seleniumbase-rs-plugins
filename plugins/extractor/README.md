# seleniumbase-rs-plugin-extractor

Reads structured data off the pages a browser opens: text, links, tables, the
fields of a repeated card or a JSON-LD block, or whatever a map of CSS selectors
names. The answer is JSON, one record per card or row, typed and checked.

It reads the page the user's browser loaded and makes no request of its own.
The page script is pure: it walks at most `max_nodes` nodes, writes nothing, and
treats page content as data that is never run. Use it on pages you load and
sites you may test.

- Category: `core`. Chromium over CDP only.
- Capabilities: `page.evaluate`, `page.navigate`, `task`. (`page.navigate`
  opens the `url` of a job.)
- API: `Extractor::discover`, `Extractor::extract`, `extract_values`,
  `Schema::json_schema`; a `JobRunner` and a `Task`.

## Options

Set them under `[plugins.extractor]` in `sbase_config.toml` or with
`--plugin-opt extractor.KEY=<TOML>`. A misspelt option is an error.

| Option | Default | Meaning |
|---|---|---|
| `min_repeats` | 3 | How many sibling elements of one shape make a list of cards (2 to 1000). |
| `max_nodes` | 20000 | Most nodes the page script walks (100 to 1,000,000); past it the answer says `"truncated": true`. |
| `max_fields` | 64 | Most fields in a schema (1 to 256). |
| `max_records` | 1000 | Most records per page (1 to 100,000). |
| `max_text_chars` | 100000 | Most characters of page text returned. |
| `max_links` | 1000 | Most links returned. |

## A job

```json
{"url": "https://shop.example/p/1"}
```

With nothing else asked, the extractor discovers the structure of the page and
reads it. Other fields of a job (all optional; unknown ones are an error):

| Field | Meaning |
|---|---|
| `url` | Opened first (`http` or `https`, no credentials). Without it the page is read where it is. |
| `select` | `{"name": "css selector"}` or `{"name": {"selector", "attr", "type", "required", "all"}}`. Reads exactly these. |
| `item` | A selector for the repeated element the `select` selectors are relative to. |
| `schema` | A schema found earlier, applied as it is. |
| `discover` | `true` forces discovery, `false` turns it off. |
| `source` | With discovery, the kind to prefer: `json-ld`, `table` or `repeat`. |
| `text`, `links`, `tables`, `meta` | Also return the visible text, `http(s)` links, tables (headers and rows), title/description/Open Graph/canonical data. |

Field types are `text` (the default), `number` (`1,234.56`, `1.234,56`, `12%`),
`money` (`$19.99`, `19.99 USD`, `EUR 5`; gives `{"amount", "currency"}`), `date`
(ISO 8601) and `url` (`http(s)`).

Example answer for `{"url": "https://shop.example/p/1"}` on a page with a
JSON-LD product:

```json
{
  "url": "https://shop.example/p/1",
  "title": "Widget Pro",
  "schema": {
    "source": "json-ld",
    "item": "Product",
    "fields": [
      {"name": "name", "path": "name", "type": "text", "required": true},
      {"name": "price", "path": "offers.price", "type": "money", "required": true}
    ]
  },
  "records": [{"name": "Widget Pro", "price": {"amount": 19.99, "currency": "USD"}}],
  "problems": []
}
```

A field that is missing and `required`, or a value that does not fit its type,
is an entry in `problems` (`{"record", "field", "problem"}`, at most 200, then
`more_problems`); the value is `null` and the rest is still returned.

## Finding structure

`discover` looks, in this order, for

1. JSON-LD blocks, one candidate per `@type`; fields are the dotted paths of
   scalar properties (`offers.price`), and a `price` is paired with the
   `priceCurrency` next to it;
2. tables with a header row, one field per column (`item` selects the rows, the
   header is `skip`ped);
3. up to three groups of at least `min_repeats` sibling elements of the same
   shape, with the fields present in at least half of the sampled cards. Names
   come from `itemprop`, `data-field`, `aria-label`, the first class or the tag;
   a link is `<name>_url`.

`Schema::json_schema()` is a JSON Schema (draft 2020-12) every record obeys: each
field is always there, `null` when missing and not `required`, a list for `all`.

## The task

```json
{"urls": ["https://shop.example/p/1", "https://shop.example/p/2"],
 "extract": {"select": {"title": "h1", "price": {"selector": ".price", "type": "money"}}},
 "delay_ms": 500}
```

or `{"jobs": [{"url": "...", "links": true}, ...]}` for a different request per
page. `sbrs plugin run extractor --input pages.json` opens one tab and reads the
pages in turn. Each page records one line to the sink (the answer above plus
`"index"`), or `{"index", "url", "error"}`; the summary is
`{"total", "ok", "failed", "records"}`. A bad address in the input stops the task
before a tab opens; a page that fails afterwards does not stop the others; a
missing capability does. At most 10000 pages and a pause of at most 60 s.

## Not covered

- `auto_save` (writing each page's records as an artifact) waits for an artifact
  API in the plugin host, so the plugin does not declare `artifacts.write` and
  the option does not exist.
- Microdata, `<label>` text and layouts without a header row are not anchors; such
  pages fall back to the structural signature or to a `select` map.
- Tables are matched row by row (`item` is `<table> tr`); a nested table inside a
  cell will add its rows.

## Tests

`cargo test -p seleniumbase-rs-plugin-extractor` uses the plugin API's fakes with
canned answers of the page script. `tests/extractor_chrome.rs` (all `#[ignore]`d)
runs the real page script in headless Chrome on fixtures (a JSON-LD product, a
table, five cards, a hostile page) through `--dump-dom`; it does not go through
the seleniumbase-rs host. Run it alone:

```text
cargo test -p seleniumbase-rs-plugin-extractor --test extractor_chrome -- --ignored --test-threads=1
```
