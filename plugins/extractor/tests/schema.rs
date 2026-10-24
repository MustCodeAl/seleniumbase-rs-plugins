//! Schemas, typing and the JSON Schema of the records: no page, no plugin.

use std::collections::BTreeMap;

use seleniumbase_rs_plugin_extractor::{
    Extraction, FieldSpec, FieldType, MAX_PROBLEMS, Schema, Source, extract_values,
};
use serde_json::{Value, json};

mod support;
use support::valid;

fn schema(value: Value) -> Schema {
    serde_json::from_value(value).unwrap()
}

fn product() -> Schema {
    schema(json!({
        "source": "json-ld",
        "item": "Product",
        "fields": [
            { "name": "name", "path": "name", "required": true },
            { "name": "price", "path": "offers.price", "type": "money", "required": true },
            { "name": "sku", "path": "sku" },
            { "name": "released", "path": "releaseDate", "type": "date" },
            { "name": "link", "path": "url", "type": "url" },
            { "name": "stock", "path": "stock", "type": "number" },
            { "name": "tags", "path": "keywords", "all": true },
        ],
    }))
}

// ---- building and checking schemas ---------------------------------------------

#[test]
fn a_select_map_becomes_a_schema_with_each_form_of_field() {
    let select: BTreeMap<String, FieldSpec> = serde_json::from_value(json!({
        "title": "h1",
        "price": { "selector": ".price", "type": "money", "required": true },
        "link": { "selector": "a.buy", "attr": "href", "type": "url" },
        "tags": { "selector": ".tag", "all": true },
    }))
    .unwrap();
    let schema = Schema::selectors(Some(".card".into()), &select, 64).unwrap();
    assert_eq!(schema.source, Source::Selectors);
    assert_eq!(schema.item.as_deref(), Some(".card"));
    let names: Vec<_> = schema.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["link", "price", "tags", "title"]);
    let by = |name: &str| schema.fields.iter().find(|f| f.name == name).unwrap();
    assert_eq!(by("title").kind, FieldType::Text);
    assert_eq!(by("price").kind, FieldType::Money);
    assert!(by("price").required);
    assert_eq!(by("link").attr.as_deref(), Some("href"));
    assert!(by("tags").all);
}

#[test]
fn a_field_spec_with_an_unknown_key_is_refused() {
    let result: Result<BTreeMap<String, FieldSpec>, _> =
        serde_json::from_value(json!({ "a": { "selector": "p", "colour": "red" } }));
    assert!(result.is_err());
}

#[test]
fn a_bad_schema_says_what_is_wrong() {
    let message = |value: Value, max: usize| schema(value).validate(max).unwrap_err().to_string();
    let field = json!({ "name": "a", "selector": "p" });
    assert!(
        message(json!({ "source": "selectors", "fields": [] }), 64).contains("at least one field")
    );
    assert!(
        message(
            json!({ "source": "selectors", "fields": [field, { "name": "b", "selector": "q" }] }),
            1
        )
        .contains("at most 1 fields")
    );
    assert!(
        message(json!({ "source": "table", "fields": [field] }), 64).contains("`item` selector")
    );
    assert!(
        message(
            json!({ "source": "selectors", "fields": [field, field] }),
            64
        )
        .contains("`a` appears twice")
    );
    assert!(
        message(
            json!({ "source": "selectors", "fields": [{ "name": "a" }] }),
            64
        )
        .contains("needs a `selector`")
    );
    assert!(
        message(json!({ "source": "json-ld", "fields": [field] }), 64).contains("needs a `path`")
    );
    assert!(
        message(
            json!({ "source": "selectors", "fields": [{ "name": "a\nb", "selector": "p" }] }),
            64
        )
        .contains("control characters")
    );
    assert!(
        message(
            json!({ "source": "selectors", "fields": [{ "name": "a", "selector": "p", "attr": "x y" }] }),
            64
        )
        .contains("not an attribute name")
    );
    let long = "p".repeat(501);
    assert!(
        message(
            json!({ "source": "selectors", "fields": [{ "name": "a", "selector": long }] }),
            64
        )
        .contains("1 to 500 characters")
    );
}

#[test]
fn a_schema_round_trips_and_refuses_unknown_keys() {
    let original = product();
    let again: Schema = serde_json::from_value(serde_json::to_value(&original).unwrap()).unwrap();
    assert_eq!(original, again);
    let result: Result<Schema, _> = serde_json::from_value(
        json!({ "source": "repeat", "item": ".c", "fields": [], "extra": 1 }),
    );
    assert!(result.is_err());
}

// ---- typing the raw records -------------------------------------------------------

fn raw_product() -> Value {
    json!({
        "name": "  Widget \n Pro ",
        "price": "19.99 USD",
        "sku": "W-1",
        "released": "2025-03-09",
        "link": "https://shop.test/widget",
        "stock": "1,200",
        "tags": ["a", "b"],
    })
}

#[test]
fn raw_text_becomes_typed_values() {
    let found = extract_values(&product(), &json!([raw_product()]));
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    assert_eq!(
        found.records[0],
        json!({
            "name": "Widget Pro",
            "price": { "amount": 19.99, "currency": "USD" },
            "sku": "W-1",
            "released": "2025-03-09",
            "link": "https://shop.test/widget",
            "stock": 1200,
            "tags": ["a", "b"],
        })
    );
}

#[test]
fn a_missing_required_field_is_a_problem_not_an_error() {
    let raw = json!([raw_product(), { "name": "", "price": null }, { "price": "$5" }]);
    let found = extract_values(&product(), &raw);
    assert_eq!(
        found.records.len(),
        3,
        "records are kept, whatever is missing"
    );
    assert_eq!(found.records[1]["name"], Value::Null);
    assert_eq!(found.records[1]["price"], Value::Null);
    assert_eq!(found.records[1]["tags"], json!([]));
    let problems: Vec<_> = found
        .problems
        .iter()
        .map(|p| (p.record, p.field.as_str(), p.problem.as_str()))
        .collect();
    assert_eq!(
        problems,
        [
            (1, "name", "missing required field"),
            (1, "price", "missing required field"),
            (2, "name", "missing required field"),
        ]
    );
}

#[test]
fn a_value_that_does_not_fit_its_type_is_null_with_a_problem() {
    let mut row = raw_product();
    row["price"] = json!("call us");
    row["released"] = json!("last week");
    row["link"] = json!("/relative");
    row["stock"] = json!("many");
    let found = extract_values(&product(), &json!([row]));
    for field in ["price", "released", "link", "stock"] {
        assert_eq!(found.records[0][field], Value::Null, "{field}");
    }
    let fields: Vec<_> = found.problems.iter().map(|p| p.field.as_str()).collect();
    assert_eq!(fields, ["price", "released", "link", "stock"]);
    assert!(found.problems[0].problem.contains("not an amount of money"));
    assert!(found.problems[3].problem.contains("not a number"));
}

#[test]
fn a_list_field_drops_empty_entries_and_keeps_the_rest() {
    let mut row = raw_product();
    row["tags"] = json!(["a", "", null, "b"]);
    let found = extract_values(&product(), &json!([row]));
    assert_eq!(found.records[0]["tags"], json!(["a", "b"]));
}

#[test]
fn a_reply_that_is_not_a_list_is_one_problem_for_the_whole_extraction() {
    for raw in [json!(null), json!({ "a": 1 }), json!("x")] {
        let found = extract_values(&product(), &raw);
        assert!(found.records.is_empty());
        assert_eq!(found.problems.len(), 1);
        assert_eq!(
            (found.problems[0].record, found.problems[0].field.as_str()),
            (0, "")
        );
    }
}

#[test]
fn problems_are_capped_and_the_rest_counted() {
    let many: Vec<Value> = (0..500).map(|_| json!({})).collect();
    let found: Extraction = extract_values(&product(), &Value::Array(many));
    assert_eq!(found.records.len(), 500);
    assert_eq!(found.problems.len(), MAX_PROBLEMS);
    assert_eq!(found.more_problems, 500 * 2 - MAX_PROBLEMS);
}

// ---- the JSON Schema of the records --------------------------------------------------

#[test]
fn the_json_schema_validates_the_extracted_records() {
    let schema = product();
    let json_schema = schema.json_schema();
    assert_eq!(
        json_schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(json_schema["additionalProperties"], false);
    assert_eq!(
        json_schema["properties"]["price"]["type"], "object",
        "price is money"
    );
    assert_eq!(
        json_schema["properties"]["price"]["properties"]["amount"],
        json!({ "type": "number" })
    );

    let good = extract_values(
        &schema,
        &json!([raw_product(), { "name": "B", "price": "$5" }]),
    );
    for record in &good.records {
        assert!(valid(&json_schema, record), "{record}");
    }
}

#[test]
fn the_json_schema_rejects_records_of_the_wrong_shape() {
    let json_schema = product().json_schema();
    let good = extract_values(&product(), &json!([raw_product()]))
        .records
        .remove(0);
    assert!(valid(&json_schema, &good));
    for (key, wrong) in [
        ("price", json!("19.99 USD")),
        ("price", json!({ "amount": "19.99", "currency": "USD" })),
        ("price", Value::Null),
        ("name", Value::Null),
        ("name", json!(5)),
        ("stock", json!("1200")),
        ("link", json!("/relative")),
        ("released", json!("last week")),
        ("tags", json!("a")),
    ] {
        let mut record = good.clone();
        record[key] = wrong.clone();
        assert!(!valid(&json_schema, &record), "{key} = {wrong}");
    }
    let mut extra = good.clone();
    extra["surprise"] = json!(1);
    assert!(!valid(&json_schema, &extra), "extra keys are refused");
    let mut missing = good;
    missing.as_object_mut().unwrap().remove("sku");
    assert!(
        !valid(&json_schema, &missing),
        "every field is always present"
    );
}

#[test]
fn an_optional_field_may_be_null_and_a_required_one_may_not() {
    let json_schema = product().json_schema();
    let mut record = extract_values(&product(), &json!([raw_product()]))
        .records
        .remove(0);
    record["sku"] = Value::Null;
    assert!(valid(&json_schema, &record));
    record["name"] = Value::Null;
    assert!(!valid(&json_schema, &record));
}
