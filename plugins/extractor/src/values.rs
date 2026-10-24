//! Turning the text a page gives into typed values, and guessing the type of
//! a column from a few samples.
//!
//! The rules are small and fixed so a record is predictable: numbers accept
//! `1,234.56`, `1.234,56`, `1 234` and `12%`; money is a number with a
//! currency symbol (`$ € £ ¥ ₹ ₩ ₽ ₺ ₪ ฿ ₫`) or a three-letter code before or
//! after it; dates are ISO 8601 (`2025-03-09`, optionally with a time); URLs
//! are `http` or `https` without spaces.

use serde_json::{Number, Value, json};

use crate::schema::FieldType;

const SYMBOLS: [(char, &str); 11] = [
    ('$', "USD"),
    ('€', "EUR"),
    ('£', "GBP"),
    ('¥', "JPY"),
    ('₹', "INR"),
    ('₩', "KRW"),
    ('₽', "RUB"),
    ('₺', "TRY"),
    ('₪', "ILS"),
    ('฿', "THB"),
    ('₫', "VND"),
];

/// A number written the way people write them.
pub(crate) fn parse_number(text: &str) -> Option<f64> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '\'' && *c != '\u{2019}')
        .collect();
    let cleaned = cleaned.strip_suffix('%').unwrap_or(&cleaned);
    let (sign, digits) = match cleaned.strip_prefix('-') {
        Some(rest) => (-1.0, rest),
        None => (1.0, cleaned.strip_prefix('+').unwrap_or(cleaned)),
    };
    if !digits
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == ',')
        || !digits.chars().any(|c| c.is_ascii_digit())
    {
        return None;
    }
    // Which separator, if any, is the decimal mark.
    let decimal = match (digits.rfind('.'), digits.rfind(',')) {
        (Some(dot), Some(comma)) => Some(dot.max(comma)),
        (Some(at), None) | (None, Some(at)) => {
            let mark = digits.as_bytes()[at];
            let repeated = digits.bytes().filter(|b| *b == mark).count() > 1;
            let thousands = mark == b',' && digits.len() - at - 1 == 3;
            if repeated || thousands {
                None
            } else {
                Some(at)
            }
        }
        (None, None) => None,
    };
    let mut normal = String::with_capacity(digits.len());
    for (at, c) in digits.char_indices() {
        if c.is_ascii_digit() {
            normal.push(c);
        } else if Some(at) == decimal {
            normal.push('.');
        }
    }
    normal
        .parse::<f64>()
        .ok()
        .map(|n| n * sign)
        .filter(|n| n.is_finite())
}

/// An amount with the currency written next to it, if any.
pub(crate) fn parse_money(text: &str) -> Option<(f64, Option<String>)> {
    let mut currency: Option<String> = None;
    let mut rest = String::new();
    for c in text.chars() {
        match SYMBOLS.iter().find(|(symbol, _)| *symbol == c) {
            Some((_, code)) => set_currency(&mut currency, code)?,
            None => rest.push(c),
        }
    }
    let mut rest = rest.trim().to_owned();
    // A code in front of the amount or behind it: `USD 5`, `5 EUR`, `EUR5`.
    if let Some(code) = rest.get(..3).filter(|c| is_code(c)).map(str::to_owned) {
        set_currency(&mut currency, &code)?;
        rest = rest[3..].trim().to_owned();
    }
    let from = rest.len().saturating_sub(3);
    if let Some(code) = rest.get(from..).filter(|c| is_code(c)).map(str::to_owned) {
        set_currency(&mut currency, &code)?;
        rest.truncate(from);
    }
    parse_number(&rest).map(|amount| (amount, currency))
}

fn is_code(text: &str) -> bool {
    text.len() == 3 && text.bytes().all(|b| b.is_ascii_uppercase())
}

/// Sets the currency, or fails when two different ones are written.
fn set_currency(currency: &mut Option<String>, code: &str) -> Option<()> {
    match currency {
        Some(known) if known != code => None,
        _ => {
            *currency = Some(code.to_owned());
            Some(())
        }
    }
}

/// An ISO 8601 date, optionally followed by a time, as written.
pub(crate) fn parse_date(text: &str) -> Option<String> {
    let text = text.trim();
    let bytes = text.as_bytes();
    if bytes.len() < 10 || !text.is_char_boundary(10) {
        return None;
    }
    let digits = |from: usize, to: usize| -> Option<u32> {
        let part = &bytes[from..to];
        if part.iter().all(u8::is_ascii_digit) {
            std::str::from_utf8(part).ok()?.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (digits(0, 4)?, digits(5, 7)?, digits(8, 10)?);
    if bytes[4] != b'-' || bytes[7] != b'-' || !(1000..=9999).contains(&year) {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let longest = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > longest {
        return None;
    }
    let tail = &bytes[10..];
    let time_ok = tail.is_empty()
        || ((tail[0] == b'T' || tail[0] == b' ')
            && tail.len() >= 6
            && tail[1..3].iter().all(u8::is_ascii_digit)
            && tail[3] == b':'
            && tail[4..6].iter().all(u8::is_ascii_digit)
            && tail[6..]
                .iter()
                .all(|b| b.is_ascii_digit() || b":.+-Zz".contains(b)));
    time_ok.then(|| text.to_owned())
}

/// An `http` or `https` address.
pub(crate) fn parse_url(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let has_scheme = lower.starts_with("http://") || lower.starts_with("https://");
    let plain = !text.chars().any(|c| c.is_whitespace() || c.is_control());
    (has_scheme && plain && text.len() > 8).then(|| text.to_owned())
}

/// The JSON value of `text` as a field of type `kind`; the error says what is
/// wrong with the text.
pub(crate) fn convert(kind: FieldType, text: &str) -> Result<Value, String> {
    match kind {
        FieldType::Text => Ok(Value::String(text.to_owned())),
        FieldType::Number => parse_number(text)
            .map(number)
            .ok_or_else(|| format!("not a number: `{}`", shorten(text))),
        FieldType::Money => parse_money(text)
            .map(|(amount, currency)| json!({ "amount": number(amount), "currency": currency }))
            .ok_or_else(|| format!("not an amount of money: `{}`", shorten(text))),
        FieldType::Date => parse_date(text)
            .map(Value::String)
            .ok_or_else(|| format!("not an ISO 8601 date: `{}`", shorten(text))),
        FieldType::Url => parse_url(text)
            .map(Value::String)
            .ok_or_else(|| format!("not an http(s) address: `{}`", shorten(text))),
    }
}

#[allow(clippy::cast_possible_truncation)]
fn number(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        return Value::Number(Number::from(value as i64));
    }
    Number::from_f64(value).map_or(Value::Null, Value::Number)
}

fn shorten(text: &str) -> String {
    text.chars().take(40).collect()
}

/// The type that fits every sample, `Text` when none does or there are none.
pub(crate) fn infer_type(samples: &[String]) -> FieldType {
    let samples: Vec<&str> = samples
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if samples.is_empty() {
        return FieldType::Text;
    }
    let all = |check: &dyn Fn(&str) -> bool| samples.iter().all(|s| check(s));
    if all(&|s| parse_money(s).is_some_and(|(_, currency)| currency.is_some())) {
        FieldType::Money
    } else if all(&|s| parse_date(s).is_some()) {
        FieldType::Date
    } else if all(&|s| parse_url(s).is_some()) {
        FieldType::Url
    } else if all(&|s| parse_number(s).is_some()) {
        FieldType::Number
    } else {
        FieldType::Text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_in_the_usual_notations() {
        for (text, expected) in [
            ("42", 42.0),
            ("-3.5", -3.5),
            ("+7", 7.0),
            ("1,234.56", 1234.56),
            ("1.234,56", 1234.56),
            ("1,234", 1234.0),
            ("1,50", 1.5),
            ("1.234.567", 1_234_567.0),
            ("1 234", 1234.0),
            ("1'234.5", 1234.5),
            ("12%", 12.0),
            (".5", 0.5),
        ] {
            assert_eq!(parse_number(text), Some(expected), "{text}");
        }
        for text in ["", "abc", "1,2,3x", "-", "12-3", "1e5", "."] {
            assert_eq!(parse_number(text), None, "{text}");
        }
    }

    #[test]
    fn money_with_symbols_and_codes() {
        let usd = Some((19.99, Some("USD".to_owned())));
        for text in [
            "$19.99",
            "$ 19.99",
            "19.99 USD",
            "USD 19.99",
            "USD19.99",
            "19.99$",
        ] {
            assert_eq!(parse_money(text), usd, "{text}");
        }
        assert_eq!(
            parse_money("€1.234,50"),
            Some((1234.5, Some("EUR".to_owned())))
        );
        assert_eq!(parse_money("19.99"), Some((19.99, None)));
        assert_eq!(parse_money("$5 EUR"), None, "two currencies");
        assert_eq!(parse_money("free"), None);
    }

    #[test]
    fn dates_are_iso_8601() {
        for text in [
            "2025-03-09",
            "2024-02-29",
            "2025-03-09T10:15:00Z",
            "2025-03-09 10:15",
            "2025-03-09T10:15:00+02:00",
        ] {
            assert_eq!(parse_date(text).as_deref(), Some(text), "{text}");
        }
        for text in [
            "2025-02-29",
            "2025-13-01",
            "09/03/2025",
            "2025-3-9",
            "2025-03-09T",
            "2025-03-09Tab:cd",
            "tomorrow",
            "",
            "2025-0é-09 and more text",
        ] {
            assert_eq!(parse_date(text), None, "{text}");
        }
    }

    #[test]
    fn urls_are_http_without_spaces() {
        assert!(parse_url("https://a.test/x?y=1").is_some());
        assert!(parse_url("HTTP://a.test").is_some());
        for text in [
            "/relative",
            "javascript:alert(1)",
            "https://a.test/a b",
            "https://",
            "ftp://a.test/x",
        ] {
            assert!(parse_url(text).is_none(), "{text}");
        }
    }

    #[test]
    fn a_type_is_inferred_only_when_every_sample_fits() {
        let s = |items: &[&str]| items.iter().map(|i| (*i).to_owned()).collect::<Vec<_>>();
        assert_eq!(infer_type(&s(&["$5", "$6.50"])), FieldType::Money);
        assert_eq!(infer_type(&s(&["5", "6.50"])), FieldType::Number);
        assert_eq!(infer_type(&s(&["$5", "6.50"])), FieldType::Text);
        assert_eq!(
            infer_type(&s(&["2025-01-01", "2025-02-03"])),
            FieldType::Date
        );
        assert_eq!(
            infer_type(&s(&["https://a.test/1", "https://a.test/2"])),
            FieldType::Url
        );
        assert_eq!(infer_type(&s(&["Widget", "Gadget"])), FieldType::Text);
        assert_eq!(infer_type(&s(&["", "  "])), FieldType::Text);
        assert_eq!(infer_type(&[]), FieldType::Text);
    }

    #[test]
    fn conversion_gives_whole_numbers_as_integers() {
        assert_eq!(convert(FieldType::Number, "12.0").unwrap(), json!(12));
        assert_eq!(convert(FieldType::Number, "12.5").unwrap(), json!(12.5));
        assert_eq!(
            convert(FieldType::Money, "£3").unwrap(),
            json!({ "amount": 3, "currency": "GBP" })
        );
        assert!(
            convert(FieldType::Number, "abc")
                .unwrap_err()
                .contains("not a number")
        );
    }
}
