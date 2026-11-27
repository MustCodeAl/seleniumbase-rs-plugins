//! Built-in geolocation catalog and proxy URL redaction helpers.

use seleniumbase_rs_plugin::{PluginError, Result};

/// Default regional persona parameters for an ISO 3166-1 alpha-2 country code.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GeoProfile {
    /// Upper-case two-letter ISO country code (for example `"DE"`).
    pub country: &'static str,
    /// BCP 47 locale tag (for example `"de-DE"`).
    pub locale: &'static str,
    /// IANA timezone identifier (for example `"Europe/Berlin"`).
    pub timezone: &'static str,
    /// Latitude in decimal degrees.
    pub latitude: f64,
    /// Longitude in decimal degrees.
    pub longitude: f64,
}

const PROFILES: &[GeoProfile] = &[
    GeoProfile {
        country: "US",
        locale: "en-US",
        timezone: "America/New_York",
        latitude: 40.7128,
        longitude: -74.0060,
    },
    GeoProfile {
        country: "GB",
        locale: "en-GB",
        timezone: "Europe/London",
        latitude: 51.5074,
        longitude: -0.1278,
    },
    GeoProfile {
        country: "DE",
        locale: "de-DE",
        timezone: "Europe/Berlin",
        latitude: 52.5200,
        longitude: 13.4050,
    },
    GeoProfile {
        country: "FR",
        locale: "fr-FR",
        timezone: "Europe/Paris",
        latitude: 48.8566,
        longitude: 2.3522,
    },
    GeoProfile {
        country: "JP",
        locale: "ja-JP",
        timezone: "Asia/Tokyo",
        latitude: 35.6762,
        longitude: 139.6503,
    },
    GeoProfile {
        country: "CA",
        locale: "en-CA",
        timezone: "America/Toronto",
        latitude: 43.6532,
        longitude: -79.3832,
    },
    GeoProfile {
        country: "AU",
        locale: "en-AU",
        timezone: "Australia/Sydney",
        latitude: -33.8688,
        longitude: 151.2093,
    },
    GeoProfile {
        country: "NL",
        locale: "nl-NL",
        timezone: "Europe/Amsterdam",
        latitude: 52.3676,
        longitude: 4.9041,
    },
    GeoProfile {
        country: "SG",
        locale: "en-SG",
        timezone: "Asia/Singapore",
        latitude: 1.3521,
        longitude: 103.8198,
    },
    GeoProfile {
        country: "BR",
        locale: "pt-BR",
        timezone: "America/Sao_Paulo",
        latitude: -23.5505,
        longitude: -46.6333,
    },
    GeoProfile {
        country: "ES",
        locale: "es-ES",
        timezone: "Europe/Madrid",
        latitude: 40.4168,
        longitude: -3.7038,
    },
    GeoProfile {
        country: "IT",
        locale: "it-IT",
        timezone: "Europe/Rome",
        latitude: 41.9028,
        longitude: 12.4964,
    },
    GeoProfile {
        country: "SE",
        locale: "sv-SE",
        timezone: "Europe/Stockholm",
        latitude: 59.3293,
        longitude: 18.0686,
    },
    GeoProfile {
        country: "CH",
        locale: "de-CH",
        timezone: "Europe/Zurich",
        latitude: 47.3769,
        longitude: 8.5417,
    },
    GeoProfile {
        country: "IN",
        locale: "en-IN",
        timezone: "Asia/Kolkata",
        latitude: 19.0760,
        longitude: 72.8777,
    },
    GeoProfile {
        country: "KR",
        locale: "ko-KR",
        timezone: "Asia/Seoul",
        latitude: 37.5665,
        longitude: 126.9780,
    },
    GeoProfile {
        country: "MX",
        locale: "es-MX",
        timezone: "America/Mexico_City",
        latitude: 19.4326,
        longitude: -99.1332,
    },
    GeoProfile {
        country: "PL",
        locale: "pl-PL",
        timezone: "Europe/Warsaw",
        latitude: 52.2297,
        longitude: 21.0122,
    },
    GeoProfile {
        country: "IE",
        locale: "en-IE",
        timezone: "Europe/Dublin",
        latitude: 53.3498,
        longitude: -6.2603,
    },
    GeoProfile {
        country: "NO",
        locale: "nb-NO",
        timezone: "Europe/Oslo",
        latitude: 59.9139,
        longitude: 10.7522,
    },
    GeoProfile {
        country: "DK",
        locale: "da-DK",
        timezone: "Europe/Copenhagen",
        latitude: 55.6761,
        longitude: 12.5683,
    },
    GeoProfile {
        country: "FI",
        locale: "fi-FI",
        timezone: "Europe/Helsinki",
        latitude: 60.1699,
        longitude: 24.9384,
    },
    GeoProfile {
        country: "BE",
        locale: "nl-BE",
        timezone: "Europe/Brussels",
        latitude: 50.8503,
        longitude: 4.3517,
    },
    GeoProfile {
        country: "AT",
        locale: "de-AT",
        timezone: "Europe/Vienna",
        latitude: 48.2082,
        longitude: 16.3738,
    },
    GeoProfile {
        country: "PT",
        locale: "pt-PT",
        timezone: "Europe/Lisbon",
        latitude: 38.7223,
        longitude: -9.1393,
    },
    GeoProfile {
        country: "CZ",
        locale: "cs-CZ",
        timezone: "Europe/Prague",
        latitude: 50.0755,
        longitude: 14.4378,
    },
    GeoProfile {
        country: "NZ",
        locale: "en-NZ",
        timezone: "Pacific/Auckland",
        latitude: -36.8509,
        longitude: 174.7645,
    },
    GeoProfile {
        country: "ZA",
        locale: "en-ZA",
        timezone: "Africa/Johannesburg",
        latitude: -26.2041,
        longitude: 28.0473,
    },
    GeoProfile {
        country: "AE",
        locale: "ar-AE",
        timezone: "Asia/Dubai",
        latitude: 25.2048,
        longitude: 55.2708,
    },
    GeoProfile {
        country: "HK",
        locale: "zh-HK",
        timezone: "Asia/Hong_Kong",
        latitude: 22.3193,
        longitude: 114.1694,
    },
    GeoProfile {
        country: "TW",
        locale: "zh-TW",
        timezone: "Asia/Taipei",
        latitude: 25.0330,
        longitude: 121.5654,
    },
    GeoProfile {
        country: "TR",
        locale: "tr-TR",
        timezone: "Europe/Istanbul",
        latitude: 41.0082,
        longitude: 28.9784,
    },
    GeoProfile {
        country: "AR",
        locale: "es-AR",
        timezone: "America/Argentina/Buenos_Aires",
        latitude: -34.6037,
        longitude: -58.3816,
    },
    GeoProfile {
        country: "CL",
        locale: "es-CL",
        timezone: "America/Santiago",
        latitude: -33.4489,
        longitude: -70.6693,
    },
    GeoProfile {
        country: "CO",
        locale: "es-CO",
        timezone: "America/Bogota",
        latitude: 4.7110,
        longitude: -74.0721,
    },
    GeoProfile {
        country: "ID",
        locale: "id-ID",
        timezone: "Asia/Jakarta",
        latitude: -6.2088,
        longitude: 106.8456,
    },
    GeoProfile {
        country: "TH",
        locale: "th-TH",
        timezone: "Asia/Bangkok",
        latitude: 13.7563,
        longitude: 100.5018,
    },
    GeoProfile {
        country: "VN",
        locale: "vi-VN",
        timezone: "Asia/Ho_Chi_Minh",
        latitude: 10.8231,
        longitude: 106.6297,
    },
    GeoProfile {
        country: "PH",
        locale: "en-PH",
        timezone: "Asia/Manila",
        latitude: 14.5995,
        longitude: 120.9842,
    },
    GeoProfile {
        country: "MY",
        locale: "ms-MY",
        timezone: "Asia/Kuala_Lumpur",
        latitude: 3.1390,
        longitude: 101.6869,
    },
];

/// Normalizes and validates an ISO 3166-1 alpha-2 country code.
///
/// # Errors
///
/// [`PluginError::Config`] when `code` is not two ASCII letters.
pub fn normalize_country(code: &str) -> Result<String> {
    let trimmed = code.trim().to_ascii_uppercase();
    if trimmed.len() != 2 || !trimmed.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(PluginError::Config(format!(
            "browser: `country` must be a two-letter ISO country code (for example \"DE\" or \"US\"), got {code:?}"
        )));
    }
    Ok(trimmed)
}

/// Looks up the built-in regional profile for a normalized country code.
#[must_use]
pub fn lookup(country: &str) -> Option<GeoProfile> {
    let upper = country.trim().to_ascii_uppercase();
    PROFILES.iter().copied().find(|p| p.country == upper)
}

/// Validates a proxy specification (`http://`, `https://`, `socks5://`, `socks5h://`)
/// without ever echoing embedded credentials in error messages.
///
/// # Errors
///
/// [`PluginError::Config`] when the scheme, host, or characters are invalid.
pub fn validate_proxy_url(raw: &str) -> Result<()> {
    let trimmed = raw.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return Err(PluginError::Config(
            "browser: proxy entry must include a scheme (`http://`, `https://`, `socks5://`, or `socks5h://`)"
                .to_owned(),
        ));
    };
    let lower = scheme.to_ascii_lowercase();
    if !matches!(lower.as_str(), "http" | "https" | "socks5" | "socks5h") {
        return Err(PluginError::Config(format!(
            "browser: unsupported proxy scheme `{lower}`; expected http, https, socks5, or socks5h"
        )));
    }
    if rest.is_empty() || trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(PluginError::Config(
            "browser: proxy entry must have a host and contain no whitespace or control characters"
                .to_owned(),
        ));
    }
    let host_part = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    if host_part.is_empty() || host_part.starts_with('/') || host_part.starts_with(':') {
        return Err(PluginError::Config(
            "browser: proxy entry is missing a valid host".to_owned(),
        ));
    }
    Ok(())
}

/// Redacts embedded credentials from a proxy URL for safe logging and `Debug` output.
#[must_use]
pub fn redact_proxy_url(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return "<redacted>".to_owned();
    };
    match rest.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://***@{host}"),
        None => raw.to_owned(),
    }
}
