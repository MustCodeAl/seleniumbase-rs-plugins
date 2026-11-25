//! OWASP Pentest-Kit (`DenisPodgurskii/pentestkit`) extension, rule catalog, and
//! passive scan envelope integration.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{OwaspError, Result};
use crate::types::{AuditorKind, Finding, OwaspCategory, Severity, redact_secret};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_MODULES_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

/// Known relative paths where PTK places `modules.json` inside an unpacked extension.
const PTK_MODULE_CANDIDATES: &[&str] = &[
    "ptk/background/sast/modules/modules.json",
    "src/ptk/background/sast/modules/modules.json",
    "ptk/background/dast/modules/passive.json",
    "src/ptk/background/dast/modules/passive.json",
    "modules/modules.json",
    "modules.json",
];

/// PTK scanning engine classification for passive findings and modules.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PtkEngine {
    /// Passive dynamic analysis of HTTP traffic and responses.
    DastPassive,
    /// Passive client-side static JavaScript/DOM analysis.
    SastPassive,
    /// Passive in-browser runtime sink/taint observation.
    IastPassive,
    /// Passive software composition analysis of client-side libraries.
    Sca,
    /// Generic passive security observation.
    #[default]
    Passive,
}

impl PtkEngine {
    /// Canonical snake_case engine identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DastPassive => "dast_passive",
            Self::SastPassive => "sast_passive",
            Self::IastPassive => "iast_passive",
            Self::Sca => "sca",
            Self::Passive => "passive",
        }
    }
}

impl fmt::Display for PtkEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PtkEngine {
    type Err = OwaspError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dast_passive" | "dast-passive" | "dast" => Ok(Self::DastPassive),
            "sast_passive" | "sast-passive" | "sast" => Ok(Self::SastPassive),
            "iast_passive" | "iast-passive" | "iast" => Ok(Self::IastPassive),
            "sca" => Ok(Self::Sca),
            "passive" => Ok(Self::Passive),
            other => Err(OwaspError::Config(format!("unknown PTK engine `{other}`"))),
        }
    }
}

/// Configuration for optional OWASP PTK extension loading and `modules.json` ingestion.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PtkExtensionConfig {
    /// Unpacked PTK extension directory containing a Manifest V3 `manifest.json`.
    pub extension_dir: Option<PathBuf>,
    /// Optional packed `.crx` or `.zip` archive path to validate before launch.
    pub extension_archive: Option<PathBuf>,
    /// Optional explicit path to a PTK `modules.json` passive rule catalog.
    pub modules_path: Option<PathBuf>,
    /// When `true`, `manifest.json` must identify itself as PTK / PentestKit.
    pub require_ptk_manifest: bool,
}

impl PtkExtensionConfig {
    /// Creates an empty PTK configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the unpacked extension directory.
    #[must_use]
    pub fn extension_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.extension_dir = Some(path.into());
        self
    }

    /// Sets a packed `.crx` or `.zip` archive path for validation.
    #[must_use]
    pub fn extension_archive(mut self, path: impl Into<PathBuf>) -> Self {
        self.extension_archive = Some(path.into());
        self
    }

    /// Sets an explicit PTK `modules.json` catalog path.
    #[must_use]
    pub fn modules_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.modules_path = Some(path.into());
        self
    }

    /// Requires the extension manifest name or description to identify PTK.
    #[must_use]
    pub fn require_ptk_manifest(mut self, required: bool) -> Self {
        self.require_ptk_manifest = required;
        self
    }

    /// Returns all configured filesystem paths that a plugin host needs read access to.
    #[must_use]
    pub fn declared_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(dir) = &self.extension_dir {
            paths.push(dir.clone());
        }
        if let Some(archive) = &self.extension_archive {
            paths.push(archive.clone());
        }
        if let Some(modules) = &self.modules_path {
            paths.push(modules.clone());
        }
        paths
    }

    /// Validates the extension directory/archive and loads any configured or discovered
    /// passive `modules.json` catalog.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::InvalidExtension`] if paths are missing, the manifest is not
    /// Manifest V3, or an archive header is invalid; or [`OwaspError::Json`] / [`OwaspError::Io`]
    /// if `modules.json` cannot be read or parsed.
    pub fn validate(&self) -> Result<PtkExtensionStatus> {
        let mut resolved_dir = None;
        let mut manifest = None;
        let mut discovered_modules_path = None;

        if let Some(dir) = &self.extension_dir {
            let mut real = canonicalize_existing(dir, "extension directory")?;
            let meta = fs::metadata(&real).map_err(|source| OwaspError::Io {
                path: real.clone(),
                source,
            })?;
            if !meta.is_dir() {
                return Err(OwaspError::InvalidExtension {
                    path: dir.clone(),
                    reason: "expected an unpacked directory, found a file".to_owned(),
                });
            }
            // Support PTK artifact root containing a `chromium-unpacked` folder.
            if !real.join("manifest.json").is_file()
                && real.join("chromium-unpacked/manifest.json").is_file()
            {
                real = canonicalize_existing(
                    &real.join("chromium-unpacked"),
                    "chromium-unpacked extension directory",
                )?;
            }
            if real.to_string_lossy().contains(',') {
                return Err(OwaspError::InvalidExtension {
                    path: dir.clone(),
                    reason: "Chromium --load-extension paths cannot contain commas".to_owned(),
                });
            }
            let parsed = validate_mv3_manifest(&real)?;
            if self.require_ptk_manifest && !parsed.is_ptk() {
                return Err(OwaspError::InvalidExtension {
                    path: dir.clone(),
                    reason: format!(
                        "manifest `{}` does not appear to be OWASP PTK / PentestKit",
                        parsed.name
                    ),
                });
            }
            discovered_modules_path = PTK_MODULE_CANDIDATES
                .iter()
                .map(|rel| real.join(rel))
                .find(|candidate| candidate.is_file());
            resolved_dir = Some(real);
            manifest = Some(parsed);
        }

        let automation_enabled = resolved_dir
            .as_deref()
            .and_then(read_dev_local_automation_enabled);

        let mut archive_format = None;
        if let Some(archive) = &self.extension_archive {
            archive_format = Some(validate_packed_archive(archive)?);
        }

        let modules_source = self.modules_path.clone().or(discovered_modules_path);
        let catalog = match &modules_source {
            Some(path) => Some(PtkModuleCatalog::from_file(path)?),
            None => None,
        };

        Ok(PtkExtensionStatus {
            extension_dir: resolved_dir,
            manifest,
            archive_format,
            modules_path: modules_source,
            catalog,
            automation_enabled,
        })
    }

    /// Validates configuration specifically for Chromium browser launch extension injection.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::InvalidExtension`] if validation fails or if only a packed archive
    /// was supplied without an unpacked `extension_dir`.
    pub fn validate_for_launch(&self) -> Result<PtkExtensionStatus> {
        let status = self.validate()?;
        if status.extension_dir.is_none()
            && let Some(archive) = &self.extension_archive
        {
            return Err(OwaspError::InvalidExtension {
                path: archive.clone(),
                reason: "Chromium LaunchSettings::extensions requires an unpacked extension_dir (unpack the archive or pair with seleniumbase-rs-plugin-browser)".to_owned(),
            });
        }
        Ok(status)
    }
}

/// Format of a validated packed browser extension archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PackedArchiveFormat {
    /// CRX version 2 (`Cr24` header with version 2).
    Crx2,
    /// CRX version 3 (`Cr24` header with version 3).
    Crx3,
    /// Standard ZIP archive (`PK\x03\x04` or empty `PK\x05\x06`).
    Zip,
}

/// Validated metadata parsed from a Chromium Manifest V3 `manifest.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtkManifestInfo {
    /// Extension display name.
    pub name: String,
    /// Extension version string.
    pub version: String,
    /// Manifest format version (must be `3`).
    pub manifest_version: u64,
    /// Optional description string.
    pub description: Option<String>,
    /// Optional MV3 `background.service_worker` path.
    pub service_worker: Option<String>,
    /// Declared `permissions` entries.
    pub permissions: Vec<String>,
    /// Declared `host_permissions` entries.
    pub host_permissions: Vec<String>,
}

impl PtkManifestInfo {
    /// Returns `true` if the manifest name or description identifies OWASP PTK / PentestKit.
    #[must_use]
    pub fn is_ptk(&self) -> bool {
        let haystack = format!(
            "{} {}",
            self.name.to_ascii_lowercase(),
            self.description
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
        );
        haystack.contains("pentestkit")
            || haystack.contains("pentest-kit")
            || haystack.contains("owasp ptk")
            || haystack == "ptk"
    }
}

/// Outcome of validating [`PtkExtensionConfig`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PtkExtensionStatus {
    /// Canonical unpacked extension directory ready for `LaunchSettings::extensions`.
    pub extension_dir: Option<PathBuf>,
    /// Parsed Manifest V3 metadata when `extension_dir` was provided.
    pub manifest: Option<PtkManifestInfo>,
    /// Validated packed archive format when `extension_archive` was provided.
    pub archive_format: Option<PackedArchiveFormat>,
    /// Path to `modules.json` that was loaded, if any.
    pub modules_path: Option<PathBuf>,
    /// Parsed passive rule catalog from `modules.json`, if present.
    pub catalog: Option<PtkModuleCatalog>,
    /// `automationEnabled` read from `dev.local.json` inside the extension folder, if present.
    pub automation_enabled: Option<bool>,
}

fn canonicalize_existing(path: &Path, label: &str) -> Result<PathBuf> {
    fs::canonicalize(path).map_err(|source| match source.kind() {
        std::io::ErrorKind::NotFound => OwaspError::InvalidExtension {
            path: path.to_path_buf(),
            reason: format!("{label} does not exist"),
        },
        _ => OwaspError::Io {
            path: path.to_path_buf(),
            source,
        },
    })
}

fn validate_mv3_manifest(dir: &Path) -> Result<PtkManifestInfo> {
    let manifest_path = dir.join("manifest.json");
    let meta = fs::metadata(&manifest_path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            OwaspError::InvalidExtension {
                path: dir.to_path_buf(),
                reason: "manifest.json is missing".to_owned(),
            }
        } else {
            OwaspError::Io {
                path: manifest_path.clone(),
                source: err,
            }
        }
    })?;
    if !meta.is_file() {
        return Err(OwaspError::InvalidExtension {
            path: manifest_path,
            reason: "manifest.json is not a regular file".to_owned(),
        });
    }
    if meta.len() > MAX_MANIFEST_BYTES {
        return Err(OwaspError::InvalidExtension {
            path: manifest_path,
            reason: "manifest.json exceeds 1 MiB limit".to_owned(),
        });
    }
    let bytes = fs::read(&manifest_path).map_err(|source| OwaspError::Io {
        path: manifest_path.clone(),
        source,
    })?;
    // Strip UTF-8 BOM produced by some Windows/JSON editors.
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    let value: Value = serde_json::from_slice(text).map_err(|source| OwaspError::Json {
        context: format!("parsing {}", manifest_path.display()),
        source,
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| OwaspError::InvalidExtension {
            path: manifest_path.clone(),
            reason: "manifest.json must be a JSON object".to_owned(),
        })?;
    let mv = object
        .get("manifest_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| OwaspError::InvalidExtension {
            path: manifest_path.clone(),
            reason: "manifest.json is missing numeric manifest_version".to_owned(),
        })?;
    if mv != 3 {
        return Err(OwaspError::InvalidExtension {
            path: manifest_path,
            reason: format!("manifest_version is {mv}; only Manifest V3 (3) is supported"),
        });
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OwaspError::InvalidExtension {
            path: manifest_path.clone(),
            reason: "manifest.json is missing a non-empty `name`".to_owned(),
        })?
        .to_owned();
    let version = object
        .get("version")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OwaspError::InvalidExtension {
            path: manifest_path,
            reason: "manifest.json is missing a non-empty `version`".to_owned(),
        })?
        .to_owned();

    let description = object
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let service_worker = object
        .get("background")
        .and_then(|bg| bg.get("service_worker"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let permissions = string_array(object.get("permissions"));
    let host_permissions = string_array(object.get("host_permissions"));

    Ok(PtkManifestInfo {
        name,
        version,
        manifest_version: mv,
        description,
        service_worker,
        permissions,
        host_permissions,
    })
}

fn validate_packed_archive(path: &Path) -> Result<PackedArchiveFormat> {
    let real = canonicalize_existing(path, "extension archive")?;
    let meta = fs::metadata(&real).map_err(|source| OwaspError::Io {
        path: real.clone(),
        source,
    })?;
    if !meta.is_file() {
        return Err(OwaspError::InvalidExtension {
            path: path.to_path_buf(),
            reason: "expected a .crx or .zip file".to_owned(),
        });
    }
    if meta.len() > MAX_ARCHIVE_BYTES {
        return Err(OwaspError::InvalidExtension {
            path: path.to_path_buf(),
            reason: "archive exceeds 512 MiB limit".to_owned(),
        });
    }
    let header = fs::read(&real).map_err(|source| OwaspError::Io {
        path: real.clone(),
        source,
    })?;
    if header.starts_with(b"Cr24") {
        if header.len() < 12 {
            return Err(OwaspError::InvalidExtension {
                path: path.to_path_buf(),
                reason: "truncated CRX header".to_owned(),
            });
        }
        let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        return match version {
            2 => Ok(PackedArchiveFormat::Crx2),
            3 => Ok(PackedArchiveFormat::Crx3),
            other => Err(OwaspError::InvalidExtension {
                path: path.to_path_buf(),
                reason: format!("unsupported CRX format version {other}"),
            }),
        };
    }
    if header.starts_with(b"PK\x03\x04") || header.starts_with(b"PK\x05\x06") {
        return Ok(PackedArchiveFormat::Zip);
    }
    Err(OwaspError::InvalidExtension {
        path: path.to_path_buf(),
        reason: "file is neither a valid CRX nor a ZIP archive".to_owned(),
    })
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Taxonomy and remediation metadata attached to a PTK module or rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtkModuleMetadata {
    /// Severity declared in `modules.json`.
    pub severity: Option<Severity>,
    /// OWASP Top 10 reference string (e.g. `A05:2021`).
    pub owasp: Option<String>,
    /// MITRE CWE code or URL (normalized to `CWE-<id>` when numeric).
    pub cwe: Option<String>,
    /// OWASP WSTG reference string (e.g. `WSTG-CONF-07`).
    pub wstg: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Defensive remediation instructions.
    pub remediation: Option<String>,
    /// Extra classification tags.
    pub tags: Vec<String>,
}

/// A single passive rule inside a [`PtkModule`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtkRuleDefinition {
    /// Rule identifier.
    pub id: String,
    /// Rule display name.
    pub name: String,
    /// Whether this rule is strictly passive (non-intrusive).
    pub passive: bool,
    /// Optional rule-level metadata overriding the parent module.
    pub metadata: PtkModuleMetadata,
}

/// A PTK module entry parsed from `modules.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtkModule {
    /// Module identifier (for example `no-inner-outer-html` or `passive-headers`).
    pub id: String,
    /// Module display name.
    pub name: String,
    /// PTK engine associated with this module.
    pub engine: PtkEngine,
    /// Whether this module runs strictly in passive mode (non-intrusive).
    pub passive: bool,
    /// Module taxonomy and documentation metadata.
    pub metadata: PtkModuleMetadata,
    /// Child rules belonging to this module.
    pub rules: Vec<PtkRuleDefinition>,
}

/// Parsed catalog of OWASP PTK `modules.json` definitions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtkModuleCatalog {
    /// Optional catalog version from `modules.json`.
    pub version: Option<String>,
    /// All parsed modules before passive filtering.
    pub modules: Vec<PtkModule>,
}

impl PtkModuleCatalog {
    /// Reads and parses a PTK `modules.json` file from disk.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Io`] or [`OwaspError::Json`] if reading or parsing fails.
    pub fn from_file(path: &Path) -> Result<Self> {
        let meta = fs::metadata(path).map_err(|source| OwaspError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if meta.len() > MAX_MODULES_BYTES {
            return Err(OwaspError::Config(format!(
                "PTK modules file `{}` exceeds 16 MiB limit",
                path.display()
            )));
        }
        let raw = fs::read_to_string(path).map_err(|source| OwaspError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json_str(&raw)
    }

    /// Parses PTK `modules.json` supporting both array-root and object-root layouts.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Json`] or [`OwaspError::Config`] if the JSON structure is invalid.
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let trimmed = raw.strip_prefix('\u{FEFF}').unwrap_or(raw);
        let value: Value = serde_json::from_str(trimmed).map_err(|source| OwaspError::Json {
            context: "parsing PTK modules.json".to_owned(),
            source,
        })?;
        Self::from_value(&value)
    }

    /// Parses a [`PtkModuleCatalog`] from a pre-parsed JSON [`Value`].
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Config`] if the root is neither an array nor an object with
    /// `modules` or `rules`.
    pub fn from_value(value: &Value) -> Result<Self> {
        match value {
            Value::Array(items) => {
                let modules = items
                    .iter()
                    .enumerate()
                    .map(|(idx, item)| parse_module(item, idx))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Self {
                    version: None,
                    modules,
                })
            }
            Value::Object(obj) => {
                let version = obj
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let items = obj
                    .get("modules")
                    .or_else(|| obj.get("rules"))
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        OwaspError::Config(
                            "PTK modules.json object must contain a `modules` or `rules` array"
                                .to_owned(),
                        )
                    })?;
                let modules = items
                    .iter()
                    .enumerate()
                    .map(|(idx, item)| parse_module(item, idx))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Self { version, modules })
            }
            _ => Err(OwaspError::Config(
                "PTK modules.json must be a JSON array or object".to_owned(),
            )),
        }
    }

    /// Returns only modules marked passive (excluding active attack/fuzz modules).
    #[must_use]
    pub fn passive_modules(&self) -> Vec<&PtkModule> {
        self.modules.iter().filter(|m| m.passive).collect()
    }

    /// Returns all passive rules across passive modules.
    #[must_use]
    pub fn passive_rules(&self) -> Vec<(&PtkModule, &PtkRuleDefinition)> {
        let mut out = Vec::new();
        for module in self.passive_modules() {
            for rule in &module.rules {
                if rule.passive {
                    out.push((module, rule));
                }
            }
        }
        out
    }
}

fn parse_module(value: &Value, index: usize) -> Result<PtkModule> {
    let obj = value.as_object().ok_or_else(|| {
        OwaspError::Config(format!("PTK module entry #{index} must be a JSON object"))
    })?;
    let id = str_field(obj, "id")
        .or_else(|| str_field(obj, "module_id"))
        .unwrap_or_else(|| format!("ptk-module-{index}"));
    let name = str_field(obj, "name").unwrap_or_else(|| id.clone());
    let passive = is_passive_entry(obj);
    let engine = str_field(obj, "engine")
        .or_else(|| str_field(obj, "type"))
        .and_then(|raw| PtkEngine::from_str(&raw).ok())
        .unwrap_or(if passive {
            PtkEngine::SastPassive
        } else {
            PtkEngine::Passive
        });
    let metadata = parse_metadata(obj);
    let rules = obj
        .get("rules")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .enumerate()
                .map(|(r_idx, r_val)| parse_rule(r_val, &id, passive, r_idx))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    Ok(PtkModule {
        id,
        name,
        engine,
        passive,
        metadata,
        rules,
    })
}

fn parse_rule(
    value: &Value,
    module_id: &str,
    module_passive: bool,
    index: usize,
) -> Result<PtkRuleDefinition> {
    let obj = value.as_object().ok_or_else(|| {
        OwaspError::Config(format!(
            "PTK rule entry #{index} in module `{module_id}` must be a JSON object"
        ))
    })?;
    let id = str_field(obj, "id").unwrap_or_else(|| format!("{module_id}-rule-{index}"));
    let name = str_field(obj, "name").unwrap_or_else(|| id.clone());
    let passive = if obj.contains_key("mode")
        || obj.contains_key("type")
        || obj.contains_key("passive")
        || obj.contains_key("active")
    {
        is_passive_entry(obj)
    } else {
        module_passive
    };
    let metadata = parse_metadata(obj);
    Ok(PtkRuleDefinition {
        id,
        name,
        passive,
        metadata,
    })
}

fn is_passive_entry(obj: &Map<String, Value>) -> bool {
    if let Some(flag) = obj.get("passive").and_then(Value::as_bool) {
        return flag;
    }
    if let Some(flag) = obj.get("active").and_then(Value::as_bool) {
        return !flag;
    }
    for key in ["mode", "type", "scan_mode", "scanMode"] {
        if let Some(val) = obj.get(key).and_then(Value::as_str) {
            let lower = val.trim().to_ascii_lowercase();
            if lower.contains("active") && !lower.contains("passive") {
                return false;
            }
            if lower == "attack" || lower == "fuzz" || lower == "exploit" {
                return false;
            }
            if lower.contains("passive") || lower == "sast" || lower == "sca" {
                return true;
            }
        }
    }
    // PTK SAST/SCA modules default to passive client-side inspection unless marked active.
    true
}

fn parse_metadata(obj: &Map<String, Value>) -> PtkModuleMetadata {
    let meta_obj = obj
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(obj);
    let tax_obj = meta_obj
        .get("taxonomy")
        .and_then(Value::as_object)
        .unwrap_or(meta_obj);

    let severity = str_field(tax_obj, "effective_severity")
        .or_else(|| str_field(tax_obj, "effectiveSeverity"))
        .or_else(|| str_field(tax_obj, "severity"))
        .or_else(|| str_field(obj, "severity"))
        .and_then(|s| Severity::from_str(&s).ok());
    let owasp = str_field(tax_obj, "owasp")
        .or_else(|| str_field(meta_obj, "owasp"))
        .or_else(|| str_field(obj, "owasp"));
    let cwe = str_field(tax_obj, "cwe")
        .or_else(|| str_field(tax_obj, "CWE"))
        .or_else(|| str_field(meta_obj, "cwe"))
        .or_else(|| str_field(meta_obj, "CWE"))
        .or_else(|| str_field(obj, "cwe"))
        .map(|raw| normalize_cwe_string(&raw));
    let wstg = str_field(tax_obj, "wstg")
        .or_else(|| str_field(meta_obj, "wstg"))
        .or_else(|| str_field(obj, "wstg"));
    let description = str_field(meta_obj, "description").or_else(|| str_field(obj, "description"));
    let remediation = str_field(meta_obj, "remediation").or_else(|| str_field(obj, "remediation"));
    let tags = string_array(meta_obj.get("tags").or_else(|| tax_obj.get("tags")));

    PtkModuleMetadata {
        severity,
        owasp,
        cwe,
        wstg,
        description,
        remediation,
        tags,
    }
}

fn str_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Normalizes `"79"`, `"CWE-79"`, or `"https://cwe.mitre.org/data/definitions/79.html"` into
/// `"CWE-79"`.
#[must_use]
pub fn normalize_cwe_string(raw: &str) -> String {
    if let Some(num) = parse_cwe_number(raw) {
        return format!("CWE-{num}");
    }
    raw.trim().to_owned()
}

/// Extracts a numeric CWE ID from `"CWE-79"`, `"79"`, or a MITRE CWE definition URL.
#[must_use]
pub fn parse_cwe_number(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if let Ok(num) = trimmed.parse::<u32>() {
        return Some(num);
    }
    let upper = trimmed.to_ascii_uppercase();
    if let Some(rest) = upper.strip_prefix("CWE-") {
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(num) = digits.parse::<u32>() {
            return Some(num);
        }
    }
    // Extract number from URLs like https://cwe.mitre.org/data/definitions/79.html
    if let Some(pos) = trimmed.rfind('/') {
        let tail = &trimmed[pos + 1..];
        let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(num) = digits.parse::<u32>() {
            return Some(num);
        }
    }
    None
}

/// A single finding formatted in the OWASP PTK passive report schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtkFinding {
    /// Unique finding or rule identifier.
    pub id: String,
    /// PTK engine that emitted or maps to this finding.
    pub engine: PtkEngine,
    /// Finding title/name.
    pub name: String,
    /// Base declared severity.
    pub severity: Severity,
    /// Effective severity after context/confidence evaluation.
    pub effective_severity: Severity,
    /// OWASP Top 10:2021 tag (`A01:2021`..`A10:2021`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
    /// MITRE CWE reference (for example `CWE-693`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// OWASP WSTG v4.2 identifier (for example `WSTG-CONF-07`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wstg: Option<String>,
    /// Affected URL, header, cookie, or DOM location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Redacted/structural evidence snippet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Detailed vulnerability/posture description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Recommended defensive remediation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Optional PTK module identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_id: Option<String>,
    /// Optional PTK rule identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Confidence score (0–100) when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
}

impl PtkFinding {
    /// Creates a [`PtkFinding`] where `effective_severity` defaults to `severity`.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        engine: PtkEngine,
        name: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.into(),
            engine,
            name: name.into(),
            severity,
            effective_severity: severity,
            owasp: None,
            cwe: None,
            wstg: None,
            url: None,
            evidence: None,
            description: None,
            remediation: None,
            module_id: None,
            rule_id: None,
            confidence: None,
        }
    }

    /// Computes effective severity given base severity and confidence (0–100).
    #[must_use]
    pub fn effective_severity_for(base: Severity, confidence: Option<u8>) -> Severity {
        match confidence {
            Some(c) if c < 40 => match base {
                Severity::Critical => Severity::High,
                Severity::High => Severity::Medium,
                Severity::Medium => Severity::Low,
                Severity::Low | Severity::Info => Severity::Info,
            },
            _ => base,
        }
    }

    /// Converts an internal [`Finding`] into a [`PtkFinding`].
    #[must_use]
    pub fn from_finding(finding: &Finding) -> Self {
        let engine = match finding.auditor {
            AuditorKind::Headers | AuditorKind::Cookies | AuditorKind::Jwt => {
                PtkEngine::DastPassive
            }
            AuditorKind::Dom => PtkEngine::IastPassive,
            AuditorKind::Sca => PtkEngine::Sca,
            AuditorKind::Ptk => PtkEngine::Passive,
        };
        Self {
            id: finding.rule_id.clone(),
            engine,
            name: finding.title.clone(),
            severity: finding.severity,
            effective_severity: finding.severity,
            owasp: Some(finding.category.code().to_owned()),
            cwe: finding.cwe_code(),
            wstg: finding.wstg.clone(),
            url: finding.location.clone(),
            evidence: finding.evidence.clone(),
            description: (!finding.description.is_empty()).then(|| finding.description.clone()),
            remediation: (!finding.remediation.is_empty()).then(|| finding.remediation.clone()),
            module_id: Some(format!("sbrs-owasp-{}", finding.auditor.as_str())),
            rule_id: Some(finding.rule_id.clone()),
            confidence: Some(100),
        }
    }

    /// Converts this PTK finding into an internal [`Finding`].
    #[must_use]
    pub fn to_finding(&self) -> Finding {
        let category = self
            .owasp
            .as_deref()
            .and_then(|s| OwaspCategory::from_str(s).ok())
            .unwrap_or(OwaspCategory::A05SecurityMisconfiguration);
        let auditor = match self.engine {
            PtkEngine::Sca => AuditorKind::Sca,
            PtkEngine::IastPassive | PtkEngine::SastPassive => AuditorKind::Ptk,
            PtkEngine::DastPassive | PtkEngine::Passive => AuditorKind::Ptk,
        };
        let mut out = Finding::new(
            self.rule_id.as_deref().unwrap_or(&self.id),
            self.name.clone(),
            self.effective_severity,
            category,
            auditor,
        )
        .tag(format!("ptk:{}", self.engine.as_str()));

        if let Some(desc) = &self.description {
            out = out.description(desc.clone());
        }
        if let Some(cwe_raw) = &self.cwe
            && let Some(cwe_num) = parse_cwe_number(cwe_raw)
        {
            out = out.cwe(cwe_num);
        }
        if let Some(wstg) = &self.wstg {
            out = out.wstg(wstg.clone());
        }
        if let Some(url) = &self.url {
            out = out.location(url.clone());
        }
        if let Some(evidence) = &self.evidence {
            out = out.evidence(redact_potential_jwt(evidence));
        }
        if let Some(remediation) = &self.remediation {
            out = out.remediation(remediation.clone());
        }
        out
    }
}

fn redact_potential_jwt(text: &str) -> String {
    if text.starts_with("eyJ") && text.matches('.').count() == 2 {
        return redact_secret(text);
    }
    text.to_owned()
}

/// Severity breakdown counters in a PTK scan result.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtkStats {
    /// Total findings count.
    pub total: usize,
    /// Critical findings count.
    pub critical: usize,
    /// High findings count.
    pub high: usize,
    /// Medium findings count.
    pub medium: usize,
    /// Low findings count.
    pub low: usize,
    /// Informational findings count.
    pub info: usize,
}

impl PtkStats {
    /// Computes counts using each finding's `effective_severity`.
    #[must_use]
    pub fn from_findings(findings: &[PtkFinding]) -> Self {
        let mut stats = Self {
            total: findings.len(),
            ..Self::default()
        };
        for f in findings {
            match f.effective_severity {
                Severity::Critical => stats.critical += 1,
                Severity::High => stats.high += 1,
                Severity::Medium => stats.medium += 1,
                Severity::Low => stats.low += 1,
                Severity::Info => stats.info += 1,
            }
        }
        stats
    }
}

/// Bidirectional passive scan envelope matching `DenisPodgurskii/pentestkit` schemas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtkScanResult {
    /// Envelope schema version.
    pub schema_version: String,
    /// Scanner identifier.
    pub scanner: String,
    /// Primary audited target URL, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Primary scan engine.
    pub engine: PtkEngine,
    /// Always `"passive"` for defensive posture audits.
    pub scan_mode: String,
    /// Effective severity counters.
    pub stats: PtkStats,
    /// Normalized findings list.
    pub findings: Vec<PtkFinding>,
}

impl PtkScanResult {
    /// Builds a [`PtkScanResult`] from passive [`Finding`] entries.
    #[must_use]
    pub fn from_findings(target: Option<String>, findings: &[Finding]) -> Self {
        let ptk_findings: Vec<PtkFinding> = findings.iter().map(PtkFinding::from_finding).collect();
        let stats = PtkStats::from_findings(&ptk_findings);
        Self {
            schema_version: "1.0.0".to_owned(),
            scanner: "owasp-ptk-passive".to_owned(),
            target,
            engine: PtkEngine::Passive,
            scan_mode: "passive".to_owned(),
            stats,
            findings: ptk_findings,
        }
    }

    /// Returns the highest `effective_severity` present in the scan, if any.
    #[must_use]
    pub fn effective_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.effective_severity).max()
    }

    /// Converts all PTK findings back into internal [`Finding`] structs.
    #[must_use]
    pub fn to_findings(&self) -> Vec<Finding> {
        self.findings.iter().map(PtkFinding::to_finding).collect()
    }

    /// Serializes this scan result as compact JSON.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Json`] if serialization fails.
    pub fn to_json_string(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|source| OwaspError::Json {
            context: "serializing PTK scan result".to_owned(),
            source,
        })
    }

    /// Serializes this scan result as pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Json`] if serialization fails.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|source| OwaspError::Json {
            context: "serializing PTK scan result".to_owned(),
            source,
        })
    }

    /// Imports a PTK passive JSON scan result, supporting both canonical `PtkScanResult`
    /// envelopes and upstream PTK extension exports (e.g. `effectiveSeverity`, `items`, `groups`).
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Json`] or [`OwaspError::Config`] if the JSON cannot be parsed
    /// or represents an unsupported active-only scan payload.
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let trimmed = raw.strip_prefix('\u{FEFF}').unwrap_or(raw);
        let value: Value = serde_json::from_str(trimmed).map_err(|source| OwaspError::Json {
            context: "parsing PTK scan result".to_owned(),
            source,
        })?;
        if let Ok(direct) = serde_json::from_value::<Self>(value.clone()) {
            let mut normalized = direct;
            normalized.stats = PtkStats::from_findings(&normalized.findings);
            return Ok(normalized);
        }
        parse_external_ptk_export(&value)
    }
}

fn parse_external_ptk_export(value: &Value) -> Result<PtkScanResult> {
    let obj = value.as_object().ok_or_else(|| {
        OwaspError::Config("PTK scan export must be a JSON object or finding array".to_owned())
    })?;

    let target = str_field(obj, "target")
        .or_else(|| str_field(obj, "url"))
        .or_else(|| str_field(obj, "domain"));
    let engine = str_field(obj, "engine")
        .or_else(|| str_field(obj, "scanEngine"))
        .and_then(|s| PtkEngine::from_str(&s).ok())
        .unwrap_or(PtkEngine::Passive);

    let mut findings = Vec::new();
    if let Some(arr) = obj
        .get("findings")
        .or_else(|| obj.get("items"))
        .and_then(Value::as_array)
    {
        for (idx, item) in arr.iter().enumerate() {
            findings.push(parse_external_ptk_finding(item, engine, idx)?);
        }
    } else if let Some(groups) = obj.get("groups").and_then(Value::as_array) {
        for group in groups {
            if let Some(items) = group
                .get("findings")
                .or_else(|| group.get("items"))
                .and_then(Value::as_array)
            {
                for (idx, item) in items.iter().enumerate() {
                    findings.push(parse_external_ptk_finding(item, engine, idx)?);
                }
            }
        }
    } else {
        return Err(OwaspError::Config(
            "PTK scan export does not contain `findings`, `items`, or `groups`".to_owned(),
        ));
    }

    let stats = PtkStats::from_findings(&findings);
    Ok(PtkScanResult {
        schema_version: str_field(obj, "schema_version").unwrap_or_else(|| "1.0.0".to_owned()),
        scanner: str_field(obj, "scanner").unwrap_or_else(|| "owasp-ptk".to_owned()),
        target,
        engine,
        scan_mode: "passive".to_owned(),
        stats,
        findings,
    })
}

fn parse_external_ptk_finding(
    value: &Value,
    default_engine: PtkEngine,
    index: usize,
) -> Result<PtkFinding> {
    let obj = value
        .as_object()
        .ok_or_else(|| OwaspError::Config(format!("PTK finding #{index} must be a JSON object")))?;
    let meta = parse_metadata(obj);
    let id = str_field(obj, "id")
        .or_else(|| str_field(obj, "rule_id"))
        .or_else(|| str_field(obj, "ruleId"))
        .unwrap_or_else(|| format!("ptk-finding-{index}"));
    let name = str_field(obj, "name")
        .or_else(|| str_field(obj, "title"))
        .unwrap_or_else(|| id.clone());
    let engine = str_field(obj, "engine")
        .and_then(|s| PtkEngine::from_str(&s).ok())
        .unwrap_or(default_engine);
    let severity = str_field(obj, "severity")
        .and_then(|s| Severity::from_str(&s).ok())
        .or(meta.severity)
        .unwrap_or(Severity::Info);
    let confidence = obj
        .get("confidence")
        .and_then(Value::as_u64)
        .and_then(|v| u8::try_from(v).ok());
    let effective_severity = str_field(obj, "effective_severity")
        .or_else(|| str_field(obj, "effectiveSeverity"))
        .and_then(|s| Severity::from_str(&s).ok())
        .unwrap_or_else(|| PtkFinding::effective_severity_for(severity, confidence));

    Ok(PtkFinding {
        id: id.clone(),
        engine,
        name,
        severity,
        effective_severity,
        owasp: str_field(obj, "owasp").or(meta.owasp),
        cwe: str_field(obj, "cwe")
            .or_else(|| str_field(obj, "CWE"))
            .map(|s| normalize_cwe_string(&s))
            .or(meta.cwe),
        wstg: str_field(obj, "wstg").or(meta.wstg),
        url: str_field(obj, "url").or_else(|| str_field(obj, "location")),
        evidence: str_field(obj, "evidence"),
        description: str_field(obj, "description").or(meta.description),
        remediation: str_field(obj, "remediation").or(meta.remediation),
        module_id: str_field(obj, "module_id").or_else(|| str_field(obj, "moduleId")),
        rule_id: str_field(obj, "rule_id")
            .or_else(|| str_field(obj, "ruleId"))
            .or(Some(id)),
        confidence,
    })
}

fn read_dev_local_automation_enabled(dir: &Path) -> Option<bool> {
    let dev_local = dir.join("dev.local.json");
    let raw = fs::read_to_string(dev_local).ok()?;
    let val: Value = serde_json::from_str(&raw).ok()?;
    val.get("automationEnabled").and_then(Value::as_bool)
}

/// Passive snapshot read from `window.PTK_AGENT` (`scanStatus` + `getFindings` responses).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PtkAgentSnapshot {
    /// Whether `window.PTK_AGENT` was present and returned `ok: true`.
    pub ok: bool,
    /// PTK session identifier, if active or completed.
    pub session_id: Option<String>,
    /// Session status (`none`, `starting`, `running`, `stopping`, `completed`, `error`, `unknown`).
    pub status: Option<String>,
    /// Error code when `ok` is `false` (for example `automation_disabled`).
    pub error_code: Option<String>,
    /// Error message when `ok` is `false`.
    pub error_message: Option<String>,
    /// Whether findings output was truncated by the bridge limit.
    pub truncated: bool,
    /// Passive findings returned by `window.PTK_AGENT`.
    pub findings: Vec<PtkFinding>,
}

impl PtkAgentSnapshot {
    /// Parses passive `window.PTK_AGENT` bridge JSON returned from page evaluation.
    ///
    /// # Errors
    ///
    /// Returns [`OwaspError::Config`] if individual finding items are malformed JSON objects.
    pub fn from_value(value: &Value) -> Result<Self> {
        let Some(obj) = value.as_object() else {
            return Ok(Self::default());
        };
        let status_obj = obj
            .get("scanStatus")
            .and_then(Value::as_object)
            .unwrap_or(obj);
        let findings_obj = obj
            .get("findingsResponse")
            .and_then(Value::as_object)
            .unwrap_or(obj);

        let ok = findings_obj
            .get("ok")
            .and_then(Value::as_bool)
            .or_else(|| status_obj.get("ok").and_then(Value::as_bool))
            .unwrap_or(false);
        let error_code = str_field(findings_obj, "code").or_else(|| str_field(status_obj, "code"));
        let error_message =
            str_field(findings_obj, "message").or_else(|| str_field(status_obj, "message"));
        let session_id =
            str_field(status_obj, "sessionId").or_else(|| str_field(status_obj, "session_id"));
        let status = str_field(status_obj, "status");
        let truncated = findings_obj
            .get("truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut findings = Vec::new();
        if let Some(arr) = findings_obj.get("findings").and_then(Value::as_array) {
            for (idx, item) in arr.iter().enumerate() {
                if let Some(item_obj) = item.as_object()
                    && !is_passive_entry(item_obj)
                {
                    continue;
                }
                findings.push(parse_external_ptk_finding(item, PtkEngine::Passive, idx)?);
            }
        }

        Ok(Self {
            ok,
            session_id,
            status,
            error_code,
            error_message,
            truncated,
            findings,
        })
    }

    /// Converts all passive bridge findings into internal [`Finding`] items.
    #[must_use]
    pub fn to_findings(&self) -> Vec<Finding> {
        self.findings.iter().map(PtkFinding::to_finding).collect()
    }
}
