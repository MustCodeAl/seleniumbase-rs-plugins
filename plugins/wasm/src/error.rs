//! Why a module was refused.

use std::path::PathBuf;

use seleniumbase_rs_plugin::PluginError;

use crate::ABI_VERSION;

/// Why the host refused a WebAssembly plugin module.
///
/// Every variant describes the module or the file, never the host: loading a
/// module returns one of these instead of panicking or hanging. A `WasmError`
/// converts into a [`PluginError`] with the same message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WasmError {
    /// The module's file could not be read.
    #[error("cannot read `{}`: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// What the operating system said.
        source: std::io::Error,
    },
    /// The module is bigger than [`Limits::max_module_bytes`](crate::Limits::max_module_bytes).
    #[error("the module is {size} bytes, more than the limit of {limit}")]
    ModuleTooLarge {
        /// The module's size in bytes (for a file, at least this many).
        size: u64,
        /// The limit in bytes.
        limit: usize,
    },
    /// The bytes are not a valid WebAssembly binary module, or use something the
    /// host does not allow (a second memory, a 64-bit memory).
    #[error("not a valid WebAssembly module: {0}")]
    InvalidModule(String),
    /// The module imports something. An ABI 1 module has no imports.
    #[error(
        "the module imports `{module}`::`{name}`; an ABI {ABI_VERSION} plugin has no imports (no files, network or clock)"
    )]
    HasImports {
        /// The import's module name.
        module: String,
        /// The import's field name.
        name: String,
    },
    /// The module asks for more memory at start than the limit.
    #[error("the module asks for {bytes} bytes of memory at start, more than the limit of {limit}")]
    MemoryTooLarge {
        /// The memory the module starts with, in bytes.
        bytes: u64,
        /// The limit in bytes.
        limit: usize,
    },
    /// The module could not be instantiated.
    #[error("the module could not be started: {0}")]
    Instantiate(String),
    /// A required export is missing, or is not a function (a memory for `memory`).
    #[error("the module does not export `{0}`")]
    MissingExport(&'static str),
    /// An export exists but is not what the ABI wants.
    #[error("the export `{export}` is not what ABI {ABI_VERSION} wants: {reason}")]
    BadExport {
        /// The export's name.
        export: &'static str,
        /// What is wrong with it.
        reason: String,
    },
    /// An export starts with the reserved prefix `sbrs_` but the ABI has no such function.
    #[error(
        "the export `{0}` starts with `sbrs_`, which is reserved for the ABI, but ABI {ABI_VERSION} has no such function"
    )]
    UnknownExport(String),
    /// The module speaks another ABI version than the host.
    #[error("the module speaks ABI version {found}; this host speaks version {ABI_VERSION}")]
    UnsupportedAbi {
        /// What `sbrs_abi_version` returned.
        found: i32,
    },
    /// A call used up its fuel: it runs too long, or never ends.
    #[error("`{export}` used up its fuel ({fuel}): a plugin function must finish quickly")]
    OutOfFuel {
        /// The function, or `(start function)`.
        export: &'static str,
        /// The fuel it was given.
        fuel: u64,
    },
    /// A call trapped: `unreachable`, a stack overflow, an out-of-bounds access, and so on.
    #[error("`{export}` trapped: {message}")]
    Trapped {
        /// The function, or `(start function)`.
        export: &'static str,
        /// What the interpreter reported.
        message: String,
    },
    /// A function returned a range that is not inside the module's memory.
    #[error(
        "`{export}` returned a range outside the module's memory (pointer {pointer}, length {length}, memory {memory} bytes)"
    )]
    OutOfBounds {
        /// The function.
        export: &'static str,
        /// The pointer half of the packed value.
        pointer: u32,
        /// The length half of the packed value.
        length: u32,
        /// The memory's size in bytes.
        memory: usize,
    },
    /// A function returned more bytes than [`Limits::max_value_bytes`](crate::Limits::max_value_bytes).
    #[error("`{export}` returned {length} bytes, more than the limit of {limit}")]
    TooLong {
        /// The function.
        export: &'static str,
        /// The length half of the packed value.
        length: u32,
        /// The limit in bytes.
        limit: usize,
    },
    /// A function returned text that is not valid UTF-8 or not the JSON the ABI wants.
    #[error("`{export}` returned invalid JSON: {message}")]
    Json {
        /// The function.
        export: &'static str,
        /// What the parser said.
        message: String,
    },
    /// A function returned well-formed JSON with a value the host refuses.
    #[error("`{export}` returned a value the host refuses: {reason}")]
    Value {
        /// The function.
        export: &'static str,
        /// Why.
        reason: String,
    },
}

impl From<WasmError> for PluginError {
    fn from(error: WasmError) -> Self {
        PluginError::other(error.to_string())
    }
}
