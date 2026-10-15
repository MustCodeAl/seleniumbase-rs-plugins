#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod abi;
mod error;
mod host;
mod limits;

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use seleniumbase_rs_plugin::{
    LaunchSettings, Package, PageHandle, Plugin, Requirements, Result, async_trait,
};
use serde_json::json;

pub use abi::{ABI_VERSION, FORBIDDEN_FLAGS};
pub use error::WasmError;
pub use limits::Limits;

/// A plugin written in WebAssembly.
///
/// [`from_bytes`](Self::from_bytes) and [`from_file`](Self::from_file) load a
/// module, run the functions of the ABI once inside a sandbox, check what they
/// return and drop the module. What is left is plain data that implements
/// [`Plugin`]: no module runs while the browser does. See the crate's README for
/// the ABI.
#[derive(Clone, PartialEq, Eq)]
pub struct WasmPlugin {
    name: String,
    launch_args: Vec<String>,
    packages: Vec<Package>,
    blocked_urls: Vec<String>,
}

impl fmt::Debug for WasmPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WasmPlugin")
            .field("name", &self.name)
            .field("launch_args", &self.launch_args)
            .field("scripts", &self.packages.len())
            .field("blocked_urls", &self.blocked_urls)
            .finish()
    }
}

impl WasmPlugin {
    /// Loads a binary WebAssembly module with the default [`Limits`].
    ///
    /// # Errors
    ///
    /// A [`WasmError`] when the bytes are not a module, the module breaks the
    /// ABI or a limit, or one of its functions traps or runs out of fuel.
    pub fn from_bytes(wasm: &[u8]) -> std::result::Result<Self, WasmError> {
        Self::from_bytes_with(wasm, &Limits::default())
    }

    /// Loads a binary WebAssembly module with `limits`.
    ///
    /// # Errors
    ///
    /// As [`from_bytes`](Self::from_bytes).
    pub fn from_bytes_with(wasm: &[u8], limits: &Limits) -> std::result::Result<Self, WasmError> {
        let raw = host::read_exports(wasm, limits)?;
        let description = abi::describe(&raw)?;
        Ok(Self {
            name: description.name,
            launch_args: description.launch_args,
            packages: description.packages,
            blocked_urls: description.blocked_urls,
        })
    }

    /// Loads the module in a file with the default [`Limits`].
    ///
    /// # Errors
    ///
    /// [`WasmError::Read`] when the file cannot be read, otherwise as
    /// [`from_bytes`](Self::from_bytes).
    pub fn from_file(path: impl AsRef<Path>) -> std::result::Result<Self, WasmError> {
        Self::from_file_with(path, &Limits::default())
    }

    /// Loads the module in a file with `limits`. A file over
    /// [`Limits::max_module_bytes`] is not read whole.
    ///
    /// # Errors
    ///
    /// As [`from_file`](Self::from_file).
    pub fn from_file_with(
        path: impl AsRef<Path>,
        limits: &Limits,
    ) -> std::result::Result<Self, WasmError> {
        let path = path.as_ref();
        let read_error = |source| WasmError::Read {
            path: path.to_path_buf(),
            source,
        };
        let file = File::open(path).map_err(read_error)?;
        // Read one byte past the limit: enough to know the file is too big.
        let cap = u64::try_from(limits.max_module_bytes)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut bytes = Vec::new();
        file.take(cap).read_to_end(&mut bytes).map_err(read_error)?;
        Self::from_bytes_with(&bytes, limits)
    }

    /// The browser switches the module asked for, already checked.
    #[must_use]
    pub fn launch_args(&self) -> &[String] {
        &self.launch_args
    }

    /// The URL patterns the module blocks, already checked.
    #[must_use]
    pub fn blocked_urls(&self) -> &[String] {
        &self.blocked_urls
    }
}

#[async_trait]
impl Plugin for WasmPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    fn requirements(&self) -> Requirements {
        if self.blocked_urls.is_empty() {
            Requirements::empty()
        } else {
            // Blocking URLs uses the DevTools Protocol.
            Requirements::CHROMIUM_ONLY
        }
    }

    fn packages(&self) -> Vec<Package> {
        self.packages.clone()
    }

    async fn before_launch(&self, launch: &mut LaunchSettings) -> Result<()> {
        launch.args.extend(self.launch_args.iter().cloned());
        Ok(())
    }

    async fn on_page_created(&self, page: &dyn PageHandle) -> Result<()> {
        if !self.blocked_urls.is_empty() {
            page.send("Network.enable", json!({})).await?;
            page.send(
                "Network.setBlockedURLs",
                json!({ "urls": self.blocked_urls }),
            )
            .await?;
        }
        Ok(())
    }
}
