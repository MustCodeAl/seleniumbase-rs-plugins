//! What the host allows a module.

/// Bounds on a module and on what it may use while it is loaded.
///
/// The defaults suit plugins that describe themselves in a few kilobytes of
/// JSON. Raise a limit only for a module you trust. Build one from
/// [`Limits::default`] with the `with_*` methods.
///
/// ```
/// use seleniumbase_rs_plugin_wasm::Limits;
///
/// let limits = Limits::default().with_fuel_per_call(1_000_000);
/// assert_eq!(limits.fuel_per_call, 1_000_000);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// The largest module, in bytes. Default 4 MiB.
    pub max_module_bytes: usize,
    /// The most linear memory a module may have, at start and after any
    /// `memory.grow`, in bytes. Default 16 MiB.
    pub max_memory_bytes: usize,
    /// The fuel each call gets, and the start function: about one unit per
    /// executed instruction. A call that spends it stops with an error. Default
    /// 20,000,000.
    pub fuel_per_call: u64,
    /// The largest JSON value a function may return, in bytes. Default 1 MiB.
    pub max_value_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_module_bytes: 4 * 1024 * 1024,
            max_memory_bytes: 16 * 1024 * 1024,
            fuel_per_call: 20_000_000,
            max_value_bytes: 1024 * 1024,
        }
    }
}

impl Limits {
    /// Sets [`max_module_bytes`](Self::max_module_bytes).
    #[must_use]
    pub fn with_max_module_bytes(mut self, bytes: usize) -> Self {
        self.max_module_bytes = bytes;
        self
    }

    /// Sets [`max_memory_bytes`](Self::max_memory_bytes).
    #[must_use]
    pub fn with_max_memory_bytes(mut self, bytes: usize) -> Self {
        self.max_memory_bytes = bytes;
        self
    }

    /// Sets [`fuel_per_call`](Self::fuel_per_call).
    #[must_use]
    pub fn with_fuel_per_call(mut self, fuel: u64) -> Self {
        self.fuel_per_call = fuel;
        self
    }

    /// Sets [`max_value_bytes`](Self::max_value_bytes).
    #[must_use]
    pub fn with_max_value_bytes(mut self, bytes: usize) -> Self {
        self.max_value_bytes = bytes;
        self
    }
}
