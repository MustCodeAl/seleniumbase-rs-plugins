//! What the host allows a module.

/// Bounds on a module and on what it may use while it is loaded.
///
/// The defaults suit plugins that describe themselves in a few kilobytes of
/// JSON. Raise a limit only for a module you trust. Build one with
/// [`Limits::builder`], which starts from the defaults.
///
/// ```
/// use seleniumbase_rs_plugin::wasm::Limits;
///
/// let limits = Limits::builder().fuel_per_call(1_000_000).build();
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

/// Builds a [`Limits`]. [`Limits::builder`] starts from the defaults;
/// [`Limits::into_builder`] starts from limits that already exist. `0` is
/// allowed: [`build`](Self::build) does not add a check.
#[must_use = "a builder does nothing until `build` is called"]
#[derive(Clone, Debug, Default)]
pub struct LimitsBuilder {
    limits: Limits,
}

impl LimitsBuilder {
    /// Sets [`Limits::max_module_bytes`].
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn max_module_bytes(mut self, bytes: usize) -> Self {
        self.limits.max_module_bytes = bytes;
        self
    }

    /// Sets [`Limits::max_memory_bytes`].
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn max_memory_bytes(mut self, bytes: usize) -> Self {
        self.limits.max_memory_bytes = bytes;
        self
    }

    /// Sets [`Limits::fuel_per_call`].
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn fuel_per_call(mut self, fuel: u64) -> Self {
        self.limits.fuel_per_call = fuel;
        self
    }

    /// Sets [`Limits::max_value_bytes`].
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn max_value_bytes(mut self, bytes: usize) -> Self {
        self.limits.max_value_bytes = bytes;
        self
    }

    /// Returns the limits. Nothing is rejected, including `0`.
    #[must_use]
    pub fn build(self) -> Limits {
        self.limits
    }
}

impl Limits {
    /// A builder that starts from [`Limits::default`].
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn builder() -> LimitsBuilder {
        LimitsBuilder::default()
    }

    /// A builder that starts from these limits.
    #[must_use = "a builder does nothing until `build` is called"]
    pub fn into_builder(self) -> LimitsBuilder {
        LimitsBuilder { limits: self }
    }
}
