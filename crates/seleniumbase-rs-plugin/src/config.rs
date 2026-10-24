//! Building plugins from names and options: `Configurable`, `Descriptor`, `Registry`.

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::metadata::Metadata;
use crate::{Plugin, PluginError, PluginSet, Result};

/// Reads the options of the plugin called `plugin` into its own typed struct,
/// for [`Configurable::configure`].
///
/// `Value::Null`, which means no options, gives `T::default()`. Declare the
/// struct with `#[serde(default, deny_unknown_fields)]`, and a misspelt option
/// is an error instead of being ignored.
///
/// ```
/// use seleniumbase_rs_plugin::config::options;
/// use seleniumbase_rs_plugin::PluginError;
/// use serde::Deserialize;
/// use serde_json::json;
///
/// #[derive(Debug, Default, Deserialize, PartialEq)]
/// #[serde(default, deny_unknown_fields)]
/// struct Options {
///     depth: u32,
/// }
///
/// let none: Options = options("crawler", &serde_json::Value::Null)?;
/// assert_eq!(none, Options::default());
/// let some: Options = options("crawler", &json!({ "depth": 3 }))?;
/// assert_eq!(some.depth, 3);
/// let error = options::<Options>("crawler", &json!({ "dept": 3 })).unwrap_err();
/// assert_eq!(error.to_string(), "plugin configuration: crawler: unknown option `dept`");
/// # Ok::<(), PluginError>(())
/// ```
///
/// # Errors
///
/// [`PluginError::Config`], naming the plugin: for an unknown option as
/// ``crawler: unknown option `dept` ``, and for any other mistake with the
/// message of the deserializer.
pub fn options<T: DeserializeOwned + Default>(plugin: &str, options: &Value) -> Result<T> {
    if options.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(options.clone()).map_err(|error| {
        let message = error.to_string();
        let unknown = message
            .strip_prefix("unknown field `")
            .and_then(|rest| rest.split_once('`'));
        PluginError::Config(match unknown {
            Some((name, _)) => format!("{plugin}: unknown option `{name}`"),
            None => format!("{plugin}: {message}"),
        })
    })
}

/// A plugin that can be built from a name and a TOML or JSON options value.
pub trait Configurable: Plugin + Sized {
    /// The name the plugin is enabled by.
    const NAME: &'static str;

    /// What the plugin declares, without building one.
    fn describe() -> Metadata;

    /// Builds the plugin from its options (`Value::Null` when there are none).
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] when an option is wrong.
    fn configure(options: &Value) -> Result<Self>;
}

/// One plugin a registry can build.
#[derive(Clone, Debug)]
pub struct Descriptor {
    name: &'static str,
    metadata: Metadata,
    build: fn(&Value) -> Result<Arc<dyn Plugin>>,
}

impl Descriptor {
    /// The descriptor of a [`Configurable`] plugin.
    #[must_use]
    pub fn of<P: Configurable>() -> Self {
        Self {
            name: P::NAME,
            metadata: P::describe(),
            build: |options| Ok(Arc::new(P::configure(options)?)),
        }
    }

    /// The name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// What the plugin declares.
    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

/// A plugin to enable: its name and options.
#[derive(Clone, Debug, PartialEq)]
pub struct PluginSpec {
    /// The plugin's name.
    pub name: String,
    /// Its options, `Value::Null` for none.
    pub options: Value,
}

impl PluginSpec {
    /// A plugin with no options.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            options: Value::Null,
        }
    }

    /// Sets the options.
    #[must_use]
    pub fn options(mut self, options: Value) -> Self {
        self.options = options;
        self
    }
}

/// The plugins a program can enable by name.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    descriptors: Vec<Descriptor>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a descriptor; a later one with the same name replaces an earlier one.
    #[must_use]
    pub fn with(mut self, descriptor: Descriptor) -> Self {
        self.descriptors.retain(|d| d.name != descriptor.name);
        self.descriptors.push(descriptor);
        self
    }

    /// The known names, in the order added.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.descriptors.iter().map(Descriptor::name).collect()
    }

    /// The descriptor called `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Descriptor> {
        self.descriptors.iter().find(|d| d.name == name)
    }

    /// Builds the plugin a spec names.
    ///
    /// # Errors
    ///
    /// [`PluginError::Config`] for an unknown name or wrong options.
    pub fn build(&self, spec: &PluginSpec) -> Result<Arc<dyn Plugin>> {
        let descriptor = self.get(&spec.name).ok_or_else(|| {
            PluginError::Config(format!(
                "no plugin named `{}` (known: {})",
                spec.name,
                self.names().join(", ")
            ))
        })?;
        (descriptor.build)(&spec.options)
    }

    /// A strict set of the plugins the specs name: declared plugins only, and
    /// Critical capabilities are not granted.
    ///
    /// # Errors
    ///
    /// The first build or duplicate-name error.
    pub fn plugin_set(&self, specs: &[PluginSpec]) -> Result<PluginSet> {
        let mut set = PluginSet::strict();
        for spec in specs {
            let plugin = self.build(spec)?;
            let grants = {
                let meta = plugin.metadata();
                meta.capabilities.union(&meta.optional).without_critical()
            };
            set = set.with_grants_shared(plugin, grants)?;
        }
        Ok(set)
    }
}
