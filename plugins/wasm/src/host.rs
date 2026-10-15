//! Runs a module in wasmi and reads what its exports return.
//!
//! The module is compiled and instantiated with no imports, so it cannot reach
//! anything outside its own memory. Every call is metered with fuel, the memory
//! has a hard cap, and what a function returns is copied out of the memory as
//! bytes, never trusted: [`crate::abi`] checks it afterwards. When
//! [`read_exports`] returns, the store, the instance and the module are gone.

use wasmi::{
    CompilationMode, Config, EnforcedLimits, Engine, Extern, ExternType, Instance, Linker, Memory,
    Module, Store, StoreLimits, StoreLimitsBuilder, TrapCode, WasmResults,
};

use crate::abi::{
    ABI_VERSION, EXPORT_BLOCKED_URLS, EXPORT_LAUNCH_ARGS, EXPORT_MEMORY, EXPORT_NAME,
    EXPORT_SCRIPTS, EXPORT_VERSION, KNOWN_FUNCTIONS, RESERVED_PREFIX, Raw, unpack,
};
use crate::{Limits, WasmError};

/// How a failure in the start function is named.
const START: &str = "(start function)";

/// The size of a WebAssembly memory page.
const PAGE_BYTES: u64 = 65_536;

/// The most elements any table may grow to.
const MAX_TABLE_ELEMENTS: usize = 100_000;

/// Loads `wasm` and returns the bytes of the values its exports describe.
pub(crate) fn read_exports(wasm: &[u8], limits: &Limits) -> Result<Raw, WasmError> {
    if wasm.len() > limits.max_module_bytes {
        return Err(WasmError::ModuleTooLarge {
            size: u64::try_from(wasm.len()).unwrap_or(u64::MAX),
            limit: limits.max_module_bytes,
        });
    }
    let engine = engine();
    let module = Module::new(&engine, wasm)
        .map_err(|error| WasmError::InvalidModule(one_line(&error.to_string())))?;
    refuse_imports(&module)?;
    refuse_big_memory(&module, limits)?;

    let mut sandbox = Sandbox::start(&engine, &module, limits)?;

    let found = sandbox.call::<i32>(EXPORT_VERSION)?;
    if found != ABI_VERSION {
        return Err(WasmError::UnsupportedAbi { found });
    }
    refuse_unknown_exports(&module)?;
    let memory = sandbox
        .instance
        .get_memory(&sandbox.store, EXPORT_MEMORY)
        .ok_or(WasmError::MissingExport(EXPORT_MEMORY))?;

    let name = sandbox.call::<i64>(EXPORT_NAME)?;
    let name = sandbox.read(memory, EXPORT_NAME, name, limits.max_value_bytes)?;
    Ok(Raw {
        name,
        launch_args: sandbox.optional(memory, EXPORT_LAUNCH_ARGS, limits)?,
        scripts: sandbox.optional(memory, EXPORT_SCRIPTS, limits)?,
        blocked_urls: sandbox.optional(memory, EXPORT_BLOCKED_URLS, limits)?,
    })
}

/// An interpreter that checks the module against what the host allows: fuel,
/// no multiple memories, the strict limits on a module's size and shape, and
/// every function compiled up front so a bad body fails here and not later.
fn engine() -> Engine {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .wasm_multi_memory(false)
        .compilation_mode(CompilationMode::Eager)
        .enforced_limits(EnforcedLimits::strict());
    Engine::new(&config)
}

/// A module imports nothing in ABI 1: no host function can be reached.
fn refuse_imports(module: &Module) -> Result<(), WasmError> {
    match module.imports().next() {
        Some(import) => Err(WasmError::HasImports {
            module: import.module().to_owned(),
            name: import.name().to_owned(),
        }),
        None => Ok(()),
    }
}

/// Refuses an exported memory that starts bigger than the limit, with a clear
/// message before anything is allocated. (The store's limiter also stops any
/// memory that starts or grows past the limit.)
fn refuse_big_memory(module: &Module, limits: &Limits) -> Result<(), WasmError> {
    let limit = u64::try_from(limits.max_memory_bytes).unwrap_or(u64::MAX);
    for export in module.exports() {
        if let ExternType::Memory(memory) = export.ty() {
            let bytes = memory.minimum().saturating_mul(PAGE_BYTES);
            if bytes > limit {
                return Err(WasmError::MemoryTooLarge {
                    bytes,
                    limit: limits.max_memory_bytes,
                });
            }
        }
    }
    Ok(())
}

/// The prefix `sbrs_` belongs to the ABI: a function with it that the ABI does
/// not define is a mistake (or from a later ABI), never ignored.
fn refuse_unknown_exports(module: &Module) -> Result<(), WasmError> {
    for export in module.exports() {
        let name = export.name();
        if name.starts_with(RESERVED_PREFIX) && !KNOWN_FUNCTIONS.contains(&name) {
            return Err(WasmError::UnknownExport(name.to_owned()));
        }
    }
    Ok(())
}

/// A running instance, with the fuel that every call to it gets.
struct Sandbox {
    store: Store<StoreLimits>,
    instance: Instance,
    fuel: u64,
}

impl Sandbox {
    /// Instantiates `module` with no imports, running its start function (if any)
    /// on the same fuel as any other call.
    fn start(engine: &Engine, module: &Module, limits: &Limits) -> Result<Self, WasmError> {
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.max_memory_bytes)
            .memories(1)
            .tables(8)
            .table_elements(MAX_TABLE_ELEMENTS)
            .instances(1)
            .build();
        let mut store = Store::new(engine, store_limits);
        store.limiter(|limits| limits);
        store
            .set_fuel(limits.fuel_per_call)
            .map_err(|error| WasmError::Instantiate(error.to_string()))?;
        let instance = Linker::<StoreLimits>::new(engine)
            .instantiate_and_start(&mut store, module)
            .map_err(|error| match error.as_trap_code() {
                None => WasmError::Instantiate(error.to_string()),
                Some(_) => trap(START, limits.fuel_per_call, &error),
            })?;
        Ok(Self {
            store,
            instance,
            fuel: limits.fuel_per_call,
        })
    }

    /// Calls the exported function `export`, which takes nothing and returns `R`,
    /// with a fresh supply of fuel.
    fn call<R: WasmResults>(&mut self, export: &'static str) -> Result<R, WasmError> {
        let function = match self.instance.get_export(&self.store, export) {
            None => return Err(WasmError::MissingExport(export)),
            Some(Extern::Func(function)) => function,
            Some(_) => {
                return Err(WasmError::BadExport {
                    export,
                    reason: "it is not a function".to_owned(),
                });
            }
        };
        let function =
            function
                .typed::<(), R>(&self.store)
                .map_err(|error| WasmError::BadExport {
                    export,
                    reason: error.to_string(),
                })?;
        self.store
            .set_fuel(self.fuel)
            .map_err(|error| WasmError::Instantiate(error.to_string()))?;
        function
            .call(&mut self.store, ())
            .map_err(|error| trap(export, self.fuel, &error))
    }

    /// The bytes an optional export describes, or `None` when the module does
    /// not export it.
    fn optional(
        &mut self,
        memory: Memory,
        export: &'static str,
        limits: &Limits,
    ) -> Result<Option<Vec<u8>>, WasmError> {
        if self.instance.get_export(&self.store, export).is_none() {
            return Ok(None);
        }
        let packed = self.call::<i64>(export)?;
        self.read(memory, export, packed, limits.max_value_bytes)
            .map(Some)
    }

    /// Copies the range a function returned out of the memory, if it is inside
    /// the memory and not longer than `max` bytes.
    fn read(
        &self,
        memory: Memory,
        export: &'static str,
        packed: i64,
        max: usize,
    ) -> Result<Vec<u8>, WasmError> {
        let (pointer, length) = unpack(packed);
        let size = usize::try_from(length).unwrap_or(usize::MAX);
        if size > max {
            return Err(WasmError::TooLong {
                export,
                length,
                limit: max,
            });
        }
        let data = memory.data(&self.store);
        usize::try_from(pointer)
            .ok()
            .and_then(|start| data.get(start..start.checked_add(size)?))
            .map(<[u8]>::to_vec)
            .ok_or(WasmError::OutOfBounds {
                export,
                pointer,
                length,
                memory: data.len(),
            })
    }
}

/// `text` on one line: the parser's messages can span several lines.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A failed call: out of fuel, or any other trap.
fn trap(export: &'static str, fuel: u64, error: &wasmi::Error) -> WasmError {
    match error.as_trap_code() {
        Some(TrapCode::OutOfFuel) => WasmError::OutOfFuel { export, fuel },
        _ => WasmError::Trapped {
            export,
            message: error.to_string(),
        },
    }
}
