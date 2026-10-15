//! Builds small WebAssembly modules from WAT for the tests.

use std::fmt::Write as _;

/// A module under construction: one exported memory page and whatever the test
/// adds. `build` turns it into a binary module with the `wat` crate.
pub struct Module {
    body: String,
    next_free: u32,
}

impl Module {
    /// A module with only the memory, exported as `memory`.
    pub fn bare() -> Self {
        Self {
            body: "(memory (export \"memory\") 1)\n".to_owned(),
            next_free: 16,
        }
    }

    /// A module with the memory, ABI version 1 and the name `name`.
    pub fn named(name: &str) -> Self {
        Self::bare()
            .version(1)
            .json("sbrs_name", &format!("\"{name}\""))
    }

    /// A module with no memory export: only `fields` (WAT module fields).
    pub fn without_memory(fields: &str) -> Self {
        Self {
            body: fields.to_owned(),
            next_free: 16,
        }
    }

    /// Exports `sbrs_abi_version` returning `version`.
    pub fn version(self, version: i32) -> Self {
        self.fields(&format!(
            "(func (export \"sbrs_abi_version\") (result i32) (i32.const {version}))"
        ))
    }

    /// Puts `json` in the memory and exports `export`, returning its packed range.
    pub fn json(self, export: &str, json: &str) -> Self {
        self.bytes(export, json.as_bytes())
    }

    /// Puts `bytes` in the memory and exports `export`, returning its packed range.
    pub fn bytes(mut self, export: &str, bytes: &[u8]) -> Self {
        let at = self.next_free;
        let len = u32::try_from(bytes.len()).expect("test data fits in u32");
        self.next_free = at + len.div_ceil(16) * 16;
        let mut escaped = String::new();
        for byte in bytes {
            write!(escaped, "\\{byte:02x}").expect("writing to a String");
        }
        self.fields(&format!("(data (i32.const {at}) \"{escaped}\")"))
            .packed(export, at, len)
    }

    /// Puts `bytes` at `at` in the memory, without moving the free pointer.
    pub fn bytes_at(self, at: u32, bytes: &[u8]) -> Self {
        let mut escaped = String::new();
        for byte in bytes {
            write!(escaped, "\\{byte:02x}").expect("writing to a String");
        }
        self.fields(&format!("(data (i32.const {at}) \"{escaped}\")"))
    }

    /// Exports `export` returning the range `pointer`, `length` as given, with no
    /// data behind it.
    pub fn packed(self, export: &str, pointer: u32, length: u32) -> Self {
        let value = (u64::from(pointer) << 32) | u64::from(length);
        // WAT reads an i64 constant as a signed number or as hex.
        self.fields(&format!(
            "(func (export \"{export}\") (result i64) (i64.const {value:#x}))"
        ))
    }

    /// Adds WAT module fields as they are.
    pub fn fields(mut self, fields: &str) -> Self {
        self.body.push_str(fields);
        self.body.push('\n');
        self
    }

    /// The binary module.
    pub fn build(&self) -> Vec<u8> {
        wat::parse_str(format!("(module\n{}\n)", self.body))
            .unwrap_or_else(|error| panic!("bad test WAT: {error}\n{}", self.body))
    }
}
