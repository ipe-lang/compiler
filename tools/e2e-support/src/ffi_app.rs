//! The app crate an FFI SEAL fixture builds its emitted bindings into.
//!
//! The crate has the shape the backend emits for a program with a foreign
//! package: `main.rs` opens with the crate-root runtime prelude and `mod ffi;`,
//! `src/ffi.rs` wraps each package's bindings in `pub mod <slug>` and re-exports
//! it, and the manifest depends on the real runtime crate. The bindings'
//! `use crate::*;` therefore resolves the runtime's own items, so a fixture
//! supplies its driver code only, never a copy of the runtime items the
//! bindings name.

use std::fmt::Write as _;
use std::path::Path;

/// The crate-root lines the backend emits ahead of a program's own items.
pub const CRATE_PRELUDE: &str =
    "pub use ipe_runtime::*;\npub use ipe_runtime::error::IpeError;\nmod ffi;\n";

/// The `src/ffi.rs` module the backend wraps one package's `bindings` in.
#[must_use]
pub fn package_module(slug: &str, bindings: &str) -> String {
    format!("pub mod {slug} {{\n{bindings}}}\npub use {slug}::*;\n")
}

/// One fixture's app crate.
pub struct FfiApp<'a> {
    /// The `[package]` name, which is also the binary's.
    pub name: &'a str,
    /// The runtime features the program reaches; the default set is off, as in
    /// the emitted manifest.
    pub runtime_features: &'a [&'a str],
    /// Further `[dependencies]` lines, such as a wrapper crate's path dependency.
    pub dependencies: &'a [String],
    /// The whole of `src/ffi.rs`.
    pub ffi_rs: &'a str,
    /// The program's items, written after [`CRATE_PRELUDE`] in `src/main.rs`.
    pub main_rs: &'a str,
}

impl FfiApp<'_> {
    /// Write the manifest, `src/main.rs` and `src/ffi.rs` into `dir`.
    ///
    /// # Errors
    /// Returns the path and cause when a directory or file cannot be written.
    pub fn write(&self, dir: &Path) -> Result<(), String> {
        let runtime = crate::require_runtime_crate();
        let features = self
            .runtime_features
            .iter()
            .map(|f| format!("{f:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        let mut manifest = format!(
            "[package]\nname = {name:?}\nversion = \"0.0.0\"\nedition = \"2024\"\n\n\
             [dependencies]\n\
             ipe_runtime = {{ package = {pkg:?}, path = {path:?}, default-features = false, \
             features = [{features}] }}\n",
            name = self.name,
            pkg = crate::warnings::RUNTIME_PACKAGE,
            path = runtime.display().to_string(),
        );
        for line in self.dependencies {
            let _ = writeln!(manifest, "{line}");
        }
        // The emitted bindings' `catch_unwind` boundary refuses to build under
        // `panic = "abort"`.
        manifest.push_str("\n[profile.dev]\npanic = \"unwind\"\n");

        let src = dir.join("src");
        std::fs::create_dir_all(&src).map_err(|e| format!("mkdir {}: {e}", src.display()))?;
        let main_rs = format!("{CRATE_PRELUDE}\n{}", self.main_rs);
        for (path, text) in [
            (dir.join("Cargo.toml"), manifest.as_str()),
            (src.join("main.rs"), main_rs.as_str()),
            (src.join("ffi.rs"), self.ffi_rs),
        ] {
            std::fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
        }
        Ok(())
    }
}
