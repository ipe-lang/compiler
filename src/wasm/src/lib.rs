//! The Ipê compiler **frontend**, compiled to WebAssembly.
//!
//! The Ipê compiler emits Rust, and the final Rust→binary step needs
//! `cargo`/`rustc`, which cannot run in a browser. So "compile in the browser"
//! means the frontend — parse → resolve → canonicalise → typecheck → lower →
//! emit — runs as a WebAssembly module, turning Ipê source into diagnostics and
//! the emitted Rust source. Running the emitted program is out of scope
//! in-browser (it needs a Rust toolchain); the playground shows the emitted Rust
//! instead.
//!
//! ## What is and is not compiled in
//!
//! This crate depends only on the frontend crate graph (`ipe_parse`, `ipe_db`,
//! `ipe_backend`, `ipe_backend_rust`, …), none of which touches
//! `std::process`, `std::fs`, or the network at runtime. The native-only
//! subsystems — cargo/rustc invocation, FFI (`ipe_ffi`/`ipe_sandbox`),
//! filesystem project discovery, the watcher, the LSP, the on-disk cache — are
//! in sibling crates this crate does not depend on, so they are simply absent
//! from the WebAssembly module. Each is a genuine platform boundary, documented
//! honestly, not a faked result.
//!
//! The in-browser compile handles a single entry module plus the transitive
//! embedded-stdlib closure (the `Ipe.*` modules embedded via `include_str!` in
//! [`ipe_stdlib`]). FFI is disabled: an FFI-backed import surfaces as an
//! ordinary compiler diagnostic, never a crash. The compile target is
//! [`ipe_ir::Target::WasmClient`] so the browser-bundle security gates
//! (server-effect kernels denied) are exactly the ones exercised.
#![forbid(unsafe_code)]

mod stdlib_inject;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// The outcome of an in-browser compile: either the emitted Rust project or a
/// rendered diagnostic. Plain owned data so the wasm-bindgen boundary can hand
/// it to JavaScript as a JSON object.
pub struct CompileOutcome {
    /// `true` when the frontend accepted the program and produced Rust.
    pub ok: bool,
    /// The rendered compiler diagnostic (colour off) when `ok` is `false`;
    /// empty when `ok` is `true`.
    pub diagnostics: String,
    /// The emitted Rust source when `ok` is `true`: each emitted project file
    /// rendered under a `// ==== path ====` banner, followed by the emitted
    /// `Cargo.toml`. Empty when `ok` is `false`.
    pub emitted_rust: String,
}

/// Compile one Ipê source string through the frontend, entirely in memory.
///
/// Mirrors the native driver's in-memory core (`ipe`'s `compile_prepared`):
/// inject the transitive embedded-stdlib closure, build a cold salsa database
/// over the source set, and demand the emit query — which transitively runs
/// parse → canon → link → typecheck → lower → emit. The compile is a pure
/// function of `source` (no hidden inputs); FFI is disabled and the target is
/// [`ipe_ir::Target::WasmClient`].
///
/// Never panics: every fallible step maps to a rendered [`CompileOutcome`] with
/// `ok == false`.
#[must_use]
pub fn compile(source: &str) -> CompileOutcome {
    match compile_inner(source) {
        Ok(emitted) => CompileOutcome {
            ok: true,
            diagnostics: String::new(),
            emitted_rust: render_emitted(&emitted),
        },
        Err(rendered) => CompileOutcome {
            ok: false,
            diagnostics: rendered,
            emitted_rust: String::new(),
        },
    }
}

/// The synthetic on-disk-looking path used for the entry module in diagnostics.
/// Never read from disk — the source text is carried in memory.
const ENTRY_BLAME: &str = "<playground>/Main.ipe";

fn compile_inner(source: &str) -> Result<ipe_backend::EmittedProject, String> {
    // Parse ONCE with a throwaway interner to learn the entry's declared module
    // path, exactly as the native single-file driver does. A parse failure here
    // renders against the entry file.
    let mut name_interner = ipe_intern::Interner::new();
    let parsed = ipe_parse::parse_module(source, &mut name_interner)
        .map_err(|diag| ipe_diagnostics::render(&diag, ENTRY_BLAME, source))?;
    let entry_path: Vec<String> = parsed
        .name
        .value
        .iter()
        .map(|s| name_interner.resolve(*s).unwrap_or_default().to_owned())
        .collect();

    // sources: module path -> (blame path, source text). Seed with the entry.
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(
        entry_path.clone(),
        (PathBuf::from(ENTRY_BLAME), source.to_owned()),
    );

    // Inject the transitive embedded-stdlib closure (pure in-memory: a token
    // scan over embedded `Ipe.*` source, no filesystem). `injected` records
    // which module paths earn `EmbeddedStdlib` trust.
    let injected = stdlib_inject::inject_compiled_std_closure(&mut sources);

    // A cold, per-invocation salsa database. Front-end stages are demanded as
    // memoized queries below; the database owns the build-wide interner.
    let db = ipe_db::IpeDatabase::new();
    let source_root = build_source_root(&db, &sources, &injected);

    let Some(entry_file) = source_root.files(&db).get(&entry_path).copied() else {
        return Err("internal: entry module missing from source map".to_owned());
    };

    // Compile target = WasmClient so the browser-bundle security gates run.
    // FFI disabled (no on-disk crate catalog in a browser); the db driver only
    // affects emitted text (no rusqlite is linked into this crate).
    let config = ipe_db::BuildConfig::new(
        &db,
        ipe_backend_rust::DbDriver::Sqlite,
        None,
        ipe_ir::Target::WasmClient,
        Vec::new(),
        ipe_backend_rust::MountBase::root(),
        false,
        // The browser playground is a development surface — Debug.* is allowed.
        ipe_backend_rust::BuildIntent::Development,
        // Wasm always vendors its runtime (closed template); dep model is a no-op.
        None,
        // The browser playground does not expose `--debugger`; never record.
        false,
        String::new(),
        // The browser playground is not the dev watch loop; no appearance hoist.
        false,
        // The browser playground is a wasm SPA, never a webview-native delivery.
        false,
    );

    // Per-module canonicalisation in dep-first order — purely for BLAME
    // attribution, so a module's own diagnostic renders against its own source.
    // `emit_manifest` below re-demands the same memos. `topo_order` cycles /
    // canon errors render against the owning module.
    let topo = ipe_db::topo_order(&db, source_root, entry_file)
        .clone()
        .map_err(|diag| render_for_module(&diag, &sources, &entry_path, source))?;
    for mod_path in topo.iter() {
        let (Some((path, src)), Some(file_handle)) = (
            sources.get(mod_path),
            source_root.files(&db).get(mod_path).copied(),
        ) else {
            return Err("internal: module in topo order missing from source map".to_owned());
        };
        ipe_db::canonicalize(&db, source_root, file_handle)
            .clone()
            .map_err(|diag| ipe_diagnostics::render(&diag, &path.to_string_lossy(), src))?;
    }

    // The emit demand: transitively link → typecheck → lower → emit. Any error
    // carries the owning module `home`; render it against that module's source
    // (falling back to the entry file when the home is empty or unknown).
    let emitted = ipe_db::emit_manifest(&db, source_root, entry_file, config)
        .clone()
        .map_err(|(diag, home)| {
            render_for_home(&db, &diag, &home, &sources, &entry_path, source)
        })?;
    Ok((*emitted).clone())
}

/// Build the salsa `SourceRoot` from the in-memory source set, tagging each
/// module `EmbeddedStdlib` iff it is in the trusted `injected` set (a user file
/// squatting on an `Ipe.*` name is NOT in `injected`, so it stays `User` and
/// remains IPE-N0025-rejected — identical to the native driver).
fn build_source_root(
    db: &ipe_db::IpeDatabase,
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    injected: &BTreeSet<Vec<String>>,
) -> ipe_db::SourceRoot {
    let file_handles: BTreeMap<Vec<String>, ipe_db::SourceFile> = sources
        .iter()
        .map(|(mod_path, (_, src))| {
            let origin = if injected.contains(mod_path) {
                ipe_canon::ModuleOrigin::EmbeddedStdlib
            } else {
                ipe_canon::ModuleOrigin::User
            };
            (
                mod_path.clone(),
                ipe_db::SourceFile::new(db, mod_path.clone(), src.clone(), origin),
            )
        })
        .collect();
    ipe_db::SourceRoot::new(db, file_handles)
}

/// Render a diagnostic against the entry module's source (used for whole-program
/// errors — topo cycles — that no single module owns).
fn render_for_module(
    diag: &ipe_diagnostics::Diagnostic,
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    entry_path: &[String],
    entry_src: &str,
) -> String {
    let (file, src) = sources.get(entry_path).map_or_else(
        || (ENTRY_BLAME.to_owned(), entry_src.to_owned()),
        |(p, s)| (p.to_string_lossy().into_owned(), s.clone()),
    );
    ipe_diagnostics::render(diag, &file, &src)
}

/// Render a diagnostic carrying an owning-module `home`: resolve `home` (a
/// symbol path) back to its source file so a dep-module error renders against
/// its own source, not the entry file. Empty/unknown home falls back to entry.
fn render_for_home(
    db: &ipe_db::IpeDatabase,
    diag: &ipe_diagnostics::Diagnostic,
    home: &[ipe_intern::Symbol],
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    entry_path: &[String],
    entry_src: &str,
) -> String {
    if !home.is_empty() {
        let interner = ipe_db::Db::interner(db).lock();
        let home_str: Option<Vec<String>> = home
            .iter()
            .map(|s| interner.resolve(*s).map(str::to_owned))
            .collect();
        drop(interner);
        if let Some(home_str) = home_str
            && let Some((path, src)) = sources.get(&home_str)
        {
            return ipe_diagnostics::render(diag, &path.to_string_lossy(), src);
        }
    }
    render_for_module(diag, sources, entry_path, entry_src)
}

/// Render an [`ipe_backend::EmittedProject`] as human-readable Rust: each file
/// under a banner, then the emitted `Cargo.toml`. Deterministic order
/// (`BTreeMap`).
fn render_emitted(emitted: &ipe_backend::EmittedProject) -> String {
    let mut out = String::new();
    for (path, body) in &emitted.files {
        out.push_str("// ==== ");
        out.push_str(path.as_str());
        out.push_str(" ====\n");
        out.push_str(body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str("// ==== Cargo.toml ====\n");
    out.push_str(&emitted.cargo_toml);
    if !emitted.cargo_toml.ends_with('\n') {
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// wasm-bindgen boundary
// ---------------------------------------------------------------------------

/// The JavaScript entry point: `compile(source) -> { ok, diagnostics,
/// emitted_rust }`. Returns a plain JS object.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(js_name = compile)]
#[must_use]
pub fn compile_js(source: &str) -> wasm_bindgen::JsValue {
    use wasm_bindgen::JsValue;
    let outcome = compile(source);
    let obj = js_sys::Object::new();
    // Best-effort: `Reflect::set` on a fresh object never fails in practice;
    // if it did, the field is simply absent and the JS side reads `undefined`.
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("ok"),
        &JsValue::from_bool(outcome.ok),
    );
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("diagnostics"),
        &JsValue::from_str(&outcome.diagnostics),
    );
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("emitted_rust"),
        &JsValue::from_str(&outcome.emitted_rust),
    );
    obj.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_world_compiles_and_emits_rust() {
        let src = "module Main exposing (main)\n\nimport Ipe.Io as Io\n\nmain : Task Error ()\nmain =\n    Io.println \"hello\"\n";
        let outcome = compile(src);
        assert!(
            outcome.ok,
            "expected hello-world to compile; diagnostics:\n{}",
            outcome.diagnostics
        );
        assert!(
            outcome.emitted_rust.contains("==== src/main.rs ===="),
            "emitted Rust should contain the entry file:\n{}",
            outcome.emitted_rust
        );
        assert!(
            outcome.emitted_rust.contains("==== Cargo.toml ===="),
            "emitted Rust should include the emitted Cargo.toml"
        );
    }

    #[test]
    fn type_error_reports_diagnostic_not_panic() {
        // `main` annotated Int but bound to a String — a type error.
        let src = "module Main exposing (main)\n\nmain : Int\nmain = \"nope\"\n";
        let outcome = compile(src);
        assert!(!outcome.ok, "expected a type error to be reported");
        assert!(
            !outcome.diagnostics.is_empty(),
            "a rejected program must carry a rendered diagnostic"
        );
    }

    #[test]
    fn parse_error_reports_diagnostic() {
        let outcome = compile("module Main exposing (main)\n\nmain = = =\n");
        assert!(!outcome.ok);
        assert!(!outcome.diagnostics.is_empty());
    }
}
