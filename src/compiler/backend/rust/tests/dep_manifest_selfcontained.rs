#![forbid(unsafe_code)]
//! SEAL: dep-model emitted `Cargo.toml` is self-contained.
//!
//! Asserts that neither the native nor the wasm dep-model manifest contains:
//! - any `*.workspace = true` inheritance (no parent workspace is present when
//!   built standalone or in a cross-compiler container);
//! - any host-absolute path dependency (which would be unreachable inside a
//!   Docker cross-compile container);
//! - any unreplaced `__IPE_RUNTIME_PATH__` template anchor.
//!
//! And asserts that the manifest does contain the relative bundled-runtime dep
//! (`path = "ipe_runtime_dep"`) that the driver materialises alongside the
//! emitted crate.

use ipe_backend::Backend;
use ipe_backend_rust::{RuntimeContentId, RuntimeDep, RustBackend};
use ipe_intern::Interner;
use ipe_ir::{ModPath, Module, Program, Target};

// ── minimal program helpers ───────────────────────────────────────────────────

fn minimal_native_program() -> (Program, Interner) {
    let mut interner = Interner::new();
    #[allow(clippy::expect_used)]
    let main = interner.intern("Main").expect("intern");
    let program = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main]),
            types: vec![],
            funcs: vec![],
            entry: None,
            records: vec![],
            uses_tea: false,
            uses_server: false,
            uses_http: false,
            uses_config: false,
            uses_compression: false,
            uses_csv: false,
            uses_cache: false,
            uses_encoding: false,
            uses_regex: false,
            uses_uuid: false,
            uses_random: false,
            uses_log: false,
            uses_decimal: false,
            uses_char_category: false,
            uses_crypto_core: false,
            uses_secret: false,
            uses_json: false,
            uses_crypto: false,
            uses_jwt: false,
            uses_url: false,
            uses_ui: false,
            uses_web: false,
            uses_tui: false,
            uses_console: false,
            uses_webview: false,
            uses_css: false,
            uses_auth: false,
            uses_principal: false,
            uses_websocket: false,
            uses_email: false,
            uses_locale: false,
            uses_time: false,
            uses_env_public: false,
            uses_debug: false,
            uses_ffi: false,
            uses_async_runtime: false,
        }],
    };
    (program, interner)
}

/// A `RuntimeDep` with a placeholder content identity.
///
/// The identity never reaches the emitted manifest, so any value selects the
/// dep-model branch without affecting the emitted text.
fn dummy_runtime_dep() -> RuntimeDep {
    RuntimeDep {
        content: RuntimeContentId::from_digest_bytes([0; 16]),
    }
}

fn emit_native_dep_cargo_toml() -> String {
    let (program, interner) = minimal_native_program();
    #[allow(clippy::expect_used)]
    RustBackend::new(&interner)
        .with_runtime_dep(Some(dummy_runtime_dep()))
        .emit(&program)
        .expect("native dep-model emit must succeed for a body-free program")
        .cargo_toml
}

fn emit_wasm_dep_cargo_toml() -> String {
    let (program, interner) = minimal_native_program();
    #[allow(clippy::expect_used)]
    RustBackend::new(&interner)
        .with_target(Target::WasmClient)
        .with_runtime_dep(Some(dummy_runtime_dep()))
        .emit(&program)
        .expect("wasm dep-model emit must succeed for a body-free program")
        .cargo_toml
}

// ── no workspace inheritance ──────────────────────────────────────────────────

/// A standalone emitted crate has no parent workspace, so `*.workspace = true`
/// fields are unresolvable. Both dep-model shapes must not emit any.
#[test]
fn native_dep_manifest_contains_no_workspace_inheritance() {
    let toml = emit_native_dep_cargo_toml();
    assert!(
        !toml.contains(".workspace = true"),
        "native dep-model Cargo.toml must not contain `*.workspace = true`;\ngot:\n{toml}"
    );
}

#[test]
fn wasm_dep_manifest_contains_no_workspace_inheritance() {
    let toml = emit_wasm_dep_cargo_toml();
    assert!(
        !toml.contains(".workspace = true"),
        "wasm dep-model Cargo.toml must not contain `*.workspace = true`;\ngot:\n{toml}"
    );
}

// ── no unreplaced template anchors ───────────────────────────────────────────

#[test]
fn native_dep_manifest_has_no_unreplaced_anchors() {
    let toml = emit_native_dep_cargo_toml();
    assert!(
        !toml.contains("__IPE_RUNTIME"),
        "native dep-model Cargo.toml must not contain any unreplaced __IPE_RUNTIME_* anchor;\ngot:\n{toml}"
    );
}

#[test]
fn wasm_dep_manifest_has_no_unreplaced_anchors() {
    let toml = emit_wasm_dep_cargo_toml();
    assert!(
        !toml.contains("__IPE_RUNTIME"),
        "wasm dep-model Cargo.toml must not contain any unreplaced __IPE_RUNTIME_* anchor;\ngot:\n{toml}"
    );
}

// ── relative bundled path dep ─────────────────────────────────────────────────

/// The dep-model runtime reference must use the relative `ipe_runtime_dep`
/// path so it resolves in any build environment (cross container, offline, CI)
/// without a host-absolute path.
#[test]
fn native_dep_manifest_uses_relative_bundled_path() {
    let toml = emit_native_dep_cargo_toml();
    assert!(
        toml.contains("path = \"ipe_runtime_dep\""),
        "native dep-model Cargo.toml must reference the bundled runtime via \
         `path = \"ipe_runtime_dep\"`;\ngot:\n{toml}"
    );
}

#[test]
fn wasm_dep_manifest_uses_relative_bundled_path() {
    let toml = emit_wasm_dep_cargo_toml();
    assert!(
        toml.contains("path = \"ipe_runtime_dep\""),
        "wasm dep-model Cargo.toml must reference the bundled runtime via \
         `path = \"ipe_runtime_dep\"`;\ngot:\n{toml}"
    );
}

// ── no absolute paths ─────────────────────────────────────────────────────────

/// Strip `#`-comment lines so a path mentioned only in prose does not
/// trigger a false positive.
fn without_comments(toml: &str) -> String {
    toml.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn native_dep_manifest_contains_no_absolute_path_deps() {
    let toml = without_comments(&emit_native_dep_cargo_toml());
    // Absolute Unix paths start with `/`; Windows extended paths start with
    // `\\` (already filtered by the UNC strip in the old path-substitution,
    // but belt-and-suspenders here). A path dependency value like `path = "/…"`
    // would be an absolute dep.
    assert!(
        !toml.contains("path = \"/"),
        "native dep-model Cargo.toml must not contain an absolute Unix path dep;\ngot:\n{toml}"
    );
}

#[test]
fn wasm_dep_manifest_contains_no_absolute_path_deps() {
    let toml = without_comments(&emit_wasm_dep_cargo_toml());
    assert!(
        !toml.contains("path = \"/"),
        "wasm dep-model Cargo.toml must not contain an absolute Unix path dep;\ngot:\n{toml}"
    );
}

// ── workspace detach ─────────────────────────────────────────────────────────

/// Both manifests carry a bare `[workspace]` section so cargo does not try to
/// find a parent workspace root when building from the emitted crate directory.
#[test]
fn native_dep_manifest_detaches_from_workspace() {
    let toml = emit_native_dep_cargo_toml();
    assert!(
        toml.contains("[workspace]"),
        "native dep-model Cargo.toml must include a bare [workspace] section;\ngot:\n{toml}"
    );
}
