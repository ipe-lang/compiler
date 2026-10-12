//! A vendored-runtime emit carries the runtime crate's own `clippy.toml`.
//!
//! The vendored runtime compiles inside the app crate, so clippy reads the app
//! crate's config. Without the runtime's `disallowed-methods`/`disallowed-types`
//! bans at the emitted project root, every runtime
//! `#[expect(clippy::disallowed_*)]` escape would be an unfulfilled expectation.
//! The dependency model needs no root copy: the bundled runtime crate keeps its
//! own `clippy.toml` beside its own `Cargo.toml`.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use ipe_backend::Backend;
use ipe_backend_rust::{RuntimeDep, RustBackend};
use ipe_intern::Interner;
use ipe_ir::{ModPath, Module, Program, Target};

/// The runtime crate's `clippy.toml`, the byte-exact source of the vendored copy.
const RUNTIME_CLIPPY_TOML: &str = include_str!("../../../../runtime/rust/clippy.toml");

/// Build a body-free single-module `Program` plus the `Interner` that names it.
fn minimal_program() -> (Program, Interner) {
    let mut interner = Interner::new();
    #[allow(clippy::expect_used)] // interning a fixed literal cannot fail
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

/// Locate the runtime crate root (`src/runtime/rust`) by walking up from the crate manifest dir.
#[allow(clippy::expect_used)] // the in-repo runtime root is the test's precondition
fn runtime_crate_root() -> PathBuf {
    let manifest = e2e_support::manifest_dir!();
    let mut here: Option<&Path> = Some(&manifest);
    let found = std::iter::from_fn(|| {
        let dir = here?;
        here = dir.parent();
        Some(dir.join("src").join("runtime").join("rust"))
    })
    .find(|candidate| candidate.join("Cargo.toml").is_file())
    .expect("the ipe-runtime-rust crate root (src/runtime/rust) must resolve");
    found
        .canonicalize()
        .expect("runtime crate root canonicalizes")
}

/// Emit the minimal program for `target`, vendored when `dep` is `None`, and return the root `clippy.toml`.
fn emitted_root_clippy_toml(target: Target, dep: Option<RuntimeDep>) -> Option<String> {
    let (program, interner) = minimal_program();
    #[allow(clippy::expect_used)] // emit-must-succeed is the test's precondition
    let project = RustBackend::new(&interner)
        .with_target(target)
        .with_runtime_dep(dep)
        .emit(&program)
        .expect("emit must succeed for a body-free program");
    project.files.get("clippy.toml").cloned()
}

/// The native vendored emit carries the runtime `clippy.toml` byte-for-byte at its root.
#[test]
fn native_vendored_emit_carries_runtime_clippy_toml() {
    let got = emitted_root_clippy_toml(Target::Native, None);
    assert_eq!(
        got.as_deref(),
        Some(RUNTIME_CLIPPY_TOML),
        "a native vendored emit must carry the runtime clippy.toml verbatim"
    );
}

/// The wasm vendored emit carries the runtime `clippy.toml` byte-for-byte at its root.
#[test]
fn wasm_vendored_emit_carries_runtime_clippy_toml() {
    let got = emitted_root_clippy_toml(Target::WasmClient, None);
    assert_eq!(
        got.as_deref(),
        Some(RUNTIME_CLIPPY_TOML),
        "a wasm vendored emit must carry the runtime clippy.toml verbatim"
    );
}

/// A dependency-model emit adds no root `clippy.toml`: the runtime dep keeps its own.
#[test]
fn dep_model_emits_carry_no_root_clippy_toml() {
    for target in [Target::Native, Target::WasmClient] {
        let got = emitted_root_clippy_toml(
            target,
            Some(RuntimeDep {
                root: runtime_crate_root(),
            }),
        );
        assert!(
            got.is_none(),
            "a dependency-model emit must not add a root clippy.toml"
        );
    }
}
