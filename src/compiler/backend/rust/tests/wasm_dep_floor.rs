//! Layer-3 red-team tests for the wasm security gate: the emitted `Cargo.toml`
//! for a `--target wasm` build MUST NOT contain any server-side dep (`tokio`,
//! `axum`, `sqlx`, `reqwest`) or activate any server-feature flag (`server`,
//! `db`, `live`), and MUST keep the browser-glue entry crate (`wasm-bindgen`)
//! the emitted `#[wasm_bindgen(start)]` references.
//!
//! Two emit shapes are covered:
//!
//!   • the dependency model (the default `ipe build --target wasm` shape): the
//!     runtime is a path dependency selected by the `wasm-client` feature floor,
//!     so the security-forbidden crates are absent from the app manifest and
//!     pulled (only their wasm-safe subset) transitively by that feature. The
//!     browser-glue crates (`web-sys`, `js-sys`, …) live in the runtime crate's
//!     own wasm32 `[target]` table, NOT the app manifest.
//!   • the vendored fallback (`IPE_RUNTIME_VENDORED=1`): the closed
//!     `WASM_CARGO_TOML` template declares every dependency non-optional, so the
//!     browser-glue crates appear directly and the forbidden crates are absent by
//!     construction.
//!
//! These are enforced BY CONSTRUCTION (the manifest templates never include the
//! forbidden crates), but construction alone is not an asserted contract — a
//! future edit that inadvertently adds one would pass every other test. This file
//! makes that contract machine-checked over BOTH shapes.

use std::path::{Path, PathBuf};

use ipe_backend::Backend;
use ipe_backend_rust::{RuntimeDep, RustBackend};
use ipe_intern::Interner;
use ipe_ir::{ModPath, Module, Program, Target};

/// Build the minimal `Program` + the `Interner` used to construct it.
/// Returns both because `RustBackend` borrows the interner for symbol resolution.
fn minimal_wasm_program() -> (Program, Interner) {
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

/// Locate the runtime crate root (`src/runtime/rust`) by walking up from the
/// crate manifest dir — the same in-repo resolution the driver performs, so the
/// dependency-model emit gets a real resolvable `path`.
#[allow(clippy::expect_used)]
fn runtime_crate_root() -> PathBuf {
    let manifest = e2e_support::manifest_dir!();
    let mut here: Option<&Path> = Some(&manifest);
    let found = std::iter::from_fn(|| {
        let dir = here?;
        here = dir.parent();
        Some(dir.join("src").join("runtime").join("rust"))
    })
    .find(|candidate| candidate.join("Cargo.toml").is_file())
    .expect("the ipe-runtime-rust crate root (src/runtime/rust) must resolve for the wasm floor");
    found
        .canonicalize()
        .expect("runtime crate root canonicalizes")
}

/// The dependency-model wasm manifest — the DEFAULT `ipe build --target wasm`
/// shape: the app crate declares the runtime as a path dependency feature-gated
/// by the `wasm-client` floor.
fn emit_wasm_dep_cargo_toml() -> String {
    let (program, interner) = minimal_wasm_program();
    #[allow(clippy::expect_used)] // emit-must-succeed is the test's precondition
    RustBackend::new(&interner)
        .with_target(Target::WasmClient)
        .with_runtime_dep(Some(RuntimeDep {
            root: runtime_crate_root(),
        }))
        .emit(&program)
        .expect("emit must succeed for a body-free wasm dep-model program")
        .cargo_toml
}

/// The vendored-fallback wasm manifest — the closed `WASM_CARGO_TOML` template
/// with every dependency non-optional.
fn emit_wasm_vendored_cargo_toml() -> String {
    let (program, interner) = minimal_wasm_program();
    #[allow(clippy::expect_used)] // emit-must-succeed is the test's precondition
    RustBackend::new(&interner)
        .with_target(Target::WasmClient)
        .emit(&program)
        .expect("emit must succeed for a body-free wasm vendored program")
        .cargo_toml
}

/// Strip `#`-comment lines so a feature/dep NAME mentioned in prose does not
/// trigger a false positive in the forbidden-substring checks below.
fn without_comments(toml: &str) -> String {
    toml.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every wasm-forbidden server-side crate — none may appear in EITHER emitted
/// manifest. `tokio`/`mio` need OS threads + epoll; `axum`/`sqlx`/`reqwest` pull
/// them transitively. Their presence would break the `wasm32-unknown-unknown`
/// build (THE SEAL) and, for `sqlx`/`reqwest`, link a credential path.
const FORBIDDEN_CRATES: &[&str] = &["tokio", "axum", "sqlx", "reqwest"];

/// The dep-model wasm manifest keeps `wasm-bindgen` (the `#[wasm_bindgen(start)]`
/// entry macro the app references by path) and selects the runtime's
/// `wasm-client` floor — the browser module set (and its glue crates: `web-sys`,
/// `js-sys`, …) is pulled transitively by that feature, not declared in the app
/// manifest.
#[test]
fn wasm_dep_manifest_keeps_wasm_bindgen_and_selects_wasm_client() {
    let toml = emit_wasm_dep_cargo_toml();
    assert!(
        toml.contains("wasm-bindgen"),
        "wasm dep-model Cargo.toml must declare wasm-bindgen (the entry macro);\ngot:\n{toml}"
    );
    assert!(
        toml.contains("package = \"ipe-runtime-rust\""),
        "wasm dep-model Cargo.toml must declare the ipe_runtime path dependency;\ngot:\n{toml}"
    );
    assert!(
        toml.contains("\"wasm-client\""),
        "wasm dep-model Cargo.toml must select the `wasm-client` floor feature;\ngot:\n{toml}"
    );
}

/// No server-side crate may appear in the dep-model wasm manifest — the app crate
/// declares only the runtime + `wasm-bindgen` + `serde`, and the runtime's
/// `wasm-client` feature graph excludes tokio/axum/sqlx/reqwest entirely.
#[test]
fn wasm_dep_manifest_excludes_server_crates() {
    let toml = without_comments(&emit_wasm_dep_cargo_toml());
    for forbidden in FORBIDDEN_CRATES {
        assert!(
            !toml.contains(forbidden),
            "wasm dep-model Cargo.toml must not contain `{forbidden}` (SEAL breach);\ngot:\n{toml}"
        );
    }
}

/// The dep-model wasm manifest must not select any server-side runtime feature.
/// The `wasm-client` floor is the ONLY feature the app selects; a drift that
/// unioned `web`/`server`/`db` (their native tokio/axum backends) would break the
/// wasm32 build.
#[test]
fn wasm_dep_manifest_selects_only_the_wasm_floor() {
    let toml = without_comments(&emit_wasm_dep_cargo_toml());
    for forbidden in [
        "\"server\"",
        "\"web\"",
        "\"db\"",
        "\"async\"",
        "\"http_client\"",
    ] {
        assert!(
            !toml.contains(forbidden),
            "wasm dep-model Cargo.toml must not select the {forbidden} feature (a native \
             tokio/axum surface has no wasm denotation);\ngot:\n{toml}"
        );
    }
}

/// The emitted crate type must be `cdylib` — a native `bin` cannot be loaded by
/// the browser's WebAssembly runtime.
#[test]
fn wasm_dep_manifest_is_cdylib() {
    let toml = emit_wasm_dep_cargo_toml();
    assert!(
        toml.contains("cdylib"),
        "wasm dep-model Cargo.toml must declare crate-type = [\"cdylib\"];\ngot:\n{toml}"
    );
}

/// The emitted manifest must detach from any ancestor workspace so `cargo build
/// --target wasm32-unknown-unknown` inside the emitted dir is hermetic.
#[test]
fn wasm_dep_manifest_detaches_from_workspace() {
    let toml = emit_wasm_dep_cargo_toml();
    assert!(
        toml.contains("[workspace]"),
        "wasm dep-model Cargo.toml must include a bare [workspace] section;\ngot:\n{toml}"
    );
}

// ── the vendored fallback keeps the same security floor ────────────────────

/// The vendored fallback manifest MUST name `wasm-bindgen` and `web-sys` (both
/// direct in the closed template) — without them the `cdylib` produces no JS glue
/// and the runtime sink cannot reach the DOM.
#[test]
fn wasm_vendored_manifest_contains_glue_crates() {
    let toml = emit_wasm_vendored_cargo_toml();
    for want in ["wasm-bindgen", "web-sys"] {
        assert!(
            toml.contains(want),
            "wasm vendored Cargo.toml must declare {want};\ngot:\n{toml}"
        );
    }
}

/// No server-side crate may appear in the vendored fallback manifest either.
#[test]
fn wasm_vendored_manifest_excludes_server_crates() {
    let toml = without_comments(&emit_wasm_vendored_cargo_toml());
    for forbidden in FORBIDDEN_CRATES {
        assert!(
            !toml.contains(forbidden),
            "wasm vendored Cargo.toml must not contain `{forbidden}` (SEAL breach);\ngot:\n{toml}"
        );
    }
}

/// The `server`, `db`, and `live` runtime features must not be declared or
/// activated in the vendored fallback manifest.
#[test]
fn wasm_vendored_manifest_excludes_server_db_web_features() {
    let toml = without_comments(&emit_wasm_vendored_cargo_toml());
    for forbidden in ["server", "db", "live"] {
        let declared = format!("{forbidden} = [");
        let activated = format!("\"{forbidden}\"");
        assert!(
            !toml.contains(&declared),
            "wasm vendored Cargo.toml must not declare the '{forbidden}' feature;\ngot:\n{toml}"
        );
        assert!(
            !toml.contains(&activated),
            "wasm vendored Cargo.toml must not activate the '{forbidden}' feature;\ngot:\n{toml}"
        );
    }
}
