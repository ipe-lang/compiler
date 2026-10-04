//! No-server floor for the native desktop-webview delivery.
//!
//! A `web desktop` (webview-native) program renders the diff/patch pipeline
//! over a LOCAL IPC bridge and runs NO HTTP server — so the emitted crate must
//! reach only the server-free `web-core` render core, never the axum `server` nor
//! the full `web` surface. This is the native counterpart of the wasm/SPA floor
//! (`wasm_dep_floor.rs`): both prove a render host reaches the same server-free
//! footing, machine-checked rather than merely enforced by construction.
//!
//! The breach class this pins: a webview program that drags a dead axum `server`
//! (a needless dependency, and — were an HTTP listener ever linked into a desktop
//! app — a Security-principle attack surface with no reason to exist). The check
//! is over BOTH the SSOT feature selection (`runtime_feature_names`) and the
//! emitted dependency-model `Cargo.toml`.

use std::path::{Path, PathBuf};

use ipe_backend::Backend;
use ipe_backend_rust::{RuntimeDep, RustBackend};
use ipe_intern::Interner;
use ipe_ir::{ModPath, Module, Program};

/// A body-free webview-native `Program`: `uses_webview` with NO `uses_web` and NO
/// `uses_server`. `uses_ui` + `uses_async_runtime` mirror a real webview app (the
/// backend forces the async spine for the webview event loop; a webview view is a
/// render surface). The one built module carries the flags the lowerer would set
/// for a `web desktop` entry.
fn webview_program(interner: &mut Interner) -> Program {
    #[allow(clippy::expect_used)]
    let main = interner.intern("Main").expect("intern");
    Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main]),
            types: vec![],
            funcs: vec![],
            entry: None,
            records: vec![],
            uses_tea: true,
            uses_server: false,
            uses_ui: true,
            uses_web: false,
            uses_tui: false,
            uses_console: false,
            uses_webview: true,
            uses_css: false,
            uses_auth: false,
            uses_principal: false,
            uses_websocket: false,
            uses_email: false,
            uses_locale: false,
            uses_time: false,
            uses_env_public: false,
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
            uses_debug: false,
            uses_ffi: false,
            uses_async_runtime: true,
        }],
    }
}

/// Locate the runtime crate root (`src/runtime/rust`) by walking up from the
/// crate manifest dir — the same resolution `wasm_dep_floor.rs` performs, so the
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
    .expect(
        "the ipe-runtime-rust crate root (src/runtime/rust) must resolve for the webview floor",
    );
    found
        .canonicalize()
        .expect("runtime crate root canonicalizes")
}

/// The dependency-model native manifest — the DEFAULT `ipe dev build` shape: the app
/// crate declares the runtime as a path dependency selected by the SSOT feature
/// list, so the security-forbidden crates are absent from the app manifest and
/// only the server-free subset is pulled transitively by the `webview` feature.
#[allow(clippy::expect_used)] // emit-must-succeed is the test's precondition
fn emit_webview_dep_cargo_toml() -> String {
    let mut interner = Interner::new();
    let program = webview_program(&mut interner);
    RustBackend::new(&interner)
        .with_runtime_dep(Some(RuntimeDep {
            root: runtime_crate_root(),
        }))
        .emit(&program)
        .expect("emit must succeed for a body-free webview dep-model program")
        .cargo_toml
}

/// The SSOT feature names the backend selects for a webview-native program.
#[allow(clippy::expect_used)]
fn webview_feature_names() -> Vec<&'static str> {
    let mut interner = Interner::new();
    let program = webview_program(&mut interner);
    RustBackend::new(&interner)
        .runtime_feature_names(&program)
        .expect("runtime_feature_names must succeed for a body-free webview program")
}

/// Strip `#`-comment lines so a feature/dep NAME mentioned in prose does not
/// trigger a false positive in the forbidden-substring checks below.
fn without_comments(toml: &str) -> String {
    toml.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The server-side crates a desktop-webview delivery must NOT link — it runs no
/// HTTP server, so `axum`/`tower-http` (the server framework), `sqlx` (the Live
/// session store), and `reqwest` (outbound HTTP) have no place in its graph.
/// `tokio` is DELIBERATELY absent from this list: the webview event loop is
/// driven through `block_on_current_thread` (a current-thread tokio runtime), so
/// `tokio` is legitimately present — it is the axum server stack that must not be.
const FORBIDDEN_CRATES: &[&str] = &["axum", "tower-http", "sqlx", "reqwest"];

/// The SSOT must select the `webview` feature (and, transitively, the server-free
/// `web-core` render core) for a webview-native program.
#[test]
fn webview_ssot_selects_webview_not_server() {
    let features = webview_feature_names();
    assert!(
        features.contains(&"webview"),
        "a webview-native program must select the `webview` runtime feature; got {features:?}"
    );
    assert!(
        !features.contains(&"server"),
        "a webview-native program must NOT select the axum `server` feature — the \
         desktop delivery runs no HTTP server; got {features:?}"
    );
    assert!(
        !features.contains(&"web"),
        "a webview-native program must NOT select the full `web` surface — its \
         render core is the server-free `web-core`; got {features:?}"
    );
}

/// No axum server-stack crate may appear in the dep-model webview manifest — the
/// app crate declares only the runtime + `serde`, and the runtime's `webview`
/// feature graph excludes axum/tower-http/sqlx/reqwest entirely.
#[test]
fn webview_dep_manifest_excludes_server_crates() {
    let toml = without_comments(&emit_webview_dep_cargo_toml());
    for forbidden in FORBIDDEN_CRATES {
        assert!(
            !toml.contains(forbidden),
            "webview dep-model Cargo.toml must not contain `{forbidden}` (a dead \
             server dependency the desktop delivery never runs);\ngot:\n{toml}"
        );
    }
}

/// The dep-model webview manifest must not select any server-side runtime
/// feature. The `webview` floor (which pulls `web-core`) is the render selection;
/// a drift that unioned `server`/`web`/`db` would drag the axum stack back in.
#[test]
fn webview_dep_manifest_selects_only_the_render_core() {
    let toml = without_comments(&emit_webview_dep_cargo_toml());
    for forbidden in ["\"server\"", "\"web\"", "\"db\"", "\"http_client\""] {
        assert!(
            !toml.contains(forbidden),
            "webview dep-model Cargo.toml must not select the {forbidden} feature (a \
             server surface the desktop-webview delivery has no HTTP listener for);\ngot:\n{toml}"
        );
    }
    // The manifest MUST select `webview` — the whole point of the floor is that
    // this selection carries the render core WITHOUT the server.
    assert!(
        toml.contains("\"webview\""),
        "webview dep-model Cargo.toml must select the `webview` feature;\ngot:\n{toml}"
    );
}
