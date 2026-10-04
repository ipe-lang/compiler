//! Ground-truth SEAL gate for the emitted runtime-module set.
//!
//! The backend trims `ipe_runtime/mod.rs` to a base set and appends
//! feature-modules per program shape (`uses_*` flags). When a shape emits code
//! that references a symbol whose vendored module was NOT appended, `ipe` exits
//! 0 but the emitted crate fails `cargo build` (E0425/E0412) — the module-set
//! SEAL breach class. A curated golden cannot catch it (goldens are hand-picked
//! and the byte-compare default never runs cargo).
//!
//! This test emits a minimal program for each reachable program shape and runs
//! an EXPLICIT `cargo build` of the emitted crate, asserting exit 0. It is the
//! authoritative gate: a passing byte-golden is not sufficient proof of the
//! SEAL.
//!
//! Gated on `IPE_E2E=1` (each shape does a full `cargo build`); without it the
//! test returns early so the default `cargo test` stays fast.
//!
//! The `*_vendored_*` tests additionally force the vendored emit model
//! (equivalent to `IPE_RUNTIME_VENDORED=1`), which was historically never run
//! in CI and concealed a class of SEAL breaks where the vendored manifest was
//! missing a Cargo feature flag required by `#[cfg(feature = "...")]` guards in
//! the vendored runtime source.
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test seal_modset
//! ```

use std::path::Path;

/// Shared error type for the emit-and-build helper.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Emit `ipe_source` for shape `name` and `cargo build` the emitted crate.
/// Returns `Ok(())` iff `ipe` exits 0 AND the emitted crate builds — THE SEAL.
fn emit_and_build(name: &str, ipe_source: &str) -> Result<(), BoxError> {
    let src_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("seal_modset_{name}_ipe"));
    let _ = std::fs::remove_dir_all(&src_dir);
    std::fs::create_dir_all(&src_dir)
        .map_err(|e| -> BoxError { format!("{name}: cannot create src dir: {e}").into() })?;

    let entry = src_dir.join("Main.ipe");
    std::fs::write(&entry, ipe_source)
        .map_err(|e| -> BoxError { format!("{name}: cannot write Main.ipe: {e}").into() })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("seal_modset_{name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe accept — a codegen bug or a rejection surfaces here.
    ipe::build(&entry, &out_dir, &runtime)
        .map_err(|e| -> BoxError { format!("{name}: ipe build failed: {e}").into() })?;

    // THE real test: the emitted crate must `cargo build` (exit 0). A missing
    // runtime-module append reads as E0425/E0412 in this step.
    e2e_support::build_rust_binary(name, &out_dir)
        .map(|_| ())
        .map_err(|e| -> BoxError { e.into() })
}

/// Like `emit_and_build` but forces the VENDORED emit model (`runtime_dep:
/// false`), regardless of the `IPE_RUNTIME_VENDORED` environment variable.
///
/// The vendored model copies the runtime source into the emitted crate and
/// compiles it with the feature flags declared in the emitted `Cargo.toml`.
/// A missing feature flag silently compiles out `#[cfg(feature = "...")]`-gated
/// items, causing E0425/E0412 at `cargo build` despite `ipe` exit 0 — a SEAL
/// breach that the default dep-model tests cannot catch.
fn emit_and_build_vendored(name: &str, ipe_source: &str) -> Result<(), BoxError> {
    // Force the vendored emit model so `#[cfg(feature = "...")]` coverage in
    // the vendored runtime source is verified — the dep-model never exercises it.
    let options = ipe::BuildOptions {
        runtime_dep: false,
        ..ipe::BuildOptions::default()
    };
    emit_and_build_with(name, ipe_source, options)
}

/// Like `emit_and_build` with explicit [`ipe::BuildOptions`]: the caller names
/// the emit model (`runtime_dep`) and any project-level input (`wasm_public_env`).
fn emit_and_build_with(
    name: &str,
    ipe_source: &str,
    options: ipe::BuildOptions,
) -> Result<(), BoxError> {
    let src_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("seal_modset_{name}_ipe"));
    let _ = std::fs::remove_dir_all(&src_dir);
    std::fs::create_dir_all(&src_dir)
        .map_err(|e| -> BoxError { format!("{name}: cannot create src dir: {e}").into() })?;

    let entry = src_dir.join("Main.ipe");
    std::fs::write(&entry, ipe_source)
        .map_err(|e| -> BoxError { format!("{name}: cannot write Main.ipe: {e}").into() })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("seal_modset_{name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build_with_options(&entry, &out_dir, &runtime, options)
        .map_err(|e| -> BoxError { format!("{name}: ipe build failed: {e}").into() })?;

    e2e_support::build_rust_binary(name, &out_dir)
        .map(|_| ())
        .map_err(|e| -> BoxError { e.into() })
}

// ── Program shapes ──────────────────────────────────────────────────────────

/// Baseline: a bare `Io.println` program. Emits only the base module set.
const BARE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    main = Io.println \"bare\"\n";

/// Minimal `Cli.tea` (`CliApp` shape) program.
///
/// `Cli.tea` emits `ipe_runtime::tea::CliApp(console_app(...))`.
/// The `fn main` epilogue must call `ipe_main().run_blocking()` rather than
/// `block_on(ipe_main())` — `CliApp` is not an `IpeTask` and `block_on`
/// does not accept it. A missing or misrouted epilogue switch produces E0277
/// or E0308 at `cargo build` (ipe exit 0 — SEAL breach). This test is the
/// always-run gate that catches that class without requiring a full `IPE_E2E`
/// run of an actual interactive binary.
const CLI_APP_LINES: &str = "module Main exposing (main)\n\
    import Ipe.Tea.Cli as Cli\n\
    import Ipe.Ui.Cli as Ui\n\
    import Ipe.Tea.Terminal.Cmd\n\
    import Ipe.Tea.Cli.Sub\n\
    type Msg = Line String\n\
    type alias Model = { count : Int }\n\
    init _unit = ( { count = 0 }, Cmd.none )\n\
    update msg model = case msg of\n\
    \x20   Line _ -> ( { model | count = model.count + 1 }, Cmd.none )\n\
    view _model = Ui.text \"ok\"\n\
    subscriptions _model = Sub.onLine onLine\n\
    onLine s = Line s\n\
    main = Cli.tea\n\
    \x20   { init = init, update = update, view = view\n\
    \x20   , subscriptions = subscriptions }\n";

/// Minimal Web TEA app that fires `Cmd.publish` from `update`. `cmd_publish`
/// lives in `web::pubsub`; the Web shape must append the `web` runtime module
/// (and, transitively, `tea`). A missing append surfaces as E0425 `cmd_publish`
/// at `cargo build`.
const CMD_PUBLISH: &str = "module Main exposing (main)\n\
    import Ipe.Tea.Web as Web\n\
    import Ipe.Tea.Web.Cmd as Cmd\n\
    import Ipe.Tea.Web.Sub as Sub\n\
    import Ipe.PubSub as PubSub\n\
    import Ipe.Ui as Ui\n\
    type Msg = Publish | Ignored\n\
    type alias Model = {}\n\
    topic = PubSub.topic \"seal-cmd\"\n\
    init _req = ( {}, Cmd.none )\n\
    update msg model = case msg of\n\
    \x20   Publish -> ( model, Cmd.publish topic \"ping\" )\n\
    \x20   Ignored -> ( model, Cmd.none )\n\
    subscriptions _model = Sub.none\n\
    view _model = Ui.html (Ui.layout [] (Ui.text \"ok\"))\n\
    main = Web.tea { init = init, update = update, view = view\n\
    \x20            , subscriptions = subscriptions, routes = [], notFound = Ignored }\n";

/// Minimal Web TEA app that registers `Sub.subscribeTopic` in `subscriptions`.
/// `sub_subscribe_topic` lives in `web::pubsub`; the Web shape must append the
/// `web` runtime module. A missing append surfaces as E0425 `sub_subscribe_topic`
/// at `cargo build`.
const SUB_SUBSCRIBE: &str = "module Main exposing (main)\n\
    import Ipe.Tea.Web as Web\n\
    import Ipe.Tea.Web.Cmd as Cmd\n\
    import Ipe.Tea.Web.Sub as Sub\n\
    import Ipe.PubSub as PubSub\n\
    import Ipe.Ui as Ui\n\
    type Msg = Got String | Ignored\n\
    type alias Model = {}\n\
    topic = PubSub.topic \"seal-sub\"\n\
    init _req = ( {}, Cmd.none )\n\
    update msg model = case msg of\n\
    \x20   Got _ -> ( model, Cmd.none )\n\
    \x20   Ignored -> ( model, Cmd.none )\n\
    subscriptions _model = Sub.subscribeTopic topic Got\n\
    view _model = Ui.html (Ui.layout [] (Ui.text \"ok\"))\n\
    main = Web.tea { init = init, update = update, view = view\n\
    \x20            , subscriptions = subscriptions, routes = [], notFound = Ignored }\n";

/// `Html.renderStatic` from a CLI `main` (web WITHOUT any TEA/server kernel).
/// The `web` module's `use crate::tea::{IpeCmd, IpeSub}` is unconditional, so
/// `tea` must be declared even though no `Cmd`/`Sub` kernel is named. Was E0432
/// `crate::tea` before the fix.
///
/// `renderStatic` lives under the shape-neutral `Ipe.Html`, so this Program
/// imports NO `Ipe.Tea.*` shape and is not misclassified as a TEA app (ADR 0005).
const LIVE_RENDER_STATIC: &str = "module Main exposing (main)\n\
    import Ipe.Html as Html\n\
    type alias Model = { title : String }\n\
    viewStatic : Model -> Html msg\n\
    viewStatic model =\n    \
        Html.node \"div\" [] [ Html.text model.title ]\n\
    main =\n    \
        Html.renderStatic viewStatic { title = \"hi\" }\n";

/// `HttpStream.chunks` where the `StreamId` arrives as a parameter (no `open`
/// in the module set). `sub_subscribe_stream` + `IpeStreamId` live in
/// `http_stream`, declared by the server append. Was E0412 `IpeStreamId` +
/// E0425 `sub_subscribe_stream` before the fix.
const HTTP_STREAM_CHUNKS: &str = "module Main exposing (main)\n\
    import Ipe.Http.Stream as HttpStream exposing (StreamId, ChunkEvent(..))\n\
    import Ipe.Io as Io\n\
    type Msg = Chunked ChunkEvent\n\
    subFor : StreamId -> Sub Msg\n\
    subFor sid = HttpStream.chunks sid Chunked\n\
    main = Io.println \"streamchunks\"\n";

/// Authed-route program using `Server.getAuthed` and `Server.AuthConfig`.
///
/// Under the vendored emit model the runtime `auth.rs` and `server.rs` carry
/// `#[cfg(feature = "jwt")]` guards over `AuthConfig`, `server_get_authed`, and
/// the JWT sign/verify helpers. Without `"jwt"` in the emitted `Cargo.toml`'s
/// `default = [...]` those items are compiled out and `main.rs` references fail
/// with E0425 (`AuthConfig` not found) — the SEAL breach this test gates.
const AUTHED_ROUTE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/authed_route_revocation_vendored_seal/Main.ipe"
));

/// Authed-route + Db-store program using `Store.allAs` behind `Server.getAuthed`.
///
/// Under the vendored emit model the emitted `ipe_runtime/mod.rs` is a trimmed
/// subset of the full runtime `mod.rs`. The runtime `db.rs` calls
/// `crate::ssrf::VettedDial` in `VettedPool::connect`
/// unconditionally (production code, not test-only), and `external_conn.rs` calls
/// `crate::dsn::{Dsn, DsnDriver}` and `crate::ssrf::VettedDial`. Without `ssrf`,
/// `dsn`, and `external_conn` appended to the vendored `mod.rs` whenever `uses_db`
/// is set, those references fail E0425/E0433 (ipe exit 0, cargo fails — SEAL
/// breach). This test gates the db-surface instance of the vendored-model SEAL
/// class.
const AUTHED_STORE_QUERY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/authed_store_query_seal/Main.ipe"
));

/// Authed-route program that calls `Revocation.revokeSession principal jti cap`
/// (the arity-3 form: `Principal -> String -> Int -> Task Error ()`).
///
/// The third argument (`cap`, a Unix-epoch expiry in seconds) was added when the
/// revocation store gained bounded-lifetime entries.  A regression to an arity-2
/// emit (dropping the `Int` argument) produces a call site that does not match
/// the three-argument runtime function `auth_revocation_revoke_session`, causing
/// E0308/E0061 at `cargo build` (ipe exits 0 — the SEAL breach class).  This
/// test catches that regression: if the emit drops the cap argument the emitted
/// crate will not build.
const REVOKE_SESSION_ARITY3: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/revoke_session_arity3_seal/Main.ipe"
));

/// Authed-route program that reads the principal's verified claims via
/// `Auth.claim : String -> Principal -> Maybe String`,
/// `Auth.hasRole : String -> Principal -> Bool`, and
/// `Auth.memberOf : String -> Principal -> Bool`.
///
/// These are compiler-backed reads over the opaque `Principal`
/// (`crate::principal::principal_claim` / `principal_has_role` /
/// `principal_member_of`). A drift between the kernel arity table, the emitted
/// call site, or the `pub mod principal;` append produces E0425/E0308/E0433 at
/// `cargo build` despite `ipe` exit 0 — the SEAL breach class this test gates
/// for the principal-read surface.
const AUTHED_PRINCIPAL_CLAIMS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/authed_principal_claims_seal/Main.ipe"
));

// ── The gate: every shape emits AND cargo-builds ────────────────────────────

#[test]
fn bare_shape_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build("bare", BARE).expect("bare shape must emit and cargo-build");
}

/// A `Cli.tea` program emits `ipe_runtime::tea::CliApp(console_app(...))`.
/// The epilogue `fn main` must call `ipe_main().run_blocking()` — `CliApp` is
/// not an `IpeTask`, so `block_on(ipe_main())` does not type-check (E0277/E0308).
/// This test is the always-run gate for that SEAL class: a misrouted or missing
/// epilogue switch causes a `cargo build` failure here despite `ipe` exiting 0.
#[test]
fn cli_app_lines_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build("cli_app_lines", CLI_APP_LINES).expect(
        "Cli.tea must emit and cargo-build \
         (ipe_main must return CliApp and fn main must call run_blocking, not block_on)",
    );
}

#[test]
fn cmd_publish_no_live_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build("cmd_publish", CMD_PUBLISH)
        .expect("Cmd.publish must pull in the live module (was E0425 cmd_publish)");
}

#[test]
fn sub_subscribe_topic_no_live_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build("sub_subscribe", SUB_SUBSCRIBE)
        .expect("Sub.subscribeTopic must pull in the live module (was E0425 sub_subscribe_topic)");
}

#[test]
fn live_render_static_cli_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build("live_render_static", LIVE_RENDER_STATIC)
        .expect("Html.renderStatic must declare tea (was E0432 crate::tea)");
}

#[test]
fn http_stream_chunks_no_open_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build("http_stream_chunks", HTTP_STREAM_CHUNKS)
        .expect("HttpStream.chunks must pull in the server/http_stream module (was E0412/E0425)");
}

/// A headless `Ipe.Http.Server` program serving an HTML response, with no
/// `Ipe.Html` import.
///
/// Its HTML responses get the dev-console banner, which `telemetry` builds
/// through `crate::escape`; `html` is not vendored for it, so `escape` must be
/// in the floor module set (or the build fails E0433). Built under the vendored
/// model in every job: the dependency model compiles the runtime crate's own
/// `mod.rs`, which never reads the floor template.
const HEADLESS_HTML_SERVER: &str = "module Main exposing (main)\n\
    import Ipe.Http.Server as Server\n\
    import Ipe.Task\n\
    handle : Server.Request -> Task Error Server.Response\n\
    handle _req =\n    Task.succeed (Server.html \"<p>headless</p>\")\n\
    main =\n    Server.listen 8080 [ Server.get \"/\" handle ]\n";

#[test]
fn headless_html_server_builds_with_the_escape_module() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build_vendored("headless_html_server", HEADLESS_HTML_SERVER).expect(
        "a server without Ipe.Html must build: the dev banner escapes through \
         crate::escape, which every module set declares",
    );
}

// ── Vendored-model SEAL: jwt feature must be in default = [...] ─────────────

/// Under the vendored emit model an authed-route program (`Server.getAuthed` +
/// `Server.AuthConfig`) must cargo-build. The runtime `auth.rs` and `server.rs`
/// gate `AuthConfig`, `server_get_authed`, and JWT helpers on
/// `#[cfg(feature = "jwt")]`; without `"jwt"` in the emitted `Cargo.toml`'s
/// `default` those items are compiled out and `main.rs` fails with E0425
/// (ipe exit 0, cargo fails — SEAL breach). This test catches that class under
/// the vendored emit path, which CI previously never ran.
#[test]
fn authed_route_vendored_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build_vendored("authed_route_vendored", AUTHED_ROUTE).expect(
        "authed route must cargo-build under the vendored emit model \
         (jwt feature must be in default = [...])",
    );
}

/// Under the vendored emit model an authed-route + Db-store program
/// (`Server.getAuthed` + `Store.allAs`) must cargo-build. The runtime `db.rs`
/// calls `crate::ssrf::VettedDial` in `VettedPool::connect` (production, not
/// test-only); `external_conn.rs` calls `crate::dsn::{Dsn, DsnDriver}` and
/// `crate::ssrf::VettedDial`. Without `ssrf`, `dsn`, and `external_conn`
/// appended to the vendored `mod.rs` under `uses_db`, the emitted crate fails
/// E0425/E0433 — ipe exit 0, cargo fails: the db-surface SEAL breach.
#[test]
fn authed_store_query_vendored_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build_vendored("authed_store_query_vendored", AUTHED_STORE_QUERY).expect(
        "authed store-query program must cargo-build under the vendored emit model \
         (ssrf + dsn + external_conn must be declared when uses_db)",
    );
}

/// Under the vendored emit model an authed-route program that reads principal
/// claims (`Auth.claim` / `Auth.hasRole` / `Auth.memberOf`) must cargo-build.
/// The emitted call sites bind to `crate::principal::principal_claim` /
/// `principal_has_role` / `principal_member_of` — a missing `pub mod principal;`
/// append or an arity/return-type mismatch fails E0433/E0308/E0425 despite
/// `ipe` exit 0 (the SEAL breach class for the principal-read surface).
#[test]
fn authed_principal_claims_vendored_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build_vendored("authed_principal_claims_vendored", AUTHED_PRINCIPAL_CLAIMS).expect(
        "authed principal-claims program must cargo-build under the vendored emit model \
         (Auth.claim/hasRole/memberOf bind to crate::principal::* reads)",
    );
}

/// Minimal `Jwt.encodeHs256` program — no server/web surface, so no `server`/
/// `web` feature to carry `uuid` transitively.
///
/// `auth.rs` is compiled under `#[cfg(feature = "jwt")]` and calls
/// `uuid::Uuid::new_v4()` to mint per-session `jti` ids in `auth_sign_token`.
/// The `uuid` dep is optional in the runtime crate; without `"uuid"` in the
/// emitted feature set the call fails with E0433 (`uuid` not in scope) despite
/// `ipe` exit 0 — the SEAL breach class this test gates in BOTH emit models.
const JWT_SIGN: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.Jwt\n\
    main =\n    \
        case Jwt.encodeHs256 \"test-secret-key-0123456789abcdef\" \"{}\" of\n    \
            Err _ -> Io.println \"err\"\n    \
            Ok _ -> Io.println \"ok\"\n";

/// Under the dep-model a JWT-only program must emit a feature set that includes
/// `uuid` (because `auth.rs` calls `uuid::Uuid::new_v4()` under the `jwt`
/// feature). Without it the emitted crate fails with E0433 at `cargo build`
/// despite `ipe` exit 0.
#[test]
fn jwt_sign_dep_model_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build("jwt_sign_dep_model", JWT_SIGN).expect(
        "JWT program must cargo-build in the dep model \
         (uuid feature must be selected — auth.rs calls uuid::Uuid::new_v4)",
    );
}

/// Under the vendored emit model the same JWT-only program must cargo-build.
/// `auth.rs` is compiled when the `jwt` feature is in `default = [...]`; it
/// calls `uuid::Uuid::new_v4()`, so the `uuid` dep must be enabled. In the
/// vendored template `uuid` is already a non-optional dep, so this test
/// primarily validates that the `jwt` feature is in `default` (which
/// `jwt_cargo_toml` handles) and that the dep is in scope for `auth.rs`.
#[test]
fn jwt_sign_vendored_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build_vendored("jwt_sign_vendored", JWT_SIGN).expect(
        "JWT program must cargo-build under the vendored emit model \
         (jwt feature must be in default = [...]; uuid dep must be in scope)",
    );
}

/// Arity-3 tripwire for `Revocation.revokeSession`.
///
/// The kernel signature is `Principal -> String -> Int -> Task Error ()`.  Any
/// regression that drops the third `Int` argument (`cap`, the Unix-epoch expiry)
/// causes the emitted Rust call site to mismatch the three-argument runtime
/// function `auth_revocation_revoke_session`, producing a `cargo build` failure
/// (E0061 — wrong number of arguments) despite `ipe` exiting 0 — the SEAL breach
/// class this test gates.
#[test]
fn revoke_session_arity3_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build("revoke_session_arity3", REVOKE_SESSION_ARITY3).expect(
        "Revocation.revokeSession must emit a three-argument call site \
         (Principal, String, Int) and the emitted crate must cargo-build \
         (regression to arity-2 drops the cap Int and fails E0061)",
    );
}

/// Minimal `Tui.tea` program — the vendored emit path must include `seal_codec`
/// in the emitted `ipe_runtime/mod.rs`.
///
/// `ui/widget.rs` unconditionally imports `crate::seal_codec` under
/// `#[cfg(feature = "json")]`, and the vendored template always enables `json`
/// (default feature). Without `pub mod seal_codec;` in the emitted `mod.rs`
/// the emitted crate fails with E0432 (`unresolved import crate::seal_codec`)
/// at `cargo build` despite `ipe` exiting 0 — the SEAL breach this test gates.
const TUI_APP: &str = "module Main exposing (main)\n\
    import Ipe.Tea.Tui as Tui\n\
    import Ipe.Ui.Cells as Cells\n\
    import Ipe.Ui.Cells exposing (Screen)\n\
    import Ipe.Tea.Tui.Cmd\n\
    import Ipe.Tea.Tui.Sub\n\
    type Msg = NoOp\n\
    type alias Model = { count : Int }\n\
    type alias KeyEvent = { kind : String, value : String }\n\
    init : () -> ( Model, Cmd Msg )\n\
    init _unit = ( { count = 0 }, Cmd.none )\n\
    update : Msg -> Model -> ( Model, Cmd Msg )\n\
    update _msg model = ( model, Cmd.none )\n\
    view : Model -> Screen Msg\n\
    view _model = Cells.text \"hello\"\n\
    subscriptions : Model -> Sub Msg\n\
    subscriptions _model = Sub.onKey onKey\n\
    onKey : KeyEvent -> Msg\n\
    onKey _event = NoOp\n\
    main = Tui.tea { init = init, update = update, view = view\n\
    \x20            , subscriptions = subscriptions }\n";

/// Under the vendored emit model a `Tui.tea` program must cargo-build.
///
/// The Tui shape appends `pub mod ui;` to the emitted `ipe_runtime/mod.rs`.
/// `ui/widget.rs` imports `crate::seal_codec` under `#[cfg(feature = "json")]`
/// (always enabled). Without `pub mod seal_codec;` also appended the emitted
/// crate fails with E0432 at `cargo build` despite `ipe` exiting 0.  This test
/// is the authoritative gate for that SEAL class on the Tui shape.
#[test]
fn tui_app_vendored_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build_vendored("tui_app_vendored", TUI_APP).expect(
        "Tui.tea must cargo-build under the vendored emit model \
         (seal_codec must be declared in ipe_runtime/mod.rs — was E0432)",
    );
}

/// Minimal native program reading `Env.public`: it appends the generated
/// `env_public` module, whose native arm reads through the runtime accessor
/// `system::read_env_var`.
const ENV_PUBLIC: &str = "module Main exposing (main)\n\
    import Ipe.Env as Env\n\
    import Ipe.Io as Io\n\
    import Ipe.Maybe as Maybe\n\
    main = Io.println (Maybe.withDefault \"(none)\" (Env.public \"APP_MODE\"))\n";

/// Emit options for [`ENV_PUBLIC`] under `runtime_dep`, allowlisting `APP_MODE`.
fn env_public_options(runtime_dep: bool) -> ipe::BuildOptions {
    ipe::BuildOptions {
        runtime_dep,
        wasm_public_env: vec!["APP_MODE".to_owned()],
        ..ipe::BuildOptions::default()
    }
}

/// Vendored model: `ipe_runtime/env_public.rs` reaches `system::read_env_var`
/// as `super::system::read_env_var`, so the accessor must be `pub` and in scope.
#[test]
fn env_public_vendored_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build_with("env_public_vendored", ENV_PUBLIC, env_public_options(false)).expect(
        "Env.public must cargo-build under the vendored emit model \
         (`super::system::read_env_var` must resolve from `ipe_runtime/env_public.rs`)",
    );
}

/// Dependency model: the relocated user-crate `src/ipe_env_public.rs` reaches
/// the accessor as `ipe_runtime::system::read_env_var` across the crate boundary,
/// so it must be `pub` (a `pub(crate)` accessor is E0603 here).
#[test]
fn env_public_dep_model_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    emit_and_build_with("env_public_dep_model", ENV_PUBLIC, env_public_options(true)).expect(
        "Env.public must cargo-build under the dependency model \
         (`ipe_runtime::system::read_env_var` must be public)",
    );
}

/// The runtime source tree the SEAL tests above vendor and build must resolve
/// to the ACTUAL runtime module tree — not merely to some directory.
/// `resolve_runtime` returns the module-tree root (the crate's `src/`), which
/// the emit SEALs copy and trim/append as `ipe_runtime/mod.rs`; the crate
/// `Cargo.toml` the SEALs splice feature flags into sits one level up. If
/// either load-bearing entry moved, every SEAL above would fail deep inside a
/// `cargo build` with an opaque error. Asserting both are present at their
/// contracted positions makes a tree move fail HERE, loudly and precisely.
#[test]
fn runtime_tree_resolves() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let module_root = Path::new(&runtime);
    assert!(
        module_root.is_dir(),
        "resolved runtime path must be a directory: {}",
        module_root.display()
    );
    // The module-set root (`ipe_runtime/mod.rs`) the backend trims and appends —
    // directly in the resolved module tree.
    let mod_rs = module_root.join("mod.rs");
    assert!(
        mod_rs.is_file(),
        "resolved runtime tree must contain `mod.rs` (the module set the emit \
         SEALs trim and append): {}",
        mod_rs.display()
    );
    // The vendored crate manifest the emit SEALs splice feature flags into sits
    // at the crate root, one level above the module tree.
    let manifest = module_root
        .parent()
        .map(|crate_root| crate_root.join("Cargo.toml"));
    assert!(
        manifest.as_ref().is_some_and(|m| m.is_file()),
        "resolved runtime crate root (parent of the module tree) must contain the \
         vendored `Cargo.toml` the SEALs splice: {manifest:?}",
    );
}
