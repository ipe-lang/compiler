//! Co-located WASI (`wasm32-wasip1`) accept-path SEAL (issue #2461).
//!
//! Obligations, all fail-closed by construction:
//!
//! * **THE SEAL (emit-side):** a `Direct`/`Script` (`main : Task Error ()`)
//!   program that reaches only the sealed WASI floor (`Ipe.Io` stdio) emits a
//!   project that `cargo build --target wasm32-wasip1` — `ipe`-accepts ⇒
//!   cargo-builds. Gated on `IPE_E2E=1` (the default `cargo test` stays fast +
//!   offline).
//! * **THE SEAL (user path):** the SAME guarantee through the real CLI selector
//!   — `ipe dev build --target wasi` on a sealed-floor `Direct` program produces a
//!   `wasm32-wasip1` module that built. This is the path an end user walks.
//! * **The refusal (emit-side):** a program reaching a NON-viable family
//!   (`Ipe.Http`, whose reqwest/`tokio/net` stack does not build on wasip1) is
//!   turned away at `ipe` time with a typed diagnostic (IPE-N0029), never
//!   emitted — so the unbuildable shape can never reach the wasip1 `cargo build`.
//! * **The refusal (user path):** `ipe dev build --target wasi` on a non-WASI-viable
//!   program is refused before any wasip1 `cargo build`, by one of two
//!   independent, defense-in-depth gates:
//!     - a TEA `Web` app is turned back at delivery-resolve time by the
//!       `admit_triple` matrix (`WasiRequiresDirectShape`) — its `ControlModel`
//!       is `Tea`, which has no co-located WASI floor.
//!     - a `Server.listen` program is a `Direct` (`script`) shape, so it PASSES
//!       the matrix; its tokio/axum-bound `ServerListen` kernel is instead turned
//!       back at `ipe` time by the per-kernel sealed floor (`check_wasm_wasi`,
//!       IPE-N0029) — the SAME floor that refuses `Ipe.Http`. This per-kernel
//!       floor is the invariant that upholds THE SEAL once `server` folds into
//!       the `Direct` bucket and the shape gate no longer refuses it.
//!
//! The refusal tests run unconditionally (no cargo, no network): they are the
//! standing check that the sealed-floor gate stays real.

use std::path::{Path, PathBuf};

use e2e_support::target::BuildTarget;
use ipe::{BuildOptions, CliError};

/// A fresh, pid-isolated scratch dir under the test tempdir (concurrent runs
/// never share a tree).
fn scratch(name: &str) -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_{}", std::process::id()));
    e2e_support::scratch::fresh(&dir);
    dir
}

/// Set only on a WASI seal test's re-exec of this binary, whose cargo
/// environment was fixed at spawn.
const SEAL_CHILD_MARKER: &str = "IPE_WASI_SEAL_CHILD";

/// Whether this process IS a WASI seal test's re-exec of this binary, whose
/// cargo environment was fixed at spawn by [`rerun_in_target`]. The caller
/// branches on this BEFORE allocating a build target: only the parent needs
/// one (to forward into the child's environment), and the child must never
/// allocate its own — it was handed the parent's already, and a second
/// `target::isolated` call in the same process tree would nest a fresh
/// isolated tree under the one the parent is still holding.
fn is_seal_child() -> bool {
    ipe_env::var_os(SEAL_CHILD_MARKER).is_some()
}

/// Re-exec this binary running exactly `test`, with its environment pinned to
/// `target`'s path and `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS` cleared — the
/// parent side of the self-rerun seal check [`is_seal_child`] detects in the
/// child.
///
/// The cargo `run_cli` spawns inherits this process's environment, and a global
/// `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS` outranks the emitter's own
/// `[target.<triple>]` config, so a pass proves the end-user seal only when
/// the build sees exactly the emitted config — set at spawn, never mutated
/// in-process. The child must actually run and pass `test`: a name matching
/// nothing is refused, never a vacuous green.
fn rerun_in_target(test: &str, target: &BuildTarget) {
    let rerun = e2e_support::rerun_this_test_exact(test, |cmd| {
        cmd.arg("--nocapture").env(SEAL_CHILD_MARKER, "1");
        e2e_support::target::set_target_dir_env(cmd, target.path());
        cmd.env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS");
    });
    assert!(
        rerun.is_ok(),
        "{test}: the cargo-env re-exec did not pass: {rerun:?}"
    );
}

fn wasi_options() -> BuildOptions {
    BuildOptions {
        target: ipe_ir::Target::WasmWasi,
        ..BuildOptions::default()
    }
}

/// `source` as the `Main` module of a fresh project fixture.
#[allow(clippy::expect_used)] // test helper: a failed fixture setup IS the failure
fn wasi_fixture(source: &str) -> ipe::RootFixture {
    ipe::RootFixture::main(source).expect("write the project fixture")
}

/// Emit `fixture` for the co-located WASI target into `out`.
#[allow(clippy::expect_used)] // test helper: an unresolvable runtime IS the failure
fn emit_wasi(fixture: &ipe::RootFixture, out: &Path) -> Result<(), CliError> {
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_fixture_with_options(fixture, out, &runtime, &wasi_options()).map(drop)
}

/// A `Direct` script that reaches only the sealed WASI floor: `Ipe.Io` stdio +
/// pure `Ipe.String`. Its `main` is a plain `Task Error ()` — the ONE control
/// model the WASI engine carries.
const DIRECT_FLOOR_SOURCE: &str = "module Main exposing (main)\n\
     \n\
     import Ipe.Io as Io\n\
     import Ipe.String as String\n\
     \n\
     main : Task Error ()\n\
     main =\n\
     \x20   Io.println (String.fromInt 42)\n";

/// A `Direct` script reaching a NON-viable family (`Ipe.Http`): reqwest pulls
/// `tokio/net`→`mio`, which does not build on `wasm32-wasip1`. It MUST be
/// refused at `ipe` time so it never reaches the wasip1 `cargo build`.
const HTTP_SHAPE_SOURCE: &str = "module Main exposing (main)\n\
     \n\
     import Ipe.Io as Io\n\
     import Ipe.Http as Http\n\
     import Ipe.Url as Url\n\
     import Ipe.Task as Task\n\
     \n\
     main : Task Error ()\n\
     main =\n\
     \x20   case Url.fromString \"https://example.com\" of\n\
     \x20       Just url ->\n\
     \x20           Task.andThen (\\_resp -> Io.println \"done\") (Http.get url)\n\
     \x20\n\
     \x20       Nothing ->\n\
     \x20           Io.println \"bad url\"\n";

/// A `Web` TEA app — a view-ful loop pinned to the `ControlModel::Tea` model,
/// which is NOT WASI-viable (its runtime spine pulls tokio/axum). `--target
/// wasi` on it must be refused at delivery-resolve time, before any emit.
const WEB_TEA_SOURCE: &str = r"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub

type Msg = Increment

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.text (String.fromInt model.count)

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Increment
        }
";

/// A `Server.listen` app — `main = Server.listen …`. It is a `Direct` (`script`)
/// shape (a plain `Task Error ()`), so it PASSES the `admit_triple` shape gate;
/// but its `Server.listen` kernel rides the axum/tokio reactor, which does not
/// build on `wasm32-wasip1` (preview1 has no socket listen/accept, and tokio/mio
/// do not compile for the target). `--target wasi` on it must be refused at
/// `ipe` time by the per-kernel sealed floor (IPE-N0029), before any emit — the
/// defense-in-depth backstop that upholds THE SEAL once `server` is a `Direct`
/// program.
const SERVER_SHAPE_SOURCE: &str = "module Main exposing (main)\n\
     \n\
     import Ipe.Http.Server as Server\n\
     import Ipe.Task\n\
     \n\
     handle : Server.Request -> Task Error Server.Response\n\
     handle _req =\n\
     \x20   Task.succeed (Server.text \"ok\")\n\
     \n\
     main =\n\
     \x20   Server.listen 8080\n\
     \x20       [ Server.get \"/\" handle ]\n";

/// THE SEAL: a sealed-floor `Direct` program emits a project that
/// `cargo build --target wasm32-wasip1` accepts. `ipe`-accepts ⇒ cargo-builds.
#[test]
#[allow(clippy::panic)] // a test-environment setup failure fails the test with its cause
fn wasi_direct_floor_program_cargo_builds_for_wasip1() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let dir = scratch("wasi_seal_floor");
    let fixture = wasi_fixture(DIRECT_FLOOR_SOURCE);
    let out = dir.join("out");

    // ipe accepts the sealed-floor program for the WASI target and emits it.
    emit_wasi(&fixture, &out).expect("sealed-floor Direct program must ipe-accept for WASI");

    // The wasm32-wasip1 dependency tree is not the shared target's: an
    // exclusive private tree.
    let isolated =
        e2e_support::target::isolated(e2e_support::target::IsolationReason::ForeignTriple);
    let Ok(isolated) = isolated else {
        panic!("isolated build target: {isolated:?}")
    };
    let target = BuildTarget::Isolated(isolated);
    let mut cargo = e2e_support::target::cargo_command(&target);
    cargo
        .arg("build")
        .args(["--target", "wasm32-wasip1"])
        .current_dir(&out)
        // Drop any ambient `RUSTFLAGS` / `CARGO_ENCODED_RUSTFLAGS` a dev host or
        // CI runner exports (e.g. `-C link-arg=-fuse-ld=mold`): a global
        // `RUSTFLAGS` OUTRANKS every `[target.<triple>] rustflags` config (cargo
        // picks the FIRST source that sets flags — env before config), so leaving
        // it set would mask the emitted crate's OWN `.cargo/config.toml`
        // wasip1-linker override. Cleared here, the child build is governed by
        // exactly the config the emitter ships — so a pass PROVES the emit-side
        // seal (the mold-free link an end user gets), never a test-only env patch.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");
    let output = cargo.output();
    let ok = matches!(&output, Ok(o) if o.status.success());
    assert!(
        ok,
        "THE SEAL: a sealed-floor WASI Direct program must cargo-build for \
         wasm32-wasip1 (ipe-accepts ⇒ cargo-builds); got {}",
        match &output {
            Ok(o) => format!(
                "status {:?}\n--- cargo stderr ---\n{}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => format!("cargo failed to spawn: {e}"),
        },
    );
}

/// The refusal: a `Direct` program reaching a non-viable family (`Ipe.Http`) is
/// turned away at `ipe` time with a typed diagnostic — fail-closed, no emit, so
/// the unbuildable shape never reaches the wasip1 `cargo build`. Runs always.
#[test]
fn wasi_http_shape_is_refused_fail_closed() {
    let dir = scratch("wasi_seal_http_refusal");
    let fixture = wasi_fixture(HTTP_SHAPE_SOURCE);
    let out = dir.join("out");

    let err = emit_wasi(&fixture, &out)
        .expect_err("an Http-reaching program must be REFUSED for the WASI sealed floor");

    // The refusal is the sealed-floor gate (IPE-N0029 server-only-kernel-for-wasm),
    // a typed pipeline diagnostic — never a cargo failure, never a silent emit.
    let rendered = format!("{err}");
    assert!(
        matches!(err, CliError::Pipeline { .. }),
        "the refusal must be a typed pipeline diagnostic, got: {rendered}",
    );
    // And nothing effectful was emitted: the accept-path never opened for it.
    assert!(
        !out.join("Cargo.toml").exists(),
        "a refused WASI shape must emit no project (fail-closed before emit)",
    );
}

/// THE SEAL through the USER selector: `ipe dev build --target wasi` on a
/// sealed-floor `Direct` program produces a `wasm32-wasip1` module that
/// `cargo build`s. This exercises the real CLI path — parse `--target wasi`,
/// resolve the compile target, gate through `admit_triple`, emit, and run the
/// wasip1 cross-compile — not the emit helper directly. `ipe`-accepts (exit 0)
/// ⇒ cargo-builds. Gated on `IPE_E2E=1`.
#[test]
#[allow(clippy::panic)] // a test-environment setup failure fails the test with its cause
fn ipe_build_target_wasi_user_path_cargo_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let dir = scratch("wasi_seal_user_path");
    let fixture = wasi_fixture(DIRECT_FLOOR_SOURCE);
    let out = dir.join("out");

    if is_seal_child() {
        let args = vec![
            "dev".to_owned(),
            "build".to_owned(),
            fixture.path().to_string_lossy().into_owned(),
            "--out".to_owned(),
            out.to_string_lossy().into_owned(),
            "--target".to_owned(),
            "wasi".to_owned(),
        ];
        // THE SEAL: `run_cli` returns `Ok` ONLY if the wasip1 `cargo build`
        // succeeded — `bundle_wasi` runs `cargo build --target wasm32-wasip1` and
        // surfaces a non-zero exit as `CliError::EmittedBuildFailed`, so an `Ok`
        // here is the end-to-end proof that the `ipe`-accepted program cargo-builds
        // for the target through the real user selector. (The module artifact path
        // is `bundle_wasi`'s own concern; a green build is the seal.)
        let result = ipe::run_cli(&args);
        assert!(
            result.is_ok(),
            "THE SEAL (user path): `ipe dev build --target wasi` on a sealed-floor Direct \
             program must succeed (ipe-accepts ⇒ cargo-builds for wasm32-wasip1); got {result:?}",
        );
    } else {
        // The wasm32-wasip1 dependency tree is not the shared target's: an
        // exclusive private tree, forwarded to the re-exec'd child's environment.
        // The wasip1 link is governed by the emitter's own `.cargo/config.toml`
        // (see `rerun_in_target`).
        let isolated =
            e2e_support::target::isolated(e2e_support::target::IsolationReason::ForeignTriple);
        let Ok(isolated) = isolated else {
            panic!("isolated build target: {isolated:?}")
        };
        let target = BuildTarget::Isolated(isolated);
        rerun_in_target("ipe_build_target_wasi_user_path_cargo_builds", &target);
    }
}

/// The user-path refusal: `ipe dev build --target wasi` on a non-WASI-viable shape
/// (a `Web` TEA app) is refused fail-closed with a typed diagnostic at
/// delivery-resolve time — never a permissive default, never an emit. Runs
/// unconditionally (no cargo): the standing check the selector fails closed.
#[test]
fn ipe_build_target_wasi_refuses_non_viable_shape_fail_closed() {
    let dir = scratch("wasi_seal_user_refusal");
    let fixture = wasi_fixture(WEB_TEA_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "build".to_owned(),
        fixture.path().to_string_lossy().into_owned(),
        "--out".to_owned(),
        out.to_string_lossy().into_owned(),
        "--target".to_owned(),
        "wasi".to_owned(),
    ];
    let err = ipe::run_cli(&args)
        .expect_err("a Web TEA app must be REFUSED for --target wasi (not WASI-viable)");

    // The refusal is a typed usage diagnostic naming the non-Direct shape — the
    // `admit_triple` matrix's `WasiRequiresDirectShape` cell, surfaced through
    // the CLI. Never a cargo failure, never a silent native fallback.
    let rendered = format!("{err}");
    assert!(
        rendered.contains("wasm32-wasip1") && rendered.contains("Direct"),
        "the refusal must teach the WASI/Direct rule, got: {rendered}",
    );
    // Fail-closed before emit: nothing was written for the refused shape.
    assert!(
        !out.exists(),
        "a refused WASI user build must emit no project (fail-closed before emit)",
    );
}

// ── the RUN path (`ipe dev run --target wasi`, embedded wasmtime) ────────────────

/// THE SEAL for the run path (feature on): `ipe dev run --target wasi` on a
/// sealed-floor `Direct` program builds the `wasm32-wasip1` module AND executes
/// it under the embedded wasmtime engine, confined by a WASI context derived
/// from the program's declared capability floor. `run_cli` returns `Ok` ONLY
/// when the guest ran to a clean exit 0 — so an `Ok` here is the end-to-end
/// proof that the `ipe`-accepted program built for the target and ran correctly
/// under the deny-by-default context. Gated on `IPE_E2E=1` (default `cargo test`
/// stays fast + offline) AND on the `wasi_run` feature (the embedded engine).
#[cfg(feature = "wasi_run")]
#[test]
#[allow(clippy::panic)] // a test-environment setup failure fails the test with its cause
fn ipe_run_target_wasi_executes_under_wasmtime() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let dir = scratch("wasi_run_exec");
    let fixture = wasi_fixture(DIRECT_FLOOR_SOURCE);
    let out = dir.join("out");

    if is_seal_child() {
        let args = vec![
            "dev".to_owned(),
            "run".to_owned(),
            fixture.path().to_string_lossy().into_owned(),
            "--out".to_owned(),
            out.to_string_lossy().into_owned(),
            "--target".to_owned(),
            "wasi".to_owned(),
        ];
        let result = ipe::run_cli(&args);
        assert!(
            result.is_ok(),
            "THE SEAL (run path): `ipe dev run --target wasi` on a sealed-floor Direct \
             program must build the wasm32-wasip1 module and run it to a clean exit \
             under embedded wasmtime; got {result:?}",
        );
    } else {
        // The wasm32-wasip1 dependency tree is not the shared target's: an
        // exclusive private tree, forwarded to the re-exec'd child's environment.
        let isolated =
            e2e_support::target::isolated(e2e_support::target::IsolationReason::ForeignTriple);
        let Ok(isolated) = isolated else {
            panic!("isolated build target: {isolated:?}")
        };
        let target = BuildTarget::Isolated(isolated);
        rerun_in_target("ipe_run_target_wasi_executes_under_wasmtime", &target);
    }
}

/// The run-path refusal (non-viable shape): `ipe dev run --target wasi` on a `Web`
/// TEA app is refused fail-closed at delivery-resolve time — the SAME
/// `admit_triple` matrix `ipe dev build --target wasi` gates on, so the run path
/// never opens a looser door than build. Runs unconditionally (no cargo, no
/// engine): the standing check that the selector fails closed for the run path.
#[test]
fn ipe_run_target_wasi_refuses_non_viable_shape_fail_closed() {
    let dir = scratch("wasi_run_refuse_shape");
    let fixture = wasi_fixture(WEB_TEA_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "run".to_owned(),
        fixture.path().to_string_lossy().into_owned(),
        "--out".to_owned(),
        out.to_string_lossy().into_owned(),
        "--target".to_owned(),
        "wasi".to_owned(),
    ];
    let err = ipe::run_cli(&args).expect_err(
        "a Web TEA app must be REFUSED for `ipe dev run --target wasi` (not WASI-viable)",
    );

    let rendered = format!("{err}");
    assert!(
        rendered.contains("wasm32-wasip1") && rendered.contains("Direct"),
        "the run-path refusal must teach the WASI/Direct rule, got: {rendered}",
    );
    assert!(
        !out.exists(),
        "a refused WASI run must emit no project (fail-closed before emit)",
    );
}

/// THE SEAL for the collapsed `server` bucket: `ipe dev build --target wasi` on a
/// `Server.listen` app is refused fail-closed at `ipe` time by the per-kernel
/// sealed floor (IPE-N0029), never a wasip1 `cargo build`. Since a server is now
/// a `Direct` (`script`) shape, the `admit_triple` shape gate PASSES it — so the
/// per-kernel floor (`check_wasm_wasi`: `ServerListen` carries `KernelClass::Server`
/// and is NOT in `available_on(WasmWasi)`) is the gate that must turn it back,
/// exactly as it does `Ipe.Http`. tokio/axum do not build on wasip1, so admitting
/// it would break the `ipe`-accepts ⇒ cargo-builds SEAL. Runs unconditionally (no
/// cargo): the standing check that this refusal — the invariant that replaces the
/// dropped shape arm — stays real.
#[test]
fn ipe_build_target_wasi_refuses_live_server_fail_closed() {
    let dir = scratch("wasi_seal_server_refusal");
    let fixture = wasi_fixture(SERVER_SHAPE_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "build".to_owned(),
        fixture.path().to_string_lossy().into_owned(),
        "--out".to_owned(),
        out.to_string_lossy().into_owned(),
        "--target".to_owned(),
        "wasi".to_owned(),
    ];
    let err = ipe::run_cli(&args)
        .expect_err("a Server.listen app must be REFUSED for --target wasi (not WASI-viable)");

    // The refusal is the per-kernel sealed floor (IPE-N0029 server-only-kernel-for-wasm),
    // a typed pipeline diagnostic — never a cargo failure, never a silent emit.
    let rendered = format!("{err}");
    assert!(
        matches!(err, CliError::Pipeline { .. }),
        "the server refusal must be the typed per-kernel-floor pipeline diagnostic, got: {rendered}",
    );
    assert!(
        rendered.contains("server-only"),
        "the refusal must name the server-only kernel floor (IPE-N0029), got: {rendered}",
    );
    // Fail-closed before emit: nothing was written for the refused server.
    assert!(
        !out.exists(),
        "a refused WASI server build must emit no project (fail-closed before emit)",
    );
}

/// The run-path mirror of the server refusal (feature ON): `ipe dev run --target
/// wasi` on a `Server.listen` app is refused fail-closed at the per-kernel sealed
/// floor (IPE-N0029) — the wasip1 module is built (and the `Server.listen` kernel
/// turned back there) before the embedded engine could run it, so the run path
/// never opens a looser door than build. Gated on `wasi_run`: without the
/// embedded engine the run path short-circuits at the feature gate first (see
/// [`ipe_run_target_wasi_feature_off_is_typed_refusal`]), a distinct fail-closed
/// refusal that also never reaches a wasip1 build.
#[cfg(feature = "wasi_run")]
#[test]
fn ipe_run_target_wasi_refuses_live_server_fail_closed() {
    let dir = scratch("wasi_run_server_refusal");
    let fixture = wasi_fixture(SERVER_SHAPE_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "run".to_owned(),
        fixture.path().to_string_lossy().into_owned(),
        "--out".to_owned(),
        out.to_string_lossy().into_owned(),
        "--target".to_owned(),
        "wasi".to_owned(),
    ];
    let err = ipe::run_cli(&args).expect_err(
        "a Server.listen app must be REFUSED for `ipe dev run --target wasi` (not WASI-viable)",
    );

    let rendered = format!("{err}");
    assert!(
        matches!(err, CliError::Pipeline { .. }),
        "the run-path server refusal must be the typed per-kernel-floor pipeline diagnostic, got: {rendered}",
    );
    assert!(
        rendered.contains("server-only"),
        "the run-path refusal must name the server-only kernel floor (IPE-N0029), got: {rendered}",
    );
    assert!(
        !out.exists(),
        "a refused WASI server run must emit no project (fail-closed before emit)",
    );
}

/// The run-path refusal (feature off): with `wasi_run` disabled, `ipe dev run
/// --target wasi` returns a typed refusal naming the missing feature — never a
/// panic, never a silent native fallback, and never a (wasted) wasip1 build.
/// Runs unconditionally when the feature is off; no cargo, no network.
#[cfg(not(feature = "wasi_run"))]
#[test]
fn ipe_run_target_wasi_feature_off_is_typed_refusal() {
    let dir = scratch("wasi_run_feature_off");
    let fixture = wasi_fixture(DIRECT_FLOOR_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "run".to_owned(),
        fixture.path().to_string_lossy().into_owned(),
        "--out".to_owned(),
        out.to_string_lossy().into_owned(),
        "--target".to_owned(),
        "wasi".to_owned(),
    ];
    let err = ipe::run_cli(&args)
        .expect_err("`ipe dev run --target wasi` without the wasi_run feature must be refused");

    assert!(
        matches!(err, CliError::WasiRunFeatureDisabled),
        "the feature-off refusal must be the typed WasiRunFeatureDisabled, got: {err:?}",
    );
    let rendered = format!("{err}");
    assert!(
        rendered.contains("wasi_run"),
        "the refusal must name the missing feature, got: {rendered}",
    );
    // Fail-closed BEFORE the (costly) wasip1 build: nothing was emitted.
    assert!(
        !out.exists(),
        "the feature-off refusal must fire before any emit (no wasted build)",
    );
}

/// The server run-path refusal (feature off): a `Server.listen` app is a `Direct`
/// (`script`) shape, so it PASSES the `admit_triple` shape gate — but with
/// `wasi_run` disabled the run path short-circuits at the feature gate first,
/// returning the typed `WasiRunFeatureDisabled` before any wasip1 build. So the
/// server run refusal stays fail-closed in BOTH feature states (the per-kernel
/// floor fires only when the feature is on and the build proceeds). Proves the
/// refusal is never one edit from vanishing when the embedded engine is absent.
#[cfg(not(feature = "wasi_run"))]
#[test]
fn ipe_run_target_wasi_server_feature_off_is_typed_refusal() {
    let dir = scratch("wasi_run_server_feature_off");
    let fixture = wasi_fixture(SERVER_SHAPE_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "run".to_owned(),
        fixture.path().to_string_lossy().into_owned(),
        "--out".to_owned(),
        out.to_string_lossy().into_owned(),
        "--target".to_owned(),
        "wasi".to_owned(),
    ];
    let err = ipe::run_cli(&args).expect_err(
        "a Server.listen app must be REFUSED for `ipe dev run --target wasi` without the wasi_run feature",
    );

    assert!(
        matches!(err, CliError::WasiRunFeatureDisabled),
        "the feature-off server run refusal must be the typed WasiRunFeatureDisabled, got: {err:?}",
    );
    // Fail-closed BEFORE any emit: nothing was written for the refused server.
    assert!(
        !out.exists(),
        "the feature-off server run refusal must fire before any emit (no wasted build)",
    );
}

// ── preopen confinement (the embedded engine's filesystem boundary) ─────────────

/// The bytes the fixture keeps outside the preopened working tree.
#[cfg(all(unix, feature = "wasi_run"))]
const OUTSIDE_SECRET: &[u8] = b"outside-the-preopen";

/// The guest's exit code when its first filesystem call is refused.
#[cfg(all(unix, feature = "wasi_run"))]
const REFUSED_AT_OPEN: i32 = 20;

/// The guest's exit code when the bytes it read reached `leak`.
#[cfg(all(unix, feature = "wasi_run"))]
const LEAK_WRITTEN: i32 = 12;

/// What a confinement guest asks of the preopen, through one path.
#[cfg(all(unix, feature = "wasi_run"))]
#[derive(Clone, Copy)]
enum GuestAct {
    /// Open `path` as a directory, open `secret` under it, read it, and write
    /// the bytes to `leak` in the preopen.
    OpenDirThenSecret { path: &'static str },
    /// Open `path` as a file, read it, and write the bytes to `leak` in the
    /// preopen.
    OpenFile { path: &'static str },
    /// Rename `path` to `moved`, both under the preopen.
    Rename { path: &'static str },
}

/// The WAT text of the guest that performs `act` against preopen fd 3.
///
/// Exit codes, one per stage reached: `20` refused at the first call, `10`
/// opened but not read, `11` read but not written, `12` the bytes written to
/// `leak`, `13` renamed. Every open of `path` follows symlinks, the guest
/// libc's default.
#[cfg(all(unix, feature = "wasi_run"))]
fn confinement_guest(act: GuestAct) -> String {
    let (path, body) = match act {
        GuestAct::OpenDirThenSecret { path } => (path, open_read_leak_body(path, 2, Some(704))),
        GuestAct::OpenFile { path } => (path, open_read_leak_body(path, 0, None)),
        GuestAct::Rename { path } => (path, rename_body(path)),
    };
    format!(
        r#"(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_rename"
    (func $path_rename (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{path}")
  (data (i32.const 64) "secret")
  (data (i32.const 128) "leak")
  (data (i32.const 192) "moved")
  (func $exit (param i32) (call $proc_exit (local.get 0)) unreachable)
  (func (export "_start")
{body}))"#
    )
}

/// The open, read and write-to-`leak` body.
///
/// `oflags` is the first open's flags; `secret_fd_at` names where a nested
/// `secret` open stores its fd, and with none the first open's fd is read.
#[cfg(all(unix, feature = "wasi_run"))]
fn open_read_leak_body(path: &str, oflags: u8, secret_fd_at: Option<u32>) -> String {
    let path_len = path.len();
    let open_secret = secret_fd_at.map_or_else(String::new, |at| {
        format!(
            "    (if (call $path_open (i32.load (i32.const 700)) (i32.const 1) (i32.const 64) (i32.const 6)
          (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const {at}))
      (then (call $exit (i32.const 10))))\n"
        )
    });
    let read_fd_at = secret_fd_at.unwrap_or(700);
    format!(
        "    (if (call $path_open (i32.const 3) (i32.const 1) (i32.const 0) (i32.const {path_len})
          (i32.const {oflags}) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 700))
      (then (call $exit (i32.const {REFUSED_AT_OPEN}))))
{open_secret}    (i32.store (i32.const 512) (i32.const 1024))
    (i32.store (i32.const 516) (i32.const 256))
    (if (call $fd_read (i32.load (i32.const {read_fd_at})) (i32.const 512) (i32.const 1) (i32.const 600))
      (then (call $exit (i32.const 10))))
    (if (call $path_open (i32.const 3) (i32.const 0) (i32.const 128) (i32.const 4)
          (i32.const 9) (i64.const 64) (i64.const 0) (i32.const 0) (i32.const 708))
      (then (call $exit (i32.const 11))))
    (i32.store (i32.const 520) (i32.const 1024))
    (i32.store (i32.const 524) (i32.load (i32.const 600)))
    (if (call $fd_write (i32.load (i32.const 708)) (i32.const 520) (i32.const 1) (i32.const 604))
      (then (call $exit (i32.const 11))))
    (call $exit (i32.const 12))"
    )
}

/// The rename body: `path` to `moved`, both under the preopen.
#[cfg(all(unix, feature = "wasi_run"))]
fn rename_body(path: &str) -> String {
    let path_len = path.len();
    format!(
        "    (if (call $path_rename (i32.const 3) (i32.const 0) (i32.const {path_len})
          (i32.const 3) (i32.const 192) (i32.const 5))
      (then (call $exit (i32.const {REFUSED_AT_OPEN}))))
    (call $exit (i32.const 13))"
    )
}

/// The host side of one confinement case.
///
/// It holds the fixture root, its preopened working tree and the sibling
/// directory holding the secret.
#[cfg(all(unix, feature = "wasi_run"))]
struct ConfinementFixture {
    root: PathBuf,
    sandbox: PathBuf,
    outside: PathBuf,
}

#[cfg(all(unix, feature = "wasi_run"))]
impl ConfinementFixture {
    /// The working tree `sandbox/` beside `outside/secret`, under the test temp root.
    ///
    /// `sandbox/up -> ../outside` and `sandbox/f -> ../outside/secret` are
    /// proven to resolve on the host first, so a refusal the guest sees is the
    /// preopen's, never a broken fixture's. `sandbox/inside/secret` and
    /// `sandbox/g` hold the same bytes inside the preopen, for the controls
    /// that prove the guest reads and leaks when the preopen allows it.
    #[allow(clippy::expect_used)] // test helper: a failed fixture setup IS the failure
    fn new(name: &str) -> Self {
        let root = ipe_test_temp::temp_root().join(format!(
            "ipe_preopen_confinement_{name}_{}",
            std::process::id()
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root).expect("clear a stale fixture");
        }
        let sandbox = root.join("sandbox");
        let outside = root.join("outside");
        std::fs::create_dir_all(&sandbox).expect("create the working tree");
        std::fs::create_dir_all(&outside).expect("create the outside directory");
        std::fs::write(outside.join("secret"), OUTSIDE_SECRET).expect("write the secret");
        std::fs::create_dir_all(sandbox.join("inside")).expect("create the inside directory");
        std::fs::write(sandbox.join("inside").join("secret"), OUTSIDE_SECRET)
            .expect("write the inside secret");
        std::fs::write(sandbox.join("g"), OUTSIDE_SECRET).expect("write the inside file");
        std::os::unix::fs::symlink("../outside", sandbox.join("up")).expect("link up");
        std::os::unix::fs::symlink("../outside/secret", sandbox.join("f")).expect("link f");
        assert_eq!(
            std::fs::read(sandbox.join("up").join("secret")).expect("read through up"),
            OUTSIDE_SECRET,
            "the directory link must resolve on the host",
        );
        assert_eq!(
            std::fs::read(sandbox.join("f")).expect("read through f"),
            OUTSIDE_SECRET,
            "the file link must resolve on the host",
        );
        Self {
            root,
            sandbox,
            outside,
        }
    }

    /// Run the guest for `act` with the working tree preopened as `.`.
    #[allow(clippy::expect_used)] // test helper: an unassemblable guest IS the failure
    fn run(&self, act: GuestAct) -> Result<(), CliError> {
        let wasm = wat::parse_str(confinement_guest(act)).expect("assemble the guest");
        let module = self.root.join("guest.wasm");
        std::fs::write(&module, wasm).expect("write the guest module");
        ipe::wasi_run::run_wasi_module(
            &module,
            &ipe::wasi_run::WasiCtx::dev_ambient(),
            &self.sandbox,
            &[],
        )
    }

    /// Whether the working tree's `leak` holds the outside secret.
    fn leaked(&self) -> bool {
        std::fs::read(self.sandbox.join("leak")).is_ok_and(|bytes| bytes == OUTSIDE_SECRET)
    }
}

/// Assert `result` is the guest's refusal exit at its first call, no other outcome.
#[cfg(all(unix, feature = "wasi_run"))]
fn assert_refused_at_open(result: &Result<(), CliError>) {
    assert!(
        matches!(
            result,
            Err(CliError::WasiRunExited {
                code: REFUSED_AT_OPEN
            })
        ),
        "the preopen must refuse the first call (guest exit {REFUSED_AT_OPEN}); got {result:?}",
    );
}

/// A directory link opened with a trailing slash stays inside the preopen.
#[cfg(all(unix, feature = "wasi_run"))]
#[test]
fn preopen_confinement_dir_link_trailing_slash() {
    let fixture = ConfinementFixture::new("dir_slash");
    let result = fixture.run(GuestAct::OpenDirThenSecret { path: "up/" });
    assert!(
        !fixture.leaked(),
        "the outside secret reached the working tree"
    );
    assert_refused_at_open(&result);
}

/// A file link opened with a trailing slash stays inside the preopen.
#[cfg(all(unix, feature = "wasi_run"))]
#[test]
fn preopen_confinement_file_link_trailing_slash() {
    let fixture = ConfinementFixture::new("file_slash");
    let result = fixture.run(GuestAct::OpenFile { path: "f/" });
    assert!(
        !fixture.leaked(),
        "the outside secret reached the working tree"
    );
    assert_refused_at_open(&result);
}

/// A directory link renamed with a trailing slash never moves its target.
#[cfg(all(unix, feature = "wasi_run"))]
#[test]
fn preopen_confinement_rename_dir_link() {
    let fixture = ConfinementFixture::new("rename_slash");
    let result = fixture.run(GuestAct::Rename { path: "up/" });
    assert!(
        std::fs::read(fixture.outside.join("secret")).is_ok_and(|bytes| bytes == OUTSIDE_SECRET),
        "the outside directory must stay at its path with its secret",
    );
    assert!(
        !std::fs::symlink_metadata(fixture.sandbox.join("moved")).is_ok_and(|m| m.is_dir()),
        "the outside directory must not be moved into the working tree",
    );
    assert_refused_at_open(&result);
}

/// A directory link with no trailing slash is refused on every engine version.
///
/// The control: it proves the fixture and the oracle can observe a refusal, so
/// the trailing-slash cases are not vacuous.
#[cfg(all(unix, feature = "wasi_run"))]
#[test]
fn preopen_confinement_control_plain_link() {
    let fixture = ConfinementFixture::new("control");
    let result = fixture.run(GuestAct::OpenDirThenSecret { path: "up" });
    assert!(
        !fixture.leaked(),
        "the outside secret reached the working tree"
    );
    assert_refused_at_open(&result);
}

/// An in-tree directory opened with a trailing slash is read and leaked.
///
/// The positive control: the same guest the refusals run reaches its last
/// stage when the preopen allows the path, so a refusal at the first call is
/// the preopen's, never a guest that cannot open anything.
#[cfg(all(unix, feature = "wasi_run"))]
#[test]
fn preopen_confinement_control_inside_dir_is_read() {
    let fixture = ConfinementFixture::new("inside_dir");
    let result = fixture.run(GuestAct::OpenDirThenSecret { path: "inside/" });
    assert!(
        matches!(result, Err(CliError::WasiRunExited { code: LEAK_WRITTEN })),
        "the guest must open, read and write in-tree (exit {LEAK_WRITTEN}); got {result:?}",
    );
    assert!(fixture.leaked(), "the in-tree secret must reach `leak`");
}

/// An in-tree file opened by name is read and leaked: the file guest's control.
#[cfg(all(unix, feature = "wasi_run"))]
#[test]
fn preopen_confinement_control_inside_file_is_read() {
    let fixture = ConfinementFixture::new("inside_file");
    let result = fixture.run(GuestAct::OpenFile { path: "g" });
    assert!(
        matches!(result, Err(CliError::WasiRunExited { code: LEAK_WRITTEN })),
        "the guest must open, read and write in-tree (exit {LEAK_WRITTEN}); got {result:?}",
    );
    assert!(fixture.leaked(), "the in-tree secret must reach `leak`");
}

/// An in-tree directory renamed with a trailing slash moves: the rename control.
#[cfg(all(unix, feature = "wasi_run"))]
#[test]
fn preopen_confinement_control_inside_rename() {
    let fixture = ConfinementFixture::new("inside_rename");
    let result = fixture.run(GuestAct::Rename { path: "inside/" });
    assert!(
        matches!(result, Err(CliError::WasiRunExited { code: 13 })),
        "the guest must rename in-tree (exit 13); got {result:?}",
    );
    assert!(
        std::fs::symlink_metadata(fixture.sandbox.join("moved")).is_ok_and(|m| m.is_dir()),
        "the in-tree directory must move to `moved`",
    );
}
