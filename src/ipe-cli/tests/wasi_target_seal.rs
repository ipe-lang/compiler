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
use std::process::Command;

use ipe::{BuildOptions, CliError};

/// A fresh, pid-isolated scratch dir under the test tempdir (concurrent runs
/// never share a tree).
fn scratch(name: &str) -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Set only on a WASI seal test's re-exec of this binary, whose cargo
/// environment was fixed at spawn.
const SEAL_CHILD_MARKER: &str = "IPE_WASI_SEAL_CHILD";

/// Run `test` in a re-exec of this binary whose environment pins
/// `CARGO_TARGET_DIR` to `target_dir` and clears `RUSTFLAGS` and
/// `CARGO_ENCODED_RUSTFLAGS`; `true` means the caller IS that child and runs the
/// body, `false` means the parent, whose child has already passed.
///
/// The cargo `run_cli` spawns inherits this process's environment, and a global
/// `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS` outranks the emitter's own
/// `[target.<triple>]` config, so a pass proves the end-user seal only when
/// the build sees exactly the emitted config — set at spawn, never mutated
/// in-process. The child must actually run and pass `test`: a name matching
/// nothing is refused, never a vacuous green.
fn in_seal_child(test: &str, target_dir: &Path) -> bool {
    if ipe_env::var_os(SEAL_CHILD_MARKER).is_some() {
        return true;
    }
    let rerun = e2e_support::rerun_this_test_exact(test, |cmd| {
        cmd.arg("--nocapture")
            .env(SEAL_CHILD_MARKER, "1")
            .env("CARGO_TARGET_DIR", target_dir)
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS");
    });
    assert!(
        rerun.is_ok(),
        "{test}: the cargo-env re-exec did not pass: {rerun:?}"
    );
    false
}

#[allow(clippy::expect_used)] // test helper: a failed scratch-dir setup IS the failure
fn write_entry(dir: &Path, source: &str) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir scratch");
    let entry = dir.join("Main.ipe");
    std::fs::write(&entry, source).expect("write entry");
    entry
}

fn wasi_options() -> BuildOptions {
    BuildOptions {
        target: ipe_ir::Target::WasmWasi,
        ..BuildOptions::default()
    }
}

/// Emit `source` for the co-located WASI target into `out`.
#[allow(clippy::expect_used)] // test helper: an unresolvable runtime IS the failure
fn emit_wasi(entry: &Path, out: &Path) -> Result<(), CliError> {
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_with_options(entry, out, &runtime, wasi_options())
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
fn wasi_direct_floor_program_cargo_builds_for_wasip1() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let dir = scratch("wasi_seal_floor");
    let entry = write_entry(&dir.join("srcdir"), DIRECT_FLOOR_SOURCE);
    let out = dir.join("out");

    // ipe accepts the sealed-floor program for the WASI target and emits it.
    emit_wasi(&entry, &out).expect("sealed-floor Direct program must ipe-accept for WASI");

    // Forward CI's warm shared target when present so the emitted crate's deps
    // reuse compiled artifacts; else isolate a per-slot target.
    let target_dir = e2e_support::child_shared_target_from_env()
        .map_or_else(|| out.join("target"), PathBuf::from);
    let mut cargo = Command::new("cargo");
    cargo
        .arg("build")
        .args(["--target", "wasm32-wasip1"])
        .current_dir(&out)
        .env("CARGO_TARGET_DIR", &target_dir)
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
    if e2e_support::child_shared_target_from_env().is_none() {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
}

/// The refusal: a `Direct` program reaching a non-viable family (`Ipe.Http`) is
/// turned away at `ipe` time with a typed diagnostic — fail-closed, no emit, so
/// the unbuildable shape never reaches the wasip1 `cargo build`. Runs always.
#[test]
fn wasi_http_shape_is_refused_fail_closed() {
    let dir = scratch("wasi_seal_http_refusal");
    let entry = write_entry(&dir.join("srcdir"), HTTP_SHAPE_SOURCE);
    let out = dir.join("out");

    let err = emit_wasi(&entry, &out)
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
fn ipe_build_target_wasi_user_path_cargo_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let dir = scratch("wasi_seal_user_path");
    let entry = write_entry(&dir.join("srcdir"), DIRECT_FLOOR_SOURCE);
    let out = dir.join("out");

    // Forward CI's warm shared target so the emitted crate's deps reuse
    // compiled artifacts; else isolate a per-slot target. The wasip1 link is
    // governed by the emitter's own `.cargo/config.toml` (see `in_seal_child`).
    let target_dir = e2e_support::child_shared_target_from_env()
        .map_or_else(|| out.join("target"), PathBuf::from);
    if in_seal_child("ipe_build_target_wasi_user_path_cargo_builds", &target_dir) {
        let args = vec![
            "dev".to_owned(),
            "build".to_owned(),
            entry.to_string_lossy().into_owned(),
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
    } else if e2e_support::child_shared_target_from_env().is_none() {
        let _ = std::fs::remove_dir_all(&target_dir);
    }
}

/// The user-path refusal: `ipe dev build --target wasi` on a non-WASI-viable shape
/// (a `Web` TEA app) is refused fail-closed with a typed diagnostic at
/// delivery-resolve time — never a permissive default, never an emit. Runs
/// unconditionally (no cargo): the standing check the selector fails closed.
#[test]
fn ipe_build_target_wasi_refuses_non_viable_shape_fail_closed() {
    let dir = scratch("wasi_seal_user_refusal");
    let entry = write_entry(&dir.join("srcdir"), WEB_TEA_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "build".to_owned(),
        entry.to_string_lossy().into_owned(),
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
fn ipe_run_target_wasi_executes_under_wasmtime() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let dir = scratch("wasi_run_exec");
    let entry = write_entry(&dir.join("srcdir"), DIRECT_FLOOR_SOURCE);
    let out = dir.join("out");

    let target_dir = e2e_support::child_shared_target_from_env()
        .map_or_else(|| out.join("target"), PathBuf::from);
    if in_seal_child("ipe_run_target_wasi_executes_under_wasmtime", &target_dir) {
        let args = vec![
            "dev".to_owned(),
            "run".to_owned(),
            entry.to_string_lossy().into_owned(),
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
    } else if e2e_support::child_shared_target_from_env().is_none() {
        let _ = std::fs::remove_dir_all(&target_dir);
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
    let entry = write_entry(&dir.join("srcdir"), WEB_TEA_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "run".to_owned(),
        entry.to_string_lossy().into_owned(),
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
    let entry = write_entry(&dir.join("srcdir"), SERVER_SHAPE_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "build".to_owned(),
        entry.to_string_lossy().into_owned(),
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
    let entry = write_entry(&dir.join("srcdir"), SERVER_SHAPE_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "run".to_owned(),
        entry.to_string_lossy().into_owned(),
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
    let entry = write_entry(&dir.join("srcdir"), DIRECT_FLOOR_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "run".to_owned(),
        entry.to_string_lossy().into_owned(),
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
    let entry = write_entry(&dir.join("srcdir"), SERVER_SHAPE_SOURCE);
    let out = dir.join("out");

    let args = vec![
        "dev".to_owned(),
        "run".to_owned(),
        entry.to_string_lossy().into_owned(),
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
