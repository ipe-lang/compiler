//! `--target wasm` build gates (spec: `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md`).
//!
//! Layer 1 — a server-only kernel named in a wasm build fails at compile time
//! with IPE-N0029 (`NameError::ServerOnlyKernelForWasm`), never at cargo
//! time and never as a runtime stub. Layer 3 — the emitted wasm project's
//! manifest is the closed cdylib template: no tokio/axum/sqlx/reqwest, no
//! `server`/`db`/`live` feature. The full browser proof (cargo build to
//! `.wasm` + a Playwright interaction) lives in the examples flow
//! (`examples/wasm/counter`).

use std::path::{Path, PathBuf};

use ipe::{BuildOptions, CliError};
use ipe_runtime_rust::encoding::MountBase;

fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Like [`scratch`] but appends the process id so concurrent or back-to-back
/// test invocations never share the same output tree.
///
/// Used for tests that spawn an external process (e.g. `cargo check`) that
/// reads from the scratch directory: without isolation a previous invocation's
/// subprocess can still be reading files while a new `scratch` call wipes and
/// rewrites the directory, producing a window where `mod.rs` declares modules
/// whose source files do not yet exist.
fn scratch_isolated(name: &str) -> PathBuf {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[allow(clippy::expect_used)] // test helper: a failed scratch-dir setup IS the failure
fn write_entry(dir: &Path, source: &str) -> PathBuf {
    std::fs::create_dir_all(dir).expect("mkdir scratch");
    let entry = dir.join("Main.ipe");
    std::fs::write(&entry, source).expect("write entry");
    entry
}

fn wasm_options() -> BuildOptions {
    BuildOptions {
        target: ipe_ir::Target::WasmClient,
        ..BuildOptions::default()
    }
}

#[allow(clippy::expect_used)] // test helper: an unresolvable runtime IS the failure
fn build_wasm(entry: &Path, out: &Path) -> Result<(), CliError> {
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_with_options(entry, out, &runtime, wasm_options())
}

/// A pure `Ipe.Ui` TEA app: the smallest program the wasm target accepts.
const PURE_UI_APP: &str = "module Main exposing (main)\n\
         import Ipe.String as String\n\
         import Ipe.Tea.Web exposing (tea)\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         \n\
         type Page = CounterPage\n\
         type Msg = Increment\n\
         type alias Model = { count : Int }\n\
         \n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( { count = 0 }, Cmd.none )\n\
         \n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update msg model =\n\
         \x20   case msg of\n\
         \x20       Increment -> ( { model | count = model.count + 1 }, Cmd.none )\n\
         \n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.none\n\
         \n\
         view : Model -> Element Msg\n\
         view model =\n\
         \x20   Ui.button [] { onPress = Just Increment, label = Ui.text (String.fromInt model.count) }\n\
         \n\
         main =\n\
         \x20   tea\n\
         \x20       { init = init\n\
         \x20       , update = update\n\
         \x20       , view = view\n\
         \x20       , subscriptions = subscriptions\n\
         \x20       , routes = []\n\
         \x20       , notFound = CounterPage\n\
         \x20       }\n";

/// Under a `/app` mount base the shell loads `boot.js`, the glue and the
/// module from absolute URLs under the base, so a deep-link reload still boots;
/// no page-relative `./` URL remains.
#[test]
fn wasm_shell_urls_derive_from_base() -> Result<(), Box<dyn std::error::Error>> {
    let out = build_shell("wasm_shell_app_base", "/app")?;
    let index = std::fs::read_to_string(out.join("www/index.html"))?;
    let boot = std::fs::read_to_string(out.join("www/boot.js"))?;
    assert!(index.contains("src=\"/app/boot.js\""), "{index}");
    assert!(
        boot.contains("import init from \"/app/pkg/ipe_app.js\";"),
        "{boot}"
    );
    assert!(
        boot.contains("module_or_path: \"/app/pkg/ipe_app_bg.wasm\""),
        "{boot}"
    );
    assert!(!index.contains("./"), "{index}");
    assert!(!boot.contains("./"), "{boot}");
    Ok(())
}

/// The root mount base keeps the shell URLs at `/`.
#[test]
fn wasm_shell_urls_sit_at_the_root() -> Result<(), Box<dyn std::error::Error>> {
    let out = build_shell("wasm_shell_root_base", "")?;
    let index = std::fs::read_to_string(out.join("www/index.html"))?;
    let boot = std::fs::read_to_string(out.join("www/boot.js"))?;
    assert!(index.contains("src=\"/boot.js\""), "{index}");
    assert!(
        boot.contains("import init from \"/pkg/ipe_app.js\";"),
        "{boot}"
    );
    Ok(())
}

/// Build [`PURE_UI_APP`] for the wasm target under the mount base `base`
/// (`""` is the root) and return the output directory.
fn build_shell(name: &str, base: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = scratch(name);
    let src = dir.join("srcdir");
    std::fs::create_dir_all(&src)?;
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, PURE_UI_APP)?;
    let out = dir.join("out");
    let mount_base = MountBase::parse(base).map_err(|r| r.to_string())?;
    let runtime = e2e_support::require_runtime().into_path_buf();
    let options = BuildOptions {
        mount_base,
        ..wasm_options()
    };
    ipe::build_with_options(&entry, &out, &runtime, options).map_err(|e| format!("{e:?}"))?;
    Ok(out)
}

/// A pure `Ipe.Ui` TEA app compiles under the wasm target, and the emitted
/// project is the browser cdylib shape (Layer 3: dependency floor).
#[test]
fn pure_ui_app_emits_wasm_project() {
    let dir = scratch("wasm_gate_green");
    let entry = write_entry(&dir.join("srcdir"), PURE_UI_APP);
    let out = dir.join("out");
    build_wasm(&entry, &out).expect("pure Ipe.Ui app must build under --target wasm");

    let manifest = std::fs::read_to_string(out.join("Cargo.toml")).expect("emitted manifest");
    assert!(manifest.contains("crate-type = [\"cdylib\"]"), "{manifest}");
    assert!(manifest.contains("wasm-bindgen"), "{manifest}");
    for absent in ["tokio", "axum", "sqlx", "reqwest", "rustls"] {
        assert!(
            !manifest.contains(absent),
            "wasm manifest must not link `{absent}`:\n{manifest}"
        );
    }
    let mod_rs =
        std::fs::read_to_string(out.join("src/ipe_runtime/mod.rs")).expect("emitted mod.rs");
    // `task` IS present as of M4 (the module's pure future-combinator half —
    // `Task.map`/`andThen`/… — has no tokio dependency; the tokio-bound half
    // stays `cfg(not(target_arch = "wasm32"))` INSIDE the file — see
    // `task.rs`'s module doc). `live`/`db`/`server` stay genuinely absent —
    // no substitute, no module declared.
    for absent in ["pub mod live;", "pub mod db;", "pub mod server;"] {
        assert!(
            !mod_rs.contains(absent),
            "wasm runtime module set must not declare `{absent}`:\n{mod_rs}"
        );
    }
    assert!(mod_rs.contains("pub mod wasm;"), "{mod_rs}");
    assert!(mod_rs.contains("pub mod task;"), "{mod_rs}");
    // The pure routing module is present (shared with the server; no tokio/axum).
    assert!(mod_rs.contains("pub mod route"), "{mod_rs}");
    // The static browser shell is emitted beside the crate.
    assert!(out.join("www/index.html").is_file());
    assert!(out.join("www/boot.js").is_file());
    let index = std::fs::read_to_string(out.join("www/index.html")).expect("shell");
    assert!(index.contains("wasm-unsafe-eval"), "{index}");
    assert!(
        !index.contains(" 'unsafe-eval'"),
        "no bare JS unsafe-eval token:\n{index}"
    );
}

/// The `ipe_main` return type under `--target wasm` renders as `IpeTask<()>`,
/// not `ipe_runtime::tea::WebApp`.
///
/// `ipe_runtime::tea::WebApp` is a native-only type absent from the
/// `wasm32-unknown-unknown` target; the emitted `ipe_main()` must return
/// `IpeTask<()>` so `ipe_runtime::wasm::run_start(ipe_main())` type-checks and
/// `cargo build --target wasm32-unknown-unknown` succeeds. The body correctly
/// calls `ipe_runtime::wasm::wasm_app`; only the declared return type was wrong
/// before the fix in `emit_types.rs`. This test guards that exact regression.
#[test]
fn wasm_web_app_ipe_main_return_type_is_ipe_task() {
    let dir = scratch("wasm_gate_ipe_main_ret");
    let entry = write_entry(
        &dir.join("srcdir"),
        "module Main exposing (main)\n\
         import Ipe.String as String\n\
         import Ipe.Tea.Web exposing (tea)\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         \n\
         type Msg = Increment\n\
         type alias Model = { count : Int }\n\
         \n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( { count = 0 }, Cmd.none )\n\
         \n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update msg model =\n\
         \x20   case msg of\n\
         \x20       Increment -> ( { model | count = model.count + 1 }, Cmd.none )\n\
         \n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.none\n\
         \n\
         view : Model -> Element Msg\n\
         view model =\n\
         \x20   Ui.button [] { onPress = Just Increment, label = Ui.text (String.fromInt model.count) }\n\
         \n\
         main =\n\
         \x20   tea\n\
         \x20       { init = init\n\
         \x20       , update = update\n\
         \x20       , view = view\n\
         \x20       , subscriptions = subscriptions\n\
         \x20       , routes = []\n\
         \x20       , notFound = Increment\n\
         \x20       }\n",
    );
    let out = dir.join("out");
    build_wasm(&entry, &out).expect("Web.tea must emit under --target wasm");

    let main_rs = std::fs::read_to_string(out.join("src/main.rs")).expect("emitted main.rs");

    // The fix: `WebApp` under `WasmClient` renders as `IpeTask<()>`.
    // A regression restores `ipe_runtime::tea::WebApp`, which does not exist
    // on `wasm32-unknown-unknown` and causes E0425 at cargo time.
    assert!(
        main_rs.contains("IpeTask"),
        "`ipe_main` return type must contain `IpeTask` on the wasm target:\n{main_rs}"
    );
    assert!(
        !main_rs.contains("ipe_runtime::tea::WebApp"),
        "`ipe_main` must NOT render the native-only `ipe_runtime::tea::WebApp` \
         on the wasm target (causes E0425 on wasm32):\n{main_rs}"
    );
    // The body must call the wasm entry-point, not the native web_app.
    assert!(
        main_rs.contains("ipe_runtime::wasm::wasm_app"),
        "`ipe_main` body must call `ipe_runtime::wasm::wasm_app` on the wasm target:\n{main_rs}"
    );
}

/// A routed `Web.tea` (Model has a `page` field, `routes` non-empty) emits
/// `wasm_app_routed` under `--target wasm`. The emitted manifest must have the
/// same closed cdylib shape as the non-routed app, and the emitted `main.rs`
/// must call `wasm_app_routed`, not `wasm_app`.
#[test]
fn routed_web_app_emits_wasm_app_routed() {
    let dir = scratch("wasm_gate_routed");
    let entry = write_entry(
        &dir.join("srcdir"),
        "module Main exposing (main)\n\
         import Ipe.String as String\n\
         import Ipe.Tea.Web exposing (tea, route)\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         \n\
         type Page = Home | About\n\
         type Msg = NoOp\n\
         type alias Model = { page : Page, count : Int }\n\
         \n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( { page = Home, count = 0 }, Cmd.none )\n\
         \n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update msg model =\n\
         \x20   case msg of\n\
         \x20       NoOp -> ( model, Cmd.none )\n\
         \n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.none\n\
         \n\
         view : Model -> Element Msg\n\
         view _model = Ui.text \"hello\"\n\
         \n\
         main =\n\
         \x20   tea\n\
         \x20       { init = init\n\
         \x20       , update = update\n\
         \x20       , view = view\n\
         \x20       , subscriptions = subscriptions\n\
         \x20       , routes = [ route \"/\" Home, route \"/about\" About ]\n\
         \x20       , notFound = Home\n\
         \x20       }\n",
    );
    let out = dir.join("out");
    build_wasm(&entry, &out).expect("routed Web.tea must build under --target wasm");

    let manifest = std::fs::read_to_string(out.join("Cargo.toml")).expect("emitted manifest");
    assert!(manifest.contains("crate-type = [\"cdylib\"]"), "{manifest}");
    assert!(manifest.contains("wasm-bindgen"), "{manifest}");
    for absent in ["tokio", "axum", "sqlx", "reqwest", "rustls"] {
        assert!(
            !manifest.contains(absent),
            "wasm manifest must not link `{absent}`:\n{manifest}"
        );
    }

    let main_rs = std::fs::read_to_string(out.join("src/main.rs")).expect("emitted main.rs");
    assert!(
        main_rs.contains("wasm_app_routed"),
        "a routed wasm app must call `wasm_app_routed`, got:\n{main_rs}"
    );
    assert!(
        !main_rs.contains("WasmRoutedApp"),
        "routed wasm app must not emit a WasmRoutedApp error:\n{main_rs}"
    );

    let mod_rs =
        std::fs::read_to_string(out.join("src/ipe_runtime/mod.rs")).expect("emitted mod.rs");
    assert!(
        mod_rs.contains("pub mod route"),
        "wasm runtime mod.rs must expose `route` for `Route::new`:\n{mod_rs}"
    );
}

/// A routed wasm app with `onNavigate` evaluates `update` once and shares it
/// between the runtime entry and the generated `set_page`.
#[test]
fn routed_web_app_with_on_navigate_emits_update_once() {
    let dir = scratch("wasm_gate_routed_on_navigate");
    let entry = write_entry(
        &dir.join("srcdir"),
        "module Main exposing (main)\n\
         import Ipe.String as String\n\
         import Ipe.Tea.Web exposing (tea, route)\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         \n\
         type Page = Home | About\n\
         type Msg = Navigate Page\n\
         type alias Model = { page : Page, count : Int }\n\
         \n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( { page = Home, count = 0 }, Cmd.none )\n\
         \n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update msg model =\n\
         \x20   case msg of\n\
         \x20       Navigate page -> ( { model | page = page }, Cmd.none )\n\
         \n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.none\n\
         \n\
         view : Model -> Element Msg\n\
         view _model = Ui.text \"hello\"\n\
         \n\
         main =\n\
         \x20   tea\n\
         \x20       { init = init\n\
         \x20       , update = update\n\
         \x20       , view = view\n\
         \x20       , subscriptions = subscriptions\n\
         \x20       , routes = [ route \"/\" Home, route \"/about\" About ]\n\
         \x20       , notFound = Home\n\
         \x20       , onNavigate = Navigate\n\
         \x20       }\n",
    );
    let out = dir.join("out");
    build_wasm(&entry, &out)
        .expect("routed Web.tea with onNavigate must build under --target wasm");

    let main_rs = std::fs::read_to_string(out.join("src/main.rs")).expect("emitted main.rs");
    assert_eq!(
        main_rs
            .matches("let __update_shared = ::std::sync::Arc::new(")
            .count(),
        1,
        "onNavigate present ⇒ `update` is emitted once and shared, got:\n{main_rs}"
    );
}

/// Naming a server-only kernel under `--target wasm` is a compile error
/// (IPE-N0029) — the kernel has no denotation, so no secret can gain a
/// client consumer and no cargo-time failure can occur (THE SEAL).
#[test]
#[allow(clippy::panic)] // test assertion: a non-pipeline error variant IS the failure
fn server_only_kernel_fails_at_compile_time() {
    let dir = scratch("wasm_gate_red");
    let entry = write_entry(
        &dir.join("srcdir"),
        "module Main exposing (main)\n\
         import Ipe.File as File\n\
         import Ipe.Path as Path\n\
         import Ipe.Task as Task\n\
         \n\
         main =\n\
         \x20   case Path.fromString \"/etc/passwd\" of\n\
         \x20       Ok p -> File.readFile p\n\
         \x20       Err e -> Task.fail e\n",
    );
    let out = dir.join("out");
    let err = build_wasm(&entry, &out).expect_err("File.readFile must be denied under wasm");
    let CliError::Pipeline { diag, .. } = err else {
        panic!("expected a pipeline diagnostic, got: {err:?}");
    };
    let rendered = format!("{diag:?}");
    assert!(
        rendered.contains("ServerOnlyKernelForWasm"),
        "expected IPE-N0029 ServerOnlyKernelForWasm, got: {rendered}"
    );
}

/// `Ipe.Process` is a server-only subprocess capability: naming `Process.run`
/// under `--target wasm` is a compile error (IPE-N0029), so no browser bundle
/// can ever spawn a child process and no cargo-time failure can occur (THE
/// SEAL). Sibling of `server_only_kernel_fails_at_compile_time` for the new
/// subprocess axis.
#[test]
#[allow(clippy::panic)] // test assertion: a non-pipeline error variant IS the failure
fn process_run_is_denied_under_wasm() {
    let dir = scratch("wasm_gate_process_red");
    let entry = write_entry(
        &dir.join("srcdir"),
        "module Main exposing (main)\n\
         import Ipe.Process as Process\n\
         import Ipe.Task as Task\n\
         \n\
         main =\n\
         \x20   Process.run \"ls\" []\n",
    );
    let out = dir.join("out");
    let err = build_wasm(&entry, &out).expect_err("Process.run must be denied under wasm");
    let CliError::Pipeline { diag, .. } = err else {
        panic!("expected a pipeline diagnostic, got: {err:?}");
    };
    let rendered = format!("{diag:?}");
    assert!(
        rendered.contains("ServerOnlyKernelForWasm"),
        "expected IPE-N0029 ServerOnlyKernelForWasm, got: {rendered}"
    );
}

/// The same subprocess program builds cleanly for the native target — the gate
/// is target-keyed, not a global restriction.
#[test]
fn process_run_still_builds_natively() {
    let dir = scratch("wasm_gate_process_native_ok");
    let entry = write_entry(
        &dir.join("srcdir"),
        "module Main exposing (main)\n\
         import Ipe.Process as Process\n\
         import Ipe.Task as Task\n\
         \n\
         main =\n\
         \x20   Process.run \"ls\" []\n",
    );
    let out = dir.join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_with_options(&entry, &out, &runtime, BuildOptions::default())
        .expect("native build of Process.run must stay green");
}

/// M5 Layer 2 (IPE-N0030): a client entry that transitively imports a
/// server-classified module (never names the server kernel itself) fails
/// with the EXACT import chain — `Main(client) -> View(shared) ->
/// Data(server: imports File.readFile)` — not just "not allowed". End-to-end
/// through the real multi-module build pipeline (not just the
/// `ipe_canon::module_classify` unit tests).
#[test]
#[allow(clippy::panic)] // test assertion: a non-pipeline error variant IS the failure
fn transitive_server_import_fails_naming_the_exact_chain() {
    let dir = scratch("wasm_gate_transitive_chain");
    let srcdir = dir.join("srcdir");
    std::fs::create_dir_all(&srcdir).expect("mkdir scratch");
    std::fs::write(
        srcdir.join("Data.ipe"),
        "module Data exposing (load)\n\
         import Ipe.File as File\n\
         import Ipe.Path as Path\n\
         import Ipe.Task as Task\n\
         \n\
         load : Task Error String\n\
         load =\n\
         \x20   case Path.fromString \"/etc/passwd\" of\n\
         \x20       Ok p -> File.readFile p\n\
         \x20       Err e -> Task.fail e\n",
    )
    .expect("write Data.ipe");
    std::fs::write(
        srcdir.join("View.ipe"),
        "module View exposing (label)\n\
         import Data exposing (load)\n\
         import Ipe.Task as Task\n\
         \n\
         label : String\n\
         label = \"view\"\n\
         \n\
         forceLink : Task Error String\n\
         forceLink = load\n",
    )
    .expect("write View.ipe");
    let entry = write_entry(
        &srcdir,
        "module Main exposing (main)\n\
         import Ipe.Io as Io\n\
         import View exposing (label)\n\
         \n\
         main =\n\
         \x20   Io.println label\n",
    );
    let out = dir.join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let err = ipe::build_loose_file_with_options(&entry, &out, &runtime, wasm_options())
        .expect_err("View -> Data's File.readFile must be denied transitively");
    let CliError::Pipeline { diag, .. } = err else {
        panic!("expected a pipeline diagnostic, got: {err:?}");
    };
    let rendered = format!("{diag:?}");
    assert!(
        rendered.contains("ServerModuleReachableFromWasmClient"),
        "expected IPE-N0030 ServerModuleReachableFromWasmClient, got: {rendered}"
    );
    assert!(
        rendered.contains("Main(client)")
            && rendered.contains("View(shared)")
            && rendered.contains("Data(server: imports File.readFile)"),
        "expected the exact import chain naming Main -> View -> Data, got: {rendered}"
    );
}

/// THE HYDRATE SEAL (issue #224): the `[wasm] mode = "hydrate"` glue must name
/// the SAME Rust type the emitted `main_from_hydration_state` signature does, so
/// the emitted crate actually compiles for `wasm32-unknown-unknown`.
///
/// This COMPILE-CHECKS the emitted crate rather than string-matching the glue.
/// The regression it guards: the glue used to hardcode `crate::MainHydrationState`
/// on a naming convention the record-alias emitter never honours — the example's
/// `type alias HydrationState = { count : Int }` is emitted structurally as
/// `RecCount`, so the old glue referenced a nonexistent type (E0433) and the
/// crate did not build. The fix threads the renderer-resolved type name into the
/// glue; a reintroduced mismatch fails `cargo check` here.
///
/// Gated on `IPE_E2E=1` (needs a working cargo) AND the `wasm32-unknown-unknown`
/// target being installed; a missing target degrades to a clean skip, never a
/// false red.
#[test]
#[allow(clippy::expect_used)] // test setup: a failed emit/cargo-spawn IS the failure
fn hydrate_glue_type_name_matches_emitted_struct_and_compiles_for_wasm() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    // Skip cleanly when the wasm target is not installed (cargo check would
    // fail on a missing target — an environment gap, not a codegen defect).
    let target_installed = std::process::Command::new("rustc")
        .args(["--print", "target-list"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-unknown-unknown"));
    if !target_installed {
        return;
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    // Emit the REAL wasm-hydration example (single source of truth) with the
    // hydrate mode its `package.ipe` declares.
    let entry = e2e_support::manifest_dir!().join("../../examples/wasm/hydration/src/Main.ipe");
    let out = scratch_isolated("wasm_hydrate_seal").join("out");
    let options = BuildOptions {
        target: ipe_ir::Target::WasmClient,
        wasm_hydrate_mode: true,
        ..BuildOptions::default()
    };
    ipe::build_loose_file_with_options(&entry, &out, &runtime, options)
        .expect("wasm-hydration must emit under --target wasm mode=hydrate");

    // The emitted glue must name the structurally-emitted struct, not a
    // convention name the emitter never produces.
    let main_rs = std::fs::read_to_string(out.join("src/main.rs")).expect("emitted main.rs");
    assert!(
        !main_rs.contains("crate::MainHydrationState"),
        "the hydrate glue must NOT reference the nonexistent convention type \
         `MainHydrationState` (issue #224):\n{main_rs}"
    );
    assert!(
        main_rs.contains("pub fn hydrate(model_json: &str)"),
        "the hydrate export must be emitted:\n{main_rs}"
    );

    // THE SEAL: the emitted crate must actually compile for wasm. A glue/type
    // name mismatch is an E0433/E0425 here, turning ipe-exit-0 into a hard red.
    //
    // The external `cargo check` runs against a STABLE wasm target dir that
    // persists across the run, so the wasm dependency graph compiles once and
    // stays warm: no first-time registry fetch or cold dep compile happens under
    // shard load. Paired with this test's `wasm-external-cargo` serialization
    // group (`.config/nextest.toml`), only one wasm `cargo check` runs at a time,
    // so it never contends the global cargo registry/target lock with a
    // concurrent build. A throwaway per-invocation target would instead force a
    // cold compile every run, which under CI load was the transient failure a
    // retry used to mask.
    let wasm_target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wasm_hydrate_seal_target");
    let status = std::process::Command::new("cargo")
        .args(["check", "--target", "wasm32-unknown-unknown"])
        .current_dir(&out)
        .env("CARGO_TARGET_DIR", &wasm_target)
        .env("IPE_RUNTIME_DIR", &runtime)
        .status()
        .expect("spawn cargo check");
    assert!(
        status.success(),
        "the emitted wasm-hydration crate must `cargo check` for wasm32-unknown-unknown \
         (the hydrate glue and the emitted HydrationState struct must share ONE type name)"
    );
}

/// The same server-only program builds cleanly for the native target — the
/// gate is target-keyed, not a global restriction.
#[test]
fn server_only_kernel_still_builds_natively() {
    let dir = scratch("wasm_gate_native_ok");
    let entry = write_entry(
        &dir.join("srcdir"),
        "module Main exposing (main)\n\
         import Ipe.File as File\n\
         import Ipe.Path as Path\n\
         import Ipe.Task as Task\n\
         \n\
         main =\n\
         \x20   case Path.fromString \"/etc/passwd\" of\n\
         \x20       Ok p -> File.readFile p\n\
         \x20       Err e -> Task.fail e\n",
    );
    let out = dir.join("out");
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_with_options(&entry, &out, &runtime, BuildOptions::default())
        .expect("native build of the same program must stay green");
}
