//! End-to-end tests for `Ipe.Terminal` `Tui.tea` — `Cells.column`,
//! `Cells.el`, `Cells.text`, and `String.fromInt`.
//!
//! Non-E2E tests (no `IPE_E2E` required):
//! - `tui_onkey_record_typechecks` — ipe-level regression for the
//!   `Tui.Sub.onKey : (KeyEvent -> msg) -> Sub msg` record scheme (T0001);
//!   verifies a single-argument record-typed key handler is accepted and that
//!   the emitter generates the bridging wrapper closure.
//!
//! E2E tests (gated on `IPE_E2E=1`):
//! - `tui_counter_build_only` — full ipe + cargo build with `Tui.tea`
//!   and a `KeyEvent -> Msg` handler (a `String -> String -> Msg` curried shape
//!   is not valid under the scheme).
//!
//! ## Architecture
//!
//! 1. A minimal Ipe.Terminal counter program is written to a temp dir.
//! 2. `ipe::build` compiles it (parse → canon → types → lower → emit Rust).
//! 3. `e2e_support::build_rust_binary` runs `cargo build` on the emitted project —
//!    the shared Cargo target lets crossterm/tokio compile once and be reused.
//!
//! The binary is NOT spawned: `tui_app_ui` requires a real TTY
//! (`TuiGuard::enter_mouse()` opens the alternate screen with raw mode), which
//! is not available in a CI environment.  A successful `cargo build` is the
//! proof that the full pipeline works:
//!
//! ```text
//! Tui.tea cfg → constrain → lower → emit_tui_call →
//!     ipe_runtime::tui::tui_app_ui(init, update, view, subs)
//! Sub.onKey handler → emit_tea_call → tui_sub_on_key(|kind, value| …)
//! ```
//!
//! The headless render assertion — does `view` produce a frame containing `0`?
//! — is covered by the runtime-level test in `runtime/src/lib.rs` (gated by
//! `--features tui`), which uses `tui::layout::element_to_cells` directly
//! without a TTY.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test tui_e2e
//! ```

/// A minimal `Tui.tea` counter exercising the `Tui.tea` scheme.
///
/// Key input is a subscription: `subscriptions` returns `Sub.onKey onKey`, and
/// `onKey` is a SINGLE-argument record handler — `KeyEvent -> Msg`.  The
/// emitter binds the handler and generates the bridging closure:
///
/// ```text
/// move |kind: String, value: String| __ipe_on_key(RecKindValue { kind, value })
/// ```
///
/// The curried `String -> String -> Msg` shape is not valid under the
/// scheme; it would unify `var(1)` (the msg type variable) with
/// `String -> Msg` which conflicts with its use in `update`/`subscriptions`.
///
/// Note: `view` returns `Screen Msg` (the Tui-only structured view type, NOT
/// wrapped in `Ui.layout` → `Html Msg` like Ipe.Web).  The Tui runtime
/// unwraps the `CellsView` and renders its Element tree directly to ANSI
/// cells; there is no HTML step.
const IPE_TUI_COUNTER: &str = r"module Main exposing (main)

import Ipe.Tea.Tui as Tui
import Ipe.Ui.Cells as Cells
import Ipe.Ui.Cells exposing (Screen)
import Ipe.Tea.Terminal.Cmd
import Ipe.String
import Ipe.Tea.Tui.Sub

type alias KeyEvent = { kind : String, value : String }

type Msg = Increment | Decrement | NoOp

type alias Model = { count : Int }

init : () -> ( Model, Cmd Msg )
init _unit =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )
        Decrement ->
            ( { model | count = model.count - 1 }, Cmd.none )
        NoOp ->
            ( model, Cmd.none )

view : Model -> Screen Msg
view model =
    Cells.column []
        [ Cells.el [] (Cells.text (String.fromInt model.count)) ]

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.onKey onKey

onKey : KeyEvent -> Msg
onKey _ =
    NoOp

main =
    Tui.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        }
";

/// Shared error type for E2E helpers.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Compile a Ipê program string, build the emitted Rust project, and return
/// the path to the compiled binary.
fn compile_and_build(test_name: &str, ipe_source: &str) -> Result<std::path::PathBuf, BoxError> {
    let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tui_e2e_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).map_err(|e| -> BoxError {
        format!("{test_name}: cannot create ipe source dir: {e}").into()
    })?;

    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, ipe_source)
        .map_err(|e| -> BoxError { format!("{test_name}: cannot write Main.ipe: {e}").into() })?;

    let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("tui_e2e_{test_name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);

    let runtime = e2e_support::require_runtime().into_path_buf();

    ipe::build(&entry, &out_dir, &runtime)
        .map_err(|e| -> BoxError { format!("{test_name}: ipe dev build failed: {e}").into() })?;

    let exe = e2e_support::build_rust_binary(test_name, &out_dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cargo build failed: {e}").into() })?;

    Ok(std::path::PathBuf::from(exe))
}

/// **Regression for T0001**: `Tui.Sub.onKey` accepts a record-typed key handler.
///
/// The handler is `onKey : KeyEvent -> Msg` where `KeyEvent = { kind : String,
/// value : String }` (a SINGLE-argument record handler).
/// The scheme PINS the key-event argument to the closed record
/// `{ kind : String, value : String }`, so a handler of any other argument
/// type fails at compile time (same sanctioned tightening as the Model / Msg
/// gates). The emitter generates a bridging wrapper:
///
/// ```text
/// move |kind: String, value: String| __ipe_on_key(RecKindValue { kind, value })
/// ```
///
/// What this test proves and what it does NOT: it typechecks the program
/// (`ipe dev build` accepts the record-alias `onKey`, no IPE-T0001) and asserts the
/// emitter produces the exact record-bridge wrapper — a `|kind, value|` closure
/// that constructs `RecKindValue { kind, value }` from BOTH parameters in ONE
/// expression, so both key fields provably flow from the runtime's
/// `Fn(String, String)` call site into the record and on into the record-typed
/// handler. It does NOT run the emitted binary (a `Tui.tea` needs a real TTY;
/// the sibling `tui_e2e::tui_app_vendored` build-only test carries the
/// `cargo build` seal for the same wrapper, and the runtime `tui` module tests
/// exercise the dispatch call). This test runs WITHOUT `IPE_E2E` (ipe-level
/// only — no cargo build), so it is always live in CI.
#[test]
fn tui_onkey_record_typechecks() {
    // ── helper: write Ipê source to a temp file, run ipe::build, check ok ──
    fn compile_ok(label: &str, source: &str) -> String {
        let ipe_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("tui_onkey_{label}_ipe"));
        let _ = std::fs::remove_dir_all(&ipe_dir);
        let created = std::fs::create_dir_all(&ipe_dir);
        assert!(
            created.is_ok(),
            "{label}: cannot create temp dir: {created:?}"
        );

        let entry = ipe_dir.join("Main.ipe");
        let wrote = std::fs::write(&entry, source);
        assert!(wrote.is_ok(), "{label}: cannot write Main.ipe: {wrote:?}");

        let out_dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("tui_onkey_{label}_emitted"));
        let _ = std::fs::remove_dir_all(&out_dir);

        let runtime = e2e_support::require_runtime().into_path_buf();

        let built = ipe::build(&entry, &out_dir, &runtime);
        assert!(
            built.is_ok(),
            "{label}: ipe dev build failed (T0001 regression?): {:?}",
            built.err()
        );

        // Return the WHOLE emitted Ipê-side tree (main.rs + ipe_mods/*.rs) for
        // structural assertions: a layout builder is compiled-source Ipê now, so a
        // home may lower into `src/ipe_mods/*.rs`.
        let src = out_dir.join("src");
        let mut combined = std::fs::read_to_string(src.join("main.rs")).unwrap_or_default();
        if let Ok(entries) = std::fs::read_dir(src.join("ipe_mods")) {
            let mut files: Vec<std::path::PathBuf> = entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "rs"))
                .collect();
            files.sort();
            for path in files {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    combined.push('\n');
                    combined.push_str(&text);
                }
            }
        }
        combined
    }

    // ── Tui.tea subscribing with `Sub.onKey : (KeyEvent -> Msg) -> Sub Msg` ──
    let app_rs = compile_ok("terminal_app_screen", IPE_TUI_COUNTER);
    assert!(
        !app_rs.is_empty(),
        "the accepted terminal app must emit Rust"
    );

    // The emitter must produce the bridging wrapper as ONE expression: the
    // `|kind: String, value: String|` closure whose body constructs
    // `RecKindValue { kind, value }` from BOTH closure parameters. Two separate
    // `contains` checks could each match unrelated emitted code; requiring the
    // closure header immediately followed (modulo whitespace) by a call passing
    // the `RecKindValue { kind, value }` record proves both key fields flow from
    // the runtime's `Fn(String, String)` call site through the record and into
    // the record-typed handler — the round-trip the bridge exists to make.
    let normalized: String = app_rs.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        normalized.contains("|kind: String, value: String|"),
        "Tui.tea emitted Rust must contain the `|kind: String, value: String|` \
         wrapper closure (onKey record bridge); got:\n{app_rs}"
    );
    // The closure body must build the closed record from both parameters and hand
    // it to the handler — not merely mention `RecKindValue` somewhere.
    assert!(
        normalized.contains("(RecKindValue { kind, value })"),
        "Tui.tea emitted Rust must pass `RecKindValue {{ kind, value }}` (both key \
         fields, from the closure parameters) into the record-typed onKey handler; \
         got:\n{app_rs}"
    );
    let closure_at = normalized
        .find("|kind: String, value: String|")
        .unwrap_or(usize::MAX);
    let record_at = normalized
        .find("(RecKindValue { kind, value })")
        .unwrap_or(0);
    assert!(
        closure_at != usize::MAX && record_at > closure_at,
        "the `RecKindValue {{ kind, value }}` construction must appear inside the \
         key-event wrapper closure body (after its `|kind, value|` header), proving \
         the bridge wires both fields through in one expression; got:\n{app_rs}"
    );
}

/// Compile-only: the Ipe.Terminal counter emits a Cargo project with the `"tui"`
/// feature in the default feature list, `crossterm` and `unicode-width` deps,
/// and `ipe_runtime::tui::tui_app_ui` in the `main` function.
///
/// This is a BUILD-ONLY test — it does not spawn the binary (Tui requires a
/// real TTY).  A successful `cargo build` is the assertion:
///
/// * constrain: `Tui.tea` correctly types the closed 4-field cfg, and
///   `Sub.onKey` a record-typed `onKey : KeyEvent -> Msg` handler.
/// * lower: the cfg record literal bypasses IPE-L0107 (same exemption
///   as `Web.tea`).
/// * emit: `emit_tui_call` delegates to `tui_app_ui(…)` with the four
///   handler arguments, and `Sub.onKey` emits `tui_sub_on_key` with the
///   `|kind, value|` wrapper.
/// * manifest: `tui_cargo_toml` adds `"tui"` to default features,
///   `crossterm` + `unicode-width` deps, and `"sync"` to tokio.
///
/// # Errors
///
/// Propagates any pipeline or Cargo build failure as a test error.
#[test]
fn tui_counter_build_only() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    // compile_and_build already does ipe + cargo build; success is the proof.
    let _exe = compile_and_build("tui_build_only", IPE_TUI_COUNTER)?;
    Ok(())
}
