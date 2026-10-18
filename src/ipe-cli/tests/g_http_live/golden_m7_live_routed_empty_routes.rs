//! Routed `Web.tea` with `routes = []` and a wrong `notFound` type must be
//! rejected by ipe with IPE-T0001.
//!
//! ## Background
//!
//! `WebRoute` is phantom-parametric (`WebRoute page`) so route CONSTRUCTORS
//! force `var(2)` (the page type) to match.  But with an EMPTY `routes = []`
//! list there is no constructor to witness `var(2)`, so `var(2)` would be
//! pinned only by `notFound` — any type would satisfy it.  Then `notFound = 5`
//! (Int) would type as ipe-Ok, and the emitted `set_page` closure (`__page:
//! Page, __model: Model`) would be rejected by cargo with E0308.
//!
//! A post-solve `RoutedWebCheck` closes the hole:
//! * If the settled Model type has a `page` field → routed app → unify
//!   `notFound`'s type with `Model.page`'s type → IPE-T0001 on mismatch.
//! * If Model has no `page` field → non-routed app → no check.
//!
//! ## Tests in this file
//!
//! * R1 (`int_notfound`): routed Model, `routes = []`, `notFound = 5` → IPE-T0001.
//! * R2 (`wrong_ctor_notfound`): routed Model, `routes = []`,
//!   `notFound = Increment` (Msg ctor, wrong ADT) → IPE-T0001.
//! * Positive control: well-typed routed app (let-bound routes, correct notFound)
//!   → ipe Ok (reuses the `live_let_bound_routes` fixture).
//! * R3 (`refused`): well-typed routed app, `routes = []` → IPE-L0159 (no page
//!   has a route).
//!
//! All tests are pure ipe-pipeline checks (parse → canon → types → lower →
//! emit). No cargo build or runtime binary required — they run without
//! `IPE_E2E=1`.

use std::path::PathBuf;

use ipe::CliError;

// ── Inline source strings for T4d/T4f/MIX and non-routed regression ──────────

/// T4d: non-empty routes, but `notFound` is the wrong ADT type (Msg not Page).
/// Part A's `WebRoute page` parametric fix pins `var(2)` via route ctors to
/// `Page`; `notFound = Increment` (Msg) then fails unification → IPE-T0001.
const T4D_NONEMPTY_ROUTES_WRONG_NOTFOUND: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub
type Page = CounterPage | AboutPage
type Msg = Increment
type alias Model = { page : Page, count : Int }
init _req = ( { page = CounterPage, count = 0 }, Cmd.none )
update msg model =
    case msg of
        Increment -> ( { model | count = model.count + 1 }, Cmd.none )
view model = Ui.text (String.fromInt model.count)
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [ Web.route "/" CounterPage, Web.route "/about" AboutPage ]
        , notFound = Increment
        }
"#;

/// T4f: non-empty routes, route ctor from wrong ADT (Increment from Msg, not Page).
/// The route ctor forces `var(2) = Msg`; `notFound = CounterPage` (Page) then
/// fails unification → IPE-T0001.
const T4F_WRONG_ROUTE_CTOR_CORRECT_NOTFOUND: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub
type Page = CounterPage | AboutPage
type Msg = Increment
type alias Model = { page : Page, count : Int }
init _req = ( { page = CounterPage, count = 0 }, Cmd.none )
update msg model =
    case msg of
        Increment -> ( { model | count = model.count + 1 }, Cmd.none )
view model = Ui.text (String.fromInt model.count)
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [ Web.route "/" Increment ]
        , notFound = CounterPage
        }
"#;

/// MIX: non-empty routes with mixed types — one correct route ctor, one wrong
/// route ctor. All route ctors share `var(2)`; the wrong ctor forces a mismatch.
const MIX_MIXED_ROUTE_CTORS: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub
type Page = CounterPage | AboutPage
type Msg = Increment
type alias Model = { page : Page, count : Int }
init _req = ( { page = CounterPage, count = 0 }, Cmd.none )
update msg model =
    case msg of
        Increment -> ( { model | count = model.count + 1 }, Cmd.none )
view model = Ui.text (String.fromInt model.count)
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [ Web.route "/" CounterPage, Web.route "/inc" Increment ]
        , notFound = CounterPage
        }
"#;

/// Non-routed regression: a plain Web.tea with Model = `{ count : Int }` (no
/// `page` field) and `notFound = Increment` (Msg).  Part B's hook MUST NOT fire
/// here — the Model has no `page` field, so we skip the check.
///
/// Type annotations are required to pass the lowerer (mirrors `LIVE_GOOD` in
/// `model_admissibility.rs`).
const NON_ROUTED_LIVE: &str = r"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub
type Msg = Increment
type alias Model = { count : Int }
init : WebReq -> ( Model, Cmd Msg )
init _req = ( { count = 0 }, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment -> ( { model | count = model.count + 1 }, Cmd.none )
view : Model -> Element Msg
view model = Ui.text (String.fromInt model.count)
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Increment
        }
";

/// `Web.tea` with a NON-EMPTY `routes` list but a Model with no `page` field.
/// A routed update against such a Model is a silent no-op, so this shape must
/// still compile on the non-routed path.
///
/// Shape mirrors `examples/24-tui-kitchen-sink` (single nullary route, no
/// `page` field in Model).
const NON_ROUTED_LIVE_WITH_NONEMPTY_ROUTES: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.String
import Ipe.Tea.Web.Sub
type Page = MainPage
type Msg = Increment
type alias Model = { count : Int }
init : WebReq -> ( Model, Cmd Msg )
init _req = ( { count = 0 }, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment -> ( { model | count = model.count + 1 }, Cmd.none )
view : Model -> Element Msg
view model = Ui.text (String.fromInt model.count)
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [ Web.route "/" MainPage ]
        , notFound = MainPage
        }
"#;

/// Compile `source` through the ipe pipeline (no cargo).
#[allow(clippy::expect_used)] // a failed scratch setup is the test failure
fn compile_src(test_name: &str, source: &str) -> Result<(), ipe::CliError> {
    let project = ipe::RootFixture::main(source).expect("the fixture project resolves");
    let out = crate::support::scratch_root().join(format!("live_routed_empty_{test_name}_out"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build_fixture(&project, &out, &runtime).map(drop)
}

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Run the ipe pipeline on the named fixture and return the build result.
/// Returns
fn run_ipec(fixture: &str, out_suffix: &str) -> Result<(), CliError> {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    crate::support::build_golden(crate::support::golden_dir_of(&entry), &out, &runtime)
}

/// R1: Routed Model (`page : Page`), `routes = []`, `notFound = 5` (Int).
///
/// Before Part B: ipe exited 0 (empty-routes hole), cargo rejected with E0308.
/// After Part B: ipe rejects with IPE-T0001 at type-check time.
#[test]
fn routed_empty_routes_int_notfound_is_ipe_t0001() {
    let result = run_ipec(
        "live_routed_empty_routes_int_notfound",
        "m7_live_routed_empty_routes_int_notfound_emit",
    );

    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "#108 R1: routed Web.tea with empty routes and Int notFound \
         must be rejected with IPE-T0001, got: {result:?}",
    );
}

/// R2: Routed Model (`page : Page`), `routes = []`,
/// `notFound = Increment` (Msg constructor — wrong ADT).
///
/// Before Part B: ipe exited 0, cargo rejected with E0631 / E0308.
/// After Part B: ipe rejects with IPE-T0001 at type-check time.
#[test]
fn routed_empty_routes_wrong_ctor_notfound_is_ipe_t0001() {
    let result = run_ipec(
        "live_routed_empty_routes_wrong_ctor_notfound",
        "m7_live_routed_empty_routes_wrong_ctor_notfound_emit",
    );

    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "#108 R2: routed Web.tea with empty routes and wrong-ADT notFound \
         must be rejected with IPE-T0001, got: {result:?}",
    );
}

/// Positive control: well-typed routed app (let-bound routeTable, correct
/// `notFound = CounterPage` which matches `page : Page`) must compile.
///
/// Reuses the `live_let_bound_routes` fixture (the IPE-I0001 regression).
/// Confirms the Part B hook does NOT trigger on a correctly-typed routed app.
#[test]
fn routed_correct_app_compiles() {
    let result = run_ipec(
        "live_let_bound_routes",
        "m7_live_let_bound_routes_partb_control",
    );
    assert!(
        result.is_ok(),
        "#108 positive control: well-typed routed Web.tea must compile, got: {:?}",
        result.err(),
    );
}

// ── Non-empty routes with wrong notFound — must produce IPE-T0001 ──────

/// T4d: non-empty routes (Part A fix), `notFound` from wrong ADT.
///
/// Part A pins `var(2)` to `Page` via route constructors.  The wrong `notFound =
/// Increment` (Msg) then fails unification → IPE-T0001.
/// Part B must NOT interfere: the hook still fires (Model has `page` field) and
/// should produce the same IPE-T0001 (or the Part A constraint fires first —
/// either way IPE-T0001 is the result).
#[test]
fn t4d_nonempty_routes_wrong_notfound_is_ipe_t0001() {
    let result = compile_src("t4d", T4D_NONEMPTY_ROUTES_WRONG_NOTFOUND);
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "T4d: non-empty routes + wrong-ADT notFound must be IPE-T0001, got: {result:?}",
    );
}

/// T4f: non-empty routes, route ctor from wrong ADT, correct notFound.
///
/// A route ctor `Web.route "/" Increment` forces `var(2) = Msg`.  The correct
/// `notFound = CounterPage` (Page) then fails unification → IPE-T0001.
#[test]
fn t4f_wrong_route_ctor_is_ipe_t0001() {
    let result = compile_src("t4f", T4F_WRONG_ROUTE_CTOR_CORRECT_NOTFOUND);
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "T4f: wrong-ADT route ctor must be IPE-T0001, got: {result:?}",
    );
}

/// MIX: non-empty routes with one correct + one wrong-ADT route ctor.
///
/// All route ctors share `var(2)`.  The wrong ctor forces a collision →
/// IPE-T0001 from the Part A constraint.
#[test]
fn mix_mixed_route_ctors_is_ipe_t0001() {
    let result = compile_src("mix", MIX_MIXED_ROUTE_CTORS);
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "MIX: mixed-type route ctors must be IPE-T0001, got: {result:?}",
    );
}

/// Non-routed regression: plain `Web.tea` with Model = `{ count : Int }` (no
/// `page` field) and `notFound = Increment` (Msg) must compile cleanly.
///
/// Part B's post-solve hook MUST NOT fire here: the Model has no `page` field,
/// so the check is skipped and ipe exits Ok.
#[test]
fn non_routed_live_app_compiles() {
    let result = compile_src("non_routed", NON_ROUTED_LIVE);
    assert!(
        result.is_ok(),
        "NON-ROUTED regression: plain Web.tea (no `page` field) must compile, got: {:?}",
        result.err(),
    );
}

// ── A well-typed routed app with an EMPTY table is refused ──
//
// R1/R2 above pin the type refusals; with a well-typed `notFound` an empty
// table still leaves every page constructor without a route, so no page has
// a canonical path to render: IPE-L0159.

/// Well-typed routed app with `routes = []` → refused with IPE-L0159 (a page
/// constructor has no route), never an app whose pages have no address.
#[test]
fn routed_empty_routes_is_refused() {
    let entry = repo_root()
        .join("tests")
        .join("golden")
        .join("live_routed_empty_routes_refused")
        .join("Main.ipe");
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("m7_live_routed_empty_routes_refused");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let result =
        crate::support::build_golden(crate::support::golden_dir_of(&entry), &out, &runtime);
    assert!(
        matches!(&result, Err(CliError::Pipeline { diag, .. }) if diag.code().as_str() == "IPE-L0159"),
        "a routed app with an empty table must be refused with IPE-L0159, got: {result:?}",
    );
}

// ── Non-empty routes, no `page` field → non-routed path ──────────────────────
//
// The golden oracle compiles a `Web.tea` with non-empty `routes` but no `page`
// field in Model — `applyRoute` calls `RecordUpdate(model, {"Page": page})`
// which silently no-ops when `Page` is absent.  This shape must not be gated
// stricter than the reference; the non-routed path (`web_app`) is emitted
// instead.

/// `Web.tea` with a non-empty `routes` list but Model has no `page`
/// field must compile on the non-routed path (mirrors `examples/24-tui-
/// kitchen-sink` and `examples/25-ipe-console`).
///
/// Before fix: ipec returned IPE-L0124 (gate was overly strict vs. golden oracle).
/// After fix: ipe exits 0 and emits `web_app` (not `web_app_routed`).
#[test]
fn non_routed_with_nonempty_routes_compiles() {
    let result = compile_src("non_routed_nonempty", NON_ROUTED_LIVE_WITH_NONEMPTY_ROUTES);
    assert!(
        result.is_ok(),
        "#153 regression: Web.tea with non-empty routes but no `page` field \
         must compile on the non-routed path (accepted shape), \
         got: {:?}",
        result.err(),
    );
}
