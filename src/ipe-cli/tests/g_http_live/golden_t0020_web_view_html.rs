//! A `Web.tea` `view` whose body settles to `Html` (it called `Ui.layout` /
//! `Ui.layoutWith` itself) must be rejected by ipe with IPE-T0020 — never
//! accepted at ipe time only to fail the emitted `cargo build` with E0308
//! (`Element` vs `Html`).
//!
//! ## Background
//!
//! `Web.tea` requires `view : Model -> Element Msg`; the shape applies
//! `Ui.layout` internally to turn that `Element` into `Html`. A `view`
//! annotated `Model -> any` severs the body's settled type from the reference
//! the shape consumes — each wildcard `any` occurrence instantiates its own
//! fresh flex — so a body returning `Html` slips past the `Element`
//! requirement. The emitter then double-wraps the `Html` in `ui_layout`, and
//! the crate fails cargo (`E0308`). The fix re-connects every reference to a
//! wildcard-`any`-return binding to its body once all defs are constrained, so
//! the body's real type flows to the shape's `Element` requirement as an
//! ordinary mismatch — rendered as IPE-T0020. Because it is plain unification,
//! it holds under every indirection (source order, `let` alias chains, nested
//! `let`, eta-expansion), not just a direct reference.
//!
//! All tests are pure ipe-pipeline checks (parse → canon → types → lower →
//! emit); no cargo build or runtime binary is required. They skip if the
//! embedded runtime cannot be resolved.

use ipe::CliError;

/// `view : Model -> any` whose body is `Ui.layout [] (...)` (returns `Html`).
/// Must be rejected with IPE-T0020.
const ANY_VIEW_RETURNS_HTML: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
view : Model -> any
view model =
    Ui.layout [] (Ui.column [] [ Ui.text "hi" ])
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// Legal: `view : Model -> any` whose body is a plain `Element` (`Ui.column`).
/// The wildcard return does NOT make this an error — only an `Html` body does.
const ANY_VIEW_RETURNS_ELEMENT: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
view : Model -> any
view model =
    Ui.column [] [ Ui.text "hi" ]
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// Legal: `view : Model -> any` whose body wraps raw `Html` back into an
/// `Element` with `Ui.html (...)`. The documented escape hatch — must compile.
const ANY_VIEW_WRAPS_WITH_UI_HTML: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
view : Model -> any
view model =
    Ui.html (Ui.layout [] (Ui.column [] [ Ui.text "hi" ]))
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// Positive control: the canonical `view : Model -> Element Msg` form must
/// compile — confirming the gate never false-rejects the correct shape.
const ELEMENT_VIEW_OK: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
view : Model -> Element Msg
view model =
    Ui.column [] [ Ui.text "hi" ]
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// `main` ABOVE `view` in source: the reference precedes the def, so the
/// wildcard-`any` body var is not recorded until later in the same pass. The
/// check must still fire (resolution is deferred until all defs are
/// constrained), or the Html view slips to a cargo E0308.
const ANY_VIEW_HTML_MAIN_FIRST: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
view : Model -> any
view model =
    Ui.layout [] (Ui.column [] [ Ui.text "hi" ])
"#;

/// The `view` is supplied through a `let` alias (`let v = view in … view = v`).
/// The field value is a `VarLocal`; resolving the alias back to the top-level
/// binding must still catch the Html body, or it slips to a cargo E0271.
const ANY_VIEW_HTML_LET_ALIAS: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
view : Model -> any
view model =
    Ui.layout [] (Ui.column [] [ Ui.text "hi" ])
main =
    let v = view
    in Web.tea
        { init = init, update = update, view = v, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// A CHAINED `let` alias (`let v = view; w = v in … view = w`): the field value
/// is a `VarLocal` two hops from the top-level ref. Body-propagation is
/// indirection-proof, so this is still caught (a syntactic reference walk would
/// miss it and slip to a cargo E0271).
const ANY_VIEW_HTML_CHAINED_ALIAS: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
view : Model -> any
view model =
    Ui.layout [] (Ui.column [] [ Ui.text "hi" ])
main =
    let v = view
        w = v
    in Web.tea
        { init = init, update = update, view = w, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// The `view` supplied through an ETA-lambda (`\m -> view m`): the field value
/// is a `Lambda`, not a reference, but its body applies the wildcard-`any`
/// binding, so the propagated `Html` still reaches the `Element` requirement.
const ANY_VIEW_HTML_ETA_LAMBDA: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
view : Model -> any
view model =
    Ui.layout [] (Ui.column [] [ Ui.text "hi" ])
main =
    Web.tea
        { init = init, update = update, view = \m -> view m, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// An EXPLICITLY `Element Msg`-annotated `view` whose body returns `Html`: the
/// `Element` / `Html` clash renders as the tailored IPE-T0020, not a bare
/// type-mismatch — the wrap-in-`Ui.html` hint applies here too.
const ELEMENT_VIEW_HTML_BODY: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
view : Model -> Element Msg
view model =
    Ui.layout [] (Ui.column [] [ Ui.text "hi" ])
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// A POINT-FREE `view` (`view = htmlBody`, zero written patterns) bound to a
/// wildcard-`any`-return helper whose body is `Html`. The def carries no
/// parameter list, so its recorded body is the whole `Model -> Html` arrow;
/// peeling both the use and the body to their results still catches it.
const ANY_VIEW_HTML_POINT_FREE: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
htmlBody : Model -> any
htmlBody model =
    Ui.layout [] (Ui.column [] [ Ui.text "hi" ])
view : Model -> any
view = htmlBody
main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// A POINT-FREE top-level alias (`alias : Model -> any; alias = view`) of a
/// wildcard-`any`-return `view` with an `Html` body, fed to the shape. The
/// alias's own annotation return is a bare wildcard `any`, so it too collects a
/// use tie back to `view`'s body.
const ANY_VIEW_HTML_POINT_FREE_ALIAS: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Msg = Bump | Ignored
type alias Model = { count : Int }
init _req = ( { count = 0 }, Cmd.none )
update msg model =
    case msg of
        Bump -> ( { model | count = model.count + 1 }, Cmd.none )
        Ignored -> ( model, Cmd.none )
subscriptions _model = Sub.none
view : Model -> any
view model =
    Ui.layout [] (Ui.column [] [ Ui.text "hi" ])
alias : Model -> any
alias = view
main =
    Web.tea
        { init = init, update = update, view = alias, subscriptions = subscriptions
        , routes = [], notFound = Ignored
        }
"#;

/// Compile an inline source through the full ipe pipeline (parse → … → emit).
/// Returns `None` (skip) when the embedded runtime cannot be resolved.
fn compile_src(test_name: &str, source: &str) -> Option<Result<(), CliError>> {
    let ipe_dir = crate::support::scratch_root().join(format!("t0020_web_view_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).ok()?;
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, source).ok()?;
    let out = crate::support::scratch_root().join(format!("t0020_web_view_{test_name}_out"));
    let _ = std::fs::remove_dir_all(&out);
    let Ok(runtime) = ipe::resolve_runtime() else {
        return None;
    };
    Some(ipe::build(&entry, &out, &runtime))
}

#[test]
fn any_view_returning_html_is_ipe_t0020() {
    let Some(result) = compile_src("html", ANY_VIEW_RETURNS_HTML) else {
        return;
    };
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0020),
        "a `view : Model -> any` returning Html (Ui.layout) must be rejected \
         with IPE-T0020, got: {result:?}",
    );
}

#[test]
fn any_view_returning_element_compiles() {
    let Some(result) = compile_src("element", ANY_VIEW_RETURNS_ELEMENT) else {
        return;
    };
    assert!(
        result.is_ok(),
        "a `view : Model -> any` returning an Element must NOT be rejected, \
         got: {result:?}",
    );
}

#[test]
fn any_view_wrapping_with_ui_html_compiles() {
    let Some(result) = compile_src("ui_html", ANY_VIEW_WRAPS_WITH_UI_HTML) else {
        return;
    };
    assert!(
        result.is_ok(),
        "a `view : Model -> any` wrapping raw Html with `Ui.html` must \
         compile, got: {result:?}",
    );
}

#[test]
fn element_view_is_positive_control() {
    let Some(result) = compile_src("control", ELEMENT_VIEW_OK) else {
        return;
    };
    assert!(
        result.is_ok(),
        "the canonical `view : Model -> Element Msg` form must compile, \
         got: {result:?}",
    );
}

#[test]
fn any_view_html_is_ipe_t0020_even_when_main_precedes_view() {
    let Some(result) = compile_src("main_first", ANY_VIEW_HTML_MAIN_FIRST) else {
        return;
    };
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0020),
        "an Html view must be rejected with IPE-T0020 even when `main` precedes \
         `view` in source order, got: {result:?}",
    );
}

#[test]
fn any_view_html_is_ipe_t0020_through_a_let_alias() {
    let Some(result) = compile_src("let_alias", ANY_VIEW_HTML_LET_ALIAS) else {
        return;
    };
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0020),
        "an Html view supplied through a `let` alias must still be rejected with \
         IPE-T0020, got: {result:?}",
    );
}

#[test]
fn any_view_html_is_ipe_t0020_through_a_chained_alias() {
    let Some(result) = compile_src("chained", ANY_VIEW_HTML_CHAINED_ALIAS) else {
        return;
    };
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0020),
        "an Html view supplied through a chained `let` alias must be rejected \
         with IPE-T0020, got: {result:?}",
    );
}

#[test]
fn any_view_html_is_ipe_t0020_through_an_eta_lambda() {
    let Some(result) = compile_src("eta", ANY_VIEW_HTML_ETA_LAMBDA) else {
        return;
    };
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0020),
        "an Html view supplied through an eta-lambda must be rejected with \
         IPE-T0020, got: {result:?}",
    );
}

#[test]
fn any_view_html_is_ipe_t0020_through_a_point_free_view() {
    let Some(result) = compile_src("point_free", ANY_VIEW_HTML_POINT_FREE) else {
        return;
    };
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0020),
        "a point-free Html view (`view = htmlBody`) must be rejected with \
         IPE-T0020, got: {result:?}",
    );
}

#[test]
fn any_view_html_is_ipe_t0020_through_a_point_free_alias() {
    let Some(result) = compile_src("point_free_alias", ANY_VIEW_HTML_POINT_FREE_ALIAS) else {
        return;
    };
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0020),
        "a point-free top-level alias of an Html view must be rejected with \
         IPE-T0020, got: {result:?}",
    );
}

#[test]
fn element_annotated_view_with_html_body_is_ipe_t0020() {
    let Some(result) = compile_src("elem_html_body", ELEMENT_VIEW_HTML_BODY) else {
        return;
    };
    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0020),
        "an explicitly `Element Msg`-annotated view with an Html body renders \
         the tailored IPE-T0020 (Element/Html clash), got: {result:?}",
    );
}
