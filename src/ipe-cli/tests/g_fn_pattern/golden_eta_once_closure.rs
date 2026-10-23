//! An eta-rebuilt closure that moves a non-`Clone` capture runs at most once.
//!
//! A partial or over-application passed as a function value is rebuilt as a
//! closure over its supplied arguments. When an inlined argument reads a
//! destructure-bound function, that closure moves the function on its first
//! call: it is `FnOnce` only, so the lowerer builds it as an
//! `Expr::OnceLambda`. The once check admits one only where its position calls
//! it at most once (an immediate saturated apply, `Task.andThen`'s
//! continuation) and refuses every other position with IPE-L0126 at the moved
//! capture, before cargo can fail on a `Box<dyn Fn>` that moves it (E0507).
//!
//! A source lambda takes the same verdict: one that moves such a capture,
//! directly or by building an inner closure that captures it, is an
//! `Expr::OnceLambda` admitted or refused by its position alike.
//!
//! An adapted-callback kernel slot (`Ui.onKeyDown`, `Lazy.lazy`,
//! `Task.retryWith`) takes the same verdict: lowering puts the slot in
//! handler normal form, so a handler that moves a task is refused at the
//! capture, and a point-free use is refused with IPE-L0152. A handler whose
//! captures are `Clone` builds and runs, its sibling reads intact.
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test g_fn_pattern golden_eta_once_closure
//! ```

use std::path::PathBuf;

use ipe::CliError;
use ipe_diagnostics::{Diagnostic, Feature, LowerError, Span};

use crate::support::repo_root;

fn golden_dir(fixture: &str) -> PathBuf {
    repo_root().join("tests").join("golden").join(fixture)
}

fn out_dir(fixture: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(fixture);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// The span of the last `needle` in the fixture source: its leading `h`.
fn capture_span(fixture: &str, needle: &str) -> Span {
    #[allow(clippy::expect_used)] // a missing fixture is a broken test, not a refusal
    let src = std::fs::read_to_string(golden_dir(fixture).join("src").join("Main.ipe"))
        .expect("fixture source reads");
    #[allow(clippy::expect_used)] // the needle is written into the fixture
    let lo = src.rfind(needle).expect("needle is in the fixture");
    #[allow(clippy::expect_used)] // fixtures are far below 4 GiB
    let lo = u32::try_from(lo).expect("offset fits u32");
    Span {
        lo,
        hi: lo.saturating_add(1),
    }
}

/// A fixture is refused at ipe time by the once check, at the moved capture.
fn assert_refused_at_capture(fixture: &str, needle: &str) {
    let built = crate::support::build_golden(
        &golden_dir(fixture),
        &out_dir(fixture),
        &e2e_support::require_runtime().into_path_buf(),
    );
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0126),
        "{fixture}: a rebuilt closure moving `h` must fail closed at ipe time, got {built:?}"
    );
    let want = capture_span(fixture, needle);
    assert!(
        matches!(
            &built,
            Err(CliError::Pipeline { diag, .. })
                if matches!(
                    diag.as_ref(),
                    Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::RebuiltClosureMovesCapture),
                    } if *span == want
                )
        ),
        "{fixture}: the refusal must come from the once check at `h` ({want:?}), got {built:?}"
    );
}

/// A named kernel partial (`Task.andThen (\x -> h x)`) mapped over a list.
#[test]
fn kernel_partial_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_partial", "h x)");
}

/// A partial of a local function value with an inlined lambda argument.
#[test]
fn value_partial_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_value_partial", "h y)");
}

/// A partial constructor whose field is a partial moving `h`.
#[test]
fn partial_ctor_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_partial_ctor", "h x)");
}

/// An over-application of a curried def with an inlined lambda argument.
#[test]
fn over_partial_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_over_partial", "h y)");
}

/// The capture is read two closures deep; building them still moves it.
#[test]
fn capture_moved_through_inner_lambdas_is_refused() {
    assert_refused_at_capture("eta_once_nested", "h y)");
}

/// A partial of a user function that moves a `Task` parameter.
#[test]
fn task_capture_partial_is_refused_at_the_capture() {
    assert_refused_at_capture("eta_once_task_capture", "t) ns");
}

/// Admitted once positions and the own-parameter rewrite pass ipe.
#[test]
fn admitted_once_positions_pass_ipe() {
    let fixture = "eta_once_admitted";
    let built = crate::support::build_golden(
        &golden_dir(fixture),
        &out_dir(fixture),
        &e2e_support::require_runtime().into_path_buf(),
    );
    assert!(
        built.is_ok(),
        "{fixture}: a once closure at a once position must pass ipe: {:?}",
        built.err()
    );
}

/// cargo-0 and run-correct for the admitted positions: gated on `IPE_E2E=1` (THE SEAL).
#[test]
fn admitted_once_positions_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let fixture = "eta_once_admitted";
    let out = crate::support::scratch_root().join("ipec_eta_once_admitted_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let built = crate::support::build_golden(
        &golden_dir(fixture),
        &out,
        &e2e_support::require_runtime().into_path_buf(),
    );
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );
    let outcome = crate::support::build_and_run_emitted(fixture, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{fixture} must build and exit 0 (no E0507/E0525); stdout: {:?}",
        outcome.stdout
    );
    // piped (inc, 4) = 5; continued (succeed 1) = 1 + 40 = 41; viaParam maps inc.
    assert!(
        outcome.stdout.contains("once=5,41 param=2,3"),
        "must print the once and param line; got: {:?}",
        outcome.stdout
    );
}

/// An inner source lambda in an admitted slot of a recalled source lambda.
const INNER_LAMBDA_IN_ADMITTED_SLOT: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.List as List
import Ipe.Task as Task


run : ( Int -> Task Error Int, Int ) -> List (Task Error Int) -> List (Task Error Int)
run ( h, _ ) ts =
    List.map (\t -> Task.andThen (\x -> h x) t) ts


inc : Int -> Task Error Int
inc n =
    Task.succeed (n + 1)


main : Task Error ()
main =
    Task.sequence (run ( inc, 0 ) [ Task.succeed 1 ])
        |> Task.andThen (\_ -> Io.println "unreachable")
"#;

/// An admitted once partial inside a recalled source lambda.
const ONCE_PARTIAL_IN_RECALLED_LAMBDA: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.List as List
import Ipe.Task as Task


combine : Task Error Int -> Int -> Task Error Int
combine t n =
    t |> Task.map (\m -> m + n)


run : Task Error Int -> List (Task Error Int) -> List (Task Error Int)
run t ts =
    List.map (\s -> Task.andThen (combine t) s) ts


main : Task Error ()
main =
    Task.sequence (run (Task.succeed 1) [ Task.succeed 2 ])
        |> Task.andThen (\_ -> Io.println "unreachable")
"#;

/// Once source lambdas at once positions, each built and run.
const SOURCE_ADMITTED: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.String
import Ipe.Task as Task


step : String -> Task Error ()
step s =
    Io.println s


combine : Task Error Int -> Int -> Task Error Int
combine t n =
    t |> Task.map (\m -> m + n)


-- The once partial with the outer lambda in `Task.andThen`'s continuation: it runs once.
chain : Task Error Int -> Task Error Int
chain t =
    Task.andThen (\n -> Task.andThen (combine t) (Task.succeed n)) (Task.succeed 2)


-- The bind of `twice`, written as an explicit `Task.andThen`.
twice : (String -> Task Error ()) -> Task Error ()
twice prepare =
    Task.andThen (\at -> Task.andThen (\_ -> prepare at) (Io.println "a")) (Task.succeed "x")


-- A destructure-bound function moved into the bind's once-only lambda.
twiceDestructured : ( String -> Task Error (), Int ) -> Task Error ()
twiceDestructured ( prepare, _ ) =
    do
        at <- Task.succeed "y"
        Io.println "b"
        prepare at
        Task.succeed ()


-- The same with a later bind inside the bind's lambda.
laterBind : ( String -> Task Error (), Int ) -> (String -> Task Error ()) -> Task Error ()
laterBind ( prepare, _ ) mutate =
    do
        at <- Task.succeed "z"
        Io.println at
        prepare at
        r <- Task.succeed "r"
        mutate r


main : Task Error ()
main =
    do
        n <- chain (Task.succeed 40)
        Io.println ("partial=" ++ String.fromInt n)
        twice step
        twiceDestructured ( step, 1 )
        laterBind ( step, 2 ) step
"#;

/// The lines [`SOURCE_ADMITTED`] prints, in order.
const SOURCE_ADMITTED_STDOUT: &str = "partial=42\na\nx\nb\ny\nz\nz\nr\n";

/// Build `source` as a one-module project fixture into a fresh out dir.
///
/// Returns the driver result and the out dir.
fn build_source(name: &str, source: &str) -> (Result<(), CliError>, PathBuf) {
    let fixture = crate::root_fixture::main(source);
    let out = crate::support::scratch_root().join(name);
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    (crate::root_fixture::build(&fixture, &out, &runtime), out)
}

/// The one-byte span of the last `needle` in `source`: its leading capture.
fn source_capture_span(source: &str, needle: &str) -> Span {
    #[allow(clippy::expect_used)] // the needle is written into the source
    let lo = source.rfind(needle).expect("needle is in the source");
    #[allow(clippy::expect_used)] // the sources are far below 4 GiB
    let lo = u32::try_from(lo).expect("offset fits u32");
    Span {
        lo,
        hi: lo.saturating_add(1),
    }
}

/// A source program is refused at ipe time by the once check, at the moved capture.
fn assert_source_refused_at_capture(name: &str, source: &str, needle: &str) {
    let (built, _) = build_source(name, source);
    let want = source_capture_span(source, needle);
    assert!(
        matches!(
            &built,
            Err(CliError::Pipeline { diag, .. })
                if matches!(
                    diag.as_ref(),
                    Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::RebuiltClosureMovesCapture),
                    } if *span == want
                )
        ),
        "{name}: a recalled source lambda moving a capture must fail closed with IPE-L0126 \
         at the capture ({want:?}), got {built:?}"
    );
}

/// Building the inner lambda moves `h` out of the `List.map` callback.
#[test]
fn source_lambda_building_a_capturing_lambda_is_refused_at_the_capture() {
    assert_source_refused_at_capture(
        "eta_once_source_inner_lambda",
        INNER_LAMBDA_IN_ADMITTED_SLOT,
        "h x)",
    );
}

/// Building the once partial moves `t` out of the `List.map` callback.
#[test]
fn source_lambda_building_a_once_partial_is_refused_at_the_capture() {
    assert_source_refused_at_capture(
        "eta_once_source_once_partial",
        ONCE_PARTIAL_IN_RECALLED_LAMBDA,
        "t) s)",
    );
}

/// Once source lambdas at once positions pass ipe.
#[test]
fn admitted_once_source_lambdas_pass_ipe() {
    let (built, _) = build_source("eta_once_source_admitted", SOURCE_ADMITTED);
    assert!(
        built.is_ok(),
        "a once source lambda at a once position must pass ipe: {:?}",
        built.err()
    );
}

/// cargo-0 and run-correct for the once source lambdas: gated on `IPE_E2E=1` (THE SEAL).
#[test]
fn admitted_once_source_lambdas_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (built, out) = build_source("eta_once_source_admitted_e2e", SOURCE_ADMITTED);
    assert!(built.is_ok(), "the build must succeed: {:?}", built.err());
    let outcome = crate::support::build_and_run_emitted("eta_once_source_admitted", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the once source lambdas must build and exit 0 (no E0507/E0525); stdout: {:?}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains(SOURCE_ADMITTED_STDOUT),
        "must print every shape's lines in order; got: {:?}",
        outcome.stdout
    );
}

/// A decoder destructure's thunk builds a closure over a function param.
///
/// The thunk is `Fn` (called once per read), so building the inner closure
/// would move a `Box<dyn Fn>` param out of it; the param's binder site
/// promotes it to the `Arc` carrier instead, so it is cloned and accepted.
const THUNK_PROMOTED: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.Json.Decode as JsonDec
import Ipe.String
import Ipe.Task as Task


shout : String -> String
shout s =
    s ++ "!"


decodeWith : (String -> String) -> String -> String
decodeWith f raw =
    let
        ( d, n ) =
            ( JsonDec.map (\s -> f s ++ ".") JsonDec.string, 1 )
    in
    case ( JsonDec.decodeString d raw, JsonDec.decodeString d raw ) of
        ( Ok a, Ok b ) ->
            a ++ b ++ String.fromInt n

        _ ->
            "err"


main : Task Error ()
main =
    Io.println (decodeWith shout "\"hi\"")
"#;

/// The line [`THUNK_PROMOTED`] prints.
const THUNK_PROMOTED_STDOUT: &str = "hi!.hi!.1\n";

/// The same thunk over a destructure-bound function: no carrier can promote it.
const THUNK_DESTRUCTURED: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.Json.Decode as JsonDec
import Ipe.String
import Ipe.Task as Task


shout : String -> String
shout s =
    s ++ "!"


decodeWith : ( String -> String, Int ) -> String -> String
decodeWith ( g, _ ) raw =
    let
        ( d, n ) =
            ( JsonDec.map (\s -> g s ++ ".") JsonDec.string, 1 )
    in
    case ( JsonDec.decodeString d raw, JsonDec.decodeString d raw ) of
        ( Ok a, Ok b ) ->
            a ++ b ++ String.fromInt n

        _ ->
            "err"


main : Task Error ()
main =
    Io.println (decodeWith ( shout, 0 ) "\"hi\"")
"#;

/// A destructure thunk building a closure over a destructure-bound function is refused.
#[test]
fn destructure_thunk_moving_a_bound_function_is_refused_at_the_capture() {
    assert_source_refused_at_capture("eta_once_thunk_destructured", THUNK_DESTRUCTURED, "g s ++");
}

/// A destructure thunk over a promotable function param passes ipe.
#[test]
fn destructure_thunk_over_a_function_param_passes_ipe() {
    let (built, _) = build_source("eta_once_thunk_promoted", THUNK_PROMOTED);
    assert!(
        built.is_ok(),
        "a promotable function param captured by a destructure thunk must pass ipe: {:?}",
        built.err()
    );
}

/// cargo-0 and run-correct for the promoted thunk capture: gated on `IPE_E2E=1` (THE SEAL).
#[test]
fn destructure_thunk_over_a_function_param_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (built, out) = build_source("eta_once_thunk_promoted_e2e", THUNK_PROMOTED);
    assert!(built.is_ok(), "the build must succeed: {:?}", built.err());
    let outcome = crate::support::build_and_run_emitted("eta_once_thunk_promoted", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the promoted thunk capture must build and exit 0 (no E0507); stdout: {:?}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains(THUNK_PROMOTED_STDOUT),
        "must decode through the promoted param twice; got: {:?}",
        outcome.stdout
    );
}

/// A `Ui.onKeyDown` handler built as a partial over a task parameter.
///
/// The handler normal form wraps the partial in the callback closure itself,
/// which moves the non-`Clone` task out on its first key press.
const UI_HANDLER_MOVES_TASK: &str = r"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Html as Html
import Ipe.Io as Io
import Ipe.Task as Task
import Ipe.Ui as Ui exposing (Element)


type Msg
    = KeyDown Int String


h : Task Error Int -> String -> Msg
h _ key =
    KeyDown 0 key


view : Task Error Int -> Element Msg
view t =
    Ui.column [ Ui.onKeyDown (h t) ] []


main : Task Error ()
main =
    Io.println (Html.render (Ui.layout [] (view (Task.succeed 1))))
";

/// A `Lazy.lazy` view built as a partial over a task parameter.
const LAZY_VIEW_MOVES_TASK: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Html as Html
import Ipe.Io as Io
import Ipe.Task as Task
import Ipe.Ui as Ui exposing (Element)
import Ipe.Ui.Lazy as Lazy


type Msg
    = NoOp


h : Task Error Int -> String -> Element Msg
h _ label =
    Ui.text label


view : Task Error Int -> Element Msg
view t =
    Ui.column [] [ Lazy.lazy (h t) "x" ]


main : Task Error ()
main =
    Io.println (Html.render (Ui.layout [] (view (Task.succeed 1))))
"#;

/// A `Task.retryWith` over a task parameter: each retry re-runs the moved task.
const RETRY_MOVES_TASK: &str = r"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.String
import Ipe.Task as Task


retried : Task Error Int -> Task Error Int
retried t =
    Task.retryWith Task.defaultRetryPolicy t


main : Task Error ()
main =
    Task.andThen (\n -> Io.println (String.fromInt n)) (retried (Task.succeed 1))
";

/// `Ui.onKeyDown`: the eta-wrapped key handler moves `t` out of the callback.
#[test]
fn ui_on_key_down_handler_moving_a_task_is_refused_at_the_capture() {
    assert_source_refused_at_capture(
        "eta_once_ui_on_key_down_task",
        UI_HANDLER_MOVES_TASK,
        "t) ]",
    );
}

/// `Lazy.lazy`: the view closure moves `t` out on its first render.
#[test]
fn lazy_lazy_view_moving_a_task_is_refused_at_the_capture() {
    assert_source_refused_at_capture("eta_once_lazy_lazy_task", LAZY_VIEW_MOVES_TASK, "t) \"x\"");
}

/// `Task.retryWith`: the re-run thunk moves `t` out on its first attempt.
#[test]
fn task_retry_with_moving_a_task_is_refused_at_the_capture() {
    assert_source_refused_at_capture(
        "eta_once_task_retry_with_task",
        RETRY_MOVES_TASK,
        "t\n\n\nmain",
    );
}

/// `Ui.onKeyDown` used point-free: its handler is never in the lowerer's hands.
const UI_ON_KEY_DOWN_POINT_FREE: &str = r"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Html as Html
import Ipe.Io as Io
import Ipe.List as List
import Ipe.Task as Task
import Ipe.Ui as Ui exposing (Element)


type Msg
    = KeyDown String


view : Element Msg
view =
    Ui.column (List.map Ui.onKeyDown [ KeyDown ]) []


main : Task Error ()
main =
    Io.println (Html.render (Ui.layout [] view))
";

/// `Ui.onKeyDown` point-free fails closed with IPE-L0152, naming the kernel.
#[test]
fn ui_on_key_down_point_free_is_refused_as_unsaturated() {
    let (built, _) = build_source(
        "eta_once_ui_on_key_down_point_free",
        UI_ON_KEY_DOWN_POINT_FREE,
    );
    assert!(
        matches!(
            &built,
            Err(CliError::Pipeline { diag, .. })
                if matches!(
                    diag.as_ref(),
                    Diagnostic::Lower {
                        msg: LowerError::UnsaturatedHandlerKernel { kernel },
                        ..
                    } if kernel.as_ref() == "Ui.onKeyDown"
                )
        ),
        "a point-free `Ui.onKeyDown` must fail closed with IPE-L0152, got {built:?}"
    );
}

/// Adapted-callback slots whose handlers capture a `Clone` model.
///
/// Each handler is a partial over a computed capture (`KeyDown (offers
/// model)`), a call returning a function, an `if`, or a function-typed
/// capture, and every element also reads `model` as a sibling: the handler
/// normal form keeps each slot's `let`s outside its callback, so the model
/// survives for the sibling and each callback is re-callable.
const HANDLERS_CAPTURE_CLONE: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Html as Html
import Ipe.Io as Io
import Ipe.String
import Ipe.Task as Task
import Ipe.Ui as Ui exposing (Element)
import Ipe.Ui.Input as Input
import Ipe.Ui.Lazy as Lazy


type alias Model =
    { keys : String }


type Msg
    = KeyDown String String
    | Toggled String Bool


offers : Model -> String
offers m =
    m.keys


pick : Model -> String -> Msg
pick m key =
    KeyDown m.keys key


apply : (String -> Msg) -> String -> Msg
apply f key =
    f key


item : String -> String -> Element Msg
item prefix label =
    Ui.text (prefix ++ label)


giveUp : Model -> Error -> Bool
giveUp m _ =
    String.length m.keys == 0


view : Bool -> Model -> Element Msg
view c model =
    Ui.column
        [ Ui.onKeyDown (KeyDown (offers model))
        , Ui.onKeyUp (pick model)
        , Ui.onInput
            (if c then
                KeyDown "x"

             else
                KeyDown (offers model)
            )
        , Ui.onChange (KeyDown (offers model))
        , Ui.onFile (KeyDown (offers model))
        , Ui.onBool (Toggled (offers model))
        ]
        [ Input.text []
            { onChange = KeyDown (offers model)
            , text = model.keys
            , placeholder = Nothing
            , label = Input.labelLeft [] (Ui.text model.keys)
            }
        , Lazy.lazy (item (offers model)) model.keys
        , Ui.text model.keys
        ]


single : Model -> Element Msg
single model =
    Ui.column [ Ui.onKeyDown (KeyDown (offers model)) ] []


sync : Model -> Element Msg
sync model =
    let
        g =
            pick model
    in
    Ui.column
        [ Ui.onKeyDown (\k -> g k)
        , Ui.onKeyUp (apply (pick model))
        ]
        [ Ui.text model.keys ]


main : Task Error ()
main =
    let
        model =
            { keys = "keys" }

        page =
            Html.render (Ui.layout [] (Ui.column [] [ view True model, single model, sync model ]))
    in
    Task.andThen
        (\n -> Io.println (page ++ "|" ++ String.fromInt n))
        (Task.retryWith
            (Task.retryOn (giveUp model) Task.defaultRetryPolicy)
            (Task.succeed (String.length (offers model)))
        )
"#;

/// Adapted-callback handlers over a `Clone` capture pass ipe.
#[test]
fn clone_capturing_adapted_handlers_pass_ipe() {
    let (built, _) = build_source("eta_once_handlers_capture_clone", HANDLERS_CAPTURE_CLONE);
    assert!(
        built.is_ok(),
        "adapted-callback handlers over a `Clone` capture must pass ipe: {:?}",
        built.err()
    );
}

/// cargo-0 and run-correct for the adapted-callback handlers: gated on `IPE_E2E=1` (THE SEAL).
///
/// Without handler normal form the emitted view fails cargo with E0382 (the
/// sibling read of a model moved into a callback) or E0507 (a single-use
/// capture moved out of an `Fn` callback).
#[test]
fn clone_capturing_adapted_handlers_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (built, out) = build_source(
        "eta_once_handlers_capture_clone_e2e",
        HANDLERS_CAPTURE_CLONE,
    );
    assert!(built.is_ok(), "the build must succeed: {:?}", built.err());
    let outcome = crate::support::build_and_run_emitted("eta_once_handlers_capture_clone", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the adapted-callback handlers must build and exit 0 (no E0382/E0507); stdout: {:?}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("keyskeys") && outcome.stdout.trim_end().ends_with("|4"),
        "must render the lazy view and the retried task's result; got: {:?}",
        outcome.stdout
    );
}

/// Adapted-callback slot shapes beyond a bare partial.
///
/// A slot under leading `let`s that mixes plain bindings with a destructure,
/// a `let`-bound function returned or passed on, an outer `let`-bound handler,
/// a record field (`Input.text`'s `onChange`) under a `let`, a pipe, a `case`,
/// `Ui.onSubmit`, and a `Lazy.lazy2` partial: each must reach the backend in
/// handler normal form, and every element still reads `model` as a sibling.
/// An outer `let`-bound or parameter handler passed on as a value inside a
/// handler (`apply g`) is re-dispatched, never handed over as its `Arc`
/// carrier to an `impl Fn` parameter (E0277).
const HANDLER_SHAPES: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Html as Html
import Ipe.Io as Io
import Ipe.String
import Ipe.Task as Task
import Ipe.Ui as Ui exposing (Element)
import Ipe.Ui.Input as Input
import Ipe.Ui.Lazy as Lazy


type alias Model =
    { keys : String }


type Msg
    = KeyDown String String
    | Toggled String Bool


offers : Model -> String
offers m =
    m.keys


pick : Model -> String -> Msg
pick m key =
    KeyDown m.keys key


apply : (String -> Msg) -> String -> Msg
apply f key =
    f key


item : String -> String -> Element Msg
item prefix label =
    Ui.text (prefix ++ label)


item2 : String -> String -> String -> Element Msg
item2 prefix a b =
    Ui.text (prefix ++ a ++ b)


handleKey : String -> Msg
handleKey k =
    KeyDown "top" k


mixedDestructure : Model -> Element Msg
mixedDestructure model =
    let
        pair =
            ( model.keys, "q" )
    in
    Ui.column
        [ Ui.onKeyDown
            (let
                a =
                    offers model

                ( p, q ) =
                    pair
             in
             KeyDown (a ++ p ++ q)
            )
        , Ui.onKeyUp
            (let
                a =
                    offers model

                ( p, _ ) =
                    pair
             in
             if p == "" then
                KeyDown a

             else
                KeyDown (a ++ p)
            )
        ]
        [ Ui.text model.keys ]


letAliases : Model -> Element Msg
letAliases model =
    let
        g =
            pick model
    in
    Ui.column
        [ Ui.onKeyDown
            (let
                h =
                    pick model
             in
             h
            )
        , Ui.onKeyUp
            (let
                h =
                    pick model
             in
             apply h
            )
        , Ui.onInput g
        , Ui.onChange (apply g)
        , Ui.onFile
            (let
                h =
                    \k -> KeyDown model.keys k
             in
             h
            )
        ]
        [ Input.text []
            { onChange =
                let
                    h =
                        pick model
                in
                h
            , text = model.keys
            , placeholder = Nothing
            , label = Input.labelLeft [] (Ui.text model.keys)
            }
        , Ui.text model.keys
        ]


pipesAndCases : Model -> Element Msg
pipesAndCases model =
    Ui.column
        [ model |> pick |> Ui.onKeyDown
        , Ui.onKeyUp <| pick model
        , Ui.onInput handleKey
        , Ui.onChange
            (case model.keys of
                "" ->
                    KeyDown "a"

                _ ->
                    KeyDown (offers model)
            )
        , Ui.onSubmit (KeyDown (offers model))
        ]
        [ Lazy.lazy2 (item2 (offers model)) model.keys "b", Ui.text model.keys ]


paramHandler : (String -> Msg) -> Model -> Element Msg
paramHandler handler model =
    Ui.column
        [ Ui.onChange (apply handler)
        , Ui.onKeyDown handler
        ]
        [ Ui.text model.keys ]


view : Model -> Element Msg
view model =
    Ui.column []
        [ mixedDestructure model
        , letAliases model
        , pipesAndCases model
        , paramHandler (pick model) model
        ]


main : Task Error ()
main =
    let
        model =
            { keys = "keys" }
    in
    Io.println (Html.render (Ui.layout [] (view model)) ++ "|" ++ model.keys)
"#;

/// Every adapted-callback slot shape of [`HANDLER_SHAPES`] passes ipe.
#[test]
fn adapted_handler_shapes_pass_ipe() {
    let (built, _) = build_source("eta_once_handler_shapes", HANDLER_SHAPES);
    assert!(
        built.is_ok(),
        "every adapted-callback slot shape must pass ipe: {:?}",
        built.err()
    );
}

/// cargo-0 and run-correct for [`HANDLER_SHAPES`]: gated on `IPE_E2E=1` (THE SEAL).
#[test]
fn adapted_handler_shapes_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (built, out) = build_source("eta_once_handler_shapes_e2e", HANDLER_SHAPES);
    assert!(built.is_ok(), "the build must succeed: {:?}", built.err());
    let outcome = crate::support::build_and_run_emitted("eta_once_handler_shapes", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the adapted-callback slot shapes must build and exit 0 (no E0382/E0507); stdout: {:?}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("keyskeysb") && outcome.stdout.trim_end().ends_with("|keys"),
        "must render the lazy view and the model; got: {:?}",
        outcome.stdout
    );
}
