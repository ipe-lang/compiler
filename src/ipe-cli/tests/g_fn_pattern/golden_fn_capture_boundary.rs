//! A function capture read in a run-statement continuation keeps a sound carrier.
//!
//! A `do` block's run statement lowers to a `TaskSeq` whose continuation the
//! backend wraps in a `move |_|` closure for the runtime's `FnOnce`
//! `task_and_then` slot. Inside a `Recallable` closure (a `List.map`
//! callback), that hidden closure moves each capture out of the enclosing
//! environment on every call. A promotable function binder there is moved onto
//! the `Clone` `Arc` carrier; a non-promotable one (bound by a tuple
//! destructure) is refused with IPE-L0126 at its use, before cargo can fail on
//! a `Box<dyn Fn>` moved out of a `Fn` closure (E0507). The `\at ->` a bind
//! statement builds is once-only, so a destructure-bound function moves into
//! it soundly.
//!
//! A record field read rides the same verdict. A field holding a move-only
//! value (a `Task`, or one wrapped in a `Maybe` or a variant) read inside a
//! `Recallable` callback, or in a continuation inside one, is refused with
//! IPE-L0126 at the record it is read from; read once at the top of a `do`
//! block, or through a function field on its `Clone` carrier, it builds.
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test g_fn_pattern golden_fn_capture_boundary
//! ```

use std::path::PathBuf;

use ipe::CliError;
use ipe_diagnostics::{Diagnostic, Feature, LowerError, Span};

/// Function captures read in run-statement continuations, each shape built and run.
const ACCEPTED: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.List as List
import Ipe.String
import Ipe.Task as Task


type alias Scratch =
    { a : String, b : String }


fresh : String -> Task Error Scratch
fresh n =
    Task.succeed { a = n, b = n ++ "-b" }


stepScratch : Scratch -> Task Error ()
stepScratch s =
    Io.println s.a


step : String -> Task Error ()
step s =
    Io.println s


decideAfter : String -> (Scratch -> Task Error ()) -> (Scratch -> Task Error ()) -> Task Error { conflict : Bool, rows : Int }
decideAfter name prepare mutate =
    do
        at <- fresh name
        Io.println at.a
        prepare at
        r <- Task.succeed "r"
        mutate at
        Io.println r
        Task.succeed { conflict = True, rows = 1 }


decideLet : String -> (Scratch -> Task Error ()) -> Task Error String
decideLet name mutate =
    let
        prepare =
            \s -> Io.println s.b
    in
    do
        at <- fresh name
        Io.println at.a
        prepare at
        r <- Task.succeed "r"
        mutate at
        Io.println r
        Task.succeed "let"


decideAlias : String -> Task Error String
decideAlias name =
    let
        prepare =
            stepScratch
    in
    do
        at <- fresh name
        Io.println at.b
        prepare at
        Task.succeed "alias"


go : String -> (String -> Task Error ()) -> Task Error ()
go name mutate =
    do
        at <- Task.succeed "x"
        Io.println at
        Io.println name
        r <- Task.succeed "r"
        mutate r


twice : (String -> Task Error ()) -> Task Error ()
twice prepare =
    do
        at <- Task.succeed "x"
        Io.println "a"
        prepare at
        Task.succeed ()


twiceBind : (String -> Task Error ()) -> Task Error ()
twiceBind prepare =
    do
        at <- Task.succeed "x"
        Io.println "a"
        prepare at
        r <- Task.succeed "r"
        Io.println r


useOnce : (String -> Task Error ()) -> Task Error ()
useOnce h =
    h "use"


effectLambda : (String -> Task Error ()) -> Task Error ()
effectLambda f =
    do
        Task.andThen (\y -> f y) (Task.succeed "e")
        f "rest"


effectMoves : (String -> Task Error ()) -> Task Error ()
effectMoves f =
    do
        Io.println "m"
        useOnce f
        f "rest"


moveThenCall : (String -> Task Error ()) -> Task Error ()
moveThenCall f =
    Task.map2 (\_ _ -> ()) (useOnce f) (f "second")


aliasParam : (String -> Task Error ()) -> Task Error ()
aliasParam f =
    let
        g =
            f
    in
    do
        at <- Task.succeed "ax"
        Io.println "a"
        g at
        r <- Task.succeed "ar"
        Io.println r


aliasNested : (String -> Task Error ()) -> List String -> Task Error ()
aliasNested f xs =
    let
        g =
            f
    in
    Task.map (\_ -> ()) (Task.sequence (List.map (\x -> Task.andThen (\y -> g y) (Task.succeed x)) xs))


runAll : Task Error () -> Task Error ()
runAll t =
    do
        Io.println "top-a"
        Io.println "top-b"
        t


main : Task Error ()
main =
    do
        d <- decideAfter "n" stepScratch stepScratch
        Io.println (String.fromInt d.rows)
        l <- decideLet "m" stepScratch
        Io.println l
        k <- decideAlias "k"
        Io.println k
        go "g" step
        twice step
        twiceBind step
        runAll (Io.println "top-c")
        effectLambda step
        effectMoves step
        moveThenCall step
        aliasParam step
        aliasNested step [ "n1", "n2" ]
"#;

/// The lines [`ACCEPTED`] prints, in order.
const ACCEPTED_STDOUT: &str = "n\nn\nn\nr\n1\nm\nm-b\nm\nr\nlet\nk-b\nk\nalias\nx\ng\nr\na\nx\na\nx\nr\ntop-a\ntop-b\ntop-c\ne\nrest\nm\nuse\nrest\nuse\nsecond\na\nax\nar\nn1\nn2\n";

/// A destructure-bound function called in a continuation inside a `List.map` callback.
const DESTRUCTURED: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.List as List
import Ipe.Task as Task


step : String -> Task Error ()
step s =
    Io.println s


go : ( String -> Task Error (), Int ) -> List String -> Task Error ()
go pair xs =
    let
        ( prepare, _ ) =
            pair
    in
    Task.map (\_ -> ())
        (Task.sequence
            (List.map
                (\x ->
                    do
                        Io.println x
                        prepare x
                )
                xs
            )
        )


main : Task Error ()
main =
    go ( step, 1 ) [ "a", "b" ]
"#;

/// Record fields read in callbacks and continuations, each shape built and run.
const FIELDS: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.List as List
import Ipe.Task as Task


type alias Job =
    { f : String -> Task Error () }


type alias TaskJob =
    { t : Task Error () }


step : String -> Task Error ()
step s =
    Io.println s


runAll : Job -> List String -> List (Task Error ())
runAll job xs =
    List.map (\x -> job.f x) xs


go : Job -> (String -> Task Error ()) -> Task Error ()
go job mutate =
    do
        at <- Task.succeed "x"
        Io.println at
        job.f at
        r <- Task.succeed "r"
        mutate r


goTask : TaskJob -> (String -> Task Error ()) -> Task Error ()
goTask job mutate =
    do
        at <- Task.succeed "y"
        Io.println at
        job.t
        r <- Task.succeed "s"
        mutate r


main : Task Error ()
main =
    do
        Task.map (\_ -> ()) (Task.sequence (runAll { f = step } [ "a", "b" ]))
        go { f = step } step
        goTask { t = Io.println "t" } step
"#;

/// The lines [`FIELDS`] prints, in order.
const FIELDS_STDOUT: &str = "a\nb\nx\nx\nr\ny\nt\ns\n";

/// A `Task` field read straight from a `List.map` callback.
const TASK_FIELD_IN_CALLBACK: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.Task as Task
import Ipe.List as List


type alias Job =
    { t : Task Error () }


run : Job -> List Int -> List (Task Error ())
run job xs =
    List.map (\_ -> job.t) xs


main =
    Task.sequence (run { t = Io.println "a" } [ 1, 2 ])
        |> Task.map (\_ -> ())
"#;

/// A `Task` field read in a continuation inside a `List.map` callback.
const TASK_FIELD_IN_CALLBACK_CONTINUATION: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.List as List
import Ipe.Task as Task


type alias Job =
    { t : Task Error () }


run : Job -> List String -> List (Task Error ())
run job xs =
    List.map
        (\x ->
            do
                Io.println x
                job.t
        )
        xs


main : Task Error ()
main =
    Task.sequence (run { t = Io.println "t" } [ "a", "b" ])
        |> Task.map (\_ -> ())
"#;

/// A `Maybe (Task ..)` field matched inside a `List.map` callback.
const MAYBE_TASK_FIELD_IN_CALLBACK: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.Task as Task
import Ipe.List as List


type alias Job =
    { m : Maybe (Task Error ()) }


run : Job -> List Int -> List (Task Error ())
run job xs =
    List.map
        (\_ ->
            case job.m of
                Just t ->
                    t

                Nothing ->
                    Task.succeed ()
        )
        xs


main =
    Task.sequence (run { m = Just (Io.println "a") } [ 1, 2 ])
        |> Task.map (\_ -> ())
"#;

/// A field holding a variant that wraps a `Task`, matched inside a `List.map` callback.
const VARIANT_FIELD_IN_CALLBACK: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.Task as Task
import Ipe.List as List


type Act
    = Act (Task Error ())


type alias Job =
    { a : Act }


run : Job -> List Int -> List (Task Error ())
run job xs =
    List.map
        (\_ ->
            case job.a of
                Act t ->
                    t
        )
        xs


main =
    Task.sequence (run { a = Act (Io.println "a") } [ 1, 2 ])
        |> Task.map (\_ -> ())
"#;

/// A captured variant that wraps a `Task`, matched inside a `List.map` callback.
const VARIANT_CAPTURE_IN_CALLBACK: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.Task as Task
import Ipe.List as List


type Act
    = Act (Task Error ())


run : Act -> List Int -> List (Task Error ())
run act xs =
    List.map
        (\_ ->
            case act of
                Act t ->
                    t
        )
        xs


main =
    Task.sequence (run (Act (Io.println "a")) [ 1, 2 ])
        |> Task.map (\_ -> ())
"#;

/// Build `source` as a one-module project fixture into a fresh out dir.
///
/// Returns the driver result and the out dir.
fn build(name: &str, source: &str) -> (Result<(), CliError>, PathBuf) {
    let fixture = crate::root_fixture::main(source);
    let out = crate::support::scratch_root().join(name);
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    (crate::root_fixture::build(&fixture, &out, &runtime), out)
}

/// The span of the last `needle` in `source`.
fn span_of(source: &str, needle: &str) -> Span {
    #[allow(clippy::expect_used)] // the needle is written into the source
    let lo = source.rfind(needle).expect("needle is in the source");
    #[allow(clippy::expect_used)] // the sources are far below 4 GiB
    let lo = u32::try_from(lo).expect("offset fits u32");
    #[allow(clippy::expect_used)] // the needle is a short identifier
    let len = u32::try_from(needle.len()).expect("needle length fits u32");
    Span {
        lo,
        hi: lo.saturating_add(len),
    }
}

/// The span of `capture` inside the last `context` in `source`.
fn span_in(source: &str, context: &str, capture: &str) -> Span {
    #[allow(clippy::expect_used)] // the context is written into the source
    let at = source.rfind(context).expect("context is in the source");
    #[allow(clippy::expect_used)] // the capture is written into its context
    let off = context.find(capture).expect("capture is in its context");
    #[allow(clippy::expect_used)] // the sources are far below 4 GiB
    let lo = u32::try_from(at.saturating_add(off)).expect("offset fits u32");
    #[allow(clippy::expect_used)] // the capture is a short identifier
    let len = u32::try_from(capture.len()).expect("capture length fits u32");
    Span {
        lo,
        hi: lo.saturating_add(len),
    }
}

/// `source` fails closed with IPE-L0126 at `capture` inside its `context`.
fn assert_refused_at(name: &str, source: &str, context: &str, capture: &str) {
    let (built, _) = build(name, source);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0126),
        "{name}: a move-only read out of a recalled callback must fail closed at ipe time, \
         got {built:?}"
    );
    let want = span_in(source, context, capture);
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
        "{name}: the refusal must name `{capture}` in `{context}` ({want:?}), got {built:?}"
    );
}

/// Every accepted shape passes ipe.
#[test]
fn continuation_captures_pass_ipe() {
    let (built, _) = build("fn_capture_boundary_accepted", ACCEPTED);
    assert!(
        built.is_ok(),
        "function captures in run-statement continuations must pass ipe: {:?}",
        built.err()
    );
}

/// cargo-0 and run-correct for every accepted shape: gated on `IPE_E2E=1` (THE SEAL).
#[test]
fn continuation_captures_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (built, out) = build("fn_capture_boundary_accepted_e2e", ACCEPTED);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );
    let outcome = crate::support::build_and_run_emitted("fn_capture_boundary_accepted", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the continuation captures must build and exit 0 (no E0507); stdout: {:?}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains(ACCEPTED_STDOUT),
        "must print every shape's lines in order; got: {:?}",
        outcome.stdout
    );
}

/// A destructure-bound function has no `Arc` carrier, so its call in the continuation refuses.
#[test]
fn destructure_bound_capture_in_a_continuation_is_refused_at_the_capture() {
    let (built, _) = build("fn_capture_boundary_destructured", DESTRUCTURED);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0126),
        "a continuation moving `prepare` out of a recalled callback must fail closed at ipe \
         time, got {built:?}"
    );
    let want = span_of(DESTRUCTURED, "prepare");
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
        "the refusal must name the call through `prepare` ({want:?}), got {built:?}"
    );
}

/// Every accepted field shape passes ipe.
#[test]
fn field_reads_pass_ipe() {
    let (built, _) = build("fn_capture_boundary_fields", FIELDS);
    assert!(
        built.is_ok(),
        "function fields in callbacks and top-level `Task` fields in continuations must \
         pass ipe: {:?}",
        built.err()
    );
}

/// cargo-0 and run-correct for every accepted field shape: gated on `IPE_E2E=1` (THE SEAL).
#[test]
fn field_reads_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (built, out) = build("fn_capture_boundary_fields_e2e", FIELDS);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );
    let outcome = crate::support::build_and_run_emitted("fn_capture_boundary_fields", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "the field reads must build and exit 0 (no E0507); stdout: {:?}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains(FIELDS_STDOUT),
        "must print every shape's lines in order; got: {:?}",
        outcome.stdout
    );
}

/// A `Task` field moved out of a `List.map` callback refuses at the record.
#[test]
fn task_field_in_a_callback_is_refused_at_the_record() {
    assert_refused_at(
        "fn_capture_boundary_task_field",
        TASK_FIELD_IN_CALLBACK,
        "job.t",
        "job",
    );
}

/// A `Task` field moved into a continuation inside a callback refuses at the record.
#[test]
fn task_field_in_a_callback_continuation_is_refused_at_the_record() {
    assert_refused_at(
        "fn_capture_boundary_task_field_continuation",
        TASK_FIELD_IN_CALLBACK_CONTINUATION,
        "job.t",
        "job",
    );
}

/// A `Maybe (Task ..)` field matched in a callback refuses at the record.
#[test]
fn maybe_task_field_in_a_callback_is_refused_at_the_record() {
    assert_refused_at(
        "fn_capture_boundary_maybe_task_field",
        MAYBE_TASK_FIELD_IN_CALLBACK,
        "job.m",
        "job",
    );
}

/// A field holding a `Task`-wrapping variant matched in a callback refuses at the record.
#[test]
fn variant_field_in_a_callback_is_refused_at_the_record() {
    assert_refused_at(
        "fn_capture_boundary_variant_field",
        VARIANT_FIELD_IN_CALLBACK,
        "job.a",
        "job",
    );
}

/// A captured `Task`-wrapping variant matched in a callback refuses at the capture.
#[test]
fn variant_capture_in_a_callback_is_refused_at_the_capture() {
    assert_refused_at(
        "fn_capture_boundary_variant_capture",
        VARIANT_CAPTURE_IN_CALLBACK,
        "case act",
        "act",
    );
}
