//! A function capture read in a run-statement continuation keeps a sound carrier.
//!
//! A `do` block's run statement lowers to a `TaskSeq` whose continuation the
//! backend wraps in a `move |_|` closure for the runtime's `FnOnce`
//! `task_and_then` slot. Inside a `Recallable` closure (the `\at ->` a bind
//! statement builds), that hidden closure moves each capture out of the
//! enclosing environment on every call. A promotable function binder there is
//! moved onto the `Clone` `Arc` carrier; a non-promotable one (bound by a tuple
//! destructure) is refused with IPE-L0126 at its use, before cargo can fail on
//! a `Box<dyn Fn>` moved out of a `Fn` closure (E0507).
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

/// A destructure-bound function called in a continuation inside the bind's lambda.
const DESTRUCTURED: &str = r#"module Main exposing (main)

import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io
import Ipe.Task as Task


step : String -> Task Error ()
step s =
    Io.println s


go : ( String -> Task Error (), Int ) -> (String -> Task Error ()) -> Task Error ()
go pair mutate =
    let
        ( prepare, _ ) =
            pair
    in
    do
        at <- Task.succeed "x"
        Io.println at
        prepare at
        r <- Task.succeed "r"
        mutate r


main : Task Error ()
main =
    go ( step, 1 ) step
"#;

/// Write `source` as a one-file program and return its entry and output dir.
#[allow(clippy::expect_used)] // an unwritable scratch dir is the test failure
fn write_program(name: &str, source: &str) -> (PathBuf, PathBuf) {
    let dir = crate::support::scratch_root().join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the fixture scratch dir must be writable");
    let entry = dir.join("Main.ipe");
    std::fs::write(&entry, source).expect("the fixture scratch dir must be writable");
    (entry, dir.join("out"))
}

fn build(name: &str, source: &str) -> (Result<(), CliError>, PathBuf) {
    let (entry, out) = write_program(name, source);
    let runtime = e2e_support::require_runtime().into_path_buf();
    (ipe::build(&entry, &out, &runtime), out)
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
        "a continuation moving `prepare` out of the bind's lambda must fail closed at ipe time, \
         got {built:?}"
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
