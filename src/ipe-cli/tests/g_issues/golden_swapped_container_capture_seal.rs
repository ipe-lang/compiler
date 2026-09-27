//! THE SEAL for a container-first kernel whose function argument captures a
//! binding the container expression also consumes by value.
//!
//! `Maybe.map f m`, `Result.andThen f r`, … render container-first in the
//! runtime (`ipe_maybe_map(m, f)`). Rust evaluates arguments left-to-right, so
//! the container runs BEFORE `f`'s closure is built: a non-Copy binding the
//! container moves (`label` passed by value into `wrapJust label`) is gone when
//! the closure's `let label = label.clone()` capture reads it — `ipe build`
//! exit 0, then `cargo build` E0382. The lowerer's last-use clone rewrite walks
//! every kernel `StdlibKernel::swaps_first_two` reverses in that evaluation
//! order, so the container's read is the one cloned and the closure's capture
//! the last, bare use.
//!
//! | Kernel | Shape | Contribution |
//! |---|---|---|
//! | `Maybe.map` | `Maybe.map (\v -> v ++ label) (wrapJust label)` | `aa` |
//! | `Maybe.andThen` | `Maybe.andThen (\v -> Just (v ++ label)) (wrapJust label)` | `bb` |
//! | `Result.map` | `Result.map (\v -> v ++ label) (wrapOk label)` | `cc` |
//! | `Result.andThen` | `Result.andThen (\v -> Ok (v ++ label)) (wrapOk label)` | `dd` |
//! | `Result.mapError` | `Result.mapError (\e -> e ++ label) (wrapErr label)` | `ee` |
//! | `Maybe.andThen`, fn param | `Maybe.andThen f (f s)` | `hhh` |
//! | `Maybe.map`, fn param | `Maybe.map (\x -> f x) (wrapJust (f s))` | `iii` |
//! | `Task.andThen`, fn param | `Task.andThen (\x -> f x) (f s)` | printed last: `jjj` |
//! | container binder shadows | `Maybe.map (\v -> v ++ label) (case wrapJust label of Just label -> …)` | `k!k` |
//! | non-`Clone` field receiver | `Maybe.map (mkF j) (wrapJust j.name)`, `j` holds a `Task` | `mm` |
//! | field-access callee | `Maybe.map (fmtWith fmt) (wrapJust (fmt.run fmt.name))` | `pqp` |
//! | lambda inside the container | `Maybe.map (\v -> v ++ label) (List.head (List.map (\y -> y ++ label) xs))` | `nnn` |
//!
//! The function-parameter, field-receiver and field-callee rows pin the
//! borrowing positions: a direct callee `f s`, a field read `j.name`, and a
//! field call `fmt.run …` borrow their receiver, so none may become a
//! `.clone()` of a value whose type has no `Clone` (E0599). The shadow row pins
//! that a container binder rebinding the captured name is not rewritten; the
//! container-lambda row pins that a closure built inside the container is the
//! EARLIER use, so it is the one given a clone.
//!
//! ```text
//! # emit check only (fast):
//! cargo test -p ipe --test g_issues golden_swapped_container_capture
//! # full (cargo build + run):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_swapped_container_capture
//! ```

use std::path::PathBuf;

use ipe::CliError;

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(), …)`
/// reads as a deliberate unconditional failure rather than a suspicious constant
/// condition.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// Write `source` as a single-file `Main.ipe` under a fresh scratch dir keyed by
/// `name`, returning the entry path (or `None` if scratch setup fails).
fn write_single(name: &str, source: &str) -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("swapped-container-capture")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(&src).ok()?;
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, source).ok()?;
    Some(entry)
}

/// The scratch output dir for `name`, cleared.
fn out_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("swapped-container-capture-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert that `source` is ACCEPTED by `ipe` (exit 0) and — under `IPE_E2E` —
/// that the emitted crate `cargo build`s and runs to `expected_stdout`.
#[track_caller]
fn assert_accepted(name: &str, source: &str, expected_stdout: &str) {
    let Some(entry) = write_single(name, source) else {
        assert!(
            false_marker(),
            "{name}: could not write the fixture into the scratch dir"
        );
        return;
    };
    let out = out_dir(name);
    let runtime = match ipe::resolve_runtime() {
        Ok(runtime) => runtime,
        Err(err) => {
            assert!(
                false_marker(),
                "{name}: the embedded runtime could not be resolved: {err:?}"
            );
            return;
        }
    };
    match ipe::build(&entry, &out, &runtime) {
        Ok(()) => {}
        Err(CliError::Pipeline { diag, .. }) => {
            assert!(
                false_marker(),
                "{name}: ipe REJECTED a well-formed program with {}",
                diag.code().as_str()
            );
            return;
        }
        Err(other) => {
            assert!(
                false_marker(),
                "{name}: non-pipeline build error: {other:?}"
            );
            return;
        }
    }

    if std::env::var("IPE_E2E").is_err() {
        return; // emit-only fast pass
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must cargo-build (THE SEAL) and run to exit 0"
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// Every Ipê-callable container-first `Maybe`/`Result` kernel, each with a
/// function argument that captures the `String` its container moves, plus the
/// borrowing-position (callee, field receiver, field callee), shadowed-binder
/// and container-lambda shapes.
const SWAPPED_CONTAINER_CAPTURE: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.List as List
import Ipe.Maybe as Maybe
import Ipe.Result as Result
import Ipe.String as String
import Ipe.Task as Task


type alias Job =
    { name : String, job : Task Error () }


type alias Fmt =
    { name : String, run : String -> String }


wrapJust : String -> Maybe String
wrapJust s =
    Just s


suffixWith : String -> String -> String
suffixWith s v =
    v ++ s


mkF : Job -> (String -> String)
mkF j =
    suffixWith j.name


fmtWith : Fmt -> String -> String
fmtWith fmt v =
    v ++ fmt.name


wrapOk : String -> Result String String
wrapOk s =
    Ok s


wrapErr : String -> Result String String
wrapErr s =
    Err s


errOr : String -> Result String String -> String
errOr fallback r =
    case r of
        Ok _ ->
            fallback

        Err e ->
            e


maybeMap : String -> Maybe String
maybeMap label =
    Maybe.map (\v -> v ++ label) (wrapJust label)


maybeAndThen : String -> Maybe String
maybeAndThen label =
    Maybe.andThen (\v -> Just (v ++ label)) (wrapJust label)


resultMap : String -> Result String String
resultMap label =
    Result.map (\v -> v ++ label) (wrapOk label)


resultAndThen : String -> Result String String
resultAndThen label =
    Result.andThen (\v -> Ok (v ++ label)) (wrapOk label)


resultMapError : String -> Result String String
resultMapError label =
    Result.mapError (\e -> e ++ label) (wrapErr label)


andThenFnParam : (String -> Maybe String) -> String -> Maybe String
andThenFnParam f s =
    Maybe.andThen f (f s)


mapFnParam : (String -> String) -> String -> Maybe String
mapFnParam f s =
    Maybe.map (\x -> f x) (wrapJust (f s))


taskFnParam : (String -> Task Error String) -> String -> Task Error String
taskFnParam f s =
    Task.andThen (\x -> f x) (f s)


jobLabel : Job -> Maybe String
jobLabel j =
    Maybe.map (mkF j) (wrapJust j.name)


fieldCallee : Fmt -> Maybe String
fieldCallee fmt =
    Maybe.map (fmtWith fmt) (wrapJust (fmt.run fmt.name))


containerLambda : String -> List String -> Maybe String
containerLambda label xs =
    Maybe.map (\v -> v ++ label) (List.head (List.map (\y -> y ++ label) xs))


shadowedBinder : String -> Maybe String
shadowedBinder label =
    Maybe.map
        (\v -> v ++ label)
        (case wrapJust label of
            Just label ->
                Just (label ++ "!")

            Nothing ->
                Nothing
        )


main : Task Error ()
main =
    Task.andThen
        (\t ->
            Io.println
                (String.join ","
                    [ Maybe.withDefault "none" (maybeMap "a")
                    , Maybe.withDefault "none" (maybeAndThen "b")
                    , Result.withDefault "err" (resultMap "c")
                    , Result.withDefault "err" (resultAndThen "d")
                    , errOr "ok" (resultMapError "e")
                    , Maybe.withDefault "none" (andThenFnParam (\v -> Just (v ++ "h")) "h")
                    , Maybe.withDefault "none" (mapFnParam (\v -> v ++ "i") "i")
                    , Maybe.withDefault "none" (shadowedBinder "k")
                    , Maybe.withDefault "none" (jobLabel { name = "m", job = Task.succeed () })
                    , Maybe.withDefault "none" (fieldCallee { name = "p", run = \v -> v ++ "q" })
                    , Maybe.withDefault "none" (containerLambda "n" [ "n" ])
                    , t
                    ]
                )
        )
        (taskFnParam (\v -> Task.succeed (v ++ "j")) "j")
"#;

#[test]
fn swapped_container_capture_builds() {
    assert_accepted(
        "swapped_container_capture",
        SWAPPED_CONTAINER_CAPTURE,
        "aa,bb,cc,dd,ee,hhh,iii,k!k,mm,pqp,nnn,jjj",
    );
}
