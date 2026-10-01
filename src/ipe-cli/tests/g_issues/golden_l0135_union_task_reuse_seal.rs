//! THE SEAL for a NON-`Clone` effect-carrier value reused non-linearly.
//!
//! A generic union derives `Clone where T: Clone`. Instantiating `T` to a
//! `Task`/`Cmd`/`Sub` (an opaque boxed future — never `Clone`) makes that bound
//! unsatisfiable, so reusing such a binding twice in a value-consuming position
//! cannot be lowered as a `.clone()`: the emitted crate fails `cargo build`
//! (E0382 use-after-move / E0277 missing-`Clone`) AFTER `ipe build` already
//! reported exit 0. That exit-0-then-cargo-fail hole is the exact SEAL break
//! `PRINCIPLES.md` forbids.
//!
//! The lowerer now fails closed on the non-linear reuse of an effect-carrier
//! value with IPE-L0135, so `ipe build` can never exit 0 with uncompilable Rust
//! for this shape.
//!
//! The gate is PARAM-scoped: a param's value arrives from the caller and cannot
//! be reconstructed, so its non-linear reuse has no sound rewrite. A `let`-bound
//! effect value is rescued instead — the backend inlines the value expression at
//! each use site, rebuilding an independent value per use — so a `let` reuse
//! still builds (the `let_task_reuse` control).
//!
//! | Fixture | Shape | Outcome |
//! |---|---|---|
//! | `union_task_reuse` | `Wrap (Task Error Int)` PARAM reused | fail-closed IPE-L0135 |
//! | `maybe_task_reuse` | `Maybe (Task Error Int)` PARAM reused | fail-closed IPE-L0135 |
//! | `union_int_reuse` | `Wrap Int` param reused (Clone control) | builds + prints `8` |
//! | `union_task_linear` | `Wrap (Task Error Int)` param used once | builds + prints `9` |
//! | `let_task_reuse` | `let` non-Clone `Task` list reused (inlined) | builds + prints `4` |
//!
//! The two negative fixtures assert the typed diagnostic at `ipe`-time (never a
//! cargo failure); the three positive fixtures prove the fix does not
//! over-reject — a `Clone` payload still round-trips, a single linear use of an
//! effect carrier is a bare move that builds, and a `let`-bound effect reuse is
//! rescued by backend inlining.
//!
//! ```text
//! # gate check only (fast):
//! cargo test -p ipe --test g_issues golden_l0135
//! # full (cargo build + run the two positive fixtures):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_l0135
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
        .join("l0135")
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
        .join("l0135-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert that `source` is REJECTED by `ipe` with `expected` (a typed pipeline
/// diagnostic), never accepted-then-cargo-failed. Runs without `IPE_E2E` — the
/// point is that emission never happens.
#[track_caller]
fn assert_rejected(name: &str, source: &str, expected: ipe_diagnostics::Code) {
    let entry = crate::support::expect_scratch_entry(name, write_single(name, source));
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            expected,
            "{name}: expected a fail-closed {expected:?}, got a different diagnostic"
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED a non-Clone effect-carrier reuse (exit 0) — the \
             emitted crate would fail cargo with E0382/E0277, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// Assert that `source` is ACCEPTED by `ipe` (exit 0) and — under `IPE_E2E` —
/// that the emitted crate `cargo build`s and runs to `expected_stdout`.
#[track_caller]
fn assert_accepted(name: &str, source: &str, expected_stdout: &str) {
    let entry = crate::support::expect_scratch_entry(name, write_single(name, source));
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build(&entry, &out, &runtime) {
        Ok(()) => {}
        Err(CliError::Pipeline { diag, .. }) => {
            assert!(
                false_marker(),
                "{name}: ipe REJECTED a well-formed program with {} — a false rejection",
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

    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return; // emit-only fast pass
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must run to exit 0"
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// A generic union `Wrap a` carrying a `Task Error Int` — the canonical
/// non-`Clone` payload — reused across two value-consuming positions. On the
/// merge base this was `ipe` exit 0 then cargo E0277/E0382; now IPE-L0135.
const UNION_TASK_REUSE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


type Wrap a = Wrap a


unwrap : Wrap a -> a
unwrap w =
    case w of
        Wrap x -> x


pair : Wrap (Task Error Int) -> ( Task Error Int, Task Error Int )
pair w =
    ( unwrap w, unwrap w )


main : Task Error ()
main =
    case pair (Wrap (Task.succeed 7)) of
        ( first, _ ) ->
            Task.andThen
                (\n -> Io.println (String.fromInt n))
                first
";

/// The composite path: a `Maybe (Task Error Int)` reused across two positions.
/// The effect carrier reached through a `Maybe` payload is equally non-`Clone`.
const MAYBE_TASK_REUSE: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.Task as Task


pair : Maybe (Task Error Int) -> ( Maybe (Task Error Int), Maybe (Task Error Int) )
pair mt =
    ( mt, mt )


main =
    Io.println "x"
"#;

/// Clone-able control: `Wrap Int` reused twice must STILL round-trip — the fix
/// rejects only genuinely non-`Clone` effect carriers, never a `Clone` payload.
const UNION_INT_REUSE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Wrap a = Wrap a


unwrap : Wrap a -> a
unwrap w =
    case w of
        Wrap x -> x


sumPair : Wrap Int -> Int
sumPair w =
    unwrap w + unwrap w


main =
    Io.println (String.fromInt (sumPair (Wrap 4)))
";

/// Linear control: `Wrap (Task Error Int)` used ONCE is a bare move — no clone
/// is needed and the crate must still build and run.
const UNION_TASK_LINEAR: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


type Wrap a = Wrap a


runOnce : Wrap (Task Error Int) -> Task Error ()
runOnce w =
    case w of
        Wrap task ->
            Task.andThen
                (\n -> Io.println (String.fromInt n))
                task


main : Task Error ()
main =
    runOnce (Wrap (Task.succeed 9))
";

/// `let`-scope control: a non-`Clone` `List (Task Error Int)` bound with `let`
/// and read at two sites. Unlike a param, a `let` value is a reconstructible
/// expression, so the backend inlines it at each use — the reuse builds and runs
/// rather than fails closed. Prints `4` (2 + 2).
const LET_TASK_REUSE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.List as List
import Ipe.Task as Task


main =
    let tasks = [ Task.succeed 1, Task.succeed 2 ] in
    let n1 = List.length tasks in
    let n2 = List.length tasks in
    Io.println (String.fromInt (n1 + n2))
";

#[test]
fn union_task_reuse_fails_closed() {
    assert_rejected(
        "union_task_reuse",
        UNION_TASK_REUSE,
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn maybe_task_reuse_fails_closed() {
    assert_rejected(
        "maybe_task_reuse",
        MAYBE_TASK_REUSE,
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn union_int_reuse_round_trips() {
    assert_accepted("union_int_reuse", UNION_INT_REUSE, "8");
}

#[test]
fn union_task_linear_round_trips() {
    assert_accepted("union_task_linear", UNION_TASK_LINEAR, "9");
}

#[test]
fn let_task_reuse_round_trips() {
    assert_accepted("let_task_reuse", LET_TASK_REUSE, "4");
}
