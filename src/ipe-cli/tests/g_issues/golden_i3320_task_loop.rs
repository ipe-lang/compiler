//! SEAL tests for `Task.loop`, the bounded constant-stack step loop.
//!
//! | Fixture / source | Shape | Outcome |
//! |---|---|---|
//! | `task_loop` | 150,000-step counter, `do`-block step; then a ceiling hit | prints `150000`, then the typed limit error |
//! | `task_loop_recursive_control` | the same counter as a self-recursive `andThen` | exits nonzero with `RecursionLimit` |
//! | `task_loop_no_step_value` | a step that always fails, its `Step` result type never fixed | refused by `ipe`, IPE-L0102 |
//! | `task_loop_nonclone_capture` | a step capturing a `Task` parameter | refused by `ipe`, IPE-L0126 |
//! | `task_loop_shapes` | top-level fn, capturing lambda, partial `Task.loop 5`, `case` on `Step` | builds and runs |
//! | `task_loop_stored_step` | a step read from a record field and from a `case`-bound ADT payload, applied directly and piped | builds and runs |
//! | `task_loop_fn_state` | a loop state that is a function | refused by `ipe`, IPE-L0114 |
//! | `task_loop_parser_clash` | qualified `Parser.Done` beside `Task.Done` | builds and runs |
//! | inline sources | a `String` ceiling; a step that is not a `Step`; two unqualified `Step(..)` imports; a point-free loop at a function state | typed type / name / lowering errors |
//!
//! Every fixture is checked at `ipe` time here; under `IPE_E2E=1` the accepted
//! ones are also built with `cargo` and run (THE SEAL).
//!
//! ```text
//! cargo test -p ipe --test g_issues golden_i3320
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_i3320
//! ```

use std::path::{Path, PathBuf};

use ipe::CliError;
use ipe_diagnostics::{Code, Diagnostic, Family, Feature, LowerError};

use crate::support::repo_root;

fn fixture_entry(root: &Path, name: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

fn out_dir(name: &str) -> PathBuf {
    let out = crate::support::scratch_root().join(format!("ipec_i3320_{name}"));
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Build the fixture `name` with `ipe`, returning its emitted directory, or
/// failing the test when `ipe` rejects it.
#[track_caller]
fn accept_fixture(name: &str) -> PathBuf {
    let entry = fixture_entry(&repo_root(), name);
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{name}: ipe must accept the fixture; got {built:?}"
    );
    out
}

/// Build the fixture `name`, then (under `IPE_E2E=1`) `cargo build` and run it,
/// asserting exit 0 and `expected_stdout`.
#[track_caller]
fn accept_and_run(name: &str, expected_stdout: &str) {
    let out = accept_fixture(name);
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// The pipeline diagnostic `ipe` refuses `entry` with, failing the test when it
/// is accepted or fails outside the pipeline.
#[track_caller]
#[allow(clippy::expect_used)] // the code is asserted present just above the `expect`
fn refusal_code(name: &str, entry: &Path) -> Code {
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(entry, &out, &runtime);
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        Ok(()) | Err(_) => None,
    };
    assert!(
        code.is_some(),
        "{name}: ipe must refuse the program with a pipeline diagnostic; got {built:?}"
    );
    code.expect("asserted present above")
}

/// Write `source` as a single-file `Main.ipe` under a fresh scratch dir.
fn write_single(name: &str, source: &str) -> Option<PathBuf> {
    let dir = crate::support::scratch_root().join("i3320-src").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let entry = dir.join("Main.ipe");
    std::fs::write(&entry, source).ok()?;
    Some(entry)
}

/// Assert `ipe` refuses `entry` through the function-loop-state gate itself.
///
/// IPE-L0114 is shared with other unsupported-lowering refusals (a function
/// constructor payload among them), so the code alone does not pin the gate;
/// the `Feature` does.
#[track_caller]
fn assert_refused_as_function_state(name: &str, entry: &Path) {
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_L0114),
        "{name}: a function loop state must fail closed at ipe time with IPE-L0114, got {built:?}"
    );
    assert!(
        matches!(
            &built,
            Err(CliError::Pipeline { diag, .. })
                if matches!(
                    diag.as_ref(),
                    Diagnostic::Lower {
                        msg: LowerError::Unsupported(Feature::TaskLoopFunctionState),
                        ..
                    }
                )
        ),
        "{name}: the refusal must come from the Task.loop function-state gate, got {built:?}"
    );
}

#[test]
fn task_loop_runs_far_past_the_recursion_guard_and_reports_its_ceiling() {
    accept_and_run(
        "task_loop",
        "150000\nLimitExceeded: Task.loop ran its step 5 times, its ceiling, without reaching Done",
    );
}

/// The control: the self-recursive `andThen` counter at the same size trips the
/// recursion guard, which proves `task_loop`'s size is past the guard.
#[test]
fn self_recursive_and_then_at_the_same_size_trips_the_recursion_guard() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = accept_fixture("task_loop_recursive_control");
    let run =
        crate::support::build_and_run_emitted_capturing_stderr("task_loop_recursive_control", &out);
    assert!(
        run.exit_code.is_some_and(|code| code != 0),
        "the self-recursive counter must exit with a nonzero CODE (a guarded trip); \
         got {:?}\n--- stderr ---\n{}",
        run.exit_code,
        run.stderr
    );
    assert!(
        run.stderr.contains("RecursionLimit"),
        "stderr must carry the classified RecursionLimit kind\n--- stderr ---\n{}",
        run.stderr
    );
}

/// A step that only fails leaves the `Step`'s result type free; a lambda whose
/// return embeds a user type at a free parameter has no concrete Rust type, so
/// `ipe` refuses it with the polymorphism code rather than emitting a guess.
#[test]
fn a_step_whose_result_type_is_never_fixed_is_refused_at_ipe_time() {
    let name = "task_loop_no_step_value";
    let entry = fixture_entry(&repo_root(), name);
    let code = refusal_code(name, &entry);
    assert_eq!(
        code,
        ipe_diagnostics::IPE_L0102,
        "{name}: expected IPE-L0102, got {}",
        code.as_str()
    );
}

#[test]
fn a_step_capturing_a_task_is_refused_at_ipe_time() {
    let name = "task_loop_nonclone_capture";
    let entry = fixture_entry(&repo_root(), name);
    let code = refusal_code(name, &entry);
    assert_eq!(
        code,
        ipe_diagnostics::IPE_L0126,
        "{name}: expected IPE-L0126, got {}",
        code.as_str()
    );
}

/// A step read out of a record field and out of a `case`-bound user-ADT payload
/// is a stored function; each reaches `Task.loop`'s step slot, applied directly
/// and piped (`r.step |> Task.loop 5 0`, `Task.loop 5 0 <| f`), and runs.
#[test]
fn a_stored_step_from_a_record_field_or_adt_payload_builds_and_runs() {
    accept_and_run("task_loop_stored_step", "2\n2\n2\n2");
}

/// A loop state that is a function would sit on two carriers at once (the
/// direct `init` and the `Continue` payload), so `ipe` refuses it.
#[test]
fn a_function_typed_loop_state_is_refused_at_ipe_time() {
    let name = "task_loop_fn_state";
    let entry = fixture_entry(&repo_root(), name);
    assert_refused_as_function_state(name, &entry);
}

#[test]
fn every_step_shape_builds_and_runs() {
    accept_and_run("task_loop_shapes", "1\nloop2\n1\ncontinue 1\ndone 2");
}

#[test]
fn qualified_parser_and_task_steps_share_one_program() {
    accept_and_run("task_loop_parser_clash", "1\n7");
}

/// Refuse `source` and assert the diagnostic's family.
#[track_caller]
fn assert_refused_in_family(name: &str, source: &str, family: Family) {
    let entry = crate::support::expect_scratch_entry(name, write_single(name, source));
    let code = refusal_code(name, &entry);
    assert_eq!(
        code.family(),
        family,
        "{name}: expected a {family:?} diagnostic, got {}",
        code.as_str()
    );
}

const STRING_CEILING: &str = r#"module Main exposing (main)

import Ipe.Task as Task exposing (Step(..))
import Ipe.String as String
import Ipe.Io as Io


main =
    Task.loop "3" 0 (\n -> Task.succeed (Done n))
        |> Task.andThen (\n -> Io.println (String.fromInt n))
"#;

const NON_STEP_RESULT: &str = r"module Main exposing (main)

import Ipe.Task as Task
import Ipe.String as String
import Ipe.Io as Io


main =
    Task.loop 3 0 (\n -> Task.succeed n)
        |> Task.andThen (\n -> Io.println (String.fromInt n))
";

const TWO_UNQUALIFIED_STEPS: &str = r"module Main exposing (main)

import Ipe.Parser exposing (Step(..))
import Ipe.Task as Task exposing (Step(..))
import Ipe.String as String
import Ipe.Io as Io


main =
    Task.loop 3 0 (\n -> Task.succeed (Done n))
        |> Task.andThen (\n -> Io.println (String.fromInt n))
";

const POINT_FREE_FN_STATE: &str = r"module Main exposing (main)

import Ipe.Task as Task exposing (Step(..))
import Ipe.Error exposing (Error)
import Ipe.String as String
import Ipe.Io as Io


runWith : (Int -> (Int -> Int) -> ((Int -> Int) -> Task Error (Step (Int -> Int) Int)) -> Task Error Int) -> Task Error Int
runWith run =
    run 3 (\x -> x + 1) (\f -> Task.succeed (Done (f 0)))


main =
    runWith Task.loop
        |> Task.andThen (\n -> Io.println (String.fromInt n))
";

/// A point-free `Task.loop` instantiated at a function state is refused at the
/// reference itself, like the saturated call.
#[test]
fn a_point_free_loop_at_a_function_state_is_refused_at_ipe_time() {
    let name = "task_loop_point_free_fn_state";
    let entry = crate::support::expect_scratch_entry(name, write_single(name, POINT_FREE_FN_STATE));
    assert_refused_as_function_state(name, &entry);
}

#[test]
fn a_string_ceiling_is_a_type_error() {
    assert_refused_in_family("task_loop_string_ceiling", STRING_CEILING, Family::Type);
}

#[test]
fn a_step_that_returns_no_step_is_a_type_error() {
    assert_refused_in_family("task_loop_non_step_result", NON_STEP_RESULT, Family::Type);
}

/// Exposing `Step` unqualified from both `Ipe.Parser` and `Ipe.Task` brings two
/// distinct types under one name; the import itself is refused as a duplicate
/// type (IPE-N0012), before any constructor use is resolved.
#[test]
fn two_unqualified_step_imports_are_refused_as_a_duplicate_type() {
    let name = "task_loop_two_unqualified_steps";
    let entry =
        crate::support::expect_scratch_entry(name, write_single(name, TWO_UNQUALIFIED_STEPS));
    let code = refusal_code(name, &entry);
    assert_eq!(
        code,
        ipe_diagnostics::IPE_N0012,
        "{name}: expected IPE-N0012, got {}",
        code.as_str()
    );
}
