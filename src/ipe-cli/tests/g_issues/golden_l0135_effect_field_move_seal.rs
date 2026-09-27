//! THE SEAL for a bare field read whose type embeds a non-`Clone` effect
//! carrier (`Task` / `Cmd` / `Sub`).
//!
//! The runtime effect carriers have no `Clone` impl, so a field read of one
//! cannot be served as `(base).field.clone()` (cargo E0599). The emitter moves
//! the field out of the base instead, and the lowerer's `IPE-L0135` gate admits
//! that move only where it is linear: a second read of the same field, or a
//! later use of the whole record, is refused at `ipe` time. A row-generic base
//! reads its fields through a borrowing witness getter, so a row field of an
//! effect-carrier type is refused outright.
//!
//! | Fixture | Shape | Outcome |
//! |---|---|---|
//! | `field_read_returns_task` | `getJob r = r.job` | builds + prints `7` |
//! | `task_field_then_other_field` | `both r.job r.tag` | builds + prints `10` |
//! | `other_field_then_task_field` | `tagFirst r.tag r.job` | builds + prints `10` |
//! | `task_field_read_twice` | `withLists r.job (Task.sequence [ r.job ]) ..` | fail-closed IPE-L0135 |
//! | `task_field_then_whole_record` | `both r.job (tagOf r)` | fail-closed IPE-L0135 |
//! | `row_generic_task_field` | `{ r \| job : Task Error Int } -> ..` | fail-closed IPE-L0135 |
//!
//! ```text
//! # gate check only (fast):
//! cargo test -p ipe --test g_issues golden_l0135_effect_field_move
//! # full (cargo build + run the positive fixtures):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_l0135_effect_field_move
//! ```

use std::path::PathBuf;

use ipe::CliError;

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(), …)`
/// reads as a deliberate unconditional failure.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// Write `source` as a single-file `Main.ipe` under a fresh scratch dir.
fn write_single(name: &str, source: &str) -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("l0135-effect-field-move")
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
        .join("l0135-effect-field-move-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert that `source` is REJECTED by `ipe` with `expected`.
#[track_caller]
fn assert_rejected(name: &str, source: &str, expected: ipe_diagnostics::Code) {
    let entry = crate::support::expect_scratch_entry(name, write_single(name, source));
    let out = out_dir(name);
    let runtime = crate::support::expect_runtime(name, ipe::resolve_runtime());
    match ipe::build(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            expected,
            "{name}: expected a fail-closed {expected:?}, got a different diagnostic"
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED a non-linear read of a non-Clone effect-carrier \
             field (exit 0) — the emitted crate would fail cargo, a SEAL break"
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
    let runtime = crate::support::expect_runtime(name, ipe::resolve_runtime());
    match ipe::build(&entry, &out, &runtime) {
        Ok(()) => {}
        Err(CliError::Pipeline { diag, .. }) => {
            assert!(
                false_marker(),
                "{name}: ipe REJECTED a linear effect-carrier field read with {}",
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
        "{name}: emitted crate must run to exit 0"
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// The shared prelude: `both` / `tagFirst` sequence an effect with an `Int`,
/// differing only in parameter order; `tagOf` reads the whole record.
const PRELUDE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


both : Task Error Int -> Int -> Task Error ()
both task n =
    Task.andThen
        (\x -> Io.println (String.fromInt (x + n)))
        task


tagFirst : Int -> Task Error Int -> Task Error ()
tagFirst n task =
    both task n


tagOf : { job : Task Error Int, tag : Int } -> Int
tagOf r =
    case r of
        { tag } ->
            tag


withLists : Task Error Int -> Task Error (List Int) -> Task Error (List Int) -> Task Error ()
withLists task first second =
    both task 0
";

/// The bare field read returning the `Task` itself.
const FIELD_READ_RETURNS_TASK: &str = r"

getJob : { job : Task Error Int, tag : Int } -> Task Error Int
getJob r =
    r.job


main : Task Error ()
main =
    Task.andThen
        (\x -> Io.println (String.fromInt x))
        (getJob { job = Task.succeed 7, tag = 3 })
";

/// The `Task` field moved, then a disjoint field read.
const TASK_FIELD_THEN_OTHER_FIELD: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run r =
    both r.job r.tag


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// A disjoint field read, then the `Task` field moved.
const OTHER_FIELD_THEN_TASK_FIELD: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run r =
    tagFirst r.tag r.job


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// The same `Task` field read twice: the second read observes a moved field.
const TASK_FIELD_READ_TWICE: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run r =
    withLists r.job (Task.sequence [ r.job ]) (Task.sequence [])


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// The `Task` field moved, then the whole (partially moved) record used.
const TASK_FIELD_THEN_WHOLE_RECORD: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run r =
    both r.job (tagOf r)


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// A row-generic record whose `Task` field would be read through a borrowing
/// witness getter.
const ROW_GENERIC_TASK_FIELD: &str = r"

getJob : { r | job : Task Error Int } -> Task Error Int
getJob rec =
    rec.job


main : Task Error ()
main =
    Task.andThen
        (\x -> Io.println (String.fromInt x))
        (getJob { job = Task.succeed 7, tag = 3 })
";

fn program(body: &str) -> String {
    format!("{PRELUDE}{body}")
}

#[test]
fn field_read_returns_task_builds() {
    assert_accepted(
        "field_read_returns_task",
        &program(FIELD_READ_RETURNS_TASK),
        "7",
    );
}

#[test]
fn task_field_then_other_field_builds() {
    assert_accepted(
        "task_field_then_other_field",
        &program(TASK_FIELD_THEN_OTHER_FIELD),
        "10",
    );
}

#[test]
fn other_field_then_task_field_builds() {
    assert_accepted(
        "other_field_then_task_field",
        &program(OTHER_FIELD_THEN_TASK_FIELD),
        "10",
    );
}

#[test]
fn task_field_read_twice_fails_closed() {
    assert_rejected(
        "task_field_read_twice",
        &program(TASK_FIELD_READ_TWICE),
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn task_field_then_whole_record_fails_closed() {
    assert_rejected(
        "task_field_then_whole_record",
        &program(TASK_FIELD_THEN_WHOLE_RECORD),
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn row_generic_task_field_fails_closed() {
    assert_rejected(
        "row_generic_task_field",
        &program(ROW_GENERIC_TASK_FIELD),
        ipe_diagnostics::IPE_L0135,
    );
}
