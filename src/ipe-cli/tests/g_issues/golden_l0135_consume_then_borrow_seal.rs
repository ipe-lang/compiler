//! THE SEAL for a non-`Clone` effect-carrier record whose field is read AFTER
//! the record was moved.
//!
//! The reuse gate counts a bare field read `w.tag` as a borrow, not a consume,
//! so `run w = both (consume w) w.tag` sees ONE consume and would pass. But the
//! emitted call evaluates its arguments left to right: `consume(w)` moves `w`,
//! then `(w).tag` reads the moved value — `ipe build` exit 0, then `cargo build`
//! E0382. An order-aware walk now rejects a borrow evaluated after a move with
//! IPE-L0135, while the borrow-then-consume order stays accepted.
//!
//! | Fixture | Shape | Outcome |
//! |---|---|---|
//! | `consume_then_borrow_call` | `both (consume w) w.tag` | fail-closed IPE-L0135 |
//! | `consume_then_borrow_kernel` | `String.append (label w) (String.fromInt w.tag)` | fail-closed IPE-L0135 |
//! | `consume_then_inlined_let_borrow` | `let xs = [Task.succeed w.tag] in withLists (consume w) (Task.sequence xs) (Task.sequence xs)` | fail-closed IPE-L0135 |
//! | `borrow_then_consume_call` | `tagFirst w.tag (consume w)` | builds + prints `10` |
//! | `let_bound_borrow_then_consume` | `let t = w.tag in both (consume w) t` | builds + prints `10` |
//! | `seq_kernel_read_then_consume` | `do { Io.println (String.fromInt w.tag) ; both (consume w) 0 }` | fail-closed IPE-L0135 |
//! | `and_then_kernel_read_then_consume` | `Task.andThen (\x -> both (consume w) x) (Task.succeed w.tag)` | fail-closed IPE-L0126 |
//! | `let_bound_seq_kernel_read` | `let w = mk n in do { .. w.tag .. ; both (consume w) 0 }` | fail-closed IPE-L0135 |
//! | `destructured_seq_kernel_read` | `let (w, _) = pair n in do { .. w.tag .. ; both (consume w) 0 }` | fail-closed IPE-L0135 |
//! | `partial_move_then_same_field` | `case w of { job } -> withLists job (Task.sequence [ w.job ]) ..` | fail-closed IPE-L0135 |
//! | `seq_user_arg_read_then_consume` | `do { x <- tagTask w.tag ; both (consume w) x }` | fail-closed IPE-L0126 |
//! | `seq_user_statement_read_then_consume` | `do { announce w.tag ; both (consume w) 0 }` | builds + prints `3`, `7` |
//!
//! A kernel call's argument order is chosen by its emitter, so a move and a
//! read of the same record in sibling kernel arguments are rejected in either
//! written order; binding the field with `let` first is the fix the diagnostic
//! names, proven by the last fixture. A multi-use `let` of a task list is
//! inlined by the emitter at each use site, so its value's reads of `w` happen
//! where the binding is used — after the move — and are rejected too.
//!
//! A sequenced task (a do-block statement or an explicit `Task.andThen`) whose
//! continuation still uses `w` makes the emitter clone every read of `w` in a
//! deferred position of the effect — a kernel argument may run inside a `move`
//! closure. A non-`Clone` record has no clone, so that shape is refused for
//! every binder form: a parameter, a `let`, and a destructured component. A
//! user function's arguments run eagerly, so the same read in a plain
//! statement only borrows and round-trips. A record pattern moves the fields it
//! binds, so reading one of them again through `w` is refused too.
//!
//! A continuation lambda (an explicit `Task.andThen` or a `<-` bind, which
//! desugars to one) that passes `w` to a call captures a non-`Clone` value in a
//! closure. The capture gate refuses that with IPE-L0126 while the lambda body
//! is lowered, before the parameter's reuse gate runs, whatever the effect
//! reads.
//!
//! ```text
//! # gate check only (fast):
//! cargo test -p ipe --test g_issues golden_l0135_consume_then_borrow
//! # full (cargo build + run the positive fixtures):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_l0135_consume_then_borrow
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
        .join("l0135-consume-borrow")
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
        .join("l0135-consume-borrow-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert that `source` is REJECTED by `ipe` with `expected` (a typed pipeline
/// diagnostic), never accepted-then-cargo-failed.
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
            "{name}: ipe ACCEPTED a field read of a non-Clone effect-carrier record \
             evaluated after the record was moved (exit 0) — the emitted crate would \
             fail cargo with E0382, a SEAL break"
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
                "{name}: ipe REJECTED a well-formed program with {} — a false rejection \
                 (a field read evaluated BEFORE the single move is sound)",
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

/// The shared prelude: `consume` moves the whole non-`Clone` record (its type
/// embeds a `Task`) and returns the effect; `both` / `tagFirst` sequence the
/// effect with an `Int`, differing only in parameter order.
const PRELUDE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


consume : { job : Task Error Int, tag : Int } -> Task Error Int
consume r =
    case r of
        { job } ->
            job


label : { job : Task Error Int, tag : Int } -> String
label r =
    case r of
        { tag } ->
            String.fromInt tag


both : Task Error Int -> Int -> Task Error ()
both task n =
    Task.andThen
        (\x -> Io.println (String.fromInt (x + n)))
        task


tagFirst : Int -> Task Error Int -> Task Error ()
tagFirst n task =
    both task n


withLists : Task Error Int -> Task Error (List Int) -> Task Error (List Int) -> Task Error ()
withLists task first second =
    both task 0
";

/// Consume-then-borrow in a user call: `consume w` moves `w`, then `w.tag`
/// reads it.
const CONSUME_THEN_BORROW_CALL: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run w =
    both (consume w) w.tag


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// Consume-then-borrow across sibling kernel arguments: `label w` moves `w`,
/// and `w.tag` reads it in the other argument.
const CONSUME_THEN_BORROW_KERNEL: &str = r"

describe : { job : Task Error Int, tag : Int } -> String
describe w =
    String.append (label w) (String.fromInt w.tag)


main : Task Error ()
main =
    Io.println (describe { job = Task.succeed 7, tag = 3 })
";

/// Consume-then-borrow through an inlined `let`: `xs` is a task list used
/// twice, so the emitter substitutes `[Task.succeed w.tag]` at both use sites,
/// after `consume w` has moved `w`.
const CONSUME_THEN_INLINED_LET_BORROW: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run w =
    let
        xs =
            [ Task.succeed w.tag ]
    in
    withLists (consume w) (Task.sequence xs) (Task.sequence xs)


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// Borrow-then-consume in a user call: `w.tag` is read while `w` is still
/// owned, then `consume w` moves it. Prints `10`.
const BORROW_THEN_CONSUME_CALL: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run w =
    tagFirst w.tag (consume w)


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// The documented fix: bind the field with `let` before the consuming call.
/// Prints `10`.
const LET_BOUND_BORROW_THEN_CONSUME: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run w =
    let
        t =
            w.tag
    in
    both (consume w) t


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// Helpers for the sequenced-task fixtures: `mk` builds the record from a
/// call (never a literal, so a `let` of it is a real Rust binder), `pair`
/// wraps it for a tuple destructure, and `tagTask` / `announce` are user
/// functions whose arguments the emitter evaluates eagerly.
const SEQ_HELPERS: &str = r"

mk : Int -> { job : Task Error Int, tag : Int }
mk n =
    { job = Task.succeed 7, tag = n }


pair : Int -> ( { job : Task Error Int, tag : Int }, Int )
pair n =
    ( mk n, n )


tagTask : Int -> Task Error Int
tagTask n =
    Task.succeed n


announce : Int -> Task Error ()
announce n =
    Io.println (String.fromInt n)
";

/// A do-block statement reads `w.tag` inside a kernel argument, then the rest
/// consumes `w`. The kernel argument may be deferred into a `move` closure, so
/// the emitter would rewrite the read to `w.clone()` for the rest to keep `w`
/// — no `Clone` impl exists.
const SEQ_KERNEL_READ_THEN_CONSUME: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run w =
    do
        Io.println (String.fromInt w.tag)
        both (consume w) 0


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// The same hazard through an explicit `Task.andThen` continuation. The
/// continuation captures `w` and passes it to `consume`, so the closure-capture
/// gate refuses it first (IPE-L0126).
const AND_THEN_KERNEL_READ_THEN_CONSUME: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run w =
    Task.andThen (\x -> both (consume w) x) (Task.succeed w.tag)


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// The do-block hazard on a `let`-bound record (a call result, so the `let`
/// is a real binder the gate must discipline).
const LET_BOUND_SEQ_KERNEL_READ: &str = r"

run : Int -> Task Error ()
run n =
    let
        w =
            mk n
    in
    do
        Io.println (String.fromInt w.tag)
        both (consume w) 0


main : Task Error ()
main =
    run 3
";

/// The do-block hazard on a record bound by a tuple destructure.
const DESTRUCTURED_SEQ_KERNEL_READ: &str = r"

run : Int -> Task Error ()
run n =
    let
        ( w, _ ) =
            pair n
    in
    do
        Io.println (String.fromInt w.tag)
        both (consume w) 0


main : Task Error ()
main =
    run 3
";

/// A record pattern moves `job` out of `w`; the arm then reads `w.job` again.
const PARTIAL_MOVE_THEN_SAME_FIELD: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run w =
    case w of
        { job } ->
            withLists job (Task.sequence [ w.job ]) (Task.succeed [])


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// A `<-` bind desugars to a `Task.andThen` continuation lambda; passing the
/// captured `w` to `consume` there is a non-`Clone` closure capture (IPE-L0126).
const SEQ_USER_ARG_READ_THEN_CONSUME: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run w =
    do
        x <- tagTask w.tag
        both (consume w) x


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

/// The eager borrow in a plain do-block statement. Prints `3` then `7`.
const SEQ_USER_STATEMENT_READ_THEN_CONSUME: &str = r"

run : { job : Task Error Int, tag : Int } -> Task Error ()
run w =
    do
        announce w.tag
        both (consume w) 0


main : Task Error ()
main =
    run { job = Task.succeed 7, tag = 3 }
";

fn seq_program(body: &str) -> String {
    format!("{PRELUDE}{SEQ_HELPERS}{body}")
}

fn program(body: &str) -> String {
    format!("{PRELUDE}{body}")
}

#[test]
fn consume_then_borrow_call_fails_closed() {
    assert_rejected(
        "consume_then_borrow_call",
        &program(CONSUME_THEN_BORROW_CALL),
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn consume_then_borrow_kernel_fails_closed() {
    assert_rejected(
        "consume_then_borrow_kernel",
        &program(CONSUME_THEN_BORROW_KERNEL),
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn consume_then_inlined_let_borrow_fails_closed() {
    assert_rejected(
        "consume_then_inlined_let_borrow",
        &program(CONSUME_THEN_INLINED_LET_BORROW),
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn borrow_then_consume_call_round_trips() {
    assert_accepted(
        "borrow_then_consume_call",
        &program(BORROW_THEN_CONSUME_CALL),
        "10",
    );
}

#[test]
fn let_bound_borrow_then_consume_round_trips() {
    assert_accepted(
        "let_bound_borrow_then_consume",
        &program(LET_BOUND_BORROW_THEN_CONSUME),
        "10",
    );
}

#[test]
fn seq_kernel_read_then_consume_fails_closed() {
    assert_rejected(
        "seq_kernel_read_then_consume",
        &seq_program(SEQ_KERNEL_READ_THEN_CONSUME),
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn and_then_kernel_read_then_consume_fails_closed() {
    assert_rejected(
        "and_then_kernel_read_then_consume",
        &seq_program(AND_THEN_KERNEL_READ_THEN_CONSUME),
        ipe_diagnostics::IPE_L0126,
    );
}

#[test]
fn let_bound_seq_kernel_read_fails_closed() {
    assert_rejected(
        "let_bound_seq_kernel_read",
        &seq_program(LET_BOUND_SEQ_KERNEL_READ),
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn destructured_seq_kernel_read_fails_closed() {
    assert_rejected(
        "destructured_seq_kernel_read",
        &seq_program(DESTRUCTURED_SEQ_KERNEL_READ),
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn partial_move_then_same_field_fails_closed() {
    assert_rejected(
        "partial_move_then_same_field",
        &seq_program(PARTIAL_MOVE_THEN_SAME_FIELD),
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn seq_user_arg_read_then_consume_capture_fails_closed() {
    assert_rejected(
        "seq_user_arg_read_then_consume",
        &seq_program(SEQ_USER_ARG_READ_THEN_CONSUME),
        ipe_diagnostics::IPE_L0126,
    );
}

#[test]
fn seq_user_statement_read_then_consume_round_trips() {
    assert_accepted(
        "seq_user_statement_read_then_consume",
        &seq_program(SEQ_USER_STATEMENT_READ_THEN_CONSUME),
        "3\n7",
    );
}
