//! THE SEAL for a non-`Clone` effect-carrier value whose second move is HIDDEN
//! inside an `Access`/`Update` record BASE.
//!
//! The reuse gate counts genuine moves of a binding via `count_value_consumes`.
//! A field read `(rec).field` and a record update `{ rec | .. }` emit a BORROW of
//! the base, so a bare `sym` base is correctly not a move. But a COMPOUND base —
//! `(mk sym).field`, `{ mk sym | .. }` — MOVES `sym` into its sub-expression, a
//! genuine consume. The base scan previously skipped the base entirely, so a
//! move there counted as 0: a non-`Clone` effect carrier reused once-in-a-base
//! plus once-elsewhere saw only ONE consume, passed the reuse gate, and emitted a
//! `.clone()` on a non-`Clone` type — `ipe build` exit 0 then `cargo build` E0382,
//! the exact accept-then-cargo-fail hole `PRINCIPLES.md` forbids.
//!
//! The base is now scanned for moves unless it is exactly a bare
//! `Var(sym)`/`CloneVar(sym)` (the borrow-only field position the `IPE-L0120`
//! admissibility gate owns), so the hidden second move is counted and the reuse
//! fails closed with IPE-L0135.
//!
//! | Fixture | Shape | Outcome |
//! |---|---|---|
//! | `access_base_move_reuse` | `w` moved in `(idRec w).tag` base + tuple slot | fail-closed IPE-L0135 |
//! | `access_base_move_linear` | `w` moved ONCE via `(idRec w).tag` base | builds + prints `3` |
//!
//! The negative fixture asserts the typed diagnostic at `ipe`-time; the positive
//! fixture is the over-rejection guard — a single move hidden in a base is still
//! linear and must build, so the fix must not wrongly reject it. A bare `sym`
//! base staying uncounted (the `IPE-L0120` admissibility position) is proven by
//! a direct-IR unit test in `ipe_lower`, which also covers the `Update`-base
//! analogue — not expressible in surface syntax, whose `{ base | .. }` requires a
//! bare variable base.
//!
//! ```text
//! # gate check only (fast):
//! cargo test -p ipe --test g_issues golden_l0135_access_base
//! # full (cargo build + run the positive fixtures):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_l0135_access_base
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
        .join("l0135-access-base")
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
        .join("l0135-access-base-out")
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
    let runtime = crate::support::expect_runtime(name, ipe::resolve_runtime());
    match ipe::build(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            expected,
            "{name}: expected a fail-closed {expected:?}, got a different diagnostic"
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED a non-Clone effect-carrier reuse (exit 0) whose \
             second move hid in an Access/Update base — the emitted crate would fail \
             cargo with E0382, a SEAL break"
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
                 (the over-rejection guard: a single base move is linear, and a bare-base \
                 field borrow is not a move)",
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

/// The `Access`-base hole: a `{ job : Task Error Int, tag : Int }` PARAM (non-
/// `Clone` — the record embeds a `Task`) whose second move hides in an `Access`
/// base. `w` moves into `idRec` in the `(idRec w).tag` base AND is moved again in
/// the tuple's second slot — two consumes. On the merge base the base move was
/// counted 0, so the gate saw ONE consume, accepted, and cargo-failed E0382; now
/// IPE-L0135.
const ACCESS_BASE_MOVE_REUSE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


idRec : { job : Task Error Int, tag : Int } -> { job : Task Error Int, tag : Int }
idRec r =
    r


pick : { job : Task Error Int, tag : Int } -> ( Int, { job : Task Error Int, tag : Int } )
pick w =
    ( (idRec w).tag, w )


main : Task Error ()
main =
    case pick { job = Task.succeed 7, tag = 3 } of
        ( t, { job } ) ->
            Task.andThen
                (\n -> Io.println (String.fromInt (n + t)))
                job
";

/// Over-rejection guard: a SINGLE move hidden in an `Access` base is linear —
/// the non-`Clone` effect-carrier record `w` is consumed once (into `idRec`) and
/// never reused — so it must NOT be miscounted as a reuse and rejected. Reading
/// the `Int` `tag` off the moved-in result is `Copy`, so the whole program
/// builds and runs. Prints `3`.
const ACCESS_BASE_MOVE_LINEAR: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


idRec : { job : Task Error Int, tag : Int } -> { job : Task Error Int, tag : Int }
idRec r =
    r


pickTag : { job : Task Error Int, tag : Int } -> Int
pickTag w =
    (idRec w).tag


main : Task Error ()
main =
    Io.println (String.fromInt (pickTag { job = Task.succeed 7, tag = 3 }))
";

#[test]
fn access_base_move_reuse_fails_closed() {
    assert_rejected(
        "access_base_move_reuse",
        ACCESS_BASE_MOVE_REUSE,
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn access_base_move_linear_round_trips() {
    assert_accepted("access_base_move_linear", ACCESS_BASE_MOVE_LINEAR, "3");
}
