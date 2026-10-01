//! THE SEAL for a point-free / partially-applied accessor-typed `Store.*`
//! query leaf or column-spec builder.
//!
//! The accessor leaves (`Store.eq`, `Store.gt`, …) and spec builders
//! (`Store.serial`, `Store.primaryKey`, …) have NO runtime function: the
//! lowering accessor-intercept rewrites the SATURATED direct call inline (the
//! `.field` accessor becomes the validated column) before the backend names the
//! symbol. Their emit names (`store_eq_col`, `store_serial`, …) are never-defined
//! placeholders.
//!
//! A point-free (`List.map (Store.eq .qty) xs`) or fully-unapplied reference
//! (`eqBuilder = Store.eq`) routes AROUND the intercept — through
//! `eta_expand_partial` or the first-class-value reify path — and would emit the
//! raw placeholder call. Before the fix `ipe build` exited 0 and `cargo build`
//! failed E0425 (cannot find function `store_eq_col`), the accept-then-cargo
//! hole `PRINCIPLES.md` forbids.
//!
//! The fix fails such a program closed at `ipe` time with IPE-L0146, so the
//! invariant holds: `ipe` accepts ⇒ the emitted Rust builds. A store leaf used
//! DIRECTLY, or wrapped in a lambda that supplies the accessor
//! (`\age -> Store.eq .qty age`), still emits correct Rust — the over-rejection
//! guard.
//!
//! ```text
//! # gate check only (fast):
//! cargo test -p ipe --test g_issues golden_i1255_pointfree_store_kernel
//! # full (cargo build + run the positive fixture):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_i1255_pointfree_store_kernel
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
        .join("i1255-pointfree-store")
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
        .join("i1255-pointfree-store-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert that `source` is REJECTED by `ipe` with `expected` (a typed pipeline
/// diagnostic), never accepted-then-cargo-failed. Runs without `IPE_E2E` — the
/// point is that emission of the placeholder symbol never happens.
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
            "{name}: ipe ACCEPTED a point-free store-kernel use (exit 0) — the \
             emitted crate names a never-defined `store_*` placeholder and would \
             fail cargo with E0425, a SEAL break"
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
                "{name}: ipe REJECTED a well-formed program with {} — a false \
                 rejection (the over-rejection guard: a store leaf applied inside a \
                 lambda IS saturated, so the intercept fires and it must build)",
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

/// Point-free / partial application: `Store.eq .qty` (accessor supplied, value
/// NOT) is passed to `List.map`. Routes through `eta_expand_partial`, which
/// would emit the raw `store_eq_col` placeholder call. Fail-closed IPE-L0146.
const POINTFREE_PARTIAL: &str = r"module Main exposing (main)

import Ipe.Db.Store as Store exposing (Store)
import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String
import Ipe.Task as Task
import Ipe.Error as Error exposing (Error)


type alias Item =
    { qty : Int }


conds : List (Store.Cond Item)
conds =
    List.map (Store.eq .qty) [ 30, 9 ]


main : Task Error ()
main =
    Io.println (String.fromInt (List.length conds))
";

/// Fully-unapplied bare reference: `Store.eq` reified as a first-class function
/// VALUE. Routes through the reify path, which would emit `Box::new(store_eq_col)`.
/// Fail-closed IPE-L0146 (the reify twin of the partial-application gate).
const BARE_FUNC_VALUE: &str = r"module Main exposing (main)

import Ipe.Db.Store as Store exposing (Store)
import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String
import Ipe.Task as Task
import Ipe.Error as Error exposing (Error)


type alias Item =
    { qty : Int }


eqBuilder : (Item -> Int) -> Int -> Store.Cond Item
eqBuilder =
    Store.eq


conds : List (Store.Cond Item)
conds =
    List.map (eqBuilder .qty) [ 30, 9 ]


main : Task Error ()
main =
    Io.println (String.fromInt (List.length conds))
";

/// The diagnostic's suggested workaround (over-rejection guard): the store leaf
/// is applied DIRECTLY inside a lambda that supplies the accessor, so the
/// intercept fires on the saturated call and the program emits correct Rust.
/// Builds and prints `2` (two `Cond`s from the two-element list).
const LAMBDA_WRAPPED: &str = r"module Main exposing (main)

import Ipe.Db.Store as Store exposing (Store)
import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String
import Ipe.Task as Task
import Ipe.Error as Error exposing (Error)


type alias Item =
    { qty : Int }


conds : List (Store.Cond Item)
conds =
    List.map (\age -> Store.eq .qty age) [ 30, 9 ]


main : Task Error ()
main =
    Io.println (String.fromInt (List.length conds))
";

#[test]
fn pointfree_partial_store_kernel_fails_closed() {
    assert_rejected(
        "pointfree_partial",
        POINTFREE_PARTIAL,
        ipe_diagnostics::IPE_L0146,
    );
}

#[test]
fn bare_func_value_store_kernel_fails_closed() {
    assert_rejected(
        "bare_func_value",
        BARE_FUNC_VALUE,
        ipe_diagnostics::IPE_L0146,
    );
}

#[test]
fn lambda_wrapped_store_kernel_round_trips() {
    assert_accepted("lambda_wrapped", LAMBDA_WRAPPED, "2");
}
