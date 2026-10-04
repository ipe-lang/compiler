//! THE SEAL for a `Store.select` projection operator called outside its query.
//!
//! `Store.literal`, `Store.upper`, `Store.lower`, `Store.coalesce`, `Store.add`,
//! `Store.sub`, and `Store.mul` have no runtime function: `Store.select` reads
//! them structurally as projection elements and renders them into SQL. A call
//! to one anywhere else — saturated (`bump a b = Store.add a b`) or
//! over-applied (`Store.literal String.fromInt 5`, since `literal : t -> t`
//! admits a function argument) — would reach the uniform call path and emit the
//! never-defined placeholder symbol (`store_add`, …), so `ipe` would accept a
//! program `cargo` rejects with E0425.
//!
//! Each program here must be refused at `ipe` time with IPE-L0146 and the typed
//! `LowerError::AccessorKernelOffIntercept` naming the kernel, before any
//! `src/main.rs` is written. The partial and point-free shapes are pinned by
//! `golden_i1255_pointfree_store_kernel_seal`.
//!
//! ```text
//! cargo test -p ipe --test g_db golden_db_store_placeholder_off_intercept
//! ```

use std::path::PathBuf;

use ipe::CliError;
use ipe_diagnostics::{Diagnostic, LowerError};

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(), …)`
/// reads as a deliberate unconditional failure.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// Write `source` as `src/Main.ipe` under a fresh scratch dir keyed by `name`.
fn write_single(name: &str, source: &str) -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("store-placeholder-off-intercept")
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
        .join("store-placeholder-off-intercept-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert `source` is refused with IPE-L0146 naming `kernel`, and emits nothing.
#[track_caller]
fn assert_refused(name: &str, source: &str, kernel: &str) {
    let entry = crate::support::expect_scratch_entry(name, write_single(name, source));
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => {
            assert_eq!(
                diag.code(),
                ipe_diagnostics::IPE_L0146,
                "{name}: expected a fail-closed IPE-L0146, got {diag:?}"
            );
            assert!(
                matches!(
                    &*diag,
                    Diagnostic::Lower {
                        msg: LowerError::AccessorKernelOffIntercept { kernel: got, .. },
                        ..
                    } if &**got == kernel
                ),
                "{name}: expected the off-intercept refusal naming `{kernel}`, got {diag:?}"
            );
        }
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED `{kernel}` outside `Store.select` (exit 0) — the \
             emitted crate names a never-defined `store_*` placeholder and would \
             fail cargo with E0425, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
    assert!(
        !out.join("src").join("main.rs").exists(),
        "{name}: a refused program must emit no `src/main.rs`"
    );
}

/// A program whose top-level declarations are `decls`, printing `shown`.
fn program(decls: &str, shown: &str) -> String {
    format!(
        "module Main exposing (main)

import Ipe.Db.Store as Store exposing (Store)
import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task
import Ipe.Error as Error exposing (Error)


{decls}


main : Task Error ()
main =
    Io.println ({shown})
"
    )
}

/// A saturated `Store.add` inside a plain forwarding function is refused.
#[test]
fn add_in_plain_forwarder_is_refused() {
    let source = program(
        "bump : Int -> Int -> Int\nbump a b =\n    Store.add a b",
        "String.fromInt (bump 1 2)",
    );
    assert_refused("add_in_plain_forwarder", &source, "Store.add");
}

/// A saturated `Store.literal` outside a query is refused.
#[test]
fn literal_outside_select_is_refused() {
    let source = program("x : Int\nx =\n    Store.literal 5", "String.fromInt x");
    assert_refused("literal_outside_select", &source, "Store.literal");
}

/// A saturated `Store.upper` outside a query is refused.
#[test]
fn upper_outside_select_is_refused() {
    let source = program("shout : String\nshout =\n    Store.upper \"a\"", "shout");
    assert_refused("upper_outside_select", &source, "Store.upper");
}

/// A saturated `Store.coalesce` outside a query is refused.
#[test]
fn coalesce_outside_select_is_refused() {
    let source = program(
        "pick : String\npick =\n    Store.coalesce \"a\" \"b\"",
        "pick",
    );
    assert_refused("coalesce_outside_select", &source, "Store.coalesce");
}

/// An over-applied `Store.literal` at a function type is refused.
#[test]
fn over_applied_placeholder_is_refused() {
    let source = program(
        "shown : String\nshown =\n    Store.literal String.fromInt 5",
        "shown",
    );
    assert_refused("over_applied_placeholder", &source, "Store.literal");
}

/// A saturated `Store.sub` inside a plain forwarding function is refused.
#[test]
fn sub_in_plain_forwarder_is_refused() {
    let source = program(
        "drop : Int -> Int -> Int\ndrop a b =\n    Store.sub a b",
        "String.fromInt (drop 3 2)",
    );
    assert_refused("sub_in_plain_forwarder", &source, "Store.sub");
}

/// A saturated `Store.mul` at `Float` outside a query is refused.
#[test]
fn mul_outside_select_is_refused() {
    let source = program(
        "twice : Float\ntwice =\n    Store.mul 2.0 1.5",
        "String.fromFloat twice",
    );
    assert_refused("mul_outside_select", &source, "Store.mul");
}

/// A saturated `Store.lower` outside a query is refused.
#[test]
fn lower_outside_select_is_refused() {
    let source = program("quiet : String\nquiet =\n    Store.lower \"A\"", "quiet");
    assert_refused("lower_outside_select", &source, "Store.lower");
}

/// A parenthesised curried spine `(Store.add a) b` is refused like the flat call.
#[test]
fn parenthesised_spine_is_refused() {
    let source = program(
        "bump : Int -> Int -> Int\nbump a b =\n    (Store.add a) b",
        "String.fromInt (bump 1 2)",
    );
    assert_refused("parenthesised_spine", &source, "Store.add");
}

/// A piped saturated call `b |> Store.add a` is refused.
#[test]
fn piped_call_is_refused() {
    let source = program(
        "bump : Int -> Int -> Int\nbump a b =\n    b |> Store.add a",
        "String.fromInt (bump 1 2)",
    );
    assert_refused("piped_call", &source, "Store.add");
}

/// A lambda whose body saturates `Store.add` is refused at that body.
#[test]
fn lambda_body_is_refused() {
    let source = program(
        "bump : Int -> Int -> Int\nbump =\n    \\a b -> Store.add a b",
        "String.fromInt (bump 1 2)",
    );
    assert_refused("lambda_body", &source, "Store.add");
}
