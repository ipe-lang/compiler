//! SEAL for a non-`Clone` effect-carrier record whose value is used as a
//! record-update base AND is also used elsewhere in the same scope.
//!
//! `emit_update` emits `let mut __ipe_rec = <base>;` which MOVES the base.
//! Before this fix, `count_value_consumes` counted a bare `Var(sym)` update
//! base as 0 (treating it as a borrow, matching the old unconditional
//! `(base).clone()` emit). After the PR that replaced the unconditional clone
//! with a move, the counter was not updated — so a non-`Clone` update base
//! reused elsewhere counted as only 1 consume total, slipped past the
//! IPE-L0135 gate, and caused `cargo build` E0382 after `ipe` exit 0.
//!
//! The fix: bare `Var(sym)` in an `Update` base now counts as 1 (a move),
//! matching the actual emitted Rust. A non-`Clone` base reused elsewhere sums
//! to ≥ 2, tripping IPE-L0135 fail-closed at `ipe` time.
//!
//! | Fixture | Shape | Outcome |
//! |---|---|---|
//! | `update_base_nonclone_reuse` | non-Clone update base + field read of same var OUTSIDE the update | fail-closed IPE-L0135 |
//! | `update_base_nonclone_field_read` | non-Clone update base whose updated field reads the base (`{ m \| c = m.c + 1 }`) | builds + emitted crate runs |
//! | `update_base_nonclone_single` | non-Clone update base, single use (last) | builds + emitted crate runs |
//! | `update_base_clone_reuse` | Clone record, update base + reuse | builds + clones correctly |
//!
//! The `field_read` fixture is the functional-update idiom: the base is read
//! INSIDE the updated field's value and moved as the update base. `emit_update`
//! binds the field value to a temporary BEFORE moving the base, so the in-field
//! read observes the base while it is still owned — no use-after-move. Before
//! that reorder the emit moved the base first, so this fixture was RED at cargo
//! (E0382) after `ipe` exit 0.
//!
//! ```text
//! # gate check only (fast):
//! cargo test -p ipe --test g_issues golden_i858
//! # full (cargo build + run positive fixtures):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_i858
//! ```

use std::path::PathBuf;

use ipe::CliError;

const fn false_marker() -> bool {
    std::hint::black_box(false)
}

fn write_single(name: &str, source: &str) -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("i858-update-base")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(&src).ok()?;
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, source).ok()?;
    Some(entry)
}

fn out_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("i858-update-base-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

#[track_caller]
fn assert_rejected(name: &str, source: &str, expected: ipe_diagnostics::Code) {
    let entry = crate::support::expect_scratch_entry(name, write_single(name, source));
    let out = out_dir(name);
    let runtime = crate::support::expect_runtime(name, ipe::resolve_runtime());
    match ipe::build(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            expected,
            "{name}: expected fail-closed {expected:?}, got a different diagnostic"
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED a non-Clone effect-carrier update-base reuse \
             (exit 0) — emitted crate would fail cargo E0382, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

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
                "{name}: ipe REJECTED a well-formed program with {} — a false \
                 rejection (single-use or Clone-reuse must build)",
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
        return;
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
        "{name}: emitted crate built but produced the wrong output"
    );
}

/// A non-`Clone` `Task`-bearing record `w` is used as the update base
/// (`{ w | tag = 1 }`) AND its field is read afterwards (`w.tag`). The update
/// MOVES `w`; the subsequent field read is a use-after-move. Must fail closed
/// at `ipe` time with IPE-L0135.
const UPDATE_BASE_NONCLONE_REUSE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


bump : { job : Task Error Int, tag : Int } -> Task Error ()
bump w =
    let
        w2 = { w | tag = 1 }
    in
    Io.println (String.fromInt (w.tag + w2.tag))


main : Task Error ()
main =
    bump { job = Task.succeed 7, tag = 3 }
";

/// Over-rejection guard: a non-`Clone` update base used ONCE (as the last
/// and only use of `w`) is linear — the move is sound, no clone needed.
/// Must build and run, printing `1`.
const UPDATE_BASE_NONCLONE_SINGLE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


bump : { job : Task Error Int, tag : Int } -> Task Error ()
bump w =
    let
        w2 = { w | tag = 1 }
    in
    Io.println (String.fromInt w2.tag)


main : Task Error ()
main =
    bump { job = Task.succeed 7, tag = 3 }
";

/// Functional-update idiom on a non-`Clone` record: the updated field's value
/// reads the base (`{ w | tag = w.tag + 1 }`) and the base is moved by the
/// update. `emit_update` binds the field value to a temporary BEFORE the move,
/// so the in-field read is sound. `w` is not used outside the update — linear,
/// no reject. Must build and run, printing `4` (`tag` 3 → 4).
const UPDATE_BASE_NONCLONE_FIELD_READ: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


bump : { job : Task Error Int, tag : Int } -> Task Error ()
bump w =
    let
        w2 = { w | tag = w.tag + 1 }
    in
    Io.println (String.fromInt w2.tag)


main : Task Error ()
main =
    bump { job = Task.succeed 7, tag = 3 }
";

/// Clone-reuse guard: a `Clone` record (`{ x : Int, y : Int }`) whose value
/// is used as an update base AND read afterwards is sound — the reuse gate
/// rewrites the base `Var(p)` to `CloneVar(p)` and emits `p.clone()`.
/// Must build and run, printing `43`.
const UPDATE_BASE_CLONE_REUSE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


bump : { x : Int, y : Int } -> Task Error ()
bump p =
    let
        q = { p | x = 41 }
    in
    Io.println (String.fromInt (q.x + p.y))


main : Task Error ()
main =
    bump { x = 1, y = 2 }
";

#[test]
fn update_base_nonclone_reuse_fails_closed() {
    assert_rejected(
        "update_base_nonclone_reuse",
        UPDATE_BASE_NONCLONE_REUSE,
        ipe_diagnostics::IPE_L0135,
    );
}

#[test]
fn update_base_nonclone_field_reads_base_builds() {
    assert_accepted(
        "update_base_nonclone_field_read",
        UPDATE_BASE_NONCLONE_FIELD_READ,
        "4",
    );
}

#[test]
fn update_base_nonclone_single_use_builds() {
    assert_accepted(
        "update_base_nonclone_single",
        UPDATE_BASE_NONCLONE_SINGLE,
        "1",
    );
}

#[test]
fn update_base_clone_reuse_builds() {
    assert_accepted("update_base_clone_reuse", UPDATE_BASE_CLONE_REUSE, "43");
}
