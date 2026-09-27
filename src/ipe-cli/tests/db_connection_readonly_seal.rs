//! The external `Ipe.Db.Connection`'s read-only posture is a TYPE, not a runtime
//! flag: `Ipe.Db.Dsn.open` yields a `Connection ReadOnly`, and every mutating
//! kernel requires a `Connection ReadWrite`. So a write against a connection from
//! `open` cannot type-check — the read-only guarantee is a COMPILE error at `ipe`
//! time, never a caught runtime `Err` and never an accept-then-`cargo`-fail.
//!
//! This pins that load-bearing security property from both sides: the negative
//! (a write against `Connection ReadOnly` is rejected at `ipe` time) and the
//! positive (a read/connect against the same connection, and a write against an
//! explicit `Connection ReadWrite`, both type-check and the emitted crate builds —
//! THE SEAL). Positive tests route through [`support::assert_seal_builds`] so the
//! SEAL claim is backed by an actual `cargo build` under `IPE_E2E=1`.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    ipe::resolve_runtime().expect("runtime must resolve for this test")
}

#[allow(clippy::expect_used)]
fn write_project(test_name: &str, main_ipe: &str) -> PathBuf {
    let dir = crate::support::scratch_root().join(format!("ipe_conn_ro_seal_{test_name}"));
    let _ = fs::remove_dir_all(&dir);
    let src = dir.join("src");
    fs::create_dir_all(&src).expect("create src/");
    fs::write(src.join("Main.ipe"), main_ipe).expect("write Main.ipe");
    fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"connroseal\" }\n",
    )
    .expect("write package.ipe");
    dir
}

/// Emit `dir` and return the `out` path. Returns `Err` if ipe rejected the
/// program; the caller decides whether rejection is expected or a failure.
fn emit(dir: &Path, test_name: &str) -> (Result<(), ipe::CliError>, PathBuf) {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("conn_ro_seal_{test_name}"));
    let _ = fs::remove_dir_all(&out);
    let result = ipe::build_project(&dir.join("package.ipe"), &out, &runtime());
    (result, out)
}

/// A write against a `Connection ReadOnly` — the type a program obtains from
/// `Ipe.Db.Dsn.open` — is a COMPILE error. `unsafeExecRawOn` requires a
/// `Connection ReadWrite`, so handing it a read-only connection cannot unify.
/// This is the centerpiece: the read-only posture is unrepresentable-as-a-write,
/// not a runtime gate.
#[test]
fn write_against_read_only_connection_is_a_type_error() {
    let dir = write_project(
        "ro_write_rejected",
        "\
module Main exposing (main)
import Ipe.Db.Dsn as Dsn exposing (Connection, ReadOnly)
import Ipe.Db.Unsafe as DbU
import Ipe.Task as Task
import Ipe.Error exposing (Error)

badWrite : Connection ReadOnly -> Task Error Int
badWrite conn =
    DbU.unsafeExecRawOn conn \"DELETE FROM t\"

main : Task Error ()
main =
    Task.succeed ()
",
    );
    let (built, _out) = emit(&dir, "ro_write_rejected");
    assert!(
        built.is_err(),
        "a write against a `Connection ReadOnly` must be an `ipe`-time TYPE error — \
         the read-only posture is a compile-time guarantee, never a runtime flag"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The positive half: connecting, reading the read-only connection, and closing
/// it all type-check, AND a write against an explicit `Connection ReadWrite`
/// type-checks. THE SEAL — `ipe`-accept ⇒ the emitted crate `cargo`-builds.
/// Routed through `support::assert_seal_builds` so the cargo build step runs
/// under `IPE_E2E=1`: a passing test without that gate proves only emit, not
/// compilation.
#[test]
fn read_only_connect_and_read_write_write_both_type_check() {
    let dir = write_project(
        "positive_modes",
        "\
module Main exposing (main)
import Ipe.Db.Dsn as Dsn exposing (Dsn, Connection, ReadOnly, ReadWrite)
import Ipe.Db.Unsafe as DbU
import Ipe.Task as Task
import Ipe.Error exposing (Error)

-- open yields Connection ReadOnly; close accepts either mode
connectAndClose : Dsn -> Task Error ()
connectAndClose dsn =
    Task.andThen Dsn.close (Dsn.open dsn)

-- a write against a ReadWrite connection is well-typed
okWrite : Connection ReadWrite -> Task Error Int
okWrite conn =
    DbU.unsafeExecRawOn conn \"DELETE FROM t\"

main : Task Error ()
main =
    case Dsn.parse \"postgres://u:p@localhost:5432/db\" of
        Ok dsn ->
            Task.map (\\_ -> ()) (connectAndClose dsn)

        Err e ->
            Task.fail e
",
    );
    let (built, out) = emit(&dir, "positive_modes");
    assert!(
        built.is_ok(),
        "connecting a Dsn (Connection ReadOnly), closing it, and a write against a \
         Connection ReadWrite must all type-check (ipe-accept): {:?}",
        built.err()
    );
    support::assert_seal_builds("conn_ro_seal_positive_modes", &out);
    let _ = fs::remove_dir_all(&dir);
}

/// The typed READ stack accepts an external `Connection ReadOnly`: `Db.queryDecodeOn`
/// (a per-row decoder) and `Store.findWhereOn` / `Store.getOn` (which decode through
/// the store's own codec) both type-check on a read-only connection AND the emitted
/// crate builds (THE SEAL). Routed through `support::assert_seal_builds` so the cargo
/// build step runs under `IPE_E2E=1`.
#[test]
fn typed_reads_over_read_only_connection_type_check_and_build() {
    let dir = write_project(
        "ro_reads_build",
        "\
module Main exposing (main)
import Ipe.Db.Dsn as Dsn exposing (Connection, ReadOnly)
import Ipe.Db as Db
import Ipe.Db.Decode
import Ipe.Db.Store as Store exposing (Store)
import Ipe.Db.Sql as Sql
import Ipe.Task as Task
import Ipe.Result as Result exposing (Result(..))
import Ipe.Maybe exposing (Maybe)
import Ipe.Error exposing (Error)

-- A per-row decoder read through the raw external queryDecode kernel.
readCode : Connection ReadOnly -> Task Error (List Int)
readCode conn =
    Db.queryDecodeOn conn \"SELECT amount FROM ledger\" [] (Db.Decode.int \"amount\")

-- The Store read surface over the SAME external connection, decoding each row
-- through the store's own codec (here a raw-column `Store Store.Row`).
readAll : Connection ReadOnly -> Store Store.Row -> Task Error (List Store.Row)
readAll conn store =
    Store.allOn conn store

readOne : Connection ReadOnly -> Store Store.Row -> SqlValue -> Task Error (Maybe Store.Row)
readOne conn store key =
    Store.getOn conn store key

readWhere : Connection ReadOnly -> Store Store.Row -> SqlFragment -> Task Error (List Store.Row)
readWhere conn store cond =
    Store.findWhereOn conn store cond

main : Task Error ()
main =
    Task.succeed ()
",
    );
    let (built, out) = emit(&dir, "ro_reads_build");
    assert!(
        built.is_ok(),
        "typed reads (Db.queryDecodeOn, Store.allOn/getOn/findWhereOn) over a \
         `Connection ReadOnly` must type-check (ipe-accept): {:?}",
        built.err()
    );
    support::assert_seal_builds("conn_ro_seal_ro_reads_build", &out);
    let _ = fs::remove_dir_all(&dir);
}

/// The write half of the read-only guarantee at the STORE layer: `Store.insert`
/// requires the app `Db`, so handing it an external `Connection ReadOnly` cannot
/// unify — a foreign write through the typed store is unrepresentable, an
/// `ipe`-time type error rather than a runtime gate.
#[test]
fn store_write_against_read_only_connection_is_a_type_error() {
    let dir = write_project(
        "ro_store_write_rejected",
        "\
module Main exposing (main)
import Ipe.Db.Dsn as Dsn exposing (Connection, ReadOnly)
import Ipe.Db.Store as Store exposing (Store)
import Ipe.Task as Task
import Ipe.Error exposing (Error)

badStoreWrite : Connection ReadOnly -> Store Store.Row -> Store.Row -> Task Error Int
badStoreWrite conn store row =
    Store.insert conn store row

main : Task Error ()
main =
    Task.succeed ()
",
    );
    let (built, _out) = emit(&dir, "ro_store_write_rejected");
    assert!(
        built.is_err(),
        "a `Store.insert` against a `Connection ReadOnly` must be an `ipe`-time TYPE \
         error — the external default has no typed write path"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// `Ipe.Db.Dsn.open` is the SAFE connector — it takes a parsed `Dsn` and needs no
/// `.Unsafe` import, so a program that only connects and reads discloses the
/// `network` and `database` axes but NOT `unsafe`. Routed through
/// `support::assert_seal_builds` so the SEAL claim is backed by an actual
/// `cargo build` under `IPE_E2E=1`.
#[test]
fn safe_open_needs_no_unsafe_import() {
    let dir = write_project(
        "safe_open",
        "\
module Main exposing (main)
import Ipe.Db.Dsn as Dsn exposing (Dsn)
import Ipe.Task as Task
import Ipe.Error exposing (Error)

main : Task Error ()
main =
    case Dsn.parse \"postgres://u:p@localhost:5432/db\" of
        Ok dsn ->
            Task.andThen Dsn.close (Dsn.open dsn)

        Err e ->
            Task.fail e
",
    );
    let (built, out) = emit(&dir, "safe_open");
    assert!(
        built.is_ok(),
        "the safe `Ipe.Db.Dsn.open` connector must type-check with no `.Unsafe` \
         import — the parsed-`Dsn` path is the terse, clean default: {:?}",
        built.err()
    );
    support::assert_seal_builds("conn_ro_seal_safe_open", &out);
    let _ = fs::remove_dir_all(&dir);
}
