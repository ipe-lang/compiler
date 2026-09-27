//! The raw-SQL escape hatch is `Ipe.Db.Unsafe.unsafeExecRaw`, and neither the
//! old unmarked `Db.execRaw` name nor the relocated `Db.unsafeExecRaw` off a
//! plain `import Ipe.Db` exists. This pins the security property that the
//! verbatim-SQL injection surface is only reachable through the lexically-marked
//! `unsafe` name in the disclosed `Ipe.Db.Unsafe` submodule — a caller cannot
//! fall into raw SQL by using an unmarked default, nor without disclosing the
//! `unsafe` capability. The positive half (that `unsafeExecRaw` itself compiles)
//! is covered by every `db_*` golden and by `postgres_driver_reachability`.

use std::fs;
use std::path::{Path, PathBuf};

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    ipe::resolve_runtime().expect("runtime must resolve for this test")
}

#[allow(clippy::expect_used)]
fn write_project(test_name: &str, main_ipe: &str) -> PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_db_unsafe_marker_{test_name}"));
    let _ = fs::remove_dir_all(&dir);
    let src = dir.join("src");
    fs::create_dir_all(&src).expect("create src/");
    fs::write(src.join("Main.ipe"), main_ipe).expect("write Main.ipe");
    fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"dbmarker\" }\n",
    )
    .expect("write package.ipe");
    dir
}

fn build(dir: &Path, test_name: &str) -> Result<(), ipe::CliError> {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("db_marker_{test_name}"));
    let _ = fs::remove_dir_all(&out);
    ipe::build_project(&dir.join("package.ipe"), &out, &runtime())
}

/// `Ipe.Db.Unsafe.unsafeExecRaw` is the raw-SQL escape hatch — it type-checks
/// when imported from its `.Unsafe` submodule (the marked path stays available
/// for DDL that cannot be parameterised).
#[test]
fn unsafe_exec_raw_is_the_raw_sql_entry() {
    let dir = write_project(
        "marked",
        "\
module Main exposing (main)
import Ipe.Db
import Ipe.Db.Unsafe
import Ipe.Task

main =
    Task.andThen
        (\\conn ->
            Unsafe.unsafeExecRaw conn \"CREATE TABLE t (id INTEGER)\"
        )
        (Db.open \"sqlite\" \"sqlite::memory:\")
",
    );
    let built = build(&dir, "marked");
    assert!(
        built.is_ok(),
        "Ipe.Db.Unsafe.unsafeExecRaw must type-check as the raw-SQL escape hatch: {:?}",
        built.err()
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The old unmarked `Db.execRaw` name is gone: reaching verbatim SQL without
/// typing `unsafe` is a compile error, so the injection-prone default is
/// unreachable.
#[test]
fn unmarked_exec_raw_no_longer_compiles() {
    let dir = write_project(
        "unmarked",
        "\
module Main exposing (main)
import Ipe.Db
import Ipe.Task

main =
    Task.andThen
        (\\conn ->
            Db.execRaw conn \"CREATE TABLE t (id INTEGER)\"
        )
        (Db.open \"sqlite\" \"sqlite::memory:\")
",
    );
    let built = build(&dir, "unmarked");
    assert!(
        built.is_err(),
        "the unmarked Db.execRaw name must NOT compile — the raw-SQL injection \
         surface may only be reached through the marked Ipe.Db.Unsafe.unsafeExecRaw"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The relocated `unsafeExecRaw` no longer resolves off a plain `import Ipe.Db`:
/// the raw-SQL surface LEFT `Ipe.Db` for `Ipe.Db.Unsafe`, so reaching it without
/// importing the disclosed `.Unsafe` submodule is a compile error.
#[test]
fn relocated_exec_raw_off_plain_db_no_longer_compiles() {
    let dir = write_project(
        "relocated",
        "\
module Main exposing (main)
import Ipe.Db
import Ipe.Task

main =
    Task.andThen
        (\\conn ->
            Db.unsafeExecRaw conn \"CREATE TABLE t (id INTEGER)\"
        )
        (Db.open \"sqlite\" \"sqlite::memory:\")
",
    );
    let built = build(&dir, "relocated");
    assert!(
        built.is_err(),
        "Db.unsafeExecRaw off a plain `import Ipe.Db` must NOT compile — the \
         raw-SQL surface relocated to the disclosed `Ipe.Db.Unsafe` submodule"
    );
    let _ = fs::remove_dir_all(&dir);
}
