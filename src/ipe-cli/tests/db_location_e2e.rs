//! `Db.open` over a typed `DbLocation`, built and run.
//!
//! A file location names the literal file: a name holding `?`, `#` or `%`
//! opens exactly that file, never a truncated or percent-decoded one. Each open
//! mode keeps its contract, and a location naming another engine than the
//! build's driver is a typed `InvalidInput` refusal at run time, never a panic.

use std::fs;
use std::path::{Path, PathBuf};

use ipe::CliError;

/// The literal file name the file-location program creates.
const LITERAL: &str = "a%2e.db?mode=ro#x";

/// Names a URL parser would derive from [`LITERAL`]; none may appear.
const STRAYS: &[&str] = &["a%2e.db", "a..db", "a.db", "a%2e.db?mode=ro"];

fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

/// A fresh scratch directory under this test target's temp root.
#[allow(clippy::expect_used)] // an unwritable test temp root is a broken setup
fn fresh_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src")).expect("create src/");
    dir
}

/// Write `package.ipe` with `extra` spliced into the package record, and `main`.
#[allow(clippy::expect_used)] // an unwritable test temp root is a broken setup
fn write_project(dir: &Path, extra: &str, main: &str) {
    fs::write(dir.join("src").join("Main.ipe"), main).expect("write Main.ipe");
    fs::write(
        dir.join("package.ipe"),
        format!(
            "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\n\
             package : Package\npackage =\n    {{ name = \"dblocation\"{extra} }}\n"
        ),
    )
    .expect("write package.ipe");
}

/// Emit the project at `dir`, build it with cargo and run it; the run's stdout.
///
/// # Errors
/// An `ipe` rejection, a cargo failure, or a nonzero exit, as a message.
fn build_and_run(name: &str, dir: &Path) -> Result<String, String> {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_out"));
    let _ = fs::remove_dir_all(&out);
    match ipe::build_project(&dir.join("package.ipe"), &out, &runtime()) {
        Ok(()) => {}
        Err(CliError::Pipeline { diag, .. }) => {
            return Err(format!(
                "ipe rejected a well-typed program with {}",
                diag.code().as_str()
            ));
        }
        Err(other) => return Err(format!("build error: {other:?}")),
    }
    let run = e2e_support::build_and_run_rust(name, &out)
        .map_err(|msg| format!("ipe accepted but cargo failed:\n{msg}"))?;
    if run.exit_code == Some(0) {
        Ok(run.stdout)
    } else {
        Err(format!("exit {:?}:\n{}", run.exit_code, run.stdout))
    }
}

/// The Ipê helper that reports whether a task succeeded, under `label`.
const OUTCOME: &str = "\
outcome : String -> Task Error a -> Task Error String
outcome label task =
    Task.onError
        (\\e -> Task.succeed (label ++ \" refused \" ++ Error.toString e))
        (Task.map (\\_ -> label ++ \" accepted\") task)


openFile : Mode -> String -> Task Error Db
openFile mode file =
    Path.fromString file
        |> Result.andThen (Location.file mode)
        |> Task.fromResult
        |> Task.andThen Db.open
";

/// The sqlite program: three file modes, memory, and a sqlite `Dsn`.
fn sqlite_main(dir: &str) -> String {
    format!(
        "module Main exposing (main)

import Ipe.Db
import Ipe.Db.Dsn as Dsn
import Ipe.Db.Location as Location exposing (Mode(..))
import Ipe.Db.Unsafe
import Ipe.Error
import Ipe.Io as Io
import Ipe.Path as Path
import Ipe.Result as Result
import Ipe.Task


{OUTCOME}

main : Task Error ()
main =
    do
        absent <- outcome \"absent read\" (openFile ReadExisting \"{dir}/absent.db\")
        Io.println absent
        absentWrite <- outcome \"absent write\" (openFile WriteExisting \"{dir}/absent.db\")
        Io.println absentWrite
        created <- openFile CreateIfMissing \"{dir}/{LITERAL}\"
        Unsafe.unsafeExecRaw created \"CREATE TABLE t (x INTEGER)\"
        writer <- openFile WriteExisting \"{dir}/{LITERAL}\"
        Db.exec writer \"INSERT INTO t (x) VALUES (?)\" [ 1 ]
        reader <- openFile ReadExisting \"{dir}/{LITERAL}\"
        readOnly <- outcome \"read-only write\" (Db.exec reader \"INSERT INTO t (x) VALUES (?)\" [ 2 ])
        Io.println readOnly
        memory <- Db.open Location.memory
        Unsafe.unsafeExecRaw memory \"CREATE TABLE m (x INTEGER)\"
        dsn <- Task.fromResult (Dsn.parse \"sqlite://{dir}/dsn.db\")
        viaDsn <- Db.open (Location.dsn dsn)
        Unsafe.unsafeExecRaw viaDsn \"CREATE TABLE d (x INTEGER)\"
        Io.println \"done\"
"
    )
}

/// E1: every typed sqlite location opens what it names, and only that.
///
/// The file location creates the literal name holding `%`, `?` and `#`; no
/// name a URL parser would derive appears. `ReadExisting` and `WriteExisting`
/// refuse an absent file, and a read-only handle refuses a write.
#[test]
fn sqlite_locations_open_the_literal_file() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = fresh_dir("db_location_sqlite");
    let data = dir.join("data");
    #[allow(clippy::expect_used)] // an unwritable test temp root is a broken setup
    fs::create_dir_all(&data).expect("create data/");
    let data_text = data.to_string_lossy().into_owned();
    write_project(&dir, "", &sqlite_main(&data_text));
    let run = build_and_run("db_location_sqlite", &dir);
    assert!(run.is_ok(), "db_location_sqlite: {run:?}");
    let stdout = run.unwrap_or_default();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        matches!(
            lines.as_slice(),
            [absent, absent_write, read_only, "done"]
                if absent.starts_with("absent read refused ")
                    && absent_write.starts_with("absent write refused ")
                    && read_only.starts_with("read-only write refused ")
        ),
        "unexpected program output:\n{stdout}"
    );
    assert!(
        data.join(LITERAL).is_file(),
        "the literal file `{LITERAL}` must exist"
    );
    for stray in STRAYS {
        assert!(
            !data.join(stray).exists(),
            "`{stray}` appeared: part of the location reached a URL parser"
        );
    }
    assert!(
        !data.join("absent.db").exists(),
        "a ReadExisting or WriteExisting open created its file"
    );
    assert!(
        data.join("dsn.db").is_file(),
        "the sqlite Dsn file must exist"
    );
}

/// The postgres-driver program opening an in-memory sqlite location.
fn postgres_main() -> String {
    format!(
        "module Main exposing (main)

import Ipe.Db
import Ipe.Db.Location as Location exposing (Mode(..))
import Ipe.Error
import Ipe.Io as Io
import Ipe.Path as Path
import Ipe.Result as Result
import Ipe.Task


{OUTCOME}

main : Task Error ()
main =
    do
        memory <- outcome \"memory\" (Db.open Location.memory)
        Io.println memory
        file <- outcome \"file\" (openFile CreateIfMissing \"app.db\")
        Io.println file
"
    )
}

/// E2: under the postgres driver a sqlite location is a typed `InvalidInput`.
///
/// No server is dialled: the engine mismatch is refused before any connect,
/// and the program keeps running past it.
#[test]
fn postgres_build_refuses_sqlite_locations() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let dir = fresh_dir("db_location_postgres");
    write_project(&dir, ", build = { database = Postgres }", &postgres_main());
    let run = build_and_run("db_location_postgres", &dir);
    assert!(run.is_ok(), "db_location_postgres: {run:?}");
    let stdout = run.unwrap_or_default();
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        matches!(
            lines.as_slice(),
            [memory, file]
                if memory.starts_with("memory refused InvalidInput")
                    && file.starts_with("file refused InvalidInput")
        ),
        "unexpected program output:\n{stdout}"
    );
}
