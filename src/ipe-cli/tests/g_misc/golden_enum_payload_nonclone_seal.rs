//! THE SEAL for user enums whose payloads hold a non-`Clone` value.
//!
//! A user enum wrapping a `Task` or an opaque FFI handle gets no `Clone` (nor
//! `Debug`/`PartialEq`) derive from the backend. Lower and backend must agree:
//! a non-linear reuse of such a value fails closed at `ipe` time, and every
//! accepted shape emits Rust that `cargo build`s.
//!
//! | Test | Shape | Outcome |
//! |---|---|---|
//! | `task_payload_enum_reuse_fails_closed` | `Run (Task Error ())` param reused | IPE-L0135 |
//! | `task_payload_enum_linear_builds` | same enum used once | builds + prints `ran` |
//! | `clone_payload_enum_reuse_builds` | `Pair Int String` param reused | builds + prints `8` |
//! | `ffi_handle_enum_reuse_fails_closed` | `Hold H.Widget` param reused | IPE-L0130 |
//! | `ffi_handle_enum_linear_builds` | same enum used once | no derive; builds + prints `3` |
//!
//! ```text
//! cargo test -p ipe --test g_misc golden_enum_payload_nonclone_seal
//! IPE_E2E=1 cargo test -p ipe --test g_misc golden_enum_payload_nonclone_seal
//! ```

use std::path::{Path, PathBuf};

use ipe::CliError;

use crate::golden_ffi_nonclone_handle_reuse_seal::{provision_handle_demo, write_project};

/// A runtime `false` the optimiser cannot fold — a deliberate failure marker.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// Write `source` as a single-file `Main.ipe` under a fresh scratch dir keyed by
/// `name`, returning the entry path. Panics on scratch-setup failure — a
/// swallowed setup error here would let a refusal test pass vacuously without
/// ever exercising the fail-closed path.
#[allow(clippy::expect_used)] // a swallowed scratch-setup error would let a refusal test pass vacuously
fn write_single(name: &str, source: &str) -> PathBuf {
    let dir = crate::support::scratch_root()
        .join("ipec_enum_payload_nonclone")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(&src)
        .expect("create scratch src dir for enum-payload-nonclone fixture");
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, source).expect("write Main.ipe fixture source");
    entry
}

/// The scratch output dir for `name`, cleared.
fn out_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("enum_payload_nonclone_out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert `ipe` rejects the build of `entry` with the typed `expected` code.
#[track_caller]
#[allow(clippy::expect_used)] // a missing runtime must fail the refusal test, never skip it
#[allow(clippy::panic)] // a refused precondition is the test failure
fn assert_rejected(name: &str, entry: &Path, expected: ipe_diagnostics::Code) {
    // Unlike an accepted-build test, a refusal test proves nothing if it skips
    // silently here — a missing runtime would let the fail-closed assertion
    // pass vacuously without ever driving the pipeline.
    let runtime = e2e_support::require_runtime().into_path_buf();
    let out = out_dir(name);
    match ipe::build_loose_file(entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            expected,
            "{name}: expected a fail-closed {expected:?}, got a different diagnostic"
        ),
        Ok(()) => panic!(
            "{name}: ipe ACCEPTED a non-Clone enum-payload reuse (exit 0) — the \
             emitted crate would fail cargo, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// Build `entry` and return its out dir; an `ipe` refusal fails the test.
#[track_caller]
#[allow(clippy::panic)] // a refused well-formed program is the test failure
fn accepted_out(name: &str, entry: &Path) -> PathBuf {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let out = out_dir(name);
    match ipe::build_loose_file(entry, &out, &runtime) {
        Ok(()) => out,
        Err(err) => {
            panic!("{name}: ipe REJECTED a well-formed program — a false rejection: {err}")
        }
    }
}

/// Under `IPE_E2E`, `cargo build` + run the crate in `out` and check its stdout.
#[track_caller]
fn assert_runs(name: &str, out: &Path, expected_stdout: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return; // emit-only fast pass
    }
    let outcome = crate::support::build_and_run_emitted(name, out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must build and run to exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// The emitted app Rust (`src/main.rs` plus every `src/ipe_mods/**.rs`).
fn emitted_app_rs(out: &Path) -> String {
    fn collect(dir: &Path, acc: &mut String) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        paths.sort();
        for path in paths {
            if path.is_dir() {
                collect(&path, acc);
            } else if path.extension().is_some_and(|x| x == "rs") {
                acc.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
                acc.push('\n');
            }
        }
    }
    let mut acc = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
    acc.push('\n');
    collect(&out.join("src").join("ipe_mods"), &mut acc);
    acc
}

/// `line` without a leading Rust visibility (`pub`, `pub(crate)`, `pub(in …)`).
fn strip_visibility(line: &str) -> &str {
    let Some(rest) = line.strip_prefix("pub") else {
        return line;
    };
    let rest = rest
        .strip_prefix('(')
        .and_then(|scoped| scoped.split_once(')'))
        .map_or(rest, |(_, after)| after);
    rest.strip_prefix(' ').unwrap_or(line)
}

/// The attribute lines directly above the `enum <name>` declaration.
fn attributes_above_enum(emitted: &str, name: &str) -> Option<Vec<String>> {
    let lines: Vec<&str> = emitted.lines().collect();
    let decl = format!("enum {name}");
    let at = lines.iter().position(|l| {
        strip_visibility(l.trim_start())
            .strip_prefix(&decl)
            .is_some_and(|rest| rest.starts_with([' ', '<', '{']))
    })?;
    Some(
        lines
            .get(..at)?
            .iter()
            .rev()
            .take_while(|l| l.trim_start().starts_with("#["))
            .map(|l| (*l).to_owned())
            .collect(),
    )
}

/// `Job` wraps a `Task` — never `Clone` — and `twice` reuses the `Job` param.
const TASK_PAYLOAD_ENUM_REUSE: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.Task as Task


type Job = Run (Task Error ())


twice : Job -> ( Job, Job )
twice j =
    ( j, j )


main =
    Io.println "x"
"#;

/// The same `Job` consumed once — a bare move that needs no `Clone`.
const TASK_PAYLOAD_ENUM_LINEAR: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.Task as Task


type Job = Run (Task Error ())


runJob : Job -> Task Error ()
runJob j =
    case j of
        Run t -> t


main : Task Error ()
main =
    runJob (Run (Io.println "ran"))
"#;

/// A `Clone` payload enum reused through a param still round-trips.
const CLONE_PAYLOAD_ENUM_REUSE: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Pair = Pair Int String


size : Pair -> Int
size p =
    case p of
        Pair n s -> n + String.length s


both : Pair -> Int
both p =
    size p + size p


main =
    Io.println (String.fromInt (both (Pair 1 "abc")))
"#;

/// `Holder` wraps the non-`Clone` foreign `Widget`; `twice` reuses the param.
const FFI_HANDLE_ENUM_REUSE: &str = "module Main exposing (main)\n\
     import Ipe.Io as Io\n\
     import Rust.Handle_demo as H\n\n\
     type Holder = Hold H.Widget\n\n\
     twice : Holder -> ( Holder, Holder )\n\
     twice h =\n\
     \x20   ( h, h )\n\n\
     main =\n\
     \x20   Io.println \"x\"\n";

/// `Holder` consumed once: unwrapped and read through the by-borrow reader.
const FFI_HANDLE_ENUM_LINEAR: &str = "module Main exposing (main)\n\
     import Ipe.Io as Io\n\
     import Ipe.Result as Result\n\
     import Ipe.String as String\n\
     import Rust.Handle_demo as H\n\n\
     type Holder = Hold H.Widget\n\n\
     count : Holder -> Result Error Int\n\
     count h =\n\
     \x20   case h of\n\
     \x20       Hold w -> Result.map (\\( n, _ ) -> n) (H.slot_count_from_widget w)\n\n\
     main =\n\
     \x20   case Result.andThen (\\w -> count (Hold w)) (H.new_from_widget ()) of\n\
     \x20       Ok n -> Io.println (String.fromInt n)\n\
     \x20       Err _ -> Io.println \"err\"\n";

#[test]
fn task_payload_enum_reuse_fails_closed() {
    let name = "task_payload_enum_reuse";
    let entry = write_single(name, TASK_PAYLOAD_ENUM_REUSE);
    assert_rejected(name, &entry, ipe_diagnostics::IPE_L0135);
}

#[test]
fn task_payload_enum_linear_builds() {
    let name = "task_payload_enum_linear";
    let entry = write_single(name, TASK_PAYLOAD_ENUM_LINEAR);
    let out = accepted_out(name, &entry);
    assert_runs(name, &out, "ran");
}

#[test]
fn clone_payload_enum_reuse_builds() {
    let name = "clone_payload_enum_reuse";
    let entry = write_single(name, CLONE_PAYLOAD_ENUM_REUSE);
    let out = accepted_out(name, &entry);
    assert_runs(name, &out, "8");
}

#[test]
fn ffi_handle_enum_reuse_fails_closed() {
    let name = "ffi_handle_enum_reuse";
    let project = crate::support::scratch_root().join("ipec_ffi_handle_enum_reuse");
    assert!(
        write_project(&project, FFI_HANDLE_ENUM_REUSE),
        "must write the fixture project + FFI cache to a temp dir"
    );
    let entry = project.join("src").join("Main.ipe");
    assert_rejected(name, &entry, ipe_diagnostics::IPE_L0130);
}

#[test]
#[allow(clippy::panic)] // a missing emitted enum is the test failure
fn ffi_handle_enum_linear_builds() {
    let name = "ffi_handle_enum_linear";
    let project = crate::support::scratch_root().join("ipec_ffi_handle_enum_linear");
    assert!(
        write_project(&project, FFI_HANDLE_ENUM_LINEAR),
        "must write the fixture project + FFI cache to a temp dir"
    );
    let entry = project.join("src").join("Main.ipe");
    let out = accepted_out(name, &entry);

    let emitted = emitted_app_rs(&out);
    // The backend module-prefixes every user type name (`naming::enum_name`,
    // `src/compiler/backend/rust/src/naming.rs`): `Holder` in `Main` emits as
    // `MainHolder`.
    let Some(attrs) = attributes_above_enum(&emitted, "MainHolder") else {
        panic!("emitted app Rust must declare `enum MainHolder`; got:\n{emitted}");
    };
    assert!(
        attrs
            .iter()
            .all(|a| !a.contains("Clone") && !a.contains("Debug") && !a.contains("PartialEq")),
        "an enum holding the opaque foreign `Widget` must get no derive the \
         foreign type cannot satisfy; got attributes: {attrs:?}"
    );

    provision_handle_demo(&project, &out);
    assert_runs(name, &out, "3");
}
