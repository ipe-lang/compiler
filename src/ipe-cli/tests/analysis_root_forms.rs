#![forbid(unsafe_code)]
//! `ipe type-check` analyses a project the same way whichever form names it.
//!
//! The no-argument form, the directory form (`.`) and the file form naming the
//! project's entry all resolve through one `src` root — the build's — so a
//! nested entry's imports resolve (or are refused) identically in each.

mod support;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// The relative path of the fixture's declared entry under the project root.
const ENTRY: &str = "src/App/Main.ipe";

/// A project whose declared entry `App.Main` is nested under `src/`, beside a
/// `Shared.Util` module and an `Extra` module that lives outside `src/`.
fn nested_entry_project(name: &str, main_body: &str) -> std::io::Result<PathBuf> {
    let root = support::scratch_root().join(name);
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    let src = root.join("src");
    fs::create_dir_all(src.join("App"))?;
    fs::create_dir_all(src.join("Shared"))?;
    fs::write(
        root.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"app\"\n    , programs = [ { name = \"app\", entry = \"App/Main.ipe\" } ]\n    }\n",
    )?;
    fs::write(
        src.join("Shared").join("Util.ipe"),
        "module Shared.Util exposing (one)\none = 1\n",
    )?;
    fs::write(
        root.join("Extra.ipe"),
        "module Extra exposing (one)\none = 1\n",
    )?;
    fs::write(root.join(ENTRY), main_body)?;
    Ok(root)
}

/// Run `ipe type-check <args>` in `dir`, bounded, returning its exit code and
/// stderr.
fn type_check_in(dir: &Path, args: &[&str]) -> std::io::Result<(Option<i32>, String)> {
    let mut child = Command::new(support::ipe_bin())
        .arg("type-check")
        .args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let exited = e2e_support::wait_for(Duration::from_secs(120), || {
        matches!(child.try_wait(), Ok(Some(_)) | Err(_))
    });
    if !exited {
        child.kill()?;
    }
    let out = child.wait_with_output()?;
    assert!(exited, "ipe type-check {args:?} did not exit");
    Ok((
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// The outcome of every form: no argument, `.`, and the entry file itself.
fn every_form(root: &Path) -> std::io::Result<[(Option<i32>, String); 3]> {
    Ok([
        type_check_in(root, &[])?,
        type_check_in(root, &["."])?,
        type_check_in(root, &[ENTRY])?,
    ])
}

#[test]
fn a_nested_entry_type_checks_through_every_form() -> std::io::Result<()> {
    let root = nested_entry_project(
        "analysis_root_forms_nested_entry_green",
        "module App.Main exposing (main)\nimport Shared.Util as Util\nmain = Util.one\n",
    )?;
    let outcomes = every_form(&root)?;
    fs::remove_dir_all(&root)?;
    for (form, (code, stderr)) in ["no argument", "`.`", ENTRY].iter().zip(&outcomes) {
        assert_eq!(
            *code,
            Some(0),
            "a nested entry importing `Shared.Util` must type-check via {form}: {stderr}"
        );
    }
    Ok(())
}

#[test]
fn an_import_from_outside_src_is_refused_alike_by_every_form() -> std::io::Result<()> {
    let root = nested_entry_project(
        "analysis_root_forms_outside_src_refused",
        "module App.Main exposing (main)\nimport Extra\nmain = Extra.one\n",
    )?;
    let [no_arg, dot, file] = every_form(&root)?;
    fs::remove_dir_all(&root)?;
    assert_eq!(
        file.0,
        Some(1),
        "an import of a module outside src/ must be refused: {}",
        file.1
    );
    assert!(
        !file.1.contains("panicked"),
        "the refusal panicked: {}",
        file.1
    );
    assert_eq!(
        no_arg, file,
        "the no-argument form must refuse as the file form does"
    );
    assert_eq!(dot, file, "the `.` form must refuse as the file form does");
    Ok(())
}
