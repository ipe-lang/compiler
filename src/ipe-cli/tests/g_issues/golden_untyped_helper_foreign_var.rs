//! An untyped helper's signature never mentions a type variable another binding keeps generic.
//!
//! A same-module use of an unannotated `chip` inside the annotated, generic
//! `row` shares `chip`'s one type with `row`'s `msg`. `row` emits `msg` as its
//! own Rust generic while `chip` has no type parameter for it, so the call
//! between the two emitted functions could not type-check under cargo. `ipe`
//! refuses `chip` at its name with IPE-L0102, naming helper, owner, and
//! variable, both across modules and within one.
//!
//! The controls stay accepted: the same helper with its own signature, and an
//! owner whose `msg` no use keeps generic (defaulted to `()`, so no binding
//! owns it). Under `IPE_E2E=1` each control's emitted crate must build and
//! print its rendering (`expected.txt`).

use std::path::{Path, PathBuf};

use ipe_diagnostics::{Diagnostic, LowerError};

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Assert `ipe` refuses `golden` with the foreign-variable refusal at `chip`'s name in `file`.
fn assert_chip_refused(name: &str, golden: &Path, file: &str) {
    let out = crate::support::scratch_root().join(format!("ipec_{name}"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(golden, &out, &runtime);
    let Err(ipe::CliError::Pipeline {
        file: diag_file,
        src,
        diag,
    }) = &built
    else {
        assert!(
            built.is_err(),
            "{name}: ipe must refuse the borrowing helper, got: {built:?}"
        );
        assert!(
            matches!(built, Err(ipe::CliError::Pipeline { .. })),
            "{name}: the refusal must be a pipeline diagnostic, got: {built:?}"
        );
        return;
    };
    assert_eq!(
        diag.code(),
        ipe_diagnostics::IPE_L0102,
        "{name}: the refusal must carry IPE-L0102, got: {diag:?}"
    );
    assert!(
        matches!(
            &**diag,
            Diagnostic::Lower {
                msg: LowerError::ForeignTypeVariable { helper, owner, var },
                ..
            } if &**helper == "chip" && &**owner == "row" && &**var == "msg"
        ),
        "{name}: the refusal must name helper `chip`, owner `row`, variable `msg`, got: {diag:?}"
    );
    assert!(
        diag_file.to_string_lossy().ends_with(file),
        "{name}: the refusal must be sited in `{file}`, got {}",
        diag_file.display()
    );
    let def = src.find("\nchip s =").map(|at| at + 1);
    let span = diag.primary_span();
    let at = usize::try_from(span.lo).ok();
    let end = usize::try_from(span.hi).ok();
    assert!(
        def.is_some() && at == def && end == def.map(|d| d + "chip".len()),
        "{name}: the refusal must sit on `chip`'s name (byte {def:?}), got {span:?}"
    );
}

/// Refused across modules: `Widgets.row` borrows into the untyped `Widgets.chip`.
#[test]
fn untyped_helper_foreign_msg_refused() {
    let name = "untyped_helper_foreign_msg_refused";
    let root = crate::support::repo_root();
    assert_chip_refused(name, &golden_dir(&root, name), "Widgets.ipe");
}

/// Refused within one module: `framed` keeps `row` generic over the `msg` `chip` borrows.
#[test]
fn untyped_helper_foreign_msg_single_refused() {
    let name = "untyped_helper_foreign_msg_single_refused";
    let root = crate::support::repo_root();
    assert_chip_refused(name, &golden_dir(&root, name), "Main.ipe");
}

/// Build `golden` and assert `ipe` accepts it.
fn assert_accepted(name: &str, golden: &Path, out: &Path) {
    let _ = std::fs::remove_dir_all(out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(golden, out, &runtime);
    assert!(
        built.is_ok(),
        "{name}: ipe dev build must accept the program, got: {built:?}"
    );
}

/// THE SEAL: build the accepted `golden`, run it, and compare its output to `expected.txt`.
fn assert_seal_runs(name: &str, golden: &Path) {
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    assert_accepted(name, golden, &out);
    let run = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        run.exit_code,
        Some(0),
        "{name}: the emitted program must exit 0"
    );
    crate::support::assert_self_regression(name, golden, &run.stdout);
}

const ANNOTATED: &str = "untyped_helper_annotated_msg_seal";
const DEFAULTED: &str = "untyped_helper_defaulted_owner_seal";

/// Control: the helper with its own signature is accepted.
#[test]
fn untyped_helper_annotated_msg_emitted() {
    let root = crate::support::repo_root();
    let out = crate::support::scratch_root().join(format!("ipec_{ANNOTATED}_emit"));
    assert_accepted(ANNOTATED, &golden_dir(&root, ANNOTATED), &out);
}

/// Control: an owner whose `msg` is defaulted owns no variable, so the untyped helper is accepted.
#[test]
fn untyped_helper_defaulted_owner_emitted() {
    let root = crate::support::repo_root();
    let out = crate::support::scratch_root().join(format!("ipec_{DEFAULTED}_emit"));
    assert_accepted(DEFAULTED, &golden_dir(&root, DEFAULTED), &out);
}

/// THE SEAL for the annotated control: the emitted crate builds and prints its rendering.
#[test]
fn untyped_helper_annotated_msg_seal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = crate::support::repo_root();
    let golden = golden_dir(&root, ANNOTATED);
    assert_seal_runs(ANNOTATED, &golden);
}

/// THE SEAL for the defaulted-owner control: the emitted crate builds and prints its rendering.
#[test]
fn untyped_helper_defaulted_owner_seal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = crate::support::repo_root();
    let golden = golden_dir(&root, DEFAULTED);
    assert_seal_runs(DEFAULTED, &golden);
}
