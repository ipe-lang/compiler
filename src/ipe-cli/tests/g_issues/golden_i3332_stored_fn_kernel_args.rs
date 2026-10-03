//! SEAL tests for a stored function value passed to a function-taking kernel.
//!
//! A function read out of storage (a record field, a constructor payload, a
//! tuple component, a destructured record field, a `let` alias of one, an `if`
//! over fields) is carried as `Arc<dyn Fn>`, which no `impl Fn` kernel
//! parameter accepts. Each fixture passes such reads to every function-taking
//! kernel of one stdlib family, directly, partially applied, and piped.
//!
//! | Fixture | Family |
//! |---|---|
//! | `stored_fn_kernel_list` | `List` |
//! | `stored_fn_kernel_maybe` | `Maybe` |
//! | `stored_fn_kernel_result` | `Result` |
//! | `stored_fn_kernel_dict` | `Dict` |
//! | `stored_fn_kernel_set` | `Set` |
//! | `stored_fn_kernel_string` | `String` |
//!
//! Every fixture is checked at `ipe` time here; under `IPE_E2E=1` it is also
//! built with `cargo` and run (THE SEAL). A coverage test keeps every
//! direct function slot of these families named in its family's fixture.
//!
//! ```text
//! cargo test -p ipe --test g_issues golden_i3332
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_i3332
//! ```

use std::path::PathBuf;

use ipe_kernels::{FnSlotCarrier, StdlibKernel};

use crate::support::repo_root;

/// Each covered stdlib family and the fixture exercising its function slots.
const FAMILIES: [(&str, &str); 6] = [
    ("List", "stored_fn_kernel_list"),
    ("Maybe", "stored_fn_kernel_maybe"),
    ("Result", "stored_fn_kernel_result"),
    ("Dict", "stored_fn_kernel_dict"),
    ("Set", "stored_fn_kernel_set"),
    ("String", "stored_fn_kernel_string"),
];

fn fixture_entry(name: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

/// Build the fixture `name`, then (under `IPE_E2E=1`) `cargo build` and run it,
/// asserting exit 0 and `expected_stdout`.
#[track_caller]
fn accept_and_run(name: &str, expected_stdout: &str) {
    let entry = fixture_entry(name);
    let out = crate::support::scratch_root().join(format!("ipec_i3332_{name}"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{name}: ipe must accept the fixture; got {built:?}"
    );
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

#[test]
fn stored_fn_reaches_every_list_kernel() {
    accept_and_run(
        "stored_fn_kernel_list",
        "10,20,30 2,3 1,1,2,2,3,3 1 6 6 0,2,6 T F 2 2,3 3,2,1 3,2,1 2,4,6 3,6,9 4,8,12 \
         5,10,15 2,3 2,3 10,20,30 6 2,4,6 1,2 2 10,20,30 6 2,3",
    );
}

#[test]
fn stored_fn_reaches_every_maybe_kernel() {
    accept_and_run(
        "stored_fn_kernel_maybe",
        "20 1 4 6 8 10 20 1 20 4 3 6 4 1 20",
    );
}

#[test]
fn stored_fn_reaches_every_result_kernel() {
    accept_and_run(
        "stored_fn_kernel_result",
        "20 2 e! 4 6 8 10 3 20 2 e! 4 3 e?7 neg 6 e",
    );
}

#[test]
fn stored_fn_reaches_every_dict_kernel() {
    accept_and_run(
        "stored_fn_kernel_dict",
        "5 5 106 60 6 6 5 60 7 6 7 106 106 3 44 60 6 1",
    );
}

#[test]
fn stored_fn_reaches_every_set_kernel() {
    accept_and_run("stored_fn_kernel_set", "5 5 60 6 6 5 60 6 3 98 6 1 60");
}

#[test]
fn stored_fn_reaches_every_string_kernel() {
    accept_and_run(
        "stored_fn_kernel_string",
        "axxa bb 4 4 T F axxa bb 4 aa zzzz3 T 4 T",
    );
}

/// Every direct function slot of a covered family is exercised by its fixture.
///
/// A kernel added to one of these families with a function parameter fails
/// here until its family fixture passes it a stored function.
#[test]
fn every_direct_fn_slot_of_a_covered_family_is_exercised() {
    let mut covered = 0_usize;
    let mut missing = Vec::new();
    for kernel in StdlibKernel::ALL {
        let decl = kernel.decl();
        let Some((_, fixture)) = FAMILIES
            .iter()
            .find(|(family, _)| *family == decl.qualifier)
        else {
            continue;
        };
        let has_direct_slot = (0..usize::from(decl.arity))
            .any(|arg| kernel.fn_slot_carrier(arg) == Some(FnSlotCarrier::Direct));
        if !has_direct_slot {
            continue;
        }
        let source = std::fs::read_to_string(fixture_entry(fixture)).unwrap_or_default();
        if source.contains(&format!("{}.{} ", decl.qualifier, decl.name)) {
            covered += 1;
        } else {
            missing.push(format!("{}.{} ({fixture})", decl.qualifier, decl.name));
        }
    }
    assert!(
        missing.is_empty(),
        "function-taking kernels no stored-function fixture exercises: {missing:?}"
    );
    // The scheme derivation must find the families' function slots at all;
    // an empty derivation would pass the loop above vacuously.
    assert!(
        covered >= 40,
        "only {covered} function-taking kernels derived across the covered families"
    );
}
