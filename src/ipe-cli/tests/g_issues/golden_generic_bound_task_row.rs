//! SEAL: a `Task`-returning function's row variable carries `Send + 'static`.
//!
//! `greet` returns a `Task` and reads its row-polymorphic record, so the
//! lowerer's signature rule gives the row variable `Send + 'static` and the
//! emitted clause renders exactly that set. Forwarding the record into another
//! function is refused at ipe time (IPE-L0131), pinned by the `ipe_lower` unit
//! test `task_returning_row_variable_inherits_send`.
//!
//! The emit gate asserts the bounds on the emitted signatures; under
//! `IPE_E2E=1` the program is built, run, and its stdout matched against
//! `expected.txt`.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "generic_bound_task_row";

/// Each `Main` function and the bounds its emitted clause must carry.
const BOUNDS: &[(&str, &[&str])] = &[("greet", &["R1: 'static + Send"])];

fn fixture_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
}

/// Emit gate: the row variable carries `Send + 'static`.
#[test]
fn generic_bound_task_row_bounds_emitted() {
    let root = crate::support::repo_root();
    let golden_dir = fixture_dir(&root);
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_emit"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&golden_dir, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe dev build must accept the program, got: {built:?}"
    );

    let emitted = crate::support::read_all_emitted_src(&out);
    for (name, needs) in BOUNDS {
        let signature = crate::support::emitted_signature(&emitted, name);
        for need in *needs {
            assert!(
                signature.as_deref().is_some_and(|text| text.contains(need)),
                "{GOLDEN}: `{name}`'s clause must carry `{need}` (the bound its \
                 callees oblige), got signature: {signature:?}"
            );
        }
    }
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must build and print every greeting.
#[test]
fn generic_bound_task_row_seal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = crate::support::repo_root();
    let dir = fixture_dir(&root);
    let out = crate::support::scratch_root().join(format!("ipec_{GOLDEN}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe dev build must accept the program, got: {built:?}"
    );

    let outcome = crate::support::build_and_run_emitted(GOLDEN, &out);
    crate::support::assert_go_parity(GOLDEN, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "{GOLDEN}: must exit 0");
}
