//! Transitive derive demotion for records: a record whose field is a record
//! whose field is a function. The `Arc<dyn Fn>` carrier demotes the derive
//! posture TRANSITIVELY — the inner record loses `PartialEq`/`Debug` because its
//! function field is not derivably comparable, and the outer record inherits
//! that demotion. A shallow `is_derivable` would emit a `derive(PartialEq)` on
//! the outer struct that fails to compile on the inner field; the fixpoint over
//! the type graph prevents that. Both structs get a hand-written `impl Clone`
//! (an `Arc::clone` refcount bump on the fn slot) and render a `<function>`
//! placeholder in `IpeStringify`.
//!
//! `run outer 5` = `o.inner.op 5 + dup.inner.op 5 + dup.inner.tag`
//! = `(5*2) + (5*2) + 7` = `10 + 10 + 7` = `27`. The `dup = o` binding reuses
//! the whole nested value, exercising the transitive hand-written `Clone`.

use std::path::{Path, PathBuf};

use crate::support::repo_root;

fn example_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("fn_record_nested_transitive")
        .join("Main.ipe")
}

#[test]
fn nested_transitive_emits_byte_identical_main_rs() {
    let root = repo_root();
    let entry = example_entry(&root);
    let golden = root
        .join("tests")
        .join("golden")
        .join("fn_record_nested_transitive")
        .join("main.rs");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fn_record_nested_transitive_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    crate::support::assert_emitted_project_matches_golden_dir(
        &out,
        crate::support::golden_dir_of(&golden),
    );
}

#[test]
fn nested_transitive_end_to_end_prints_twenty_seven() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root = repo_root();
    let entry = example_entry(&root);
    let out = crate::support::scratch_root().join("ipec_fn_record_nested_transitive_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted("fn_record_nested_transitive", &out);
    assert_eq!(
        outcome.stdout, "27\n",
        "nested record of functions prints its sum"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0 (THE SEAL)");
}
