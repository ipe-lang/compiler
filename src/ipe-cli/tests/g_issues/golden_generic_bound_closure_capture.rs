//! SEAL: a closure capturing a caller generic obliges the callback slot's auto traits.
//!
//! `runWith`'s callback renders as `FN1: Fn(..) -> i64 + Send + Sync + 'static`,
//! and `countOf` passes it a lambda capturing `xs : List a`. The closure is
//! `Send + Sync` only when `a` is, so `countOf`'s clause must carry that
//! capture obligation, or the emitted crate is ipe-accepted but fails
//! `cargo build` with E0277.
//!
//! The emit gate asserts the bounds on the emitted signatures; under
//! `IPE_E2E=1` the program is built, run, and its stdout matched against
//! `expected.txt`.

use std::path::{Path, PathBuf};

const GOLDEN: &str = "generic_bound_closure_capture";

/// Each `Main` function and the bounds its emitted clause must carry.
const BOUNDS: &[(&str, &[&str])] = &[("countOf", &["T1: 'static + Send + Sync"])];

fn fixture_dir(root: &Path) -> PathBuf {
    root.join("tests").join("golden").join(GOLDEN)
}

/// The emitted signature line of the `Main` function spelled `ipe_name`.
///
/// Matches the emitted `main_<snake_case>` name with its underscores removed
/// against the lower-cased Ipê name, so the check does not re-derive the
/// backend's snake-casing.
fn signature_of<'a>(emitted: &'a str, ipe_name: &str) -> Option<&'a str> {
    let wanted = format!("main{}", ipe_name.to_lowercase());
    emitted.lines().find(|line| {
        line.split_once("fn ").is_some_and(|(_, rest)| {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .filter(|c| *c != '_')
                .collect();
            name == wanted
        })
    })
}

/// Emit gate: the capturing caller's generic carries `Send + Sync + 'static`.
#[test]
fn generic_bound_closure_capture_bounds_emitted() {
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
        let signature = signature_of(&emitted, name);
        for need in *needs {
            assert!(
                signature.is_some_and(|line| line.contains(need)),
                "{GOLDEN}: `{name}`'s clause must carry `{need}` (the bound its \
                 callees oblige), got signature: {signature:?}"
            );
        }
    }
}

/// THE SEAL: under `IPE_E2E=1` the emitted crate must build and print both counts.
#[test]
fn generic_bound_closure_capture_seal_runs() {
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
