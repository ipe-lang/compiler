//! Every exported `Ipe.Random` member is CALLABLE from user code and completes
//! the SEAL.
//!
//! `Ipe.Random` is a compiled-source Layer-3 module: the entropy-Task tier
//! (`int`/`float`/`range`/`choice`/`shuffle`/`weighted`) resolves through
//! `Ffi.kernel "Random_*"` aliases to the registered `Random*` kernels, and the
//! seeded tier (`seed`/`seededInt`/`seededFloat`/`seededChoice` over the opaque
//! `Seed`) is pure Ipê over the seeded raw kernels
//! (`tests/golden/random_members/Main.ipe`). This pins ipe-0 ∧ cargo-0 ∧ run-0
//! (THE SEAL: ipe exit 0 ⇒ emitted Rust builds and runs): the entropy tier is
//! drawn through `Cmd.perform` and the seeded tier is asserted reproducible
//! (two draws from one `Seed` agree), so the rendered line is stable.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test g_issues golden_i672`.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn random_members_ipec_cargo_and_run_zero() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("random_members");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_random_members_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe-0: compiling a program that calls every Random member must succeed.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for random_members: {:?}",
        built.err()
    );

    // cargo-0 ∧ run-0: the binary builds, draws every tier, exits 0.
    let outcome = crate::support::build_and_run_emitted("random_members", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "random_members binary must exit 0 on stdin EOF; got {:?}",
        outcome.exit_code
    );
    assert!(
        outcome.stdout.contains("seeded:ok"),
        "the seeded tier must be reproducible (two draws from one Seed agree); got: {:?}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("entropy:ok"),
        "the entropy tier must draw successfully through Cmd.perform; got: {:?}",
        outcome.stdout
    );
}
