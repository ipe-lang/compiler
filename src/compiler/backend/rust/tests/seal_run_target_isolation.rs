//! Regression guard for the no-explicit-bin-table invariant the backend SEAL
//! run-output migration depends on.
//!
//! A SEAL test that RUNS an emitted binary and asserts its stdout/exit now
//! builds through `seal_e2e::build_and_run_emitted`, which shares the warm
//! target across goldens by renaming EACH emitted crate's `[package] name`
//! uniquely before building (`e2e_support::build_and_run_rust`). That rename
//! only prevents one golden's binary from clobbering another's because the
//! base emit template (`templates/Cargo.toml`) declares no explicit `[[bin]]`
//! table and no `autobins = false` — cargo's own default ties the binary's
//! name to `[package] name`, so renaming the package also renames the
//! resulting binary artifact. A future template edit that adds an explicit
//! `[[bin]]` (fixing the binary name independent of the package) would
//! silently reopen the exact shared-target clobber hazard the migration
//! closed; this test pins the fact structurally so that edit breaks the build
//! here, not a run-output assertion two steps downstream.

/// The native emit template declares no `[[bin]]` table and no
/// `autobins = false` — the binary name follows `[package] name`, which is
/// what lets a per-golden package rename double as a per-golden binary
/// rename under the shared warm target.
#[test]
fn base_template_has_no_explicit_bin_table() {
    let template = include_str!("../templates/Cargo.toml");
    assert!(
        !template.contains("[[bin]]"),
        "an explicit [[bin]] table would fix the binary name independent of \
         [package] name, reopening the shared-target binary-clobber hazard \
         the per-golden package rename closes:\n{template}"
    );
    assert!(
        !template.contains("autobins"),
        "autobins = false would disable the implicit package-name-to-binary-\
         name convention the per-golden rename relies on:\n{template}"
    );
}
