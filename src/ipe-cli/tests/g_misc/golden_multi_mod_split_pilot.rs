//! Multi-module split pilot fixture: a deliberately MULTI-MODULE program
//! (`Main` + `Lib`) that ALSO uses `Ipe.Db`.
//!
//! This is the ONE fixture that exercises the multi-module split AND the
//! `SqlValue`/`SqlField` Spine-routing (design doc §2.2) together. `emit_program`
//! produces real per-module output: the golden
//! is the Spine-only `main.rs` (preamble + `SqlValue`/`SqlField` enums +
//! DB-projection impls + kernel-wrapper prelude + `fn main()` + the
//! `mod`/`pub(crate) use` barrel) PLUS one `ipe_mods/<ident>.rs` per Ipê module
//! (`ipe_mod_lib.rs`, `ipe_mod_main.rs`). The home-qualified names
//! (`lib_label`/`main_summary`, `LibStatus`) follow §1.3; the split
//! emission is the file split itself.
//!
//! Modelled on `golden_m0.rs`, using the shared directory-diff helper
//! `crate::support::assert_emitted_project_matches_golden_dir` for `main.rs` +
//! `Cargo.toml`, extended by a fixture-local `ipe_mods/*.rs` byte-diff for the
//! split's per-module files.

use std::path::{Path, PathBuf};

/// The `ipe-lang` workspace root (two levels up from this crate's manifest).
fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_dir() -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join("multi_mod_split_pilot")
}

// `runtime()` is non-`#[test]` scaffolding — `expect` is the idiomatic way to
// fail loudly on a broken environment (mirrors `golden_mm.rs`'s own helper).
#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

/// Byte-diff every checked-in `ipe_mods/<name>.rs` golden against its
/// counterpart under `<out>/src/ipe_mods/`. `emit_program` produces real
/// per-module output, so the pilot golden carries
/// one `ipe_mods/*.rs` file per Ipê module (`ipe_mod_lib.rs`,
/// `ipe_mod_main.rs`) alongside the Spine-only `main.rs`. The shared
/// `assert_emitted_project_matches_golden_dir` helper only diffs `main.rs` +
/// `Cargo.toml`; this fixture-local check extends that to the split's new
/// per-module files, so the multi-file output is proven byte-for-byte, not
/// merely that `main.rs` shrank. Under-emission (a golden module file with no
/// emitted counterpart) and content drift both fail loudly.
// The lone `panic!` guards a test-support invariant: the checked-in golden
// `ipe_mods/` dir must be readable, or the fixture itself is broken. Per-entry
// and per-file errors fold into `mismatches`/`assert!`; only the missing-dir
// case aborts, which IS the correct failure-reporting mechanism here.
#[allow(clippy::panic)]
fn assert_module_files_match_golden(out: &Path, golden_dir: &Path) {
    let golden_mods = golden_dir.join("ipe_mods");
    let emitted_mods = out.join("src").join("ipe_mods");
    let mut mismatches = Vec::new();
    let mut compared = 0usize;

    // Missing/unreadable golden dir is a broken-fixture invariant → abort
    // (see the function-level `#[allow(clippy::panic)]` justification). Per-entry
    // errors below fold into `mismatches` and surface through the final `assert!`.
    let entries = match std::fs::read_dir(&golden_mods) {
        Ok(entries) => entries,
        Err(e) => {
            panic!(
                "golden ipe_mods dir unreadable at {}: {e}",
                golden_mods.display()
            )
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                mismatches.push(format!("ipe_mods entry unreadable: {e}"));
                continue;
            }
        };
        let name = entry.file_name();
        let want_path = golden_mods.join(&name);
        let got_path = emitted_mods.join(&name);
        match (
            std::fs::read_to_string(&want_path),
            std::fs::read_to_string(&got_path),
        ) {
            (Ok(want), Ok(got)) if want == got => compared += 1,
            (Ok(want), Ok(got)) => mismatches.push(format!(
                "ipe_mods/{}: emitted != golden ({} vs {} bytes)",
                name.to_string_lossy(),
                got.len(),
                want.len(),
            )),
            (_, Err(e)) => mismatches.push(format!(
                "ipe_mods/{}: emitted missing or unreadable at {}: {e}",
                name.to_string_lossy(),
                got_path.display(),
            )),
            (Err(e), _) => mismatches.push(format!(
                "ipe_mods/{}: golden missing or unreadable at {}: {e}",
                name.to_string_lossy(),
                want_path.display(),
            )),
        }
    }
    assert!(
        mismatches.is_empty(),
        "ipe_mods golden mismatch:\n{}",
        mismatches.join("\n"),
    );
    assert!(
        compared >= 2,
        "expected at least the two pilot module files (ipe_mod_lib.rs, ipe_mod_main.rs) to be \
         compared, only {compared} matched — the split may have silently stopped materialising"
    );
}

#[test]
fn emits_split_spine_and_per_module_files() {
    let fixture = fixture_dir();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("multi_mod_split_pilot");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&fixture.join("package.ipe"), &out, &runtime());
    assert!(res.is_ok(), "build_project failed: {:?}", res.err());

    // Directory-diff the emitted project against the checked-in golden dir:
    // asserts the emitted Spine-only `src/main.rs` AND the golden `Cargo.toml`
    // match byte-for-byte (`main.rs` is the Spine
    // tier: preamble, SqlValue/SqlField enums + DB-projection impls, the
    // kernel-wrapper prelude, `fn main()`, and the `mod`/`pub(crate) use`
    // barrel — NOT the user modules' own types/funcs).
    crate::support::assert_emitted_project_matches_golden_dir(&out, &fixture);

    // …plus the per-Ipê-module files the split emits under
    // `src/ipe_mods/`. `ipe_mod_lib.rs`'s Db call site references
    // `MainSqlValue`/`MainSqlField` variants resolving via `use crate::*;`
    // back to the Spine's declarations — the file-level proof of §2.2's fix.
    assert_module_files_match_golden(&out, &fixture);
}

/// Full spine (gated on `IPE_E2E=1`): compile, build the emitted Cargo
/// project, and run it. Proves THE SEAL — the multi-module + `Ipe.Db` emitted
/// project actually `cargo build`s and runs. The two rows seeded in
/// `Lib.seedAndCount` are counted and printed as `seeded:2`.
#[test]
fn end_to_end_builds_and_prints_seeded_count() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let fixture = fixture_dir();
    // Build OUTSIDE the workspace tree (an emitted project under the
    // workspace target/ is rejected by cargo as a non-member package).
    let out = crate::support::scratch_root().join("ipec_multi_mod_split_pilot_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&fixture.join("package.ipe"), &out, &runtime());
    assert!(res.is_ok(), "build_project failed: {:?}", res.err());

    let outcome = crate::support::build_and_run_emitted("multi_mod_split_pilot", &out);
    assert_eq!(
        outcome.stdout.trim_end(),
        "seeded:2",
        "the two seeded rows must be counted and printed via the cross-module summary"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}
