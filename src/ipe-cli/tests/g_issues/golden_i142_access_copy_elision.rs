//! AUD-09 — type-directed `Copy` elision on record-field access.
//!
//! Emitting an UNCONDITIONAL `.clone()` on `Expr::Access` (on the belief that
//! rustc elides redundant clones) is wrong: rustc does NOT elide a
//! `.clone()` on a heap type — every heap-field read is an O(field-size) deep
//! copy, compounding to O(n²) in per-element render loops (the
//! "list-of-records renders" case). Even for `Copy` scalars the `.clone()`
//! call is pure noise.
//!
//! Instead (`docs/adr/0002-codegen-soundness-and-the-seal.md` §3): `Expr::Access`
//! carries the field's solved type (`field_ty`); the emitter reads
//! definitely-`Copy` fields BARE and keeps `.clone()` for everything else
//! (heap-backed, generics, composites). The heap half of the audit's fix
//! (last-use analysis) is explicitly deferred — spec §3.5.
//!
//! Two layers:
//! * an emission-level regression (no `IPE_E2E`) asserting the Copy/non-Copy
//!   split in the generated Rust text, and
//! * an E2E build+run proving correctness is unaffected
//!   (`IPE_E2E=1 cargo test -p ipe --test golden_i142_access_copy_elision`).

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile the fixture and return the concatenated emitted Rust sources.
fn emit_fixture(out_name: &str) -> String {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("copy_field_no_clone")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join(out_name);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else {
        return String::new();
    };

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for copy_field_no_clone: {:?}",
        built.err()
    );

    let src = out.join("src");
    let mut emitted = String::new();
    if let Ok(entries) = std::fs::read_dir(&src) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                emitted.push_str(&text);
                emitted.push('\n');
            }
        }
    }
    emitted
}

/// Emission-level regression (unit-tier, no `IPE_E2E`): the `Int` field read
/// must be BARE while the `String` field read keeps `.clone()` — proving the
/// type-directed split actually took effect, not merely that the program still
/// happens to run (which a no-op fix would also pass).
#[test]
fn copy_field_reads_bare_heap_field_keeps_clone() {
    let emitted = emit_fixture("ipec_i142_copy_field_no_clone_emit");

    let relevant = || {
        emitted
            .lines()
            .filter(|l| l.contains(".count") || l.contains(".label"))
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    };

    // `c.count : Int` — Copy: the read must NOT clone.
    assert!(
        !emitted.contains(".count.clone()"),
        "Copy Int field read must be bare (no .clone()).\nRelevant lines:\n{}",
        relevant()
    );
    assert!(
        emitted.contains(".count"),
        "the Int field must still be read.\nRelevant lines:\n{}",
        relevant()
    );
    // `c.label : String` — heap-backed: the read MUST keep `.clone()` (it is
    // read twice; eliding it would be a use-after-move, E0382).
    assert!(
        emitted.contains(".label.clone()"),
        "heap String field read must keep .clone().\nRelevant lines:\n{}",
        relevant()
    );
}

/// E2E: the elision must not change behavior — the emitted project builds
/// (cargo-0; a wrong elision on `.label` would be E0382 here) and prints the
/// exact expected value.
#[test]
fn copy_field_no_clone_compiles_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let _ = emit_fixture("ipec_i142_copy_field_no_clone_e2e");
    let out = crate::support::scratch_root().join("ipec_i142_copy_field_no_clone_e2e");

    let outcome = crate::support::build_and_run_emitted("copy_field_no_clone", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "binary must exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "6|xx",
        "Copy elision must not change program output"
    );
}
