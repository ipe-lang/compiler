//! Regression for the "Ipe.Csv record literal vs nominal `CsvDoc` mismatch at
//! the kernel boundary". A record literal of the canonical `Csv`
//! shape `{ header : List String, rows : List (List String) }` fed directly to
//! `Csv.encode` must not be emitted as a backend-synthesised `RecHeaderRows`
//! struct while the `csv_encode` kernel takes `ipe_runtime::csv::CsvDoc`:
//! that is `ipe` exit 0 then a `cargo build` E0308
//! (`expected CsvDoc, found RecHeaderRows`).
//!
//! So `ipe_lower::lower::ir_type_from_ty` / `ir_type_from_canon` fold a
//! record of that exact shape (field NAMES `header`/`rows` AND field TYPES
//! `List String` / `List (List String)`) to the nominal `IrType::CsvDoc`
//! (`is_csv_doc_shape` / `is_csv_doc_canon_shape`) — mirror of the
//! `HttpRequest` / `CacheCfg` folds. `ipe_backend_rust::emit_expr::emit_record`
//! defers to the lowerer's registered-struct decision, then falls back to its
//! own `CSV_DOC_FIELDS` name-only heuristic (sound: a genuine `Csv` literal
//! never gets a registered struct because the lowerer intercepts it first), so
//! the literal constructs the runtime `CsvDoc`.
//!
//! ## Why the emit-only assertions run in the DEFAULT gate
//!
//! `IPE_E2E`-gated tests do not run in the default `cargo nextest` gate. This
//! file's first test inspects the emitted `src/main.rs` text (no cargo build)
//! so it runs in the DEFAULT gate and pins the regression even when `IPE_E2E`
//! is unset; the second test is the `IPE_E2E`-gated cargo-build-and-run proof
//! that the emitted crate actually compiles AND prints the right count.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("csv_record_nominal_fold_seal")
        .join("Main.ipe")
}

/// Recursively concatenate every emitted `.rs` file under `dir`. The
/// `Csv.encode` call site lands in `src/ipe_mods/ipe_mod_main.rs` (top-level
/// bindings emit to per-module files), not `src/main.rs`, so the assertions
/// must scan the whole emitted tree rather than a single file.
fn concat_emitted_rs(dir: &Path, out: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            concat_emitted_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            out.push_str(&text);
            out.push('\n');
        }
    }
}

/// Build the fixture and return the concatenated emitted Rust source. `None`
/// when the runtime resolver is unavailable in this environment (mirrors the
/// resolve-skip convention every other golden test in this suite uses) or when
/// the build itself fails (the caller's `assert!` reports the diag).
fn built_main_rs(root: &Path, out: &Path) -> (Result<(), ipe::CliError>, Option<String>) {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let Ok(runtime) = ipe::resolve_runtime() else {
        return (Ok(()), None);
    };
    let built = ipe::build(&entry, out, &runtime);
    let emitted = if built.is_ok() {
        // Scan the emitted APP modules only (`src/ipe_mods/` + `src/main.rs`),
        // not the vendored `src/ipe_runtime/` — the runtime's own `csv.rs`
        // defines `CsvDoc` and would mask what the app-side codegen chose.
        let mut acc = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
        acc.push('\n');
        concat_emitted_rs(&out.join("src").join("ipe_mods"), &mut acc);
        Some(acc)
    } else {
        None
    };
    (built, emitted)
}

/// The `Csv`-shaped record literal must be emitted as the runtime `CsvDoc`
/// struct literal (`CsvDoc { header: ..., rows: ... }`), NOT a backend-
/// synthesised `RecHeaderRows` — the `csv_encode` kernel takes `CsvDoc`, so a
/// synthesised struct would reject at the call boundary with E0308.
#[test]
fn csv_record_literal_emits_runtime_csv_doc_struct() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_csv_record_nominal_fold_seal_emit");
    let (built, main_rs) = built_main_rs(&root, &out);
    assert!(
        built.is_ok(),
        "csv_record_nominal_fold_seal: must be accepted, got: {built:?}"
    );
    let Some(main_rs) = main_rs else {
        return; // resolver unavailable — skip, matches the other goldens
    };

    assert!(
        main_rs.contains("CsvDoc {"),
        "the `Csv`-shaped record literal fed to `Csv.encode` must be emitted \
         as a `CsvDoc {{ .. }}` struct literal (the runtime struct the \
         `csv_encode` kernel takes).\n--- src/main.rs ---\n{main_rs}"
    );
    assert!(
        !main_rs.contains("RecHeaderRows"),
        "the `Csv`-shaped record literal must NOT resolve to a synthesised \
         `RecHeaderRows` struct — that would mismatch the kernel's `CsvDoc` \
         param with E0308.\n--- src/main.rs ---\n{main_rs}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, actually `cargo build` the
/// emitted crate and run it. A `RecHeaderRows` fold would fail `cargo build`
/// with E0308 (`expected CsvDoc, found RecHeaderRows`); the nominal `CsvDoc`
/// fold builds and prints `2` (the parsed-back header has two columns, `id` +
/// `name`).
#[test]
fn csv_record_nominal_fold_seal_builds_and_runs() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_csv_record_nominal_fold_seal_e2e");
    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let entry = fixture_entry(&root);
    let _ = std::fs::remove_dir_all(&out);
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "csv_record_nominal_fold_seal: must be accepted, got: {built:?}"
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let outcome = crate::support::build_and_run_emitted("csv_record_nominal_fold_seal", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "csv_record_nominal_fold_seal: emitted crate must build and exit 0 \
         (pre-fix: E0308, `expected CsvDoc, found RecHeaderRows`); stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(outcome.stdout.trim(), "2", "wrong runtime output");
}
