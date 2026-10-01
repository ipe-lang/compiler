//! The native-vs-legacy equivalence gate over the WHOLE golden corpus: run the
//! native Doc emit path against the legacy `emit_expr_at` + `rustfmt` path for every
//! single-module fixture and assert the two renders agree byte-for-byte. The native
//! path is the live emit path, so a divergence here is a native-renderer layout bug.
//!
//! It lowers every corpus program and spawns `rustfmt` per function body, so it
//! requires `rustfmt` on `PATH`.

use std::path::{Path, PathBuf};

use ipe_intern::Interner;

/// The `ipe-lang` workspace root (two levels up from this crate's manifest).
fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Lower a single-module `Main.ipe` entry to an [`ipe_ir::Program`], or `None`
/// when any pipeline stage rejects it (a multi-module or otherwise
/// single-file-unlowerable fixture — the sweep only covers the single-module
/// corpus, which is where `emit_expr_at` bodies live).
fn lower_entry(entry: &Path) -> Option<(Interner, ipe_ir::Program)> {
    let src = std::fs::read_to_string(entry).ok()?;
    let mut interner = Interner::new();
    let module = ipe_parse::parse_module(&src, &mut interner).ok()?;
    let canonical = ipe_canon::canonicalise(&module, &mut interner).ok()?;
    let types = ipe_types::infer(&canonical, &mut interner).ok()?;
    let program = ipe_lower::lower(&canonical, &types, &mut interner, "", "").ok()?;
    Some((interner, program))
}

/// Every golden corpus directory that carries both a `Main.ipe` source and a
/// checked-in `main.rs` emitted-Rust golden — the byte-exact reference the native
/// path must reproduce.
fn corpus_entries() -> Vec<PathBuf> {
    let golden = repo_root().join("tests").join("golden");
    let mut entries = Vec::new();
    let Ok(read) = std::fs::read_dir(&golden) else {
        return entries;
    };
    for dir in read.flatten() {
        let path = dir.path();
        if path.join("Main.ipe").is_file() && path.join("main.rs").is_file() {
            entries.push(path.join("Main.ipe"));
        }
    }
    entries.sort();
    entries
}

#[test]
fn native_vs_legacy_whole_corpus_sweep() {
    let entries = corpus_entries();
    assert!(
        !entries.is_empty(),
        "no corpus entries found under tests/golden (expected 70)"
    );

    let mut total_compared = 0usize;
    let mut total_skipped = 0usize;
    let mut all_divergences: Vec<String> = Vec::new();
    let mut lowered_programs = 0usize;

    for entry in &entries {
        let Some((interner, program)) = lower_entry(entry) else {
            // A fixture the single-file pipeline cannot lower (multi-module, or a
            // frontend-rejected shape) — its emitted bytes are covered by its own
            // golden, not this sweep.
            continue;
        };
        lowered_programs += 1;
        let (divergences, compared, skipped) =
            ipe_backend_rust::native_vs_legacy_sweep(&interner, &program)
                .expect("sweep must not error");
        total_compared += compared;
        total_skipped += skipped;
        let fixture = entry
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for d in divergences {
            all_divergences.push(format!(
                "DIVERGES in {fixture} :: fn {} (body {})\n  --- native ---\n{}\n  --- legacy ---\n{}\n",
                d.func, d.expr_head, d.native, d.legacy
            ));
        }
    }

    eprintln!(
        "native-vs-legacy WHOLE-CORPUS sweep: {lowered_programs} programs lowered, \
         {total_compared} bodies compared, {total_skipped} skipped, \
         {} diverged",
        all_divergences.len()
    );
    for d in &all_divergences {
        eprintln!("{d}");
    }
    assert!(
        all_divergences.is_empty(),
        "{} function body/bodies diverge between the native render and legacy \
         rustfmt across the corpus (see stderr) — a native-renderer layout bug",
        all_divergences.len()
    );
}
