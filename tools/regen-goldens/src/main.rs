//! Regenerate every golden's expected emitted output from its Ipê source using
//! the CURRENT compiler.
//!
//! A golden test byte-compares the compiler's emitted `src/main.rs` (and, where
//! the golden checks them in, `Cargo.toml` and the per-module `ipe_mods/*.rs`
//! split files) against the stored fixture under `tests/golden/<name>/`. After
//! any emit-changing compiler change, those stored fixtures must be rebuilt.
//! This tool does exactly that, through the SAME emit path the golden harness
//! asserts on ([`ipe::build`] / [`ipe::build_project`], the `ipe` library — not
//! a possibly-stale pre-built binary), so a regeneration is faithful by
//! construction: on an unchanged compiler it is a no-op (`git status` stays
//! clean).
//!
//! Scope mirrors the golden harness's `assert_emitted_project_matches_golden_dir`
//! exactly — the byte-diffable EMITTED artifacts only:
//!   * `main.rs`            (always)
//!   * `Cargo.toml`         (only when the golden dir checks one in)
//!   * `ipe_mods/*.rs`      (the per-Ipê-module split, symmetric: emitted and
//!     stale-golden files both reconciled)
//!
//! It never touches the cached behavioural oracle (`expected.txt`,
//! `expected_go.txt`, `oracle.meta` — those belong to the oracle-refresh tool),
//! the Ipê sources (`Main.ipe`, `package.ipe`, `src/*.ipe`), or the reference
//! `ipe_runtime/` tree.
//!
//! Usage:
//!   regen-goldens                 # regenerate every golden with a stored main.rs
//!   regen-goldens <name> [<name>] # regenerate only the named golden(s)

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let filter: BTreeSet<String> = match ipe_docs::argv::host_args() {
        Ok(args) => args.into_iter().collect(),
        Err(refused) => {
            eprintln!("regen-goldens: {refused}");
            return ExitCode::FAILURE;
        }
    };

    let repo_root = repo_root();
    let golden_root = repo_root.join("tests").join("golden");

    // The emit path resolves the runtime by walking up from the CWD. Anchor the
    // CWD at the repo root so resolution is deterministic regardless of where the
    // tool was launched from.
    if let Err(e) = std::env::set_current_dir(&repo_root) {
        eprintln!(
            "regen-goldens: cannot chdir to repo root {}: {e}",
            repo_root.display()
        );
        return ExitCode::FAILURE;
    }
    let runtime = match ipe::resolve_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("regen-goldens: cannot resolve runtime: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let goldens = match collect_goldens(&golden_root, &filter) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("regen-goldens: {e}");
            return ExitCode::FAILURE;
        }
    };
    if goldens.is_empty() {
        eprintln!(
            "regen-goldens: no goldens with a stored main.rs matched under {}",
            golden_root.display()
        );
        return ExitCode::FAILURE;
    }

    let tmp_base = match ipe::scratch::ScratchDir::new("regen-goldens-emit") {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("regen-goldens: cannot create a private scratch directory: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failures = 0usize;
    let mut changed = 0usize;
    for dir in &goldens {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unnamed>");
        let out = tmp_base.path().join(name);
        let _ = std::fs::remove_dir_all(&out);
        match regenerate_one(dir, &out, &runtime) {
            Ok(n) => {
                changed += n;
                if n > 0 {
                    println!("regenerated {name} ({n} file(s) changed)");
                }
            }
            Err(e) => {
                failures += 1;
                eprintln!("FAILED {name}: {e}");
            }
        }
    }
    drop(tmp_base);

    println!(
        "regen-goldens: {} golden(s), {changed} file(s) rewritten, {failures} failure(s)",
        goldens.len()
    );
    if failures > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// The `ipe-lang` workspace root — two levels up from this crate's manifest
/// (`tools/regen-goldens`). Canonicalised so downstream path joins are absolute;
/// falls back to the un-normalised join if a component does not exist (never the
/// green path in a checked-out tree).
fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Every golden directory under `golden_root` that stores a `main.rs` fixture,
/// sorted for deterministic output. When `filter` is non-empty, only the named
/// goldens are returned (and a name that matches no golden is an error, so a
/// typo never silently regenerates nothing).
fn collect_goldens(golden_root: &Path, filter: &BTreeSet<String>) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(golden_root)
        .map_err(|e| format!("cannot read golden root {}: {e}", golden_root.display()))?;
    let mut seen_names: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read golden entry: {e}"))?;
        let dir = entry.path();
        if !dir.is_dir() || !dir.join("main.rs").is_file() {
            continue;
        }
        let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !filter.is_empty() && !filter.contains(name) {
            continue;
        }
        seen_names.insert(name.to_owned());
        out.push(dir);
    }
    if !filter.is_empty() {
        let missing: Vec<&String> = filter.iter().filter(|n| !seen_names.contains(*n)).collect();
        if !missing.is_empty() {
            return Err(format!(
                "no golden with a stored main.rs named: {}",
                missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    out.sort();
    Ok(out)
}

/// Emit one golden into `out` and reconcile its stored fixtures with the emitted
/// bytes. Returns the number of fixture files rewritten (0 = already current).
fn regenerate_one(dir: &Path, out: &Path, runtime: &Path) -> Result<usize, String> {
    emit_golden(dir, out, runtime)?;

    let emitted_src = out.join("src");
    let mut rewritten = 0usize;

    // main.rs — always.
    rewritten += sync_file(&emitted_src.join("main.rs"), &dir.join("main.rs"))?;

    // Cargo.toml — only when the golden checks one in (mirrors the harness).
    // The emitted manifest contains a machine-specific absolute path for the
    // ipe-runtime-rust dependency. Normalize it to the stable placeholder before
    // writing so the blessed golden is portable: a regen on any machine produces
    // an identical file and `git diff` stays empty (idempotent regen).
    if dir.join("Cargo.toml").is_file() {
        rewritten += sync_cargo_toml(&out.join("Cargo.toml"), &dir.join("Cargo.toml"))?;
    }

    // ipe_mods/*.rs — symmetric reconcile over the union of emitted and stored
    // module files, so a module the split no longer emits is removed (matching
    // the harness's stale-golden failure) and a new one is written.
    rewritten += sync_ipe_mods(&emitted_src.join("ipe_mods"), &dir.join("ipe_mods"))?;

    Ok(rewritten)
}

/// Run the compiler's emit path for one golden. A golden carrying a
/// `package.ipe` or legacy `ipe.toml` manifest is a multi-module project
/// ([`ipe::build_project`]); otherwise it is a single-file program built from
/// `Main.ipe` ([`ipe::build`]) — exactly the two shapes the golden harness
/// compiles.
fn emit_golden(dir: &Path, out: &Path, runtime: &Path) -> Result<(), String> {
    let package_ipe = dir.join("package.ipe");
    let ipe_toml = dir.join("ipe.toml");
    let result = if package_ipe.is_file() {
        ipe::build_project(&package_ipe, out, runtime)
    } else if ipe_toml.is_file() {
        ipe::build_project(&ipe_toml, out, runtime)
    } else {
        ipe::build(&dir.join("Main.ipe"), out, runtime)
    };
    result.map_err(|e| format!("compiler emit failed: {e:?}"))
}

/// Overwrite `dst` with the bytes of `src` when they differ, creating parent
/// directories as needed. Returns 1 if a write occurred, 0 if already identical.
fn sync_file(src: &Path, dst: &Path) -> Result<usize, String> {
    let want =
        std::fs::read(src).map_err(|e| format!("cannot read emitted {}: {e}", src.display()))?;
    if let Ok(existing) = std::fs::read(dst)
        && existing == want
    {
        return Ok(0);
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(dst, &want).map_err(|e| format!("cannot write {}: {e}", dst.display()))?;
    Ok(1)
}

/// Like [`sync_file`] but normalises the emitted `Cargo.toml` text before
/// comparing and writing: the `ipe-runtime-rust` dependency `path = "<abs>"`
/// is replaced with [`e2e_support::RUNTIME_PATH_PLACEHOLDER`] so the blessed
/// golden is portable across machines and a regen is idempotent (`git diff`
/// stays empty on an unchanged compiler).
fn sync_cargo_toml(src: &Path, dst: &Path) -> Result<usize, String> {
    let raw = std::fs::read_to_string(src)
        .map_err(|e| format!("cannot read emitted {}: {e}", src.display()))?;
    let want = e2e_support::normalize_runtime_dep_path(&raw);
    if let Ok(existing) = std::fs::read_to_string(dst)
        && existing == want
    {
        return Ok(0);
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(dst, want).map_err(|e| format!("cannot write {}: {e}", dst.display()))?;
    Ok(1)
}

/// Reconcile the emitted `ipe_mods/` split against the stored one: every `*.rs`
/// in the union is written from the emitted side, and a stored module the split
/// no longer emits is deleted. Returns the number of files rewritten or removed.
fn sync_ipe_mods(emitted_dir: &Path, golden_dir: &Path) -> Result<usize, String> {
    let emitted = rs_files_in(emitted_dir)?;
    let stored = rs_files_in(golden_dir)?;
    if emitted.is_empty() && stored.is_empty() {
        return Ok(0);
    }

    let mut rewritten = 0usize;
    for name in &emitted {
        rewritten += sync_file(&emitted_dir.join(name), &golden_dir.join(name))?;
    }
    // Stale stored modules the current split no longer emits.
    for name in stored.difference(&emitted) {
        let path = golden_dir.join(name);
        std::fs::remove_file(&path)
            .map_err(|e| format!("cannot remove stale {}: {e}", path.display()))?;
        rewritten += 1;
    }
    Ok(rewritten)
}

/// The set of `*.rs` file names directly in `dir` (empty if `dir` is absent).
fn rs_files_in(dir: &Path) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(names);
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.extension().is_some_and(|x| x == "rs")
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            names.insert(name.to_owned());
        }
    }
    Ok(names)
}
