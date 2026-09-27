//! The compiler-crate surface: one row per compiler crate, judged on test
//! coverage, production-panic freedom, and module documentation.
//!
//! A [`CompilerCrate`] names one crate under `src/compiler/`. Each column
//! inspects the crate tree directly, without building, so the surface runs in
//! the fast (non-E2E) path alongside the env-var surface.
//!
//! **Columns**
//!
//! - `tested` — the crate has at least one `#[test]` attribute anywhere in its
//!   `src/` or `tests/` trees, signalling standing tests.
//! - `no-panic` — no `unwrap()`, `expect(`, `panic!(`, or `.index(` appears in
//!   production code within `src/`: source lines outside `#[cfg(test)]` /
//!   `mod tests { … }` blocks, in files that are not a confirmed out-of-line
//!   test module ([`panic_scan::is_verified_test_path`]).
//! - `documented` — `src/lib.rs` opens with at least one `//!` inner doc line.
//!
//! `staleness` was considered but dropped: measuring whether test coverage has
//! drifted behind code churn requires git-blame heuristics that produce too many
//! false positives to be actionable. The column is omitted; the three remaining
//! columns are concretely checkable without build or VCS history.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::coverage::contract::Surface;

/// One compiler crate on the surface.
#[derive(Clone, Debug)]
pub struct CompilerCrate {
    /// The Cargo package name (e.g. `ipe_parse`).
    pub name: &'static str,
    /// The crate directory name under `src/compiler/` (e.g. `parse`).
    pub dir: &'static str,
    /// Resolved `src/` path — production source; used for no-panic and
    /// documented columns.
    pub src_path: Arc<PathBuf>,
    /// Resolved crate root — includes `src/` and `tests/`; used for the
    /// tested column so integration tests count alongside unit tests.
    pub crate_path: Arc<PathBuf>,
}

/// All compiler crates that make up the Ipê compiler pipeline, in alphabetical
/// order by directory name.
///
/// This list is the SSOT for the surface. Add a new entry here when a new
/// compiler crate is created under `src/compiler/`.
static COMPILER_CRATES: &[(&str, &str)] = &[
    ("ipe_annotate", "annotate"),
    ("ipe_backend", "backend"),
    ("ipe_canon", "canon"),
    ("ipe_db", "db"),
    ("ipe_diagnostics", "diagnostics"),
    ("ipe_ffi", "ffi"),
    ("ipe_intern", "intern"),
    ("ipe_ir", "ir"),
    ("ipe_kernels", "kernels"),
    ("ipe_lint", "lint"),
    ("ipe_lower", "lower"),
    ("ipe_parse", "parse"),
    ("ipe_path_core", "path-core"),
    ("ipe_sandbox", "sandbox"),
    ("ipe_syntax", "syntax"),
    ("ipe_types", "types"),
    ("ipe_watch", "watch"),
];

/// The compiler-crate surface.
///
/// Zero-sized: it resolves `src/compiler/<dir>/src/` paths at enumeration time,
/// so no state needs to be stored between calls.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompilerSurface;

impl Surface for CompilerSurface {
    type Item = CompilerCrate;

    fn name(&self) -> &'static str {
        "compiler"
    }

    fn all(&self) -> Vec<CompilerCrate> {
        let compiler_root = compiler_root();
        COMPILER_CRATES
            .iter()
            .map(|(name, dir)| {
                let crate_root = compiler_root.join(dir);
                let src_path = Arc::new(crate_root.join("src"));
                let crate_path = Arc::new(crate_root);
                CompilerCrate {
                    name,
                    dir,
                    src_path,
                    crate_path,
                }
            })
            .collect()
    }

    fn label(item: &CompilerCrate) -> String {
        item.name.to_owned()
    }
}

/// Resolve the workspace-root-relative `src/compiler/` directory.
fn compiler_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("src/compiler")
}

// ── prod-source scanner ───────────────────────────────────────────────────────

/// Strip `#[cfg(test)]` blocks and `mod tests { … }` blocks from Rust source so
/// only production lines remain.
///
/// The strip is conservative: it recognises the two canonical test-gating
/// patterns used in this codebase (`#[cfg(test)]` before an item, and
/// `mod tests { … }` with an arbitrary depth). Any line inside such a block is
/// excluded from the scan result. Lines that are merely comments mentioning
/// "test" are kept — only attribute-gated blocks are removed.
///
/// A brace-balance counter is used to skip the body once the opening `{` of a
/// test block is found. This is not a full parser; it can mis-count over raw
/// strings or macros with unbalanced braces, but the codebase's style does not
/// use those in test blocks.
#[must_use]
pub fn prod_source(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut in_test_block = false;
    let mut depth: usize = 0;
    let mut skip_next_item = false;

    for line in src.lines() {
        let trimmed = line.trim();

        if in_test_block {
            for ch in line.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            in_test_block = false;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }

        // `#[cfg(test)]` or `#[test]` gates the *next* item.
        if trimmed == "#[cfg(test)]" || trimmed == "#[test]" {
            skip_next_item = true;
            continue;
        }

        if skip_next_item {
            skip_next_item = false;
            // Any braced item gated by #[cfg(test)]: enter test-block mode and
            // skip until the matching closing brace.
            if trimmed.contains('{') {
                in_test_block = true;
                depth = 0;
                for ch in line.chars() {
                    match ch {
                        '{' => depth += 1,
                        '}' => {
                            depth = depth.saturating_sub(1);
                            if depth == 0 {
                                in_test_block = false;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                continue;
            }
            // A non-braced item (a `use` or `type` alias) — skip only this line.
            continue;
        }

        // `mod tests {` (without a preceding `#[cfg(test)]`) is also a
        // conventional test module.
        if (trimmed.starts_with("mod tests") || trimmed.starts_with("pub mod tests"))
            && trimmed.contains('{')
        {
            in_test_block = true;
            depth = 1;
            continue;
        }

        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Whether a prod-stripped source string contains any panic-prone pattern.
///
/// Patterns checked: `unwrap()`, `expect(`, `panic!(`, `.index(`.
/// All four are prohibited in production code per the soundness principle.
#[must_use]
pub fn has_prod_panic(prod: &str) -> bool {
    prod.contains("unwrap()")
        || prod.contains("expect(")
        || prod.contains("panic!(")
        || prod.contains(".index(")
}

/// Collect every `.rs` file under `root`, skipping hidden directories and
/// `target/`.
#[must_use]
pub fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !root.exists() {
        return out;
    }
    let mut stack = vec![root.to_owned()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !name.starts_with('.') && name != "target" {
                    stack.push(path);
                }
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}
