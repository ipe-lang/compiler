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
//! - `no-panic` — `panic_scan::scan_str` (the same AST scanner the
//!   `panic-scan` CI job runs) finds no unsanctioned panic site in production
//!   code within `src/`, outside the confirmed out-of-line test modules
//!   ([`panic_scan::is_verified_test_path`]).
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
    ("ipe_fs_open", "fs_open"),
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
