//! The compiler-crate aspect columns: tested, no-panic, documented.
//!
//! Each column judges one [`CompilerCrate`] of the [`CompilerSurface`]. All
//! three columns inspect the crate's `src/` tree directly, without building, so
//! they run in the fast (non-E2E) path.

use crate::coverage::compiler_surface::{CompilerCrate, rust_files};
use crate::coverage::contract::{AspectCheck, Cell};

// ── tested ────────────────────────────────────────────────────────────────────

/// Column **tested**: the crate has at least one `#[test]` attribute anywhere
/// in its `src/` or `tests/` trees.
///
/// Integration tests under `tests/` count alongside inline unit tests: either
/// form signals deliberate test authorship for the crate's behaviour.
pub struct TestedColumn;

impl AspectCheck<CompilerCrate> for TestedColumn {
    fn name(&self) -> &'static str {
        "tested"
    }

    fn check(&self, item: &CompilerCrate) -> Cell {
        let files = rust_files(&item.crate_path);
        for path in &files {
            let Ok(src) = std::fs::read_to_string(path) else {
                continue;
            };
            if src.contains("#[test]") {
                return Cell::Ok;
            }
        }
        Cell::Hole(format!(
            "`{}` has no `#[test]` in its `src/` or `tests/` tree — add tests",
            item.name
        ))
    }
}

// ── no-panic ──────────────────────────────────────────────────────────────────

/// Column **no-panic**: `panic_scan::scan_str` finds no unsanctioned panic
/// site in production source.
///
/// The column judges through the same AST scanner the `panic-scan` CI job runs,
/// so it can never disagree with that gate: test-only nodes and
/// `IPE-RUST-AUDIT:ACCEPTED` sites are exempt there and here alike, and a
/// lint attribute such as `#[expect(clippy::x)]` is never mistaken for a call.
/// The out-of-line test modules [`panic_scan::is_verified_test_path`] confirms
/// are skipped; a file the scanner cannot read or parse holes the crate.
///
/// Panics in production code violate the soundness principle: a well-typed Ipê
/// program must never trigger a runtime failure in the generated Rust, and the
/// compiler itself holds to the same bar.
pub struct NoPanicColumn;

impl AspectCheck<CompilerCrate> for NoPanicColumn {
    fn name(&self) -> &'static str {
        "no-panic"
    }

    fn check(&self, item: &CompilerCrate) -> Cell {
        let files = rust_files(&item.src_path);
        let mut violations: Vec<String> = Vec::new();
        // An unread file is unaudited, not clean: it holes the crate.
        let mut unreadable: Vec<String> = Vec::new();

        for path in &files {
            let is_test_module = path
                .strip_prefix(item.src_path.as_path())
                .is_ok_and(|rel| panic_scan::is_verified_test_path(&item.src_path, rel));
            if is_test_module {
                continue;
            }
            let src = match std::fs::read_to_string(path) {
                Ok(src) => src,
                Err(error) => {
                    unreadable.push(format!("{} ({error})", path.display()));
                    continue;
                }
            };
            match panic_scan::scan_str(&src) {
                Ok(hits) if hits.is_empty() => {}
                Ok(_) => {
                    let short = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                    violations.push(short.to_owned());
                }
                Err(error) => unreadable.push(format!("{} ({error})", path.display())),
            }
        }

        if !unreadable.is_empty() {
            return Cell::Hole(format!(
                "`{}` cannot be audited for panic-prone patterns: unreadable or \
                 unparsable production source: {}",
                item.name,
                unreadable.join(", ")
            ));
        }
        if violations.is_empty() {
            Cell::Ok
        } else {
            violations.sort();
            violations.dedup();
            Cell::Hole(format!(
                "`{}` has panic-prone patterns (unwrap/expect/panic!/index) in \
                 production source: {}",
                item.name,
                violations.join(", ")
            ))
        }
    }
}

// ── documented ────────────────────────────────────────────────────────────────

/// Column **documented**: `src/lib.rs` opens with at least one `//!` inner-doc
/// line, giving the module a crate-level doc comment.
///
/// A crate without a doc comment is invisible to `ipe doc` and to any reader
/// starting at the module boundary.
pub struct DocumentedColumn;

impl AspectCheck<CompilerCrate> for DocumentedColumn {
    fn name(&self) -> &'static str {
        "documented"
    }

    fn check(&self, item: &CompilerCrate) -> Cell {
        let lib_rs = item.src_path.join("lib.rs");
        let Ok(src) = std::fs::read_to_string(&lib_rs) else {
            return Cell::Hole(format!(
                "`{}` has no `src/lib.rs` — cannot verify crate-level documentation",
                item.name
            ));
        };
        let has_doc = src.lines().any(|l| l.trim_start().starts_with("//!"));
        if has_doc {
            Cell::Ok
        } else {
            Cell::Hole(format!(
                "`{}` `src/lib.rs` has no `//!` inner-doc line — add a crate-level \
                 doc comment",
                item.name
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::NoPanicColumn;
    use crate::coverage::compiler_surface::CompilerCrate;
    use crate::coverage::contract::{AspectCheck, Cell};

    fn crate_with_lib(tag: &str, lib: &str) -> (PathBuf, CompilerCrate) {
        let root = ipe_test_temp::temp_root()
            .join(format!("ipe-no-panic-column-{tag}-{}", std::process::id()));
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("lib.rs"), lib).unwrap();
        let item = CompilerCrate {
            name: "probe",
            dir: "probe",
            src_path: Arc::new(src),
            crate_path: Arc::new(root.clone()),
        };
        (root, item)
    }

    #[test]
    fn a_production_unwrap_holes_the_crate() {
        let (root, item) = crate_with_lib(
            "unwrap",
            "pub fn f(o: Option<u8>) -> u8 {\n    o.unwrap()\n}\n",
        );
        let cell = NoPanicColumn.check(&item);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(
            matches!(cell, Cell::Hole(ref why) if why.contains("lib.rs")),
            "{cell:?}"
        );
    }

    #[test]
    fn a_lint_expectation_is_not_a_panic_site() {
        let (root, item) = crate_with_lib(
            "expect-attr",
            "#[expect(clippy::needless_pass_by_value)]\npub fn f(s: String) -> usize {\n    s.len()\n}\n",
        );
        let cell = NoPanicColumn.check(&item);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(matches!(cell, Cell::Ok), "{cell:?}");
    }

    #[test]
    fn unparsable_source_holes_the_crate() {
        let (root, item) = crate_with_lib("unparsable", "pub fn f( {\n");
        let cell = NoPanicColumn.check(&item);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(
            matches!(cell, Cell::Hole(ref why) if why.contains("unparsable")),
            "{cell:?}"
        );
    }
}
