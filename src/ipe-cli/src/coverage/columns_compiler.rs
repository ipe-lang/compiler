//! The compiler-crate aspect columns: tested, no-panic, documented.
//!
//! Each column judges one [`CompilerCrate`] of the [`CompilerSurface`]. All
//! three columns inspect the crate's `src/` tree directly, without building, so
//! they run in the fast (non-E2E) path.

use crate::coverage::compiler_surface::{CompilerCrate, has_prod_panic, prod_source, rust_files};
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

/// Column **no-panic**: no `unwrap()`, `expect(`, `panic!(`, or `.index(` in production source.
///
/// Production source excludes inline `#[cfg(test)]` / `mod tests { … }` blocks
/// and the out-of-line test modules [`panic_scan::is_verified_test_path`]
/// confirms (a `tests/` directory or `tests.rs` declared `#[cfg(test)] mod
/// tests;`); an unconfirmed test module stays in scope.
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
            let prod = prod_source(&src);
            if has_prod_panic(&prod) {
                let short = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
                violations.push(short.to_owned());
            }
        }

        if !unreadable.is_empty() {
            return Cell::Hole(format!(
                "`{}` cannot be audited for panic-prone patterns: unreadable \
                 production source: {}",
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
