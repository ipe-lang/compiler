//! The diagnostic surface: one row per `IPE-XXXX` code in [`ALL_CODES`], judged
//! on three aspect columns.
//!
//! Items are [`ipe_diagnostics::code::Code`] values drawn directly from the
//! single-source-of-truth [`ALL_CODES`] slice, so the surface stays in sync with
//! the taxonomy automatically — no secondary registry to maintain.
//!
//! Columns:
//!
//! - **`has-conforming-explain-page`** — the code's explain page exists (guaranteed
//!   by `include_str!` at compile time) AND its first line is exactly
//!   `# <CODE>: <title>` AND the body carries at least three ` ```ipe ` fences.
//!   Reuses the same invariants the in-crate `every_code_has_a_conforming_explain_page`
//!   test asserts, so this column is a standing per-code cell for the same check.
//!
//! - **`documented`** — the explain page exists and is non-empty. Because
//!   `include_str!` makes a missing file a build error, `documented` is structurally
//!   always `Ok` for any code in the taxonomy; the column still appears so future
//!   stubs are visible on the surface rather than hidden.
//!
//! - **`refusal-tested`** — a standing test in the test suite drives this code to
//!   fire. Two forms are recognised in `.rs` files under `src/` or `tools/` that
//!   are not registry or surface authoring files:
//!   1. The quoted wire string literal (e.g. `"IPE-N0028"`).
//!   2. The `Code` associated-constant identifier (e.g. `IPE_N0028`, optionally
//!      qualified as `Code::IPE_N0028`).
//!
//! A code with no match in either form is a Hole — a rejection one edit can
//! delete unnoticed. An [`ALLOWLIST`] in `diagnostic_coverage_matrix.rs` records
//! known, tracked gaps.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ipe_diagnostics::{ALL_CODES, Code, explain_page, title};

use crate::coverage::contract::{AspectCheck, Cell, Surface};
use crate::coverage::source_tree::{TreeRefusal, for_each_source};

// ── surface ───────────────────────────────────────────────────────────────────

/// Zero-sized: it enumerates `ALL_CODES` afresh on each [`Surface::all`].
#[derive(Clone, Copy, Debug, Default)]
pub struct DiagnosticSurface;

impl Surface for DiagnosticSurface {
    type Item = Code;

    fn name(&self) -> &'static str {
        "diagnostic"
    }

    fn all(&self) -> Vec<Code> {
        ALL_CODES.to_vec()
    }

    fn label(item: &Code) -> String {
        item.as_str().to_owned()
    }
}

// ── columns ───────────────────────────────────────────────────────────────────

/// Column **`has-conforming-explain-page`**: the explain page exists, its first
/// line is `# <CODE>: <title()>`, and it carries at least three ` ```ipe ` fences.
///
/// The `include_str!` in [`ipe_diagnostics::code::explain_page`] already makes a
/// missing file a build error; this column asserts the structural invariants on
/// top of bare existence so a skeletal or misnamed page is a surface Hole.
pub struct ExplainPageColumn;

impl AspectCheck<Code> for ExplainPageColumn {
    fn name(&self) -> &'static str {
        "has-conforming-explain-page"
    }

    fn check(&self, code: &Code) -> Cell {
        let Some(page) = explain_page(*code) else {
            // Structurally unreachable: `include_str!` fails the build first.
            return Cell::Hole(format!(
                "{} has no explain page (include_str! should have caught this at build time)",
                code.as_str()
            ));
        };
        let expected_header = format!("# {}: {}", code.as_str(), title(*code));
        let first_line = page.lines().next().unwrap_or("");
        if first_line != expected_header {
            return Cell::Hole(format!(
                "{} explain page line 1 is `{}`, expected `{}`",
                code.as_str(),
                first_line,
                expected_header,
            ));
        }
        let fence_count = page.matches("```ipe").count();
        if fence_count < 3 {
            return Cell::Hole(format!(
                "{} explain page has {} ```ipe fence(s), need >= 3",
                code.as_str(),
                fence_count,
            ));
        }
        Cell::Ok
    }
}

/// Column **`documented`**: the explain page is present and non-empty.
///
/// Because `include_str!` makes a missing page a compile error, this column is
/// structurally always `Ok` for any code reachable through `ALL_CODES`. It appears
/// so a stub page (empty after the header) is a visible Hole rather than a silent
/// gap.
pub struct DocumentedColumn;

impl AspectCheck<Code> for DocumentedColumn {
    fn name(&self) -> &'static str {
        "documented"
    }

    fn check(&self, code: &Code) -> Cell {
        match explain_page(*code) {
            None => Cell::Hole(format!("{} has no explain page", code.as_str())),
            Some(page) if page.trim().is_empty() => {
                Cell::Hole(format!("{} explain page is empty", code.as_str()))
            }
            Some(_) => Cell::Ok,
        }
    }
}

/// Column **`refusal-tested`**: a standing test drives this code to fire.
///
/// The scan recognises two forms in `.rs` files under `src/` or `tools/` that
/// are not registry or surface authoring files:
/// - the quoted wire string literal (e.g. `"IPE-N0028"`), and
/// - the `Code` associated-constant identifier (e.g. `IPE_N0028`, optionally
///   qualified as `Code::IPE_N0028`).
///
/// A match in either form means the code is exercised; no match is a Hole — a
/// rejection path one edit away from vanishing unnoticed.
pub struct RefusalTestedColumn {
    tested: TestedCodes,
}

impl RefusalTestedColumn {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tested: TestedCodes::scan(),
        }
    }
}

impl Default for RefusalTestedColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<Code> for RefusalTestedColumn {
    fn name(&self) -> &'static str {
        "refusal-tested"
    }

    fn check(&self, code: &Code) -> Cell {
        let found = match self.tested.contains(code.as_str()) {
            Ok(found) => found,
            Err(refusal) => {
                return Cell::Hole(format!(
                    "{} cannot be checked for a standing refusal test: {refusal}",
                    code.as_str()
                ));
            }
        };
        if found {
            Cell::Ok
        } else {
            Cell::Hole(format!(
                "{} ({}) has no standing test that drives it to fire — \
                 add a negative-suite case or record it in the allowlist with a tracking reason",
                code.as_str(),
                title(*code),
            ))
        }
    }
}

// ── test-scan ─────────────────────────────────────────────────────────────────

/// The set of diagnostic wire strings confirmed present in source files.
///
/// A code is counted when either its quoted wire string literal (e.g.
/// `"IPE-N0028"`) or its `Code` associated-constant identifier (e.g.
/// `IPE_N0028`) appears in a `.rs` file under `src/` or `tools/` that is not a
/// registry or surface authoring file.
///
/// Scanned once from the `src/` and `tools/` trees; cloned cheaply via the inner
/// [`Arc`] when columns are registered in a surface runner. A tree that cannot be
/// read whole leaves no code provably tested or untested.
#[derive(Clone, Debug)]
pub struct TestedCodes {
    inner: Arc<Result<BTreeSet<String>, TreeRefusal>>,
}

impl TestedCodes {
    /// Scan the workspace for source files referencing diagnostic codes.
    #[must_use]
    pub fn scan() -> Self {
        Self::scan_roots(&[workspace_path("src"), workspace_path("tools")])
    }

    /// Scan every `.rs` file under `roots`, or refuse the whole scan.
    fn scan_roots(roots: &[PathBuf]) -> Self {
        let mut found: BTreeSet<String> = BTreeSet::new();
        let scanned = roots
            .iter()
            .try_for_each(|root| scan_tree(root, &mut found))
            .map(|()| found);
        Self {
            inner: Arc::new(scanned),
        }
    }

    /// Whether the wire string (e.g. `"IPE-N0028"`) was found in a source file.
    ///
    /// # Errors
    ///
    /// The [`TreeRefusal`] that kept the scan from reading every source file.
    pub fn contains(&self, wire: &str) -> Result<bool, &TreeRefusal> {
        match self.inner.as_ref() {
            Ok(found) => Ok(found.contains(wire)),
            Err(refusal) => Err(refusal),
        }
    }
}

/// Resolve a workspace-root-relative path from this crate's manifest directory.
fn workspace_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// Files that declare the code taxonomy or author the surface itself.
///
/// Excluded from both the wire-literal and the constant-identifier scan: a
/// code that appears only in these files is not a tested refusal.
fn is_authoring_file(path: &Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/");
    s.contains("diagnostics/src/code.rs")
        || s.contains("ipe-cli/src/coverage/diagnostic_surface.rs")
        || s.contains("ipe-cli/tests/diagnostic_coverage_matrix.rs")
}

/// Files whose code-constant identifiers are bulk `use`/`pub use` re-exports
/// of the full taxonomy, not evidence of a test driving the code to fire.
///
/// Excluded from the constant-identifier scan only; their wire string literals
/// (e.g. in `HelpLine::SeeExplain`) remain eligible.
fn is_const_reexport_file(path: &Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/");
    s.contains("diagnostics/src/diagnostic.rs") || s.contains("diagnostics/src/lib.rs")
}

/// Walk `root`, collecting every recognised diagnostic code reference from `.rs` files.
///
/// # Errors
///
/// A [`TreeRefusal`] when any file under `root` cannot be listed or read.
fn scan_tree(root: &Path, found: &mut BTreeSet<String>) -> Result<(), TreeRefusal> {
    for_each_source(root, panic_scan::Want::RustFiles, |path, src| {
        if is_authoring_file(path) {
            return;
        }
        extract_wire_strings(src, found);
        if !is_const_reexport_file(path) {
            extract_constant_idents(src, found);
        }
    })
}

/// Extract every `"IPE-[A-Z][0-9]{4}"` quoted literal from a Rust source string.
fn extract_wire_strings(src: &str, found: &mut BTreeSet<String>) {
    let needle = "\"IPE-";
    let mut rest = src;
    while let Some(pos) = rest.find(needle) {
        // Advance past the opening quote.
        let Some(after_quote) = rest.get(pos + 1..) else {
            break;
        };
        rest = after_quote;
        let end = rest.find('"').unwrap_or(rest.len());
        let candidate = rest.get(..end).unwrap_or(rest);
        if is_valid_wire(candidate) {
            found.insert(candidate.to_owned());
        }
        rest = rest.get(end..).unwrap_or("");
    }
}

/// Extract every `IPE_[A-Z][0-9]{4}` identifier from a Rust source string and
/// insert its wire form (e.g. `IPE_N0028` → `IPE-N0028`) into `found`.
///
/// Word-boundary guards ensure only the exact 9-character token matches:
/// - the character immediately before `IPE_` (if any) must not be alphanumeric
///   or `_`, and
/// - the character immediately after the four digits (if any) must not be
///   alphanumeric or `_`.
///
/// This covers both the bare form (`IPE_N0028`) and the qualified form
/// (`Code::IPE_N0028`), while rejecting longer identifiers such as `XIPE_N0028`
/// or `IPE_N00281`.
fn extract_constant_idents(src: &str, found: &mut BTreeSet<String>) {
    let needle = "IPE_";
    let bytes = src.as_bytes();
    let mut start = 0usize;
    while let Some(rel) = src[start..].find(needle) {
        let pos = start + rel;

        // Word-boundary: char before `IPE_` must not be [A-Za-z0-9_].
        if pos > 0
            && let Some(&prev) = bytes.get(pos - 1)
            && (prev.is_ascii_alphanumeric() || prev == b'_')
        {
            start = pos + 1;
            continue;
        }

        // After "IPE_" expect exactly one uppercase ASCII letter then four digits.
        let after = pos + needle.len(); // index of char after "IPE_"
        let Some(tail) = src.get(after..after + 5) else {
            start = pos + 1;
            continue;
        };
        let mut tail_chars = tail.chars();
        let family = tail_chars.next().unwrap_or('\0');
        if !family.is_ascii_uppercase() {
            start = pos + 1;
            continue;
        }
        let digits: &str = &tail[1..];
        if !digits.chars().all(|c| c.is_ascii_digit()) {
            start = pos + 1;
            continue;
        }

        // Word-boundary: char after the four digits must not be [A-Za-z0-9_].
        let end = after + 5;
        if let Some(&next) = bytes.get(end)
            && (next.is_ascii_alphanumeric() || next == b'_')
        {
            start = pos + 1;
            continue;
        }

        // Convert identifier form to wire form: first `_` after `IPE` → `-`.
        let wire = format!("IPE-{family}{digits}");
        found.insert(wire);
        start = end;
    }
}

/// Whether `s` matches `IPE-[A-Z][0-9]{4}` exactly.
fn is_valid_wire(s: &str) -> bool {
    let Some(after_prefix) = s.strip_prefix("IPE-") else {
        return false;
    };
    let mut chars = after_prefix.chars();
    let Some(family) = chars.next() else {
        return false;
    };
    if !family.is_ascii_uppercase() {
        return false;
    }
    let digits: String = chars.collect();
    digits.len() == 4 && digits.chars().all(|c| c.is_ascii_digit())
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_consts(src: &str) -> BTreeSet<String> {
        let mut found = BTreeSet::new();
        extract_constant_idents(src, &mut found);
        found
    }

    /// A tree the walker refuses holes every code with the cause, never "untested".
    #[test]
    fn an_unlisted_tree_holes_every_code_with_its_cause() {
        let root = ipe_test_temp::temp_root().join(format!(
            "ipe-diagnostic-scan-missing-{}",
            std::process::id()
        ));
        let column = RefusalTestedColumn {
            tested: TestedCodes::scan_roots(std::slice::from_ref(&root)),
        };
        let code = ALL_CODES.first().expect("the registry declares a code");
        let cell = column.check(code);
        assert!(
            matches!(cell, Cell::Hole(ref why)
                if why.contains("cannot be listed") && why.contains(&*root.to_string_lossy())),
            "{cell:?}"
        );
    }

    #[test]
    fn bare_ident_maps_to_wire() {
        let found = collect_consts("assert_eq!(err.code(), IPE_N0028);");
        assert!(
            found.contains("IPE-N0028"),
            "bare IPE_N0028 must map to IPE-N0028"
        );
    }

    #[test]
    fn qualified_ident_maps_to_wire() {
        let found = collect_consts("let x = Code::IPE_N0028;");
        assert!(
            found.contains("IPE-N0028"),
            "Code::IPE_N0028 must map to IPE-N0028"
        );
    }

    #[test]
    fn t_family_ident_maps_to_wire() {
        let found = collect_consts("let x = Code::IPE_T0001;");
        assert!(
            found.contains("IPE-T0001"),
            "Code::IPE_T0001 must map to IPE-T0001"
        );
    }

    #[test]
    fn leading_alpha_rejected() {
        let found = collect_consts("XIPE_N0028");
        assert!(
            !found.contains("IPE-N0028"),
            "XIPE_N0028 must not match (leading alpha boundary violated)"
        );
    }

    #[test]
    fn trailing_digit_rejected() {
        let found = collect_consts("IPE_N00281");
        assert!(
            !found.contains("IPE-N0028"),
            "IPE_N00281 must not match (trailing digit boundary violated)"
        );
    }

    #[test]
    fn lowercase_family_rejected() {
        let found = collect_consts("IPE_n0028");
        assert!(
            !found.contains("IPE-n0028"),
            "IPE_n0028 must not match (lowercase family letter)"
        );
    }

    #[test]
    fn short_digits_rejected() {
        let found = collect_consts("IPE_N002");
        assert!(
            !found.contains("IPE-N002"),
            "IPE_N002 must not match (only 3 digits)"
        );
    }

    #[test]
    fn multiple_codes_in_one_source() {
        let src = "use ipe_diagnostics::{IPE_L0200, IPE_N0012};\nassert_eq!(x, IPE_T0001);";
        let found = collect_consts(src);
        assert!(found.contains("IPE-L0200"));
        assert!(found.contains("IPE-N0012"));
        assert!(found.contains("IPE-T0001"));
    }

    #[test]
    fn leading_underscore_rejected() {
        // _IPE_N0028 has `_` before IPE_, which is an identifier-continue char.
        let found = collect_consts("_IPE_N0028");
        assert!(
            !found.contains("IPE-N0028"),
            "_IPE_N0028 must not match (underscore is a word char)"
        );
    }
}
