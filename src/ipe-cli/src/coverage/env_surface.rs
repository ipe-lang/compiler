//! The env-var surface: one reconciled enumeration of every `IPE_*` variable the
//! runtime reads, paired with a scan of the source tree for the read sites.
//!
//! The `IPE_*` env vars drift the same way a stdlib symbol does: a variable read
//! in code but absent from the [`ipe_docs::env_vars`] registry is an orphan read,
//! and a registry entry no code reads is a dead entry. This surface fuses the
//! registry with a one-time source scan so both drifts are named at their
//! coordinate by the coverage columns.
//!
//! An [`EnvItem`] is either a [`ipe_docs::env_vars::EnvVar`] registry entry or an
//! orphan read literal found in the source with no registry (or exclusion) home.
//! The registered column judges orphan reads; the remaining columns apply only to
//! registry entries (an orphan has no registry facets to judge).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ipe_docs::env_vars::{ENV_VARS, EXCLUDED_NAMES, EnvVar};

use crate::coverage::contract::Surface;
use crate::coverage::source_tree::{TreeRefusal, for_each_source};

/// One item of the env-var surface: a registry entry, or an orphan read.
///
/// The registered column turns an orphan into a hole; the read-in-code,
/// documented, truthy-parse, and prod-safety columns judge a registry entry and
/// treat an orphan as not applicable (it has no registry row to judge).
#[derive(Clone, Debug)]
pub enum EnvItem {
    /// A variable declared in the [`ENV_VARS`] registry.
    Registered(&'static EnvVar),
    /// An `IPE_*` literal read in the source with no registry or exclusion home.
    OrphanRead(String),
}

impl EnvItem {
    /// The variable name, for either kind.
    #[must_use]
    pub const fn name(&self) -> &str {
        match self {
            Self::Registered(v) => v.name,
            Self::OrphanRead(name) => name.as_str(),
        }
    }
}

/// The env-var surface. Zero-sized: it reads the registry and scans the source
/// afresh on each [`Surface::all`], so the enumeration reflects the current tree.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvVarSurface;

impl Surface for EnvVarSurface {
    type Item = EnvItem;

    fn name(&self) -> &'static str {
        "env-var"
    }

    fn all(&self) -> Vec<EnvItem> {
        let registered: BTreeSet<&'static str> = ENV_VARS.iter().map(|v| v.name).collect();
        let excluded: BTreeSet<&'static str> = EXCLUDED_NAMES.iter().copied().collect();

        let mut items: Vec<EnvItem> = ENV_VARS.iter().map(EnvItem::Registered).collect();

        // Orphan reads: a variable a Rust `read_env_var`/`env::var` call reads
        // that neither the registry nor the exclusion list homes. Scoped to Rust
        // read *calls* (not every `IPE_*` mention) so a doc string, a template
        // placeholder, or a build-script variable is not a false orphan. A
        // tree that cannot be read whole names no orphan; the read-in-code
        // column then holes every registered variable with the cause.
        let scan = SourceReads::scan();
        if let Ok(reads) = scan.env_reads() {
            for name in reads {
                if !registered.contains(name.as_str()) && !excluded.contains(name.as_str()) {
                    items.push(EnvItem::OrphanRead(name.clone()));
                }
            }
        }

        // Deterministic order: by name, registry entries before an orphan of the
        // same name (an orphan never shares a registered name by construction).
        items.sort_by(|a, b| {
            a.name()
                .cmp(b.name())
                .then_with(|| kind_rank(a).cmp(&kind_rank(b)))
        });
        items
    }

    fn label(item: &EnvItem) -> String {
        item.name().to_owned()
    }
}

/// Sort tie-break: a registry entry sorts before an orphan of the same name.
const fn kind_rank(item: &EnvItem) -> u8 {
    match item {
        EnvItem::Registered(_) => 0,
        EnvItem::OrphanRead(_) => 1,
    }
}

/// The result of scanning the source tree for `IPE_*` variable use.
///
/// Two name sets, because "read" means different things to two columns:
///
/// - `rust_literals` — every `"IPE_…"` string literal in a Rust file that is not a
///   registry-authoring file. A name is read via its literal whether the call is
///   direct (`read_env_var("IPE_…")`) or bound to a `const NAME = "IPE_…"` the
///   runtime then reads, so the literal is the read's fingerprint. A literal with
///   no registry home is a genuine orphan read (the registry-drift-gate scope).
/// - `all_reads` — `rust_literals` plus every shell reference (`$IPE_…`,
///   `${IPE_…}`, or an `IPE_…=` assignment). A registry entry a build or sweep
///   script consumes is read by the tree even when no Rust reads it, so
///   read-in-code checks against this wider set. Shell references do NOT widen the
///   orphan scope: a script-local build variable is not an operator env var.
///
/// Plus whether any Rust file hand-rolls a truthy `matches!` table. Scanned once
/// and cloned into each column so the tree is walked a single time per run. A
/// tree that cannot be read whole answers every question with its refusal.
#[derive(Clone, Debug)]
pub struct SourceReads {
    inner: Arc<Result<SourceReadsInner, TreeRefusal>>,
}

#[derive(Debug, Default)]
struct SourceReadsInner {
    rust_literals: BTreeSet<String>,
    all_reads: BTreeSet<String>,
    hand_rolled_truthy: bool,
}

impl SourceReads {
    /// Scan the `src/` and `tools/` trees for `IPE_*` variable use.
    #[must_use]
    pub fn scan() -> Self {
        Self::scan_roots(&[workspace_path("src"), workspace_path("tools")])
    }

    /// Scan every `.rs`, `.sh`, and `.bash` file under `roots`, or refuse the scan.
    fn scan_roots(roots: &[PathBuf]) -> Self {
        let mut acc = ScanAcc::default();
        let scanned = roots
            .iter()
            .try_for_each(|root| scan_tree(root, &mut acc))
            .map(|()| {
                acc.all_reads.extend(acc.rust_literals.iter().cloned());
                SourceReadsInner {
                    rust_literals: acc.rust_literals,
                    all_reads: acc.all_reads,
                    hand_rolled_truthy: acc.hand_rolled_truthy,
                }
            });
        Self {
            inner: Arc::new(scanned),
        }
    }

    /// The scan, or the refusal that kept it from reading every source file.
    fn scanned(&self) -> Result<&SourceReadsInner, &TreeRefusal> {
        self.inner.as_ref().as_ref()
    }

    /// Names read via a Rust `"IPE_…"` literal — the orphan-read scope.
    ///
    /// # Errors
    ///
    /// The [`TreeRefusal`] that kept the scan from reading every source file.
    pub fn env_reads(&self) -> Result<&BTreeSet<String>, &TreeRefusal> {
        self.scanned().map(|inner| &inner.rust_literals)
    }

    /// Names read anywhere in the tree, Rust or shell — the read-in-code scope.
    ///
    /// # Errors
    ///
    /// The [`TreeRefusal`] that kept the scan from reading every source file.
    pub fn all_reads(&self) -> Result<&BTreeSet<String>, &TreeRefusal> {
        self.scanned().map(|inner| &inner.all_reads)
    }

    /// Whether any read site hand-rolls a `matches!(v, "1" | "true" | …)` truthy
    /// table rather than routing through a single canonical parser.
    ///
    /// # Errors
    ///
    /// The [`TreeRefusal`] that kept the scan from reading every source file.
    pub fn has_hand_rolled_truthy(&self) -> Result<bool, &TreeRefusal> {
        self.scanned().map(|inner| inner.hand_rolled_truthy)
    }
}

/// A mutable accumulator threaded through the tree walk.
#[derive(Default)]
struct ScanAcc {
    rust_literals: BTreeSet<String>,
    all_reads: BTreeSet<String>,
    hand_rolled_truthy: bool,
}

/// Resolve a workspace-root-relative path from this crate's manifest directory.
fn workspace_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// Files whose `IPE_*` literals declare or index the registry (or are this
/// surface's own test fixtures), not reads of a variable. Counting a declaration
/// would make every registered name trivially "read", hiding a dead entry;
/// counting a fixture would make a probe name a false orphan.
fn is_registry_authoring_file(path: &Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/");
    s.contains("ipe-docs/src/env_vars.rs")
        || s.contains("ipe-docs/src/bin/gen_env_docs.rs")
        || s.contains("ipe-docs/src/lib.rs")
        || s.contains("ipe-cli/src/coverage/")
        || s.contains("ipe-cli/tests/env_var_coverage_matrix.rs")
}

/// Walk one tree, folding each file's `IPE_*` use into the accumulator.
///
/// # Errors
///
/// A [`TreeRefusal`] when any file under `root` cannot be listed or read.
fn scan_tree(root: &Path, acc: &mut ScanAcc) -> Result<(), TreeRefusal> {
    for_each_source(root, panic_scan::Want::RustAndShellScripts, |path, src| {
        let ext = path.extension().and_then(|e| e.to_str());
        match ext {
            Some("rs") => {
                if is_registry_authoring_file(path) {
                    return;
                }
                for name in extract_ipe_literals(src) {
                    acc.rust_literals.insert(name);
                }
                if src.contains("matches!(v, \"1\" | \"true\"") {
                    acc.hand_rolled_truthy = true;
                }
            }
            Some("sh" | "bash") => {
                for name in extract_ipe_shell_refs(src) {
                    acc.all_reads.insert(name);
                }
            }
            _ => {}
        }
    })
}

/// Extract every `"IPE_[A-Z0-9_]+"` string literal from a Rust source string.
///
/// A name read via a `const NAME = "IPE_…"` indirection is caught by its literal
/// declaration, so this is the read's fingerprint whether the call is direct or
/// via a bound constant.
fn extract_ipe_literals(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(pos) = rest.find("\"IPE_") {
        // Step past the opening quote so the closing quote is the next one.
        let Some(after_quote) = rest.get(pos + 1..) else {
            break;
        };
        rest = after_quote;
        let end = rest.find('"').unwrap_or(rest.len());
        let candidate = rest.get(..end).unwrap_or(rest);
        if is_valid_ipe_name(candidate) {
            out.push(candidate.to_owned());
        }
        rest = rest.get(end..).unwrap_or("");
    }
    out
}

/// Extract every `IPE_*` variable a shell script references: `$IPE_…`,
/// `${IPE_…}`, or a bare `IPE_…=` assignment/export.
///
/// A leading name char before `IPE_` (as in the `__IPE_RUNTIME_PATH__` template
/// anchor or an `_IPE_…` script-local) disqualifies the match — only a token that
/// actually begins with `IPE_` is a reference to a registry variable.
fn extract_ipe_shell_refs(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = src.as_bytes();
    let mut i = 0;
    while let Some(pos) = src.get(i..).and_then(|s| s.find("IPE_")) {
        let start = i + pos;
        let preceded_by_name_char = start
            .checked_sub(1)
            .and_then(|p| bytes.get(p))
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
        let mut end = start;
        while let Some(c) = bytes.get(end) {
            if c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_' {
                end += 1;
            } else {
                break;
            }
        }
        if !preceded_by_name_char
            && let Some(name) = src.get(start..end)
            && is_valid_ipe_name(name)
        {
            out.push(name.to_owned());
        }
        i = end.max(start + 1);
    }
    out
}

/// Whether `s` matches `IPE_[A-Z0-9_]+` with a non-empty suffix.
fn is_valid_ipe_name(s: &str) -> bool {
    let Some(suffix) = s.strip_prefix("IPE_") else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::columns_env::{ReadInCodeColumn, TruthyParseColumn};
    use crate::coverage::contract::{AspectCheck, Cell};

    /// A tree the scan cannot read whole holes every registered variable with the
    /// cause, never "read nowhere" and never a clean truthy check.
    #[test]
    fn an_unlisted_tree_holes_every_registered_variable_with_its_cause() {
        let missing = ipe_test_temp::temp_root()
            .join(format!("ipe-env-surface-missing-{}", std::process::id()));
        let reads = SourceReads::scan_roots(&[missing]);
        assert!(reads.env_reads().is_err());
        assert!(reads.all_reads().is_err());
        assert!(reads.has_hand_rolled_truthy().is_err());
        let refused = |cell: &Cell| {
            matches!(cell, Cell::Hole(msg) if msg.contains("cannot be checked")
                && msg.contains("cannot be listed whole"))
        };
        let read_in_code = ReadInCodeColumn::new(reads.clone());
        let truthy = TruthyParseColumn::new(&reads);
        let mut truthy_holes = 0_usize;
        for var in ENV_VARS.iter() {
            let item = EnvItem::Registered(var);
            let cell = read_in_code.check(&item);
            assert!(refused(&cell), "{cell:?}");
            let cell = truthy.check(&item);
            if refused(&cell) {
                truthy_holes += 1;
            } else {
                assert!(matches!(cell, Cell::NotApplicable { .. }), "{cell:?}");
            }
        }
        assert!(truthy_holes > 0, "no boolean-style variable was judged");
    }
}
