//! The env-var aspect columns: registered, read-in-code, documented,
//! truthy-parse-consistent, prod-safety-gated.
//!
//! Each column judges one [`EnvItem`] of the [`EnvVarSurface`]. The registered
//! column judges an orphan read (a variable read in code with no registry home);
//! the remaining columns judge a registry entry and treat an orphan as not
//! applicable — an orphan has no registry row for read-in-code, documentation,
//! parsing, or prod-safety to judge.

use std::path::PathBuf;
use std::sync::OnceLock;

use ipe_docs::env_vars::EnvVar;

use crate::coverage::contract::{AspectCheck, Cell};
use crate::coverage::env_surface::{EnvItem, SourceReads};

/// The registered variable, or `NotApplicable` for an orphan read.
///
/// A small helper so each registry-only column early-returns uniformly.
const fn as_registered(item: &EnvItem) -> Option<&'static EnvVar> {
    match item {
        EnvItem::Registered(v) => Some(*v),
        EnvItem::OrphanRead(_) => None,
    }
}

// ── registered ────────────────────────────────────────────────────────────────

/// Column **registered**: every `IPE_*` read in the tree has a registry (or
/// exclusion) home — no orphan read.
///
/// An orphan read is a variable a code path reads but that the
/// [`ipe_docs::env_vars`] registry does not know, so it drifts undocumented and
/// unaudited. A registry entry passes trivially here; the orphan is the hole.
pub struct RegisteredColumn;

impl AspectCheck<EnvItem> for RegisteredColumn {
    fn name(&self) -> &'static str {
        "registered"
    }

    fn check(&self, item: &EnvItem) -> Cell {
        match item {
            EnvItem::Registered(_) => Cell::Ok,
            EnvItem::OrphanRead(name) => Cell::Hole(format!(
                "`{name}` is read in the source but is in neither ENV_VARS nor \
                 EXCLUDED_NAMES — register it (operator-facing) or exclude it \
                 (test/internal)"
            )),
        }
    }
}

// ── read-in-code ──────────────────────────────────────────────────────────────

/// Column **read-in-code**: every registered variable is actually read
/// somewhere — no dead registry entry.
///
/// A registry entry no code reads is documentation for a knob that does nothing;
/// it drifts as a promise the runtime never keeps. The scan excludes the registry
/// authoring files (the declaration is not a read), so a name found only there is
/// a genuine dead entry.
pub struct ReadInCodeColumn {
    reads: SourceReads,
}

impl ReadInCodeColumn {
    #[must_use]
    pub const fn new(reads: SourceReads) -> Self {
        Self { reads }
    }
}

impl AspectCheck<EnvItem> for ReadInCodeColumn {
    fn name(&self) -> &'static str {
        "read-in-code"
    }

    fn check(&self, item: &EnvItem) -> Cell {
        let Some(var) = as_registered(item) else {
            return Cell::not_applicable(
                "not a registered environment variable — this column judges registered vars only",
            );
        };
        let reads = match self.reads.all_reads() {
            Ok(reads) => reads,
            Err(refusal) => {
                return Cell::Hole(format!(
                    "`{}` cannot be checked for a read in the source: {refusal}",
                    var.name
                ));
            }
        };
        if reads.contains(var.name) {
            Cell::Ok
        } else {
            Cell::Hole(format!(
                "`{}` is registered in ENV_VARS but is read nowhere in the source \
                 — remove the dead entry or wire the read",
                var.name
            ))
        }
    }
}

// ── documented ────────────────────────────────────────────────────────────────

/// Column **documented**: every registered variable appears in
/// `docs/reference/env.md`, the generated reference.
///
/// The reference is generated from the registry, so a registered variable is
/// documented by construction unless the committed file has drifted from the
/// registry (its own gate). This column lifts that to a per-variable cell: a
/// variable whose name is absent from the committed reference is a hole.
pub struct DocumentedColumn {
    reference: Result<String, std::io::ErrorKind>,
}

impl DocumentedColumn {
    #[must_use]
    pub fn new() -> Self {
        Self::with_reference(load_env_reference())
    }

    /// The column over one read of the reference, its failure kind kept.
    const fn with_reference(reference: Result<String, std::io::ErrorKind>) -> Self {
        Self { reference }
    }
}

impl Default for DocumentedColumn {
    fn default() -> Self {
        Self::new()
    }
}

impl AspectCheck<EnvItem> for DocumentedColumn {
    fn name(&self) -> &'static str {
        "documented"
    }

    fn check(&self, item: &EnvItem) -> Cell {
        let Some(var) = as_registered(item) else {
            return Cell::not_applicable(
                "not a registered environment variable — this column judges registered vars only",
            );
        };
        let reference = match &self.reference {
            Ok(reference) => reference,
            Err(kind) => {
                return Cell::Hole(format!(
                    "docs/reference/env.md cannot be read ({kind}), so `{}` cannot be \
                     shown documented",
                    var.name
                ));
            }
        };
        // The reference renders each name inside backticks (`IPE_WEB_PORT`); match
        // that exact token so a name that is a prefix of another (IPE_WEB_STORE vs
        // IPE_WEB_STORE_PATH) is not falsely counted as documented.
        let token = format!("`{}`", var.name);
        if reference.contains(&token) {
            Cell::Ok
        } else {
            Cell::Hole(format!(
                "`{}` is registered but absent from docs/reference/env.md — \
                 regenerate the reference (`cargo run -p ipe_docs --bin \
                 gen-env-docs`)",
                var.name
            ))
        }
    }
}

/// Read the committed env reference once, keeping why a read failed.
fn load_env_reference() -> Result<String, std::io::ErrorKind> {
    static REFERENCE: OnceLock<Result<String, std::io::ErrorKind>> = OnceLock::new();
    REFERENCE
        .get_or_init(|| {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("docs/reference/env.md");
            std::fs::read_to_string(path).map_err(|error| error.kind())
        })
        .clone()
}

// ── truthy-parse-consistent ───────────────────────────────────────────────────

/// Column **truthy-parse-consistent**: a boolean-style variable routes through a
/// single canonical truthy parser rather than a per-site hand-rolled
/// `matches!(v, "1" | "true" | …)` table.
///
/// Advisory (a [`Cell::Warn`], not a [`Cell::Hole`]): a hand-rolled truthy table
/// is a readability and consistency smell, not a soundness gap — the divergent
/// truthy sets (`{1,true}` vs `{1,true,yes,on}` vs `{non-empty, != 0}`) accept
/// subtly different inputs, but each is fail-closed. The cleanup is tracked; this
/// column keeps it visible until one canonical parser subsumes the hand-rolls.
pub struct TruthyParseColumn {
    reads: SourceReads,
}

impl TruthyParseColumn {
    #[must_use]
    pub fn new(reads: &SourceReads) -> Self {
        Self {
            reads: reads.clone(),
        }
    }
}

impl AspectCheck<EnvItem> for TruthyParseColumn {
    fn name(&self) -> &'static str {
        "truthy-parse-consistent"
    }

    fn check(&self, item: &EnvItem) -> Cell {
        let Some(var) = as_registered(item) else {
            return Cell::not_applicable(
                "not a registered environment variable — this column judges registered vars only",
            );
        };
        if !is_boolean_style(var) {
            return Cell::not_applicable(
                "not a boolean-style variable — truthy-parse consistency applies to on/off \
                 toggles only",
            );
        }
        let hand_rolled = match self.reads.has_hand_rolled_truthy() {
            Ok(hand_rolled) => hand_rolled,
            Err(refusal) => {
                return Cell::Hole(format!(
                    "`{}` cannot be checked for a hand-rolled truthy table: {refusal}",
                    var.name
                ));
            }
        };
        if hand_rolled {
            Cell::Warn(format!(
                "`{}` is a boolean-style var and the tree still hand-rolls a \
                 `matches!(v, \"1\" | \"true\" | …)` truthy table rather than \
                 routing every boolean var through one canonical parser \
                 (cleanup tracked)",
                var.name
            ))
        } else {
            Cell::Ok
        }
    }
}

/// Whether a variable is boolean-style: its purpose describes an on/off toggle
/// keyed on truthy tokens.
fn is_boolean_style(var: &EnvVar) -> bool {
    let p = var.purpose;
    let mentions_truthy = p.contains("`1`")
        || p.contains("`true`")
        || p.contains("`on`")
        || p.contains("`off`")
        || p.contains("truthy");
    let mentions_disable_enable = p.contains("Set to")
        && (p.contains("disable") || p.contains("enable") || p.contains("off"));
    mentions_truthy || mentions_disable_enable
}

// ── prod-safety-gated ─────────────────────────────────────────────────────────

/// Column **prod-safety-gated**: a dev-only variable (a hot-swap token, a
/// state reset, a dev overlay) is inert or absent in a production build.
///
/// Advisory (a [`Cell::Warn`]): the registry marks these dev-only in prose and
/// the endpoints they gate are only mounted in a dev build, but this static
/// column cannot *prove* the prod build never reads the variable — proving
/// inertness needs the build columns (an emitted release binary that ignores it).
/// Until that probe exists, a dev-only variable is flagged so its prod-inertness
/// stays a watched claim rather than an unchecked one.
pub struct ProdSafetyColumn;

impl AspectCheck<EnvItem> for ProdSafetyColumn {
    fn name(&self) -> &'static str {
        "prod-safety-gated"
    }

    fn check(&self, item: &EnvItem) -> Cell {
        let Some(var) = as_registered(item) else {
            return Cell::not_applicable(
                "not a registered environment variable — this column judges registered vars only",
            );
        };
        if is_dev_only(var) {
            Cell::Warn(format!(
                "`{}` is a dev-only var; its inertness in a release build is \
                 asserted in prose but not yet proven by a prod-build probe",
                var.name
            ))
        } else {
            Cell::not_applicable(
                "not a dev-only variable — prod-safety gating applies to dev-only vars only",
            )
        }
    }
}

/// Whether a variable is dev-only: its purpose declares it has no effect in a
/// release build or must never be set in production.
fn is_dev_only(var: &EnvVar) -> bool {
    let p = var.purpose;
    p.contains("Dev-only")
        || p.contains("dev-only")
        || p.contains("never set in production")
        || p.contains("never set in CI or production")
        || p.contains("no effect on a release build")
        || p.contains("release build never sets it")
        || p.contains("never mounted in a release build")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_docs::env_vars::ENV_VARS;

    /// A reference that cannot be read holes every registered variable naming
    /// the cause.
    #[test]
    fn an_unreadable_env_reference_holes_with_its_cause() {
        let column = DocumentedColumn::with_reference(Err(std::io::ErrorKind::PermissionDenied));
        let var = ENV_VARS.first().expect("the env registry is non-empty");
        let cell = column.check(&EnvItem::Registered(var));
        let cause = std::io::ErrorKind::PermissionDenied.to_string();
        assert!(
            matches!(&cell, Cell::Hole(msg) if msg.contains(&cause)),
            "{cell:?}"
        );
    }
}
