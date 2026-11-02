//! Cycle-safe, per-declaration database accessors for interactive LSP request handlers.
//!
//! Every direct `ipe_db::canonicalize` demand on a cyclic import graph hits
//! salsa's dependency-cycle panic. The diagnostics worker avoids this by
//! gating on `topo_order` first (see `diagnostics.rs`). This module provides
//! the same gate as the shared accessors every interactive provider calls
//! instead of a raw query, making the ungated demand structurally
//! unrepresentable on the interactive path.
//!
//! The accessors read `ipe_db::lsp_degraded`, so one failing declaration
//! withholds only itself and the declarations that read it, never the whole
//! module. Diagnostics keep the strict, fail-first queries.

use std::sync::Arc;

use ipe_db::{CanonicalModule, IpeDatabase, ModuleTypes, SourceFile, SourceRoot};

/// One module's per-declaration analysis.
#[derive(Clone, Debug)]
pub struct Analysis {
    /// The canonical module, each failed value declaration left out and its
    /// occurrences poisoned.
    pub canonical: Arc<CanonicalModule>,
    /// Whether the module canonicalised with no failure, so its index records
    /// every occurrence the module spells.
    pub complete: bool,
}

/// The analysis of `file`, or `None` on an import cycle or when no declaration-level analysis exists.
///
/// Proves the import graph acyclic via `topo_order` before demanding any
/// canonicalisation, so a cyclic graph yields `None` here instead of salsa's
/// dependency-cycle panic.
#[must_use]
pub fn analysis(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: SourceFile,
    file: SourceFile,
) -> Option<Analysis> {
    ipe_db::topo_order(db, root, entry).as_ref().ok()?; // cycle → None, no panic
    let canonical = ipe_db::lsp_degraded::canonicalize(db, root, file)?;
    let complete = ipe_db::canonicalize(db, root, file).is_ok();
    Some(Analysis {
        canonical,
        complete,
    })
}

/// The solved types of `file`, each failing declaration pruned and every unpinned type withheld.
///
/// `None` on an import cycle or when no degraded solve of the module exists.
#[must_use]
pub fn module_types(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: SourceFile,
    file: SourceFile,
) -> Option<Arc<ModuleTypes>> {
    ipe_db::topo_order(db, root, entry).as_ref().ok()?; // cycle → None, no panic
    ipe_db::lsp_degraded::typecheck_module(db, root, entry, file)
}
