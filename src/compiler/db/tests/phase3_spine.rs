#![forbid(unsafe_code)]
//! Phase-3 spine proofs (spec:
//! `docs/architecture/salsa-incremental-compilation-2026-07-11.md` §5 row 3).
//!
//! - [`ipe_db::topo_order`]: memoized dep-first order; an import cycle is a
//!   IPE-N0021 **value**, never salsa's dependency-cycle panic.
//! - [`ipe_db::linked_program`]: the coarse whole-program spine — assembles
//!   every per-module `canonicalize` memo and links. Correct-but-coarse: any
//!   semantic edit re-links; byte-equal re-saves and repeat demands do not.
//! - [`ipe_db::kernel_types`]: the kernel type-scheme table as a memoized
//!   query — derived once, independent of every source edit.
//! - [`ipe_db::sync_source_root`]: the driver-boundary input reconciler — a
//!   byte-identical re-sync dirties nothing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use ipe_db::{
    Db as _, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot, kernel_types, linked_program,
    sync_source_root, topo_order,
};
use ipe_diagnostics::{Diagnostic, NameError};

/// A shared, poison-safe log of executed-query debug keys.
#[derive(Clone, Default)]
struct EventLog(Arc<Mutex<Vec<String>>>);

impl EventLog {
    fn push(&self, entry: String) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(entry);
    }

    /// Number of `WillExecute` events whose debug key mentions `needle`.
    fn executions_of(&self, needle: &str) -> usize {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|e| e.contains(needle))
            .count()
    }

    fn clear(&self) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

/// A database whose `WillExecute` events land in the returned log.
fn logged_db() -> (IpeDatabase, EventLog) {
    let log = EventLog::default();
    let sink = log.clone();
    let db = IpeDatabase::with_event_callback(Box::new(move |event: salsa::Event| {
        if let salsa::EventKind::WillExecute { database_key } = event.kind {
            sink.push(format!("{database_key:?}"));
        }
    }));
    (db, log)
}

fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
    SourceFile::new(
        db,
        path.iter().map(|s| (*s).to_owned()).collect(),
        text.to_owned(),
        ModuleOrigin::User,
    )
}

fn root_of(db: &IpeDatabase, files: &[(&[&str], SourceFile)]) -> SourceRoot {
    SourceRoot::new(
        db,
        files
            .iter()
            .map(|(path, f)| (path.iter().map(|s| (*s).to_owned()).collect(), *f))
            .collect(),
    )
}

const DEP_A: &str = "module A exposing (visible)\n\nvisible = 1\n\nhidden = 2\n";
const DEP_A_BODY_EDIT: &str = "module A exposing (visible)\n\nvisible = 1\n\nhidden = 3\n";
const IMPORTER_B: &str = "module B exposing (b)\n\nimport A exposing (visible)\n\nb = visible\n";
const CYCLIC_A: &str = "module A exposing (a)\n\nimport B\n\na = 1\n";
const CYCLIC_B: &str = "module B exposing (b)\n\nimport A\n\nb = 2\n";
const ENTRY_C: &str = "module C exposing (c)\n\nc = 3\n";

// ---------------------------------------------------------------------------
// topo_order
// ---------------------------------------------------------------------------

/// Dep-first order with the entry last; memoized on repeat demand.
#[test]
fn topo_order_dep_first_and_memoized() {
    let (db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let order = topo_order(&db, root, b)
        .clone()
        .expect("acyclic graph must order");
    assert_eq!(
        *order,
        vec![vec!["A".to_owned()], vec!["B".to_owned()]],
        "dep A precedes importer B"
    );
    assert_eq!(log.executions_of("topo_order("), 1);

    // Repeat demand is a memo hit.
    log.clear();
    let again = topo_order(&db, root, b).clone().expect("still ordered");
    assert_eq!(*again, *order);
    assert_eq!(
        log.executions_of("topo_order("),
        0,
        "repeat demand memoized"
    );
}

/// An import cycle is returned as the IPE-N0021 diagnostic value — this query
/// (and [`linked_program`], which gates on it) never reaches salsa's
/// dependency-cycle panic even on a direct demand against a cyclic graph.
#[test]
fn topo_order_cycle_is_a_value_not_a_panic() {
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], CYCLIC_A);
    let b = file(&db, &["B"], CYCLIC_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let err = topo_order(&db, root, a)
        .clone()
        .expect_err("A↔B cycle must be rejected");
    assert!(
        matches!(
            &err,
            Diagnostic::Name {
                msg: NameError::ImportCycle { .. },
                ..
            }
        ),
        "cycle must surface as IPE-N0021, got: {err:?}"
    );

    // The whole-program spine returns the same value-level diagnostic.
    let spine_err = linked_program(&db, root, a)
        .clone()
        .expect_err("spine sees the same cycle");
    assert!(
        matches!(
            &spine_err,
            Diagnostic::Name {
                msg: NameError::ImportCycle { .. },
                ..
            }
        ),
        "linked_program must propagate IPE-N0021, got: {spine_err:?}"
    );
}

/// A cycle among modules the ENTRY never reaches (orphans) is still detected.
/// Entry C imports nothing; the orphaned pair A↔B forms a cycle. The cycle
/// gate must cover the whole file set — not just the entry-reachable prefix —
/// so `topo_order` returns the IPE-N0021 value and `linked_program`'s
/// per-module `canonicalize` recursion never reaches salsa's dependency-cycle
/// panic.
#[test]
fn topo_order_orphan_cycle_is_a_value_not_a_panic() {
    let (db, _log) = logged_db();
    let c = file(&db, &["C"], ENTRY_C);
    let a = file(&db, &["A"], CYCLIC_A);
    let b = file(&db, &["B"], CYCLIC_B);
    let root = root_of(&db, &[(&["C"], c), (&["A"], a), (&["B"], b)]);

    let err = topo_order(&db, root, c)
        .clone()
        .expect_err("orphan A↔B cycle must be rejected");
    assert!(
        matches!(
            &err,
            Diagnostic::Name {
                msg: NameError::ImportCycle { .. },
                ..
            }
        ),
        "orphan cycle must surface as IPE-N0021, got: {err:?}"
    );

    // The driver-level spine canonicalises the orphan pair; it must return the
    // same value-level diagnostic rather than panic on the salsa cycle.
    let spine_err = linked_program(&db, root, c)
        .clone()
        .expect_err("spine sees the orphan cycle");
    assert!(
        matches!(
            &spine_err,
            Diagnostic::Name {
                msg: NameError::ImportCycle { .. },
                ..
            }
        ),
        "linked_program must propagate IPE-N0021 on an orphan cycle, got: {spine_err:?}"
    );
}

// ---------------------------------------------------------------------------
// linked_program (the coarse spine)
// ---------------------------------------------------------------------------

/// The linked module carries every module's defs (whole-program merge).
#[test]
fn linked_program_links_all_modules() {
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let linked = linked_program(&db, root, b)
        .clone()
        .expect("program must link");
    // A: visible + hidden; B: b — three defs in the merged module.
    assert_eq!(linked.module.defs.len(), 3, "A(2 defs) + B(1 def) merged");
    let interner = db.interner();
    let guard = interner.lock();
    let entry: Vec<&str> = linked
        .entry_name
        .iter()
        .map(|s| guard.resolve(*s).unwrap_or("<?>"))
        .collect();
    assert_eq!(entry, vec!["B"], "entry name is the demanded entry module");
}

/// Coarse-but-memoized: a repeat demand and a byte-equal re-save execute
/// nothing; a dep body edit re-executes the spine (the spine links at
/// whole-program granularity, so any semantic edit re-links).
#[test]
fn linked_program_memoized_coarse_floor() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert!(linked_program(&db, root, b).is_ok());
    assert_eq!(log.executions_of("linked_program("), 1);

    // Repeat demand: memo hit.
    log.clear();
    assert!(linked_program(&db, root, b).is_ok());
    assert_eq!(log.executions_of("linked_program("), 0);

    // Byte-equal re-save: boundary no-op, nothing executes.
    log.clear();
    assert!(!ipe_db::set_text_if_changed(&mut db, a, DEP_A));
    assert!(linked_program(&db, root, b).is_ok());
    assert_eq!(log.executions_of("linked_program("), 0);

    // Dep body edit: the coarse spine re-links (canonicalize(A) re-runs, its
    // value changed, so the assembled link input changed).
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_BODY_EDIT));
    assert!(linked_program(&db, root, b).is_ok());
    assert_eq!(
        log.executions_of("linked_program("),
        1,
        "coarse spine re-links on a semantic edit"
    );
}

// ---------------------------------------------------------------------------
// kernel_types
// ---------------------------------------------------------------------------

/// The kernel table is derived once and is independent of source edits: a
/// text edit re-executes nothing under `kernel_types`, and the memoized table
/// is exactly what a direct `ipe_types::kernel_type_table` read produces
/// against the same interner (one code path — no drift).
#[test]
fn kernel_types_memoized_and_source_independent() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let root = root_of(&db, &[(&["A"], a)]);

    let table = kernel_types(&db, root)
        .clone()
        .expect("kernel table must derive");
    assert_eq!(
        table.rows().len(),
        ipe_kernels::StdlibKernel::ALL.len(),
        "one row per wired kernel, schemed or not"
    );
    assert!(
        table.schemed().count() > 100,
        "the registry schemes hundreds of kernels, got {}",
        table.schemed().count()
    );
    assert_eq!(log.executions_of("kernel_types("), 1);

    // Repeat demand: memo hit.
    log.clear();
    assert!(kernel_types(&db, root).is_ok());
    assert_eq!(log.executions_of("kernel_types("), 0);

    // Source edits never re-derive the table.
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_BODY_EDIT));
    assert!(kernel_types(&db, root).is_ok());
    assert_eq!(
        log.executions_of("kernel_types("),
        0,
        "kernel table is independent of source text"
    );

    // Faithful lift: the query's table == a direct read through the same
    // scheme method inference uses, on the same interner.
    let direct = {
        let interner = db.interner().clone();
        let mut guard = interner.lock();
        ipe_types::kernel_type_table(&mut guard).expect("direct table must derive")
    };
    assert_eq!(*table, direct, "query table must equal the direct read");
}

// ---------------------------------------------------------------------------
// sync_source_root (driver-boundary reconciler)
// ---------------------------------------------------------------------------

/// A byte-identical re-sync dirties nothing (no re-executions); adding a
/// module updates the file set; removing it drops the module again.
#[test]
fn sync_source_root_noop_add_remove() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert!(linked_program(&db, root, b).is_ok());

    // Identical desired state: nothing re-executes on the next demand.
    let desired: BTreeMap<Vec<String>, (String, ModuleOrigin)> = [
        (vec!["A".to_owned()], (DEP_A.to_owned(), ModuleOrigin::User)),
        (
            vec!["B".to_owned()],
            (IMPORTER_B.to_owned(), ModuleOrigin::User),
        ),
    ]
    .into_iter()
    .collect();
    log.clear();
    sync_source_root(&mut db, root, &desired);
    assert!(linked_program(&db, root, b).is_ok());
    assert_eq!(
        log.executions_of("linked_program("),
        0,
        "byte-identical re-sync must dirty nothing"
    );

    // Add module C: membership changes, the spine re-links and carries C.
    let mut with_c = desired.clone();
    with_c.insert(
        vec!["C".to_owned()],
        (
            "module C exposing (c)\n\nc = 3\n".to_owned(),
            ModuleOrigin::User,
        ),
    );
    sync_source_root(&mut db, root, &with_c);
    let linked = linked_program(&db, root, b)
        .clone()
        .expect("still links with C present");
    assert_eq!(linked.module.defs.len(), 4, "C's def joins the merge");

    // Remove C again: back to the original membership and def count.
    sync_source_root(&mut db, root, &desired);
    let linked = linked_program(&db, root, b)
        .clone()
        .expect("links after removal");
    assert_eq!(linked.module.defs.len(), 3, "C's def is gone after removal");
}
