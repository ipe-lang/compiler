#![forbid(unsafe_code)]
//! Incrementality proofs (spec:
//! `docs/architecture/salsa-incremental-compilation-2026-07-11.md` §5 row 2).
//!
//! The load-bearing test is `module_interface_firewall`: a body-only edit to
//! a dep module re-executes the dep's `canonicalize` but NOT its importer's —
//! the `module_interface` projection comes out equal, salsa backdates it, and
//! the importer's memo stays valid. Proven via salsa's event log
//! (`EventKind::WillExecute`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use ipe_db::{
    ImportResolution, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot, canonicalize,
    module_interface, resolve_imports,
};
use ipe_diagnostics::{Diagnostic, NameError};
use salsa::Setter as _;

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
    ///
    /// Needles are written with a trailing `(` (`"canonicalize("`) so
    /// `"resolve_imports("` never cross-matches `"imports("` and vice versa.
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
    file_with_origin(db, path, text, ModuleOrigin::User)
}

fn file_with_origin(
    db: &IpeDatabase,
    path: &[&str],
    text: &str,
    origin: ModuleOrigin,
) -> SourceFile {
    SourceFile::new(
        db,
        path.iter().map(|s| (*s).to_owned()).collect(),
        text.to_owned(),
        origin,
    )
}

fn root_of(db: &IpeDatabase, files: &[(&[&str], SourceFile)]) -> SourceRoot {
    SourceRoot::new(db, files_map(files))
}

fn files_map(files: &[(&[&str], SourceFile)]) -> BTreeMap<Vec<String>, SourceFile> {
    files
        .iter()
        .map(|(path, f)| (path.iter().map(|s| (*s).to_owned()).collect(), *f))
        .collect()
}

const DEP_A: &str = "module A exposing (visible)\n\nvisible = 1\n\nhidden = 2\n";
const DEP_A_BODY_EDIT: &str = "module A exposing (visible)\n\nvisible = 1\n\nhidden = 3\n";
const DEP_A_EXPORT_EDIT: &str =
    "module A exposing (visible, hidden)\n\nvisible = 1\n\nhidden = 2\n";
const IMPORTER_B: &str = "module B exposing (b)\n\nimport A exposing (visible)\n\nb = visible\n";
const UNRELATED_C: &str = "module C exposing (c)\n\nc = 10\n";
const UNRELATED_C_EDIT: &str = "module C exposing (c)\n\nc = 11\n";

/// Editing an unrelated module re-canonicalises only that module.
#[test]
fn canonicalize_granularity() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let c = file(&db, &["C"], UNRELATED_C);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b), (&["C"], c)]);

    // Cold run: all three canonicalize (B's demand recurses into A's).
    assert!(canonicalize(&db, root, b).is_ok(), "B must canonicalise");
    assert!(canonicalize(&db, root, a).is_ok());
    assert!(canonicalize(&db, root, c).is_ok());
    assert_eq!(log.executions_of("canonicalize("), 3, "cold run canons all");

    // Edit C ONLY, then demand all three again.
    log.clear();
    c.set_text(&mut db).to(UNRELATED_C_EDIT.to_owned());
    assert!(canonicalize(&db, root, a).is_ok());
    assert!(canonicalize(&db, root, b).is_ok());
    assert!(canonicalize(&db, root, c).is_ok());
    let total = log.executions_of("canonicalize(");
    assert_eq!(
        total, 1,
        "after editing C only, exactly one canonicalize re-executes (got {total})"
    );
}

/// Incrementality proof (the module-interface firewall): a body-only edit to
/// dep A re-runs `canonicalize(A)` and `module_interface(A)`, but the interface
/// value comes out EQUAL, salsa backdates it, and the importer's
/// `canonicalize(B)` memo is validated WITHOUT re-executing.
#[test]
fn module_interface_firewall() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let warm = canonicalize(&db, root, b).clone();
    assert!(warm.is_ok(), "importer must canonicalise on the warm run");
    assert_eq!(
        log.executions_of("canonicalize("),
        2,
        "warm run canons A + B"
    );

    // Body-only edit to A: `hidden` (a PRIVATE, unexported binding) changes.
    log.clear();
    a.set_text(&mut db).to(DEP_A_BODY_EDIT.to_owned());
    let after = canonicalize(&db, root, b).clone();
    assert!(after.is_ok());

    // A re-canonicalises; its interface recomputes (and backdates on equality).
    assert_eq!(
        log.executions_of("canonicalize("),
        1,
        "only the DEP re-canonicalises on a body-only edit — the importer is \
         firewalled by module_interface backdating"
    );
    assert_eq!(log.executions_of("module_interface("), 1);
    // The importer's memoized value is unchanged.
    assert_eq!(warm, after, "importer's canon result must be byte-stable");
}

/// The completeness counterpart (canon tier): changing the dep's EXPORT
/// surface must punch through the firewall and re-canonicalise the importer.
#[test]
fn module_interface_completeness() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert!(canonicalize(&db, root, b).is_ok());

    // Export-surface edit: A now ALSO exposes `hidden`.
    log.clear();
    a.set_text(&mut db).to(DEP_A_EXPORT_EDIT.to_owned());
    assert!(canonicalize(&db, root, b).is_ok());
    assert_eq!(
        log.executions_of("canonicalize("),
        2,
        "an export-surface change must re-canonicalise BOTH dep and importer"
    );
}

/// Closed-enum resolution values: in-set imports resolve to the dep's
/// `SourceFile`; kernel/missing imports are `Unresolved`.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn resolve_imports_shape() {
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(
        &db,
        &["B"],
        "module B exposing (b)\n\nimport A exposing (visible)\nimport Ipe.Io\n\nb = visible\n",
    );
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let resolutions = resolve_imports(&db, root, b);
    let Ok(resolutions) = resolutions else {
        panic!("B must parse");
    };
    let expected = vec![
        (vec!["A".to_owned()], ImportResolution::Resolved(a)),
        (
            vec!["Ipe".to_owned(), "Io".to_owned()],
            ImportResolution::Unresolved,
        ),
    ];
    assert_eq!(resolutions.as_ref(), &expected);
}

/// Add-a-module: a previously-missing import flips
/// `Unresolved` → `Resolved` when the file set gains the module, and the
/// importer re-canonicalises from red to green.
#[test]
fn resolve_imports_add_module() {
    let (mut db, log) = logged_db();
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["B"], b)]);

    // A is absent: import resolution is Unresolved and canon is red (N0020).
    let red = canonicalize(&db, root, b);
    assert!(
        matches!(
            &red,
            Err(Diagnostic::Name {
                msg: NameError::ModuleNotFound { .. },
                ..
            })
        ),
        "missing dep must surface IPE-N0020, got {red:?}"
    );

    // Add A to the file set.
    log.clear();
    let a = file(&db, &["A"], DEP_A);
    root.set_files(&mut db)
        .to(files_map(&[(&["A"], a), (&["B"], b)]));

    assert_eq!(
        resolve_imports(&db, root, b)
            .clone()
            .ok()
            .and_then(|r| r.first().map(|(_, res)| *res)),
        Some(ImportResolution::Resolved(a)),
        "adding the module must flip resolution to Resolved"
    );
    assert!(
        canonicalize(&db, root, b).is_ok(),
        "importer must re-canonicalise green after the module appears"
    );
    assert!(
        log.executions_of("resolve_imports(") >= 1,
        "file-set change must re-validate the importer's resolutions"
    );
}

/// Delete-a-module: removing an imported module flips its
/// importer red — never a stale green from the old memo.
#[test]
fn resolve_imports_delete_module() {
    let (mut db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert!(canonicalize(&db, root, b).is_ok(), "green while A exists");

    // Remove A from the file set (the input entity remains; the SET is the input).
    root.set_files(&mut db).to(files_map(&[(&["B"], b)]));

    let red = canonicalize(&db, root, b);
    assert!(
        matches!(
            &red,
            Err(Diagnostic::Name {
                msg: NameError::ModuleNotFound { .. },
                ..
            })
        ),
        "deleting the dep must re-resolve and go red, got {red:?}"
    );
}

/// Rename: retargeting the module path re-resolves importers;
/// fixing the importer's `import` line restores green.
#[test]
fn resolve_imports_rename_module() {
    let (mut db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);
    assert!(canonicalize(&db, root, b).is_ok());

    // Rename A → A2 (new path key, new module header).
    let a2 = file(
        &db,
        &["A2"],
        "module A2 exposing (visible)\n\nvisible = 1\n",
    );
    root.set_files(&mut db)
        .to(files_map(&[(&["A2"], a2), (&["B"], b)]));

    let red = canonicalize(&db, root, b);
    assert!(
        matches!(
            &red,
            Err(Diagnostic::Name {
                msg: NameError::ModuleNotFound { .. },
                ..
            })
        ),
        "importer must go red after the dep is renamed, got {red:?}"
    );

    // Fix B to import the new name → green again.
    b.set_text(&mut db)
        .to("module B exposing (b)\n\nimport A2 exposing (visible)\n\nb = visible\n".to_owned());
    assert!(canonicalize(&db, root, b).is_ok());
}

/// Shadow (driver trust tag): a USER file squatting on a
/// `Ipe.…` path stays IPE-N0025-rejected, while the same path with the
/// driver-vouched `EmbeddedStdlib` origin canonicalises.
#[test]
fn stdlib_shadow_stays_rejected() {
    let (db, _log) = logged_db();
    let squatter = file(
        &db,
        &["Ipe", "Fake"],
        "module Ipe.Fake exposing (x)\n\nx = 1\n",
    );
    let root = root_of(&db, &[(&["Ipe", "Fake"], squatter)]);
    let red = canonicalize(&db, root, squatter);
    assert!(
        matches!(
            &red,
            Err(Diagnostic::Name {
                msg: NameError::ReservedNamespace { .. },
                ..
            })
        ),
        "user file on a Std path must stay IPE-N0025-rejected, got {red:?}"
    );

    // Same path, driver-vouched origin (and the annotation the stdlib gate
    // requires) → legitimate.
    let (db2, _log2) = logged_db();
    let genuine = file_with_origin(
        &db2,
        &["Ipe", "Fake"],
        "module Ipe.Fake exposing (x)\n\nx : Int\nx = 1\n",
        ModuleOrigin::EmbeddedStdlib,
    );
    let root2 = root_of(&db2, &[(&["Ipe", "Fake"], genuine)]);
    assert!(
        canonicalize(&db2, root2, genuine).is_ok(),
        "driver-vouched EmbeddedStdlib origin must pass the reserved-namespace gate"
    );
}

/// The interface projection itself: exports carry exactly the exposed
/// surface, and a body-only edit leaves the interface value EQUAL (the
/// property backdating keys on).
#[test]
fn module_interface_value_stability() {
    let (mut db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let root = root_of(&db, &[(&["A"], a)]);

    let before = module_interface(&db, root, a).clone();
    a.set_text(&mut db).to(DEP_A_BODY_EDIT.to_owned());
    let after = module_interface(&db, root, a).clone();
    assert_eq!(
        before, after,
        "a private-body edit must not change the module interface value"
    );

    a.set_text(&mut db).to(DEP_A_EXPORT_EDIT.to_owned());
    let widened = module_interface(&db, root, a).clone();
    assert_ne!(
        before, widened,
        "an export-surface change MUST change the interface value"
    );
}
