#![forbid(unsafe_code)]
//! Build-config seam proofs (spec:
//! `docs/architecture/salsa-incremental-compilation-2026-07-11.md` §11 —
//! the `project_config()` seam).
//!
//! [`ipe_db::BuildConfig`] is a genuine salsa **input** carrying the ONE
//! build-relevant field with a real tracked-query consumer: `db_driver`.
//! [`ipe_db::emit_project`] is that consumer — the coarse SEAM over
//! `RustBackend::emit`, mirroring the `typecheck`/`lower_program` shape one
//! layer further down the pipeline.
//!
//! These tests prove two independent things:
//!
//! 1. **Coarse-but-real memoization** — repeat demand / byte-equal re-save
//!    execute nothing; a reachable dep's body edit re-executes.
//! 2. **Config lives on its own input** — a `BuildConfig`-only edit
//!    re-executes `emit_project` WITHOUT re-executing `linked_program` /
//!    `typecheck` / `lower_program` at all. This is the property that makes
//!    `BuildConfig` a genuine "config seam", not just a second parameter
//!    threaded into the whole-program spine.

use salsa::Setter as _;
use std::sync::{Arc, Mutex, PoisonError};

use ipe_backend_rust::DbDriver;
use ipe_db::{BuildConfig, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

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

// ---------------------------------------------------------------------------
// emit_project — the coarse per-program SEAM over `RustBackend::emit`
// ---------------------------------------------------------------------------

#[test]
fn emit_project_memoized_coarse_floor() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);
    let config = BuildConfig::new(
        &db,
        DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        ipe_backend_rust::BuildIntent::Development,
        None,
        false,
        String::new(),
        false,
        false,
    );

    let emitted = ipe_db::emit_project(&db, root, b, config)
        .clone()
        .expect("trivial int program must emit");
    assert!(
        !emitted.cargo_toml.is_empty(),
        "emitted project must carry a Cargo.toml"
    );
    assert_eq!(log.executions_of("emit_project("), 1);

    // Repeat demand: memo hit.
    log.clear();
    assert!(ipe_db::emit_project(&db, root, b, config).is_ok());
    assert_eq!(
        log.executions_of("emit_project("),
        0,
        "repeat demand memoized"
    );

    // Byte-equal re-save: boundary no-op, nothing executes anywhere in the
    // chain (parse -> canonicalize -> linked_program -> typecheck ->
    // lower_program -> emit_project).
    log.clear();
    assert!(!ipe_db::set_text_if_changed(&mut db, a, DEP_A));
    assert!(ipe_db::emit_project(&db, root, b, config).is_ok());
    assert_eq!(log.executions_of("emit_project("), 0);

    // Dep body edit: the coarse seam re-executes end to end.
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_BODY_EDIT));
    assert!(ipe_db::emit_project(&db, root, b, config).is_ok());
    assert_eq!(
        log.executions_of("emit_project("),
        1,
        "coarse seam re-emits on a semantic edit anywhere in the program"
    );
    assert_eq!(log.executions_of("lower_program("), 1);
}

/// The property that makes `BuildConfig` a genuine config seam rather than
/// just a second argument: a `db_driver`-only edit re-executes
/// `emit_project` WITHOUT re-executing `linked_program` / `typecheck` /
/// `lower_program` at all — those queries never read `BuildConfig`, so they
/// are entirely unaffected by a config-only revision.
#[test]
fn emit_project_config_change_does_not_retrigger_lower() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);
    let config = BuildConfig::new(
        &db,
        DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        ipe_backend_rust::BuildIntent::Development,
        None,
        false,
        String::new(),
        false,
        false,
    );

    assert!(ipe_db::emit_project(&db, root, b, config).is_ok());
    assert_eq!(log.executions_of("emit_project("), 1);
    assert_eq!(log.executions_of("lower_program("), 1);
    assert_eq!(log.executions_of("typecheck("), 1);
    assert_eq!(log.executions_of("linked_program("), 1);

    log.clear();
    config.set_db_driver(&mut db).to(DbDriver::Postgres);
    assert!(ipe_db::emit_project(&db, root, b, config).is_ok());

    assert_eq!(
        log.executions_of("emit_project("),
        1,
        "a config-only edit must re-execute the seam that reads it"
    );
    assert_eq!(
        log.executions_of("lower_program("),
        0,
        "a db_driver edit must NOT retrigger lowering — lower_program never reads BuildConfig"
    );
    assert_eq!(
        log.executions_of("typecheck("),
        0,
        "a db_driver edit must NOT retrigger typecheck"
    );
    assert_eq!(
        log.executions_of("linked_program("),
        0,
        "a db_driver edit must NOT retrigger the canonicalisation/link spine"
    );

    // Repeat with the SAME (already-updated) config: full memo hit again.
    log.clear();
    assert!(ipe_db::emit_project(&db, root, b, config).is_ok());
    assert_eq!(
        log.executions_of("emit_project("),
        0,
        "repeat demand memoized"
    );
}

/// The other direction: a plain source edit (config untouched) re-executes
/// the whole chain through to `emit_project`, exactly like every other seam.
#[test]
fn emit_project_source_edit_retriggers_lower_and_emit() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);
    let config = BuildConfig::new(
        &db,
        DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        ipe_backend_rust::BuildIntent::Development,
        None,
        false,
        String::new(),
        false,
        false,
    );

    assert!(ipe_db::emit_project(&db, root, b, config).is_ok());

    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_BODY_EDIT));
    assert!(ipe_db::emit_project(&db, root, b, config).is_ok());
    assert_eq!(log.executions_of("lower_program("), 1);
    assert_eq!(log.executions_of("emit_project("), 1);
}

/// `emit_project` never reaches `RustBackend::emit` on ill-typed input — it
/// short-circuits through `lower_program`'s error via `?`, so a direct
/// demand on a red program surfaces the SAME diagnostic `lower_program`
/// itself would give.
#[test]
fn emit_project_short_circuits_on_lower_error() {
    const RED_ENTRY: &str = "module Entry exposing (e)\n\n\
        e : Int\n\
        e = \"not an int\"\n";
    let (db, _log) = logged_db();
    let entry = file(&db, &["Entry"], RED_ENTRY);
    let root = root_of(&db, &[(&["Entry"], entry)]);
    let config = BuildConfig::new(
        &db,
        DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        ipe_backend_rust::BuildIntent::Development,
        None,
        false,
        String::new(),
        false,
        false,
    );

    let lower_err = ipe_db::lower_program(&db, root, entry)
        .clone()
        .expect_err("ill-typed program must fail to lower");
    let emit_err = ipe_db::emit_project(&db, root, entry, config)
        .clone()
        .expect_err("must propagate lower's error");
    assert_eq!(
        <(ipe_diagnostics::Diagnostic, Vec<ipe_intern::Symbol>)>::from(lower_err),
        emit_err,
        "emit_project's error must be lower_program's own diagnostic, verbatim"
    );
}
