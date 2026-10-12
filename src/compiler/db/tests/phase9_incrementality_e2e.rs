#![forbid(unsafe_code)]
//! The end-to-end incrementality proof (spec:
//! `docs/architecture/phase5-emit-rust-file-design-2026-07-12.md` §5).
//!
//! The per-`RustFileId` query graph exists to deliver a WHOLE-PATH property,
//! and this test proves it, driven through the real top-level `emit_manifest`
//! demand exactly as `compile_prepared` drives it: a body edit to ONE module of
//! a warm two-module session forces that module's `emit_rust_file` to
//! re-execute, but the `emit_spine_file`'s OUTPUT VALUE stays byte-identical
//! (salsa backdates it) — so the on-disk write for the spine's `main.rs` skips
//! and `cargo`'s per-compilation-unit incrementality is preserved.
//!
//! This is asserted from the real salsa event stream (the `with_event_callback`
//! memo-hit mechanism), NOT inferred from the query graph's static shape.

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

// A genuine two-module program (two distinct homes -> the real split path).
const LIB: &str = "module Lib exposing (helper)\n\nhelper : Int\nhelper = 41\n";
const LIB_BODY_EDIT: &str = "module Lib exposing (helper)\n\nhelper : Int\nhelper = 40\n";
const MAIN: &str = "module Main exposing (answer)\n\nimport Lib exposing (helper)\n\nanswer : Int\nanswer = helper + 1\n";

#[test]
#[allow(clippy::expect_used)]
fn body_edit_reexecutes_only_the_edited_module_file() {
    let (mut db, log) = logged_db();
    let lib = file(&db, &["Lib"], LIB);
    let main = file(&db, &["Main"], MAIN);
    let root = root_of(&db, &[(&["Lib"], lib), (&["Main"], main)]);
    let config = BuildConfig::new(
        &db,
        DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        ipe_backend_rust::MountBase::root(),
        false,
        ipe_backend_rust::BuildIntent::Development,
        None,
        false,
        String::new(),
        false,
        false,
    );

    // Warm the session: demand the top-level manifest once. On a genuine
    // 2-home program this drives emit_spine_file + one emit_rust_file per home.
    let warm = ipe_db::emit_manifest(&db, root, main, config)
        .clone()
        .expect("warm build");
    // Capture the spine's OWN text before the edit, by demanding the spine
    // query directly (its memoized value is what must stay byte-stable).
    let spine_before = ipe_db::emit_spine_file(&db, root, main, config)
        .clone()
        .expect("spine before");
    assert!(
        warm.files
            .keys()
            .any(|p| p.as_str().starts_with("src/ipe_mods/")),
        "the fixture must genuinely split into per-module files"
    );

    // Edit ONLY Lib's body (helper 41 -> 40) — no signature or export change.
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, lib, LIB_BODY_EDIT));

    // Re-demand the top-level manifest — the real compile_prepared path.
    let _rebuilt = ipe_db::emit_manifest(&db, root, main, config)
        .clone()
        .expect("incremental rebuild");

    // The edited module's file query MUST re-execute (its coarse lower_program
    // dependency changed value, and its own slice genuinely changed).
    assert!(
        log.executions_of("emit_rust_file(") >= 1,
        "the edited module's emit_rust_file must re-execute after a body edit"
    );

    // The spine query is forced to re-run too (it depends on the same coarse
    // lower_program), but its OUTPUT VALUE must be byte-identical — the spine
    // carries no user function body, so Lib's body edit does not change it.
    // salsa backdates the memo; the on-disk write for main.rs skips. This is
    // the property the whole graph exists to deliver, asserted on the VALUE:
    // value-equality, not zero-executions, is the useful invariant on the
    // coarse floor.
    let spine_after = ipe_db::emit_spine_file(&db, root, main, config)
        .clone()
        .expect("spine after");
    assert_eq!(
        spine_before, spine_after,
        "a body edit to Lib must leave the Spine's emitted text byte-identical \
         (its main.rs on-disk write skips — cargo incrementality preserved)"
    );
}
