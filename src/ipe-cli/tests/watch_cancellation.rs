#![forbid(unsafe_code)]
//! Cancellation proof: a concurrent input edit cancels an in-flight
//! `compile_prepared` demand via salsa's OWN cancellation mechanism — the
//! exact pattern `crates/ipe/src/watch.rs`'s orchestrator relies on (see
//! that module's doc comment "Cancellation, and why it needs no
//! extra machinery").
//!
//! Deterministic, no wall-clock race: warm salsa recompute on a tiny
//! fixture is fast enough that racing a real file-save against it (as an
//! end-to-end `ipe dev watch` test would have to) is unreliable. Instead this
//! test registers an event callback on the WORKER's database that signals
//! the very FIRST `WillExecute` and parks the worker there until the edit
//! sets salsa's cancellation flag — a two-module program (`A` imported by
//! `Main`) guarantees more tracked-query demands remain after that point
//! (`resolve_imports`, canonicalize ×2, `module_interface`, `linked_program`,
//! `typecheck`, `lower_program`, `emit_project`), so the cancelling edit is
//! GUARANTEED to land while the worker still has salsa checkpoints ahead of
//! it, not racing to land before the compile already finished.
//!
//! This is intentionally independent of `crate::watch`'s orchestrator
//! scaffolding — it exercises `ipe_db`'s cancellation contract directly
//! against `ipe::compile_prepared` (the exact function the orchestrator's
//! compile worker calls), so a failure here points at the MECHANISM, not at
//! `watch.rs`'s wiring around it.

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use ipe_db::{BuildConfig, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

const DEP_A: &str = "module A exposing (visible)\n\nvisible = 1\n";
const ENTRY: &str = "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.String as String\nimport A exposing (visible)\n\nmain : Task Error ()\nmain =\n    Io.println (String.fromInt visible)\n";

/// Inject the transitive closure of compiled-source stdlib modules that the
/// given file map's sources import into both `file_map` and `sources`.
/// Only modules absent from `file_map` are added; user modules already
/// present are left untouched.
fn inject_stdlib_closure(
    db: &IpeDatabase,
    file_map: &mut BTreeMap<Vec<String>, SourceFile>,
    sources: &mut BTreeMap<Vec<String>, (PathBuf, String)>,
) {
    use std::collections::VecDeque;

    let mut work: VecDeque<Vec<String>> = VecDeque::new();

    // Seed from every import in the already-present user files.
    for sf in file_map.values() {
        for imp in ipe_db::extract_imports_from_source(sf.text(db)) {
            if ipe_stdlib::is_compiled_source_segments(&imp) && !file_map.contains_key(&imp) {
                work.push_back(imp);
            }
        }
    }

    while let Some(path) = work.pop_front() {
        if file_map.contains_key(&path) {
            continue;
        }
        let Some(source) = ipe_stdlib::compiled_std_source_segments(&path) else {
            continue;
        };
        let sf = SourceFile::new(
            db,
            path.clone(),
            source.to_owned(),
            ModuleOrigin::EmbeddedStdlib,
        );
        let pb = PathBuf::from(format!("<stdlib>/{}.ipe", path.join("/")));
        file_map.insert(path.clone(), sf);
        sources.insert(path.clone(), (pb, source.to_owned()));

        for imp in ipe_db::extract_imports_from_source(source) {
            if ipe_stdlib::is_compiled_source_segments(&imp) && !file_map.contains_key(&imp) {
                work.push_back(imp);
            }
        }
    }
}

#[test]
fn compile_worker_is_cancelled_by_a_concurrent_input_edit() {
    let (first_exec_tx, first_exec_rx) = mpsc::channel::<()>();
    let (flag_set_tx, flag_set_rx) = mpsc::channel::<()>();
    let flag_set_rx = Mutex::new(flag_set_rx);
    let signalled = Arc::new(AtomicBool::new(false));
    let signalled_in_callback = Arc::clone(&signalled);
    let mut db = IpeDatabase::with_event_callback(Box::new(move |event: salsa::Event| {
        match event.kind {
            salsa::EventKind::WillExecute { .. }
                if !signalled_in_callback.swap(true, Ordering::SeqCst) =>
            {
                let _ = first_exec_tx.send(());
                // Park the worker until the edit raises the cancellation flag,
                // so its next checkpoint observes the flag however fast the
                // remaining queries run.
                if let Ok(rx) = flag_set_rx.lock() {
                    let _ = rx.recv_timeout(Duration::from_secs(10));
                }
            }
            salsa::EventKind::DidSetCancellationFlag => {
                let _ = flag_set_tx.send(());
            }
            _ => {}
        }
    }));

    let a_path = vec!["A".to_owned()];
    let main_path = vec!["Main".to_owned()];
    let a_file = SourceFile::new(&db, a_path.clone(), DEP_A.to_owned(), ModuleOrigin::User);
    let main_file = SourceFile::new(&db, main_path.clone(), ENTRY.to_owned(), ModuleOrigin::User);

    let mut file_map: BTreeMap<Vec<String>, SourceFile> =
        BTreeMap::from([(a_path.clone(), a_file), (main_path.clone(), main_file)]);
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::from([
        (a_path, (PathBuf::from("<test>/A.ipe"), DEP_A.to_owned())),
        (
            main_path.clone(),
            (PathBuf::from("<test>/Main.ipe"), ENTRY.to_owned()),
        ),
    ]);
    inject_stdlib_closure(&db, &mut file_map, &mut sources);
    let root = SourceRoot::new(&db, file_map);

    let config = BuildConfig::new(
        &db,
        ipe_backend_rust::DbDriver::Sqlite,
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

    let db_worker = db.clone();
    let entry_for_worker = main_path;
    let worker = thread::Builder::new()
        .spawn(move || {
            salsa::Cancelled::catch(AssertUnwindSafe(|| {
                ipe::compile_prepared(
                    &db_worker,
                    root,
                    &sources,
                    &entry_for_worker,
                    Path::new("<test>"),
                    config,
                )
            }))
        })
        .expect("spawn test thread");

    first_exec_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("worker never reached its first tracked-query demand");

    // Cancel by editing an input on the MAIN thread's (original) db handle —
    // exactly what `sync_source_root` does inside `watch.rs`'s orchestrator
    // on a settled batch, mirrored directly here without the orchestrator
    // scaffolding so this proof is about salsa's OWN mechanism.
    ipe_db::set_text_if_changed(
        &mut db,
        a_file,
        "module A exposing (visible)\n\nvisible = 2\n",
    );

    let result = worker.join().expect("worker thread must not panic");
    assert!(
        matches!(
            result,
            Err(salsa::Cancelled::Local | salsa::Cancelled::PendingWrite)
        ),
        "expected the in-flight compile to be CANCELLED by the concurrent edit \
         (the exact mechanism `ipe dev watch`'s Task-25 orchestrator relies on), \
         but it was not — got Ok(..) or an unexpected Cancelled variant"
    );
}

/// Negative control: WITHOUT a concurrent edit, the same two-module program
/// compiles successfully — proves the fixture itself is valid and that the
/// cancellation in the test above is caused by the edit, not by an
/// unrelated fixture defect.
#[test]
fn the_same_fixture_compiles_cleanly_without_a_concurrent_edit() {
    let db = IpeDatabase::new();
    let a_path = vec!["A".to_owned()];
    let main_path = vec!["Main".to_owned()];
    let a_file = SourceFile::new(&db, a_path.clone(), DEP_A.to_owned(), ModuleOrigin::User);
    let main_file = SourceFile::new(&db, main_path.clone(), ENTRY.to_owned(), ModuleOrigin::User);

    let mut file_map: BTreeMap<Vec<String>, SourceFile> =
        BTreeMap::from([(a_path.clone(), a_file), (main_path.clone(), main_file)]);
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::from([
        (a_path, (PathBuf::from("<test>/A.ipe"), DEP_A.to_owned())),
        (
            main_path.clone(),
            (PathBuf::from("<test>/Main.ipe"), ENTRY.to_owned()),
        ),
    ]);
    inject_stdlib_closure(&db, &mut file_map, &mut sources);
    let root = SourceRoot::new(&db, file_map);

    let config = BuildConfig::new(
        &db,
        ipe_backend_rust::DbDriver::Sqlite,
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

    let result =
        ipe::compile_prepared(&db, root, &sources, &main_path, Path::new("<test>"), config);
    assert!(result.is_ok(), "fixture must compile cleanly on its own");
}
