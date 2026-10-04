#![forbid(unsafe_code)]
//! The LSP handoff seam (spec:
//! `docs/architecture/salsa-incremental-compilation-2026-07-11.md` §15).
//!
//! **Scope**: seam + integration test only; the LSP feature itself is a
//! separate deliverable. This file does NOT implement an LSP server,
//! JSON-RPC framing, or editor integration — it proves the salsa database
//! `ipe_db` already ships is directly reusable, unmodified, by an LSP-shaped
//! request loop: in-memory buffer inputs (no disk read), `Send`-safe
//! cross-thread reuse (one worker thread per demand, exactly `ipe watch`'s
//! orchestrator/worker split — see `crates/ipe/src/watch.rs`'s own doc
//! comment), and salsa's own cancellation firing on a `typecheck` demand
//! exactly as it already does on `ipe watch`'s `compile_prepared`
//! (`crates/ipe/tests/watch_cancellation.rs`).
//!
//! Nothing in `ipe_db` needs to change for this: [`ipe_db::SourceFile`] /
//! [`ipe_db::SourceRoot`] are plain salsa inputs the driver already sets
//! from disk-read text ([`ipe_db::sync_source_root`]) — an LSP driver sets
//! the exact same inputs from an unsaved editor buffer instead. `ipe_db`'s
//! own module doc states the invariant this seam depends on (INV-1): "no
//! query here touches `std::fs`, `std::env`, or the clock" — this test
//! suite never creates a temp file or opens a real path, which is the
//! structural (not merely observed) proof that the access pattern below
//! never routes through a file-reading path.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use ipe_db::{ImportResolution, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

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

const DEP_A: &str = "module A exposing (visible)\n\nvisible = 1\n";
const ENTRY_OK: &str =
    "module Main exposing (main)\n\nimport A exposing (visible)\n\nmain = visible\n";
/// Same buffer, one "keystroke" later: an annotated binding whose body no
/// longer matches — a real diagnostic a hover/problems-panel LSP push would
/// surface, not a parse failure.
const ENTRY_TYPE_ERROR: &str = "module Main exposing (main)\n\nimport A exposing (visible)\n\n\
    main : Int\n\
    main = \"not an int\"\n";

// ---------------------------------------------------------------------------
// (b) `IpeDatabase` is `Send` — a compile-time proof, not an inference from
// the fact that the tests below happen to compile.
// ---------------------------------------------------------------------------

/// The LSP's request loop must be able to hand a database clone to a
/// worker thread per demand (exactly [`ipe_db::IpeDatabase`]'s existing
/// `Clone` + `ipe watch`'s orchestrator/worker split). This is a
/// compile-time assertion, not a runtime one: if a future change to
/// `SharedInterner` or the `salsa::Storage<IpeDatabase>` field ever made the
/// database `!Send`, this line fails to compile rather than the property
/// silently regressing.
const _: fn() = || {
    const fn assert_send<T: Send>() {}
    assert_send::<IpeDatabase>();
};

// ---------------------------------------------------------------------------
// (a) In-memory buffer inputs drive diagnostics + navigation, no disk I/O
// ---------------------------------------------------------------------------

/// The LSP-shaped access pattern from the test-first spec:
/// "`set_source_text` on an open buffer, demand `typecheck` for
/// diagnostics, demand `parse`/`resolve_imports` for navigation" — driven
/// entirely against in-memory [`SourceFile`] inputs, then a simulated
/// keystroke (an in-place buffer edit) whose effect every re-demand
/// observes immediately.
#[test]
fn lsp_shaped_buffer_edit_drives_diagnostics_and_navigation_in_memory() {
    // "Open buffer": the editor hands the compiler two modules' full text.
    // Note there is no `Path`, no `std::fs`, anywhere in this test — the
    // structural proof that this pattern never touches disk.
    let mut db = IpeDatabase::new();
    let a = file(&db, &["A"], DEP_A);
    let entry = file(&db, &["Main"], ENTRY_OK);
    let root = root_of(&db, &[(&["A"], a), (&["Main"], entry)]);

    // Diagnostics: `typecheck` is the same coarse per-program seam `ipe
    // watch` already consumes (§9 of the spec) — an LSP's
    // publishDiagnostics push would demand exactly this.
    let solved = ipe_db::typecheck(&db, root, entry)
        .clone()
        .expect("well-typed buffer must type-check clean");
    assert!(
        !solved.env.is_empty(),
        "solved types must carry at least one binding"
    );

    // Navigation: `parse` (AST — outline/symbols) and `resolve_imports`
    // (import-edge resolution — go-to-def target) are both PER-FILE tracked
    // queries, unaffected by whole-program coarseness.
    let parsed = ipe_db::parse(&db, entry)
        .clone()
        .expect("buffer must parse");
    assert_eq!(parsed.imports.len(), 1, "one `import A` declaration");
    let resolutions = ipe_db::resolve_imports(&db, root, entry)
        .clone()
        .expect("resolve_imports must succeed");
    assert_eq!(resolutions.len(), 1);
    assert!(
        matches!(
            resolutions.first(),
            Some((_, ImportResolution::Resolved(resolved))) if *resolved == a
        ),
        "go-to-def target for `import A` must resolve to the A buffer's own SourceFile handle"
    );

    // Keystroke: the editor edits the OPEN buffer in place, introducing a
    // real type error. This is the exact `set_text_if_changed` call
    // `sync_source_root` makes for a disk-driven `ipe watch` edit — here fed
    // straight from the in-memory buffer text, no file write in between.
    assert!(
        ipe_db::set_text_if_changed(&mut db, entry, ENTRY_TYPE_ERROR),
        "the keystroke must be an observed text change"
    );

    // Re-demand: diagnostics reflect the edit immediately — no stale `Ok`
    // survives the keystroke.
    ipe_db::typecheck(&db, root, entry)
        .clone()
        .expect_err("the edited buffer must now surface a type error");

    // A second keystroke fixes the buffer; diagnostics converge back to
    // clean, and the navigation queries (never touched by the type error at
    // all — they are upstream of `typecheck`) still agree with the latest
    // text.
    assert!(ipe_db::set_text_if_changed(&mut db, entry, ENTRY_OK));
    ipe_db::typecheck(&db, root, entry)
        .clone()
        .expect("buffer fixed by a second keystroke must type-check clean again");
    assert!(ipe_db::parse(&db, entry).is_ok());
    assert!(ipe_db::resolve_imports(&db, root, entry).is_ok());
}

// ---------------------------------------------------------------------------
// (c) Cancellation on the next keystroke, using the LSP's own diagnostics
// query directly (not `ipe::compile_prepared`) — proving the cancellation
// mechanism already wired for `ipe watch` is genuinely query-agnostic.
// ---------------------------------------------------------------------------

/// Mirrors `crates/ipe/tests/watch_cancellation.rs`'s
/// `compile_worker_is_cancelled_by_a_concurrent_input_edit`, but against
/// [`ipe_db::typecheck`] directly (the LSP's own diagnostics demand) rather
/// than `ipe::compile_prepared` — proving the cancellation mechanism is a
/// property of the DATABASE, not of `ipe watch`'s particular call chain, so
/// the LSP inherits it for free.
///
/// Deterministic, no wall-clock race (same technique as the watch proof):
/// an event callback signals the worker's FIRST `WillExecute` and parks the
/// worker there until the edit sets salsa's cancellation flag, so the edit
/// lands while the worker still has salsa checkpoints ahead of it (`parse` → `resolve_imports` → `canonicalize` ×2 →
/// `module_interface` → `linked_program` → `typecheck`).
#[test]
fn lsp_diagnostics_query_is_cancelled_by_the_next_keystroke_and_converges_to_latest_state() {
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

    let a = file(&db, &["A"], DEP_A);
    let entry = file(&db, &["Main"], ENTRY_OK);
    let root = root_of(&db, &[(&["A"], a), (&["Main"], entry)]);

    // The LSP demands diagnostics for the open buffer on a background
    // worker thread — never on the request-loop thread itself — holding a
    // CLONED database handle, exactly `ipe watch`'s orchestrator/worker
    // split (see the doc comment in `crates/ipe/src/watch.rs`).
    let db_worker = db.clone();
    let worker = thread::Builder::new()
        .spawn(move || {
            salsa::Cancelled::catch(AssertUnwindSafe(|| {
                ipe_db::typecheck(&db_worker, root, entry).clone()
            }))
        })
        .expect("spawn test thread");

    first_exec_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("worker never reached its first tracked-query checkpoint");

    // The "next keystroke": edit the SAME open buffer on the request loop's
    // OWN (original, non-cloned) db handle while the worker's diagnostics
    // pass is still in flight.
    assert!(ipe_db::set_text_if_changed(
        &mut db,
        entry,
        ENTRY_TYPE_ERROR
    ));

    let cancelled = worker.join().expect("worker thread must not panic");
    assert!(
        matches!(
            cancelled,
            Err(salsa::Cancelled::Local | salsa::Cancelled::PendingWrite)
        ),
        "the in-flight diagnostics query must be CANCELLED by the keystroke edit — \
         never allowed to commit a stale Ok(..) result racing the new text"
    );

    // The db converges to the LATEST input state with no manual recovery:
    // a plain fresh demand right after the cancelled worker joins sees the
    // edited buffer and reports the NEW diagnostic — proving no stale
    // result was committed anywhere along the cancelled query's path: the db
    // converges to the latest input state; no stale result is committed.
    ipe_db::typecheck(&db, root, entry)
        .clone()
        .expect_err("a fresh demand after the cancelling edit must see the edited buffer");
}
