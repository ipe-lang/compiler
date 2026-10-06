#![forbid(unsafe_code)]
//! Per-`RustFileId` salsa query-graph proofs (spec:
//! `docs/architecture/phase5-emit-rust-file-design-2026-07-12.md` §4).
//!
//! The per-`RustFileId` salsa query graph sits on top of the coarse
//! `lower_program` floor. It changes NO emitted bytes — it makes the
//! COMPILER's own re-derivation of each Rust file's content salsa-tracked and
//! memoized, so an unaffected module's text is not re-rendered when an
//! unrelated module is edited (§3.4).
//!
//! [`ipe_db::RustFileId`] is a genuine `#[salsa::interned]` key — distinct
//! from the non-interned `ipe_backend_rust::RustFileId` (§4.1). The rest of
//! the file proves the tracked queries built on it.

use std::sync::{Arc, Mutex, PoisonError};

use ipe_backend_rust::DbDriver;
use ipe_db::{BuildConfig, Db as _, IpeDatabase, ModuleOrigin, RustFileId, SourceFile, SourceRoot};
use ipe_ir::ModPath;

/// A shared, poison-safe log of executed-query debug keys — the same
/// `WillExecute`-event proof mechanism every prior seam's memoization test
/// uses (`phase6_build_config.rs`).
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

/// Intern a `ModPath` through the database's shared interner — the same table
/// every salsa query resolves symbols against, so a `ModPath` built here is
/// comparable to one the real lowering path produces.
///
/// `expect` is sanctioned here: this is a test helper, and interning a short
/// ASCII segment cannot fail on a fresh interner (`clippy.toml`'s
/// `allow-expect-in-tests` covers `#[test]` fns but not a free helper, so the
/// allow is explicit).
#[allow(clippy::expect_used)]
fn mod_path(db: &IpeDatabase, segs: &[&str]) -> ModPath {
    let mut interner = db.interner().lock();
    ModPath(
        segs.iter()
            .map(|s| {
                interner
                    .intern(s)
                    .expect("intern must succeed for a test segment")
            })
            .collect(),
    )
}

#[test]
fn rust_file_id_interns_distinct_homes_distinctly() {
    let db = IpeDatabase::new();
    let lib = mod_path(&db, &["Lib"]);
    let main = mod_path(&db, &["Main"]);

    let id_lib = RustFileId::new(&db, lib.clone());
    let id_main = RustFileId::new(&db, main);

    assert_ne!(
        id_lib, id_main,
        "distinct homes must intern to distinct RustFileId keys"
    );

    // Interning the SAME home twice returns the SAME salsa id (interning
    // dedups by value — the standard salsa-interned-key smoke test).
    let id_lib_again = RustFileId::new(&db, lib);
    assert_eq!(
        id_lib, id_lib_again,
        "interning the same home twice must return the same salsa id"
    );

    // The stored field round-trips.
    assert_eq!(*id_lib.home(&db), mod_path(&db, &["Lib"]));
}

// ---------------------------------------------------------------------------
// program_rust_file_ids / emit_spine_file / emit_rust_file
// (spec §4.2 + §4.3's honest divergence: assert on VALUE-equality, not
// zero-executions, since emit_rust_file is forced to re-run whenever its
// coarse `lower_program` dependency's value changes)
// ---------------------------------------------------------------------------

// A two-module program: `Lib` owns `helper`, `Main` owns `answer` and imports
// `Lib`. Both are genuine distinct `home`s, so the backend emits an own Rust
// file for each — exactly the multi-home shape per-file incrementality is
// built on.
const LIB: &str = "module Lib exposing (helper)\n\nhelper : Int\nhelper = 41\n";
const LIB_BODY_EDIT: &str = "module Lib exposing (helper)\n\nhelper : Int\nhelper = 40\n";
const MAIN_IMPORTS_LIB: &str = "module Main exposing (answer)\n\nimport Lib exposing (helper)\n\nanswer : Int\nanswer = helper + 1\n";
const MAIN_EDIT: &str = "module Main exposing (answer)\n\nimport Lib exposing (helper)\n\nanswer : Int\nanswer = helper + 2\n";
const EXTRA: &str = "module Extra exposing (bonus)\n\nbonus : Int\nbonus = 7\n";
const MAIN_IMPORTS_BOTH: &str = "module Main exposing (answer)\n\n\
    import Lib exposing (helper)\n\
    import Extra exposing (bonus)\n\n\
    answer : Int\nanswer = helper + bonus\n";

fn two_module_root(db: &IpeDatabase) -> (SourceRoot, SourceFile, SourceFile) {
    let lib = file(db, &["Lib"], LIB);
    let main = file(db, &["Main"], MAIN_IMPORTS_LIB);
    let root = root_of(db, &[(&["Lib"], lib), (&["Main"], main)]);
    (root, lib, main)
}

/// Look up the salsa `RustFileId` for a module path — intern its `home`
/// (interning dedups, so this yields the SAME id `emit_manifest` would demand),
/// after asserting it is genuinely one of the program's emitted homes.
/// Panics (test-only) if absent — a missing home is itself a bug the
/// assertion should surface loudly.
#[allow(clippy::expect_used)]
fn file_id_for<'db>(
    db: &'db IpeDatabase,
    root: SourceRoot,
    entry: SourceFile,
    segs: &[&str],
) -> RustFileId<'db> {
    let target = mod_path(db, segs);
    let homes = ipe_db::program_rust_file_ids(db, root, entry)
        .clone()
        .expect("program must produce file ids");
    assert!(
        homes.contains(&target),
        "expected {segs:?} to be one of the program's emitted homes"
    );
    RustFileId::new(db, target)
}

#[test]
#[allow(clippy::expect_used)]
fn emit_spine_file_memoized_coarse_floor() {
    let (mut db, log) = logged_db();
    let (root, _lib, main) = two_module_root(&db);
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

    let spine = ipe_db::emit_spine_file(&db, root, main, config)
        .clone()
        .expect("spine must render");
    assert!(!spine.is_empty(), "spine text must be non-empty");
    assert_eq!(log.executions_of("emit_spine_file("), 1);

    // Repeat demand: memo hit.
    log.clear();
    assert!(ipe_db::emit_spine_file(&db, root, main, config).is_ok());
    assert_eq!(
        log.executions_of("emit_spine_file("),
        0,
        "repeat demand memoized"
    );

    // Byte-equal re-save: boundary no-op, nothing executes.
    log.clear();
    assert!(!ipe_db::set_text_if_changed(
        &mut db,
        main,
        MAIN_IMPORTS_LIB
    ));
    assert!(ipe_db::emit_spine_file(&db, root, main, config).is_ok());
    assert_eq!(log.executions_of("emit_spine_file("), 0);

    // A dependency (source) edit re-executes the coarse floor.
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, main, MAIN_EDIT));
    assert!(ipe_db::emit_spine_file(&db, root, main, config).is_ok());
    assert_eq!(
        log.executions_of("emit_spine_file("),
        1,
        "a semantic edit re-executes the coarse spine seam"
    );
    assert_eq!(log.executions_of("lower_program("), 1);
}

/// Per-file incrementality invariant (spec §4.3). A body edit to module A
/// forces `lower_program` to re-execute (coarse floor, unchanged), which in
/// turn forces `emit_rust_file(B)` to re-run — so we do NOT assert zero
/// executions for B. The USEFUL invariant, the one that preserves `cargo`'s
/// per-compilation-unit incrementality, is that B's produced STRING comes out
/// byte-identical (salsa backdates B's memo, `emit_manifest`/`write_if_changed`
/// skip B's write). We assert exactly that.
#[test]
#[allow(clippy::expect_used)]
fn emit_rust_file_memoized_per_file() {
    let (mut db, _log) = logged_db();
    let (root, lib, main) = two_module_root(&db);
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

    // Interned ids carry `db`'s borrow, so they cannot be held across a
    // `&mut db` edit — but interning is stable (same `home` -> same id across
    // revisions), so re-deriving after the edit yields the SAME salsa key. We
    // therefore capture the "before" strings, drop the ids, mutate, then
    // re-derive.
    let (lib_before, main_before) = {
        let file_lib = file_id_for(&db, root, main, &["Lib"]);
        let file_main = file_id_for(&db, root, main, &["Main"]);
        let lib = ipe_db::emit_rust_file(&db, root, main, config, file_lib)
            .clone()
            .expect("Lib file must render");
        let main = ipe_db::emit_rust_file(&db, root, main, config, file_main)
            .clone()
            .expect("Main file must render");
        (lib, main)
    };
    assert_ne!(
        lib_before, main_before,
        "the two module files must have distinct text"
    );

    // Edit ONLY Lib's body (helper = 41 -> 40): no signature/export change.
    assert!(ipe_db::set_text_if_changed(&mut db, lib, LIB_BODY_EDIT));

    let file_lib = file_id_for(&db, root, main, &["Lib"]);
    let file_main = file_id_for(&db, root, main, &["Main"]);
    let lib_after = ipe_db::emit_rust_file(&db, root, main, config, file_lib)
        .clone()
        .expect("Lib re-renders after its own body edit");
    let main_after = ipe_db::emit_rust_file(&db, root, main, config, file_main)
        .clone()
        .expect("Main re-renders (forced by lower_program) after Lib's edit");

    assert_ne!(
        lib_before, lib_after,
        "Lib's OWN body edit must change Lib's emitted text"
    );
    assert_eq!(
        main_before, main_after,
        "the UNRELATED module Main's emitted text must be byte-identical after \
         a body edit to Lib (§4.3 red-green: salsa backdates, the on-disk write skips)"
    );
}

#[test]
#[allow(clippy::expect_used)]
fn program_rust_file_ids_tracks_module_add_delete() {
    let (mut db, _log) = logged_db();
    let lib = file(&db, &["Lib"], LIB);
    let main = file(&db, &["Main"], MAIN_IMPORTS_LIB);

    let root2 = root_of(&db, &[(&["Lib"], lib), (&["Main"], main)]);
    let ids2 = ipe_db::program_rust_file_ids(&db, root2, main)
        .clone()
        .expect("two-module program");
    assert_eq!(ids2.len(), 2, "two distinct homes -> two RustFileIds");

    // Add a third module `Extra` with a distinct home; wire `Main` to import
    // it so it is reachable (unreachable modules are DCE'd out of the program).
    let extra = file(&db, &["Extra"], EXTRA);
    assert!(ipe_db::set_text_if_changed(
        &mut db,
        main,
        MAIN_IMPORTS_BOTH
    ));
    let root3 = root_of(
        &db,
        &[(&["Lib"], lib), (&["Main"], main), (&["Extra"], extra)],
    );

    let ids3 = ipe_db::program_rust_file_ids(&db, root3, main)
        .clone()
        .expect("three-module program");
    assert_eq!(
        ids3.len(),
        3,
        "adding a reachable third module grows the RustFileId set by one"
    );
    assert_eq!(
        ids3.len(),
        ids2.len() + 1,
        "the set grew by exactly one on the module add"
    );
}

// ---------------------------------------------------------------------------
// emit_manifest (the Spine-collapse invariant at the SALSA layer)
// ---------------------------------------------------------------------------

/// For a SINGLE-module program, `emit_manifest` must be BYTE-IDENTICAL to
/// `emit_project` — the Spine-collapse invariant (§3.3), proven at the salsa
/// layer. This is the property that lets `compile_prepared` call
/// `emit_manifest` in place of `emit_project` (§4.4) with zero emitted-byte
/// change.
#[test]
#[allow(clippy::expect_used)]
fn emit_manifest_matches_emit_project_for_single_module() {
    let (db, _log) = logged_db();
    // A single user module (no imports) — exactly one distinct home, so the
    // Spine-collapse branch fires and the whole project is one `src/main.rs`.
    let main = file(
        &db,
        &["Main"],
        "module Main exposing (answer)\n\nanswer : Int\nanswer = 42\n",
    );
    let root = root_of(&db, &[(&["Main"], main)]);
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

    let via_project = ipe_db::emit_project(&db, root, main, config)
        .clone()
        .expect("emit_project must succeed");
    let via_manifest = ipe_db::emit_manifest(&db, root, main, config)
        .clone()
        .expect("emit_manifest must succeed");

    assert_eq!(
        via_manifest.cargo_toml, via_project.cargo_toml,
        "Cargo.toml must be byte-identical"
    );
    assert_eq!(
        via_manifest.files, via_project.files,
        "every emitted file must be byte-identical between emit_manifest and emit_project"
    );
}

/// The split-assembly path's own SEAL: for a genuine TWO-module program,
/// `emit_manifest` (which assembles from the demanded `emit_spine_file` +
/// per-`emit_rust_file` outputs) must be BYTE-IDENTICAL to `emit_project`
/// (which renders the split inline). This guards the
/// `assemble_split_manifest` seam against drift — a barrel-line, module-order,
/// or file-path mismatch would surface here rather than as an
/// exit-0-then-cargo-fail downstream.
#[test]
#[allow(clippy::expect_used)]
fn emit_manifest_matches_emit_project_for_two_modules() {
    let (db, _log) = logged_db();
    let (root, _lib, main) = two_module_root(&db);
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

    // Precondition: this program genuinely splits (2 distinct homes), so
    // `emit_manifest` takes the assemble_split_manifest path, not the collapse.
    let homes = ipe_db::program_rust_file_ids(&db, root, main)
        .clone()
        .expect("homes");
    assert_eq!(homes.len(), 2, "fixture must be a genuine 2-home split");

    let via_project = ipe_db::emit_project(&db, root, main, config)
        .clone()
        .expect("emit_project must succeed");
    let via_manifest = ipe_db::emit_manifest(&db, root, main, config)
        .clone()
        .expect("emit_manifest must succeed");

    assert_eq!(
        via_manifest.cargo_toml, via_project.cargo_toml,
        "Cargo.toml must be byte-identical across the split assembly"
    );
    assert_eq!(
        via_manifest.files, via_project.files,
        "every emitted file (main.rs barrel + each ipe_mods/*.rs) must be byte-identical \
         between emit_manifest's assemble-from-pieces path and emit_project's inline split"
    );
}
