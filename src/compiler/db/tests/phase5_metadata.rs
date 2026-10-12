#![forbid(unsafe_code)]
//! Phase-5 proofs (spec:
//! `docs/architecture/salsa-incremental-compilation-2026-07-11.md` §5 row 5).
//!
//! [`ipe_db::program_metadata`] is the coarse, LOCKED whole-program
//! DCE-reachability seam over [`ipe_db::lower_program`]'s output: it depends
//! DIRECTLY on the full lowered-IR set (never firewalled behind an interface
//! summary), so it re-executes on the exact same coarse floor
//! `typecheck`/`lower_program` already established in Phase 4. These tests
//! prove that shape, PLUS the actual reachability computation itself
//! (something Phase 4's coarse seams had no equivalent of — `typecheck` and
//! `lower_program` reuse an existing whole-program computation unchanged;
//! `program_metadata` is a genuinely new structural analysis, so it needs its
//! own correctness proof, not just a memoization proof).

use std::sync::{Arc, Mutex, PoisonError};

use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

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

/// Like [`root_of`] but also injects the transitive closure of compiled-source
/// stdlib modules (e.g. `Ipe.Io`, `Ipe.Time`) that the user files import.
///
/// Kernel-qualifier modules (`Ipe.String`, `Ipe.Task`, …) resolve from the
/// canon catalog without source injection — only compiled-source modules need
/// this. Each injected file carries [`ModuleOrigin::EmbeddedStdlib`] so canon
/// accepts the `Ipe.*` namespace without an IPE-N0025 rejection.
fn root_with_std(db: &IpeDatabase, files: &[(&[&str], SourceFile)]) -> SourceRoot {
    use std::collections::{BTreeMap, VecDeque};

    let mut file_map: BTreeMap<Vec<String>, SourceFile> = files
        .iter()
        .map(|(path, f)| (path.iter().map(|s| (*s).to_owned()).collect(), *f))
        .collect();

    // Seed worklist from every compiled-source import across the user files.
    let mut work: VecDeque<Vec<String>> = VecDeque::new();
    for sf in file_map.values() {
        for imp in ipe_db::extract_imports_from_source(sf.text(db)) {
            if ipe_stdlib::is_compiled_source_segments(&imp) {
                work.push_back(imp);
            }
        }
    }

    // BFS: inject each compiled-source module once, then enqueue its own
    // compiled-source imports (kernel imports inside an embedded module are
    // skipped — they stay qualifier-resolved).
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
        file_map.insert(path.clone(), sf);

        for imp in ipe_db::extract_imports_from_source(source) {
            if ipe_stdlib::is_compiled_source_segments(&imp) && !file_map.contains_key(&imp) {
                work.push_back(imp);
            }
        }
    }

    SourceRoot::new(db, file_map)
}

const DEP_A: &str = "module A exposing (visible)\n\nvisible = 1\n\nhidden = 2\n";
const DEP_A_BODY_EDIT: &str = "module A exposing (visible)\n\nvisible = 1\n\nhidden = 3\n";
const IMPORTER_B: &str = "module B exposing (b)\n\nimport A exposing (visible)\n\nb = visible\n";

// ---------------------------------------------------------------------------
// Memoization shape (same coarse floor as typecheck / lower_program)
// ---------------------------------------------------------------------------

/// Coarse-but-memoized: a repeat demand and a byte-equal re-save execute
/// nothing; a reachable dep's body edit re-executes the whole computation —
/// the same shape the coarse `typecheck`/`lower_program` seams hold, now one
/// layer further down the pipeline.
#[test]
fn program_metadata_memoized_coarse_floor() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let meta = ipe_db::program_metadata(&db, root, b)
        .clone()
        .expect("trivial int program must lower");
    assert!(
        !meta.reachable_funcs.is_empty(),
        "a program with at least one def must report at least one reachable func \
         (no-entry fallback: every func is reachable)"
    );
    assert_eq!(log.executions_of("program_metadata("), 1);

    // Repeat demand: memo hit.
    log.clear();
    assert!(ipe_db::program_metadata(&db, root, b).is_ok());
    assert_eq!(
        log.executions_of("program_metadata("),
        0,
        "repeat demand memoized"
    );

    // Byte-equal re-save: boundary no-op, nothing executes anywhere in the
    // chain (parse → canonicalize → linked_program → typecheck →
    // lower_program → program_metadata).
    log.clear();
    assert!(!ipe_db::set_text_if_changed(&mut db, a, DEP_A));
    assert!(ipe_db::program_metadata(&db, root, b).is_ok());
    assert_eq!(log.executions_of("program_metadata("), 0);

    // Dep body edit: the coarse seam re-executes (lower_program's output
    // changed, and program_metadata depends on it directly — never
    // firewalled, per the design spec's own H6 lock).
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_BODY_EDIT));
    assert!(ipe_db::program_metadata(&db, root, b).is_ok());
    assert_eq!(
        log.executions_of("program_metadata("),
        1,
        "coarse seam re-computes on a semantic edit anywhere in the program"
    );
}

/// `program_metadata` never reaches its own structural walk on ill-typed
/// input — it short-circuits through `lower_program`'s (and therefore
/// `typecheck`'s) error via `?`.
#[test]
fn program_metadata_short_circuits_on_lower_error() {
    const RED_ENTRY: &str = "module Entry exposing (e)\n\n\
        e : Int\n\
        e = \"not an int\"\n";
    let (db, _log) = logged_db();
    let entry = file(&db, &["Entry"], RED_ENTRY);
    let root = root_of(&db, &[(&["Entry"], entry)]);

    let lower_err = ipe_db::lower_program(&db, root, entry)
        .clone()
        .expect_err("ill-typed program must fail to lower");
    let meta_err = ipe_db::program_metadata(&db, root, entry)
        .clone()
        .expect_err("program_metadata must refuse to analyse an unlowered program");
    assert_eq!(
        <(ipe_diagnostics::Diagnostic, Vec<ipe_intern::Symbol>)>::from(lower_err),
        meta_err,
        "program_metadata's short-circuit must surface lower_program's own diagnostic verbatim"
    );
}

// ---------------------------------------------------------------------------
// The reachability computation itself
// ---------------------------------------------------------------------------

/// A genuine dead-code exclusion: `main` calls `live`, which never mentions
/// `dead`. Since [`ipe_db::lower_program`] now PRUNES functions unreachable
/// from the entry, `dead` is absent from the lowered module entirely (a
/// stronger guarantee than merely being excluded from `reachable_funcs`), and
/// `program_metadata`'s reachable set — computed over that already-pruned IR —
/// contains exactly the surviving `main` and `live`.
#[test]
fn program_metadata_excludes_unreached_function() {
    const ENTRY_WITH_DEAD_CODE: &str = "module Entry exposing (main)\n\n\
        import Ipe.Io as Io\n\
        import Ipe.String as String\n\n\
        live = 1\n\n\
        dead = 2\n\n\
        main = Io.println (String.fromInt live)\n";
    let (db, _log) = logged_db();
    let entry = file(&db, &["Entry"], ENTRY_WITH_DEAD_CODE);
    let root = root_with_std(&db, &[(&["Entry"], entry)]);

    let program = ipe_db::lower_program(&db, root, entry)
        .clone()
        .expect("must lower");
    let meta = ipe_db::program_metadata(&db, root, entry)
        .clone()
        .expect("must compute metadata");

    let module = program
        .modules
        .first()
        .expect("lower_program must produce at least one module");
    assert!(
        module.entry.is_some(),
        "a module defining `main` must record it as the program entry"
    );
    let main_id = find_func_id(&db, module, "main");
    let live_id = find_func_id(&db, module, "live");

    assert!(
        find_func_id_opt(&db, module, "dead").is_none(),
        "a function nothing reachable calls must be PRUNED from the lowered \
         module — dead code is eliminated, not merely marked unreachable"
    );
    assert!(
        meta.reachable_funcs.contains(&main_id),
        "the entry function itself must be reachable"
    );
    assert!(
        meta.reachable_funcs.contains(&live_id),
        "a function the entry calls must be reachable"
    );
}

/// Transitive reachability: `main` calls `mid`, which calls `leaf` — `leaf`
/// must be reachable even though `main` never names it directly.
#[test]
fn program_metadata_reachability_is_transitive() {
    const CHAIN: &str = "module Entry exposing (main)\n\n\
        import Ipe.Io as Io\n\
        import Ipe.String as String\n\n\
        leaf = 1\n\n\
        mid = leaf\n\n\
        dead = 99\n\n\
        main = Io.println (String.fromInt mid)\n";
    let (db, _log) = logged_db();
    let entry = file(&db, &["Entry"], CHAIN);
    let root = root_with_std(&db, &[(&["Entry"], entry)]);

    let program = ipe_db::lower_program(&db, root, entry)
        .clone()
        .expect("must lower");
    let meta = ipe_db::program_metadata(&db, root, entry)
        .clone()
        .expect("must compute metadata");
    let module = program
        .modules
        .first()
        .expect("lower_program must produce at least one module");

    assert!(
        meta.reachable_funcs
            .contains(&find_func_id(&db, module, "main"))
    );
    assert!(
        meta.reachable_funcs
            .contains(&find_func_id(&db, module, "mid"))
    );
    assert!(
        meta.reachable_funcs
            .contains(&find_func_id(&db, module, "leaf")),
        "reachability must transit through an intermediate call, not just direct callees"
    );
    assert!(
        find_func_id_opt(&db, module, "dead").is_none(),
        "the dead function must be pruned from the lowered module"
    );
}

/// Function-level dependency emission: a kernel a program only reaches from a
/// DEAD helper must not set the module's `uses_*` flag, so its runtime module
/// and crate subtree are never linked. Here a dead `slow` function calls
/// `Time.now` (which would set `uses_time` and pull the `chrono-tz` IANA-zone
/// subtree); `main` never reaches it, so `uses_time` must stay `false`.
#[test]
fn unreached_kernel_call_does_not_set_module_flag() {
    const DEAD_TIME_CALL: &str = "module Entry exposing (main)\n\n\
        import Ipe.Time as Time\n\
        import Ipe.Io as Io\n\n\
        slow = Time.isLeapYear 2024\n\n\
        main = Io.println \"hi\"\n";
    let (db, _log) = logged_db();
    let entry = file(&db, &["Entry"], DEAD_TIME_CALL);
    let root = root_with_std(&db, &[(&["Entry"], entry)]);

    let program = ipe_db::lower_program(&db, root, entry)
        .clone()
        .expect("must lower");
    let module = program
        .modules
        .first()
        .expect("lower_program must produce one module");

    assert!(
        find_func_id_opt(&db, module, "slow").is_none(),
        "the Time-calling helper is dead — it must be pruned from the module"
    );
    assert!(
        !module.uses_time,
        "a Time kernel reached only from a DEAD function must NOT set `uses_time` \
         (else the emitted program links `chrono-tz` it never invokes)"
    );
}

/// The dual of the previous test: when the SAME `Time.isLeapYear` call is
/// reachable from `main`, `uses_time` must be set — reachability restriction
/// must never drop a dependency the program actually exercises.
#[test]
fn reached_kernel_call_sets_module_flag() {
    const LIVE_TIME_CALL: &str = "module Entry exposing (main)\n\n\
        import Ipe.Time as Time\n\
        import Ipe.Io as Io\n\n\
        main =\n\
        \x20   let\n\
        \x20       leap = Time.isLeapYear 2024\n\
        \x20   in\n\
        \x20   Io.println (if leap then \"leap\" else \"not\")\n";
    let (db, _log) = logged_db();
    let entry = file(&db, &["Entry"], LIVE_TIME_CALL);
    let root = root_with_std(&db, &[(&["Entry"], entry)]);

    let program = ipe_db::lower_program(&db, root, entry)
        .clone()
        .expect("must lower");
    let module = program
        .modules
        .first()
        .expect("lower_program must produce one module");
    assert!(
        module.uses_time,
        "a Time kernel reachable from main MUST set `uses_time`"
    );
}

/// Look up a lowered function's [`ipe_ir::FuncId`] by its source name.
/// Test-only helper (`expect`, not `panic!`, per the workspace's clippy
/// bar — bare `panic!` is denied even in test code, `expect` is allowed).
/// `clippy.toml`'s `allow-expect-in-tests` only auto-exempts code lexically
/// inside a `#[test]` fn; a free helper called FROM one needs the explicit
/// allow.
#[allow(clippy::expect_used)]
fn find_func_id(db: &ipe_db::IpeDatabase, module: &ipe_ir::Module, name: &str) -> ipe_ir::FuncId {
    let msg = format!("no func named {name:?} in the lowered module");
    find_func_id_opt(db, module, name).expect(&msg)
}

/// Like [`find_func_id`] but returns `None` when the function is absent —
/// used to assert a dead function was PRUNED from the lowered module.
fn find_func_id_opt(
    db: &ipe_db::IpeDatabase,
    module: &ipe_ir::Module,
    name: &str,
) -> Option<ipe_ir::FuncId> {
    let interner = ipe_db::Db::interner(db).lock();
    module
        .funcs
        .iter()
        .find(|f| interner.resolve(f.name) == Some(name))
        .map(|f| f.id)
}

/// A program with no `main` binding has no entry to seed a fixpoint from —
/// the conservative fallback treats every function as reachable rather than
/// guessing (never under-reports).
#[test]
fn program_metadata_no_entry_falls_back_to_conservative_reachable_everything() {
    const NO_MAIN: &str = "module Lib exposing (a, b)\n\na = 1\n\nb = 2\n";
    let (db, _log) = logged_db();
    let entry = file(&db, &["Lib"], NO_MAIN);
    let root = root_of(&db, &[(&["Lib"], entry)]);

    let program = ipe_db::lower_program(&db, root, entry)
        .clone()
        .expect("must lower");
    let meta = ipe_db::program_metadata(&db, root, entry)
        .clone()
        .expect("must compute metadata");
    let module = program
        .modules
        .first()
        .expect("lower_program must produce at least one module");
    assert!(module.entry.is_none(), "this fixture defines no `main`");
    assert_eq!(
        meta.reachable_funcs.len(),
        module.funcs.len(),
        "no-entry fallback must report every function reachable, never fewer"
    );
}
