#![forbid(unsafe_code)]
//! Coarse per-program seam proofs (spec:
//! `docs/architecture/salsa-incremental-compilation-2026-07-11.md` §5 row 4).
//!
//! [`ipe_db::typecheck`] and [`ipe_db::lower_program`] are the coarse
//! per-program SEAMS over `ipe_types::infer_attributed` / `ipe_lower::lower`:
//! memoized, but keyed on the whole [`ipe_db::linked_program`] merge, not on
//! any individual module. These tests prove exactly that shape — real memo
//! hits on a no-op repeat/re-save, AND a full re-execution on ANY reachable
//! module's body edit, even one unrelated to the edited module's siblings
//! (the documented coarseness, not a bug).

use std::sync::{Arc, Mutex, PoisonError};

use ipe_db::{Db as _, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

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

const DEP_C: &str = "module C exposing (c)\n\nc = 2\n";
const DEP_C_BODY_EDIT: &str = "module C exposing (c)\n\nc = 3\n";
const ENTRY_WITH_TWO_DEPS: &str = "module Entry exposing (e)\n\n\
    import A exposing (visible)\n\
    import C exposing (c)\n\n\
    e = visible + c\n";

// ---------------------------------------------------------------------------
// typecheck — the coarse per-program SEAM
// ---------------------------------------------------------------------------

/// Coarse-but-memoized, the `linked_program` pattern: a repeat demand and a
/// byte-equal re-save execute nothing; a reachable dep's body edit
/// re-executes the whole solve (documented coarseness — a true per-module
/// `typecheck(ModuleId)` query is finer than this seam, which is
/// program-wide).
#[test]
fn typecheck_memoized_coarse_floor() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let solved = ipe_db::typecheck(&db, root, b)
        .clone()
        .expect("trivial int program must type-check");
    assert!(
        !solved.env.is_empty(),
        "solved types must carry at least one binding"
    );
    assert_eq!(log.executions_of("typecheck("), 1);

    // Repeat demand: memo hit.
    log.clear();
    assert!(ipe_db::typecheck(&db, root, b).is_ok());
    assert_eq!(log.executions_of("typecheck("), 0, "repeat demand memoized");

    // Byte-equal re-save: boundary no-op, nothing executes anywhere in the
    // chain (parse → canonicalize → linked_program → typecheck).
    log.clear();
    assert!(!ipe_db::set_text_if_changed(&mut db, a, DEP_A));
    assert!(ipe_db::typecheck(&db, root, b).is_ok());
    assert_eq!(log.executions_of("typecheck("), 0);

    // Dep body edit: the coarse seam re-executes (linked_program's assembled
    // input changed, so typecheck's own dependency changed).
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_BODY_EDIT));
    assert!(ipe_db::typecheck(&db, root, b).is_ok());
    assert_eq!(
        log.executions_of("typecheck("),
        1,
        "coarse seam re-checks on a semantic edit anywhere in the program"
    );
}

/// The whole-program `typecheck` seam is genuinely PROGRAM-wide, not
/// per-module: editing module C's body (unrelated to sibling module A — no
/// import edge between them) still forces a full re-execution of
/// `typecheck`, because both are merged into the SAME `linked_program`.
/// This is the emission path's documented coarseness; the per-module
/// `typecheck_module` query does NOT share it —
/// `unrelated_sibling_edit_leaves_module_memo_untouched`
/// (`per_module_typecheck.rs`) proves the finer granularity.
#[test]
fn typecheck_is_program_wide_not_per_module() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let c = file(&db, &["C"], DEP_C);
    let entry = file(&db, &["Entry"], ENTRY_WITH_TWO_DEPS);
    let root = root_of(&db, &[(&["A"], a), (&["C"], c), (&["Entry"], entry)]);

    assert!(ipe_db::typecheck(&db, root, entry).is_ok());
    assert_eq!(log.executions_of("typecheck("), 1);

    // Edit ONLY C — a sibling dep of A under Entry, no edge to A at all.
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, c, DEP_C_BODY_EDIT));
    assert!(ipe_db::typecheck(&db, root, entry).is_ok());
    assert_eq!(
        log.executions_of("typecheck("),
        1,
        "unrelated sibling's body edit still busts the whole-program seam"
    );
}

// ---------------------------------------------------------------------------
// lower_program — the coarse per-program SEAM, typecheck's sibling
// ---------------------------------------------------------------------------

/// Same coarse-but-memoized shape as `typecheck`, one layer further down the
/// pipeline: `lower_program` depends on BOTH `linked_program` and
/// `typecheck`, so it re-executes exactly when either upstream seam would
/// have re-run `ipe_lower::lower` today — but a repeat demand or a no-op
/// re-save now executes nothing.
#[test]
fn lower_program_memoized_coarse_floor() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let program = ipe_db::lower_program(&db, root, b)
        .clone()
        .expect("trivial int program must lower");
    assert!(
        !program.modules.is_empty(),
        "lowered IR must carry at least one module"
    );
    assert_eq!(log.executions_of("lower_program("), 1);
    // typecheck is a real dependency, demanded fresh on this first call too.
    assert_eq!(log.executions_of("typecheck("), 1);

    // Repeat demand: both memo-hit.
    log.clear();
    assert!(ipe_db::lower_program(&db, root, b).is_ok());
    assert_eq!(
        log.executions_of("lower_program("),
        0,
        "repeat demand memoized"
    );
    assert_eq!(log.executions_of("typecheck("), 0);

    // Byte-equal re-save: still nothing executes.
    log.clear();
    assert!(!ipe_db::set_text_if_changed(&mut db, a, DEP_A));
    assert!(ipe_db::lower_program(&db, root, b).is_ok());
    assert_eq!(log.executions_of("lower_program("), 0);

    // Dep body edit: both typecheck and lower_program re-execute in lockstep
    // (the documented coarse floor — lower_program has no independent
    // invalidation edge finer than typecheck's own).
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_BODY_EDIT));
    assert!(ipe_db::lower_program(&db, root, b).is_ok());
    assert_eq!(log.executions_of("typecheck("), 1);
    assert_eq!(log.executions_of("lower_program("), 1);
}

/// `lower_program` never reaches `ipe_lower::lower` on ill-typed input — it
/// short-circuits through `typecheck`'s error via `?`, so a direct demand on
/// a red program surfaces the SAME diagnostic `typecheck` itself would give
/// (never a `ipe_lower`-side panic or a different, confusing error).
#[test]
fn lower_program_short_circuits_on_typecheck_error() {
    const RED_ENTRY: &str = "module Entry exposing (e)\n\n\
        e : Int\n\
        e = \"not an int\"\n";
    let (db, _log) = logged_db();
    let entry = file(&db, &["Entry"], RED_ENTRY);
    let root = root_of(&db, &[(&["Entry"], entry)]);

    let typecheck_err = ipe_db::typecheck(&db, root, entry)
        .clone()
        .expect_err("annotated Int binding with a String body must be rejected");
    let lower_err = ipe_db::lower_program(&db, root, entry)
        .clone()
        .expect_err("lower_program must refuse to lower an ill-typed program");
    assert!(
        matches!(typecheck_err, ipe_db::TypecheckError::Infer(_)),
        "a type error is the type checker's refusal, got {typecheck_err:?}"
    );
    assert_eq!(
        ipe_db::PipelineError::from(typecheck_err),
        lower_err,
        "lower_program's short-circuit must surface typecheck's own diagnostic verbatim"
    );
}

/// A link refusal reaches `typecheck`, `typecheck_module`, and `lower_program`
/// as the link diagnostic itself, demanded cold: never re-classified as a
/// type-checker error and never an internal compiler error.
#[test]
fn typecheck_carries_a_link_refusal_verbatim() {
    const UNBOUND_ENTRY: &str = "module Entry exposing (e)\n\ne = notDefinedAnywhere\n";
    let (db, _log) = logged_db();
    let entry = file(&db, &["Entry"], UNBOUND_ENTRY);
    let root = root_of(&db, &[(&["Entry"], entry)]);

    let module_err = ipe_db::typecheck_module(&db, root, entry, entry)
        .clone()
        .expect_err("an unbound name must refuse the module's types");
    let typecheck_err = ipe_db::typecheck(&db, root, entry)
        .clone()
        .expect_err("an unbound name must refuse the program");
    let link_err = ipe_db::linked_program(&db, root, entry)
        .clone()
        .expect_err("an unbound name must refuse the link");
    assert!(
        matches!(link_err, ipe_diagnostics::Diagnostic::Name { .. }),
        "an unbound name is a name error, got {link_err:?}"
    );
    assert_eq!(
        typecheck_err,
        ipe_db::TypecheckError::Link(link_err.clone()),
        "typecheck must carry the link diagnostic verbatim"
    );
    assert_eq!(
        module_err, typecheck_err,
        "the per-module query serves the same link refusal"
    );
    assert_eq!(
        ipe_db::lower_program(&db, root, entry)
            .clone()
            .expect_err("lowering must refuse an unlinked program"),
        ipe_db::PipelineError::Lower(link_err, Vec::new()),
        "lower_program reports the link refusal with no blamed module"
    );
}

// ---------------------------------------------------------------------------
// typecheck_module — the per-module query. Its scoped body (deps'-typed-
// interface solve, `per_module_typecheck.rs`) and its whole-program-
// projection fallback must both slice the program per module home; these
// tests pin the slicing contract itself: each module gets EXACTLY its own
// home's entries, the slices partition the whole, and same-named
// cross-module bindings never conflate.
// ---------------------------------------------------------------------------

/// Two modules with same-named-but-distinct bindings: `A.shared : Int` and
/// `B.shared : String`. The per-module projection must give each module ONLY
/// its own home's entries — never the other's — and the two slices must union
/// to exactly the whole-program env, proving the projection loses nothing and
/// invents nothing.
#[test]
fn typecheck_module_projection_matches_whole_program() {
    const DEP: &str = "module A exposing (shared, av)\n\n\
        shared : Int\n\
        shared = 1\n\n\
        av : Int\n\
        av = shared\n";
    const ENTRY: &str = "module B exposing (shared, bv)\n\n\
        import A exposing (av)\n\n\
        shared : String\n\
        shared = \"s\"\n\n\
        bv : Int\n\
        bv = av\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], DEP);
    let b = file(&db, &["B"], ENTRY);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let whole = ipe_db::typecheck(&db, root, b)
        .clone()
        .expect("program type-checks");
    let a_types = ipe_db::typecheck_module(&db, root, b, a)
        .clone()
        .expect("A projects");
    let b_types = ipe_db::typecheck_module(&db, root, b, b)
        .clone()
        .expect("B projects");

    // Resolve the two home paths so we can filter the whole-program env.
    let (a_home, b_home) = {
        let mut i = db.interner().lock();
        (vec![i.intern("A").unwrap()], vec![i.intern("B").unwrap()])
    };

    // Each projection equals the whole-program env filtered to that home.
    let whole_a: std::collections::BTreeMap<_, _> = whole
        .env
        .iter()
        .filter(|((h, _), _)| *h == a_home)
        .map(|((_, n), ty)| (*n, ty.clone()))
        .collect();
    let whole_b: std::collections::BTreeMap<_, _> = whole
        .env
        .iter()
        .filter(|((h, _), _)| *h == b_home)
        .map(|((_, n), ty)| (*n, ty.clone()))
        .collect();
    assert_eq!(
        a_types.env, whole_a,
        "A's projected env must equal the whole-program env filtered to home A"
    );
    assert_eq!(
        b_types.env, whole_b,
        "B's projected env must equal the whole-program env filtered to home B"
    );

    // Disjoint + total: the two homes' env slices union to the whole env
    // (every binding in this two-module program belongs to A or B).
    assert_eq!(
        a_types.env.len() + b_types.env.len(),
        whole.env.len(),
        "the per-module env slices partition the whole-program env"
    );

    // The same-named `shared` resolves DIFFERENTLY per module — the projection
    // must not conflate them (the exact cross-module-collision hazard the
    // home-keyed `SolvedTypes` maps exist to prevent).
    let shared_sym = {
        let mut i = db.interner().lock();
        i.intern("shared").unwrap()
    };
    let a_shared = a_types.env.get(&shared_sym).expect("A.shared typed");
    let b_shared = b_types.env.get(&shared_sym).expect("B.shared typed");
    assert_ne!(
        a_shared, b_shared,
        "A.shared : Int and B.shared : String must project to distinct types"
    );

    // regions and expected slices are likewise home-scoped and union to the
    // whole (no region belongs to neither module).
    assert_eq!(
        a_types.regions.len() + b_types.regions.len(),
        whole.regions.len(),
        "per-module region slices partition the whole-program regions"
    );
    assert_eq!(
        a_types.expected.len() + b_types.expected.len(),
        whole.expected.len(),
        "per-module expected slices partition the whole-program expected sidecar"
    );
}

/// The per-module query is memoized and its value backdates: a repeat
/// demand executes nothing, and a byte-equal re-save executes nothing
/// anywhere in the chain.
#[test]
fn typecheck_module_is_memoized() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert!(ipe_db::typecheck_module(&db, root, b, b).is_ok());
    assert_eq!(log.executions_of("typecheck_module("), 1);

    // Repeat demand: memo hit.
    log.clear();
    assert!(ipe_db::typecheck_module(&db, root, b, b).is_ok());
    assert_eq!(
        log.executions_of("typecheck_module("),
        0,
        "repeat per-module demand is memoized"
    );

    // Byte-equal re-save: boundary no-op, nothing re-projects.
    log.clear();
    assert!(!ipe_db::set_text_if_changed(&mut db, a, DEP_A));
    assert!(ipe_db::typecheck_module(&db, root, b, b).is_ok());
    assert_eq!(log.executions_of("typecheck_module("), 0);
}
