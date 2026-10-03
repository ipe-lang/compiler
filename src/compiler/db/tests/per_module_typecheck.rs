#![forbid(unsafe_code)]
//! The genuinely-per-module typecheck tier: scoped solves over deps' typed
//! interfaces ([`ipe_db::infer_module_scoped`] / [`ipe_db::typed_interface`]
//! behind [`ipe_db::typecheck_module`]).
//!
//! Proves the three properties the redesign exists for:
//! - **True per-module invalidation**: an edit to an unrelated sibling module
//!   leaves a module's memo untouched (the property the whole-program
//!   `typecheck` seam documents as NOT holding for itself).
//! - **Typed-interface firewall**: a dep body edit that preserves the dep's
//!   exported schemes re-solves the dep only — importers' scoped memos stand.
//! - **Fail-closed openness**: a module whose exported scheme an importer can
//!   still pin (information flowing against the import direction) never takes
//!   the scoped path; consumers get exactly the whole-program result.

use std::sync::{Arc, Mutex, PoisonError};

use ipe_db::{Db as _, IpeDatabase, ModuleOrigin, ScopedModuleTypes, SourceFile, SourceRoot};

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

/// The whole-program projection for `module`, normalized — the fallback
/// body's exact computation, for comparing the scoped path against. `None`
/// when the program does not type-check.
fn joint_projection(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: SourceFile,
    module: SourceFile,
) -> Option<ipe_db::ModuleTypes> {
    let solved = ipe_db::typecheck(db, root, entry).clone().ok()?;
    let home: Vec<ipe_intern::Symbol> = {
        let mut interner = db.interner().lock();
        module
            .module_path(db)
            .iter()
            .map(|segment| interner.intern(segment).ok())
            .collect::<Option<_>>()?
    };
    Some(ipe_db::normalize_module_types(
        ipe_db::project_module_types(&solved, &home),
    ))
}

// Exported bindings are ANNOTATED: an exported untyped binding whose type
// still carries a residual obligation (e.g. `visible = 1`, a `Number` super
// variable until program-wide defaulting) is genuinely pinnable by an
// importer in the joint solve, so it is honestly OPEN and falls back — see
// `open_interface_falls_back_to_the_joint_solve`. Non-exported bindings
// (`hidden`) may stay untyped: their residuals are unreachable from outside.
const DEP_A: &str = "module A exposing (visible)\n\nvisible : Int\nvisible = 1\n\nhidden = 2\n";
const DEP_A_HIDDEN_GROWN: &str =
    "module A exposing (visible)\n\nvisible : Int\nvisible = 1\n\nhidden = 2 + 3\n";
const IMPORTER_B: &str = "module B exposing (b)\n\nimport A exposing (visible)\n\nb = visible\n";

const DEP_C: &str = "module C exposing (c)\n\nc : Int\nc = 2\n";
const DEP_C_BODY_EDIT: &str = "module C exposing (c)\n\nc : Int\nc = 3\n";
const ENTRY_WITH_TWO_DEPS: &str = "module Entry exposing (e)\n\n\
    import A exposing (visible)\n\
    import C exposing (c)\n\n\
    e = visible + c\n";

// ---------------------------------------------------------------------------
// The scoped path engages and agrees with the whole-program slice
// ---------------------------------------------------------------------------

/// The scoped solve engages on a modular two-module program (closed
/// interfaces all the way down, including the module's own), and its result
/// is byte-identical to the normalized whole-program projection.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn scoped_solve_engages_and_matches_projection() {
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    for module in [a, b] {
        let scoped = ipe_db::infer_module_scoped(&db, root, module);
        let ScopedModuleTypes::PerModule { types, .. } = scoped else {
            panic!("closed modular program must take the scoped path");
        };
        assert_eq!(
            Some(&**types),
            joint_projection(&db, root, b, module).as_ref(),
            "scoped result must equal the normalized whole-program slice"
        );
        let via_query = ipe_db::typecheck_module(&db, root, b, module)
            .clone()
            .expect("green program must project per module");
        assert_eq!(
            *via_query, **types,
            "typecheck_module serves the scoped result"
        );
    }
}

// ---------------------------------------------------------------------------
// True per-module invalidation — the flip of the whole-program seam's
// documented coarseness
// ---------------------------------------------------------------------------

/// Editing module C's body in an `{A, C, Entry}` program where A and C share
/// no import edge leaves `typecheck_module(A)`'s memo untouched — no
/// re-execution of the per-module query, its scoped solve, or (crucially)
/// the whole-program `typecheck`. This is the property
/// `typecheck_is_program_wide_not_per_module` (`phase4_seams.rs`) documents
/// as NOT holding for the whole-program seam.
#[test]
fn unrelated_sibling_edit_leaves_module_memo_untouched() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let c = file(&db, &["C"], DEP_C);
    let entry = file(&db, &["Entry"], ENTRY_WITH_TWO_DEPS);
    let root = root_of(&db, &[(&["A"], a), (&["C"], c), (&["Entry"], entry)]);

    let before = ipe_db::typecheck_module(&db, root, entry, a)
        .clone()
        .expect("A type-checks");
    assert_eq!(log.executions_of("typecheck_module("), 1);
    assert!(
        matches!(
            ipe_db::infer_module_scoped(&db, root, a),
            ScopedModuleTypes::PerModule { .. }
        ),
        "A must take the scoped path for the invalidation claim to be about it"
    );
    assert_eq!(
        log.executions_of("typecheck("),
        0,
        "the scoped path must not demand the whole-program solve"
    );

    // Edit ONLY C — a sibling dep of A under Entry, no edge to A at all.
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, c, DEP_C_BODY_EDIT));
    let after = ipe_db::typecheck_module(&db, root, entry, a)
        .clone()
        .expect("A still type-checks");
    assert_eq!(
        log.executions_of("typecheck_module("),
        0,
        "unrelated sibling's body edit must NOT re-execute A's per-module query"
    );
    assert_eq!(
        log.executions_of("infer_module_scoped("),
        0,
        "unrelated sibling's body edit must NOT re-run A's scoped solve"
    );
    assert_eq!(
        log.executions_of("typecheck("),
        0,
        "no whole-program solve anywhere on this path"
    );
    assert_eq!(before, after, "the memoized value is served unchanged");
}

// ---------------------------------------------------------------------------
// Typed-interface firewall
// ---------------------------------------------------------------------------

/// A body-only edit to a dep that does NOT change any exported scheme
/// (growing a non-exported binding's body) re-runs the DEP's scoped solve
/// only: `typed_interface` re-projects, comes out equal, backdates — and the
/// importer's scoped solve plus its per-module query stand without
/// re-executing.
#[test]
fn scheme_preserving_dep_edit_does_not_resolve_importers() {
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let before = ipe_db::typecheck_module(&db, root, b, b)
        .clone()
        .expect("B type-checks");
    assert!(matches!(
        ipe_db::infer_module_scoped(&db, root, b),
        ScopedModuleTypes::PerModule { .. }
    ));

    // Body-only edit to A's non-exported binding: A's own regions change
    // (new spans), so A's scoped result is a genuinely new value — but A's
    // exported schemes are untouched.
    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_HIDDEN_GROWN));
    let after = ipe_db::typecheck_module(&db, root, b, b)
        .clone()
        .expect("B still type-checks");

    assert_eq!(
        log.executions_of("infer_module_scoped("),
        1,
        "exactly the DEP's scoped solve re-runs (A), never the importer's (B)"
    );
    assert_eq!(
        log.executions_of("typed_interface("),
        1,
        "the interface re-projects from A's fresh solve (and then backdates)"
    );
    assert_eq!(
        log.executions_of("typecheck_module("),
        0,
        "B's per-module query memo stands"
    );
    assert_eq!(
        log.executions_of("typecheck("),
        0,
        "no whole-program solve anywhere on this path"
    );
    assert_eq!(before, after, "B's value is served unchanged");

    // And A's own per-module result DID change (the edit is real).
    let a_after = ipe_db::typecheck_module(&db, root, b, a)
        .clone()
        .expect("A type-checks");
    assert!(
        !a_after.regions.is_empty(),
        "A's re-solved regions are present"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed openness — the anti-modular shapes never take the scoped path
// ---------------------------------------------------------------------------

/// An exported untyped binding whose type an importer can still pin
/// (`double x = x + x` — a residual Number obligation at A's boundary,
/// which B's `double 1.5` pins to Float in the joint solve) marks A's
/// interface OPEN: both modules fall back to the whole-program path, and
/// A's served env shows the Float the JOINT solve inferred — never a scoped
/// solve's premature Int default.
#[test]
fn open_interface_falls_back_to_the_joint_solve() {
    const OPEN_DEP: &str = "module A exposing (double)\n\ndouble x = x + x\n";
    const FLOAT_IMPORTER: &str =
        "module B exposing (b)\n\nimport A exposing (double)\n\nb = double 1.5\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], OPEN_DEP);
    let b = file(&db, &["B"], FLOAT_IMPORTER);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert!(
        ipe_db::typed_interface(&db, root, a).is_none(),
        "a pinnable exported scheme must yield an OPEN interface"
    );
    assert!(matches!(
        ipe_db::infer_module_scoped(&db, root, a),
        ScopedModuleTypes::WholeProgram
    ));
    assert!(
        matches!(
            ipe_db::infer_module_scoped(&db, root, b),
            ScopedModuleTypes::WholeProgram
        ),
        "an importer of an open module falls back too"
    );

    // Both modules serve exactly the joint slice — including the
    // against-import-direction Float pin on A's exported binding.
    for module in [a, b] {
        let served = ipe_db::typecheck_module(&db, root, b, module)
            .clone()
            .expect("program green");
        assert_eq!(
            Some(&*served),
            joint_projection(&db, root, b, module).as_ref()
        );
    }
    let float_pinned = ipe_db::typecheck_module(&db, root, b, a)
        .clone()
        .expect("program green");
    let double_sym = db
        .interner()
        .lock()
        .intern("double")
        .expect("interner append");
    let double_ty = float_pinned.env.get(&double_sym).cloned();
    let mut namer = ipe_types::VarNamer::new();
    let doc = {
        let interner = db.interner().lock();
        ipe_types::ty_to_doc(
            double_ty.as_ref().expect("A.double typed"),
            &interner,
            &mut namer,
        )
    }
    .expect("renderable");
    assert_eq!(
        ipe_diagnostics::render_ty(&doc),
        "Float -> Float",
        "A's served type carries the importer's Float pin (the joint solve's answer)"
    );
}

// ---------------------------------------------------------------------------
// Red-edit resilience
// ---------------------------------------------------------------------------

/// A red edit in one module no longer blanks an unrelated module's types:
/// the unrelated module's scoped solve stands on its own, while the red
/// module surfaces the whole-program diagnostic verbatim.
#[test]
fn unrelated_module_keeps_types_while_sibling_is_red() {
    const RED_C: &str = "module C exposing (c)\n\nc : Int\nc = \"not an int\"\n"; // annotated, body red
    let (mut db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let c = file(&db, &["C"], DEP_C);
    let entry = file(&db, &["Entry"], ENTRY_WITH_TWO_DEPS);
    let root = root_of(&db, &[(&["A"], a), (&["C"], c), (&["Entry"], entry)]);

    assert!(ipe_db::typecheck_module(&db, root, entry, a).is_ok());

    assert!(ipe_db::set_text_if_changed(&mut db, c, RED_C));
    assert!(
        ipe_db::typecheck_module(&db, root, entry, a).is_ok(),
        "A's scoped types survive C's red edit"
    );
    let program_err = ipe_db::typecheck(&db, root, entry)
        .clone()
        .expect_err("C's annotation mismatch must be rejected");
    let module_err = ipe_db::typecheck_module(&db, root, entry, c)
        .clone()
        .expect_err("C's per-module query surfaces the failure");
    assert_eq!(
        program_err, module_err,
        "the red module serves the whole-program diagnostic verbatim"
    );
}
