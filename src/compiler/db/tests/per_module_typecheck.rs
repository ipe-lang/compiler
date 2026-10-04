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
//!
//! And the typed-program source [`ipe_db::program_types`]: its scoped assembly
//! equals the joint solve in canonical form, every fallback names its reason,
//! and a red program reports the joint solve's error verbatim.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Arc, Mutex, PoisonError};

use ipe_db::{
    Db as _, FallbackReason, IpeDatabase, ModuleOrigin, ScopedModuleTypes, SourceFile, SourceRoot,
    TypedBy,
};
use ipe_intern::Symbol;

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

/// The interned module path of `module`.
fn home_of(db: &IpeDatabase, module: SourceFile) -> Vec<Symbol> {
    let mut interner = db.interner().lock();
    module
        .module_path(db)
        .iter()
        .map(|segment| interner.intern(segment).expect("interner append"))
        .collect()
}

/// The whole-program slice for `module` in canonical form — the fallback
/// body's exact computation, for comparing the scoped path against. `None`
/// when the program does not type-check.
fn joint_projection(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: SourceFile,
    module: SourceFile,
) -> Option<ipe_db::ModuleTypes> {
    let solved = ipe_db::typecheck(db, root, entry).clone().ok()?;
    ipe_db::canonical_module_types(&solved, &home_of(db, module)).ok()
}

/// The joint solve in program-canonical form, or its refusal.
fn canonical_joint(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: SourceFile,
) -> Result<ipe_types::CanonicalTypes, ipe_db::TypecheckError> {
    ipe_db::typecheck(db, root, entry).clone().map(|solved| {
        ipe_types::canonicalize(
            ipe_types::SolvedTypes::clone(&solved),
            ipe_types::VarScope::Program,
            ipe_types::VarCeiling::SOLVER,
        )
        .expect("the joint solve fits the solver space")
    })
}

/// [`ipe_db::program_types`] equals the joint solve in canonical form: the
/// same full typed program on a green program, the same error on a red one.
/// Returns the served [`TypedBy`] on a green program.
fn assert_program_oracle(db: &IpeDatabase, root: SourceRoot, entry: SourceFile) -> Option<TypedBy> {
    let served = ipe_db::program_types(db, root, entry).clone();
    let joint = canonical_joint(db, root, entry);
    assert_eq!(
        served.is_ok(),
        joint.is_ok(),
        "program_types and the joint solve must agree on acceptance: {served:?} vs {joint:?}"
    );
    if let (Ok(served), Ok(joint)) = (&served, &joint) {
        assert_eq!(
            *served.types, *joint,
            "the served typed program must equal the canonical joint solve"
        );
    }
    if let (Err(served), Err(joint)) = (&served, &joint) {
        assert_eq!(
            served, joint,
            "a red program reports the joint error verbatim"
        );
    }
    served.ok().map(|program| program.typed_by)
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
/// is the joint solve's slice of that module in canonical form, field for
/// field.
#[test]
fn scoped_solve_engages_and_matches_projection() {
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);
    let joint = ipe_db::typecheck(&db, root, b)
        .clone()
        .expect("program type-checks");

    for module in [a, b] {
        let scoped = ipe_db::infer_module_scoped(&db, root, module);
        assert!(
            matches!(scoped, ScopedModuleTypes::PerModule { .. }),
            "closed modular program must take the scoped path, got {scoped:?}"
        );
        let ScopedModuleTypes::PerModule { solved, .. } = scoped else {
            return;
        };
        let home = home_of(&db, module);
        assert_eq!(
            Ok(&**solved),
            ipe_db::canonical_module_slice(&joint, &home).as_ref(),
            "the scoped slice must equal the joint slice in canonical form"
        );
        let projected = ipe_db::project_module_types(solved, &home);
        assert_eq!(
            Some(&projected),
            joint_projection(&db, root, b, module).as_ref(),
            "the scoped view must equal the joint view"
        );
        let via_query = ipe_db::typecheck_module(&db, root, b, module)
            .clone()
            .expect("green program must project per module");
        assert_eq!(
            *via_query, projected,
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
    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, a),
        &ScopedModuleTypes::WholeProgram(FallbackReason::OpenInterface)
    );
    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, b),
        &ScopedModuleTypes::WholeProgram(FallbackReason::MissingInterface),
        "an importer of an open module falls back too"
    );
    assert_eq!(
        assert_program_oracle(&db, root, b),
        Some(TypedBy::Joint(FallbackReason::OpenInterface)),
        "the program is served by the joint solve, attributed to the first open module"
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

// ---------------------------------------------------------------------------
// The typed-program source: scoped assembly and its fallbacks
// ---------------------------------------------------------------------------

/// A one-home canonical slice holding `vars` distinct solver variables, one
/// per region.
fn slice_with_vars(home: &[Symbol], vars: u32) -> ipe_db::ModuleSlice {
    let regions = (0..vars)
        .map(|n| {
            (
                (home.to_vec(), ipe_diagnostics::Span::new(n, n + 1)),
                ipe_types::Ty::Var(ipe_types::tag_solver_var(n)),
            )
        })
        .collect();
    let solved = ipe_types::SolvedTypes {
        env: BTreeMap::new(),
        regions,
        expected: BTreeMap::new(),
        bounds: BTreeMap::new(),
        warnings: Vec::new(),
        poly_var_map: BTreeMap::new(),
        untyped_type_params: BTreeMap::new(),
        msg_defaulted_vars: BTreeMap::new(),
        signature_wildcards: BTreeMap::new(),
    };
    let canonical = ipe_types::canonicalize(
        solved,
        ipe_types::VarScope::PerHome,
        ipe_types::VarCeiling::SOLVER,
    )
    .expect("a handful of variables fits the solver space");
    (home.to_vec(), Arc::new(canonical))
}

/// A ceiling of `n` variable ids.
fn ceiling(n: u32) -> ipe_types::VarCeiling {
    ipe_types::VarCeiling::at_most(NonZeroU32::new(n).expect("a non-zero ceiling"))
}

/// The assembly refuses to mint more variable ids than its ceiling admits,
/// and accepts the same slices at a ceiling that fits them.
#[test]
fn assembly_refuses_a_var_space_past_its_ceiling() {
    let home = vec![Symbol::from_raw(1)];
    let slices = [slice_with_vars(&home, 3)];
    let linked = BTreeSet::from([home]);
    assert_eq!(
        ipe_db::assemble_scoped(&slices, &linked, ceiling(2)).err(),
        Some(FallbackReason::VarSpaceExhausted),
        "three distinct variables must not fit a ceiling of two"
    );
    assert!(
        ipe_db::assemble_scoped(&slices, &linked, ceiling(3)).is_ok(),
        "three distinct variables fit a ceiling of three"
    );
    assert!(
        ipe_db::assemble_scoped(&slices, &linked, ipe_types::VarCeiling::SOLVER).is_ok(),
        "three distinct variables fit the solver space"
    );
}

/// The assembly fails closed when a linked module has no slice, when two
/// slices claim one home, and when a slice holds keys of another home.
#[test]
fn assembly_refuses_an_incomplete_or_conflicting_cover() {
    let a = vec![Symbol::from_raw(1)];
    let b = vec![Symbol::from_raw(2)];
    let a_slice = slice_with_vars(&a, 1);
    let solver = ipe_types::VarCeiling::SOLVER;

    assert_eq!(
        ipe_db::assemble_scoped(
            std::slice::from_ref(&a_slice),
            &BTreeSet::from([a.clone(), b.clone()]),
            solver
        )
        .err(),
        Some(FallbackReason::IncompleteCover),
        "a linked home absent from the slices must refuse the assembly"
    );
    assert_eq!(
        ipe_db::assemble_scoped(
            &[a_slice.clone(), a_slice.clone()],
            &BTreeSet::from([a.clone()]),
            solver
        )
        .err(),
        Some(FallbackReason::AssemblyConflict),
        "two slices for one home must refuse the assembly"
    );
    let misfiled = (b.clone(), Arc::clone(&a_slice.1));
    assert_eq!(
        ipe_db::assemble_scoped(&[misfiled], &BTreeSet::from([b]), solver).err(),
        Some(FallbackReason::AssemblyConflict),
        "a slice holding another home's keys must refuse the assembly"
    );
    assert!(
        ipe_db::assemble_scoped(&[a_slice], &BTreeSet::from([a]), solver).is_ok(),
        "a complete, disjoint cover assembles"
    );
}

/// A closed modular program is served by the scoped assembly, which never
/// demands the joint solve and equals it in canonical form.
#[test]
fn closed_program_is_served_by_the_scoped_assembly() {
    let (db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let c = file(&db, &["C"], DEP_C);
    let entry = file(&db, &["Entry"], ENTRY_WITH_TWO_DEPS);
    let root = root_of(&db, &[(&["A"], a), (&["C"], c), (&["Entry"], entry)]);

    assert!(ipe_db::program_types(&db, root, entry).is_ok());
    assert_eq!(
        log.executions_of("typecheck("),
        0,
        "the scoped assembly never demands the joint solve"
    );
    assert_eq!(
        assert_program_oracle(&db, root, entry),
        NonZeroUsize::new(3).map(|modules| TypedBy::Scoped { modules })
    );
}

/// A cyclic import graph is served by the joint solve, whose link refusal
/// comes back verbatim.
#[test]
fn import_cycle_falls_back_with_the_joint_error() {
    const CYCLE_A: &str = "module A exposing (a)\n\nimport B exposing (b)\n\na : Int\na = b\n";
    const CYCLE_B: &str = "module B exposing (b)\n\nimport A exposing (a)\n\nb : Int\nb = a\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], CYCLE_A);
    let b = file(&db, &["B"], CYCLE_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, a),
        &ScopedModuleTypes::WholeProgram(FallbackReason::Cycle)
    );
    assert!(
        matches!(
            ipe_db::program_types(&db, root, a),
            Err(ipe_db::TypecheckError::Link(_))
        ),
        "a cycle is a link refusal"
    );
    assert_eq!(assert_program_oracle(&db, root, a), None);
}

/// A module that fails to canonicalize falls back, and the program reports
/// the joint error verbatim.
#[test]
fn canon_error_falls_back_with_the_joint_error() {
    const UNBOUND_B: &str =
        "module B exposing (b)\n\nimport A exposing (visible)\n\nb : Int\nb = missing\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], UNBOUND_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, b),
        &ScopedModuleTypes::WholeProgram(FallbackReason::CanonError)
    );
    assert!(ipe_db::program_types(&db, root, b).is_err());
    assert_eq!(assert_program_oracle(&db, root, b), None);
}

/// A type error in a dep falls back at the dep, its importer reports the
/// missing interface, and the program reports the joint error verbatim.
#[test]
fn dep_type_error_falls_back_with_the_joint_error() {
    const RED_A: &str = "module A exposing (visible)\n\nvisible : Int\nvisible = \"no\"\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], RED_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, a),
        &ScopedModuleTypes::WholeProgram(FallbackReason::SolveError)
    );
    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, b),
        &ScopedModuleTypes::WholeProgram(FallbackReason::MissingInterface)
    );
    assert!(ipe_db::program_types(&db, root, b).is_err());
    assert_eq!(assert_program_oracle(&db, root, b), None);
}

/// A type error in the entry falls back at the entry while its dep stays
/// scoped, and the program reports the joint error verbatim.
#[test]
fn entry_type_error_falls_back_with_the_joint_error() {
    const RED_B: &str =
        "module B exposing (b)\n\nimport A exposing (visible)\n\nb : Int\nb = \"no\"\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], RED_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert!(matches!(
        ipe_db::infer_module_scoped(&db, root, a),
        ScopedModuleTypes::PerModule { .. }
    ));
    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, b),
        &ScopedModuleTypes::WholeProgram(FallbackReason::SolveError)
    );
    assert!(ipe_db::program_types(&db, root, b).is_err());
    assert_eq!(assert_program_oracle(&db, root, b), None);
}

/// The scoped path refuses `main_src`'s use of `lib_src` exactly where the
/// joint solve does: the dep stays scoped, the importer's scoped solve
/// refuses, and the program reports the joint error verbatim.
fn assert_importer_use_refused(lib_src: &str, main_src: &str) {
    let (db, _log) = logged_db();
    let lib = file(&db, &["Lib"], lib_src);
    let main = file(&db, &["Main"], main_src);
    let root = root_of(&db, &[(&["Lib"], lib), (&["Main"], main)]);

    assert!(
        matches!(
            ipe_db::infer_module_scoped(&db, root, lib),
            ScopedModuleTypes::PerModule { .. }
        ),
        "the dep must be scoped for the importer's check to be the scoped one"
    );
    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, main),
        &ScopedModuleTypes::WholeProgram(FallbackReason::SolveError),
        "the importer's scoped solve must refuse the use"
    );
    assert!(
        ipe_db::typecheck(&db, root, main).is_err(),
        "the joint solve refuses the use"
    );
    assert_eq!(assert_program_oracle(&db, root, main), None);
}

/// An importer instantiating a dep's pinned wildcard at a type outside its
/// pin is refused on the scoped path.
#[test]
fn importer_wildcard_pin_mismatch_is_refused() {
    assert_importer_use_refused(
        "module Lib exposing (h)\n\nh : any -> Bool\nh x =\n    x + x == x\n",
        "module Main exposing (main)\n\nimport Lib exposing (h)\n\nmain =\n    h 1.5\n",
    );
}

/// An importer using a dep's super-bounded generic at a type outside the
/// bound is refused on the scoped path.
#[test]
fn importer_super_bound_violation_is_refused() {
    assert_importer_use_refused(
        "module Lib exposing (double)\n\ndouble : a -> a\ndouble x =\n    x + x\n",
        "module Main exposing (main)\n\nimport Lib exposing (double)\n\nmain =\n    double (1 == 1)\n",
    );
}

/// Warnings of every module reach the scoped assembly, in the same canonical
/// order as the joint solve's.
#[test]
fn warnings_agree_across_both_solves() {
    const WARN_A: &str = "module A exposing (visible)\n\n\
        type Color = Red | Green\n\n\
        visible : Int\n\
        visible = shade Red\n\n\
        shade : Color -> Int\n\
        shade c =\n    case c of\n        Red -> 1\n        Green -> 2\n        Red -> 3\n";
    const WARN_B: &str = "module B exposing (b)\n\n\
        import A exposing (visible)\n\n\
        type Dir = Up | Down\n\n\
        b : Int\n\
        b = visible + turn Up\n\n\
        turn : Dir -> Int\n\
        turn d =\n    case d of\n        Up -> 1\n        Down -> 2\n        Up -> 3\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], WARN_A);
    let b = file(&db, &["B"], WARN_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    assert_eq!(
        assert_program_oracle(&db, root, b),
        NonZeroUsize::new(2).map(|modules| TypedBy::Scoped { modules }),
        "both modules must be scoped for the warnings to come from the assembly"
    );
    let served = ipe_db::program_types(&db, root, b)
        .clone()
        .expect("warnings do not refuse the program");
    let homes: Vec<&[Symbol]> = served
        .types
        .warnings
        .iter()
        .map(ipe_types::HomedWarning::home)
        .collect();
    let (a_home, b_home) = (home_of(&db, a), home_of(&db, b));
    assert_eq!(
        homes,
        [a_home.as_slice(), b_home.as_slice()],
        "one redundant-branch warning per module, in canonical order"
    );
    let joint = canonical_joint(&db, root, b).expect("the program type-checks");
    assert_eq!(served.types.warnings, joint.warnings);
}

/// A body-only edit to a dep re-solves the dep alone and leaves its
/// importer's scoped solve memoized; an interface edit re-solves the
/// importer. The served program equals the joint solve after both.
#[test]
fn program_types_invalidates_per_module() {
    const DEP_A_FLOAT: &str =
        "module A exposing (visible)\n\nvisible : Float\nvisible = 1.5\n\nhidden = 2\n";
    let (mut db, log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let b = file(&db, &["B"], IMPORTER_B);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);
    let scoped = NonZeroUsize::new(2).map(|modules| TypedBy::Scoped { modules });
    assert_eq!(assert_program_oracle(&db, root, b), scoped);

    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_HIDDEN_GROWN));
    assert!(ipe_db::program_types(&db, root, b).is_ok());
    assert_eq!(
        log.executions_of("infer_module_scoped("),
        1,
        "a body-only dep edit re-solves the dep, never its importer"
    );
    assert_eq!(
        log.executions_of("typecheck("),
        0,
        "the scoped assembly never demands the joint solve"
    );
    assert_eq!(assert_program_oracle(&db, root, b), scoped);

    log.clear();
    assert!(ipe_db::set_text_if_changed(&mut db, a, DEP_A_FLOAT));
    assert!(ipe_db::program_types(&db, root, b).is_ok());
    assert_eq!(
        log.executions_of("infer_module_scoped("),
        2,
        "an interface edit re-solves the dep and its importer"
    );
    assert_eq!(assert_program_oracle(&db, root, b), scoped);
}
