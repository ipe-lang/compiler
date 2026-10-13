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
    Db as _, FallbackReason, IpeDatabase, ModuleOrigin, ScopedModuleTypes, SolveLimits, SourceFile,
    SourceRoot, TypedBy,
};
use ipe_diagnostics::{Diagnostic, TypeError};
use ipe_intern::Symbol;
use ipe_types::{SolverSteps, SolverStepsError};

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
#[allow(clippy::expect_used)] // an interner refusal is the test failure
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
#[allow(clippy::expect_used)] // a joint solve past the solver space is the test failure
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
#[allow(clippy::panic)] // the scoped path not engaging is the test failure
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
        let ScopedModuleTypes::PerModule { solved, .. } = scoped else {
            panic!("closed modular program must take the scoped path, got {scoped:?}");
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

/// A red edit in one module does not blank an unrelated module's types:
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
#[allow(clippy::expect_used)] // a fixture past the solver space is the test failure
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

/// A canonical slice holding no keys and one redundant-branch warning owned by
/// `owner`.
#[allow(clippy::expect_used)] // a refused fixture warning is the test failure
fn slice_with_warning_of(owner: &[Symbol]) -> ipe_types::CanonicalTypes {
    let solved = solve_with_warning_of(owner);
    ipe_types::canonicalize(
        solved,
        ipe_types::VarScope::PerHome,
        ipe_types::VarCeiling::SOLVER,
    )
    .expect("a variable-free slice fits the solver space")
}

/// A ceiling of `n` variable ids.
#[allow(clippy::expect_used)] // a zero ceiling is a test bug
const fn ceiling(n: u32) -> ipe_types::VarCeiling {
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
    // Two key-free slices of one home share no key, so only the home check
    // can refuse them.
    let a_empty = slice_with_vars(&a, 0);
    assert_eq!(
        ipe_db::assemble_scoped(
            &[a_empty.clone(), a_empty],
            &BTreeSet::from([a.clone()]),
            solver
        )
        .err(),
        Some(FallbackReason::AssemblyConflict),
        "two key-free slices for one home must refuse the assembly"
    );
    let b_slice = slice_with_vars(&b, 1);
    assert_eq!(
        ipe_db::assemble_scoped(
            &[a_slice.clone(), b_slice],
            &BTreeSet::from([a.clone()]),
            solver
        )
        .err(),
        Some(FallbackReason::AssemblyConflict),
        "a slice with entries for a home the linked program lacks must refuse the assembly"
    );
    assert!(
        ipe_db::assemble_scoped(
            &[a_slice.clone(), slice_with_vars(&b, 0)],
            &BTreeSet::from([a.clone()]),
            solver
        )
        .is_ok(),
        "an empty slice for an unlinked module adds nothing and is admitted"
    );
    let misfiled = (b.clone(), Arc::clone(&a_slice.1));
    assert_eq!(
        ipe_db::assemble_scoped(&[misfiled], &BTreeSet::from([b.clone()]), solver).err(),
        Some(FallbackReason::AssemblyConflict),
        "a slice holding another home's keys must refuse the assembly"
    );
    let misfiled_warning = (a.clone(), Arc::new(slice_with_warning_of(&b)));
    assert_eq!(
        ipe_db::assemble_scoped(&[misfiled_warning], &BTreeSet::from([a.clone()]), solver).err(),
        Some(FallbackReason::AssemblyConflict),
        "a slice holding another home's warning must refuse the assembly"
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

// ---------------------------------------------------------------------------
// Polymorphic side tables: each fixture fills the table it is about, so the
// full-program comparison is not vacuous on it
// ---------------------------------------------------------------------------

/// Serve `entry`'s program, require the scoped assembly over `modules`
/// modules to equal the canonical joint solve on every field, and return the
/// served program.
///
/// Every generic binding in these fixtures is annotated, so no synthesized
/// type-parameter name is minted and no compared table depends on which solve
/// named it.
#[allow(clippy::expect_used)] // a refused program is the test failure
fn assert_scoped_oracle(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: SourceFile,
    modules: usize,
) -> Arc<ipe_db::ProgramTypes> {
    assert_eq!(
        assert_program_oracle(db, root, entry),
        NonZeroUsize::new(modules).map(|modules| TypedBy::Scoped { modules }),
        "every module must be scoped for the comparison to cover the assembly"
    );
    let served = ipe_db::program_types(db, root, entry)
        .clone()
        .expect("the program type-checks");
    assert!(
        served.types.untyped_type_params.is_empty(),
        "an annotated fixture mints no synthesized type parameter"
    );
    served
}

/// The homes holding at least one entry of a `(home, _)`-keyed table.
fn homes_of<K, V>(table: &BTreeMap<(Vec<Symbol>, K), V>) -> BTreeSet<Vec<Symbol>> {
    table.keys().map(|(home, _)| home.clone()).collect()
}

/// An annotated generic in a dep, used by an annotated generic in its
/// importer: both homes key their rigid variables in `poly_var_map`, and the
/// scoped assembly renumbers those keys exactly as the joint solve does.
#[test]
fn poly_var_map_agrees_across_a_module_edge() {
    const GENERIC_DEP: &str = "module A exposing (ident)\n\nident : a -> a\nident x =\n    x\n";
    const GENERIC_IMPORTER: &str = "module B exposing (b)\n\n\
        import A exposing (ident)\n\n\
        keep : k -> k\n\
        keep y =\n    ident y\n\n\
        b : Int\n\
        b =\n    keep 1\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], GENERIC_DEP);
    let b = file(&db, &["B"], GENERIC_IMPORTER);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let served = assert_scoped_oracle(&db, root, b, 2);
    assert_eq!(
        homes_of(&served.types.poly_var_map),
        BTreeSet::from([home_of(&db, a), home_of(&db, b)]),
        "each module's annotated generic keys its rigid variable"
    );
    assert!(
        served
            .types
            .poly_var_map
            .values()
            .all(|vars| !vars.is_empty()),
        "every keyed binding maps at least one variable"
    );
}

/// A dep's wildcard parameter pinned by its body, used by an importer at the
/// pinned type: `signature_wildcards` carries the pin, and the scoped
/// assembly serves it exactly as the joint solve does.
#[test]
fn signature_wildcards_agree_across_a_module_edge() {
    const WILDCARD_DEP: &str = "module A exposing (h)\n\nh : any -> Bool\nh x =\n    x + x == x\n";
    const WILDCARD_IMPORTER: &str =
        "module B exposing (b)\n\nimport A exposing (h)\n\nb : Bool\nb =\n    h 2\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], WILDCARD_DEP);
    let b = file(&db, &["B"], WILDCARD_IMPORTER);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);

    let served = assert_scoped_oracle(&db, root, b, 2);
    assert_eq!(
        homes_of(&served.types.signature_wildcards),
        BTreeSet::from([home_of(&db, a)]),
        "the dep's wildcard signature is recorded under its own home"
    );
    assert!(
        served
            .types
            .signature_wildcards
            .values()
            .any(|wildcards| !wildcards.pins.is_empty()),
        "the body pins the wildcard, so the pinned type is compared too"
    );
}

/// A private binding whose message slot no use pins: `msg_defaulted_vars`
/// records the defaulted slot, and the scoped assembly serves it exactly as
/// the joint solve does. The binding is not exported, so no importer's use
/// can change the default and the module stays scoped.
#[test]
fn msg_defaulted_vars_agree_across_a_module_edge() {
    const MSG_SLOT_MODULE: &str = "module V exposing (count)\n\n\
        import A exposing (visible)\n\n\
        page : Int -> Html msg\n\
        page n =\n    spin n\n\n\
        spin : Int -> Html msg\n\
        spin n =\n    spin n\n\n\
        count : Int\n\
        count =\n    visible\n";
    let (db, _log) = logged_db();
    let a = file(&db, &["A"], DEP_A);
    let v = file(&db, &["V"], MSG_SLOT_MODULE);
    let root = root_of(&db, &[(&["A"], a), (&["V"], v)]);

    let served = assert_scoped_oracle(&db, root, v, 2);
    assert_eq!(
        homes_of(&served.types.msg_defaulted_vars),
        BTreeSet::from([home_of(&db, v)]),
        "the private binding's unpinned message slot is defaulted"
    );
    assert!(
        served
            .types
            .msg_defaulted_vars
            .values()
            .all(|vars| !vars.is_empty()),
        "every keyed binding defaults at least one variable"
    );
}

// ---------------------------------------------------------------------------
// The scoped slice: dependency seeds are dropped, every other foreign entry refused
// ---------------------------------------------------------------------------

/// A solve holding no entries.
const fn empty_solve() -> ipe_types::SolvedTypes {
    ipe_types::SolvedTypes {
        env: BTreeMap::new(),
        regions: BTreeMap::new(),
        expected: BTreeMap::new(),
        bounds: BTreeMap::new(),
        warnings: Vec::new(),
        poly_var_map: BTreeMap::new(),
        untyped_type_params: BTreeMap::new(),
        msg_defaulted_vars: BTreeMap::new(),
        signature_wildcards: BTreeMap::new(),
    }
}

/// The dependency interfaces of a scoped solve: `dep` exporting `values`.
fn deps_exporting(
    dep: &[Symbol],
    values: &[Symbol],
) -> BTreeMap<Vec<Symbol>, Arc<ipe_types::TypedInterface>> {
    let interface = ipe_types::TypedInterface {
        values: values
            .iter()
            .map(|name| {
                (
                    *name,
                    ipe_types::TypedScheme {
                        ty: ipe_types::Ty::Unit,
                        bounds: BTreeMap::new(),
                        wildcard_pins: BTreeMap::new(),
                    },
                )
            })
            .collect(),
        unions: Vec::new(),
        reachable_unions: Vec::new(),
    };
    BTreeMap::from([(dep.to_vec(), Arc::new(interface))])
}

/// One solve per keyed field other than `env`, each holding a single entry of
/// `key_home`, labelled by its field.
fn one_entry_per_field(
    key_home: &[Symbol],
    name: Symbol,
) -> [(&'static str, ipe_types::SolvedTypes); 7] {
    let key = (key_home.to_vec(), name);
    let span_key = (key_home.to_vec(), ipe_diagnostics::Span::new(0, 1));
    [
        (
            "regions",
            ipe_types::SolvedTypes {
                regions: BTreeMap::from([(span_key.clone(), ipe_types::Ty::Unit)]),
                ..empty_solve()
            },
        ),
        (
            "expected",
            ipe_types::SolvedTypes {
                expected: BTreeMap::from([(span_key, ipe_types::Ty::Unit)]),
                ..empty_solve()
            },
        ),
        (
            "bounds",
            ipe_types::SolvedTypes {
                bounds: BTreeMap::from([(key.clone(), BTreeMap::new())]),
                ..empty_solve()
            },
        ),
        (
            "poly_var_map",
            ipe_types::SolvedTypes {
                poly_var_map: BTreeMap::from([(key.clone(), BTreeMap::new())]),
                ..empty_solve()
            },
        ),
        (
            "untyped_type_params",
            ipe_types::SolvedTypes {
                untyped_type_params: BTreeMap::from([(key.clone(), Vec::new())]),
                ..empty_solve()
            },
        ),
        (
            "msg_defaulted_vars",
            ipe_types::SolvedTypes {
                msg_defaulted_vars: BTreeMap::from([(key.clone(), BTreeSet::new())]),
                ..empty_solve()
            },
        ),
        (
            "signature_wildcards",
            ipe_types::SolvedTypes {
                signature_wildcards: BTreeMap::from([(
                    key,
                    ipe_types::SignatureWildcards::default(),
                )]),
                ..empty_solve()
            },
        ),
    ]
}

/// A solve holding one redundant-branch warning owned by `owner`.
#[allow(clippy::expect_used)] // a refused fixture warning is the test failure
fn solve_with_warning_of(owner: &[Symbol]) -> ipe_types::SolvedTypes {
    let warning = ipe_types::HomedWarning::new(
        ipe_diagnostics::Diagnostic::Type {
            span: ipe_diagnostics::Span::DUMMY,
            msg: ipe_diagnostics::TypeError::RedundantCaseBranch {
                constructor: "Red".into(),
            },
        },
        owner,
    )
    .expect("a redundant branch is a homed warning");
    ipe_types::SolvedTypes {
        warnings: vec![warning],
        ..empty_solve()
    }
}

/// `env` admits a foreign key only as a value of the matching dependency's
/// interface, and drops it from the slice; a key of a home that is no
/// dependency, or of a name the dependency does not export, is refused.
#[test]
fn scoped_slice_admits_only_dependency_interface_values_in_env() {
    let home = vec![Symbol::from_raw(1)];
    let dep = vec![Symbol::from_raw(2)];
    let stranger = vec![Symbol::from_raw(3)];
    let (own, seeded, unexported) = (
        Symbol::from_raw(10),
        Symbol::from_raw(11),
        Symbol::from_raw(12),
    );
    let deps = deps_exporting(&dep, &[seeded]);
    let own_entry = ((home.clone(), own), ipe_types::Ty::Unit);

    let seeded_solve = ipe_types::SolvedTypes {
        env: BTreeMap::from([
            own_entry.clone(),
            ((dep.clone(), seeded), ipe_types::Ty::Unit),
        ]),
        ..empty_solve()
    };
    assert_eq!(
        ipe_db::scoped_module_slice(&seeded_solve, &home, &deps),
        Ok(ipe_types::SolvedTypes {
            env: BTreeMap::from([own_entry.clone()]),
            ..empty_solve()
        }),
        "a dependency interface value is admitted and left to the dependency's slice"
    );

    for (what, foreign) in [
        ("a home that is no dependency", (stranger, seeded)),
        ("a name the dependency does not export", (dep, unexported)),
    ] {
        let solve = ipe_types::SolvedTypes {
            env: BTreeMap::from([own_entry.clone(), (foreign, ipe_types::Ty::Unit)]),
            ..empty_solve()
        };
        assert_eq!(
            ipe_db::scoped_module_slice(&solve, &home, &deps),
            Err(FallbackReason::AssemblyConflict),
            "an env key of {what} must be refused"
        );
    }
}

/// Every keyed field but `env` is refused on any foreign key, a dependency's
/// included, and kept whole when its keys are all the module's own.
#[test]
fn scoped_slice_refuses_a_foreign_key_in_every_other_field() {
    let home = vec![Symbol::from_raw(1)];
    let dep = vec![Symbol::from_raw(2)];
    let seeded = Symbol::from_raw(11);
    let deps = deps_exporting(&dep, &[seeded]);

    for (field, solve) in one_entry_per_field(&home, seeded) {
        assert_eq!(
            ipe_db::scoped_module_slice(&solve, &home, &deps),
            Ok(solve.clone()),
            "an own-home `{field}` entry is kept"
        );
    }
    for (field, solve) in one_entry_per_field(&dep, seeded) {
        assert_eq!(
            ipe_db::scoped_module_slice(&solve, &home, &deps),
            Err(FallbackReason::AssemblyConflict),
            "a dependency-home `{field}` entry must be refused"
        );
    }
}

/// A warning owned by another module is refused; the module's own is kept.
#[test]
fn scoped_slice_refuses_a_foreign_warning() {
    let home = vec![Symbol::from_raw(1)];
    let dep = vec![Symbol::from_raw(2)];
    let deps = deps_exporting(&dep, &[]);

    let own = solve_with_warning_of(&home);
    assert_eq!(
        ipe_db::scoped_module_slice(&own, &home, &deps),
        Ok(own.clone()),
        "the module's own warning is kept"
    );
    assert_eq!(
        ipe_db::scoped_module_slice(&solve_with_warning_of(&dep), &home, &deps),
        Err(FallbackReason::AssemblyConflict),
        "a dependency's warning must be refused"
    );
}

// ---------------------------------------------------------------------------
// One solver budget: the joint program's, bounding every scoped solve too
// ---------------------------------------------------------------------------

/// The solver steps `module`'s scoped solve spent, when it took the scoped path.
fn scoped_steps(db: &IpeDatabase, root: SourceRoot, module: SourceFile) -> Option<u64> {
    match ipe_db::infer_module_scoped(db, root, module) {
        ScopedModuleTypes::PerModule { steps, .. } => Some(*steps),
        ScopedModuleTypes::InterfaceOnly { .. } | ScopedModuleTypes::WholeProgram(_) => None,
    }
}

/// Run every solve in `db` under a step budget of `steps`.
fn set_steps(db: &mut IpeDatabase, steps: u64) {
    let limits = SolverSteps::new(steps).map(|steps| SolveLimits {
        steps,
        ..SolveLimits::DEFAULT
    });
    assert!(limits.is_some(), "a positive step budget");
    if let Some(limits) = limits {
        db.set_solve_limits(Ok(limits));
    }
}

/// Whether `err` is the step-budget refusal for a budget of `budget`.
const fn refuses_at_budget(err: &ipe_db::TypecheckError, budget: u64) -> bool {
    matches!(
        err.diagnostic(),
        Diagnostic::Type {
            msg: TypeError::StepBudgetExceeded { budget: refused },
            ..
        } if *refused == budget
    )
}

/// The `{A, C, Entry}` program and its modules, in that order.
fn two_dep_program(db: &IpeDatabase) -> (SourceRoot, [SourceFile; 3]) {
    let a = file(db, &["A"], DEP_A);
    let c = file(db, &["C"], DEP_C);
    let entry = file(db, &["Entry"], ENTRY_WITH_TWO_DEPS);
    let root = root_of(db, &[(&["A"], a), (&["C"], c), (&["Entry"], entry)]);
    (root, [a, c, entry])
}

/// Scoped solves whose steps sum past half the budget are not served: the
/// joint solve decides under the full budget. Under a budget twice their
/// sum, the same program is served by the scoped assembly.
#[test]
fn scoped_steps_past_half_the_budget_route_to_the_joint_solve() {
    let (mut db, _log) = logged_db();
    let (root, modules) = two_dep_program(&db);
    let [_, _, entry] = modules;
    let spent = modules.map(|module| scoped_steps(&db, root, module));
    assert!(
        spent.iter().all(|steps| matches!(steps, Some(n) if *n > 0)),
        "every module solves scoped and spends steps: {spent:?}"
    );
    let steps: Vec<u64> = spent.into_iter().flatten().collect();
    let Some(&most) = steps.iter().max() else {
        return;
    };
    let sum = steps.iter().fold(0_u64, |sum, n| sum.saturating_add(*n));

    // At the band's edge the scoped assembly is served, and the joint solve
    // accepts the same program under the same budget.
    set_steps(&mut db, sum.saturating_mul(2));
    assert_eq!(
        assert_program_oracle(&db, root, entry),
        NonZeroUsize::new(3).map(|modules| TypedBy::Scoped { modules }),
        "a sum of exactly half the budget is served scoped"
    );

    // Every module still fits a budget of the largest spend, but together
    // they spend more than half of it.
    set_steps(&mut db, most);
    assert_eq!(
        modules.map(|module| scoped_steps(&db, root, module)),
        spent,
        "each module's solve fits a budget of the largest spend"
    );
    let served = assert_program_oracle(&db, root, entry);
    let refusal = ipe_db::program_types(&db, root, entry).clone().err();
    assert!(
        served == Some(TypedBy::Joint(FallbackReason::BudgetBand))
            || refusal
                .as_ref()
                .is_some_and(|err| refuses_at_budget(err, most)),
        "past the band the joint solve decides: {served:?} / {refusal:?}"
    );
}

/// A module whose scoped solve runs one step past the budget falls back,
/// naming the budget, and the program reports the joint solve's refusal; the
/// exact budget admits the module.
#[test]
fn module_past_the_step_budget_falls_back_to_the_joint_refusal() {
    let (mut db, _log) = logged_db();
    let (root, [a, c, entry]) = two_dep_program(&db);
    let leaves = [a, c].map(|leaf| (leaf, scoped_steps(&db, root, leaf)));
    let heaviest = leaves
        .iter()
        .filter_map(|(leaf, steps)| steps.map(|steps| (*leaf, steps)))
        .max_by_key(|(_, steps)| *steps);
    assert!(
        matches!(heaviest, Some((_, steps)) if steps > 1),
        "a leaf spends more than one step: {leaves:?}"
    );
    let Some((leaf, steps)) = heaviest else {
        return;
    };

    set_steps(&mut db, steps - 1);
    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, leaf),
        &ScopedModuleTypes::WholeProgram(FallbackReason::BudgetExceeded),
        "one step short of the module's spend refuses its scoped solve"
    );
    assert_eq!(assert_program_oracle(&db, root, entry), None);
    let refusal = ipe_db::program_types(&db, root, entry).clone().err();
    assert!(
        refusal
            .as_ref()
            .is_some_and(|err| refuses_at_budget(err, steps - 1)),
        "the program reports the joint budget refusal: {refusal:?}"
    );

    set_steps(&mut db, steps);
    assert_eq!(
        scoped_steps(&db, root, leaf),
        Some(steps),
        "the exact budget admits the module"
    );
}

/// A module's spent steps are a function of the module and its deps'
/// interfaces: an unrelated sibling edit and a fresh database leave them
/// unchanged.
#[test]
fn scoped_steps_are_deterministic() {
    let (mut db, _log) = logged_db();
    let (root, [a, c, _]) = two_dep_program(&db);
    let cold = scoped_steps(&db, root, a);
    assert!(cold.is_some(), "A solves scoped");

    assert!(ipe_db::set_text_if_changed(&mut db, c, DEP_C_BODY_EDIT));
    assert_eq!(scoped_steps(&db, root, a), cold, "after a sibling edit");

    let (fresh, _fresh_log) = logged_db();
    let (fresh_root, [fresh_a, _, _]) = two_dep_program(&fresh);
    assert_eq!(
        scoped_steps(&fresh, fresh_root, fresh_a),
        cold,
        "in a fresh database"
    );
}

/// The variable ceiling a database holds bounds the scoped renumbering: one
/// id below the least ceiling that serves the program scoped, the joint solve
/// is served for the exhausted space.
#[test]
fn var_ceiling_bounds_the_scoped_renumbering() {
    const GENERIC_DEP: &str = "module A exposing (ident)\n\nident : a -> a\nident x =\n    x\n";
    const GENERIC_IMPORTER: &str = "module B exposing (b)\n\n\
        import A exposing (ident)\n\n\
        keep : k -> k\n\
        keep y =\n    ident y\n\n\
        b : Int\n\
        b =\n    keep 1\n";
    let (mut db, _log) = logged_db();
    let a = file(&db, &["A"], GENERIC_DEP);
    let b = file(&db, &["B"], GENERIC_IMPORTER);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);
    let scoped = NonZeroUsize::new(2).map(|modules| TypedBy::Scoped { modules });

    let serve_at = |db: &mut IpeDatabase, n: u32| {
        db.set_solve_limits(Ok(SolveLimits {
            var_ceiling: ceiling(n),
            ..SolveLimits::DEFAULT
        }));
        ipe_db::program_types(&*db, root, b)
            .as_ref()
            .ok()
            .map(|program| program.typed_by)
    };
    let least = (1..=256).find(|n| serve_at(&mut db, *n) == scoped);
    assert!(
        matches!(least, Some(n) if n > 1),
        "the program needs more than one variable id: {least:?}"
    );
    let Some(least) = least else {
        return;
    };

    assert_eq!(
        serve_at(&mut db, least - 1),
        Some(TypedBy::Joint(FallbackReason::VarSpaceExhausted)),
        "one id short of the least ceiling exhausts the scoped space"
    );
    assert_eq!(
        assert_program_oracle(&db, root, b),
        Some(TypedBy::Joint(FallbackReason::VarSpaceExhausted)),
        "the joint solve renumbers in the full solver space"
    );
}

/// A zero solver budget is refused, never read as "no limit": every program
/// reports the budget-`0` refusal from both solves, and the default setting
/// serves the same program.
#[test]
fn zero_solver_budget_refuses_every_program() {
    let (mut db, _log) = logged_db();
    let (root, [a, _, entry]) = two_dep_program(&db);

    db.set_solve_limits(Err(SolverStepsError::Zero));
    assert_eq!(
        ipe_db::infer_module_scoped(&db, root, a),
        &ScopedModuleTypes::WholeProgram(FallbackReason::BudgetExceeded)
    );
    assert_eq!(assert_program_oracle(&db, root, entry), None);
    let refusal = ipe_db::typecheck(&db, root, entry).clone().err();
    assert!(
        refusal
            .as_ref()
            .is_some_and(|err| refuses_at_budget(err, 0)),
        "the joint solve refuses a zero budget: {refusal:?}"
    );

    db.set_solve_limits(Ok(SolveLimits::DEFAULT));
    assert_eq!(
        assert_program_oracle(&db, root, entry),
        NonZeroUsize::new(3).map(|modules| TypedBy::Scoped { modules })
    );
}

/// The budget band's premise: a program whose scoped solves spend `s` steps
/// is accepted by the joint solve under a budget of `2 · s`, so the scoped
/// assembly never serves a program the joint solve refuses for its budget.
#[test]
fn joint_solve_fits_twice_the_scoped_spend() {
    const GENERIC_DEP: &str = "module A exposing (ident)\n\nident : a -> a\nident x =\n    x\n";
    const GENERIC_IMPORTER: &str = "module B exposing (b)\n\n\
        import A exposing (ident)\n\n\
        keep : k -> k\n\
        keep y =\n    ident y\n\n\
        b : Int\n\
        b =\n    keep 1\n";
    let programs: [&[(&[&str], &str)]; 3] = [
        &[
            (&["A"], DEP_A),
            (&["C"], DEP_C),
            (&["Entry"], ENTRY_WITH_TWO_DEPS),
        ],
        &[(&["A"], DEP_A), (&["B"], IMPORTER_B)],
        &[(&["A"], GENERIC_DEP), (&["B"], GENERIC_IMPORTER)],
    ];
    for program in programs {
        let (mut db, _log) = logged_db();
        let modules: Vec<(&[&str], SourceFile)> = program
            .iter()
            .map(|(path, text)| (*path, file(&db, path, text)))
            .collect();
        let root = root_of(&db, &modules);
        let Some(&(entry_path, entry)) = modules.last() else {
            continue;
        };
        let spent: Vec<Option<u64>> = modules
            .iter()
            .map(|(_, module)| scoped_steps(&db, root, *module))
            .collect();
        assert!(
            spent.iter().all(|steps| matches!(steps, Some(n) if *n > 0)),
            "{entry_path:?}: every module solves scoped: {spent:?}"
        );
        let sum = spent
            .iter()
            .flatten()
            .try_fold(0_u64, |sum, n| sum.checked_add(*n));
        assert!(sum.is_some(), "{entry_path:?}: the scoped sum fits a u64");
        let Some(sum) = sum else { continue };
        set_steps(&mut db, sum.saturating_mul(2));
        assert_eq!(
            assert_program_oracle(&db, root, entry),
            NonZeroUsize::new(modules.len()).map(|modules| TypedBy::Scoped { modules }),
            "{entry_path:?}: at twice the scoped spend both solves accept"
        );
    }
}
