//! The layout-cost bound over the golden corpus: every function body of every
//! lowerable `tests/golden/*/Main.ipe` lays out within an eighth of the
//! renderer's fuel, never falling back to its plain layout.
//!
//! Each entry is lowered through the build's front-end seam (compiled-source
//! stdlib injection, the salsa source root, `ipe_db::lower_program`) and each
//! body is measured by the backend's layout-budget seam
//! ([`ipe_backend_rust::body_layout_budgets`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ipe_db::Db;

/// The fixtures whose bodies once ran the fuel out; each must lower and be measured.
const NAMED_FIXTURES: [&str; 2] = ["db_store_rename_column", "analytics_store_gate"];

/// The `ipe-lang` workspace root (two levels up from this crate's manifest).
fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Every golden fixture directory that carries a `Main.ipe` entry, sorted.
fn golden_entries() -> Vec<PathBuf> {
    let golden = repo_root().join("tests").join("golden");
    let mut entries = Vec::new();
    let Ok(read) = std::fs::read_dir(&golden) else {
        return entries;
    };
    for dir in read.flatten() {
        let entry = dir.path().join("Main.ipe");
        if entry.is_file() {
            entries.push(entry);
        }
    }
    entries.sort();
    entries
}

/// The fixture directory name of `entry`.
fn fixture_name(entry: &Path) -> String {
    entry
        .parent()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The layout budget of every body in `entry`, or the reason none was measured.
fn measure(entry: &Path) -> Result<Vec<ipe_backend_rust::BodyLayoutBudget>, String> {
    let src = std::fs::read_to_string(entry).map_err(|e| format!("read: {e}"))?;
    measure_source(entry, src)
}

/// The layout budget of every body in the `Main` module source `src`.
fn measure_source(
    entry: &Path,
    src: String,
) -> Result<Vec<ipe_backend_rust::BodyLayoutBudget>, String> {
    measure_source_on(entry, src, None)
}

/// [`measure_source`], with the emit and layout run on a thread of `stack` bytes
/// when given.
fn measure_source_on(
    entry: &Path,
    src: String,
    stack: Option<usize>,
) -> Result<Vec<ipe_backend_rust::BodyLayoutBudget>, String> {
    let main = vec!["Main".to_owned()];
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(main.clone(), (entry.to_path_buf(), src));
    let mut discovered = Vec::new();
    let injected = ipe::project::inject_compiled_std_closure(&mut sources, &mut discovered);
    let db = ipe_db::IpeDatabase::new();
    let root = ipe::create_source_root(&db, &sources, &injected, &BTreeSet::new());
    let entry_file = root
        .files(&db)
        .get(&main)
        .copied()
        .ok_or_else(|| "the entry module is absent from the source root".to_owned())?;
    let program = ipe_db::lower_program(&db, root, entry_file)
        .clone()
        .map_err(|refusal| format!("lower: {refusal:?}"))?;
    emit_on(&db.interner().lock(), &program, stack)
}

/// The layout budgets of `program`'s bodies, measured on a thread of `stack` bytes
/// when given.
fn emit_on(
    interner: &ipe_intern::Interner,
    program: &ipe_ir::Program,
    stack: Option<usize>,
) -> Result<Vec<ipe_backend_rust::BodyLayoutBudget>, String> {
    let emit = move || {
        ipe_backend_rust::body_layout_budgets(interner, program).map_err(|e| format!("emit: {e:?}"))
    };
    let Some(stack) = stack else {
        return emit();
    };
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(stack)
            .spawn_scoped(scope, emit)
            .map_err(|e| format!("spawn: {e}"))?
            .join()
            .map_err(|_| "the emit thread panicked".to_owned())?
    })
}

#[test]
fn golden_bodies_render_within_fuel_fraction() {
    let entries = golden_entries();
    assert!(
        !entries.is_empty(),
        "no Main.ipe fixtures under tests/golden"
    );
    let ceiling = ipe_backend_rust::LAYOUT_FUEL >> 3;
    let mut measured_bodies = 0usize;
    let mut unmeasured = 0usize;
    let mut named_measured = [0usize; NAMED_FIXTURES.len()];
    let mut over: Vec<String> = Vec::new();
    for entry in &entries {
        let fixture = fixture_name(entry);
        let named = NAMED_FIXTURES.iter().position(|n| *n == fixture);
        let budgets = match measure(entry) {
            Ok(budgets) => budgets,
            Err(reason) => {
                assert!(
                    named.is_none(),
                    "{fixture} must lower and emit to be measured: {reason}"
                );
                // A fixture the pipeline turns away (an expected-error golden, a
                // multi-package shape) has no body a build would lay out.
                unmeasured += 1;
                continue;
            }
        };
        if let Some(slot) = named.and_then(|i| named_measured.get_mut(i)) {
            *slot += budgets.len();
        }
        measured_bodies += budgets.len();
        for b in budgets {
            if b.exhausted || b.spent > ceiling {
                over.push(format!(
                    "{fixture} :: fn {} spent {} (ceiling {ceiling}, exhausted {})",
                    b.func, b.spent, b.exhausted
                ));
            }
        }
    }
    eprintln!(
        "layout budget: {measured_bodies} bodies measured, {unmeasured} fixtures unmeasured, \
         {} over the ceiling",
        over.len()
    );
    assert!(measured_bodies > 0, "no function body was measured");
    for (name, count) in NAMED_FIXTURES.iter().zip(named_measured) {
        assert!(count > 0, "{name}: no function body was measured");
    }
    assert!(
        over.is_empty(),
        "function bodies past an eighth of the layout fuel:\n{}",
        over.join("\n")
    );
}

/// A shared zero-parameter binding (a CAF) lays its body out exactly once: the
/// cell-wrapped form is the only body built, never an inline body discarded
/// after it.
#[test]
fn caf_body_renders_once() {
    let src = "module Main exposing (main)\n\n\
               import Ipe.Io as Io\n\n\n\
               greeting : String\n\
               greeting =\n    \"hello\"\n\n\n\
               main =\n    Io.println greeting\n"
        .to_owned();
    let measured = measure_source(Path::new("Main.ipe"), src);
    assert!(
        measured.is_ok(),
        "the CAF program must lower and emit: {measured:?}"
    );
    let budgets = measured.unwrap_or_default();
    let names: Vec<&str> = budgets.iter().map(|b| b.func.as_str()).collect();
    let renders = names.iter().filter(|n| n.ends_with("greeting")).count();
    assert_eq!(renders, 1, "the CAF body must render once, got {names:?}");
}

/// The stack `ipe dev watch` compiles on: a spawned thread's default.
const WATCH_WORKER_STACK: usize = 2 << 20;

/// A `main` whose body chains `n` `Task.andThen` continuations.
fn task_pipe_source(n: usize) -> String {
    let mut body = String::from("Io.println \"s\"");
    for _ in 0..n {
        body.push_str(" |> Task.andThen (\\_ -> Io.println \"s\")");
    }
    format!(
        "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.Task as Task\n\n\n\
         main =\n    {body}\n"
    )
}

/// A `main` whose body nests `n` `Task.andThen` continuations, each inside the last.
fn task_nest_source(n: usize) -> String {
    let mut body = String::from("Io.println \"end\"");
    for _ in 0..n {
        body = format!("Io.println \"s\" |> Task.andThen (\\_ -> {body})");
    }
    format!(
        "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.Task as Task\n\n\n\
         main =\n    {body}\n"
    )
}

/// One nesting bound: its name, the source it shapes at a depth, the deepest depth
/// it admits, and the diagnostic refusing one step deeper.
struct NestingCase {
    name: &'static str,
    source: fn(usize) -> String,
    deepest: usize,
    refusal: &'static str,
}

/// The deepest body each nesting bound admits lays out on the watch worker's
/// stack, and one step deeper is refused by that bound instead of reaching the
/// renderer: the IR bound for a chained pipeline, the parser bound for nested
/// continuations.
#[test]
fn deepest_admitted_body_lays_out_on_watch_stack() {
    let cases = [
        NestingCase {
            name: "chained",
            source: task_pipe_source,
            deepest: 93,
            refusal: "BackendNestingTooDeep",
        },
        NestingCase {
            name: "nested",
            source: task_nest_source,
            deepest: 25,
            refusal: "NestingTooDeep",
        },
    ];
    for NestingCase {
        name,
        source,
        deepest,
        refusal,
    } in cases
    {
        let admitted = measure_source_on(
            Path::new("Main.ipe"),
            source(deepest),
            Some(WATCH_WORKER_STACK),
        );
        assert!(
            admitted
                .as_ref()
                .is_ok_and(|budgets| budgets.iter().all(|b| !b.exhausted)),
            "{name}: depth {deepest} must be admitted and lay out within fuel: {admitted:?}"
        );
        let refused = measure_source(Path::new("Main.ipe"), source(deepest + 1));
        assert!(
            refused
                .as_ref()
                .is_err_and(|reason| reason.contains(refusal)),
            "{name}: depth {} must be refused by {refusal}, got {refused:?}",
            deepest + 1
        );
    }
}
