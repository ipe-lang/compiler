#![forbid(unsafe_code)]
//! Anti-drift gate: every EXPORT of every compiled-source stdlib module resolves
//! through the real compiler pipeline.
//!
//! The source-vs-kernel drift class: a compiled-source `Ipe.*` module declares a
//! member in its `exposing (...)` list, but the member has no resolvable home —
//! no local body, no re-export, and (for an `Ffi.kernel "…"` alias) no matching
//! registered kernel. Such a member type-checks nowhere: a `Module.member` call
//! fails name-resolution (IPE-N0005 / IPE-N0028). An earlier `Ipe.Random`
//! shipped exactly this — `shuffle`/`weighted`/the seeded helpers were declared
//! but had no kernel row.
//!
//! This gate canonicalises EVERY compiled-source module (types included, unlike
//! the parse-only `ipe_stdlib::every_exported_value_has_a_home` floor) by
//! importing it into one `Main` and driving the production compile pipeline. A
//! module whose export is a dangling declaration or a broken kernel alias fails
//! its own canonicalisation here — pre-cargo, in the fast (non-E2E) path.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ipe::project;

type UserSources = BTreeMap<Vec<String>, String>;
type PreparedSources = BTreeMap<Vec<String>, (PathBuf, String)>;

fn prepared(user: &UserSources) -> (PreparedSources, BTreeSet<Vec<String>>) {
    let mut sources: PreparedSources = user
        .iter()
        .map(|(p, text)| {
            (
                p.clone(),
                (
                    PathBuf::from(format!("<resolvability>/{}.ipe", p.join("/"))),
                    text.clone(),
                ),
            )
        })
        .collect();
    let mut discovered: Vec<project::DiscoveredModule> = sources
        .iter()
        .map(|(p, (path, _))| project::DiscoveredModule::user(path.clone(), p.clone()))
        .collect();
    let injected = project::inject_compiled_std_closure(&mut sources, &mut discovered);
    (sources, injected)
}

fn entry_path() -> Vec<String> {
    vec!["Main".to_owned()]
}

/// Compile one synthesized `Main` through the production pipeline; `Ok` iff the
/// whole closure — every injected compiled-source module — canonicalises,
/// type-checks, and lowers.
fn compile_main(main: &str) -> Result<(), String> {
    let mut user = UserSources::new();
    user.insert(entry_path(), main.to_owned());
    let (sources, injected) = prepared(&user);
    let db = ipe_db::IpeDatabase::new();
    let root = ipe::create_source_root(&db, &sources, &injected, &BTreeSet::new());
    let config = ipe_db::BuildConfig::new(
        &db,
        ipe_backend_rust::DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        false,
        None,
        false,
        String::new(),
        false,
        false,
    );
    ipe::compile_prepared(
        &db,
        root,
        &sources,
        &entry_path(),
        Path::new("<resolvability>"),
        config,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Like [`compile_main`], but adds extra user modules to the graph. Used to route
/// a `Ipe.Tea.*` shape module through a `main`-less helper (exempt from the
/// IPE-N0033 Program-imports-a-shape gate) while `Main` stays a plain Program.
fn compile_main_with_helper(main: &str, extras: &[(Vec<String>, String)]) -> Result<(), String> {
    let mut user = UserSources::new();
    user.insert(entry_path(), main.to_owned());
    for (path, text) in extras {
        user.insert(path.clone(), text.clone());
    }
    let (sources, injected) = prepared(&user);
    let db = ipe_db::IpeDatabase::new();
    let root = ipe::create_source_root(&db, &sources, &injected, &BTreeSet::new());
    let config = ipe_db::BuildConfig::new(
        &db,
        ipe_backend_rust::DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        false,
        None,
        false,
        String::new(),
        false,
        false,
    );
    ipe::compile_prepared(
        &db,
        root,
        &sources,
        &entry_path(),
        Path::new("<resolvability>"),
        config,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Every compiled-source stdlib module, imported ONE AT A TIME into a `Main`,
/// must resolve.
///
/// Each module is compiled in isolation (a `Main` importing only it) so the gate
/// tests one module's own export resolution — not the incidental cross-module
/// name interactions of importing the whole stdlib into a single graph. A broken
/// export (a dangling declaration or an `Ffi.kernel "…"` alias with no registered
/// kernel) fails the imported module's own canonicalisation, so the compile fails
/// and the culprit is named. Importing with `as` (no member use) is enough: the
/// injected module is canonicalised as a dependency, and a homeless export cannot
/// survive that pass.
#[test]
fn compiled_source_modules_resolve_all_exports() {
    let mut failures: Vec<String> = Vec::new();
    for m in ipe_stdlib::COMPILED_STD_MODULES {
        // A `Ipe.Tea.*` shape module marks any plain-`main` importer a TEA-app
        // contradiction (IPE-N0033). Route it through a `main`-less helper module
        // — exempt from that gate — so the export resolution still runs while
        // `Main` stays a plain Program.
        let is_tea_shape = m
            .dotted
            .strip_prefix("Ipe.Tea.")
            .is_some_and(|rest| rest.contains('.'));
        let result = if is_tea_shape {
            let helper = format!(
                "module Probe exposing (probe)\nimport {} as M\n\nprobe : Int\nprobe =\n    0\n",
                m.dotted,
            );
            compile_main_with_helper(
                "module Main exposing (main)\nimport Ipe.Io as Io\nimport Probe\n\n\
                 main : Task Error ()\nmain =\n    Io.println \"ok\"\n",
                &[(vec!["Probe".to_owned()], helper)],
            )
        } else {
            let main = format!(
                "module Main exposing (main)\nimport Ipe.Io as Io\nimport {} as M\n\n\
                 main : Task Error ()\nmain =\n    Io.println \"ok\"\n",
                m.dotted,
            );
            compile_main(&main)
        };
        if let Err(e) = result {
            failures.push(format!("{}: {e}", m.dotted));
        }
    }
    assert!(
        failures.is_empty(),
        "every compiled-source stdlib module must resolve all its exports \
         through the real pipeline — a failure here is source-vs-kernel drift \
         (a declared-but-homeless export or a broken `Ffi.kernel` alias):\n{}",
        failures.join("\n"),
    );
}

/// Every EXPOSED VALUE of every kernel-veneer `MODULES` fixture resolves through
/// the real pipeline against the qualifier catalog.
///
/// The veneers (`Ipe.System`, `Ipe.File`, `Ipe.Http`, …) are NEVER injected as
/// source — `inject_compiled_std_closure` consults `COMPILED_STD_MODULES` alone,
/// so their `Kernel.kernel "…"` bodies never compile. A `Module.member` call
/// instead resolves against the pre-installed kernel-qualifier catalog. A member
/// listed in the veneer's `exposing (...)` but absent from that catalog (and from
/// the kernel registry) type-checks nowhere: the call is IPE-N0005, yet `ipe doc`
/// still advertises it (docs derive from the fixtures). This gate references
/// every exposed value at a real call site so a catalog-homeless veneer export
/// fails the compile here, pre-cargo — closing the same drift class the
/// compiled-source gate closes for `COMPILED_STD_MODULES`.
#[test]
fn kernel_veneer_modules_resolve_all_exports() {
    use ipe_intern::Interner;
    use ipe_syntax::{Exposed, Exposing};

    let mut failures: Vec<String> = Vec::new();
    for m in ipe_stdlib::MODULES {
        let mut interner = Interner::new();
        let parsed = match ipe_parse::parse_module(m.source, &mut interner) {
            Ok(p) => p,
            Err(e) => {
                failures.push(format!("{}: veneer failed to parse: {e:?}", m.name));
                continue;
            }
        };
        let value_names: Vec<String> = match &parsed.exposing.value {
            // An export-all veneer has nothing to cross-check name-by-name.
            Exposing::All => continue,
            Exposing::List(items) => items
                .iter()
                .filter_map(|item| match &item.value {
                    Exposed::Value(n) => interner.resolve(*n).map(str::to_owned),
                    Exposed::Type(_, _) => None,
                })
                .collect(),
        };
        if value_names.is_empty() {
            continue;
        }

        // Reference every exposed value at a real call site: one bare top-level
        // binding per value forces name resolution (and HM inference of its
        // scheme) independently, so a catalog-homeless member fails resolution
        // and names itself. No application is needed — a dangling `Module.member`
        // reference already resolves against the catalog.
        let mut probes = String::new();
        for (i, name) in value_names.iter().enumerate() {
            let _ = writeln!(probes, "probe{i} = M.{name}");
        }
        let main = format!(
            "module Main exposing (main)\nimport Ipe.Io as Io\nimport {} as M\n\n\
             {probes}\nmain : Task Error ()\nmain =\n    Io.println \"ok\"\n",
            m.name,
        );

        if let Err(e) = compile_main(&main) {
            failures.push(format!("{}: {e}", m.name));
        }
    }
    assert!(
        failures.is_empty(),
        "every kernel-veneer stdlib module must resolve all its exposed values \
         through the real pipeline — a failure here is a veneer that advertises \
         (and documents) a member with no catalog home (IPE-N0005 at any call \
         site):\n{}",
        failures.join("\n"),
    );
}

/// Focused regression: the whole `Ipe.Random` surface resolves + type-checks at
/// real call sites — the exact members that were homeless (`shuffle`,
/// `weighted`, `choice`, and the seeded `seed`/`seededInt`/`seededFloat`/
/// `seededChoice` over the opaque `Seed`).
#[test]
fn random_full_surface_resolves() {
    let main = concat!(
        "module Main exposing (main)\n",
        "import Ipe.Io as Io\n",
        "import Ipe.String as String\n",
        "import Ipe.Task as Task\n",
        "import Ipe.Random as Random\n\n",
        "seededLine : String\n",
        "seededLine =\n",
        "    let\n",
        "        s0 = Random.seed 7\n",
        "        i = Random.seededInt s0 1 10\n",
        "        f = Random.seededFloat s0\n",
        "        c = Random.seededChoice s0 [ 1, 2, 3 ]\n",
        "    in\n",
        "    case i of\n",
        "        ( v, _ ) -> String.fromInt v\n\n",
        "draw : Task Error String\n",
        "draw =\n",
        "    Random.int 1 6\n",
        "        |> Task.andThen (\\_ -> Random.float 0.0 1.0)\n",
        "        |> Task.andThen (\\_ -> Random.range 1 6)\n",
        "        |> Task.andThen (\\_ -> Random.choice [ 10, 20 ])\n",
        "        |> Task.andThen (\\_ -> Random.shuffle [ 1, 2, 3 ])\n",
        "        |> Task.andThen (\\_ -> Random.weighted [ ( 1.0, \"a\" ) ])\n",
        "        |> Task.map (\\_ -> seededLine)\n\n",
        "main : Task Error ()\n",
        "main = Task.andThen (\\line -> Io.println line) draw\n",
    );

    let outcome = compile_main(main);
    assert!(
        outcome.is_ok(),
        "the whole Ipe.Random surface must resolve + type-check: {:?}",
        outcome.err(),
    );
}
