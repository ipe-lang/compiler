//! `infer_package_capabilities` surfaces the real compiler diagnostic when a
//! package cannot be lowered, rather than a generic "nothing lowered" that hides
//! the actual cause (regression guard for the opaque failure that masked several
//! example-sweep reds). It also infers over ONE shared source graph: the result
//! equals the per-entry union, and each module is analyzed once per package.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use ipe::PackageSourceSet;
use ipe_ir::Capability;

/// A package whose only module fails to lower yields the module's real
/// diagnostic (`CliError::Pipeline`), naming the offending file — never the
/// generic `CliError::Usage` "no module could be lowered".
#[test]
fn a_package_that_cannot_lower_surfaces_the_real_diagnostic() -> Result<(), Box<dyn Error>> {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipe_capinfer_bad_entry");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"badpkg\", version = \"0.1.0\" }\n",
    )?;
    // `Main` references a name that does not exist, so lowering fails.
    fs::write(
        dir.join("src/Main.ipe"),
        "module Main\n\nmain : Task ()\nmain = thisNameDoesNotExist\n",
    )?;

    let result = ipe::infer_package_capabilities(&dir.join("package.ipe"));

    // The entry's real diagnostic (Pipeline, naming Main.ipe) must surface —
    // never the generic Usage "no module could be lowered".
    let surfaced_entry_diagnostic = matches!(
        &result,
        Err(ipe::CliError::Pipeline { file, .. }) if file.ends_with("Main.ipe")
    );
    assert!(
        surfaced_entry_diagnostic,
        "expected the entry's real Pipeline diagnostic, got: {result:?}"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared-graph inference: equivalence with the per-entry union + once-guard
// ---------------------------------------------------------------------------

const MANIFEST: &str = "module Package exposing (package)\n\n\npackage =\n    { name = \"sharedpkg\", version = \"0.1.0\" }\n";

/// `Main` imports a helper that reaches `Ipe.Html.Unsafe`; the unimported
/// sibling `Extra` reaches the network.
const UNSAFE_AND_SIBLING_NETWORK: &[(&str, &str)] = &[
    (
        "Main.ipe",
        "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Lib.Page exposing (page)\n\n\
         main : Task ()\nmain =\n\x20   Io.println page\n",
    ),
    (
        "Lib/Page.ipe",
        "module Lib.Page exposing (page)\n\nimport Ipe.Html exposing (render, section)\n\
         import Ipe.Html.Unsafe exposing (unsafeScript)\n\n\
         page : String\npage =\n\x20   render (section [] [ unsafeScript \"console.log(1)\" ])\n",
    ),
    (
        "Extra.ipe",
        "module Extra exposing (fetch)\n\nimport Ipe.Http as Http\n\
         import Ipe.Task as Task\nimport Ipe.Io as Io\nimport Ipe.Url as Url\n\n\
         fetch : Task ()\nfetch =\n\
         \x20   case Url.fromString \"http://example.com\" of\n\
         \x20       Ok url ->\n\
         \x20           Http.get url\n\
         \x20               |> Task.andThen (\\_ -> Io.println \"done\")\n\n\
         \x20       Err e ->\n\
         \x20           Task.fail e\n",
    ),
];

/// `Main` reaches the network and the clock; `Util` is pure; the UNIMPORTED
/// `Broken` does not compile, so the package is refused exactly as `ipe build`
/// refuses it, with the diagnostic framed against `Broken.ipe`.
const NETWORK_CLOCK_WITH_BROKEN_SIBLING: &[(&str, &str)] = &[
    (
        "Main.ipe",
        include_str!("fixtures/capabilities/uses_http_and_clock.ipe"),
    ),
    (
        "Util.ipe",
        "module Util exposing (shout)\n\nimport Ipe.String as String\n\n\
         shout : String -> String\nshout s =\n\x20   String.toUpper s\n",
    ),
    (
        "Broken.ipe",
        "module Broken exposing (oops)\n\noops : Int\noops =\n\x20   thisNameDoesNotExist\n",
    ),
];

/// Materialise a package (`package.ipe` + `src/<files>`) under a unique temp dir.
fn scratch_package(tag: &str, files: &[(&str, &str)]) -> Result<PathBuf, Box<dyn Error>> {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_capinfer_shared_{tag}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src"))?;
    fs::write(dir.join("package.ipe"), MANIFEST)?;
    for (rel, src) in files {
        let path = dir.join("src").join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, src)?;
    }
    Ok(dir)
}

/// The per-entry reference: each entry lowered alone in its own cold database,
/// skipped when it does not lower, and the results unioned.
fn per_entry_union(package: &PackageSourceSet) -> BTreeSet<Capability> {
    let mut union = BTreeSet::new();
    for entry in package.entry_module_paths() {
        if let Ok(caps) = ipe::infer_package_capabilities_in(
            &ipe_db::IpeDatabase::new(),
            &package.restricted_to_entry(entry),
        ) {
            union.extend(caps);
        }
    }
    union
}

/// The package's disclosed set, after pinning that the shared graph equals the
/// per-entry union and that the public entry point agrees run after run.
fn shared_capabilities(
    tag: &str,
    files: &[(&str, &str)],
) -> Result<BTreeSet<Capability>, Box<dyn Error>> {
    let dir = scratch_package(tag, files)?;
    let manifest = dir.join("package.ipe");
    let package = PackageSourceSet::read(&manifest)?;

    let shared = ipe::infer_package_capabilities_in(&ipe_db::IpeDatabase::new(), &package)?;
    assert_eq!(
        shared,
        per_entry_union(&package),
        "shared-graph inference must equal the per-entry union"
    );
    // The public entry point agrees, run after run.
    assert_eq!(ipe::infer_package_capabilities(&manifest)?, shared);
    assert_eq!(ipe::infer_package_capabilities(&manifest)?, shared);
    let _ = fs::remove_dir_all(&dir);
    Ok(shared)
}

fn assert_shared_equals_per_entry(
    tag: &str,
    files: &[(&str, &str)],
    must_contain: &[Capability],
) -> Result<(), Box<dyn Error>> {
    let shared = shared_capabilities(tag, files)?;
    for cap in must_contain {
        assert!(
            shared.contains(cap),
            "fixture `{tag}` must lower and disclose {cap:?}, got {shared:?}"
        );
    }
    Ok(())
}

#[test]
fn shared_graph_equals_per_entry_union_with_an_unimported_sibling() -> Result<(), Box<dyn Error>> {
    assert_shared_equals_per_entry(
        "unsafe_sibling",
        UNSAFE_AND_SIBLING_NETWORK,
        &[Capability::Unsafe, Capability::Network],
    )
}

// ---------------------------------------------------------------------------
// Disclosure follows reachability from the package's own code
// ---------------------------------------------------------------------------

/// `Main` imports `Ipe.Time` but calls only its pure `isLeapYear`; the
/// clock-reading exports stay uncalled.
const IMPORTS_TIME_CALLS_ONLY_PURE: &[(&str, &str)] = &[(
    "Main.ipe",
    "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.Time as Time\n\n\
     main : Task ()\nmain =\n\
     \x20   if Time.isLeapYear 2024 then\n\
     \x20       Io.println \"leap\"\n\n\
     \x20   else\n\
     \x20       Io.println \"common\"\n",
)];

/// `Main` calls `Ipe.Time.now`, which reads the clock.
const CALLS_TIME_NOW: &[(&str, &str)] = &[(
    "Main.ipe",
    "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.Task as Task\n\
     import Ipe.Time as Time\n\n\
     main : Task ()\nmain =\n\
     \x20   Time.now ()\n\
     \x20       |> Task.andThen (\\t -> Io.println (Time.timeString t))\n",
)];

/// `Main` is pure; the package module `Clock` exposes a clock read nothing in
/// the package calls, which a consumer still can.
const OWN_UNCALLED_CLOCK_EXPORT: &[(&str, &str)] = &[
    (
        "Main.ipe",
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\
         main : Task ()\nmain =\n\x20   Io.println \"ok\"\n",
    ),
    (
        "Clock.ipe",
        "module Clock exposing (stamp)\n\nimport Ipe.Error exposing (Error)\n\
         import Ipe.Time as Time\nimport Ipe.Time.Timestamp exposing (Timestamp)\n\n\
         stamp : Task Error Timestamp\nstamp =\n\x20   Time.now ()\n",
    ),
];

/// An imported stdlib module whose clock-reading exports the package never
/// calls does not disclose `clock`.
#[test]
fn an_unused_stdlib_export_does_not_disclose_its_capability() -> Result<(), Box<dyn Error>> {
    let shared = shared_capabilities("time_pure_only", IMPORTS_TIME_CALLS_ONLY_PURE)?;
    assert!(
        !shared.contains(&Capability::Clock),
        "an uncalled `Time.now` must not disclose `clock`, got {shared:?}"
    );
    assert!(
        !shared.contains(&Capability::Unsafe),
        "no `*.Unsafe` module is imported or reached, got {shared:?}"
    );
    Ok(())
}

/// Calling the same stdlib export discloses its capability.
#[test]
fn a_called_stdlib_export_discloses_its_capability() -> Result<(), Box<dyn Error>> {
    assert_shared_equals_per_entry("time_now", CALLS_TIME_NOW, &[Capability::Clock])
}

/// A package module's own export is consumer-callable, so its capability is
/// disclosed even when nothing in the package calls it (never under-disclose).
#[test]
fn an_uncalled_package_export_still_discloses_its_capability() -> Result<(), Box<dyn Error>> {
    assert_shared_equals_per_entry(
        "own_uncalled_clock",
        OWN_UNCALLED_CLOCK_EXPORT,
        &[Capability::Clock],
    )
}

/// The result is a `Pipeline` error framed against `file_name`.
fn is_pipeline_error_in<T>(result: &Result<T, ipe::CliError>, file_name: &str) -> bool {
    matches!(result, Err(ipe::CliError::Pipeline { file, .. }) if file.ends_with(file_name))
}

/// An unimported sibling that does not compile refuses the whole package.
///
/// Every entry links the whole source tree, as the build does, so no entry
/// lowers: the shared graph and the per-entry union agree (nothing disclosed),
/// the diagnostic is blamed on the sibling's own file, and a consent surface is
/// never published with the broken module's capabilities missing.
#[test]
fn a_broken_unimported_sibling_refuses_the_package_like_the_build() -> Result<(), Box<dyn Error>> {
    let dir = scratch_package("broken_sibling", NETWORK_CLOCK_WITH_BROKEN_SIBLING)?;
    let manifest = dir.join("package.ipe");
    let package = PackageSourceSet::read(&manifest)?;

    let shared = ipe::infer_package_capabilities_in(&ipe_db::IpeDatabase::new(), &package);
    assert!(
        is_pipeline_error_in(&shared, "Broken.ipe"),
        "expected the sibling's diagnostic framed against Broken.ipe, got: {shared:?}"
    );
    assert!(
        per_entry_union(&package).is_empty(),
        "no entry lowers per-entry either"
    );
    let public = ipe::infer_package_capabilities(&manifest);
    assert!(
        is_pipeline_error_in(&public, "Broken.ipe"),
        "expected the public entry point to agree, got: {public:?}"
    );
    // The build graph refuses the same package, blamed on the same file.
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_project(&manifest, &dir.join("out"), &runtime);
    assert!(
        is_pipeline_error_in(&built, "Broken.ipe"),
        "expected the build graph to refuse on Broken.ipe"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// A poison-safe log of the debug key of every executed salsa query.
#[derive(Clone, Default)]
struct ExecutionLog(Arc<Mutex<Vec<String>>>);

impl ExecutionLog {
    fn push(&self, key: String) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(key);
    }

    fn keys(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn executions_of(&self, query: &str) -> usize {
        let needle = format!("{query}(");
        self.keys().iter().filter(|k| k.contains(&needle)).count()
    }
}

fn logged_db() -> (ipe_db::IpeDatabase, ExecutionLog) {
    let log = ExecutionLog::default();
    let sink = log.clone();
    let db = ipe_db::IpeDatabase::with_event_callback(Box::new(move |event: salsa::Event| {
        if let salsa::EventKind::WillExecute { database_key } = event.kind {
            sink.push(format!("{database_key:?}"));
        }
    }));
    (db, log)
}

/// Each module (package and stdlib alike) is parsed and canonicalized at most
/// once for the whole package, each entry is lowered exactly once on the
/// caller's database, and no query instance ever executes twice.
///
/// `expect_refusal` pins whether the package is accepted or refused, so the
/// refusal path's error attribution is held to the same once-guard.
fn assert_each_module_analyzed_once(
    tag: &str,
    files: &[(&str, &str)],
    expect_refusal: bool,
) -> Result<(), Box<dyn Error>> {
    let dir = scratch_package(tag, files)?;
    let package = PackageSourceSet::read(&dir.join("package.ipe"))?;
    let (db, log) = logged_db();
    let outcome = ipe::infer_package_capabilities_in(&db, &package);
    assert_eq!(
        outcome.is_err(),
        expect_refusal,
        "fixture `{tag}` outcome: {outcome:?}"
    );

    let keys = log.keys();
    let distinct: BTreeSet<&String> = keys.iter().collect();
    assert_eq!(
        distinct.len(),
        keys.len(),
        "a query instance executed more than once: {keys:?}"
    );
    let modules = package.module_count();
    assert!(
        log.executions_of("parse") <= modules,
        "parse ran more often than there are modules ({modules})"
    );
    assert!(
        log.executions_of("canonicalize") <= modules,
        "canonicalize ran more often than there are modules ({modules})"
    );
    assert_eq!(
        log.executions_of("lower_program"),
        package.entry_module_paths().count(),
        "every entry is lowered exactly once, on the caller's database"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn each_module_is_analyzed_once_per_package() -> Result<(), Box<dyn Error>> {
    assert_each_module_analyzed_once("once_unsafe", UNSAFE_AND_SIBLING_NETWORK, false)?;
    assert_each_module_analyzed_once("once_broken", NETWORK_CLOCK_WITH_BROKEN_SIBLING, true)
}

// ---------------------------------------------------------------------------
// Every injected compiled-source stdlib module lowers as its own entry
// ---------------------------------------------------------------------------

/// A plain-`main` program importing `dotted`, plus a `main`-less `Probe` helper
/// for an `Ipe.Tea.*` shape module (a plain-`main` importer of a shape is an
/// IPE-N0033 contradiction; a `main`-less helper is exempt).
fn importer_of(dotted: &str) -> Vec<(&'static str, String)> {
    let is_tea_shape = dotted
        .strip_prefix("Ipe.Tea.")
        .is_some_and(|rest| rest.contains('.'));
    if is_tea_shape {
        vec![
            (
                "Main.ipe",
                "module Main exposing (main)\nimport Ipe.Io as Io\nimport Probe\n\n\
                 main : Task Error ()\nmain =\n    Io.println \"ok\"\n"
                    .to_owned(),
            ),
            (
                "Probe.ipe",
                format!(
                    "module Probe exposing (probe)\nimport {dotted} as M\n\n\
                     probe : Int\nprobe =\n    0\n"
                ),
            ),
        ]
    } else {
        vec![(
            "Main.ipe",
            format!(
                "module Main exposing (main)\nimport Ipe.Io as Io\nimport {dotted} as M\n\n\
                 main : Task Error ()\nmain =\n    Io.println \"ok\"\n"
            ),
        )]
    }
}

/// Every module in `COMPILED_STD_MODULES` a package imports becomes its own
/// capability-inference entry and lowers on its own.
///
/// The fold refuses a package when any entry fails, injected stdlib included,
/// so a stdlib module that cannot lower alone would refuse every package that
/// imports it. This pins that no such module exists.
#[test]
fn every_compiled_stdlib_module_lowers_as_its_own_entry() -> Result<(), Box<dyn Error>> {
    let mut failures: Vec<String> = Vec::new();
    for m in ipe_stdlib::COMPILED_STD_MODULES {
        let files = importer_of(m.dotted);
        let borrowed: Vec<(&str, &str)> = files.iter().map(|(p, s)| (*p, s.as_str())).collect();
        let dir = scratch_package(&format!("stdlib_entry_{}", m.dotted), &borrowed)?;
        let package = PackageSourceSet::read(&dir.join("package.ipe"))?;
        let segments: Vec<String> = m.dotted.split('.').map(str::to_owned).collect();
        if !package
            .entry_module_paths()
            .any(|entry| entry == segments.as_slice())
        {
            failures.push(format!("{}: not injected as an inference entry", m.dotted));
        } else if let Err(e) =
            ipe::infer_package_capabilities_in(&ipe_db::IpeDatabase::new(), &package)
        {
            failures.push(format!("{}: {e}", m.dotted));
        }
        let _ = fs::remove_dir_all(&dir);
    }
    assert!(
        failures.is_empty(),
        "every compiled-source stdlib module must lower as its own capability-\
         inference entry, or every package importing it is refused:\n{}",
        failures.join("\n"),
    );
    Ok(())
}
