#![forbid(unsafe_code)]
//! The scoped-vs-whole parity gate (NON-NEGOTIABLE for the per-module tier).
//!
//! Wherever the per-module scoped solve engages
//! ([`ipe_db::ScopedModuleTypes::PerModule`]), its result MUST equal the
//! normalized whole-program projection of that module — for EVERY module of
//! EVERY golden fixture, and at every state of the adversarial multi-module
//! edit sequence. A scoped result that diverges from the joint solve is a
//! correctness violation (the LSP would show a type the build disagrees
//! with); a scoped tier that never engages is a vacuous one, so aggregate
//! engagement is asserted too. A module engages only when every exported
//! binding's scheme is closed (annotated, or settled concrete) — an
//! unannotated importer-pinnable export honestly refuses the scoped path.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ipe::project;

#[macro_use]
mod parity_shards;

type UserSources = BTreeMap<Vec<String>, String>;
type PreparedSources = BTreeMap<Vec<String>, (PathBuf, String)>;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Driver-shaped preparation for one source state (same shape as the
/// clean-vs-incremental gate): synthesize stable blame paths, inject the
/// compiled-source stdlib closure.
fn prepared(user: &UserSources) -> (PreparedSources, BTreeSet<Vec<String>>) {
    let mut sources: PreparedSources = user
        .iter()
        .map(|(p, text)| {
            (
                p.clone(),
                (
                    PathBuf::from(format!("<parity>/{}.ipe", p.join("/"))),
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

const ENTRY: &[&str] = &["Main"];

fn entry_path() -> Vec<String> {
    ENTRY.iter().map(|s| (*s).to_owned()).collect()
}

/// Per-state parity sweep: demand the JOINT solve first, then every
/// module's scoped outcome; assert each engaged module's scoped result
/// equals the normalized joint projection. Returns `(engaged, total)`.
fn assert_state_parity(
    label: &str,
    db: &ipe_db::IpeDatabase,
    root: ipe_db::SourceRoot,
) -> (usize, usize) {
    use ipe_db::Db as _;
    let files: Vec<(Vec<String>, ipe_db::SourceFile)> = root
        .files(db)
        .iter()
        .map(|(p, f)| (p.clone(), *f))
        .collect();
    let entry_file = files
        .iter()
        .find(|(p, _)| *p == entry_path())
        .map(|&(_, f)| f);
    assert!(
        entry_file.is_some(),
        "[{label}] fixture must carry a Main module"
    );
    let Some(entry_file) = entry_file else {
        return (0, files.len());
    };
    let joint = ipe_db::typecheck(db, root, entry_file);

    let mut engaged = 0usize;
    for (path, file) in &files {
        match ipe_db::infer_module_scoped(db, root, *file) {
            ipe_db::ScopedModuleTypes::PerModule { types, .. } => {
                engaged += 1;
                // On a red program there is no joint slice to compare
                // against — the scoped result standing on closed
                // interfaces is the red-edit-resilience property, and
                // diagnostics still come from the joint query.
                if let Ok(solved) = &joint {
                    let home: Option<Vec<ipe_intern::Symbol>> = {
                        let mut interner = db.interner().lock();
                        path.iter()
                            .map(|segment| interner.intern(segment).ok())
                            .collect()
                    };
                    assert!(home.is_some(), "[{label}] interner append failed");
                    let Some(home) = home else {
                        return (engaged, files.len());
                    };
                    let projected =
                        ipe_db::normalize_module_types(ipe_db::project_module_types(solved, &home));
                    assert_eq!(
                        **types,
                        projected,
                        "[{label}] scoped result for {} diverges from the joint slice",
                        path.join(".")
                    );
                }
            }
            ipe_db::ScopedModuleTypes::InterfaceOnly { .. }
            | ipe_db::ScopedModuleTypes::WholeProgram => {}
        }
    }
    (engaged, files.len())
}

/// Cold-database parity sweep over one source state.
fn cold_state_parity(label: &str, user: &UserSources) -> (usize, usize) {
    let (sources, injected) = prepared(user);
    let db = ipe_db::IpeDatabase::new();
    let root =
        ipe::create_source_root(&db, &sources, &injected, &std::collections::BTreeSet::new());
    assert_state_parity(label, &db, root)
}

/// Load a golden fixture directory into an in-memory source map (every
/// `*.ipe` under it). `None` when the directory holds no `Main` module.
fn fixture_user_sources(dir: &Path) -> Option<UserSources> {
    let discovered = project::discover_modules(dir).ok()?;
    if !discovered.iter().any(|m| m.module_path() == entry_path()) {
        return None;
    }
    let mut user = UserSources::new();
    for m in discovered {
        user.insert(
            m.module_path().to_vec(),
            std::fs::read_to_string(m.path()).ok()?,
        );
    }
    Some(user)
}

/// All golden fixture dirs, deterministically ordered.
fn golden_fixture_dirs() -> Vec<PathBuf> {
    let root = repo_root().join("tests").join("golden");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

/// Drive one shard of the golden fixture population; the union of all shards
/// is the full set.
fn parity_shard(shard: usize, count: usize) {
    let dirs = golden_fixture_dirs();
    assert!(
        dirs.len() >= 100,
        "gate must see the real fixture population, found {}",
        dirs.len()
    );
    let mut covered = 0usize;
    let mut shard_engaged = 0usize;
    for (i, dir) in dirs.iter().enumerate() {
        if !parity_shards::owns(i, shard, count) {
            continue;
        }
        let Some(state0) = fixture_user_sources(dir) else {
            continue;
        };
        let label = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (engaged, _total) = cold_state_parity(&label, &state0);
        shard_engaged += engaged;
        covered += 1;
    }
    assert!(covered > 0, "shard {shard} covered zero fixtures");
    // Engagement is a per-module property (an unannotated importer-pinnable
    // export honestly refuses the scoped path), so it is asserted in
    // aggregate here — and precisely, per fixture shape, in
    // `src/compiler/db/tests/per_module_typecheck.rs`.
    assert!(
        shard_engaged > 0,
        "shard {shard}: scoped tier engaged zero modules across {covered} fixtures — vacuous"
    );
}

parity_shards!(parity_shard;
    scoped_parity_golden_fixtures_shard0 = 0,
    scoped_parity_golden_fixtures_shard1 = 1,
    scoped_parity_golden_fixtures_shard2 = 2,
    scoped_parity_golden_fixtures_shard3 = 3,
);

// ---------------------------------------------------------------------------
// Adversarial multi-module edit sequence — the same edit classes the
// clean-vs-incremental gate scripts, driven WARM (one database, inputs
// reconciled per state) so scoped memos survive across states and parity is
// asserted against each state's joint solve.
// ---------------------------------------------------------------------------

fn sources_of(pairs: &[(&[&str], &str)]) -> UserSources {
    pairs
        .iter()
        .map(|(p, text)| {
            (
                p.iter().map(|s| (*s).to_owned()).collect(),
                (*text).to_owned(),
            )
        })
        .collect()
}

const MAIN_V1: &str = "module Main exposing (main)\n\
     import Lib.Util exposing (bump)\n\n\
     main = Io.println (String.fromInt (bump 41))\n";
// Annotated export → engageable closed interface.
const UTIL_V1: &str = "module Lib.Util exposing (bump)\n\nbump : Int -> Int\nbump x = x + 1\n";
const UTIL_BODY_EDIT: &str =
    "module Lib.Util exposing (bump)\n\nbump : Int -> Int\nbump x = x + 2\n";
const UTIL_WIDENED: &str = "module Lib.Util exposing (bump, extra)\n\n\
     bump : Int -> Int\nbump x = x + 2\n\nextra : Int\nextra = 7\n";
// UNANNOTATED numeric export: an importer-pinnable scheme — the scoped tier
// must refuse it (open interface) and parity must hold via the fallback.
const UTIL_UNANNOTATED: &str = "module Lib.Util exposing (bump)\n\nbump x = x + 2\n";
const UTIL_FLIPPED: &str =
    "module Lib.Util exposing (bump)\n\nbump : String -> String\nbump s = s ++ \"!\"\n";
const MAIN_FLIPPED: &str = "module Main exposing (main)\n\
     import Lib.Util exposing (bump)\n\n\
     main = Io.println (bump \"x\")\n";
const EXTRA_MOD: &str = "module Lib.Extra exposing (offset)\n\noffset : Int\noffset = 100\n";
const MAIN_WITH_EXTRA: &str = "module Main exposing (main)\n\
     import Lib.Util exposing (bump)\n\
     import Lib.Extra exposing (offset)\n\n\
     main = Io.println (String.fromInt (bump offset))\n";

/// Body-only edit, export widening, unannotated (open-interface) flip,
/// export type flip (red then green), module add, module delete — warm
/// scoped memos must agree with each state's joint solve at EVERY step.
#[test]
fn scoped_parity_adversarial_edits_warm() {
    let util: &[&str] = &["Lib", "Util"];
    let extra: &[&str] = &["Lib", "Extra"];
    let main: &[&str] = &["Main"];

    // `(label, sources, min_engaged)` — the open-interface state HONESTLY
    // engages zero modules (Lib.Util's unannotated numeric export is
    // importer-pinnable; Main imports it, so both fall back).
    let states: Vec<(&str, UserSources, usize)> = vec![
        (
            "baseline",
            sources_of(&[(main, MAIN_V1), (util, UTIL_V1)]),
            1,
        ),
        (
            "dep-body-edit",
            sources_of(&[(main, MAIN_V1), (util, UTIL_BODY_EDIT)]),
            1,
        ),
        (
            "export-widened",
            sources_of(&[(main, MAIN_V1), (util, UTIL_WIDENED)]),
            1,
        ),
        (
            "unannotated-open",
            sources_of(&[(main, MAIN_V1), (util, UTIL_UNANNOTATED)]),
            0,
        ),
        (
            "export-type-flip-red",
            sources_of(&[(main, MAIN_V1), (util, UTIL_FLIPPED)]),
            1,
        ),
        (
            "export-type-flip-green",
            sources_of(&[(main, MAIN_FLIPPED), (util, UTIL_FLIPPED)]),
            1,
        ),
        (
            "module-added",
            sources_of(&[(main, MAIN_WITH_EXTRA), (util, UTIL_V1), (extra, EXTRA_MOD)]),
            2,
        ),
        (
            "module-deleted",
            sources_of(&[(main, MAIN_V1), (util, UTIL_V1)]),
            1,
        ),
    ];

    let mut db = ipe_db::IpeDatabase::new();
    let mut warm_root: Option<ipe_db::SourceRoot> = None;
    for (label, state, min_engaged) in &states {
        let (sources, injected) = prepared(state);
        let root = if let Some(root) = warm_root {
            let desired: BTreeMap<Vec<String>, (String, ipe_db::ModuleOrigin)> = sources
                .iter()
                .map(|(p, (_, text))| {
                    let origin = if injected.contains(p) {
                        ipe_db::ModuleOrigin::EmbeddedStdlib
                    } else {
                        ipe_db::ModuleOrigin::User
                    };
                    (p.clone(), (text.clone(), origin))
                })
                .collect();
            ipe_db::sync_source_root(&mut db, root, &desired);
            root
        } else {
            let root = ipe::create_source_root(
                &db,
                &sources,
                &injected,
                &std::collections::BTreeSet::new(),
            );
            warm_root = Some(root);
            root
        };

        let (engaged, total) = assert_state_parity(label, &db, root);
        assert!(
            engaged >= *min_engaged,
            "[{label}] scoped tier engaged {engaged} of {total} modules, expected >= {min_engaged}"
        );

        // Cold-vs-warm agreement of the scoped tier itself: a cold database
        // over the same state must serve the same engaged/parity verdicts.
        let (cold_engaged, cold_total) = cold_state_parity(&format!("{label}/cold"), state);
        assert_eq!(
            (engaged, total),
            (cold_engaged, cold_total),
            "[{label}] warm and cold scoped-tier engagement diverged"
        );
    }
}

// ---------------------------------------------------------------------------
// Importer-pinnable UI-msg slots: a module whose own solved facts depend on
// its importers' use sites never serves its own types from the scoped path;
// its exported schemes do not depend on those use sites, so its importers do.
// ---------------------------------------------------------------------------

const MSG_MAIN: &str = "module Main exposing (main)\n\n\
     import Ipe.Html as Html exposing (Html)\n\
     import Ipe.Io as Io\n\
     import Lib exposing (sharedRow)\n\n\
     type Msg\n    = Click\n\n\
     view : Html Msg\n\
     view =\n    Html.div [] [ sharedRow ]\n\n\
     main =\n    Io.println (Html.render view)\n";
// The importer renders the slot without pinning it, so the joint solve
// defaults it.
const MSG_MAIN_UNPINNED: &str = "module Main exposing (main)\n\n\
     import Ipe.Html as Html exposing (Html)\n\
     import Ipe.Io as Io\n\
     import Lib exposing (sharedRow)\n\n\
     main =\n    Io.println (Html.render sharedRow)\n";
// Unannotated: the msg-only quantified root defaults to `()` unless a
// cross-module use pins it, and only the joint solve sees that use.
const MSG_LIB_UNTYPED: &str = "module Lib exposing (sharedRow)\n\n\
     import Ipe.Html as Html exposing (Html)\n\n\
     sharedRow =\n    Html.div [] [ Html.text \"shared\" ]\n";
// Annotated: `msg` is a message-only result slot whose defaulting reads every
// use site, importers' included.
const MSG_LIB_TYPED: &str = "module Lib exposing (sharedRow)\n\n\
     import Ipe.Html as Html exposing (Html)\n\n\
     sharedRow : Html msg\n\
     sharedRow =\n    Html.div [] [ Html.text \"shared\" ]\n";

/// The module's own scoped solve read straight off [`ipe_types::infer_module`]
/// over its deps' served interfaces: the facts an
/// [`ipe_db::ScopedModuleTypes::InterfaceOnly`] verdict withholds.
fn scoped_own_types(
    db: &ipe_db::IpeDatabase,
    root: ipe_db::SourceRoot,
    file: ipe_db::SourceFile,
    home: &[ipe_intern::Symbol],
) -> Result<ipe_db::ModuleTypes, String> {
    use ipe_db::Db as _;
    let canonical = ipe_db::canonicalize(db, root, file)
        .clone()
        .map_err(|e| format!("canonicalize failed: {e:?}"))?;
    let resolutions = ipe_db::resolve_imports(db, root, file)
        .clone()
        .map_err(|e| format!("import resolution failed: {e:?}"))?;
    let mut dep_interfaces = Vec::new();
    for (path, resolution) in resolutions.iter() {
        if let ipe_db::ImportResolution::Resolved(dep) = resolution {
            let interface = ipe_db::typed_interface(db, root, *dep)
                .clone()
                .ok_or_else(|| format!("dep {} has an open interface", path.join(".")))?;
            dep_interfaces.push((path.clone(), interface));
        }
    }
    let mut interner = db.interner().lock();
    let mut deps = BTreeMap::new();
    for (path, interface) in dep_interfaces {
        let key = path
            .iter()
            .map(|segment| interner.intern(segment))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("interner append failed: {e:?}"))?;
        deps.insert(key, interface);
    }
    let inference =
        ipe_types::infer_module(&canonical.module, &canonical.exports, &deps, &mut interner)
            .map_err(|e| format!("scoped solve failed: {e:?}"))?;
    drop(interner);
    Ok(ipe_db::normalize_module_types(
        ipe_db::project_module_types(&inference.solved, home),
    ))
}

/// An exported message-only UI slot keeps its module's own types on the
/// whole-program solve, while its closed interface still serves the importer,
/// and both agree with the joint solve.
#[test]
fn importer_pinnable_msg_slot_refuses_scoped_path() -> Result<(), String> {
    use ipe_db::Db as _;
    let lib: &[&str] = &["Lib"];
    let main: &[&str] = &["Main"];
    // `own_diverges`: Lib's own scoped facts disagree with the joint slice, so
    // serving them (a `PerModule` verdict) would fail the served-types check
    // below: the refusal is load-bearing, not merely conservative.
    for (label, main_src, lib_src, own_diverges) in [
        ("untyped", MSG_MAIN, MSG_LIB_UNTYPED, true),
        ("typed", MSG_MAIN, MSG_LIB_TYPED, false),
        (
            "untyped-unpinned",
            MSG_MAIN_UNPINNED,
            MSG_LIB_UNTYPED,
            false,
        ),
        ("typed-unpinned", MSG_MAIN_UNPINNED, MSG_LIB_TYPED, false),
    ] {
        let (sources, injected) = prepared(&sources_of(&[(main, main_src), (lib, lib_src)]));
        let db = ipe_db::IpeDatabase::new();
        let root =
            ipe::create_source_root(&db, &sources, &injected, &std::collections::BTreeSet::new());
        let file_at = |path: &[&str]| {
            root.files(&db)
                .iter()
                .find(|(p, _)| p.iter().map(String::as_str).eq(path.iter().copied()))
                .map(|(_, f)| *f)
        };
        let lib_file = file_at(lib).ok_or_else(|| format!("[{label}] fixture must carry Lib"))?;
        let main_file =
            file_at(main).ok_or_else(|| format!("[{label}] fixture must carry Main"))?;
        let joint = ipe_db::typecheck(&db, root, main_file)
            .clone()
            .map_err(|e| format!("[{label}] program must type-check: {e:?}"))?;
        assert!(
            matches!(
                ipe_db::infer_module_scoped(&db, root, lib_file),
                ipe_db::ScopedModuleTypes::InterfaceOnly { .. }
            ),
            "[{label}] Lib's own types must come from the whole-program solve"
        );
        assert!(
            ipe_db::typed_interface(&db, root, lib_file).is_some(),
            "[{label}] Lib's exported schemes are closed, so its interface must be served"
        );
        let lib_home: Vec<ipe_intern::Symbol> = {
            let mut interner = db.interner().lock();
            lib.iter()
                .map(|segment| interner.intern(segment))
                .collect::<Result<_, _>>()
                .map_err(|e| format!("[{label}] interner append failed: {e:?}"))?
        };
        let lib_served = ipe_db::typecheck_module(&db, root, main_file, lib_file)
            .clone()
            .map_err(|e| format!("[{label}] Lib's types must be served: {e:?}"))?;
        let lib_joint =
            ipe_db::normalize_module_types(ipe_db::project_module_types(&joint, &lib_home));
        assert_eq!(
            *lib_served, lib_joint,
            "[{label}] Lib's served types must be the joint slice"
        );
        let shared_row = db
            .interner()
            .lock()
            .intern("sharedRow")
            .map_err(|e| format!("[{label}] interner append failed: {e:?}"))?;
        let lib_own = scoped_own_types(&db, root, lib_file, &lib_home)?;
        let own_entry = lib_own.env.get(&shared_row);
        let joint_entry = lib_joint.env.get(&shared_row);
        assert!(
            own_entry.is_some() && joint_entry.is_some(),
            "[{label}] both solves must type `sharedRow`"
        );
        assert_eq!(
            own_entry != joint_entry,
            own_diverges,
            "[{label}] Lib's own scoped `sharedRow` {own_entry:?} vs joint {joint_entry:?}"
        );
        // The engaged set is the injected stdlib closure plus the importer:
        // Main solves against Lib's closed interface.
        let engaged_set: Vec<String> = root
            .files(&db)
            .iter()
            .filter(|(_, f)| {
                matches!(
                    ipe_db::infer_module_scoped(&db, root, **f),
                    ipe_db::ScopedModuleTypes::PerModule { .. }
                )
            })
            .map(|(p, _)| p.join("."))
            .collect();
        assert_eq!(
            engaged_set,
            ["Ipe.Html", "Ipe.Io", "Main"],
            "[{label}] the stdlib closure and the importer engage the scoped tier"
        );
        let (engaged, _) = assert_state_parity(label, &db, root);
        assert_eq!(
            engaged,
            engaged_set.len(),
            "[{label}] parity sweep and engaged set disagree"
        );
    }
    Ok(())
}

// A message slot chained through two unannotated helpers: `Lib.nav` sits inside
// `Mid.wrap`, whose slot only `Main.view` pins.
const CHAIN_LIB: &str = "module Lib exposing (nav)\n\n\
     import Ipe.Html as Html exposing (Html)\n\n\
     nav =\n    Html.div [] [ Html.text \"nav\" ]\n";
const CHAIN_MID: &str = "module Mid exposing (wrap)\n\n\
     import Ipe.Html as Html exposing (Html)\n\
     import Lib exposing (nav)\n\n\
     wrap =\n    Html.div [] [ nav ]\n";
const CHAIN_MAIN: &str = "module Main exposing (main)\n\n\
     import Ipe.Html as Html exposing (Html)\n\
     import Ipe.Io as Io\n\
     import Mid exposing (wrap)\n\n\
     type Msg\n    = Click\n\n\
     view : Html Msg\n\
     view =\n    Html.div [] [ wrap ]\n\n\
     main =\n    Io.println (Html.render view)\n";

/// A module's scoped verdict, as a comparable name.
const fn verdict_name(verdict: &ipe_db::ScopedModuleTypes) -> &'static str {
    match verdict {
        ipe_db::ScopedModuleTypes::PerModule { .. } => "PerModule",
        ipe_db::ScopedModuleTypes::InterfaceOnly { .. } => "InterfaceOnly",
        ipe_db::ScopedModuleTypes::WholeProgram => "WholeProgram",
    }
}

/// Every module's scoped verdict, by dotted path.
fn verdicts(db: &ipe_db::IpeDatabase, root: ipe_db::SourceRoot) -> BTreeMap<String, &'static str> {
    root.files(db)
        .iter()
        .map(|(p, f)| {
            (
                p.join("."),
                verdict_name(ipe_db::infer_module_scoped(db, root, *f)),
            )
        })
        .collect()
}

/// Type-check `user` cold and return its database, root and verdicts.
fn checked(
    user: &UserSources,
) -> Result<
    (
        ipe_db::IpeDatabase,
        ipe_db::SourceRoot,
        BTreeMap<String, &'static str>,
    ),
    String,
> {
    let (sources, injected) = prepared(user);
    let db = ipe_db::IpeDatabase::new();
    let root =
        ipe::create_source_root(&db, &sources, &injected, &std::collections::BTreeSet::new());
    let main_file = root
        .files(&db)
        .get(&entry_path())
        .copied()
        .ok_or("fixture must carry Main")?;
    ipe_db::typecheck(&db, root, main_file)
        .clone()
        .map_err(|e| format!("program must type-check: {e:?}"))?;
    let seen = verdicts(&db, root);
    Ok((db, root, seen))
}

/// Both helpers of a chained message slot keep their own types on the
/// whole-program solve, the importer that pins the slot solves against their
/// closed interfaces, and every engaged module agrees with the joint solve.
#[test]
fn chained_msg_slot_serves_interfaces_only() -> Result<(), String> {
    let (db, root, seen) = checked(&sources_of(&[
        (&["Main"], CHAIN_MAIN),
        (&["Mid"], CHAIN_MID),
        (&["Lib"], CHAIN_LIB),
    ]))?;
    let user: Vec<(&str, Option<&&str>)> = ["Lib", "Mid", "Main"]
        .into_iter()
        .map(|m| (m, seen.get(m)))
        .collect();
    assert_eq!(
        user,
        [
            ("Lib", Some(&"InterfaceOnly")),
            ("Mid", Some(&"InterfaceOnly")),
            ("Main", Some(&"PerModule")),
        ],
        "chained helpers serve interfaces only; the pinning importer engages"
    );
    let engaged = seen.values().filter(|v| **v == "PerModule").count();
    let (swept, _) = assert_state_parity("chained-msg-slot", &db, root);
    assert_eq!(swept, engaged, "parity sweep and engaged set disagree");
    Ok(())
}

// An unannotated field-accessor export: its scheme carries an open row only an
// importer's record closes.
const ACCESSOR_LIB: &str = "module Lib exposing (getX)\n\n\
     getX r =\n    r.x\n";
const ACCESSOR_MAIN: &str = "module Main exposing (main)\n\n\
     import Ipe.Io as Io\n\
     import Ipe.String as String\n\
     import Lib exposing (getX)\n\n\
     main =\n    Io.println (String.fromInt (getX { x = 1, y = 2 }))\n";

/// A field-accessor export's open-row scheme has no closed interface, so its
/// module and every importer stay on the whole-program solve: the scoped tier
/// never serves a scheme an importer's record still shapes.
#[test]
fn field_accessor_export_parity() -> Result<(), String> {
    let (db, root, seen) = checked(&sources_of(&[
        (&["Main"], ACCESSOR_MAIN),
        (&["Lib"], ACCESSOR_LIB),
    ]))?;
    assert_eq!(
        (seen.get("Lib"), seen.get("Main")),
        (Some(&"WholeProgram"), Some(&"WholeProgram")),
        "an open-row export keeps its module and importer on the whole-program solve"
    );
    let engaged = seen.values().filter(|v| **v == "PerModule").count();
    let (swept, _) = assert_state_parity("field-accessor", &db, root);
    assert_eq!(swept, engaged, "parity sweep and engaged set disagree");
    Ok(())
}
