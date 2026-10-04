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
            ipe_db::ScopedModuleTypes::WholeProgram => {}
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
// its importers' use sites never takes the scoped path.
// ---------------------------------------------------------------------------

const MSG_MAIN: &str = "module Main exposing (main)\n\n\
     import Ipe.Html as Html exposing (Html)\n\
     import Ipe.Io as Io\n\
     import Lib exposing (sharedRow)\n\n\
     type Msg\n    = Click\n\n\
     view : Html Msg\n\
     view =\n    Html.div [] [ sharedRow ]\n\n\
     main =\n    Io.println (Html.render view)\n";
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

/// An exported message-only UI slot refuses the scoped path for its module
/// and every importer, and the fallback still agrees with the joint solve.
#[test]
fn importer_pinnable_msg_slot_refuses_scoped_path() {
    let lib: &[&str] = &["Lib"];
    let main: &[&str] = &["Main"];
    for (label, lib_src) in [("untyped", MSG_LIB_UNTYPED), ("typed", MSG_LIB_TYPED)] {
        let (sources, injected) = prepared(&sources_of(&[(main, MSG_MAIN), (lib, lib_src)]));
        let db = ipe_db::IpeDatabase::new();
        let root =
            ipe::create_source_root(&db, &sources, &injected, &std::collections::BTreeSet::new());
        let file_at = |path: &[&str]| {
            root.files(&db)
                .iter()
                .find(|(p, _)| p.iter().map(String::as_str).eq(path.iter().copied()))
                .map(|(_, f)| *f)
        };
        let (lib_file, main_file) = (file_at(lib), file_at(main));
        assert!(
            lib_file.is_some() && main_file.is_some(),
            "[{label}] fixture must carry Lib and Main"
        );
        let (Some(lib_file), Some(main_file)) = (lib_file, main_file) else {
            return;
        };
        assert!(
            ipe_db::typecheck(&db, root, main_file).is_ok(),
            "[{label}] program must type-check"
        );
        assert!(
            ipe_db::typed_interface(&db, root, lib_file).is_none(),
            "[{label}] an exported message-only UI slot must yield an OPEN interface"
        );
        for (who, module) in [("Lib", lib_file), ("Main", main_file)] {
            assert!(
                matches!(
                    ipe_db::infer_module_scoped(&db, root, module),
                    ipe_db::ScopedModuleTypes::WholeProgram
                ),
                "[{label}] {who} must fall back to the whole-program solve"
            );
        }
        // The engaged set is exactly the injected stdlib closure: it imports
        // nothing user-side, so the user's message-only slot cannot reach it.
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
            ["Ipe.Html", "Ipe.Io"],
            "[{label}] only the stdlib closure may engage the scoped tier"
        );
        let (engaged, _) = assert_state_parity(label, &db, root);
        assert_eq!(
            engaged,
            engaged_set.len(),
            "[{label}] parity sweep and engaged set disagree"
        );
    }
}
