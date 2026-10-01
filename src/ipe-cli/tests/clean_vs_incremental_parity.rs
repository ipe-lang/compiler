#![forbid(unsafe_code)]
//! The clean-vs-incremental parity gate (NON-NEGOTIABLE).
//!
//! For any edit sequence, the emitted project from an **incrementally
//! updated** (warm) database must be byte-identical to the emitted project
//! from a **cold** database built from the final source state. An
//! incremental result that diverges from a clean build is a soundness hole —
//! this gate is the primary guard against every under-invalidation hazard
//! and against interner demand-order nondeterminism (spec §3.3's recorded
//! warm-db limitation: symbol *numbering* differs between warm and cold
//! databases; this gate proves whether the numbering ever leaks into
//! emitted bytes).
//!
//! Both sides drive [`ipe::compile_prepared`] — THE production pipeline —
//! so the gate can never pass against a divergent copy of the compiler.
//!
//! Coverage:
//! - every fixture under `tests/golden/*` (single- and multi-module), each
//!   through a probe-edit → revert sequence that forces warm-db re-parses
//!   and interns a brand-new identifier at a warm (tail) symbol id;
//! - a purpose-built multi-module fixture exercising the adversarial edit
//!   classes: body-only edit, export widening, export type flip, red edit
//!   (type error), module add, module delete, module rename.

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

/// Driver-shaped preparation for one source state: synthesize stable blame
/// paths, inject the compiled-source stdlib closure, return the full source
/// map plus the trusted-injection record — exactly what `compile_modules`
/// computes before creating inputs.
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

type CompileOutcome = Result<ipe_backend::EmittedProject, String>;

/// The cold side: a fresh database built from the final source state — the
/// exact shape `compile_modules` produces on a one-shot `ipe build`.
fn cold_compile(user: &UserSources) -> CompileOutcome {
    let (sources, injected) = prepared(user);
    let db = ipe_db::IpeDatabase::new();
    let root =
        ipe::create_source_root(&db, &sources, &injected, &std::collections::BTreeSet::new());
    let config = ipe_db::BuildConfig::new(
        &db,
        ipe_backend_rust::DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        ipe_backend_rust::BuildIntent::Development,
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
        Path::new("<parity>"),
        config,
    )
    .map_err(|e| e.to_string())
}

/// The warm side: ONE database reused across the whole edit sequence, inputs
/// reconciled per state via [`ipe_db::sync_source_root`].
struct WarmSession {
    db: ipe_db::IpeDatabase,
    root: Option<ipe_db::SourceRoot>,
    // A STABLE `BuildConfig` handle across the whole sequence:
    // constructing a fresh `BuildConfig` per
    // `compile_prepared` call would give `emit_project` a different memo key
    // every demand, silently defeating the seam's memoization on the warm
    // side (the gate would never actually exercise a cache hit for emit).
    config: Option<ipe_db::BuildConfig>,
}

impl WarmSession {
    fn new() -> Self {
        Self {
            db: ipe_db::IpeDatabase::new(),
            root: None,
            config: None,
        }
    }

    fn compile(&mut self, user: &UserSources) -> CompileOutcome {
        let (sources, injected) = prepared(user);
        let root = if let Some(root) = self.root {
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
            ipe_db::sync_source_root(&mut self.db, root, &desired);
            root
        } else {
            let root = ipe::create_source_root(
                &self.db,
                &sources,
                &injected,
                &std::collections::BTreeSet::new(),
            );
            self.root = Some(root);
            root
        };
        let config = *self.config.get_or_insert_with(|| {
            ipe_db::BuildConfig::new(
                &self.db,
                ipe_backend_rust::DbDriver::Sqlite,
                None,
                ipe_ir::Target::Native,
                Vec::new(),
                false,
                ipe_backend_rust::BuildIntent::Development,
                None,
                false,
                String::new(),
                false,
                false,
            )
        });
        ipe::compile_prepared(
            &self.db,
            root,
            &sources,
            &entry_path(),
            Path::new("<parity>"),
            config,
        )
        .map_err(|e| e.to_string())
    }
}

/// First differing line between two strings, for actionable failures.
fn first_diff(a: &str, b: &str) -> String {
    for (i, (la, lb)) in a.lines().zip(b.lines()).enumerate() {
        if la != lb {
            return format!("line {}:\n  warm: {la}\n  cold: {lb}", i + 1);
        }
    }
    format!(
        "line counts differ: warm {} vs cold {}",
        a.lines().count(),
        b.lines().count()
    )
}

/// The gate: warm output must be BYTE-IDENTICAL to cold output — same
/// success/failure status, same file set, same bytes per file.
fn assert_parity(label: &str, warm: &CompileOutcome, cold: &CompileOutcome) {
    match (warm, cold) {
        (Ok(w), Ok(c)) => {
            let w_keys: Vec<&str> = w.files.keys().map(ipe_backend::RelPath::as_str).collect();
            let c_keys: Vec<&str> = c.files.keys().map(ipe_backend::RelPath::as_str).collect();
            assert_eq!(w_keys, c_keys, "[{label}] emitted file sets diverged");
            assert!(
                w.cargo_toml == c.cargo_toml,
                "[{label}] Cargo.toml diverged — {}",
                first_diff(&w.cargo_toml, &c.cargo_toml)
            );
            // Collect rather than assert-per-iteration: avoids indexing /
            // unwrap on the `get` result (both clippy-denied in this
            // workspace) while still surfacing every divergence, not just
            // the first.
            let mut missing_in_cold: Vec<&str> = Vec::new();
            let mut divergent: Vec<String> = Vec::new();
            for (rel, w_text) in &w.files {
                match c.files.get(rel) {
                    Some(c_text) if w_text == c_text => {}
                    Some(c_text) => {
                        divergent.push(format!(
                            "{} — {}",
                            rel.as_str(),
                            first_diff(w_text, c_text)
                        ));
                    }
                    None => missing_in_cold.push(rel.as_str()),
                }
            }
            assert!(
                missing_in_cold.is_empty(),
                "[{label}] key sets already compared equal but missing from cold output: {missing_in_cold:?}"
            );
            assert!(
                divergent.is_empty(),
                "[{label}] file(s) diverged between warm and cold builds: {divergent:?}"
            );
        }
        (Err(w), Err(c)) => {
            assert_eq!(w, c, "[{label}] diagnostics diverged between warm and cold");
        }
        (w, c) => {
            assert_eq!(
                w.is_ok(),
                c.is_ok(),
                "[{label}] build status diverged: warm ok={} cold ok={}\nwarm: {:?}\ncold: {:?}",
                w.is_ok(),
                c.is_ok(),
                w.as_ref().err(),
                c.as_ref().err()
            );
        }
    }
}

/// Load a golden fixture directory into an in-memory source map (every
/// `*.ipe` under it, module paths derived from the relative file paths).
/// `None` when the directory holds no `Main` module.
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

/// Run the probe-edit → revert sequence over one fixture:
///
/// - state0: the fixture as-is;
/// - state1: a brand-new top-level identifier appended to `Main` — on the
///   warm db this interns at a tail symbol id, on the cold db mid-parse: the
///   sharpest probe for symbol-numbering leaking into bytes;
/// - state0 again (revert): warm memos from revision 0 may backdate; output
///   must still equal the plain cold build.
fn probe_fixture(label: &str, state0: &UserSources) {
    let mut state1 = state0.clone();
    if let Some(main) = state1.get_mut(&entry_path()) {
        main.push_str("\n\nzzIncrementalParityProbe = 42\n");
    }

    let cold0 = cold_compile(state0);
    let cold1 = cold_compile(&state1);

    let mut warm = WarmSession::new();
    assert_parity(&format!("{label}/state0"), &warm.compile(state0), &cold0);
    assert_parity(
        &format!("{label}/probe-added"),
        &warm.compile(&state1),
        &cold1,
    );
    assert_parity(
        &format!("{label}/probe-reverted"),
        &warm.compile(state0),
        &cold0,
    );
}

/// Drive one shard of the golden fixture population; the union of all shards
/// is the full set.
fn probe_shard(shard: usize, count: usize) {
    let dirs = golden_fixture_dirs();
    assert!(
        dirs.len() >= 100,
        "gate must see the real fixture population, found {}",
        dirs.len()
    );
    let mut covered = 0usize;
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
        probe_fixture(&label, &state0);
        covered += 1;
    }
    assert!(
        covered > 0,
        "shard {shard} of {count} covered zero fixtures"
    );
}

// Each shard holds about a dozen fixtures, so no single test is a long pole
// and nextest bin-packs the population across every core.
parity_shards!(probe_shard;
    parity_probe_golden_fixtures_shard00 = 0,
    parity_probe_golden_fixtures_shard01 = 1,
    parity_probe_golden_fixtures_shard02 = 2,
    parity_probe_golden_fixtures_shard03 = 3,
    parity_probe_golden_fixtures_shard04 = 4,
    parity_probe_golden_fixtures_shard05 = 5,
    parity_probe_golden_fixtures_shard06 = 6,
    parity_probe_golden_fixtures_shard07 = 7,
    parity_probe_golden_fixtures_shard08 = 8,
    parity_probe_golden_fixtures_shard09 = 9,
    parity_probe_golden_fixtures_shard10 = 10,
    parity_probe_golden_fixtures_shard11 = 11,
    parity_probe_golden_fixtures_shard12 = 12,
    parity_probe_golden_fixtures_shard13 = 13,
    parity_probe_golden_fixtures_shard14 = 14,
    parity_probe_golden_fixtures_shard15 = 15,
    parity_probe_golden_fixtures_shard16 = 16,
    parity_probe_golden_fixtures_shard17 = 17,
    parity_probe_golden_fixtures_shard18 = 18,
    parity_probe_golden_fixtures_shard19 = 19,
    parity_probe_golden_fixtures_shard20 = 20,
    parity_probe_golden_fixtures_shard21 = 21,
    parity_probe_golden_fixtures_shard22 = 22,
    parity_probe_golden_fixtures_shard23 = 23,
    parity_probe_golden_fixtures_shard24 = 24,
    parity_probe_golden_fixtures_shard25 = 25,
    parity_probe_golden_fixtures_shard26 = 26,
    parity_probe_golden_fixtures_shard27 = 27,
    parity_probe_golden_fixtures_shard28 = 28,
    parity_probe_golden_fixtures_shard29 = 29,
    parity_probe_golden_fixtures_shard30 = 30,
    parity_probe_golden_fixtures_shard31 = 31,
    parity_probe_golden_fixtures_shard32 = 32,
    parity_probe_golden_fixtures_shard33 = 33,
    parity_probe_golden_fixtures_shard34 = 34,
    parity_probe_golden_fixtures_shard35 = 35,
    parity_probe_golden_fixtures_shard36 = 36,
    parity_probe_golden_fixtures_shard37 = 37,
    parity_probe_golden_fixtures_shard38 = 38,
    parity_probe_golden_fixtures_shard39 = 39,
    parity_probe_golden_fixtures_shard40 = 40,
    parity_probe_golden_fixtures_shard41 = 41,
    parity_probe_golden_fixtures_shard42 = 42,
    parity_probe_golden_fixtures_shard43 = 43,
    parity_probe_golden_fixtures_shard44 = 44,
    parity_probe_golden_fixtures_shard45 = 45,
    parity_probe_golden_fixtures_shard46 = 46,
    parity_probe_golden_fixtures_shard47 = 47,
    parity_probe_golden_fixtures_shard48 = 48,
    parity_probe_golden_fixtures_shard49 = 49,
    parity_probe_golden_fixtures_shard50 = 50,
    parity_probe_golden_fixtures_shard51 = 51,
    parity_probe_golden_fixtures_shard52 = 52,
    parity_probe_golden_fixtures_shard53 = 53,
    parity_probe_golden_fixtures_shard54 = 54,
    parity_probe_golden_fixtures_shard55 = 55,
    parity_probe_golden_fixtures_shard56 = 56,
    parity_probe_golden_fixtures_shard57 = 57,
    parity_probe_golden_fixtures_shard58 = 58,
    parity_probe_golden_fixtures_shard59 = 59,
    parity_probe_golden_fixtures_shard60 = 60,
    parity_probe_golden_fixtures_shard61 = 61,
    parity_probe_golden_fixtures_shard62 = 62,
    parity_probe_golden_fixtures_shard63 = 63,
);

/// The shard index list is the shard count: a gap, a duplicate, or an
/// out-of-order index is refused.
#[test]
fn parity_shard_indices_refuse_gaps_duplicates_and_disorder() {
    assert!(parity_shards::dense(&[0, 1, 2]));
    assert!(!parity_shards::dense(&[0, 2]));
    assert!(!parity_shards::dense(&[0, 0, 1]));
    assert!(!parity_shards::dense(&[1, 0]));
    assert!(!parity_shards::dense(&[1]));
    assert!(parity_shards::dense(PARITY_SHARDS));
}

/// Every fixture position belongs to exactly one shard, and a zero shard count
/// owns nothing.
#[test]
fn parity_shards_partition_every_fixture_exactly_once() {
    let count = PARITY_SHARDS.len();
    for position in 0..1000 {
        let owners = (0..count)
            .filter(|&shard| parity_shards::owns(position, shard, count))
            .count();
        assert_eq!(owners, 1, "fixture {position} owned by {owners} shards");
    }
    assert!(!parity_shards::owns(0, 0, 0));
}

// ---------------------------------------------------------------------------
// Purpose-built multi-module adversarial edit sequence
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
const UTIL_V1: &str = "module Lib.Util exposing (bump)\n\nbump x = x + 1\n";
const UTIL_BODY_EDIT: &str = "module Lib.Util exposing (bump)\n\nbump x = x + 2\n";
const UTIL_WIDENED: &str =
    "module Lib.Util exposing (bump, extra)\n\nbump x = x + 2\n\nextra = 7\n";
const UTIL_FLIPPED: &str =
    "module Lib.Util exposing (bump)\n\nbump : String -> String\nbump s = s ++ \"!\"\n";
const MAIN_FLIPPED: &str = "module Main exposing (main)\n\
     import Lib.Util exposing (bump)\n\n\
     main = Io.println (bump \"x\")\n";
const EXTRA_MOD: &str = "module Lib.Extra exposing (offset)\n\noffset = 100\n";
const MAIN_WITH_EXTRA: &str = "module Main exposing (main)\n\
     import Lib.Util exposing (bump)\n\
     import Lib.Extra exposing (offset)\n\n\
     main = Io.println (String.fromInt (bump offset))\n";
const HELPER_MOD: &str = "module Lib.Helper exposing (bump)\n\nbump x = x + 1\n";
const MAIN_RENAMED: &str = "module Main exposing (main)\n\
     import Lib.Helper exposing (bump)\n\n\
     main = Io.println (String.fromInt (bump 41))\n";

/// The scripted adversarial sequence from the plan: body-only edit, export
/// widening, export type flip, red edit, module add, module delete, module
/// rename — warm output byte-identical to a cold build at EVERY step.
#[test]
fn parity_multimodule_adversarial_edits() {
    let util: &[&str] = &["Lib", "Util"];
    let extra: &[&str] = &["Lib", "Extra"];
    let helper: &[&str] = &["Lib", "Helper"];
    let main: &[&str] = &["Main"];

    let states: Vec<(&str, UserSources)> = vec![
        ("baseline", sources_of(&[(main, MAIN_V1), (util, UTIL_V1)])),
        (
            "dep-body-edit",
            sources_of(&[(main, MAIN_V1), (util, UTIL_BODY_EDIT)]),
        ),
        (
            "export-widened",
            sources_of(&[(main, MAIN_V1), (util, UTIL_WIDENED)]),
        ),
        (
            "export-type-flip-red",
            // Lib.Util's export flips Int→String while Main still passes an
            // Int: both sides must reject with the SAME diagnostic.
            sources_of(&[(main, MAIN_V1), (util, UTIL_FLIPPED)]),
        ),
        (
            "export-type-flip-green",
            sources_of(&[(main, MAIN_FLIPPED), (util, UTIL_FLIPPED)]),
        ),
        (
            "module-added",
            sources_of(&[(main, MAIN_WITH_EXTRA), (util, UTIL_V1), (extra, EXTRA_MOD)]),
        ),
        (
            "module-deleted",
            sources_of(&[(main, MAIN_V1), (util, UTIL_V1)]),
        ),
        (
            "module-renamed",
            sources_of(&[(main, MAIN_RENAMED), (helper, HELPER_MOD)]),
        ),
        (
            "renamed-back",
            sources_of(&[(main, MAIN_V1), (util, UTIL_V1)]),
        ),
    ];

    let mut warm = WarmSession::new();
    for (label, state) in &states {
        let warm_out = warm.compile(state);
        let cold_out = cold_compile(state);
        assert_parity(&format!("adversarial/{label}"), &warm_out, &cold_out);
    }
}

// ---------------------------------------------------------------------------
// Watch-mode shape: the exact incremental pattern `ipe watch`'s orchestrator
// runs (one `SourceRoot` reused across `FsBatch` cycles via
// `sync_source_root`, feeding the same `compile_prepared` call every cycle —
// see `src/ipe-cli/src/watch.rs`'s `OrchestratorEvent::FsBatch` arm).
// `WarmSession` above already reproduces this shape; this test names it
// explicitly so a future reader does not have to infer watch-mode coverage
// from the golden-fixture probes.
// ---------------------------------------------------------------------------

// A closure-capture program: `compose` forwards a fn-typed param through a
// lambda, which lowers through the `eta_*` fresh-name pool (see
// `capture_fn_forwarded`/`firstclass_curried` under `tests/golden/`) — the
// exact pool the doc's warm-vs-cold hazard is about, so this probe exercises
// the numbering hazard rather than passing on an empty diff.
const WATCH_PROBE_V0: &str = "module Main exposing (main)\n\n\
     applyTwice : (Int -> Int) -> Int -> Int\n\
     applyTwice g x =\n    g (g x)\n\n\
     compose : (Int -> Int) -> Int -> Int\n\
     compose f =\n    \\x -> applyTwice f x\n\n\
     main =\n    Io.println (String.fromInt (compose (\\n -> n + 1) 3))\n";

/// One save-cycle in `ipe watch` that adds a brand-new top-level identifier
/// — the sharpest symbol-numbering probe (a warm db interns it at a tail id;
/// a cold db interns it mid-parse) — must still emit byte-identical Rust to
/// a cold build of the post-edit source, on a program whose lowering mints
/// `eta_*` fresh names (so the probe actually exercises the numbering
/// hazard, not just a byte-identical no-op).
#[test]
fn watch_mode_identifier_add_parity() {
    let state0 = sources_of(&[(["Main"].as_slice(), WATCH_PROBE_V0)]);
    let mut state1 = state0.clone();
    state1
        .get_mut(&entry_path())
        .expect("Main present")
        .push_str("\n\nwatchModeProbeIdentifier = 99\n");

    let mut warm = WarmSession::new();
    assert_parity(
        "watch-mode/state0",
        &warm.compile(&state0),
        &cold_compile(&state0),
    );
    assert_parity(
        "watch-mode/identifier-added",
        &warm.compile(&state1),
        &cold_compile(&state1),
    );
}
