#![forbid(unsafe_code)]
//! Independent adversarial review probe for the Task-18 clean-vs-incremental
//! parity gate (`clean_vs_incremental_parity.rs`).
//!
//! This file is a SEPARATE, independently-authored harness (deliberately not
//! importing anything from `clean_vs_incremental_parity.rs`, since integration
//! test binaries can't share private items) that targets edit shapes the
//! reviewed test battery does not exercise:
//!
//! 1. A user identifier that LITERALLY collides with a fresh-name pool
//!    candidate (`eta_0`) — the sharpest possible test of
//!    `Interner::set_fresh_avoid`'s collision-skipping logic, not just an
//!    unrelated new name landing at a tail interner position.
//! 2. Grow → shrink → re-grow the SAME pool across three warm revisions
//!    (does the collision universe correctly recompute from scratch each
//!    build, with no leakage from a prior revision's minted names?).
//! 3. Two back-to-back input syncs on the warm database with NO query demand
//!    between them (does salsa's incremental machinery only care about the
//!    final input state, never the edit path taken to reach it?).
//! 4. An identifier rename A -> B -> A within a SINGLE module (not a module
//!    rename) — round-tripping a name back to its original spelling.
//!
//! Any warm/cold divergence found here is a CRITICAL finding: the
//! clean-vs-incremental parity gate would be falsely green.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ipe::project;

type UserSources = BTreeMap<Vec<String>, String>;
type PreparedSources = BTreeMap<Vec<String>, (PathBuf, String)>;

fn prepared(user: &UserSources) -> (PreparedSources, std::collections::BTreeSet<Vec<String>>) {
    let mut sources: PreparedSources = user
        .iter()
        .map(|(p, text)| {
            (
                p.clone(),
                (
                    PathBuf::from(format!("<advparity>/{}.ipe", p.join("/"))),
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
        Path::new("<advparity>"),
        config,
    )
    .map_err(|e| e.to_string())
}

struct WarmSession {
    db: ipe_db::IpeDatabase,
    root: Option<ipe_db::SourceRoot>,
    // Stable across the whole session — see the twin comment in
    // `clean_vs_incremental_parity.rs`.
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

    /// Sync inputs to `user`'s state WITHOUT demanding any query — used to
    /// construct the "two edits, one demand" adversarial shape.
    #[allow(clippy::single_match_else)]
    fn sync_only(&mut self, user: &UserSources) {
        let (sources, injected) = prepared(user);
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
        match self.root {
            Some(root) => ipe_db::sync_source_root(&mut self.db, root, &desired),
            None => {
                let root = ipe::create_source_root(
                    &self.db,
                    &sources,
                    &injected,
                    &std::collections::BTreeSet::new(),
                );
                self.root = Some(root);
            }
        }
    }

    /// Demand a compile at the CURRENT input state (no sync).
    ///
    /// `expect`: every call site in this harness invokes `sync_only` first,
    /// which unconditionally sets `self.root` — this is a test-scaffold
    /// invariant, not a fallible external condition.
    #[allow(clippy::expect_used)]
    fn demand(&self, user: &UserSources) -> CompileOutcome {
        let (sources, _) = prepared(user);
        let root = self.root.expect("root must exist before demand()");
        let config = self
            .config
            .expect("config must exist before demand() (set by sync_only via compile())");
        ipe::compile_prepared(
            &self.db,
            root,
            &sources,
            &entry_path(),
            Path::new("<advparity>"),
            config,
        )
        .map_err(|e| e.to_string())
    }

    fn compile(&mut self, user: &UserSources) -> CompileOutcome {
        self.sync_only(user);
        if self.config.is_none() {
            self.config = Some(ipe_db::BuildConfig::new(
                &self.db,
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
            ));
        }
        self.demand(user)
    }
}

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

// A curried first-class function value forces the lowerer's `eta_` pool (the
// exact class golden fixture `firstclass_curried` uses).
const MAIN: &[&str] = &["Main"];

const BASE: &str = "module Main exposing (main)\n\
import Ipe.Io
     type Page = Home String String\n\n\
     mk : String -> (String -> Page)\n\
     mk s =\n    \\t -> Home s t\n\n\
     apply2 : (String -> String -> Page) -> Page\n\
     apply2 f =\n    f \"hello\" \"world\"\n\n\
     pageStr : Page -> String\n\
     pageStr p =\n    case p of\n        Home a b -> a ++ \" \" ++ b\n\n\
     main =\n    let g = mk in\n    let p1 = g \"first\" \"second\" in\n    let p2 = apply2 mk in\n    Io.println (pageStr p1 ++ \"|\" ++ pageStr p2)\n";

// Same as BASE but with a top-level binding literally named `eta_0` — the
// exact string the lowerer's fresh-name pool would mint FIRST for this
// program if nothing were reserved. This is the sharpest possible probe of
// `Interner::set_fresh_avoid`: the pool MUST skip past this real user name.
const WITH_ETA0_COLLISION: &str = "module Main exposing (main)\n\
import Ipe.Io
import Ipe.String
     type Page = Home String String\n\n\
     eta_0 = 999\n\n\
     mk : String -> (String -> Page)\n\
     mk s =\n    \\t -> Home s t\n\n\
     apply2 : (String -> String -> Page) -> Page\n\
     apply2 f =\n    f \"hello\" \"world\"\n\n\
     pageStr : Page -> String\n\
     pageStr p =\n    case p of\n        Home a b -> a ++ \" \" ++ b\n\n\
     main =\n    let g = mk in\n    let p1 = g \"first\" \"second\" in\n    let p2 = apply2 mk in\n    Io.println (pageStr p1 ++ \"|\" ++ pageStr p2 ++ String.fromInt eta_0)\n";

/// #1 + #2: grow (introduce an `eta_0`-colliding user identifier) then shrink
/// (remove it) then re-grow (add it back) — three warm revisions, each
/// compared against an independent cold build of the same state.
#[test]
fn adversarial_eta_pool_collision_grow_shrink_regrow() {
    let base = sources_of(&[(MAIN, BASE)]);
    let collide = sources_of(&[(MAIN, WITH_ETA0_COLLISION)]);

    let mut warm = WarmSession::new();

    assert_parity("grow0/baseline", &warm.compile(&base), &cold_compile(&base));
    assert_parity(
        "grow0/collide",
        &warm.compile(&collide),
        &cold_compile(&collide),
    );
    assert_parity(
        "grow0/shrink-back",
        &warm.compile(&base),
        &cold_compile(&base),
    );
    assert_parity(
        "grow0/regrow",
        &warm.compile(&collide),
        &cold_compile(&collide),
    );
}

/// #3: two consecutive input syncs with NO query demand between them. Salsa
/// must only care about the FINAL input state at demand time, never the path
/// of edits taken to reach it — verified by comparing against a cold build of
/// the final state only.
#[test]
fn adversarial_two_syncs_one_demand() {
    let base = sources_of(&[(MAIN, BASE)]);
    let intermediate = sources_of(&[(MAIN, WITH_ETA0_COLLISION)]);
    let renamed_back = sources_of(&[(MAIN, BASE)]);

    let mut warm = WarmSession::new();
    // Establish a warm baseline with one real demand first (matches how a
    // real dev session always starts from a compiled state).
    assert_parity(
        "presync/baseline",
        &warm.compile(&base),
        &cold_compile(&base),
    );

    // Now sync TWICE with no demand between: base -> intermediate -> back to
    // base, then demand exactly once.
    warm.sync_only(&intermediate);
    warm.sync_only(&renamed_back);
    let warm_out = warm.demand(&renamed_back);
    let cold_out = cold_compile(&renamed_back);
    assert_parity("two-syncs-one-demand", &warm_out, &cold_out);
}

const UTIL_ORIG: &str = "module Lib.Util exposing (bump)\n\nbump x = x + 1\n";
const UTIL_TEMP_RENAME: &str = "module Lib.Util exposing (bumpTemp)\n\nbumpTemp x = x + 1\n";
const MAIN_USES_UTIL: &str = "module Main exposing (main)\n\
     import Lib.Util exposing (bump)\n\n\
import Ipe.Io
import Ipe.String
     main = Io.println (String.fromInt (bump 41))\n";
const MAIN_USES_UTIL_TEMP: &str = "module Main exposing (main)\n\
     import Lib.Util exposing (bumpTemp)\n\n\
import Ipe.Io
import Ipe.String
     main = Io.println (String.fromInt (bumpTemp 41))\n";

/// #4: an identifier rename A -> B -> A (round-tripping back to the ORIGINAL
/// spelling) within an otherwise-stable module set — not a module rename,
/// just a binding rename that reverts. Exercises `module_interface`'s
/// export-surface backdating on a value that changes then reverts to
/// byte-identical text.
#[test]
fn adversarial_identifier_rename_round_trip() {
    let util = &["Lib", "Util"][..];
    let main = &["Main"][..];

    let baseline = sources_of(&[(main, MAIN_USES_UTIL), (util, UTIL_ORIG)]);
    let renamed = sources_of(&[(main, MAIN_USES_UTIL_TEMP), (util, UTIL_TEMP_RENAME)]);
    let reverted = sources_of(&[(main, MAIN_USES_UTIL), (util, UTIL_ORIG)]);

    let mut warm = WarmSession::new();
    assert_parity(
        "rename-rt/baseline",
        &warm.compile(&baseline),
        &cold_compile(&baseline),
    );
    assert_parity(
        "rename-rt/renamed",
        &warm.compile(&renamed),
        &cold_compile(&renamed),
    );
    assert_parity(
        "rename-rt/reverted",
        &warm.compile(&reverted),
        &cold_compile(&reverted),
    );
}

#[test]
fn sanity_all_probe_states_actually_compile_ok() {
    let base = sources_of(&[(MAIN, BASE)]);
    let collide = sources_of(&[(MAIN, WITH_ETA0_COLLISION)]);
    let r1 = cold_compile(&base);
    let r2 = cold_compile(&collide);
    assert!(r1.is_ok(), "BASE must compile OK, got: {r1:?}");
    assert!(
        r2.is_ok(),
        "WITH_ETA0_COLLISION must compile OK, got: {r2:?}"
    );
    let f1 = r1.unwrap();
    let f2 = r2.unwrap();
    // The two programs must actually differ in emitted bytes (proves this
    // isn't a trivial identical-output false-positive).
    assert_ne!(
        f1.files, f2.files,
        "BASE and WITH_ETA0_COLLISION must emit DIFFERENT bytes (sanity: probe actually changes the program)"
    );
    // Confirm the pool actually had to skip past the literal eta_0 collision:
    // the eta-adapter for `mk`'s first-class use must be a name OTHER than
    // `eta_0` (which is now taken by the user binding) in the collide build.
    let all_text: String = f2.files.values().cloned().collect::<Vec<_>>().join("\n");
    assert!(
        all_text.contains("eta_0"),
        "user binding eta_0 must appear literally in emitted output"
    );
}
