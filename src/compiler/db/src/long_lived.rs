//! The single owner of a database that outlives one build.
//!
//! Interner symbols, interner bytes and created inputs are append-only: no
//! edit ever releases them, and salsa LRU over memo values bounds none of
//! them. A process that keeps one database across builds (`ipe dev watch`,
//! the language server) reaches it only through [`LongLivedDb`], which
//! declares a [`GrowthCeiling`] over all three and, once a sync finds the
//! database past it, drops the whole generation — database, interner, root
//! and config — and rebuilds it cold from the desired inputs. A cold build
//! equals a warm one, so a reset costs latency, never behaviour.

use std::collections::BTreeMap;

use salsa::Database as _;

use crate::{BuildConfig, Db as _, IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

/// The append-only growth one database generation may reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrowthCeiling {
    /// Distinct interned strings.
    pub symbols: u32,
    /// Summed byte length of the distinct interned strings.
    pub symbol_bytes: u64,
    /// Floor of the created-input ceiling; the live ceiling is the larger of
    /// this and four times the live input count.
    pub inputs: u64,
}

/// The ceiling every long-lived database runs under.
pub const LONG_LIVED_CEILING: GrowthCeiling = GrowthCeiling {
    symbols: 1 << 22,
    symbol_bytes: 256 * 1024 * 1024,
    inputs: 16_384,
};

/// Multiplier of the live input count in the created-input ceiling.
const LIVE_INPUT_FACTOR: u64 = 4;

/// Multiplier of a cold generation's own size that bounds its growth when
/// that size alone already stands past the absolute arms.
const COLD_EXCESS_FACTOR: u64 = 2;

/// The size a cold generation measured at its first sync, recorded only when
/// it already stood past the absolute arms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ColdExcess {
    /// Inputs created when the size was measured.
    inputs: u64,
    /// Distinct interned strings when the size was measured.
    symbols: u64,
    /// Interned bytes when the size was measured.
    symbol_bytes: u64,
}

/// Whether a sync kept the database generation or replaced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    /// The previous generation's handles stay valid.
    Kept,
    /// Every handle from the previous generation is dead.
    Reset,
}

/// The outcome of [`LongLivedDb::sync`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Synced {
    /// The current generation's root over the desired inputs.
    pub root: SourceRoot,
    /// Whether this sync replaced the generation.
    pub generation: Generation,
}

/// Every field of a [`BuildConfig`], as the driver resolved it for one sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildConfigFields {
    /// See [`BuildConfig::settings`].
    pub settings: ipe_backend_rust::EmitSettings,
}

/// A database generation plus the handles derived from it.
pub struct LongLivedDb {
    db: IpeDatabase,
    root: Option<SourceRoot>,
    config: Option<BuildConfig>,
    inputs_created: u64,
    resets: u64,
    ceiling: GrowthCeiling,
    /// Set until the first measurement of a generation built cold.
    cold: bool,
    /// A cold generation already past the absolute arms: those arms then
    /// fire only once inputs grow beyond its measurement or the interner
    /// grows past [`COLD_EXCESS_FACTOR`] times it.
    cold_excess: Option<ColdExcess>,
}

impl Default for LongLivedDb {
    fn default() -> Self {
        Self::new()
    }
}

impl LongLivedDb {
    /// An empty generation under [`LONG_LIVED_CEILING`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_ceiling(LONG_LIVED_CEILING)
    }

    /// An empty generation under `ceiling`.
    #[must_use]
    pub fn with_ceiling(ceiling: GrowthCeiling) -> Self {
        Self {
            db: IpeDatabase::new(),
            root: None,
            config: None,
            inputs_created: 0,
            resets: 0,
            ceiling,
            cold: true,
            cold_excess: None,
        }
    }

    /// The current generation's database.
    #[must_use]
    pub const fn db(&self) -> &IpeDatabase {
        &self.db
    }

    /// The current generation's database, mutably, for input setters.
    pub const fn db_mut(&mut self) -> &mut IpeDatabase {
        &mut self.db
    }

    /// The current generation's root, once a sync has built it.
    #[must_use]
    pub const fn root(&self) -> Option<SourceRoot> {
        self.root
    }

    /// The current generation's build config, once one is installed.
    #[must_use]
    pub const fn config(&self) -> Option<BuildConfig> {
        self.config
    }

    /// The current generation's build config, holding exactly `fields`.
    ///
    /// The first call of a generation creates the config; every later call
    /// sets each field that differs, so a warm config never keeps a value a
    /// cold one would not hold.
    pub fn sync_config(&mut self, fields: BuildConfigFields) -> BuildConfig {
        use salsa::Setter as _;
        let BuildConfigFields { settings } = fields;
        let Some(config) = self.config else {
            let config = BuildConfig::new(&self.db, settings);
            self.config = Some(config);
            return config;
        };
        let db = &mut self.db;
        if *config.settings(db) != settings {
            config.set_settings(db).to(settings);
        }
        config
    }

    /// How many generations this owner has dropped.
    #[must_use]
    pub const fn resets(&self) -> u64 {
        self.resets
    }

    /// How many inputs the current generation has created.
    #[must_use]
    pub const fn inputs_created(&self) -> u64 {
        self.inputs_created
    }

    /// Reconcile the inputs against `desired`, first replacing the generation
    /// when it stands past the ceiling.
    ///
    /// Like [`crate::sync_source_root`], this blocks until every clone of the
    /// database a worker holds has dropped.
    pub fn sync<T: AsRef<str>>(
        &mut self,
        desired: &BTreeMap<Vec<String>, (T, ModuleOrigin)>,
    ) -> Synced {
        let generation = if self.past_ceiling() {
            self.reset();
            Generation::Reset
        } else {
            Generation::Kept
        };
        let root = match self.root {
            Some(root) => {
                let created = crate::reconcile_source_root(&mut self.db, root, desired);
                self.inputs_created = self.inputs_created.saturating_add(created);
                root
            }
            None => self.create_root(desired),
        };
        Synced { root, generation }
    }

    /// Whether the generation has grown past the ceiling.
    ///
    /// A cold generation's own size is the layout walker's to bound: when
    /// its first measurement already stands past the absolute arms, a reset
    /// would only rebuild the same size, so those arms then fire on growth
    /// alone — a created input past the measurement, or an interner grown
    /// past [`COLD_EXCESS_FACTOR`] times it. Every arm stays a hard bound.
    fn past_ceiling(&mut self) -> bool {
        let live = self.root.map_or(0, |root| {
            u64::try_from(root.files(&self.db).len()).unwrap_or(u64::MAX)
        });
        let input_limit = self
            .ceiling
            .inputs
            .max(live.saturating_mul(LIVE_INPUT_FACTOR));
        let (symbols, symbol_bytes) = {
            let interner = self.db.interner().lock();
            (
                u64::try_from(interner.len()).unwrap_or(u64::MAX),
                interner.held_bytes(),
            )
        };
        let past = |symbol_limit: u64, byte_limit: u64| {
            symbols > symbol_limit || symbol_bytes > byte_limit
        };
        let symbol_limit = u64::from(self.ceiling.symbols);
        let byte_limit = self.ceiling.symbol_bytes;
        if std::mem::take(&mut self.cold) {
            self.cold_excess = past(symbol_limit, byte_limit).then_some(ColdExcess {
                inputs: self.inputs_created,
                symbols,
                symbol_bytes,
            });
        }
        if self.inputs_created > input_limit {
            return true;
        }
        match self.cold_excess {
            None => past(symbol_limit, byte_limit),
            Some(excess) => {
                let grown_inputs = self.inputs_created > excess.inputs;
                let grown_symbols = past(
                    symbol_limit.max(excess.symbols.saturating_mul(COLD_EXCESS_FACTOR)),
                    byte_limit.max(excess.symbol_bytes.saturating_mul(COLD_EXCESS_FACTOR)),
                );
                grown_symbols || (grown_inputs && past(symbol_limit, byte_limit))
            }
        }
    }

    /// Drop the generation, waiting for every worker clone to release it.
    fn reset(&mut self) {
        self.db.trigger_cancellation();
        let resets = self.resets.saturating_add(1);
        *self = Self::with_ceiling(self.ceiling);
        self.resets = resets;
    }

    /// Build the generation's root cold from `desired`.
    fn create_root<T: AsRef<str>>(
        &mut self,
        desired: &BTreeMap<Vec<String>, (T, ModuleOrigin)>,
    ) -> SourceRoot {
        let files: BTreeMap<Vec<String>, SourceFile> = desired
            .iter()
            .map(|(path, (text, origin))| {
                let file =
                    SourceFile::new(&self.db, path.clone(), text.as_ref().to_owned(), *origin);
                (path.clone(), file)
            })
            .collect();
        let created = u64::try_from(files.len()).unwrap_or(u64::MAX);
        self.inputs_created = self.inputs_created.saturating_add(created);
        let root = SourceRoot::new(&self.db, files);
        self.root = Some(root);
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: GrowthCeiling = GrowthCeiling {
        symbols: 64,
        symbol_bytes: 4096,
        inputs: 16,
    };

    type Desired = BTreeMap<Vec<String>, (String, ModuleOrigin)>;

    fn module(name: &str, body: &str) -> String {
        format!("module {name} exposing (..)\n\n{body}\n")
    }

    fn one(name: &str, body: &str) -> Desired {
        BTreeMap::from([(
            vec![name.to_owned()],
            (module(name, body), ModuleOrigin::User),
        )])
    }

    fn intern_fresh(owner: &LongLivedDb, round: usize, count: usize) {
        for n in 0..count {
            let fresh = owner
                .db()
                .interner()
                .lock()
                .intern(&format!("churn_{round}_{n}"));
            assert!(fresh.is_ok());
        }
    }

    fn symbols(owner: &LongLivedDb) -> usize {
        owner.db().interner().lock().len()
    }

    #[test]
    fn long_lived_churn_stays_bounded() {
        const ROUNDS: usize = 1000;
        const PER_SYNC: usize = 8;
        let mut owner = LongLivedDb::with_ceiling(SMALL);
        let symbol_bound = usize::try_from(SMALL.symbols).unwrap_or(usize::MAX) + PER_SYNC;
        // Fresh identifiers over a stable path: only the symbol arm can fire.
        for round in 0..ROUNDS {
            owner.sync(&one("Main", "main = 1"));
            intern_fresh(&owner, round, PER_SYNC);
            assert!(symbols(&owner) <= symbol_bound, "round {round}");
        }
        let symbol_resets = owner.resets();
        assert!(
            symbol_resets >= 10,
            "the symbol arm reset {symbol_resets} times"
        );
        // Fresh paths: only the created-input arm can fire.
        for round in 0..ROUNDS {
            owner.sync(&one(&format!("M{round}"), "x = 1"));
            assert!(owner.inputs_created() <= SMALL.inputs + 1, "round {round}");
        }
        assert!(
            owner.resets() - symbol_resets >= 10,
            "the input arm reset {} times",
            owner.resets() - symbol_resets
        );
    }

    #[test]
    fn long_lived_reset_is_invisible() {
        const MAIN: &str = "module Main exposing (main)\n\n\
            import Lib exposing (answer, discard)\n\n\
            main = discard answer\n";
        let desired: Desired = BTreeMap::from([
            (
                vec!["Lib".to_owned()],
                (
                    module("Lib", "answer = 42\n\ndiscard n = ()"),
                    ModuleOrigin::User,
                ),
            ),
            (
                vec!["Main".to_owned()],
                (MAIN.to_owned(), ModuleOrigin::User),
            ),
        ]);
        let entry = vec!["Main".to_owned()];
        let render = |owner: &LongLivedDb, root: SourceRoot| {
            let file = root.files(owner.db()).get(&entry).copied();
            file.map(|file| {
                let linked = crate::linked_program(owner.db(), root, file).is_ok();
                let lowered = crate::lower_program(owner.db(), root, file);
                let interner = owner.db().interner().lock();
                lowered
                    .as_ref()
                    .map(|program| ipe_ir::pretty(program, &interner))
                    .map_err(|err| format!("{err:?}"))
                    .map(|text| (linked, text))
            })
        };

        let mut fresh = LongLivedDb::with_ceiling(SMALL);
        let fresh_root = fresh.sync(&desired).root;
        let expected = render(&fresh, fresh_root);
        assert!(matches!(expected, Some(Ok((true, _)))), "{expected:?}");

        // A warm generation that answered queries and then churned symbols
        // past the ceiling.
        let mut warm = LongLivedDb::with_ceiling(SMALL);
        let synced = warm.sync(&desired);
        assert_eq!(render(&warm, synced.root), expected);
        intern_fresh(&warm, 0, usize::try_from(SMALL.symbols).unwrap_or(0) + 1);
        let synced = warm.sync(&desired);
        assert_eq!(synced.generation, Generation::Reset);
        assert_eq!(warm.resets(), 1);
        assert_eq!(render(&warm, synced.root), expected);
        let synced = warm.sync(&desired);
        assert_eq!(synced.generation, Generation::Kept);
        assert_eq!(render(&warm, synced.root), expected);
    }

    #[test]
    fn long_lived_stable_workspace_never_resets() {
        let desired: Desired = (0..50)
            .map(|n| {
                let name = format!("M{n}");
                let text = module(&name, &format!("v{n} = {n}"));
                (vec![name], (text, ModuleOrigin::User))
            })
            .collect();
        let mut owner = LongLivedDb::with_ceiling(SMALL);
        for _ in 0..1000 {
            assert_eq!(owner.sync(&desired).generation, Generation::Kept);
        }
        assert_eq!(owner.resets(), 0);
        assert_eq!(owner.inputs_created(), 50);
    }

    #[test]
    fn long_lived_oversized_cold_generation_resets_once() {
        let mut owner = LongLivedDb::with_ceiling(SMALL);
        let baseline = usize::try_from(SMALL.symbols).unwrap_or(0) * 2;
        for _ in 0..100 {
            owner.sync(&one("Main", "main = 1"));
            // The same identifiers every round: the cold baseline alone
            // stands past the symbol arm.
            intern_fresh(&owner, 0, baseline);
        }
        assert_eq!(
            owner.resets(),
            1,
            "a cold baseline past the ceiling must not thrash"
        );
        // Created-input growth re-arms the absolute arms.
        owner.sync(&one("Other", "x = 1"));
        owner.sync(&one("Other", "x = 1"));
        assert_eq!(owner.resets(), 2);
    }

    #[test]
    fn long_lived_oversized_cold_generation_growth_stays_bounded() {
        const PER_SYNC: usize = 64;
        let mut owner = LongLivedDb::with_ceiling(SMALL);
        let baseline = usize::try_from(SMALL.symbols).unwrap_or(0) * 2;
        owner.sync(&one("Main", "main = 1"));
        intern_fresh(&owner, 0, baseline);
        assert_eq!(
            owner.sync(&one("Main", "main = 1")).generation,
            Generation::Reset
        );
        // The cold generation alone stands past the symbol arm.
        intern_fresh(&owner, 0, baseline);
        assert_eq!(
            owner.sync(&one("Main", "main = 1")).generation,
            Generation::Kept
        );
        let bound = symbols(&owner) * 2 + PER_SYNC;
        // Fresh identifiers over the same inputs: growth alone must reset.
        for round in 1..=100 {
            owner.sync(&one("Main", "main = 1"));
            intern_fresh(&owner, round, PER_SYNC);
            assert!(
                symbols(&owner) <= bound,
                "round {round}: {}",
                symbols(&owner)
            );
        }
        assert!(owner.resets() >= 2, "resets: {}", owner.resets());
    }

    fn fields(crate_name: ipe_backend_rust::CrateName) -> BuildConfigFields {
        BuildConfigFields {
            settings: ipe_backend_rust::EmitSettings {
                db_driver: ipe_backend_rust::DbDriver::Sqlite,
                ffi: None,
                target: ipe_ir::Target::Native,
                wasm_public_env: Vec::new(),
                mount_base: ipe_backend_rust::MountBase::root(),
                server_origins: ipe_backend_rust::ServerOrigins::none(),
                wasm_hydrate_mode: false,
                runtime_dep: None,
                debugger: false,
                crate_name,
                hot_appearance: false,
                host: ipe_backend_rust::EmitHost::Served,
                intent: ipe_backend_rust::BuildIntent::Development,
            },
        }
    }

    fn pinned(name: &str) -> ipe_backend_rust::CrateName {
        ipe_backend_rust::CrateName::Pinned(ipe_backend_rust::CargoPackageName::sanitize(name))
    }

    #[test]
    fn warm_config_holds_every_resolved_field() {
        let mut owner = LongLivedDb::with_ceiling(SMALL);
        owner.sync(&one("Main", "main = 1"));
        let first = owner.sync_config(fields(pinned("first")));
        // Every field differs from the first sync's, so each set is pinned.
        let changed = BuildConfigFields {
            settings: ipe_backend_rust::EmitSettings {
                db_driver: ipe_backend_rust::DbDriver::Postgres,
                ffi: Some(ipe_backend_rust::FfiEmit::default()),
                target: ipe_ir::Target::WasmClient,
                wasm_public_env: vec!["PUBLIC_KEY".to_owned()],
                mount_base: ipe_backend_rust::MountBase::parse("/app")
                    .unwrap_or_else(|_| ipe_backend_rust::MountBase::root()),
                server_origins: ipe_backend_rust::ServerOrigin::parse("https://api.example")
                    .ok()
                    .and_then(|origin| ipe_backend_rust::ServerOrigins::new([origin]).ok())
                    .unwrap_or_else(ipe_backend_rust::ServerOrigins::none),
                wasm_hydrate_mode: true,
                runtime_dep: Some(ipe_backend_rust::RuntimeDep {
                    root: std::path::PathBuf::from("/runtime"),
                }),
                debugger: true,
                crate_name: pinned("second"),
                hot_appearance: true,
                host: ipe_backend_rust::EmitHost::WebView(ipe_backend_rust::WebViewWindow {
                    title: "Second".to_owned(),
                    width: 640,
                    height: 480,
                }),
                intent: ipe_backend_rust::BuildIntent::Release,
            },
        };
        assert_ne!(
            changed.settings.mount_base,
            ipe_backend_rust::MountBase::root()
        );
        assert!(!changed.settings.server_origins.is_empty());
        let second = owner.sync_config(changed.clone());
        assert!(first == second, "a warm sync keeps the one config handle");
        let held = BuildConfigFields {
            settings: second.settings(owner.db()).clone(),
        };
        assert_eq!(held, changed, "a warm config holds what a cold one would");
    }

    #[test]
    fn long_lived_reset_drops_the_config() {
        let mut owner = LongLivedDb::with_ceiling(SMALL);
        owner.sync(&one("Main", "main = 1"));
        assert!(owner.config().is_none());
        let installed = owner.sync_config(fields(ipe_backend_rust::CrateName::SingleFile));
        assert!(owner.config() == Some(installed));
        let mut generations = (0..=SMALL.inputs.saturating_mul(2))
            .map(|round| owner.sync(&one(&format!("M{round}"), "x = 1")).generation);
        assert!(generations.any(|generation| generation == Generation::Reset));
        drop(generations);
        assert!(owner.config().is_none(), "a reset drops the config handle");
    }
}
