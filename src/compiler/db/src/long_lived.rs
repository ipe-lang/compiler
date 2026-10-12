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

/// Whether a sync kept the database generation or replaced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    /// The previous generation's handles stay valid.
    Kept,
    /// Every handle from the previous generation is dead.
    Reset,
}

/// The outcome of [`LongLivedDb::sync`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Synced {
    /// The current generation's root over the desired inputs.
    pub root: SourceRoot,
    /// Whether this sync replaced the generation.
    pub generation: Generation,
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
    /// The created-input count at which a cold generation already stood past
    /// the absolute arms; those arms stay quiet until inputs grow beyond it.
    absolute_quiet_until: Option<u64>,
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
            absolute_quiet_until: None,
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

    /// The current generation's build config, built by `make` when absent.
    pub fn config_or_insert_with(
        &mut self,
        make: impl FnOnce(&IpeDatabase) -> BuildConfig,
    ) -> BuildConfig {
        if let Some(config) = self.config {
            return config;
        }
        let config = make(&self.db);
        self.config = Some(config);
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
    fn past_ceiling(&mut self) -> bool {
        let live = self.root.map_or(0, |root| {
            u64::try_from(root.files(&self.db).len()).unwrap_or(u64::MAX)
        });
        let input_limit = self
            .ceiling
            .inputs
            .max(live.saturating_mul(LIVE_INPUT_FACTOR));
        if self.inputs_created > input_limit {
            return true;
        }
        let absolute = {
            let interner = self.db.interner().lock();
            let symbols = u64::try_from(interner.len()).unwrap_or(u64::MAX);
            symbols > u64::from(self.ceiling.symbols)
                || interner.held_bytes() > self.ceiling.symbol_bytes
        };
        if std::mem::take(&mut self.cold) {
            // A cold generation's own size is the walker's to bound: past the
            // absolute arms already, a fresh reset would only rebuild it.
            self.absolute_quiet_until = absolute.then_some(self.inputs_created);
        }
        absolute
            && self
                .absolute_quiet_until
                .is_none_or(|quiet| self.inputs_created > quiet)
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
        let mut interner = owner.db().interner().lock();
        for n in 0..count {
            let fresh = interner.intern(&format!("churn_{round}_{n}"));
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
        let desired: Desired = BTreeMap::from([
            (
                vec!["Lib".to_owned()],
                (module("Lib", "answer = 42"), ModuleOrigin::User),
            ),
            (
                vec!["Main".to_owned()],
                (
                    "module Main exposing (main)\n\nimport Lib exposing (answer)\n\nmain = answer\n".to_owned(),
                    ModuleOrigin::User,
                ),
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
                    .map(|program| ipe_ir::pretty(&program, &interner))
                    .map_err(|err| format!("{err:?}"))
                    .map(|text| (linked, text))
            })
        };

        let mut fresh = LongLivedDb::with_ceiling(SMALL);
        let fresh_root = fresh.sync(&desired).root;
        let expected = render(&fresh, fresh_root);
        assert!(matches!(expected, Some(Ok((true, _)))), "{expected:?}");

        // A warm generation that answered queries and then churned symbols.
        let mut warm = LongLivedDb::with_ceiling(SMALL);
        for round in 0..4 {
            let synced = warm.sync(&desired);
            assert_eq!(render(&warm, synced.root), expected, "round {round}");
            intern_fresh(&warm, round, usize::try_from(SMALL.symbols).unwrap_or(0));
        }
        let synced = warm.sync(&desired);
        assert_eq!(synced.generation, Generation::Reset);
        assert!(warm.resets() >= 2);
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
    fn long_lived_reset_drops_the_config() {
        let mut owner = LongLivedDb::with_ceiling(SMALL);
        owner.sync(&one("Main", "main = 1"));
        assert!(owner.config().is_none());
        let installed = owner.config_or_insert_with(|db| {
            BuildConfig::new(
                db,
                ipe_backend_rust::DbDriver::Sqlite,
                None,
                ipe_ir::Target::Native,
                Vec::new(),
                ipe_backend_rust::MountBase::root(),
                false,
                ipe_backend_rust::BuildIntent::Development,
                None,
                false,
                String::new(),
                false,
                false,
            )
        });
        assert_eq!(owner.config(), Some(installed));
        let mut generations = (0..=SMALL.inputs.saturating_mul(2))
            .map(|round| owner.sync(&one(&format!("M{round}"), "x = 1")).generation);
        assert!(generations.any(|generation| generation == Generation::Reset));
        drop(generations);
        assert!(owner.config().is_none(), "a reset drops the config handle");
    }
}
