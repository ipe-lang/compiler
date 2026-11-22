//! The one index every `ipe doc` member lookup answers from.
//!
//! Each exposed member of every documented standard-library module is one
//! [`Row`], documented or not, and each row is filed under every key that
//! names it ([`member_keys`]). A key holds a [`RowSet`], which is non-empty by
//! construction; a key two rows share is an explicit ambiguity, never a silent
//! pick of one.
//!
//! The rows carry names only. The checked signature is computed for the hit
//! alone, by type-checking its one module, so building the index never
//! type-checks the whole standard library.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ipe_intern::Interner;
use ipe_stdlib::{Role, STDLIB, StdlibModule};
use ipe_syntax::{Exposed, Exposing};

/// A parsed lookup key: one or more non-empty dotted segments, no whitespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key(String);

impl Key {
    /// `text` as a key, or `None` when it is not dotted segments.
    pub fn parse(text: &str) -> Option<Self> {
        let well_formed = !text.is_empty()
            && text
                .split('.')
                .all(|segment| !segment.is_empty() && !segment.chars().any(char::is_whitespace));
        well_formed.then(|| Self(text.to_owned()))
    }
}

/// The position of a row in [`DocIndex::rows`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RowId(usize);

/// The rows one key names: at least one, by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RowSet {
    first: RowId,
    rest: Vec<RowId>,
}

impl RowSet {
    /// Add `id`, unless the set already holds it.
    fn add(&mut self, id: RowId) {
        if self.first != id && !self.rest.contains(&id) {
            self.rest.push(id);
        }
    }

    fn ids(&self) -> impl Iterator<Item = RowId> + '_ {
        std::iter::once(self.first).chain(self.rest.iter().copied())
    }
}

/// One exposed member of a standard-library module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The owning module's registry row.
    pub module: &'static StdlibModule,
    /// The member's name as exposed.
    pub name: String,
}

impl PartialOrd for Row {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Row {
    /// Qualified-key order; a module's dotted name is unique in [`STDLIB`].
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.module.dotted, &self.name).cmp(&(other.module.dotted, &other.name))
    }
}

impl Row {
    /// The fully qualified key, `Ipe.File.readFile`.
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.module.dotted, self.name)
    }
}

/// What a key names.
#[derive(Debug, PartialEq, Eq)]
pub enum Resolved<'a> {
    /// Exactly one row.
    One(&'a Row),
    /// More than one row, in qualified-key order.
    Ambiguous(Vec<&'a Row>),
}

/// Why the index could not be built.
#[derive(Debug)]
pub enum DocIndexError {
    /// A registered module's embedded source did not parse.
    Parse {
        /// The module's dotted name.
        module: &'static str,
        /// The parser's diagnostic.
        diagnostic: Box<ipe_diagnostics::Diagnostic>,
    },
}

impl fmt::Display for DocIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { module, diagnostic } => {
                write!(f, "parse error in {module}: {diagnostic:?}")
            }
        }
    }
}

/// Every exposed standard-library member, filed under every key that names it.
#[derive(Debug, Default)]
pub struct DocIndex {
    rows: Vec<Row>,
    by_key: BTreeMap<Key, RowSet>,
}

/// Every key naming member `name` of module `dotted`: the qualified key, the
/// key under each proper suffix of the module path, and the bare name.
///
/// The suffixes are the spellings `import … as` binds by default: `Ipe.Ui.Input`
/// is reachable as `Ui.Input` and `Input`, so `Input.labelHidden` names its
/// member. The resolver's own alias table is import-driven and private to the
/// canonicaliser, so the rule is stated here over the dotted path.
pub fn member_keys(dotted: &str, name: &str) -> Vec<String> {
    let segments: Vec<&str> = dotted.split('.').collect();
    let mut keys: Vec<String> = (0..segments.len())
        .filter_map(|from| segments.get(from..))
        .map(|suffix| format!("{}.{name}", suffix.join(".")))
        .collect();
    keys.push(name.to_owned());
    keys
}

impl DocIndex {
    /// The index over `members`, each `(module, name)` one row.
    pub fn from_members(
        members: impl IntoIterator<Item = (&'static StdlibModule, String)>,
    ) -> Self {
        let unique: BTreeSet<Row> = members
            .into_iter()
            .map(|(module, name)| Row { module, name })
            .collect();
        let mut index = Self::default();
        for row in unique {
            let id = RowId(index.rows.len());
            for key in member_keys(row.module.dotted, &row.name) {
                let Some(key) = Key::parse(&key) else {
                    continue;
                };
                match index.by_key.get_mut(&key) {
                    Some(set) => set.add(id),
                    None => {
                        index.by_key.insert(
                            key,
                            RowSet {
                                first: id,
                                rest: Vec::new(),
                            },
                        );
                    }
                }
            }
            index.rows.push(row);
        }
        index
    }

    /// The index over every documented [`STDLIB`] row.
    ///
    /// A kernel module's members are `kernel_members(dotted)`, the names its
    /// kernel documentation lists; a module with a source exposes what its
    /// `exposing` clause names.
    ///
    /// # Errors
    /// [`DocIndexError::Parse`] when a registered source does not parse.
    pub fn build(kernel_members: impl Fn(&str) -> Vec<String>) -> Result<Self, DocIndexError> {
        let mut members = Vec::new();
        for module in STDLIB {
            match module.role {
                Role::Retired => {}
                Role::Kernel { veneer } => {
                    members.extend(
                        kernel_members(module.dotted)
                            .into_iter()
                            .map(|n| (module, n)),
                    );
                    // A kernel module's types (`Crypto.Key`, `Http.HttpMethod`)
                    // are declared by its veneer, not its kernel table.
                    if let Some(source) = veneer {
                        members.extend(
                            exposed_names(module.dotted, source, Exposure::TypesOnly)?
                                .into_iter()
                                .map(|n| (module, n)),
                        );
                    }
                }
                Role::Compiled { source, .. }
                | Role::CompiledVeneer { source, .. }
                | Role::DocOnly { source } => {
                    members.extend(
                        exposed_names(module.dotted, source, Exposure::Every)?
                            .into_iter()
                            .map(|n| (module, n)),
                    );
                }
            }
        }
        Ok(Self::from_members(members))
    }

    /// Every row, in qualified-key order.
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// What `text` names, or `None` when it names no row.
    pub fn resolve(&self, text: &str) -> Option<Resolved<'_>> {
        let set = self.by_key.get(&Key::parse(text)?)?;
        let mut rows: Vec<&Row> = set
            .ids()
            .filter_map(|RowId(at)| self.rows.get(at))
            .collect();
        rows.sort();
        match rows.as_slice() {
            [] => None,
            [one] => Some(Resolved::One(one)),
            _ => Some(Resolved::Ambiguous(rows)),
        }
    }
}

/// Which exposed names [`exposed_names`] keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    /// Values, unions and aliases.
    Every,
    /// Unions and aliases only.
    TypesOnly,
}

/// The names `source`'s `exposing` clause names, kept per `exposure`; for `exposing (..)`, every
/// top-level value, union and alias.
///
/// # Errors
/// [`DocIndexError::Parse`] when `source` does not parse.
pub fn exposed_names(
    module: &'static str,
    source: &str,
    exposure: Exposure,
) -> Result<Vec<String>, DocIndexError> {
    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(source, &mut interner).map_err(|diagnostic| {
        DocIndexError::Parse {
            module,
            diagnostic: Box::new(diagnostic),
        }
    })?;
    let symbols: Vec<ipe_intern::Symbol> = match &parsed.exposing.value {
        Exposing::List(items) => items
            .iter()
            .filter_map(|item| match &item.value {
                Exposed::Value(symbol) => (exposure == Exposure::Every).then_some(*symbol),
                Exposed::Type(symbol, _) => Some(*symbol),
            })
            .collect(),
        Exposing::All => parsed
            .values
            .iter()
            .filter(|_| exposure == Exposure::Every)
            .map(|v| v.value.name.value)
            .chain(parsed.unions.iter().map(|u| u.value.name.value))
            .chain(parsed.aliases.iter().map(|a| a.value.name.value))
            .collect(),
    };
    Ok(symbols
        .into_iter()
        .filter_map(|symbol| interner.resolve(symbol).map(str::to_owned))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(dotted: &str) -> &'static StdlibModule {
        STDLIB
            .iter()
            .find(|m| m.dotted == dotted)
            .expect("a registered module")
    }

    fn fixture() -> DocIndex {
        DocIndex::from_members([
            (module("Ipe.File"), "readFile".to_owned()),
            (module("Ipe.Parser"), "int".to_owned()),
            (module("Ipe.Url.Parser"), "int".to_owned()),
            (module("Ipe.Ui.Input"), "labelHidden".to_owned()),
        ])
    }

    #[test]
    fn a_member_is_filed_under_its_qualified_key_each_suffix_and_its_bare_name() {
        assert_eq!(
            member_keys("Ipe.Ui.Input", "labelHidden"),
            [
                "Ipe.Ui.Input.labelHidden",
                "Ui.Input.labelHidden",
                "Input.labelHidden",
                "labelHidden"
            ]
        );
        let index = fixture();
        for key in ["readFile", "File.readFile", "Ipe.File.readFile"] {
            assert!(
                matches!(index.resolve(key), Some(Resolved::One(row)) if row.qualified() == "Ipe.File.readFile"),
                "{key}"
            );
        }
        assert!(matches!(
            index.resolve("Input.labelHidden"),
            Some(Resolved::One(row)) if row.qualified() == "Ipe.Ui.Input.labelHidden"
        ));
    }

    #[test]
    #[allow(clippy::panic)] // a wrong variant in a unit test IS the failure
    fn a_shared_suffix_lists_every_owner_and_picks_none() {
        let index = fixture();
        let Some(Resolved::Ambiguous(rows)) = index.resolve("Parser.int") else {
            panic!("`Parser.int` names two members");
        };
        let owners: Vec<String> = rows.iter().map(|r| r.qualified()).collect();
        assert_eq!(owners, ["Ipe.Parser.int", "Ipe.Url.Parser.int"]);
        assert!(matches!(
            index.resolve("Url.Parser.int"),
            Some(Resolved::One(row)) if row.qualified() == "Ipe.Url.Parser.int"
        ));
    }

    #[test]
    fn a_malformed_or_unknown_key_names_nothing() {
        let index = fixture();
        for key in [
            "",
            " ",
            "File.",
            ".readFile",
            "File..readFile",
            "read File",
            "zzqqxx",
        ] {
            assert_eq!(index.resolve(key), None, "{key:?}");
        }
    }

    #[test]
    fn a_member_listed_twice_is_one_row() {
        let index = DocIndex::from_members([
            (module("Ipe.File"), "readFile".to_owned()),
            (module("Ipe.File"), "readFile".to_owned()),
        ]);
        assert_eq!(index.rows().len(), 1);
        assert!(matches!(index.resolve("readFile"), Some(Resolved::One(_))));
    }
}
