//! The registry of operator environment variables the runtime reads.
//!
//! Each variable is declared once, as a typed key in its subsystem's file. The
//! key's constructor fixes the variable's [`Grammar`], so the parser a consumer
//! reads through and the form the docs and refusals state cannot disagree.
//! [`startup_check`] judges every compiled-in entry before the program's first
//! line and returns every refusal at once.

pub mod data;
pub mod io;
pub mod listen;
pub mod log;
pub mod security;
pub mod telemetry;
pub mod web;

use crate::env_grammar::{Class, EnvFlag, EnvRefusal, Grammar, ListenPort, judge};

/// Which runtime feature reads a variable; an entry whose feature is not
/// compiled in is not judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    /// Read in every build.
    Always,
    /// Read by the `log` module.
    Log,
    /// Read by the `Server.listen` HTTP listener.
    Server,
    /// Read by the served `Ipe.Web` listener.
    Web,
}

impl Feature {
    /// Whether this build compiles the reader in.
    #[must_use]
    pub const fn is_compiled(self) -> bool {
        match self {
            Self::Always => true,
            Self::Log => cfg!(feature = "log"),
            Self::Server => cfg!(feature = "server"),
            Self::Web => cfg!(all(feature = "web-core", feature = "server")),
        }
    }
}

/// When a variable's value takes effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifetime {
    /// Fixed once at startup; a later `System.setenv` does not move it.
    Startup,
    /// Read again where it is used, so a value a program sets before that use applies.
    AtUse,
}

/// The runtime subsystem that reads a variable, as the reference groups it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subsystem {
    /// The developer console and its proxy.
    Console,
    /// CSV serialisation.
    Csv,
    /// Database connection pools.
    Db,
    /// Email sending.
    Email,
    /// File I/O limits.
    File,
    /// The HTTP client and the `Server.listen` listener.
    Http,
    /// Logging, tracing and telemetry export.
    Observability,
    /// Regex matching.
    Regex,
    /// Compression.
    Compression,
    /// Config-file loading.
    Config,
    /// The runtime itself.
    Runtime,
    /// The `Ipe.Web` server.
    Web,
    /// WebSocket client and server.
    Ws,
    /// UI layout render.
    Ui,
}

/// The value applied while a variable is unset, as the reference states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefaultValue {
    /// A phrase, e.g. "unset (info)".
    Text(&'static str),
    /// A number.
    Count(u64),
    /// A TCP port.
    Port(u16),
    /// A boolean switch's position.
    Flag(EnvFlag),
}

impl std::fmt::Display for DefaultValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(text) => f.write_str(text),
            Self::Count(n) => write!(f, "{n}"),
            Self::Port(port) => write!(f, "{port}"),
            Self::Flag(EnvFlag::On) => f.write_str("on"),
            Self::Flag(EnvFlag::Off) => f.write_str("off"),
        }
    }
}

/// What the reference says about a variable, besides its name and form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Doc {
    /// How the value may be shown.
    pub class: Class,
    /// Which feature reads it.
    pub feature: Feature,
    /// When it takes effect.
    pub lifetime: Lifetime,
    /// Where the reference groups it.
    pub subsystem: Subsystem,
    /// One paragraph on what it controls.
    pub purpose: &'static str,
}

/// One registered variable: its name, its one accepted form, and its docs.
///
/// Built only by a typed key's constructor, which fixes the grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvEntry {
    name: &'static str,
    grammar: Grammar,
    default: DefaultValue,
    doc: Doc,
}

impl EnvEntry {
    /// The variable's name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The one form it accepts.
    #[must_use]
    pub const fn grammar(&self) -> Grammar {
        self.grammar
    }

    /// The value applied while it is unset.
    #[must_use]
    pub const fn default(&self) -> DefaultValue {
        self.default
    }

    /// How its value may be shown.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.doc.class
    }

    /// Which feature reads it.
    #[must_use]
    pub const fn feature(&self) -> Feature {
        self.doc.feature
    }

    /// When it takes effect.
    #[must_use]
    pub const fn lifetime(&self) -> Lifetime {
        self.doc.lifetime
    }

    /// Where the reference groups it.
    #[must_use]
    pub const fn subsystem(&self) -> Subsystem {
        self.doc.subsystem
    }

    /// What it controls.
    #[must_use]
    pub const fn purpose(&self) -> &'static str {
        self.doc.purpose
    }

    /// Whether the default's kind is the grammar's.
    ///
    /// A flag defaults to a switch position, and only a flag does.
    #[must_use]
    pub const fn default_fits_grammar(&self) -> bool {
        matches!(self.grammar, Grammar::Flag) == matches!(self.default, DefaultValue::Flag(_))
    }

    /// Judges the live value (overlay first) against this entry's grammar.
    ///
    /// # Errors
    ///
    /// The refusal naming the variable when its value is present but refused.
    pub fn check(&self) -> Result<(), EnvRefusal> {
        self.grammar.check(
            self.name,
            self.doc.class,
            crate::system::read_env_var(self.name),
        )
    }
}

/// A variable holding a TCP port a listener binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortKey(EnvEntry);

impl PortKey {
    /// A port variable named `name`.
    #[must_use]
    pub const fn new(name: &'static str, default: DefaultValue, doc: Doc) -> Self {
        Self(EnvEntry {
            name,
            grammar: Grammar::Port,
            default,
            doc,
        })
    }

    /// The registry entry.
    #[must_use]
    pub const fn entry(self) -> EnvEntry {
        self.0
    }

    /// The variable's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.0.name
    }

    /// Parses a raw lookup of this variable.
    ///
    /// # Errors
    ///
    /// The refusal naming the variable when the value is set but not a port.
    pub fn parse(
        self,
        raw: Result<String, std::env::VarError>,
    ) -> Result<Option<ListenPort>, EnvRefusal> {
        judge(
            self.0.name,
            Grammar::Port,
            self.0.doc.class,
            raw,
            ListenPort::parse,
        )
    }

    /// Reads and parses the live value (overlay first); `Ok(None)` when unset.
    ///
    /// # Errors
    ///
    /// The refusal naming the variable when the value is set but not a port.
    pub fn read(self) -> Result<Option<ListenPort>, EnvRefusal> {
        self.parse(crate::system::read_env_var(self.0.name))
    }
}

/// A variable naming one member of a closed, lowercase set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChoiceKey {
    entry: EnvEntry,
    names: &'static [&'static str],
}

impl ChoiceKey {
    /// A choice variable named `name` over `names`.
    #[must_use]
    pub const fn new(
        name: &'static str,
        names: &'static [&'static str],
        default: DefaultValue,
        doc: Doc,
    ) -> Self {
        Self {
            entry: EnvEntry {
                name,
                grammar: Grammar::Choice(names),
                default,
                doc,
            },
            names,
        }
    }

    /// The registry entry.
    #[must_use]
    pub const fn entry(self) -> EnvEntry {
        self.entry
    }

    /// The variable's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.entry.name
    }

    /// The accepted names.
    #[must_use]
    pub const fn names(self) -> &'static [&'static str] {
        self.names
    }

    /// Parses a raw lookup of this variable into the accepted name it spells.
    ///
    /// # Errors
    ///
    /// The refusal naming the variable when the value is set but names no member.
    pub fn parse(
        self,
        raw: Result<String, std::env::VarError>,
    ) -> Result<Option<&'static str>, EnvRefusal> {
        let names = self.names;
        judge(
            self.entry.name,
            self.entry.grammar,
            self.entry.doc.class,
            raw,
            |value| crate::env_grammar::choose(names, value),
        )
    }

    /// Reads and parses the live value (overlay first); `Ok(None)` when unset.
    ///
    /// # Errors
    ///
    /// The refusal naming the variable when the value is set but names no member.
    pub fn read(self) -> Result<Option<&'static str>, EnvRefusal> {
        self.parse(crate::system::read_env_var(self.entry.name))
    }
}

/// A boolean switch variable, parsed by [`EnvFlag::parse`] with a declared default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlagKey {
    entry: EnvEntry,
    default: EnvFlag,
}

impl FlagKey {
    /// A switch variable named `name`, at `default` while unset.
    #[must_use]
    pub const fn new(name: &'static str, default: EnvFlag, doc: Doc) -> Self {
        Self {
            entry: EnvEntry {
                name,
                grammar: Grammar::Flag,
                default: DefaultValue::Flag(default),
                doc,
            },
            default,
        }
    }

    /// The registry entry.
    #[must_use]
    pub const fn entry(self) -> EnvEntry {
        self.entry
    }

    /// The variable's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.entry.name
    }

    /// The position applied while the variable is unset.
    #[must_use]
    pub const fn default_flag(self) -> EnvFlag {
        self.default
    }

    /// Parses a raw lookup of this variable; the default when unset.
    ///
    /// # Errors
    ///
    /// The refusal naming the variable when the value is set but spells no switch.
    pub fn parse(self, raw: Result<String, std::env::VarError>) -> Result<EnvFlag, EnvRefusal> {
        judge(
            self.entry.name,
            Grammar::Flag,
            self.entry.doc.class,
            raw,
            EnvFlag::parse,
        )
        .map(|flag| flag.unwrap_or(self.default))
    }

    /// Reads and parses the live value (overlay first); the default when unset.
    ///
    /// # Errors
    ///
    /// The refusal naming the variable when the value is set but spells no switch.
    pub fn read(self) -> Result<EnvFlag, EnvRefusal> {
        self.parse(crate::system::read_env_var(self.entry.name))
    }
}

/// A variable holding a decimal ceiling; its name and default are the ceiling's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CeilingKey {
    entry: EnvEntry,
    ceiling: crate::system::EnvCeiling,
}

impl CeilingKey {
    /// The variable `ceiling` reads.
    #[must_use]
    pub const fn new(ceiling: crate::system::EnvCeiling, doc: Doc) -> Self {
        Self {
            entry: EnvEntry {
                name: ceiling.name(),
                grammar: Grammar::Ceiling(ceiling),
                default: DefaultValue::Count(ceiling.default_value()),
                doc,
            },
            ceiling,
        }
    }

    /// The registry entry.
    #[must_use]
    pub const fn entry(self) -> EnvEntry {
        self.entry
    }

    /// The ceiling that parses this variable.
    #[must_use]
    pub const fn ceiling(self) -> crate::system::EnvCeiling {
        self.ceiling
    }
}

/// A name no longer read: setting it is refused, naming its replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredKey(EnvEntry);

impl RetiredKey {
    /// The retired variable `name`, replaced by `use_instead` when given.
    #[must_use]
    pub const fn new(name: &'static str, use_instead: Option<&'static str>, doc: Doc) -> Self {
        Self(EnvEntry {
            name,
            grammar: Grammar::Retired { use_instead },
            default: DefaultValue::Text("unset"),
            doc,
        })
    }

    /// The registry entry.
    #[must_use]
    pub const fn entry(self) -> EnvEntry {
        self.0
    }
}

/// Every subsystem's entries, in reference order.
const SUBSYSTEMS: [&[EnvEntry]; 7] = [
    listen::ENTRIES,
    web::ENTRIES,
    security::ENTRIES,
    log::ENTRIES,
    telemetry::ENTRIES,
    data::ENTRIES,
    io::ENTRIES,
];

/// Whether every entry of every subsystem has a default of its grammar's kind.
const fn defaults_fit_grammars(mut subsystems: &[&[EnvEntry]]) -> bool {
    while let [entries, rest @ ..] = subsystems {
        let mut entries: &[EnvEntry] = entries;
        while let [entry, more @ ..] = entries {
            if !entry.default_fits_grammar() {
                return false;
            }
            entries = more;
        }
        subsystems = rest;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a registered entry's default is not of its grammar's kind, so a switch always documents a switch position [ledger #boundary]
const _: () = assert!(defaults_fit_grammars(&SUBSYSTEMS));

/// Every registered variable, for the reference generator.
#[doc(hidden)]
pub fn registry() -> impl Iterator<Item = &'static EnvEntry> {
    SUBSYSTEMS.into_iter().flatten()
}

/// Judges every entry whose feature is compiled in, in order, collecting every
/// refusal rather than stopping at the first.
pub fn check_entries<'a>(entries: impl IntoIterator<Item = &'a EnvEntry>) -> Vec<EnvRefusal> {
    entries
        .into_iter()
        .filter(|entry| entry.feature().is_compiled())
        .filter_map(|entry| entry.check().err())
        .collect()
}

/// Judges every compiled-in registered variable before the program's first
/// line, then fixes the values read once per process.
///
/// # Errors
///
/// Every refusal, in registry order, so an operator fixes a deployment in one
/// round trip.
pub fn startup_check() -> Result<(), Vec<EnvRefusal>> {
    let mut refusals = check_entries(registry());
    if refusals.is_empty() {
        if let Err(refusal) = crate::core::recursion_startup_check() {
            refusals.push(EnvRefusal::Ceiling(refusal));
        }
        #[cfg(feature = "log")]
        if let Err(refusal) = crate::log::startup_check() {
            refusals.push(refusal);
        }
        #[cfg(all(feature = "web-core", feature = "server"))]
        crate::web::csrf::fix_origin_check();
    }
    if refusals.is_empty() {
        Ok(())
    } else {
        Err(refusals)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    const DOC: Doc = Doc {
        class: Class::Tunable,
        feature: Feature::Always,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Runtime,
        purpose: "a registry test probe",
    };

    #[test]
    fn names_are_unique_and_prefixed() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in registry() {
            assert!(entry.name().starts_with("IPE_"), "{}", entry.name());
            assert!(
                entry
                    .name()
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "{}",
                entry.name()
            );
            assert!(
                seen.insert(entry.name()),
                "{} is registered twice",
                entry.name()
            );
            assert!(!entry.purpose().is_empty(), "{}", entry.name());
        }
        assert!(!seen.is_empty());
    }

    /// A ceiling entry reads the variable its ceiling parses.
    #[test]
    fn ceiling_entries_name_their_ceilings_variable() {
        for entry in registry() {
            if let Grammar::Ceiling(ceiling) = entry.grammar() {
                assert_eq!(ceiling.name(), entry.name());
                assert_eq!(
                    entry.default(),
                    DefaultValue::Count(ceiling.default_value())
                );
            }
        }
    }

    /// A choice's names are lowercase, so the case-folded match is exact.
    #[test]
    fn choice_names_are_lowercase_and_distinct() {
        for entry in registry() {
            if let Grammar::Choice(names) = entry.grammar() {
                assert!(!names.is_empty(), "{}", entry.name());
                for name in names {
                    assert!(
                        !name.is_empty() && name.bytes().all(|b| !b.is_ascii_uppercase()),
                        "{}: {name}",
                        entry.name()
                    );
                }
                let distinct: std::collections::BTreeSet<_> = names.iter().collect();
                assert_eq!(distinct.len(), names.len(), "{}", entry.name());
            }
        }
    }

    /// Three malformed variables yield three refusals, in entry order.
    #[test]
    fn check_collects_every_refusal_in_order() {
        const A: PortKey = PortKey::new("IPE_REGISTRY_TEST_PORT_A", DefaultValue::Port(1), DOC);
        const B: ChoiceKey = ChoiceKey::new(
            "IPE_REGISTRY_TEST_CHOICE_B",
            &["one", "two"],
            DefaultValue::Text("one"),
            DOC,
        );
        const C: PortKey = PortKey::new("IPE_REGISTRY_TEST_PORT_C", DefaultValue::Port(1), DOC);
        const GOOD: PortKey =
            PortKey::new("IPE_REGISTRY_TEST_PORT_GOOD", DefaultValue::Port(1), DOC);
        const UNSET: PortKey =
            PortKey::new("IPE_REGISTRY_TEST_PORT_UNSET", DefaultValue::Port(1), DOC);
        let set = [(A.name(), "99999"), (B.name(), "three"), (C.name(), "")];
        for (name, value) in set {
            crate::system::locked_set_var(name, value);
        }
        crate::system::locked_set_var(GOOD.name(), "8080");
        crate::system::locked_remove_var(UNSET.name());
        let entries = [A.entry(), GOOD.entry(), B.entry(), UNSET.entry(), C.entry()];
        let refusals = check_entries(&entries);
        for (name, _) in set {
            crate::system::locked_remove_var(name);
        }
        crate::system::locked_remove_var(GOOD.name());
        let names: Vec<_> = refusals.iter().map(EnvRefusal::name).collect();
        assert_eq!(names, [A.name(), B.name(), C.name()], "{refusals:?}");
        let text: Vec<String> = refusals.iter().map(ToString::to_string).collect();
        assert!(text[0].contains("1..=65535"), "{}", text[0]);
        assert!(text[1].contains("one of one, two"), "{}", text[1]);
        assert!(text[2].contains("empty value"), "{}", text[2]);
    }

    /// A retired name refuses only while set, naming its replacement.
    #[test]
    fn retired_entry_refuses_when_set() {
        const OLD: RetiredKey = RetiredKey::new(
            "IPE_REGISTRY_TEST_RETIRED",
            Some("IPE_REGISTRY_TEST_NEW"),
            DOC,
        );
        crate::system::locked_remove_var(OLD.entry().name());
        assert!(check_entries(&[OLD.entry()]).is_empty());
        crate::system::locked_set_var(OLD.entry().name(), "1");
        let refusals = check_entries(&[OLD.entry()]);
        crate::system::locked_remove_var(OLD.entry().name());
        assert_eq!(
            refusals,
            [EnvRefusal::Retired {
                name: "IPE_REGISTRY_TEST_RETIRED",
                use_instead: Some("IPE_REGISTRY_TEST_NEW"),
            }]
        );
    }

    /// An entry whose reader is not compiled in is not judged.
    #[test]
    fn entry_of_an_absent_feature_is_skipped() {
        const SERVED: PortKey = PortKey::new(
            "IPE_REGISTRY_TEST_PORT_SERVED",
            DefaultValue::Port(1),
            Doc {
                feature: Feature::Server,
                ..DOC
            },
        );
        crate::system::locked_set_var(SERVED.name(), "abc");
        let refusals = check_entries(&[SERVED.entry()]);
        crate::system::locked_remove_var(SERVED.name());
        assert_eq!(refusals.len(), usize::from(cfg!(feature = "server")));
    }

    /// The registry is reachable from the crate root only by its module path:
    /// neither crate root re-exports it into an emitted program's namespace,
    /// and the vendored root declares both modules.
    #[test]
    fn crate_roots_declare_but_never_glob_export_the_registry() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let roots = [
            manifest.join("src/mod.rs"),
            manifest.join("../../compiler/backend/rust/templates/ipe_runtime/mod.rs"),
        ];
        for root in roots {
            #[allow(clippy::expect_used)] // a missing crate root is the failure under test
            let text = std::fs::read_to_string(&root).expect("read a runtime crate root");
            for module in ["env_grammar", "env_registry"] {
                assert!(
                    text.lines()
                        .any(|l| l.trim() == format!("pub mod {module};")),
                    "{} must declare `pub mod {module};`",
                    root.display()
                );
                assert!(
                    !text.contains(&format!("pub use {module}")),
                    "{} must not re-export {module}",
                    root.display()
                );
            }
        }
    }
}
