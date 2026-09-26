//! `ipe diff <old> <new>` — public-API delta + enforced semver.
//!
//! Compares two package versions by their [`crate::api_surface::PublicApi`],
//! classifies each change as breaking or compatible (Elm's `elm diff` rules,
//! mapped to Ipê's pre-1.0 semver), and derives the required version bump. The
//! gate consumes [`check_semver_bump`] to reject a version that under-bumps.
//!
//! Ipê is pre-1.0, so a major bump is reserved: a **breaking** delta requires a
//! **minor** bump, a **compatible** delta a **patch** bump (matching the
//! release-please config). The classifier is conservative (Security first): a
//! change it cannot prove compatible is breaking — a false-breaking wastes a
//! version number, a false-compatible ships a silent break.

use std::path::{Path, PathBuf};

use semver::Version;

use crate::CliError;
use crate::api_surface::{DiffError, ModuleApi, PublicApi, extract_tree};

/// Whether a public-API delta breaks existing users.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compatibility {
    /// No change, or a purely additive one — existing users keep compiling.
    Compatible,
    /// A removal, rename, or type change — existing users may break.
    Breaking,
}

/// The minimum version-component bump a delta requires (pre-1.0 mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequiredBump {
    /// A patch bump (`0.y.Z`) — a compatible delta (or no change; a re-release
    /// still needs a new version).
    Patch,
    /// A minor bump (`0.Y.0`) — a breaking delta (major is reserved pre-1.0).
    Minor,
}

/// One classified difference between two public APIs.
///
/// A closed sum over the finite change kinds — the classifier's `match` over it
/// is exhaustive, so a new change kind is a compile error, never a silently
/// mis-classified magnitude.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApiChange {
    /// An exported module present in `old` is gone from `new`.
    ModuleRemoved { module: String },
    /// An exported module present in `new` is new.
    ModuleAdded { module: String },
    /// An exported value was removed (a rename surfaces as a removal + an add).
    ValueRemoved { module: String, name: String },
    /// A new exported value.
    ValueAdded { module: String, name: String },
    /// An exported value's type signature changed.
    ValueChanged {
        module: String,
        name: String,
        old: String,
        new: String,
    },
    /// An exported union type was removed.
    UnionRemoved { module: String, name: String },
    /// A new exported union type.
    UnionAdded { module: String, name: String },
    /// An exported union's type-parameter arity changed.
    UnionArityChanged {
        module: String,
        name: String,
        old: usize,
        new: usize,
    },
    /// A constructor was removed from an exported union.
    ConstructorRemoved {
        module: String,
        union: String,
        ctor: String,
    },
    /// A constructor was added to an exported union.
    ConstructorAdded {
        module: String,
        union: String,
        ctor: String,
    },
    /// A constructor's argument types changed.
    ConstructorChanged {
        module: String,
        union: String,
        ctor: String,
    },
}

impl ApiChange {
    /// Classify this change's compatibility (Elm's rules, conservative).
    ///
    /// Additive changes (a new module / value / union) are compatible; every
    /// removal, rename, or type change is breaking. A new constructor to an
    /// exposed union is breaking — importers may write exhaustive `case`
    /// expressions a new variant would break — matching Elm and Ipê's exhaustive
    /// matching.
    #[must_use]
    pub const fn compatibility(&self) -> Compatibility {
        match self {
            Self::ModuleAdded { .. } | Self::ValueAdded { .. } | Self::UnionAdded { .. } => {
                Compatibility::Compatible
            }
            Self::ModuleRemoved { .. }
            | Self::ValueRemoved { .. }
            | Self::ValueChanged { .. }
            | Self::UnionRemoved { .. }
            | Self::UnionArityChanged { .. }
            | Self::ConstructorRemoved { .. }
            | Self::ConstructorAdded { .. }
            | Self::ConstructorChanged { .. } => Compatibility::Breaking,
        }
    }
}

/// The full result of comparing two package versions: the classified changes,
/// the required bump, and whether the proposed new version clears its floor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemverReport {
    /// Every classified change, in a deterministic order.
    pub changes: Vec<ApiChange>,
    /// The overall compatibility (breaking if any change is breaking).
    pub compatibility: Compatibility,
    /// The minimum bump the delta requires.
    pub required: RequiredBump,
    /// The minimum acceptable new version given `old_version` and `required`.
    pub floor: Version,
    /// Whether the proposed new version is at or above the floor.
    pub satisfied: bool,
}

/// Diff `old` against `new`, producing the classified changes in deterministic
/// (module-then-name) order.
#[must_use]
pub fn diff_api(old: &PublicApi, new: &PublicApi) -> Vec<ApiChange> {
    let mut changes = Vec::new();

    for module in old.modules.keys() {
        if !new.modules.contains_key(module) {
            changes.push(ApiChange::ModuleRemoved {
                module: module.join("."),
            });
        }
    }
    for module in new.modules.keys() {
        if !old.modules.contains_key(module) {
            changes.push(ApiChange::ModuleAdded {
                module: module.join("."),
            });
        }
    }

    // Modules present in both: diff their surfaces.
    for (module, old_api) in &old.modules {
        let Some(new_api) = new.modules.get(module) else {
            continue;
        };
        diff_module(&module.join("."), old_api, new_api, &mut changes);
    }

    changes
}

/// Diff one module's values and unions, appending to `changes`.
fn diff_module(module: &str, old: &ModuleApi, new: &ModuleApi, changes: &mut Vec<ApiChange>) {
    for (name, old_sig) in &old.values {
        match new.values.get(name) {
            None => changes.push(ApiChange::ValueRemoved {
                module: module.to_owned(),
                name: name.clone(),
            }),
            Some(new_sig) if new_sig != old_sig => changes.push(ApiChange::ValueChanged {
                module: module.to_owned(),
                name: name.clone(),
                old: old_sig.clone(),
                new: new_sig.clone(),
            }),
            Some(_) => {}
        }
    }
    for name in new.values.keys() {
        if !old.values.contains_key(name) {
            changes.push(ApiChange::ValueAdded {
                module: module.to_owned(),
                name: name.clone(),
            });
        }
    }

    for (name, old_union) in &old.unions {
        match new.unions.get(name) {
            None => changes.push(ApiChange::UnionRemoved {
                module: module.to_owned(),
                name: name.clone(),
            }),
            Some(new_union) => {
                if new_union.params != old_union.params {
                    changes.push(ApiChange::UnionArityChanged {
                        module: module.to_owned(),
                        name: name.clone(),
                        old: old_union.params,
                        new: new_union.params,
                    });
                }
                for (ctor, old_args) in &old_union.ctors {
                    match new_union.ctors.get(ctor) {
                        None => changes.push(ApiChange::ConstructorRemoved {
                            module: module.to_owned(),
                            union: name.clone(),
                            ctor: ctor.clone(),
                        }),
                        Some(new_args) if new_args != old_args => {
                            changes.push(ApiChange::ConstructorChanged {
                                module: module.to_owned(),
                                union: name.clone(),
                                ctor: ctor.clone(),
                            });
                        }
                        Some(_) => {}
                    }
                }
                for ctor in new_union.ctors.keys() {
                    if !old_union.ctors.contains_key(ctor) {
                        changes.push(ApiChange::ConstructorAdded {
                            module: module.to_owned(),
                            union: name.clone(),
                            ctor: ctor.clone(),
                        });
                    }
                }
            }
        }
    }
    for name in new.unions.keys() {
        if !old.unions.contains_key(name) {
            changes.push(ApiChange::UnionAdded {
                module: module.to_owned(),
                name: name.clone(),
            });
        }
    }
}

/// The overall compatibility of a set of changes: breaking if any change is
/// breaking, else compatible (the max-magnitude fold, collapsed to two
/// outcomes). An empty delta is compatible.
#[must_use]
pub fn magnitude(changes: &[ApiChange]) -> Compatibility {
    if changes
        .iter()
        .any(|c| c.compatibility() == Compatibility::Breaking)
    {
        Compatibility::Breaking
    } else {
        Compatibility::Compatible
    }
}

/// Map a delta's compatibility to its required bump (pre-1.0).
#[must_use]
pub const fn required_bump(compat: Compatibility) -> RequiredBump {
    match compat {
        Compatibility::Compatible => RequiredBump::Patch,
        Compatibility::Breaking => RequiredBump::Minor,
    }
}

/// The version a floor is measured from, classified once from its [`Version`].
///
/// A prerelease of core `C` precedes the release `C` itself (semver §11), so it
/// admits `C` as a compatible successor; a release `C` does not. Each variant
/// carries the bare core (`major.minor.patch`, no prerelease or build tag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Predecessor {
    /// A release version — its own core.
    Release(Version),
    /// A prerelease (`C-<pre>`) of the release core `C`.
    PrereleaseOf(Version),
}

impl Predecessor {
    /// Classify `version` by whether it carries a prerelease tag.
    #[must_use]
    pub fn of(version: &Version) -> Self {
        let core = Version::new(version.major, version.minor, version.patch);
        if version.pre.is_empty() {
            Self::Release(core)
        } else {
            Self::PrereleaseOf(core)
        }
    }

    /// The bare `major.minor.patch` core.
    #[must_use]
    pub const fn core(&self) -> &Version {
        match self {
            Self::Release(core) | Self::PrereleaseOf(core) => core,
        }
    }
}

/// No version can clear the floor: the required bump overflows a `u64`
/// version component of the predecessor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloorOverflow {
    /// The predecessor the floor was measured from.
    pub predecessor: Predecessor,
    /// The bump whose component overflowed.
    pub required: RequiredBump,
}

impl std::fmt::Display for FloorOverflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no version can clear a {} bump over {}: a version component would overflow",
            self.required.as_str(),
            self.predecessor.core()
        )
    }
}

impl std::error::Error for FloorOverflow {}

/// The minimum acceptable new version given the predecessor and the required
/// bump (pre-1.0 floors).
///
/// - `Patch` over a release `C`: `C` with `patch + 1` — any strict increase.
/// - `Patch` over a prerelease of `C`: `C` itself — graduating the prerelease.
/// - `Minor` over either: at least `major.(minor + 1).0` — a patch bump, or
///   graduating a prerelease, does not clear a breaking delta.
///
/// # Errors
/// [`FloorOverflow`] when the bumped component would exceed `u64::MAX` — fail
/// closed: no version is accepted rather than a wrapped or saturated floor.
pub fn bump_floor(
    predecessor: &Predecessor,
    required: RequiredBump,
) -> Result<Version, FloorOverflow> {
    let overflow = || FloorOverflow {
        predecessor: predecessor.clone(),
        required,
    };
    match (predecessor, required) {
        (Predecessor::PrereleaseOf(core), RequiredBump::Patch) => Ok(core.clone()),
        (Predecessor::Release(core), RequiredBump::Patch) => core
            .patch
            .checked_add(1)
            .map(|patch| Version::new(core.major, core.minor, patch))
            .ok_or_else(overflow),
        (Predecessor::Release(core) | Predecessor::PrereleaseOf(core), RequiredBump::Minor) => core
            .minor
            .checked_add(1)
            .map(|minor| Version::new(core.major, minor, 0))
            .ok_or_else(overflow),
    }
}

/// Compare two package trees + their versions and produce the full report.
///
/// # Errors
/// [`DiffError`] when either tree cannot be read, does not typecheck, or exposes
/// an open interface, or when the required bump overflows
/// ([`DiffError::FloorOverflow`]).
pub fn check_semver_bump(
    old_tree: &Path,
    new_tree: &Path,
    old_version: &Version,
    new_version: &Version,
) -> Result<SemverReport, DiffError> {
    let old_api = extract_tree(old_tree)?;
    let new_api = extract_tree(new_tree)?;
    report(&old_api, &new_api, old_version, new_version).map_err(DiffError::from)
}

/// Build the [`SemverReport`] for two already-extracted APIs + versions.
///
/// # Errors
/// [`FloorOverflow`] when the required bump over `old_version` overflows.
pub fn report(
    old_api: &PublicApi,
    new_api: &PublicApi,
    old_version: &Version,
    new_version: &Version,
) -> Result<SemverReport, FloorOverflow> {
    let changes = diff_api(old_api, new_api);
    let compatibility = magnitude(&changes);
    let required = required_bump(compatibility);
    let floor = bump_floor(&Predecessor::of(old_version), required)?;
    let satisfied = *new_version >= floor;
    Ok(SemverReport {
        changes,
        compatibility,
        required,
        floor,
        satisfied,
    })
}

impl RequiredBump {
    /// The lowercase name of the bump, for messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
        }
    }
}

impl std::fmt::Display for ApiChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ModuleRemoved { module } => write!(f, "  - removed module {module}"),
            Self::ModuleAdded { module } => write!(f, "  + added module {module}"),
            Self::ValueRemoved { module, name } => write!(f, "  - removed {module}.{name}"),
            Self::ValueAdded { module, name } => write!(f, "  + added {module}.{name}"),
            Self::ValueChanged {
                module,
                name,
                old,
                new,
            } => write!(f, "  ~ changed {module}.{name} : {old}  ->  {new}"),
            Self::UnionRemoved { module, name } => write!(f, "  - removed type {module}.{name}"),
            Self::UnionAdded { module, name } => write!(f, "  + added type {module}.{name}"),
            Self::UnionArityChanged {
                module,
                name,
                old,
                new,
            } => write!(
                f,
                "  ~ changed type parameters of {module}.{name}: {old} -> {new}"
            ),
            Self::ConstructorRemoved {
                module,
                union,
                ctor,
            } => write!(f, "  - removed constructor {module}.{union}.{ctor}"),
            Self::ConstructorAdded {
                module,
                union,
                ctor,
            } => write!(f, "  + added constructor {module}.{union}.{ctor}"),
            Self::ConstructorChanged {
                module,
                union,
                ctor,
            } => write!(f, "  ~ changed constructor {module}.{union}.{ctor}"),
        }
    }
}

/// The wire word for a compatibility, shared by every output form.
const fn compat_word(compatibility: Compatibility) -> &'static str {
    match compatibility {
        Compatibility::Compatible => "compatible",
        Compatibility::Breaking => "breaking",
    }
}

/// Render `report` in the requested [`OutputFormat`] and print it to stdout.
///
/// - Human (default): a guttered report — a heading, one bullet per change, and
///   a sentence naming the required bump.
/// - `--plain`: one flush-left record per line. A `change\t<description>` row per
///   change, then a `bump\t<compat>\t<required>\t<floor>` verdict row, so
///   `grep`/`awk` slice the table.
/// - `--json`: `{"compatibility": "…", "required": "…", "floor": "…",
///   "changes": ["…", …]}`, a stable object.
fn print_report(report: &SemverReport, format: crate::cli_args::OutputFormat) {
    use crate::cli_args::OutputFormat::{Human, Json, Plain};
    let compat = compat_word(report.compatibility);
    let required = report.required.as_str();
    match format {
        Plain => {
            for change in &report.changes {
                // The Display form leads with indent + glyph; trim to a
                // flush-left `<+|-|~> <detail>` record for a clean pipe.
                println!("change\t{}", change.to_string().trim());
            }
            println!("bump\t{compat}\t{required}\t{}", report.floor);
        }
        Json => {
            let changes: Vec<String> = report
                .changes
                .iter()
                .map(|c| format!("{:?}", c.to_string().trim()))
                .collect();
            println!(
                "{{\"compatibility\":{compat:?},\"required\":{required:?},\
                 \"floor\":{:?},\"changes\":[{}]}}",
                report.floor.to_string(),
                changes.join(","),
            );
        }
        Human => {
            use std::fmt::Write as _;

            let mut body = String::new();
            if report.changes.is_empty() {
                body.push_str("No public API changes.\n");
            } else {
                body.push_str("Public API changes:\n");
                for change in &report.changes {
                    let _ = writeln!(body, "{change}");
                }
            }
            let _ = write!(
                body,
                "\nThis is a {compat} change — it requires at least a {required} bump (>= {}).\n",
                report.floor,
            );
            print!("{}", crate::style::gutter(&body));
        }
    }
}

/// `ipe diff <old> <new>` — the report mode — or
/// `ipe diff check <old> <new> <old-version> <new-version>` — the verify mode.
///
/// The bare command prints the classified public-API changes and the required
/// bump, exiting 0 (it is a report). The bare-word `check` mode also verifies the
/// proposed new version clears the required floor, exiting non-zero (a typed
/// [`CliError::SemverRejected`]) when it does not — the gate primitive in CLI
/// form. The former `--check <old-version> <new-version>` flag is a deprecated
/// alias for the `check` mode, kept dispatchable so it does not break existing
/// invocations; it prints a notice pointing at the bare word.
///
/// # Errors
/// [`CliError::Usage`] on argument misuse, [`CliError::UsageOwned`] on a
/// malformed version, [`CliError::Diff`] when a tree cannot be read/typechecked,
/// or [`CliError::SemverRejected`] when the verify mode finds an under-bump.
pub fn run_diff(rest: &[String]) -> Result<(), CliError> {
    run_diff_with(rest, &mut |msg| eprintln!("{msg}"))
}

/// The stderr notice emitted when the deprecated `--check` alias is used.
const CHECK_DEPRECATION_NOTICE: &str =
    "note: `ipe diff --check` is deprecated; use `ipe diff check` instead";

/// [`run_diff`] with the deprecation-notice sink injected, so a test can observe
/// the alias notice without inspecting a process's stderr.
fn run_diff_with(rest: &[String], notice: &mut dyn FnMut(&str)) -> Result<(), CliError> {
    const USAGE: &str = "usage: ipe diff <old-path> <new-path>\n   \
         or: ipe diff check <old-path> <new-path> <old-version> <new-version>";

    // Peel the deprecated `--check <old-version> <new-version>` alias FIRST, so
    // the shared format parse (which rejects any other unknown `-`-leading flag)
    // never sees `diff`'s own alias flag. The two version arguments follow it.
    let mut check: Option<(String, String)> = None;
    let deflagged: Vec<String> = if let Some(pos) = rest.iter().position(|a| a == "--check") {
        notice(CHECK_DEPRECATION_NOTICE);
        let old_v = rest.get(pos + 1).ok_or(CliError::Usage(USAGE))?.clone();
        let new_v = rest.get(pos + 2).ok_or(CliError::Usage(USAGE))?.clone();
        check = Some((old_v, new_v));
        rest.iter()
            .enumerate()
            .filter(|(i, _)| *i != pos && *i != pos + 1 && *i != pos + 2)
            .map(|(_, a)| a.clone())
            .collect()
    } else {
        rest.to_vec()
    };

    // Peel the output-format flags, so `--plain` / `--json` compose with the
    // positional paths and the verify-mode arguments.
    let (format, args) = crate::cli_args::split_format(&deflagged, "diff")?;

    let mut positional: Vec<&str> = Vec::new();
    let mut it = args.into_iter();

    // A leading bare `check` selects the verify mode; its two version arguments
    // follow the two package paths.
    let verify_mode = matches!(it.clone().next(), Some("check"));
    if verify_mode {
        it.next();
    }

    for arg in it {
        positional.push(arg);
    }

    // In bare `check` mode the two versions are the trailing positionals, after
    // the two package paths.
    if verify_mode {
        if check.is_some() {
            return Err(CliError::Usage(USAGE));
        }
        let [old_path, new_path, old_v, new_v] = positional.as_slice() else {
            return Err(CliError::Usage(USAGE));
        };
        check = Some(((*old_v).to_owned(), (*new_v).to_owned()));
        positional = vec![old_path, new_path];
    }
    let [old_path, new_path] = positional.as_slice() else {
        return Err(CliError::Usage(USAGE));
    };
    let old_tree = PathBuf::from(old_path);
    let new_tree = PathBuf::from(new_path);

    match check {
        None => {
            // Report mode: diff against a placeholder version pair so the report
            // still names the required bump. The floor is informational here.
            let old_api = extract_tree(&old_tree)?;
            let new_api = extract_tree(&new_tree)?;
            let placeholder = Version::new(0, 0, 0);
            let rep =
                report(&old_api, &new_api, &placeholder, &placeholder).map_err(DiffError::from)?;
            print_report(&rep, format);
            Ok(())
        }
        Some((old_v, new_v)) => {
            let old_version = parse_version(&old_v)?;
            let new_version = parse_version(&new_v)?;
            let rep = check_semver_bump(&old_tree, &new_tree, &old_version, &new_version)?;
            print_report(&rep, format);
            if rep.satisfied {
                Ok(())
            } else {
                Err(CliError::SemverRejected {
                    required: rep.required.as_str().to_owned(),
                    floor: rep.floor.to_string(),
                    proposed: new_version.to_string(),
                })
            }
        }
    }
}

/// Parse a semver version argument, mapping a malformed value to a usage error.
fn parse_version(raw: &str) -> Result<Version, CliError> {
    Version::parse(raw).map_err(|_| CliError::UsageOwned(format!("diff: invalid version `{raw}`")))
}
