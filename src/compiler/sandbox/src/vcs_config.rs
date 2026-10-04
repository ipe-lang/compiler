//! Detection of version-control configuration that names host-run code inside a writable grant.
//!
//! A carved VCS metadata directory keeps a jailed program from rewriting the
//! hooks a host tool runs, but the tool also reads configuration that can point
//! anywhere: `core.hooksPath`, an `include.path`, an alias, a Mercurial
//! extension, a Jujutsu fix tool, a Darcs test command. When any value names a
//! path inside a writable grant, the jailed program can plant code the host
//! later runs outside the jail. [`scan`] reads every configuration file the
//! tool reads from the carved metadata, follows its includes, and refuses when
//! a value names such a path or cannot be proven not to.
//!
//! The scan is key-agnostic: every value is split into words and every
//! path-shaped word is resolved, except under the few settings [`NON_CODE`]
//! lists as never naming code. A relative word is resolved against both the
//! configuration file's directory and the working tree, `~` through the
//! injected [`Home`]; a command substitution, an expansion, another user's
//! home, or a `..` below a missing directory is unprovable and refuses. Every
//! read goes through a held directory handle, every loop is bounded by
//! [`ConfigLimits`], and every unreadable, oversized, or malformed file
//! refuses.

use std::fmt::{self, Write as _};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use ipe_fs_open::{ByteCap, EntryCap, EntryName, FileKind, HeldDir, OpenRefusal, RegularFile};

use crate::covers::path_covers;
use crate::mounts::CanonicalPath;
use crate::vcs_metadata::VcsKind;

/// The longest path-shaped word, in bytes, the resolver takes.
pub const MAX_PATH_BYTES: usize = 4096;

/// The most components a path-shaped word may have.
pub const MAX_PATH_COMPONENTS: usize = 256;

/// `n` as a [`NonZeroU64`], or one for zero.
const fn nonzero_u64(n: u64) -> NonZeroU64 {
    match NonZeroU64::new(n) {
        Some(value) => value,
        None => NonZeroU64::MIN,
    }
}

/// `n` as a [`NonZeroU32`], or one for zero.
const fn nonzero_u32(n: u32) -> NonZeroU32 {
    match NonZeroU32::new(n) {
        Some(value) => value,
        None => NonZeroU32::MIN,
    }
}

/// The ceilings one scan works within; reaching any of them refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigLimits {
    /// The largest single configuration file.
    pub file_bytes: ByteCap,
    /// The most bytes read across every file of one scan.
    pub total_bytes: NonZeroU64,
    /// The most configuration files one scan reads.
    pub files: NonZeroU32,
    /// The deepest include chain; a root file is at depth zero.
    pub include_depth: NonZeroU32,
    /// The most entries listed from one directory.
    pub listing: EntryCap,
    /// The most path-shaped words and links one scan resolves.
    pub paths: NonZeroU32,
}

impl ConfigLimits {
    /// The ceilings every jail scan uses.
    pub const DEFAULT: Self = Self {
        file_bytes: ByteCap::from_nonzero(nonzero_u64(1 << 20)),
        total_bytes: nonzero_u64(16 << 20),
        files: nonzero_u32(1024),
        include_depth: nonzero_u32(10),
        listing: EntryCap::from_nonzero(nonzero_u32(1024)),
        paths: nonzero_u32(4096),
    };
}

/// The writable grants a jail binds: the working tree and every other one.
#[derive(Debug, Clone)]
pub struct Grants<'g> {
    /// The working tree, the base a relative value is also resolved against.
    worktree: &'g CanonicalPath,
    /// Every writable grant, the working tree included.
    writable: Vec<&'g CanonicalPath>,
}

impl<'g> Grants<'g> {
    /// The grants of a jail binding `worktree` and `others` writable.
    #[must_use]
    pub fn new(worktree: &'g CanonicalPath, others: &[&'g CanonicalPath]) -> Self {
        let mut writable = Vec::with_capacity(others.len().saturating_add(1));
        writable.push(worktree);
        writable.extend_from_slice(others);
        Self { worktree, writable }
    }

    /// Whether `path` lies inside any writable grant.
    fn cover(&self, path: &Path) -> bool {
        self.writable
            .iter()
            .any(|grant| path_covers(grant.as_path(), path))
    }
}

/// The host user's home directory, injected so the scan reads no environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home(Option<CanonicalPath>);

impl Home {
    /// A known home directory.
    #[must_use]
    pub const fn known(dir: CanonicalPath) -> Self {
        Self(Some(dir))
    }

    /// No known home directory: every `~` value is unprovable.
    #[must_use]
    pub const fn unknown() -> Self {
        Self(None)
    }
}

/// The carved metadata directories of one tool, the roots its configuration is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigRoots<'r> {
    /// Git: the gitdir, and its common dir when it differs.
    Git {
        /// The gitdir holding `config`, `config.worktree`, and `hooks`.
        gitdir: &'r Path,
        /// The common dir a linked worktree's gitdir names.
        commondir: Option<&'r Path>,
    },
    /// Mercurial: `.hg`, and the share source's `.hg` for a shared repository.
    Mercurial {
        /// The `.hg` directory.
        dot_hg: &'r Path,
        /// The share source's `.hg` directory.
        shared: Option<&'r Path>,
    },
    /// Jujutsu: `.jj` and the repository directory it uses.
    Jujutsu {
        /// The `.jj` directory.
        dot_jj: &'r Path,
        /// The repository directory: `.jj/repo`, or the one its pointer names.
        repo: &'r Path,
    },
    /// Darcs: `_darcs`.
    Darcs {
        /// The `_darcs` directory.
        dot_darcs: &'r Path,
    },
}

impl ConfigRoots<'_> {
    /// The tool these roots belong to.
    const fn kind(&self) -> VcsKind {
        match self {
            Self::Git { .. } => VcsKind::Git,
            Self::Mercurial { .. } => VcsKind::Mercurial,
            Self::Jujutsu { .. } => VcsKind::Jujutsu,
            Self::Darcs { .. } => VcsKind::Darcs,
        }
    }
}

/// Which subsections a [`NonCode`] pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubsectionMatch {
    /// Only a key with no subsection.
    Absent,
    /// Only a key under some subsection.
    Present,
    /// A key with or without a subsection.
    Either,
}

/// Which keys a [`NonCode`] pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMatch {
    /// Every key.
    Any,
    /// The one key, compared in the tool's own case.
    Named(&'static str),
}

/// Which values a [`NonCode`] pattern matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueMatch {
    /// Every value.
    Any,
    /// Every value but one beginning `ext::`, which names a program Git runs.
    NotExtTransport,
}

/// A setting whose value never names code a tool runs, so it is not scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonCode {
    /// The tool the setting belongs to.
    pub kind: VcsKind,
    /// The section; for Jujutsu, the top-level table.
    pub section: &'static str,
    /// The subsections matched.
    pub subsection: SubsectionMatch,
    /// The keys matched.
    pub key: KeyMatch,
    /// The values matched.
    pub value: ValueMatch,
}

impl NonCode {
    /// A pattern matching every value.
    const fn any_value(
        kind: VcsKind,
        section: &'static str,
        subsection: SubsectionMatch,
        key: KeyMatch,
    ) -> Self {
        Self {
            kind,
            section,
            subsection,
            key,
            value: ValueMatch::Any,
        }
    }

    /// Whether this pattern matches the setting and value.
    fn matches(&self, kind: VcsKind, setting: (&str, Option<&str>, &str), value: &str) -> bool {
        let (section, subsection, key) = setting;
        let subsection_ok = match self.subsection {
            SubsectionMatch::Absent => subsection.is_none(),
            SubsectionMatch::Present => subsection.is_some(),
            SubsectionMatch::Either => true,
        };
        let key_ok = match self.key {
            KeyMatch::Any => true,
            KeyMatch::Named(name) => name == key,
        };
        let value_ok = match self.value {
            ValueMatch::Any => true,
            ValueMatch::NotExtTransport => !value.starts_with("ext::"),
        };
        self.kind == kind && self.section == section && subsection_ok && key_ok && value_ok
    }
}

/// Every setting exempt from the scan, the one list of them.
///
/// Git keys are lowercase, as Git compares them. Git's refspecs
/// (`remote.*.fetch`, `remote.*.push`) are listed because every clone writes
/// one shaped like a path, and a refspec names refs, never a file.
pub const NON_CODE: &[NonCode] = &[
    NonCode::any_value(
        VcsKind::Git,
        "core",
        SubsectionMatch::Absent,
        KeyMatch::Named("worktree"),
    ),
    NonCode::any_value(
        VcsKind::Git,
        "core",
        SubsectionMatch::Absent,
        KeyMatch::Named("excludesfile"),
    ),
    NonCode::any_value(
        VcsKind::Git,
        "core",
        SubsectionMatch::Absent,
        KeyMatch::Named("attributesfile"),
    ),
    NonCode::any_value(
        VcsKind::Git,
        "commit",
        SubsectionMatch::Absent,
        KeyMatch::Named("template"),
    ),
    NonCode::any_value(
        VcsKind::Git,
        "blame",
        SubsectionMatch::Absent,
        KeyMatch::Named("ignorerevsfile"),
    ),
    NonCode::any_value(
        VcsKind::Git,
        "submodule",
        SubsectionMatch::Present,
        KeyMatch::Named("url"),
    ),
    NonCode::any_value(
        VcsKind::Git,
        "branch",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::any_value(VcsKind::Git, "user", SubsectionMatch::Either, KeyMatch::Any),
    NonCode {
        kind: VcsKind::Git,
        section: "remote",
        subsection: SubsectionMatch::Present,
        key: KeyMatch::Named("url"),
        value: ValueMatch::NotExtTransport,
    },
    NonCode {
        kind: VcsKind::Git,
        section: "remote",
        subsection: SubsectionMatch::Present,
        key: KeyMatch::Named("pushurl"),
        value: ValueMatch::NotExtTransport,
    },
    NonCode::any_value(
        VcsKind::Git,
        "remote",
        SubsectionMatch::Present,
        KeyMatch::Named("fetch"),
    ),
    NonCode::any_value(
        VcsKind::Git,
        "remote",
        SubsectionMatch::Present,
        KeyMatch::Named("push"),
    ),
    NonCode::any_value(
        VcsKind::Mercurial,
        "paths",
        SubsectionMatch::Absent,
        KeyMatch::Any,
    ),
    NonCode::any_value(
        VcsKind::Mercurial,
        "ui",
        SubsectionMatch::Absent,
        KeyMatch::Named("username"),
    ),
    NonCode::any_value(
        VcsKind::Jujutsu,
        "revset-aliases",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::any_value(
        VcsKind::Jujutsu,
        "templates",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::any_value(
        VcsKind::Jujutsu,
        "template-aliases",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::any_value(
        VcsKind::Jujutsu,
        "colors",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::any_value(
        VcsKind::Jujutsu,
        "user",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
];

/// Whether [`NON_CODE`] exempts the setting and value.
fn exempt(kind: VcsKind, setting: (&str, Option<&str>, &str), value: &str) -> bool {
    NON_CODE
        .iter()
        .any(|pattern| pattern.matches(kind, setting, value))
}

/// The setting a refused value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSetting {
    /// A key under a section and optional subsection; for Jujutsu, under its table path.
    Key {
        /// The section, or the dotted table path; empty for a top-level key.
        section: String,
        /// The subsection, when the key has one.
        subsection: Option<String>,
        /// The key.
        key: String,
    },
    /// A Mercurial `%include` directive.
    Include,
    /// A Darcs preference line, by its one-based number.
    Line(usize),
}

impl fmt::Display for ConfigSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key {
                section,
                subsection,
                key,
            } => {
                if !section.is_empty() {
                    write!(f, "{}.", Shown(section))?;
                }
                if let Some(subsection) = subsection {
                    write!(f, "{}.", Shown(subsection))?;
                }
                write!(f, "{}", Shown(key))
            }
            Self::Include => f.write_str("%include"),
            Self::Line(number) => write!(f, "on line {number}"),
        }
    }
}

/// Why a value cannot be proven to name nothing inside a writable grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unprovable {
    /// The value runs a command substitution (`$(` or a backtick).
    CommandSubstitution,
    /// A path-shaped word expands a variable (`$NAME`, `%NAME%`).
    Expansion,
    /// A path-shaped word names another user's home (`~user`).
    TildeUser,
    /// A path-shaped word starts with `~` and no home directory is known.
    NoHome,
    /// A `..` follows a directory that does not exist yet.
    DotDot,
    /// The path names an entry that exists but does not resolve.
    Unresolvable,
    /// The word is longer than [`MAX_PATH_BYTES`] or has more than [`MAX_PATH_COMPONENTS`] components.
    TooLong,
}

impl fmt::Display for Unprovable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandSubstitution => f.write_str(
                "it runs a command substitution, whose output is unknown until the tool runs",
            ),
            Self::Expansion => {
                f.write_str("it expands a variable, whose value is unknown until the tool runs")
            }
            Self::TildeUser => f.write_str("it names another user's home directory"),
            Self::NoHome => f.write_str("it starts with `~` and the home directory is unknown"),
            Self::DotDot => {
                f.write_str("it climbs with `..` out of a directory that does not exist")
            }
            Self::Unresolvable => f.write_str("it names an entry that exists but does not resolve"),
            Self::TooLong => write!(
                f,
                "it is longer than {MAX_PATH_BYTES} bytes or {MAX_PATH_COMPONENTS} components"
            ),
        }
    }
}

/// What a refused value or link names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Named {
    /// This resolved path, inside a writable grant.
    InGrant(PathBuf),
    /// A path that cannot be proven outside every writable grant.
    Unprovable(Unprovable),
}

/// Why a configuration file could not be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFault {
    /// Opening or reading it was refused.
    Open(OpenRefusal),
    /// This one-based line is not valid syntax for the tool.
    Malformed {
        /// The line.
        line: usize,
    },
    /// Its includes nest deeper than [`ConfigLimits::include_depth`], or form a cycle.
    IncludeDepth,
    /// The scan reached [`ConfigLimits::files`].
    Files,
    /// The scan reached [`ConfigLimits::total_bytes`].
    Bytes,
    /// The scan reached [`ConfigLimits::paths`].
    Paths,
    /// It is not valid UTF-8.
    NotUtf8,
}

impl fmt::Display for ConfigFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(refusal) => write!(f, "{refusal}"),
            Self::Malformed { line } => write!(f, "line {line} is not valid configuration syntax"),
            Self::IncludeDepth => f.write_str("its includes nest past the include depth limit"),
            Self::Files => f.write_str("the scan reached its limit on configuration files"),
            Self::Bytes => f.write_str("the scan reached its limit on configuration bytes"),
            Self::Paths => f.write_str("the scan reached its limit on resolved paths"),
            Self::NotUtf8 => f.write_str("it is not valid UTF-8"),
        }
    }
}

/// The fault an [`OpenRefusal`] is.
const fn fault_of(refusal: OpenRefusal) -> ConfigFault {
    match refusal {
        OpenRefusal::NotUtf8 => ConfigFault::NotUtf8,
        OpenRefusal::Absent
        | OpenRefusal::Link
        | OpenRefusal::NotRegular(_)
        | OpenRefusal::Denied
        | OpenRefusal::InUse
        | OpenRefusal::TooLarge(_)
        | OpenRefusal::TooManyEntries(_)
        | OpenRefusal::BadName
        | OpenRefusal::Io(_) => ConfigFault::Open(refusal),
    }
}

/// Why the scan refused a jail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigRefusal {
    /// A configuration value names, or may name, a path inside a writable grant.
    NamesWritableCode {
        /// The tool.
        kind: VcsKind,
        /// The configuration file holding the value.
        source: PathBuf,
        /// The setting holding the value.
        setting: ConfigSetting,
        /// What the value names.
        named: Named,
    },
    /// A link the tool follows (a configuration file, a hooks directory or hook) points inside a writable grant, or may.
    LinkNamesWritable {
        /// The tool.
        kind: VcsKind,
        /// The link.
        link: PathBuf,
        /// What the link points at.
        named: Named,
    },
    /// A configuration file could not be checked.
    Unreadable {
        /// The tool.
        kind: VcsKind,
        /// The file or directory.
        path: PathBuf,
        /// Why.
        fault: ConfigFault,
    },
}

/// The plain name of a tool, for a sentence.
const fn tool_name(kind: VcsKind) -> &'static str {
    match kind {
        VcsKind::Git => "Git",
        VcsKind::Mercurial => "Mercurial",
        VcsKind::Jujutsu => "Jujutsu",
        VcsKind::Darcs => "Darcs",
    }
}

/// The closing clause every refusal shares.
const REFUSING: &str = "or run without the filesystem grant; refusing to build the jail";

impl ConfigRefusal {
    /// The sentence for a value naming `named`.
    fn fmt_value(
        f: &mut fmt::Formatter<'_>,
        kind: VcsKind,
        source: &Path,
        setting: &ConfigSetting,
        named: &Named,
    ) -> fmt::Result {
        let tool = tool_name(kind);
        let source = Shown(source.as_os_str());
        match named {
            Named::InGrant(path) => write!(
                f,
                "the {tool} setting {setting} in `{source}` names `{}` inside a writable grant, so \
                 a jailed program could change code {tool} runs outside the jail; point the \
                 setting outside the writable grants, {REFUSING}",
                Shown(path.as_os_str())
            ),
            Named::Unprovable(why) => write!(
                f,
                "the {tool} setting {setting} in `{source}` cannot be proven to name nothing inside \
                 a writable grant: {why}; give the setting a plain absolute path outside the \
                 writable grants, {REFUSING}"
            ),
        }
    }

    /// The sentence for a link pointing at `named`.
    fn fmt_link(
        f: &mut fmt::Formatter<'_>,
        kind: VcsKind,
        link: &Path,
        named: &Named,
    ) -> fmt::Result {
        let tool = tool_name(kind);
        let link = Shown(link.as_os_str());
        match named {
            Named::InGrant(path) => write!(
                f,
                "the {tool} link `{link}` points at `{}` inside a writable grant, so a jailed \
                 program could change what {tool} reads or runs outside the jail; replace the link \
                 with the file it names, {REFUSING}",
                Shown(path.as_os_str())
            ),
            Named::Unprovable(why) => write!(
                f,
                "the {tool} link `{link}` cannot be proven to point outside the writable grants: \
                 {why}; replace the link with the file it names, {REFUSING}"
            ),
        }
    }
}

impl fmt::Display for ConfigRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NamesWritableCode {
                kind,
                source,
                setting,
                named,
            } => Self::fmt_value(f, *kind, source, setting, named),
            Self::LinkNamesWritable { kind, link, named } => Self::fmt_link(f, *kind, link, named),
            Self::Unreadable { kind, path, fault } => write!(
                f,
                "the {} configuration `{}` cannot be checked for code inside a writable grant: \
                 {fault}; fix or remove it, {REFUSING}",
                tool_name(*kind),
                Shown(path.as_os_str())
            ),
        }
    }
}

impl std::error::Error for ConfigRefusal {}

/// Text shown injectively: a backslash, a control or bidirectional-format
/// character, and every byte that is not UTF-8 is written as an escape.
struct Shown<'a, T: ?Sized>(&'a T);

impl<T: AsRef<std::ffi::OsStr> + ?Sized> fmt::Display for Shown<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.as_ref().as_encoded_bytes().utf8_chunks() {
            for c in chunk.valid().chars() {
                if c == '\\' {
                    f.write_str("\\\\")?;
                } else if c.is_control()
                    || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                {
                    let code = u32::from(c);
                    write!(f, "\\u{{{code:x}}}")?;
                } else {
                    f.write_char(c)?;
                }
            }
            for byte in chunk.invalid() {
                write!(f, "\\x{byte:02x}")?;
            }
        }
        Ok(())
    }
}

/// Scan the configuration a tool reads from `roots`, refusing when it names code inside a grant.
///
/// Every configuration file the tool reads from the carved metadata is read
/// through a held handle, its includes followed, and every value judged; the
/// Git hooks directories are listed for links. Nothing is read from the
/// environment: the grants and the home directory are injected.
///
/// # Errors
/// [`ConfigRefusal::NamesWritableCode`] for a value naming, or perhaps naming,
/// a path inside a writable grant; [`ConfigRefusal::LinkNamesWritable`] for
/// such a link; [`ConfigRefusal::Unreadable`] for a root directory or file that
/// cannot be opened, read, or parsed, or a ceiling reached.
pub fn scan(
    roots: &ConfigRoots<'_>,
    grants: &Grants<'_>,
    home: &Home,
    limits: ConfigLimits,
) -> Result<(), ConfigRefusal> {
    let mut run = Scan {
        kind: roots.kind(),
        grants,
        home,
        limits,
        files: 0,
        bytes: 0,
        paths: 0,
        pending: Vec::new(),
    };
    run.seed(roots)?;
    while let Some(item) = run.pending.pop() {
        run.read(item)?;
    }
    Ok(())
}

/// The configuration syntax a file is parsed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Syntax {
    /// Git's `config` syntax.
    Git,
    /// Mercurial's `hgrc` syntax.
    Hg,
    /// Jujutsu's TOML.
    Toml,
    /// Darcs's line-per-preference files.
    Darcs,
}

/// A configuration file waiting to be read.
#[derive(Debug)]
struct Pending {
    /// The path the tool reads it at.
    path: PathBuf,
    /// Its include depth.
    depth: u32,
    /// Its syntax.
    syntax: Syntax,
}

/// A configuration file being judged.
struct FileCtx {
    /// The path the tool reads it at.
    source: PathBuf,
    /// The directories a relative value is resolved against, before the working tree.
    bases: Vec<PathBuf>,
    /// Its include depth.
    depth: u32,
    /// Its syntax.
    syntax: Syntax,
}

/// How a value is judged.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Role {
    /// Never names code: not judged.
    Exempt,
    /// Every path-shaped word is judged.
    Words,
    /// Every path-shaped word, and this text as one path whatever its shape.
    Forced(String),
    /// As [`Role::Forced`] over the whole value, then the file it names is read.
    Include,
    /// As [`Role::Forced`] over the whole value, then the directory it names is listed for links.
    HooksPath,
}

/// Where a parsed value came from, sharing its section text.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Setting {
    /// A key under a section and optional subsection.
    Key {
        /// The section; lowercase for Git.
        section: Rc<str>,
        /// The subsection.
        subsection: Option<Rc<str>>,
        /// The key, as written.
        key: String,
    },
    /// A Mercurial `%include`.
    Include,
    /// A Darcs line.
    Line(usize),
}

impl Setting {
    /// The public form.
    fn public(&self) -> ConfigSetting {
        match self {
            Self::Key {
                section,
                subsection,
                key,
            } => ConfigSetting::Key {
                section: section.to_string(),
                subsection: subsection.as_ref().map(ToString::to_string),
                key: key.clone(),
            },
            Self::Include => ConfigSetting::Include,
            Self::Line(number) => ConfigSetting::Line(*number),
        }
    }
}

/// One parsed value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// Where it came from.
    setting: Setting,
    /// The value, unquoted and unescaped.
    value: String,
}

/// A path resolved through its longest existing prefix.
#[derive(Debug)]
struct Resolved {
    /// The canonical existing prefix joined with the rest.
    path: PathBuf,
    /// Whether the whole path exists.
    exists: bool,
}

/// Why judging a value stopped.
enum Stop {
    /// The value names this.
    Named(Named),
    /// A refusal not about the value itself (a ceiling, a link reached from it).
    Refused(ConfigRefusal),
}

impl Stop {
    /// The refusal, with the setting built only now.
    fn into_refusal(
        self,
        kind: VcsKind,
        source: &Path,
        setting: impl FnOnce() -> ConfigSetting,
    ) -> ConfigRefusal {
        match self {
            Self::Named(named) => ConfigRefusal::NamesWritableCode {
                kind,
                source: source.to_path_buf(),
                setting: setting(),
                named,
            },
            Self::Refused(refusal) => refusal,
        }
    }
}

/// An opened configuration file.
struct Opened {
    /// The held file.
    file: RegularFile,
    /// The directories its relative values resolve against.
    bases: Vec<PathBuf>,
}

/// One scan's state.
struct Scan<'s> {
    /// The tool.
    kind: VcsKind,
    /// The writable grants.
    grants: &'s Grants<'s>,
    /// The home directory.
    home: &'s Home,
    /// The ceilings.
    limits: ConfigLimits,
    /// Files read so far.
    files: u32,
    /// Bytes read so far.
    bytes: u64,
    /// Paths resolved so far.
    paths: u32,
    /// Files still to read.
    pending: Vec<Pending>,
}

impl Scan<'_> {
    /// An unreadable refusal.
    fn unreadable(&self, path: &Path, fault: ConfigFault) -> ConfigRefusal {
        ConfigRefusal::Unreadable {
            kind: self.kind,
            path: path.to_path_buf(),
            fault,
        }
    }

    /// A link refusal.
    fn link_refusal(&self, link: &Path, named: Named) -> ConfigRefusal {
        ConfigRefusal::LinkNamesWritable {
            kind: self.kind,
            link: link.to_path_buf(),
            named,
        }
    }

    /// Queue a root file.
    fn queue(&mut self, path: PathBuf, syntax: Syntax) {
        self.pending.push(Pending {
            path,
            depth: 0,
            syntax,
        });
    }

    /// Require a root directory to exist and open.
    fn require(&self, dir: &Path) -> Result<(), ConfigRefusal> {
        self.root(dir).map(drop)
    }

    /// Hold a root directory, which must exist.
    fn root(&self, dir: &Path) -> Result<HeldDir, ConfigRefusal> {
        HeldDir::open_root(dir).map_err(|refusal| self.unreadable(dir, fault_of(refusal)))
    }

    /// Queue every root file of `roots` and list the Git hooks directories.
    fn seed(&mut self, roots: &ConfigRoots<'_>) -> Result<(), ConfigRefusal> {
        match *roots {
            ConfigRoots::Git { gitdir, commondir } => {
                self.require(gitdir)?;
                let common = commondir.unwrap_or(gitdir);
                self.require(common)?;
                self.queue(gitdir.join("config"), Syntax::Git);
                self.queue(gitdir.join("config.worktree"), Syntax::Git);
                if common != gitdir {
                    self.queue(common.join("config"), Syntax::Git);
                }
                self.list_hooks(&gitdir.join("hooks"))?;
                if common != gitdir {
                    self.list_hooks(&common.join("hooks"))?;
                }
            }
            ConfigRoots::Mercurial { dot_hg, shared } => {
                self.require(dot_hg)?;
                self.queue(dot_hg.join("hgrc"), Syntax::Hg);
                self.queue(dot_hg.join("hgrc-not-shared"), Syntax::Hg);
                if let Some(shared) = shared {
                    self.require(shared)?;
                    self.queue(shared.join("hgrc"), Syntax::Hg);
                }
            }
            ConfigRoots::Jujutsu { dot_jj, repo } => {
                self.queue_toml(dot_jj)?;
                self.queue_toml(repo)?;
            }
            ConfigRoots::Darcs { dot_darcs } => {
                self.require(dot_darcs)?;
                let prefs = dot_darcs.join("prefs");
                self.queue(prefs.join("defaults"), Syntax::Darcs);
                self.queue(prefs.join("prefs"), Syntax::Darcs);
            }
        }
        Ok(())
    }

    /// Queue every `*.toml` entry directly in `dir` that is not a directory.
    fn queue_toml(&mut self, dir: &Path) -> Result<(), ConfigRefusal> {
        let held = self.root(dir)?;
        let listed = held
            .entries(self.limits.listing)
            .map_err(|refusal| self.unreadable(dir, fault_of(refusal)))?;
        for (name, kind) in listed {
            let is_toml = Path::new(name.as_os_str())
                .extension()
                .is_some_and(|ext| ext == "toml");
            if is_toml && kind != FileKind::Dir {
                self.queue(dir.join(name.as_os_str()), Syntax::Toml);
            }
        }
        Ok(())
    }

    /// Count one resolution against [`ConfigLimits::paths`].
    fn count_path(&mut self, source: &Path) -> Result<(), ConfigRefusal> {
        self.paths = self.paths.saturating_add(1);
        if self.paths > self.limits.paths.get() {
            return Err(self.unreadable(source, ConfigFault::Paths));
        }
        Ok(())
    }

    /// Resolve the link `link`, refusing when it points inside a grant or cannot be proven not to.
    fn link_target(&mut self, link: &Path) -> Result<Resolved, ConfigRefusal> {
        self.count_path(link)?;
        let target = std::fs::read_link(link)
            .map_err(|e| self.unreadable(link, ConfigFault::Open(OpenRefusal::Io(e.kind()))))?;
        let joined = link
            .parent()
            .map_or_else(|| target.clone(), |dir| dir.join(&target));
        let resolved =
            resolve(&joined).map_err(|why| self.link_refusal(link, Named::Unprovable(why)))?;
        if self.grants.cover(&resolved.path) {
            return Err(self.link_refusal(link, Named::InGrant(resolved.path)));
        }
        Ok(resolved)
    }

    /// List a hooks directory, refusing a link (the directory or an entry) into a grant.
    fn list_hooks(&mut self, hooks: &Path) -> Result<(), ConfigRefusal> {
        let Some((parent, name)) = split(hooks) else {
            return Err(self.unreadable(hooks, ConfigFault::Open(OpenRefusal::BadName)));
        };
        let held = match HeldDir::open_root(parent) {
            Ok(held) => held,
            Err(OpenRefusal::Absent) => return Ok(()),
            Err(refusal) => return Err(self.unreadable(parent, fault_of(refusal))),
        };
        let kind = held
            .kind_of(&name)
            .map_err(|refusal| self.unreadable(hooks, fault_of(refusal)))?;
        let (dir, listed_at) = match kind {
            None
            | Some(
                FileKind::Regular
                | FileKind::Fifo
                | FileKind::Socket
                | FileKind::Device
                | FileKind::Other,
            ) => return Ok(()),
            Some(FileKind::Dir) => (
                held.child_dir(&name)
                    .map_err(|refusal| self.unreadable(hooks, fault_of(refusal)))?,
                hooks.to_path_buf(),
            ),
            Some(FileKind::Symlink) => {
                let target = self.link_target(hooks)?;
                if !target.exists {
                    return Ok(());
                }
                let dir = HeldDir::open_root(&target.path)
                    .map_err(|refusal| self.unreadable(&target.path, fault_of(refusal)))?;
                (dir, target.path)
            }
        };
        let entries = dir
            .entries(self.limits.listing)
            .map_err(|refusal| self.unreadable(&listed_at, fault_of(refusal)))?;
        for (entry, entry_kind) in entries {
            if entry_kind == FileKind::Symlink {
                self.link_target(&listed_at.join(entry.as_os_str()))?;
            }
        }
        Ok(())
    }

    /// Open the configuration file at `path`; `None` when it is absent.
    fn open(&mut self, path: &Path) -> Result<Option<Opened>, ConfigRefusal> {
        let Some((dir, name)) = split(path) else {
            return Err(self.unreadable(path, ConfigFault::Open(OpenRefusal::BadName)));
        };
        let held = match HeldDir::open_root(dir) {
            Ok(held) => held,
            Err(OpenRefusal::Absent) => return Ok(None),
            Err(refusal) => return Err(self.unreadable(dir, fault_of(refusal))),
        };
        match held.open_regular(&name) {
            Ok(file) => Ok(Some(Opened {
                file,
                bases: vec![dir.to_path_buf()],
            })),
            Err(OpenRefusal::Absent) => Ok(None),
            Err(OpenRefusal::Link) => self.open_link(path, dir),
            Err(refusal) => Err(self.unreadable(path, fault_of(refusal))),
        }
    }

    /// Open the file the link `path` points at, once it is proven outside every grant.
    fn open_link(&mut self, path: &Path, dir: &Path) -> Result<Option<Opened>, ConfigRefusal> {
        let target = self.link_target(path)?;
        if !target.exists {
            return Ok(None);
        }
        let Some((target_dir, target_name)) = split(&target.path) else {
            return Err(self.unreadable(&target.path, ConfigFault::Open(OpenRefusal::BadName)));
        };
        let held = HeldDir::open_root(target_dir)
            .map_err(|refusal| self.unreadable(target_dir, fault_of(refusal)))?;
        match held.open_regular(&target_name) {
            Ok(file) => Ok(Some(Opened {
                file,
                bases: vec![dir.to_path_buf(), target_dir.to_path_buf()],
            })),
            Err(OpenRefusal::Absent) => Ok(None),
            Err(refusal) => Err(self.unreadable(&target.path, fault_of(refusal))),
        }
    }

    /// Read, parse, and judge one configuration file.
    fn read(&mut self, item: Pending) -> Result<(), ConfigRefusal> {
        if item.depth > self.limits.include_depth.get() {
            return Err(self.unreadable(&item.path, ConfigFault::IncludeDepth));
        }
        let Some(opened) = self.open(&item.path)? else {
            return Ok(());
        };
        self.files = self.files.saturating_add(1);
        if self.files > self.limits.files.get() {
            return Err(self.unreadable(&item.path, ConfigFault::Files));
        }
        let text = opened
            .file
            .read_utf8(self.limits.file_bytes)
            .map_err(|refusal| self.unreadable(&item.path, fault_of(refusal)))?;
        let read = u64::try_from(text.len()).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(read);
        if self.bytes > self.limits.total_bytes.get() {
            return Err(self.unreadable(&item.path, ConfigFault::Bytes));
        }
        let ctx = FileCtx {
            source: item.path,
            bases: opened.bases,
            depth: item.depth,
            syntax: item.syntax,
        };
        let malformed = |line| ConfigFault::Malformed { line };
        match ctx.syntax {
            Syntax::Git => {
                let entries = parse_git(&text)
                    .map_err(|line| self.unreadable(&ctx.source, malformed(line)))?;
                self.judge_entries(&ctx, &entries)
            }
            Syntax::Hg => {
                let entries = parse_hg(&text)
                    .map_err(|line| self.unreadable(&ctx.source, malformed(line)))?;
                self.judge_entries(&ctx, &entries)
            }
            Syntax::Toml => self.judge_toml(&ctx, &text),
            Syntax::Darcs => self.judge_entries(&ctx, &parse_darcs(&text)),
        }
    }

    /// Judge every entry of a parsed file.
    fn judge_entries(&mut self, ctx: &FileCtx, entries: &[Entry]) -> Result<(), ConfigRefusal> {
        let kind = self.kind;
        for entry in entries {
            let role = match ctx.syntax {
                Syntax::Git => git_role(&entry.setting, &entry.value),
                Syntax::Hg => hg_role(&entry.setting, &entry.value),
                Syntax::Toml | Syntax::Darcs => Role::Words,
            };
            self.judge(ctx, &role, &entry.value)
                .map_err(|stop| stop.into_refusal(kind, &ctx.source, || entry.setting.public()))?;
        }
        Ok(())
    }

    /// Parse a Jujutsu TOML file and judge every string in it, outside the exempt tables.
    ///
    /// The walk keeps an explicit stack, so the depth the parser admits never
    /// becomes recursion here; each key is kept once in an arena of
    /// parent-linked labels, and a setting's text is built only on refusal.
    fn judge_toml(&mut self, ctx: &FileCtx, text: &str) -> Result<(), ConfigRefusal> {
        let table: toml::Table = toml::from_str(text).map_err(|e| {
            let line = e.span().map_or(1, |span| line_of(text, span.start));
            self.unreadable(&ctx.source, ConfigFault::Malformed { line })
        })?;
        let kind = self.kind;
        let mut labels: Vec<(Option<usize>, &str)> = Vec::new();
        let mut stack: Vec<(TomlNode<'_>, Option<usize>, bool)> =
            vec![(TomlNode::Table(&table), None, true)];
        while let Some((node, label, top)) = stack.pop() {
            match node {
                TomlNode::Table(table) => {
                    for (key, value) in table {
                        if top && exempt(VcsKind::Jujutsu, (key.as_str(), None, ""), "") {
                            continue;
                        }
                        let index = labels.len();
                        labels.push((label, key.as_str()));
                        stack.push((TomlNode::Value(value), Some(index), top && key == "--scope"));
                    }
                }
                TomlNode::Value(value) => match value {
                    toml::Value::String(text) => {
                        self.judge(ctx, &Role::Words, text).map_err(|stop| {
                            stop.into_refusal(kind, &ctx.source, || toml_setting(&labels, label))
                        })?;
                    }
                    toml::Value::Array(items) => {
                        stack.extend(items.iter().map(|item| (TomlNode::Value(item), label, top)));
                    }
                    toml::Value::Table(inner) => stack.push((TomlNode::Table(inner), label, top)),
                    toml::Value::Integer(_)
                    | toml::Value::Float(_)
                    | toml::Value::Boolean(_)
                    | toml::Value::Datetime(_) => {}
                },
            }
        }
        Ok(())
    }

    /// Judge one value by its role.
    fn judge(&mut self, ctx: &FileCtx, role: &Role, value: &str) -> Result<(), Stop> {
        match role {
            Role::Exempt => Ok(()),
            Role::Words => self.judge_words(ctx, value),
            Role::Forced(path) => {
                self.judge_words(ctx, value)?;
                self.judge_forced(ctx, path).map(drop)
            }
            Role::Include => {
                self.judge_words(ctx, value)?;
                let resolved = self.judge_forced(ctx, value)?;
                if let Some(target) = resolved.into_iter().next().filter(|r| r.exists) {
                    self.pending.push(Pending {
                        path: target.path,
                        depth: ctx.depth.saturating_add(1),
                        syntax: ctx.syntax,
                    });
                }
                Ok(())
            }
            Role::HooksPath => {
                self.judge_words(ctx, value)?;
                for target in self.judge_forced(ctx, value)? {
                    if target.exists {
                        self.list_hooks(&target.path).map_err(Stop::Refused)?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Judge every path-shaped word of `value`.
    fn judge_words(&mut self, ctx: &FileCtx, value: &str) -> Result<(), Stop> {
        if value.contains("$(") || value.contains('`') {
            return Err(Stop::Named(Named::Unprovable(
                Unprovable::CommandSubstitution,
            )));
        }
        for word in shell_words(value) {
            let compound = word.contains(is_word_separator);
            let pieces = std::iter::once(word.as_str())
                .chain(word.split(is_word_separator).filter(|_| compound));
            for piece in pieces {
                let piece = strip_runners(piece);
                if is_path_shaped(piece) {
                    self.judge_path(ctx, piece)?;
                }
            }
        }
        Ok(())
    }

    /// Judge `text` as one path whatever its shape; empty text names nothing.
    fn judge_forced(&mut self, ctx: &FileCtx, text: &str) -> Result<Vec<Resolved>, Stop> {
        let path = strip_runners(text.trim_matches(is_c_space));
        if path.is_empty() {
            return Ok(Vec::new());
        }
        self.judge_path(ctx, path)
    }

    /// Resolve `word` against every base, refusing a resolution inside a grant.
    fn judge_path(&mut self, ctx: &FileCtx, word: &str) -> Result<Vec<Resolved>, Stop> {
        self.count_path(&ctx.source).map_err(Stop::Refused)?;
        let unprovable = |why| Stop::Named(Named::Unprovable(why));
        let candidates = self.candidates(word, &ctx.bases).map_err(unprovable)?;
        let mut resolved = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let found = resolve(&candidate).map_err(unprovable)?;
            if self.grants.cover(&found.path) {
                return Err(Stop::Named(Named::InGrant(found.path)));
            }
            resolved.push(found);
        }
        Ok(resolved)
    }

    /// The absolute paths `word` may name: itself, under the home, or under each base and the working tree.
    fn candidates(&self, word: &str, bases: &[PathBuf]) -> Result<Vec<PathBuf>, Unprovable> {
        if word.len() > MAX_PATH_BYTES {
            return Err(Unprovable::TooLong);
        }
        if word.contains('$') || word.split('%').nth(2).is_some() {
            return Err(Unprovable::Expansion);
        }
        if let Some(rest) = word.strip_prefix('~') {
            let tail = if rest.is_empty() {
                ""
            } else {
                let Some(tail) = rest.strip_prefix(is_separator) else {
                    return Err(Unprovable::TildeUser);
                };
                tail
            };
            let Some(home) = &self.home.0 else {
                return Err(Unprovable::NoHome);
            };
            return Ok(vec![home.as_path().join(tail)]);
        }
        let path = Path::new(word);
        if path.is_absolute() {
            return Ok(vec![path.to_path_buf()]);
        }
        Ok(bases
            .iter()
            .map(|base| base.join(path))
            .chain(std::iter::once(self.grants.worktree.as_path().join(path)))
            .collect())
    }
}

/// A node of a parsed TOML document.
#[derive(Clone, Copy)]
enum TomlNode<'t> {
    /// A table.
    Table(&'t toml::Table),
    /// A value.
    Value(&'t toml::Value),
}

/// The setting the label `label` names, walking its parents.
fn toml_setting(labels: &[(Option<usize>, &str)], label: Option<usize>) -> ConfigSetting {
    let mut keys: Vec<&str> = Vec::new();
    let mut at = label;
    while let Some(index) = at {
        let Some(&(parent, key)) = labels.get(index) else {
            break;
        };
        keys.push(key);
        // A parent always precedes its child, so the walk strictly descends.
        at = parent.filter(|p| *p < index);
    }
    keys.reverse();
    let key = keys.pop().unwrap_or_default().to_owned();
    ConfigSetting::Key {
        section: keys.join("."),
        subsection: None,
        key,
    }
}

/// The one-based line holding byte `offset` of `text`.
fn line_of(text: &str, offset: usize) -> usize {
    text.get(..offset)
        .map_or(1, |head| head.matches('\n').count().saturating_add(1))
}

/// The directory and entry name of `path`.
fn split(path: &Path) -> Option<(&Path, EntryName)> {
    let dir = path.parent()?;
    let name = EntryName::new(path.file_name()?)?;
    Some((dir, name))
}

/// Resolve an absolute path through its longest existing prefix.
///
/// The prefix is canonicalised; the rest must not exist from its first
/// component on, and must hold no `..`, so the result is the one place the path
/// will name when it is created.
fn resolve(path: &Path) -> Result<Resolved, Unprovable> {
    if path.as_os_str().len() > MAX_PATH_BYTES || path.components().count() > MAX_PATH_COMPONENTS {
        return Err(Unprovable::TooLong);
    }
    if !path.is_absolute() {
        return Err(Unprovable::Unresolvable);
    }
    for ancestor in path.ancestors() {
        let Ok(real) = CanonicalPath::resolve(ancestor) else {
            continue;
        };
        let Ok(rest) = path.strip_prefix(ancestor) else {
            return Err(Unprovable::Unresolvable);
        };
        return below(real.as_path(), rest);
    }
    Err(Unprovable::Unresolvable)
}

/// `rest` joined below the existing canonical `real`.
fn below(real: &Path, rest: &Path) -> Result<Resolved, Unprovable> {
    let mut joined = real.to_path_buf();
    let mut exists = true;
    for component in rest.components() {
        match component {
            Component::Normal(part) => {
                if exists {
                    let next = joined.join(part);
                    match std::fs::symlink_metadata(&next) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => exists = false,
                        Ok(_) | Err(_) => return Err(Unprovable::Unresolvable),
                    }
                }
                joined.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir => return Err(Unprovable::DotDot),
            Component::RootDir | Component::Prefix(_) => return Err(Unprovable::Unresolvable),
        }
    }
    Ok(Resolved {
        path: joined,
        exists,
    })
}

/// A path separator of the host.
const fn is_separator(c: char) -> bool {
    c == '/' || (cfg!(windows) && c == '\\')
}

/// A character a shell or tool splits one word into several at.
const fn is_word_separator(c: char) -> bool {
    matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>' | '=' | ':' | ',')
}

/// C's `isspace`, which Git and Mercurial both split on.
const fn is_c_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
}

/// `word` without the prefixes that make a tool run what follows (`=`, `!`, `ext::`, `python:`).
fn strip_runners(word: &str) -> &str {
    let mut rest = word;
    while let Some(next) = rest
        .strip_prefix('=')
        .or_else(|| rest.strip_prefix('!'))
        .or_else(|| rest.strip_prefix("ext::"))
        .or_else(|| rest.strip_prefix("python:"))
    {
        rest = next;
    }
    rest
}

/// Whether `word` is shaped like a path: it holds a separator, starts with `~`, or is `.` or `..`.
fn is_path_shaped(word: &str) -> bool {
    word.contains(is_separator) || word.starts_with('~') || word == "." || word == ".."
}

/// `value` split into shell words: quotes group, a backslash escapes, whitespace separates.
///
/// An unterminated quote ends the last word at the end of the value, so its
/// text is still judged.
fn shell_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('"'), '\\') | (None, '\\') => {
                in_word = true;
                if let Some(escaped) = chars.next() {
                    word.push(escaped);
                }
            }
            (Some(_), other) => word.push(other),
            (None, '\'' | '"') => {
                in_word = true;
                quote = Some(c);
            }
            (None, other) if is_c_space(other) => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            (None, other) => {
                in_word = true;
                word.push(other);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

/// Whether `value` is a Git boolean.
fn is_git_bool(value: &str) -> bool {
    ["", "true", "false", "yes", "no", "on", "off", "1", "0"]
        .iter()
        .any(|word| value.eq_ignore_ascii_case(word))
}

/// How Git treats a value of `setting`.
fn git_role(setting: &Setting, value: &str) -> Role {
    let Setting::Key {
        section,
        subsection,
        key,
    } = setting
    else {
        return Role::Words;
    };
    let key = key.to_ascii_lowercase();
    let subsection = subsection.as_deref();
    let shape = (&**section, subsection.is_some(), key.as_str());
    if matches!(
        shape,
        ("include", false, "path") | ("includeif", true, "path")
    ) {
        return Role::Include;
    }
    if shape == ("core", false, "hookspath") {
        return Role::HooksPath;
    }
    let forced = shape == ("init", false, "templatedir")
        || (shape == ("core", false, "fsmonitor") && !is_git_bool(value));
    if forced {
        return Role::Forced(value.to_owned());
    }
    if exempt(VcsKind::Git, (&**section, subsection, key.as_str()), value) {
        Role::Exempt
    } else {
        Role::Words
    }
}

/// How Mercurial treats a value of `setting`.
fn hg_role(setting: &Setting, value: &str) -> Role {
    let (section, key) = match setting {
        Setting::Key { section, key, .. } => (section, key),
        Setting::Include => return Role::Include,
        Setting::Line(_) => return Role::Words,
    };
    if &**section == "extensions" {
        return Role::Forced(value.to_owned());
    }
    if &**section == "hooks" {
        if let Some((path, _)) = value
            .strip_prefix("python:")
            .and_then(|rest| rest.rsplit_once(':'))
        {
            return Role::Forced(path.to_owned());
        }
    }
    if exempt(VcsKind::Mercurial, (&**section, None, key.as_str()), value) {
        Role::Exempt
    } else {
        Role::Words
    }
}

/// A character stream with Git's line handling: `\r\n` reads as `\n`, the end reads as `\n`.
struct GitLexer<'t> {
    /// The remaining text.
    chars: std::iter::Peekable<std::str::Chars<'t>>,
    /// The one-based line of the last character read.
    line: usize,
    /// Whether the last character read ended a line.
    ended_line: bool,
    /// Whether the end was reached.
    eof: bool,
}

impl<'t> GitLexer<'t> {
    /// A lexer over `text`.
    fn new(text: &'t str) -> Self {
        Self {
            chars: text.chars().peekable(),
            line: 1,
            ended_line: false,
            eof: false,
        }
    }

    /// The next character; `\n` at and past the end.
    fn next_char(&mut self) -> char {
        if self.ended_line {
            self.line = self.line.saturating_add(1);
            self.ended_line = false;
        }
        let c = match self.chars.next() {
            None => {
                self.eof = true;
                return '\n';
            }
            Some('\r') if self.chars.peek() == Some(&'\n') => {
                self.chars.next();
                '\n'
            }
            Some(c) => c,
        };
        self.ended_line = c == '\n';
        c
    }
}

/// A Git key character.
const fn is_git_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// Parse Git `config` text into its values, or the line of its first syntax error.
///
/// Mirrors Git's own parser: a section header `[name]`, `[name "sub"]`, or the
/// deprecated `[name.sub]`; a key of alphanumerics and `-` starting with a
/// letter, optionally `=` and a value; quotes, the escapes `\n \t \b \" \\`, a
/// trailing `\` continuing the line, `#` and `;` comments. A key before any
/// section, an unknown escape, and an unterminated quote are errors.
fn parse_git(text: &str) -> Result<Vec<Entry>, usize> {
    let mut lexer = GitLexer::new(text.strip_prefix('\u{feff}').unwrap_or(text));
    let mut entries = Vec::new();
    let mut section: Option<(Rc<str>, Option<Rc<str>>)> = None;
    let mut comment = false;
    loop {
        let c = lexer.next_char();
        if c == '\n' {
            if lexer.eof {
                return Ok(entries);
            }
            comment = false;
            continue;
        }
        if comment || is_c_space(c) {
            continue;
        }
        if c == '#' || c == ';' {
            comment = true;
            continue;
        }
        if c == '[' {
            let (name, subsection) = git_section(&mut lexer).ok_or(lexer.line)?;
            section = Some((Rc::from(name), subsection.map(Rc::from)));
            continue;
        }
        let Some((name, subsection)) = section.as_ref().filter(|_| c.is_ascii_alphabetic()) else {
            return Err(lexer.line);
        };
        let (key, value) = git_item(&mut lexer, c).ok_or(lexer.line)?;
        entries.push(Entry {
            setting: Setting::Key {
                section: Rc::clone(name),
                subsection: subsection.clone(),
                key,
            },
            value: value.unwrap_or_default(),
        });
    }
}

/// The rest of a section header after `[`: its lowercase name and its subsection.
fn git_section(lexer: &mut GitLexer<'_>) -> Option<(String, Option<String>)> {
    let mut name = String::new();
    loop {
        let c = lexer.next_char();
        if lexer.eof || c == '\n' {
            return None;
        }
        if is_c_space(c) {
            let subsection = git_subsection(lexer)?;
            return (!name.is_empty()).then_some((name, Some(subsection)));
        }
        if c == ']' {
            if name.is_empty() {
                return None;
            }
            return Some(match name.split_once('.') {
                Some((head, tail)) => (head.to_owned(), Some(tail.to_owned())),
                None => (name, None),
            });
        }
        if !(is_git_key_char(c) || c == '.') {
            return None;
        }
        name.push(c.to_ascii_lowercase());
    }
}

/// A quoted subsection and the closing `]`, after the space that opened it.
fn git_subsection(lexer: &mut GitLexer<'_>) -> Option<String> {
    let mut c = lexer.next_char();
    while is_c_space(c) {
        if c == '\n' {
            return None;
        }
        c = lexer.next_char();
    }
    if c != '"' {
        return None;
    }
    let mut subsection = String::new();
    loop {
        let c = lexer.next_char();
        match c {
            '\n' => return None,
            '"' => break,
            '\\' => {
                let escaped = lexer.next_char();
                if escaped == '\n' {
                    return None;
                }
                subsection.push(escaped);
            }
            other => subsection.push(other),
        }
    }
    (lexer.next_char() == ']').then_some(subsection)
}

/// A key starting with `first`, and its value; `None` for a bare boolean key.
fn git_item(lexer: &mut GitLexer<'_>, first: char) -> Option<(String, Option<String>)> {
    let mut key = String::from(first);
    let mut c = lexer.next_char();
    while c != '\n' && is_git_key_char(c) {
        key.push(c);
        c = lexer.next_char();
    }
    while c == ' ' || c == '\t' {
        c = lexer.next_char();
    }
    if c == '\n' {
        return Some((key, None));
    }
    if c != '=' {
        return None;
    }
    git_value(lexer).map(|value| (key, Some(value)))
}

/// A value after `=`, through the end of its (possibly continued) line.
fn git_value(lexer: &mut GitLexer<'_>) -> Option<String> {
    let mut value = String::new();
    let mut quoted = false;
    let mut comment = false;
    let mut spaces: usize = 0;
    loop {
        let c = lexer.next_char();
        if c == '\n' {
            return (!quoted).then_some(value);
        }
        if comment {
            continue;
        }
        if is_c_space(c) && !quoted {
            if !value.is_empty() {
                spaces = spaces.saturating_add(1);
            }
            continue;
        }
        if !quoted && (c == ';' || c == '#') {
            comment = true;
            continue;
        }
        value.extend(std::iter::repeat_n(' ', spaces));
        spaces = 0;
        match c {
            '\\' => {
                let escaped = match lexer.next_char() {
                    '\n' => continue,
                    't' => '\t',
                    'b' => '\u{8}',
                    'n' => '\n',
                    other @ ('\\' | '"') => other,
                    _ => return None,
                };
                value.push(escaped);
            }
            '"' => quoted = !quoted,
            other => value.push(other),
        }
    }
}

/// Mercurial's lines: split at `\r\n`, `\n`, and `\r`.
fn hg_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .flat_map(|line| line.strip_suffix('\r').unwrap_or(line).split('\r'))
}

/// The name of a section header line (`[name]`, the name holding no `[`).
fn hg_section(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('[')?;
    let run = rest.split('[').next()?;
    let close = run.rfind(']')?;
    if close == 0 {
        return None;
    }
    run.get(..close)
}

/// The key and value of an item line (`key = value`).
fn hg_item(line: &str) -> Option<(String, String)> {
    let first = line.chars().next()?;
    if first == '=' || is_c_space(first) {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    Some((
        key.trim_end_matches(is_c_space).to_owned(),
        value.trim_matches(is_c_space).to_owned(),
    ))
}

/// The text after a directive (`%include`, `%unset`) and its separating space, when non-empty.
fn hg_directive<'l>(line: &'l str, directive: &str) -> Option<&'l str> {
    let rest = line.strip_prefix(directive)?;
    if !rest.starts_with(is_c_space) {
        return None;
    }
    let argument = rest.trim_matches(is_c_space);
    (!argument.is_empty()).then_some(argument)
}

/// Parse an `hgrc` into its values and includes, or the line of its first syntax error.
///
/// Mirrors Mercurial's own parser: an indented line continues the last item,
/// `%include` and `%unset` directives, `#` and `;` comments, `[section]`
/// headers, `key = value` items; any other line is an error.
fn parse_hg(text: &str) -> Result<Vec<Entry>, usize> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut entries: Vec<Entry> = Vec::new();
    let mut section: Rc<str> = Rc::from("");
    let mut continues = false;
    for (index, line) in hg_lines(text).enumerate() {
        let number = index.saturating_add(1);
        let trimmed = line.trim_matches(is_c_space);
        if continues {
            if line.starts_with([';', '#']) {
                continue;
            }
            if line.starts_with(is_c_space) && !trimmed.is_empty() {
                if let Some(last) = entries.last_mut() {
                    last.value.push('\n');
                    last.value.push_str(trimmed);
                }
                continue;
            }
            continues = false;
        }
        if let Some(path) = hg_directive(line, "%include") {
            entries.push(Entry {
                setting: Setting::Include,
                value: path.to_owned(),
            });
            continue;
        }
        if line.starts_with([';', '#']) || trimmed.is_empty() {
            continue;
        }
        if let Some(name) = hg_section(line) {
            section = Rc::from(name);
            continue;
        }
        if let Some((key, value)) = hg_item(line) {
            entries.push(Entry {
                setting: Setting::Key {
                    section: Rc::clone(&section),
                    subsection: None,
                    key,
                },
                value,
            });
            continues = true;
            continue;
        }
        if hg_directive(line, "%unset").is_none() {
            return Err(number);
        }
    }
    Ok(entries)
}

/// A Darcs preference file's lines, each one value.
fn parse_darcs(text: &str) -> Vec<Entry> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_matches(is_c_space).is_empty())
        .map(|(index, line)| Entry {
            setting: Setting::Line(index.saturating_add(1)),
            value: line.to_owned(),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)] // test fixtures: the scratch dirs and files must exist
mod tests {
    use super::*;
    use crate::test_dir::TestDir;

    struct Fixture {
        _dir: TestDir,
        tree: PathBuf,
        out: PathBuf,
        home: PathBuf,
        other: PathBuf,
    }

    fn fixture(label: &str) -> Fixture {
        let dir = TestDir::new(&format!("vcscfg-{label}")).expect("test dir");
        let root = dir.path().to_path_buf();
        let fixture = Fixture {
            tree: root.join("tree"),
            out: root.join("out"),
            home: root.join("home"),
            other: root.join("other"),
            _dir: dir,
        };
        for dir in [&fixture.tree, &fixture.out, &fixture.home, &fixture.other] {
            make_dir(dir);
        }
        make_dir(&fixture.tree.join(".git"));
        fixture
    }

    fn make_dir(path: &Path) {
        std::fs::create_dir_all(path).expect("create dir");
    }

    fn write(path: &Path, text: &str) {
        if let Some(dir) = path.parent() {
            make_dir(dir);
        }
        std::fs::write(path, text).expect("write fixture file");
    }

    fn canonical(path: &Path) -> CanonicalPath {
        CanonicalPath::resolve(path).expect("canonical fixture path")
    }

    fn scan_with(
        fixture: &Fixture,
        roots: &ConfigRoots<'_>,
        limits: ConfigLimits,
    ) -> Result<(), ConfigRefusal> {
        let tree = canonical(&fixture.tree);
        let other = canonical(&fixture.other);
        let grants = Grants::new(&tree, &[&other]);
        let home = Home::known(canonical(&fixture.home));
        scan(roots, &grants, &home, limits)
    }

    fn scan_git_at(fixture: &Fixture, gitdir: &Path) -> Result<(), ConfigRefusal> {
        let roots = ConfigRoots::Git {
            gitdir,
            commondir: None,
        };
        scan_with(fixture, &roots, ConfigLimits::DEFAULT)
    }

    fn scan_git(fixture: &Fixture) -> Result<(), ConfigRefusal> {
        scan_git_at(fixture, &fixture.tree.join(".git"))
    }

    fn git_config(fixture: &Fixture, text: &str) {
        write(&fixture.tree.join(".git/config"), text);
    }

    fn in_grant(result: &Result<(), ConfigRefusal>) -> Option<&Path> {
        match result {
            Err(ConfigRefusal::NamesWritableCode {
                named: Named::InGrant(path),
                ..
            }) => Some(path.as_path()),
            Ok(()) | Err(_) => None,
        }
    }

    fn unprovable(result: &Result<(), ConfigRefusal>) -> Option<Unprovable> {
        match result {
            Err(ConfigRefusal::NamesWritableCode {
                named: Named::Unprovable(why),
                ..
            }) => Some(*why),
            Ok(()) | Err(_) => None,
        }
    }

    fn fault(result: &Result<(), ConfigRefusal>) -> Option<ConfigFault> {
        match result {
            Err(ConfigRefusal::Unreadable { fault, .. }) => Some(*fault),
            Ok(()) | Err(_) => None,
        }
    }

    fn source(result: &Result<(), ConfigRefusal>) -> Option<&Path> {
        match result {
            Err(ConfigRefusal::NamesWritableCode { source, .. }) => Some(source.as_path()),
            Ok(()) | Err(_) => None,
        }
    }

    #[test]
    fn absent_config_admitted_and_absent_root_refused() {
        let f = fixture("absent");
        assert_eq!(scan_git(&f), Ok(()));
        let missing = f.out.join("no-such-gitdir");
        let result = scan_git_at(&f, &missing);
        assert_eq!(fault(&result), Some(ConfigFault::Open(OpenRefusal::Absent)));
    }

    #[test]
    fn git_hooks_path_in_tree_refused() {
        let f = fixture("hookspath");
        git_config(
            &f,
            "[core]\n\trepositoryformatversion = 0\n\thooksPath = .githooks\n",
        );
        let result = scan_git(&f);
        assert_eq!(
            in_grant(&result),
            Some(f.tree.join(".git/.githooks").as_path())
        );
        assert!(
            matches!(
                &result,
                Err(ConfigRefusal::NamesWritableCode {
                    setting: ConfigSetting::Key { key, .. },
                    ..
                }) if key == "hooksPath"
            ),
            "{result:?}"
        );
        let outside = f.out.join("hooks");
        make_dir(&outside);
        write(&outside.join("pre-commit"), "#!/bin/sh\n");
        let shown = outside.display();
        git_config(&f, &format!("[core]\n\thooksPath = {shown}\n"));
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn include_path_in_tree_refused() {
        let f = fixture("include");
        let tree = f.tree.display();
        git_config(&f, &format!("[include]\n\tpath = {tree}/shared.cfg\n"));
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("shared.cfg").as_path()));

        let outside = f.out.join("shared.cfg");
        write(&outside, &format!("[core]\n\thooksPath = {tree}/hooks\n"));
        let shown = outside.display();
        git_config(&f, &format!("[include]\n\tpath = {shown}\n"));
        let result = scan_git(&f);
        assert_eq!(source(&result), Some(outside.as_path()));
        assert_eq!(in_grant(&result), Some(f.tree.join("hooks").as_path()));
    }

    #[test]
    fn includeif_inactive_still_scanned() {
        let f = fixture("includeif");
        let tree = f.tree.display();
        let included = f.out.join("work.cfg");
        write(&included, &format!("[alias]\n\tci = !{tree}/bin/ci\n"));
        let shown = included.display();
        git_config(
            &f,
            &format!("[includeIf \"gitdir:/no/such/place/\"]\n\tpath = {shown}\n"),
        );
        let result = scan_git(&f);
        assert_eq!(source(&result), Some(included.as_path()));
        assert_eq!(in_grant(&result), Some(f.tree.join("bin/ci").as_path()));
    }

    #[test]
    fn config_worktree_scanned_without_extension() {
        let f = fixture("cfgworktree");
        git_config(&f, "[core]\n\trepositoryformatversion = 0\n");
        let tree = f.tree.display();
        let worktree_config = f.tree.join(".git/config.worktree");
        write(
            &worktree_config,
            &format!("[core]\n\thooksPath = {tree}/h\n"),
        );
        let result = scan_git(&f);
        assert_eq!(source(&result), Some(worktree_config.as_path()));
        assert_eq!(in_grant(&result), Some(f.tree.join("h").as_path()));
    }

    #[test]
    fn relative_value_resolves_both_bases() {
        let f = fixture("bases");
        let outside_gitdir = f.out.join("gitdir");
        write(&outside_gitdir.join("config"), "[alias]\n\tx = !bin/run\n");
        let result = scan_git_at(&f, &outside_gitdir);
        assert_eq!(in_grant(&result), Some(f.tree.join("bin/run").as_path()));

        let granted_gitdir = f.other.join("gitdir");
        write(&granted_gitdir.join("config"), "[alias]\n\tx = !bin/run\n");
        let result = scan_git_at(&f, &granted_gitdir);
        assert_eq!(
            in_grant(&result),
            Some(granted_gitdir.join("bin/run").as_path())
        );
    }

    #[test]
    fn unknown_key_with_in_tree_path_refused() {
        let f = fixture("unknownkey");
        let tree = f.tree.display();
        git_config(
            &f,
            &format!("[frobnicate \"x\"]\n\trunner = sh -c {tree}/run.sh\n"),
        );
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("run.sh").as_path()));
        git_config(&f, "[frobnicate \"x\"]\n\trunner = sh -c true\n");
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn command_substitution_refused() {
        let f = fixture("cmdsubst");
        git_config(&f, "[alias]\n\tx = !echo $(id -u)\n");
        assert_eq!(
            unprovable(&scan_git(&f)),
            Some(Unprovable::CommandSubstitution)
        );
        git_config(&f, "[alias]\n\tx = !echo `id -u`\n");
        assert_eq!(
            unprovable(&scan_git(&f)),
            Some(Unprovable::CommandSubstitution)
        );
        git_config(&f, "[alias]\n\tx = !$HOME/bin/x\n");
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::Expansion));
    }

    #[test]
    fn tilde_user_refused() {
        let f = fixture("tildeuser");
        git_config(&f, "[alias]\n\tx = !~root/bin/x\n");
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::TildeUser));
        git_config(&f, "[alias]\n\tx = !~/bin/x\n");
        assert_eq!(scan_git(&f), Ok(()));
        let tree = canonical(&f.tree);
        let grants = Grants::new(&tree, &[]);
        let roots = ConfigRoots::Git {
            gitdir: &f.tree.join(".git"),
            commondir: None,
        };
        let result = scan(&roots, &grants, &Home::unknown(), ConfigLimits::DEFAULT);
        assert_eq!(unprovable(&result), Some(Unprovable::NoHome));
    }

    #[test]
    fn dotdot_remainder_refused() {
        let f = fixture("dotdot");
        let out = f.out.display();
        git_config(&f, &format!("[alias]\n\tx = !{out}/missing/../evil\n"));
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::DotDot));
        make_dir(&f.out.join("present"));
        git_config(&f, &format!("[alias]\n\tx = !{out}/present/../evil\n"));
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn noncode_key_admitted() {
        let f = fixture("noncode");
        let tree = f.tree.display();
        git_config(
            &f,
            &format!(
                "[core]\n\tbare = false\n\tworktree = {tree}\n\texcludesFile = {tree}/.ignore\n\
                 \tfsmonitor = true\n\
                 [remote \"origin\"]\n\turl = git@example.com:team/tree.git\n\
                 \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
                 [branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n\
                 [user]\n\tname = A Person\n\
                 [extensions]\n\tworktreeConfig = true\n"
            ),
        );
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn ext_url_refused() {
        let f = fixture("exturl");
        let tree = f.tree.display();
        git_config(
            &f,
            &format!("[remote \"origin\"]\n\turl = ext::{tree}/transport %S\n"),
        );
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("transport").as_path()));
    }

    #[test]
    fn fsmonitor_hook_path_refused() {
        let f = fixture("fsmonitor");
        git_config(&f, "[core]\n\tfsmonitor = fsmonitor-hook\n");
        let result = scan_git(&f);
        assert_eq!(
            in_grant(&result),
            Some(f.tree.join(".git/fsmonitor-hook").as_path())
        );
    }

    #[test]
    fn malformed_git_line_refused() {
        let f = fixture("malformed");
        for (text, line) in [
            ("[core\n", 1),
            ("bare = true\n", 1),
            ("[core]\n\tbare = \"unterminated\n", 2),
            ("[core]\n\tx = a\\qb\n", 2),
            ("[core]\n\n\t9key = 1\n", 3),
        ] {
            git_config(&f, text);
            let result = scan_git(&f);
            assert_eq!(
                fault(&result),
                Some(ConfigFault::Malformed { line }),
                "{text:?}"
            );
        }
    }

    #[test]
    fn git_parser_follows_git_syntax() {
        let text = "\u{feff}# c\n[Core]\n\tBare\n[a \"Sub\\\"x\"] k = \"v ; w\" # tail\n\
                    [b.Sub]\n\tz = one\\\n two\n\tq = a\\tb\r\n";
        let parsed = parse_git(text).expect("valid git config");
        let shapes: Vec<(String, Option<String>, String, String)> = parsed
            .iter()
            .filter_map(|entry| match &entry.setting {
                Setting::Key {
                    section,
                    subsection,
                    key,
                } => Some((
                    section.to_string(),
                    subsection.as_ref().map(ToString::to_string),
                    key.clone(),
                    entry.value.clone(),
                )),
                Setting::Include | Setting::Line(_) => None,
            })
            .collect();
        let expected = [
            ("core", None, "Bare", ""),
            ("a", Some("Sub\"x"), "k", "v ; w"),
            ("b", Some("sub"), "z", "one two"),
            ("b", Some("sub"), "q", "a\tb"),
        ];
        assert_eq!(shapes.len(), expected.len(), "{shapes:?}");
        for (got, want) in shapes.iter().zip(expected) {
            assert_eq!(got.0, want.0);
            assert_eq!(got.1.as_deref(), want.1);
            assert_eq!(got.2, want.2);
            assert_eq!(got.3, want.3);
        }
    }

    #[test]
    fn hg_include_and_extensions_refused() {
        let f = fixture("hg");
        let dot_hg = f.tree.join(".hg");
        let tree = f.tree.display();
        let out = f.out.display();
        let roots = ConfigRoots::Mercurial {
            dot_hg: &dot_hg,
            shared: None,
        };
        write(
            &dot_hg.join("hgrc"),
            &format!(
                "[paths]\ndefault = {tree}\n[ui]\nusername = A <a@example.com>\n\
                 [extensions]\nrebase =\n[hooks]\nx = python:hgext.hook.run\n\
                 y = python:{out}/hook.py:run\n"
            ),
        );
        assert_eq!(scan_with(&f, &roots, ConfigLimits::DEFAULT), Ok(()));

        write(&dot_hg.join("hgrc"), &format!("%include {tree}/team.rc\n"));
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(f.tree.join("team.rc").as_path()));
        assert!(
            matches!(
                &result,
                Err(ConfigRefusal::NamesWritableCode {
                    setting: ConfigSetting::Include,
                    ..
                })
            ),
            "{result:?}"
        );

        write(&dot_hg.join("hgrc"), "[extensions]\nlocal = ext/local.py\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(
            in_grant(&result),
            Some(dot_hg.join("ext/local.py").as_path())
        );

        write(&dot_hg.join("hgrc"), "[extensions]\nlocal = local.py\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(dot_hg.join("local.py").as_path()));

        write(
            &dot_hg.join("hgrc"),
            "[hooks]\ncommit = python:hook.py:run\n",
        );
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(dot_hg.join("hook.py").as_path()));

        write(&dot_hg.join("hgrc"), "[ui]\nnot an item\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(fault(&result), Some(ConfigFault::Malformed { line: 2 }));
    }

    #[test]
    fn jj_toml_deep_nesting_errors() {
        let f = fixture("jj");
        let dot_jj = f.tree.join(".jj");
        let repo = dot_jj.join("repo");
        make_dir(&repo);
        let roots = ConfigRoots::Jujutsu {
            dot_jj: &dot_jj,
            repo: &repo,
        };
        let deep = format!("a = {}{}\n", "[".repeat(300), "]".repeat(300));
        write(&repo.join("config.toml"), &deep);
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert!(
            matches!(fault(&result), Some(ConfigFault::Malformed { .. })),
            "{result:?}"
        );

        let tree = f.tree.display();
        write(
            &repo.join("config.toml"),
            &format!(
                "[user]\nname = \"A\"\n[templates]\nlog = \"{tree}/x\"\n\
                 [[--scope]]\n--when.repositories = [\"/elsewhere\"]\n\
                 [--scope.revset-aliases]\n\"mine()\" = \"{tree}/y\"\n"
            ),
        );
        assert_eq!(scan_with(&f, &roots, ConfigLimits::DEFAULT), Ok(()));

        write(
            &repo.join("config.toml"),
            &format!("[fix.tools.fmt]\ncommand = [\"{tree}/fmt\", \"--stdin\"]\n"),
        );
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(f.tree.join("fmt").as_path()));
        assert!(
            matches!(
                &result,
                Err(ConfigRefusal::NamesWritableCode {
                    setting: ConfigSetting::Key { section, key, .. },
                    ..
                }) if section == "fix.tools.fmt" && key == "command"
            ),
            "{result:?}"
        );

        write(
            &dot_jj.join("workspace.toml"),
            &format!(
                "[[--scope]]\n--when.commands = [\"log\"]\n[--scope.ui]\npager = \"{tree}/pager\"\n"
            ),
        );
        write(&repo.join("config.toml"), "");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(f.tree.join("pager").as_path()));
    }

    #[test]
    fn darcs_test_pref_refused() {
        let f = fixture("darcs");
        let dot_darcs = f.tree.join("_darcs");
        let roots = ConfigRoots::Darcs {
            dot_darcs: &dot_darcs,
        };
        write(&dot_darcs.join("prefs/prefs"), "test make check\n");
        assert_eq!(scan_with(&f, &roots, ConfigLimits::DEFAULT), Ok(()));
        write(&dot_darcs.join("prefs/prefs"), "\ntest ./run-tests.sh\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(
            in_grant(&result),
            Some(dot_darcs.join("prefs/run-tests.sh").as_path())
        );
        assert!(
            matches!(
                &result,
                Err(ConfigRefusal::NamesWritableCode {
                    setting: ConfigSetting::Line(2),
                    ..
                })
            ),
            "{result:?}"
        );
        write(&dot_darcs.join("prefs/prefs"), "");
        write(&dot_darcs.join("prefs/defaults"), "apply posthook ./hook\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(
            in_grant(&result),
            Some(dot_darcs.join("prefs/hook").as_path())
        );
    }

    #[cfg(unix)]
    fn link(target: &Path, at: &Path) {
        std::os::unix::fs::symlink(target, at).expect("create link");
    }

    #[cfg(unix)]
    fn link_named(result: &Result<(), ConfigRefusal>) -> Option<(&Path, &Path)> {
        match result {
            Err(ConfigRefusal::LinkNamesWritable {
                link,
                named: Named::InGrant(path),
                ..
            }) => Some((link.as_path(), path.as_path())),
            Ok(()) | Err(_) => None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn hooks_symlink_into_tree_refused() {
        let f = fixture("hooklink");
        let hooks = f.tree.join(".git/hooks");
        make_dir(&hooks);
        write(&hooks.join("pre-commit.sample"), "#!/bin/sh\n");
        write(&f.out.join("tool"), "#!/bin/sh\n");
        link(&f.out.join("tool"), &hooks.join("post-checkout"));
        assert_eq!(scan_git(&f), Ok(()));

        write(&f.tree.join("evil.sh"), "#!/bin/sh\n");
        link(&f.tree.join("evil.sh"), &hooks.join("pre-commit"));
        let result = scan_git(&f);
        assert_eq!(
            link_named(&result),
            Some((
                hooks.join("pre-commit").as_path(),
                f.tree.join("evil.sh").as_path()
            ))
        );

        let gitdir = f.out.join("gitdir");
        make_dir(&gitdir);
        make_dir(&f.tree.join("hooks"));
        link(&f.tree.join("hooks"), &gitdir.join("hooks"));
        let result = scan_git_at(&f, &gitdir);
        assert_eq!(
            link_named(&result),
            Some((
                gitdir.join("hooks").as_path(),
                f.tree.join("hooks").as_path()
            ))
        );

        let elsewhere = f.out.join("hooks-elsewhere");
        make_dir(&elsewhere);
        link(&f.tree.join("evil.sh"), &elsewhere.join("pre-push"));
        let shown = elsewhere.display();
        write(
            &gitdir.join("config"),
            &format!("[core]\n\thooksPath = {shown}\n"),
        );
        std::fs::remove_file(gitdir.join("hooks")).expect("remove hooks link");
        let result = scan_git_at(&f, &gitdir);
        assert_eq!(
            link_named(&result),
            Some((
                elsewhere.join("pre-push").as_path(),
                f.tree.join("evil.sh").as_path()
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn config_symlink_into_tree_refused() {
        let f = fixture("cfglink");
        let gitdir = f.out.join("gitdir");
        make_dir(&gitdir);
        write(&f.tree.join("planted.cfg"), "[core]\n\tbare = false\n");
        link(&f.tree.join("planted.cfg"), &gitdir.join("config"));
        let result = scan_git_at(&f, &gitdir);
        assert_eq!(
            link_named(&result),
            Some((
                gitdir.join("config").as_path(),
                f.tree.join("planted.cfg").as_path()
            ))
        );

        std::fs::remove_file(gitdir.join("config")).expect("remove config link");
        let tree = f.tree.display();
        let real = f.out.join("real.cfg");
        write(&real, &format!("[core]\n\thooksPath = {tree}/h\n"));
        link(&real, &gitdir.join("config"));
        let result = scan_git_at(&f, &gitdir);
        assert_eq!(in_grant(&result), Some(f.tree.join("h").as_path()));

        write(&real, "[core]\n\tbare = false\n");
        assert_eq!(scan_git_at(&f, &gitdir), Ok(()));
    }

    fn limits_with(change: impl FnOnce(&mut ConfigLimits)) -> ConfigLimits {
        let mut limits = ConfigLimits::DEFAULT;
        change(&mut limits);
        limits
    }

    fn scan_git_limited(f: &Fixture, limits: ConfigLimits) -> Result<(), ConfigRefusal> {
        let gitdir = f.tree.join(".git");
        let roots = ConfigRoots::Git {
            gitdir: &gitdir,
            commondir: None,
        };
        scan_with(f, &roots, limits)
    }

    #[test]
    fn config_byte_file_depth_ceilings() {
        let f = fixture("ceilings");
        let eight = ByteCap::new(8).expect("non-zero cap");
        git_config(&f, "[a]\nb=1\n");
        let at_cap = limits_with(|l| l.file_bytes = eight);
        assert_eq!(scan_git_limited(&f, at_cap), Ok(()));
        git_config(&f, "[a]\nb=12\n");
        assert_eq!(
            fault(&scan_git_limited(&f, at_cap)),
            Some(ConfigFault::Open(OpenRefusal::TooLarge(eight)))
        );

        git_config(&f, "[a]\nb=1\n");
        write(&f.tree.join(".git/config.worktree"), "[a]\nc=1\n");
        let two_files = limits_with(|l| l.files = nonzero_u32(2));
        assert_eq!(scan_git_limited(&f, two_files), Ok(()));
        let one_file = limits_with(|l| l.files = nonzero_u32(1));
        assert_eq!(
            fault(&scan_git_limited(&f, one_file)),
            Some(ConfigFault::Files)
        );
        let sixteen = limits_with(|l| l.total_bytes = nonzero_u64(16));
        assert_eq!(scan_git_limited(&f, sixteen), Ok(()));
        let fifteen = limits_with(|l| l.total_bytes = nonzero_u64(15));
        assert_eq!(
            fault(&scan_git_limited(&f, fifteen)),
            Some(ConfigFault::Bytes)
        );
        std::fs::remove_file(f.tree.join(".git/config.worktree")).expect("remove file");

        let first = f.out.join("first.cfg");
        let second = f.out.join("second.cfg");
        write(
            &first,
            &format!("[include]\n\tpath = {}\n", second.display()),
        );
        write(&second, "[a]\nb=1\n");
        git_config(&f, &format!("[include]\n\tpath = {}\n", first.display()));
        let depth_two = limits_with(|l| l.include_depth = nonzero_u32(2));
        assert_eq!(scan_git_limited(&f, depth_two), Ok(()));
        let depth_one = limits_with(|l| l.include_depth = nonzero_u32(1));
        assert_eq!(
            fault(&scan_git_limited(&f, depth_one)),
            Some(ConfigFault::IncludeDepth)
        );

        let cycle = f.out.join("cycle.cfg");
        write(
            &cycle,
            &format!("[include]\n\tpath = {}\n", cycle.display()),
        );
        git_config(&f, &format!("[include]\n\tpath = {}\n", cycle.display()));
        assert_eq!(
            fault(&scan_git_limited(&f, ConfigLimits::DEFAULT)),
            Some(ConfigFault::IncludeDepth)
        );

        let out = f.out.display();
        git_config(&f, &format!("[alias]\n\tx = !{out}/a {out}/b\n"));
        let two_paths = limits_with(|l| l.paths = nonzero_u32(2));
        assert_eq!(scan_git_limited(&f, two_paths), Ok(()));
        let one_path = limits_with(|l| l.paths = nonzero_u32(1));
        assert_eq!(
            fault(&scan_git_limited(&f, one_path)),
            Some(ConfigFault::Paths)
        );

        git_config(&f, "");
        let hooks = f.tree.join(".git/hooks");
        write(&hooks.join("a.sample"), "");
        write(&hooks.join("b.sample"), "");
        let two_entries = limits_with(|l| l.listing = EntryCap::from_nonzero(nonzero_u32(2)));
        assert_eq!(scan_git_limited(&f, two_entries), Ok(()));
        let one_entry = EntryCap::from_nonzero(nonzero_u32(1));
        let one_listed = limits_with(|l| l.listing = one_entry);
        assert_eq!(
            fault(&scan_git_limited(&f, one_listed)),
            Some(ConfigFault::Open(OpenRefusal::TooManyEntries(one_entry)))
        );
    }

    #[test]
    fn vcs_display_escapes_control_bytes() {
        let refusal = |source: &str, key: &str| ConfigRefusal::NamesWritableCode {
            kind: VcsKind::Git,
            source: PathBuf::from(source),
            setting: ConfigSetting::Key {
                section: "alias".to_owned(),
                subsection: None,
                key: key.to_owned(),
            },
            named: Named::InGrant(PathBuf::from("/tree/\u{1b}[2Jx")),
        };
        let shown = refusal("/a\nb", "k\u{202e}").to_string();
        assert!(!shown.contains('\n'), "{shown}");
        assert!(!shown.contains('\u{1b}'), "{shown}");
        assert!(!shown.contains('\u{202e}'), "{shown}");
        assert!(shown.contains("/a\\u{a}b"), "{shown}");
        assert!(shown.contains("alias.k\\u{202e}"), "{shown}");
        assert!(
            shown.contains("point the setting outside the writable grants"),
            "{shown}"
        );
        let literal = refusal("/a\\u{a}b", "k").to_string();
        let raw = refusal("/a\nb", "k").to_string();
        assert_ne!(literal, raw);
    }
}
