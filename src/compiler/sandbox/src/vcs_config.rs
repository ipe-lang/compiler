//! Detection of version-control configuration that names host-run code inside a writable grant.
//!
//! A carved VCS metadata directory keeps a jailed program from rewriting the
//! hooks a host tool runs, but the tool also reads configuration that can point
//! anywhere: `core.hooksPath`, an `include.path`, an alias, a remote URL, a
//! Mercurial extension, a Jujutsu fix tool, a Darcs test command. When any
//! value names a path inside a writable grant, the jailed program can plant
//! code the host later runs outside the jail. [`scan`] reads every
//! configuration file the tool reads from the carved metadata, follows its
//! includes, and refuses when a value names such a path or cannot be proven
//! not to.
//!
//! The scan fails closed. Every value is split into words, under every setting
//! but the few [`NON_CODE`] lists as never naming code. A path-shaped word is
//! resolved against the configuration file's directory and the working tree,
//! `~` through the injected [`Home`]; an option's argument is judged as a word
//! of its own and the option word whole besides; a program name passes, as the
//! setting's tool composes it: less only the one runner prefix (`!`,
//! `python:`) that tool consumes (anywhere else `!/x` is a relative path), and
//! with the `git-` a Git alias, credential helper, or remote helper names a
//! program by, and whole, `~` and spaces included, where the tool runs it
//! without a shell; any other word, a `--` or `-` ending a
//! program's options, a command substitution, an expansion, a glob or brace
//! expansion, another user's home, an `ext::` transport, or a relative `..` is
//! unprovable and refuses. Every path is judged twice: lexically against the
//! grants, and by a walk that opens each component through a held directory
//! handle, follows each link it meets (at most [`MAX_LINKS`]), and refuses a
//! link stored inside a writable grant and any component that lands inside
//! one. A configuration file or hook that is a hard link refuses. Every loop
//! is bounded by [`ConfigLimits`] or a declared constant, and every
//! unreadable, oversized, or malformed file refuses.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Write as _};
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use ipe_fs_open::{
    ByteCap, EntryCap, EntryName, FileId, FileKind, HeldDir, OpenRefusal, RegularFile,
};

use crate::covers::path_covers;
use crate::mounts::CanonicalPath;
use crate::vcs_metadata::VcsKind;

/// The longest path-shaped word or link target, in bytes, the resolver takes.
pub const MAX_PATH_BYTES: usize = 4096;

/// The most components a path-shaped word or link target may have.
pub const MAX_PATH_COMPONENTS: usize = 256;

/// The most links one path walk follows.
pub const MAX_LINKS: u32 = 40;

/// The most words one value splits into, options' arguments included.
pub const MAX_WORDS: u32 = 4096;

/// The deepest nesting of Git submodule directories the scan reads.
pub const MAX_MODULE_DEPTH: u32 = 32;

/// The most steps one path walk takes, links' targets included.
const MAX_WALK_STEPS: u32 = 8192;

/// The most URL rewrites (Git `insteadOf` and `pushInsteadOf`, Mercurial `[schemes]`) one scan reads.
pub const MAX_URL_REWRITES: usize = 256;

/// The most pairs of a URL rewrite and a URL form one scan composes, each step of a Mercurial scheme chain included.
pub const MAX_REWRITE_PAIRS: usize = 16384;

/// The most URL values one scan keeps to judge once every file is read, in each of its lists.
pub const MAX_URL_VALUES: usize = 16384;

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
    /// The most path-shaped words, links, and submodule directories one scan resolves.
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

/// The writable grants a jail binds, and the carved directories it binds read-only inside them.
#[derive(Debug, Clone)]
pub struct Grants<'g> {
    /// The working tree, the base a relative command word is also resolved against.
    worktree: &'g CanonicalPath,
    /// Every writable grant, the working tree included.
    writable: Vec<&'g CanonicalPath>,
    /// The directories carved read-only out of the grants.
    carves: Vec<&'g CanonicalPath>,
}

impl<'g> Grants<'g> {
    /// The grants of a jail binding `worktree` and `others` writable, with nothing carved.
    #[must_use]
    pub fn new(worktree: &'g CanonicalPath, others: &[&'g CanonicalPath]) -> Self {
        let mut writable = Vec::with_capacity(others.len().saturating_add(1));
        writable.push(worktree);
        writable.extend_from_slice(others);
        Self {
            worktree,
            writable,
            carves: Vec::new(),
        }
    }

    /// These grants with `carves` bound read-only inside them.
    #[must_use]
    pub fn with_carves(mut self, carves: &[&'g CanonicalPath]) -> Self {
        self.carves.extend_from_slice(carves);
        self
    }

    /// Whether `path` lies inside a writable grant and not lexically inside a carve of it.
    fn covers(&self, path: &Path) -> bool {
        let plain = lexical(path);
        self.writable.iter().any(|grant| {
            path_covers(grant.as_path(), path)
                && !self.carves.iter().any(|carve| {
                    plain.starts_with(carve.as_path())
                        && carve.as_path().starts_with(grant.as_path())
                })
        })
    }
}

/// `path` with `.` dropped and each `..` removing the component before it, without touching the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut plain = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                plain.pop();
            }
            Component::CurDir => {}
            Component::Normal(_) | Component::RootDir | Component::Prefix(_) => {
                plain.push(component);
            }
        }
    }
    plain
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
    /// Every key whose part after its last `:` is this sub-option (Mercurial's `name:option`).
    Suboption(&'static str),
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
}

impl NonCode {
    /// A pattern over `kind`'s `section`.
    const fn new(
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
        }
    }

    /// Whether this pattern matches the setting.
    fn matches(&self, kind: VcsKind, setting: (&str, Option<&str>, &str)) -> bool {
        let (section, subsection, key) = setting;
        let subsection_ok = match self.subsection {
            SubsectionMatch::Absent => subsection.is_none(),
            SubsectionMatch::Present => subsection.is_some(),
            SubsectionMatch::Either => true,
        };
        let key_ok = match self.key {
            KeyMatch::Any => true,
            KeyMatch::Named(name) => name == key,
            KeyMatch::Suboption(name) => key.rsplit_once(':').is_some_and(|(_, sub)| sub == name),
        };
        self.kind == kind && self.section == section && subsection_ok && key_ok
    }
}

/// Every setting exempt from the scan, the one list of them.
///
/// Git keys are lowercase, as Git compares them. Git's refspecs
/// (`remote.*.fetch`, `remote.*.push`) are listed because every clone writes
/// one shaped like a path, and a refspec names refs, never a file. A remote or
/// submodule URL is never exempt: it is admitted only when it is a network URL
/// or names a defined remote, and judged as a path otherwise.
pub const NON_CODE: &[NonCode] = &[
    NonCode::new(
        VcsKind::Git,
        "core",
        SubsectionMatch::Absent,
        KeyMatch::Named("worktree"),
    ),
    NonCode::new(
        VcsKind::Git,
        "core",
        SubsectionMatch::Absent,
        KeyMatch::Named("excludesfile"),
    ),
    NonCode::new(
        VcsKind::Git,
        "core",
        SubsectionMatch::Absent,
        KeyMatch::Named("attributesfile"),
    ),
    NonCode::new(
        VcsKind::Git,
        "commit",
        SubsectionMatch::Absent,
        KeyMatch::Named("template"),
    ),
    NonCode::new(
        VcsKind::Git,
        "blame",
        SubsectionMatch::Absent,
        KeyMatch::Named("ignorerevsfile"),
    ),
    NonCode::new(
        VcsKind::Git,
        "branch",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::new(VcsKind::Git, "user", SubsectionMatch::Either, KeyMatch::Any),
    NonCode::new(
        VcsKind::Git,
        "remote",
        SubsectionMatch::Present,
        KeyMatch::Named("fetch"),
    ),
    NonCode::new(
        VcsKind::Git,
        "remote",
        SubsectionMatch::Present,
        KeyMatch::Named("push"),
    ),
    NonCode::new(
        VcsKind::Git,
        "url",
        SubsectionMatch::Present,
        KeyMatch::Named("insteadof"),
    ),
    NonCode::new(
        VcsKind::Git,
        "url",
        SubsectionMatch::Present,
        KeyMatch::Named("pushinsteadof"),
    ),
    NonCode::new(
        VcsKind::Mercurial,
        "paths",
        SubsectionMatch::Absent,
        KeyMatch::Suboption("pushrev"),
    ),
    NonCode::new(
        VcsKind::Mercurial,
        "ui",
        SubsectionMatch::Absent,
        KeyMatch::Named("username"),
    ),
    NonCode::new(
        VcsKind::Jujutsu,
        "revset-aliases",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::new(
        VcsKind::Jujutsu,
        "templates",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::new(
        VcsKind::Jujutsu,
        "template-aliases",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::new(
        VcsKind::Jujutsu,
        "colors",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::new(
        VcsKind::Jujutsu,
        "user",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
    NonCode::new(
        VcsKind::Jujutsu,
        "--when",
        SubsectionMatch::Either,
        KeyMatch::Any,
    ),
];

/// Whether [`NON_CODE`] exempts the setting.
fn exempt(kind: VcsKind, setting: (&str, Option<&str>, &str)) -> bool {
    NON_CODE
        .iter()
        .any(|pattern| pattern.matches(kind, setting))
}

/// The setting a refused value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSetting {
    /// A key under a section and optional subsection.
    Key {
        /// The section; empty for a key outside any section.
        section: Box<str>,
        /// The subsection, when the key has one.
        subsection: Option<Box<str>>,
        /// The key.
        key: Box<str>,
    },
    /// A Jujutsu value, by the path of table keys leading to it.
    Table(Vec<String>),
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
                let head = Some(&**section).filter(|text| !text.is_empty());
                let parts = head
                    .into_iter()
                    .chain(subsection.as_deref())
                    .chain(std::iter::once(&**key));
                write_parts(f, parts)
            }
            Self::Table(parts) => write_parts(f, parts.iter().map(String::as_str)),
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
    /// The value expands a variable (`$NAME`, `%NAME%`) or interpolates a path (`%(prefix)`).
    Expansion,
    /// A path-shaped word names another user's home (`~user`).
    TildeUser,
    /// A path-shaped word starts with `~` and no home directory is known.
    NoHome,
    /// A `..` follows a missing directory or one inside a writable grant, or a relative command word holds one.
    DotDot,
    /// The path names an entry that exists but cannot be walked, or follows more than [`MAX_LINKS`] links.
    Unresolvable,
    /// The word or a link target is longer than [`MAX_PATH_BYTES`] or has more than [`MAX_PATH_COMPONENTS`] components.
    TooLong,
    /// A word is neither a program name, a path, nor an option.
    BareWord,
    /// A word is `--` or `-`, after which a program may read any later word, one shaped like an option included, as a file.
    EndOfOptions,
    /// A word holds a glob character (`*`, `?`, `[`) or a brace (`{`, `}`), which the shell expands into words.
    Glob,
    /// The value or its subsection names Git's `ext::` transport, which runs a program.
    ExtTransport,
    /// The file has more than one name.
    HardLinked,
    /// The value splits into more than [`MAX_WORDS`] words.
    TooManyWords,
    /// The value holds a carriage return, vertical tab, or form feed, which tools split words at differently.
    OddSpace,
    /// The value or its setting's name holds a NUL, at which a tool reading it as a C string ends the text.
    Nul,
    /// A Mercurial list value holds a quote, which Mercurial's list parser groups and unescapes into items.
    ListQuote,
    /// The value lets Git hand a URL the scan does not read (one in `.gitmodules`, one typed on a command line) to a remote helper.
    ///
    /// A URL rewrite to a base Git may read as `<helper>::` once a URL's text
    /// follows it (`hg:`, `gcrypt:`), or a `protocol.<name>.allow` letting a
    /// helper run from any URL, turns such a URL into a program run on a
    /// path the jail writes.
    RemoteHelper,
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
            Self::DotDot => f.write_str(
                "it climbs with `..` out of a directory that does not exist or lies inside a \
                 writable grant, or from the directory the tool runs in",
            ),
            Self::Unresolvable => write!(
                f,
                "it names an entry that exists but cannot be walked, or follows more than \
                 {MAX_LINKS} links"
            ),
            Self::TooLong => write!(
                f,
                "it is longer than {MAX_PATH_BYTES} bytes or {MAX_PATH_COMPONENTS} components"
            ),
            Self::BareWord => f.write_str(
                "it holds a word that is not a path or an option, which may name a file \
                 relative to the directory the tool runs in",
            ),
            Self::EndOfOptions => f.write_str(
                "it holds `--` or `-`, after which a program may read any word, one shaped like \
                 an option included, as a file relative to the directory the tool runs in",
            ),
            Self::Glob => f.write_str(
                "it holds a glob pattern or a brace expansion, which the shell expands into \
                 words the scan does not see",
            ),
            Self::ExtTransport => f.write_str("it runs a program through Git's `ext::` transport"),
            Self::HardLinked => f.write_str(
                "it is a hard link, so another name of the same file may lie inside a writable \
                 grant",
            ),
            Self::TooManyWords => write!(f, "it splits into more than {MAX_WORDS} words"),
            Self::OddSpace => f.write_str(
                "it holds a carriage return, vertical tab, or form feed, which the shell and the \
                 tool split words at differently",
            ),
            Self::Nul => f.write_str(
                "it holds a NUL byte, at which the tool ends the text while the scan reads on",
            ),
            Self::ListQuote => f.write_str(
                "it is a Mercurial list holding a quote, which Mercurial groups into items the \
                 scan does not model",
            ),
            Self::RemoteHelper => f.write_str(
                "it lets Git hand a URL the scan does not read, such as one in `.gitmodules`, to a \
                 remote helper or `ext::`, which runs a program",
            ),
        }
    }
}

/// What a refused value or link names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Named {
    /// This path, inside a writable grant.
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
    /// Its submodule directories nest deeper than [`MAX_MODULE_DEPTH`].
    ModuleDepth,
    /// The scan reached [`ConfigLimits::files`].
    Files,
    /// The scan reached [`ConfigLimits::total_bytes`].
    Bytes,
    /// The scan reached [`ConfigLimits::paths`].
    Paths,
    /// The scan read more than [`MAX_URL_REWRITES`] URL rewrites, composed more than [`MAX_REWRITE_PAIRS`] pairs of a rewrite and a URL, or met a Mercurial scheme chain applying one rewrite twice.
    Rewrites,
    /// The scan read more than [`MAX_URL_VALUES`] URL values.
    UrlValues,
    /// It is not valid UTF-8.
    NotUtf8,
}

impl fmt::Display for ConfigFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(refusal) => write!(f, "{refusal}"),
            Self::Malformed { line } => write!(f, "line {line} is not valid configuration syntax"),
            Self::IncludeDepth => f.write_str("its includes nest past the include depth limit"),
            Self::ModuleDepth => write!(
                f,
                "its submodule directories nest deeper than {MAX_MODULE_DEPTH} levels"
            ),
            Self::Files => f.write_str("the scan reached its limit on configuration files"),
            Self::Bytes => f.write_str("the scan reached its limit on configuration bytes"),
            Self::Paths => f.write_str("the scan reached its limit on resolved paths"),
            Self::Rewrites => f.write_str(
                "the scan reached its limit on URL rewrites, or a Mercurial scheme chain applies \
                 one scheme twice",
            ),
            Self::UrlValues => f.write_str("the scan reached its limit on URL values"),
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
    /// A link or hard link the tool reads through (a configuration file, a hooks directory or hook) reaches inside a writable grant, or may.
    LinkNamesWritable {
        /// The tool.
        kind: VcsKind,
        /// The link.
        link: PathBuf,
        /// What the link reaches.
        named: Named,
    },
    /// A configuration file or directory the tool reads lies inside a writable grant, or may.
    ConfigInGrant {
        /// The tool.
        kind: VcsKind,
        /// The file or directory, as the tool reads it.
        path: PathBuf,
        /// Where it lies.
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

    /// The sentence for a link reaching `named`.
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
                 with a copy of the file it names, {REFUSING}",
                Shown(path.as_os_str())
            ),
            Named::Unprovable(why) => write!(
                f,
                "the {tool} link `{link}` cannot be proven to point outside the writable grants: \
                 {why}; replace the link with a copy of the file it names, {REFUSING}"
            ),
        }
    }

    /// The sentence for a configuration file or directory lying at `named`.
    fn fmt_config(
        f: &mut fmt::Formatter<'_>,
        kind: VcsKind,
        path: &Path,
        named: &Named,
    ) -> fmt::Result {
        let tool = tool_name(kind);
        let path = Shown(path.as_os_str());
        match named {
            Named::InGrant(at) => write!(
                f,
                "the {tool} configuration `{path}` lies at `{}` inside a writable grant, so a \
                 jailed program could change what {tool} reads or runs outside the jail; carve it \
                 out of the grant, {REFUSING}",
                Shown(at.as_os_str())
            ),
            Named::Unprovable(why) => write!(
                f,
                "the {tool} configuration `{path}` cannot be proven to lie outside the writable \
                 grants: {why}; carve it out of the grant, {REFUSING}"
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
            Self::ConfigInGrant { kind, path, named } => Self::fmt_config(f, *kind, path, named),
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

/// Write `bytes` injectively: a backslash, a control, bidirectional-format, or
/// invisible separator character, every byte that is not UTF-8, and with
/// `quote` a double quote, each as an escape.
fn write_escaped(f: &mut fmt::Formatter<'_>, bytes: &[u8], quote: bool) -> fmt::Result {
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c == '\\' {
                f.write_str("\\\\")?;
            } else if quote && c == '"' {
                f.write_str("\\\"")?;
            } else if c.is_control()
                || matches!(
                    c,
                    '\u{61c}'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{2028}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{feff}'
                )
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

/// One part of a dotted setting name: bare when it is a plain identifier, quoted and escaped otherwise.
fn write_part(f: &mut fmt::Formatter<'_>, part: &str) -> fmt::Result {
    let bare = !part.is_empty()
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if bare {
        return f.write_str(part);
    }
    f.write_char('"')?;
    write_escaped(f, part.as_bytes(), true)?;
    f.write_char('"')
}

/// The parts of a setting name, joined with `.`.
fn write_parts<'p>(
    f: &mut fmt::Formatter<'_>,
    parts: impl IntoIterator<Item = &'p str>,
) -> fmt::Result {
    for (index, part) in parts.into_iter().enumerate() {
        if index > 0 {
            f.write_char('.')?;
        }
        write_part(f, part)?;
    }
    Ok(())
}

/// Text shown injectively, as [`write_escaped`] writes it.
struct Shown<'a, T: ?Sized>(&'a T);

impl<T: AsRef<OsStr> + ?Sized> fmt::Display for Shown<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_escaped(f, self.0.as_ref().as_encoded_bytes(), false)
    }
}

/// Scan the configuration a tool reads from `roots`, refusing when it names code inside a grant.
///
/// Every configuration file the tool reads from the carved metadata (Git's
/// per-worktree and submodule configuration included) is reached by a held
/// walk, its includes followed, and every value judged; the Git hooks
/// directories are listed for links and hard links. Nothing is read from the
/// environment: the grants and the home directory are injected.
///
/// # Errors
/// [`ConfigRefusal::NamesWritableCode`] for a value naming, or perhaps naming,
/// a path inside a writable grant; [`ConfigRefusal::LinkNamesWritable`] for
/// such a link or a hard-linked file; [`ConfigRefusal::ConfigInGrant`] for a
/// configuration file or directory lying inside a grant;
/// [`ConfigRefusal::Unreadable`] for a grant, root directory, or file that
/// cannot be opened, read, or parsed, or a ceiling reached.
pub fn scan(
    roots: &ConfigRoots<'_>,
    grants: &Grants<'_>,
    home: &Home,
    limits: ConfigLimits,
) -> Result<(), ConfigRefusal> {
    let kind = roots.kind();
    let mut run = Scan {
        kind,
        grants,
        home,
        limits,
        marks: marks(grants, kind)?,
        files: 0,
        bytes: 0,
        paths: 0,
        pending: Vec::new(),
        scopes: 0,
        remotes: BTreeMap::new(),
        deferred: Vec::new(),
        network_urls: Vec::new(),
        helper_remote: false,
        rewrites: Vec::new(),
        urls: Vec::new(),
    };
    run.seed(roots)?;
    while let Some(item) = run.pending.pop() {
        run.read(item)?;
    }
    run.judge_deferred()
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
    /// A Git `remotes/` or `branches/` file naming a remote's URL.
    GitRemote,
}

/// What the files read so far say of one Git remote's URLs.
///
/// Git uses a remote's name as a URL, so as a path relative to the directory
/// it runs in, when the remote has no URL. An empty `url` value clears the
/// URLs set before it; the scan does not read files in the tool's order, so a
/// cleared remote stays undefined whatever is set after it. Only a file read
/// [`Reading::Always`] sets a URL; a clearing value counts from any file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteUrls {
    /// A non-empty URL is set, and no empty `url` value was seen.
    Set,
    /// An empty `url` value was seen.
    Cleared,
}

/// The configuration a Git remote name is looked up in.
///
/// A remote defined in one repository's configuration does not exist in
/// another's: the tool reads a name no remote of its own carries as a URL or
/// local path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    /// The repository the tool runs in: its common `config` and its own
    /// `config.worktree`, with every file they include.
    Main,
    /// Another worktree's `config.worktree`, read with the common `config`.
    Worktree(u32),
    /// A configuration read on its own: a submodule's, a Jujutsu store's, or
    /// a file the tool running here never reads.
    Own(u32),
}

impl Scope {
    /// The scope whose remotes a name looked up in `self` also sees.
    const fn parent(self) -> Option<Self> {
        match self {
            Self::Worktree(_) => Some(Self::Main),
            Self::Main | Self::Own(_) => None,
        }
    }
}

/// Whether the tool reads a file whenever it reads the configuration of the file's scope.
///
/// The scan reads every file the tool may read, so every value is judged;
/// only a file the tool always reads may define what another value relies on
/// (a remote's URL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// Always read: a root `config`, or a file an unconditional include names.
    Always,
    /// Read only when a condition holds: a `config.worktree` (read with
    /// `extensions.worktreeConfig`), an `includeIf` target, or a file one of
    /// them includes.
    Conditional,
}

impl Reading {
    /// The reading of a file named by an include read as `include` from a file read as `self`.
    const fn then(self, include: Self) -> Self {
        match self {
            Self::Always => include,
            Self::Conditional => Self::Conditional,
        }
    }
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
    /// The configuration its Git remotes belong to.
    scope: Scope,
    /// Whether the tool always reads it.
    reading: Reading,
}

/// A configuration file being judged.
#[derive(Debug, Clone)]
struct FileCtx {
    /// The path the tool reads it at.
    source: PathBuf,
    /// The directories a relative value is resolved against, before the working tree.
    bases: Vec<PathBuf>,
    /// Its include depth.
    depth: u32,
    /// Its syntax.
    syntax: Syntax,
    /// The configuration its Git remotes belong to.
    scope: Scope,
    /// Whether the tool always reads it.
    reading: Reading,
}

/// How a value is judged.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Role {
    /// Never names code: not judged.
    Exempt,
    /// Every word is judged, after the runner prefix the tool consumes.
    Words(Runner),
    /// The words of this text, and this text as one command path whatever its shape.
    ///
    /// The text is the part of the value the tool runs or loads: the whole
    /// value for Git, a Mercurial extension's path without the `!` that
    /// disables it, a `python:` hook's file without its function.
    Forced(String),
    /// The whole value as one path to a file that is then read, as this include reads it.
    Include(Reading),
    /// Every word, and the whole value as one directory that is then listed for links.
    HooksPath,
    /// Admitted when a network URL (also in `host:path` form when `scp`), judged as [`Role::Forced`] otherwise.
    Url {
        /// Whether Git's `host:path` form counts as a network URL.
        scp: bool,
    },
    /// A Mercurial `[paths]` value: the whole value, and each item of it as a list, judged as [`Role::Url`] without the `host:path` form.
    ///
    /// Mercurial reads the value as a list of URLs (`parselist`: commas and
    /// whitespace separate) once `<name>:multi-urls` is set, in this file or
    /// any other, and as one URL otherwise. Both readings are judged; a quote,
    /// which the list parser groups and unescapes by, refuses.
    UrlList,
}

/// How a tool turns a setting's value into the command line it runs.
///
/// A tool strips a runner prefix once, from the first character of the value
/// as written, and only for the settings that declare it. Everywhere else a
/// runner-shaped word (`!/x`, `=/x`) is run as written: a relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Runner {
    /// The value is the command line.
    None,
    /// One leading `!` makes the rest a shell command: a Mercurial `[alias]`.
    Bang,
    /// A Git `alias.*`: one leading `!` makes the rest a shell command;
    /// otherwise Git reads its own options off the front, and the first word
    /// left names a Git command, which Git runs as the program `git-<word>`
    /// (`execv_dashed_external`), relative to its working directory once the
    /// word holds a `/`.
    GitAlias,
    /// A Git `credential.helper`: one leading `!` makes the rest a shell
    /// command, an absolute path runs as written, and anything else runs as
    /// `git credential-<value>`, the program `git-credential-<word>`
    /// (`credential.c`).
    GitHelper,
    /// One leading `python:` makes the rest a Python callable: a Mercurial `[hooks]` value.
    Python,
    /// The value is run without a shell (Git's `gpg.program`, `core.askPass`,
    /// `core.gitProxy`), or split at spaces only (`gpg.ssh.defaultKeyCommand`):
    /// a `~`, a quote, or a space is part of the program path.
    Exec,
    /// A Git `remote.<name>.vcs`: run without a shell as the program `git-remote-<value>`.
    GitRemote,
}

/// The command line a tool runs for a value, as [`Runner::consume`] composes it.
enum Line<'v> {
    /// Text the tool splits into shell words.
    Shell {
        /// The text split into words.
        text: Cow<'v, str>,
        /// The program prefix the tool adds to the first word not shaped like an option.
        command_prefix: Option<&'static str>,
    },
    /// Text the tool runs as one program, neither split nor expanded.
    Exec(Cow<'v, str>),
}

impl<'v> Line<'v> {
    /// A command line run as written.
    const fn of(text: Cow<'v, str>) -> Self {
        Self::Shell {
            text,
            command_prefix: None,
        }
    }
}

impl Runner {
    /// The command line the tool runs for `value`.
    fn consume(self, value: &str) -> Line<'_> {
        let strip = |prefix: &str| {
            value
                .strip_prefix(prefix)
                .map(|rest| Line::of(Cow::Borrowed(rest)))
        };
        match self {
            Self::None => Line::of(Cow::Borrowed(value)),
            Self::Bang => strip("!").unwrap_or_else(|| Line::of(Cow::Borrowed(value))),
            Self::Python => strip("python:").unwrap_or_else(|| Line::of(Cow::Borrowed(value))),
            Self::GitHelper if is_git_absolute(value) => Line::of(Cow::Borrowed(value)),
            Self::GitHelper => strip("!")
                .unwrap_or_else(|| Line::of(Cow::Owned(format!("git-credential-{value}")))),
            // Git splits an alias into words and reads its own options
            // (`-p`, `-c <name>`) off the front before the word naming a
            // command, so the prefix lands on a word, not on the value's text.
            Self::GitAlias => strip("!").unwrap_or(Line::Shell {
                text: Cow::Borrowed(value),
                command_prefix: Some("git-"),
            }),
            Self::Exec => Line::Exec(Cow::Borrowed(value)),
            Self::GitRemote => Line::Exec(Cow::Owned(format!("git-remote-{value}"))),
        }
    }
}

/// Git's `is_absolute_path`: a leading `/`, and on Windows a leading `\` or a drive prefix.
fn is_git_absolute(value: &str) -> bool {
    let mut chars = value.chars();
    match (chars.next(), chars.next()) {
        (Some('/'), _) => true,
        (Some('\\'), _) => cfg!(windows),
        (Some(letter), Some(':')) => cfg!(windows) && letter.is_ascii_alphabetic(),
        (Some(_) | None, _) => false,
    }
}

/// What becomes of a value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// It is judged in this role.
    Judge(Role),
    /// It names a remote: admitted when one is defined, judged as a URL otherwise, once every file is read.
    RemoteName,
}

/// Which bases a relative path word resolves against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// A program or argument: the file's directories and the working tree; a `..` is unprovable.
    Command,
    /// A file the tool reads relative to the including file: only the file's directories.
    Include,
}

/// Where a word stands in its command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Position {
    /// The program a command runs, found through the host's `PATH`.
    Program,
    /// An argument, which a program may read relative to the directory it runs in.
    Argument,
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
                section: Box::from(&**section),
                subsection: subsection.as_deref().map(Box::from),
                key: Box::from(key.as_str()),
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

/// A value kept to be judged once every file is read: a remote name, a URL, a network remote URL.
///
/// The file's context is shared, never copied per value, and each list
/// holding these is bounded by [`MAX_URL_VALUES`] before every push.
struct Deferred {
    /// The file it came from.
    ctx: Rc<FileCtx>,
    /// The setting holding it.
    setting: Setting,
    /// The value.
    value: String,
}

/// A rewrite a tool applies to a URL before it reads it.
///
/// Git applies a prefix rewrite once and never to its own result. Mercurial
/// resolves a scheme's result again through every scheme
/// (`ShortRepository.instance` looks the rewritten URL's scheme up anew, an
/// overridden built-in scheme included), so a scheme rewrite [`Rewrite::chains`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rewrite {
    /// Git's `url.<base>.insteadOf` or `pushInsteadOf`: a URL starting with `prefix` has it replaced by `base`.
    Prefix {
        /// The file it came from.
        source: PathBuf,
        /// The text a URL starts with.
        prefix: String,
        /// The text put in its place.
        base: String,
    },
    /// Mercurial's `[schemes]`: a URL `<scheme>://<rest>` becomes `template` followed by `rest`.
    Scheme {
        /// The file it came from.
        source: PathBuf,
        /// The scheme, matched in any case.
        scheme: String,
        /// The URL text put in place of `<scheme>://`.
        template: String,
    },
}

impl Rewrite {
    /// The file it came from.
    fn source(&self) -> &Path {
        match self {
            Self::Prefix { source, .. } | Self::Scheme { source, .. } => source,
        }
    }

    /// Whether the tool applies rewrites again to this rewrite's result: a Mercurial scheme.
    const fn chains(&self) -> bool {
        match self {
            Self::Prefix { .. } => false,
            Self::Scheme { .. } => true,
        }
    }

    /// The form `url` takes under this rewrite, or `None` when it does not apply.
    ///
    /// A template holding a brace substitutes parts of the URL through
    /// Mercurial's templater, which the scan does not model, so it is
    /// unprovable. A form longer than [`MAX_PATH_BYTES`] is refused before it
    /// is built, which bounds every form of a scheme chain.
    fn apply(&self, url: &str) -> Option<Result<String, Unprovable>> {
        let (head, rest) = match self {
            Self::Prefix { prefix, base, .. } => (base, url.strip_prefix(prefix.as_str())?),
            Self::Scheme {
                scheme, template, ..
            } => {
                let (name, rest) = url.split_once("://")?;
                if !name.eq_ignore_ascii_case(scheme) {
                    return None;
                }
                if template.contains(['{', '}']) {
                    return Some(Err(Unprovable::Glob));
                }
                (template, rest)
            }
        };
        if head.len().saturating_add(rest.len()) > MAX_PATH_BYTES {
            return Some(Err(Unprovable::TooLong));
        }
        Some(Ok(format!("{head}{rest}")))
    }
}

/// A URL value as written, kept to be judged in each form a [`Rewrite`] gives it.
struct UrlValue {
    /// The value and where it came from.
    item: Deferred,
    /// Whether Git's `host:path` form counts as a network URL for it.
    scp: bool,
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

/// A value stopped as unprovable.
const fn unproven(why: Unprovable) -> Stop {
    Stop::Named(Named::Unprovable(why))
}

/// Where a walk stands relative to the grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Zone {
    /// Outside every grant.
    Outside,
    /// Inside a writable grant and outside its carves.
    Writable,
    /// Inside a carve.
    Carved,
}

/// A grant or carve directory, by path and identity.
struct Mark {
    /// Its canonical path.
    path: PathBuf,
    /// Its identity.
    id: FileId,
    /// [`Zone::Writable`] for a grant, [`Zone::Carved`] for a carve.
    zone: Zone,
}

/// Every grant and carve of `grants`, identified now.
fn marks(grants: &Grants<'_>, kind: VcsKind) -> Result<Vec<Mark>, ConfigRefusal> {
    let writable = grants.writable.iter().map(|path| (path, Zone::Writable));
    let carved = grants.carves.iter().map(|path| (path, Zone::Carved));
    writable
        .chain(carved)
        .map(|(path, zone)| {
            let path = path.as_path();
            FileId::of_path(path)
                .map(|id| Mark {
                    path: path.to_path_buf(),
                    id,
                    zone,
                })
                .map_err(|refusal| ConfigRefusal::Unreadable {
                    kind,
                    path: path.to_path_buf(),
                    fault: fault_of(refusal),
                })
        })
        .collect()
}

/// One step of a path walk.
enum Step {
    /// Enter the entry of this name.
    Name(OsString),
    /// Climb to the parent.
    Up,
}

/// Push the steps of `path` so that popping yields them in order.
fn push_steps(steps: &mut Vec<Step>, path: &Path) {
    for component in path.components().rev() {
        match component {
            Component::Normal(part) => steps.push(Step::Name(part.to_os_string())),
            Component::ParentDir => steps.push(Step::Up),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
}

/// The root of an absolute path: its prefix and root components.
fn root_of(path: &Path) -> PathBuf {
    path.components()
        .take_while(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
        .collect()
}

/// A path walk in progress: the held directory reached, its real path, and the steps left.
struct Walk {
    /// The directory reached.
    cur: HeldDir,
    /// Its path, as the walk reached it through real directories.
    real: PathBuf,
    /// Its zone.
    zone: Zone,
    /// The zone of every directory above it, innermost last.
    above: Vec<Zone>,
    /// The steps left, next last.
    steps: Vec<Step>,
    /// Links followed.
    links: u32,
    /// Steps taken.
    taken: u32,
    /// Whether a link was followed.
    linked: bool,
}

/// Why a walk stopped.
enum WalkStop {
    /// The path names this.
    Named {
        /// What it names.
        named: Named,
        /// Whether the walk followed a link before it stopped.
        linked: bool,
    },
    /// A refusal not about the path (a ceiling).
    Refused(ConfigRefusal),
}

impl From<WalkStop> for Stop {
    fn from(stop: WalkStop) -> Self {
        match stop {
            WalkStop::Named { named, .. } => Self::Named(named),
            WalkStop::Refused(refusal) => Self::Refused(refusal),
        }
    }
}

impl Walk {
    /// The walk stopped as unprovable.
    const fn stop(&self, why: Unprovable) -> WalkStop {
        WalkStop::Named {
            named: Named::Unprovable(why),
            linked: self.linked,
        }
    }

    /// Climb to the parent through the handle; the root's parent is the root.
    fn up(&mut self) -> Result<(), WalkStop> {
        if self.zone == Zone::Writable {
            return Err(self.stop(Unprovable::DotDot));
        }
        match self.cur.parent() {
            Ok(Some(parent)) => {
                let Some(zone) = self.above.pop() else {
                    return Err(self.stop(Unprovable::Unresolvable));
                };
                self.cur = parent;
                self.zone = zone;
                self.real.pop();
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(_) => Err(self.stop(Unprovable::Unresolvable)),
        }
    }

    /// Append the steps left below a missing entry, which must hold no `..`.
    fn missing(&mut self) -> Result<(), WalkStop> {
        let mut count = self.real.components().count();
        while let Some(step) = self.steps.pop() {
            match step {
                Step::Name(part) => {
                    count = count.saturating_add(1);
                    if count > MAX_PATH_COMPONENTS {
                        return Err(self.stop(Unprovable::TooLong));
                    }
                    self.real.push(part);
                }
                Step::Up => return Err(self.stop(Unprovable::DotDot)),
            }
        }
        Ok(())
    }
}

/// What a walk ended on.
enum End {
    /// Nothing: the path names an entry that does not exist yet.
    Missing,
    /// A directory.
    Dir(HeldDir),
    /// An entry that is neither a directory nor a link, in the held directory.
    Entry(HeldDir, EntryName),
}

/// A walked path proven outside every writable grant.
struct Resolved {
    /// The path the walk reached, through real directories.
    path: PathBuf,
    /// What it ended on.
    end: End,
}

/// What one named step of a walk led to.
enum Next {
    /// A directory or a link: the walk goes on.
    Continue,
    /// A missing entry: the walk is over.
    Missing,
    /// A non-directory entry: the walk is over.
    Entry(EntryName),
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
    /// The grants and carves, identified.
    marks: Vec<Mark>,
    /// Files read so far.
    files: u32,
    /// Bytes read so far.
    bytes: u64,
    /// Paths resolved so far.
    paths: u32,
    /// Files still to read.
    pending: Vec<Pending>,
    /// Scopes opened so far besides [`Scope::Main`].
    scopes: u32,
    /// The Git remotes given a URL or cleared, by the configuration naming them.
    remotes: BTreeMap<(Scope, String), RemoteUrls>,
    /// Remote-name values waiting for every remote to be known, at most [`MAX_URL_VALUES`].
    deferred: Vec<Deferred>,
    /// Remote URL values admitted as network URLs, judged again as paths when a remote names a helper, at most [`MAX_URL_VALUES`].
    network_urls: Vec<Deferred>,
    /// Whether any file read sets `remote.<name>.vcs`, which hands a remote's URL verbatim to `git-remote-<vcs>`.
    helper_remote: bool,
    /// The URL rewrites of every file read, always or conditionally.
    rewrites: Vec<Rewrite>,
    /// Every URL value as written, a Mercurial list's items and a scheme template included, judged again in each form a rewrite gives it; at most [`MAX_URL_VALUES`].
    urls: Vec<UrlValue>,
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

    /// The refusal for a configuration file or directory at `path` whose walk stopped.
    fn root_refusal(&self, path: &Path, stop: WalkStop) -> ConfigRefusal {
        match stop {
            WalkStop::Refused(refusal) => refusal,
            WalkStop::Named {
                named,
                linked: true,
            } => self.link_refusal(path, named),
            WalkStop::Named {
                named,
                linked: false,
            } => ConfigRefusal::ConfigInGrant {
                kind: self.kind,
                path: path.to_path_buf(),
                named,
            },
        }
    }

    /// Queue a root file of the repository the tool runs in, which the tool always reads.
    fn queue(&mut self, path: PathBuf, syntax: Syntax) {
        self.queue_in(path, syntax, Scope::Main, Reading::Always);
    }

    /// Queue a root file whose Git remotes belong to `scope`, read as `reading`.
    fn queue_in(&mut self, path: PathBuf, syntax: Syntax, scope: Scope, reading: Reading) {
        self.pending.push(Pending {
            path,
            depth: 0,
            syntax,
            scope,
            reading,
        });
    }

    /// A scope no file has yet.
    ///
    /// Besides at most two seeded scopes, every scope is opened for a listed
    /// directory entry, so the listing and path ceilings keep the count far
    /// below `u32::MAX`.
    const fn fresh_scope(&mut self) -> u32 {
        self.scopes = self.scopes.saturating_add(1);
        self.scopes
    }

    /// Require a root directory to exist and open.
    fn require(&self, dir: &Path) -> Result<(), ConfigRefusal> {
        self.root(dir).map(drop)
    }

    /// Hold a root directory, which must exist.
    fn root(&self, dir: &Path) -> Result<HeldDir, ConfigRefusal> {
        HeldDir::open_root(dir).map_err(|refusal| self.unreadable(dir, fault_of(refusal)))
    }

    /// Queue every root file of `roots`, and list the Git hooks directories.
    fn seed(&mut self, roots: &ConfigRoots<'_>) -> Result<(), ConfigRefusal> {
        match *roots {
            ConfigRoots::Git { gitdir, commondir } => {
                self.require(gitdir)?;
                let common = commondir.unwrap_or(gitdir);
                self.require(common)?;
                let own_worktree = gitdir.join("config.worktree");
                self.queue_in(own_worktree, Syntax::Git, Scope::Main, Reading::Conditional);
                if common == gitdir {
                    self.queue(gitdir.join("config"), Syntax::Git);
                } else {
                    // A linked worktree's own `config` is never read, and the
                    // common `config.worktree` belongs to the main worktree.
                    let unread = Scope::Own(self.fresh_scope());
                    self.queue_in(gitdir.join("config"), Syntax::Git, unread, Reading::Always);
                    self.queue(common.join("config"), Syntax::Git);
                    let primary = Scope::Worktree(self.fresh_scope());
                    let primary_worktree = common.join("config.worktree");
                    self.queue_in(primary_worktree, Syntax::Git, primary, Reading::Conditional);
                }
                self.list_hooks(&gitdir.join("hooks"))?;
                if common != gitdir {
                    self.list_hooks(&common.join("hooks"))?;
                }
                self.seed_worktrees(common, gitdir)?;
                self.seed_modules(common)?;
                self.seed_remote_files(common, Scope::Main)?;
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
                self.seed_jj_git(&repo.join("store"))?;
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

    /// Queue the Git repository a Jujutsu store keeps its commits in, and list its hooks.
    ///
    /// The store names the repository in `git_target`, relative to the store;
    /// without that file it is the store's `git` directory. Text holding a
    /// control character names no path the scan can judge as the tool reads it.
    fn seed_jj_git(&mut self, store: &Path) -> Result<(), ConfigRefusal> {
        let target = store.join("git_target");
        let gitdir = match self.open(&target)? {
            None => store.join("git"),
            Some(opened) => {
                let text = opened
                    .file
                    .read_utf8(self.limits.file_bytes)
                    .map_err(|refusal| self.unreadable(&target, fault_of(refusal)))?;
                if text.is_empty() || text.contains(char::is_control) {
                    return Err(self.unreadable(&target, ConfigFault::Malformed { line: 1 }));
                }
                store.join(text)
            }
        };
        if self.open_dir(&gitdir)?.is_some() {
            let scope = Scope::Own(self.fresh_scope());
            self.queue_in(gitdir.join("config"), Syntax::Git, scope, Reading::Always);
            let worktree = gitdir.join("config.worktree");
            self.queue_in(worktree, Syntax::Git, scope, Reading::Conditional);
            self.list_hooks(&gitdir.join("hooks"))?;
            self.seed_remote_files(&gitdir, scope)?;
        }
        Ok(())
    }

    /// Queue every file of `common/remotes` and `common/branches` in `scope`, each judged as the URLs it names.
    ///
    /// A file never defines the remote it is named for: a Git built with its
    /// breaking changes reads neither directory, and uses the name as a path.
    /// A directory there would name a remote holding a `/`, read from a file
    /// below it; it is refused rather than walked.
    fn seed_remote_files(&mut self, common: &Path, scope: Scope) -> Result<(), ConfigRefusal> {
        for listed in ["remotes", "branches"] {
            let Some((dir, real)) = self.open_dir(&common.join(listed))? else {
                continue;
            };
            let entries = dir
                .entries(self.limits.listing)
                .map_err(|refusal| self.unreadable(&real, fault_of(refusal)))?;
            for (name, kind) in entries {
                let path = real.join(name.as_os_str());
                if kind == FileKind::Dir {
                    let fault = ConfigFault::Open(OpenRefusal::NotRegular(FileKind::Dir));
                    return Err(self.unreadable(&path, fault));
                }
                self.queue_in(path, Syntax::GitRemote, scope, Reading::Conditional);
            }
        }
        Ok(())
    }

    /// Queue the `config.worktree` of every linked worktree of `common` but `gitdir`'s own.
    fn seed_worktrees(&mut self, common: &Path, gitdir: &Path) -> Result<(), ConfigRefusal> {
        let Some((dir, real)) = self.open_dir(&common.join("worktrees"))? else {
            return Ok(());
        };
        let own = lexical(gitdir);
        let entries = dir
            .entries(self.limits.listing)
            .map_err(|refusal| self.unreadable(&real, fault_of(refusal)))?;
        for (name, kind) in entries {
            if matches!(kind, FileKind::Dir | FileKind::Symlink) {
                let entry = real.join(name.as_os_str());
                if entry != own {
                    let scope = Scope::Worktree(self.fresh_scope());
                    let config = entry.join("config.worktree");
                    self.queue_in(config, Syntax::Git, scope, Reading::Conditional);
                }
            }
        }
        Ok(())
    }

    /// Queue the configuration and list the hooks of every submodule gitdir below `common/modules`.
    ///
    /// A directory holding a `config` entry is a submodule gitdir, whose own
    /// `modules` directory is walked next; any other directory groups
    /// submodules by name and every directory or link in it is walked. The walk
    /// keeps an explicit stack, and every directory it pushes is counted
    /// against [`ConfigLimits::paths`].
    fn seed_modules(&mut self, common: &Path) -> Result<(), ConfigRefusal> {
        let mut stack: Vec<(PathBuf, u32)> = vec![(common.join("modules"), 1)];
        while let Some((path, depth)) = stack.pop() {
            let Some((dir, real)) = self.open_dir(&path)? else {
                continue;
            };
            if depth > MAX_MODULE_DEPTH {
                return Err(self.unreadable(&path, ConfigFault::ModuleDepth));
            }
            let entries = dir
                .entries(self.limits.listing)
                .map_err(|refusal| self.unreadable(&real, fault_of(refusal)))?;
            let gitdir = entries
                .iter()
                .any(|(name, kind)| name.as_os_str() == "config" && *kind != FileKind::Dir);
            let below = depth.saturating_add(1);
            if gitdir {
                let module = Scope::Own(self.fresh_scope());
                self.queue_in(real.join("config"), Syntax::Git, module, Reading::Always);
                let worktree = real.join("config.worktree");
                self.queue_in(worktree, Syntax::Git, module, Reading::Conditional);
                self.list_hooks(&real.join("hooks"))?;
                self.seed_remote_files(&real, module)?;
                self.count_path(&real)?;
                stack.push((real.join("modules"), below));
            } else {
                for (name, kind) in entries {
                    if matches!(kind, FileKind::Dir | FileKind::Symlink) {
                        self.count_path(&real)?;
                        stack.push((real.join(name.as_os_str()), below));
                    }
                }
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

    /// The zone of the directory `dir`, held at `real`, below a directory of zone `parent`.
    fn classify(&self, dir: &HeldDir, real: &Path, parent: Zone) -> Result<Zone, Unprovable> {
        let id = dir.id().map_err(|_| Unprovable::Unresolvable)?;
        let hit = |zone: Zone| {
            self.marks
                .iter()
                .any(|mark| mark.zone == zone && (mark.id == id || mark.path.as_path() == real))
        };
        if hit(Zone::Carved) {
            Ok(Zone::Carved)
        } else if hit(Zone::Writable) {
            Ok(Zone::Writable)
        } else {
            Ok(parent)
        }
    }

    /// Begin a walk of the absolute `path` at its root.
    fn walk_start(&self, path: &Path) -> Result<Walk, Unprovable> {
        if path.as_os_str().len() > MAX_PATH_BYTES
            || path.components().count() > MAX_PATH_COMPONENTS
        {
            return Err(Unprovable::TooLong);
        }
        if !path.is_absolute() {
            return Err(Unprovable::Unresolvable);
        }
        let root = root_of(path);
        let cur = HeldDir::open_root(&root).map_err(|_| Unprovable::Unresolvable)?;
        let zone = self.classify(&cur, &root, Zone::Outside)?;
        let mut steps = Vec::new();
        push_steps(&mut steps, path);
        Ok(Walk {
            cur,
            real: root,
            zone,
            above: Vec::new(),
            steps,
            links: 0,
            taken: 0,
            linked: false,
        })
    }

    /// Walk the absolute `path` component by component through held handles.
    ///
    /// Each directory is opened below the last without following a link; a
    /// link is read through its directory's handle and its target walked in
    /// its place, unless the link lies inside a writable grant. The walk stops
    /// with [`Named::InGrant`] when it ends inside a writable grant, and with
    /// [`Named::Unprovable`] for a `..` below a missing entry or out of a
    /// grant, an entry that cannot be walked, or a ceiling. `source` is the
    /// file a link count is charged to.
    fn walk(&mut self, path: &Path, source: &Path) -> Result<Resolved, WalkStop> {
        let mut walk = self.walk_start(path).map_err(|why| WalkStop::Named {
            named: Named::Unprovable(why),
            linked: false,
        })?;
        while let Some(step) = walk.steps.pop() {
            walk.taken = walk.taken.saturating_add(1);
            if walk.taken > MAX_WALK_STEPS {
                return Err(walk.stop(Unprovable::TooLong));
            }
            let next = match step {
                Step::Up => {
                    walk.up()?;
                    Next::Continue
                }
                Step::Name(part) => self.walk_name(&mut walk, &part, source)?,
            };
            match next {
                Next::Continue => {}
                Next::Missing => {
                    let Walk {
                        real, zone, linked, ..
                    } = walk;
                    return self.finish(real, zone, linked, End::Missing);
                }
                Next::Entry(name) => {
                    let Walk {
                        cur,
                        real,
                        zone,
                        linked,
                        ..
                    } = walk;
                    return self.finish(real, zone, linked, End::Entry(cur, name));
                }
            }
        }
        let Walk {
            cur,
            real,
            zone,
            linked,
            ..
        } = walk;
        self.finish(real, zone, linked, End::Dir(cur))
    }

    /// Take the step into the entry `part` of the walk's directory.
    fn walk_name(
        &mut self,
        walk: &mut Walk,
        part: &OsStr,
        source: &Path,
    ) -> Result<Next, WalkStop> {
        let Some(name) = EntryName::new(part) else {
            return Err(walk.stop(Unprovable::Unresolvable));
        };
        let kind = walk
            .cur
            .kind_of(&name)
            .map_err(|_| walk.stop(Unprovable::Unresolvable))?;
        match kind {
            None => {
                walk.real.push(part);
                walk.missing()?;
                Ok(Next::Missing)
            }
            Some(FileKind::Dir) => {
                let child = walk
                    .cur
                    .child_dir(&name)
                    .map_err(|_| walk.stop(Unprovable::Unresolvable))?;
                if walk.above.len() >= MAX_PATH_COMPONENTS {
                    return Err(walk.stop(Unprovable::TooLong));
                }
                walk.real.push(part);
                let zone = self
                    .classify(&child, &walk.real, walk.zone)
                    .map_err(|why| walk.stop(why))?;
                walk.above.push(walk.zone);
                walk.zone = zone;
                walk.cur = child;
                Ok(Next::Continue)
            }
            Some(FileKind::Symlink) => {
                self.walk_link(walk, &name, source)?;
                Ok(Next::Continue)
            }
            Some(
                FileKind::Regular
                | FileKind::Fifo
                | FileKind::Socket
                | FileKind::Device
                | FileKind::Other,
            ) => {
                if !walk.steps.is_empty() {
                    return Err(walk.stop(Unprovable::Unresolvable));
                }
                walk.real.push(part);
                Ok(Next::Entry(name))
            }
        }
    }

    /// Replace the link `name` of the walk's directory with the steps of its target.
    fn walk_link(
        &mut self,
        walk: &mut Walk,
        name: &EntryName,
        source: &Path,
    ) -> Result<(), WalkStop> {
        if walk.zone == Zone::Writable {
            return Err(WalkStop::Named {
                named: Named::InGrant(walk.real.join(name.as_os_str())),
                linked: true,
            });
        }
        walk.links = walk.links.saturating_add(1);
        if walk.links > MAX_LINKS {
            return Err(walk.stop(Unprovable::Unresolvable));
        }
        self.count_path(source).map_err(WalkStop::Refused)?;
        walk.linked = true;
        let target = walk
            .cur
            .read_link(name)
            .map_err(|_| walk.stop(Unprovable::Unresolvable))?;
        if target.as_os_str().len() > MAX_PATH_BYTES
            || target.components().count() > MAX_PATH_COMPONENTS
        {
            return Err(walk.stop(Unprovable::TooLong));
        }
        if target.is_absolute() {
            let root = root_of(&target);
            let cur = HeldDir::open_root(&root).map_err(|_| walk.stop(Unprovable::Unresolvable))?;
            let zone = self
                .classify(&cur, &root, Zone::Outside)
                .map_err(|why| walk.stop(why))?;
            walk.cur = cur;
            walk.real = root;
            walk.zone = zone;
            walk.above.clear();
        } else if target.has_root()
            || matches!(target.components().next(), Some(Component::Prefix(_)))
        {
            return Err(walk.stop(Unprovable::Unresolvable));
        }
        push_steps(&mut walk.steps, &target);
        Ok(())
    }

    /// End a walk at `real`, refusing a place inside a writable grant.
    fn finish(
        &self,
        real: PathBuf,
        zone: Zone,
        linked: bool,
        end: End,
    ) -> Result<Resolved, WalkStop> {
        if zone == Zone::Writable || self.grants.covers(&real) {
            return Err(WalkStop::Named {
                named: Named::InGrant(real),
                linked,
            });
        }
        Ok(Resolved { path: real, end })
    }

    /// Refuse the regular file `name` of `dir`, reached for `at`, when it has more than one name.
    ///
    /// An entry that is gone or not a regular file (a device, a FIFO) is
    /// left to the tool: it runs no rewritable file.
    fn single_named(&self, at: &Path, dir: &HeldDir, name: &EntryName) -> Result<(), Stop> {
        match dir.open_regular(name).and_then(|file| file.link_count()) {
            Ok(count) if count <= 1 => Ok(()),
            Ok(_) => Err(unproven(Unprovable::HardLinked)),
            Err(OpenRefusal::Absent | OpenRefusal::NotRegular(_)) => Ok(()),
            Err(refusal) => Err(Stop::Refused(self.unreadable(at, fault_of(refusal)))),
        }
    }

    /// Refuse a file with more than one name.
    fn single_link(&self, at: &Path, file: &RegularFile) -> Result<(), ConfigRefusal> {
        match file.link_count() {
            Ok(count) if count <= 1 => Ok(()),
            Ok(_) => Err(self.link_refusal(at, Named::Unprovable(Unprovable::HardLinked))),
            Err(refusal) => Err(self.unreadable(at, fault_of(refusal))),
        }
    }

    /// Walk to the directory at `path`; `None` when it is absent or not a directory.
    fn open_dir(&mut self, path: &Path) -> Result<Option<(HeldDir, PathBuf)>, ConfigRefusal> {
        let found = self
            .walk(path, path)
            .map_err(|stop| self.root_refusal(path, stop))?;
        match found.end {
            End::Missing | End::Entry(..) => Ok(None),
            End::Dir(dir) => Ok(Some((dir, found.path))),
        }
    }

    /// List a hooks directory, refusing a link into a grant and a hard-linked hook.
    fn list_hooks(&mut self, hooks: &Path) -> Result<(), ConfigRefusal> {
        if let Some((dir, real)) = self.open_dir(hooks)? {
            self.list_held(&dir, &real)?;
        }
        Ok(())
    }

    /// Check every entry of the held hooks directory at `real`.
    fn list_held(&mut self, dir: &HeldDir, real: &Path) -> Result<(), ConfigRefusal> {
        let entries = dir
            .entries(self.limits.listing)
            .map_err(|refusal| self.unreadable(real, fault_of(refusal)))?;
        for (name, kind) in entries {
            let at = real.join(name.as_os_str());
            match kind {
                FileKind::Symlink => self.held_link(dir, real, &name, &at)?,
                FileKind::Regular => {
                    let file = dir
                        .open_regular(&name)
                        .map_err(|refusal| self.unreadable(&at, fault_of(refusal)))?;
                    self.single_link(&at, &file)?;
                }
                FileKind::Dir
                | FileKind::Fifo
                | FileKind::Socket
                | FileKind::Device
                | FileKind::Other => {}
            }
        }
        Ok(())
    }

    /// Check the hook link `name` of the held directory at `real`, listed as `at`.
    fn held_link(
        &mut self,
        dir: &HeldDir,
        real: &Path,
        name: &EntryName,
        at: &Path,
    ) -> Result<(), ConfigRefusal> {
        let target = dir
            .read_link(name)
            .map_err(|refusal| self.unreadable(at, fault_of(refusal)))?;
        self.count_path(at)?;
        let found = self
            .walk(&real.join(target), at)
            .map_err(|stop| match stop {
                WalkStop::Named { named, .. } => self.link_refusal(at, named),
                WalkStop::Refused(refusal) => refusal,
            })?;
        if let End::Entry(holder, entry) = found.end {
            match holder.open_regular(&entry) {
                Ok(file) => self.single_link(at, &file)?,
                Err(OpenRefusal::Absent) => {}
                Err(refusal) => return Err(self.unreadable(at, fault_of(refusal))),
            }
        }
        Ok(())
    }

    /// Open the configuration file at `path`; `None` when it is absent.
    fn open(&mut self, path: &Path) -> Result<Option<Opened>, ConfigRefusal> {
        let found = self
            .walk(path, path)
            .map_err(|stop| self.root_refusal(path, stop))?;
        let file = match found.end {
            End::Missing => return Ok(None),
            End::Dir(_) => {
                let fault = ConfigFault::Open(OpenRefusal::NotRegular(FileKind::Dir));
                return Err(self.unreadable(path, fault));
            }
            End::Entry(dir, name) => match dir.open_regular(&name) {
                Ok(file) => file,
                Err(OpenRefusal::Absent) => return Ok(None),
                Err(refusal) => return Err(self.unreadable(path, fault_of(refusal))),
            },
        };
        self.single_link(path, &file)?;
        // The directory as named, followed through its links and `..`
        // steps as the tool's own open does; that directory with `..` folded
        // lexically; and the directory the walk reached.
        let mut bases: Vec<PathBuf> = Vec::with_capacity(3);
        let named = path.parent().map(Path::to_path_buf);
        let folded = path.parent().map(lexical);
        let walked = found.path.parent().map(Path::to_path_buf);
        for dir in [named, folded, walked].into_iter().flatten() {
            if !bases.contains(&dir) {
                bases.push(dir);
            }
        }
        Ok(Some(Opened { file, bases }))
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
        let ctx = Rc::new(FileCtx {
            source: item.path,
            bases: opened.bases,
            depth: item.depth,
            syntax: item.syntax,
            scope: item.scope,
            reading: item.reading,
        });
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
            Syntax::GitRemote => self.judge_entries(&ctx, &parse_git_remote(&text)),
        }
    }

    /// Judge every entry of a parsed file.
    fn judge_entries(&mut self, ctx: &Rc<FileCtx>, entries: &[Entry]) -> Result<(), ConfigRefusal> {
        let kind = self.kind;
        for entry in entries {
            let refuse =
                |stop: Stop| stop.into_refusal(kind, &ctx.source, || entry.setting.public());
            if holds_nul(entry) {
                return Err(refuse(unproven(Unprovable::Nul)));
            }
            let route = match ctx.syntax {
                Syntax::Git => {
                    self.judge_git_subsection(ctx, &entry.setting)
                        .map_err(&refuse)?;
                    git_protocol(&entry.setting, &entry.value).map_err(&refuse)?;
                    self.note_remote(ctx, &entry.setting, &entry.value);
                    git_route(&entry.setting, &entry.value)
                }
                Syntax::Hg => Route::Judge(hg_role(&entry.setting, &entry.value)),
                Syntax::Toml | Syntax::Darcs => Route::Judge(Role::Words(Runner::None)),
                Syntax::GitRemote => Route::Judge(Role::Url { scp: true }),
            };
            if let Some(rewrite) = rewrite_of(ctx, &entry.setting, &entry.value) {
                if self.rewrites.len() >= MAX_URL_REWRITES {
                    return Err(self.unreadable(&ctx.source, ConfigFault::Rewrites));
                }
                self.rewrites.push(rewrite);
            }
            match &route {
                Route::Judge(Role::Url { scp }) => {
                    self.keep_url(ctx, &entry.setting, &entry.value, *scp)?;
                }
                Route::Judge(Role::UrlList) => {
                    self.keep_url(ctx, &entry.setting, &entry.value, false)?;
                    let items = hg_list_items(&entry.value).map_err(|why| refuse(unproven(why)))?;
                    for item in items.filter(|item| *item != entry.value) {
                        self.keep_url(ctx, &entry.setting, item, false)?;
                    }
                }
                Route::RemoteName => {
                    if entry.value != "." {
                        self.keep_url(ctx, &entry.setting, &entry.value, true)?;
                    }
                }
                Route::Judge(
                    Role::Exempt
                    | Role::Words(_)
                    | Role::Forced(_)
                    | Role::Include(_)
                    | Role::HooksPath,
                ) => {}
            }
            if is_remote_url(ctx.syntax, &entry.setting) && is_network_url(&entry.value, true) {
                if self.network_urls.len() >= MAX_URL_VALUES {
                    return Err(self.unreadable(&ctx.source, ConfigFault::UrlValues));
                }
                self.network_urls.push(Deferred {
                    ctx: Rc::clone(ctx),
                    setting: entry.setting.clone(),
                    value: entry.value.clone(),
                });
            }
            match route {
                Route::Judge(role) => self.judge(ctx, &role, &entry.value).map_err(&refuse)?,
                Route::RemoteName => {
                    if entry.value != "." && !is_network_url(&entry.value, true) {
                        if self.deferred.len() >= MAX_URL_VALUES {
                            return Err(self.unreadable(&ctx.source, ConfigFault::UrlValues));
                        }
                        self.deferred.push(Deferred {
                            ctx: Rc::clone(ctx),
                            setting: entry.setting.clone(),
                            value: entry.value.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Keep the URL `value` of `setting` in `ctx` to be judged in each form a rewrite gives it.
    ///
    /// Refuses once [`MAX_URL_VALUES`] are kept, before the push.
    fn keep_url(
        &mut self,
        ctx: &Rc<FileCtx>,
        setting: &Setting,
        value: &str,
        scp: bool,
    ) -> Result<(), ConfigRefusal> {
        if self.urls.len() >= MAX_URL_VALUES {
            return Err(self.unreadable(&ctx.source, ConfigFault::UrlValues));
        }
        self.urls.push(UrlValue {
            item: Deferred {
                ctx: Rc::clone(ctx),
                setting: setting.clone(),
                value: value.to_owned(),
            },
            scp,
        });
        Ok(())
    }

    /// Judge a Git subsection: an `ext::` transport anywhere refuses, and a `url` section's names a URL.
    fn judge_git_subsection(&mut self, ctx: &FileCtx, setting: &Setting) -> Result<(), Stop> {
        let Setting::Key {
            section,
            subsection: Some(subsection),
            ..
        } = setting
        else {
            return Ok(());
        };
        if has_ext(subsection) {
            return Err(unproven(Unprovable::ExtTransport));
        }
        if &**section == "url" {
            if is_helper_base(subsection) {
                return Err(unproven(Unprovable::RemoteHelper));
            }
            return self.judge(ctx, &Role::Url { scp: true }, subsection);
        }
        Ok(())
    }

    /// Record what a `remote.<name>.url` setting in `ctx` says of the remote.
    ///
    /// An empty value clears its URLs, from any file; a non-empty one sets a
    /// URL only from a file the tool always reads, since a value the tool may
    /// never read cannot make the name stop naming a path.
    fn note_remote(&mut self, ctx: &FileCtx, setting: &Setting, value: &str) {
        let Setting::Key {
            section,
            subsection: Some(name),
            key,
        } = setting
        else {
            return;
        };
        if &**section != "remote" {
            return;
        }
        // A helper named from any file, read always or not, counts.
        if key.eq_ignore_ascii_case("vcs") {
            self.helper_remote = true;
        }
        if key.eq_ignore_ascii_case("url") {
            let urls = match (value.is_empty(), ctx.reading) {
                (true, Reading::Always | Reading::Conditional) => RemoteUrls::Cleared,
                (false, Reading::Always) => RemoteUrls::Set,
                (false, Reading::Conditional) => return,
            };
            self.note_urls(ctx.scope, name, urls);
        }
    }

    /// Record `urls` for the remote `name` in `scope`; a cleared remote stays cleared.
    fn note_urls(&mut self, scope: Scope, name: &str, urls: RemoteUrls) {
        let slot = self.remotes.entry((scope, name.to_owned())).or_insert(urls);
        if urls == RemoteUrls::Cleared {
            *slot = RemoteUrls::Cleared;
        }
    }

    /// Judge every remote-name value naming no remote its scope sees as a URL,
    /// and every network remote URL as a path once a remote names a helper.
    ///
    /// A remote is defined when a scope the name is looked up in sets a URL
    /// for it and none clears its URLs. A helper (`remote.<name>.vcs`) is
    /// handed the URL verbatim and may read it as a local path, so with one
    /// set anywhere no remote URL is admitted for its network shape.
    fn judge_deferred(&mut self) -> Result<(), ConfigRefusal> {
        let kind = self.kind;
        self.judge_rewritten()?;
        let network_urls = std::mem::take(&mut self.network_urls);
        if self.helper_remote {
            for item in network_urls {
                self.judge(&item.ctx, &Role::Forced(item.value.clone()), &item.value)
                    .map_err(|stop| {
                        stop.into_refusal(kind, &item.ctx.source, || item.setting.public())
                    })?;
            }
        }
        for item in std::mem::take(&mut self.deferred) {
            let looked_up = item.ctx.scope;
            let mut set = false;
            let mut cleared = false;
            for scope in [Some(looked_up), looked_up.parent()].into_iter().flatten() {
                match self.remotes.get(&(scope, item.value.clone())) {
                    Some(RemoteUrls::Set) => set = true,
                    Some(RemoteUrls::Cleared) => cleared = true,
                    None => {}
                }
            }
            if set && !cleared {
                continue;
            }
            self.judge(&item.ctx, &Role::Url { scp: true }, &item.value)
                .map_err(|stop| {
                    stop.into_refusal(kind, &item.ctx.source, || item.setting.public())
                })?;
        }
        Ok(())
    }

    /// Judge every form a URL rewrite gives a URL value, as a URL of the value's setting.
    ///
    /// The tool rewrites a URL before reading it, so the value as written
    /// proves nothing about what it reads: `[url "ext:"] insteadOf = ab` turns
    /// `ab:/tree/x`, a network URL as written, into `ext::/tree/x`. Git applies
    /// only the longest matching prefix, once; every match is judged, the
    /// longest among them. Mercurial resolves a scheme's result again, so
    /// every form of a scheme chain is judged ([`Self::judge_forms`]). A rewritten URL that is a network URL is kept to be judged
    /// as a path too once a remote names a helper.
    fn judge_rewritten(&mut self) -> Result<(), ConfigRefusal> {
        if self.rewrites.is_empty() {
            return Ok(());
        }
        let pairs = self.rewrites.len().saturating_mul(self.urls.len());
        if pairs > MAX_REWRITE_PAIRS {
            let source = self
                .rewrites
                .first()
                .map(|rewrite| rewrite.source().to_path_buf())
                .unwrap_or_default();
            return Err(self.unreadable(&source, ConfigFault::Rewrites));
        }
        let rewrites = std::mem::take(&mut self.rewrites);
        let mut attempts: usize = 0;
        for url in std::mem::take(&mut self.urls) {
            self.judge_forms(&rewrites, &url, &mut attempts)?;
        }
        Ok(())
    }

    /// Judge every form `rewrites` give `url`: one step of each, and every step of a chain of scheme rewrites.
    ///
    /// A depth-first walk keeps one frame per form on its chain: the form, the
    /// rewrite that gave it (`None` for the value as written), and the next
    /// rewrite to try on it. A prefix rewrite applies only to the value as
    /// written; a scheme rewrite applies to every form, as Mercurial resolves
    /// its result again. Each try is charged to `attempts`, refusing past
    /// [`MAX_REWRITE_PAIRS`]; a chain applying one rewrite twice refuses, as
    /// Mercurial would resolve it without end or the scan cannot bound it, so
    /// a chain holds at most one frame per rewrite.
    fn judge_forms(
        &mut self,
        rewrites: &[Rewrite],
        url: &UrlValue,
        attempts: &mut usize,
    ) -> Result<(), ConfigRefusal> {
        let kind = self.kind;
        let item = &url.item;
        let refuse =
            |stop: Stop| stop.into_refusal(kind, &item.ctx.source, || item.setting.public());
        let mut chain: Vec<(String, Option<usize>, usize)> = vec![(item.value.clone(), None, 0)];
        loop {
            let Some((form, made_by, next)) = chain.last_mut() else {
                return Ok(());
            };
            let index = *next;
            let Some(rewrite) = rewrites.get(index) else {
                chain.pop();
                continue;
            };
            *next = index.saturating_add(1);
            *attempts = attempts.saturating_add(1);
            if *attempts > MAX_REWRITE_PAIRS {
                return Err(self.unreadable(rewrite.source(), ConfigFault::Rewrites));
            }
            if made_by.is_some() && !rewrite.chains() {
                continue;
            }
            let Some(rewritten) = rewrite.apply(form) else {
                continue;
            };
            let rewritten = rewritten.map_err(|reason| refuse(unproven(reason)))?;
            self.judge(&item.ctx, &Role::Url { scp: url.scp }, &rewritten)
                .map_err(&refuse)?;
            if is_network_url(&rewritten, url.scp) && is_remote_url(item.ctx.syntax, &item.setting)
            {
                self.keep_network_url(item, &rewritten)?;
            }
            if rewrite.chains() {
                if chain.iter().any(|(_, made, _)| *made == Some(index)) {
                    return Err(self.unreadable(rewrite.source(), ConfigFault::Rewrites));
                }
                chain.push((rewritten, Some(index), 0));
            }
        }
    }

    /// Keep `value`, a network URL `item`'s setting reads, to be judged as a path once a remote names a helper.
    ///
    /// Refuses once [`MAX_URL_VALUES`] are kept, before the push.
    fn keep_network_url(&mut self, item: &Deferred, value: &str) -> Result<(), ConfigRefusal> {
        if self.network_urls.len() >= MAX_URL_VALUES {
            return Err(self.unreadable(&item.ctx.source, ConfigFault::UrlValues));
        }
        self.network_urls.push(Deferred {
            ctx: Rc::clone(&item.ctx),
            setting: item.setting.clone(),
            value: value.to_owned(),
        });
        Ok(())
    }

    /// Parse a Jujutsu TOML file and judge every string in it, outside the exempt tables.
    ///
    /// The walk keeps an explicit stack, so the depth the parser admits never
    /// becomes recursion here; each key is kept once in an arena of
    /// parent-linked labels, and a setting's text is built only on refusal. A
    /// string is judged as a command line, an array's items as the words of
    /// one: the first the program, the rest its arguments.
    fn judge_toml(&mut self, ctx: &FileCtx, text: &str) -> Result<(), ConfigRefusal> {
        let table: toml::Table = toml::from_str(text).map_err(|e| {
            let line = e.span().map_or(1, |span| line_of(text, span.start));
            self.unreadable(&ctx.source, ConfigFault::Malformed { line })
        })?;
        let kind = self.kind;
        let mut labels: Vec<(Option<usize>, &str)> = Vec::new();
        let mut stack: Vec<(TomlNode<'_>, Option<usize>, bool, TomlPos)> =
            vec![(TomlNode::Table(&table), None, true, TomlPos::Text)];
        while let Some((node, label, top, pos)) = stack.pop() {
            match node {
                TomlNode::Table(table) => {
                    for (key, value) in table {
                        if top && exempt(VcsKind::Jujutsu, (key.as_str(), None, "")) {
                            continue;
                        }
                        let index = labels.len();
                        labels.push((label, key.as_str()));
                        let scope = top && key == "--scope";
                        stack.push((TomlNode::Value(value), Some(index), scope, TomlPos::Text));
                    }
                }
                TomlNode::Value(value) => match value {
                    toml::Value::String(text) => {
                        let judged = match pos {
                            TomlPos::Text => self.judge(ctx, &Role::Words(Runner::None), text),
                            TomlPos::Word(position) => self.judge_word(ctx, text, position),
                        };
                        judged.map_err(|stop| {
                            stop.into_refusal(kind, &ctx.source, || toml_setting(&labels, label))
                        })?;
                    }
                    toml::Value::Array(items) => {
                        stack.extend(items.iter().enumerate().map(|(index, item)| {
                            let position = if index == 0 {
                                Position::Program
                            } else {
                                Position::Argument
                            };
                            (TomlNode::Value(item), label, top, TomlPos::Word(position))
                        }));
                    }
                    toml::Value::Table(inner) => {
                        stack.push((TomlNode::Table(inner), label, top, TomlPos::Text));
                    }
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
        if *role != Role::Exempt {
            value_checks(value).map_err(unproven)?;
        }
        match role {
            Role::Exempt => Ok(()),
            Role::Words(runner) => self.judge_words(ctx, value, *runner),
            Role::Forced(path) => {
                self.judge_words(ctx, path, Runner::None)?;
                self.judge_forced(ctx, path, Reach::Command).map(drop)
            }
            Role::Include(include) => {
                // Queued as named, not as walked: the tool resolves the
                // included file's own relative includes against the directory
                // it named, which a link at the end does not change.
                let mut queued: Vec<PathBuf> = Vec::new();
                for (named, found) in self.judge_forced(ctx, value, Reach::Include)? {
                    if matches!(found.end, End::Entry(..)) && !queued.contains(&named) {
                        queued.push(named);
                    }
                }
                for path in queued {
                    self.pending.push(Pending {
                        path,
                        depth: ctx.depth.saturating_add(1),
                        syntax: ctx.syntax,
                        scope: ctx.scope,
                        reading: ctx.reading.then(*include),
                    });
                }
                Ok(())
            }
            Role::HooksPath => {
                self.judge_words(ctx, value, Runner::None)?;
                for (_, found) in self.judge_forced(ctx, value, Reach::Command)? {
                    if let End::Dir(dir) = found.end {
                        self.list_held(&dir, &found.path).map_err(Stop::Refused)?;
                    }
                }
                Ok(())
            }
            Role::Url { scp } => {
                if is_network_url(value, *scp) {
                    return Ok(());
                }
                self.judge_words(ctx, value, Runner::None)?;
                self.judge_forced(ctx, value, Reach::Command).map(drop)
            }
            Role::UrlList => {
                let url = Role::Url { scp: false };
                self.judge(ctx, &url, value)?;
                for item in hg_list_items(value).map_err(unproven)? {
                    if item != value {
                        self.judge(ctx, &url, item)?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Judge every word of the command line `value`, once `runner` consumed its prefix.
    ///
    /// The prefix is stripped from the value as written, before it is split,
    /// so only the first word loses it, and only when the tool sees it there:
    /// a quoted `'!'/x` keeps it, and the shell then runs `!/x`.
    fn judge_words(&mut self, ctx: &FileCtx, value: &str, runner: Runner) -> Result<(), Stop> {
        let tilde = match ctx.syntax {
            Syntax::Git | Syntax::Hg | Syntax::Darcs | Syntax::GitRemote => Tilde::Shell,
            Syntax::Toml => Tilde::Verbatim,
        };
        let mut words = Words::default();
        match runner.consume(value) {
            Line::Shell {
                text,
                command_prefix,
            } => {
                words
                    .push_split(&text, Position::Program, tilde)
                    .map_err(unproven)?;
                if let Some(prefix) = command_prefix {
                    words.prefix_command(prefix);
                }
            }
            // The whole text is the program, a leading `~` the first
            // character of a relative path; it is judged both ways.
            Line::Exec(text) => words
                .push_forms(text.into_owned(), Position::Program)
                .map_err(unproven)?,
        }
        self.judge_queue(ctx, &mut words)
    }

    /// Judge `text` as one word of a command, standing at `position`.
    fn judge_word(&mut self, ctx: &FileCtx, text: &str, position: Position) -> Result<(), Stop> {
        value_checks(text).map_err(unproven)?;
        let mut words = Words::default();
        words
            .push_forms(text.to_owned(), position)
            .map_err(unproven)?;
        self.judge_queue(ctx, &mut words)
    }

    /// Judge every word on `words`, splitting options and compound words onto it.
    ///
    /// Each word is judged whole by every rule its text triggers, and a
    /// classification only adds judgments: an option's attached argument
    /// ([`option_argument`]) is queued as one word of its own and judged first,
    /// then the option word comes back and is judged whole like any other. A
    /// path-shaped word is resolved; a word holding whitespace, which a program
    /// may run again as a command line (`sh -c '...'`), also has its shell
    /// words queued, the first as a program; a compound word also has its
    /// pieces queued ([`Words::push_pieces`]). The whole word is then admitted
    /// only when it is path-shaped (and resolved), empty, a program name, or an
    /// option; any other word, a number included, may name a file relative to
    /// the directory the tool runs in, so it is unprovable, and `--` or `-`
    /// lets a program read any later word as such a file. Every word is judged
    /// as written: a runner prefix a tool consumes is gone before the value is
    /// split ([`Runner`]), so a runner-shaped word left here (`!/x`, `=/x`) is
    /// the relative path the shell runs.
    ///
    /// Every queued word is strictly shorter than the word that queued it,
    /// but an option word queued back once to be judged whole, and
    /// [`MAX_WORDS`] bounds the pushes.
    fn judge_queue(&mut self, ctx: &FileCtx, words: &mut Words) -> Result<(), Stop> {
        while let Some((word, position, stage)) = words.stack.pop() {
            if word.len() > MAX_PATH_BYTES {
                return Err(unproven(Unprovable::TooLong));
            }
            if word.contains(is_expansion_char) {
                return Err(unproven(Unprovable::Glob));
            }
            if stage == Stage::Fresh
                && let Some(argument) = option_argument(&word)
                    .filter(|argument| !argument.is_empty())
                    .map(str::to_owned)
            {
                words
                    .push_staged(word, position, Stage::ArgumentQueued)
                    .map_err(unproven)?;
                words
                    .push_forms(argument, Position::Argument)
                    .map_err(unproven)?;
                continue;
            }
            let text = word.as_str();
            if text == "-" || text == "--" {
                return Err(unproven(Unprovable::EndOfOptions));
            }
            if text.contains(is_c_space) {
                words
                    .push_split(text, Position::Program, Tilde::Shell)
                    .map_err(unproven)?;
            }
            let shaped = is_path_shaped(text);
            if shaped {
                self.judge_path(ctx, text, Reach::Command)?;
            }
            if text.contains(is_word_separator) {
                words.push_pieces(text, position).map_err(unproven)?;
            }
            let admitted = shaped
                || text.is_empty()
                || position == Position::Program
                || option_argument(text).is_some();
            if !admitted {
                return Err(unproven(Unprovable::BareWord));
            }
        }
        Ok(())
    }

    /// Judge `text` as one path whatever its shape; empty text names nothing.
    ///
    /// Surrounding whitespace is trimmed, which only moves the path within
    /// its directory or makes it absolute; text of whitespace alone (a quoted
    /// `" "`) still names the entry of that name, so it is kept whole. No
    /// runner prefix is stripped: a tool opens the path a setting names
    /// verbatim, so `!/x` is the relative path `!/x`.
    fn judge_forced(
        &mut self,
        ctx: &FileCtx,
        text: &str,
        reach: Reach,
    ) -> Result<Vec<(PathBuf, Resolved)>, Stop> {
        let trimmed = text.trim_matches(is_c_space);
        let path = if trimmed.is_empty() { text } else { trimmed };
        if path.is_empty() {
            return Ok(Vec::new());
        }
        self.judge_path(ctx, path, reach)
    }

    /// Walk `word` from every base, refusing a place inside a grant reached lexically or by the walk.
    ///
    /// A regular file reached is refused when it has a second name: a hard
    /// link the jail holds in a grant rewrites the file the tool runs, and its
    /// other names cannot be found. Each candidate path comes back with what
    /// its walk reached.
    fn judge_path(
        &mut self,
        ctx: &FileCtx,
        word: &str,
        reach: Reach,
    ) -> Result<Vec<(PathBuf, Resolved)>, Stop> {
        self.count_path(&ctx.source).map_err(Stop::Refused)?;
        let candidates = self.candidates(word, &ctx.bases, reach).map_err(unproven)?;
        let mut resolved = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let found = self.walk(&candidate, &ctx.source).map_err(Stop::from)?;
            if self.grants.covers(&candidate) {
                return Err(Stop::Named(Named::InGrant(lexical(&candidate))));
            }
            if let End::Entry(dir, name) = &found.end {
                self.single_named(&candidate, dir, name)?;
            }
            resolved.push((candidate, found));
        }
        Ok(resolved)
    }

    /// The absolute paths `word` may name: itself, under the home, or under each base (and the working tree for a command).
    fn candidates(
        &self,
        word: &str,
        bases: &[PathBuf],
        reach: Reach,
    ) -> Result<Vec<PathBuf>, Unprovable> {
        if word.len() > MAX_PATH_BYTES {
            return Err(Unprovable::TooLong);
        }
        if word.contains('$') || word.contains("%(") || word.split('%').nth(2).is_some() {
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
        let command = reach == Reach::Command;
        if command
            && path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(Unprovable::DotDot);
        }
        let worktree = command.then(|| self.grants.worktree.as_path().join(path));
        Ok(bases
            .iter()
            .map(|base| base.join(path))
            .chain(worktree)
            .collect())
    }
}

/// How far the judging of one queued word has gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Not yet looked at.
    Fresh,
    /// An option whose attached argument is already queued, so only the rules its whole text triggers remain.
    ArgumentQueued,
}

/// How a tool runs the words of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tilde {
    /// Through a shell, which expands a word's unquoted leading `~` to the home directory.
    Shell,
    /// Split like a shell line but run as written (Jujutsu): a leading `~` may be a relative path's first character.
    Verbatim,
}

/// The words of one value still to judge, bounded by [`MAX_WORDS`].
#[derive(Default)]
struct Words {
    /// The words left, next last.
    stack: Vec<(String, Position, Stage)>,
    /// Words pushed so far.
    pushed: u32,
}

impl Words {
    /// Prefix `prefix` to the first pushed word not shaped like an option, at the position it stands.
    ///
    /// A word after a leading option keeps its argument position: it may be
    /// that option's argument (`-c <name>`), and the command then follows it.
    fn prefix_command(&mut self, prefix: &str) {
        if let Some((word, _, _)) = self
            .stack
            .iter_mut()
            .rev()
            .find(|(word, _, _)| !word.starts_with('-'))
        {
            word.insert_str(0, prefix);
        }
    }

    /// Push one word not yet looked at.
    fn push(&mut self, word: String, position: Position) -> Result<(), Unprovable> {
        self.push_staged(word, position, Stage::Fresh)
    }

    /// Push one word judged as far as `stage`.
    fn push_staged(
        &mut self,
        word: String,
        position: Position,
        stage: Stage,
    ) -> Result<(), Unprovable> {
        self.pushed = self.pushed.saturating_add(1);
        if self.pushed > MAX_WORDS {
            return Err(Unprovable::TooManyWords);
        }
        self.stack.push((word, position, stage));
        Ok(())
    }

    /// Push one word, and when it starts with `~` that word read verbatim too.
    ///
    /// A `~` no shell expands (a piece after a separator, an option's
    /// argument, a word a tool runs without a shell) is the first character
    /// of a relative path, and some shells expand one at those places:
    /// both readings are judged.
    fn push_forms(&mut self, word: String, position: Position) -> Result<(), Unprovable> {
        let verbatim = word.starts_with('~').then(|| format!("./{word}"));
        self.push(word, position)?;
        if let Some(verbatim) = verbatim {
            self.push(verbatim, position)?;
        }
        Ok(())
    }

    /// Push the shell words of `text`, the first at `first` and the rest as arguments.
    ///
    /// A word whose leading `~` was quoted or escaped arrives as `./~...`
    /// ([`shell_words`]); one whose leading `~` was not is read as the shell
    /// reads it under [`Tilde::Shell`], and both ways under [`Tilde::Verbatim`].
    fn push_split(&mut self, text: &str, first: Position, tilde: Tilde) -> Result<(), Unprovable> {
        for (index, word) in shell_words(text).into_iter().enumerate().rev() {
            let position = if index == 0 {
                first
            } else {
                Position::Argument
            };
            match tilde {
                Tilde::Shell => self.push(word, position)?,
                Tilde::Verbatim => self.push_forms(word, position)?,
            }
        }
        Ok(())
    }

    /// Push the pieces of `word` between its separators.
    ///
    /// The first piece stands at `position`; each later one at the position
    /// the separator before it leaves: [`piece_after`].
    fn push_pieces(&mut self, word: &str, position: Position) -> Result<(), Unprovable> {
        let mut pieces: Vec<(&str, Position)> = Vec::new();
        let mut next = position;
        for chunk in word.split_inclusive(is_word_separator) {
            let mut chars = chunk.chars();
            let separator = chars.next_back().filter(|c| is_word_separator(*c));
            let piece = if separator.is_some() {
                chars.as_str()
            } else {
                chunk
            };
            pieces.push((piece, next));
            if let Some(separator) = separator {
                next = piece_after(separator, position);
            }
        }
        for (piece, at) in pieces.into_iter().rev() {
            self.push_forms(piece.to_owned(), at)?;
        }
        Ok(())
    }
}

/// The position of the piece after `separator` in a word standing at `word`.
///
/// A redirection (`<`, `>`), an assignment (`=`), and a closing parenthesis
/// are followed by a file or value the program reads, so an argument
/// whatever the word's position. A shell operator that starts a command (`;`,
/// `&`, `|`, `(`) and a `:` or `,` joining parts of one name keep the word's
/// own position: a piece is never judged more leniently than its word.
const fn piece_after(separator: char, word: Position) -> Position {
    match separator {
        ')' | '<' | '>' | '=' => Position::Argument,
        // `; & | ( : ,`, and any other character: never more lenient than the word.
        _ => word,
    }
}

/// Where a TOML node stands: free text, or one word of an argument array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TomlPos {
    /// A string judged as a whole command line.
    Text,
    /// An array item judged as one word.
    Word(Position),
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
    let mut keys: Vec<String> = Vec::new();
    let mut at = label;
    while let Some(index) = at {
        let Some(&(parent, key)) = labels.get(index) else {
            break;
        };
        keys.push(key.to_owned());
        // A parent always precedes its child, so the walk strictly descends.
        at = parent.filter(|p| *p < index);
    }
    keys.reverse();
    ConfigSetting::Table(keys)
}

/// The one-based line holding byte `offset` of `text`.
fn line_of(text: &str, offset: usize) -> usize {
    text.get(..offset)
        .map_or(1, |head| head.matches('\n').count().saturating_add(1))
}

/// Whether `text` names Git's `ext::` transport anywhere, in any case.
fn has_ext(text: &str) -> bool {
    text.as_bytes()
        .windows(5)
        .any(|window| window.eq_ignore_ascii_case(b"ext::"))
}

/// The checks every judged value passes first: no NUL, substitution, expansion, odd space, or `ext::` transport.
fn value_checks(value: &str) -> Result<(), Unprovable> {
    if value.contains('\0') {
        return Err(Unprovable::Nul);
    }
    if value.contains("$(") || value.contains('`') {
        return Err(Unprovable::CommandSubstitution);
    }
    if value.contains('$') {
        return Err(Unprovable::Expansion);
    }
    if value.contains(['\r', '\u{b}', '\u{c}']) {
        return Err(Unprovable::OddSpace);
    }
    if has_ext(value) {
        return Err(Unprovable::ExtTransport);
    }
    Ok(())
}

/// The URL schemes that reach a repository over the network, never through a local program or file.
const NETWORK_SCHEMES: &[&str] = &[
    "http", "https", "ssh", "git", "git+ssh", "ssh+git", "ftp", "ftps",
];

/// Whether `authority` (`[user@]host[:port]`) names a host that cannot be read as an option.
fn host_ok(authority: &str) -> bool {
    let host = authority.rsplit('@').next().unwrap_or_default();
    !authority.is_empty()
        && !authority.starts_with('-')
        && !host.is_empty()
        && !host.starts_with('-')
}

/// Whether `value` is a network URL: a known scheme with a host, or with `scp` Git's `host:path` form.
///
/// A value holding `::` is never one: Git reads `<helper>::<address>`
/// before either form and runs the program `git-remote-<helper>` on the
/// address (`hg::/tree/repo` runs Mercurial on a repository the jail
/// writes), so such a value is judged as a path.
fn is_network_url(value: &str, scp: bool) -> bool {
    if value.is_empty() || value.contains(char::is_whitespace) || value.contains("::") {
        return false;
    }
    if let Some((scheme, rest)) = value.split_once("://") {
        let known = NETWORK_SCHEMES
            .iter()
            .any(|name| scheme.eq_ignore_ascii_case(name));
        let authority = rest.split('/').next().unwrap_or_default();
        return known && host_ok(authority);
    }
    let Some((head, _)) = value.split_once(':').filter(|_| scp) else {
        return false;
    };
    head.len() >= 2
        && head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
        && !head.starts_with(['-', '.'])
        && host_ok(head)
}

/// A path separator of the host.
const fn is_separator(c: char) -> bool {
    c == '/' || (cfg!(windows) && c == '\\')
}

/// A character the shell expands a word at: a glob character or a brace.
///
/// A brace expansion (`{sh,evil}`) turns one word into several, the first a
/// program, so its pieces have no position the scan can prove.
const fn is_expansion_char(c: char) -> bool {
    matches!(c, '*' | '?' | '[' | '{' | '}')
}

/// A character a shell or tool splits one word into several at.
const fn is_word_separator(c: char) -> bool {
    matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>' | '=' | ':' | ',')
}

/// Git's `isspace`: space, tab, newline, and carriage return, never a vertical tab or form feed.
///
/// A judged value still holding a carriage return, vertical tab, or form
/// feed is refused ([`Unprovable::OddSpace`]), so a tool splitting at more or
/// fewer of them than this never sees words the scan did not.
const fn is_c_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// Python's and Haskell's `isspace`, which Mercurial and Darcs split on: Git's and a vertical tab or form feed.
const fn is_wide_space(c: char) -> bool {
    is_c_space(c) || matches!(c, '\u{b}' | '\u{c}')
}

/// Whether `name` is an option name: ASCII letters, digits, and `-`, starting with a letter or digit.
fn is_option_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// The argument the option `word` carries, or `None` when `word` is not an option.
///
/// An option is `--name`, or `--name=` and an argument, with an
/// [`is_option_name`] name; or `-`, one ASCII letter or digit, and an attached
/// argument after an optional `=`. The text beside the argument is then only
/// those characters. Any other word starting with `-` (`--x;/tree/evil.sh`,
/// `-;evil`, `--`, `-`) is not an option. Being an option only admits a word
/// whose whole text no other rule refuses ([`Scan::judge_queue`]).
fn option_argument(word: &str) -> Option<&str> {
    if let Some(long) = word.strip_prefix("--") {
        let (name, argument) = long.split_once('=').unwrap_or((long, ""));
        return is_option_name(name).then_some(argument);
    }
    let rest = word
        .strip_prefix('-')?
        .strip_prefix(|c: char| c.is_ascii_alphanumeric())?;
    Some(rest.strip_prefix('=').unwrap_or(rest))
}

/// Whether `word` is shaped like a path: it holds a separator, starts with `~`, or is `.` or `..`.
fn is_path_shaped(word: &str) -> bool {
    word.contains(is_separator) || word.starts_with('~') || word == "." || word == ".."
}

/// `value` split into shell words: quotes group, a backslash escapes, whitespace separates.
///
/// An unterminated quote ends the last word at the end of the value, so its
/// text is still judged. The shell expands a leading `~` only when every
/// character of its tilde prefix, from the `~` to the first unquoted `/` or
/// the end of the word, is unquoted. A word whose `~` is quoted or escaped
/// (`'~/x'`, `"~/x"`, `\~/x`, `''~/x`), or whose prefix holds a quote or an
/// escape (`~"/x"`, `~\/x`, `~''/x`), names the relative path `~/x`, so it
/// comes back as `./~/x`.
fn shell_words(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    // Whether the word being read started with an unquoted `~` and its tilde prefix is unquoted so far.
    let mut home = false;
    // Whether the word's tilde prefix is still being read.
    let mut in_prefix = false;
    let mut quote: Option<char> = None;
    let finish = |word: String, home: bool| {
        if word.starts_with('~') && !home {
            format!("./{word}")
        } else {
            word
        }
    };
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        let unquoted = match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => {
                quote = None;
                false
            }
            (Some('"') | None, '\\') => {
                in_word = true;
                if let Some(escaped) = chars.next() {
                    word.push(escaped);
                }
                false
            }
            (Some(_), other) => {
                word.push(other);
                false
            }
            (None, '\'' | '"') => {
                in_word = true;
                quote = Some(c);
                false
            }
            (None, other) if is_c_space(other) => {
                if in_word {
                    words.push(finish(std::mem::take(&mut word), home));
                    in_word = false;
                    home = false;
                    in_prefix = false;
                }
                continue;
            }
            (None, other) => {
                if !in_word {
                    home = other == '~';
                    in_prefix = home;
                } else if in_prefix && is_separator(other) {
                    in_prefix = false;
                }
                in_word = true;
                word.push(other);
                true
            }
        };
        if !unquoted && in_prefix {
            home = false;
            in_prefix = false;
        }
    }
    if in_word {
        words.push(finish(word, home));
    }
    words
}

/// Whether Git may read `base` with more URL text after it as `<helper>::<address>`.
///
/// Git takes a URL's leading run of scheme characters (an ASCII letter or
/// digit, then also `+`, `-` and `.`) as a helper's name when `::` follows
/// it. A base that is only such a run, or such a run and one `:` (`hg:`,
/// `ext:`, `gcrypt:`), reaches that form when the rewritten URL's rest starts
/// with `::` or `:`, whatever URL the rest comes from. A base whose run is
/// followed by anything else (`https://`, `git@host:`) never does.
fn is_helper_base(base: &str) -> bool {
    let run = base
        .char_indices()
        .take_while(|&(at, c)| {
            c.is_ascii_alphanumeric() || (at > 0 && matches!(c, '+' | '-' | '.'))
        })
        .count();
    let rest = base.get(run..).unwrap_or_default();
    rest.is_empty() || rest == ":"
}

/// Refuse a `protocol.allow` or `protocol.<name>.allow` that lets Git run a program from a URL the scan does not read.
///
/// Git allows `ext::` only by `protocol.ext.allow` or `protocol.allow`, and
/// a remote helper from a submodule's `.gitmodules` URL only by `always`. A
/// URL the scan reads is judged whatever these say; a URL in a file the jail
/// writes and the scan does not read (`.gitmodules`) is not, so a policy
/// opening either refuses. The network and file transports Git ships run no
/// program a URL names.
fn git_protocol(setting: &Setting, value: &str) -> Result<(), Stop> {
    let Setting::Key {
        section,
        subsection,
        key,
    } = setting
    else {
        return Ok(());
    };
    if &**section != "protocol" || !key.eq_ignore_ascii_case("allow") {
        return Ok(());
    }
    let never = value.eq_ignore_ascii_case("never");
    let always = value.eq_ignore_ascii_case("always");
    let named = |names: &[&str]| {
        subsection
            .as_deref()
            .is_some_and(|name| names.iter().any(|n| name.eq_ignore_ascii_case(n)))
    };
    let opened = if named(&["ext"]) {
        (!never).then_some(Unprovable::ExtTransport)
    } else if named(&["http", "https", "git", "ssh", "file"]) {
        None
    } else {
        always.then_some(Unprovable::RemoteHelper)
    };
    opened.map_or(Ok(()), |why| Err(unproven(why)))
}

/// The URL rewrite `setting` of a file in `ctx` declares: Git's `url.<base>.insteadOf` or `pushInsteadOf`, or a Mercurial `[schemes]` entry.
fn rewrite_of(ctx: &FileCtx, setting: &Setting, value: &str) -> Option<Rewrite> {
    let Setting::Key {
        section,
        subsection,
        key,
    } = setting
    else {
        return None;
    };
    match (ctx.syntax, subsection.as_deref()) {
        (Syntax::Git, Some(base))
            if &**section == "url"
                && (key.eq_ignore_ascii_case("insteadof")
                    || key.eq_ignore_ascii_case("pushinsteadof")) =>
        {
            Some(Rewrite::Prefix {
                source: ctx.source.clone(),
                prefix: value.to_owned(),
                base: base.to_owned(),
            })
        }
        (Syntax::Hg, _) if &**section == "schemes" => Some(Rewrite::Scheme {
            source: ctx.source.clone(),
            scheme: key.clone(),
            template: value.to_owned(),
        }),
        (Syntax::Git | Syntax::Hg | Syntax::Toml | Syntax::Darcs | Syntax::GitRemote, _) => None,
    }
}

/// Whether `value` is a Git boolean.
fn is_git_bool(value: &str) -> bool {
    ["", "true", "false", "yes", "no", "on", "off", "1", "0"]
        .iter()
        .any(|word| value.eq_ignore_ascii_case(word))
}

/// What Git does with a value of `setting`.
fn git_route(setting: &Setting, value: &str) -> Route {
    let Setting::Key {
        section,
        subsection,
        key,
    } = setting
    else {
        return Route::Judge(Role::Words(Runner::None));
    };
    let key = key.to_ascii_lowercase();
    let subsection = subsection.as_deref();
    let shape = (&**section, subsection.is_some(), key.as_str());
    if shape == ("include", false, "path") {
        return Route::Judge(Role::Include(Reading::Always));
    }
    if shape == ("includeif", true, "path") {
        return Route::Judge(Role::Include(Reading::Conditional));
    }
    if shape == ("core", false, "hookspath") {
        return Route::Judge(Role::HooksPath);
    }
    let forced = shape == ("init", false, "templatedir")
        || (shape == ("core", false, "fsmonitor") && !is_git_bool(value));
    if forced {
        return Route::Judge(Role::Forced(value.to_owned()));
    }
    if matches!(
        shape,
        ("remote", true, "url" | "pushurl") | ("submodule", true, "url")
    ) {
        return Route::Judge(Role::Url { scp: true });
    }
    if matches!(
        shape,
        ("branch", true, "remote" | "pushremote") | ("remote", false, "pushdefault")
    ) {
        return Route::RemoteName;
    }
    if exempt(VcsKind::Git, (&**section, subsection, key.as_str())) {
        return Route::Judge(Role::Exempt);
    }
    let runner = match shape {
        // The subsection form (`[alias "x"] command`) is judged the same way:
        // an alias Git does not read runs nothing, one it reads runs so.
        ("alias", _, _) => Runner::GitAlias,
        ("credential", _, "helper") => Runner::GitHelper,
        ("gpg", _, "program" | "defaultkeycommand") | ("core", false, "askpass" | "gitproxy") => {
            Runner::Exec
        }
        ("remote", true, "vcs") => Runner::GitRemote,
        _ => Runner::None,
    };
    Route::Judge(Role::Words(runner))
}

/// Whether `setting` of a file in `syntax` gives a Git remote a URL: `remote.<name>.url` or `pushurl`, or a line of a `remotes/` or `branches/` file.
fn is_remote_url(syntax: Syntax, setting: &Setting) -> bool {
    match (syntax, setting) {
        (Syntax::GitRemote, _) => true,
        (
            Syntax::Git,
            Setting::Key {
                section,
                subsection: Some(_),
                key,
            },
        ) => {
            &**section == "remote"
                && (key.eq_ignore_ascii_case("url") || key.eq_ignore_ascii_case("pushurl"))
        }
        (Syntax::Git | Syntax::Hg | Syntax::Toml | Syntax::Darcs, _) => false,
    }
}

/// The items Mercurial's list parser reads from `value`: text between commas and whitespace.
///
/// A quote, which `parselist` groups and unescapes by, is unprovable rather
/// than modelled.
fn hg_list_items(value: &str) -> Result<impl Iterator<Item = &str>, Unprovable> {
    if value.contains('"') {
        return Err(Unprovable::ListQuote);
    }
    Ok(value
        .split(|c: char| c == ',' || is_wide_space(c))
        .filter(|item| !item.is_empty()))
}

/// Whether `entry`'s value or the name of its setting holds a NUL.
fn holds_nul(entry: &Entry) -> bool {
    let name_holds = match &entry.setting {
        Setting::Key {
            section,
            subsection,
            key,
        } => {
            section.contains('\0')
                || subsection.as_ref().is_some_and(|sub| sub.contains('\0'))
                || key.contains('\0')
        }
        Setting::Include | Setting::Line(_) => false,
    };
    name_holds || entry.value.contains('\0')
}

/// How Mercurial treats a value of `setting`.
fn hg_role(setting: &Setting, value: &str) -> Role {
    let (section, key) = match setting {
        Setting::Key { section, key, .. } => (section, key),
        Setting::Include => return Role::Include(Reading::Always),
        Setting::Line(_) => return Role::Words(Runner::None),
    };
    if &**section == "extensions" {
        // A leading `!` disables the extension; the path after it is still judged.
        return Role::Forced(value.strip_prefix('!').unwrap_or(value).to_owned());
    }
    if &**section == "hooks"
        && let Some((path, _)) = value
            .strip_prefix("python:")
            .and_then(|rest| rest.rsplit_once(':'))
    {
        return Role::Forced(path.to_owned());
    }
    if &**section == "paths" && (!key.contains(':') || key.ends_with(":pushurl")) {
        return Role::UrlList;
    }
    // A `[schemes]` template or a `[subpaths]` replacement is the URL the
    // tool reads in place of one it was given, `.hgsub` sources included; a
    // template is also a URL the scheme chain rewrites again.
    if &**section == "schemes" || &**section == "subpaths" {
        return Role::Url { scp: false };
    }
    if exempt(VcsKind::Mercurial, (&**section, None, key.as_str())) {
        return Role::Exempt;
    }
    // Mercurial runs an `[alias]` after one `!` through the shell, and calls
    // a `[hooks]` value after `python:` as a Python callable it imports.
    let runner = match &**section {
        "alias" => Runner::Bang,
        "hooks" => Runner::Python,
        _ => Runner::None,
    };
    Role::Words(runner)
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
/// deprecated `[name.sub]`, named as Git names them ([`git_header`]); a key of
/// alphanumerics and `-` starting with a letter, optionally `=` and a value; quotes, the escapes `\n \t \b \" \\`, a
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
            let name = git_section(&mut lexer).ok_or(lexer.line)?;
            section = Some(git_header(&name));
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

/// The rest of a section header after `[`: the name Git builds from it, before the key.
///
/// Git lowercases the unquoted part and, for `[base "text"]`, appends `.`
/// and the quoted text verbatim (`get_extended_base_var`), so `[a.B "c"]`
/// names `a.b.c`; [`git_header`] splits that name as Git does.
fn git_section(lexer: &mut GitLexer<'_>) -> Option<String> {
    let mut name = String::new();
    loop {
        let c = lexer.next_char();
        if lexer.eof || c == '\n' {
            return None;
        }
        if is_c_space(c) {
            if name.is_empty() {
                return None;
            }
            let subsection = git_subsection(lexer)?;
            name.push('.');
            name.push_str(&subsection);
            return Some(name);
        }
        if c == ']' {
            return (!name.is_empty()).then_some(name);
        }
        if !(is_git_key_char(c) || c == '.') {
            return None;
        }
        name.push(c.to_ascii_lowercase());
    }
}

/// The section and subsection Git reads from the header name `name`: the section ends at the first `.`.
///
/// Git joins the header name and the key with `.` and splits the full name
/// back (`parse_config_key`): the section up to the first `.`, the key after
/// the last, the subsection between. The key holds no `.`, so the
/// subsection is everything after the header name's first `.`, dots
/// included: `[a.b "c"]` is section `a`, subsection `b.c`.
fn git_header(name: &str) -> (Rc<str>, Option<Rc<str>>) {
    match name.split_once('.') {
        Some((section, subsection)) => (Rc::from(section), Some(Rc::from(subsection))),
        None => (Rc::from(name), None),
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
    if first == '=' || is_wide_space(first) {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    Some((
        key.trim_end_matches(is_wide_space).to_owned(),
        value.trim_matches(is_wide_space).to_owned(),
    ))
}

/// The text after a directive (`%include`, `%unset`) and its separating space, when non-empty.
fn hg_directive<'l>(line: &'l str, directive: &str) -> Option<&'l str> {
    let rest = line.strip_prefix(directive)?;
    if !rest.starts_with(is_wide_space) {
        return None;
    }
    let argument = rest.trim_matches(is_wide_space);
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
        let trimmed = line.trim_matches(is_wide_space);
        if continues {
            if line.starts_with([';', '#']) {
                continue;
            }
            if line.starts_with(is_wide_space) && !trimmed.is_empty() {
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
        .filter(|(_, line)| !line.trim_matches(is_wide_space).is_empty())
        .map(|(index, line)| Entry {
            setting: Setting::Line(index.saturating_add(1)),
            value: line.to_owned(),
        })
        .collect()
}

/// The URLs a Git `remotes/` or `branches/` file names, one entry per URL.
///
/// A `remotes/` file names its URL on a `URL:` line, and its refspecs on
/// `Push:` and `Pull:` lines, which name no file. A `branches/` file holds a
/// URL followed by `#` and a branch; the URL before the `#` is judged, and the
/// whole line too. Any other line is judged as a URL.
fn parse_git_remote(text: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_matches(is_c_space);
        if line.is_empty() || line.starts_with("Push:") || line.starts_with("Pull:") {
            continue;
        }
        let url = line
            .strip_prefix("URL:")
            .map_or(line, |rest| rest.trim_matches(is_c_space));
        let setting = Setting::Line(index.saturating_add(1));
        if let Some((head, _)) = url.split_once('#') {
            entries.push(Entry {
                setting: setting.clone(),
                value: head.to_owned(),
            });
        }
        entries.push(Entry {
            setting,
            value: url.to_owned(),
        });
    }
    entries
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
        for carve in [".git", ".hg", ".jj", "_darcs"] {
            make_dir(&fixture.tree.join(carve));
        }
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
        let carves =
            [".git", ".hg", ".jj", "_darcs"].map(|name| canonical(&fixture.tree.join(name)));
        let [git, hg, jj, darcs] = &carves;
        let grants = Grants::new(&tree, &[&other]).with_carves(&[git, hg, jj, darcs]);
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

    #[cfg(unix)]
    fn hard_linked(result: &Result<(), ConfigRefusal>) -> Option<&Path> {
        match result {
            Err(ConfigRefusal::LinkNamesWritable {
                link,
                named: Named::Unprovable(Unprovable::HardLinked),
                ..
            }) => Some(link.as_path()),
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
        assert_eq!(in_grant(&result), Some(f.tree.join(".githooks").as_path()));
        assert!(
            matches!(
                &result,
                Err(ConfigRefusal::NamesWritableCode {
                    setting: ConfigSetting::Key { key, .. },
                    ..
                }) if &**key == "hooksPath"
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
    fn other_worktree_and_submodule_configs_scanned() {
        let f = fixture("wtmodules");
        let tree = f.tree.display();
        let linked = f.tree.join(".git/worktrees/wt/config.worktree");
        write(&linked, &format!("[core]\n\thooksPath = {tree}/h\n"));
        let result = scan_git(&f);
        assert_eq!(source(&result), Some(linked.as_path()));
        assert_eq!(in_grant(&result), Some(f.tree.join("h").as_path()));
        std::fs::remove_file(&linked).expect("remove worktree config");

        let module = f.tree.join(".git/modules/sub/config");
        write(&module, &format!("[alias]\n\tx = !{tree}/x\n"));
        let result = scan_git(&f);
        assert_eq!(source(&result), Some(module.as_path()));
        assert_eq!(in_grant(&result), Some(f.tree.join("x").as_path()));
    }

    #[test]
    fn config_dir_inside_uncarved_grant_refused() {
        let f = fixture("uncarved");
        let granted_gitdir = f.other.join("gitdir");
        write(&granted_gitdir.join("config"), "[core]\n\tbare = false\n");
        let result = scan_git_at(&f, &granted_gitdir);
        assert!(
            matches!(&result, Err(ConfigRefusal::ConfigInGrant { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn relative_value_resolves_both_bases() {
        let f = fixture("bases");
        let outside_gitdir = f.out.join("gitdir");
        write(&outside_gitdir.join("config"), "[alias]\n\tx = !bin/run\n");
        let result = scan_git_at(&f, &outside_gitdir);
        assert_eq!(in_grant(&result), Some(f.tree.join("bin/run").as_path()));
    }

    #[cfg(unix)]
    #[test]
    fn relative_value_through_link_into_grant_refused() {
        let f = fixture("baselink");
        let outside_gitdir = f.out.join("gitdir");
        write(&outside_gitdir.join("config"), "[alias]\n\tx = !bin/run\n");
        make_dir(&f.other.join("bin"));
        link(&f.other.join("bin"), &outside_gitdir.join("bin"));
        let result = scan_git_at(&f, &outside_gitdir);
        assert_eq!(in_grant(&result), Some(f.other.join("bin/run").as_path()));
    }

    #[cfg(unix)]
    #[test]
    fn nested_include_resolves_against_the_named_directory() {
        let f = fixture("includenamed");
        let real = f.out.join("deep/real.inc");
        write(&real, "[include]\n\tpath = team.cfg\n");
        link(&real, &f.out.join("inc"));
        link(&f.tree.join("team.cfg"), &f.out.join("team.cfg"));
        let shown = f.out.join("inc");
        git_config(&f, &format!("[include]\n\tpath = {}\n", shown.display()));
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("team.cfg").as_path()));
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
        let out = f.out.display();
        git_config(
            &f,
            &format!("[frobnicate \"x\"]\n\trunner = sh {out}/run.sh\n"),
        );
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn non_path_words_refused() {
        let f = fixture("barewords");
        git_config(&f, "[alias]\n\tx = !sh evil\n");
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::BareWord));
        let out = f.out.display();
        git_config(&f, &format!("[alias]\n\tx = !cat {out}/*\n"));
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::Glob));
        git_config(&f, "[alias]\n\tx = !ssh '-oProxyCommand=sh x' host\n");
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::BareWord));
        git_config(&f, "[alias]\n\tx = -c core.hooksPath=x status\n");
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::BareWord));
        git_config(&f, "[alias]\n\tx = !../x\n");
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::DotDot));
    }

    #[test]
    fn program_word_pieces_after_redirect_or_assignment_are_arguments() {
        let f = fixture("programpieces");
        for text in [
            "[alias]\n\tx = !sh<evil\n",
            "[alias]\n\tx = !BASH_ENV=evil;bash\n",
            "[core]\n\tpager = sh<evil\n",
        ] {
            git_config(&f, text);
            assert_eq!(
                unprovable(&scan_git(&f)),
                Some(Unprovable::BareWord),
                "{text:?}"
            );
        }
        git_config(&f, "[alias]\n\tx = !status;log\n");
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn odd_space_in_value_refused() {
        let f = fixture("oddspace");
        let out = f.out.display();
        for space in ['\u{b}', '\u{c}'] {
            git_config(&f, &format!("[alias]\n\tx = !evil{space}{out}/x\n"));
            assert_eq!(
                unprovable(&scan_git(&f)),
                Some(Unprovable::OddSpace),
                "{space:?}"
            );
        }
        git_config(&f, &format!("[alias]\n\tx = \"!evil\r{out}/x\"\n"));
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::OddSpace));
        git_config(&f, &format!("[core]\n\tpager = {out}/x\r\n"));
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
        git_config(&f, "[include]\n\tpath = %(prefix)/etc/team.cfg\n");
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::Expansion));
    }

    #[test]
    fn tilde_user_refused() {
        let f = fixture("tildeuser");
        git_config(&f, "[core]\n\tpager = ~root/bin/x\n");
        assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::TildeUser));
        git_config(&f, "[core]\n\tpager = ~/bin/x\n");
        assert_eq!(scan_git(&f), Ok(()));
        let tree = canonical(&f.tree);
        let git = canonical(&f.tree.join(".git"));
        let grants = Grants::new(&tree, &[]).with_carves(&[&git]);
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
        git_config(&f, &format!("[core]\n\tpager = {out}/present/../evil\n"));
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
                 \tattributesFile = {tree}/.attrs\n\tfsmonitor = true\n\
                 [commit]\n\ttemplate = {tree}/.msg\n\
                 [blame]\n\tignoreRevsFile = {tree}/.revs\n\
                 [remote \"origin\"]\n\turl = git@example.com:team/tree.git\n\
                 \tpushurl = https://example.com/team/tree.git\n\
                 \tfetch = +refs/heads/*:refs/remotes/origin/*\n\
                 \tpush = refs/heads/*:refs/heads/*\n\
                 [branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n\
                 [user]\n\tname = A Person\n\temail = a@example.com\n\
                 [extensions]\n\tworktreeConfig = true\n"
            ),
        );
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn remote_name_resolved_against_defined_remotes() {
        let f = fixture("remotename");
        git_config(
            &f,
            "[remote \"up\"]\n\turl = https://example.com/r\n[branch \"main\"]\n\tremote = up\n",
        );
        assert_eq!(scan_git(&f), Ok(()));
        git_config(&f, "[branch \"main\"]\n\tremote = sub/repo\n");
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("sub/repo").as_path()));
    }

    #[test]
    fn remote_name_defined_only_in_another_repository_judged() {
        let f = fixture("remotescope");
        write(
            &f.tree.join(".git/modules/sub/config"),
            "[remote \"evil\"]\n\turl = https://example.com/r\n",
        );
        git_config(&f, "[branch \"main\"]\n\tremote = evil\n");
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("evil").as_path()));

        git_config(&f, "[remote \"up\"]\n\turl = https://example.com/r\n");
        write(
            &f.tree.join(".git/worktrees/wt/config.worktree"),
            "[branch \"topic\"]\n\tremote = up\n",
        );
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn ext_transport_refused() {
        let f = fixture("exturl");
        let tree = f.tree.display();
        for text in [
            format!("[remote \"origin\"]\n\turl = ext::{tree}/transport %S\n"),
            "[remote \"origin\"]\n\turl = EXT::sh -c x\n".to_owned(),
            "[url \"ext::sh -c x\"]\n\tinsteadOf = origin\n".to_owned(),
            "[submodule \"s\"]\n\turl = ext::sh\n".to_owned(),
        ] {
            git_config(&f, &text);
            assert_eq!(
                unprovable(&scan_git(&f)),
                Some(Unprovable::ExtTransport),
                "{text:?}"
            );
        }
    }

    #[test]
    fn fsmonitor_hook_path_refused() {
        let f = fixture("fsmonitor");
        git_config(&f, "[core]\n\tfsmonitor = fsmonitor-hook\n");
        let result = scan_git(&f);
        assert_eq!(
            in_grant(&result),
            Some(f.tree.join("fsmonitor-hook").as_path())
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
                    [b.Sub]\n\tz = one\\\n two\n\tq = a\\tb\r\n[c.D \"e.F\"]\n\tk = v\n";
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
            ("c", Some("d.e.F"), "k", "v"),
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
        let other = f.other.display();
        let roots = ConfigRoots::Mercurial {
            dot_hg: &dot_hg,
            shared: None,
        };
        write(
            &dot_hg.join("hgrc"),
            &format!(
                "[paths]\ndefault = https://example.com/repo\ndefault:pushrev = .\n\
                 [ui]\nusername = A <a@example.com>\n\
                 [extensions]\nrebase =\nstrip = !\ngone = !{out}/gone.py\n\
                 [hooks]\nx = python:hgext.hook.run\ny =python:{out}/hook.py:run\n"
            ),
        );
        assert_eq!(scan_with(&f, &roots, ConfigLimits::DEFAULT), Ok(()));

        write(
            &dot_hg.join("hgrc"),
            &format!("[paths]\ndefault = {other}/repo\n"),
        );
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(f.other.join("repo").as_path()));

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
            Some(f.tree.join("ext/local.py").as_path())
        );

        write(&dot_hg.join("hgrc"), "[extensions]\nlocal = local.py\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(f.tree.join("local.py").as_path()));

        write(
            &dot_hg.join("hgrc"),
            "[hooks]\ncommit = python:hook.py:run\n",
        );
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(f.tree.join("hook.py").as_path()));

        write(&dot_hg.join("hgrc"), "[ui]\nnot an item\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(fault(&result), Some(ConfigFault::Malformed { line: 2 }));
    }

    #[test]
    fn jj_git_target_repository_scanned() {
        let f = fixture("jjtarget");
        let dot_jj = f.tree.join(".jj");
        let repo = dot_jj.join("repo");
        make_dir(&repo);
        let roots = ConfigRoots::Jujutsu {
            dot_jj: &dot_jj,
            repo: &repo,
        };
        let tree = f.tree.display();
        let target = f.out.join("gitrepo");
        write(
            &target.join("config"),
            &format!("[core]\n\thooksPath = {tree}/h\n"),
        );
        write(
            &repo.join("store/git_target"),
            &target.display().to_string(),
        );
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(f.tree.join("h").as_path()));

        let granted = f.other.join("gitrepo");
        make_dir(&granted);
        write(
            &repo.join("store/git_target"),
            &granted.display().to_string(),
        );
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert!(
            matches!(&result, Err(ConfigRefusal::ConfigInGrant { .. })),
            "{result:?}"
        );

        write(&repo.join("store/git_target"), "git\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(fault(&result), Some(ConfigFault::Malformed { line: 1 }));
    }

    #[test]
    fn git_remote_and_branch_files_judged() {
        let f = fixture("remotefiles");
        let tree = f.tree.display();
        let other = f.other.display();
        let remotes = f.tree.join(".git/remotes/origin");
        write(
            &remotes,
            &format!("URL: {tree}/repo\nPull: refs/heads/*:refs/remotes/origin/*\n"),
        );
        let result = scan_git(&f);
        assert_eq!(source(&result), Some(remotes.as_path()));
        assert_eq!(in_grant(&result), Some(f.tree.join("repo").as_path()));

        write(
            &remotes,
            "URL: https://example.com/r\nPull: refs/heads/*:refs/remotes/origin/*\n",
        );
        assert_eq!(scan_git(&f), Ok(()));

        write(
            &f.tree.join(".git/branches/b"),
            &format!("{other}/r#main\n"),
        );
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.other.join("r").as_path()));
    }

    #[test]
    fn remote_without_url_judged_by_name() {
        let f = fixture("remotenourl");
        let branch = "[branch \"main\"]\n\tremote = evil\n";
        for remote in [
            "[remote \"evil\"]\n\turl =\n",
            "[remote \"evil\"]\n\turl = https://example.com/r\n\turl =\n",
        ] {
            git_config(&f, &format!("{remote}{branch}"));
            let result = scan_git(&f);
            assert_eq!(
                in_grant(&result),
                Some(f.tree.join("evil").as_path()),
                "{remote:?}"
            );
        }
    }

    #[test]
    fn remote_files_never_define_their_remote() {
        let f = fixture("remotefiledef");
        git_config(&f, "[branch \"main\"]\n\tremote = evil\n");
        let remotes = f.tree.join(".git/remotes/evil");
        let branches = f.tree.join(".git/branches/evil");
        let cases = [
            (&remotes, ""),
            (&remotes, "Pull: refs/heads/*:refs/remotes/evil/*\n"),
            (&remotes, "URL:  \n"),
            (&remotes, "URL: https://example.com/r\n"),
            (&branches, "\nhttps://example.com/r\n"),
            (&branches, "https://example.com/r#main\n"),
        ];
        for (file, text) in cases {
            write(file, text);
            let result = scan_git(&f);
            assert_eq!(
                in_grant(&result),
                Some(f.tree.join("evil").as_path()),
                "{file:?} {text:?}"
            );
            std::fs::remove_file(file).expect("remove fixture file");
        }
        git_config(
            &f,
            "[remote \"evil\"]\n\turl = https://example.com/r\n[branch \"main\"]\n\tremote = evil\n",
        );
        write(&remotes, "URL: https://example.com/r\n");
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn remote_defined_only_in_a_conditionally_read_file_judged_by_name() {
        let f = fixture("conditionalremote");
        let defs = f.out.join("defs.cfg");
        let nested = f.out.join("nested.cfg");
        let define = "[remote \"evil\"]\n\turl = https://example.com/r\n";
        let branch = "[branch \"main\"]\n\tremote = evil\n";
        let shown = defs.display();
        write(&defs, define);
        write(&nested, &format!("[include]\n\tpath = {shown}\n"));
        let nested_shown = nested.display();
        for config in [
            format!("[includeIf \"gitdir:/no/such/place/\"]\n\tpath = {shown}\n{branch}"),
            format!("[includeIf \"gitdir:/no/such/place/\"]\n\tpath = {nested_shown}\n{branch}"),
        ] {
            git_config(&f, &config);
            let result = scan_git(&f);
            assert_eq!(
                in_grant(&result),
                Some(f.tree.join("evil").as_path()),
                "{config:?}"
            );
        }

        git_config(&f, branch);
        let worktree_config = f.tree.join(".git/config.worktree");
        write(&worktree_config, define);
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("evil").as_path()));
        std::fs::remove_file(&worktree_config).expect("remove fixture file");

        for config in [
            format!("[include]\n\tpath = {shown}\n{branch}"),
            format!("[include]\n\tpath = {nested_shown}\n{branch}"),
        ] {
            git_config(&f, &config);
            assert_eq!(scan_git(&f), Ok(()), "{config:?}");
        }
    }

    #[test]
    fn remote_cleared_after_an_include_that_sets_it_judged_by_name() {
        let f = fixture("clearedafterinclude");
        let defs = f.out.join("defs.cfg");
        write(&defs, "[remote \"evil\"]\n\turl = https://example.com/r\n");
        let shown = defs.display();
        git_config(
            &f,
            &format!(
                "[include]\n\tpath = {shown}\n[remote \"evil\"]\n\turl =\n\
                 [branch \"main\"]\n\tremote = evil\n"
            ),
        );
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("evil").as_path()));
    }

    #[test]
    fn whitespace_only_url_names_an_entry() {
        let f = fixture("spaceurl");
        git_config(&f, "[remote \"origin\"]\n\turl = \" \"\n");
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join(" ").as_path()));
    }

    #[test]
    fn module_and_jj_git_remote_files_judged() {
        let f = fixture("moduleremotes");
        let tree = f.tree.display();
        let module = f.tree.join(".git/modules/sub");
        write(&module.join("config"), "");
        let remotes = module.join("remotes/origin");
        write(&remotes, &format!("URL: {tree}/evil\n"));
        let result = scan_git(&f);
        assert_eq!(source(&result), Some(remotes.as_path()));
        assert_eq!(in_grant(&result), Some(f.tree.join("evil").as_path()));

        // A module's remote is defined for the module, never for the repository above it.
        write(&remotes, "URL: https://example.com/r\n");
        let define = "[remote \"origin\"]\n\turl = https://example.com/r\n";
        write(&module.join("config"), define);
        git_config(&f, "[branch \"main\"]\n\tremote = origin\n");
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("origin").as_path()));
        git_config(&f, "");
        write(
            &module.join("config"),
            &format!("{define}[branch \"main\"]\n\tremote = origin\n"),
        );
        assert_eq!(scan_git(&f), Ok(()));

        let dot_jj = f.tree.join(".jj");
        let repo = dot_jj.join("repo");
        let jj_remotes = repo.join("store/git/remotes/origin");
        write(&jj_remotes, &format!("URL: {tree}/evil\n"));
        let roots = ConfigRoots::Jujutsu {
            dot_jj: &dot_jj,
            repo: &repo,
        };
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(source(&result), Some(jj_remotes.as_path()));
        assert_eq!(in_grant(&result), Some(f.tree.join("evil").as_path()));
    }

    #[test]
    fn brace_expansion_refused() {
        let f = fixture("brace");
        for text in [
            "[alias]\n\tx = !{sh,evil}\n",
            "[core]\n\tpager = {sh,evil}\n",
        ] {
            git_config(&f, text);
            assert_eq!(
                unprovable(&scan_git(&f)),
                Some(Unprovable::Glob),
                "{text:?}"
            );
        }
    }

    #[test]
    fn quoted_command_line_words_judged() {
        let f = fixture("nestedline");
        let out = f.out.display();
        let tree = f.tree.display();
        for key in ["[core]\n\tpager = ", "[alias]\n\tx = !"] {
            git_config(&f, &format!("{key}sh -c '{out}/run {tree}/evil.sh'\n"));
            let result = scan_git(&f);
            assert_eq!(
                in_grant(&result),
                Some(f.tree.join("evil.sh").as_path()),
                "{key:?}"
            );
            git_config(&f, &format!("{key}sh -c '{out}/run evil'\n"));
            assert_eq!(
                unprovable(&scan_git(&f)),
                Some(Unprovable::BareWord),
                "{key:?}"
            );
            git_config(&f, &format!("{key}sh -c '{out}/run {out}/x.sh'\n"));
            assert_eq!(scan_git(&f), Ok(()), "{key:?}");
        }
    }

    /// `value` as a double-quoted Git config value that parses back to `value`.
    fn git_quoted(value: &str) -> String {
        let mut quoted = String::from("\"");
        for c in value.chars() {
            match c {
                '\\' => quoted.push_str("\\\\"),
                '"' => quoted.push_str("\\\""),
                '\n' => quoted.push_str("\\n"),
                '\t' => quoted.push_str("\\t"),
                other => quoted.push(other),
            }
        }
        quoted.push('"');
        quoted
    }

    #[test]
    fn option_shaped_word_with_a_command_tail_judged() {
        let f = fixture("optiontail");
        let tree = f.tree.display();
        let pager = "[core]\n\tpager";
        let alias = "[alias]\n\tx";
        let value = git_quoted(&format!("less --x;{tree}/evil.sh"));
        git_config(&f, &format!("{pager} = {value}\n"));
        let result = scan_git(&f);
        assert!(
            in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
            "{result:?}"
        );
        for (line, value) in [
            (pager, format!("less --x;{tree}/evil=1")),
            (alias, format!("!sh -c '--x&{tree}/evil'")),
            (pager, format!("less '--x\n{tree}/evil'")),
        ] {
            git_config(&f, &format!("{line} = {}\n", git_quoted(&value)));
            let result = scan_git(&f);
            assert!(
                matches!(result, Err(ConfigRefusal::NamesWritableCode { .. })),
                "{value:?}: {result:?}"
            );
        }
    }

    #[test]
    fn every_option_branch_judges_its_tail() {
        let f = fixture("optionbranches");
        let tree = f.tree.display();
        let out = f.out.display();
        let heads = [
            ("--x", ""),
            ("--x", "=1"),
            ("--x=1", ""),
            ("-x", ""),
            ("-", ""),
            ("!--x", ""),
            ("=--x", ""),
        ];
        for (line, runner) in [("[core]\n\tpager", ""), ("[alias]\n\tx", "!")] {
            for (head, tail) in heads {
                for smuggled in [";", "&", "|", "\n", "\"", "'", " "] {
                    let word = format!("{head}{smuggled}{tree}/evil.sh{tail}");
                    let value = git_quoted(&format!("{runner}less '{word}'"));
                    git_config(&f, &format!("{line} = {value}\n"));
                    let result = scan_git(&f);
                    assert!(
                        matches!(result, Err(ConfigRefusal::NamesWritableCode { .. })),
                        "{line:?} {word:?}: {result:?}"
                    );
                }
            }
            let admitted = format!("{runner}less -R -n --quit-if-one-screen --pattern {out}/x");
            git_config(&f, &format!("{line} = {}\n", git_quoted(&admitted)));
            assert_eq!(scan_git(&f), Ok(()), "{line:?}");
        }
    }

    #[test]
    fn option_word_judged_whole_as_well_as_its_argument() {
        let f = fixture("optionwhole");
        let out = f.out.display();
        let pager = "[core]\n\tpager";
        let alias = "[alias]\n\tx";
        for (line, value) in [
            (pager, format!("-a{out}/less")),
            (alias, format!("!-a{out}/less")),
            (alias, format!("!sh -a{out}/x")),
            (pager, format!("less -5{out}/x")),
            (alias, format!("!sh --a={out}/x")),
            (pager, format!("less {out}/y;-a{out}/x")),
            (pager, "-ax/y".to_owned()),
            (alias, "!sh -ax/y".to_owned()),
            (pager, format!("less {out}/y;-ax/y")),
        ] {
            git_config(&f, &format!("{line} = {}\n", git_quoted(&value)));
            let result = scan_git(&f);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
                "{value:?}: {result:?}"
            );
        }
        for (line, value, why) in [
            (alias, format!("!sh -- -a{out}/x"), Unprovable::EndOfOptions),
            (alias, "!sh -- -ax/y".to_owned(), Unprovable::EndOfOptions),
            (alias, "!sh - -e".to_owned(), Unprovable::EndOfOptions),
            (pager, "less -- -".to_owned(), Unprovable::EndOfOptions),
            (pager, "less 5".to_owned(), Unprovable::BareWord),
            (alias, "!ssh -F5".to_owned(), Unprovable::BareWord),
            (alias, "!sh ';'".to_owned(), Unprovable::BareWord),
            (pager, "less ':'".to_owned(), Unprovable::BareWord),
        ] {
            git_config(&f, &format!("{line} = {}\n", git_quoted(&value)));
            assert_eq!(unprovable(&scan_git(&f)), Some(why), "{value:?}");
        }
    }

    #[test]
    fn runner_prefix_stripped_only_from_a_program_word() {
        let f = fixture("runnerarg");
        let out = f.out.display();
        for text in [
            format!("[core]\n\tpager = less ={out}/x\n"),
            format!("[core]\n\tpager = less !{out}/x\n"),
            format!("[alias]\n\tx = !sh python:{out}/x\n"),
            format!("[core]\n\thooksPath = !{out}/h\n"),
            format!("[core]\n\thooksPath = ={out}/h\n"),
            format!("[init]\n\ttemplateDir = !{out}/t\n"),
        ] {
            git_config(&f, &text);
            let result = scan_git(&f);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
                "{text:?}: {result:?}"
            );
        }
        for value in ["!sh '='", "!sh '!'", "less =x"] {
            git_config(&f, &format!("[alias]\n\tx = {}\n", git_quoted(value)));
            assert_eq!(
                unprovable(&scan_git(&f)),
                Some(Unprovable::BareWord),
                "{value:?}"
            );
        }
        git_config(&f, &format!("[alias]\n\tx = !{out}/a\n"));
        assert_eq!(scan_git(&f), Ok(()));

        // An include path is a file name, never a command: `!` there is the
        // first component of a path relative to the including file's directory.
        let tree = f.tree.display();
        write(&f.out.join("inc"), "[core]\n\tpager = less\n");
        let literal = f.tree.join(".git").join(format!("!{out}")).join("inc");
        write(&literal, &format!("[core]\n\thooksPath = {tree}/hooks\n"));
        git_config(&f, &format!("[include]\n\tpath = !{out}/inc\n"));
        let result = scan_git(&f);
        assert_eq!(source(&result), Some(literal.as_path()), "{result:?}");
        assert_eq!(in_grant(&result), Some(f.tree.join("hooks").as_path()));
    }

    #[cfg(unix)]
    #[test]
    fn spaced_option_argument_judged_as_one_path() {
        let f = fixture("optionspaced");
        let out = f.out.display();
        write(&f.tree.join("evil.sh"), "#!/bin/sh\n");
        link(&f.tree.join("evil.sh"), &f.out.join("a 1"));
        let value = git_quoted(&format!("less '-F{out}/a 1'"));
        git_config(&f, &format!("[core]\n\tpager = {value}\n"));
        let result = scan_git(&f);
        assert_eq!(
            in_grant(&result),
            Some(f.tree.join("evil.sh").as_path()),
            "{result:?}"
        );
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
                    setting: ConfigSetting::Table(parts),
                    ..
                }) if parts == &["fix", "tools", "fmt", "command"]
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
        let out = f.out.display();
        write(
            &dot_darcs.join("prefs/prefs"),
            &format!("test {out}/check.sh\n"),
        );
        assert_eq!(scan_with(&f, &roots, ConfigLimits::DEFAULT), Ok(()));
        write(&dot_darcs.join("prefs/prefs"), "test sh run\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(unprovable(&result), Some(Unprovable::BareWord));
        write(&dot_darcs.join("prefs/prefs"), "\ntest ./run-tests.sh\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(
            in_grant(&result),
            Some(f.tree.join("run-tests.sh").as_path())
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
        write(
            &dot_darcs.join("prefs/defaults"),
            "apply --posthook=./hook\n",
        );
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(f.tree.join("hook").as_path()));
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
    fn hooks_path_through_link_inside_grant_refused() {
        let f = fixture("husky");
        link(&f.out, &f.tree.join(".husky"));
        git_config(&f, "[core]\n\thooksPath = .husky/_\n");
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join(".husky").as_path()));
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

    #[cfg(unix)]
    #[test]
    fn hard_linked_config_and_hook_refused() {
        let f = fixture("hardlink");
        let planted = f.out.join("planted.cfg");
        write(&planted, "[core]\n\tbare = false\n");
        let config = f.tree.join(".git/config");
        std::fs::hard_link(&planted, &config).expect("hard link config");
        assert_eq!(hard_linked(&scan_git(&f)), Some(config.as_path()));
        std::fs::remove_file(&config).expect("remove config");

        let tool = f.out.join("tool");
        write(&tool, "#!/bin/sh\n");
        let hook = f.tree.join(".git/hooks/pre-commit");
        make_dir(&f.tree.join(".git/hooks"));
        std::fs::hard_link(&tool, &hook).expect("hard link hook");
        assert_eq!(hard_linked(&scan_git(&f)), Some(hook.as_path()));
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
        git_config(&f, &format!("[core]\n\tpager = {out}/a {out}/b\n"));
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
    fn helper_transport_url_judged_as_a_path() {
        let f = fixture("helperurl");
        let tree = f.tree.display();
        for text in [
            format!("[remote \"o\"]\n\turl = hg::{tree}/r\n"),
            "[remote \"o\"]\n\turl = hg::vendor/x\n".to_owned(),
            format!("[remote \"o\"]\n\tpushurl = gcrypt::{tree}/r\n"),
            format!("[submodule \"s\"]\n\turl = hg::{tree}/r\n"),
            format!("[branch \"main\"]\n\tremote = hg::{tree}/r\n"),
            format!("[url \"hg::{tree}/r\"]\n\tinsteadOf = x\n"),
            "[remote \"o\"]\n\tvcs = hg\n\turl = https://example.com/x\n".to_owned(),
            "[remote \"o\"]\n\turl = https://example.com/x\n[remote \"p\"]\n\tvcs = hg\n"
                .to_owned(),
        ] {
            git_config(&f, &text);
            let result = scan_git(&f);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
                "{text:?}: {result:?}"
            );
        }
        write(
            &f.tree.join(".git/remotes/o"),
            "URL: https://example.com/x\n",
        );
        git_config(&f, "[remote \"o\"]\n\tvcs = hg\n");
        let result = scan_git(&f);
        assert!(
            in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
            "{result:?}"
        );
        std::fs::remove_file(f.tree.join(".git/remotes/o")).expect("remove remote file");

        git_config(
            &f,
            "[remote \"o\"]\n\turl = https://example.com/x\n\tpushurl = host:repo\n\
             [branch \"main\"]\n\tremote = o\n",
        );
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn quoted_leading_tilde_judged_as_a_relative_path() {
        let f = fixture("quotedtilde");
        for value in [
            "'~/bin/less'",
            "\"~/bin/less\"",
            "\\~/bin/less",
            "''~/bin/less",
            "~\"/bin/less\"",
            "~\\/bin/less",
            "~''/bin/less",
        ] {
            git_config(&f, &format!("[core]\n\tpager = {}\n", git_quoted(value)));
            assert_eq!(
                in_grant(&scan_git(&f)),
                Some(f.tree.join("~/bin/less").as_path()),
                "{value:?}"
            );
        }
        git_config(&f, "[core]\n\tpager = less --log-file=~/log\n");
        assert_eq!(
            in_grant(&scan_git(&f)),
            Some(f.tree.join("~/log").as_path())
        );
        git_config(&f, "[core]\n\tpager = ~/bin/less -R ~/x\n");
        assert_eq!(scan_git(&f), Ok(()));

        let dot_jj = f.tree.join(".jj");
        let repo = dot_jj.join("repo");
        make_dir(&repo);
        let roots = ConfigRoots::Jujutsu {
            dot_jj: &dot_jj,
            repo: &repo,
        };
        for text in [
            "[ui]\npager = [\"~/bin/less\"]\n",
            "[ui]\npager = [\"less\", \"~/x\"]\n",
            "[ui]\npager = \"~/bin/less\"\n",
        ] {
            write(&repo.join("config.toml"), text);
            let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(f.tree.join("~"))),
                "{text:?}: {result:?}"
            );
        }
        write(&repo.join("config.toml"), "[ui]\npager = \"less -R\"\n");
        assert_eq!(scan_with(&f, &roots, ConfigLimits::DEFAULT), Ok(()));
    }

    fn names_code(result: &Result<(), ConfigRefusal>) -> bool {
        matches!(result, Err(ConfigRefusal::NamesWritableCode { .. }))
    }

    #[test]
    fn rewritten_git_url_judged_after_the_rewrite() {
        let f = fixture("urlrewrite");
        let tree = f.tree.display();
        for text in [
            format!(
                "[protocol \"ext\"]\n\tallow = always\n[url \"ext:\"]\n\tinsteadOf = ab\n\
                 [remote \"origin\"]\n\turl = ab:{tree}/evil\n"
            ),
            format!(
                "[url \"ext:\"]\n\tinsteadOf = ab\n[remote \"origin\"]\n\turl = ab:{tree}/evil\n"
            ),
            format!(
                "[url \"ext:\"]\n\tpushInsteadOf = ab\n[remote \"origin\"]\n\tpushurl = ab:{tree}/evil\n"
            ),
            format!(
                "[url \"hg:\"]\n\tinsteadOf = ab\n[remote \"origin\"]\n\turl = ab:{tree}/evil\n"
            ),
            format!("[url \"hg:\"]\n\tinsteadOf = ab\n[submodule \"x\"]\n\turl = ab:{tree}/evil\n"),
            format!("[url \"hg:\"]\n\tinsteadOf = ab\n[branch \"x\"]\n\tremote = ab:{tree}/evil\n"),
            format!(
                "[url \"gcrypt:\"]\n\tinsteadOf = ab\n[remote \"o\"]\n\turl = ab:{tree}/evil\n"
            ),
        ] {
            git_config(&f, &text);
            let result = scan_git(&f);
            assert!(names_code(&result), "{text:?}: {result:?}");
        }

        // The rewrite in an included file, the URL in the file including it.
        let included = f.out.join("rewrite.cfg");
        write(&included, "[url \"hg:\"]\n\tinsteadOf = ab\n");
        let shown = included.display();
        for include in ["[include]", "[includeIf \"gitdir:/no/such/place/\"]"] {
            git_config(
                &f,
                &format!("{include}\n\tpath = {shown}\n[remote \"o\"]\n\turl = ab:{tree}/evil\n"),
            );
            let result = scan_git(&f);
            assert!(names_code(&result), "{include}: {result:?}");
        }

        for text in [
            "[url \"https://example.com/\"]\n\tinsteadOf = gh:\n[remote \"o\"]\n\turl = gh:x/y\n",
            "[url \"git@example.com:\"]\n\tinsteadOf = https://example.com/\n\
             [remote \"o\"]\n\turl = https://example.com/x/y\n",
            "[url \"ssh://git@example.com/\"]\n\tpushInsteadOf = https://example.com/\n\
             [remote \"o\"]\n\turl = https://example.com/x/y\n",
            "[remote \"o\"]\n\turl = example.com:x/y\n",
        ] {
            git_config(&f, text);
            assert_eq!(scan_git(&f), Ok(()), "{text:?}");
        }
    }

    #[test]
    fn rewrite_base_a_helper_can_follow_refused() {
        let f = fixture("helperbase");
        for base in ["hg:", "ext:", "gcrypt:", "hg", "a.b-c+d:", ""] {
            git_config(&f, &format!("[url \"{base}\"]\n\tinsteadOf = gh\n"));
            assert_eq!(
                unprovable(&scan_git(&f)),
                Some(Unprovable::RemoteHelper),
                "{base:?}"
            );
        }
        for base in ["https://example.com/", "git@example.com:", "ab:c", "a_b:"] {
            git_config(&f, &format!("[url \"{base}\"]\n\tinsteadOf = gh\n"));
            assert_eq!(scan_git(&f), Ok(()), "{base:?}");
        }
    }

    #[test]
    fn protocol_policy_opening_a_helper_refused() {
        let f = fixture("protocol");
        for (text, why) in [
            (
                "[protocol \"ext\"]\n\tallow = always\n",
                Unprovable::ExtTransport,
            ),
            (
                "[protocol \"EXT\"]\n\tallow = user\n",
                Unprovable::ExtTransport,
            ),
            (
                "[protocol \"hg\"]\n\tallow = Always\n",
                Unprovable::RemoteHelper,
            ),
            ("[protocol]\n\tallow = always\n", Unprovable::RemoteHelper),
        ] {
            git_config(&f, text);
            assert_eq!(unprovable(&scan_git(&f)), Some(why), "{text:?}");
        }
        for text in [
            "[protocol \"ext\"]\n\tallow = never\n",
            "[protocol \"file\"]\n\tallow = always\n",
            "[protocol \"https\"]\n\tallow = always\n",
            "[protocol \"hg\"]\n\tallow = user\n",
            "[protocol]\n\tallow = user\n",
        ] {
            git_config(&f, text);
            assert_eq!(scan_git(&f), Ok(()), "{text:?}");
        }
    }

    #[test]
    fn rewrite_ceilings() {
        use std::fmt::Write as _;
        let f = fixture("rewriteceil");
        let repeated = |n: usize, line: fn(&mut String, usize)| -> String {
            let mut text = String::new();
            for i in 0..n {
                line(&mut text, i);
            }
            text
        };
        let rewrites = |n: usize| {
            repeated(n, |text, i| {
                write!(
                    text,
                    "[url \"https://example.com/{i}/\"]\n\tinsteadOf = p{i}:\n"
                )
                .expect("write to a String");
            })
        };
        let remotes = |n: usize| {
            repeated(n, |text, i| {
                write!(
                    text,
                    "[remote \"r{i}\"]\n\turl = https://example.com/r{i}\n"
                )
                .expect("write to a String");
            })
        };
        git_config(&f, &rewrites(MAX_URL_REWRITES));
        assert_eq!(scan_git(&f), Ok(()));
        git_config(&f, &rewrites(MAX_URL_REWRITES.saturating_add(1)));
        assert_eq!(fault(&scan_git(&f)), Some(ConfigFault::Rewrites));

        git_config(&f, &format!("{}{}", rewrites(128), remotes(128)));
        assert_eq!(scan_git(&f), Ok(()));
        git_config(&f, &format!("{}{}", rewrites(128), remotes(129)));
        assert_eq!(fault(&scan_git(&f)), Some(ConfigFault::Rewrites));
    }

    #[test]
    fn hg_scheme_rewrite_judged() {
        let f = fixture("hgschemes");
        let dot_hg = f.tree.join(".hg");
        let roots = ConfigRoots::Mercurial {
            dot_hg: &dot_hg,
            shared: None,
        };
        write(
            &dot_hg.join("hgrc"),
            "[schemes]\nhttps = evil\n[paths]\ndefault = https://example.com/x\n",
        );
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert!(
            in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
            "{result:?}"
        );
        write(
            &dot_hg.join("hgrc"),
            "[schemes]\nssh = https://{1}.example.com/\n[paths]\ndefault = ssh://x/y\n",
        );
        assert_eq!(
            unprovable(&scan_with(&f, &roots, ConfigLimits::DEFAULT)),
            Some(Unprovable::Glob)
        );
        write(&dot_hg.join("hgrc"), "[subpaths]\nhttp://h/(.*) = \\1\n");
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        let mut replaced = f.tree.clone();
        replaced.push(r"\1");
        assert_eq!(in_grant(&result), Some(replaced.as_path()));
        write(
            &dot_hg.join("hgrc"),
            "[schemes]\npy = https://hg.example.com/\n[paths]\ndefault = https://example.com/x\n\
             [subpaths]\nhttp://h/(.*)-hg/ = https://hg.example.com/\\1/\n",
        );
        assert_eq!(scan_with(&f, &roots, ConfigLimits::DEFAULT), Ok(()));
    }

    #[test]
    fn runner_prefix_judged_as_written_where_no_tool_consumes_it() {
        let f = fixture("runnerwhole");
        let out = f.out.display();
        for text in [
            format!("[core]\n\tpager = !{out}/less\n"),
            format!("[core]\n\tpager = ={out}/less\n"),
            format!("[core]\n\teditor = !{out}/e\n"),
            format!("[alias]\n\tx = !!{out}/x\n"),
            format!("[alias]\n\tx = \"'!'{out}/x\"\n"),
            format!("[credential]\n\thelper = !!{out}/helper\n"),
            format!("[core]\n\tpager = \"less;!{out}/x\"\n"),
            format!("[alias]\n\tx = !sh -c '!{out}/x'\n"),
            format!("[alias]\n\tx = !sh -c '!{out}/x {out}/y'\n"),
        ] {
            git_config(&f, &text);
            let result = scan_git(&f);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
                "{text:?}: {result:?}"
            );
        }
        git_config(&f, "[alias]\n\tst = !git\n");
        assert_eq!(scan_git(&f), Ok(()));
    }

    #[test]
    fn runner_prefix_consumed_once_where_the_tool_declares_it() {
        let f = fixture("runnerdeclared");
        let out = f.out.display();
        for text in [
            format!("[alias]\n\tx = !{out}/a {out}/b\n"),
            format!("[credential]\n\thelper = !{out}/helper\n"),
            format!("[credential \"https://example.com\"]\n\thelper = !{out}/helper\n"),
        ] {
            git_config(&f, &text);
            assert_eq!(scan_git(&f), Ok(()), "{text:?}");
        }
        // Under a key not declared to consume the prefix, the same values refuse.
        for text in [
            format!("[core]\n\tpager = !{out}/a {out}/b\n"),
            format!("[credential]\n\tusername = !{out}/helper\n"),
        ] {
            git_config(&f, &text);
            let result = scan_git(&f);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
                "{text:?}: {result:?}"
            );
        }
    }

    #[test]
    fn git_command_word_judged_as_the_program_git_runs() {
        let f = fixture("gitdashed");
        let out = f.out.display();
        for text in [
            format!("[alias]\n\tx = {out}/x\n"),
            format!("[alias]\n\tx = -p {out}/x\n"),
            format!("[alias]\n\tx = \"'-p' {out}/x\"\n"),
            format!("[alias]\n\tx = --paginate {out}/x\n"),
            format!("[alias \"x\"]\n\tcommand = {out}/x\n"),
            "[alias]\n\tx = ~/x\n".to_owned(),
            "[credential]\n\thelper = ~/x\n".to_owned(),
            "[credential \"https://example.com\"]\n\thelper = ~/x\n".to_owned(),
        ] {
            git_config(&f, &text);
            let result = scan_git(&f);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
                "{text:?}: {result:?}"
            );
        }
        // An option's argument (`-c <name>`) may stand before the command word.
        git_config(&f, &format!("[alias]\n\tx = -c a.b {out}/x\n"));
        assert!(scan_git(&f).is_err());
        for text in [
            "[alias]\n\tco = checkout\n".to_owned(),
            "[alias]\n\tlg = log --oneline\n".to_owned(),
            format!("[alias \"x\"]\n\tcommand = !{out}/x\n"),
            "[alias]\n\tx = !~/x\n".to_owned(),
            "[credential]\n\thelper = store\n".to_owned(),
            format!("[credential]\n\thelper = {out}/helper\n"),
            "[credential]\n\thelper = !~/x\n".to_owned(),
            "[core]\n\tpager = ~/x\n".to_owned(),
        ] {
            git_config(&f, &text);
            assert_eq!(scan_git(&f), Ok(()), "{text:?}");
        }
    }

    #[test]
    fn git_program_run_without_a_shell_judged_whole() {
        let f = fixture("gitexec");
        let out = f.out.display();
        for text in [
            "[gpg]\n\tprogram = ~/x\n".to_owned(),
            format!("[gpg]\n\tprogram = \"a {out}/x\"\n"),
            "[gpg \"ssh\"]\n\tprogram = ~/x\n".to_owned(),
            "[gpg \"ssh\"]\n\tdefaultKeyCommand = ~/x\n".to_owned(),
            "[core]\n\taskPass = ~/x\n".to_owned(),
            format!("[core]\n\taskPass = \"a {out}/x\"\n"),
            "[core]\n\tgitProxy = ~/x\n".to_owned(),
            "[remote \"o\"]\n\tvcs = ~/x\n".to_owned(),
            format!("[remote \"o\"]\n\tvcs = {out}/x\n"),
            format!("[remote \"o\"]\n\tvcs = \"a {out}/x\"\n"),
        ] {
            git_config(&f, &text);
            let result = scan_git(&f);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
                "{text:?}: {result:?}"
            );
        }
        for text in [
            "[gpg]\n\tprogram = gpg2\n".to_owned(),
            format!("[gpg]\n\tprogram = {out}/gpg\n"),
            format!("[core]\n\taskPass = {out}/askpass\n"),
            "[remote \"o\"]\n\tvcs = hg\n".to_owned(),
            "[core]\n\tsshCommand = ~/x\n".to_owned(),
        ] {
            git_config(&f, &text);
            assert_eq!(scan_git(&f), Ok(()), "{text:?}");
        }
    }

    #[test]
    fn hg_runner_prefix_consumed_only_by_alias_and_hooks() {
        let f = fixture("hgrunner");
        let dot_hg = f.tree.join(".hg");
        let out = f.out.display();
        let roots = ConfigRoots::Mercurial {
            dot_hg: &dot_hg,
            shared: None,
        };
        for text in [
            format!("[alias]\nx = !{out}/x\n"),
            "[hooks]\nx = python:hgext.hook.run\n".to_owned(),
            format!("[hooks]\nx = python:{out}/mod.run\n"),
        ] {
            write(&dot_hg.join("hgrc"), &text);
            assert_eq!(
                scan_with(&f, &roots, ConfigLimits::DEFAULT),
                Ok(()),
                "{text:?}"
            );
        }
        for text in [
            format!("[alias]\nx = !!{out}/x\n"),
            format!("[alias]\nx = python:{out}/mod.run\n"),
            format!("[hooks]\nx = !{out}/x\n"),
            format!("[ui]\neditor = !{out}/x\n"),
        ] {
            write(&dot_hg.join("hgrc"), &text);
            let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
                "{text:?}: {result:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_program_refused() {
        let f = fixture("hardprogram");
        let out = f.out.display();
        write(&f.out.join("single"), "#!/bin/sh\n");
        git_config(&f, &format!("[core]\n\tpager = {out}/single -R\n"));
        assert_eq!(scan_git(&f), Ok(()));

        write(&f.tree.join("pager"), "#!/bin/sh\n");
        std::fs::hard_link(f.tree.join("pager"), f.out.join("pager")).expect("hard link");
        for text in [
            format!("[core]\n\tpager = {out}/pager\n"),
            format!("[core]\n\tpager = less {out}/pager\n"),
            format!("[init]\n\ttemplateDir = {out}/pager\n"),
        ] {
            git_config(&f, &text);
            assert_eq!(
                unprovable(&scan_git(&f)),
                Some(Unprovable::HardLinked),
                "{text:?}"
            );
        }
    }

    #[test]
    fn git_header_names_split_as_git_splits_them() {
        let f = fixture("headername");
        let tree = f.tree.display();
        git_config(
            &f,
            &format!(
                "[remote.o \"x\"]\n\tvcs = hg\n[remote \"o.x\"]\n\turl = ab:{tree}/evil\n\
                 [branch \"main\"]\n\tremote = o.x\n"
            ),
        );
        let result = scan_git(&f);
        assert!(
            in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
            "{result:?}"
        );
        git_config(&f, "[url.a \"/evil\"]\n\tinsteadOf = gh:\n");
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("a./evil").as_path()));
        git_config(&f, "[branch.main \"x\"]\n\tremote = evil\n");
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("evil").as_path()));
    }

    #[test]
    fn git_value_composed_by_a_rewrite_judged() {
        let f = fixture("composed");
        let root = f.tree.parent().expect("fixture root").display().to_string();
        let rewrite = format!("[url \"{root}/\"]\n\tinsteadOf = gh:\n");
        for text in [
            format!("{rewrite}[remote \"o\"]\n\turl = gh:tree/evil\n"),
            format!("{rewrite}[branch \"x\"]\n\tremote = gh:tree/evil\n"),
        ] {
            git_config(&f, &text);
            let result = scan_git(&f);
            assert_eq!(
                in_grant(&result),
                Some(f.tree.join("evil").as_path()),
                "{text:?}"
            );
        }
        git_config(&f, &rewrite);
        write(&f.tree.join(".git/remotes/o"), "URL: gh:tree/evil\n");
        let result = scan_git(&f);
        assert_eq!(in_grant(&result), Some(f.tree.join("evil").as_path()));
    }

    #[test]
    fn hg_paths_value_judged_as_a_list() {
        let f = fixture("hglist");
        let dot_hg = f.tree.join(".hg");
        let roots = ConfigRoots::Mercurial {
            dot_hg: &dot_hg,
            shared: None,
        };
        let tree = f.tree.display();
        for text in [
            format!(
                "[paths]\ndefault = https://example.com/r,{tree}/evil\ndefault:multi-urls = yes\n"
            ),
            format!("[paths]\ndefault = https://example.com/r,{tree}/evil\n"),
            format!("[paths]\ndefault:pushurl = https://example.com/r,,{tree}/evil\n"),
        ] {
            write(&dot_hg.join("hgrc"), &text);
            let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
            assert_eq!(
                in_grant(&result),
                Some(f.tree.join("evil").as_path()),
                "{text:?}"
            );
        }
        // Spaces separate items too; the whole value, holding one, is judged as words.
        write(
            &dot_hg.join("hgrc"),
            &format!("[paths]\ndefault = https://example.com/r {tree}/evil\n"),
        );
        assert!(names_code(&scan_with(&f, &roots, ConfigLimits::DEFAULT)));
        write(&dot_hg.join("hgrc"), "[paths]\ndefault = \"https://a/r\"\n");
        assert_eq!(
            unprovable(&scan_with(&f, &roots, ConfigLimits::DEFAULT)),
            Some(Unprovable::ListQuote)
        );
        write(
            &dot_hg.join("hgrc"),
            "[paths]\ndefault = https://a/r,https://b/r\n",
        );
        assert_eq!(scan_with(&f, &roots, ConfigLimits::DEFAULT), Ok(()));
    }

    #[test]
    fn hg_scheme_chain_judged_to_its_end() {
        let f = fixture("hgchain");
        let dot_hg = f.tree.join(".hg");
        let roots = ConfigRoots::Mercurial {
            dot_hg: &dot_hg,
            shared: None,
        };
        let root = f.tree.parent().expect("fixture root").display().to_string();
        for text in [
            format!(
                "[schemes]\nhttps = ssh://tree/\nssh = {root}/\n[paths]\ndefault = https://x/evil\n"
            ),
            // Each template, rewritten once, is a network URL or a path
            // outside the grants; only the third form reaches the tree.
            format!(
                "[schemes]\nhttps = git://ee/\ngit = ssh://tr\nssh = {root}/\n\
                 [paths]\ndefault = https://x/evil\n"
            ),
            // A template is a URL the chain rewrites again.
            format!("[schemes]\nhttps = ssh://tree/\nssh = {root}/\n"),
        ] {
            write(&dot_hg.join("hgrc"), &text);
            let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
            assert!(
                in_grant(&result).is_some_and(|path| path.starts_with(&f.tree)),
                "{text:?}: {result:?}"
            );
        }
        write(&dot_hg.join("hgrc"), "[schemes]\nhttps = https://x/\n");
        assert_eq!(
            fault(&scan_with(&f, &roots, ConfigLimits::DEFAULT)),
            Some(ConfigFault::Rewrites)
        );
        write(
            &dot_hg.join("hgrc"),
            "[schemes]\ngh = https://example.com/\n[paths]\ndefault = https://example.com/r\n",
        );
        assert_eq!(scan_with(&f, &roots, ConfigLimits::DEFAULT), Ok(()));
    }

    #[cfg(unix)]
    #[test]
    fn hg_scheme_composing_a_path_judged() {
        let f = fixture("hgcompose");
        let dot_hg = f.tree.join(".hg");
        let roots = ConfigRoots::Mercurial {
            dot_hg: &dot_hg,
            shared: None,
        };
        let tree = f.tree.display().to_string();
        let relative = tree.strip_prefix('/').expect("absolute fixture tree");
        write(
            &dot_hg.join("hgrc"),
            &format!("[schemes]\nhttps = /\n[paths]\ndefault = https://{relative}/evil\n"),
        );
        let result = scan_with(&f, &roots, ConfigLimits::DEFAULT);
        assert_eq!(in_grant(&result), Some(f.tree.join("evil").as_path()));
    }

    #[test]
    fn url_values_ceiling() {
        let f = fixture("urlceil");
        let urls = |n: usize| format!("[remote \"o\"]\n{}", "\turl = ab:c\n".repeat(n));
        git_config(&f, &urls(MAX_URL_VALUES));
        assert_eq!(scan_git(&f), Ok(()));
        git_config(&f, &urls(MAX_URL_VALUES.saturating_add(1)));
        assert_eq!(fault(&scan_git(&f)), Some(ConfigFault::UrlValues));
        let rewritten = format!(
            "[url \"https://h/\"]\n\tinsteadOf = ab:\n{}",
            urls(MAX_URL_VALUES)
        );
        git_config(&f, &rewritten);
        assert_eq!(fault(&scan_git(&f)), Some(ConfigFault::UrlValues));
    }

    #[cfg(unix)]
    #[test]
    fn hg_scheme_chain_tries_bounded() {
        let f = fixture("hgtries");
        let dot_hg = f.tree.join(".hg");
        let roots = ConfigRoots::Mercurial {
            dot_hg: &dot_hg,
            shared: None,
        };
        let levels = [
            ("https", "ssh"),
            ("ssh", "git"),
            ("git", "ftp"),
            ("ftp", "ftps"),
            ("ftps", "http"),
            ("http", "git+ssh"),
            ("git+ssh", "ssh+git"),
        ];
        let mut text = String::from("[schemes]\n");
        for (name, next) in levels {
            text.push_str(&format!("{name} = {next}://h/\n").repeat(18));
        }
        write(&dot_hg.join("hgrc"), &text);
        assert_eq!(
            fault(&scan_with(&f, &roots, ConfigLimits::DEFAULT)),
            Some(ConfigFault::Rewrites)
        );
    }

    #[cfg(unix)]
    #[test]
    fn hg_scheme_form_too_long_refused() {
        let f = fixture("hglong");
        let dot_hg = f.tree.join(".hg");
        let roots = ConfigRoots::Mercurial {
            dot_hg: &dot_hg,
            shared: None,
        };
        let long = "a".repeat(MAX_PATH_BYTES);
        write(
            &dot_hg.join("hgrc"),
            &format!("[schemes]\nssh = https://h/{long}/\n[paths]\ndefault = ssh://x/r\n"),
        );
        assert_eq!(
            unprovable(&scan_with(&f, &roots, ConfigLimits::DEFAULT)),
            Some(Unprovable::TooLong)
        );
    }

    #[test]
    fn nul_in_a_value_or_a_name_refused() {
        let f = fixture("nul");
        let tree = f.tree.display();
        for text in [
            format!("[core]\n\thooksPath = \"{tree}\0x\"\n"),
            "[remote \"o\0x\"]\n\turl = https://h/r\n[branch \"m\"]\n\tremote = \"o\0x\"\n"
                .to_owned(),
        ] {
            git_config(&f, &text);
            assert_eq!(unprovable(&scan_git(&f)), Some(Unprovable::Nul), "{text:?}");
        }
    }

    #[test]
    fn vcs_display_escapes_control_bytes() {
        let refusal = |source: &str, key: &str| ConfigRefusal::NamesWritableCode {
            kind: VcsKind::Git,
            source: PathBuf::from(source),
            setting: ConfigSetting::Key {
                section: "alias".into(),
                subsection: None,
                key: key.into(),
            },
            named: Named::InGrant(PathBuf::from("/tree/\u{1b}[2Jx")),
        };
        let shown = refusal("/a\nb", "k\u{202e}").to_string();
        assert!(!shown.contains('\n'), "{shown}");
        assert!(!shown.contains('\u{1b}'), "{shown}");
        assert!(!shown.contains('\u{202e}'), "{shown}");
        assert!(shown.contains("/a\\u{a}b"), "{shown}");
        assert!(shown.contains("alias.\"k\\u{202e}\""), "{shown}");
        assert!(
            shown.contains("point the setting outside the writable grants"),
            "{shown}"
        );
        let literal = refusal("/a\\u{a}b", "k").to_string();
        let raw = refusal("/a\nb", "k").to_string();
        assert_ne!(literal, raw);
    }
}
