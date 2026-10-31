//! The package index entry schema and reader.
//!
//! The index is a git repository holding one entry file per package at
//! `packages/<name>.toml`. An entry lists every published version, and for each
//! the source repository, its pinned revision, the sha256 of the source tree at
//! that revision, and the capability set the publisher declared. Resolution
//! ([`resolve_version`]) picks the highest published version satisfying a
//! [`semver::VersionReq`].
//!
//! Parse, don't validate: an entry file is read into a typed [`IndexEntry`] whose
//! versions are [`PublishedVersion`]s and whose capabilities are [`Capability`],
//! so a malformed version, a version carrying build metadata, or an unknown
//! capability name is a hard error at read time, never a resolution-time
//! surprise.
//!
//! [`SourceUrl`] and [`CommitId`] are typed newtypes that gate the two
//! publisher-controlled fields. An unvalidated string can never reach the `git`
//! subprocess — it must first pass through one of these constructors.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use ipe_diagnostics::terminal::{DisplayHazard, is_display_hazard};
use ipe_ir::Capability;
use ipe_path_core::{ElementClass, Namespace, Regime, Volume};

use crate::CliError;
pub use crate::cache::TreeHashError;
use crate::line_grammar::{LINE_BLANKS, LineFault, LineKey, LineShape, TextLine, quoted};
use crate::package_name::PackageName;
use crate::published_version::{PublishedVersion, require_successor};
use crate::publisher::{AttestedActor, BlessedPublisher, SelfDeclaredPublisher};
use crate::signing::SignatureBundle;

/// A git transport the package index accepts for a source repository.
///
/// Every accepted transport authenticates the server (`https`, `ssh`) or is
/// local (`file`). The plaintext `git://` transport, which neither encrypts
/// nor authenticates, has no variant, so no source URL can carry it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// `https://` — TLS-authenticated HTTP.
    Https,
    /// `ssh://` — SSH with host-key checking.
    Ssh,
    /// A local directory — a `file://` URL or a bare absolute path.
    File,
}

impl Transport {
    /// Every accepted transport.
    pub const ALL: [Self; 3] = [Self::Https, Self::Ssh, Self::File];

    /// The transport's name as `GIT_ALLOW_PROTOCOL` spells it.
    #[must_use]
    pub const fn git_protocol(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Ssh => "ssh",
            Self::File => "file",
        }
    }
}

/// Why a text names a network or device location, never a local directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemotePath {
    /// `\\server\share`, `//server/share`, `/\server`, a bare `\\server`.
    Unc,
    /// `\\?\UNC\server\share`.
    VerbatimUnc,
    /// `\\.\…` (pipes, volumes, `\\.\C:`).
    DeviceNamespace,
    /// `\\?\<name>` whose name is not a drive (`\\?\GLOBALROOT\…`, `\\?\Volume{…}`).
    VerbatimNonDrive,
    /// `\??\…` / `/??/…` — the NT object-manager prefix Win32 passes through.
    NtObjectPath,
    /// `file://<host>/…` with a host other than empty or `localhost`.
    FileAuthority,
}

impl RemotePath {
    /// The kind of location, as a refusal names it.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Unc => "a UNC network share",
            Self::VerbatimUnc => "a verbatim UNC network share",
            Self::DeviceNamespace => "a Win32 device-namespace path",
            Self::VerbatimNonDrive => "a verbatim path that names no drive",
            Self::NtObjectPath => "an NT object-manager path",
            Self::FileAuthority => "a file:// URL naming another host",
        }
    }
}

/// The network share or device `text` names, if any — the one classifier.
///
/// The text is read under the Windows volume grammar ([`Volume::parse`] under
/// [`Regime::Windows`]) on every host: a recorded source is shared data a
/// Windows host may read later, and on Unix a `//`-led path is only another
/// spelling of `/`, so refusing it there costs nothing.
#[must_use]
pub fn remote_path(text: &str) -> Option<RemotePath> {
    match Volume::parse(text, Regime::Windows) {
        Volume::Unc { .. } => Some(RemotePath::Unc),
        Volume::VerbatimUnc { .. } => Some(RemotePath::VerbatimUnc),
        Volume::Namespaced {
            tag: Namespace::Device,
            ..
        } => Some(RemotePath::DeviceNamespace),
        Volume::Namespaced {
            tag: Namespace::Verbatim,
            name,
        } => (!name.is_some_and(is_drive_name)).then_some(RemotePath::VerbatimNonDrive),
        Volume::Drive(_) | Volume::None => {
            names_nt_object_root(text).then_some(RemotePath::NtObjectPath)
        }
    }
}

/// Is `name` a drive designator (`C:`): one UTF-16 unit, then `:`?
fn is_drive_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some(drive), Some(':'), None) if drive.len_utf16() == 1
    )
}

/// Does `text` open with the NT object-manager root (`\??\`, `/??/`, a bare `\??`)?
fn names_nt_object_root(text: &str) -> bool {
    let sep = |c: &u8| matches!(c, b'/' | b'\\');
    match text.as_bytes() {
        [lead, b'?', b'?', rest @ ..] if sep(lead) => rest.first().is_none_or(sep),
        _ => false,
    }
}

/// Does `text` lead with a drive, plain (`C:`) or verbatim (`\\?\C:`)?
fn names_a_drive(text: &str) -> bool {
    match Volume::parse(text, Regime::Windows) {
        Volume::Drive(_) => true,
        Volume::Namespaced {
            tag: Namespace::Verbatim,
            name,
        } => name.is_some_and(is_drive_name),
        Volume::None
        | Volume::Unc { .. }
        | Volume::VerbatimUnc { .. }
        | Volume::Namespaced {
            tag: Namespace::Device,
            ..
        } => false,
    }
}

/// Why a local source was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalRefusal {
    /// The text names a network share or a device.
    Remote(RemotePath),
    /// Not an absolute local path on this host: a relative path, `C:x`
    /// (drive-relative), or `\x` / `/x` on Windows (current-drive-relative).
    NotAnchored,
    /// A drive form (`C:\x`, `\\?\C:\x`) under the Unix regime, where git would
    /// read `C:` as an scp-style host.
    ForeignDrive,
    /// A Windows element that opens a device (`CON`, `nul.txt`, `COM1`).
    DeviceElement,
    /// A `\\?\X:\…` whose remainder is not lossless as a plain path.
    LossyVerbatim,
    /// A `%` in a `file://` URL, which git would decode into a text nobody judged.
    PercentInFileUrl,
}

/// A local repository location, in the plain spelling git receives.
///
/// Built only by reading the text under the Windows volume grammar, so no
/// inhabitant names a network share, a device namespace, an NT object path or
/// a non-local `file://` host, under either host regime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalRepo {
    plain: String,
}

impl LocalRepo {
    /// Read a bare path as an absolute local location under `regime`.
    fn parse(text: &str, regime: Regime) -> Result<Self, LocalRefusal> {
        if let Some(kind) = remote_path(text) {
            return Err(LocalRefusal::Remote(kind));
        }
        let plain = match regime {
            Regime::Unix => {
                if names_a_drive(text) {
                    return Err(LocalRefusal::ForeignDrive);
                }
                if !text.starts_with('/') {
                    return Err(LocalRefusal::NotAnchored);
                }
                text
            }
            Regime::Windows => Self::windows_plain(text)?,
        };
        Ok(Self {
            plain: plain.to_owned(),
        })
    }

    /// The plain spelling of an absolute Windows location: `X:\…` / `X:/…`, or
    /// a lossless `\\?\X:\…` with its verbatim prefix dropped.
    fn windows_plain(text: &str) -> Result<&str, LocalRefusal> {
        let volume = Volume::parse(text, Regime::Windows);
        match volume {
            Volume::Drive(_) => {
                let rooted = text
                    .get(volume.byte_len()..)
                    .is_some_and(|rest| rest.starts_with(['\\', '/']));
                if !rooted {
                    return Err(LocalRefusal::NotAnchored);
                }
                if ElementClass::windows_elements(text).any(|c| c == ElementClass::DosDevice) {
                    return Err(LocalRefusal::DeviceElement);
                }
                Ok(text)
            }
            Volume::Namespaced {
                tag: Namespace::Verbatim,
                name: Some(drive),
            } if is_drive_name(drive) => Self::verbatim_plain(text, drive),
            Volume::None
            | Volume::Unc { .. }
            | Volume::VerbatimUnc { .. }
            | Volume::Namespaced { .. } => Err(LocalRefusal::NotAnchored),
        }
    }

    /// `\\?\X:\a\b` as `X:\a\b`, when every element after the drive is a plain
    /// name that Win32 reads unchanged without the verbatim prefix.
    fn verbatim_plain<'a>(text: &'a str, drive: &str) -> Result<&'a str, LocalRefusal> {
        let plain = text
            .strip_prefix(r"\\?\")
            .ok_or(LocalRefusal::LossyVerbatim)?;
        let tail = plain
            .strip_prefix(drive)
            .and_then(|after| after.strip_prefix('\\'))
            .ok_or(LocalRefusal::LossyVerbatim)?;
        let lossless = !tail.contains('/')
            && (tail.is_empty()
                || tail
                    .split('\\')
                    .all(|e| ElementClass::of(e.as_bytes()) == ElementClass::Name));
        if lossless {
            Ok(plain)
        } else {
            Err(LocalRefusal::LossyVerbatim)
        }
    }

    /// Read the text after `file://` as a local location under `regime`.
    fn from_file_url(after_scheme: &str, regime: Regime) -> Result<Self, LocalRefusal> {
        let path = file_url_path(after_scheme)?;
        let path = match path.strip_prefix('/') {
            Some(drive_path) if regime.is_windows() && names_a_drive(drive_path) => drive_path,
            Some(_) | None => path,
        };
        Self::parse(path, regime)
    }

    /// The location as a filesystem path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.plain)
    }
}

/// The path of a `file://` URL (the text after the scheme), refusing a
/// non-local host, a `%`, or a path naming a network share or device.
fn file_url_path(after_scheme: &str) -> Result<&str, LocalRefusal> {
    let (authority, path) = after_scheme
        .find('/')
        .map_or((after_scheme, ""), |at| after_scheme.split_at(at));
    if !(authority.is_empty() || authority.eq_ignore_ascii_case("localhost")) {
        return Err(LocalRefusal::Remote(RemotePath::FileAuthority));
    }
    if after_scheme.contains('%') {
        return Err(LocalRefusal::PercentInFileUrl);
    }
    remote_path(path).map_or(Ok(path), |kind| Err(LocalRefusal::Remote(kind)))
}

/// Where a source repository lives, by transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceKind {
    /// `https://` — TLS-authenticated HTTP.
    Https,
    /// `ssh://` — SSH with host-key checking.
    Ssh,
    /// A local directory, from a bare absolute path or a `file://` URL.
    Local(LocalRepo),
}

/// Whether `c` may appear in a network source URL.
///
/// An RFC 3986 unreserved or reserved character, or `%`. ASCII only, so no
/// homoglyph, space, quote, backslash, or invisible character reaches a
/// consent prompt or `git`.
#[must_use]
pub const fn is_url_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.'
                | '_'
                | '~'
                | ':'
                | '/'
                | '?'
                | '#'
                | '['
                | ']'
                | '@'
                | '!'
                | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | ';'
                | '='
                | '%'
        )
}

/// Whether `c` may appear in a recorded local path: anything but `"` and a
/// [`is_display_hazard`] character, so a path stays inside its quoted line and
/// displays as the bytes it names.
#[must_use]
pub fn is_recordable_path_char(c: char) -> bool {
    c != '"' && !is_display_hazard(c)
}

/// Why a raw `source` value was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRefusal {
    /// The plaintext, unauthenticated `git://` transport.
    Plaintext,
    /// An injection-shaped value: a leading `-`, a `::`, or a character outside
    /// the location's alphabet ([`is_url_char`] or [`is_recordable_path_char`]).
    Invalid,
    /// A network share or a device.
    Remote(RemotePath),
    /// A local location this host cannot admit.
    Local(LocalRefusal),
}

impl From<LocalRefusal> for SourceRefusal {
    fn from(refusal: LocalRefusal) -> Self {
        match refusal {
            LocalRefusal::Remote(kind) => Self::Remote(kind),
            LocalRefusal::NotAnchored
            | LocalRefusal::ForeignDrive
            | LocalRefusal::DeviceElement
            | LocalRefusal::LossyVerbatim
            | LocalRefusal::PercentInFileUrl => Self::Local(refusal),
        }
    }
}

impl SourceRefusal {
    /// The refusal as the CLI reports it for package `pkg`'s `raw` source.
    #[must_use]
    pub fn into_cli(self, pkg: &PackageName, raw: &str) -> CliError {
        let shown = crate::style::TerminalSafe::sanitize(&format!("{raw:?}"));
        CliError::Resolve(match self {
            Self::Plaintext => crate::text::msg::index_source_url_plaintext(pkg, &shown),
            Self::Remote(kind) | Self::Local(LocalRefusal::Remote(kind)) => {
                crate::text::msg::index_source_url_remote(pkg, &kind.describe(), &shown)
            }
            Self::Invalid
            | Self::Local(
                LocalRefusal::NotAnchored
                | LocalRefusal::ForeignDrive
                | LocalRefusal::DeviceElement
                | LocalRefusal::LossyVerbatim
                | LocalRefusal::PercentInFileUrl,
            ) => crate::text::msg::index_source_url_invalid(pkg, &shown),
        })
    }
}

/// A validated source-repository location accepted by the package index.
///
/// The accept set is the [`Transport`] set: `https://`, `ssh://`, and a local
/// directory, named by a `file://` URL whose host is empty or `localhost` or
/// by a bare path absolute on this host (`/x` on Unix; `X:\x` or `\\?\X:\x` on
/// Windows). A `git://` URL is refused with a diagnostic naming its `https://`
/// fix. Any value that begins with `-` (option injection) or contains `::`
/// (git transport helpers such as `ext::` or `fd::`, the real RCE vector) is
/// rejected at parse time so a malicious index entry can never reach the `git`
/// subprocess. A network URL admits only [`is_url_char`] (RFC 3986, ASCII) and a
/// local location only [`is_recordable_path_char`], so a source can neither
/// break out of the quoted, line-oriented files (`ipe.lock`, index entries) it
/// is recorded in nor display differently from what `git` is handed. A location naming a network share or a device (`//host/share`,
/// `\\?\UNC\…`, `\\.\…`, `\??\…`, `file://host/…`) has no representation on any
/// host, so opening a source never contacts a host the transport did not name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceUrl {
    recorded: String,
    kind: SourceKind,
}

impl SourceUrl {
    /// Parse a raw string from the index into a [`SourceUrl`] under the host's
    /// path regime.
    ///
    /// Rejected: `git://` (plaintext, unauthenticated), a leading `-` (git flag
    /// injection), `::` anywhere (transport-helper execution, the RCE vector),
    /// a network URL character outside [`is_url_char`] or a local character
    /// outside [`is_recordable_path_char`], a network share or device location,
    /// and any local location that is not absolute on this host.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when the value is not an accepted source form.
    pub fn parse(pkg: &PackageName, raw: &str) -> Result<Self, CliError> {
        Self::parse_in(raw, ipe_path_core::HOST).map_err(|refusal| refusal.into_cli(pkg, raw))
    }

    /// [`Self::parse`] under an explicit path `regime`.
    fn parse_in(raw: &str, regime: Regime) -> Result<Self, SourceRefusal> {
        if raw.starts_with("git://") {
            return Err(SourceRefusal::Plaintext);
        }
        // Fail closed: absent proof the transport is safe, reject.
        // `-`-leading values would be parsed as git flags; `::` introduces
        // transport helpers (e.g. `ext::`) that execute arbitrary commands.
        let network = raw.starts_with("https://") || raw.starts_with("ssh://");
        let alphabet: fn(char) -> bool = if network {
            is_url_char
        } else {
            is_recordable_path_char
        };
        if raw.starts_with('-') || raw.contains("::") || !raw.chars().all(alphabet) {
            return Err(SourceRefusal::Invalid);
        }
        let kind = if raw.starts_with("https://") {
            SourceKind::Https
        } else if raw.starts_with("ssh://") {
            SourceKind::Ssh
        } else if let Some(after_scheme) = raw.strip_prefix("file://") {
            SourceKind::Local(LocalRepo::from_file_url(after_scheme, regime)?)
        } else {
            SourceKind::Local(LocalRepo::parse(raw, regime)?)
        };
        Ok(Self {
            recorded: raw.to_owned(),
            kind,
        })
    }

    /// The recorded spelling, as the lockfile, an index entry and publisher
    /// inference hold it — never a git argument (that is [`Self::git_remote`]).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.recorded
    }

    /// Where the repository lives.
    #[must_use]
    pub const fn kind(&self) -> &SourceKind {
        &self.kind
    }

    /// The `git remote add` argument: the recorded URL for `https`/`ssh`, the
    /// plain path for a local repository.
    ///
    /// The exact text returned is judged again here, so a value built by any
    /// path is refused at the sink when it names a network share or a device.
    ///
    /// # Errors
    /// [`SourceRefusal::Remote`] when the argument names a network share or a
    /// device; [`SourceRefusal::Invalid`] when it is injection-shaped.
    pub fn git_remote(&self) -> Result<&str, SourceRefusal> {
        let arg = match &self.kind {
            SourceKind::Https | SourceKind::Ssh => self.recorded.as_str(),
            SourceKind::Local(repo) => repo.plain.as_str(),
        };
        sink_check(arg)?;
        Ok(arg)
    }

    /// The transport the location uses.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        match self.kind {
            SourceKind::Https => Transport::Https,
            SourceKind::Ssh => Transport::Ssh,
            SourceKind::Local(_) => Transport::File,
        }
    }
}

/// The git-sink refusal: `arg` names no network share or device (spelled bare
/// or as a `file://` URL) and is not injection-shaped.
fn sink_check(arg: &str) -> Result<(), SourceRefusal> {
    if let Some(after_scheme) = arg
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("file://"))
        .and_then(|_| arg.get(7..))
    {
        file_url_path(after_scheme)?;
    }
    if let Some(kind) = remote_path(arg) {
        return Err(SourceRefusal::Remote(kind));
    }
    if arg.starts_with('-') || arg.contains("::") {
        return Err(SourceRefusal::Invalid);
    }
    Ok(())
}

impl std::fmt::Display for SourceUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.recorded)
    }
}

/// An injection-safe requested ref: what the author typed in their manifest.
///
/// Accepts full commit hashes, abbreviated hashes, ref names, and `HEAD` —
/// anything git itself accepts — as long as the value is not injection-shaped.
/// Rejected: a leading `-` (git flag injection), `::` anywhere (transport
/// helper), whitespace or control characters, git refspec metacharacters
/// (`..`, `~`, `^`, `:`, `?`, `*`, `[`, `\`, `@{`), and a trailing `/` or
/// `.lock` (path-confusion vectors).
///
/// A `CommitId` is the REQUEST spelling — what to check out. It is deliberately
/// distinct from [`PinnedRev`], which holds only the resolved immutable SHA
/// recorded in the lockfile or index entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitId(String);

impl CommitId {
    /// Parse a raw string into a [`CommitId`], rejecting injection-shaped values.
    ///
    /// Accepts any non-injection ref name, including full/abbreviated hashes,
    /// branch names, and `HEAD`. Rejected: a leading `-`, `::`, whitespace,
    /// control chars, git refspec metacharacters (`..`, `~`, `^`, `:`, `?`,
    /// `*`, `[`, `\`, `@{`), trailing `/`, and `.lock` suffix.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when the value is injection-shaped.
    pub fn parse(pkg: &PackageName, raw: &str) -> Result<Self, CliError> {
        let injection = raw.is_empty()
            || raw.starts_with('-')
            || raw.contains("::")
            || raw
                .chars()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
            || raw.contains("..")
            || raw.contains('~')
            || raw.contains('^')
            || raw.contains(':')
            || raw.contains('?')
            || raw.contains('*')
            || raw.contains('[')
            || raw.contains('\\')
            || raw.contains("@{")
            || raw.ends_with('/')
            || std::path::Path::new(raw)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("lock"));
        if injection {
            return Err(CliError::Resolve(crate::text::msg::index_rev_injection(
                pkg,
                &crate::style::TerminalSafe::sanitize(&format!("{raw:?}")),
            )));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The validated commit-id string, safe to pass to `git checkout <rev>`.
    ///
    /// The `CommitId` parse boundary guarantees this value cannot start with
    /// `-`, so passing it without `--` is safe — `--` in `git checkout` means
    /// "treat as a path, not a ref", which is wrong for a commit id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CommitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a recorded rev was read, which decides how to recover from a bad one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevSite {
    /// A `rev` field of `ipe.lock`.
    Lockfile,
    /// A `rev` field of a registry index entry.
    IndexEntry,
    /// The commit `git rev-parse` reported for a checkout.
    GitHead,
}

impl RevSite {
    /// The remedy a refused rev read at this site names.
    #[must_use]
    pub const fn remedy(self) -> &'static str {
        match self {
            Self::Lockfile => crate::text::lock_remedy(),
            Self::IndexEntry => crate::text::index_entry_remedy(),
            Self::GitHead => crate::text::index_rev_remedy_sha1(),
        }
    }
}

/// An immutable, resolved commit SHA pinned in a lockfile or index entry.
///
/// The only inhabitants are 40-char lowercase-hex strings. A moving ref
/// (`HEAD`, `main`, a tag) cannot inhabit this type: the write path records the
/// commit a fetch actually checked out, read from the checkout's `HEAD`, and
/// the read path re-parses a stored value via [`PinnedRev::from_full_sha`].
///
/// This is the recorded-pin type. [`CommitId`] is the distinct request type
/// (what the author typed; may be a branch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedRev(String);

impl PinnedRev {
    /// Parse a recorded rev read at `site`, accepting only a 40-char
    /// lowercase-hex SHA.
    ///
    /// A non-SHA value (e.g. a legacy `"HEAD"` or `"main"`) is a hard error —
    /// fail closed rather than re-fetching a moving tip. The refusal's remedy
    /// is `site`'s, so it never names the step that produced the value.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when `raw` is not a 40-char lowercase-hex string.
    pub fn from_full_sha(pkg: &PackageName, raw: &str, site: RevSite) -> Result<Self, CliError> {
        Self::parse_sha(raw).ok_or_else(|| {
            CliError::Resolve(crate::text::msg::index_rev_not_immutable(
                pkg,
                &crate::style::TerminalSafe::sanitize(&format!("{raw:?}")),
                &site.remedy(),
            ))
        })
    }

    /// Parse `raw` as exactly 40 lowercase hex characters — no uppercase, no
    /// short hashes — or `None`.
    #[must_use]
    pub fn parse_sha(raw: &str) -> Option<Self> {
        let is_sha = raw.len() == 40 && raw.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        is_sha.then(|| Self(raw.to_owned()))
    }

    /// The pinned SHA string, suitable for use as a cache-dir key or for
    /// writing to the lockfile or index entry.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PinnedRev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The shape a requested ref takes, classified once from an already
/// injection-validated [`CommitId`] so the same string is never re-parsed.
///
/// A same-shaped ref (a branch or tag literally named like a hex string) is
/// resolved by git BEFORE it is ever tried as an abbreviated or full object
/// id — this classification is what lets [`check_served`] tell "the checkout
/// moved because the ref moved" (expected, for [`Head`](Self::Head) and
/// [`Name`](Self::Name)) apart from "the checkout served a different commit
/// than the hex the author pinned" (a mismatch, for
/// [`FullSha`](Self::FullSha) and [`AbbrevHex`](Self::AbbrevHex)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestedRev {
    /// The literal string `"HEAD"` — always the checkout's current tip.
    Head,
    /// Exactly 40 lowercase-hex characters: an unambiguous full commit SHA.
    FullSha(PinnedRev),
    /// 4 to 39 lowercase-hex characters: an abbreviated commit SHA, ambiguous
    /// with a same-shaped ref name.
    AbbrevHex(String),
    /// Anything else a branch, tag, or other ref name. Free to move; never
    /// compared against what was served.
    Name(String),
}

impl RequestedRev {
    /// Classify an already-[`CommitId::parse`]d requested ref by hex shape.
    ///
    /// Mixed-case hex (e.g. `"DeadBEEF"`) is rejected outright: it is neither
    /// a valid SHA spelling (git SHAs are always lowercase) nor a plausible
    /// ref name, so treating it as a [`Name`](Self::Name) would silently
    /// widen what counts as a moving ref.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when `id` is mixed-case hex.
    pub fn classify(pkg: &PackageName, id: &CommitId) -> Result<Self, CliError> {
        let raw = id.as_str();
        if raw == "HEAD" {
            return Ok(Self::Head);
        }
        let all_hex_lower = raw.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        let all_hex_any_case = raw.chars().all(|c| c.is_ascii_hexdigit());
        if all_hex_any_case && !all_hex_lower {
            return Err(CliError::Resolve(
                crate::text::msg::index_rev_mixed_case_hex(
                    pkg,
                    &crate::style::TerminalSafe::sanitize(raw),
                ),
            ));
        }
        if let Some(full) = PinnedRev::parse_sha(raw) {
            return Ok(Self::FullSha(full));
        }
        if all_hex_lower && (4..=39).contains(&raw.len()) {
            return Ok(Self::AbbrevHex(raw.to_owned()));
        }
        Ok(Self::Name(raw.to_owned()))
    }
}

/// A requested ref's shape disagreed with the commit git actually served
/// after checkout — [`check_served`]'s only two outcomes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevMismatch {
    /// An unambiguous SHA (full or abbreviated with no shadow) does not
    /// prefix-match what was served: a hard refusal. Named `requested` for a
    /// [`RequestedRev::FullSha`]; the served commit did not come from
    /// resolving that exact hash.
    Different {
        /// The full SHA the author pinned.
        requested: PinnedRev,
        /// The commit git actually checked out.
        served: PinnedRev,
    },
    /// An abbreviated hex ref was shadowed by a same-shaped ref name (a
    /// branch or tag literally spelled like the abbreviation), so git served
    /// that ref's commit instead of resolving the hex as an object id.
    /// Warn, never refuse — the checkout itself succeeded and its result is
    /// used as pinned.
    ShadowedAbbrev {
        /// The abbreviated hex the author pinned.
        requested: String,
        /// The commit the shadowing ref actually served.
        served: PinnedRev,
    },
}

/// Compare a classified request against the commit git actually served.
///
/// [`RequestedRev::Head`] and [`RequestedRev::Name`] never mismatch — both
/// name refs that are expected to move. A [`RequestedRev::FullSha`] that
/// disagrees with `served` is a [`RevMismatch::Different`] (hard refuse); a
/// [`RequestedRev::AbbrevHex`] that is not a prefix of `served` is a
/// [`RevMismatch::ShadowedAbbrev`] (warn only).
#[must_use]
pub fn check_served(requested: &RequestedRev, served: &PinnedRev) -> Option<RevMismatch> {
    match requested {
        RequestedRev::Head | RequestedRev::Name(_) => None,
        RequestedRev::FullSha(full) => (full != served).then(|| RevMismatch::Different {
            requested: full.clone(),
            served: served.clone(),
        }),
        RequestedRev::AbbrevHex(abbrev) => {
            (!served.as_str().starts_with(abbrev.as_str())).then(|| RevMismatch::ShadowedAbbrev {
                requested: abbrev.clone(),
                served: served.clone(),
            })
        }
    }
}

/// A validated source-tree content hash: exactly 64 lowercase hex characters.
///
/// The only inhabitants are the digests `hex::encode(Sha256)` produces
/// ([`crate::cache::hash_tree`], the hash the resolver verifies a fetched tree
/// against). A short, uppercase, non-hex, or otherwise malformed value cannot
/// inhabit this type, so a garbage integrity anchor is refused at the entry-parse
/// boundary — the cheap structural gate (`ipe package validate-entry`) the index
/// CI runs first — rather than only surfacing as a fetch-time mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// Parse a stored `sha256` field, accepting only a 64-char lowercase-hex
    /// digest.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when `raw` is not exactly 64 lowercase hex chars.
    pub fn parse(pkg: &PackageName, raw: &str) -> Result<Self, CliError> {
        let is_digest = raw.len() == 64 && raw.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        if !is_digest {
            return Err(CliError::Resolve(crate::text::msg::index_sha256_invalid(
                pkg,
                &crate::style::TerminalSafe::sanitize(&format!("{raw:?}")),
            )));
        }
        Ok(Self(raw.to_owned()))
    }

    /// Hash the source tree at `root`, as the resolver verifies it.
    ///
    /// # Errors
    /// [`TreeHashError::Io`] for the first entry that cannot be read;
    /// [`TreeHashError::Exceeded`] past a package-source tree ceiling or on an
    /// entry of a refused shape.
    pub fn of_tree(root: &Path) -> Result<Self, TreeHashError> {
        crate::cache::hash_tree(root).map(Self)
    }

    /// [`Sha256Hex::of_tree`] under an explicit tree ceiling.
    ///
    /// # Errors
    /// As [`Sha256Hex::of_tree`].
    pub fn of_tree_within(
        root: &Path,
        ceiling: &crate::remote_ingest::TreeCeiling,
    ) -> Result<Self, TreeHashError> {
        crate::cache::hash_tree_within(root, ceiling).map(Self)
    }

    /// The finalized hex of an already-walked tree `digest`.
    #[must_use]
    pub fn of_digest(digest: &crate::cache::TreeDigest) -> Self {
        Self(digest.to_hex())
    }

    /// The validated 64-hex digest string, compared against a freshly-computed
    /// tree hash at verify-before-trust time.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A parsed index entry: one package and every version published for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    /// The package name, matching the entry file stem (`packages/<name>.toml`).
    pub name: PackageName,
    /// The publisher the entry claims — self-declared and untrusted; provenance
    /// only. A privilege rests on a [`crate::publisher::BlessedPublisher`], never
    /// on this field.
    pub publisher: SelfDeclaredPublisher,
    /// Every published version, in file order. [`resolve_version`] scans these
    /// for the highest match rather than relying on file order.
    pub versions: Vec<EntryVersion>,
}

/// One published version of a package: where its source lives, exactly which
/// revision, the content hash to verify the fetched tree against, and the
/// capabilities the publisher declared.
///
/// `source` is a [`SourceUrl`] and `rev` is a [`PinnedRev`] — typed newtypes
/// that prevent an unvalidated or moving ref from reaching the `git` subprocess
/// or being written to the lockfile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryVersion {
    /// The exact published version (never carrying build metadata).
    pub version: PublishedVersion,
    /// The source repository URL, validated at parse time.
    pub source: SourceUrl,
    /// The immutable commit SHA pinned at publish time.
    pub rev: PinnedRev,
    /// The sha256 of the source tree at `rev`. A fetched tree is trusted only
    /// when its hash equals this (verify-before-trust, in `crate::resolve`).
    pub sha256: Sha256Hex,
    /// The capability set the publisher declared for this version, surfaced for
    /// consent at `ipe add`.
    pub capabilities: BTreeSet<Capability>,
    /// The publisher's Sigstore signature bundle over this version's `sha256`,
    /// when one was published. Optional and backward-compatible: an absent
    /// `signature` is an unsigned version (resolved with a warning unless the
    /// trust policy requires a signature). A PRESENT-but-malformed bundle is a
    /// hard parse error, never a silently-dropped field — a malformed signature
    /// must not masquerade as "unsigned".
    pub signature: Option<crate::signing::SignatureBundle>,
}

/// The path of a package's entry file inside an index checkout.
///
/// Takes a validated [`PackageName`] so the name is a single, non-traversing
/// path component by construction — an unvalidated string cannot reach this
/// join and reroot it outside the index root.
fn entry_path(index_root: &Path, name: &PackageName) -> PathBuf {
    index_root.join(PACKAGES_DIR).join(entry_file_name(name))
}

/// The index checkout directory holding one entry file per package.
const PACKAGES_DIR: &str = "packages";

/// The entry file name of the package `name` inside [`PACKAGES_DIR`].
fn entry_file_name(name: &PackageName) -> String {
    format!("{}.toml", name.as_str())
}

/// Whether the package named `name` has an entry file in the index checkout at
/// `index_root`.
///
/// Publish uses this to distinguish a first publish (no file — create it) from a
/// present-but-unreadable entry (a real error to surface), rather than treating
/// every read failure as "absent".
///
/// # Errors
/// [`CliError::Resolve`] when `name` is not a valid package name (it would
/// otherwise be joined into a filesystem path).
pub fn entry_file_exists(index_root: &Path, name: &str) -> Result<bool, CliError> {
    let name = PackageName::parse(name)?;
    Ok(entry_path(index_root, &name).is_file())
}

/// The three-way outcome of looking up a package entry in the index.
///
/// This split prevents callers from collapsing "genuinely absent" and
/// "present-but-unreadable" into the same value — the fused form that lets
/// security gates fail open. Use [`EntryLookup::require_present`] for
/// integrity gates (Unreadable → propagate error → refuse) and
/// [`EntryLookup::absent_or_err`] where the first-version skip must survive a
/// true absence but still refuse on corruption.
#[must_use]
pub enum EntryLookup {
    /// The entry file does not exist — the package has never been published.
    Absent,
    /// The entry file exists and parsed successfully.
    Present(IndexEntry),
    /// The entry file exists but could not be read or parsed.
    Unreadable(CliError),
}

impl EntryLookup {
    /// Fail-closed accessor for integrity gates.
    ///
    /// `Absent` → `Ok(None)` (no published baseline; a new submission is
    /// allowed through). `Present` → `Ok(Some(entry))`. `Unreadable` → `Err`
    /// (propagate the error; the gate refuses rather than treating corruption
    /// as "no baseline").
    ///
    /// # Errors
    /// The [`CliError`] carried by the `Unreadable` variant.
    pub fn require_present(self) -> Result<Option<IndexEntry>, CliError> {
        match self {
            Self::Absent => Ok(None),
            Self::Present(e) => Ok(Some(e)),
            Self::Unreadable(err) => Err(err),
        }
    }

    /// Fail-closed accessor for the semver-bump gate.
    ///
    /// Semantically identical to [`require_present`](Self::require_present):
    /// `Absent` → `Ok(None)` (first version; skip preserved), `Present` →
    /// `Ok(Some(entry))`, `Unreadable` → `Err` (refuse; a corrupt predecessor
    /// cannot be treated as "no predecessor").
    ///
    /// # Errors
    /// The [`CliError`] carried by the `Unreadable` variant.
    pub fn absent_or_err(self) -> Result<Option<IndexEntry>, CliError> {
        self.require_present()
    }
}

/// Read and parse the index entry for `name` as a [`EntryLookup`].
///
/// Returns the three-way outcome (Absent / Present / Unreadable) that
/// distinguishes genuinely absent from present-but-unreadable. Use this in
/// every integrity gate so an unreadable baseline propagates as an error (fail
/// closed) rather than collapsing to "absent → skip".
pub fn read_entry_lookup(index_root: &Path, name: &str) -> EntryLookup {
    let name = match PackageName::parse(name) {
        Ok(name) => name,
        Err(err) => return EntryLookup::Unreadable(err),
    };
    let text = match read_entry_text(index_root, &name) {
        Ok(t) => t,
        Err(crate::CliError::Io { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return EntryLookup::Absent;
        }
        Err(e) => {
            return EntryLookup::Unreadable(crate::CliError::Resolve(
                crate::text::msg::index_entry_unreadable(&name, &e),
            ));
        }
    };
    match parse_entry(&name, &text) {
        Ok(entry) => EntryLookup::Present(entry),
        Err(err) => EntryLookup::Unreadable(err),
    }
}

/// Read and parse the index entry for `name` from an index checkout rooted at
/// `index_root` (which holds `packages/<name>.toml`).
///
/// For non-security callers that treat both absence and corruption as errors
/// (e.g. the resolver, publish). Security/integrity gates must use
/// [`read_entry_lookup`] instead so they cannot accidentally collapse
/// "unreadable" to "absent → skip".
///
/// # Errors
/// [`CliError::Resolve`] when the entry file is absent or malformed.
pub fn read_entry(index_root: &Path, name: &str) -> Result<IndexEntry, CliError> {
    let package_name = PackageName::parse(name)?;
    let text = read_entry_text(index_root, &package_name).map_err(|e| match e {
        crate::CliError::Io { ref source, .. } => read_entry_error(&package_name, source),
        other => other,
    })?;
    parse_entry(&package_name, &text)
}

/// The text of `packages/<name>.toml` below `index_root`, opened level by level, never through a symlink.
///
/// An index checkout is fetched content: a link planted at the entry or at
/// `packages` is refused, never followed out of the checkout.
fn read_entry_text(index_root: &Path, name: &PackageName) -> Result<String, CliError> {
    let file = entry_file_name(name);
    crate::io_bounded::read_named_in(
        index_root,
        &[PACKAGES_DIR, &file],
        crate::io_bounded::SMALL_FILE_CAP,
    )
}

/// The typed diagnostic when an index entry cannot be read. A missing entry is
/// the ordinary "unknown package" case: the message names the package and points
/// the user at the index, WITHOUT leaking the internal cache path or the errno
/// tail. Any other read failure (a permission or corruption problem the user can
/// act on) keeps a readable kind description, still errno-free.
fn read_entry_error(name: &PackageName, e: &std::io::Error) -> CliError {
    if e.kind() == std::io::ErrorKind::NotFound {
        CliError::Resolve(crate::text::msg::add_package_not_in_index(name))
    } else {
        CliError::Resolve(crate::text::msg::add_index_entry_unreadable(
            name,
            &e.kind(),
        ))
    }
}

/// Validate a single `packages/<name>.toml` entry file by its own path, the way
/// the index repository's admission CI checks a submitted entry.
///
/// The package name is the file stem (the schema's authoritative name), so the
/// file `packages/http-extras.toml` is validated as package `http-extras`. This
/// is the same parse [`read_entry`] runs, reused so the validator and the reader
/// can never disagree about what a well-formed entry is: a version that parses
/// here is a version the resolver will later accept.
///
/// Fail-closed: any parse failure (a bad version, a missing per-version field,
/// an unknown capability, an absent `publisher`, or zero `[[version]]` blocks)
/// is a hard error, never a warning. Structure only — the source pin and the
/// package gate are the admission CI's fetch and `ipe package audit` steps, not
/// this offline check.
///
/// # Errors
/// [`CliError::Usage`] when `path` has no `.toml` file-stem to name the
/// package; [`CliError::Io`] when the file cannot be read; [`CliError::Resolve`]
/// when the entry is malformed.
pub fn validate_entry_file(path: &Path) -> Result<IndexEntry, CliError> {
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CliError::Usage(crate::text::msg::index_entry_path_invalid(&path.display()))
        })?;
    let name = PackageName::parse(name)?;
    // Named on the command line, but the file comes from an untrusted registry
    // checkout: a link there is refused, never followed.
    let text = crate::io_bounded::read_leaf_capped(path, crate::io_bounded::SMALL_FILE_READ_CAP)?;
    parse_entry(&name, &text)
}

/// The per-entry version ceiling enforced at admission.
///
/// A real package accrues versions across many reviewed PRs; one submission
/// listing more than this is a resource / review-flooding vector, refused
/// fail-closed.
pub const MAX_ENTRY_VERSIONS: usize = 1024;

/// The structural admission checks that need no fetch.
///
/// Covers the version-count ceiling, per-version immutability against the
/// baseline, and source continuity (anti-squat). A pure function of the
/// submitted entry and the previously published `baseline` (if any), so the
/// whole deny/accept surface is testable without a network, a git fetch, or a
/// build.
///
/// Fail-closed and deny-by-default:
/// - **Version ceiling** — more than [`MAX_ENTRY_VERSIONS`] versions is refused.
/// - **Immutability** — a submitted version whose NUMBER already exists in the
///   baseline must be byte-for-byte identical; rewriting its
///   source/rev/sha256/capabilities is a supply-chain mutation and is refused.
/// - **Append-only** — a version NUMBER published in the baseline must not be
///   dropped from the submission; the index never removes a published version.
///   The one carve-out (drop-only) is the disposable reserved smoke namespace
///   owned by the blessed first-party publisher, which may reset to a single
///   version — granted only when `attested` (the admission workflow's
///   authenticated PR author) proves the claimed publisher is blessed, never on
///   the entry's self-declared `publisher` alone.
/// - **Monotonicity** — every version new to the submission (absent from the
///   baseline) must exceed every baseline version, prereleases included, so a
///   release never goes backwards and the enforced-semver predecessor is always
///   the greatest published release below it.
/// - **Source continuity** — a package name is bound to one source repository.
///   The established source is the baseline's first published version's source
///   (on first publish, the submitted entry's own first version fixes it); a
///   version pointing elsewhere is a name-squat and is refused.
///
/// Build metadata never reaches this check: an entry's versions are
/// [`PublishedVersion`]s, refused at read time when they carry a `+…` suffix.
///
/// # Errors
/// [`CliError::VersionRefused`] when a new version does not exceed every
/// baseline version; [`CliError::Usage`] naming the exact rule otherwise.
pub fn admission_precheck(
    submitted: &IndexEntry,
    baseline: Option<&IndexEntry>,
    attested: Option<&AttestedActor>,
) -> Result<(), CliError> {
    if submitted.versions.len() > MAX_ENTRY_VERSIONS {
        return Err(CliError::Usage(
            crate::text::msg::index_entry_too_many_versions(
                &submitted.name,
                &submitted.versions.len(),
                &MAX_ENTRY_VERSIONS,
            ),
        ));
    }

    let baseline_by_version: std::collections::BTreeMap<&PublishedVersion, &EntryVersion> =
        baseline
            .map(|e| e.versions.iter().map(|v| (&v.version, v)).collect())
            .unwrap_or_default();

    // Immutability: an existing version NUMBER must match the published row exactly.
    for version in &submitted.versions {
        if let Some(&prior) = baseline_by_version.get(&version.version)
            && prior != version
        {
            return Err(CliError::Usage(
                crate::text::msg::index_entry_version_rewritten(&submitted.name, &version.version),
            ));
        }
    }

    // Append-only: a version NUMBER published in the baseline must not be
    // dropped from the submission. A published version is immutable AND
    // permanent — silently removing one is a supply-chain regression (a
    // consumer's pinned resolution would vanish), so it is refused fail-closed.
    //
    // Carve-out (drop-only, both conditions required): the disposable reserved
    // smoke namespace may reset to a single version when the attested PR author
    // proves the claimed publisher is the blessed first-party identity. A reserved
    // name without that proof (no attestation, an attestation not matching the
    // claim, a non-blessed attestation), or a non-reserved name, still hits the
    // rejection — absent proof the drop is the sanctioned reset, the permissive
    // branch is unreachable. Rewriting a version stays forbidden everywhere
    // (enforced above); only dropping is carved out.
    let reserved_name = ipe_kernels::reserved_package_prefix_of(submitted.name.as_str()).is_some();
    let blessing = BlessedPublisher::from_attested(attested, &submitted.publisher);
    let reset_allowed = reserved_name
        && blessing
            .as_ref()
            .is_ok_and(|blessed| blessed.vouches_for(&submitted.publisher));
    if !reset_allowed {
        let reset_refusal = blessing.as_ref().err().filter(|_| reserved_name);
        let submitted_versions: std::collections::BTreeSet<&PublishedVersion> =
            submitted.versions.iter().map(|v| &v.version).collect();
        for baseline_version in baseline_by_version.keys() {
            if !submitted_versions.contains(*baseline_version) {
                return Err(CliError::Usage(reset_refusal.map_or_else(
                    || {
                        crate::text::msg::index_entry_version_dropped(
                            &submitted.name,
                            baseline_version,
                        )
                    },
                    |refusal| {
                        crate::text::msg::index_entry_version_dropped_reset_refused(
                            &submitted.name,
                            baseline_version,
                            refusal,
                        )
                    },
                )));
            }
        }
    }

    // Monotonicity: each submitted version absent from the baseline is checked
    // against the greatest baseline version and refused unless strictly above it.
    // Versions carried over from the baseline are covered by the immutability
    // check above. This holds for the reserved reset too: a reset may drop
    // history but never go below the greatest version it drops. The map is
    // ordered, so its last key is the greatest baseline version.
    let greatest_published = baseline_by_version.keys().next_back().copied();
    for version in &submitted.versions {
        if !baseline_by_version.contains_key(&version.version) {
            require_successor(greatest_published, &version.version)
                .map_err(|refusal| refusal.for_package(submitted.name.as_str()))?;
        }
    }

    // Source continuity (anti-squat): every version's source must equal the
    // package's established source.
    let established_source: Option<&str> = baseline
        .and_then(|e| e.versions.first())
        .map(|v| v.source.as_str())
        .or_else(|| submitted.versions.first().map(|v| v.source.as_str()));
    if let Some(expected_source) = established_source {
        for version in &submitted.versions {
            if version.source.as_str() != expected_source {
                return Err(CliError::Usage(crate::text::msg::index_entry_source_moved(
                    &submitted.name,
                    &version.version,
                    &version.source.as_str(),
                    &expected_source,
                )));
            }
        }
    }

    Ok(())
}

/// Resolve the highest published version satisfying `req`.
///
/// # Errors
/// [`CliError::Resolve`] when no published version matches — the requirement is
/// unsatisfiable against this entry, named so the user sees what was available.
pub fn resolve_version<'a>(
    entry: &'a IndexEntry,
    req: &semver::VersionReq,
) -> Result<&'a EntryVersion, CliError> {
    entry
        .versions
        .iter()
        .filter(|v| req.matches(v.version.as_semver()))
        .max_by(|a, b| a.version.cmp(&b.version))
        .ok_or_else(|| {
            let available: Vec<String> = entry
                .versions
                .iter()
                .map(|v| v.version.to_string())
                .collect();
            CliError::Resolve(crate::text::msg::index_no_version_satisfies(
                &entry.name,
                req,
                &if available.is_empty() {
                    crate::text::index_no_version_available().to_owned()
                } else {
                    available.join(", ")
                },
            ))
        })
}

/// Parse an entry's claimed `publisher` into a login-shaped [`SelfDeclaredPublisher`].
///
/// The refusal names only why the value is not a login, never the value itself,
/// so a hostile entry cannot put control bytes or escapes into the error text.
fn parse_publisher(name: &PackageName, claimed: &str) -> Result<SelfDeclaredPublisher, CliError> {
    SelfDeclaredPublisher::parse(claimed).map_err(|refusal| {
        CliError::Resolve(crate::text::msg::index_publisher_not_login(name, &refusal))
    })
}

/// The header opening one published version's table in an entry file.
pub const VERSION_HEADER: &str = "[[version]]";

/// The JSON mirror's key for the version list (the entry file spells each
/// element as a [`VERSION_HEADER`] table instead).
const JSON_VERSIONS_KEY: &str = "versions";

/// A key of an entry file's header, before the first [`VERSION_HEADER`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderKey {
    /// `name`: the package, equal to the entry file's stem when present.
    Name,
    /// `publisher`: the self-declared publisher login.
    Publisher,
}

impl HeaderKey {
    /// Every header key, in the order the writer renders them.
    pub const ALL: [Self; 2] = [Self::Name, Self::Publisher];

    /// The key as written in an entry file.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Publisher => "publisher",
        }
    }
}

/// A key of one [`VERSION_HEADER`] table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionKey {
    /// `version`: the [`PublishedVersion`].
    Version,
    /// `source`: the [`SourceUrl`].
    Source,
    /// `rev`: the [`PinnedRev`].
    Rev,
    /// `sha256`: the [`Sha256Hex`] of the source tree.
    Sha256,
    /// `capabilities`: a list of [`Capability`] names.
    Capabilities,
    /// `signature`: an optional Sigstore bundle.
    Signature,
}

impl VersionKey {
    /// Every version key, in the order the writer renders them.
    pub const ALL: [Self; 6] = [
        Self::Version,
        Self::Source,
        Self::Rev,
        Self::Sha256,
        Self::Capabilities,
        Self::Signature,
    ];

    /// The key as written in an entry file.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Source => "source",
            Self::Rev => "rev",
            Self::Sha256 => "sha256",
            Self::Capabilities => "capabilities",
            Self::Signature => "signature",
        }
    }
}

/// A key of an index entry file, bound by its variant to the one table that
/// may hold it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKey {
    /// A key of the entry's header.
    Header(HeaderKey),
    /// A key of one published version's table.
    Version(VersionKey),
}

impl EntryKey {
    /// The key as written in an entry file.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Header(key) => key.as_str(),
            Self::Version(key) => key.as_str(),
        }
    }
}

impl LineKey for EntryKey {
    fn parse(raw: &str) -> Option<Self> {
        HeaderKey::ALL
            .into_iter()
            .find(|key| key.as_str() == raw)
            .map(Self::Header)
            .or_else(|| {
                VersionKey::ALL
                    .into_iter()
                    .find(|key| key.as_str() == raw)
                    .map(Self::Version)
            })
    }
}

impl std::fmt::Display for EntryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why one line of an index entry file is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryFault {
    /// Not blank, a comment, the [`VERSION_HEADER`], or a `key = value` field.
    UnrecognisedLine,
    /// A field whose key is no [`EntryKey`]; cut to
    /// [`crate::line_grammar::MAX_KEY_ECHO`] characters.
    UnknownKey(String),
    /// A field outside the table its key belongs to.
    MisplacedKey(EntryKey),
    /// A field whose value does not have its key's shape.
    MalformedValue(EntryKey),
    /// A field its table already holds.
    DuplicateKey(EntryKey),
    /// A second [`VERSION_HEADER`] table for a version already listed.
    DuplicateVersion(PublishedVersion),
    /// A `name` that is not the package the entry file is read as.
    NameMismatch,
    /// A comment holding a control, bidi, or invisible character.
    HiddenCharacter(DisplayHazard),
}

/// An index entry file refused by the closed entry grammar.
///
/// Rendered through the message catalog; boxed inside
/// [`CliError::IndexEntryRefused`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryRefusal {
    entry: PackageName,
    line: TextLine,
    fault: EntryFault,
}

impl EntryRefusal {
    /// The refused line.
    #[must_use]
    pub const fn line(&self) -> TextLine {
        self.line
    }

    /// Why the line is refused.
    #[must_use]
    pub const fn fault(&self) -> &EntryFault {
        &self.fault
    }
}

/// Every admitted entry key, as a refusal lists them.
fn known_entry_keys() -> String {
    HeaderKey::ALL
        .into_iter()
        .map(EntryKey::Header)
        .chain(VersionKey::ALL.into_iter().map(EntryKey::Version))
        .map(|key| format!("`{key}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The shape a value of `key` must have, as a refusal names it.
const fn value_shape(key: EntryKey) -> &'static str {
    match key {
        EntryKey::Header(HeaderKey::Name | HeaderKey::Publisher)
        | EntryKey::Version(
            VersionKey::Version | VersionKey::Source | VersionKey::Rev | VersionKey::Sha256,
        ) => crate::text::index_entry_shape_quoted(),
        EntryKey::Version(VersionKey::Capabilities) => crate::text::index_entry_shape_list(),
        EntryKey::Version(VersionKey::Signature) => crate::text::index_entry_shape_signature(),
    }
}

impl std::fmt::Display for EntryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { entry, line, fault } = self;
        let remedy = crate::text::index_entry_remedy();
        f.write_str(&match fault {
            EntryFault::UnrecognisedLine => {
                crate::text::index_entry_unrecognised_line(entry, line, &remedy)
            }
            EntryFault::UnknownKey(key) => crate::text::index_entry_unknown_key(
                entry,
                line,
                &crate::style::TerminalSafe::sanitize(&key.escape_debug().to_string()),
                &known_entry_keys(),
                &remedy,
            ),
            EntryFault::MisplacedKey(key @ EntryKey::Header(_)) => {
                crate::text::index_entry_key_needs_header(entry, line, key, &remedy)
            }
            EntryFault::MisplacedKey(key @ EntryKey::Version(_)) => {
                crate::text::index_entry_key_needs_version(entry, line, key, &remedy)
            }
            EntryFault::MalformedValue(key) => crate::text::index_entry_malformed_value(
                entry,
                line,
                key,
                &value_shape(*key),
                &remedy,
            ),
            EntryFault::DuplicateKey(key) => {
                crate::text::index_entry_duplicate_key(entry, line, key, &remedy)
            }
            EntryFault::DuplicateVersion(version) => {
                crate::text::index_entry_duplicate_version(entry, line, version, &remedy)
            }
            EntryFault::NameMismatch => {
                crate::text::index_entry_name_mismatch(entry, line, &remedy)
            }
            EntryFault::HiddenCharacter(hazard) => crate::text::index_entry_hidden_character(
                entry,
                line,
                &hazard.position(),
                &format!("{:04X}", u32::from(hazard.ch())),
                &remedy,
            ),
        })
    }
}

impl From<EntryRefusal> for CliError {
    fn from(refusal: EntryRefusal) -> Self {
        Self::IndexEntryRefused(Box::new(refusal))
    }
}

/// Parse an entry file's text into a typed [`IndexEntry`].
///
/// The grammar is closed: every line is blank, a comment, the
/// [`VERSION_HEADER`], or one `key = value` field whose [`EntryKey`] belongs to
/// the table it sits in — the header's keys before the first version table, a
/// version's keys inside one. Anything else, a repeated key, a repeated
/// version, or a `name` other than the package read is an [`EntryRefusal`] naming its
/// line, never skipped.
fn parse_entry(name: &PackageName, text: &str) -> Result<IndexEntry, CliError> {
    let refuse = |line: TextLine, fault: EntryFault| {
        CliError::from(EntryRefusal {
            entry: name.clone(),
            line,
            fault,
        })
    };
    let mut raw = RawEntry::default();
    for (index, text_line) in text.lines().enumerate() {
        let line = TextLine::at(index);
        match crate::line_grammar::classify::<EntryKey>(text_line, VERSION_HEADER) {
            Ok(LineShape::Ignorable) => {}
            Ok(LineShape::Header) => raw.open_version(line),
            Ok(LineShape::Field(key, value)) => {
                raw.take(line, key, value)
                    .map_err(|fault| refuse(line, fault))?;
            }
            Err(LineFault::Unrecognised) => return Err(refuse(line, EntryFault::UnrecognisedLine)),
            Err(LineFault::UnknownKey(key)) => {
                return Err(refuse(line, EntryFault::UnknownKey(key)));
            }
            Err(LineFault::HiddenCharacter(hazard)) => {
                return Err(refuse(line, EntryFault::HiddenCharacter(hazard)));
            }
        }
    }
    raw.close_version();

    if let Some((line, recorded)) = raw.name
        && recorded != name.as_str()
    {
        return Err(refuse(line, EntryFault::NameMismatch));
    }
    let publisher = raw
        .publisher
        .ok_or_else(|| CliError::Resolve(crate::text::msg::index_entry_missing_publisher(name)))
        .and_then(|claimed| parse_publisher(name, claimed))?;
    if raw.versions.is_empty() {
        return Err(CliError::Resolve(
            crate::text::msg::index_entry_no_versions(name),
        ));
    }
    let mut seen: BTreeSet<PublishedVersion> = BTreeSet::new();
    let mut versions = Vec::with_capacity(raw.versions.len());
    for record in raw.versions {
        let header = record.header;
        let version = record.into_version(name)?;
        if !seen.insert(version.version.clone()) {
            return Err(refuse(
                header,
                EntryFault::DuplicateVersion(version.version),
            ));
        }
        versions.push(version);
    }

    Ok(IndexEntry {
        name: name.clone(),
        publisher,
        versions,
    })
}

/// The refusal detail for a JSON mirror key no [`EntryKey`] admits.
fn json_unknown_key(key: &str) -> String {
    let shown: String = key
        .chars()
        .take(crate::line_grammar::MAX_KEY_ECHO)
        .collect();
    format!("unknown key {shown:?}")
}

/// The refusal detail for a JSON mirror object that lists one key twice.
fn json_duplicate_key(key: &str) -> String {
    let shown: String = key
        .chars()
        .take(crate::line_grammar::MAX_KEY_ECHO)
        .collect();
    format!("key {shown:?} is listed twice")
}

/// Scan raw JSON `text` for the first object that lists one key twice,
/// returning that key, decoded.
///
/// `serde_json::Value` keeps only the LAST value of a repeated object key —
/// the repeat is gone before any reader working from the decoded `Value` can
/// see it, so checking the decoded form can never catch it. This scan instead
/// walks the raw text once, keeping one key set per currently-open object (an
/// open array keeps no set, since a JSON array has no keys), so it catches a
/// repeat at every nesting level in one pass: the top-level header object,
/// each `versions` element, and a nested `signature` bundle alike. It is
/// iterative — a growable `Vec` is the only thing input depth can grow, never
/// the call stack — so it cannot overflow on a maliciously deep mirror.
fn find_duplicate_json_key(text: &str) -> Option<String> {
    let mut stack: Vec<Option<BTreeSet<String>>> = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((start, ch)) = chars.next() {
        match ch {
            '{' => stack.push(Some(BTreeSet::new())),
            '[' => stack.push(None),
            '}' | ']' => {
                stack.pop();
            }
            '"' => {
                let mut end = None;
                while let Some((pos, inner)) = chars.next() {
                    match inner {
                        '\\' => {
                            chars.next();
                        }
                        '"' => {
                            end = Some(pos + inner.len_utf8());
                            break;
                        }
                        _ => {}
                    }
                }
                let Some(end) = end else { break };
                let Some(literal) = text.get(start..end) else {
                    break;
                };
                let mut probe = chars.clone();
                let mut follows_colon = false;
                while let Some(&(_, next)) = probe.peek() {
                    if next.is_whitespace() {
                        probe.next();
                    } else {
                        follows_colon = next == ':';
                        break;
                    }
                }
                if follows_colon
                    && let Some(Some(keys)) = stack.last_mut()
                    && let Ok(decoded) = serde_json::from_str::<String>(literal)
                    && !keys.insert(decoded.clone())
                {
                    return Some(decoded);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse the registry's per-package JSON mirror (`/packages/<name>.json`) into
/// the SAME typed [`IndexEntry`] the TOML reader produces.
///
/// The Pages read API serves a JSON mirror of the authoritative `packages/<name>.toml`
/// so the resolver can discover an entry without cloning the index repo. This is
/// an optimisation ONLY: the trust root stays the per-version pinned `rev` +
/// `sha256`, still git-fetched and hash-verified downstream. Every publisher-
/// controlled field passes the same [`SourceUrl`] / [`PinnedRev`] / [`Capability`]
/// constructors as the TOML path, so a malformed or partial JSON response is a
/// hard error — never a partial entry trusted as complete. The caller treats any
/// error here as a signal to fall back to the git-checkout reader.
///
/// The expected shape:
///
/// ```json
/// { "name": "http-extras", "publisher": "tester",
///   "versions": [ { "version": "1.2.0", "source": "https://…",
///                   "rev": "<40-hex>", "sha256": "…",
///                   "capabilities": ["network"] } ] }
/// ```
///
/// # Errors
/// [`CliError::Resolve`] when the JSON is malformed, repeats a key within one
/// JSON object at any nesting level, is missing `publisher` or `versions`,
/// lists zero versions or one version twice, or any per-version field fails
/// its typed constructor (an unknown or repeated capability, a non-immutable
/// `rev`, an injection-shaped `source`).
pub fn parse_entry_json(name: &str, text: &str) -> Result<IndexEntry, CliError> {
    let name = &PackageName::parse(name)?;
    let malformed = |detail: &str| {
        CliError::Resolve(crate::text::msg::registry_json_malformed(
            name,
            &crate::style::TerminalSafe::sanitize(detail),
        ))
    };

    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| malformed(&format!("not valid JSON: {e}")))?;
    // `value` already collapsed a repeated object key to its last writer —
    // this scan runs on the raw text, before that information is lost, so a
    // repeat is refused rather than silently last-wins at ANY nesting level.
    if let Some(key) = find_duplicate_json_key(text) {
        return Err(malformed(&json_duplicate_key(&key)));
    }
    let object = value
        .as_object()
        .ok_or_else(|| malformed("top level is not a JSON object"))?;
    if let Some(key) = object.keys().find(|key| {
        !HeaderKey::ALL
            .iter()
            .any(|known| known.as_str() == key.as_str())
            && key.as_str() != JSON_VERSIONS_KEY
    }) {
        return Err(malformed(&json_unknown_key(key)));
    }
    if let Some(recorded) = object.get(HeaderKey::Name.as_str())
        && recorded.as_str() != Some(name.as_str())
    {
        return Err(malformed("`name` names another package"));
    }

    let publisher = object
        .get(HeaderKey::Publisher.as_str())
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| malformed("missing string field `publisher`"))
        .and_then(|claimed| parse_publisher(name, claimed))?;

    let raw_versions = object
        .get(JSON_VERSIONS_KEY)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| malformed("missing array field `versions`"))?;
    if raw_versions.is_empty() {
        return Err(malformed("`versions` is empty"));
    }

    let mut seen: BTreeSet<PublishedVersion> = BTreeSet::new();
    let mut versions = Vec::with_capacity(raw_versions.len());
    for raw in raw_versions {
        let version = parse_entry_version_json(name, raw)?;
        if !seen.insert(version.version.clone()) {
            return Err(malformed(&format!(
                "version {} is listed twice",
                version.version
            )));
        }
        versions.push(version);
    }

    Ok(IndexEntry {
        name: name.clone(),
        publisher,
        versions,
    })
}

/// Parse one element of the JSON mirror's `versions` array into a typed
/// [`EntryVersion`], routing every publisher-controlled field through the same
/// constructors the TOML reader uses (parse, don't validate).
fn parse_entry_version_json(
    name: &PackageName,
    raw: &serde_json::Value,
) -> Result<EntryVersion, CliError> {
    let malformed = |detail: String| {
        CliError::Resolve(crate::text::msg::registry_json_malformed(
            name,
            &crate::style::TerminalSafe::sanitize(&detail),
        ))
    };
    let object = raw
        .as_object()
        .ok_or_else(|| malformed("a `versions` element is not an object".to_owned()))?;
    if let Some(key) = object.keys().find(|key| {
        !VersionKey::ALL
            .iter()
            .any(|known| known.as_str() == key.as_str())
    }) {
        return Err(malformed(json_unknown_key(key)));
    }
    let field = |key: &str| -> Result<&str, CliError> {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| malformed(format!("a `versions` element is missing string `{key}`")))
    };

    let version_str = field("version")?;
    let version = PublishedVersion::parse(version_str)
        .map_err(|refusal| refusal.for_package(name.as_str()))?;
    // Parse-don't-validate: the same typed boundaries the TOML path uses. A
    // moving or injection-shaped value can never reach `git` from the JSON path
    // either.
    let source = SourceUrl::parse(name, field("source")?)?;
    let rev = PinnedRev::from_full_sha(name, field("rev")?, RevSite::IndexEntry)?;
    let sha256 = Sha256Hex::parse(name, field("sha256")?)?;

    // `capabilities` is an optional array of strings; absent means none. An
    // unknown capability name is a hard error, never a silently-dropped effect.
    let mut capabilities = BTreeSet::new();
    if let Some(caps) = object.get("capabilities") {
        let array = caps
            .as_array()
            .ok_or_else(|| malformed("`capabilities` is not an array".to_owned()))?;
        for cap in array {
            let token = cap
                .as_str()
                .ok_or_else(|| malformed("a `capabilities` element is not a string".to_owned()))?;
            let parsed = Capability::from_str(token).map_err(|e| {
                CliError::Resolve(crate::text::msg::index_capability_unknown(
                    name,
                    &crate::style::TerminalSafe::sanitize(&e.to_string()),
                ))
            })?;
            if !capabilities.insert(parsed) {
                return Err(malformed(
                    "a `capabilities` element is listed twice".to_owned(),
                ));
            }
        }
    }

    // `signature` is an optional Sigstore bundle. In the JSON mirror it is a
    // nested object (the bundle envelope), re-serialized verbatim and routed
    // through the same typed constructor as the TOML path. A present-but-
    // malformed bundle is a hard error, never a silently-dropped field.
    let signature = match object.get("signature") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let raw = serde_json::to_string(value)
                .map_err(|e| malformed(format!("`signature` could not be serialized: {e}")))?;
            Some(SignatureBundle::parse(name.as_str(), &raw)?)
        }
    };

    Ok(EntryVersion {
        version,
        source,
        rev,
        sha256,
        capabilities,
        signature,
    })
}

/// The fields of an entry file collected during the line scan, borrowed from its
/// text, before they are parsed into the typed [`IndexEntry`].
#[derive(Default)]
struct RawEntry<'a> {
    /// The header's `name` and the line holding it.
    name: Option<(TextLine, &'a str)>,
    /// The header's `publisher`.
    publisher: Option<&'a str>,
    /// Every closed version table, in file order.
    versions: Vec<RawVersion<'a>>,
    /// The version table being read, once the first header is seen.
    current: Option<RawVersion<'a>>,
}

impl<'a> RawEntry<'a> {
    /// Open a version table whose header sits at `header`, closing the open one.
    fn open_version(&mut self, header: TextLine) {
        if let Some(done) = self.current.replace(RawVersion::opened_at(header)) {
            self.versions.push(done);
        }
    }

    /// Close the open version table, if any.
    fn close_version(&mut self) {
        if let Some(done) = self.current.take() {
            self.versions.push(done);
        }
    }

    /// Record the field `key = value` read at `line`.
    fn take(&mut self, line: TextLine, key: EntryKey, value: &'a str) -> Result<(), EntryFault> {
        match (key, self.current.as_mut()) {
            (EntryKey::Header(HeaderKey::Name), None) => {
                fill(&mut self.name, key, quoted(value).map(|name| (line, name)))
            }
            (EntryKey::Header(HeaderKey::Publisher), None) => {
                fill(&mut self.publisher, key, quoted(value))
            }
            (EntryKey::Version(version_key), Some(record)) => record.take(version_key, value),
            (EntryKey::Header(_), Some(_)) | (EntryKey::Version(_), None) => {
                Err(EntryFault::MisplacedKey(key))
            }
        }
    }
}

/// Fill an empty `slot` with `value`, the field `key` parsed to its shape.
///
/// # Errors
/// [`EntryFault::MalformedValue`] when `value` did not parse;
/// [`EntryFault::DuplicateKey`] when the slot is already filled.
fn fill<T>(slot: &mut Option<T>, key: EntryKey, value: Option<T>) -> Result<(), EntryFault> {
    let value = value.ok_or(EntryFault::MalformedValue(key))?;
    if slot.is_some() {
        return Err(EntryFault::DuplicateKey(key));
    }
    *slot = Some(value);
    Ok(())
}

/// The quoted capability names of a `["…", …]` list, or `None` unless the
/// value is exactly `[]` or a comma-separated list of non-empty quoted names,
/// none repeated.
fn capability_items(value: &str) -> Option<Vec<&str>> {
    let inner = value
        .strip_prefix('[')?
        .strip_suffix(']')?
        .trim_matches(LINE_BLANKS);
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let items: Vec<&str> = inner
        .split(',')
        .map(|item| quoted(item.trim_matches(LINE_BLANKS)).filter(|item| !item.is_empty()))
        .collect::<Option<_>>()?;
    let mut seen = BTreeSet::new();
    items.iter().all(|item| seen.insert(*item)).then_some(items)
}

/// The bundle inside a `signature = "…"` value: exactly one outer pair of
/// quotes stripped, holding no [`is_display_hazard`] character, so the line
/// displays as the bytes read. The bundle is JSON and keeps its own quotes; its
/// structure is [`SignatureBundle::parse`]'s to prove.
fn signature_text(value: &str) -> Option<&str> {
    value
        .strip_prefix('"')?
        .strip_suffix('"')
        .filter(|bundle| !bundle.is_empty() && DisplayHazard::find(bundle).is_none())
}

/// The raw fields of one version table, borrowed from the entry text, before
/// they are parsed into the typed [`EntryVersion`].
struct RawVersion<'a> {
    /// Where the table's header sits.
    header: TextLine,
    version: Option<&'a str>,
    source: Option<&'a str>,
    rev: Option<&'a str>,
    sha256: Option<&'a str>,
    capabilities: Option<Vec<&'a str>>,
    signature: Option<&'a str>,
}

impl<'a> RawVersion<'a> {
    /// An empty table whose header sits at `header`.
    const fn opened_at(header: TextLine) -> Self {
        Self {
            header,
            version: None,
            source: None,
            rev: None,
            sha256: None,
            capabilities: None,
            signature: None,
        }
    }

    /// Record the field `key = value`, parsed to the key's shape.
    fn take(&mut self, key: VersionKey, value: &'a str) -> Result<(), EntryFault> {
        let entry_key = EntryKey::Version(key);
        match key {
            VersionKey::Version => fill(&mut self.version, entry_key, quoted(value)),
            VersionKey::Source => fill(&mut self.source, entry_key, quoted(value)),
            VersionKey::Rev => fill(&mut self.rev, entry_key, quoted(value)),
            VersionKey::Sha256 => fill(&mut self.sha256, entry_key, quoted(value)),
            VersionKey::Capabilities => {
                fill(&mut self.capabilities, entry_key, capability_items(value))
            }
            VersionKey::Signature => fill(&mut self.signature, entry_key, signature_text(value)),
        }
    }

    /// Turn the collected raw fields into a typed [`EntryVersion`], erroring on a
    /// missing required field, a malformed version, or an unknown capability.
    fn into_version(self, name: &PackageName) -> Result<EntryVersion, CliError> {
        let missing = |key: VersionKey| {
            CliError::Resolve(crate::text::msg::index_version_missing_field(
                name,
                &key.as_str(),
            ))
        };
        let version_str = self.version.ok_or_else(|| missing(VersionKey::Version))?;
        let version = PublishedVersion::parse(version_str)
            .map_err(|refusal| refusal.for_package(name.as_str()))?;
        let raw_source = self.source.ok_or_else(|| missing(VersionKey::Source))?;
        let raw_rev = self.rev.ok_or_else(|| missing(VersionKey::Rev))?;
        let raw_sha256 = self.sha256.ok_or_else(|| missing(VersionKey::Sha256))?;
        // Parse-don't-validate: typed constructors reject invalid values at
        // the read boundary before any value can reach `git`.
        let source = SourceUrl::parse(name, raw_source)?;
        let rev = PinnedRev::from_full_sha(name, raw_rev, RevSite::IndexEntry)?;
        // A malformed content hash is refused here, at the cheap structural gate,
        // not deferred to a fetch-time mismatch.
        let sha256 = Sha256Hex::parse(name, raw_sha256)?;
        let capabilities = parse_capabilities(name, &self.capabilities.unwrap_or_default())?;
        // A present `signature` is parsed into a typed bundle; a malformed one is
        // a hard error, never a silently-dropped field. Absent = unsigned.
        let signature = self
            .signature
            .map(|raw| SignatureBundle::parse(name.as_str(), raw))
            .transpose()?;
        Ok(EntryVersion {
            version,
            source,
            rev,
            sha256,
            capabilities,
            signature,
        })
    }
}

/// Parse the names of a `capabilities` list into a typed set via
/// [`Capability::from_str`]. An unknown name is a hard error — a typo can never
/// become a silently-dropped capability the user is then not warned about.
fn parse_capabilities(
    name: &PackageName,
    items: &[&str],
) -> Result<BTreeSet<Capability>, CliError> {
    items
        .iter()
        .map(|token| {
            Capability::from_str(token).map_err(|e| {
                CliError::Resolve(crate::text::msg::index_capability_unknown(
                    name,
                    &crate::style::TerminalSafe::sanitize(&e.to_string()),
                ))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        CommitId, EntryFault, EntryKey, HeaderKey, IndexEntry, PackageName, PinnedRev,
        RequestedRev, RevMismatch, RevSite, SourceUrl, Transport, VersionKey, check_served,
        read_entry, resolve_version,
    };
    use ipe_ir::Capability;
    use std::path::{Path, PathBuf};

    /// A fixture package name.
    #[allow(clippy::expect_used)] // fixture names are literal registry names
    fn pn(raw: &str) -> PackageName {
        PackageName::parse(raw).expect("fixture package name parses")
    }

    /// A 40-char lowercase hex placeholder rev used across fixtures.
    const FIXTURE_REV: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    /// Write a minimal fixture index with one package publishing the given
    /// versions, and return the index root. Every version shares one placeholder
    /// source/rev/sha256; capabilities are `["network"]`.
    fn write_fixture_index(root: &Path, name: &str, versions: &[&str]) {
        use std::fmt::Write as _;
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("create packages dir");
        let mut text = format!("name = \"{name}\"\npublisher = \"tester\"\n");
        for v in versions {
            let _ = write!(
                text,
                "\n[[version]]\nversion = \"{v}\"\nsource = \"https://example.invalid/{name}\"\n\
                 rev = \"{FIXTURE_REV}\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = [\"network\"]\n"
            );
        }
        std::fs::write(packages.join(format!("{name}.toml")), text).expect("write entry");
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = ipe_test_temp::temp_root().join(format!(
            "ipe-index-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// An index entry, or the `packages` directory, planted as a symlink is refused, never followed.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_index_entry_is_refused() {
        let outside = temp_dir("link-outside");
        write_fixture_index(&outside, "http-extras", &["1.0.0"]);
        let real_entry = outside.join("packages").join("http-extras.toml");
        let linked_entry = temp_dir("link-entry");
        std::fs::create_dir_all(linked_entry.join("packages")).expect("create packages dir");
        std::os::unix::fs::symlink(
            &real_entry,
            linked_entry.join("packages").join("http-extras.toml"),
        )
        .expect("link the entry");
        let linked_dir = temp_dir("link-dir");
        std::os::unix::fs::symlink(outside.join("packages"), linked_dir.join("packages"))
            .expect("link the packages dir");
        let entry = read_entry(&linked_entry, "http-extras");
        let lookup = super::read_entry_lookup(&linked_entry, "http-extras");
        let through_dir = read_entry(&linked_dir, "http-extras");
        let direct = read_entry(&outside, "http-extras");
        for dir in [&outside, &linked_entry, &linked_dir] {
            let _ = std::fs::remove_dir_all(dir);
        }
        for result in [&entry, &through_dir] {
            assert!(
                matches!(
                    result,
                    Err(crate::CliError::SourceRefused {
                        reason: crate::io_bounded::SourceRefusal::Symlink,
                        ..
                    })
                ),
                "a symlinked index entry is refused: {result:?}"
            );
        }
        assert!(
            matches!(lookup, super::EntryLookup::Unreadable(_)),
            "a symlinked entry is unreadable, never absent or present"
        );
        assert!(direct.is_ok(), "the real entry reads: {direct:?}");
    }

    #[test]
    fn reads_and_resolves_the_highest_matching_version() {
        let root = temp_dir("highest");
        write_fixture_index(&root, "http-extras", &["1.0.0", "1.2.0", "2.0.0"]);
        let entry = read_entry(&root, "http-extras").expect("entry parses");
        assert_eq!(entry.publisher, "tester");
        assert_eq!(entry.versions.len(), 3);

        let req = "^1.0".parse().expect("valid req");
        let chosen = resolve_version(&entry, &req).expect("a match exists");
        assert_eq!(chosen.version.to_string(), "1.2.0");
        assert!(chosen.capabilities.contains(&Capability::Network));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unknown_package_is_an_error() {
        let root = temp_dir("unknown-pkg");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        let err = read_entry(&root, "absent").unwrap_err();
        assert!(format!("{err}").contains("absent"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unsatisfiable_requirement_is_an_error() {
        let root = temp_dir("unsat");
        write_fixture_index(&root, "http-extras", &["1.0.0", "1.2.0"]);
        let entry = read_entry(&root, "http-extras").expect("entry parses");
        let req = "^3".parse().expect("valid req");
        let err = resolve_version(&entry, &req).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no published version"), "{msg}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unknown_capability_is_rejected() {
        let root = temp_dir("bad-cap");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        std::fs::write(
            root.join("packages").join("weird.toml"),
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/weird\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = [\"telepathy\"]\n"
            ),
        )
        .expect("write entry");
        let err = read_entry(&root, "weird").unwrap_err();
        assert!(format!("{err}").contains("telepathy"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_per_version_field_is_rejected() {
        let root = temp_dir("missing-field");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        // No `sha256` — the integrity anchor is mandatory, so validation rejects
        // on the missing field before even reaching transport/commit validation.
        std::fs::write(
            root.join("packages").join("nohash.toml"),
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/nohash\"\nrev = \"{FIXTURE_REV}\"\n"
            ),
        )
        .expect("write entry");
        let err = read_entry(&root, "nohash").unwrap_err();
        assert!(format!("{err}").contains("sha256"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_entry_file_accepts_a_well_formed_entry() {
        // The admission-CI validator names the package by the file stem and
        // parses it exactly as the resolver would.
        use super::validate_entry_file;
        let root = temp_dir("validate-ok");
        write_fixture_index(&root, "http-extras", &["1.0.0", "1.2.0"]);
        let entry = validate_entry_file(&root.join("packages").join("http-extras.toml"))
            .expect("well-formed entry validates");
        assert_eq!(entry.name, "http-extras");
        assert_eq!(entry.versions.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_entry_file_rejects_an_unknown_capability() {
        use super::validate_entry_file;
        let root = temp_dir("validate-bad-cap");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        let path = packages.join("weird.toml");
        std::fs::write(
            &path,
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/weird\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = [\"telepathy\"]\n"
            ),
        )
        .expect("write entry");
        let err = validate_entry_file(&path).unwrap_err();
        assert!(format!("{err}").contains("telepathy"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_entry_file_rejects_a_missing_field() {
        use super::validate_entry_file;
        let root = temp_dir("validate-missing");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        let path = packages.join("nohash.toml");
        // No `sha256` — the integrity anchor is mandatory, so validation rejects
        // on the missing field before reaching transport/commit validation.
        std::fs::write(
            &path,
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/nohash\"\nrev = \"{FIXTURE_REV}\"\n"
            ),
        )
        .expect("write entry");
        let err = validate_entry_file(&path).unwrap_err();
        assert!(format!("{err}").contains("sha256"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn multiple_versions_are_all_parsed() {
        // Guards the array-of-tables scan: each `[[version]]` starts a fresh
        // record rather than overwriting the previous.
        let root = temp_dir("multi");
        write_fixture_index(&root, "p", &["0.1.0", "0.2.0", "0.3.0"]);
        let entry: IndexEntry = read_entry(&root, "p").expect("parses");
        let versions: Vec<String> = entry
            .versions
            .iter()
            .map(|v| v.version.to_string())
            .collect();
        assert_eq!(versions, vec!["0.1.0", "0.2.0", "0.3.0"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    // --- SourceUrl parse-boundary tests ---

    #[test]
    fn source_url_accepts_https() {
        assert!(SourceUrl::parse(&pn("p"), "https://github.com/user/repo").is_ok());
    }

    #[test]
    fn source_url_accepts_ssh() {
        let url = SourceUrl::parse(&pn("p"), "ssh://git@github.com/user/repo").unwrap();
        assert_eq!(url.transport(), Transport::Ssh);
    }

    #[test]
    fn source_url_refuses_plaintext_git_transport_naming_https() {
        let err = SourceUrl::parse(&pn("p"), "git://github.com/user/repo").unwrap_err();
        let shown = format!("{err}");
        assert!(matches!(err, crate::CliError::Resolve(_)), "{shown}");
        assert!(shown.contains("git://"), "{shown}");
        assert!(
            shown.contains("use the repository's https:// URL"),
            "{shown}"
        );
    }

    #[test]
    fn source_url_records_its_transport() {
        let cases = [
            ("https://github.com/user/repo", Transport::Https),
            ("ssh://git@github.com/user/repo", Transport::Ssh),
            ("file:///home/user/repo", Transport::File),
            ("/home/user/repo", Transport::File),
        ];
        for (raw, transport) in cases {
            assert_eq!(
                SourceUrl::parse(&pn("p"), raw).unwrap().transport(),
                transport
            );
        }
    }

    #[test]
    fn source_url_rejects_ext_transport_helper() {
        // `ext::` spawns an arbitrary shell command at clone time — RCE vector.
        let err = SourceUrl::parse(&pn("p"), "ext::sh -c 'id > /tmp/pwned'").unwrap_err();
        assert!(format!("{err}").contains("https://"), "{err}");
    }

    #[test]
    fn source_url_rejects_dash_leading_value() {
        // A value starting with `-` would be parsed by git as a flag.
        let err = SourceUrl::parse(&pn("p"), "--upload-pack=evil").unwrap_err();
        assert!(format!("{err}").contains("https://"), "{err}");
    }

    #[test]
    fn source_url_accepts_file_scheme() {
        // `file://` is on the allow-list so local and test-fixture repos work.
        assert!(SourceUrl::parse(&pn("p"), "file:///home/user/repo").is_ok());
    }

    #[test]
    fn source_url_accepts_bare_absolute_path() {
        assert!(SourceUrl::parse(&pn("p"), "/home/user/repo").is_ok());
    }

    #[test]
    fn source_url_rejects_fd_transport() {
        let err = SourceUrl::parse(&pn("p"), "fd::4").unwrap_err();
        assert!(format!("{err}").contains("https://"), "{err}");
    }

    #[test]
    fn source_url_rejects_a_field_break_out() {
        for raw in [
            "https://h/r\"\nsha256 = \"0",
            "https://h/r\nrev = \"x\"",
            "https://h/r\u{1b}[2J",
            "/abs/r\"",
        ] {
            let err = SourceUrl::parse(&pn("p"), raw).unwrap_err();
            assert!(!err.to_string().contains('\n'), "{err:?}");
        }
    }

    // --- CommitId parse-boundary tests ---

    #[test]
    fn commit_id_accepts_40_char_lowercase_hex() {
        assert!(CommitId::parse(&pn("p"), FIXTURE_REV).is_ok());
    }

    #[test]
    fn commit_id_accepts_64_char_sha256() {
        let sha256_rev = "a".repeat(64);
        assert!(CommitId::parse(&pn("p"), &sha256_rev).is_ok());
    }

    #[test]
    fn commit_id_accepts_short_hex() {
        // Abbreviated hashes are valid ref names with no injection shape.
        assert!(CommitId::parse(&pn("p"), "deadbeef").is_ok());
        assert!(CommitId::parse(&pn("p"), "abc").is_ok());
        assert!(CommitId::parse(&pn("p"), "00").is_ok());
    }

    #[test]
    fn commit_id_accepts_branch_name() {
        // Branch names are valid ref names with no injection shape.
        assert!(CommitId::parse(&pn("p"), "main").is_ok());
        assert!(CommitId::parse(&pn("p"), "HEAD").is_ok());
    }

    #[test]
    fn commit_id_accepts_uppercase_hex() {
        // Mixed-case is not injection-shaped.
        assert!(CommitId::parse(&pn("p"), "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2").is_ok());
    }

    #[test]
    fn commit_id_rejects_dash_leading_value() {
        // A `-`-leading rev would be parsed by git as a flag — injection shape.
        let err = CommitId::parse(&pn("p"), "-S injected").unwrap_err();
        assert!(format!("{err}").contains("rev"), "{err}");
    }

    #[test]
    fn commit_id_rejects_double_dot() {
        // `..` is a refspec metacharacter — injection shape.
        let err = CommitId::parse(&pn("p"), "HEAD..main").unwrap_err();
        assert!(format!("{err}").contains("rev"), "{err}");
    }

    #[test]
    fn commit_id_rejects_transport_helper_colons() {
        // `::` is the transport-helper separator — RCE vector.
        let err = CommitId::parse(&pn("p"), "ext::evil").unwrap_err();
        assert!(format!("{err}").contains("rev"), "{err}");
    }

    #[test]
    fn commit_id_rejects_at_brace() {
        // `@{` is a git reflog selector — injection shape.
        let err = CommitId::parse(&pn("p"), "HEAD@{0}").unwrap_err();
        assert!(format!("{err}").contains("rev"), "{err}");
    }

    #[test]
    fn malicious_index_entry_is_rejected_at_parse_time() {
        // An entry with `source = "ext::sh -c …"` must be rejected by
        // `read_entry` before any git invocation is possible.
        let root = temp_dir("malicious");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("evil.toml"),
            format!(
                "publisher = \"attacker\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"ext::sh -c 'id > /tmp/pwned'\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\n"
            ),
        )
        .expect("write entry");
        let err = read_entry(&root, "evil").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("source"), "{msg}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn injection_shaped_rev_in_index_entry_is_rejected_at_parse_time() {
        // A `-`-leading `rev` must be rejected by `read_entry` before any git
        // invocation — flag injection is the real threat, not plain ref names.
        let root = temp_dir("bad-rev");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("badrev.toml"),
            "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/badrev\"\nrev = \"-S injected\"\n\
             sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\n",
        )
        .expect("write entry");
        let err = read_entry(&root, "badrev").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rev"), "{msg}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // EntryLookup / read_entry_lookup — fail-closed integrity gate regression
    // -----------------------------------------------------------------------

    fn write_corrupt_entry(packages: &std::path::Path, name: &str) {
        // A file that exists but is not valid TOML / missing required fields.
        std::fs::write(
            packages.join(format!("{name}.toml")),
            "publisher = \"tester\"\n\n[[version]]\nversion = \"NOT_SEMVER\"\n\
             source = \"https://example.invalid/x\"\nrev = \"aabbcc\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
        )
        .expect("write corrupt entry");
    }

    #[test]
    fn lookup_absent_is_absent_variant() {
        let root = temp_dir("lookup-absent");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        let result = super::read_entry_lookup(&root, "nosuchpkg");
        assert!(
            matches!(result, super::EntryLookup::Absent),
            "a missing file must produce Absent, not Unreadable"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lookup_present_is_present_variant() {
        let root = temp_dir("lookup-present");
        write_fixture_index(&root, "mypkg", &["1.0.0"]);
        let result = super::read_entry_lookup(&root, "mypkg");
        assert!(
            matches!(result, super::EntryLookup::Present(_)),
            "a well-formed entry must produce Present"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lookup_corrupt_is_unreadable_variant() {
        let root = temp_dir("lookup-corrupt");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        write_corrupt_entry(&packages, "broken");
        let result = super::read_entry_lookup(&root, "broken");
        assert!(
            matches!(result, super::EntryLookup::Unreadable(_)),
            "a present-but-malformed entry must produce Unreadable, not Absent"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A traversing name must be refused by the name gate BEFORE `entry_path`
    /// joins it — never read an entry from outside the index root. The gate
    /// surfaces as `Unreadable` (fail-closed), never `Absent` (which a gate would
    /// treat as "first version → skip").
    #[test]
    fn lookup_rejects_traversal_name_as_unreadable() {
        let root = temp_dir("lookup-traversal");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        for hostile in ["..", "../../etc/passwd", "/etc/passwd", "a/b"] {
            let result = super::read_entry_lookup(&root, hostile);
            assert!(
                matches!(result, super::EntryLookup::Unreadable(_)),
                "hostile name {hostile:?} must be Unreadable (refused), got a non-Unreadable variant"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `read_entry` must refuse a traversing name with an error rather than
    /// joining it into a path and reading an arbitrary `.toml`.
    #[test]
    fn read_entry_rejects_traversal_name() {
        let root = temp_dir("read-entry-traversal");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        for hostile in ["..", "../secret", "/etc/hosts", "a/b"] {
            super::read_entry(&root, hostile)
                .expect_err(&format!("hostile name {hostile:?} must be rejected"));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `entry_file_exists` must refuse a traversing name rather than probing a
    /// path outside the index root.
    #[test]
    fn entry_file_exists_rejects_traversal_name() {
        let root = temp_dir("exists-traversal");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        super::entry_file_exists(&root, "../../etc/passwd")
            .expect_err("a traversing name must be rejected, not probed");
    }

    #[test]
    fn require_present_absent_yields_ok_none() {
        let root = temp_dir("rp-absent");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        let got = super::read_entry_lookup(&root, "nosuchpkg")
            .require_present()
            .expect("Absent must be Ok(None)");
        assert!(got.is_none(), "Absent must map to Ok(None), got Some");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn require_present_present_yields_ok_some() {
        let root = temp_dir("rp-present");
        write_fixture_index(&root, "mypkg", &["2.0.0"]);
        let got = super::read_entry_lookup(&root, "mypkg")
            .require_present()
            .expect("Present must be Ok(Some(_))")
            .expect("inner Option must be Some");
        assert_eq!(got.name, "mypkg");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn require_present_unreadable_yields_err() {
        // Regression for #1: a present-but-corrupt baseline must NOT produce
        // Ok(None) — that would let the immutability wall treat every submitted
        // version as "new" and skip the mutation check.
        let root = temp_dir("rp-corrupt");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        write_corrupt_entry(&packages, "broken");
        let result = super::read_entry_lookup(&root, "broken").require_present();
        assert!(
            result.is_err(),
            "Unreadable must map to Err (fail closed), got Ok"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absent_or_err_unreadable_yields_err() {
        // Regression for #2: a corrupt predecessor must NOT produce Ok(None)
        // (which the semver gate treats as "first version → skip").
        let root = temp_dir("aoe-corrupt");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        write_corrupt_entry(&packages, "broken");
        let result = super::read_entry_lookup(&root, "broken").absent_or_err();
        assert!(
            result.is_err(),
            "Unreadable must map to Err (fail closed) in absent_or_err, got Ok"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // --- PinnedRev type tests (test plan E) ---

    #[test]
    fn pinned_rev_rejects_moving_refs() {
        // Moving refs cannot inhabit PinnedRev; CommitId still accepts them
        // (the request role is deliberately distinct from the pin role).
        assert!(
            CommitId::parse(&pn("p"), "HEAD").is_ok(),
            "CommitId must accept HEAD as a request ref"
        );
        assert!(
            CommitId::parse(&pn("p"), "main").is_ok(),
            "CommitId must accept branch names as request refs"
        );
        assert!(
            PinnedRev::from_full_sha(&pn("p"), "HEAD", RevSite::IndexEntry).is_err(),
            "PinnedRev must reject HEAD"
        );
        assert!(
            PinnedRev::from_full_sha(&pn("p"), "main", RevSite::IndexEntry).is_err(),
            "PinnedRev must reject branch names"
        );
        assert!(
            PinnedRev::from_full_sha(&pn("p"), "v1.0", RevSite::IndexEntry).is_err(),
            "PinnedRev must reject tag names"
        );
        // Length boundary: 39 and 41 chars must be rejected.
        let short = "a".repeat(39);
        let long = "a".repeat(41);
        assert!(
            PinnedRev::from_full_sha(&pn("p"), &short, RevSite::IndexEntry).is_err(),
            "39-char hex must be rejected"
        );
        assert!(
            PinnedRev::from_full_sha(&pn("p"), &long, RevSite::IndexEntry).is_err(),
            "41-char hex must be rejected"
        );
        // Non-hex characters must be rejected even at length 40.
        let nonhex = format!("{}g", "a".repeat(39));
        assert!(
            PinnedRev::from_full_sha(&pn("p"), &nonhex, RevSite::IndexEntry).is_err(),
            "non-hex char must be rejected"
        );
        // Uppercase is rejected — the stored form must be lowercase hex.
        let upper = "A".repeat(40);
        assert!(
            PinnedRev::from_full_sha(&pn("p"), &upper, RevSite::IndexEntry).is_err(),
            "uppercase hex must be rejected"
        );
        // A valid 40-char lowercase hex string must be accepted.
        assert!(
            PinnedRev::from_full_sha(&pn("p"), FIXTURE_REV, RevSite::IndexEntry).is_ok(),
            "40-char lowercase hex must be accepted"
        );
    }

    // --- RequestedRev::classify / check_served (shape vs served-commit) ---

    #[test]
    fn requested_rev_classifies_head_and_names() {
        assert!(matches!(
            RequestedRev::classify(&pn("p"), &CommitId::parse(&pn("p"), "HEAD").unwrap()),
            Ok(RequestedRev::Head)
        ));
        assert!(matches!(
            RequestedRev::classify(&pn("p"), &CommitId::parse(&pn("p"), "main").unwrap()),
            Ok(RequestedRev::Name(name)) if name == "main"
        ));
        assert!(matches!(
            RequestedRev::classify(&pn("p"), &CommitId::parse(&pn("p"), "v1.2").unwrap()),
            Ok(RequestedRev::Name(name)) if name == "v1.2"
        ));
        // 3 hex chars is below the abbreviation floor (git's own minimum is 4) —
        // still a `Name`, not `AbbrevHex`.
        assert!(matches!(
            RequestedRev::classify(&pn("p"), &CommitId::parse(&pn("p"), "abc").unwrap()),
            Ok(RequestedRev::Name(name)) if name == "abc"
        ));
    }

    #[test]
    fn requested_rev_classifies_hex_by_length() {
        let abbrev4 = CommitId::parse(&pn("p"), "dead").unwrap();
        assert!(matches!(
            RequestedRev::classify(&pn("p"), &abbrev4),
            Ok(RequestedRev::AbbrevHex(a)) if a == "dead"
        ));
        let abbrev39 = CommitId::parse(&pn("p"), &"a".repeat(39)).unwrap();
        assert!(matches!(
            RequestedRev::classify(&pn("p"), &abbrev39),
            Ok(RequestedRev::AbbrevHex(a)) if a.len() == 39
        ));
        let full40 = CommitId::parse(&pn("p"), FIXTURE_REV).unwrap();
        assert!(matches!(
            RequestedRev::classify(&pn("p"), &full40),
            Ok(RequestedRev::FullSha(sha)) if sha.as_str() == FIXTURE_REV
        ));
        // 41 lowercase-hex chars is past the SHA-1 width — a `Name`, not a rev.
        let over41 = CommitId::parse(&pn("p"), &"a".repeat(41)).unwrap();
        assert!(matches!(
            RequestedRev::classify(&pn("p"), &over41),
            Ok(RequestedRev::Name(name)) if name.len() == 41
        ));
    }

    #[test]
    fn requested_rev_rejects_mixed_case_and_uppercase_hex() {
        let mixed = CommitId::parse(&pn("p"), "DeadBeef").unwrap();
        assert!(
            RequestedRev::classify(&pn("p"), &mixed).is_err(),
            "mixed-case hex must be rejected, not silently treated as a name"
        );
        let upper40 = CommitId::parse(&pn("p"), &"A".repeat(40)).unwrap();
        assert!(
            RequestedRev::classify(&pn("p"), &upper40).is_err(),
            "all-uppercase hex must be rejected — a SHA is always lowercase"
        );
    }

    #[test]
    fn check_served_is_permissive_for_head_and_name() {
        let served = PinnedRev::from_full_sha(&pn("p"), FIXTURE_REV, RevSite::IndexEntry).unwrap();
        assert!(check_served(&RequestedRev::Head, &served).is_none());
        assert!(check_served(&RequestedRev::Name("main".to_owned()), &served).is_none());
    }

    #[test]
    fn check_served_full_sha_agrees_or_refuses() {
        let served = PinnedRev::from_full_sha(&pn("p"), FIXTURE_REV, RevSite::IndexEntry).unwrap();
        assert!(check_served(&RequestedRev::FullSha(served.clone()), &served).is_none());

        let other_sha = "b".repeat(40);
        let requested =
            PinnedRev::from_full_sha(&pn("p"), &other_sha, RevSite::IndexEntry).unwrap();
        let mismatch = check_served(&RequestedRev::FullSha(requested), &served);
        assert!(
            matches!(mismatch, Some(RevMismatch::Different { .. })),
            "expected Different, got {mismatch:?}"
        );
        if let Some(RevMismatch::Different {
            requested: r,
            served: s,
        }) = mismatch
        {
            assert_eq!(r.as_str(), other_sha);
            assert_eq!(s.as_str(), FIXTURE_REV);
        }
    }

    #[test]
    fn check_served_abbrev_hex_prefix_match_or_shadowed() {
        let served = PinnedRev::from_full_sha(&pn("p"), FIXTURE_REV, RevSite::IndexEntry).unwrap();
        let prefix = FIXTURE_REV[..6].to_owned();
        assert!(
            check_served(&RequestedRev::AbbrevHex(prefix), &served).is_none(),
            "a genuine prefix of the served commit must not be flagged"
        );

        let non_prefix = "deadbe".to_owned();
        let mismatch = check_served(&RequestedRev::AbbrevHex(non_prefix.clone()), &served);
        assert!(
            matches!(mismatch, Some(RevMismatch::ShadowedAbbrev { .. })),
            "expected ShadowedAbbrev, got {mismatch:?}"
        );
        if let Some(RevMismatch::ShadowedAbbrev {
            requested,
            served: s,
        }) = mismatch
        {
            assert_eq!(requested, non_prefix);
            assert_eq!(s.as_str(), FIXTURE_REV);
        }
    }

    // --- Entry reader refuses non-SHA rev (test plan F) ---

    #[test]
    fn entry_reader_refuses_nonsha_rev() {
        // An index entry with a non-SHA rev is rejected at parse time.
        let root = temp_dir("nonsha-rev");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("badpin.toml"),
            "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/badpin\"\nrev = \"main\"\n\
             sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\n",
        )
        .expect("write entry");
        let err = read_entry(&root, "badpin").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rev"), "{msg}");
        assert!(msg.contains("immutable"), "{msg}");
        let _ = std::fs::remove_dir_all(&root);

        // Also verify a legacy "HEAD" stored rev is refused.
        let root2 = temp_dir("head-rev");
        let packages2 = root2.join("packages");
        std::fs::create_dir_all(&packages2).expect("packages dir");
        std::fs::write(
            packages2.join("headpin.toml"),
            "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/headpin\"\nrev = \"HEAD\"\n\
             sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\n",
        )
        .expect("write entry");
        let err2 = read_entry(&root2, "headpin").unwrap_err();
        let msg2 = format!("{err2}");
        assert!(msg2.contains("rev"), "{msg2}");
        let _ = std::fs::remove_dir_all(&root2);
    }

    // --- signature field: parse, backward-compat, malformed refusal ---

    /// A minimal well-formed single-line JSON-object bundle for fixtures.
    const BUNDLE_JSON: &str =
        r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":{}}"#;

    #[test]
    fn an_entry_without_a_signature_parses_as_unsigned() {
        // Backward compatibility: an entry with no `signature` field parses
        // exactly as before, with `signature == None`.
        let root = temp_dir("no-sig");
        write_fixture_index(&root, "http-extras", &["1.0.0"]);
        let entry = read_entry(&root, "http-extras").expect("entry parses");
        let v = entry.versions.first().expect("one version");
        assert!(v.signature.is_none(), "absent signature must be None");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_signed_entry_parses_the_bundle_from_toml() {
        // The bundle is stored as `ipe package publish` renders it: single-line
        // JSON inside exactly one outer pair of quotes.
        let root = temp_dir("signed-toml");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("signed.toml"),
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/signed\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\nsignature = \"{BUNDLE_JSON}\"\n"
            ),
        )
        .expect("write entry");
        let entry = read_entry(&root, "signed").expect("entry parses");
        let v = entry.versions.first().expect("one version");
        assert!(
            v.signature.is_some(),
            "present signature must parse to Some"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_malformed_signature_is_a_hard_error_not_silently_unsigned() {
        // A present-but-malformed bundle must be a hard error, never dropped to
        // "unsigned" — a malformed signature must not masquerade as absent.
        let root = temp_dir("bad-sig");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("badsig.toml"),
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/badsig\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"{}\"\ncapabilities = []\nsignature = not-json-at-all\n",
                "0".repeat(64)
            ),
        )
        .expect("write entry");
        let err = read_entry(&root, "badsig").unwrap_err();
        assert!(format!("{err}").contains("signature"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn json_mirror_parses_a_nested_signature_object() {
        // The JSON mirror carries `signature` as a nested object, re-serialized
        // and routed through the same typed constructor.
        let json = r#"{ "name": "http-extras", "publisher": "p",
            "versions": [ { "version": "1.0.0",
                            "source": "https://example.invalid/x",
                            "rev": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                            "signature": { "dsseEnvelope": {} } } ] }"#;
        let entry = super::parse_entry_json("http-extras", json).expect("parses");
        let v = entry.versions.first().expect("one version");
        assert!(v.signature.is_some(), "nested signature object must parse");
        let _ = v;
    }

    #[test]
    fn json_mirror_null_signature_is_unsigned() {
        // An explicit null `signature` is unsigned, backward-compatible.
        let json = r#"{ "name": "x", "publisher": "p",
            "versions": [ { "version": "1.0.0",
                            "source": "https://example.invalid/x",
                            "rev": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                            "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "signature": null } ] }"#;
        let entry = super::parse_entry_json("x", json).expect("parses");
        assert!(entry.versions.first().expect("v").signature.is_none());
    }

    /// A repeated object key is refused, never last-wins, at the top-level
    /// header object AND inside a nested `versions` element — mirroring the
    /// TOML reader's [`EntryFault::DuplicateKey`].
    #[test]
    fn json_mirror_refuses_a_duplicate_key() {
        use crate::CliError;
        let sha = "0".repeat(64);
        let duplicate_name = format!(
            r#"{{ "name": "http-extras", "name": "http-extras", "publisher": "p",
                "versions": [ {{ "version": "1.0.0",
                    "source": "https://example.invalid/x",
                    "rev": "{FIXTURE_REV}",
                    "sha256": "{sha}" }} ] }}"#
        );
        let err = super::parse_entry_json("http-extras", &duplicate_name)
            .expect_err("a duplicate top-level key must be refused");
        assert!(matches!(err, CliError::Resolve(_)), "{err}");

        let duplicate_rev = format!(
            r#"{{ "name": "http-extras", "publisher": "p",
                "versions": [ {{ "version": "1.0.0",
                    "source": "https://example.invalid/x",
                    "rev": "{FIXTURE_REV}",
                    "rev": "{FIXTURE_REV}",
                    "sha256": "{sha}" }} ] }}"#
        );
        let err = super::parse_entry_json("http-extras", &duplicate_rev)
            .expect_err("a duplicate key inside a `versions` element must be refused");
        assert!(matches!(err, CliError::Resolve(_)), "{err}");
    }

    /// A `publisher` that is not login-shaped is refused by both entry readers,
    /// and the refusal never echoes the hostile bytes.
    #[test]
    fn a_non_login_publisher_is_refused_by_both_readers() {
        use crate::CliError;
        let version = "\n[[version]]\nversion = \"1.0.0\"\nsource = \"https://example.invalid/x\"\n\
                       rev = \"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\"\n\
                       sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n";
        let too_long = "x".repeat(40);
        for hostile in [
            "",
            too_long.as_str(),
            "evil\x1b[2J",
            "bell\x07",
            "sp ace",
            "-lead",
            "dou--ble",
        ] {
            let toml = format!("name = \"x\"\npublisher = \"{hostile}\"\n{version}");
            let refused = super::parse_entry(&pn("x"), &toml);
            assert!(
                matches!(refused, Err(CliError::Resolve(_))),
                "TOML publisher {hostile:?} must be refused"
            );
            let Err(CliError::Resolve(msg)) = refused else {
                return;
            };
            assert!(msg.contains("is not a GitHub login"), "{msg}");
            assert!(!msg.contains('\x1b') && !msg.contains('\x07'), "{msg:?}");

            let quoted = serde_json::to_string(hostile).expect("a str serializes");
            let json = format!(
                r#"{{ "name": "x", "publisher": {quoted},
                    "versions": [ {{ "version": "1.0.0",
                        "source": "https://example.invalid/x",
                        "rev": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000" }} ] }}"#
            );
            let refused = super::parse_entry_json("x", &json);
            assert!(
                matches!(refused, Err(CliError::Resolve(_))),
                "JSON publisher {hostile:?} must be refused"
            );
            let Err(CliError::Resolve(msg)) = refused else {
                return;
            };
            assert!(msg.contains("is not a GitHub login"), "{msg}");
            assert!(!msg.contains('\x1b') && !msg.contains('\x07'), "{msg:?}");
        }
    }

    #[test]
    fn ssot_guardrail_no_read_entry_ok_in_ipe_cli_src() {
        // Assert that no future edit re-introduces a fail-open collapse of
        // `read_entry` at an integrity gate. The pattern `read_entry(…).ok()`
        // fuses "absent" and "unreadable" into None; every integrity gate must
        // use `read_entry_lookup` + `require_present` / `absent_or_err` instead.
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut violations = Vec::new();
        collect_ssot_violations(&src_dir, &mut violations);
        assert!(
            violations.is_empty(),
            "fail-open read_entry collapse detected — use read_entry_lookup instead:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn ssot_guardrail_no_read_to_string_ok_in_unsafe_scan_scope() {
        // Assert that no future edit re-introduces a fail-open read in the
        // unsafe-acknowledgment scan. `read_to_string(…).ok()` silently drops
        // unreadable modules so they never reach the acknowledgment gate; every
        // read in a security scan must propagate errors, not swallow them.
        // The scan covers index.rs's own production code: it reads only each
        // file's pre-`#[cfg(test)]` region, so the guardrail bodies below
        // (which mention the banned substrings as string literals) never
        // self-trigger.
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut violations = Vec::new();
        collect_read_to_string_ok_violations(&src_dir, &mut violations);
        assert!(
            violations.is_empty(),
            "fail-open read_to_string collapse detected — propagate the error instead:\n{}",
            violations.join("\n")
        );
    }

    /// The number of production lines to scan in a source file: everything up
    /// to (but not including) the first `#[cfg(test)]` attribute. Both guardrails
    /// enforce a *production* invariant — a fail-open collapse in shipped code —
    /// so scanning only the production region (a) covers this file's own
    /// production `read_entry` without the test-module guardrail bodies
    /// self-triggering on their `.contains("read_entry(")` string literals, and
    /// (b) never false-flags a `read_entry(x).ok()` written legitimately inside
    /// another file's test code.
    ///
    /// Relies on the crate convention that `#[cfg(test)]` items sit at the end of
    /// each file (a trailing `mod tests`, or a test-only helper below the
    /// production body); code above the first such attribute is production. The
    /// guardrail is defense-in-depth — the load-bearing guarantee is the fallible
    /// `Result` signature the call sites `?`-propagate.
    fn production_line_count(text: &str) -> usize {
        text.lines()
            .position(|l| l.trim_start().starts_with("#[cfg(test)]"))
            .unwrap_or_else(|| text.lines().count())
    }

    /// The production lines of every `.rs` file under `dir` that is not a
    /// comment, as `(path, 1-based line number, trimmed text)`. The tree is read
    /// whole or the guardrail fails: a skipped file is an unscanned file.
    fn production_lines(dir: &std::path::Path) -> Vec<(std::path::PathBuf, usize, String)> {
        let files = panic_scan::rust_sources(dir, panic_scan::Want::RustFiles)
            .expect("the guardrail lists the whole tree");
        let mut lines = Vec::new();
        for path in files {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("{}: {e}", path.display()))
                .expect("the guardrail reads every listed file");
            let prod = production_line_count(&text);
            for (i, line) in text.lines().take(prod).enumerate() {
                let trimmed = line.trim();
                if !trimmed.starts_with("//") {
                    lines.push((path.clone(), i + 1, trimmed.to_owned()));
                }
            }
        }
        lines
    }

    fn collect_ssot_violations(dir: &std::path::Path, out: &mut Vec<String>) {
        for (path, line_no, trimmed) in production_lines(dir) {
            if trimmed.contains("read_entry(") && trimmed.contains(".ok()") {
                out.push(format!("{}:{line_no}: {trimmed}", path.display()));
            }
            if trimmed.contains("let Ok(") && trimmed.contains("read_entry(") {
                out.push(format!("{}:{line_no}: {trimmed}", path.display()));
            }
        }
    }

    fn collect_read_to_string_ok_violations(dir: &std::path::Path, out: &mut Vec<String>) {
        for (path, line_no, trimmed) in production_lines(dir) {
            // The two banned forms that produce a fail-open unsafe scan:
            // 1. filter_map(|…| fs::read_to_string(…).ok()) — silently
            //    drops unreadable modules from the security scan.
            // 2. read_to_string(entry).ok().into_iter() — same defect on
            //    the single-file fallback path.
            if trimmed.contains("read_to_string") && trimmed.contains("filter_map") {
                out.push(format!("{}:{line_no}: {trimmed}", path.display()));
            }
            if trimmed.contains("read_to_string(") && trimmed.contains(".ok().into_iter()") {
                out.push(format!("{}:{line_no}: {trimmed}", path.display()));
            }
        }
    }

    /// Source locations: the network-share and device refusals, under both regimes.
    mod source_location {
        use super::super::{LocalRefusal, RemotePath, SourceKind, SourceRefusal, sink_check};
        use super::{SourceUrl, pn};
        use ipe_path_core::Regime;

        /// Every network-share and device spelling, with the kind it names.
        const REMOTE_ROWS: [(&str, RemotePath); 17] = [
            ("//h/s/r", RemotePath::Unc),
            (r"\\h\s\r", RemotePath::Unc),
            (r"/\h\s\r", RemotePath::Unc),
            (r"\/h/s", RemotePath::Unc),
            ("//h", RemotePath::Unc),
            (r"\\?\UNC\h\s\r", RemotePath::VerbatimUnc),
            ("//?/UNC/h/s", RemotePath::VerbatimUnc),
            (r"\\.\pipe\x", RemotePath::DeviceNamespace),
            ("//./C:/r", RemotePath::DeviceNamespace),
            (
                r"\\?\GLOBALROOT\Device\Mup\h\s",
                RemotePath::VerbatimNonDrive,
            ),
            (r"\??\UNC\h\s", RemotePath::NtObjectPath),
            ("/??/UNC/h/s", RemotePath::NtObjectPath),
            ("file://h/s/r", RemotePath::FileAuthority),
            ("file://H.example/r", RemotePath::FileAuthority),
            ("file:////h/s/r", RemotePath::Unc),
            (r"file:///\\h\s", RemotePath::Unc),
            ("file://localhost//h/s", RemotePath::Unc),
        ];

        const PERCENT_ROWS: [&str; 2] = ["file:///%5C%5Ch%5Cs", "file:///home/u/r%20x"];
        const WINDOWS_UNANCHORED_ROWS: [&str; 3] = ["C:repo", r"\repo", "/home/u/repo"];
        const WINDOWS_DRIVE_CONTROLS: [&str; 2] = [r"C:\repo", "C:/repo"];
        const DEVICE_ROWS: [&str; 3] = [r"C:\r\CON", r"C:\r\nul.txt\x", r"C:\COM1"];
        const LOSSY_ROWS: [&str; 3] = [r"\\?\C:\a\..\b", r"\\?\C:\a.\b", r"\\?\C:/a"];
        const FOREIGN_DRIVE_ROWS: [&str; 3] = [r"C:\r", "C:/r", r"\\?\C:\r"];

        /// The refusal `raw` meets under `regime`, or `None` when admitted.
        fn refusal(raw: &str, regime: Regime) -> Option<SourceRefusal> {
            SourceUrl::parse_in(raw, regime).err()
        }

        /// The `git remote add` argument `raw` yields under `regime`.
        #[allow(clippy::expect_used)] // every caller passes an admitted control
        fn git_arg(raw: &str, regime: Regime) -> String {
            let url = SourceUrl::parse_in(raw, regime).expect("control source is admitted");
            url.git_remote()
                .expect("admitted source reaches git")
                .to_owned()
        }

        #[test]
        fn a_remote_source_is_refused_under_every_regime() {
            for regime in [Regime::Unix, Regime::Windows] {
                for (raw, kind) in REMOTE_ROWS {
                    assert_eq!(
                        refusal(raw, regime),
                        Some(SourceRefusal::Remote(kind)),
                        "{raw:?} under {regime:?}"
                    );
                }
            }
            assert_eq!(refusal("/home/u/r", Regime::Unix), None);
            assert_eq!(refusal(r"C:\r", Regime::Windows), None);
        }

        #[test]
        fn a_percent_in_a_file_url_is_refused() {
            for raw in PERCENT_ROWS {
                assert_eq!(
                    refusal(raw, Regime::Unix),
                    Some(SourceRefusal::Local(LocalRefusal::PercentInFileUrl)),
                    "{raw:?}"
                );
            }
            assert_eq!(refusal("file:///home/u/r", Regime::Unix), None);
        }

        #[test]
        fn a_windows_unanchored_source_is_refused() {
            for raw in WINDOWS_UNANCHORED_ROWS {
                assert_eq!(
                    refusal(raw, Regime::Windows),
                    Some(SourceRefusal::Local(LocalRefusal::NotAnchored)),
                    "{raw:?}"
                );
            }
            for raw in WINDOWS_DRIVE_CONTROLS {
                assert_eq!(refusal(raw, Regime::Windows), None, "{raw:?}");
            }
        }

        #[test]
        fn a_windows_device_element_is_refused() {
            for raw in DEVICE_ROWS {
                assert_eq!(
                    refusal(raw, Regime::Windows),
                    Some(SourceRefusal::Local(LocalRefusal::DeviceElement)),
                    "{raw:?}"
                );
            }
            assert_eq!(refusal(r"C:\r\console", Regime::Windows), None);
            assert_eq!(refusal("/srv/aux/r", Regime::Unix), None);
        }

        #[test]
        fn a_lossy_verbatim_drive_is_refused() {
            for raw in LOSSY_ROWS {
                assert_eq!(
                    refusal(raw, Regime::Windows),
                    Some(SourceRefusal::Local(LocalRefusal::LossyVerbatim)),
                    "{raw:?}"
                );
            }
            assert_eq!(refusal(r"\\?\C:\a\b", Regime::Windows), None);
        }

        #[test]
        fn a_drive_source_is_refused_under_the_unix_regime() {
            for raw in FOREIGN_DRIVE_ROWS {
                assert_eq!(
                    refusal(raw, Regime::Unix),
                    Some(SourceRefusal::Local(LocalRefusal::ForeignDrive)),
                    "{raw:?}"
                );
            }
            assert_eq!(refusal("/r", Regime::Unix), None);
        }

        #[test]
        fn a_local_source_reaches_git_in_plain_spelling() {
            assert_eq!(git_arg(r"\\?\C:\a\b", Regime::Windows), r"C:\a\b");
            assert_eq!(git_arg("file:///C:/a", Regime::Windows), "C:/a");
            assert_eq!(git_arg("file://LOCALHOST/C:/a", Regime::Windows), "C:/a");
            assert_eq!(git_arg("file:///home/u/r", Regime::Unix), "/home/u/r");
            for remote in ["https://h/r", "ssh://git@h/r"] {
                assert_eq!(git_arg(remote, Regime::Unix), remote);
            }
            let local = SourceUrl::parse_in("file:///home/u/r", Regime::Unix);
            assert!(
                matches!(
                    local.as_ref().map(SourceUrl::kind),
                    Ok(SourceKind::Local(_))
                ),
                "{local:?}"
            );
            assert_eq!(
                local.map(|url| url.as_str().to_owned()),
                Ok("file:///home/u/r".to_owned()),
                "the recorded spelling is kept for the lockfile"
            );
        }

        #[test]
        fn the_git_sink_refuses_a_remote_spelling() {
            for (raw, kind) in REMOTE_ROWS {
                assert_eq!(sink_check(raw), Err(SourceRefusal::Remote(kind)), "{raw:?}");
            }
            for injected in ["-uhack", "ext::sh"] {
                assert_eq!(
                    sink_check(injected),
                    Err(SourceRefusal::Invalid),
                    "{injected:?}"
                );
            }
            for control in [r"C:\a\b", "C:/a", "/home/u/r", "https://h/r"] {
                assert_eq!(sink_check(control), Ok(()), "{control:?}");
            }
        }

        #[test]
        fn the_host_parse_is_the_host_regime_parse() {
            let rows = REMOTE_ROWS
                .iter()
                .map(|(raw, _)| *raw)
                .chain(PERCENT_ROWS)
                .chain(WINDOWS_UNANCHORED_ROWS)
                .chain(WINDOWS_DRIVE_CONTROLS)
                .chain(DEVICE_ROWS)
                .chain(LOSSY_ROWS)
                .chain(FOREIGN_DRIVE_ROWS)
                .chain([
                    "file:///home/u/r",
                    r"C:\r\console",
                    "/srv/aux/r",
                    r"\\?\C:\a\b",
                    "file:///C:/a",
                    "file://LOCALHOST/C:/a",
                    "https://h/r",
                    "ssh://git@h/r",
                ]);
            for raw in rows {
                assert_eq!(
                    SourceUrl::parse(&pn("p"), raw).is_ok(),
                    SourceUrl::parse_in(raw, ipe_path_core::HOST).is_ok(),
                    "{raw:?}"
                );
            }
            assert!(
                SourceUrl::parse(&pn("p"), "//h/s/r").is_err(),
                "the production entry point refuses a UNC share on this host"
            );
        }
    }

    // --- closed entry grammar: every line outside it is a located refusal ---

    /// A well-formed entry for `http-extras`: header on lines 1-2, one version
    /// table from line 4.
    fn closed_fixture() -> String {
        format!(
            "name = \"http-extras\"\npublisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/http-extras\"\nrev = \"{FIXTURE_REV}\"\n\
             sha256 = \"{}\"\ncapabilities = [\"network\"]\n",
            "0".repeat(64)
        )
    }

    /// The closed-grammar refusal `text` earns, read as `http-extras`.
    fn entry_refusal(text: &str) -> Option<super::EntryRefusal> {
        match super::parse_entry(&pn("http-extras"), text) {
            Err(crate::CliError::IndexEntryRefused(refusal)) => Some(*refusal),
            Ok(_) | Err(_) => None,
        }
    }

    /// Assert `text` is refused at 1-based `line` with `fault`.
    fn assert_refused(text: &str, line: usize, fault: &EntryFault) {
        let refusal = entry_refusal(text);
        assert_eq!(
            refusal.as_ref().map(|r| (r.line(), r.fault().clone())),
            Some((crate::line_grammar::TextLine::numbered(line), fault.clone())),
            "{text:?}"
        );
    }

    #[test]
    fn the_closed_fixture_and_the_live_schema_example_parse() {
        assert!(super::parse_entry(&pn("http-extras"), &closed_fixture()).is_ok());
        let example = "# A complete, valid index entry. It is a schema example \u{2014} \
                       not a real package.\nname = \"example-package\"\npublisher = \"arthurmaciel\"\n\n\
                       [[version]]\nversion = \"1.1.0\"\n\
                       source = \"https://github.com/arthurmaciel/example-package\"\n\
                       rev = \"1a2b3c4d5e6f70819a2b3c4d5e6f70819a2b3c4d\"\n\
                       sha256 = \"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9\"\n\
                       capabilities = [\"network\", \"clock\"]\n";
        assert!(super::parse_entry(&pn("example-package"), example).is_ok());
    }

    #[test]
    fn entry_garbage_line_is_refused_with_its_line() {
        let text = closed_fixture().replace("\n\n[[version]]", "\nnot a field\n[[version]]");
        assert_refused(&text, 3, &EntryFault::UnrecognisedLine);
        let section = closed_fixture().replace("\n\n[[version]]", "\n[other]\n[[version]]");
        assert_refused(&section, 3, &EntryFault::UnrecognisedLine);
        let single = closed_fixture().replace("[[version]]", "[version]");
        assert_refused(&single, 4, &EntryFault::UnrecognisedLine);
        let assigned = closed_fixture().replace("[[version]]", "[[version]] = \"1.0.0\"");
        assert_refused(&assigned, 4, &EntryFault::UnrecognisedLine);
    }

    #[test]
    fn entry_unknown_key_is_refused() {
        let header = closed_fixture().replace("\n\n[[version]]", "\nhomepage = \"x\"\n[[version]]");
        assert_refused(&header, 3, &EntryFault::UnknownKey("homepage".to_owned()));
        let version = format!("{}yanked = \"true\"\n", closed_fixture());
        assert_refused(&version, 10, &EntryFault::UnknownKey("yanked".to_owned()));
        let long = format!("{}{} = \"x\"\n", closed_fixture(), "k".repeat(200));
        assert_refused(
            &long,
            10,
            &EntryFault::UnknownKey("k".repeat(crate::line_grammar::MAX_KEY_ECHO)),
        );
    }

    #[test]
    fn entry_key_outside_its_table_is_refused() {
        let header_in_version = format!("{}publisher = \"other\"\n", closed_fixture());
        assert_refused(
            &header_in_version,
            10,
            &EntryFault::MisplacedKey(EntryKey::Header(HeaderKey::Publisher)),
        );
        let version_before_header = closed_fixture().replace(
            "publisher = \"tester\"\n",
            "publisher = \"tester\"\nrev = \"x\"\n",
        );
        assert_refused(
            &version_before_header,
            3,
            &EntryFault::MisplacedKey(EntryKey::Version(VersionKey::Rev)),
        );
    }

    #[test]
    fn entry_value_outside_its_shape_is_refused() {
        let cases = [
            (
                "version = \"1.0.0\"",
                "version = 1.0.0",
                VersionKey::Version,
            ),
            (
                "version = \"1.0.0\"",
                "version = \"1.0.0\" # note",
                VersionKey::Version,
            ),
            (
                "version = \"1.0.0\"",
                "version = \"1.0\"\"0\"",
                VersionKey::Version,
            ),
            (
                "capabilities = [\"network\"]",
                "capabilities = network",
                VersionKey::Capabilities,
            ),
            (
                "capabilities = [\"network\"]",
                "capabilities = [network]",
                VersionKey::Capabilities,
            ),
            (
                "capabilities = [\"network\"]",
                "capabilities = [\"network\",]",
                VersionKey::Capabilities,
            ),
            (
                "capabilities = [\"network\"]",
                "capabilities = [\"\"]",
                VersionKey::Capabilities,
            ),
            (
                "capabilities = [\"network\"]",
                "capabilities = [\"network\", \"network\"]",
                VersionKey::Capabilities,
            ),
        ];
        for (good, bad, key) in cases {
            let text = closed_fixture().replace(good, bad);
            let refusal = entry_refusal(&text);
            assert_eq!(
                refusal.map(|r| r.fault().clone()),
                Some(EntryFault::MalformedValue(EntryKey::Version(key))),
                "{bad}"
            );
        }
        let bare_signature = format!("{}signature = {BUNDLE_JSON}\n", closed_fixture());
        assert_refused(
            &bare_signature,
            10,
            &EntryFault::MalformedValue(EntryKey::Version(VersionKey::Signature)),
        );
        let signed = format!("{}signature = \"{BUNDLE_JSON}\"\n", closed_fixture());
        assert!(super::parse_entry(&pn("http-extras"), &signed).is_ok());
        for hazard in ['\u{202e}', '\u{2066}', '\u{200b}', '\t', '\u{7f}'] {
            let hidden = signed.replace("dsseEnvelope", &format!("dsse{hazard}Envelope"));
            assert_refused(
                &hidden,
                10,
                &EntryFault::MalformedValue(EntryKey::Version(VersionKey::Signature)),
            );
        }
    }

    #[test]
    fn json_mirror_refuses_a_repeated_version_or_capability() {
        let version = |v: &str, caps: &str| {
            format!(
                "{{\"version\":\"{v}\",\"source\":\"https://example.invalid/x\",\
                 \"rev\":\"{FIXTURE_REV}\",\"sha256\":\"{}\",\"capabilities\":[{caps}]}}",
                "0".repeat(64)
            )
        };
        let entry = |versions: &[String]| {
            format!(
                "{{\"name\":\"http-extras\",\"publisher\":\"tester\",\"versions\":[{}]}}",
                versions.join(",")
            )
        };
        let one = version("1.0.0", "\"network\"");
        assert!(super::parse_entry_json("http-extras", &entry(std::slice::from_ref(&one))).is_ok());
        let other_rev = one.replace(FIXTURE_REV, &"1".repeat(40));
        for (text, needle) in [
            (entry(&[one, other_rev]), "listed twice"),
            (
                entry(&[version("1.0.0", "\"network\",\"network\"")]),
                "listed twice",
            ),
        ] {
            let rendered = super::parse_entry_json("http-extras", &text)
                .err()
                .map(|err| err.to_string())
                .unwrap_or_default();
            assert!(rendered.contains(needle), "{rendered}");
        }
    }

    #[test]
    fn entry_duplicate_key_is_refused() {
        let header = closed_fixture().replace(
            "publisher = \"tester\"\n",
            "publisher = \"tester\"\npublisher = \"attacker\"\n",
        );
        assert_refused(
            &header,
            3,
            &EntryFault::DuplicateKey(EntryKey::Header(HeaderKey::Publisher)),
        );
        let version = format!("{}sha256 = \"{}\"\n", closed_fixture(), "1".repeat(64));
        assert_refused(
            &version,
            10,
            &EntryFault::DuplicateKey(EntryKey::Version(VersionKey::Sha256)),
        );
    }

    #[test]
    fn entry_duplicate_version_is_refused_at_its_second_header() {
        let fixture = closed_fixture();
        let table = fixture.split_once("\n\n").map_or("", |(_, table)| table);
        let text = format!("{fixture}\n{table}");
        let version = crate::published_version::PublishedVersion::parse("1.0.0").ok();
        assert_eq!(
            entry_refusal(&text).map(|r| (r.line(), r.fault().clone())),
            version.map(|v| (
                crate::line_grammar::TextLine::numbered(11),
                EntryFault::DuplicateVersion(v)
            )),
        );
    }

    #[test]
    fn entry_name_naming_another_package_is_refused() {
        let text = closed_fixture().replace("name = \"http-extras\"", "name = \"other\"");
        assert_refused(&text, 1, &EntryFault::NameMismatch);
    }

    #[test]
    fn entry_hidden_characters_are_refused() {
        let bidi = format!("# safe \u{202e}evil\n{}", closed_fixture());
        assert!(matches!(
            entry_refusal(&bidi).map(|r| (r.line(), r.fault().clone())),
            Some((line, EntryFault::HiddenCharacter(_)))
                if line == crate::line_grammar::TextLine::numbered(1)
        ));
        let separator = closed_fixture().replace("[[version]]", "\u{2028}[[version]]");
        assert_refused(&separator, 4, &EntryFault::UnrecognisedLine);
        let nbsp_key = closed_fixture().replace("\nrev =", "\n\u{a0}rev =");
        assert!(entry_refusal(&nbsp_key).is_some());
        let carriage =
            closed_fixture().replace("[[version]]\n", "[[version]]\rversion = \"9.9.9\"\n");
        assert!(entry_refusal(&carriage).is_some());
    }

    #[test]
    fn entry_refusal_renders_the_line_and_the_remedy() {
        let text = closed_fixture().replace(
            "\n\n[[version]]",
            "\nhome\u{1b}[31mpage = \"x\"\n[[version]]",
        );
        let rendered = super::parse_entry(&pn("http-extras"), &text)
            .err()
            .map(|err| err.to_string())
            .unwrap_or_default();
        assert!(rendered.contains("line 3"), "{rendered}");
        assert!(
            rendered.contains(crate::text::index_entry_remedy()),
            "{rendered}"
        );
        assert!(!rendered.contains('\u{1b}'), "{rendered}");
    }

    #[test]
    fn json_mirror_refuses_unknown_keys_and_another_name() {
        let entry = |top: &str, version_extra: &str| {
            format!(
                "{{\"name\":\"http-extras\",\"publisher\":\"tester\",{top}\"versions\":[{{\
                 \"version\":\"1.0.0\",\"source\":\"https://example.invalid/x\",\
                 \"rev\":\"{FIXTURE_REV}\",\"sha256\":\"{}\",\"capabilities\":[]{version_extra}}}]}}",
                "0".repeat(64)
            )
        };
        assert!(super::parse_entry_json("http-extras", &entry("", "")).is_ok());
        for (text, needle) in [
            (entry("\"homepage\":\"x\",", ""), "homepage"),
            (entry("", ",\"yanked\":true"), "yanked"),
            (
                entry("", "").replace("\"name\":\"http-extras\"", "\"name\":\"other\""),
                "another package",
            ),
        ] {
            let rendered = super::parse_entry_json("http-extras", &text)
                .err()
                .map(|err| err.to_string())
                .unwrap_or_default();
            assert!(rendered.contains(needle), "{rendered}");
        }
    }

    #[test]
    fn source_url_refuses_characters_outside_its_alphabet() {
        for raw in [
            "https://example.invalid/a b",
            "https://example.invalid/a\\b",
            "https://ex\u{430}mple.invalid/x",
            "https://example.invalid/\u{202e}x",
            "https://example.invalid/\u{200b}x",
            "ssh://git@example.invalid/a\u{a0}b",
        ] {
            assert!(SourceUrl::parse(&pn("p"), raw).is_err(), "{raw:?}");
        }
        assert!(SourceUrl::parse(&pn("p"), "https://example.invalid/a-b_c~d%20e?f=g#h").is_ok());
        #[cfg(unix)]
        {
            assert!(SourceUrl::parse(&pn("p"), "/srv/repo\u{202e}x").is_err());
            assert!(SourceUrl::parse(&pn("p"), "/srv/repo\u{2066}x").is_err());
            assert!(SourceUrl::parse(&pn("p"), "/srv/r\u{e9}po with space").is_ok());
        }
    }

    #[test]
    fn rev_remedy_follows_its_site() {
        let refused = |site: RevSite| {
            PinnedRev::from_full_sha(&pn("pkg"), "HEAD", site)
                .err()
                .map(|err| err.to_string())
                .unwrap_or_default()
        };
        let lock = refused(RevSite::Lockfile);
        let entry = refused(RevSite::IndexEntry);
        let head = refused(RevSite::GitHead);
        for (rendered, remedy) in [
            (&lock, crate::text::lock_remedy()),
            (&entry, crate::text::index_entry_remedy()),
            (&head, crate::text::index_rev_remedy_sha1()),
        ] {
            assert!(rendered.ends_with(remedy), "{rendered}");
            assert!(!rendered.contains("re-run `ipe add`"), "{rendered}");
        }
    }
}
