//! `Ipe.Path` — a typed, opaque filesystem path.
//!
//! Every `Path` holds text produced by ONE constructor, `path_core::seal`,
//! under the host separator regime. The builders that reach it are
//! [`path_from_string`] (Ipê text) and `from_os` (OS-produced text, refused
//! when not valid UTF-8 — never rewritten lossily). The seal normalises the
//! path lexically and REJECTS the byte-level primitives that make a raw
//! `String` path a traversal / injection surface:
//!
//! * a NUL byte (`\0`) — a C-string terminator that truncates the path at the
//!   syscall boundary, so `"safe.txt\0../../etc/passwd"` reaches the kernel as
//!   `"safe.txt"` on one code path and the full string on another (a classic
//!   poisoned-NUL bypass);
//! * on Windows, an element that trailing dot/space stripping turns into `..`;
//!   and
//! * a traversal escape — a relative path whose `..` elements climb ABOVE the
//!   directory it is resolved against (cleaned form is `..` or begins `../`).
//!   A rooted path cannot escape (`Clean` already stops `..` at the root), so
//!   it is allowed; a relative path that stays at or below its base is allowed.
//!
//! Because every `Path` is sealed at construction, the pure helpers
//! ([`path_base`] / [`path_dir`] / [`path_ext`] / [`path_is_absolute`]) and the
//! `Ipe.File` kernels take a `Path` and never re-validate — the type is the
//! proof. The helpers read the path under the same host regime, so a Windows
//! volume prefix (`C:`, `\\srv\shr`) is never cut or mistaken for an element.
//! [`path_to_string`] is the single un-parse back to the raw `String`.
//!
//! The lexical engine ([`clean_with`]) implements `filepath` semantics directly
//! rather than wrapping `std::path`, which is OS-tagged and diverges on
//! trailing slashes, repeated separators, and dotfiles. On Windows the same
//! engine is driven with the Windows separator set (`\` and `/`) and
//! volume-prefix parsing so the traversal check is not `\`-bypassable.
//!
//! # Trust model — what `Path` does and does NOT guarantee
//!
//! `Path` is a LEXICAL guard, not a jail. It guarantees the string contains no
//! NUL byte and does not `..`-escape *lexically*. It deliberately does NOT:
//! * forbid ABSOLUTE paths — `/etc/passwd` is a valid `Path`. Confining a
//!   program to a subtree is the job of the runtime capability jail (whether a
//!   program may touch the filesystem AT ALL is the `Filesystem` capability),
//!   not of this lexical constructor.
//! * resolve or forbid SYMLINKS — a validated `Path` may still point through a
//!   symlink that leaves any intended root. Symlink containment is an OS/jail
//!   concern (`openat2(RESOLVE_BENEATH)` / a chroot), out of lexical scope.
//!
//! # Composition — `under` / `absolute`
//!
//! Paths are composed ONLY through [`path_under`] (`root` + relative `child`),
//! never by string concatenation. It refuses an empty, absolute,
//! volume-prefixed, `..`-bearing, or NUL-bearing child, and re-checks that the
//! cleaned join lies component-wise below the root (`/repo2/x` is not under
//! `/repo`). On Windows it also refuses a child element holding a `:`, made
//! only of dots and spaces, naming a reserved DOS device, or ending in a dot or
//! a space, and re-scans the joined result for each of them independently of
//! the child parse.
//! [`path_absolute`] resolves a relative path against the working
//! directory through the same join.
//!
//! Symlink decision: both are LEXICAL and do not touch the filesystem. They do
//! not resolve, follow, or forbid symlinks, so a joined path whose ancestor is
//! a link can still reach outside the root when later opened. This fails
//! closed in the only sense a lexical operation can: nothing is ever resolved
//! into a wider path than the text names. Holding the root as a directory
//! handle (`openat`-style resolution) is the `Ipe.File` boundary's concern.
//!
//! In short: `Path` closes the raw-string traversal/NUL-injection hole at the
//! type boundary; it is not a substitute for the capability jail's authority
//! decision about which paths a program is allowed to reach.

use super::{IpeError, IpeResult, IpeTask, ok_res};
// The lexical seal lives once in the sibling `path_core` module (shared with
// the compiler's literal-path gate, which `include!`s the SAME `path_core.rs` file
// via the `ipe_path_core` crate); this module drives it with the HOST regime so
// the runtime seal stays target-specific. A sibling module (not an extern
// crate) so it resolves both in the workspace AND when the runtime is vendored
// as `mod ipe_runtime` into an emitted app.
#[cfg(feature = "server")]
use super::path_core::RelPath;
use super::path_core::{
    ChildElement, ElementClass, ElementRefusal, HOST, Regime, SealRefusal, Volume, clean_with,
    escapes_root, has_nul, is_dos_device, is_sep, seal, volume_name_len,
};
use std::ffi::OsStr;
use std::path::PathBuf;

/// `Ipe.Path`'s opaque, sealed newtype.
///
/// The wrapped `String` is always the output of `path_core::seal` under the
/// host regime: [`path_from_string`] and `from_os` are the only builders.
///
/// `Clone` is derived (a `Path` may be stored and passed to more than one
/// kernel). `Debug` / `PartialEq` / `Eq` are derived and safe: a `Path` is not
/// a secret, so printing or comparing the cleaned string leaks nothing the
/// caller did not already hand in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path(String);

// The cleaned path string, identical to [`path_to_string`].
crate::stringify::show_row!("Path", Value, [] Path, |p| p.0.clone());

/// `Ipe.Path.fromString : String -> Result Error Path` — THE seal.
///
/// The public constructor: every `Path` built from Ipê text traces back to
/// one of these calls, so a reviewer can `grep` this one symbol to audit every
/// place a raw string becomes a typed path.
///
/// Fails closed (`Err`, kind `InvalidInput`) on a NUL byte, a Windows
/// trailing-dot/space traversal disguise, or a `..` escape; succeeds with the
/// lexically-cleaned form otherwise. The empty string cleans to `"."`.
#[must_use]
pub fn path_from_string<E: From<IpeError>>(s: String) -> IpeResult<E, Path> {
    match seal(&s, HOST) {
        Ok(cleaned) => IpeResult::Ok(Path(cleaned)),
        Err(why) => IpeResult::Err(PathRefusal::Seal { path: s, why }.into_error()),
    }
}

/// Seal an OS path into a `Path` under the host regime.
///
/// THE decode for OS-produced paths (the working directory, a created temp
/// entry): text that is not valid UTF-8 is refused, never rewritten lossily
/// into a path that names a different file, and valid text still passes the
/// one seal.
///
/// # Errors
///
/// An `InvalidInput` [`IpeError`] naming `origin` when `p` is not valid UTF-8
/// or the seal refuses it.
pub(crate) fn from_os(p: &std::path::Path, origin: OsOrigin) -> Result<Path, IpeError> {
    from_os_with(p.as_os_str(), origin, HOST)
        .map(Path)
        .map_err(PathRefusal::into_error)
}

/// The OS-path decode under an explicit regime, as [`from_os`].
fn from_os_with(p: &OsStr, origin: OsOrigin, regime: Regime) -> Result<String, PathRefusal> {
    let text = utf8_of(p, origin)?;
    seal(text, regime).map_err(|why| PathRefusal::Seal {
        path: text.to_owned(),
        why,
    })
}

/// Decode one OS directory-entry name as UTF-8 text.
///
/// An entry name is a single element, not a `Path`; the name is refused, never
/// rewritten lossily, when it is not valid UTF-8.
///
/// # Errors
///
/// An `InvalidInput` [`IpeError`] naming `origin` when `n` is not valid UTF-8.
pub(crate) fn name_from_os(n: &OsStr, origin: OsOrigin) -> Result<String, IpeError> {
    utf8_of(n, origin)
        .map(str::to_owned)
        .map_err(PathRefusal::into_error)
}

/// Borrow `text` as UTF-8, or refuse it on behalf of `origin`.
fn utf8_of(text: &OsStr, origin: OsOrigin) -> Result<&str, PathRefusal> {
    text.to_str().ok_or_else(|| PathRefusal::NotUtf8 {
        origin,
        text: text.to_owned(),
    })
}

/// Join an OS directory-entry name beneath the directory `root` it was read from.
///
/// The walk's one composition: the name passes [`join_beneath`] like any
/// `Ipe.Path.under` child, so a name the host resolves outside `root` (a `..`,
/// a Windows device or stream) is refused rather than yielded.
///
/// # Errors
///
/// An `InvalidInput` [`IpeError`] when the join refuses `name`.
pub(crate) fn join_entry(root: &Path, name: &str) -> Result<Path, IpeError> {
    join_beneath(JoinOp::Walk, root.as_str(), name, HOST)
        .map(Path)
        .map_err(PathRefusal::into_error)
}

/// Where an OS text refused by [`from_os`] / [`name_from_os`] came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OsOrigin {
    /// `Ipe.Path.absolute` reading the working directory.
    AbsoluteCwd,
    /// `Ipe.System.cwd` reading the working directory.
    SystemCwd,
    /// `Ipe.File.readDir` reading an entry name.
    ReadDir,
    /// `Ipe.File.walk` / `walkMatching` reading an entry name.
    Walk,
    /// `Ipe.File.tempFile` reading the created file's path.
    TempFile,
    /// `Ipe.File.tempDir` reading the created directory's path.
    TempDir,
}

impl OsOrigin {
    /// The Ipê-facing operation name that prefixes the refusal.
    const fn op(self) -> &'static str {
        match self {
            Self::AbsoluteCwd => "Ipe.Path.absolute",
            Self::SystemCwd => "Ipe.System.cwd",
            Self::ReadDir => "Ipe.File.readDir",
            Self::Walk => "Ipe.File.walk",
            Self::TempFile => "Ipe.File.tempFile",
            Self::TempDir => "Ipe.File.tempDir",
        }
    }

    /// What the refused text names.
    const fn what(self) -> &'static str {
        match self {
            Self::AbsoluteCwd | Self::SystemCwd => "working directory",
            Self::ReadDir | Self::Walk => "entry name",
            Self::TempFile | Self::TempDir => "temporary path",
        }
    }
}

/// Why a `Path` operation refused its input.
///
/// Every refusal of the seal, the OS decode, [`under_with`] and
/// [`absolute_from`] is one of these; it becomes text only at the Ipê-facing
/// boundary, through its one `Display`, as an `InvalidInput` [`IpeError`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum PathRefusal {
    /// The seal refused `path`.
    Seal { path: String, why: SealRefusal },
    /// An OS text from `origin` is not valid UTF-8.
    NotUtf8 {
        origin: OsOrigin,
        text: std::ffi::OsString,
    },
    /// The join behind `op` refused the child itself.
    Child {
        op: JoinOp,
        child: String,
        why: ChildRefusal,
    },
    /// The cleaned join behind `op` does not lie strictly beneath the root.
    NotBeneath {
        op: JoinOp,
        child: String,
        root: String,
    },
    /// `absolute` met a working directory with no complete volume to anchor a
    /// Windows root-relative path.
    CwdNoVolume { cwd: String, path: String },
}

impl PathRefusal {
    /// The refusal as the caller's input error (`InvalidInput`), never `Unexpected`.
    fn into_error<E: From<IpeError>>(self) -> E {
        IpeError::invalid_input(self.to_string()).into()
    }
}

impl std::fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Seal { path, why } => write!(f, "{}", why.describe(path)),
            Self::NotUtf8 { origin, text } => write!(
                f,
                "{}: the {} {text:?} is not valid UTF-8",
                origin.op(),
                origin.what()
            ),
            Self::Child { op, child, why } => {
                write!(f, "{}: child path {child:?} {}", op.name(), why.reason())
            }
            Self::NotBeneath { op, child, root } => write!(
                f,
                "{}: {child:?} does not resolve beneath the root {root:?}",
                op.name()
            ),
            Self::CwdNoVolume { cwd, path } => write!(
                f,
                "Ipe.Path.absolute: the working directory {cwd:?} names no complete volume to \
                 anchor {path:?}"
            ),
        }
    }
}

/// The `Ipe.Path` operation whose child join refused, named in the refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum JoinOp {
    /// `Ipe.Path.under` joining its child beneath its root.
    Under,
    /// `Ipe.Path.absolute` joining a relative path beneath the working directory.
    Absolute,
    /// `Ipe.File.walk` joining an entry name beneath the directory it was read from.
    Walk,
    /// A static-file mount joining a request path beneath its served directory.
    #[cfg(feature = "server")]
    Static,
}

impl JoinOp {
    /// The Ipê-facing operation name that prefixes the refusal.
    const fn name(self) -> &'static str {
        match self {
            Self::Under => "Ipe.Path.under",
            Self::Absolute => "Ipe.Path.absolute",
            Self::Walk => "Ipe.File.walk",
            #[cfg(feature = "server")]
            Self::Static => "static file request",
        }
    }
}

/// Why `under` refused a child on its own, before any containment check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ChildRefusal {
    /// The root or the child holds a NUL byte.
    Nul,
    /// The child names the root itself (empty or `.`).
    Empty,
    /// The child is rooted or volume-prefixed, so it would replace the root.
    Absolute,
    /// The root is a bare drive (`C:`), which is drive-relative.
    BareDriveRoot,
    /// One raw element of the child may never be joined.
    Element(ElementRefusal),
}

impl ChildRefusal {
    /// The reason text [`PathRefusal`]'s `Display` reports after the child.
    const fn reason(self) -> &'static str {
        match self {
            Self::Nul => "contains a NUL byte",
            Self::Empty => "is empty (it names the root itself)",
            Self::Absolute => "is absolute or volume-prefixed (it would replace the root)",
            Self::BareDriveRoot => "cannot be joined to a bare drive root (drive-relative)",
            Self::Element(e) => e.reason(),
        }
    }
}

/// `Ipe.Path.toString : Path -> String` — THE single un-parse: recover the
/// cleaned path string. Consumes the `Path` (the typed proof is spent when the
/// raw string comes back out).
#[must_use]
pub fn path_to_string(p: Path) -> String {
    p.0
}

/// Borrow the cleaned path string. For the `Ipe.File` kernel boundary, which
/// needs the `&str` to hand to `std::fs`.
impl Path {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the owned cleaned string (for kernels that need `String`).
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Split a sealed `path` into its volume prefix and the rest under `regime`.
fn split_volume(path: &str, regime: Regime) -> (&str, &str) {
    path.split_at_checked(volume_name_len(path, regime))
        .unwrap_or(("", path))
}

/// The byte index just past the last separator in `s` (`0` when none).
fn after_last_sep(s: &str, regime: Regime) -> usize {
    s.as_bytes()
        .iter()
        .rposition(|&c| is_sep(c, regime))
        .map_or(0, |i| i + 1)
}

/// `Ipe.Path.base : Path -> String` — the final element.
///
/// "" → "."; a path with no element past its volume and root → that root
/// spelling (`/`, `C:\`, `\\srv\shr`); else the final element with trailing
/// separators stripped.
#[must_use]
pub fn path_base(p: Path) -> String {
    base_with(&p.0, HOST)
}

/// The final element of `path` under `regime`, as [`path_base`].
fn base_with(path: &str, regime: Regime) -> String {
    if path.is_empty() {
        return ".".to_string();
    }
    let (volume, rest) = split_volume(path, regime);
    let stripped =
        rest.trim_end_matches(|c: char| u8::try_from(c).is_ok_and(|c| is_sep(c, regime)));
    if stripped.is_empty() {
        // No element past the volume: the volume plus its root separator.
        let root_len = volume.len() + usize::from(!rest.is_empty());
        return path.get(..root_len).unwrap_or(path).to_string();
    }
    stripped
        .get(after_last_sep(stripped, regime)..)
        .unwrap_or("")
        .to_string()
}

/// `Ipe.Path.dir : Path -> String` — all but the last element, then cleaned.
///
/// The volume prefix is never cut: "" / "foo" → "."; "/" → "/";
/// "/foo/bar" → "/foo"; "a//b" → "a"; on Windows `C:x` → `C:`.
#[must_use]
pub fn path_dir(p: Path) -> String {
    dir_with(&p.0, HOST)
}

/// All but the last element of `path` under `regime`, as [`path_dir`].
fn dir_with(path: &str, regime: Regime) -> String {
    let (volume, rest) = split_volume(path, regime);
    let dir = clean_with(
        rest.get(..after_last_sep(rest, regime)).unwrap_or(""),
        regime,
    );
    if volume.is_empty() {
        dir
    } else if dir == "." {
        volume.to_string()
    } else {
        format!("{volume}{dir}")
    }
}

/// `Ipe.Path.ext : Path -> String` — the final element's extension.
///
/// The suffix from the LAST `.` in the final path element (including the dot),
/// or "" when the final element has no dot; the volume prefix is never read.
/// `".bashrc"` → `".bashrc"`.
#[must_use]
pub fn path_ext(p: Path) -> String {
    ext_with(&p.0, HOST)
}

/// The final element's extension of `path` under `regime`, as [`path_ext`].
fn ext_with(path: &str, regime: Regime) -> String {
    let (_, rest) = split_volume(path, regime);
    let element = rest.get(after_last_sep(rest, regime)..).unwrap_or("");
    element
        .rfind('.')
        .and_then(|i| element.get(i..))
        .unwrap_or("")
        .to_string()
}

/// `Ipe.Path.isAbsolute : Path -> Bool` — does the path need no working directory?
///
/// Unix: it begins with `/`. Windows: it is rooted AND names its volume
/// (`C:\x`, `\\srv\shr\x`); a root-relative `\x` or a drive-relative `C:x` is not.
#[must_use]
pub fn path_is_absolute(p: Path) -> bool {
    is_self_anchored(p.as_str(), HOST)
}

/// Is `p` rooted (any regime separator right after its volume prefix)?
///
/// Every separator the regime honours counts (`/` AND `\` on Windows), so a
/// raw `/x` is rooted on both. A bare Windows drive (`C:x`) is drive-relative,
/// not rooted; a lone UNC or verbatim prefix is rooted.
fn is_rooted(p: &str, regime: Regime) -> bool {
    let vol = Volume::parse(p, regime);
    let len = vol.byte_len();
    p.as_bytes().get(len).is_some_and(|&c| is_sep(c, regime))
        || (!vol.is_drive() && len > 2 && len == p.len())
}

/// Does `p` end in any separator the regime honours?
fn ends_with_sep(p: &str, regime: Regime) -> bool {
    p.as_bytes().last().is_some_and(|&c| is_sep(c, regime))
}

/// Does the cleaned `candidate` lie at or below the cleaned `root`?
///
/// Component-wise, never a bare string prefix: `/repo2/x` is NOT under
/// `/repo`. A root that already ends in a separator (`/`, `C:\`) prefixes its
/// children directly.
fn is_within(root: &str, candidate: &str, regime: Regime) -> bool {
    if root == "." {
        return !candidate
            .as_bytes()
            .first()
            .is_some_and(|&c| is_sep(c, regime))
            && !is_rooted(candidate, regime)
            && volume_name_len(candidate, regime) == 0
            && !(regime.is_windows() && first_element_has_colon(candidate))
            && !escapes_root(candidate, regime);
    }
    if candidate == root {
        return true;
    }
    candidate.strip_prefix(root).is_some_and(|rest| {
        ends_with_sep(root, regime) || rest.as_bytes().first().is_some_and(|&c| is_sep(c, regime))
    })
}

/// Does the cleaned `joined` lie STRICTLY below the cleaned `root`?
///
/// The independent post-join check: a join that names the root itself, or
/// anything outside it, is refused whatever the pre-join scans concluded.
fn strictly_beneath(root: &str, joined: &str, regime: Regime) -> bool {
    joined != root
        && is_within(root, joined, regime)
        && !(regime.is_windows()
            && (has_stripped_element(root, joined)
                || has_device_element(root, joined)
                || has_colon_element(root, joined)))
}

/// The part of `joined` below `root` (all of it for the root `.`).
fn below_root<'a>(root: &str, joined: &'a str) -> &'a str {
    if root == "." {
        joined
    } else {
        joined.strip_prefix(root).unwrap_or(joined)
    }
}

/// Does `p`'s first Windows element (up to a `\` or `/`) carry a `:`?
///
/// A raw byte scan that neither cleans nor parses a [`Volume`], so the root-`.`
/// containment check refuses a drive-designated join (`é:\x`, `1:x`) even if
/// the volume grammar ever misses a drive form Win32 honours.
fn first_element_has_colon(p: &str) -> bool {
    p.as_bytes()
        .split(|&b| is_sep(b, Regime::Windows))
        .next()
        .is_some_and(|e| e.contains(&b':'))
}

/// Does the part of the Windows `joined` below `root` hold an element Windows
/// strips to another name?
///
/// Windows strips trailing dots and spaces from every element, so an element
/// made only of them names `.` or `..` rather than a child of its own — a join
/// ending in `\ ` resolves to the root itself — and a name ending in one
/// (`a.`) opens a sibling entry (`a`): every non-empty [`ElementClass`] made
/// only of dots and spaces (`.`, `..` and both disguises) and the stripped
/// tail. Re-classifies the joined result itself, independent of the child
/// parse run before the join.
fn has_stripped_element(root: &str, joined: &str) -> bool {
    ElementClass::windows_elements(below_root(root, joined)).any(|c| {
        matches!(
            c,
            ElementClass::Current
                | ElementClass::Parent
                | ElementClass::DisguisedCurrent
                | ElementClass::DisguisedParent
                | ElementClass::StrippedTail
        )
    })
}

/// Does the part of the Windows `joined` below `root` hold a reserved DOS
/// device name?
///
/// Win32 opens the device (`CON`, `nul.txt`) rather than a file beneath the
/// root. Scans the joined result, independent of the child-element parser.
fn has_device_element(root: &str, joined: &str) -> bool {
    below_root(root, joined)
        .as_bytes()
        .split(|&b| is_sep(b, Regime::Windows))
        .any(is_dos_device)
}

/// Does the part of the Windows `joined` below `root` hold a `:`?
///
/// A `:` below the root names an alternate data stream (`a:b`) or a drive
/// designator, never a plain child. A raw byte scan of the joined result,
/// independent of the child-element parser.
fn has_colon_element(root: &str, joined: &str) -> bool {
    below_root(root, joined).as_bytes().contains(&b':')
}

/// Why `child` may not be joined beneath any root, judged on its RAW text.
///
/// Runs before any cleaning, so a `..` element or a Windows dot/space disguise
/// is refused even when cleaning would have folded it into an in-bounds form.
fn raw_child_refusal(c: &str, regime: Regime) -> Option<ChildRefusal> {
    c.as_bytes()
        .split(|&b| is_sep(b, regime))
        .find_map(|e| ChildElement::parse(e, regime).err())
        .map(ChildRefusal::Element)
        .or_else(|| {
            (is_rooted(c, regime) || volume_name_len(c, regime) > 0)
                .then_some(ChildRefusal::Absolute)
        })
}

/// Why the CLEANED `child` may not be joined, re-checking the raw verdict.
fn clean_child_refusal(c: &str, regime: Regime) -> Option<ChildRefusal> {
    if c == "." {
        Some(ChildRefusal::Empty)
    } else if is_rooted(c, regime) || volume_name_len(c, regime) > 0 {
        Some(ChildRefusal::Absolute)
    } else if escapes_root(c, regime) {
        Some(ChildRefusal::Element(ElementRefusal::Parent))
    } else {
        None
    }
}

/// Join `child` beneath `root` under a separator regime, as `Ipe.Path.under`.
///
/// Split from [`path_under`] so the Windows refusals are proven on any host.
fn under_with(r: &str, c: &str, regime: Regime) -> Result<String, PathRefusal> {
    join_beneath(JoinOp::Under, r, c, regime)
}

/// Join the parsed request path `rel` beneath the served directory `root`,
/// under the regime `rel` was parsed under.
///
/// The post-join boundary of a static-file mount: `rel` already passed the
/// per-element parse, and [`join_beneath`] re-runs the raw child scan, the
/// cleaned re-check and the strictly-beneath scans on the joined text.
///
/// # Errors
///
/// The [`PathRefusal`] of the join, naming the static file request.
#[cfg(feature = "server")]
pub(crate) fn join_rel(root: &str, rel: &RelPath) -> Result<String, PathRefusal> {
    join_beneath(JoinOp::Static, root, rel.as_str(), rel.regime())
}

/// Join `child` beneath `root` under a separator regime on behalf of `op`.
///
/// Neither input is trusted to be clean: the raw child is scanned first, then
/// both are cleaned under the regime (a raw root `""` becomes `.`), and the
/// join is always cleaned. `Err` carries the reason the join was refused,
/// naming `op`.
fn join_beneath(op: JoinOp, r: &str, c: &str, regime: Regime) -> Result<String, PathRefusal> {
    let refused = |why: ChildRefusal| {
        Err(PathRefusal::Child {
            op,
            child: c.to_string(),
            why,
        })
    };
    if has_nul(r) || has_nul(c) {
        return refused(ChildRefusal::Nul);
    }
    if c.is_empty() {
        return refused(ChildRefusal::Empty);
    }
    if let Some(why) = raw_child_refusal(c, regime) {
        return refused(why);
    }
    let cc = clean_with(c, regime);
    if let Some(why) = clean_child_refusal(&cc, regime) {
        return refused(why);
    }
    let rr = clean_with(r, regime);
    let root_vol = volume_name_len(&rr, regime);
    if root_vol > 0 && root_vol == rr.len() && !is_rooted(&rr, regime) {
        return refused(ChildRefusal::BareDriveRoot);
    }
    let joined = if rr == "." {
        cc
    } else if ends_with_sep(&rr, regime) {
        clean_with(&format!("{rr}{cc}"), regime)
    } else {
        clean_with(
            &format!("{rr}{}{cc}", char::from(regime.separator())),
            regime,
        )
    };
    // Defence in depth: the child checks above already refuse every input
    // known to land outside `rr`, so no input is known to reach this refusal;
    // it re-proves containment on the joined result independently of them.
    if !strictly_beneath(&rr, &joined, regime) {
        return Err(PathRefusal::NotBeneath {
            op,
            child: c.to_string(),
            root: rr,
        });
    }
    Ok(joined)
}

/// `Ipe.Path.under : Path -> Path -> Result Error Path` — join `child` beneath `root`.
///
/// THE typed path-composition operation: it replaces every `root ++ "/" ++ x`
/// string concatenation. Fails closed (`Err`, kind `InvalidInput`) when
/// `child` is empty (`.`), rooted or volume-prefixed (an absolute child would
/// replace the root), holds any `..` element or Windows dot/space disguise, or
/// carries a NUL byte; and, as an independent second check on the joined
/// result, when the cleaned join does not lie component-wise strictly below
/// `root`. Also refuses a bare Windows drive root (`C:`), whose join would
/// silently re-anchor a drive-relative root at the drive root.
///
/// Containment is LEXICAL: a symlink below `root` may still point outside it
/// (see the module's trust model).
#[must_use]
pub fn path_under<E: From<IpeError>>(root: Path, child: Path) -> IpeResult<E, Path> {
    match under_with(root.as_str(), child.as_str(), HOST) {
        Ok(joined) => IpeResult::Ok(Path(joined)),
        Err(why) => IpeResult::Err(why.into_error()),
    }
}

/// Is `p` anchored on its own, needing no working directory to resolve?
///
/// Unix: any rooted path. Windows: a rooted path that ALSO names its volume
/// (`C:\x`, `\\srv\shr\x`); a root-relative `\x` still depends on the current
/// drive.
fn is_self_anchored(p: &str, regime: Regime) -> bool {
    is_rooted(p, regime) && (!regime.is_windows() || volume_name_len(p, regime) > 0)
}

/// Seal `p` under `regime`, keeping the refused text in the refusal.
fn seal_as_refusal(p: &str, regime: Regime) -> Result<String, PathRefusal> {
    seal(p, regime).map_err(|why| PathRefusal::Seal {
        path: p.to_owned(),
        why,
    })
}

/// Resolve `p` against the working directory `cwd` under a separator regime.
///
/// Split from [`path_absolute`] so the refusals (a non-UTF-8 `cwd`, a
/// drive-relative `p`) and the Windows root-relative anchoring are proven on
/// any host. A self-anchored path is returned sealed; a Windows root-relative
/// `\x` is anchored on the working directory's volume; a relative path is
/// joined beneath `cwd` through [`join_beneath`], inheriting every refusal
/// under its own operation name.
fn absolute_from(cwd: &OsStr, p: &str, regime: Regime) -> Result<String, PathRefusal> {
    if is_self_anchored(p, regime) {
        return seal_as_refusal(p, regime);
    }
    let cwd = from_os_with(cwd, OsOrigin::AbsoluteCwd, regime)?;
    if is_rooted(p, regime) {
        // Windows root-relative (`\x`): rooted on the CURRENT drive, so anchor
        // it on the working directory's volume instead of returning it
        // drive-ambiguous.
        let vol = Volume::parse(&cwd, regime);
        if !vol.anchors() {
            return Err(PathRefusal::CwdNoVolume {
                cwd,
                path: p.to_string(),
            });
        }
        let prefix = cwd.get(..vol.byte_len()).unwrap_or("");
        return seal_as_refusal(&format!("{prefix}{p}"), regime);
    }
    if clean_with(p, regime) == "." {
        return Ok(cwd);
    }
    join_beneath(JoinOp::Absolute, &cwd, p, regime)
}

/// `Ipe.Path.absolute : Path -> Task Error Path` — resolve a path against the working directory.
///
/// A volume-rooted path is returned unchanged; a Windows root-relative `\x`
/// is anchored on the working directory's volume; a relative one is joined
/// beneath the process working directory through [`path_under`]'s join, so it
/// inherits every refusal. Fails closed (`InvalidInput`) on a working
/// directory that is not valid UTF-8 (never a lossy rewrite that would name a
/// different directory) or that the seal rejects. Lexical only: symlinks are
/// not resolved.
#[must_use]
pub fn path_absolute<E: Send + From<IpeError> + 'static>(p: Path) -> IpeTask<E, Path> {
    Box::pin(async move {
        let cwd = if is_self_anchored(p.as_str(), HOST) {
            PathBuf::new()
        } else {
            match std::env::current_dir() {
                Ok(d) => d,
                Err(e) => {
                    return IpeResult::Err(
                        IpeError::from(format!("Ipe.Path.absolute: {e}")).into(),
                    );
                }
            }
        };
        match absolute_from(cwd.as_os_str(), p.as_str(), HOST) {
            Ok(abs) => ok_res(Path(abs)),
            Err(why) => IpeResult::Err(why.into_error()),
        }
    })
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::super::{IpeErrorKind, ipe_error_kind};
    use super::*;

    fn mk(s: &str) -> Path {
        match path_from_string::<IpeError>(s.to_string()) {
            IpeResult::Ok(p) => p,
            IpeResult::Err(e) => panic!("expected {s:?} to be a valid Path, got Err: {e}"),
        }
    }

    /// The HOST regime's own spelling of a Unix-slashed literal.
    ///
    /// Rewrites every `/` to the HOST separator, so an expected literal
    /// matches `clean_with`'s own canonicalisation instead of hardcoding
    /// Unix's `/` on every host.
    fn host_sep(unix_spelled: &str) -> String {
        if HOST.is_windows() {
            unix_spelled.replace('/', "\\")
        } else {
            unix_spelled.to_string()
        }
    }

    /// A HOST-absolute literal for `tail`.
    ///
    /// Unix roots it with `/`; Windows anchors it with a drive, since a bare
    /// root with no volume is not self-anchored there — so no test embeds a
    /// Unix-only `/abs` literal into a host-regime judgement.
    fn host_abs(tail: &str) -> String {
        if HOST.is_windows() {
            format!("C:/{tail}")
        } else {
            format!("/{tail}")
        }
    }

    // ── construction: the seal validates ────────────────────────────────────

    #[test]
    fn empty_cleans_to_dot() {
        assert_eq!(path_to_string(mk("")), ".");
    }

    #[test]
    fn plain_relative_is_accepted() {
        assert_eq!(path_to_string(mk("src/Main.ipe")), host_sep("src/Main.ipe"));
    }

    #[test]
    fn repeated_separators_collapse() {
        assert_eq!(path_to_string(mk("a//b///c")), host_sep("a/b/c"));
    }

    #[test]
    fn interior_dotdot_that_stays_in_bounds_is_accepted() {
        // "a/b/../c" resolves to "a/c" — never climbs above the base.
        assert_eq!(path_to_string(mk("a/b/../c")), host_sep("a/c"));
    }

    #[test]
    fn rooted_dotdot_cannot_escape_and_is_accepted() {
        // `Clean` stops `..` at the root, so a rooted path is always safe.
        assert_eq!(path_to_string(mk("/a/../../b")), host_sep("/b"));
    }

    // ── construction: the seal rejects ──────────────────────────────────────

    #[test]
    fn nul_byte_is_rejected() {
        let r: IpeResult<IpeError, Path> =
            path_from_string("safe.txt\0../../etc/passwd".to_string());
        assert!(
            matches!(r, IpeResult::Err(_)),
            "a NUL byte must be rejected"
        );
    }

    #[test]
    fn leading_dotdot_escape_is_rejected() {
        let r: IpeResult<IpeError, Path> = path_from_string("../secret".to_string());
        assert!(
            matches!(r, IpeResult::Err(_)),
            "a relative path that climbs above its base must be rejected"
        );
    }

    #[test]
    fn dotdot_that_resolves_to_escape_is_rejected() {
        // "a/../../etc" cleans to "../etc" — escapes the base.
        let r: IpeResult<IpeError, Path> = path_from_string("a/../../etc".to_string());
        assert!(
            matches!(r, IpeResult::Err(_)),
            "a path whose cleaned form escapes the base must be rejected"
        );
    }

    #[test]
    fn bare_dotdot_is_rejected() {
        let r: IpeResult<IpeError, Path> = path_from_string("..".to_string());
        assert!(matches!(r, IpeResult::Err(_)), "bare `..` escapes the base");
    }

    // ── pure helpers over a validated Path ──────────────────────────────────

    #[test]
    fn base_filename() {
        assert_eq!(path_base(mk("/foo/bar.txt")), "bar.txt");
    }

    #[test]
    fn base_root() {
        assert_eq!(path_base(mk("/")), host_sep("/"));
    }

    #[test]
    fn dir_with_parent() {
        assert_eq!(path_dir(mk("/foo/bar.txt")), host_sep("/foo"));
    }

    #[test]
    fn dir_bare_name() {
        assert_eq!(path_dir(mk("hello.ipe")), ".");
    }

    #[test]
    fn ext_present() {
        assert_eq!(path_ext(mk("/foo/bar.txt")), ".txt");
    }

    #[test]
    fn ext_dotfile() {
        assert_eq!(path_ext(mk(".bashrc")), ".bashrc");
    }

    #[test]
    fn ext_multiple_dots() {
        assert_eq!(path_ext(mk("a.b.c")), ".c");
    }

    #[test]
    fn is_absolute_true() {
        assert!(path_is_absolute(mk(&host_abs("usr/bin"))));
    }

    #[test]
    fn is_absolute_false() {
        assert!(!path_is_absolute(mk("relative/path")));
    }

    // ── Windows separator set — proven on Linux via the host-independent
    //    `clean_with` / `escapes_root` under `Regime::Windows` / `volume_name_len`.
    //    Each test names the Windows bypass vector it defends. `would_seal`
    //    mirrors the Windows branch of `path_from_string` (disguise guard +
    //    clean + escape check) so the whole seal is exercised off a real
    //    Windows host. ────────────────────────────────────────────────────────

    /// True when the Windows seal would ACCEPT `s` (mirror of the Windows
    /// `path_from_string` branch, forced on for a Linux-hosted test).
    fn win_seal_accepts(s: &str) -> bool {
        seal(s, Regime::Windows).is_ok()
    }

    #[test]
    fn unix_seal_rejects_consecutive_leading_dotdot() {
        // Regression: two consecutive leading `..` must stay separated (`../..`),
        // never glue into a `....` run that `escapes_root` misses. Each of these
        // escapes the root, so the Unix seal (clean + escapes_root) must reject it.
        for s in [
            "../..",
            "../../../etc/passwd",
            "a/../../..",
            "../../..",
            "x/../../../../y",
        ] {
            let cleaned = clean_with(s, Regime::Unix);
            assert!(
                escapes_root(&cleaned, Regime::Unix),
                "unix seal must reject escaping path {s:?} (cleaned to {cleaned:?})"
            );
        }
    }

    #[test]
    fn escapes_root_rejects_leading_glued_dot_run() {
        // Defence-in-depth: `escapes_root` rejects a leading all-dots element of
        // length >= 2 DIRECTLY, so a glued `...`/`....` a broken cleaner might
        // ever emit is caught independently of the cleaner. Exact `..` still
        // rejects; a real filename with dots plus other chars (`..foo`) does not.
        for regime in [Regime::Unix, Regime::Windows] {
            for escape in ["..", "...", "....", ".../x", "..../x"] {
                assert!(
                    escapes_root(escape, regime),
                    "leading all-dots element must escape ({escape:?}, {regime:?})"
                );
            }
            for keep in ["..foo", "..foo/bar", "a/b"] {
                assert!(
                    !escapes_root(keep, regime),
                    "dotted filename / in-bounds path must NOT escape ({keep:?}, {regime:?})"
                );
            }
        }
    }

    #[test]
    fn unix_clean_dotdot_corpus() {
        // `clean_with` Unix-regime correctness for dotdot traversal paths.
        for (input, want) in [
            ("../..", "../.."),
            ("../../../etc/passwd", "../../../etc/passwd"),
            ("a/../../..", "../.."),
            ("./../a", "../a"),
            ("a/b/../../../c", "../c"),
        ] {
            assert_eq!(
                clean_with(input, Regime::Unix),
                want,
                "clean drift for {input:?}"
            );
        }
    }

    #[test]
    fn win_backslash_traversal_is_rejected() {
        // Vector: `..\` — a backslash-separated parent climb Unix would miss.
        assert!(!win_seal_accepts("..\\secret"), "`..\\` must be rejected");
    }

    #[test]
    fn win_mixed_separator_traversal_is_rejected() {
        // Vector: `../..\` — separators mixed to slip one style past the scan.
        assert!(
            !win_seal_accepts("a/../..\\etc"),
            "mixed `../..\\` climbing out must be rejected"
        );
    }

    #[test]
    fn win_drive_relative_dotdot_is_rejected() {
        // Vector: `C:..\` — a drive-RELATIVE (not rooted) `..` climb. `C:` is a
        // bare volume, so the remainder is relative and its `..` escapes.
        assert!(
            !win_seal_accepts("C:..\\Windows"),
            "drive-relative `C:..\\` must be rejected"
        );
    }

    #[test]
    fn win_unc_root_is_not_escapable() {
        // Vector: `\\server\share\..\..\x` — `..` must not climb out of the UNC
        // share; it stays pinned at the volume and cleans in-bounds.
        let cleaned = clean_with("\\\\server\\share\\..\\..\\x", Regime::Windows);
        assert_eq!(cleaned, "\\\\server\\share\\x");
        assert!(
            !escapes_root(&cleaned, Regime::Windows),
            "UNC root must not be escapable"
        );
    }

    #[test]
    fn win_drive_absolute_dotdot_stops_at_root() {
        // A ROOTED drive path (`C:\`) stops `..` at the drive root, like Unix.
        let cleaned = clean_with("C:\\a\\..\\..\\b", Regime::Windows);
        assert_eq!(cleaned, "C:\\b");
        assert!(!escapes_root(&cleaned, Regime::Windows));
    }

    #[test]
    fn win_trailing_dot_space_disguised_dotdot_is_rejected() {
        // Vector: `.. ` / `...` — Windows strips trailing dots/spaces, turning a
        // literal element back into the `..` parent token the scan would miss.
        let disguised =
            |s: &str| ElementClass::windows_elements(s).any(|c| c == ElementClass::DisguisedParent);
        assert!(disguised("a\\.. \\b"), "`.. ` disguise");
        assert!(disguised("a\\...\\b"), "`...` disguise");
        assert!(!win_seal_accepts("a\\.. \\secret"));
        assert!(!win_seal_accepts("foo/.../bar"));
    }

    #[test]
    fn win_plain_dotdot_element_is_not_treated_as_a_disguise() {
        // The exact `..` token is handled by the normal scan, not the disguise
        // guard — so an in-bounds `a\..\b` still resolves rather than false-firing.
        assert!(
            !ElementClass::windows_elements("a\\..\\b").any(|c| c == ElementClass::DisguisedParent)
        );
        assert_eq!(clean_with("a\\..\\b", Regime::Windows), "b");
        assert!(win_seal_accepts("a\\..\\b"));
    }

    #[test]
    fn win_legitimate_path_cleans_and_normalises_separators() {
        // A real Windows path: mixed separators normalise, `.`/dup-sep collapse.
        assert_eq!(
            clean_with("C:\\Users\\me/Documents\\.\\a.ipe", Regime::Windows),
            "C:\\Users\\me\\Documents\\a.ipe"
        );
        assert!(win_seal_accepts("C:\\Users\\me\\Documents\\a.ipe"));
    }

    #[test]
    fn win_volume_name_len_recognises_drive_and_unc() {
        assert_eq!(
            volume_name_len("C:\\x", Regime::Windows),
            2,
            "drive designator"
        );
        assert_eq!(
            volume_name_len("\\\\srv\\shr\\x", Regime::Windows),
            9,
            "UNC server+share"
        );
        assert_eq!(
            volume_name_len("relative\\x", Regime::Windows),
            0,
            "no volume"
        );
        assert_eq!(
            volume_name_len("C:\\x", Regime::Unix),
            0,
            "no volume under Unix rules"
        );
    }

    #[test]
    fn win_nul_byte_still_rejected() {
        assert!(!win_seal_accepts("safe.txt\0..\\..\\Windows"));
    }

    // ── SSOT: a sealed literal carries exactly each regime's runtime seal ──
    //    `PathLitText::seal` (the compile-time gate) is built from the same
    //    `seal` the runtime's `path_from_string` applies, once per regime, so an
    //    accepted literal's form for a regime IS that regime's runtime seal, and
    //    a refused literal is refused by the runtime seal of the regime it names.

    /// A corpus over `{a . / \ : NUL C 1 space}` up to length 4 — every byte
    /// that participates in a separator, a `.`/`..` element, a drive prefix, a
    /// NUL truncation, or the disguise scan.
    fn corpus() -> Vec<String> {
        const ALPHABET: [char; 9] = ['a', '.', '/', '\\', ':', '\0', 'C', '1', ' '];
        let mut out = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for c in ALPHABET {
                    let mut s = prefix.clone();
                    s.push(c);
                    next.push(s);
                }
            }
            out.extend(next.iter().cloned());
            frontier = next;
        }
        out
    }

    #[test]
    fn literal_forms_are_each_regimes_runtime_seal() {
        use super::super::path_core::PathLitText;
        for s in corpus() {
            match PathLitText::seal(&s) {
                Ok(text) => {
                    for regime in [Regime::Unix, Regime::Windows] {
                        assert_eq!(
                            seal(&s, regime).as_deref(),
                            Ok(text.sealed(regime)),
                            "literal {s:?} drifted from the {regime:?} runtime seal"
                        );
                    }
                }
                Err(refusal) => assert_eq!(
                    seal(&s, refusal.regime),
                    Err(refusal.why.clone()),
                    "literal {s:?} refused for a reason the {:?} runtime seal does not give",
                    refusal.regime
                ),
            }
        }
    }

    #[test]
    fn compile_time_gate_rejects_the_windows_traversal_vectors() {
        // Each is a Unix-clean no-op yet a traversal on a Windows target, so the
        // all-targets compile-time gate must refuse every one.
        for vector in ["..\\secret", "C:..\\x", ".. \\x", "...", "a\\..\\..\\b"] {
            assert!(
                super::super::path_core::PathLitText::seal(vector).is_err(),
                "compile-time gate must reject the Windows traversal vector {vector:?}"
            );
        }
    }

    #[test]
    fn host_seal_is_the_host_regime_seal() {
        for s in corpus() {
            let host = match path_from_string::<IpeError>(s.clone()) {
                IpeResult::Ok(p) => Some(path_to_string(p)),
                IpeResult::Err(_) => None,
            };
            assert_eq!(host, seal(&s, HOST).ok(), "{s:?}");
        }
    }

    // ── composition: `under` joins beneath a root, refusals fail closed ─────

    /// Seal `s` into a `Path`, or `None` when the seal refuses it.
    fn sealed(s: &str) -> Option<Path> {
        match path_from_string::<IpeError>(s.to_string()) {
            IpeResult::Ok(p) => Some(p),
            IpeResult::Err(_) => None,
        }
    }

    /// `under root child` over sealed strings; `None` when a seal or the join refuses.
    fn join(root: &str, child: &str) -> Option<String> {
        let (r, c) = (sealed(root)?, sealed(child)?);
        match path_under::<IpeError>(r, c) {
            IpeResult::Ok(p) => Some(path_to_string(p)),
            IpeResult::Err(_) => None,
        }
    }

    /// The Unix-regime join over UNSEALED strings, proving the join's own
    /// refusals hold even for a value that never passed the seal.
    fn unix_raw(root: &str, child: &str) -> Option<String> {
        under_with(root, child, Regime::Unix).ok()
    }

    /// The Windows-regime join over UNSEALED strings (proven on any host).
    fn win_raw(root: &str, child: &str) -> Option<String> {
        under_with(root, child, Regime::Windows).ok()
    }

    /// Why the Windows-regime join refused `child` itself, or `None` when it
    /// joined or refused only after the join.
    fn win_child_refusal(root: &str, child: &str) -> Option<ChildRefusal> {
        match under_with(root, child, Regime::Windows) {
            Err(PathRefusal::Child { why, .. }) => Some(why),
            _ => None,
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn under_joins_a_relative_child_beneath_the_root() {
        assert_eq!(
            join("/repo", "src/Main.ipe").as_deref(),
            Some("/repo/src/Main.ipe")
        );
        assert_eq!(join("repo", "a/b").as_deref(), Some("repo/a/b"));
        assert_eq!(join(".", "a/b").as_deref(), Some("a/b"));
        assert_eq!(join("/repo", "a/./b//c").as_deref(), Some("/repo/a/b/c"));
    }

    #[cfg(not(windows))]
    #[test]
    fn under_handles_trailing_separators_on_root_and_child() {
        assert_eq!(join("/repo/", "a/").as_deref(), Some("/repo/a"));
        assert_eq!(join("/", "a").as_deref(), Some("/a"));
        assert_eq!(unix_raw("/repo/", "a").as_deref(), Some("/repo/a"));
    }

    #[test]
    fn under_refuses_a_dotdot_escape() {
        // The seal already refuses a leading-`..` child ...
        assert_eq!(join("/repo", "../etc/passwd"), None);
        // ... and the join refuses it again on its own, under both regimes.
        for child in ["../etc/passwd", "a/../../x", "..", "a/.."] {
            assert_eq!(unix_raw("/repo", child), None, "{child:?}");
            assert_eq!(win_raw("C:\\repo", child), None, "{child:?}");
        }
        assert_eq!(win_raw("C:\\repo", "a\\..\\..\\x"), None);
    }

    #[test]
    fn under_refuses_an_absolute_child() {
        assert_eq!(join("/repo", "/etc/passwd"), None);
        assert_eq!(join("/repo", "/"), None);
        assert_eq!(unix_raw("/repo", "/etc"), None);
        assert_eq!(win_raw("C:\\repo", "\\etc"), None, "rooted");
        assert_eq!(win_raw("C:\\repo", "D:\\etc"), None, "drive-absolute");
        assert_eq!(win_raw("C:\\repo", "D:etc"), None, "drive-relative");
        assert_eq!(win_raw("C:\\repo", "\\\\srv\\shr\\x"), None, "UNC");
    }

    #[test]
    fn under_refuses_an_empty_child() {
        assert_eq!(join("/repo", ""), None);
        assert_eq!(join("/repo", "."), None);
        assert_eq!(join("/repo", "a/.."), None);
        assert_eq!(unix_raw("/repo", ""), None);
        assert_eq!(win_raw("C:\\repo", "."), None);
    }

    #[test]
    fn under_refuses_a_nul_byte() {
        assert_eq!(unix_raw("/repo", "a\0b"), None);
        assert_eq!(unix_raw("/re\0po", "a"), None);
        assert_eq!(win_raw("C:\\repo", "a\0b"), None);
    }

    #[test]
    fn containment_is_component_wise_not_a_string_prefix() {
        assert!(
            !is_within("/repo", "/repo2/x", Regime::Unix),
            "prefix confusion"
        );
        assert!(
            !is_within("/repo", "/repox", Regime::Unix),
            "prefix confusion"
        );
        assert!(is_within("/repo", "/repo/x", Regime::Unix));
        assert!(is_within("/", "/x", Regime::Unix));
        assert!(!is_within(".", "/x", Regime::Unix));
        assert!(!is_within(".", "../x", Regime::Unix));
        assert!(
            !is_within("C:\\repo", "C:\\repo2\\x", Regime::Windows),
            "prefix confusion"
        );
        assert!(is_within("C:\\", "C:\\x", Regime::Windows));
        // A join never yields a sibling that merely shares the root's prefix.
        assert_eq!(unix_raw("/repo", "2/x").as_deref(), Some("/repo/2/x"));
    }

    #[test]
    fn windows_regime_joins_and_refuses_a_bare_drive_root() {
        assert_eq!(
            win_raw("C:\\repo", "a\\b").as_deref(),
            Some("C:\\repo\\a\\b")
        );
        assert_eq!(
            win_raw("C:\\repo", "a/b").as_deref(),
            Some("C:\\repo\\a\\b")
        );
        assert_eq!(win_raw("C:\\", "a").as_deref(), Some("C:\\a"));
        assert_eq!(
            win_raw("\\\\srv\\shr", "a").as_deref(),
            Some("\\\\srv\\shr\\a")
        );
        // `C:` + `a` must not silently become the drive-rooted `C:\a`.
        assert_eq!(win_raw("C:", "a"), None);
    }

    #[test]
    fn under_refusal_arrives_on_the_error_channel() {
        let r = path_under::<IpeError>(Path("/repo".to_string()), Path("/etc".to_string()));
        assert!(
            matches!(&r, IpeResult::Err(e) if e.to_string().contains("absolute")),
            "{r:?}"
        );
    }

    #[test]
    fn under_treats_every_windows_separator_as_rooting() {
        // A `/`-rooted child replaces the root on Windows too: never the drive root.
        assert_eq!(win_raw(".", "/x"), None, "escape to the drive root");
        assert_eq!(win_raw(".", "\\x"), None);
        assert_eq!(win_raw("C:\\repo", "/etc"), None, "`/` roots on Windows");
        assert_eq!(win_raw("C:\\repo", "//srv/shr/x"), None, "`/`-spelled UNC");
        assert!(is_rooted("/x", Regime::Windows) && is_rooted("\\x", Regime::Windows));
        assert!(ends_with_sep("C:/", Regime::Windows) && ends_with_sep("C:\\", Regime::Windows));
        assert!(
            !ends_with_sep("a\\", Regime::Unix),
            "`\\` is a filename byte on Unix"
        );
    }

    #[test]
    fn under_cleans_a_raw_root_before_joining() {
        // A raw empty root is `.`, never re-anchored at `/`.
        assert_eq!(unix_raw("", "a").as_deref(), Some("a"));
        assert_eq!(win_raw("", "a").as_deref(), Some("a"));
        assert_eq!(unix_raw(".", "./a/").as_deref(), Some("a"));
        assert_eq!(win_raw(".", "a/b").as_deref(), Some("a\\b"));
    }

    #[test]
    fn under_accepts_valid_joins_beneath_an_unclean_root() {
        assert_eq!(win_raw("C:/repo", "a").as_deref(), Some("C:\\repo\\a"));
        assert_eq!(
            win_raw("C:/repo/", "a/b").as_deref(),
            Some("C:\\repo\\a\\b")
        );
        assert_eq!(win_raw("src/a", "b").as_deref(), Some("src\\a\\b"));
        assert_eq!(unix_raw("./a", "b").as_deref(), Some("a/b"));
        assert_eq!(unix_raw("/repo//x/", "b").as_deref(), Some("/repo/x/b"));
        assert_eq!(unix_raw("src/a", "b").as_deref(), Some("src/a/b"));
    }

    #[test]
    fn under_refuses_a_windows_dot_space_disguise() {
        for child in [".. \\x", "a\\...\\x", "a/. ./x", "...", "a\\.. "] {
            assert_eq!(win_raw("C:\\repo", child), None, "{child:?}");
        }
    }

    #[test]
    fn under_refuses_verbatim_and_device_children() {
        for child in [
            "\\\\?\\C:\\x",
            "\\\\.\\x",
            "//?/C:/x",
            "\\\\.\\PhysicalDrive0",
        ] {
            assert_eq!(win_raw("C:\\repo", child), None, "{child:?}");
        }
    }

    #[test]
    fn under_refuses_a_join_that_names_the_root_itself() {
        assert_eq!(unix_raw("/repo", "./"), None);
        assert_eq!(win_raw("C:\\repo", ".\\"), None);
        // The post-join check refuses the root itself and any sibling on its own.
        assert!(!strictly_beneath("/repo", "/repo", Regime::Unix));
        assert!(!strictly_beneath("/repo", "/repo2", Regime::Unix));
        assert!(!strictly_beneath("C:\\repo", "C:\\repo", Regime::Windows));
        assert!(strictly_beneath("/repo", "/repo/a", Regime::Unix));
    }

    // ── `absolute` resolves against the working directory ──────────────────

    /// Poll a ready-at-first-poll `IpeTask` once, without an executor.
    fn run_now<A>(mut t: IpeTask<IpeError, A>) -> Option<IpeResult<IpeError, A>> {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match t.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(r) => Some(r),
            std::task::Poll::Pending => None,
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn absolute_keeps_a_rooted_path_and_roots_a_relative_one() {
        let rooted = sealed("/etc/x").map(|p| run_now(path_absolute::<IpeError>(p)));
        assert!(
            matches!(&rooted, Some(Some(IpeResult::Ok(p))) if p.as_str() == "/etc/x"),
            "{rooted:?}"
        );
        let rel = sealed("a/b").map(|p| run_now(path_absolute::<IpeError>(p)));
        assert!(
            matches!(&rel, Some(Some(IpeResult::Ok(p)))
                if is_rooted(p.as_str(), HOST) && p.as_str().ends_with("/a/b")),
            "{rel:?}"
        );
        let dot = sealed(".").map(|p| run_now(path_absolute::<IpeError>(p)));
        assert!(
            matches!(&dot, Some(Some(IpeResult::Ok(p))) if is_rooted(p.as_str(), HOST)),
            "{dot:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn absolute_refuses_a_non_utf8_working_directory() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let cwd = OsString::from_vec(vec![0xff]);
        let r = absolute_from(&cwd, "a", Regime::Unix).map_err(|e| e.to_string());
        assert_eq!(
            r,
            Err(
                "Ipe.Path.absolute: the working directory \"\\xFF\" is not valid UTF-8".to_string()
            )
        );
    }

    #[test]
    fn absolute_resolves_under_both_regimes() {
        let unix = |p: &str| absolute_from(OsStr::new("/work"), p, Regime::Unix);
        assert_eq!(unix("/etc/x"), Ok("/etc/x".to_string()));
        assert_eq!(unix("a/b"), Ok("/work/a/b".to_string()));
        assert_eq!(unix("."), Ok("/work".to_string()));
        let win = |p: &str| absolute_from(OsStr::new("C:\\work"), p, Regime::Windows);
        assert_eq!(win("D:\\x"), Ok("D:\\x".to_string()));
        assert_eq!(win("a/b"), Ok("C:\\work\\a\\b".to_string()));
        // A `/`-rooted path is rooted on Windows, never joined as relative.
        assert_eq!(win("/x"), Ok("C:\\x".to_string()));
    }

    #[test]
    fn absolute_anchors_a_windows_root_relative_path_on_the_cwd_volume() {
        let at = |cwd: &str, p: &str| absolute_from(OsStr::new(cwd), p, Regime::Windows);
        assert_eq!(at("C:\\work", "\\x"), Ok("C:\\x".to_string()));
        assert_eq!(
            at("\\\\srv\\shr\\work", "\\x"),
            Ok("\\\\srv\\shr\\x".to_string())
        );
        // A cwd with no volume cannot anchor it: refused, never left ambiguous.
        assert!(at("\\work", "\\x").is_err());
    }

    #[test]
    fn absolute_refuses_a_drive_relative_or_escaping_path() {
        let win = |p: &str| absolute_from(OsStr::new("C:\\work"), p, Regime::Windows);
        assert!(win("D:x").is_err(), "drive-relative");
        assert!(win("..\\x").is_err());
        assert!(win(".. \\x").is_err(), "disguise");
        let unix = absolute_from(OsStr::new("/work"), "../x", Regime::Unix);
        assert!(unix.is_err(), "{unix:?}");
    }

    #[test]
    fn absolute_refuses_an_escaping_unsealed_child() {
        let r = run_now(path_absolute::<IpeError>(Path("../x".to_string())));
        assert!(matches!(r, Some(IpeResult::Err(_))), "{r:?}");
    }

    #[test]
    fn win_under_refuses_a_colon_or_dot_space_run_child() {
        for child in [
            "é:\\x", "1:x", "a:b", "x\\a:b", " ", ". ", "a\\. ", ".. ", "...",
        ] {
            assert_eq!(win_raw(".", child), None, "root `.` joined {child:?}");
            assert_eq!(
                win_raw("C:\\repo", child),
                None,
                "`C:\\repo` joined {child:?}"
            );
        }
        // A plain name with an inner dot or space is still a child.
        assert_eq!(
            win_raw("C:\\repo", "a b\\c.d").as_deref(),
            Some("C:\\repo\\a b\\c.d")
        );
    }

    #[test]
    fn win_containment_post_checks_hold_without_the_child_parse() {
        // The root-`.` check refuses a drive-designated candidate on its own.
        assert!(!is_within(".", "é:\\x", Regime::Windows));
        assert!(!is_within(".", "1:x", Regime::Windows));
        // Drive designators the volume parser never names: a non-BMP letter
        // and a multi-letter prefix (an alternate data stream).
        assert!(!is_within(".", "𝒳:x", Regime::Windows));
        assert!(!is_within(".", "ab:c", Regime::Windows));
        // A leading separator is refused by its raw first byte alone.
        assert!(!is_within(".", "/x", Regime::Unix));
        assert!(!is_within(".", "\\x", Regime::Windows));
        assert!(!is_within(".", "/x", Regime::Windows));
        assert!(is_within(".", "x", Regime::Windows));
        // A reserved device element below the root is refused on its own.
        assert!(!strictly_beneath(
            "C:\\repo",
            "C:\\repo\\a\\CON",
            Regime::Windows
        ));
        assert!(!strictly_beneath(".", "nul.txt", Regime::Windows));
        assert!(strictly_beneath(
            "C:\\repo",
            "C:\\repo\\CONSOLE",
            Regime::Windows
        ));
        // A trailing dot/space-only element names the root, never beneath it.
        assert!(!strictly_beneath(
            "C:\\repo",
            "C:\\repo\\ ",
            Regime::Windows
        ));
        assert!(!strictly_beneath(".", ". ", Regime::Windows));
        // A `:` below a non-`.` root (a stream or a drive) is refused on its own.
        assert!(!strictly_beneath(
            "C:\\repo",
            "C:\\repo\\a:b",
            Regime::Windows
        ));
        assert!(!strictly_beneath(
            "C:\\repo",
            "C:\\repo\\x\\f.txt:s",
            Regime::Windows
        ));
        assert!(!strictly_beneath(".", "x\\a:b", Regime::Windows));
        assert!(strictly_beneath("C:\\repo", "C:\\repo\\a", Regime::Windows));
        // The Unix regime has no streams: a `:` is a plain name byte.
        assert!(strictly_beneath("/repo", "/repo/a:b", Regime::Unix));
        // A lone non-ASCII drive is drive-relative, never a rooted root.
        assert!(!is_rooted("é:", Regime::Windows));
    }

    #[test]
    fn win_under_refuses_a_dos_device_child() {
        for child in [
            "CON",
            "con.txt",
            "NUL ",
            "COM1",
            "COM\u{b9}",
            "CONOUT$",
            "aux.tar.gz",
            "a\\CON",
            "CON.",
            "CON .txt",
            "LPT0",
            "CONIN$",
            "lpt\u{b9}",
            "CON\u{131}N$",
            "con\u{131}n$",
            "CON\u{131}N$.txt",
            "a\\COM1",
            "LPT9.log",
            "nul.txt",
        ] {
            for root in [".", "C:\\uploads"] {
                assert_eq!(
                    win_child_refusal(root, child),
                    Some(ChildRefusal::Element(ElementRefusal::DosDevice)),
                    "{root:?} joined {child:?}"
                );
            }
        }
        for child in ["CONSOLE", "COM10", "nulx"] {
            assert_eq!(
                win_raw("C:\\uploads", child),
                Some(format!("C:\\uploads\\{child}")),
                "{child:?}"
            );
        }
        // Device names are a Win32 namespace; the Unix regime joins them.
        assert_eq!(unix_raw("/repo", "CON").as_deref(), Some("/repo/CON"));
    }

    #[test]
    fn win_under_refuses_a_stripped_tail_child() {
        for child in ["a.", "a ", "d\\a.", "a.txt."] {
            for root in [".", "C:\\uploads"] {
                assert_eq!(
                    win_child_refusal(root, child),
                    Some(ChildRefusal::Element(ElementRefusal::StrippedTail)),
                    "{root:?} joined {child:?}"
                );
            }
        }
        // The post-join scan refuses the stripped tail on its own.
        assert!(!strictly_beneath(".", "a.", Regime::Windows));
        assert!(!strictly_beneath(
            "C:\\uploads",
            "C:\\uploads\\d\\a ",
            Regime::Windows
        ));
        assert!(strictly_beneath(
            "C:\\uploads",
            "C:\\uploads\\d\\a.b",
            Regime::Windows
        ));
        // A trailing dot is a legal Unix name.
        assert_eq!(unix_raw("/repo", "a.").as_deref(), Some("/repo/a."));
    }

    #[test]
    fn walk_join_refuses_a_stripped_tail_entry_on_windows() {
        assert_eq!(
            join_beneath(JoinOp::Walk, "dir", "a.", Regime::Windows),
            Err(PathRefusal::Child {
                op: JoinOp::Walk,
                child: "a.".to_string(),
                why: ChildRefusal::Element(ElementRefusal::StrippedTail),
            })
        );
    }

    #[cfg(feature = "server")]
    #[test]
    fn join_rel_joins_under_the_regime_the_path_was_parsed_under() {
        let win = RelPath::from_segments(["a", "b.css"], Regime::Windows).expect("windows rel");
        assert_eq!(
            join_rel("C:\\site", &win).as_deref(),
            Ok("C:\\site\\a\\b.css")
        );
        // A Unix name holding `\` stays one element under the Unix regime.
        let unix = RelPath::from_segments(["a\\b"], Regime::Unix).expect("unix rel");
        assert_eq!(
            join_rel("/srv/site", &unix).as_deref(),
            Ok("/srv/site/a\\b")
        );
    }

    #[test]
    fn child_parse_and_rel_path_agree() {
        use super::super::path_core::{RelPath, RelPathRefusal};
        for regime in [Regime::Unix, Regime::Windows] {
            for e in corpus() {
                if e.bytes().any(|b| is_sep(b, regime)) || has_nul(&e) {
                    continue;
                }
                let parsed = ChildElement::parse(e.as_bytes(), regime);
                let rel = RelPath::from_segments([e.as_str()], regime);
                assert_eq!(
                    rel.is_ok(),
                    parsed == Ok(ChildElement::Name),
                    "{e:?} under {regime:?}"
                );
                if let Err(why) = parsed {
                    assert_eq!(
                        rel,
                        Err(RelPathRefusal::Element(why)),
                        "{e:?} under {regime:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn child_parse_and_device_scan_agree_with_the_shared_classifier() {
        for e in [
            "",
            ".",
            "..",
            "...",
            ". ",
            " ",
            "a",
            "a.",
            "a:b",
            "CON",
            "nul.txt",
            "COM\u{b9}",
            "COM10",
        ] {
            let class = ElementClass::of(e.as_bytes());
            assert_eq!(
                ChildElement::parse(e.as_bytes(), Regime::Windows)
                    == Err(ElementRefusal::DosDevice),
                class == ElementClass::DosDevice,
                "{e:?}"
            );
            assert_eq!(
                is_dos_device(e.as_bytes()),
                class == ElementClass::DosDevice,
                "{e:?}"
            );
        }
    }

    #[test]
    fn refusals_render_their_boundary_text() {
        assert_eq!(
            PathRefusal::Seal {
                path: "a\0b".to_string(),
                why: SealRefusal::Nul
            }
            .to_string(),
            "Ipe.Path: path contains a NUL byte (a syscall-boundary truncation / traversal risk)"
        );
        assert_eq!(
            under_with("C:\\uploads", "CON", Regime::Windows)
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some(
                "Ipe.Path.under: child path \"CON\" contains a reserved Windows device name \
                 (`CON`, `NUL`, `COM1`, ...) that opens a device"
            )
        );
        assert_eq!(
            under_with("/repo", "../x", Regime::Unix)
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some("Ipe.Path.under: child path \"../x\" contains a `..` element")
        );
        // A relative path joined by `absolute` names `absolute`, not `under`.
        assert_eq!(
            absolute_from(OsStr::new("/work"), "../x", Regime::Unix)
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some("Ipe.Path.absolute: child path \"../x\" contains a `..` element")
        );
        assert_eq!(
            absolute_from(OsStr::new("C:\\work"), "CON", Regime::Windows)
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some(
                "Ipe.Path.absolute: child path \"CON\" contains a reserved Windows device name \
                 (`CON`, `NUL`, `COM1`, ...) that opens a device"
            )
        );
        // The post-join containment refusal names its operation too; no input
        // is known to reach it past the child checks, so its text is pinned here.
        assert_eq!(
            PathRefusal::NotBeneath {
                op: JoinOp::Absolute,
                child: "x".to_string(),
                root: "/work".to_string(),
            }
            .to_string(),
            "Ipe.Path.absolute: \"x\" does not resolve beneath the root \"/work\""
        );
        assert_eq!(
            seal_as_refusal("../x", Regime::Unix)
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some(
                "Ipe.Path: path escapes its root via `..` traversal: \"../x\" (cleaned: \"../x\")"
            )
        );
    }

    #[test]
    fn absolute_anchors_on_a_verbatim_unc_share_and_refuses_a_device_unc() {
        let at = |cwd: &str, p: &str| absolute_from(OsStr::new(cwd), p, Regime::Windows);
        assert_eq!(
            at("\\\\?\\UNC\\srv\\shr\\work", "\\x"),
            Ok("\\\\?\\UNC\\srv\\shr\\x".to_string())
        );
        assert!(at("\\\\.\\UNC\\srv\\shr\\work", "\\x").is_err());
        assert!(at("\\\\srv", "\\x").is_err(), "UNC with no share");
    }

    // ── host-regime helpers: volume-aware `base` / `dir` / `ext` / `isAbsolute` ──

    #[test]
    fn is_absolute_needs_a_volume_under_windows() {
        assert!(is_self_anchored("C:\\x", Regime::Windows));
        assert!(is_self_anchored("\\\\srv\\shr\\x", Regime::Windows));
        assert!(!is_self_anchored("\\x", Regime::Windows), "root-relative");
        assert!(!is_self_anchored("C:x", Regime::Windows), "drive-relative");
        assert!(is_self_anchored("/x", Regime::Unix));
        assert!(!is_self_anchored("C:\\x", Regime::Unix));
    }

    #[test]
    fn dir_keeps_the_volume() {
        assert_eq!(dir_with("C:x", Regime::Windows), "C:");
        assert_eq!(dir_with("C:\\a\\b", Regime::Windows), "C:\\a");
        assert_eq!(dir_with("C:\\a", Regime::Windows), "C:\\");
        assert_eq!(
            dir_with("\\\\srv\\shr\\a", Regime::Windows),
            "\\\\srv\\shr\\"
        );
        assert_eq!(dir_with("a\\b", Regime::Windows), "a");
        assert_eq!(dir_with("/foo/bar", Regime::Unix), "/foo");
        assert_eq!(dir_with("a\\b", Regime::Unix), ".");
        assert_eq!(dir_with("/", Regime::Unix), "/");
        assert_eq!(dir_with("", Regime::Unix), ".");
    }

    #[test]
    fn base_never_invents_a_unix_root_under_windows() {
        assert_ne!(base_with("\\\\", Regime::Windows), "/");
        assert_eq!(base_with("C:\\", Regime::Windows), "C:\\");
        assert_eq!(base_with("C:\\a\\b.txt", Regime::Windows), "b.txt");
        assert_eq!(base_with("C:b.txt", Regime::Windows), "b.txt");
        assert_eq!(base_with("a\\b", Regime::Windows), "b");
        assert_eq!(base_with("a\\b", Regime::Unix), "a\\b");
        assert_eq!(base_with("//", Regime::Unix), "/");
        assert_eq!(base_with("", Regime::Unix), ".");
    }

    #[test]
    fn ext_reads_only_the_final_element() {
        assert_eq!(ext_with("C:\\a.d\\b", Regime::Windows), "");
        assert_eq!(ext_with("C:\\a\\b.txt", Regime::Windows), ".txt");
        assert_eq!(ext_with("a.d\\b", Regime::Unix), ".d\\b");
        assert_eq!(ext_with("a.d/b", Regime::Unix), "");
    }

    // ── OS-produced text: refused, never rewritten lossily ──────────────────

    #[cfg(unix)]
    #[test]
    fn os_text_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStrExt;
        let bad = OsStr::from_bytes(b"a\xff");
        assert_eq!(
            from_os_with(bad, OsOrigin::TempFile, Regime::Unix),
            Err(PathRefusal::NotUtf8 {
                origin: OsOrigin::TempFile,
                text: bad.to_owned(),
            })
        );
        let name = name_from_os(bad, OsOrigin::ReadDir);
        assert!(
            name.is_err_and(|e| ipe_error_kind(e) == IpeErrorKind::InvalidInput),
            "a non-UTF-8 entry name is an input refusal"
        );
    }

    #[test]
    fn os_text_still_passes_the_seal() {
        assert_eq!(
            from_os_with(OsStr::new("a/../../x"), OsOrigin::SystemCwd, Regime::Unix),
            Err(PathRefusal::Seal {
                path: "a/../../x".to_string(),
                why: SealRefusal::Escape {
                    cleaned: "../x".to_string()
                },
            })
        );
        assert_eq!(
            from_os_with(OsStr::new("/w//x/"), OsOrigin::SystemCwd, Regime::Unix),
            Ok("/w/x".to_string())
        );
    }

    #[test]
    fn walk_join_refuses_an_escaping_entry_name() {
        let root = mk("dir");
        assert!(
            join_entry(&root, "..").is_err_and(|e| ipe_error_kind(e) == IpeErrorKind::InvalidInput)
        );
        assert_eq!(
            join_beneath(JoinOp::Walk, "dir", "..", Regime::Unix)
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some("Ipe.File.walk: child path \"..\" contains a `..` element")
        );
        assert_eq!(
            join_entry(&mk("."), "name")
                .map(path_to_string)
                .ok()
                .as_deref(),
            Some("name")
        );
    }

    #[test]
    fn refusals_reach_the_caller_as_invalid_input() {
        let seal_refused = path_from_string::<IpeError>("../x".to_string());
        assert!(matches!(
            seal_refused,
            IpeResult::Err(IpeError::Error(IpeErrorKind::InvalidInput, _))
        ));
        let join_refused = path_under::<IpeError>(mk("/repo"), Path("/etc".to_string()));
        assert!(matches!(
            join_refused,
            IpeResult::Err(IpeError::Error(IpeErrorKind::InvalidInput, _))
        ));
    }

    /// The production half of a runtime source file (before its test module).
    fn production(src: &str) -> &str {
        src.split(concat!("#[cfg(", "test)]")).next().unwrap_or(src)
    }

    #[test]
    fn path_producing_kernels_never_decode_lossily_nor_bypass_the_seal() {
        let lossy = concat!("to_string", "_lossy");
        let bypass = concat!("path_", "literal(");
        for (name, src) in [
            ("path.rs", include_str!("path.rs")),
            ("file.rs", include_str!("file.rs")),
            ("system.rs", include_str!("system.rs")),
        ] {
            let prod = production(src);
            assert!(!prod.contains(lossy), "{name} decodes an OS path lossily");
            assert!(
                !prod.contains(bypass),
                "{name} builds a Path without the seal"
            );
        }
    }
}
