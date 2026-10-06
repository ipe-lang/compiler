//! The on-disk build cache.
//!
//! Decision record: `docs/adr/0007-build-incrementality-and-release-infra.md`.
//!
//! Everything in-process is memoized, but nothing survives ACROSS process
//! invocations — every `ipe dev build` starts a cold [`ipe_db::IpeDatabase`].
//! This module closes that gap for the coarse, whole-project granularity
//! that genuinely exists (`ipe_db::emit_project`'s output — see this
//! module's own doc section below for why that is a deliberate, documented
//! divergence from the design doc's literal "persist per-module lowered IR"
//! wording).
//!
//! ## What is cached, and why not literally "lowered IR"
//!
//! The design doc's Option-B locks in persisting `ipe_ir` (the lowered IR)
//! to `.ipe/lowered/`. `ipe_lower::lower` always produces exactly ONE
//! whole-program [`ipe_ir::Program`], so "per module" was never on the
//! table. The DEEPER blocker for persisting `ipe_ir::Program` itself,
//! specifically:
//! every [`ipe_intern::Symbol`] embedded in the IR (`Var`, `Ctor`, record
//! field names, `IrType::Generic`, …) is a raw index into THIS process's
//! [`ipe_intern::Interner`] — meaningless, and NOT merely "differently
//! numbered", in a fresh process with a fresh, empty interner. Making that
//! sound requires a relocation pass: serialize every embedded `Symbol` as
//! its resolved STRING, and on load, re-intern each string into the
//! CURRENT process's interner and rewrite every `Symbol` occurrence to the
//! newly-assigned id — a walker over every `Symbol`-carrying site in
//! `ipe_ir::ir` (far more sites than [`ipe_db::program_metadata`]'s
//! `Ctor`-only walk touches: `Var`, `CloneVar`, `Access`, record field
//! keys, `FuncSig` params/generics, `EnumDef`/`TypeDef` fields, …) plus
//! full `serde` coverage across ~20 IR types. That is a genuine, multi-
//! session redesign, not a corner to cut.
//!
//! **What ships instead**: [`ipe_backend::EmittedProject`] — the output of
//! [`ipe_db::emit_project`] — is cached. It is pure `String` data (no
//! `Symbol`, no interner dependency whatsoever: `RelPath` wraps a `String`,
//! `files` maps `RelPath -> String`, `cargo_toml` is a `String`), so it
//! serializes and deserializes losslessly with zero cross-process identity
//! risk. The practical win is AT LEAST as large as literal IR caching would
//! give for `ipe dev build`'s actual use case (a cold-start cache hit skips
//! parse -> canon -> link -> infer -> lower -> emit ENTIRELY, not just
//! infer -> lower -> emit), at the cost of not serving a hypothetical
//! future interpreter tier that wants to consume `ipe_ir` directly (design
//! doc §"Why `ipe_ir` is the cut-point") — that tier does not exist yet,
//! so the cost is paid by nobody today. This divergence is deliberate and
//! recorded here, not silently substituted.
//!
//! ## Content address (the cache KEY)
//!
//! [`compute_project_key`] hashes, with explicit length-prefixed framing
//! (never delimiter-joined — a delimiter that can appear inside a module
//! segment or source text would make two distinct projects collide) so
//! there is no ambiguity between e.g. `[["AB"], ["C"]]` and `[["A"], ["BC"]]`:
//!
//! - the entry module path,
//! - the SQL driver ([`ipe_backend_rust::DbDriver`]),
//! - every in-scope module's path, trust origin (injected stdlib vs. user
//!   source — the module-IDENTITY axis the design doc's cache-key-
//!   completeness note calls out: an add/delete/rename of a module MUST
//!   yield a different key, never a stale hit), and full source text,
//! - every emit-shape build flag (target, production, `--debugger`,
//!   hot-appearance, the webview host and window).
//!
//! `blame_path` (diagnostic-only) and the vendored runtime tree are
//! deliberately NOT part of the key: neither affects [`EmittedProject`]'s
//! content (blame only shapes error rendering on a FAILED compile, which is
//! never cached; the runtime tree is copied by `write_emitted_project`
//! independently of the cache, exactly as it always was).
//!
//! ## Version epoch (toolchain refuse-don't-guess)
//!
//! [`derive_epoch`] hashes the CURRENTLY RUNNING `ipe` binary's own bytes
//! (`compiler_revision()`, matching the design doc's row verbatim: "content
//! hash seeded from the `ipe` binary's own build hash") together with the
//! active `rustc`'s `-vV` output (`toolchain_fingerprint()`). The epoch is a
//! DIRECTORY PREFIX (`<cache_root>/<epoch>/<key>.json`), not a value
//! compared after a hit — so "refuse, don't guess" is achieved BY
//! CONSTRUCTION, the same mechanism the design doc's FFI cache uses ("stale
//! entry has a different address -> unreachable miss", H1/H4 in the hazard
//! ledger): a `cargo build`/`cargo install` of `ipe` OR a `rustup update`
//! moves every subsequent build to a DIFFERENT directory, so entries from
//! the old compiler/toolchain pairing are never even looked up, let alone
//! trusted. There is nothing to "refuse" at lookup time because the stale
//! entries are structurally unreachable.
//!
//! Either probe failing (no `current_exe`, no `rustc` on `PATH`) disables
//! the cache for that invocation ([`derive_epoch`] returns `None`) — never a
//! guess, never a build failure: a compile just runs uncached, exactly as
//! every build did before this module existed.
//!
//! **Not yet ported**: `ipe dev watch`'s specific mid-session UX (hard-refuse a
//! REBUILD with `toolchain changed (was A, now B) — restart 'ipe dev watch'`
//! while keeping the last-good binary alive) needs a live watch session to
//! refuse INTO. The sound foundation that UX builds on is the version-epoch
//! gate itself.
//!
//! ## Advisory semantics (never a build failure)
//!
//! Every cache operation is best-effort: a missing directory, a corrupt
//! entry, or a write failure (permissions, full disk) is treated as "cache
//! unavailable for this build" and silently falls through to a full
//! compile — matching the design doc's own "Entries are advisory: hash
//! miss -> recompute, corrupt entry -> discard." A cache-write failure
//! after a SUCCESSFUL compile must never turn that success into a reported
//! build failure.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ipe_backend::EmittedProject;
use ipe_backend_rust::DbDriver;
use ipe_fs_open::{ByteCap, EntryCap, EntryName, FileKind, HeldDir, OpenRefusal, RegularFile};
use ipe_intern::{Interner, SerdeInternerGuard};
use ipe_ir::Program;

use crate::output_dir::OwnedDir;
use crate::remote_ingest::{IngestLimit, LocalRefusal, LocalSource, PACKAGE_SOURCE, TreeCeiling};
use crate::secret_file::OwnerDir;
use crate::toolchain::RustcVersion;
use sha2::{Digest, Sha256};

/// Domain-separation tag for the content-address hash — bumped whenever the
/// key's ingredient set changes shape (never for a value change within the
/// same shape; that is what the hash itself captures).
const KEY_TAG: &[u8] = b"ipec-build-cache-key-v2";

/// Domain-separation tag for the version-epoch hash.
const EPOCH_TAG: &[u8] = b"ipec-build-cache-epoch-v1";

/// Hash `bytes` into `hasher` with an explicit little-endian length prefix,
/// so two distinct inputs can never concatenate into the same byte stream
/// (the classic delimiter-collision hazard: `["AB", "C"]` vs `["A", "BC"]`
/// must hash differently, and would if segments were simply joined).
fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

fn update_str(hasher: &mut Sha256, s: &str) {
    update_len_prefixed(hasher, s.as_bytes());
}

/// Domain-separation tag for the source-tree content hash — the integrity check
/// a resolved package is verified against (`crate::resolve`).
const TREE_TAG: &[u8] = b"ipe-source-tree-v1";

/// The fixed chunk size the file bytes are streamed into the hasher in, so a
/// file's contribution never buffers more than one chunk at a time.
const TREE_HASH_CHUNK_BYTES: usize = 64 * 1024;

/// Why a source tree could not be hashed.
#[derive(Debug)]
pub enum TreeHashError {
    /// An entry could not be walked or read.
    Io {
        /// The failing entry.
        path: PathBuf,
        /// What went wrong reading it.
        source: std::io::Error,
    },
    /// The tree crosses a package-source ceiling or holds an entry of a refused shape.
    Exceeded(LocalRefusal),
}

impl From<TreeHashError> for crate::CliError {
    fn from(err: TreeHashError) -> Self {
        match err {
            TreeHashError::Io { path, source } => Self::Io { path, source },
            TreeHashError::Exceeded(refusal) => Self::LocalLimitExceeded(refusal),
        }
    }
}

impl std::fmt::Display for TreeHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Exceeded(refusal) => refusal.fmt(f),
        }
    }
}

/// A path relative to the hashed tree's root, parsed once as it is walked.
///
/// Forward-slash separated so the hash is identical across platforms; every
/// component is valid UTF-8, non-empty, and neither `.` nor `..`, so two
/// distinct trees never name a file alike.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TreePath(String);

impl TreePath {
    /// The tree's root, which names no file itself.
    const fn root() -> Self {
        Self(String::new())
    }

    /// `name`, the entry inside the directory this path names.
    ///
    /// A name that is not UTF-8 is refused as [`IngestLimit::NonUtf8Name`].
    /// [`EntryName`] already holds the single-component rule (never empty,
    /// `.` or `..`, never holding a separator or NUL).
    fn child(&self, name: &EntryName) -> Result<Self, TreeHashError> {
        let Some(name) = name.as_os_str().to_str() else {
            return Err(tree_exceeded(IngestLimit::NonUtf8Name));
        };
        if self.0.is_empty() {
            return Ok(Self(name.to_owned()));
        }
        let mut joined = String::with_capacity(self.0.len() + 1 + name.len());
        joined.push_str(&self.0);
        joined.push('/');
        joined.push_str(name);
        Ok(Self(joined))
    }

    /// Whether the last component is hidden (dot-prefixed).
    fn is_hidden(&self) -> bool {
        self.0
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with('.'))
    }

    const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Wrap an I/O failure on `path` as a [`TreeHashError::Io`].
fn tree_io(path: &Path, source: std::io::Error) -> TreeHashError {
    TreeHashError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// The refusal of a tree past one of its package-source ceilings.
const fn tree_exceeded(limit: IngestLimit) -> TreeHashError {
    TreeHashError::Exceeded(LocalRefusal {
        source: LocalSource::PackageTree,
        limit,
        name: None,
    })
}

/// Compute a sha256 over the content of the directory tree rooted at `root`,
/// deterministically over `(relative_path, file_bytes)` pairs sorted by path.
///
/// This is the content integrity check a fetched package is verified against:
/// the hash the index pins equals `hash_tree` over the source the publisher
/// registered, so a mismatch means the fetched bytes are not that source. The
/// `.git` directory is excluded so the hash is of the source tree itself, not of
/// git's own bookkeeping (which varies across clones of the same revision). Each
/// path and its bytes are length-prefixed, so no rearrangement of files can
/// collide (the delimiter-collision hazard, as in [`update_len_prefixed`]).
///
/// The walk is held to the tree ceiling of [`PACKAGE_SOURCE`]: a tree past its
/// entries, cumulative bytes, per-file bytes or depth is refused before it is
/// read further, as is a symlink, a special file or a name that is not UTF-8.
///
/// # Errors
/// [`TreeHashError::Io`] with the failing path when the tree cannot be walked
/// or a file cannot be read; [`TreeHashError::Exceeded`] past a tree ceiling
/// or on a refused entry.
pub fn hash_tree(root: &Path) -> Result<String, TreeHashError> {
    hash_tree_within(root, PACKAGE_SOURCE.tree())
}

/// [`hash_tree`] under an explicit tree ceiling.
///
/// # Errors
/// As [`hash_tree`].
pub fn hash_tree_within(root: &Path, ceiling: &TreeCeiling) -> Result<String, TreeHashError> {
    Ok(hex::encode(tree_hasher_within(root, ceiling)?.finalize()))
}

/// The content hash of one source tree, from exactly one budgeted walk.
///
/// It holds the UN-finalized [`Sha256`] state of the byte stream [`hash_tree`]
/// hashes, so `hex(finalize)` is that tree's [`hash_tree`] value. Every consumer
/// of a fetched tree — each trusted identity's signature check and the pinned
/// `sha256` comparison — reads this one value, so a tree whose shape its remote
/// author controls is walked once per fetch, never once per consumer.
#[derive(Clone)]
pub struct TreeDigest(Sha256);

impl TreeDigest {
    /// Walk and hash the tree at `root` under `ceiling`.
    ///
    /// # Errors
    /// As [`hash_tree`].
    pub fn of_tree_within(root: &Path, ceiling: &TreeCeiling) -> Result<Self, TreeHashError> {
        tree_hasher_within(root, ceiling).map(Self)
    }

    /// A copy of the un-finalized hasher, for an API that finalizes it itself —
    /// sigstore's `verify_digest(input_digest: Sha256, …)` compares
    /// `hex(input_digest.finalize())` against a DSSE bundle's signed subject
    /// digest, binding that comparison to exactly this tree hash.
    #[cfg(feature = "signing")]
    #[must_use]
    pub fn hasher(&self) -> Sha256 {
        self.0.clone()
    }

    /// The finalized digest as lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.clone().finalize())
    }
}

/// Feed the deterministic byte stream [`hash_tree`] hashes into a fresh
/// [`Sha256`] under `ceiling` and return the UN-finalized hasher.
///
/// The root is held once; every entry below it is reached from that handle,
/// one entry name per level, each level opened without following a link, so
/// no lookup leaves the tree or passes through a link.
///
/// # Errors
/// As [`hash_tree`].
fn tree_hasher_within(root: &Path, ceiling: &TreeCeiling) -> Result<Sha256, TreeHashError> {
    let held = HeldDir::open_root(root).map_err(|refusal| tree_io(root, refusal.into_io()))?;
    let files = walk_tree(&held, root, ceiling)?;
    hash_walked(&held, root, &files, ceiling)
}

/// A regular file the walk listed: its tree path and the entry names that reach it from the root.
#[derive(Debug)]
struct WalkedFile {
    rel: TreePath,
    names: Vec<EntryName>,
}

/// List every regular file below the held `dir`, sorted by tree path.
///
/// `root` is the path `dir` was opened from, used only to name a failing
/// entry in an error; nothing is opened through it.
///
/// # Errors
/// As [`hash_tree`].
fn walk_tree(
    dir: &HeldDir,
    root: &Path,
    ceiling: &TreeCeiling,
) -> Result<Vec<WalkedFile>, TreeHashError> {
    let mut files = Vec::new();
    let mut seen: u64 = 0;
    let mut walk = Walk {
        root,
        ceiling,
        out: &mut files,
        seen: &mut seen,
    };
    walk.collect(dir, &TreePath::root(), &[], 0)?;
    // Sort by the relative path so the hash is independent of directory-read
    // order (which the OS does not guarantee).
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(files)
}

/// Hash the listed `files`, each opened afresh from the held `dir` and read from that one handle.
///
/// Each file is reached by [`HeldDir::open_rel`], which opens every level
/// without following a link and proves the final entry a regular file from
/// its own handle, so an entry swapped for a link, a FIFO or a device after
/// the walk is refused, never followed or blocked on: the bytes hashed are
/// the bytes of the handle that was checked.
///
/// # Errors
/// As [`hash_tree`].
fn hash_walked(
    dir: &HeldDir,
    root: &Path,
    files: &[WalkedFile],
    ceiling: &TreeCeiling,
) -> Result<Sha256, TreeHashError> {
    let mut hasher = Sha256::new();
    update_len_prefixed(&mut hasher, TREE_TAG);
    let count = u64::try_from(files.len()).unwrap_or(u64::MAX);
    hasher.update(count.to_le_bytes());
    // One reusable chunk buffer for the whole tree — the hashed byte stream is
    // identical to a per-file allocation, since every file streams through the
    // same fixed-size window.
    let mut buf = vec![0u8; TREE_HASH_CHUNK_BYTES];
    let mut total_bytes: u64 = 0;
    for walked in files {
        let shown = root.join(walked.rel.as_str());
        update_str(&mut hasher, walked.rel.as_str());
        let file = dir
            .open_rel(&walked.names)
            .map_err(|refusal| tree_refusal(&shown, refusal, ceiling))?;
        let len = hash_one_file(
            &mut hasher,
            file,
            walked.rel.as_str(),
            &shown,
            &mut buf,
            total_bytes,
            ceiling,
        )?;
        total_bytes = total_bytes.saturating_add(len);
    }
    Ok(hasher)
}

/// The tree-hash refusal an [`OpenRefusal`] of the entry at `shown` stands for.
fn tree_refusal(shown: &Path, refusal: OpenRefusal, ceiling: &TreeCeiling) -> TreeHashError {
    match refusal {
        OpenRefusal::Link => tree_exceeded(IngestLimit::Symlink),
        OpenRefusal::NotRegular(_) => tree_exceeded(IngestLimit::SpecialFile),
        OpenRefusal::NotUtf8 => tree_exceeded(IngestLimit::NonUtf8Name),
        OpenRefusal::TooLarge(cap) => tree_exceeded(IngestLimit::Bytes(cap.get())),
        OpenRefusal::TooManyEntries(_) => tree_exceeded(IngestLimit::Entries(ceiling.entries())),
        OpenRefusal::BadName => tree_io(
            shown,
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a directory listing named an entry that is not a single path component",
            ),
        ),
        OpenRefusal::Absent | OpenRefusal::Denied | OpenRefusal::InUse | OpenRefusal::Io(_) => {
            tree_io(shown, refusal.into_io())
        }
    }
}

/// Stream one opened file's bytes into `hasher` with an explicit little-endian
/// length prefix (matching [`update_len_prefixed`]'s framing), refusing a file
/// past `ceiling.per_file()` before the read can exhaust memory.
///
/// The length prefix is the length the handle's own proof saw, re-checked
/// against the bytes actually read: the read stops just past it, so a
/// file that grows or shrinks after the proof (a race an attacker controls)
/// is refused rather than framed with a stale, mismatched length that would
/// corrupt the integrity hash.
///
/// `buf` is a caller-owned scratch chunk reused across every file in a tree; its
/// length is the streaming window and its contents on entry are irrelevant.
/// `hashed_so_far` is the byte total of the tree's earlier files: a file that
/// would carry the tree past `ceiling.bytes()` is refused before it is read.
/// `shown` names the file in an error only. Returns the file's length.
fn hash_one_file(
    hasher: &mut Sha256,
    file: RegularFile,
    rel: &str,
    shown: &Path,
    buf: &mut [u8],
    hashed_so_far: u64,
    ceiling: &TreeCeiling,
) -> Result<u64, TreeHashError> {
    use std::io::Read as _;

    let declared_len = file.len();
    if declared_len > ceiling.per_file() {
        return Err(tree_exceeded(IngestLimit::Bytes(ceiling.per_file())));
    }
    if hashed_so_far.saturating_add(declared_len) > ceiling.bytes() {
        return Err(tree_exceeded(IngestLimit::Bytes(ceiling.bytes())));
    }

    hasher.update(declared_len.to_le_bytes());

    let one_past = ByteCap::from_nonzero(std::num::NonZeroU64::MIN.saturating_add(declared_len));
    let mut reader = file.into_reader(one_past);
    let mut total: u64 = 0;
    loop {
        let n = match reader.read(buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::FileTooLarge => {
                return Err(size_changed(shown, rel, declared_len));
            }
            Err(e) => return Err(tree_io(shown, e)),
        };
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > declared_len {
            break;
        }
        let chunk = buf.get(..n).ok_or_else(|| {
            tree_io(
                shown,
                std::io::Error::other("short read reported more bytes than the buffer holds"),
            )
        })?;
        hasher.update(chunk);
    }

    if total != declared_len {
        return Err(size_changed(shown, rel, declared_len));
    }
    Ok(declared_len)
}

/// The refusal of the file `rel` at `shown`, whose content stopped matching the `declared` length its proof saw.
fn size_changed(shown: &Path, rel: &str, declared: u64) -> TreeHashError {
    tree_io(
        shown,
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("file `{rel}` changed size during hashing (declared {declared} bytes)"),
        ),
    )
}

/// One depth-first walk of a held tree, collecting every regular file it lists.
///
/// Hidden (dot-prefixed) directories are skipped. These hold VCS and local
/// tooling metadata — `.git`, a code indexer's `.tokensave`, an editor's
/// `.vscode`/`.idea` — never a package's published source, which lives in named
/// directories. Excluding them keeps the content hash a function of the source
/// alone, so a fetched checkout hashes identically no matter what local tools
/// have dropped a scratch directory into it.
///
/// A published package source holds only plain files and directories, so every
/// other entry is refused rather than silently left out of the hash (which
/// would leave it invisible to the integrity check): a symlink cannot be
/// checked without following it (a TOCTOU and path-escape hazard), a FIFO would
/// block the read, and a name that is not UTF-8 cannot be hashed without two
/// distinct trees colliding.
///
/// `seen` counts every entry listed across the whole walk; one past
/// `ceiling.entries()` refuses the tree. A directory below `ceiling.depth()`
/// levels is refused before it is listed, bounding the recursion; only the
/// chain of directories above the one being listed is held open.
struct Walk<'a> {
    root: &'a Path,
    ceiling: &'a TreeCeiling,
    out: &'a mut Vec<WalkedFile>,
    seen: &'a mut u64,
}

impl Walk<'_> {
    /// Collect the regular files below the held `dir`, which `rel` and `names` reach from the root.
    fn collect(
        &mut self,
        dir: &HeldDir,
        rel: &TreePath,
        names: &[EntryName],
        depth: u32,
    ) -> Result<(), TreeHashError> {
        if depth > self.ceiling.depth() {
            return Err(tree_exceeded(IngestLimit::Depth(self.ceiling.depth())));
        }
        // One past the entries the tree may still hold: the listing itself is
        // bounded, and a directory that alone crosses the ceiling is refused.
        let remaining = self.ceiling.entries().saturating_sub(*self.seen);
        let listing_cap = EntryCap::from_nonzero(
            std::num::NonZeroU32::MIN.saturating_add(u32::try_from(remaining).unwrap_or(u32::MAX)),
        );
        let entries = dir.entries(listing_cap).map_err(|refusal| {
            tree_refusal(&self.root.join(rel.as_str()), refusal, self.ceiling)
        })?;
        *self.seen = self
            .seen
            .saturating_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
        if *self.seen > self.ceiling.entries() {
            return Err(tree_exceeded(IngestLimit::Entries(self.ceiling.entries())));
        }
        for (name, kind) in entries {
            match kind {
                FileKind::Symlink => return Err(tree_exceeded(IngestLimit::Symlink)),
                FileKind::Fifo | FileKind::Socket | FileKind::Device | FileKind::Other => {
                    return Err(tree_exceeded(IngestLimit::SpecialFile));
                }
                FileKind::Dir => {
                    let child = rel.child(&name)?;
                    if child.is_hidden() {
                        continue;
                    }
                    let held = dir.child_dir(&name).map_err(|refusal| {
                        tree_refusal(&self.root.join(child.as_str()), refusal, self.ceiling)
                    })?;
                    let child_names = extended(names, name);
                    self.collect(&held, &child, &child_names, depth.saturating_add(1))?;
                }
                FileKind::Regular => {
                    let child = rel.child(&name)?;
                    self.out.push(WalkedFile {
                        rel: child,
                        names: extended(names, name),
                    });
                }
            }
        }
        Ok(())
    }
}

/// `names` followed by `name`.
fn extended(names: &[EntryName], name: EntryName) -> Vec<EntryName> {
    let mut joined = Vec::with_capacity(names.len().saturating_add(1));
    joined.extend_from_slice(names);
    joined.push(name);
    joined
}

/// Compute the content-address key for one build: a pure function of every
/// input that determines [`EmittedProject`]'s bytes (see the module doc's
/// "Content address" section for exactly what is, and is not, included).
///
/// `sources` is the driver's `module_path -> (fs_path, text)` map AFTER
/// [`crate::project::inject_compiled_std_closure`] has run (so it already
/// includes the injected stdlib closure's text) — the fs path itself is
/// deliberately unhashed, matching [`ipe_db::SourceFile`]'s own input shape
/// (module path + text + origin; never the on-disk path).
#[must_use]
#[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)] // a content-address key over every independent emit-affecting input
pub fn compute_project_key(
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    injected: &BTreeSet<Vec<String>>,
    entry_path: &[String],
    db_driver: DbDriver,
    target: ipe_ir::Target,
    wasm_public_env: &[String],
    intent: ipe_backend_rust::BuildIntent,
    debugger: bool,
    hot_appearance: bool,
    webview_host: bool,
    webview_window: Option<&ipe_backend_rust::WebViewWindow>,
) -> String {
    let mut hasher = Sha256::new();
    update_len_prefixed(&mut hasher, KEY_TAG);
    // The target changes the emitted manifest/entry shape — a native-keyed
    // entry must never serve a wasm build (or vice versa).
    update_len_prefixed(&mut hasher, format!("{target:?}").as_bytes());

    // The dev-only appearance hot-swap flag changes the emitted view (style
    // literals routed through a `LiteralTable`), so a flag-on emit must never be
    // served from a flag-off cache entry, or vice versa. Keying on it keeps the
    // two disjoint; for a program with no hoist-eligible literal the emitted
    // bytes are identical either way and the extra bit only costs a cold entry.
    hasher.update([u8::from(hot_appearance)]);

    // The webview-native (`web desktop`) delivery emits a different executor and
    // default-feature set than a served `web`, so a webview emit must never be
    // served from a served-`web` cache entry (or vice versa). Keying on it keeps
    // the two disjoint; for a non-web program the emitted bytes are identical
    // either way and the extra bit only costs a cold entry.
    hasher.update([u8::from(webview_host)]);

    // The webview desktop window (title / size) is emitted as literals into the
    // executor, so a window change must invalidate a stale cache entry. Absence
    // folds a distinct marker from any present window.
    match webview_window {
        Some(w) => {
            hasher.update([1u8]);
            update_len_prefixed(&mut hasher, w.title.as_bytes());
            hasher.update(w.width.to_le_bytes());
            hasher.update(w.height.to_le_bytes());
        }
        None => hasher.update([0u8]),
    }

    // The build intent changes the emitted crate: a Development emit carries
    // the runtime `dev-posture` feature (the console's loopback dev default),
    // and a Release emit rejects any `Debug.*` use (IPE-L0140). Keying on it
    // keeps the two builds' cache entries disjoint, so a dev-cached project is
    // never served to a release build, and vice versa.
    hasher.update([match intent {
        ipe_backend_rust::BuildIntent::Development => 0u8,
        ipe_backend_rust::BuildIntent::Release => 1u8,
    }]);

    // `--debugger` changes the emitted crate: the runtime `debugger` feature,
    // the cli/worker entry's session-codec argument and the serde derives the
    // typed session log needs. A debugger build must never be served a plain
    // cached project (it would fail cargo on the entry's arity), or vice versa.
    hasher.update([u8::from(debugger)]);

    let entry_len = u64::try_from(entry_path.len()).unwrap_or(u64::MAX);
    hasher.update(entry_len.to_le_bytes());
    for segment in entry_path {
        update_str(&mut hasher, segment);
    }

    let driver_tag: u8 = match db_driver {
        DbDriver::Sqlite => 0,
        DbDriver::Postgres => 1,
    };
    hasher.update([driver_tag]);

    // `[wasm] publicEnv` only affects the final emit stage (the generated
    // `env_public.rs`), the same class of input `db_driver` is — see this
    // fn's sibling [`compute_ir_key`], which deliberately excludes both.
    let public_env_len = u64::try_from(wasm_public_env.len()).unwrap_or(u64::MAX);
    hasher.update(public_env_len.to_le_bytes());
    for name in wasm_public_env {
        update_str(&mut hasher, name);
    }

    // `BTreeMap` iteration is already sorted by key — deterministic across
    // runs and independent of insertion order.
    let sources_len = u64::try_from(sources.len()).unwrap_or(u64::MAX);
    hasher.update(sources_len.to_le_bytes());
    for (path, (_fs_path, text)) in sources {
        let path_len = u64::try_from(path.len()).unwrap_or(u64::MAX);
        hasher.update(path_len.to_le_bytes());
        for segment in path {
            update_str(&mut hasher, segment);
        }
        let origin_tag: u8 = u8::from(injected.contains(path));
        hasher.update([origin_tag]);
        update_str(&mut hasher, text);
    }

    hex::encode(hasher.finalize())
}

/// Domain-separation tag for the lowered-IR content-address key —
/// distinct from [`KEY_TAG`] because this tier's key excludes `db_driver`
/// (see [`compute_ir_key`]'s doc for why).
const IR_KEY_TAG: &[u8] = b"ipec-build-cache-ir-key-v1";

/// Compute the content-address key for the lowered-IR cache tier:
/// a pure function of every input that determines
/// [`ipe_db::lower_program`]'s output.
///
/// Deliberately NARROWER than [`compute_project_key`]: `db_driver` only
/// affects the FINAL emit stage (`ipe_db::emit_project` reads
/// `config.db_driver`), never `linked_program`/`typecheck`/`lower_program`
/// (see `docs/architecture/salsa-incremental-compilation-2026-07-11.md`
/// §11.2/§13) — so an IR-tier key that included it would over-invalidate: a
/// `[database] driver` edit in `package.ipe` would needlessly miss a perfectly
/// reusable `Program`, even though the ONLY thing that changed is read by
/// the emit stage this tier deliberately sits upstream of.
#[must_use]
pub fn compute_ir_key(
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    injected: &BTreeSet<Vec<String>>,
    entry_path: &[String],
    target: ipe_ir::Target,
) -> String {
    let mut hasher = Sha256::new();
    update_len_prefixed(&mut hasher, IR_KEY_TAG);
    // The IR itself is target-independent, but the fast path re-emits from a
    // cached Program WITHOUT re-running canonicalisation — keying on target
    // keeps the wasm Layer-1 gate (which runs at canon) unskippable.
    update_len_prefixed(&mut hasher, format!("{target:?}").as_bytes());

    let entry_len = u64::try_from(entry_path.len()).unwrap_or(u64::MAX);
    hasher.update(entry_len.to_le_bytes());
    for segment in entry_path {
        update_str(&mut hasher, segment);
    }

    let sources_len = u64::try_from(sources.len()).unwrap_or(u64::MAX);
    hasher.update(sources_len.to_le_bytes());
    for (path, (_fs_path, text)) in sources {
        let path_len = u64::try_from(path.len()).unwrap_or(u64::MAX);
        hasher.update(path_len.to_le_bytes());
        for segment in path {
            update_str(&mut hasher, segment);
        }
        let origin_tag: u8 = u8::from(injected.contains(path));
        hasher.update([origin_tag]);
        update_str(&mut hasher, text);
    }

    hex::encode(hasher.finalize())
}

/// The whole-project content hash of the CURRENTLY RUNNING `ipe` binary's
/// bytes — the design doc's `compiler_revision()`. `None` when the running
/// executable cannot be located or read (never a hard error: the cache is
/// simply unavailable for this invocation).
fn compiler_revision_hash() -> Option<String> {
    use std::io::Read as _;

    let exe = std::env::current_exe().ok()?;
    let mut file = fs::File::open(&exe).ok()?;
    let mut hasher = Sha256::new();
    // Stream the running binary in fixed chunks rather than buffering the whole
    // (statically linked) executable in one `Vec` — the digest is byte-identical,
    // and the exe cannot change under a running process, so version isolation is
    // unweakened.
    let mut buf = vec![0u8; TREE_HASH_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n)?);
    }
    Some(hex::encode(hasher.finalize()))
}

/// The active `rustc`'s `-vV` output, hashed — the design doc's
/// `toolchain_fingerprint()`.
///
/// `None` when the query is refused: `rustc` is missing, crosses its ceiling,
/// exits non-zero, or prints a report [`RustcVersion::parse`] refuses.
fn toolchain_fingerprint_hash() -> Option<String> {
    RustcVersion::active().ok().map(toolchain_fingerprint_of)
}

/// The fingerprint of `version`'s exact report bytes.
fn toolchain_fingerprint_of(version: &RustcVersion) -> String {
    hex::encode(Sha256::digest(version.verbatim()))
}

/// Derive the version-epoch directory name for this process, or `None` when
/// either probe is unavailable (cache disabled for this invocation — see
/// the module doc's "Advisory semantics" section).
#[must_use]
pub fn derive_epoch() -> Option<String> {
    // Both probes (the running exe's content hash and the active `rustc -vV`
    // fingerprint) are invariant for the life of the process, so compute the
    // epoch once and reuse it — turning a per-build IO + hash + `rustc` spawn on
    // the warm cache path into a single up-front cost. The `None` outcome (a
    // probe was unavailable) is memoized too, matching today's per-call result.
    static EPOCH: OnceLock<Option<String>> = OnceLock::new();
    EPOCH.get_or_init(derive_epoch_uncached).clone()
}

fn derive_epoch_uncached() -> Option<String> {
    let compiler_revision = compiler_revision_hash()?;
    let toolchain = toolchain_fingerprint_hash()?;
    let mut hasher = Sha256::new();
    update_len_prefixed(&mut hasher, EPOCH_TAG);
    update_str(&mut hasher, &compiler_revision);
    update_str(&mut hasher, &toolchain);
    Some(hex::encode(hasher.finalize()))
}

/// The directory below the build output that holds the default cache.
pub const CACHE_DIR_NAME: &str = ".ipe-cache";

/// Where the build cache lives, chosen before the output dir is claimed.
///
/// A site only reads. Writing takes a [`CacheRoot`], and an in-output site
/// yields one only from the claimed output dir ([`CacheSite::root`]), so no
/// cache write can reach the output dir before the claim proves it ipe's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheSite {
    /// `<out_dir>/.ipe-cache/<salt>`, inside the build output.
    InOutput {
        /// The output dir the build claims.
        out_dir: PathBuf,
        /// The per-user secret naming the partition.
        salt: String,
    },
    /// A directory the user named through `IPE_BUILD_CACHE_DIR`.
    Explicit(PathBuf),
}

/// A writable build-cache root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheRoot {
    /// `.ipe-cache/<salt>` below a claimed output dir.
    ///
    /// Every write goes through [`OwnedDir::path_to`], which refuses a symlink
    /// at any level and replaces the entry by a rename.
    InOwned {
        /// The claimed output dir.
        dir: OwnedDir,
        /// The per-user secret naming the partition.
        salt: String,
    },
    /// A directory the user named through `IPE_BUILD_CACHE_DIR`.
    Explicit(PathBuf),
}

impl CacheSite {
    /// The writable root, given `claimed`, the claim of this site's output dir.
    ///
    /// `None` when `claimed` is some other directory.
    #[must_use]
    pub fn root(&self, claimed: &OwnedDir) -> Option<CacheRoot> {
        match self {
            Self::InOutput { out_dir, salt } => {
                (claimed.path() == out_dir).then(|| CacheRoot::InOwned {
                    dir: claimed.clone(),
                    salt: salt.clone(),
                })
            }
            Self::Explicit(dir) => Some(CacheRoot::Explicit(dir.clone())),
        }
    }

    /// The bytes of entry `file_name` under `epoch`, read through no symlink.
    ///
    /// An in-output entry is read only from an output dir ipe owns now (a
    /// genuine marker and no claim in flight, read through one held handle);
    /// every level below it (and below an explicit root) is opened from the
    /// held level above without following a link, and a symlink anywhere is a
    /// miss.
    fn read(&self, epoch: &str, file_name: &str) -> Option<Vec<u8>> {
        match self {
            Self::InOutput { out_dir, salt } => {
                let out = crate::output_dir::held::HeldDir::open(out_dir).ok()??;
                read_in_owned(
                    &out,
                    &[CACHE_DIR_NAME, salt.as_str(), epoch, file_name],
                    crate::io_bounded::BUILD_CACHE_ENTRY_CAP,
                )
            }
            Self::Explicit(dir) => read_without_links(
                dir,
                &[epoch, file_name],
                crate::io_bounded::BUILD_CACHE_ENTRY_CAP,
            ),
        }
    }
}

impl CacheRoot {
    /// Best-effort write of entry `file_name` under `epoch`.
    ///
    /// Every failure is swallowed, a refused symlink included.
    ///
    /// An entry past [`crate::io_bounded::BUILD_CACHE_ENTRY_CAP`] is skipped, since a read
    /// of it would be a miss anyway.
    fn write(&self, epoch: &str, file_name: &str, bytes: &[u8]) {
        if !within_cap(bytes, crate::io_bounded::BUILD_CACHE_ENTRY_CAP)
            || !ipe_fs_open::is_one_spelled_name(std::ffi::OsStr::new(epoch))
            || !ipe_fs_open::is_one_spelled_name(std::ffi::OsStr::new(file_name))
        {
            return;
        }
        match self {
            Self::InOwned { dir, salt } => {
                let rel = Path::new(CACHE_DIR_NAME)
                    .join(salt)
                    .join(epoch)
                    .join(file_name);
                if let Ok(path) = dir.path_to(rel) {
                    let _ = path.write(bytes);
                }
            }
            Self::Explicit(root) => write_entry(root, epoch, file_name, bytes),
        }
    }
}

/// Whether `bytes` fits within `cap` bytes.
fn within_cap(bytes: &[u8], cap: u64) -> bool {
    u64::try_from(bytes.len()).is_ok_and(|len| len <= cap)
}

/// Read `base/<parts...>` when each part is one spelled name and no level is a symlink.
///
/// Every level below `base` is opened relative to the held level above it,
/// never following a link, and the file is proven regular and read from that
/// one handle, so a link swapped in at any level is a miss. At most `cap + 1`
/// bytes are read, and a file past `cap` is a miss.
fn read_without_links(base: &Path, parts: &[&str], cap: u64) -> Option<Vec<u8>> {
    read_below(&HeldDir::open_root(base).ok()?, parts, cap)
}

/// Read `<parts...>` below the output dir `out` holds, when ipe owns that held dir now.
///
/// Ownership is decided by [`crate::output_dir::held::HeldDir::owned_now`]
/// on `out`'s own handle (a genuine marker and no claim in flight), and the
/// levels below are opened from a handle proven to be the same directory
/// object as `out` (equal identity while both are open), so an output dir
/// swapped for a link or for another directory after it was held is a miss:
/// the entry read sits in the directory whose ownership was checked.
fn read_in_owned(
    out: &crate::output_dir::held::HeldDir,
    parts: &[&str],
    cap: u64,
) -> Option<Vec<u8>> {
    if out.owned_now().ok()? != crate::output_dir::held::OwnedNow::Owned {
        return None;
    }
    let dir = HeldDir::open_root(out.path()).ok()?;
    if dir.id().ok()? != out.id().ok()? {
        return None;
    }
    read_below(&dir, parts, cap)
}

/// Read `<parts...>` below the held `dir`, at most `cap` bytes, no level a link.
///
/// Each part must pass [`ipe_fs_open::is_one_spelled_name`], the rule
/// [`write_entry`] and [`CacheRoot::write`] apply, so a read never names an
/// entry the cache could not have written.
fn read_below(dir: &HeldDir, parts: &[&str], cap: u64) -> Option<Vec<u8>> {
    let names = parts
        .iter()
        .map(|part| {
            let name = std::ffi::OsStr::new(part);
            ipe_fs_open::is_one_spelled_name(name)
                .then(|| EntryName::new(name))
                .flatten()
        })
        .collect::<Option<Vec<_>>>()?;
    let cap = ByteCap::new(cap)?;
    dir.open_rel(&names).ok()?.read_bytes(cap).ok()
}

/// The cache site for a build writing to `out_dir`.
///
/// - `IPE_BUILD_CACHE=0` (also `off` / `false`) disables the cache entirely.
/// - `IPE_BUILD_CACHE_DIR=<path>` overrides the default location.
/// - Otherwise: `<out_dir>/.ipe-cache/<user salt>`, colocated with the build
///   output so removing it also resets the cache.
///
/// A cached entry is emitted verbatim, so the default partition is named by a
/// secret per-user salt kept in `IPE_HOME`: a cache a cloned repository ships
/// inside a force-added `out/` sits under a name this user never reads, and can
/// never substitute the Rust built from the sources. No salt (no resolvable
/// `IPE_HOME`) disables the default cache.
#[must_use]
pub fn env_cache_dir(out_dir: &Path) -> Option<CacheSite> {
    if matches!(
        ipe_env::var("IPE_BUILD_CACHE").as_deref(),
        Ok("0" | "off" | "false")
    ) {
        return None;
    }
    if let Ok(dir) = ipe_env::var("IPE_BUILD_CACHE_DIR") {
        return Some(CacheSite::Explicit(PathBuf::from(dir)));
    }
    default_cache_site(out_dir)
}

/// `<out_dir>/.ipe-cache/<user salt>`, or `None` when no salt is available.
fn default_cache_site(out_dir: &Path) -> Option<CacheSite> {
    static SALT: OnceLock<Option<String>> = OnceLock::new();
    let salt = SALT.get_or_init(user_cache_salt).clone()?;
    Some(CacheSite::InOutput {
        out_dir: out_dir.to_path_buf(),
        salt,
    })
}

/// The bytes of randomness in a per-user cache salt.
const SALT_BYTES: usize = 32;

/// The per-user secret naming the default cache partition, created on first use.
///
/// Stored as hex in `$IPE_HOME/build-cache-salt`. The file is created, and
/// read back, only relative to the `IPE_HOME` handle [`crate::secret_file`]
/// proved private, through a file handle proven owner-only. A symlink, a
/// malformed file, a file another user could read, a directory (or ancestor)
/// another user can write, or a host that cannot keep the file owner-only
/// yields `None` (the default cache is then disabled), never a salt another
/// user could read or an attacker could have chosen. A refused `IPE_HOME`
/// is warned about once, naming why, since the user can fix it.
fn user_cache_salt() -> Option<String> {
    let home = crate::runtime_embed::ipe_home().ok()?;
    let dir =
        match crate::secret_file::create_owner_dir(crate::secret_file::HOST_SECRET_STORE, &home) {
            Ok(dir) => dir,
            Err(refusal) => {
                if let Some(warning) = salt_dir_warning(&refusal) {
                    crate::screen::chatter(
                        crate::screen::Stream::Stderr,
                        crate::screen::Tone::UserError,
                        &warning,
                    );
                }
                return None;
            }
        };
    let name = EntryName::new(std::ffi::OsStr::new(SALT_FILE_NAME))?;
    salt_in(&dir, &name)
}

/// The warning a refused salt directory earns, if the user can act on it.
///
/// A link standing for `IPE_HOME`, or a component another user could write,
/// is named; a host without owner-only files, or a failing filesystem call,
/// disables the default cache silently.
fn salt_dir_warning(refusal: &crate::secret_file::SecretFileError) -> Option<crate::text::Message> {
    use crate::secret_file::{DirRefusal, SecretFileError};
    match refusal {
        SecretFileError::Dir(DirRefusal::Symlinked(dir)) => {
            Some(crate::text::msg::build_cache_dir_symlinked(&dir.display()))
        }
        SecretFileError::Dir(DirRefusal::Untrusted(dir)) => {
            Some(crate::text::msg::build_cache_dir_untrusted(&dir.display()))
        }
        SecretFileError::Unsupported
        | SecretFileError::Io(_)
        | SecretFileError::NotOwnerOnly(_)
        | SecretFileError::NotRegularFile(_) => None,
    }
}

/// The name of the salt file inside `IPE_HOME`.
const SALT_FILE_NAME: &str = "build-cache-salt";

/// The salt kept as `name` in `dir`, created there when the name is vacant.
fn salt_in(dir: &OwnerDir, name: &EntryName) -> Option<String> {
    if dir.is_vacant(name).ok()? {
        create_salt(dir, name)
    } else {
        read_salt(dir, name)
    }
}

/// The most bytes read from a salt file: its hex digits plus trailing whitespace.
const SALT_READ_CAP: u64 = 128;

/// The salt stored as `name` in `dir`, read through a handle proven owner-only.
///
/// `None` when the file is absent, not private to the invoking user, or not
/// exactly [`SALT_BYTES`] hex-encoded bytes.
fn read_salt(dir: &OwnerDir, name: &EntryName) -> Option<String> {
    use std::io::Read as _;
    let file = dir.open_existing(name).ok()?;
    let mut text = String::new();
    file.take(SALT_READ_CAP).read_to_string(&mut text).ok()?;
    let text = text.trim().to_owned();
    (text.len() == SALT_BYTES * 2 && text.bytes().all(|b| b.is_ascii_hexdigit())).then_some(text)
}

/// Create a fresh salt as the unused `name` in `dir`, durable before it is used.
///
/// A salt file left half-written is removed. A concurrent first build that
/// won the race to create `name` supplies the salt instead.
fn create_salt(dir: &OwnerDir, name: &EntryName) -> Option<String> {
    use std::io::Write as _;
    let mut bytes = [0u8; SALT_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    let salt = hex::encode(bytes);
    match dir.create_new(name) {
        Ok(mut file) => {
            let written = file
                .write_all(salt.as_bytes())
                .and_then(|()| file.sync_all());
            drop(file);
            if written.is_err() {
                let _ = dir.remove(name);
                return None;
            }
            Some(salt)
        }
        Err(crate::secret_file::SecretFileError::Io(e))
            if e.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            read_salt(dir, name)
        }
        Err(_) => None,
    }
}

/// Write `bytes` to `<cache_root>/<epoch>/<file_name>` through held directory handles.
///
/// Best-effort: every failure is swallowed. `cache_root` is opened without
/// following a final link and the epoch level beneath it through that handle,
/// so a level swapped for a symlink between the check and the write refuses
/// the write rather than landing it through the link. The entry is staged in
/// an exclusively created, process-unique temp file renamed over the name.
fn write_entry(cache_root: &Path, epoch: &str, file_name: &str, bytes: &[u8]) {
    use crate::output_dir::held::{HeldDir, level_held};
    use ipe_fs_open::is_one_spelled_name;
    use std::ffi::OsStr;
    use std::io::Write as _;
    if !is_one_spelled_name(OsStr::new(epoch))
        || !is_one_spelled_name(OsStr::new(file_name))
        || fs::create_dir_all(cache_root).is_err()
    {
        return;
    }
    let Ok(Some(root)) = HeldDir::open(cache_root) else {
        return;
    };
    level_held(root.path());
    let Ok((dir, _)) = root.create_child(std::ffi::OsStr::new(epoch)) else {
        return;
    };
    level_held(dir.path());
    let _ = dir.write_file(std::ffi::OsStr::new(file_name), None, |file| {
        file.write_all(bytes)
    });
}

/// The file name of the `EmittedProject`-tier entry for `key`.
fn entry_file_name(key: &str) -> String {
    format!("{key}.json")
}

/// Look up a cached [`EmittedProject`] for `key` under `epoch`. Every
/// failure mode (missing file, unreadable, corrupt JSON, an entry that
/// deserializes but fails `RelPath`'s validation) is a plain cache MISS —
/// `None`, never an error, matching "corrupt entry -> discard".
#[must_use]
pub fn try_load(site: &CacheSite, epoch: &str, key: &str) -> Option<EmittedProject> {
    let bytes = site.read(epoch, &entry_file_name(key))?;
    serde_json::from_slice(&bytes).ok()
}

/// Best-effort store of a successfully compiled [`EmittedProject`] under
/// `key`/`epoch`. Every failure (directory creation, serialize, write,
/// rename) is silently swallowed — a cache-write failure must never turn a
/// successful build into a reported failure. Writes atomically (tmp file +
/// rename) so a concurrent reader (a second `ipe dev build` racing this one)
/// never observes a partially-written entry; a torn read is impossible, a
/// missing-then-appearing file is the only visible race, which `try_load`
/// already treats as an ordinary miss.
///
/// The tmp file name is unique to this process, so two concurrent
/// `ipe dev build` invocations computing the same key never write to the same
/// tmp path and so never interleave into one entry a third reader could load.
///
/// An in-output root writes through [`OwnedDir::path_to`]: a symlink planted
/// at any level below the claimed output dir skips the store, never writes
/// through the link.
pub fn store(root: &CacheRoot, epoch: &str, key: &str, project: &EmittedProject) {
    let Ok(json) = serde_json::to_vec(project) else {
        return;
    };
    root.write(epoch, &entry_file_name(key), &json);
}

// ---------------------------------------------------------------------------
// The lowered-IR cache tier
// ---------------------------------------------------------------------------
//
// Sits ONE STAGE EARLIER than the `EmittedProject` tier above: a hit here
// skips parse -> canon -> link -> infer -> lower ENTIRELY (no
// `ipe_db::IpeDatabase` is even constructed — see `compile_modules_observed`
// in `crate::lib`), running only `RustBackend::emit` over the recovered
// `ipe_ir::Program` before falling through to the SAME
// `write_emitted_project`/tier-1-`store` path a full pipeline run uses. A
// hit here is therefore a smaller win than an `EmittedProject`-tier hit
// (emit still runs), but covers the case an `EmittedProject`-tier miss does
// NOT: a `db_driver`-only edit (SQL driver flip in `package.ipe`), where the
// SAME `Program` this tier caches is still exactly reusable even though the
// `EmittedProject` tier's key (which folds in `db_driver`) misses.
//
// **The relocation pass.** `ipe_ir::Program` embeds `ipe_intern::Symbol`
// pervasively — a raw index into the WRITING process's interner, meaningless
// against any other. `ipe_intern::Symbol`'s `serde` impls close this by
// serialising the symbol's resolved STRING and re-interning it into an
// AMBIENT interner installed via `SerdeInternerGuard::install` (see that
// type's own module doc for the full design + the cross-process id-drift
// proof). Every (de)serialize call in this section installs a guard around
// exactly one `Program` (de)serialize call, so a `Program` deserialized here
// behaves identically to a fresh `ipe_lower::lower` output IN THE CALLING
// PROCESS's interner — never a raw-id mismatch.
//
// **Security.** `ipe_intern::Symbol::deserialize` validates every embedded
// string through `ipe_intern::is_valid_symbol_text` before interning it —
// closing the SAME class of hole `RelPath`'s hand-written `Deserialize`
// closes for path traversal, applied to identifier text instead of paths
// (a poisoned symbol string could otherwise splice arbitrary Rust source
// into the next `RustBackend::emit` call, since the backend trusts an
// interned string verbatim when emitting identifiers). `ipe_ir::Match`
// similarly carries a hand-written `Deserialize` that re-validates through
// `Match::new_flat`'s structural backstop rather than trusting the arm list
// verbatim. Every failure mode here — corrupt JSON, a poisoned `Symbol`
// string, a malformed `Match` — is `None`/silently-swallowed, the SAME
// "corrupt entry -> discard" contract the `EmittedProject` tier established.

/// The file name of the lowered-IR-tier entry for `key`.
fn ir_entry_file_name(key: &str) -> String {
    format!("{key}.ir.json")
}

/// Look up a cached lowered [`Program`] for `key` under `epoch`, relocating
/// every embedded `Symbol` into `interner` (the RELOCATION PASS — see this
/// section's module doc). Every failure mode (missing file, unreadable,
/// corrupt JSON, a `Symbol` text that fails `ipe_intern::is_valid_symbol_text`,
/// a `Match` arm list `Match::new_flat` rejects) is a plain cache MISS —
/// `None`, never an error — matching the `EmittedProject` tier's contract
/// exactly ([`try_load`]).
#[must_use]
pub fn try_load_ir(
    site: &CacheSite,
    epoch: &str,
    key: &str,
    interner: &Arc<Mutex<Interner>>,
) -> Option<Program> {
    let bytes = site.read(epoch, &ir_entry_file_name(key))?;
    let _guard = SerdeInternerGuard::install(Arc::clone(interner));
    serde_json::from_slice(&bytes).ok()
}

/// Best-effort store of a successfully lowered [`Program`]. Same
/// advisory/atomic-write contract as [`store`]: every failure (directory
/// creation, resolve/serialize, write, rename) is silently swallowed — a
/// cache-write failure must never turn a successful build into a reported
/// failure. PID-suffixed tmp name for the same concurrent-writer safety
/// [`store`]'s own doc explains.
pub fn store_ir(
    root: &CacheRoot,
    epoch: &str,
    key: &str,
    program: &Program,
    interner: &Arc<Mutex<Interner>>,
) {
    let json = {
        let _guard = SerdeInternerGuard::install(Arc::clone(interner));
        serde_json::to_vec(program)
    };
    let Ok(json) = json else {
        return;
    };
    root.write(epoch, &ir_entry_file_name(key), &json);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_hash_input_is_the_verbatim_output() {
        let report: &[u8] = b"rustc 1.80.0 (abcdef 2024-01-01)\n\
            binary: rustc\n\
            host: x86_64-unknown-linux-gnu\n\
            release: 1.80.0\n\
            LLVM version: 18.1.7\n\n";
        let version = RustcVersion::parse(report);
        assert!(version.is_ok(), "{version:?}");
        let mut hasher = Sha256::new();
        hasher.update(report);
        assert_eq!(
            version.as_ref().ok().map(toolchain_fingerprint_of),
            Some(hex::encode(hasher.finalize()))
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)] // the test temp root is writable and its path holds no `PATH` separator
    fn a_rustc_query_past_its_wall_disables_the_cache() {
        use crate::remote_ingest::{LocalWall, RUSTC_QUERY_LIMITS};
        use crate::toolchain::{RustcQueryRefusal, RustcRunFailure, StubRustc};
        let stub = StubRustc::new(
            "slow",
            "sleep 30\nprintf 'rustc 1.0 (x)\\nhost: a-b-c\\nrelease: 1.0\\n'",
        )
        .expect("write the stub rustc");
        let mut rustc = std::process::Command::new("rustc");
        rustc.env("PATH", stub.path().expect("join the stub PATH"));
        let started = std::time::Instant::now();
        let query = RustcVersion::query(
            rustc,
            RUSTC_QUERY_LIMITS.with_wall(LocalWall::of_secs::<1>()),
        );
        assert!(
            matches!(
                query,
                Err(RustcQueryRefusal::Run(RustcRunFailure::Exceeded(
                    LocalRefusal {
                        source: LocalSource::RustcQuery,
                        limit: IngestLimit::Time(_),
                        ..
                    }
                )))
            ),
            "{query:?}"
        );
        assert_eq!(query.as_ref().ok().map(toolchain_fingerprint_of), None);
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    /// A fresh, empty scratch directory for one salt test, held as a secret dir.
    #[cfg(unix)]
    fn salt_test_dir(tag: &str) -> (PathBuf, OwnerDir) {
        let base = ipe_test_temp::temp_root()
            .canonicalize()
            .expect("canonical temp dir");
        let dir = base.join(format!(
            "ipe-cache-salt-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let held = crate::secret_file::create_owner_dir(
            crate::secret_file::SecretStore::OwnerOnlyFile,
            &dir,
        )
        .expect("create test dir");
        (dir, held)
    }

    /// The entry name `text`, which the test knows to be one plain component.
    #[cfg(unix)]
    fn salt_entry(text: &str) -> EntryName {
        EntryName::new(std::ffi::OsStr::new(text)).expect("a plain component")
    }

    #[cfg(unix)]
    #[test]
    fn a_created_salt_is_owner_only_and_read_back() {
        let (dir, held) = salt_test_dir("roundtrip");
        let name = salt_entry(SALT_FILE_NAME);
        let created = salt_in(&held, &name);
        assert!(
            created
                .as_ref()
                .is_some_and(|salt| salt.len() == SALT_BYTES * 2),
            "a fresh salt must be created: {created:?}"
        );
        assert_eq!(
            read_salt(&held, &name),
            created,
            "the salt reads back unchanged"
        );
        assert_eq!(salt_in(&held, &name), created, "an existing salt is reused");
        assert_eq!(
            create_salt(&held, &name),
            created,
            "a lost creation race reuses the winner's salt"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_refused_salt_dir_is_warned_about_with_its_typed_reason() {
        use std::os::unix::fs::PermissionsExt as _;
        let (base, _held) = salt_test_dir("dir-refused");
        let real = base.join("real");
        fs::create_dir(&real).expect("create real dir");
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("plant dir symlink");
        let store = crate::secret_file::SecretStore::OwnerOnlyFile;

        let linked = crate::secret_file::create_owner_dir(store, &link).map(drop);
        let warning = linked.as_ref().err().and_then(salt_dir_warning);
        assert_eq!(
            warning,
            Some(crate::text::msg::build_cache_dir_symlinked(&link.display())),
            "a symlinked IPE_HOME is warned about as a link: {linked:?}"
        );

        let shared = base.join("shared");
        fs::create_dir(&shared).expect("create shared dir");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).expect("chmod shared");
        let exposed = crate::secret_file::create_owner_dir(store, &shared).map(drop);
        let warning = exposed.as_ref().err().and_then(salt_dir_warning);
        assert_eq!(
            warning,
            Some(crate::text::msg::build_cache_dir_untrusted(
                &shared.display()
            )),
            "a shared IPE_HOME is warned about as untrusted: {exposed:?}"
        );

        let unsupported = crate::secret_file::create_owner_dir(
            crate::secret_file::SecretStore::Unsupported,
            &real,
        )
        .map(drop);
        assert_eq!(
            unsupported.as_ref().err().and_then(salt_dir_warning),
            None,
            "a host without owner-only files disables the cache silently"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn a_salt_another_user_could_read_or_a_symlink_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let (dir, held) = salt_test_dir("refused");
        let name = salt_entry(SALT_FILE_NAME);
        let path = dir.join(SALT_FILE_NAME);
        let created = create_salt(&held, &name);
        assert!(created.is_some(), "a fresh salt must be created");
        for mode in [0o644, 0o640] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod salt");
            assert_eq!(
                salt_in(&held, &name),
                None,
                "a mode-{mode:o} salt must be refused"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod salt");
        std::os::unix::fs::symlink(&path, dir.join("linked-salt")).expect("plant symlink");
        assert_eq!(
            salt_in(&held, &salt_entry("linked-salt")),
            None,
            "a symlinked salt must be refused"
        );
        let malformed = salt_entry("malformed-salt");
        assert!(
            create_salt(&held, &malformed).is_some(),
            "create a salt to corrupt"
        );
        fs::write(dir.join("malformed-salt"), "not hex").expect("corrupt salt");
        assert_eq!(
            salt_in(&held, &malformed),
            None,
            "a malformed salt is refused"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    fn entry_file_path(cache_root: &Path, epoch: &str, key: &str) -> PathBuf {
        cache_root.join(epoch).join(entry_file_name(key))
    }

    fn ir_entry_file_path(cache_root: &Path, epoch: &str, key: &str) -> PathBuf {
        cache_root.join(epoch).join(ir_entry_file_name(key))
    }

    fn explicit_site(dir: &Path) -> CacheSite {
        CacheSite::Explicit(dir.to_path_buf())
    }

    fn explicit_root(dir: &Path) -> CacheRoot {
        CacheRoot::Explicit(dir.to_path_buf())
    }

    type TestSources = BTreeMap<Vec<String>, (PathBuf, String)>;

    fn sample_sources() -> (TestSources, BTreeSet<Vec<String>>) {
        let mut sources = BTreeMap::new();
        sources.insert(
            vec!["Main".to_owned()],
            (
                PathBuf::from("Main.ipe"),
                "module Main exposing (main)\n".to_owned(),
            ),
        );
        sources.insert(
            vec!["Ipe".to_owned(), "Basics".to_owned()],
            (
                PathBuf::from("<embedded>"),
                "module Ipe.Basics exposing (x)\nx = 1\n".to_owned(),
            ),
        );
        let injected = BTreeSet::from([vec!["Ipe".to_owned(), "Basics".to_owned()]]);
        (sources, injected)
    }

    fn entry() -> Vec<String> {
        vec!["Main".to_owned()]
    }

    #[test]
    fn key_is_deterministic() {
        let (sources, injected) = sample_sources();
        let a = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        let b = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        assert_eq!(a, b, "same inputs must hash to the same key");
    }

    #[test]
    fn key_changes_with_source_text() {
        let (mut sources, injected) = sample_sources();
        let base = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        if let Some(main) = sources.get_mut(&vec!["Main".to_owned()]) {
            main.1.push_str("\n-- comment\n");
        }
        let edited = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        assert_ne!(base, edited, "a body edit must change the key");
    }

    #[test]
    fn key_changes_with_db_driver() {
        let (sources, injected) = sample_sources();
        let sqlite = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        let postgres = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Postgres,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        assert_ne!(sqlite, postgres, "the SQL driver is part of the key");
    }

    /// A Development emit carries `dev-posture` and a Release emit refuses
    /// `Debug.*`, so the key separates the two intents: a dev-cached project is
    /// never served to a release build, or vice versa.
    #[test]
    fn key_changes_with_build_intent() {
        let (sources, injected) = sample_sources();
        let dev = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        let prod = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Release,
            false,
            false,
            false,
            None,
        );
        assert_ne!(dev, prod, "the build intent is part of the key");
    }

    /// A `--debugger` emit differs from a plain one (runtime feature, session
    /// codec argument, serde derives), so the key must separate the two.
    #[test]
    fn key_changes_with_debugger() {
        let (sources, injected) = sample_sources();
        let key = |debugger| {
            compute_project_key(
                &sources,
                &injected,
                &entry(),
                DbDriver::Sqlite,
                ipe_ir::Target::Native,
                &[],
                ipe_backend_rust::BuildIntent::Development,
                debugger,
                false,
                false,
                None,
            )
        };
        assert_ne!(
            key(false),
            key(true),
            "the debugger flag is part of the key"
        );
    }

    /// The dev appearance hot-swap flag routes style literals through a
    /// `LiteralTable`, changing the emitted view — so a flag-on build must never
    /// be served a flag-off cached project, or vice versa.
    #[test]
    fn key_changes_with_hot_appearance() {
        let (sources, injected) = sample_sources();
        let off = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        let on = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            true,
            false,
            None,
        );
        assert_ne!(off, on, "the hot-appearance flag is part of the key");
    }

    #[test]
    fn key_changes_with_webview_window() {
        let (sources, injected) = sample_sources();
        let small = ipe_backend_rust::WebViewWindow {
            title: "App".to_owned(),
            width: 800,
            height: 600,
        };
        let large = ipe_backend_rust::WebViewWindow {
            width: 1600,
            ..small.clone()
        };
        let key = |w: Option<&ipe_backend_rust::WebViewWindow>| {
            compute_project_key(
                &sources,
                &injected,
                &entry(),
                DbDriver::Sqlite,
                ipe_ir::Target::Native,
                &[],
                ipe_backend_rust::BuildIntent::Development,
                false,
                false,
                true,
                w,
            )
        };
        assert_ne!(
            key(None),
            key(Some(&small)),
            "an explicit window must differ from the fallback"
        );
        assert_ne!(
            key(Some(&small)),
            key(Some(&large)),
            "a window size change must invalidate the cache entry"
        );
    }

    /// `[wasm] publicEnv` only affects the final emit stage (the generated
    /// `env_public.rs`) — same class of input as `db_driver` (see this
    /// module's `compute_project_key` doc) — so a cached `EmittedProject`
    /// entry must never serve a stale `env_public.rs` after a `publicEnv`
    /// edit; this test is the tier-1 (project-key) proof of that.
    #[test]
    fn key_changes_with_wasm_public_env() {
        let (sources, injected) = sample_sources();
        let empty_allowlist = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        let with_allowlist = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &["API_BASE_URL".to_owned()],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        assert_ne!(
            empty_allowlist, with_allowlist,
            "the [wasm] publicEnv allowlist is part of the key"
        );
    }

    #[test]
    fn key_changes_with_entry_path() {
        let (sources, injected) = sample_sources();
        let a = compute_project_key(
            &sources,
            &injected,
            &["Main".to_owned()],
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        let b = compute_project_key(
            &sources,
            &injected,
            &["Other".to_owned()],
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        assert_ne!(a, b, "the entry module path is part of the key");
    }

    #[test]
    fn key_changes_with_module_add_and_remove() {
        let (sources, injected) = sample_sources();
        let base = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );

        let mut added = sources.clone();
        added.insert(
            vec!["Extra".to_owned()],
            (
                PathBuf::from("Extra.ipe"),
                "module Extra exposing (y)\ny = 2\n".to_owned(),
            ),
        );
        let with_extra = compute_project_key(
            &added,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        assert_ne!(base, with_extra, "adding a module must change the key");

        let mut removed = sources;
        removed.remove(&vec!["Ipe".to_owned(), "Basics".to_owned()]);
        let mut injected_without = injected;
        injected_without.remove(&vec!["Ipe".to_owned(), "Basics".to_owned()]);
        let without_basics = compute_project_key(
            &removed,
            &injected_without,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        assert_ne!(
            base, without_basics,
            "removing a module must change the key"
        );
    }

    #[test]
    fn key_changes_with_module_origin() {
        // Same path + text, different trust origin (injected vs. user) —
        // the design doc's module-identity axis. This can't happen through
        // the real driver (a path is injected or it isn't), but the key
        // function must still be sensitive to it: origin affects
        // canonicalisation (IPE-N0025), and the module doc's own "when in
        // doubt, include it" principle applies.
        let (sources, _injected) = sample_sources();
        let no_injection: BTreeSet<Vec<String>> = BTreeSet::new();
        let all_injected: BTreeSet<Vec<String>> = sources.keys().cloned().collect();
        let a = compute_project_key(
            &sources,
            &no_injection,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        let b = compute_project_key(
            &sources,
            &all_injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        assert_ne!(a, b, "the trust-origin flag is part of the key");
    }

    #[test]
    fn key_is_delimiter_collision_safe() {
        // ["AB", "C"] and ["A", "BC"] must NOT collide even though a naive
        // "join with no delimiter" scheme would produce the same bytes.
        let mut left = BTreeMap::new();
        left.insert(
            vec!["AB".to_owned(), "C".to_owned()],
            (PathBuf::from("x"), String::new()),
        );
        let mut right = BTreeMap::new();
        right.insert(
            vec!["A".to_owned(), "BC".to_owned()],
            (PathBuf::from("x"), String::new()),
        );
        let empty: BTreeSet<Vec<String>> = BTreeSet::new();
        let a = compute_project_key(
            &left,
            &empty,
            &[],
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        let b = compute_project_key(
            &right,
            &empty,
            &[],
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            ipe_backend_rust::BuildIntent::Development,
            false,
            false,
            false,
            None,
        );
        assert_ne!(a, b, "differently-segmented module paths must not collide");
    }

    #[cfg(unix)] // a cache hit needs a file identity check
    #[test]
    fn store_and_load_round_trip() {
        let dir = ipe_test_temp::temp_root().join(format!("ipe-cache-test-{}", std::process::id()));
        let cache_root = dir.join("cache-root-round-trip");
        let mut files = BTreeMap::new();
        files.insert(
            ipe_backend::RelPath::new("src/main.rs").expect("valid path"),
            "fn main() {}".to_owned(),
        );
        let project = EmittedProject {
            files,
            cargo_toml: "[package]\nname = \"x\"\n".to_owned(),
            uses_webview: false,
        };

        assert!(
            try_load(&explicit_site(&cache_root), "epoch-a", "key-a").is_none(),
            "empty cache misses"
        );
        store(&explicit_root(&cache_root), "epoch-a", "key-a", &project);
        let loaded = try_load(&explicit_site(&cache_root), "epoch-a", "key-a");
        assert_eq!(loaded, Some(project));

        // A different epoch or key must NOT see the stored entry — the
        // version-epoch/content-address separation is structural.
        assert!(try_load(&explicit_site(&cache_root), "epoch-b", "key-a").is_none());
        assert!(try_load(&explicit_site(&cache_root), "epoch-a", "key-b").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_load_treats_corrupt_entry_as_a_miss() {
        let dir = ipe_test_temp::temp_root()
            .join(format!("ipe-cache-test-corrupt-{}", std::process::id()));
        let cache_root = dir.join("cache-root-corrupt");
        let path = entry_file_path(&cache_root, "epoch", "key");
        fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir must succeed");
        fs::write(&path, b"not valid json at all {{{").expect("write must succeed");

        assert!(
            try_load(&explicit_site(&cache_root), "epoch", "key").is_none(),
            "corrupt entry must be discarded as a miss, never a panic or error propagation"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_load_treats_a_poisoned_relpath_entry_as_a_miss() {
        // Even a syntactically-valid JSON document with a semantically
        // unsafe `RelPath` key must be discarded, not partially trusted —
        // proven at the `ipe_backend` level (`emitted_project_deserialize_
        // rejects_a_poisoned_key`); this test proves the cache layer
        // inherits that rejection via `.ok()` rather than accidentally
        // routing around it.
        let dir = ipe_test_temp::temp_root()
            .join(format!("ipe-cache-test-poison-{}", std::process::id()));
        let cache_root = dir.join("cache-root-poison");
        let path = entry_file_path(&cache_root, "epoch", "key");
        fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir must succeed");
        fs::write(
            &path,
            br#"{"files":{"../../etc/passwd":"pwned"},"cargo_toml":""}"#,
        )
        .expect("write must succeed");

        assert!(try_load(&explicit_site(&cache_root), "epoch", "key").is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_cache_dir_respects_disable_and_override() {
        // Pure-function shape avoided here on purpose: `env_cache_dir` reads
        // process env, so this test only checks the UNSET default (the
        // env-mutation cases are exercised end-to-end in
        // `crates/ipe/src/lib.rs`'s cache integration tests via the
        // explicit-cache-dir seam, never via `std::env::set_var` — see that
        // module's doc for why).
        let out_dir = Path::new("/tmp/ipe-cache-dir-does-not-need-to-exist");
        let default = default_cache_site(out_dir);
        // The default sits under `<out>/.ipe-cache/` in a partition named by
        // the per-user salt — 64 hex digits a shipped cache cannot predict.
        if let Some(site) = &default {
            let in_output_with_hex_salt = match site {
                CacheSite::InOutput { out_dir: dir, salt } => {
                    dir.as_path() == out_dir
                        && salt.len() == 64
                        && salt.bytes().all(|b| b.is_ascii_hexdigit())
                }
                CacheSite::Explicit(_) => false,
            };
            assert!(
                in_output_with_hex_salt,
                "the default is `<out>/.ipe-cache/<hex salt>`, got {site:?}"
            );
        }
    }

    /// A claimed `out/` in a fresh scratch base, plus a directory outside it.
    fn claimed_out_and_elsewhere(tag: &str) -> (PathBuf, OwnedDir, PathBuf) {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe-cache-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let elsewhere = base.join("elsewhere");
        fs::create_dir_all(&elsewhere).expect("create the outside dir");
        let owned = OwnedDir::claim(&base.join("out")).expect("claim out");
        (base, owned, elsewhere)
    }

    fn in_output_site(owned: &OwnedDir) -> CacheSite {
        CacheSite::InOutput {
            out_dir: owned.path().to_path_buf(),
            salt: "salt".to_owned(),
        }
    }

    fn sample_project() -> EmittedProject {
        let mut files = BTreeMap::new();
        files.insert(
            ipe_backend::RelPath::new("src/main.rs").expect("valid path"),
            "fn main() {}".to_owned(),
        );
        EmittedProject {
            files,
            cargo_toml: "[package]\nname = \"x\"\n".to_owned(),
            uses_webview: false,
        }
    }

    fn plant_entry(path: &Path) {
        fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir planted entry");
        fs::write(
            path,
            serde_json::to_vec(&sample_project()).expect("serialize"),
        )
        .expect("plant entry");
    }

    /// Every entry below `dir`, recursively.
    fn tree(dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(next) = stack.pop() {
            for entry in fs::read_dir(&next).into_iter().flatten().flatten() {
                let path = entry.path();
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(path.clone());
                }
                found.push(path);
            }
        }
        found
    }

    /// A marked `out/` whose `.ipe-cache` is a planted link: the build keeps
    /// going uncached (the cache is advisory), and nothing is written or read
    /// through the link.
    #[test]
    fn in_output_cache_never_goes_through_a_planted_cache_dir_link() {
        let (base, owned, elsewhere) = claimed_out_and_elsewhere("dir-link");
        let link = owned.path().join(CACHE_DIR_NAME);
        crate::output_dir::test_links::plant_link(&elsewhere, &link);
        let site = in_output_site(&owned);
        let root = site.root(&owned).expect("root from the claimed dir");

        store(&root, "epoch", "key", &sample_project());
        assert!(
            tree(&elsewhere).is_empty(),
            "nothing may be written through the planted link"
        );
        assert!(
            fs::symlink_metadata(&link).is_ok_and(|m| m.file_type().is_symlink()),
            "the planted link is left as found"
        );

        plant_entry(&elsewhere.join("salt").join("epoch").join("key.json"));
        assert!(
            try_load(&site, "epoch", "key").is_none(),
            "an entry behind the planted link is never loaded"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// As above, with the link one level down, at the salt partition.
    #[test]
    fn in_output_cache_never_goes_through_a_planted_salt_link() {
        let (base, owned, elsewhere) = claimed_out_and_elsewhere("salt-link");
        let cache = owned.path().join(CACHE_DIR_NAME);
        fs::create_dir_all(&cache).expect("mkdir .ipe-cache");
        crate::output_dir::test_links::plant_link(&elsewhere, &cache.join("salt"));
        let site = in_output_site(&owned);
        let root = site.root(&owned).expect("root from the claimed dir");

        store(&root, "epoch", "key", &sample_project());
        assert!(
            tree(&elsewhere).is_empty(),
            "nothing may be written through the planted link"
        );

        plant_entry(&elsewhere.join("epoch").join("key.json"));
        assert!(
            try_load(&site, "epoch", "key").is_none(),
            "an entry behind the planted link is never loaded"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// A planted link at the entry file itself is a miss, never followed.
    #[test]
    fn in_output_load_refuses_a_linked_entry_file() {
        let (base, owned, elsewhere) = claimed_out_and_elsewhere("file-link");
        let planted = elsewhere.join("key.json");
        plant_entry(&planted);
        let epoch_dir = owned.path().join(CACHE_DIR_NAME).join("salt").join("epoch");
        fs::create_dir_all(&epoch_dir).expect("mkdir epoch");
        crate::output_dir::test_links::plant_link(&planted, &epoch_dir.join("key.json"));
        assert!(try_load(&in_output_site(&owned), "epoch", "key").is_none());
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)] // a cache hit needs a file identity check
    #[test]
    fn in_output_round_trip_stays_inside_the_claimed_dir() {
        let (base, owned, elsewhere) = claimed_out_and_elsewhere("round-trip");
        let site = in_output_site(&owned);
        let root = site.root(&owned).expect("root from the claimed dir");
        let project = sample_project();
        store(&root, "epoch", "key", &project);
        assert_eq!(try_load(&site, "epoch", "key"), Some(project));
        assert!(
            owned
                .path()
                .join(CACHE_DIR_NAME)
                .join("salt")
                .join("epoch")
                .join("key.json")
                .is_file()
        );
        assert!(tree(&elsewhere).is_empty());
        let _ = fs::remove_dir_all(&base);
    }

    /// An in-output epoch or key that is not one spelled name stores nothing.
    #[test]
    fn in_output_store_refuses_a_name_that_is_not_one_spelled_name() {
        let (base, owned, _) = claimed_out_and_elsewhere("spelled-store");
        let site = in_output_site(&owned);
        let root = site.root(&owned).expect("root from the claimed dir");
        store(&root, "ep/och", "key", &sample_project());
        store(&root, "epoch", "k/ey", &sample_project());
        assert!(
            tree(owned.path())
                .iter()
                .all(|p| !p.ends_with("key.json") && !p.ends_with("ey.json")),
            "a multi-level epoch or key writes no entry"
        );
        store(&root, "epoch", "key", &sample_project());
        assert!(
            owned
                .path()
                .join(CACHE_DIR_NAME)
                .join("salt")
                .join("epoch")
                .join("key.json")
                .is_file(),
            "one plain epoch and key are stored"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// An in-output site yields a writable root only from its own claimed dir.
    #[test]
    fn in_output_site_yields_no_root_from_another_claimed_dir() {
        let (base, owned, _) = claimed_out_and_elsewhere("other-dir");
        let site = CacheSite::InOutput {
            out_dir: base.join("not-out"),
            salt: "salt".to_owned(),
        };
        assert!(site.root(&owned).is_none());
        let _ = fs::remove_dir_all(&base);
    }

    /// An unmarked dir is not ipe's, so its cache is never read.
    #[test]
    fn in_output_load_needs_a_marked_output_dir() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe-cache-unmarked-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let out = base.join("out");
        plant_entry(
            &out.join(CACHE_DIR_NAME)
                .join("salt")
                .join("epoch")
                .join("key.json"),
        );
        let site = CacheSite::InOutput {
            out_dir: out,
            salt: "salt".to_owned(),
        };
        assert!(try_load(&site, "epoch", "key").is_none());
        let _ = fs::remove_dir_all(&base);
    }

    /// An in-output read misses while a claim is in flight and when the marker is a hard link.
    #[test]
    fn cache_read_misses_on_a_linked_marker_and_on_a_claim_in_flight() {
        let root =
            ipe_test_temp::temp_root().join(format!("ipe-cache-claiming-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("make root");
        let base = fs::canonicalize(&root).expect("canonicalize root");
        let out = base.join("out");
        crate::output_dir::OwnedDir::claim(&out).expect("claim out");
        let entry = out
            .join(CACHE_DIR_NAME)
            .join("salt")
            .join("epoch")
            .join("raw.txt");
        fs::create_dir_all(entry.parent().expect("entry dir")).expect("make entry dir");
        fs::write(&entry, "hit").expect("plant entry");
        let site = CacheSite::InOutput {
            out_dir: out.clone(),
            salt: "salt".to_owned(),
        };
        assert_eq!(site.read("epoch", "raw.txt").as_deref(), Some(&b"hit"[..]));

        let claim = out.join(crate::output_dir::CLAIM_FILE);
        fs::write(&claim, b"").expect("claim in flight");
        assert!(
            site.read("epoch", "raw.txt").is_none(),
            "a claim in flight is a miss"
        );
        fs::remove_file(&claim).expect("drop the claim");

        let marker = out.join(crate::output_dir::OWNERSHIP_MARKER);
        let aside = base.join("marker-aside");
        fs::rename(&marker, &aside).expect("move the marker aside");
        fs::hard_link(&aside, &marker).expect("link the marker back");
        assert!(
            site.read("epoch", "raw.txt").is_none(),
            "a hard-linked marker is a miss"
        );
        let _ = fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------
    // The lowered-IR cache tier
    // -----------------------------------------------------------------

    #[allow(clippy::too_many_lines)] // exhaustive `Module` literal (every `uses_*` flag)
    fn sample_ir_program(i: &mut Interner) -> ipe_diagnostics::DResult<Program> {
        use ipe_ir::{
            Arm, CallPin, Callee, EnumDef, Expr, Func, FuncId, IrType, KernelFn, Match, ModPath,
            Module, OnFormKind, Pat, TypeDef, Variant,
        };

        let msg_ty = i.intern("Msg")?;
        let inc = i.intern("Increment")?;
        let dec = i.intern("Decrement")?;
        let main_sym = i.intern("main")?;
        let main_mod = i.intern("Main")?;
        let msg_param = i.intern("msg")?;

        let body = Expr::Match(Match::new(
            Expr::Var(msg_param),
            vec![
                Arm::new(
                    Pat::Ctor {
                        home: ModPath(vec![]),
                        ty: msg_ty,
                        variant: inc,
                        args: vec![],
                    },
                    Expr::Call {
                        callee: Callee::Kernel(KernelFn::IoPrintln),
                        args: vec![],
                        pin: CallPin::None,
                        on_form: OnFormKind::NotForm,
                    },
                ),
                Arm::new(
                    Pat::Ctor {
                        home: ModPath(vec![]),
                        ty: msg_ty,
                        variant: dec,
                        args: vec![],
                    },
                    Expr::Call {
                        callee: Callee::Kernel(KernelFn::IoPrintln),
                        args: vec![],
                        pin: CallPin::None,
                        on_form: OnFormKind::NotForm,
                    },
                ),
            ],
            &[inc, dec],
        )?);

        Ok(Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    home: ModPath(vec![]),
                    name: msg_ty,
                    type_params: vec![],
                    variants: vec![
                        Variant {
                            name: inc,
                            fields: vec![],
                        },
                        Variant {
                            name: dec,
                            fields: vec![],
                        },
                    ],
                })],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: main_sym,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![(msg_param, IrType::Generic(msg_param))],
                    ret: IrType::Unit,
                    body,
                }],
                entry: Some(FuncId::from_raw(0)),
                records: vec![],
                uses_tea: false,
                uses_server: false,
                uses_http: false,
                uses_config: false,
                uses_compression: false,
                uses_csv: false,
                uses_cache: false,
                uses_encoding: false,
                uses_regex: false,
                uses_uuid: false,
                uses_random: false,
                uses_log: false,
                uses_decimal: false,
                uses_char_category: false,
                uses_crypto_core: false,
                uses_secret: false,
                uses_json: false,
                uses_crypto: false,
                uses_jwt: false,
                uses_url: false,
                uses_ui: false,
                uses_web: false,
                uses_tui: false,
                uses_console: false,
                uses_webview: false,
                uses_css: false,
                uses_auth: false,
                uses_principal: false,
                uses_websocket: false,
                uses_email: false,
                uses_locale: false,
                uses_time: false,
                uses_env_public: false,
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        })
    }

    #[test]
    fn compute_ir_key_is_deterministic_and_excludes_db_driver() {
        let (sources, injected) = sample_sources();
        let a = compute_ir_key(&sources, &injected, &entry(), ipe_ir::Target::Native);
        let b = compute_ir_key(&sources, &injected, &entry(), ipe_ir::Target::Native);
        assert_eq!(a, b, "same inputs must hash to the same IR key");

        // Unlike `compute_project_key`, `compute_ir_key` must be blind to
        // `db_driver` entirely — it isn't even a parameter, so there is
        // nothing to vary here; this test pins the SIGNATURE difference
        // itself (a `db_driver`-only rebuild reuses the SAME IR key).
        assert_eq!(
            compute_ir_key(&sources, &injected, &entry(), ipe_ir::Target::Native),
            a,
            "compute_ir_key has no db_driver parameter to vary"
        );
    }

    #[test]
    fn compute_ir_key_changes_with_source_text() {
        let (mut sources, injected) = sample_sources();
        let base = compute_ir_key(&sources, &injected, &entry(), ipe_ir::Target::Native);
        if let Some(main) = sources.get_mut(&vec!["Main".to_owned()]) {
            main.1.push_str("\n-- comment\n");
        }
        let edited = compute_ir_key(&sources, &injected, &entry(), ipe_ir::Target::Native);
        assert_ne!(base, edited, "a body edit must change the IR key");
    }

    #[cfg(unix)] // a cache hit needs a file identity check
    #[test]
    fn ir_store_and_load_round_trip_within_one_interner() -> ipe_diagnostics::DResult<()> {
        let mut plain = Interner::new();
        let program = sample_ir_program(&mut plain)?;
        let interner = Arc::new(Mutex::new(plain));

        let dir =
            ipe_test_temp::temp_root().join(format!("ipec-ir-cache-test-{}", std::process::id()));
        let cache_root = dir.join("cache-root-ir-round-trip");
        let _ = fs::remove_dir_all(&dir);

        assert!(
            try_load_ir(&explicit_site(&cache_root), "epoch-a", "key-a", &interner).is_none(),
            "empty cache misses"
        );
        store_ir(
            &explicit_root(&cache_root),
            "epoch-a",
            "key-a",
            &program,
            &interner,
        );
        let loaded = try_load_ir(&explicit_site(&cache_root), "epoch-a", "key-a", &interner);
        assert_eq!(loaded, Some(program));

        // Different epoch/key must not see the entry — same structural
        // separation as the `EmittedProject` tier.
        assert!(try_load_ir(&explicit_site(&cache_root), "epoch-b", "key-a", &interner).is_none());
        assert!(try_load_ir(&explicit_site(&cache_root), "epoch-a", "key-b", &interner).is_none());

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    /// **Cross-process id-drift proof, at the on-disk cache boundary.**
    /// Stores a `Program` written through one interner, then loads it
    /// through a COMPLETELY DIFFERENT, differently-polluted interner (the
    /// scenario a real `ipe dev build` -> `ipe dev build` sequence produces: a
    /// fresh `Interner::new()` per invocation). Asserts the relocated
    /// `Program`'s structural content (via `ipe_ir::pretty::pretty`,
    /// resolved-name comparison — not raw `Symbol` equality, which is not
    /// expected to survive the boundary) matches a Program built fresh in
    /// the reader's own, unrelated interner.
    #[cfg(unix)] // a cache hit needs a file identity check
    #[test]
    fn ir_cache_hit_survives_cross_process_symbol_id_drift() -> ipe_diagnostics::DResult<()> {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipec-ir-cache-drift-{}", std::process::id()));
        let cache_root = dir.join("cache-root-drift");
        let _ = fs::remove_dir_all(&dir);

        // "Process A" (the writer): noise, then build + store.
        let mut interner_a = Interner::new();
        for noise in ["foo", "bar", "baz", "qux"] {
            interner_a.intern(noise)?;
        }
        let program_a = sample_ir_program(&mut interner_a)?;
        let interner_a = Arc::new(Mutex::new(interner_a));
        store_ir(
            &explicit_root(&cache_root),
            "epoch",
            "key",
            &program_a,
            &interner_a,
        );

        // "Process B" (the reader): DIFFERENT noise, different count/order.
        let mut interner_b = Interner::new();
        for noise in ["zzz_1", "zzz_2"] {
            interner_b.intern(noise)?;
        }
        let interner_b = Arc::new(Mutex::new(interner_b));
        let program_b = try_load_ir(&explicit_site(&cache_root), "epoch", "key", &interner_b)
            .expect("must be a cache hit");

        // "Process C" (ground truth): independent construction, never
        // touches the cache at all.
        let mut interner_c = Interner::new();
        interner_c.intern("unrelated")?;
        let program_c = sample_ir_program(&mut interner_c)?;

        let dump_b = {
            let guard = interner_b
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ipe_ir::pretty(&program_b, &guard)
        };
        let dump_c = ipe_ir::pretty(&program_c, &interner_c);
        assert_eq!(
            dump_b, dump_c,
            "an IR-cache entry loaded through a differently-polluted \
             interner must be structurally/name-identical to a fresh, \
             never-cached construction"
        );
        assert!(dump_b.contains("Increment") && dump_b.contains("main"));

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn ir_try_load_treats_corrupt_entry_as_a_miss() {
        let dir = ipe_test_temp::temp_root()
            .join(format!("ipec-ir-cache-corrupt-{}", std::process::id()));
        let cache_root = dir.join("cache-root-corrupt");
        let path = ir_entry_file_path(&cache_root, "epoch", "key");
        fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir must succeed");
        fs::write(&path, b"not valid json at all {{{").expect("write must succeed");

        let interner = Arc::new(Mutex::new(Interner::new()));
        assert!(
            try_load_ir(&explicit_site(&cache_root), "epoch", "key", &interner).is_none(),
            "corrupt entry must be discarded as a miss, never a panic or error propagation"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// A poisoned `Symbol` text (would-be Rust-injection payload) inside an
    /// otherwise-valid-JSON IR cache entry must be rejected as a whole-entry
    /// miss — proving the on-disk boundary inherits `ipe_intern::Symbol`'s
    /// deserialize-time validation rather than accidentally routing around
    /// it (the same class of proof `try_load_treats_a_poisoned_relpath_
    /// entry_as_a_miss` gives for the `EmittedProject` tier).
    #[test]
    fn ir_try_load_treats_a_poisoned_symbol_entry_as_a_miss() {
        let dir =
            ipe_test_temp::temp_root().join(format!("ipec-ir-cache-poison-{}", std::process::id()));
        let cache_root = dir.join("cache-root-poison");
        let path = ir_entry_file_path(&cache_root, "epoch", "key");
        fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir must succeed");
        // A syntactically-valid `Program` shape whose module name embeds an
        // injection-shaped payload instead of a legal identifier.
        fs::write(
            &path,
            br#"{"modules":[{"name":["x; std::process::exit(1); //"],"types":[],"funcs":[],"entry":null,"records":[],"uses_tea":false,"uses_server":false,"uses_ui":false,"uses_web":false,"uses_tui":false,"uses_webview":false,"uses_css":false,"uses_auth":false}]}"#,
        )
        .expect("write must succeed");

        let interner = Arc::new(Mutex::new(Interner::new()));
        assert!(
            try_load_ir(&explicit_site(&cache_root), "epoch", "key", &interner).is_none(),
            "a poisoned Symbol text must be rejected — whole entry discarded, never partially trusted"
        );
        // The poisoned text must never have reached the interner.
        let resolved: Option<String> = {
            let guard = interner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard
                .resolve(ipe_intern::Symbol::from_raw(0))
                .map(str::to_owned)
        };
        assert!(
            resolved.is_none(),
            "a rejected symbol text must never be interned"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ir_env_extension_does_not_collide_with_emitted_project_tier() {
        // The two tiers must write to DIFFERENT files under the same
        // `(cache_root, epoch, key)` triple — proven structurally rather
        // than by inspection, so a future accidental filename collision
        // (one tier silently overwriting the other) is caught immediately.
        let cache_root = Path::new("/tmp/x");
        let a = entry_file_path(cache_root, "epoch", "key");
        let b = ir_entry_file_path(cache_root, "epoch", "key");
        assert_ne!(
            a, b,
            "the EmittedProject and lowered-IR tiers must use distinct file paths"
        );
    }

    /// A fetched tree containing a symlink is refused by its shape — the
    /// integrity hash never silently omits a tree entry.
    #[test]
    #[cfg(unix)]
    fn hash_tree_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-symlink-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        std::fs::write(base.join("file.ipe"), b"hello").expect("write file");
        symlink("/etc/passwd", base.join("link.ipe")).expect("create symlink");

        let result = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            matches!(
                result,
                Err(TreeHashError::Exceeded(LocalRefusal {
                    source: LocalSource::PackageTree,
                    limit: IngestLimit::Symlink,
                    name: None,
                }))
            ),
            "hash_tree must refuse a tree containing a symlink, got: {result:?}"
        );
    }

    /// A tree with only plain files hashes normally and produces the same
    /// result on a second call (deterministic, no symlinks → no rejection).
    #[test]
    fn hash_tree_plain_tree_is_deterministic() {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-plain-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        std::fs::write(base.join("Main.ipe"), b"module Main").expect("write file");

        let h1 = hash_tree(&base).expect("plain tree hashes ok");
        let h2 = hash_tree(&base).expect("plain tree hashes ok second time");
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(h1, h2, "hash_tree must be deterministic for plain trees");
    }

    /// One file under a fresh test root, `len` bytes long, for a per-file ceiling test.
    fn one_file_tree(tag: &str, len: usize) -> PathBuf {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        std::fs::write(base.join("File.ipe"), vec![b'a'; len]).expect("write file");
        base
    }

    /// A file one byte over the per-file ceiling is refused as a typed byte overrun.
    #[test]
    fn hash_tree_within_refuses_one_byte_over_a_small_ceiling() {
        let base = one_file_tree("over-small-cap", 17);
        let result = hash_tree_within(&base, &ceiling(64, 8, 16, 4));
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            matches!(result, Err(TreeHashError::Exceeded(refusal)) if refusal == refused(IngestLimit::Bytes(16)))
        );
    }

    /// A file exactly at the per-file ceiling hashes: the ceiling is inclusive.
    #[test]
    fn hash_tree_within_accepts_a_file_at_a_small_ceiling() {
        let base = one_file_tree("at-small-cap", 16);
        let result = hash_tree_within(&base, &ceiling(64, 8, 16, 4));
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            result.is_ok(),
            "a file exactly at the ceiling must hash, got: {result:?}"
        );
    }

    /// [`hash_tree`] holds each file to [`crate::remote_ingest::PACKAGE_FILE_MAX_BYTES`].
    ///
    /// The over-ceiling file is extended with `set_len`, never written: the
    /// refusal reads only its declared length, so the proof costs no 64 MiB write.
    #[test]
    fn hash_tree_uses_the_package_file_ceiling() {
        let cap = crate::remote_ingest::PACKAGE_FILE_MAX_BYTES;
        assert_eq!(PACKAGE_SOURCE.tree().per_file(), cap);

        let base = one_file_tree("package-cap", 0);
        std::fs::File::options()
            .write(true)
            .open(base.join("File.ipe"))
            .and_then(|file| file.set_len(cap + 1))
            .expect("extend file one byte past the package ceiling");
        let result = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            matches!(result, Err(TreeHashError::Exceeded(refusal)) if refusal == refused(IngestLimit::Bytes(cap)))
        );
    }

    /// A directory tree deeper than the production depth ceiling is refused as
    /// a typed depth overrun rather than recursing until the stack overflows.
    #[test]
    fn hash_tree_rejects_a_tree_over_the_depth_ceiling() {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-deep-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");

        let mut deep = base.clone();
        for _ in 0..=(crate::remote_ingest::PACKAGE_TREE_MAX_DEPTH + 1) {
            deep = deep.join("d");
        }
        std::fs::create_dir_all(&deep).expect("create deep tree");
        std::fs::write(deep.join("Leaf.ipe"), b"module Leaf\n").expect("write leaf");

        let result = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);

        assert!(matches!(
            result,
            Err(TreeHashError::Exceeded(LocalRefusal {
                source: LocalSource::PackageTree,
                limit: IngestLimit::Depth(crate::remote_ingest::PACKAGE_TREE_MAX_DEPTH),
                name: None,
            }))
        ));
    }

    /// A two-file, three-entry tree of 16 bytes: `a` (10 bytes), `sub/`, `sub/b` (6 bytes).
    fn capped_tree(tag: &str) -> PathBuf {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("sub")).expect("create tree");
        std::fs::write(base.join("a"), [b'a'; 10]).expect("write a");
        std::fs::write(base.join("sub").join("b"), [b'b'; 6]).expect("write b");
        base
    }

    /// A test tree ceiling; the pairing it must satisfy holds for every caller.
    fn ceiling(bytes: u64, entries: u64, per_file: u64, depth: u32) -> TreeCeiling {
        TreeCeiling::for_test(bytes, entries, per_file, depth).expect("paired tree ceiling")
    }

    /// The package-tree refusal `limit` names.
    const fn refused(limit: IngestLimit) -> LocalRefusal {
        LocalRefusal {
            source: LocalSource::PackageTree,
            limit,
            name: None,
        }
    }

    /// A file exactly at the per-file ceiling hashes; one byte under the
    /// largest file refuses the tree by that file's size.
    #[test]
    fn a_file_at_the_per_file_ceiling_hashes_and_one_past_is_refused() {
        let base = capped_tree("tree-per-file");
        let at = tree_hasher_within(&base, &ceiling(16, 3, 10, 8));
        let past = tree_hasher_within(&base, &ceiling(16, 3, 9, 8));
        let _ = std::fs::remove_dir_all(&base);
        assert!(at.is_ok(), "a file at the per-file ceiling must hash");
        assert!(
            matches!(past, Err(TreeHashError::Exceeded(refusal)) if refusal == refused(IngestLimit::Bytes(9)))
        );
    }

    /// A tree exactly as deep as its depth ceiling hashes; one level deeper is refused.
    #[test]
    fn a_tree_at_the_depth_ceiling_hashes_and_one_level_past_is_refused() {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-depth-edge-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let deep = base.join("d").join("d").join("d");
        std::fs::create_dir_all(&deep).expect("create deep tree");
        std::fs::write(deep.join("Leaf.ipe"), b"module Leaf\n").expect("write leaf");

        let at = tree_hasher_within(&base, &ceiling(64, 16, 64, 3));
        let past = tree_hasher_within(&base, &ceiling(64, 16, 64, 2));
        let _ = std::fs::remove_dir_all(&base);
        assert!(at.is_ok(), "a tree at the depth ceiling must hash");
        assert!(
            matches!(past, Err(TreeHashError::Exceeded(refusal)) if refusal == refused(IngestLimit::Depth(2)))
        );
    }

    /// A file name that is not UTF-8 is refused by its shape rather than
    /// dropped from the hash.
    #[test]
    #[cfg(unix)]
    fn hash_tree_refuses_a_non_utf8_name() {
        use std::os::unix::ffi::OsStrExt as _;

        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-non-utf8-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        let name = std::ffi::OsStr::from_bytes(b"bad\xff.ipe");
        std::fs::write(base.join(name), b"module Bad\n").expect("write non-UTF-8 name");

        let result = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            matches!(result, Err(TreeHashError::Exceeded(refusal)) if refusal == refused(IngestLimit::NonUtf8Name))
        );
    }

    /// A FIFO is refused by its shape rather than opened (which would block).
    #[cfg(unix)]
    fn make_fifo(path: &std::path::Path) {
        let made = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo must create the FIFO");
    }

    #[test]
    #[cfg(unix)]
    fn hash_tree_refuses_a_fifo() {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-fifo-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        make_fifo(&base.join("pipe.ipe"));

        let result = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            matches!(result, Err(TreeHashError::Exceeded(refusal)) if refusal == refused(IngestLimit::SpecialFile))
        );
    }

    /// A tree exactly at both cumulative ceilings hashes, and equals the unbounded hash.
    #[test]
    fn a_tree_at_its_cumulative_ceilings_hashes() {
        let base = capped_tree("tree-at-cap");
        let within = tree_hasher_within(&base, &ceiling(16, 3, 16, 8));
        let full = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            matches!((&within, &full), (Ok(_), Ok(_))),
            "a tree at its ceilings must hash"
        );
        let (Ok(within), Ok(full)) = (within, full) else {
            return;
        };
        assert_eq!(
            hex::encode(within.finalize()),
            full,
            "a tree at its ceilings must hash to the same value"
        );
    }

    /// A tree one byte past its cumulative byte ceiling is refused as a local-limit overrun.
    #[test]
    fn a_tree_one_byte_past_its_cumulative_ceiling_is_refused() {
        let base = capped_tree("tree-bytes-over");
        let result = tree_hasher_within(&base, &ceiling(15, 3, 15, 8));
        let _ = std::fs::remove_dir_all(&base);
        assert!(matches!(
            result,
            Err(TreeHashError::Exceeded(LocalRefusal {
                source: LocalSource::PackageTree,
                limit: IngestLimit::Bytes(15),
                name: None,
            }))
        ));
    }

    /// A tree one entry past its cumulative entry ceiling is refused as a local-limit overrun.
    #[test]
    fn a_tree_one_entry_past_its_cumulative_ceiling_is_refused() {
        let base = capped_tree("tree-entries-over");
        let result = tree_hasher_within(&base, &ceiling(16, 2, 16, 8));
        let _ = std::fs::remove_dir_all(&base);
        assert!(matches!(
            result,
            Err(TreeHashError::Exceeded(LocalRefusal {
                source: LocalSource::PackageTree,
                limit: IngestLimit::Entries(2),
                name: None,
            }))
        ));
    }

    /// `TreeDigest` finalized to hex MUST equal `hash_tree` byte-for-byte —
    /// the un-finalized hasher fed to sigstore's `verify_digest` finalizes to
    /// exactly the pinned tree hash, so the digest-binding check is over the
    /// same value the resolver hash-verifies.
    #[test]
    fn tree_hasher_finalized_equals_hash_tree() {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-hasher-eq-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        std::fs::create_dir_all(base.join("sub")).expect("create subdir");
        std::fs::write(base.join("Main.ipe"), b"module Main exposing (main)\n")
            .expect("write file");
        std::fs::write(base.join("sub").join("Helper.ipe"), b"module Helper\n")
            .expect("write nested file");

        let via_hasher = TreeDigest::of_tree_within(&base, PACKAGE_SOURCE.tree())
            .expect("digest ok")
            .to_hex();
        let via_hash_tree = hash_tree(&base).expect("hash_tree ok");
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            via_hasher, via_hash_tree,
            "TreeDigest::to_hex must equal hash_tree(t) exactly"
        );
    }

    /// A fresh test root holding `Main.ipe` and `sub/Helper.ipe`.
    fn two_file_tree(tag: &str) -> PathBuf {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("sub")).expect("create tree");
        std::fs::write(base.join("Main.ipe"), b"module Main exposing (main)\n")
            .expect("write file");
        std::fs::write(base.join("sub").join("Helper.ipe"), b"module Helper\n")
            .expect("write nested file");
        base
    }

    /// The held root of `base` and the files a walk of it lists.
    #[cfg(unix)]
    fn walked(base: &Path) -> (HeldDir, Vec<WalkedFile>) {
        let held = HeldDir::open_root(base).expect("hold the tree root");
        let files = walk_tree(&held, base, PACKAGE_SOURCE.tree()).expect("walk the tree");
        (held, files)
    }

    /// The digest of a fixed tree is a literal: hashing through held handles
    /// keeps the byte stream, so no pinned package hash moves.
    #[test]
    fn the_digest_of_a_fixed_tree_is_pinned() {
        let base = two_file_tree("pinned-digest");
        let digest = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(
            digest.expect("a plain tree hashes"),
            "167b37abffdcb99712c3a6b27bc51955e3aed6248c244f2059772190bb62d466"
        );
    }

    /// A file the walk listed, swapped for a symlink before it is opened, is
    /// refused as a link and yields no digest: the hash never reads a link's target.
    #[test]
    #[cfg(unix)]
    fn a_file_swapped_for_a_symlink_between_listing_and_open_is_refused() {
        let base = two_file_tree("swap-file-link");
        let outside = base.with_extension("outside");
        std::fs::write(&outside, b"a secret outside the tree").expect("write outside file");
        let (held, files) = walked(&base);
        std::fs::remove_file(base.join("Main.ipe")).expect("remove listed file");
        std::os::unix::fs::symlink(&outside, base.join("Main.ipe")).expect("plant link");

        let result = hash_walked(&held, &base, &files, PACKAGE_SOURCE.tree());
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_file(&outside);
        assert!(
            matches!(&result, Err(TreeHashError::Exceeded(refusal)) if *refusal == refused(IngestLimit::Symlink)),
            "a file swapped for a link after the walk must be refused as a link, got: {:?}",
            result.map(|_| ())
        );
    }

    /// A file the walk listed, swapped for a FIFO before it is opened, is
    /// refused as a special file without the open blocking on the FIFO.
    #[test]
    #[cfg(unix)]
    fn a_file_swapped_for_a_fifo_after_listing_is_refused_not_hung() {
        let base = two_file_tree("swap-file-fifo");
        let (held, files) = walked(&base);
        std::fs::remove_file(base.join("Main.ipe")).expect("remove listed file");
        make_fifo(&base.join("Main.ipe"));

        let (send, receive) = std::sync::mpsc::channel();
        let hashed_base = base.clone();
        std::thread::Builder::new()
            .spawn(move || {
                let result = hash_walked(&held, &hashed_base, &files, PACKAGE_SOURCE.tree());
                let _ = send.send(result.map(|_| ()));
            })
            .expect("spawn hashing thread");
        let answer = receive.recv_timeout(std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            matches!(&answer, Ok(Err(TreeHashError::Exceeded(refusal))) if *refusal == refused(IngestLimit::SpecialFile)),
            "a FIFO swapped in after the walk must be refused within five seconds, got: {answer:?}"
        );
    }

    /// A directory the walk listed, swapped for a symlink before its files are
    /// opened, is refused as a link rather than followed.
    #[test]
    #[cfg(unix)]
    fn a_dir_swapped_for_a_link_mid_walk_is_refused() {
        let base = two_file_tree("swap-dir-link");
        let aside = base.with_extension("aside");
        let _ = std::fs::remove_dir_all(&aside);
        let (held, files) = walked(&base);
        std::fs::rename(base.join("sub"), &aside).expect("move listed dir aside");
        std::os::unix::fs::symlink(&aside, base.join("sub")).expect("plant link");

        let result = hash_walked(&held, &base, &files, PACKAGE_SOURCE.tree());
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&aside);
        assert!(
            matches!(&result, Err(TreeHashError::Exceeded(refusal)) if *refusal == refused(IngestLimit::Symlink)),
            "a directory swapped for a link after the walk must be refused as a link, got: {:?}",
            result.map(|_| ())
        );
    }

    /// A plain cache entry below plain levels is read back.
    #[test]
    fn read_without_links_reads_a_plain_entry() {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-plain-entry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("a").join("b")).expect("create levels");
        std::fs::write(base.join("a").join("b").join("entry"), b"cached").expect("write entry");
        let read = read_without_links(&base, &["a", "b", "entry"], 64);
        let past_cap = read_without_links(&base, &["a", "b", "entry"], 5);
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(read.as_deref(), Some(&b"cached"[..]));
        assert_eq!(past_cap, None, "an entry one byte past its cap is a miss");
    }

    /// The file `name` of the held `base`, proven regular, with the length its proof saw.
    fn proven_file(base: &Path, name: &str) -> RegularFile {
        HeldDir::open_root(base)
            .expect("hold the base")
            .open_regular(&EntryName::new(std::ffi::OsStr::new(name)).expect("plain name"))
            .expect("open the regular file")
    }

    /// A file whose content stops matching the length its proof saw, by one
    /// byte more, by more than the read window holds, or by one byte less, is
    /// refused with the one size-change refusal, never hashed.
    #[test]
    fn a_file_that_changes_size_after_its_proof_is_refused() {
        use std::io::Write as _;
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-size-change-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        let path = base.join("File.ipe");
        let grow_by = |extra: usize| {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .and_then(|mut file| file.write_all(&vec![b'b'; extra]))
                .expect("grow the file");
        };
        let mut outcomes = Vec::new();
        for change in ["grow by one", "grow past the window", "shrink by one"] {
            std::fs::write(&path, b"module A\n").expect("write the file");
            let file = proven_file(&base, "File.ipe");
            match change {
                "grow by one" => grow_by(1),
                "grow past the window" => grow_by(TREE_HASH_CHUNK_BYTES.saturating_mul(2)),
                _ => std::fs::write(&path, b"module \n").expect("shrink the file"),
            }
            let mut buf = vec![0u8; TREE_HASH_CHUNK_BYTES];
            let result = hash_one_file(
                &mut Sha256::new(),
                file,
                "File.ipe",
                &path,
                &mut buf,
                0,
                PACKAGE_SOURCE.tree(),
            );
            outcomes.push((change, result));
        }
        let _ = std::fs::remove_dir_all(&base);
        for (change, result) in outcomes {
            let size_change = matches!(
                &result,
                Err(TreeHashError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::InvalidInput
                        && source.to_string().contains("changed size during hashing")
            );
            assert!(
                size_change,
                "{change}: must be refused as a size change, got: {:?}",
                result.map(|_| ())
            );
        }
    }

    /// The in-output cache reads only below the directory whose marker it
    /// checked: an output dir swapped, after it was held, for a link to (or
    /// a rename of) another marked dir holding the same entry is a miss.
    #[test]
    #[cfg(unix)]
    fn an_in_output_read_misses_when_the_held_output_dir_is_swapped() {
        let (base, owned, _elsewhere) = claimed_out_and_elsewhere("marked-swap");
        let other = OwnedDir::claim(&base.join("other")).expect("claim the other dir");
        let parts = [CACHE_DIR_NAME, "salt", "epoch", "entry"];
        let plant = |dir: &Path, bytes: &[u8]| {
            let level = dir.join(CACHE_DIR_NAME).join("salt").join("epoch");
            fs::create_dir_all(&level).expect("create entry levels");
            fs::write(level.join("entry"), bytes).expect("write entry");
        };
        plant(owned.path(), b"own");
        plant(other.path(), b"other");
        let out = owned.path().to_path_buf();
        let aside = base.join("aside");

        let marked = crate::output_dir::held::HeldDir::open(&out)
            .expect("hold out")
            .expect("out exists");
        let unswapped = read_in_owned(&marked, &parts, 64);
        fs::rename(&out, &aside).expect("move the held out dir aside");
        std::os::unix::fs::symlink(other.path(), &out).expect("plant a link at out");
        let through_link = read_in_owned(&marked, &parts, 64);
        fs::remove_file(&out).expect("remove the link");
        fs::rename(other.path(), &out).expect("rename the other dir onto out");
        let through_rename = read_in_owned(&marked, &parts, 64);
        let _ = fs::remove_dir_all(&base);

        assert_eq!(unswapped.as_deref(), Some(&b"own"[..]));
        assert_eq!(
            through_link, None,
            "an output dir swapped for a link after it was held must be a miss"
        );
        assert_eq!(
            through_rename, None,
            "an output dir replaced by another marked dir after it was held must be a miss"
        );
    }

    /// A symlink standing at any level below the base, the entry included, is a miss.
    #[test]
    #[cfg(unix)]
    fn read_without_links_misses_on_a_link_at_every_level() {
        let base = ipe_test_temp::temp_root().join(format!(
            "ipe-cache-test-link-levels-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let parts = ["a", "b", "entry"];
        for (depth, link_name) in parts.iter().enumerate() {
            let _ = std::fs::remove_dir_all(&base);
            let real = base.join("real");
            std::fs::create_dir_all(real.join("a").join("b")).expect("create real levels");
            std::fs::write(real.join("a").join("b").join("entry"), b"cached")
                .expect("write real entry");
            let linked = base.join("linked");
            let mut level = linked.clone();
            for part in parts.iter().take(depth) {
                level.push(part);
            }
            std::fs::create_dir_all(&level).expect("create linked levels");
            let mut target = real.clone();
            for part in parts.iter().take(depth + 1) {
                target.push(part);
            }
            std::os::unix::fs::symlink(&target, level.join(link_name)).expect("plant link");

            let through_real = read_without_links(&real, &parts, 64);
            let through_link = read_without_links(&linked, &parts, 64);
            let _ = std::fs::remove_dir_all(&base);
            assert_eq!(through_real.as_deref(), Some(&b"cached"[..]));
            assert_eq!(
                through_link, None,
                "a link at level {depth} must make the read a miss"
            );
        }
    }

    /// An epoch level swapped for a link after the write held it never writes through the link.
    #[cfg(unix)]
    #[test]
    fn write_entry_never_follows_an_epoch_swapped_for_a_link_mid_walk() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_cache_swap_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("cache");
        let victim = base.join("victim");
        fs::create_dir_all(root.join("e1")).expect("make epoch");
        fs::create_dir_all(&victim).expect("make victim");
        let level = root.join("e1");
        let (from, target) = (level.clone(), victim.clone());
        let mut swap = Some(move || {
            fs::rename(&from, from.with_extension("aside")).expect("move epoch aside");
            std::os::unix::fs::symlink(&target, &from).expect("plant link");
        });
        let held_at = level.clone();
        crate::output_dir::held::set_level_hook(Some(Box::new(move |held: &Path| {
            if held == held_at
                && let Some(swap) = swap.take()
            {
                swap();
            }
        })));
        write_entry(&root, "e1", "k.json", b"payload");
        crate::output_dir::held::set_level_hook(None);
        assert_eq!(
            fs::read_dir(&victim).expect("read victim").count(),
            0,
            "nothing reaches the link target"
        );
        assert_eq!(
            fs::read(level.with_extension("aside").join("k.json"))
                .ok()
                .as_deref(),
            Some(b"payload".as_slice()),
            "the write went through the held epoch handle"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// An empty epoch level junctioned in place after the write held it never writes through it.
    ///
    /// A held level cannot be renamed on this platform, only turned into a
    /// junction while empty.
    #[cfg(windows)]
    #[test]
    fn write_entry_never_follows_an_epoch_junctioned_in_place_mid_walk() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_cache_junction_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("cache");
        let victim = base.join("victim");
        fs::create_dir_all(root.join("e1")).expect("make epoch");
        fs::create_dir_all(&victim).expect("make victim");
        let level = root.join("e1");
        let (at, target) = (level.clone(), victim.clone());
        let mut swap = Some(move || {
            crate::output_dir::test_links::junction_in_place(&at, &target);
        });
        let held_at = level.clone();
        crate::output_dir::held::set_level_hook(Some(Box::new(move |held: &Path| {
            if held == held_at
                && let Some(swap) = swap.take()
            {
                swap();
            }
        })));
        write_entry(&root, "e1", "k.json", b"payload");
        crate::output_dir::held::set_level_hook(None);
        assert_eq!(
            fs::read_dir(&victim).expect("read victim").count(),
            0,
            "nothing reaches the junction target"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// An epoch or file name that is not one plain component is never written.
    #[test]
    fn write_entry_refuses_a_non_plain_name() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_cache_plain_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("cache");
        write_entry(&root, "../escape", "k.json", b"x");
        write_entry(&root, "e1", "../k.json", b"x");
        write_entry(&root, ".", "k.json", b"x");
        write_entry(&root, "", "k.json", b"x");
        write_entry(&root, "e1", "", b"x");
        write_entry(&root, "e\0", "k.json", b"x");
        write_entry(&root, "e1", "k\0.json", b"x");
        #[cfg(windows)]
        for (epoch, file_name) in [
            ("e1.", "k.json"),
            ("e1 ", "k.json"),
            ("NUL", "k.json"),
            ("e1", "k.json."),
            ("e1", "k.json "),
            ("e1", "con.json"),
            ("e1", "k.json:stream"),
        ] {
            write_entry(&root, epoch, file_name, b"x");
        }
        assert!(
            !base.join("escape").exists(),
            "a traversing epoch writes nothing"
        );
        assert!(
            !root.join("k.json").exists(),
            "a traversing file name writes nothing"
        );
        assert!(!root.exists(), "a refused write creates nothing");
        write_entry(&root, "e1", "k.json", b"x");
        assert_eq!(
            fs::read(root.join("e1").join("k.json")).ok().as_deref(),
            Some(b"x".as_slice()),
            "one plain epoch and file name are written"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// A read part that is not one spelled name misses, even where an entry of that name exists.
    #[test]
    fn a_read_part_that_is_not_one_spelled_name_misses() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_cache_spelled_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("cache");
        fs::create_dir_all(root.join("e1")).unwrap();
        fs::write(root.join("e1").join("k.json"), b"in").unwrap();
        fs::write(base.join("k.json"), b"out").unwrap();
        let refused: [&[&str]; 5] = [
            &["..", "k.json"],
            &["e1/k.json"],
            &[".", "e1", "k.json"],
            &["", "k.json"],
            &["e1", "k\0.json"],
        ];
        for parts in refused {
            assert_eq!(read_without_links(&root, parts, 64), None, "{parts:?}");
        }
        #[cfg(windows)]
        {
            let real = fs::canonicalize(&root).unwrap();
            fs::create_dir(real.join("e1.")).unwrap();
            fs::write(real.join("e1.").join("k.json"), b"dot").unwrap();
            fs::write(real.join("e1").join("k.json "), b"space").unwrap();
            for parts in [["e1.", "k.json"], ["e1", "k.json "]] {
                assert_eq!(read_without_links(&root, &parts, 64), None, "{parts:?}");
            }
        }
        assert_eq!(
            read_without_links(&root, &["e1", "k.json"], 64).as_deref(),
            Some(b"in".as_slice()),
            "one spelled epoch and file name are read"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// A cache entry one byte past the cap is a miss; one at the cap is read whole.
    #[test]
    fn a_cache_entry_past_the_cap_is_a_miss() {
        let base = ipe_test_temp::temp_root().join(format!("ipe_cache_cap_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("e1")).unwrap();
        fs::write(base.join("e1").join("at.json"), [b'x'; 8]).unwrap();
        fs::write(base.join("e1").join("over.json"), [b'x'; 9]).unwrap();
        #[cfg(unix)] // a cache hit needs a file identity check
        assert_eq!(
            read_without_links(&base, &["e1", "at.json"], 8),
            Some(vec![b'x'; 8]),
            "an entry at the cap is read whole"
        );
        assert_eq!(
            read_without_links(&base, &["e1", "over.json"], 8),
            None,
            "an entry past the cap is a miss"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// The write-side check agrees with the read cap at the boundary.
    #[test]
    fn only_an_entry_within_the_cap_fits() {
        assert!(within_cap(&[0; 8], 8), "at the cap fits");
        assert!(!within_cap(&[0; 9], 8), "one past the cap does not");
        assert!(within_cap(&[], 0), "an empty entry fits a zero cap");
    }

    /// A planted entry past the build-cache cap is never loaded through the site.
    #[test]
    fn a_planted_oversized_entry_is_never_loaded() {
        let base =
            ipe_test_temp::temp_root().join(format!("ipe_cache_oversized_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("e1")).unwrap();
        let file = fs::File::create(base.join("e1").join("big.json")).unwrap();
        file.set_len(crate::io_bounded::BUILD_CACHE_ENTRY_CAP + 1)
            .unwrap();
        drop(file);
        assert_eq!(
            explicit_site(&base).read("e1", "big.json"),
            None,
            "a sparse entry past the cap is a miss"
        );
        let _ = fs::remove_dir_all(&base);
    }
}
