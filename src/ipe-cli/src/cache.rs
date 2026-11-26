//! The on-disk build cache.
//!
//! Decision record: `docs/adr/0007-build-incrementality-and-release-infra.md`.
//!
//! Everything in-process is memoized, but nothing survives ACROSS process
//! invocations — every `ipe build` starts a cold [`ipe_db::IpeDatabase`].
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
//! give for `ipe build`'s actual use case (a cold-start cache hit skips
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
//! **Not yet ported**: `ipe watch`'s specific mid-session UX (hard-refuse a
//! REBUILD with `toolchain changed (was A, now B) — restart 'ipe watch'`
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
use ipe_intern::{Interner, SerdeInternerGuard};
use ipe_ir::Program;

use crate::output_dir::OwnedDir;
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

/// The maximum directory depth [`collect_files`] descends before refusing a tree
/// with a typed `InvalidInput` error. A published package source is never this
/// deep; an adversarial or accidentally unbounded tree is turned back rather than
/// exhausting the stack (mirroring `crate::project`'s `MAX_DISCOVERY_DEPTH`).
const MAX_TREE_DEPTH: usize = 64;

/// The maximum bytes a single file may contribute to the tree hash before it is
/// refused with a typed `InvalidInput` error. A `hash_tree` runs over a fetched,
/// still-untrusted git checkout, so attacker-supplied bytes must never be
/// materialized whole; a file over this ceiling is turned back rather than
/// allowed to exhaust memory. 64 MiB is far above any real published source file
/// while refusing a multi-GiB blob.
const MAX_HASHED_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The fixed chunk size the file bytes are streamed into the hasher in, so a
/// file's contribution never buffers more than one chunk at a time.
const TREE_HASH_CHUNK_BYTES: usize = 64 * 1024;

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
/// # Errors
/// Returns the failing path and its [`std::io::Error`] if the tree cannot be
/// walked or a file cannot be read.
pub fn hash_tree(root: &Path) -> Result<String, (PathBuf, std::io::Error)> {
    Ok(hex::encode(tree_hasher(root)?.finalize()))
}

/// Feed the identical deterministic byte stream [`hash_tree`] hashes into a fresh
/// [`Sha256`] and return the UN-finalized hasher.
///
/// [`hash_tree`] is exactly `hex(tree_hasher(root)?.finalize())` — the two share
/// this one byte stream so a tree hashes to a single value no matter which entry
/// point is used. The un-finalized hasher exists for a caller that must hand a
/// `Sha256` (not a hex digest) to an API that finalizes it itself — sigstore's
/// `verify_digest(input_digest: Sha256, …)`, which finalizes the hasher and, for
/// a DSSE bundle, compares `hex(input_digest.finalize())` against the bundle's
/// signed subject digest. Feeding this hasher binds that comparison to exactly
/// the pinned tree hash without re-deriving it from bytes twice.
///
/// # Errors
/// Returns the failing path and its [`std::io::Error`] if the tree cannot be
/// walked or a file cannot be read.
pub fn tree_hasher(root: &Path) -> Result<Sha256, (PathBuf, std::io::Error)> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    collect_files(root, root, &mut files, 0)?;
    // Sort by the relative path so the hash is independent of directory-read
    // order (which the OS does not guarantee).
    files.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    update_len_prefixed(&mut hasher, TREE_TAG);
    let count = u64::try_from(files.len()).unwrap_or(u64::MAX);
    hasher.update(count.to_le_bytes());
    // One reusable chunk buffer for the whole tree — the hashed byte stream is
    // identical to a per-file allocation, since every file streams through the
    // same fixed-size window.
    let mut buf = vec![0u8; TREE_HASH_CHUNK_BYTES];
    for (rel, abs) in &files {
        update_str(&mut hasher, rel);
        hash_one_file(&mut hasher, rel, abs, &mut buf)?;
    }
    Ok(hasher)
}

/// Stream one file's bytes into `hasher` with an explicit little-endian
/// length prefix (matching [`update_len_prefixed`]'s framing), refusing past
/// [`MAX_HASHED_FILE_BYTES`] with a typed `InvalidInput` error before the read
/// can exhaust memory.
///
/// The length prefix is derived from the file's metadata size and re-checked
/// against the bytes actually read, so a file that grows between `stat` and the
/// final read (a race an attacker controls) is refused rather than framed with a
/// stale, mismatched length that would corrupt the integrity hash.
///
/// `buf` is a caller-owned scratch chunk reused across every file in a tree; its
/// length is the streaming window and its contents on entry are irrelevant.
fn hash_one_file(
    hasher: &mut Sha256,
    rel: &str,
    abs: &Path,
    buf: &mut [u8],
) -> Result<(), (PathBuf, std::io::Error)> {
    use std::io::Read as _;

    let file = fs::File::open(abs).map_err(|e| (abs.to_path_buf(), e))?;
    let declared_len = file.metadata().map_err(|e| (abs.to_path_buf(), e))?.len();
    if declared_len > MAX_HASHED_FILE_BYTES {
        return Err((abs.to_path_buf(), file_too_large_error(rel, declared_len)));
    }

    hasher.update(declared_len.to_le_bytes());

    let mut reader = file.take(declared_len);
    let mut total: u64 = 0;
    loop {
        let n = reader.read(buf).map_err(|e| (abs.to_path_buf(), e))?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        let chunk = buf.get(..n).ok_or_else(|| {
            (
                abs.to_path_buf(),
                std::io::Error::other("short read reported more bytes than the buffer holds"),
            )
        })?;
        hasher.update(chunk);
    }

    if total != declared_len {
        return Err((
            abs.to_path_buf(),
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "file `{rel}` changed size during hashing (declared {declared_len} bytes, \
                     read {total})"
                ),
            ),
        ));
    }
    Ok(())
}

fn file_too_large_error(rel: &str, size: u64) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "file `{rel}` is {size} bytes, over the {MAX_HASHED_FILE_BYTES}-byte per-file \
             ceiling for a hashed package source tree"
        ),
    )
}

/// Depth-first collect every regular file under `dir` as `(relative_path,
/// absolute_path)`, with the relative path expressed in forward slashes so the
/// hash is identical across platforms.
///
/// Hidden (dot-prefixed) directories are skipped. These hold VCS and local
/// tooling metadata — `.git`, a code indexer's `.tokensave`, an editor's
/// `.vscode`/`.idea` — never a package's published source, which lives in named
/// directories. Excluding them keeps the content hash a function of the source
/// alone, so a fetched checkout hashes identically no matter what local tools
/// have dropped a scratch directory into it.
///
/// Symlinks are rejected with an `InvalidInput` error. A published package
/// source must contain only plain files and directories; symlinks cannot be
/// integrity-checked safely without following them (which opens TOCTOU and
/// path-escape hazards), so we fail-closed rather than silently omitting them
/// from the hash (which would leave them invisible to the integrity check).
///
/// A tree deeper than [`MAX_TREE_DEPTH`] is refused with an `InvalidInput`
/// error, bounding the recursion so a pathological tree cannot exhaust the
/// stack.
fn collect_files(
    base: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
    depth: usize,
) -> Result<(), (PathBuf, std::io::Error)> {
    if depth > MAX_TREE_DEPTH {
        return Err((
            dir.to_path_buf(),
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "directory tree exceeded the {MAX_TREE_DEPTH}-level depth ceiling for a \
                     hashed package source tree"
                ),
            ),
        ));
    }
    let entries = fs::read_dir(dir).map_err(|e| (dir.to_path_buf(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| (dir.to_path_buf(), e))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| (path.clone(), e))?;
        if file_type.is_symlink() {
            return Err((
                path,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "symlinks are not permitted in a published package source tree",
                ),
            ));
        } else if file_type.is_dir() {
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.'))
            {
                continue;
            }
            collect_files(base, &path, out, depth + 1)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect::<Vec<_>>()
                .join("/");
            out.push((rel, path));
        }
    }
    Ok(())
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
    production: bool,
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

    // `ipe release` rejects any `Debug.*` use (IPE-L0140), so its outcome
    // differs from a development build for a Debug-using program (error vs
    // emitted project). Keying on it keeps the two builds' cache entries
    // disjoint — a dev-cached project is never served to a release build, and
    // vice versa. (For a Debug-free program the emitted bytes are identical
    // either way; the extra key bit only costs a one-time cold entry.)
    hasher.update([u8::from(production)]);

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
/// `toolchain_fingerprint()`. `None` when `rustc` is not on `PATH` or exits
/// non-zero.
fn toolchain_fingerprint_hash() -> Option<String> {
    let output = std::process::Command::new("rustc")
        .arg("-vV")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(&output.stdout);
    Some(hex::encode(hasher.finalize()))
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
    /// An in-output entry is read only from a marked, non-symlink output dir;
    /// every level below it (and below an explicit root) is lstat'd, and a
    /// symlink anywhere is a miss.
    fn read(&self, epoch: &str, file_name: &str) -> Option<Vec<u8>> {
        match self {
            Self::InOutput { out_dir, salt } => {
                let meta = fs::symlink_metadata(out_dir).ok()?;
                let owned =
                    meta.is_dir() && crate::output_dir::has_marker(out_dir).unwrap_or(false);
                if !owned {
                    return None;
                }
                read_without_links(out_dir, &[CACHE_DIR_NAME, salt.as_str(), epoch, file_name])
            }
            Self::Explicit(dir) => read_without_links(dir, &[epoch, file_name]),
        }
    }
}

impl CacheRoot {
    /// Best-effort write of entry `file_name` under `epoch`.
    ///
    /// Every failure is swallowed, a refused symlink included.
    fn write(&self, epoch: &str, file_name: &str, bytes: &[u8]) {
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

/// Read `base/<parts...>` when each part is one plain name and no level is a symlink.
///
/// The opened file must be the regular file the lstat saw, so a link swapped
/// in after the check is a miss too.
fn read_without_links(base: &Path, parts: &[&str]) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let mut path = base.to_path_buf();
    let mut seen = None;
    for part in parts {
        let mut components = Path::new(part).components();
        if !matches!(
            (components.next(), components.next()),
            (Some(std::path::Component::Normal(_)), None)
        ) {
            return None;
        }
        path.push(part);
        let meta = fs::symlink_metadata(&path).ok()?;
        if meta.file_type().is_symlink() {
            return None;
        }
        seen = Some(meta);
    }
    let seen = seen.filter(fs::Metadata::is_file)?;
    let mut file =
        crate::io_bounded::open_regular(&path, crate::io_bounded::FinalLink::Refuse).ok()?;
    let opened = file.metadata().ok()?;
    if !same_file(&seen, &opened) {
        return None;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// Whether two metadata records name the same file.
#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// No stable file identity in a metadata record here, so never the same file: the cache runs cold.
#[cfg(windows)]
const fn same_file(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    false
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
/// read back, only through a handle proven owner-only by
/// [`crate::secret_file`]. A symlink, a malformed file, a file another user
/// could read, a directory another user can write, or a host that cannot keep
/// the file owner-only yields `None` (the default cache is then disabled),
/// never a salt another user could read or an attacker could have chosen.
fn user_cache_salt() -> Option<String> {
    let home = crate::runtime_embed::ipe_home().ok()?;
    let path = home.join("build-cache-salt");
    if fs::symlink_metadata(&path).is_ok() {
        return read_salt(&path);
    }
    crate::secret_file::create_owner_dir(crate::secret_file::HOST_SECRET_STORE, &home).ok()?;
    create_salt(&path)
}

/// The most bytes read from a salt file: its hex digits plus trailing whitespace.
const SALT_READ_CAP: u64 = 128;

/// The salt stored at `path`, read through a handle proven owner-only.
///
/// `None` when the file is absent, not private to the invoking user, or not
/// exactly [`SALT_BYTES`] hex-encoded bytes.
fn read_salt(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let file =
        crate::secret_file::open_existing(crate::secret_file::HOST_SECRET_STORE, path).ok()?;
    let mut text = String::new();
    file.take(SALT_READ_CAP).read_to_string(&mut text).ok()?;
    let text = text.trim().to_owned();
    (text.len() == SALT_BYTES * 2 && text.bytes().all(|b| b.is_ascii_hexdigit())).then_some(text)
}

/// Create a fresh salt at the unused name `path`, durable before it is used.
///
/// A salt file left half-written is removed. A concurrent first build that
/// won the race to create `path` supplies the salt instead.
fn create_salt(path: &Path) -> Option<String> {
    use std::io::Write as _;
    let mut bytes = [0u8; SALT_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    let salt = hex::encode(bytes);
    match crate::secret_file::create_new(crate::secret_file::HOST_SECRET_STORE, path) {
        Ok(mut file) => {
            let written = file
                .write_all(salt.as_bytes())
                .and_then(|()| file.sync_all());
            drop(file);
            if written.is_err() {
                let _ = fs::remove_file(path);
                return None;
            }
            Some(salt)
        }
        Err(crate::secret_file::SecretFileError::Io(e))
            if e.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            read_salt(path)
        }
        Err(_) => None,
    }
}

/// Whether `part` is one plain path component, never a separator, `..` or `.`.
fn is_plain_name(part: &str) -> bool {
    let mut components = Path::new(part).components();
    matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(name)), None) if name == std::ffi::OsStr::new(part)
    )
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
    use std::io::Write as _;
    if !is_plain_name(epoch) || !is_plain_name(file_name) || fs::create_dir_all(cache_root).is_err()
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
/// rename) so a concurrent reader (a second `ipe build` racing this one)
/// never observes a partially-written entry; a torn read is impossible, a
/// missing-then-appearing file is the only visible race, which `try_load`
/// already treats as an ordinary miss.
///
/// The tmp file name is unique to this process, so two concurrent
/// `ipe build` invocations computing the same key never write to the same
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

    /// A fresh, empty scratch directory for one salt test.
    #[cfg(unix)]
    fn salt_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ipe-cache-salt-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[cfg(unix)]
    #[test]
    fn a_created_salt_is_owner_only_and_read_back() {
        let dir = salt_test_dir("roundtrip");
        let path = dir.join("build-cache-salt");
        let created = create_salt(&path);
        assert!(
            created
                .as_ref()
                .is_some_and(|salt| salt.len() == SALT_BYTES * 2),
            "a fresh salt must be created: {created:?}"
        );
        assert_eq!(read_salt(&path), created, "the salt reads back unchanged");
        assert_eq!(
            create_salt(&path),
            created,
            "a lost creation race reuses the winner's salt"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_salt_another_user_could_read_or_a_symlink_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = salt_test_dir("refused");
        let path = dir.join("build-cache-salt");
        let created = create_salt(&path);
        assert!(created.is_some(), "a fresh salt must be created");
        for mode in [0o644, 0o640] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod salt");
            assert_eq!(
                read_salt(&path),
                None,
                "a mode-{mode:o} salt must be refused"
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod salt");
        let link = dir.join("linked-salt");
        std::os::unix::fs::symlink(&path, &link).expect("plant symlink");
        assert_eq!(read_salt(&link), None, "a symlinked salt must be refused");
        let malformed = dir.join("malformed-salt");
        assert!(
            create_salt(&malformed).is_some(),
            "create a salt to corrupt"
        );
        fs::write(&malformed, "not hex").expect("corrupt salt");
        assert_eq!(read_salt(&malformed), None, "a malformed salt is refused");
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
            false,
            false,
            false,
            None,
        );
        assert_ne!(sqlite, postgres, "the SQL driver is part of the key");
    }

    /// `ipe release` rejects any `Debug.*` use (IPE-L0140), so its outcome
    /// differs from a development build for a Debug-using program. The key must
    /// separate the two so a dev-cached project is never served to a release
    /// build (or vice versa) — the tier-1 proof of the emit demand's
    /// production gate.
    #[test]
    fn key_changes_with_production() {
        let (sources, injected) = sample_sources();
        let dev = compute_project_key(
            &sources,
            &injected,
            &entry(),
            DbDriver::Sqlite,
            ipe_ir::Target::Native,
            &[],
            false,
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
            true,
            false,
            false,
            false,
            None,
        );
        assert_ne!(dev, prod, "the production flag is part of the key");
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
                false,
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
            false,
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
            false,
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
                false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
        let dir = std::env::temp_dir().join(format!("ipe-cache-test-{}", std::process::id()));
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
        let dir =
            std::env::temp_dir().join(format!("ipe-cache-test-corrupt-{}", std::process::id()));
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
        let dir =
            std::env::temp_dir().join(format!("ipe-cache-test-poison-{}", std::process::id()));
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
        let base = std::env::temp_dir().join(format!("ipe-cache-{tag}-{}", std::process::id()));
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
        let base = std::env::temp_dir().join(format!("ipe-cache-unmarked-{}", std::process::id()));
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

        let dir = std::env::temp_dir().join(format!("ipec-ir-cache-test-{}", std::process::id()));
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
    /// scenario a real `ipe build` -> `ipe build` sequence produces: a
    /// fresh `Interner::new()` per invocation). Asserts the relocated
    /// `Program`'s structural content (via `ipe_ir::pretty::pretty`,
    /// resolved-name comparison — not raw `Symbol` equality, which is not
    /// expected to survive the boundary) matches a Program built fresh in
    /// the reader's own, unrelated interner.
    #[cfg(unix)] // a cache hit needs a file identity check
    #[test]
    fn ir_cache_hit_survives_cross_process_symbol_id_drift() -> ipe_diagnostics::DResult<()> {
        let dir = std::env::temp_dir().join(format!("ipec-ir-cache-drift-{}", std::process::id()));
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
        let dir =
            std::env::temp_dir().join(format!("ipec-ir-cache-corrupt-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("ipec-ir-cache-poison-{}", std::process::id()));
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

    /// A fetched tree containing a symlink must be rejected — the integrity
    /// hash must never silently omit a tree entry.
    #[test]
    #[cfg(unix)]
    fn hash_tree_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
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
            result.is_err(),
            "hash_tree must reject a tree containing a symlink"
        );
        let (_, err) = result.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "symlink rejection must use InvalidInput"
        );
    }

    /// A tree with only plain files hashes normally and produces the same
    /// result on a second call (deterministic, no symlinks → no rejection).
    #[test]
    fn hash_tree_plain_tree_is_deterministic() {
        let base = std::env::temp_dir().join(format!(
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

    /// A single file over [`MAX_HASHED_FILE_BYTES`] must be refused with a typed
    /// `InvalidInput` error rather than materialized whole in memory — the `DoS`
    /// ceiling on a fetched, still-untrusted checkout.
    #[test]
    fn hash_tree_rejects_a_file_over_the_per_file_ceiling() {
        let base = std::env::temp_dir().join(format!(
            "ipe-cache-test-bigfile-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        // One byte over the ceiling — proves the boundary, not a multi-GiB write.
        let over = usize::try_from(MAX_HASHED_FILE_BYTES).expect("cap fits usize") + 1;
        std::fs::write(base.join("Big.ipe"), vec![b'a'; over]).expect("write oversized file");

        let result = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);

        let (_, err) = result.expect_err("a file over the ceiling must be refused");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "an oversized file must be refused with InvalidInput"
        );
    }

    /// A file exactly at [`MAX_HASHED_FILE_BYTES`] must still hash (the ceiling
    /// is inclusive — a file at the cap succeeds, one byte over fails).
    #[test]
    fn hash_tree_accepts_a_file_at_the_per_file_ceiling() {
        let base = std::env::temp_dir().join(format!(
            "ipe-cache-test-atcap-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");
        let at = usize::try_from(MAX_HASHED_FILE_BYTES).expect("cap fits usize");
        std::fs::write(base.join("AtCap.ipe"), vec![b'a'; at]).expect("write file at cap");

        let result = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);

        assert!(
            result.is_ok(),
            "a file exactly at the ceiling must hash, got: {result:?}"
        );
    }

    /// A directory tree deeper than [`MAX_TREE_DEPTH`] must be refused with a
    /// typed `InvalidInput` error rather than recursing until the stack
    /// overflows.
    #[test]
    fn hash_tree_rejects_a_tree_over_the_depth_ceiling() {
        let base = std::env::temp_dir().join(format!(
            "ipe-cache-test-deep-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("create base");

        let mut deep = base.clone();
        for _ in 0..=(MAX_TREE_DEPTH + 1) {
            deep = deep.join("d");
        }
        std::fs::create_dir_all(&deep).expect("create deep tree");
        std::fs::write(deep.join("Leaf.ipe"), b"module Leaf\n").expect("write leaf");

        let result = hash_tree(&base);
        let _ = std::fs::remove_dir_all(&base);

        let (_, err) = result.expect_err("a tree over the depth ceiling must be refused");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "an over-deep tree must be refused with InvalidInput"
        );
    }

    /// `tree_hasher` finalized to hex MUST equal `hash_tree` byte-for-byte —
    /// the un-finalized hasher fed to sigstore's `verify_digest` finalizes to
    /// exactly the pinned tree hash, so the digest-binding check is over the
    /// same value the resolver hash-verifies.
    #[test]
    fn tree_hasher_finalized_equals_hash_tree() {
        let base = std::env::temp_dir().join(format!(
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

        let via_hasher = hex::encode(tree_hasher(&base).expect("hasher ok").finalize());
        let via_hash_tree = hash_tree(&base).expect("hash_tree ok");
        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            via_hasher, via_hash_tree,
            "hex(tree_hasher(t).finalize()) must equal hash_tree(t) exactly"
        );
    }

    /// An epoch level swapped for a link after the write held it never writes through the link.
    #[cfg(unix)]
    #[test]
    fn write_entry_never_follows_an_epoch_swapped_for_a_link_mid_walk() {
        let base = std::env::temp_dir().join(format!("ipe_cache_swap_{}", std::process::id()));
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
        let base = std::env::temp_dir().join(format!("ipe_cache_junction_{}", std::process::id()));
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
        let base = std::env::temp_dir().join(format!("ipe_cache_plain_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = base.join("cache");
        write_entry(&root, "../escape", "k.json", b"x");
        write_entry(&root, "e1", "../k.json", b"x");
        write_entry(&root, ".", "k.json", b"x");
        assert!(
            !base.join("escape").exists(),
            "a traversing epoch writes nothing"
        );
        assert!(
            !root.join("k.json").exists(),
            "a traversing file name writes nothing"
        );
        assert!(!root.exists(), "a refused write creates nothing");
        let _ = fs::remove_dir_all(&base);
    }
}
