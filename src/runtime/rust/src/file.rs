// File kernel stubs — generic over E.
//
// Every path argument is a typed [`crate::path::Path`], not a raw `String`:
// the `Ipe.File` surface is sealed so a caller CANNOT reach a filesystem
// syscall with an unvalidated string. Construction (and the traversal / NUL
// rejection that guards it) lives once in `path::path_from_string`; each kernel
// here unwraps the already-validated `Path` to its cleaned string via
// `.into_string()` and proceeds — it never re-validates, because the type is
// the proof.
use super::path::{OsOrigin, Path, from_os, join_entry, name_from_os};
use super::{IpeError, IpeResult, IpeTask, from_u8_slice, ok_res, str_err};

// ── shared blocking-pool helper ───────────────────────────────────────
//
// Every kernel in this module does a blocking `std::fs` syscall inside its
// `Box::pin(async move { ... })` body. On a tokio worker thread (the shape
// every generated Ipe.Web/Ipe.Http.Server/Ipe.Console/Ipe.Tui app runs under),
// a blocking syscall stalls that worker for its full duration — reactor
// starvation under concurrent load, or a real multi-second stall on a
// slow/network filesystem. `run_blocking` offloads the closure to tokio's
// blocking-thread pool via `spawn_blocking`, mirroring the pattern already
// used by `auth.rs` for bcrypt (`auth_register`/`auth_login`/`auth_set_role`).
//
// Feature-gating note: `pub mod file;` (`mod.rs`) is UNCONDITIONAL — unlike
// `compression.rs`, which is gated on a `compression` feature that always
// pulls in `tokio` — while `tokio` itself is an `optional = true` dependency.
// The main CI clippy job (`cargo clippy --all-targets --workspace`) builds
// with the crate's `default = []` features, i.e. `tokio` NOT enabled, so an
// unconditional `tokio::task::spawn_blocking` reference here would break that
// job. Every REAL generated Ipê project always has `tokio` (`Task.run`/
// `block_on` need it regardless of which kernels are used — see
// `tests/golden/basics/Cargo.toml`), so the `#[cfg(not(feature = "tokio"))]`
// fallback below only matters for the standalone `ipe-runtime-rust` crate's
// own narrow-feature builds, never for a real Ipê program. See
// `docs/adr/0003-security-render-and-data-access-invariants.md` §2.2.
// tokio is native-only (declared under the `cfg(not(target_arch = "wasm32"))`
// dependency table), so the `spawn_blocking` offload compiles only there. On
// wasm32 the synchronous fallback runs even when `feature = "tokio"` is set —
// the browser has no blocking-thread pool to offload to.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
async fn run_blocking<T, Er, F>(f: F) -> Result<T, Er>
where
    F: FnOnce() -> Result<T, Er> + Send + 'static,
    T: Send + 'static,
    Er: From<String> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(_) => Err(Er::from("background file task panicked".to_string())),
    }
}

#[cfg(any(not(feature = "tokio"), target_arch = "wasm32"))]
// `async` is required here to match the tokio variant's signature; callers
// always use `.await` to work with both feature configurations uniformly.
#[allow(clippy::unused_async)]
async fn run_blocking<T, Er, F>(f: F) -> Result<T, Er>
where
    F: FnOnce() -> Result<T, Er> + Send + 'static,
    T: Send + 'static,
    Er: From<String> + Send + 'static,
{
    f()
}

/// Default `File.readFile` ceiling in bytes, applied only when `IPE_FILE_READ_MAX` is unset.
pub const READ_FILE_DEFAULT_CEILING: u64 = 512 * 1024 * 1024;

/// Fixed `File.readFileBytes` ceiling in bytes.
///
/// Lower than the text ceiling because each input byte materialises as an
/// eight-byte `i64`.
const READ_FILE_BYTES_CEILING: u64 = 10 * 1024 * 1024;

/// Longest prefix of a malformed `IPE_FILE_READ_MAX` value echoed in its refusal.
const READ_CEILING_SHOWN_CHARS: usize = 32;

/// The operator's `IPE_FILE_READ_MAX` setting, parsed once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadCeiling {
    /// The variable is absent; `READ_FILE_DEFAULT_CEILING` applies.
    Unset,
    /// An explicit byte ceiling; `0` refuses every non-empty file.
    Bytes(u64),
}

impl ReadCeiling {
    const fn bytes(self) -> u64 {
        match self {
            Self::Unset => READ_FILE_DEFAULT_CEILING,
            Self::Bytes(n) => n,
        }
    }
}

/// Parses the raw `IPE_FILE_READ_MAX` lookup into a ceiling.
///
/// Only an absent variable yields the default. A present value must be a plain
/// decimal byte count (`0` included); anything else — empty, signed, padded,
/// suffixed, overflowing, non-Unicode — is a refusal, so a typo never widens
/// the ceiling.
fn parse_read_ceiling(raw: Result<String, std::env::VarError>) -> Result<ReadCeiling, String> {
    let shown = match raw {
        Err(std::env::VarError::NotPresent) => return Ok(ReadCeiling::Unset),
        Err(std::env::VarError::NotUnicode(os)) => shown_env_value(os.as_encoded_bytes()),
        Ok(v) => {
            if !v.is_empty()
                && v.bytes().all(|b| b.is_ascii_digit())
                && let Ok(n) = v.parse::<u64>()
            {
                return Ok(ReadCeiling::Bytes(n));
            }
            shown_env_value(v.as_bytes())
        }
    };
    Err(format!(
        "IPE_FILE_READ_MAX must be a decimal byte count (got \"{shown}\")"
    ))
}

/// Renders a refused environment value for its error text without losing or
/// smuggling a byte: valid UTF-8 keeps its printable characters and escapes
/// every other one (`char::escape_debug` — controls, ESC, CR/LF, bidi
/// overrides, `"` and `\`), and each byte that is not UTF-8 shows as `\xNN`.
/// At most `READ_CEILING_SHOWN_CHARS` source characters or bytes are shown.
fn shown_env_value(raw: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let mut budget = READ_CEILING_SHOWN_CHARS;
    for chunk in raw.utf8_chunks() {
        for c in chunk.valid().chars() {
            let Some(left) = budget.checked_sub(1) else {
                return out;
            };
            budget = left;
            out.extend(c.escape_debug());
        }
        for b in chunk.invalid() {
            let Some(left) = budget.checked_sub(1) else {
                return out;
            };
            budget = left;
            let _ = write!(out, "\\x{b:02X}");
        }
    }
    out
}

/// Resolves the `File.readFile` ceiling from `IPE_FILE_READ_MAX`.
///
/// The ceiling bounds an attacker-controlled path pointing at an unbounded
/// source (`/dev/zero`, a named pipe, a multi-GiB file) so it cannot exhaust
/// memory. A malformed setting fails the read closed rather than falling back.
fn file_read_ceiling() -> Result<u64, String> {
    parse_read_ceiling(crate::system::read_env_var("IPE_FILE_READ_MAX")).map(ReadCeiling::bytes)
}

fn file_read_file_sync(path: &str, cap: u64) -> Result<String, String> {
    use std::io::Read;
    let f = std::fs::File::open(path).map_err(|e| format!("{e}"))?;
    // take(cap + 1): if the source yields more than `cap` bytes we still
    // stop at a bounded read and report an error rather than OOM.
    let mut buf = String::new();
    let read = f
        .take(cap.saturating_add(1))
        .read_to_string(&mut buf)
        .map_err(|e| format!("{e}"))?;
    if read as u64 > cap {
        return Err(format!(
            "file exceeds read ceiling of {cap} bytes (raise IPE_FILE_READ_MAX or use File.readFileLimit): {path}"
        ));
    }
    Ok(buf)
}

#[must_use]
pub fn file_read_file<E: Send + From<String> + 'static>(path: Path) -> IpeTask<E, String> {
    let path = path.into_string();
    Box::pin(async move {
        let cap = match file_read_ceiling() {
            Ok(cap) => cap,
            Err(e) => return IpeResult::Err(str_err(&e)),
        };
        match run_blocking(move || file_read_file_sync(&path, cap)).await {
            Ok(s) => ok_res(s),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

fn file_write_file_sync(path: &str, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("{e}"))
}

#[must_use]
pub fn file_write_file<E: Send + From<String> + 'static>(
    path: Path,
    content: String,
) -> IpeTask<E, ()> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_write_file_sync(&path, &content)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

#[must_use]
pub fn file_exists<E: Send + 'static>(path: Path) -> IpeTask<E, bool> {
    let path = path.into_string();
    Box::pin(async move {
        // Infallible closure — `run_blocking`'s `Err` arm is unreachable here
        // (kept `Result`-shaped only to satisfy the shared helper's bound), so
        // a hypothetical `JoinError` (task panicked) falls back to `false`
        // rather than propagating — there is no `Err` channel on this
        // kernel's existing `IpeTask<E, bool>` signature to propagate into.
        let exists = run_blocking(move || Ok::<_, String>(std::path::Path::new(&path).exists()))
            .await
            .unwrap_or(false);
        ok_res(exists)
    })
}

/// Alias of `file_remove` (the `remove` contract). Kept as a public name for
/// ABI stability; delegates so the two never drift.
#[must_use]
pub fn file_delete<E: Send + From<String> + 'static>(path: Path) -> IpeTask<E, ()> {
    file_remove(path)
}

fn file_mkdir_all_sync(path: &str) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("{e}"))
}

/// `Ipe.File.mkdirAll : String -> Task Error ()` — create the directory
/// and every missing parent (mkdir -p). Already-exists is `Ok` (matching
/// `std::fs::create_dir_all`); a real I/O failure is `Err`.
#[must_use]
pub fn file_mkdir_all<E: Send + From<String> + 'static>(path: Path) -> IpeTask<E, ()> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_mkdir_all_sync(&path)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

// ─── Read variants ─────────────────────────────────────────────────────────

fn file_read_file_limit_sync(path: &str, cap: u64) -> Result<String, String> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).map_err(|e| format!("{e}"))?;
    let mut buf = String::new();
    let read = f
        .take(cap.saturating_add(1))
        .read_to_string(&mut buf)
        .map_err(|e| format!("{e}"))?;
    if read as u64 > cap {
        return Err(format!(
            "file exceeds {cap}-byte limit (stopped reading at the limit — actual size not reported to bound memory use): {path}"
        ));
    }
    Ok(buf)
}

/// Parses a raw `readFileLimit` kernel argument into a byte ceiling.
///
/// `0` is the zero-byte ceiling; a negative value is refused. The stdlib
/// wrapper passes a non-negative `ByteSize`, so this is the independent second
/// boundary for any direct caller of the kernel.
fn read_limit(limit: i64) -> Result<u64, String> {
    u64::try_from(limit).map_err(|_| {
        format!("File.readFileLimit: limit must be a non-negative byte count (got {limit})")
    })
}

/// `Ipe.File.readFileLimit : String -> Int -> Task Error String`
/// Read at most `limit` bytes. Returns `Err` when the file is larger than
/// `limit` (to avoid OOM on unbounded inputs) or when the content is not
/// valid UTF-8 (use `readFileBytes` for binary data in that case).
/// A limit of `0` is a zero-byte ceiling (only an empty file reads); a
/// negative limit is refused before the file is opened.
///
/// No separate `metadata()` pre-check: a stat-then-read split is TOCTOU — a
/// file that grows between the two syscalls would pass the stale size check
/// and then have `take(cap)` silently truncate. Reading `cap + 1` bytes in a
/// single pass and checking the bytes actually read (same idiom as
/// `file_read_file`, and `compression.rs`'s decompression-bomb check) leaves
/// nothing to race against.
#[must_use]
pub fn file_read_file_limit<E: Send + From<String> + 'static>(
    path: Path,
    limit: i64,
) -> IpeTask<E, String> {
    let path = path.into_string();
    let cap = read_limit(limit);
    Box::pin(async move {
        let cap = match cap {
            Ok(cap) => cap,
            Err(e) => return IpeResult::Err(str_err(&e)),
        };
        match run_blocking(move || file_read_file_limit_sync(&path, cap)).await {
            Ok(s) => ok_res(s),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

fn file_read_file_bytes_sync(path: &str) -> Result<Vec<i64>, String> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).map_err(|e| format!("{e}"))?;
    let mut buf = Vec::new();
    // Read `READ_FILE_BYTES_CEILING + 1` bytes in one pass and check the bytes
    // actually read (same idiom as `file_read_file_sync`): a file over the cap
    // must `Err`, never silently truncate and report `Ok`.
    let read = f
        .take(READ_FILE_BYTES_CEILING.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| format!("{e}"))?;
    if read as u64 > READ_FILE_BYTES_CEILING {
        return Err(format!(
            "file exceeds {READ_FILE_BYTES_CEILING}-byte limit (stopped reading at the limit — actual size not reported to bound memory use): {path}"
        ));
    }
    Ok(from_u8_slice(&buf))
}

/// `Ipe.File.readFileBytes : String -> Task Error (List Int)`
/// Read the file as raw bytes, returned as `Vec<i64>` (Ipê `List Int`,
/// values 0..=255). Bounded by `READ_FILE_BYTES_CEILING` (10 MiB) — a file
/// over the cap is an `Err`, never a silent truncation. For text content with
/// guaranteed UTF-8, prefer `readFile` / `readFileLimit`.
#[must_use]
pub fn file_read_file_bytes<E: Send + From<String> + 'static>(path: Path) -> IpeTask<E, Vec<i64>> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_read_file_bytes_sync(&path)).await {
            Ok(v) => ok_res(v),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

// ─── Write variants ────────────────────────────────────────────────────────

fn file_append_sync(path: &str, content: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|e| format!("{e}"))?;
    f.write_all(content.as_bytes()).map_err(|e| format!("{e}"))
}

/// `Ipe.File.append : String -> String -> Task Error ()`
/// Append `content` to the end of the file at `path`, creating it if absent.
/// Implements `os.OpenFile(…, O_APPEND|O_CREATE|O_WRONLY, 0644)`.
#[must_use]
pub fn file_append<E: Send + From<String> + 'static>(
    path: Path,
    content: String,
) -> IpeTask<E, ()> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_append_sync(&path, &content)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

// ─── Removal ───────────────────────────────────────────────────────────────

fn file_remove_sync(path: &str) -> Result<(), String> {
    std::fs::remove_file(path).map_err(|e| format!("{e}"))
}

/// `Ipe.File.remove : String -> Task Error ()`
/// Remove the file at `path`. Returns `Err` on any I/O failure (including
/// "not found"). Implements `os.Remove`.
#[must_use]
pub fn file_remove<E: Send + From<String> + 'static>(path: Path) -> IpeTask<E, ()> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_remove_sync(&path)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

// ─── Directory queries ─────────────────────────────────────────────────────

fn file_read_dir_sync(path: &str) -> Result<Vec<String>, IpeError> {
    // Propagate per-entry read errors instead of silently dropping them
    // (`rd.flatten()` would discard `Err` items mid-walk, omitting entries
    // a transient stat/readdir failure touched —  `os.ReadDir` surfaces
    // such an error rather than returning a truncated list).
    // A name that is not valid UTF-8 is refused, never rewritten lossily.
    let rd = std::fs::read_dir(path).map_err(|e| IpeError::from(format!("{e}")))?;
    let mut names: Vec<String> = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|e| IpeError::from(format!("{e}")))?;
        names.push(name_from_os(&entry.file_name(), OsOrigin::ReadDir)?);
    }
    Ok(names)
}

/// `Ipe.File.readDir : String -> Task Error (List String)`
/// Return the names (not full paths) of all entries in the directory at
/// `path`, in filesystem order. Implements `os.ReadDir` → `e.Name()`.
#[must_use]
pub fn file_read_dir<E: Send + From<IpeError> + 'static>(path: Path) -> IpeTask<E, Vec<String>> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_read_dir_sync(&path)).await {
            Ok(names) => ok_res(names),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// `Ipe.File.isDir : String -> Task Error Bool`
/// Returns `Ok(true)` when `path` exists and is a directory, `Ok(false)` when
/// it exists and is not a directory, and `Ok(false)` (not `Err`) when the path
/// does not exist — matching  shape (`os.Stat` error → `false`).
#[must_use]
pub fn file_is_dir<E: Send + 'static>(path: Path) -> IpeTask<E, bool> {
    let path = path.into_string();
    Box::pin(async move {
        // Same infallible-closure shape as `file_exists` above.
        let is_dir = run_blocking(move || {
            Ok::<_, String>(std::fs::metadata(&path).is_ok_and(|m| m.is_dir()))
        })
        .await
        .unwrap_or(false);
        ok_res(is_dir)
    })
}

// ─── Temp paths ────────────────────────────────────────────────────────────

/// `Ipe.File.tempFile : String -> Task Error String`
/// Create a private, unguessably named empty file in the system temp directory,
/// tagged with `prefix`. Returns the absolute path.
/// The caller is responsible for removing the file when done.
///
/// The file is created through the shared scratch primitive: under a verified
/// temp base, exclusively, never through a symlink, mode 0600, with a name
/// carrying 128 bits of OS CSPRNG entropy.
#[must_use]
pub fn file_temp_file<E: Send + From<IpeError> + 'static>(prefix: String) -> IpeTask<E, String> {
    Box::pin(async move {
        match run_blocking(move || temp_file_sync(&prefix)).await {
            Ok(p) => ok_res(p),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// `Ipe.File.tempDir : String -> Task Error String`
/// Create a private, unguessably named directory in the system temp directory,
/// tagged with `prefix`. Returns the absolute path.
/// The caller is responsible for removing the directory when done.
///
/// The directory is created through the shared scratch primitive: under a
/// verified temp base, exclusively, mode 0700, re-verified as the effective
/// user's, with a name carrying 128 bits of OS CSPRNG entropy.
#[must_use]
pub fn file_temp_dir<E: Send + From<IpeError> + 'static>(prefix: String) -> IpeTask<E, String> {
    Box::pin(async move {
        match run_blocking(move || temp_dir_sync(&prefix)).await {
            Ok(p) => ok_res(p),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// A private temp file tagged with `prefix`, kept past this call.
///
/// The created path passes the host seal like every other `Path`-shaped value;
/// a location the seal refuses (not UTF-8, say) is removed again and reported,
/// never rewritten lossily.
fn temp_file_sync(prefix: &str) -> Result<String, IpeError> {
    let (path, _file) = super::scratch_core::private_temp_file(prefix)
        .map_err(|e| IpeError::from(e.to_string()))?;
    sealed_temp(&path, OsOrigin::TempFile)
}

/// A private temp directory tagged with `prefix`, kept past this call.
///
/// Sealed under the host regime exactly as [`temp_file_sync`].
fn temp_dir_sync(prefix: &str) -> Result<String, IpeError> {
    let dir =
        super::scratch_core::ScratchDir::new(prefix).map_err(|e| IpeError::from(e.to_string()))?;
    sealed_temp(&dir.into_path(), OsOrigin::TempDir)
}

/// Seal a freshly created temp entry, removing it again when the seal refuses.
fn sealed_temp(path: &std::path::Path, origin: OsOrigin) -> Result<String, IpeError> {
    from_os(path, origin)
        .map(Path::into_string)
        .inspect_err(|_| {
            // Best-effort cleanup of an entry the caller can never name; the
            // refusal is the error reported either way.
            let _ = if matches!(origin, OsOrigin::TempDir) {
                std::fs::remove_dir(path)
            } else {
                std::fs::remove_file(path)
            };
        })
}

// ─── Copy / rename ─────────────────────────────────────────────────────────

fn file_copy_sync(src: &str, dst: &str) -> Result<(), String> {
    std::fs::copy(src, dst)
        .map(|_| ())
        .map_err(|e| format!("{e}"))
}

/// `Ipe.File.copy : String -> String -> Task Error ()`
/// Copy the file at `src` to `dst`, creating or overwriting `dst`.
/// Implements `io.Copy(out, in)` pattern.
#[must_use]
pub fn file_copy<E: Send + From<String> + 'static>(src: Path, dst: Path) -> IpeTask<E, ()> {
    let (src, dst) = (src.into_string(), dst.into_string());
    Box::pin(async move {
        match run_blocking(move || file_copy_sync(&src, &dst)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

fn file_rename_sync(src: &str, dst: &str) -> Result<(), String> {
    std::fs::rename(src, dst).map_err(|e| format!("{e}"))
}

/// `Ipe.File.rename : String -> String -> Task Error ()`
/// Rename (move) the file or directory at `src` to `dst`.
/// Implements `os.Rename`.
#[must_use]
pub fn file_rename<E: Send + From<String> + 'static>(src: Path, dst: Path) -> IpeTask<E, ()> {
    let (src, dst) = (src.into_string(), dst.into_string());
    Box::pin(async move {
        match run_blocking(move || file_rename_sync(&src, &dst)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

// ─── Recursive walk ────────────────────────────────────────────────────────

/// Recursive engine shared by `file_walk_sync` and `file_walk_matching_sync`.
///
/// Descends `dir`, appending every regular file (and symlink-to-file) as a
/// `Path` to `out`. Directories are recursed into; symlink cycles are detected
/// by tracking the canonicalized real path of every directory before descending
/// — if the real path is already in `visited`, the directory is skipped (no
/// error, no infinite loop). A broken symlink or an unresolvable `canonicalize`
/// call is silently skipped (fail-closed for traversal safety; surfacing those
/// as errors would expose path or permission information from subtrees the
/// caller did not ask about).
///
/// `pred`: optional predicate on the file's `Path`. `None` includes all files;
/// `Some(f)` includes only those where `f(path)` is `true`. The predicate
/// borrows the `Path` by reference; the caller clones only if it keeps it.
fn walk_dir(
    dir: &Path,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
    pred: Option<&dyn Fn(&Path) -> bool>,
    out: &mut Vec<Path>,
) -> Result<(), IpeError> {
    // Guard against symlink cycles: canonicalize this directory's real path
    // and skip if already seen. `canonicalize` follows all symlinks; if it
    // fails (broken symlink, permission denied, path does not exist), skip
    // this subtree rather than erroring.
    let real = match std::fs::canonicalize(dir.as_str()) {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    if !visited.insert(real) {
        // Already visited this real directory — cycle detected, skip.
        return Ok(());
    }

    let rd = match std::fs::read_dir(dir.as_str()) {
        Ok(rd) => rd,
        Err(e) => return Err(IpeError::from(format!("{e}"))),
    };

    for entry in rd {
        let entry = entry.map_err(|e| IpeError::from(format!("{e}")))?;
        // Every yielded `Path` is the sealed join of the sealed root and the
        // entry name: a name that is not UTF-8, or that the join refuses, fails
        // the walk rather than being rewritten or skipped.
        let name = name_from_os(&entry.file_name(), OsOrigin::Walk)?;
        let entry_path = join_entry(dir, &name)?;

        // Use `metadata()` (follows symlinks) so symlinks to files and
        // symlinks to directories are classified correctly. Symlink-to-
        // directory cycles are caught by the `canonicalize` guard above.
        let meta = match std::fs::metadata(entry_path.as_str()) {
            Ok(m) => m,
            Err(_) => continue, // broken symlink or permission denied — skip
        };

        if meta.is_dir() {
            walk_dir(&entry_path, visited, pred, out)?;
        } else if meta.is_file() && pred.is_none_or(|f| f(&entry_path)) {
            out.push(entry_path);
        }
        // Symlinks to files: covered by `meta.is_file()` above.
        // Symlinks to directories: covered by `meta.is_dir()` + cycle guard.
    }

    Ok(())
}

fn file_walk_sync(root: &Path) -> Result<Vec<Path>, IpeError> {
    if !std::path::Path::new(root.as_str()).is_dir() {
        return Err(IpeError::from(format!(
            "not a directory: {}",
            root.as_str()
        )));
    }
    let mut visited = std::collections::HashSet::new();
    let mut out = Vec::new();
    walk_dir(root, &mut visited, None, &mut out)?;
    out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    Ok(out)
}

fn file_walk_matching_sync(
    root: &Path,
    pred: &dyn Fn(&Path) -> bool,
) -> Result<Vec<Path>, IpeError> {
    if !std::path::Path::new(root.as_str()).is_dir() {
        return Err(IpeError::from(format!(
            "not a directory: {}",
            root.as_str()
        )));
    }
    let mut visited = std::collections::HashSet::new();
    let mut out = Vec::new();
    walk_dir(root, &mut visited, Some(pred), &mut out)?;
    out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    Ok(out)
}

/// `Ipe.File.walk : Path -> Task Error (List Path)`
/// Recursively walk `root`, returning the absolute path of every regular file
/// (files only, no directories) reachable from it in deterministic
/// (lexicographically sorted) order.
///
/// Symlink cycles are detected and skipped — a symlink loop cannot cause
/// unbounded recursion or a stack overflow. Broken symlinks and unreadable
/// subtrees are silently skipped (fail-closed for traversal safety). An error
/// is returned only if `root` itself is not a readable directory.
#[must_use]
pub fn file_walk<E: Send + From<IpeError> + 'static>(root: Path) -> IpeTask<E, Vec<Path>> {
    Box::pin(async move {
        match run_blocking(move || file_walk_sync(&root)).await {
            Ok(paths) => ok_res(paths),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// `Ipe.File.walkMatching : Path -> (Path -> Bool) -> Task Error (List Path)`
/// Like `walk`, but only includes files for which `pred` returns `True`.
/// The predicate receives the file's absolute `Path` and runs synchronously
/// during the walk (no `Task`, no I/O inside the predicate). Returns files in
/// deterministic (lexicographically sorted) order.
#[must_use]
pub fn file_walk_matching<E: Send + From<IpeError> + 'static>(
    root: Path,
    pred: Box<dyn Fn(Path) -> bool + Send + Sync + 'static>,
) -> IpeTask<E, Vec<Path>> {
    Box::pin(async move {
        // Bridge: the emitted predicate owns its `Path` argument, but
        // `walk_dir` borrows. Wrap in an adapter that clones the borrow into
        // an owned value before calling `pred`.
        let adapter: Box<dyn Fn(&Path) -> bool + Send + Sync + 'static> =
            Box::new(move |p: &Path| pred(p.clone()));
        match run_blocking(move || file_walk_matching_sync(&root, adapter.as_ref())).await {
            Ok(paths) => ok_res(paths),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// Test-only: seal an absolute `std::path::Path` (always a rooted, non-escaping
/// path) into an `Ipe.Path`. Kernel call sites now take a typed `Path`, so the
/// tests construct one through the same validated seal a real program uses.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
fn tp(p: &std::path::Path) -> Path {
    match super::path::path_from_string::<IpeError>(p.to_string_lossy().into_owned()) {
        IpeResult::Ok(path) => path,
        IpeResult::Err(e) => panic!("test temp path failed Path validation: {e}"),
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod read_ceiling_tests {
    use super::*;

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    // SECURITY/DoS regression: readFile must refuse a source larger than the
    // ceiling instead of allocating it unbounded.
    #[test]
    fn read_file_rejects_over_ceiling() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rc_over_{}.txt", std::process::id()));
        std::fs::write(&p, vec![b'x'; 8192]).unwrap();
        crate::system::locked_set_var("IPE_FILE_READ_MAX", "1024");
        let res: IpeResult<String, String> = block(file_read_file(tp(&p)));
        crate::system::locked_remove_var("IPE_FILE_READ_MAX");
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(res, IpeResult::Err(_)),
            "8 KiB read under a 1 KiB ceiling must Err"
        );
    }

    /// A malformed ceiling fails the read closed and names the variable.
    #[test]
    fn read_file_refuses_a_malformed_ceiling() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rc_bad_{}.txt", std::process::id()));
        std::fs::write(&p, b"hello").unwrap();
        crate::system::locked_set_var("IPE_FILE_READ_MAX", "abc");
        let res: IpeResult<String, String> = block(file_read_file(tp(&p)));
        crate::system::locked_remove_var("IPE_FILE_READ_MAX");
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(&res, IpeResult::Err(e) if e.contains("IPE_FILE_READ_MAX")),
            "a malformed IPE_FILE_READ_MAX must fail the read: {res:?}"
        );
    }

    #[test]
    fn ceiling_unset_is_the_default() {
        assert_eq!(
            parse_read_ceiling(Err(std::env::VarError::NotPresent)),
            Ok(ReadCeiling::Unset)
        );
        assert_eq!(ReadCeiling::Unset.bytes(), READ_FILE_DEFAULT_CEILING);
    }

    #[test]
    fn ceiling_decimal_values_are_bytes() {
        assert_eq!(
            parse_read_ceiling(Ok("0".into())),
            Ok(ReadCeiling::Bytes(0))
        );
        assert_eq!(
            parse_read_ceiling(Ok("1024".into())),
            Ok(ReadCeiling::Bytes(1024))
        );
        assert_eq!(
            parse_read_ceiling(Ok("18446744073709551615".into())),
            Ok(ReadCeiling::Bytes(u64::MAX))
        );
    }

    #[test]
    fn ceiling_malformed_values_are_refused() {
        for bad in [
            "",
            "-1",
            "+1024",
            "16MiB",
            " 1024",
            "1024 ",
            "18446744073709551616",
        ] {
            let res = parse_read_ceiling(Ok(bad.into()));
            assert!(
                matches!(&res, Err(e) if e.contains("IPE_FILE_READ_MAX")),
                "{bad:?} must be refused naming the variable: {res:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn ceiling_non_unicode_is_refused() {
        use std::os::unix::ffi::OsStringExt as _;
        let raw = std::ffi::OsString::from_vec(vec![b'1', 0xff]);
        let res = parse_read_ceiling(Err(std::env::VarError::NotUnicode(raw)));
        assert!(
            matches!(&res, Err(e) if e.contains("IPE_FILE_READ_MAX")),
            "{res:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ceiling_non_unicode_shows_every_byte_escaped() {
        use std::os::unix::ffi::OsStringExt as _;
        let raw = std::ffi::OsString::from_vec(vec![b'1', 0xff, 0x1b, b'[', b'2', b'J', 0xfe]);
        let res = parse_read_ceiling(Err(std::env::VarError::NotUnicode(raw)));
        assert_eq!(
            res,
            Err(
                r#"IPE_FILE_READ_MAX must be a decimal byte count (got "1\xFF\u{1b}[2J\xFE")"#
                    .to_string()
            )
        );
    }

    #[test]
    fn ceiling_refusal_escapes_controls_and_quotes() {
        let res = parse_read_ceiling(Ok("1\n\"\u{202e}\\".into()));
        assert_eq!(
            res,
            Err(
                r#"IPE_FILE_READ_MAX must be a decimal byte count (got "1\n\"\u{202e}\\")"#
                    .to_string()
            )
        );
    }

    #[test]
    fn ceiling_refusal_truncates_the_shown_value() {
        let long = "x".repeat(200);
        let res = parse_read_ceiling(Ok(long));
        assert!(
            matches!(&res, Err(e) if !e.contains(&"x".repeat(READ_CEILING_SHOWN_CHARS + 1))
                && e.contains(&"x".repeat(READ_CEILING_SHOWN_CHARS))),
            "{res:?}"
        );
    }

    #[test]
    fn read_file_under_ceiling_ok() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rc_ok_{}.txt", std::process::id()));
        std::fs::write(&p, b"hello").unwrap();
        let res: IpeResult<String, String> = block(file_read_file(tp(&p)));
        let _ = std::fs::remove_file(&p);
        match res {
            IpeResult::Ok(s) => assert_eq!(s, "hello"),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod read_file_limit_tests {
    use super::*;

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn under_limit_reads_full_content() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rfl_under_{}.txt", std::process::id()));
        std::fs::write(&p, b"hello world").unwrap();
        let res: IpeResult<String, String> = block(file_read_file_limit(tp(&p), 1024));
        let _ = std::fs::remove_file(&p);
        match res {
            IpeResult::Ok(s) => assert_eq!(s, "hello world"),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
    }

    /// Boundary: a file whose size is EXACTLY `limit` bytes must succeed with
    /// the full content, not be rejected as "over" (the `> cap` check, not
    /// `>= cap`).
    #[test]
    fn exactly_at_limit_is_ok() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rfl_exact_{}.txt", std::process::id()));
        let content = vec![b'a'; 16];
        std::fs::write(&p, &content).unwrap();
        let res: IpeResult<String, String> = block(file_read_file_limit(tp(&p), 16));
        let _ = std::fs::remove_file(&p);
        match res {
            IpeResult::Ok(s) => assert_eq!(s.len(), 16),
            IpeResult::Err(e) => panic!("exactly-at-limit must be Ok, got Err: {e}"),
        }
    }

    /// Regression for the TOCTOU fix: a file ONE byte over the limit must
    /// Err, never silently truncate to `limit` bytes and report Ok. This
    /// pins the single-pass rewrite's over-limit-at-rest behavior while
    /// removing the stat-then-read race window a growing-file scenario
    /// would otherwise hit.
    #[test]
    fn over_limit_by_one_byte_errs() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rfl_over_{}.txt", std::process::id()));
        std::fs::write(&p, vec![b'a'; 17]).unwrap();
        let res: IpeResult<String, String> = block(file_read_file_limit(tp(&p), 16));
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(res, IpeResult::Err(_)),
            "17 bytes under a 16-byte limit must Err, not silently truncate"
        );
    }

    fn limit_read(name: &str, content: &[u8], limit: i64) -> IpeResult<String, String> {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rfl_{name}_{}.txt", std::process::id()));
        std::fs::write(&p, content).unwrap();
        let res: IpeResult<String, String> = block(file_read_file_limit(tp(&p), limit));
        let _ = std::fs::remove_file(&p);
        res
    }

    /// A zero limit is the zero-byte ceiling, never a fallback to a default.
    #[test]
    fn zero_limit_refuses_a_non_empty_file() {
        let res = limit_read("zero_full", b"small", 0);
        assert!(
            matches!(&res, IpeResult::Err(e) if e.contains("0-byte limit")),
            "a 5-byte file under a 0-byte limit must Err: {res:?}"
        );
    }

    #[test]
    fn zero_limit_admits_an_empty_file() {
        let res = limit_read("zero_empty", b"", 0);
        assert!(matches!(&res, IpeResult::Ok(s) if s.is_empty()), "{res:?}");
    }

    /// A negative limit is refused before the path is opened: the refusal
    /// names the limit even for a path that does not exist.
    #[test]
    fn negative_limit_is_refused_without_reading() {
        let missing = crate::scratch_core::test_temp_root().join(format!(
            "ipe_rfl_missing_{}_does_not_exist.txt",
            std::process::id()
        ));
        for bad in [-1_i64, i64::MIN] {
            let res: IpeResult<String, String> = block(file_read_file_limit(tp(&missing), bad));
            assert!(
                matches!(&res, IpeResult::Err(e)
                    if e.contains("non-negative byte count") && e.contains(&bad.to_string())),
                "limit {bad} must be refused naming the limit: {res:?}"
            );
            let res = limit_read("negative", b"x", bad);
            assert!(
                matches!(res, IpeResult::Err(_)),
                "limit {bad} on a real file must Err"
            );
        }
    }

    #[test]
    fn limit_one_past_the_content_admits() {
        let res = limit_read("one_past", b"small", 6);
        assert!(matches!(&res, IpeResult::Ok(s) if s == "small"), "{res:?}");
    }

    #[test]
    fn limit_one_short_refuses() {
        let res = limit_read("one_short", b"small", 4);
        assert!(matches!(res, IpeResult::Err(_)), "{res:?}");
    }
}

/// Sibling of `read_file_limit_tests` for `File.readFileBytes`'s own fixed
/// 10 MiB cap: `readFileBytes` must ERROR when a file exceeds the cap, not
/// silently truncate at it via `take(DEFAULT_CAP).read_to_end(..)` with no
/// post-read size check — the same class as `readFileLimit`'s TOCTOU.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod read_file_bytes_tests {
    use super::*;

    const DEFAULT_CAP: usize = 10 * 1024 * 1024;

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn under_cap_reads_full_content() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rfb_under_{}.bin", std::process::id()));
        std::fs::write(&p, [1u8, 2, 3, 255, 0]).unwrap();
        let res: IpeResult<String, Vec<i64>> = block(file_read_file_bytes(tp(&p)));
        let _ = std::fs::remove_file(&p);
        match res {
            IpeResult::Ok(v) => assert_eq!(v, vec![1, 2, 3, 255, 0]),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
    }

    /// Boundary: a file whose size is EXACTLY the 10 MiB cap must succeed
    /// with the full content, not be rejected as "over" (the `> cap` check,
    /// not `>= cap`).
    #[test]
    fn exactly_at_cap_is_ok() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rfb_exact_{}.bin", std::process::id()));
        std::fs::write(&p, vec![7u8; DEFAULT_CAP]).unwrap();
        let res: IpeResult<String, Vec<i64>> = block(file_read_file_bytes(tp(&p)));
        let _ = std::fs::remove_file(&p);
        match res {
            IpeResult::Ok(v) => assert_eq!(v.len(), DEFAULT_CAP),
            IpeResult::Err(e) => panic!("exactly-at-cap must be Ok, got Err: {e}"),
        }
    }

    /// Regression: a file ONE byte over the 10 MiB cap must `Err`, never
    /// silently truncate to `DEFAULT_CAP` bytes and report `Ok` — this is
    /// the exact bug this fix closes. Pre-fix, this assertion FAILS: the old
    /// `take(DEFAULT_CAP).read_to_end(..)` reads exactly `DEFAULT_CAP` bytes
    /// with no error, and the returned `Vec` has `DEFAULT_CAP` elements
    /// (silently dropping the last byte) instead of erroring.
    #[test]
    fn over_cap_by_one_byte_errs() {
        let p = crate::scratch_core::test_temp_root()
            .join(format!("ipe_rfb_over_{}.bin", std::process::id()));
        std::fs::write(&p, vec![7u8; DEFAULT_CAP + 1]).unwrap();
        let res: IpeResult<String, Vec<i64>> = block(file_read_file_bytes(tp(&p)));
        let _ = std::fs::remove_file(&p);
        assert!(
            matches!(res, IpeResult::Err(_)),
            "a file one byte over the 10 MiB cap must Err, not silently truncate: {res:?}"
        );
    }
}

#[cfg(all(test, feature = "tokio"))]
#[cfg(not(target_arch = "wasm32"))]
mod spawn_blocking_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Reactor-starvation guard: on a SINGLE-WORKER (current_thread) runtime, a
    /// blocking `std::fs` read called directly on the polled future would
    /// starve every other task on that runtime until the read completes.
    /// This proves `file_read_file` offloads the blocking read to tokio's
    /// blocking-thread pool instead of running it on the (sole) worker
    /// thread: a concurrently-spawned cheap ticker task must make progress
    /// (ticks > 0) WHILE the read is in flight.
    ///
    /// Pre-fix this is NOT a flaky race: the ticker makes EXACTLY zero
    /// progress deterministically, because the worker thread never yields
    /// back to the executor until `read_to_string` returns.
    #[test]
    fn file_read_file_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let p = crate::scratch_core::test_temp_root().join(format!(
            "ipe_spawn_blocking_probe_{}.txt",
            std::process::id()
        ));
        // Large enough that the read takes measurable (not instant) wall time.
        std::fs::write(&p, vec![b'x'; 64 * 1024 * 1024]).unwrap(); // 64 MiB
        crate::system::locked_set_var("IPE_FILE_READ_MAX", &(128 * 1024 * 1024).to_string());
        let path = super::tp(&p);

        let ticks = rt.block_on(async move {
            let counter = Arc::new(AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let read_fut: IpeTask<String, String> = file_read_file(path);
            let _res: IpeResult<String, String> = read_fut.await;
            ticker.abort();
            counter.load(Ordering::Relaxed)
        });

        crate::system::locked_remove_var("IPE_FILE_READ_MAX");
        let _ = std::fs::remove_file(&p);

        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while file_read_file ran — \
             the blocking read is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }

    /// Same shape as above, for `file_write_file` — proves the write path is
    /// ALSO offloaded (a sibling kernel with the identical un-wrapped
    /// `std::fs::write` shape pre-fix).
    #[test]
    fn file_write_file_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let p = crate::scratch_core::test_temp_root().join(format!(
            "ipe_spawn_blocking_write_probe_{}.txt",
            std::process::id()
        ));
        let path = super::tp(&p);
        let content = "x".repeat(64 * 1024 * 1024); // 64 MiB

        let ticks = rt.block_on(async move {
            let counter = Arc::new(AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let write_fut: IpeTask<String, ()> = file_write_file(path, content);
            let _res: IpeResult<String, ()> = write_fut.await;
            ticker.abort();
            counter.load(Ordering::Relaxed)
        });

        let _ = std::fs::remove_file(&p);

        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while file_write_file ran — \
             the blocking write is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod walk_tests {
    use super::*;

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    /// Build a temp dir tree:
    ///   root/
    ///     a.txt
    ///     sub/
    ///       b.txt
    ///       c.txt
    ///     empty/          (dir, no files)
    /// Returns the root path.
    fn make_tree() -> std::path::PathBuf {
        let root = crate::scratch_core::test_temp_root().join(format!(
            "ipe_walk_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::write(root.join("a.txt"), b"a").unwrap();
        std::fs::write(root.join("sub").join("b.txt"), b"b").unwrap();
        std::fs::write(root.join("sub").join("c.txt"), b"c").unwrap();
        root
    }

    fn cleanup(root: &std::path::Path) {
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn walk_returns_files_only_no_dirs() {
        let root = make_tree();
        let res: IpeResult<IpeError, Vec<Path>> = block(file_walk(tp(&root)));
        let names: Vec<String> = match res {
            IpeResult::Ok(paths) => paths.into_iter().map(|p| p.into_string()).collect(),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        };
        // All results must be files (not directories).
        for name in &names {
            let m = std::fs::metadata(name).unwrap();
            assert!(m.is_file(), "{name} should be a file");
        }
        // Three files total: a.txt, sub/b.txt, sub/c.txt.
        assert_eq!(names.len(), 3, "expected 3 files, got: {names:?}");
        cleanup(&root);
    }

    #[test]
    fn walk_order_is_deterministic_lexicographic() {
        let root = make_tree();
        let res: IpeResult<IpeError, Vec<Path>> = block(file_walk(tp(&root)));
        let paths: Vec<String> = match res {
            IpeResult::Ok(ps) => ps.into_iter().map(|p| p.into_string()).collect(),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        };
        // The list must be sorted.
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted, "walk results are not in sorted order");
        cleanup(&root);
    }

    #[test]
    fn walk_matching_filters_by_predicate() {
        let root = make_tree();
        // Keep only files ending in b.txt.
        let pred: Box<dyn Fn(Path) -> bool + Send + Sync + 'static> =
            Box::new(|p: Path| p.as_str().ends_with("b.txt"));
        let res: IpeResult<IpeError, Vec<Path>> = block(file_walk_matching(tp(&root), pred));
        let paths: Vec<String> = match res {
            IpeResult::Ok(ps) => ps.into_iter().map(|p| p.into_string()).collect(),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        };
        assert_eq!(
            paths.len(),
            1,
            "expected 1 file matching b.txt, got: {paths:?}"
        );
        assert!(
            paths[0].ends_with("b.txt"),
            "expected b.txt, got: {}",
            paths[0]
        );
        cleanup(&root);
    }

    #[test]
    fn walk_on_nonexistent_root_errs() {
        let root = crate::scratch_core::test_temp_root().join("ipe_walk_nonexistent_38291");
        let res: IpeResult<IpeError, Vec<Path>> = block(file_walk(tp(&root)));
        assert!(
            matches!(res, IpeResult::Err(_)),
            "walk on non-existent root should Err"
        );
    }

    /// Symlink cycle must not hang or stack-overflow — the walk terminates and
    /// returns the non-cyclic files.
    #[cfg(unix)]
    #[test]
    fn walk_symlink_cycle_does_not_hang() {
        use std::os::unix::fs::symlink;
        let root = crate::scratch_core::test_temp_root().join(format!(
            "ipe_walk_cycle_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("real.txt"), b"r").unwrap();
        // Create a symlink `loop -> root` — walking into `loop` would re-enter
        // `root`, which we have already canonicalized and placed in `visited`.
        let link_path = root.join("loop");
        let _ = symlink(&root, &link_path);

        let res: IpeResult<IpeError, Vec<Path>> = block(file_walk(tp(&root)));
        let paths: Vec<String> = match res {
            IpeResult::Ok(ps) => ps.into_iter().map(|p| p.into_string()).collect(),
            IpeResult::Err(e) => panic!("unexpected Err from cyclic walk: {e}"),
        };
        // The cycle is skipped; real.txt is still returned.
        assert!(
            paths.iter().any(|p| p.ends_with("real.txt")),
            "real.txt must be present even with a symlink cycle: {paths:?}"
        );
        cleanup(&root);
    }

    /// walk must not escape the capability root via path traversal — the
    /// path argument goes through `path_from_string`, which rejects `..`
    /// escapes lexically. This test confirms the guard is wired correctly.
    #[test]
    fn walk_rejects_dotdot_escape_at_path_boundary() {
        // `path_from_string` rejects relative paths that `..`-escape their
        // base. Construct the attempt and assert it fails at the seal.
        let escape_attempt = "../..".to_string();
        let seal_result = super::super::path::path_from_string::<IpeError>(escape_attempt);
        assert!(
            matches!(seal_result, IpeResult::Err(_)),
            "path_from_string must reject `../..` traversal"
        );
    }

    /// An entry name that is not valid UTF-8 fails the walk and `readDir` as
    /// an input refusal; it is never rewritten lossily nor silently skipped.
    #[cfg(unix)]
    #[test]
    fn non_utf8_entry_names_are_refused_as_invalid_input() {
        use std::os::unix::ffi::OsStrExt;
        let root = crate::scratch_core::test_temp_root().join(format!(
            "ipe_walk_non_utf8_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        std::fs::create_dir_all(&root).unwrap();
        let bad = root.join(std::ffi::OsStr::from_bytes(b"a\xff"));
        if std::fs::write(&bad, b"x").is_err() {
            // A filesystem that itself refuses non-UTF-8 names cannot host
            // the case; there is nothing for the kernel to refuse.
            cleanup(&root);
            return;
        }
        let walked: IpeResult<IpeError, Vec<Path>> = block(file_walk(tp(&root)));
        let listed: IpeResult<IpeError, Vec<String>> = block(file_read_dir(tp(&root)));
        cleanup(&root);
        assert!(
            matches!(
                walked,
                IpeResult::Err(IpeError::Error(super::super::IpeErrorKind::InvalidInput, _))
            ),
            "walk must refuse a non-UTF-8 entry name"
        );
        assert!(
            matches!(
                listed,
                IpeResult::Err(IpeError::Error(super::super::IpeErrorKind::InvalidInput, _))
            ),
            "readDir must refuse a non-UTF-8 entry name"
        );
    }

    #[test]
    fn temp_paths_pass_the_seal() {
        let file: IpeResult<IpeError, String> = block(file_temp_file("ipe_seal_".to_string()));
        let dir: IpeResult<IpeError, String> = block(file_temp_dir("ipe_seal_".to_string()));
        for made in [file, dir] {
            assert!(made.is_ok(), "temp creation failed");
            let IpeResult::Ok(text) = made else {
                return;
            };
            let resealed = super::super::path::path_from_string::<IpeError>(text.clone());
            let _ = std::fs::remove_file(&text);
            let _ = std::fs::remove_dir(&text);
            assert!(
                matches!(resealed, IpeResult::Ok(ref p) if p.as_str() == text),
                "{text:?} is not its own seal"
            );
        }
    }
}
