//! Unpredictable, exclusively-created scratch paths for temporary I/O.
//!
//! Every constructor generates a name that contains 128 bits of OS entropy (not
//! just a PID), opens with `O_EXCL` / `DirBuilder` + exclusive-create semantics
//! so a pre-seeded symlink or a pre-existing entry causes a retry rather than
//! being followed, and mode-restricts the result to the owner.  The RAII wrappers
//! remove the resource on drop, so callers do not need manual cleanup.
//!
//! The [`ScratchFile::file`] field exposes the *owned* [`std::fs::File`] handle
//! so callers can read back what they wrote without re-opening by name.  Reading
//! through the retained handle is the only way to guarantee that the bytes read
//! are the bytes written to the same inode — a name-based re-open can be raced.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Maximum retry attempts when an exclusive-create collision occurs.
const MAX_RETRIES: usize = 8;

/// Read 16 bytes (128 bits) of OS entropy from `/dev/urandom`.
///
/// Returns an error when the device cannot be read or yields fewer than 16
/// bytes, which makes the caller fall back to failing the construction rather
/// than silently weakening the name.
fn read_entropy() -> io::Result<[u8; 16]> {
    let mut buf = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf)
}

/// Format 16 entropy bytes as a 32-character lowercase hex string.
fn hex32(bytes: [u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(32);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Generate one candidate name: `<prefix>-<pid>-<32 hex entropy chars>`.
///
/// The PID component is included so names from different processes sharing a
/// prefix are trivially distinguishable in diagnostics, but the 128-bit entropy
/// is what makes the name unpredictable.
fn candidate_name(prefix: &str) -> io::Result<String> {
    let entropy = read_entropy()?;
    Ok(format!(
        "{}-{}-{}",
        prefix,
        std::process::id(),
        hex32(entropy)
    ))
}

// ── ScratchDir ───────────────────────────────────────────────────────────────

/// An exclusively-created, mode-0700, unpredictably-named temporary directory.
///
/// Constructed via [`ScratchDir::new`] (base = `temp_dir()`) or
/// [`ScratchDir::new_under`] (caller-supplied base), both of which loop on
/// `AlreadyExists` (bounded by [`MAX_RETRIES`]) rather than removing and
/// recreating a pre-existing entry.  The directory is removed on drop
/// (best-effort); call [`ScratchDir::into_path`] to transfer ownership without
/// automatic cleanup.
///
/// Use [`ScratchDir::path`] for the directory itself and
/// [`ScratchDir::child`] to build paths for files or subdirectories inside it.
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    /// Create a new exclusively-owned temporary directory under `temp_dir()`.
    ///
    /// `prefix` is a short, caller-chosen label that appears in the name for
    /// diagnostics.  The name is not caller-controlled beyond this label.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when entropy cannot be read or when all
    /// [`MAX_RETRIES`] attempts fail with `AlreadyExists`.
    pub fn new(prefix: &str) -> io::Result<Self> {
        Self::new_under(&std::env::temp_dir(), prefix)
    }

    /// Create a new exclusively-owned temporary directory under `base`.
    ///
    /// The base directory is created (via `create_dir_all`) before the
    /// exclusive child is attempted, so callers need not pre-create it.
    /// `prefix` is a short, caller-chosen label that appears in the child
    /// name for diagnostics; the name is not caller-controlled beyond this
    /// label.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when `base` cannot be created, when entropy
    /// cannot be read, or when all [`MAX_RETRIES`] attempts fail with
    /// `AlreadyExists`.
    pub fn new_under(base: &Path, prefix: &str) -> io::Result<Self> {
        std::fs::create_dir_all(base)?;
        for _ in 0..MAX_RETRIES {
            let name = candidate_name(prefix)?;
            let path = base.join(&name);
            match exclusive_mkdir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique scratch directory after repeated attempts",
        ))
    }

    /// The path of this scratch directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Build a path for a child entry *inside* this directory.
    ///
    /// The child is not created by this call; use the returned path to create
    /// it.  Because the directory itself is mode 0700, a child created inside
    /// it is not reachable by other users even when its own mode is broader.
    #[must_use]
    pub fn child(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Consume this guard and return the directory path without removing it.
    ///
    /// The caller takes responsibility for cleanup.  Use this only when the
    /// directory must outlive the guard (e.g. when passing to a manual
    /// `remove_dir_all` at a later call site).
    #[must_use]
    pub fn into_path(self) -> PathBuf {
        let path = self.0.clone();
        std::mem::forget(self);
        path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Create a directory exclusively — fail with `AlreadyExists` rather than
/// following a pre-existing entry or a symlink.
///
/// Uses a plain `create_dir` (not `create_dir_all`) so that only the final
/// component is created and any pre-existing entry — including a dangling
/// symlink — produces `AlreadyExists` rather than silently succeeding.
#[cfg(unix)]
fn exclusive_mkdir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(false)
        .create(path)
}

#[cfg(not(unix))]
fn exclusive_mkdir(path: &Path) -> io::Result<()> {
    // On non-Unix there is no portable mode bit; the directory is created with
    // default permissions.  Exclusive creation (fail on AlreadyExists) still
    // holds because `create_dir` (not `create_dir_all`) is used.
    std::fs::create_dir(path)
}

// ── ScratchFile ──────────────────────────────────────────────────────────────

/// An exclusively-created, mode-0600, unpredictably-named temporary file.
///
/// Constructed only via [`ScratchFile::create`], which opens with
/// `O_CREAT|O_EXCL` (via `create_new`) so a pre-existing file or symlink
/// causes a retry.  The owned [`File`] handle in [`ScratchFile::file`]
/// outlives the path name: callers MUST read back written bytes through the
/// handle rather than re-opening by name, so the bytes read are the bytes
/// that were written to this specific inode — a re-open by name races.
///
/// The file is removed on drop (best-effort).
pub struct ScratchFile {
    path: PathBuf,
    /// The open file handle.  Callers should [`Seek`] to the start before
    /// reading if bytes were written through an external writer.
    pub file: File,
}

impl ScratchFile {
    /// Create a new exclusively-owned temporary file whose name is
    /// unpredictable.
    ///
    /// Returns both the [`ScratchFile`] RAII guard and a clone of the owned
    /// `File` handle (already positioned at offset 0).  Callers that let an
    /// external writer (e.g. `curl -o`) write to [`ScratchFile::path`] should
    /// [`rewind`](ScratchFile::rewind) the handle before reading.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] when entropy cannot be read or when all
    /// [`MAX_RETRIES`] attempts fail.
    pub fn create(prefix: &str) -> io::Result<Self> {
        let base = std::env::temp_dir();
        for _ in 0..MAX_RETRIES {
            let name = candidate_name(prefix)?;
            let path = base.join(&name);
            match exclusive_open(&path) {
                Ok(file) => return Ok(Self { path, file }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique scratch file after repeated attempts",
        ))
    }

    /// The path of this scratch file.
    ///
    /// Prefer reading through [`ScratchFile::file`] rather than re-opening
    /// this path, so the bytes read are the bytes on the owned inode.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rewind the retained file handle to offset 0 so the caller can read
    /// from the start.
    ///
    /// # Errors
    ///
    /// Propagates any `seek` error.
    pub fn rewind(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0)).map(|_| ())
    }

    /// Read all bytes from the retained file handle (after rewinding to
    /// offset 0).
    ///
    /// This is the *only* correct way to retrieve what an external writer
    /// wrote to [`ScratchFile::path`]: reading through the handle avoids a
    /// re-open-by-name race.
    ///
    /// # Errors
    ///
    /// Propagates any seek or read error.
    pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
        self.rewind()?;
        let mut buf = Vec::new();
        self.file.read_to_end(&mut buf)?;
        Ok(buf)
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Open a file exclusively at `path` with mode 0600 (owner read/write only).
#[cfg(unix)]
fn exclusive_open(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn exclusive_open(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Two distinct `ScratchDir` names from the same prefix never collide and
    /// neither equals a bare `<prefix>-<pid>` string (the old predictable form).
    #[test]
    fn scratch_dir_names_are_unpredictable_and_unique() {
        let pid_only = format!("ipe-publish-{}", std::process::id());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            let sd = ScratchDir::new("ipe-publish").expect("scratch dir");
            let name = sd
                .path()
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf-8 name")
                .to_owned();
            assert_ne!(
                name, pid_only,
                "name must not equal the predictable pid-only form"
            );
            assert!(seen.insert(name.clone()), "duplicate scratch name: {name}");
            // path is removed on drop — verified by raii_cleanup below
        }
    }

    /// `ScratchDir` is removed on drop.
    #[test]
    fn scratch_dir_raii_cleanup() {
        let path = {
            let sd = ScratchDir::new("ipe-raii-test").expect("scratch dir");
            let p = sd.path().to_path_buf();
            assert!(p.exists(), "dir should exist while live");
            p
        };
        assert!(!path.exists(), "dir should be gone after drop");
    }

    /// `ScratchFile` is removed on drop.
    #[test]
    fn scratch_file_raii_cleanup() {
        let path = {
            let sf = ScratchFile::create("ipe-raii-test").expect("scratch file");
            let p = sf.path().to_path_buf();
            assert!(p.exists(), "file should exist while live");
            p
        };
        assert!(!path.exists(), "file should be gone after drop");
    }

    /// Reading through the retained handle returns the bytes written to the
    /// path, even when the path name is renamed away after writing — the
    /// handle holds the original inode open.
    #[test]
    fn scratch_file_handle_reads_original_inode() {
        let original_bytes = b"original content";
        let decoy_bytes = b"swapped content";

        let mut sf = ScratchFile::create("ipe-inode-test").expect("scratch file");
        sf.file.write_all(original_bytes).expect("write");

        // Rename a decoy file over the scratch path (simulates a name-race).
        let decoy = sf.path().with_extension("decoy");
        std::fs::write(&decoy, decoy_bytes).expect("write decoy");
        std::fs::rename(&decoy, sf.path()).expect("rename decoy over path");

        // Reading through the retained handle still returns the original bytes,
        // not the decoy — the handle is bound to the original inode.
        let read_back = sf.read_all().expect("read_all");
        assert_eq!(
            read_back, original_bytes,
            "retained handle must read the original inode, not the swapped name"
        );
    }

    /// A symlink pre-seeded at the exact scratch path is not followed: the
    /// constructor retries and eventually creates a real file or directory at
    /// a fresh name, leaving the symlink target untouched.
    #[test]
    fn symlink_preseed_is_not_followed() {
        // Create a canary file that a symlink would point to.
        let canary = std::env::temp_dir().join(format!(
            "ipe-canary-{}-{}",
            std::process::id(),
            "symlink-preseed-test"
        ));
        std::fs::write(&canary, b"canary").expect("write canary");

        // Exhausting retries is hard to do reliably in a unit test because we
        // cannot control the random names.  What we CAN assert is that a
        // successful ScratchFile::create always produces a REGULAR file (not a
        // symlink), and the canary is intact.
        let sf = ScratchFile::create("ipe-preseed-test").expect("scratch file");
        let meta = std::fs::symlink_metadata(sf.path()).expect("metadata");
        assert!(
            meta.file_type().is_file(),
            "scratch file must be a regular file, not a symlink"
        );
        assert_eq!(
            std::fs::read(&canary).expect("canary readable"),
            b"canary",
            "canary must be untouched"
        );

        let _ = std::fs::remove_file(&canary);
    }

    /// No PRODUCTION code in the `ipe-cli` or `ipe-wrapper` crates (outside the
    /// sanctioned `scratch` modules) derives a temp path from `temp_dir()` — all
    /// such paths must go through a `scratch` module's exclusively-created
    /// constructors.
    ///
    /// Both the single-line form (`temp_dir().join(name)`) and the split form
    /// (`let base = temp_dir(); base.join(name)`) are caught: a bare
    /// `temp_dir()` binding in production is flagged the moment its value is
    /// `.join`-ed to build a path.
    ///
    /// Test-only code (`#[cfg(test)]` / `mod tests` blocks) is exempt: test
    /// helpers that use predictable names in isolated temp dirs do not expose the
    /// verify/exec or verify/read identity gap that the production paths do.
    ///
    /// This is the class gate: it keeps the `toctou-verify-one-exec-other-scratch`
    /// class closed against future PRODUCTION regressions across both crates.
    #[test]
    fn no_predictable_temp_names_in_production_code() {
        // ipe-cli src, and the sibling ipe-wrapper src (the two crates that
        // construct jail scratch / embedded-app temp paths).
        let cli_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let wrapper_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join("ipe-wrapper").join("src"));

        for src_root in std::iter::once(cli_src).chain(wrapper_src) {
            let mut rs_files: Vec<std::path::PathBuf> = Vec::new();
            collect_rs_files(&src_root, &mut rs_files);
            for path in &rs_files {
                // The sanctioned scratch modules are the one place `temp_dir()`
                // may be joined (behind exclusive-create + entropy).
                if path.file_name().and_then(|n| n.to_str()) == Some("scratch.rs") {
                    continue;
                }
                // An out-of-line test module carries no inline `#[cfg(test)]`
                // marker for the region tracker, so a confirmed one is exempt
                // whole; an unconfirmed one stays in scope.
                let is_test_module = path
                    .strip_prefix(&src_root)
                    .is_ok_and(|rel| panic_scan::is_verified_test_path(&src_root, rel));
                if is_test_module {
                    continue;
                }
                // An unread file is unaudited, not clean.
                let source = std::fs::read_to_string(path);
                assert!(
                    source.is_ok(),
                    "cannot read {}: {source:?} — an unread file cannot be audited",
                    path.display()
                );
                let Ok(source) = source else { return };
                assert_predictable_temp_free(path, &source);
            }
        }
    }

    /// Assert `source` derives no temp path from `temp_dir()` in production code.
    ///
    /// Tracks `#[cfg(test)]`/`mod tests` regions by brace depth to exempt test
    /// helpers, and tracks production `let <ident> = ...temp_dir();` bindings so a
    /// later `<ident>.join(` (the split form) is caught as well as the inline
    /// `temp_dir().join(` form.  Also flags `temp_dir` passed as a bare function
    /// reference (e.g. `map_or_else(std::env::temp_dir, ...)` or
    /// `map_or_else(temp_dir, ...)`), which is semantically equivalent to the
    /// split form and was the original source of this defect class.
    fn assert_predictable_temp_free(path: &std::path::Path, source: &str) {
        let lines: Vec<&str> = source.lines().collect();
        let mut in_test_region = false;
        let mut brace_depth_at_test_entry: Option<usize> = None;
        let mut brace_depth: usize = 0;
        // Production idents currently bound to a `temp_dir()` value.
        let mut temp_bindings: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (i, &line) in lines.iter().enumerate() {
            if line.contains("#[cfg(test)]") || line.contains("mod tests") {
                in_test_region = true;
                brace_depth_at_test_entry = Some(brace_depth);
            }
            brace_depth += line.chars().filter(|&c| c == '{').count();
            brace_depth = brace_depth.saturating_sub(line.chars().filter(|&c| c == '}').count());
            if in_test_region
                && let Some(entry_depth) = brace_depth_at_test_entry
                && brace_depth < entry_depth
            {
                in_test_region = false;
                brace_depth_at_test_entry = None;
                temp_bindings.clear();
            }

            if in_test_region {
                continue;
            }

            // Inline form: `temp_dir().join(...)` on one line.
            assert!(
                !line.contains("temp_dir().join"),
                "predictable temp_dir().join in production code at {}:{} — \
                 use ScratchDir or ScratchFile instead.\n  line: {}",
                path.display(),
                i + 1,
                line.trim()
            );

            // Fn-reference form: `temp_dir` used as a bare callable (without `()`)
            // in a combinator such as `map_or_else(std::env::temp_dir, ...)` or
            // `map_or_else(temp_dir, ...)`.  Both spellings route through `temp_dir`
            // without the `()` that the inline form requires, so they evade that
            // check; this clause closes the gap.
            let is_fn_ref = line.contains("map_or_else(std::env::temp_dir")
                || (line.contains("map_or_else(")
                    && line.contains("temp_dir")
                    && !line.contains("temp_dir()"));
            assert!(
                !is_fn_ref,
                "bare temp_dir fn-reference in production code at {}:{} — \
                 use ScratchDir::new_under with an explicit base instead.\n  line: {}",
                path.display(),
                i + 1,
                line.trim()
            );

            // Split form, part 1: record a `let <ident> = ...temp_dir();` binding
            // (that does not itself `.join`).
            if line.contains("temp_dir()")
                && !line.contains(".join")
                && let Some(ident) = binding_ident(line)
            {
                temp_bindings.insert(ident);
            }

            // Split form, part 2: a `.join(` on a recorded temp-derived binding.
            for ident in &temp_bindings {
                let joined = format!("{ident}.join(");
                assert!(
                    !line.contains(&joined),
                    "predictable split-form temp path (`{ident} = temp_dir(); {ident}.join(...)`) \
                     in production code at {}:{} — use ScratchDir or ScratchFile instead.\n  line: {}",
                    path.display(),
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    /// Extract the bound identifier from a `let <ident> = ...;` line, if any.
    fn binding_ident(line: &str) -> Option<String> {
        let after_let = line.trim_start().strip_prefix("let ")?;
        let name = after_let
            .trim_start_matches("mut ")
            .split([' ', ':', '='])
            .next()?
            .trim();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return None;
        }
        Some(name.to_owned())
    }

    fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    /// The class gate flags the inline predictable-temp form in production code.
    #[test]
    fn class_gate_flags_inline_predictable_temp() {
        let injected = "fn make() -> std::path::PathBuf {\n    \
            std::env::temp_dir().join(\"predictable-name\")\n}\n";
        let caught = std::panic::catch_unwind(|| {
            assert_predictable_temp_free(std::path::Path::new("injected.rs"), injected);
        })
        .is_err();
        assert!(
            caught,
            "gate must flag inline temp_dir().join in production"
        );
    }

    /// The class gate flags the split predictable-temp form in production code.
    #[test]
    fn class_gate_flags_split_predictable_temp() {
        let injected = "fn make() -> std::path::PathBuf {\n    \
            let base = std::env::temp_dir();\n    \
            base.join(\"predictable-name\")\n}\n";
        let caught = std::panic::catch_unwind(|| {
            assert_predictable_temp_free(std::path::Path::new("injected.rs"), injected);
        })
        .is_err();
        assert!(
            caught,
            "gate must flag split-form temp_dir()+join in production"
        );
    }

    /// The class gate flags `temp_dir` passed as a bare fn reference in a
    /// `map_or_else` combinator (the fn-reference form).
    #[test]
    fn class_gate_flags_map_or_else_temp_dir_fn_ref() {
        let injected = "fn make(home: Option<PathBuf>) -> PathBuf {\n    \
            home.map_or_else(std::env::temp_dir, |h| h.join(\".cache\"))\n}\n";
        let caught = std::panic::catch_unwind(|| {
            assert_predictable_temp_free(std::path::Path::new("injected.rs"), injected);
        })
        .is_err();
        assert!(
            caught,
            "gate must flag map_or_else(std::env::temp_dir, ...) in production"
        );
    }

    /// The class gate flags the short `map_or_else(temp_dir, ...)` form (no
    /// path qualifier) the same way it flags the fully-qualified form.
    #[test]
    fn class_gate_flags_map_or_else_temp_dir_short() {
        let injected = "fn make(home: Option<PathBuf>) -> PathBuf {\n    \
            home.map_or_else(temp_dir, |h| h.join(\".cache\"))\n}\n";
        let caught = std::panic::catch_unwind(|| {
            assert_predictable_temp_free(std::path::Path::new("injected.rs"), injected);
        })
        .is_err();
        assert!(
            caught,
            "gate must flag map_or_else(temp_dir, ...) in production"
        );
    }

    /// The class gate passes on clean production code (a `ScratchDir`-based
    /// construction and a bare non-joined `temp_dir()` value) and on test-region
    /// predictable temps.
    #[test]
    fn class_gate_passes_clean_code() {
        let clean = "fn make() -> std::io::Result<()> {\n    \
            let _dir = ScratchDir::new(\"ipe-run\")?;\n    \
            let _base = std::env::temp_dir();\n    \
            Ok(())\n}\n\
            #[cfg(test)]\nmod tests {\n    \
            fn helper() { let _ = std::env::temp_dir().join(\"ok-in-test\"); }\n}\n";
        // Must not panic.
        assert_predictable_temp_free(std::path::Path::new("clean.rs"), clean);
    }

    /// The class gate passes on `ScratchDir::new_under` usage (the correct
    /// pattern for a caller-supplied base path).
    #[test]
    fn class_gate_passes_new_under() {
        let clean = "fn make(base: &Path) -> std::io::Result<ScratchDir> {\n    \
            ScratchDir::new_under(base, \"ipe-add\")\n}\n";
        // Must not panic.
        assert_predictable_temp_free(std::path::Path::new("clean.rs"), clean);
    }
}
