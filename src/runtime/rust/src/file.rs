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
// blocking-thread pool through `threads::join_blocking`; a build without the
// pool (no `tokio`, or wasm32) runs it inline.

/// Runs the blocking file operation `f` off the async worker.
///
/// A pool that cannot start a thread is an `Unavailable` error; a panic in `f`
/// is the "background file task panicked" error.
///
/// # Errors
///
/// `f` failed, no thread could be started for it, or it panicked.
async fn run_blocking<T, Ce, E, F>(f: F) -> Result<T, E>
where
    F: FnOnce() -> Result<T, Ce> + Send + 'static,
    T: Send + 'static,
    Ce: From<String> + Send + 'static,
    E: From<Ce> + crate::FromUnavailable,
{
    match crate::threads::join_blocking("File", f).await {
        Ok(done) => done.map_err(E::from),
        Err(crate::threads::BlockingFailure::Refused(refused)) => Err(refused.into_error()),
        Err(crate::threads::BlockingFailure::Panicked) => Err(E::from(Ce::from(
            "background file task panicked".to_owned(),
        ))),
    }
}

/// Default `File.readFile` ceiling in bytes, applied only when `IPE_FILE_READ_MAX` is unset.
pub const READ_FILE_DEFAULT_CEILING: u64 = 512 * 1024 * 1024;

/// Fixed `File.readFileBytes` ceiling in bytes.
///
/// Lower than the text ceiling because each input byte materialises as an
/// eight-byte `i64`.
const READ_FILE_BYTES_CEILING: u64 = 10 * 1024 * 1024;

/// The operator's `IPE_FILE_READ_MAX` setting; `0` refuses every non-empty file.
const FILE_READ_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_FILE_READ_MAX",
    READ_FILE_DEFAULT_CEILING,
    crate::system::ZeroCeiling::Accepted,
    "decimal byte count",
);

/// Resolves the `File.readFile` ceiling from `IPE_FILE_READ_MAX`.
///
/// The ceiling bounds an attacker-controlled path pointing at an unbounded
/// source (`/dev/zero`, a named pipe, a multi-GiB file) so it cannot exhaust
/// memory. A malformed setting fails the read closed rather than falling back.
fn file_read_ceiling() -> Result<u64, String> {
    FILE_READ_CEILING.read().map_err(String::from)
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
pub fn file_read_file<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
) -> IpeTask<E, String> {
    let path = path.into_string();
    Box::pin(async move {
        let cap = match file_read_ceiling() {
            Ok(cap) => cap,
            Err(e) => return IpeResult::Err(str_err(&e)),
        };
        match run_blocking(move || file_read_file_sync(&path, cap)).await {
            Ok(s) => ok_res(s),
            Err(e) => IpeResult::Err(e),
        }
    })
}

fn file_write_file_sync(path: &str, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("{e}"))
}

#[must_use]
pub fn file_write_file<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
    content: String,
) -> IpeTask<E, ()> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_write_file_sync(&path, &content)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(e),
        }
    })
}

#[must_use]
pub fn file_exists<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
) -> IpeTask<E, bool> {
    let path = path.into_string();
    Box::pin(async move {
        // The probe itself cannot fail; an `Err` here is a refused or panicked
        // offload, which is no answer about the path, so it is never `false`.
        match run_blocking(move || Ok::<_, String>(std::path::Path::new(&path).exists())).await {
            Ok(exists) => ok_res(exists),
            Err(e) => IpeResult::Err(e),
        }
    })
}

/// Alias of `file_remove` (the `remove` contract). Kept as a public name for
/// ABI stability; delegates so the two never drift.
#[must_use]
pub fn file_delete<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
) -> IpeTask<E, ()> {
    file_remove(path)
}

fn file_mkdir_all_sync(path: &str) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("{e}"))
}

/// `Ipe.File.mkdirAll : String -> Task Error ()` — create the directory
/// and every missing parent (mkdir -p). Already-exists is `Ok` (matching
/// `std::fs::create_dir_all`); a real I/O failure is `Err`.
#[must_use]
pub fn file_mkdir_all<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
) -> IpeTask<E, ()> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_mkdir_all_sync(&path)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(e),
        }
    })
}

// ─── Read variants ─────────────────────────────────────────────────────────

/// Opens `path` to read, following links, refusing anything but a regular file.
///
/// The open never blocks: a FIFO with no writer, or a device, is refused by a
/// `fstat` on the opened handle instead of stalling the reader, and a terminal
/// never becomes the controlling one.
#[cfg(unix)]
fn open_regular_following(path: &str) -> Result<std::fs::File, String> {
    use rustix::fs::{CWD, FileType, Mode, OFlags};
    let shown = |errno: rustix::io::Errno| format!("{}", std::io::Error::from(errno));
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    let fd = rustix::fs::openat(CWD, path, flags, Mode::empty()).map_err(shown)?;
    let stat = rustix::fs::fstat(&fd).map_err(shown)?;
    if !matches!(FileType::from_raw_mode(stat.st_mode), FileType::RegularFile) {
        return Err(format!("not a regular file: {path}"));
    }
    let status = rustix::fs::fcntl_getfl(&fd).map_err(shown)?;
    rustix::fs::fcntl_setfl(&fd, status.difference(OFlags::NONBLOCK)).map_err(shown)?;
    Ok(std::fs::File::from(fd))
}

/// Opens `path` to read, following links.
#[cfg(not(unix))]
fn open_regular_following(path: &str) -> Result<std::fs::File, String> {
    std::fs::File::open(path).map_err(|e| format!("{e}"))
}

fn file_read_file_limit_sync(path: &str, cap: u64) -> Result<String, String> {
    use std::io::Read as _;
    let f = open_regular_following(path)?;
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

/// Parses the raw limit argument of `kernel` into a byte ceiling.
///
/// `0` is the zero-byte ceiling; a negative value is refused. The stdlib
/// wrapper passes a non-negative `ByteSize`, so this is the independent second
/// boundary for any direct caller of the kernel.
fn read_limit(kernel: &str, limit: i64) -> Result<u64, String> {
    u64::try_from(limit)
        .map_err(|_| format!("{kernel}: limit must be a non-negative byte count (got {limit})"))
}

/// `Ipe.File.readFileLimit : String -> Int -> Task Error String`
/// Read at most `limit` bytes. Returns `Err` when the file is larger than
/// `limit` (to avoid OOM on unbounded inputs) or when the content is not
/// valid UTF-8 (use `readFileBytes` for binary data in that case).
/// A limit of `0` is a zero-byte ceiling (only an empty file reads); a
/// negative limit is refused before the file is opened. On Unix anything but a
/// regular file (a FIFO, a device, a socket) is refused without blocking; links
/// are followed, since this is the unconfined reader.
///
/// No separate `metadata()` pre-check: a stat-then-read split is TOCTOU — a
/// file that grows between the two syscalls would pass the stale size check
/// and then have `take(cap)` silently truncate. Reading `cap + 1` bytes in a
/// single pass and checking the bytes actually read (same idiom as
/// `file_read_file`, and `compression.rs`'s decompression-bomb check) leaves
/// nothing to race against.
#[must_use]
pub fn file_read_file_limit<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
    limit: i64,
) -> IpeTask<E, String> {
    let path = path.into_string();
    let cap = read_limit("File.readFileLimit", limit);
    Box::pin(async move {
        let cap = match cap {
            Ok(cap) => cap,
            Err(e) => return IpeResult::Err(str_err(&e)),
        };
        match run_blocking(move || file_read_file_limit_sync(&path, cap)).await {
            Ok(s) => ok_res(s),
            Err(e) => IpeResult::Err(e),
        }
    })
}

// ─── Root-confined read ────────────────────────────────────────────────────

/// The kernel name a confined-read refusal carries.
const BENEATH_KERNEL: &str = "File.readFileBeneath";

/// `Ipe.File.readFileBeneath` kernel: reads `rel` beneath the directory `root`, never following a link.
///
/// `root` must be absolute; `rel` must be relative, with no empty, `.` or `..`
/// component. Every component is opened relative to the directory handle
/// before it, starting from a held handle on `root`, and none is followed as a
/// symbolic link, the root's own final component included (its ancestors are
/// the operator's and are followed). The leaf must be a regular file with a
/// single hard link; a FIFO, a device or a socket is refused without blocking.
/// At most the smaller of `limit` and the `IPE_FILE_READ_MAX` ceiling is read:
/// a larger file is refused, never truncated, and a negative `limit` is refused
/// before any open.
///
/// Not proven: a bind mount inside `root`, and the trust of `root`'s
/// ancestors. A platform without a handle-relative open (Windows, wasm)
/// refuses every read.
#[must_use]
pub fn file_read_file_beneath(root: Path, rel: Path, limit: i64) -> IpeTask<IpeError, String> {
    let requested = read_limit(BENEATH_KERNEL, limit).map_err(IpeError::invalid_input);
    Box::pin(async move {
        let effective = requested.and_then(|cap| {
            file_read_ceiling()
                .map(|ceiling| cap.min(ceiling))
                .map_err(IpeError::invalid_input)
        });
        let cap = match effective {
            Ok(cap) => cap,
            Err(e) => return IpeResult::Err(e),
        };
        match run_blocking::<String, IpeError, IpeError, _>(move || beneath::read(&root, &rel, cap))
            .await
        {
            Ok(text) => ok_res(text),
            Err(e) => IpeResult::Err(e),
        }
    })
}

/// The handle-relative walk behind [`file_read_file_beneath`].
#[cfg(unix)]
mod beneath {
    use super::{BENEATH_KERNEL, IpeError, Path};
    use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};
    use rustix::io::Errno;
    use std::os::fd::{AsFd, OwnedFd};

    /// The kind of object a refused entry is.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Kind {
        Regular,
        Dir,
        Symlink,
        Fifo,
        Socket,
        Device,
        Other,
    }

    impl Kind {
        /// The kind a stat file type carries.
        const fn of(file_type: FileType) -> Self {
            match file_type {
                FileType::RegularFile => Self::Regular,
                FileType::Directory => Self::Dir,
                FileType::Symlink => Self::Symlink,
                FileType::Fifo => Self::Fifo,
                FileType::Socket => Self::Socket,
                FileType::CharacterDevice | FileType::BlockDevice => Self::Device,
                FileType::Unknown => Self::Other,
            }
        }

        /// The kind as a refusal names it.
        const fn label(self) -> &'static str {
            match self {
                Self::Regular => "regular file",
                Self::Dir => "directory",
                Self::Symlink => "symbolic link",
                Self::Fifo => "FIFO",
                Self::Socket => "socket",
                Self::Device => "device",
                Self::Other => "special file",
            }
        }
    }

    /// Why a confined read is refused.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum BeneathRefusal {
        /// The root is not an absolute path.
        RootNotAbsolute,
        /// The path beneath the root is absolute.
        RelAbsolute,
        /// A component of the path beneath the root is empty, `.`, `..`, or carries NUL.
        BadName,
        /// A component is a symbolic link.
        Link,
        /// A component walked as a directory is something else.
        NotDirectory(Kind),
        /// The leaf is not a regular file.
        NotRegular(Kind),
        /// The leaf has more than one hard link, so its name proves nothing about where it lives.
        HardLinked,
        /// The leaf holds more than `cap` bytes.
        TooLarge { cap: u64 },
        /// The leaf's bytes are not UTF-8.
        NotUtf8,
        /// A component does not exist.
        Absent,
        /// The operating system denied access.
        Denied,
        /// Any other failure, by kind.
        Io(std::io::ErrorKind),
    }

    impl BeneathRefusal {
        /// The refusal as fixed text; it never carries file content.
        fn describe(&self) -> String {
            match self {
                Self::RootNotAbsolute => "the root is not an absolute path".to_owned(),
                Self::RelAbsolute => "the path beneath the root is absolute".to_owned(),
                Self::BadName => {
                    "the path beneath the root has an empty, `.`, `..` or NUL-bearing component"
                        .to_owned()
                }
                Self::Link => "a symbolic link is never followed beneath the root".to_owned(),
                Self::NotDirectory(kind) => {
                    format!("a {} stands where a directory is walked", kind.label())
                }
                Self::NotRegular(kind) => format!("a {} is not a regular file", kind.label()),
                Self::HardLinked => "a file with more than one hard link is refused".to_owned(),
                Self::TooLarge { cap } => format!("file exceeds the {cap}-byte read ceiling"),
                Self::NotUtf8 => "file content is not valid UTF-8".to_owned(),
                Self::Absent => "no such file or directory".to_owned(),
                Self::Denied => "permission denied".to_owned(),
                Self::Io(kind) => format!("I/O failure: {kind}"),
            }
        }

        /// The typed error a refusal of reading `rel` surfaces as.
        fn into_error(self, rel: &str) -> IpeError {
            let message = format!("{BENEATH_KERNEL}: {rel:?}: {}", self.describe());
            match self {
                Self::RootNotAbsolute
                | Self::RelAbsolute
                | Self::BadName
                | Self::Link
                | Self::NotDirectory(_)
                | Self::NotRegular(_)
                | Self::HardLinked
                | Self::TooLarge { .. }
                | Self::NotUtf8 => IpeError::invalid_input(message),
                Self::Absent => IpeError::not_found().with_message(message),
                Self::Denied => IpeError::permission_denied().with_message(message),
                Self::Io(_) => IpeError::io(message),
            }
        }
    }

    /// One directory entry name: never empty, `.`, `..`, a separator, or NUL.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct EntryName(String);

    impl EntryName {
        /// Accepts `raw` as one entry name, or nothing.
        pub(super) fn parse(raw: &str) -> Option<Self> {
            let refused = raw.is_empty() || raw == "." || raw == ".." || raw.contains(['/', '\0']);
            (!refused).then(|| Self(raw.to_owned()))
        }
    }

    /// The absolute directory a confined read starts from.
    #[derive(Debug)]
    pub(super) struct BeneathRoot(String);

    impl BeneathRoot {
        /// Accepts `root` when it is absolute.
        pub(super) fn parse(root: &Path) -> Result<Self, BeneathRefusal> {
            if crate::path::path_is_absolute(root.clone()) {
                Ok(Self(root.as_str().to_owned()))
            } else {
                Err(BeneathRefusal::RootNotAbsolute)
            }
        }
    }

    /// The non-empty chain of names a confined read walks: directories, then the leaf.
    #[derive(Debug)]
    pub(super) struct BeneathPath {
        dirs: Vec<EntryName>,
        leaf: EntryName,
    }

    impl BeneathPath {
        /// Accepts `raw` as a relative, `/`-separated chain of entry names.
        pub(super) fn parse(raw: &str) -> Result<Self, BeneathRefusal> {
            if raw.starts_with('/') {
                return Err(BeneathRefusal::RelAbsolute);
            }
            let mut dirs = raw
                .split('/')
                .map(EntryName::parse)
                .collect::<Option<Vec<_>>>()
                .ok_or(BeneathRefusal::BadName)?;
            let leaf = dirs.pop().ok_or(BeneathRefusal::BadName)?;
            Ok(Self { dirs, leaf })
        }
    }

    /// A held directory handle every further step opens relative to.
    #[derive(Debug)]
    pub(super) struct HeldDir(OwnedFd);

    /// Flags for a directory step: never a link, never inherited by a child.
    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    /// Flags for the leaf: never a link, never blocking on a FIFO, never a controlling terminal.
    fn leaf_flags() -> OFlags {
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC
    }

    /// Whether `errno` reports a link met where none is followed.
    ///
    /// Linux and most systems answer `ELOOP`; FreeBSD answers `EMLINK` for an
    /// `O_NOFOLLOW` open of a link, and NetBSD `EFTYPE`.
    fn is_link_errno(errno: Errno) -> bool {
        #[cfg(target_os = "freebsd")]
        if errno == Errno::MLINK {
            return true;
        }
        #[cfg(target_os = "netbsd")]
        if errno == Errno::FTYPE {
            return true;
        }
        errno == Errno::LOOP
    }

    /// The refusal an `errno` from an open or a stat stands for.
    fn refusal(errno: Errno) -> BeneathRefusal {
        if errno == Errno::NOENT {
            BeneathRefusal::Absent
        } else if is_link_errno(errno) {
            BeneathRefusal::Link
        } else if errno == Errno::NXIO {
            BeneathRefusal::NotRegular(Kind::Socket)
        } else if errno == Errno::ACCESS || errno == Errno::PERM {
            BeneathRefusal::Denied
        } else {
            BeneathRefusal::Io(std::io::Error::from(errno).kind())
        }
    }

    /// Classifies a refused directory step on `name` under `dir`.
    ///
    /// A link and a non-directory both refuse the open; a no-follow stat of
    /// `name` tells them apart. The stat only names the refusal: nothing it
    /// reaches is opened.
    fn dir_refusal<Fd: AsFd>(dir: Fd, name: &str, errno: Errno) -> BeneathRefusal {
        if errno != Errno::NOTDIR && !is_link_errno(errno) {
            return refusal(errno);
        }
        match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => match Kind::of(FileType::from_raw_mode(stat.st_mode)) {
                Kind::Symlink => BeneathRefusal::Link,
                Kind::Dir => refusal(errno),
                kind @ (Kind::Regular | Kind::Fifo | Kind::Socket | Kind::Device | Kind::Other) => {
                    BeneathRefusal::NotDirectory(kind)
                }
            },
            Err(stat_errno) => refusal(stat_errno),
        }
    }

    /// Opens `root`, then each of `dirs` relative to the handle before it.
    pub(super) fn open_dir_chain(
        root: &BeneathRoot,
        dirs: &[EntryName],
    ) -> Result<HeldDir, BeneathRefusal> {
        let mut held = rustix::fs::openat(CWD, root.0.as_str(), dir_flags(), Mode::empty())
            .map(HeldDir)
            .map_err(|errno| dir_refusal(CWD, root.0.as_str(), errno))?;
        for name in dirs {
            held = rustix::fs::openat(&held.0, name.0.as_str(), dir_flags(), Mode::empty())
                .map(HeldDir)
                .map_err(|errno| dir_refusal(&held.0, name.0.as_str(), errno))?;
        }
        Ok(held)
    }

    /// Opens the leaf `name` under `dir` as a regular file with one hard link, ready to read.
    pub(super) fn open_leaf(
        dir: &HeldDir,
        name: &EntryName,
    ) -> Result<std::fs::File, BeneathRefusal> {
        let fd = rustix::fs::openat(&dir.0, name.0.as_str(), leaf_flags(), Mode::empty())
            .map_err(refusal)?;
        let stat = rustix::fs::fstat(&fd).map_err(refusal)?;
        let kind = Kind::of(FileType::from_raw_mode(stat.st_mode));
        if kind != Kind::Regular {
            return Err(BeneathRefusal::NotRegular(kind));
        }
        if stat.st_nlink != 1 {
            return Err(BeneathRefusal::HardLinked);
        }
        let status = rustix::fs::fcntl_getfl(&fd).map_err(refusal)?;
        rustix::fs::fcntl_setfl(&fd, status.difference(OFlags::NONBLOCK)).map_err(refusal)?;
        Ok(std::fs::File::from(fd))
    }

    /// Reads `file` as UTF-8, refusing it when it holds more than `cap` bytes.
    pub(super) fn read_capped(file: std::fs::File, cap: u64) -> Result<String, BeneathRefusal> {
        use std::io::Read as _;
        let mut bytes = Vec::new();
        let read = file
            .take(cap.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| BeneathRefusal::Io(e.kind()))?;
        if !u64::try_from(read).is_ok_and(|n| n <= cap) {
            return Err(BeneathRefusal::TooLarge { cap });
        }
        String::from_utf8(bytes).map_err(|_| BeneathRefusal::NotUtf8)
    }

    /// Reads the raw `rel` beneath `root`, both re-parsed before any syscall.
    pub(super) fn read_refusing(
        root: &Path,
        rel: &str,
        cap: u64,
    ) -> Result<String, BeneathRefusal> {
        let root = BeneathRoot::parse(root)?;
        let path = BeneathPath::parse(rel)?;
        let dir = open_dir_chain(&root, &path.dirs)?;
        read_capped(open_leaf(&dir, &path.leaf)?, cap)
    }

    /// Reads `rel` beneath `root`, a refusal surfacing as its typed error.
    pub(super) fn read(root: &Path, rel: &Path, cap: u64) -> Result<String, IpeError> {
        read_refusing(root, rel.as_str(), cap).map_err(|refused| refused.into_error(rel.as_str()))
    }
}

/// The confined read on a platform without a handle-relative open.
#[cfg(not(unix))]
mod beneath {
    use super::{BENEATH_KERNEL, IpeError, Path};

    /// Refuses every read: nothing here could hold the walk beneath the root.
    pub(super) fn read(_root: &Path, rel: &Path, _cap: u64) -> Result<String, IpeError> {
        Err(IpeError::invalid_input(format!(
            "{BENEATH_KERNEL}: {:?}: a root-confined read is unsupported on this platform",
            rel.as_str()
        )))
    }
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
pub fn file_read_file_bytes<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
) -> IpeTask<E, Vec<i64>> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_read_file_bytes_sync(&path)).await {
            Ok(v) => ok_res(v),
            Err(e) => IpeResult::Err(e),
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
pub fn file_append<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
    content: String,
) -> IpeTask<E, ()> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_append_sync(&path, &content)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(e),
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
pub fn file_remove<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
) -> IpeTask<E, ()> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_remove_sync(&path)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(e),
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
pub fn file_read_dir<E: Send + From<IpeError> + crate::FromUnavailable + 'static>(
    path: Path,
) -> IpeTask<E, Vec<String>> {
    let path = path.into_string();
    Box::pin(async move {
        match run_blocking(move || file_read_dir_sync(&path)).await {
            Ok(names) => ok_res(names),
            Err(e) => IpeResult::Err(e),
        }
    })
}

/// `Ipe.File.isDir : String -> Task Error Bool`
/// Returns `Ok(true)` when `path` exists and is a directory, `Ok(false)` when
/// it exists and is not a directory, and `Ok(false)` (not `Err`) when the path
/// does not exist — matching  shape (`os.Stat` error → `false`).
#[must_use]
pub fn file_is_dir<E: Send + From<String> + crate::FromUnavailable + 'static>(
    path: Path,
) -> IpeTask<E, bool> {
    let path = path.into_string();
    Box::pin(async move {
        // As in `file_exists`: an `Err` is a failed offload, never `false`.
        match run_blocking(move || {
            Ok::<_, String>(std::fs::metadata(&path).is_ok_and(|m| m.is_dir()))
        })
        .await
        {
            Ok(is_dir) => ok_res(is_dir),
            Err(e) => IpeResult::Err(e),
        }
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
pub fn file_temp_file<E: Send + From<IpeError> + crate::FromUnavailable + 'static>(
    prefix: String,
) -> IpeTask<E, String> {
    Box::pin(async move {
        match run_blocking(move || temp_file_sync(&prefix)).await {
            Ok(p) => ok_res(p),
            Err(e) => IpeResult::Err(e),
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
pub fn file_temp_dir<E: Send + From<IpeError> + crate::FromUnavailable + 'static>(
    prefix: String,
) -> IpeTask<E, String> {
    Box::pin(async move {
        match run_blocking(move || temp_dir_sync(&prefix)).await {
            Ok(p) => ok_res(p),
            Err(e) => IpeResult::Err(e),
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
pub fn file_copy<E: Send + From<String> + crate::FromUnavailable + 'static>(
    src: Path,
    dst: Path,
) -> IpeTask<E, ()> {
    let (src, dst) = (src.into_string(), dst.into_string());
    Box::pin(async move {
        match run_blocking(move || file_copy_sync(&src, &dst)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(e),
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
pub fn file_rename<E: Send + From<String> + crate::FromUnavailable + 'static>(
    src: Path,
    dst: Path,
) -> IpeTask<E, ()> {
    let (src, dst) = (src.into_string(), dst.into_string());
    Box::pin(async move {
        match run_blocking(move || file_rename_sync(&src, &dst)).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(e),
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
pub fn file_walk<E: Send + From<IpeError> + crate::FromUnavailable + 'static>(
    root: Path,
) -> IpeTask<E, Vec<Path>> {
    Box::pin(async move {
        match run_blocking(move || file_walk_sync(&root)).await {
            Ok(paths) => ok_res(paths),
            Err(e) => IpeResult::Err(e),
        }
    })
}

/// `Ipe.File.walkMatching : Path -> (Path -> Bool) -> Task Error (List Path)`
/// Like `walk`, but only includes files for which `pred` returns `True`.
/// The predicate receives the file's absolute `Path` and runs synchronously
/// during the walk (no `Task`, no I/O inside the predicate). Returns files in
/// deterministic (lexicographically sorted) order.
#[must_use]
pub fn file_walk_matching<E: Send + From<IpeError> + crate::FromUnavailable + 'static>(
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
            Err(e) => IpeResult::Err(e),
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

    #[test]
    fn env_ceilings_honour_the_shared_contract() {
        crate::system::assert_env_ceiling_contract(FILE_READ_CEILING);
    }

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

    /// The `IPE_FILE_READ_MAX` parse as `File.readFile` surfaces it.
    fn parse_read_ceiling(raw: Result<String, std::env::VarError>) -> Result<u64, String> {
        FILE_READ_CEILING.parse(raw).map_err(String::from)
    }

    #[test]
    fn ceiling_unset_is_the_default() {
        assert_eq!(
            parse_read_ceiling(Err(std::env::VarError::NotPresent)),
            Ok(READ_FILE_DEFAULT_CEILING)
        );
    }

    #[test]
    fn ceiling_decimal_values_are_bytes() {
        assert_eq!(parse_read_ceiling(Ok("0".into())), Ok(0));
        assert_eq!(parse_read_ceiling(Ok("1024".into())), Ok(1024));
        assert_eq!(
            parse_read_ceiling(Ok("18446744073709551615".into())),
            Ok(u64::MAX)
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
            matches!(&res, Err(e) if !e.contains(&"x".repeat(crate::system::ENV_VALUE_SHOWN_CHARS + 1))
                && e.contains(&"x".repeat(crate::system::ENV_VALUE_SHOWN_CHARS))),
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

#[cfg(test)]
#[cfg(unix)]
mod read_file_beneath_tests {
    use super::beneath::{
        BeneathRefusal, BeneathRoot, EntryName, open_dir_chain, open_leaf, read_capped,
        read_refusing,
    };
    use super::*;
    use crate::IpeErrorKind;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::Duration;

    /// How long one confined read may take before the test fails instead of hanging.
    const BOUND: Duration = Duration::from_secs(30);

    /// The bytes outside the root a confined read must never return.
    const SECRET: &str = "outside-the-root";

    fn block<T>(fut: impl std::future::Future<Output = T>) -> Option<T> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let out = rt.block_on(async { tokio::time::timeout(BOUND, fut).await.ok() });
        rt.shutdown_background();
        out
    }

    /// A scratch tree holding `root/` and a sibling `outside/` with `secret` and `f` in it.
    struct World(crate::scratch_core::ScratchDir);

    impl World {
        fn new() -> Self {
            Self::in_dir(crate::scratch_core::ScratchDir::new("ipe_beneath").unwrap())
        }

        /// A world under the short `/tmp`, for an entry with a path-length ceiling (a socket).
        fn short() -> Self {
            let tmp = std::path::Path::new("/tmp");
            Self::in_dir(crate::scratch_core::ScratchDir::new_under(tmp, "ib").unwrap())
        }

        fn in_dir(dir: crate::scratch_core::ScratchDir) -> Self {
            std::fs::create_dir(dir.path().join("root")).unwrap();
            std::fs::create_dir(dir.path().join("outside")).unwrap();
            std::fs::write(dir.path().join("outside").join("secret"), SECRET).unwrap();
            std::fs::write(dir.path().join("outside").join("f"), SECRET).unwrap();
            Self(dir)
        }

        fn base(&self) -> PathBuf {
            self.0.path().to_path_buf()
        }

        fn root(&self) -> PathBuf {
            self.base().join("root")
        }

        fn outside(&self) -> PathBuf {
            self.base().join("outside")
        }

        /// Writes `bytes` at `rel` beneath the root, creating its directories.
        fn put(&self, rel: &str, bytes: &[u8]) {
            let path = self.root().join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, bytes).unwrap();
        }
    }

    /// `text` through the one `Path` seal a program uses.
    fn sealed(text: &str) -> Path {
        let sealed = match crate::path::path_from_string::<IpeError>(text.to_owned()) {
            IpeResult::Ok(path) => Ok(path),
            IpeResult::Err(e) => Err(e),
        };
        sealed.expect("a test path passes the seal")
    }

    fn read_paths(root: Path, rel: Path, limit: i64) -> IpeResult<IpeError, String> {
        block(file_read_file_beneath(root, rel, limit))
            .expect("the confined read finished within the bound")
    }

    fn read_at(root: &std::path::Path, rel: &str, limit: i64) -> IpeResult<IpeError, String> {
        read_paths(tp(root), sealed(rel), limit)
    }

    /// The read was refused with `kind`, naming `fragment`, and never showed the outside bytes.
    fn assert_refused(res: &IpeResult<IpeError, String>, kind: IpeErrorKind, fragment: &str) {
        assert!(
            matches!(res, IpeResult::Err(IpeError::Error(k, info))
                if *k == kind && info.message.contains(fragment)),
            "expected {kind:?} naming {fragment:?}, got {res:?}"
        );
        assert!(
            !format!("{res:?}").contains(SECRET),
            "outside bytes leaked: {res:?}"
        );
    }

    fn assert_read(res: &IpeResult<IpeError, String>, want: &str) {
        assert!(
            matches!(res, IpeResult::Ok(text) if text == want),
            "expected {want:?}, got {res:?}"
        );
    }

    #[test]
    fn a_nested_regular_file_reads() {
        let world = World::new();
        world.put("a/b/c.txt", b"inside");
        assert_read(&read_at(&world.root(), "a/b/c.txt", 1024), "inside");
    }

    #[test]
    fn a_final_symlink_is_refused_not_followed() {
        let world = World::new();
        symlink(world.outside().join("secret"), world.root().join("x")).unwrap();
        assert_refused(
            &read_at(&world.root(), "x", 1024),
            IpeErrorKind::InvalidInput,
            "symbolic link is never followed",
        );
    }

    #[test]
    fn an_intermediate_symlink_or_file_is_refused() {
        let world = World::new();
        symlink(world.outside(), world.root().join("d")).unwrap();
        assert_refused(
            &read_at(&world.root(), "d/secret", 1024),
            IpeErrorKind::InvalidInput,
            "symbolic link is never followed",
        );
        world.put("plain", b"x");
        assert_refused(
            &read_at(&world.root(), "plain/x", 1024),
            IpeErrorKind::InvalidInput,
            "a regular file stands where a directory is walked",
        );
    }

    /// A dangling link is a link, never an absence.
    #[test]
    fn a_dangling_symlink_is_a_link_not_absent() {
        let world = World::new();
        symlink("nowhere", world.root().join("x")).unwrap();
        assert_refused(
            &read_at(&world.root(), "x", 1024),
            IpeErrorKind::InvalidInput,
            "symbolic link is never followed",
        );
    }

    /// A root that does not exist proves the refusal came before any open.
    fn missing_root() -> Path {
        let world = World::new();
        tp(&world.base().join("never-created"))
    }

    #[test]
    fn dot_dot_components_are_refused_before_any_open() {
        let root = missing_root();
        for raw in ["..", "../x", "a/..", "a/../../x", "a/./b"] {
            assert_eq!(
                read_refusing(&root, raw, 1024),
                Err(BeneathRefusal::BadName),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn an_absolute_path_beneath_the_root_is_refused() {
        let world = World::new();
        assert_refused(
            &read_at(&world.root(), "/etc/passwd", 1024),
            IpeErrorKind::InvalidInput,
            "the path beneath the root is absolute",
        );
        assert_eq!(
            read_refusing(&missing_root(), "/etc/passwd", 1024),
            Err(BeneathRefusal::RelAbsolute)
        );
    }

    #[test]
    fn empty_dot_and_nul_components_are_refused() {
        let root = missing_root();
        for raw in ["", ".", "a//b", "a/", "a/\0b", "\0"] {
            assert_eq!(
                read_refusing(&root, raw, 1024),
                Err(BeneathRefusal::BadName),
                "{raw:?}"
            );
        }
        let world = World::new();
        for sealed_text in ["", "."] {
            assert_refused(
                &read_at(&world.root(), sealed_text, 1024),
                IpeErrorKind::InvalidInput,
                "NUL-bearing component",
            );
        }
    }

    #[test]
    fn a_relative_root_is_refused() {
        assert_refused(
            &read_paths(sealed("repo"), sealed("f"), 1024),
            IpeErrorKind::InvalidInput,
            "the root is not an absolute path",
        );
    }

    /// The root's own final component is never followed; its ancestors are.
    #[test]
    fn a_symlinked_root_is_refused() {
        let world = World::new();
        world.put("f", b"ok");
        let alias = world.base().join("alias");
        symlink(world.root(), &alias).unwrap();
        assert_refused(
            &read_at(&alias, "f", 1024),
            IpeErrorKind::InvalidInput,
            "symbolic link is never followed",
        );
        assert_read(&read_at(&world.root(), "f", 1024), "ok");
    }

    /// Plants a FIFO with no writer at `path`.
    #[cfg(not(target_vendor = "apple"))]
    fn plant_fifo(path: &std::path::Path) {
        use rustix::fs::{CWD, FileType, Mode};
        rustix::fs::mknodat(CWD, path, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
    }

    #[cfg(not(target_vendor = "apple"))]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let world = World::new();
        plant_fifo(&world.root().join("p"));
        assert_refused(
            &read_at(&world.root(), "p", 1024),
            IpeErrorKind::InvalidInput,
            "a FIFO is not a regular file",
        );
    }

    /// The unconfined `readFileLimit` refuses a FIFO too, instead of hanging on its open.
    #[cfg(not(target_vendor = "apple"))]
    #[test]
    fn read_file_limit_refuses_a_fifo_without_blocking() {
        let world = World::new();
        let fifo = world.root().join("p");
        plant_fifo(&fifo);
        let res: IpeResult<String, String> = block(file_read_file_limit(tp(&fifo), 1024))
            .expect("readFileLimit finished within the bound");
        assert!(
            matches!(&res, IpeResult::Err(e) if e.contains("not a regular file")),
            "{res:?}"
        );
    }

    #[test]
    fn devices_sockets_and_directories_are_refused() {
        let world = World::short();
        symlink("/dev/null", world.root().join("dev")).unwrap();
        assert_refused(
            &read_at(&world.root(), "dev", 1024),
            IpeErrorKind::InvalidInput,
            "symbolic link is never followed",
        );
        let _listener = std::os::unix::net::UnixListener::bind(world.root().join("sock")).unwrap();
        assert_refused(
            &read_at(&world.root(), "sock", 1024),
            IpeErrorKind::InvalidInput,
            "a socket is not a regular file",
        );
        std::fs::create_dir(world.root().join("dir")).unwrap();
        assert_refused(
            &read_at(&world.root(), "dir", 1024),
            IpeErrorKind::InvalidInput,
            "a directory is not a regular file",
        );
    }

    #[test]
    fn the_cap_admits_exactly_its_bytes() {
        let world = World::new();
        world.put("over", &[b'a'; 17]);
        world.put("exact", &[b'a'; 16]);
        world.put("empty", b"");
        world.put("small", b"x");
        assert_refused(
            &read_at(&world.root(), "over", 16),
            IpeErrorKind::InvalidInput,
            "exceeds the 16-byte read ceiling",
        );
        assert_read(&read_at(&world.root(), "exact", 16), &"a".repeat(16));
        assert_read(&read_at(&world.root(), "empty", 0), "");
        assert_refused(
            &read_at(&world.root(), "small", 0),
            IpeErrorKind::InvalidInput,
            "exceeds the 0-byte read ceiling",
        );
    }

    #[test]
    fn a_negative_limit_is_refused_before_any_open() {
        for bad in [-1_i64, i64::MIN] {
            let res = read_paths(missing_root(), sealed("f"), bad);
            assert_refused(
                &res,
                IpeErrorKind::InvalidInput,
                "File.readFileBeneath: limit must be a non-negative byte count",
            );
        }
    }

    /// A limit above the operator ceiling reads no more than the ceiling.
    #[test]
    fn the_operator_ceiling_bounds_a_larger_limit() {
        let world = World::new();
        world.put("five", b"12345");
        world.put("four", b"1234");
        crate::system::locked_set_var("IPE_FILE_READ_MAX", "4");
        let five = read_at(&world.root(), "five", 1024);
        let four = read_at(&world.root(), "four", 1024);
        crate::system::locked_remove_var("IPE_FILE_READ_MAX");
        assert_refused(
            &five,
            IpeErrorKind::InvalidInput,
            "exceeds the 4-byte read ceiling",
        );
        assert_read(&four, "1234");
    }

    #[test]
    fn non_utf8_content_is_refused() {
        let world = World::new();
        world.put("bin", &[0xff, 0xfe]);
        assert_refused(
            &read_at(&world.root(), "bin", 1024),
            IpeErrorKind::InvalidInput,
            "not valid UTF-8",
        );
    }

    /// A hard link to an outside inode has an inside name; its link count refuses it.
    #[test]
    fn a_hard_linked_file_is_refused() {
        let world = World::new();
        std::fs::hard_link(world.outside().join("secret"), world.root().join("h")).unwrap();
        assert_refused(
            &read_at(&world.root(), "h", 1024),
            IpeErrorKind::InvalidInput,
            "more than one hard link",
        );
    }

    #[test]
    fn a_missing_file_is_not_found() {
        let world = World::new();
        assert_refused(
            &read_at(&world.root(), "missing", 1024),
            IpeErrorKind::NotFound,
            "no such file or directory",
        );
    }

    /// Swapping a walked directory for a link after the walk holds it cannot redirect the read.
    #[test]
    fn a_directory_swapped_for_a_link_mid_walk_reads_the_held_inode() {
        let world = World::new();
        world.put("d/f", b"inside");
        let root = BeneathRoot::parse(&tp(&world.root())).unwrap();
        let held = open_dir_chain(&root, &[EntryName::parse("d").unwrap()]).unwrap();
        std::fs::rename(world.root().join("d"), world.root().join("moved")).unwrap();
        symlink(world.outside(), world.root().join("d")).unwrap();
        let file = open_leaf(&held, &EntryName::parse("f").unwrap()).unwrap();
        assert_eq!(read_capped(file, 1024), Ok("inside".to_owned()));
        assert_refused(
            &read_at(&world.root(), "d/f", 1024),
            IpeErrorKind::InvalidInput,
            "symbolic link is never followed",
        );
    }
}

#[cfg(all(test, not(unix)))]
mod read_file_beneath_stub_tests {
    use super::*;

    #[test]
    fn every_confined_read_is_refused_as_unsupported() {
        let path = match crate::path::path_from_string::<IpeError>("x".to_owned()) {
            IpeResult::Ok(path) => Ok(path),
            IpeResult::Err(e) => Err(e),
        }
        .expect("a test path passes the seal");
        let res = beneath::read(&path, &path, 0);
        assert!(
            matches!(&res, Err(IpeError::Error(crate::IpeErrorKind::InvalidInput, info))
                if info.message.contains("unsupported on this platform")),
            "{res:?}"
        );
    }
}
