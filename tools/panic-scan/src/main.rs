//! Flag authored abrupt-failure constructs in the production regions of Rust files.
//!
//! `panic-scan <file>…` scans the listed files; `panic-scan --walk <dir>…`
//! scans every `.rs` file and `Cargo.toml` under the listed directories. Exit 0
//! when clean, 1 when a banned construct is found, 2 when the input cannot be
//! audited — including when there is no input at all. The working directory is
//! the scanned root: every argument is a relative path inside it, and every
//! scanned file must resolve inside it.
//!
//! Test code ([`panic_scan::is_test_path`]) is skipped only once its test-only
//! premise is confirmed on disk ([`panic_scan::check_test_path`]); an
//! unconfirmed test path fails closed with exit 2, because a `pub mod tests;`
//! would put its body in the production build. For the same reason a
//! production `#[path]` or `include!` naming test code, a `Cargo.toml` whose
//! production target lies in test code, and a symlinked directory the walk
//! cannot vouch for all exit 2. A production `#[path]` or `include!` naming a
//! legal source is resolved and that source scanned in turn; one that escapes
//! the root, names no file, or lands in test or template code exits 2. Files
//! under `templates/` hold emitted-program Rust copied verbatim into every
//! generated binary, so they are scanned as production code. A file too large,
//! too many tokens long, or nested too deep to parse within the scanner's
//! ceilings exits 2. Inline `#[cfg(test)]` bodies are skipped by the scanner
//! itself.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use panic_scan::{
    IncludeForm, IncludeTarget, IncludedSource, PathRefusal, TestPathError, TestPathInclude,
};

/// Flag selecting directory-walk mode.
const WALK_FLAG: &str = "--walk";

/// File name of a crate manifest.
const MANIFEST_FILE: &str = "Cargo.toml";

/// Exit status for input that cannot be audited.
const EXIT_UNAUDITABLE: u8 = 2;

/// Why a command-line path is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgumentRefusal {
    /// The argument is empty.
    Empty,
    /// The argument is absolute, so it may lie outside the scanned root.
    Absolute,
    /// The argument climbs out through `..`.
    ParentDir,
}

impl fmt::Display for ArgumentRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "is empty",
            Self::Absolute => "is absolute",
            Self::ParentDir => "has a `..` component",
        })
    }
}

/// Why a run stops before its verdict.
#[derive(Debug)]
enum Unauditable {
    /// No file or directory was named.
    NoInput,
    /// A command-line path is not a relative path inside the working directory.
    Argument {
        path: String,
        reason: ArgumentRefusal,
    },
    /// A walk found no Rust file to scan.
    EmptyWalk { dirs: NonEmpty<PathBuf> },
    /// A test path's test-only premise does not hold.
    TestPath {
        path: PathBuf,
        source: TestPathError,
    },
    /// A manifest cannot be read or names test code as a production target.
    Manifest {
        path: PathBuf,
        source: TestPathError,
    },
    /// A file or directory could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A file is over a parse ceiling or does not parse as Rust.
    Parse {
        path: PathBuf,
        source: panic_scan::ScanError,
    },
    /// A walk met a symlink to a directory, whose contents it cannot vouch for.
    SymlinkedDirectory { path: PathBuf },
    /// A file to scan resolves outside the scanned root.
    OutsideRoot { path: PathBuf },
    /// A production file compiles in a source the scan cannot audit.
    TestPathInclude {
        path: PathBuf,
        includes: Vec<TestPathInclude>,
    },
}

impl fmt::Display for Unauditable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInput => write!(
                f,
                "no file named (usage: panic-scan <file>… | panic-scan {WALK_FLAG} <dir>…) — nothing audited; fail closed"
            ),
            Self::Argument { path, reason } => write!(
                f,
                "argument `{path}` {reason}; name paths relative to the working directory, inside it — fail closed"
            ),
            Self::EmptyWalk { dirs } => write!(
                f,
                "{WALK_FLAG} found no .rs file under {:?} — nothing audited; fail closed",
                dirs.iter().collect::<Vec<_>>()
            ),
            Self::TestPath { path, source } => write!(
                f,
                "{source} — cannot confirm {} is test-only; fail closed",
                path.display()
            ),
            Self::Manifest { path, source } => write!(
                f,
                "{source} — cannot confirm {} compiles no test code into production; fail closed",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(f, "cannot read {}: {source} — fail closed", path.display())
            }
            Self::Parse { path, source } => write!(
                f,
                "{}: could not parse as Rust within the scan ceilings ({source}) — cannot audit; fail closed",
                path.display()
            ),
            Self::SymlinkedDirectory { path } => write!(
                f,
                "{}: symlinked directory — the walk does not follow it, so it cannot be audited; fail closed",
                path.display()
            ),
            Self::OutsideRoot { path } => write!(
                f,
                "{}: resolves outside the working directory — fail closed",
                path.display()
            ),
            Self::TestPathInclude { path, includes } => {
                write!(f, "{}:", path.display())?;
                for include in includes {
                    write!(f, " {include};")?;
                }
                f.write_str(" fail closed")
            }
        }
    }
}

/// A list with at least one element.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NonEmpty<T> {
    first: T,
    rest: Vec<T>,
}

impl<T> NonEmpty<T> {
    /// The list `items`, or `None` when it is empty.
    fn from_vec(items: Vec<T>) -> Option<Self> {
        let mut items = items.into_iter();
        items.next().map(|first| Self {
            first,
            rest: items.collect(),
        })
    }

    /// Every element, first to last.
    fn iter(&self) -> impl Iterator<Item = &T> {
        std::iter::once(&self.first).chain(self.rest.iter())
    }
}

/// What the arguments ask the scan to cover.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    /// Scan exactly these files.
    Files(NonEmpty<PathBuf>),
    /// Scan every `.rs` file and manifest under these directories.
    Walk(NonEmpty<PathBuf>),
}

impl Mode {
    /// Parse the command-line arguments; naming no file or directory is no input.
    fn parse(args: &[String]) -> Result<Self, Unauditable> {
        let (walk, paths) = match args.split_first() {
            Some((flag, dirs)) if flag == WALK_FLAG => (true, dirs),
            _ => (false, args),
        };
        let paths = paths
            .iter()
            .map(|arg| parse_argument(arg))
            .collect::<Result<Vec<_>, _>>()?;
        let paths = NonEmpty::from_vec(paths).ok_or(Unauditable::NoInput)?;
        Ok(if walk {
            Self::Walk(paths)
        } else {
            Self::Files(paths)
        })
    }
}

/// Parse one argument into a relative path inside the working directory.
///
/// `.` components are dropped, so `./src/a.rs` and `src/a.rs` name the same
/// file; an argument that is only `.` names the working directory itself.
fn parse_argument(arg: &str) -> Result<PathBuf, Unauditable> {
    let refuse = |reason| Unauditable::Argument {
        path: arg.to_owned(),
        reason,
    };
    if arg.is_empty() {
        return Err(refuse(ArgumentRefusal::Empty));
    }
    let mut path = PathBuf::new();
    for component in Path::new(arg).components() {
        match component {
            Component::Normal(name) => path.push(name),
            Component::CurDir => {}
            Component::ParentDir => return Err(refuse(ArgumentRefusal::ParentDir)),
            Component::RootDir | Component::Prefix(_) => {
                return Err(refuse(ArgumentRefusal::Absolute));
            }
        }
    }
    if path.as_os_str().is_empty() {
        path.push(Component::CurDir);
    }
    Ok(path)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match Mode::parse(&args).and_then(|mode| run(&mode)) {
        Ok(true) => ExitCode::FAILURE,
        Ok(false) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("panic-scan: {reason}");
            ExitCode::from(EXIT_UNAUDITABLE)
        }
    }
}

/// Scan the files `mode` covers; `Ok(true)` when a banned construct is found.
fn run(mode: &Mode) -> Result<bool, Unauditable> {
    let files = match mode {
        Mode::Files(files) => files.iter().cloned().collect(),
        Mode::Walk(dirs) => walk_all(dirs)?,
    };
    let mut audit = Audit::new()?;
    // Files sharing a parent directory share their outermost test marker, so
    // one confirmed premise covers the whole directory.
    let mut verified_test_dirs: BTreeSet<PathBuf> = BTreeSet::new();
    let mut found = false;
    for path in &files {
        if panic_scan::is_test_path(path) {
            let dir = path.parent().unwrap_or_else(|| Path::new(""));
            if !verified_test_dirs.contains(dir) {
                panic_scan::check_test_path(Path::new(""), path).map_err(|source| {
                    Unauditable::TestPath {
                        path: path.clone(),
                        source,
                    }
                })?;
                verified_test_dirs.insert(dir.to_path_buf());
            }
            continue;
        }
        if is_manifest(path) {
            panic_scan::check_manifest(path).map_err(|source| Unauditable::Manifest {
                path: path.clone(),
                source,
            })?;
            continue;
        }
        found |= audit.scan_tree(path)?;
    }
    Ok(found)
}

/// Whether `path` names a crate manifest.
fn is_manifest(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == MANIFEST_FILE)
}

/// Whether `path` names a Rust source file.
fn is_rust_file(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "rs")
}

/// Run-wide scan state: the scanned root and every file already scanned.
struct Audit {
    /// The canonical working directory; no source outside it is audited.
    root: PathBuf,
    /// Canonical paths of the files already scanned, so each is scanned once.
    scanned: BTreeSet<PathBuf>,
}

impl Audit {
    /// State for a run rooted at the working directory.
    fn new() -> Result<Self, Unauditable> {
        let cwd = Path::new(".");
        let root = std::fs::canonicalize(cwd).map_err(|source| Unauditable::Io {
            path: cwd.to_path_buf(),
            source,
        })?;
        Ok(Self {
            root,
            scanned: BTreeSet::new(),
        })
    }

    /// Scan `start` and every legal source it includes, transitively.
    ///
    /// Each file is scanned at most once, so the work is bounded by the number
    /// of files under the root. `Ok(true)` when any banned construct is found.
    fn scan_tree(&mut self, start: &Path) -> Result<bool, Unauditable> {
        let mut pending = vec![start.to_path_buf()];
        let mut found = false;
        while let Some(path) = pending.pop() {
            let canonical = std::fs::canonicalize(&path).map_err(|source| Unauditable::Io {
                path: path.clone(),
                source,
            })?;
            if !canonical.starts_with(&self.root) {
                return Err(Unauditable::OutsideRoot { path });
            }
            if !self.scanned.insert(canonical) {
                continue;
            }
            let (hits, sources) = scan_file(&path)?;
            found |= hits;
            for source in sources {
                pending.extend(self.resolve(&path, &source)?);
            }
        }
        Ok(found)
    }

    /// The files a legal `#[path]` or `include!` in `file` compiles in.
    ///
    /// An `include!` resolves beside `file`. A `#[path]` inside inline modules
    /// resolves under those modules' directories, rooted either beside `file`
    /// (a `mod.rs` or crate root) or under its stem (any other module file);
    /// both readings are judged, and at least one must name a file. Each
    /// target is judged both as written (`..` folded lexically) and as the
    /// file system resolves it, and the resolved file is the one scanned.
    fn resolve(&self, file: &Path, source: &IncludedSource) -> Result<Vec<PathBuf>, Unauditable> {
        let dir = file.parent().unwrap_or_else(|| Path::new(""));
        let mut bases = vec![dir.to_path_buf()];
        if source.form == IncludeForm::PathAttr && !source.inline_mods.is_empty() {
            if let Some(stem) = file.file_stem() {
                bases.push(dir.join(stem));
            }
            for base in &mut bases {
                base.extend(&source.inline_mods);
            }
        }
        let refuse = |target| Unauditable::TestPathInclude {
            path: file.to_path_buf(),
            includes: vec![TestPathInclude {
                line: source.line,
                form: source.form,
                target,
            }],
        };
        let refused = |reason| {
            refuse(IncludeTarget::Refused {
                path: source.literal.clone(),
                reason,
            })
        };
        let mut targets = Vec::new();
        for base in bases {
            let joined = base.join(&source.literal);
            let lexical = normalize(&joined).ok_or_else(|| refused(PathRefusal::EscapesRoot))?;
            let canonical = match std::fs::canonicalize(&joined) {
                Ok(canonical) => canonical,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(Unauditable::Io {
                        path: joined,
                        source,
                    });
                }
            };
            let Ok(inside) = canonical.strip_prefix(&self.root) else {
                return Err(refused(PathRefusal::EscapesRoot));
            };
            for judged in [lexical.as_path(), inside] {
                if panic_scan::is_template_path(judged) {
                    return Err(refused(PathRefusal::Template));
                }
                if panic_scan::is_test_path(judged) {
                    return Err(refuse(IncludeTarget::TestPath(source.literal.clone())));
                }
            }
            if !canonical.is_file() {
                return Err(refused(PathRefusal::Missing));
            }
            targets.push(inside.to_path_buf());
        }
        if targets.is_empty() {
            return Err(refused(PathRefusal::Missing));
        }
        Ok(targets)
    }
}

/// `path` with `.` dropped and each `..` folded into its parent.
///
/// `None` when a `..` climbs above the start of `path` — out of the working
/// directory, since every scanned path is relative to it — or when `path` is
/// absolute.
fn normalize(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Scan one production file, printing each hit.
///
/// Returns whether any hit was found, with the legal sources the file includes.
fn scan_file(path: &Path) -> Result<(bool, Vec<IncludedSource>), Unauditable> {
    let src = panic_scan::read_source(path).map_err(|error| match error {
        panic_scan::SourceReadError::Io(source) => Unauditable::Io {
            path: path.to_path_buf(),
            source,
        },
        panic_scan::SourceReadError::Refused(source) => Unauditable::Parse {
            path: path.to_path_buf(),
            source,
        },
    })?;
    // A file the scanner cannot parse is unaudited, not clean: "cannot
    // analyze" must never read as "no panics".
    let scan = panic_scan::scan_source(&src).map_err(|source| Unauditable::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    if !scan.test_path_includes.is_empty() {
        return Err(Unauditable::TestPathInclude {
            path: path.to_path_buf(),
            includes: scan.test_path_includes,
        });
    }
    for hit in &scan.hits {
        println!(
            "{}:{}: banned abrupt-failure construct `{}`",
            path.display(),
            hit.line,
            hit.tok
        );
    }
    Ok((!scan.hits.is_empty(), scan.included_sources))
}

/// Every `.rs` file and manifest under `dirs`, in sorted order.
///
/// A walk that finds no Rust file is refused: an empty scan would read as a pass.
fn walk_all(dirs: &NonEmpty<PathBuf>) -> Result<Vec<PathBuf>, Unauditable> {
    let mut files = Vec::new();
    for dir in dirs.iter() {
        walk(dir, &mut files)?;
    }
    if files.iter().any(|path| is_rust_file(path)) {
        Ok(files)
    } else {
        Err(Unauditable::EmptyWalk { dirs: dirs.clone() })
    }
}

/// Append every `.rs` file and manifest under `dir` to `files`.
///
/// A symlink is judged by its target: a symlinked file is listed, so the scan
/// reads its target; a symlinked directory is refused, because the walk does
/// not follow it and so cannot vouch for what it holds.
fn walk(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), Unauditable> {
    let unreadable = |source: std::io::Error| Unauditable::Io {
        path: dir.to_path_buf(),
        source,
    };
    let mut entries = std::fs::read_dir(dir)
        .map_err(unreadable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(unreadable)?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(unreadable)?;
        if file_type.is_symlink() {
            let target = std::fs::metadata(&path).map_err(|source| Unauditable::Io {
                path: path.clone(),
                source,
            })?;
            if target.is_dir() {
                return Err(Unauditable::SymlinkedDirectory { path });
            }
        }
        if file_type.is_dir() {
            walk(&path, files)?;
        } else if is_rust_file(&path) || is_manifest(&path) {
            files.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| String::from(*arg)).collect()
    }

    #[test]
    fn naming_no_file_or_directory_is_no_input() {
        for list in [&[][..], &[WALK_FLAG][..]] {
            let mode = Mode::parse(&args(list));
            assert!(matches!(mode, Err(Unauditable::NoInput)), "{list:?}");
        }
    }

    #[test]
    fn arguments_select_the_mode() {
        let mode = Mode::parse(&args(&["a.rs", "b.rs"]));
        assert!(
            matches!(&mode, Ok(Mode::Files(files)) if files.iter().count() == 2),
            "{mode:?}"
        );
        let mode = Mode::parse(&args(&[WALK_FLAG, "src"]));
        assert!(
            matches!(&mode, Ok(Mode::Walk(dirs)) if dirs.first.as_path() == Path::new("src")),
            "{mode:?}"
        );
    }

    #[test]
    fn arguments_are_normalized() {
        for (arg, want) in [
            ("./src/a.rs", "src/a.rs"),
            ("src/./a.rs", "src/a.rs"),
            (".", "."),
            ("./", "."),
        ] {
            let path = parse_argument(arg);
            assert!(
                matches!(&path, Ok(p) if p.as_path() == Path::new(want)),
                "{arg}: {path:?}"
            );
        }
    }

    #[test]
    fn arguments_outside_the_working_directory_are_refused() {
        for (arg, want) in [
            ("", ArgumentRefusal::Empty),
            ("/etc/a.rs", ArgumentRefusal::Absolute),
            ("../a.rs", ArgumentRefusal::ParentDir),
            ("src/../a.rs", ArgumentRefusal::ParentDir),
        ] {
            let path = parse_argument(arg);
            assert!(
                matches!(&path, Err(Unauditable::Argument { reason, .. }) if *reason == want),
                "{arg}: {path:?}"
            );
        }
    }

    #[test]
    fn normalizing_folds_parents_and_refuses_escapes() {
        assert_eq!(
            normalize(Path::new("a/b/../c.rs")),
            Some(PathBuf::from("a/c.rs"))
        );
        assert_eq!(
            normalize(Path::new("./a/./c.rs")),
            Some(PathBuf::from("a/c.rs"))
        );
        assert_eq!(normalize(Path::new("a/../../c.rs")), None);
        assert_eq!(normalize(Path::new("/a/c.rs")), None);
    }
}
