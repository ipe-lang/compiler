//! The declared repository roots, parsed once into one owner per directory.
//!
//! Every root is one (tag, directory identity) pair: its spelling is
//! canonicalized and its directory identity ([`FileId`]) is taken from an
//! opened handle, so `.`, `./`, `a/..` and a symbolic link to a declared root
//! all name that one root and are refused as a second one. When roots nest,
//! a path belongs only to its deepest enclosing declared root: each root
//! records the nearest declared root that encloses it ([`Enclosure`]), and the
//! walk of an outer root skips everything under a directory whose identity is
//! one of its inner roots.

use crate::model::{RepoSpec, RepoTag};
use crate::walk::{FileId, shown};
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// The most roots one run may declare; `tests/max_repos.json` holds the same value.
pub const MAX_REPOS: usize = 64;

/// A non-empty `/`-joined relative path whose segments are plain names.
///
/// No segment is empty, `.` or `..`, so a prefix never climbs out of the
/// root it is relative to and compares segment by segment, never by bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelPrefix(String);

impl RelPrefix {
    /// Parses the remainder of a canonical path below an ancestor, or `None`.
    fn parse(rest: &Path) -> Option<Self> {
        let mut segments = Vec::new();
        for component in rest.components() {
            let std::path::Component::Normal(name) = component else {
                return None;
            };
            let name = name.to_str()?;
            if matches!(name, "" | "." | "..") || name.contains('/') {
                return None;
            }
            segments.push(name);
        }
        if segments.is_empty() {
            None
        } else {
            Some(Self(segments.join("/")))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The nearest declared root that encloses another, and where the inner one sits in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enclosure {
    outer: RepoTag,
    prefix: RelPrefix,
}

impl Enclosure {
    pub fn prefix(&self) -> &RelPrefix {
        &self.prefix
    }
}

/// One declared root: its tag, canonical UTF-8 directory, and directory identity.
#[derive(Debug, Clone)]
pub struct DeclaredRoot {
    tag: RepoTag,
    root: String,
    id: FileId,
    within: Option<Enclosure>,
}

impl DeclaredRoot {
    pub fn tag(&self) -> &RepoTag {
        &self.tag
    }

    /// The canonical root directory, as the UTF-8 text git is run in.
    pub fn root_str(&self) -> &str {
        &self.root
    }

    pub fn root(&self) -> &Path {
        Path::new(&self.root)
    }

    /// The identity the root directory had when the set was parsed.
    pub fn id(&self) -> FileId {
        self.id
    }

    pub fn within(&self) -> Option<&Enclosure> {
        self.within.as_ref()
    }
}

/// One row of the root set an index was built under.
///
/// `nesting` is the enclosing root's tag and the prefix this root sits at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordedRoot {
    pub tag: String,
    pub nesting: Option<(String, String)>,
}

/// Why a set of `--repo` roots was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoSetError {
    /// No root was declared.
    Empty,
    /// More than `limit` roots were declared.
    TooManyRoots { limit: usize },
    /// One tag names two roots.
    DuplicateTag(RepoTag),
    /// The root could not be canonicalized, opened, or inspected.
    Unreachable { tag: RepoTag, kind: io::ErrorKind },
    /// The root is not a directory.
    NotADirectory(RepoTag),
    /// The canonical root is not UTF-8, so git output could not name it.
    NonUtf8Root(RepoTag),
    /// Two tags name one directory.
    SameRoot { first: RepoTag, second: RepoTag },
    /// The host cannot prove directory identity, so a second root is refused.
    IdentityUnavailable,
}

impl fmt::Display for RepoSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = |t: &RepoTag| shown(t.as_str());
        match self {
            Self::Empty => f.write_str("no --repo to index"),
            Self::TooManyRoots { limit } => {
                write!(f, "more than {limit} --repo roots are declared")
            }
            Self::DuplicateTag(t) => write!(f, "--repo tag `{}` is given twice", tag(t)),
            Self::Unreachable { tag: t, kind } => {
                write!(f, "--repo `{}`: the root cannot be opened ({kind})", tag(t))
            }
            Self::NotADirectory(t) => write!(f, "--repo `{}`: the root is not a directory", tag(t)),
            Self::NonUtf8Root(t) => write!(f, "--repo `{}`: the root path is not UTF-8", tag(t)),
            Self::SameRoot { first, second } => write!(
                f,
                "--repo `{}` and `{}` name the same directory; declare each root once",
                tag(first),
                tag(second)
            ),
            Self::IdentityUnavailable => f.write_str(
                "several --repo roots need directory identity, which this platform does not provide; declare one root",
            ),
        }
    }
}

impl std::error::Error for RepoSetError {}

/// Whether the host can tell two directories apart by identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identity {
    /// Device and inode distinguish directories.
    Proven,
    /// Every directory compares equal, so only one root is safe.
    Unavailable,
}

const HOST_IDENTITY: Identity = if cfg!(unix) {
    Identity::Proven
} else {
    Identity::Unavailable
};

/// A root after canonicalization, before nesting is computed.
struct Probed {
    tag: RepoTag,
    root: PathBuf,
    id: FileId,
}

/// Canonicalizes `spec`'s root and takes its identity from an opened handle.
fn probe(spec: &RepoSpec) -> Result<Probed, RepoSetError> {
    let unreachable = |e: io::Error| RepoSetError::Unreachable {
        tag: spec.tag.clone(),
        kind: e.kind(),
    };
    let root = std::fs::canonicalize(&spec.root).map_err(unreachable)?;
    if root.to_str().is_none() {
        return Err(RepoSetError::NonUtf8Root(spec.tag.clone()));
    }
    let held = File::open(&root).map_err(unreachable)?;
    let md = held.metadata().map_err(unreachable)?;
    if !md.is_dir() {
        return Err(RepoSetError::NotADirectory(spec.tag.clone()));
    }
    Ok(Probed {
        tag: spec.tag.clone(),
        root,
        id: FileId::of(&md),
    })
}

/// The deepest declared root strictly above `inner`, found by directory identity.
fn enclosure(inner: &Probed, all: &[Probed]) -> Result<Option<Enclosure>, RepoSetError> {
    for ancestor in inner.root.ancestors().skip(1) {
        let md = std::fs::metadata(ancestor).map_err(|e| RepoSetError::Unreachable {
            tag: inner.tag.clone(),
            kind: e.kind(),
        })?;
        let id = FileId::of(&md);
        let Some(outer) = all.iter().find(|o| o.id == id) else {
            continue;
        };
        let prefix = inner
            .root
            .strip_prefix(ancestor)
            .ok()
            .and_then(RelPrefix::parse)
            .ok_or_else(|| RepoSetError::SameRoot {
                first: outer.tag.clone(),
                second: inner.tag.clone(),
            })?;
        return Ok(Some(Enclosure {
            outer: outer.tag.clone(),
            prefix,
        }));
    }
    Ok(None)
}

/// The declared roots of one run: non-empty, at most [`MAX_REPOS`], one directory per tag.
#[derive(Debug, Clone)]
pub struct RepoSet(Vec<DeclaredRoot>);

impl RepoSet {
    /// Parses the declared roots, refusing any set that gives a path two owners.
    pub fn parse(specs: &[RepoSpec]) -> Result<Self, RepoSetError> {
        Self::parse_with(specs, HOST_IDENTITY, probe)
    }

    fn parse_with(
        specs: &[RepoSpec],
        identity: Identity,
        probe: impl Fn(&RepoSpec) -> Result<Probed, RepoSetError>,
    ) -> Result<Self, RepoSetError> {
        if specs.is_empty() {
            return Err(RepoSetError::Empty);
        }
        if specs.len() > MAX_REPOS {
            return Err(RepoSetError::TooManyRoots { limit: MAX_REPOS });
        }
        for (i, spec) in specs.iter().enumerate() {
            if specs.iter().take(i).any(|s| s.tag == spec.tag) {
                return Err(RepoSetError::DuplicateTag(spec.tag.clone()));
            }
        }
        if specs.len() > 1 && identity == Identity::Unavailable {
            return Err(RepoSetError::IdentityUnavailable);
        }
        let probed = specs.iter().map(probe).collect::<Result<Vec<_>, _>>()?;
        for (i, second) in probed.iter().enumerate() {
            if let Some(first) = probed.iter().take(i).find(|p| p.id == second.id) {
                return Err(RepoSetError::SameRoot {
                    first: first.tag.clone(),
                    second: second.tag.clone(),
                });
            }
        }
        let mut roots = Vec::with_capacity(probed.len());
        for p in &probed {
            let within = if probed.len() > 1 {
                enclosure(p, &probed)?
            } else {
                None
            };
            let Some(root) = p.root.to_str() else {
                return Err(RepoSetError::NonUtf8Root(p.tag.clone()));
            };
            roots.push(DeclaredRoot {
                tag: p.tag.clone(),
                root: root.to_string(),
                id: p.id,
                within,
            });
        }
        Ok(Self(roots))
    }

    pub fn iter(&self) -> std::slice::Iter<'_, DeclaredRoot> {
        self.0.iter()
    }

    /// The roots nested directly in `outer`; a deeper root is reached through its parent.
    pub fn claimed_in(&self, outer: &DeclaredRoot) -> Vec<&DeclaredRoot> {
        self.0
            .iter()
            .filter(|r| r.within.as_ref().is_some_and(|w| w.outer == outer.tag))
            .collect()
    }

    /// The set as the rows an index records, sorted by tag.
    pub fn recorded(&self) -> Vec<RecordedRoot> {
        let mut rows: Vec<RecordedRoot> = self
            .0
            .iter()
            .map(|r| RecordedRoot {
                tag: r.tag.as_str().to_string(),
                nesting: r
                    .within
                    .as_ref()
                    .map(|w| (w.outer.as_str().to_string(), w.prefix.as_str().to_string())),
            })
            .collect();
        rows.sort();
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(tag: &str, root: &str) -> RepoSpec {
        RepoSpec {
            tag: RepoTag::parse(tag).unwrap(),
            root: root.to_string(),
        }
    }

    fn same_root(specs: &[RepoSpec]) -> bool {
        matches!(RepoSet::parse(specs), Err(RepoSetError::SameRoot { .. }))
    }

    /// A scratch directory beside the test binary, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        #[allow(clippy::expect_used)] // a scratch dir that cannot be made fails the test
        fn new(name: &str) -> Self {
            let exe = std::env::current_exe().expect("test binary path");
            let dir = exe
                .parent()
                .expect("test binary dir")
                .join("repo-set-fixtures")
                .join(format!("{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn path(&self, rel: &str) -> String {
            self.0.join(rel).to_str().unwrap().to_string()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn same_dir_two_tags_refused() {
        assert!(same_root(&[spec("a", "."), spec("b", "./")]));
        assert!(RepoSet::parse(&[spec("a", ".")]).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_same_dir_refused() {
        let s = Scratch::new("symlinked");
        std::fs::create_dir(s.0.join("a")).unwrap();
        std::os::unix::fs::symlink(s.0.join("a"), s.0.join("b")).unwrap();
        assert!(same_root(&[
            spec("a", &s.path("a")),
            spec("b", &s.path("b"))
        ]));
    }

    #[test]
    fn dotdot_spelling_same_dir_refused() {
        let s = Scratch::new("dotdot");
        std::fs::create_dir(s.0.join("sub")).unwrap();
        assert!(same_root(&[
            spec("a", &s.path("")),
            spec("b", &s.path("sub/.."))
        ]));
    }

    #[test]
    fn too_many_roots_refused() {
        let s = Scratch::new("too-many");
        let specs: Vec<RepoSpec> = (0..=MAX_REPOS)
            .map(|i| {
                std::fs::create_dir(s.0.join(format!("r{i}"))).unwrap();
                spec(&format!("t{i}"), &s.path(&format!("r{i}")))
            })
            .collect();
        assert_eq!(
            RepoSet::parse(&specs).err(),
            Some(RepoSetError::TooManyRoots { limit: MAX_REPOS })
        );
        let at_limit = specs.get(..MAX_REPOS).unwrap();
        assert_eq!(
            RepoSet::parse(at_limit).map(|set| set.iter().len()),
            Ok(MAX_REPOS)
        );
    }

    // The ceiling is one value: the code-review app reads the same vector file.
    #[test]
    fn max_repos_matches_the_shared_vector() {
        let row: serde_json::Value =
            serde_json::from_str(include_str!("../tests/max_repos.json")).unwrap();
        assert_eq!(
            row["max_repos"].as_u64(),
            u64::try_from(MAX_REPOS).ok(),
            "tests/max_repos.json has drifted from MAX_REPOS"
        );
    }

    // Off unix every directory compares equal, so a second root has no proof of
    // being another directory and is refused; one root still parses.
    #[test]
    fn second_root_refused_without_identity() {
        let two = [spec("a", "."), spec("b", "src")];
        assert_eq!(
            RepoSet::parse_with(&two, Identity::Unavailable, probe).err(),
            Some(RepoSetError::IdentityUnavailable)
        );
        assert!(RepoSet::parse_with(&two[..1], Identity::Unavailable, probe).is_ok());
        assert!(RepoSet::parse_with(&two, Identity::Proven, probe).is_ok());
    }

    #[test]
    fn a_root_that_is_absent_or_a_file_is_refused() {
        assert_eq!(
            RepoSet::parse(&[spec("a", "no-such-dir")]).err(),
            Some(RepoSetError::Unreachable {
                tag: RepoTag::parse("a").unwrap(),
                kind: io::ErrorKind::NotFound
            })
        );
        assert_eq!(
            RepoSet::parse(&[spec("a", "Cargo.toml")]).err(),
            Some(RepoSetError::NotADirectory(RepoTag::parse("a").unwrap()))
        );
    }

    // Each root records its nearest declared enclosure, by identity; a
    // grandchild is claimed through its parent alone.
    #[test]
    fn nesting_is_recorded_for_the_nearest_enclosing_root() {
        let s = Scratch::new("nesting");
        std::fs::create_dir_all(s.0.join("mid/deep")).unwrap();
        std::fs::create_dir(s.0.join("mid2")).unwrap();
        let set = RepoSet::parse(&[
            spec("out", &s.path("")),
            spec("mid", &s.path("mid")),
            spec("deep", &s.path("mid/./deep")),
            spec("sib", &s.path("mid2")),
        ])
        .unwrap();
        let nest = |outer: &str, prefix: &str| Some((outer.to_string(), prefix.to_string()));
        let row = |tag: &str, nesting| RecordedRoot {
            tag: tag.to_string(),
            nesting,
        };
        assert_eq!(
            set.recorded(),
            [
                row("deep", nest("mid", "deep")),
                row("mid", nest("out", "mid")),
                row("out", None),
                row("sib", nest("out", "mid2")),
            ]
        );
        let out = set.iter().next().unwrap();
        let claimed: Vec<&str> = set
            .claimed_in(out)
            .iter()
            .map(|r| r.tag().as_str())
            .collect();
        assert_eq!(claimed, ["mid", "sib"]);
    }
}
