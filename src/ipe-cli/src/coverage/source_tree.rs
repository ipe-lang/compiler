//! The one way a coverage column reads a source tree: every file the walk lists
//! is read, or the whole tree is refused.
//!
//! A column that certifies "no file mentions X" or "some file mentions X" is only
//! as good as the set of files it read. Listing goes through
//! [`panic_scan::rust_sources`], which refuses rather than shortens, and every
//! listed file is read whole; an unreadable one refuses the tree too. A column
//! turns the refusal into a hole naming its cause, never into an absent mention.

use std::fmt;
use std::path::{Path, PathBuf};

use panic_scan::{WalkError, Want, rust_sources};

/// Why a source tree a column scans could not be read whole.
#[derive(Debug)]
pub enum TreeRefusal {
    /// The walker refused to list the tree.
    Walk(WalkError),
    /// A listed file could not be read.
    Read {
        file: PathBuf,
        error: std::io::Error,
    },
}

impl fmt::Display for TreeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Walk(error) => write!(f, "the source tree cannot be listed whole ({error})"),
            Self::Read { file, error } => {
                write!(f, "source {} is unreadable ({error})", file.display())
            }
        }
    }
}

impl std::error::Error for TreeRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Walk(error) => Some(error),
            Self::Read { error, .. } => Some(error),
        }
    }
}

/// Hand `visit` the path and text of every file under `root` that `want` admits,
/// in sorted path order.
///
/// # Errors
///
/// A [`TreeRefusal`] when the walk refuses the tree or a listed file cannot be
/// read as UTF-8 text; files visited before the refusal must be treated as
/// unscanned by the caller, never as a partial pass.
pub fn for_each_source(
    root: &Path,
    want: Want,
    mut visit: impl FnMut(&Path, &str),
) -> Result<(), TreeRefusal> {
    for path in rust_sources(root, want).map_err(TreeRefusal::Walk)? {
        match std::fs::read_to_string(&path) {
            Ok(text) => visit(&path, &text),
            Err(error) => return Err(TreeRefusal::Read { file: path, error }),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file the walk lists but no read can decode refuses the tree.
    #[test]
    fn an_unreadable_listed_file_refuses_the_tree() {
        let root = ipe_test_temp::temp_root()
            .join(format!("ipe-coverage-source-tree-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.rs"), "fn a() {}\n").unwrap();
        std::fs::write(root.join("b.rs"), [0xff_u8, 0xfe, 0x00]).unwrap();
        let mut seen = Vec::new();
        let outcome = for_each_source(&root, Want::RustFiles, |path, _| {
            seen.push(path.to_path_buf());
        });
        std::fs::remove_dir_all(&root).unwrap();
        assert!(
            matches!(&outcome, Err(TreeRefusal::Read { file, .. }) if file.ends_with("b.rs")),
            "{outcome:?}"
        );
        assert_eq!(seen, vec![root.join("a.rs")]);
    }

    /// A missing root is a refusal, never an empty tree.
    #[test]
    fn a_missing_root_refuses_the_tree() {
        let root = ipe_test_temp::temp_root().join(format!(
            "ipe-coverage-source-tree-missing-{}",
            std::process::id()
        ));
        let outcome = for_each_source(&root, Want::RustFiles, |_, _| {});
        assert!(
            matches!(&outcome, Err(TreeRefusal::Walk(WalkError::Missing { .. }))),
            "{outcome:?}"
        );
    }
}
