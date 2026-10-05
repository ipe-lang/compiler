//! The identity of the ipe-index build that extracts an index.
//!
//! `build.rs` includes this file by `#[path]` and hands the digest to the
//! crate as `env!("IPE_INDEX_EXTRACTOR")`; the crate compiles it only for the
//! test that recomputes the digest over the same sources.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The deepest directory level under `src/` the digest walks.
const MAX_DEPTH: usize = 16;

/// The most files the digest reads.
const MAX_FILES: usize = 4096;

/// The files beside `src/` whose bytes change what the extractor produces.
const MANIFEST_FILES: [&str; 2] = ["Cargo.toml", "Cargo.lock"];

/// The `blake3:<64 hex>` digest of the extractor sources under `root`.
///
/// It covers every regular file under `src/`, plus `Cargo.toml` and
/// `Cargo.lock`, in sorted order of their `/`-joined relative paths. Each
/// file is framed as its path length (u64 LE), path bytes, content length
/// (u64 LE) and content bytes, so no two inputs share a byte stream. A
/// symbolic link, any other non-regular entry, a name that is not UTF-8, a
/// tree deeper than [`MAX_DEPTH`], or more than [`MAX_FILES`] files is an
/// error.
pub fn extractor_digest(root: &Path) -> io::Result<String> {
    let mut files = source_files(root)?;
    for name in MANIFEST_FILES {
        let path = root.join(name);
        if !fs::symlink_metadata(&path)?.file_type().is_file() {
            return Err(refusal(&path, "is not a regular file"));
        }
        files.push((name.to_string(), path));
    }
    if files.len() > MAX_FILES {
        return Err(io::Error::other(format!(
            "the extractor digest reads at most {MAX_FILES} files"
        )));
    }
    files.sort();
    let mut hasher = blake3::Hasher::new();
    for (rel, path) in &files {
        let bytes = fs::read(path)?;
        hasher.update(&frame_len(rel.len())?);
        hasher.update(rel.as_bytes());
        hasher.update(&frame_len(bytes.len())?);
        hasher.update(&bytes);
    }
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

/// Every regular file under `root/src`, as its `/`-joined relative path and its path.
fn source_files(root: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let mut files = Vec::new();
    let mut dirs = vec![(root.join("src"), "src".to_string(), 0_usize)];
    while let Some((dir, rel, depth)) = dirs.pop() {
        if depth > MAX_DEPTH {
            return Err(refusal(&dir, "is nested too deep for the extractor digest"));
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| refusal(&path, "is not named in UTF-8"))?;
            let child = format!("{rel}/{name}");
            let kind = entry.file_type()?;
            if kind.is_dir() {
                dirs.push((path, child, depth + 1));
            } else if kind.is_file() {
                if files.len() >= MAX_FILES {
                    return Err(io::Error::other(format!(
                        "the extractor digest reads at most {MAX_FILES} files"
                    )));
                }
                files.push((child, path));
            } else {
                return Err(refusal(&path, "is neither a regular file nor a directory"));
            }
        }
    }
    Ok(files)
}

/// A length as the eight little-endian bytes that frame it.
fn frame_len(len: usize) -> io::Result<[u8; 8]> {
    u64::try_from(len)
        .map(u64::to_le_bytes)
        .map_err(|_| io::Error::other("a length does not fit in 64 bits"))
}

/// The error naming `path` as an input the digest refuses.
fn refusal(path: &Path, why: &str) -> io::Error {
    io::Error::other(format!("{} {why}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The digest the binary carries is the one its own sources give, so an
    // input `build.rs` misses, or a change it does not rerun on, turns this red.
    #[test]
    fn extractor_digest_names_this_source() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(extractor_digest(root).unwrap(), env!("IPE_INDEX_EXTRACTOR"));
    }

    // A symbolic link under `src/` is refused, never followed.
    #[cfg(unix)]
    #[test]
    fn extractor_digest_refuses_a_symbolic_link() {
        let root = std::env::current_exe()
            .unwrap()
            .with_file_name(format!("ipe-index-digest-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).unwrap();
        for name in MANIFEST_FILES {
            fs::write(root.join(name), "").unwrap();
        }
        fs::write(root.join("src/a.rs"), "fn a() {}\n").unwrap();
        assert!(extractor_digest(&root).is_ok());
        std::os::unix::fs::symlink("a.rs", root.join("src/b.rs")).unwrap();
        let err = extractor_digest(&root).map(|_| ()).unwrap_err();
        assert!(err.to_string().contains("neither a regular file"), "{err}");
        fs::remove_dir_all(&root).unwrap();
    }
}
