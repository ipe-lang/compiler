//! Generator for `docs/reference/requirements.md`.
//!
//! Reads the version facts scattered across the repo's SSOT sources and
//! renders a single user-facing reference page that clearly separates a
//! **pinned** version (exact — the Rust toolchain, the edition) from a
//! **minimum** version (a floor — the database engine versions `Ipe.Db`
//! requires at connect time).
//!
//! Sources, each parsed with a strict text parser that fails the generator
//! (never silently defaults) when the expected shape is not found:
//! - `rust-toolchain.toml` — the `channel` key (an exact pin).
//! - the workspace `Cargo.toml` — the `edition` key.
//! - `src/runtime/rust/src/db.rs` — the `SQLITE_VERSION_FLOOR` /
//!   `POSTGRES_VERSION_FLOOR` constants (each an `EngineVersion::new(major,
//!   minor)`).
//!
//! The `db` feature (`sqlx` + `tokio`) is not pulled into this crate to read
//! those two integers: it would be a heavy, needless dependency for a
//! documentation generator, so the constants are parsed from source text
//! instead — the same trade-off `gen-env-docs` makes when it scans source for
//! `IPE_*` literals rather than linking every crate that reads one.
//!
//! The output is deterministic: the same sources always produce
//! byte-identical output.
//!
//! # Usage
//!
//! ```text
//! cargo run -p ipe_docs --bin gen-requirements-docs -- --repo-root <path>
//! ```
//!
//! By default `--repo-root` is the workspace root located by walking upward
//! from `CARGO_MANIFEST_DIR`.

#![forbid(unsafe_code)]

use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gen-requirements-docs: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let repo_root = find_repo_root()?;
    let facts = gather_facts(&repo_root)?;
    let content = render_requirements_docs(&facts);
    write_file(&repo_root.join("docs/reference/requirements.md"), &content)?;
    Ok(())
}

// ── Facts ───────────────────────────────────────────────────────────────────

/// The version facts surfaced in `docs/reference/requirements.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequirementsFacts {
    /// The exact `rust-toolchain.toml` `channel` pin.
    pub rust_channel: String,
    /// The workspace `Cargo.toml` `edition`.
    pub edition: String,
    /// `(major, minor)` — `SQLITE_VERSION_FLOOR`.
    pub sqlite_floor: (u32, u32),
    /// `(major, minor)` — `POSTGRES_VERSION_FLOOR`.
    pub postgres_floor: (u32, u32),
}

/// Read and strictly parse every source this doc depends on.
fn gather_facts(repo_root: &Path) -> Result<RequirementsFacts, String> {
    let toolchain_path = repo_root.join("rust-toolchain.toml");
    let toolchain_src = std::fs::read_to_string(&toolchain_path)
        .map_err(|e| format!("cannot read {}: {e}", toolchain_path.display()))?;
    let rust_channel = parse_rust_channel(&toolchain_src)?;

    let cargo_toml_path = repo_root.join("Cargo.toml");
    let cargo_toml_src = std::fs::read_to_string(&cargo_toml_path)
        .map_err(|e| format!("cannot read {}: {e}", cargo_toml_path.display()))?;
    let edition = parse_edition(&cargo_toml_src)?;

    let db_rs_path = repo_root.join("src/runtime/rust/src/db.rs");
    let db_rs_src = std::fs::read_to_string(&db_rs_path)
        .map_err(|e| format!("cannot read {}: {e}", db_rs_path.display()))?;
    let sqlite_floor = parse_engine_floor(&db_rs_src, "SQLITE_VERSION_FLOOR")?;
    let postgres_floor = parse_engine_floor(&db_rs_src, "POSTGRES_VERSION_FLOOR")?;

    Ok(RequirementsFacts {
        rust_channel,
        edition,
        sqlite_floor,
        postgres_floor,
    })
}

/// Strictly parse the `channel = "..."` key out of a `rust-toolchain.toml`
/// source string. Fails — never defaults — when the key is missing or
/// malformed.
fn parse_rust_channel(src: &str) -> Result<String, String> {
    let needle = "channel = \"";
    let start = src
        .find(needle)
        .ok_or_else(|| "cannot find `channel = \"...\"` in rust-toolchain.toml".to_owned())?;
    let rest = &src[start + needle.len()..];
    let end = rest
        .find('"')
        .ok_or_else(|| "unterminated `channel` string in rust-toolchain.toml".to_owned())?;
    let channel = &rest[..end];
    if channel.is_empty() {
        return Err("empty `channel` in rust-toolchain.toml".to_owned());
    }
    Ok(channel.to_owned())
}

/// Strictly parse the workspace `edition = "..."` key out of the root
/// `Cargo.toml` source string. Fails — never defaults — when the key is
/// missing or malformed.
fn parse_edition(src: &str) -> Result<String, String> {
    let needle = "edition = \"";
    let start = src
        .find(needle)
        .ok_or_else(|| "cannot find `edition = \"...\"` in Cargo.toml".to_owned())?;
    let rest = &src[start + needle.len()..];
    let end = rest
        .find('"')
        .ok_or_else(|| "unterminated `edition` string in Cargo.toml".to_owned())?;
    let edition = &rest[..end];
    if edition.is_empty() {
        return Err("empty `edition` in Cargo.toml".to_owned());
    }
    Ok(edition.to_owned())
}

/// Strictly parse `pub const <const_name>: EngineVersion = EngineVersion::new(major, minor);`
/// out of `db.rs`'s source text. Fails — never defaults — when the constant is
/// missing or its argument shape is not exactly two `u32` literals.
fn parse_engine_floor(src: &str, const_name: &str) -> Result<(u32, u32), String> {
    let needle = format!("pub const {const_name}: EngineVersion = EngineVersion::new(");
    let start = src
        .find(&needle)
        .ok_or_else(|| format!("cannot find `{needle}` in db.rs"))?;
    let rest = &src[start + needle.len()..];
    let end = rest
        .find(')')
        .ok_or_else(|| format!("unterminated `EngineVersion::new(...)` for {const_name}"))?;
    let args = &rest[..end];
    let mut parts = args.split(',').map(str::trim);

    let major = parts
        .next()
        .ok_or_else(|| format!("missing major version for {const_name}"))?
        .parse::<u32>()
        .map_err(|e| format!("invalid major version for {const_name}: {e}"))?;
    let minor = parts
        .next()
        .ok_or_else(|| format!("missing minor version for {const_name}"))?
        .parse::<u32>()
        .map_err(|e| format!("invalid minor version for {const_name}: {e}"))?;
    if parts.next().is_some() {
        return Err(format!(
            "unexpected extra argument in `EngineVersion::new(...)` for {const_name}"
        ));
    }
    Ok((major, minor))
}

// ── Renderer ─────────────────────────────────────────────────────────────────

/// Render `docs/reference/requirements.md` from the gathered facts. The
/// output is byte-identical for the same input.
#[must_use]
pub fn render_requirements_docs(facts: &RequirementsFacts) -> String {
    let mut out = String::new();

    out.push_str("<!-- Generated by gen-requirements-docs. Do not edit by hand. -->\n\n");
    out.push_str("# Version requirements\n\n");
    out.push_str(
        "The versions Ipê is built with and requires at runtime, split into two kinds: a **pinned** version is exact — every build uses precisely that release — while a **minimum** is a floor — the oldest release verified to work; anything newer is accepted.\n\n",
    );

    out.push_str("## Pinned exactly\n\n");
    out.push_str("| What | Version |\n");
    out.push_str("|------|---------|\n");
    let _ = writeln!(out, "| Rust toolchain | `{}` |", facts.rust_channel);
    let _ = writeln!(out, "| Edition | `{}` |", facts.edition);
    out.push('\n');

    out.push_str("## Minimum floor — database engines\n\n");
    out.push_str(
        "`Ipe.Db` refuses to connect, at connect time, to an engine below its floor rather than emit SQL the engine may not understand.\n\n",
    );
    out.push_str("| Engine | Minimum version |\n");
    out.push_str("|--------|------------------|\n");
    let _ = writeln!(
        out,
        "| SQLite | `{}.{}` |",
        facts.sqlite_floor.0, facts.sqlite_floor.1
    );
    let _ = writeln!(
        out,
        "| PostgreSQL | `{}.{}` |",
        facts.postgres_floor.0, facts.postgres_floor.1
    );
    out.push('\n');

    out
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn find_repo_root() -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--repo-root" {
            let path = args
                .next()
                .ok_or_else(|| "--repo-root requires a path argument".to_owned())?;
            return Ok(PathBuf::from(path));
        }
    }
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    find_workspace_root(Path::new(manifest_dir))
}

fn find_workspace_root(start: &Path) -> Result<PathBuf, String> {
    let mut current = start;
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            let content = std::fs::read_to_string(&candidate)
                .map_err(|e| format!("cannot read {}: {e}", candidate.display()))?;
            if content.contains("[workspace]") {
                return Ok(current.to_owned());
            }
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return Err("workspace root not found — pass --repo-root".to_owned()),
        }
    }
}

fn write_file(path: &Path, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_facts() -> RequirementsFacts {
        RequirementsFacts {
            rust_channel: "1.98.1".to_owned(),
            edition: "2024".to_owned(),
            sqlite_floor: (3, 35),
            postgres_floor: (9, 5),
        }
    }

    /// Resolve the workspace root (two levels up from this crate's manifest).
    fn workspace_root() -> PathBuf {
        let manifest = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest).join("../..")
    }

    /// Resolve a workspace-root-relative path.
    fn workspace_path(rel: &str) -> PathBuf {
        workspace_root().join(rel)
    }

    #[test]
    fn render_is_byte_idempotent() {
        let facts = sample_facts();
        let first = render_requirements_docs(&facts);
        let second = render_requirements_docs(&facts);
        assert_eq!(first, second, "two renders must be byte-identical");
    }

    #[test]
    fn render_contains_sentinel() {
        let out = render_requirements_docs(&sample_facts());
        assert!(
            out.contains("Generated by gen-requirements-docs"),
            "output must carry the generated-file sentinel"
        );
    }

    #[test]
    fn render_distinguishes_pinned_from_floor() {
        let out = render_requirements_docs(&sample_facts());
        assert!(out.contains("## Pinned exactly"));
        assert!(out.contains("## Minimum floor"));
        assert!(out.contains("`1.98.1`"), "must show the exact Rust pin");
        assert!(out.contains("`3.35`"), "must show the SQLite floor");
        assert!(out.contains("`9.5`"), "must show the PostgreSQL floor");
    }

    #[test]
    fn parse_rust_channel_succeeds_on_wellformed_toml() {
        let toml = "[toolchain]\nchannel = \"1.98.1\"\ncomponents = [\"clippy\"]\n";
        assert_eq!(parse_rust_channel(toml), Ok("1.98.1".to_owned()));
    }

    #[test]
    fn parse_rust_channel_fails_closed_when_key_absent() {
        let toml = "[toolchain]\ncomponents = [\"clippy\"]\n";
        assert!(
            parse_rust_channel(toml).is_err(),
            "a missing `channel` key must fail the generator, never default"
        );
    }

    #[test]
    fn parse_rust_channel_fails_closed_when_unterminated() {
        let toml = "[toolchain]\nchannel = \"1.98.1\n";
        assert!(
            parse_rust_channel(toml).is_err(),
            "an unterminated string must fail the generator, never default"
        );
    }

    #[test]
    fn parse_edition_fails_closed_when_key_absent() {
        assert!(parse_edition("[workspace.package]\nversion = \"1.0.0\"\n").is_err());
    }

    #[test]
    fn parse_engine_floor_succeeds_on_wellformed_const() {
        let src = "pub const SQLITE_VERSION_FLOOR: EngineVersion = EngineVersion::new(3, 35);\n";
        assert_eq!(parse_engine_floor(src, "SQLITE_VERSION_FLOOR"), Ok((3, 35)));
    }

    #[test]
    fn parse_engine_floor_fails_closed_when_const_absent() {
        let src = "pub const OTHER: u32 = 1;\n";
        assert!(
            parse_engine_floor(src, "SQLITE_VERSION_FLOOR").is_err(),
            "a missing constant must fail the generator, never default"
        );
    }

    #[test]
    fn parse_engine_floor_fails_closed_on_non_numeric_argument() {
        let src =
            "pub const SQLITE_VERSION_FLOOR: EngineVersion = EngineVersion::new(three, 35);\n";
        assert!(
            parse_engine_floor(src, "SQLITE_VERSION_FLOOR").is_err(),
            "a non-numeric argument must fail the generator, never default"
        );
    }

    #[test]
    fn parse_engine_floor_fails_closed_on_extra_argument() {
        let src = "pub const SQLITE_VERSION_FLOOR: EngineVersion = EngineVersion::new(3, 35, 0);\n";
        assert!(
            parse_engine_floor(src, "SQLITE_VERSION_FLOOR").is_err(),
            "an unexpected extra argument must fail the generator, never default"
        );
    }

    /// Drift gate: `gather_facts` run against the real repo sources must
    /// produce the facts baked into the committed `docs/reference/requirements.md`.
    #[test]
    fn gathered_facts_match_repo_sources() {
        let repo_root = workspace_root();
        let facts = gather_facts(&repo_root).expect("facts must parse from repo sources");
        assert_eq!(facts.sqlite_floor, (3, 35));
        assert_eq!(facts.postgres_floor, (9, 5));
        assert_eq!(facts.edition, "2024");
    }

    /// Committed file must match what the generator produces today.
    ///
    /// Run `cargo run -p ipe_docs --bin gen-requirements-docs` to regenerate.
    #[test]
    fn committed_requirements_md_matches_generator() {
        let repo_root = workspace_root();
        let facts = gather_facts(&repo_root).expect("facts must parse from repo sources");
        let path = workspace_path("docs/reference/requirements.md");
        let committed = std::fs::read_to_string(&path).expect(
            "cannot read docs/reference/requirements.md; \
             run `cargo run -p ipe_docs --bin gen-requirements-docs` to generate it",
        );
        let generated = render_requirements_docs(&facts);
        assert_eq!(
            committed, generated,
            "docs/reference/requirements.md is out of date.\n\
             Run `cargo run -p ipe_docs --bin gen-requirements-docs` to regenerate it."
        );
    }
}
