//! Generator for `docs/reference/cli.md`.
//!
//! Renders the CLI surface (`help::COMMANDS` / `SECTIONS` / `GROUPS`) via
//! [`ipe::cli_docs::render_cli_docs`] into `docs/reference/cli.md`. The output is
//! deterministic: commands, sections, and groups appear in registry order, so
//! the same tables always produce byte-identical output.
//!
//! # Usage
//!
//! ```text
//! cargo run -p ipe --bin gen-cli-docs -- --repo-root <path>
//! ```
//!
//! By default `--repo-root` is the workspace root located by walking upward from
//! `CARGO_MANIFEST_DIR`. A CI drift gate runs this generator and fails the build
//! when the committed `docs/reference/cli.md` differs from the regenerated one,
//! so an added command or flag that is not documented reddens the build.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            ipe::screen::chatter(
                ipe::screen::Stream::Stderr,
                ipe::screen::Tone::UserError,
                &format!("gen-cli-docs: {e}"),
            );
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let repo_root = find_repo_root()?;
    let content = ipe::cli_docs::render_cli_docs();
    let path = repo_root.join("docs/reference/cli.md");
    std::fs::write(&path, &content).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

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
