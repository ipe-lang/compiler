//! The `ipe add` / `ipe remove` package-authoring commands.
//!
//! These add and remove Ipê packages (not Rust crates — that is `ipe rust`).
//! `ipe add <name>[@<req>]` resolves the package through the index (fetch,
//! hash-verify, lock) and records the requirement in the project's `package.ipe`
//! manifest; `ipe remove <name>` drops it from both. The resolution and the
//! manifest rewrite live in [`crate::resolve`] and
//! [`crate::package_manifest::upsert_index_dependency`].

use std::path::PathBuf;

use crate::CliError;
use crate::text;

/// `ipe add <package>[@<req>]` — add an Ipê package dependency.
///
/// Resolves the requirement through the index (verify-before-trust), records the
/// exact pin in `ipe.lock`, and writes the `dep "<name>" "<req>"` entry into
/// `package.ipe` so a fresh clone re-resolves the same dependency.
///
/// # Errors
/// [`CliError::UsageOwned`] when no package is named or the requirement is
/// malformed; [`CliError::Usage`] when there is no `package.ipe` here;
/// [`CliError::Resolve`] / [`CliError::HashMismatch`] on a resolution or
/// integrity failure; [`CliError::Io`] on a filesystem failure.
pub fn run_add(rest: &[String]) -> Result<(), CliError> {
    let (name, req) = parse_add_arg(rest)?;
    let project_root = project_root()?;
    crate::resolve::resolve_and_add(&project_root, name, &req, &crate::resolve::index_root()?)
}

/// `ipe remove <package>` — remove an Ipê package dependency from both
/// `package.ipe` and `ipe.lock`.
///
/// # Errors
/// [`CliError::UsageOwned`] when no package is named; [`CliError::Usage`] when
/// there is no `package.ipe` here; [`CliError::Io`] on a filesystem failure.
pub fn run_remove(rest: &[String]) -> Result<(), CliError> {
    let package = package_arg(rest, "remove")?;
    let project_root = project_root()?;
    crate::resolve::resolve_and_remove(&project_root, package)
}

/// The current directory, confirmed to be an Ipê project holding a `package.ipe`.
///
/// The manifest reader/writer both key off this root.
///
/// # Errors
/// [`CliError::Io`] if the current directory cannot be read; [`CliError::Usage`]
/// when there is no `package.ipe` here (with the legacy-toml hint when only a
/// legacy `ipe.toml` is present).
fn project_root() -> Result<PathBuf, CliError> {
    let cwd = std::env::current_dir().map_err(|e| CliError::Io {
        path: PathBuf::from("."),
        source: e,
    })?;
    if crate::project::manifest_in_dir(&cwd).is_some() {
        return Ok(cwd);
    }
    if crate::project::has_only_legacy_toml(&cwd) {
        return Err(CliError::Usage(text::legacy_toml_hint()));
    }
    Err(CliError::Usage(text::pkg_no_manifest()))
}

/// Parse `ipe add`'s single argument into a package name and a version
/// requirement. The `name@req` split takes the requirement after the first `@`;
/// with no `@`, the requirement is `*` (the latest published version).
///
/// # Errors
/// [`CliError::UsageOwned`] on the wrong number of arguments or a malformed
/// requirement.
fn parse_add_arg(rest: &[String]) -> Result<(&str, semver::VersionReq), CliError> {
    let arg = package_arg(rest, "add")?;
    let (name, req_str) = arg.split_once('@').map_or((arg, "*"), |(n, r)| (n, r));
    if name.is_empty() {
        return Err(CliError::UsageOwned(text::pkg_usage(&"add")));
    }
    let req = req_str
        .parse::<semver::VersionReq>()
        .map_err(|e| CliError::UsageOwned(text::pkg_invalid_requirement(&req_str, &e)))?;
    Ok((name, req))
}

/// The single positional package argument shared by `add` and `remove`. Extra
/// positionals or none at all are misuse, and a leading-`-` token is an unknown
/// flag (rejected as such rather than accepted as a package name) so a flag typo
/// cannot masquerade as a dependency name and slip past with an exit-0 "nothing
/// to remove".
///
/// # Errors
/// [`CliError::UsageOwned`] naming the command's usage, or the shared
/// unknown-flag phrasing on a leading-`-` token.
fn package_arg<'a>(rest: &'a [String], command: &str) -> Result<&'a str, CliError> {
    match rest {
        [one] if one.starts_with('-') => Err(crate::cli_args::usage_unknown_flag(command, one)),
        [one] => Ok(one.as_str()),
        _ => Err(CliError::UsageOwned(text::pkg_usage(&command))),
    }
}
