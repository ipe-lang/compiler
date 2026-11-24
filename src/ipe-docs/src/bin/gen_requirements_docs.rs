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
//! - `install.sh` — the `c-toolchain` row of each family in
//!   `PREREQ_FAMILIES`, the host C toolchain command the installer prints.
//!
//! The **Target toolchains** section is rendered from the
//! `ipe_target_toolchains` table itself, the one the build reads.
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

use ipe_target_toolchains::{CrossArchAdvice, PackageFamily, StaticTriple, Verified};

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
    /// The host C toolchain row per installer family, in `PREREQ_FAMILIES`
    /// order.
    pub host_c_toolchain: Vec<HostCToolchainRow>,
}

/// One installer family's host C toolchain advice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostCToolchainRow {
    /// The family as the docs name it.
    pub host: &'static str,
    /// The command the installer prints, or its note when nothing is to be
    /// installed.
    pub advice: HostAdvice,
}

/// What the installer prints for a family's C toolchain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostAdvice {
    /// A command to run.
    Command(String),
    /// A note that the toolchain ships with the system.
    Note(String),
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

    let install_sh_path = repo_root.join("install.sh");
    let install_sh_src = std::fs::read_to_string(&install_sh_path)
        .map_err(|e| format!("cannot read {}: {e}", install_sh_path.display()))?;
    let host_c_toolchain = parse_host_c_toolchain(&install_sh_src)?;

    Ok(RequirementsFacts {
        rust_channel,
        edition,
        sqlite_floor,
        postgres_floor,
        host_c_toolchain,
    })
}

/// The docs name of an installer family, or `None` for a family this page
/// does not know.
fn installer_family_label(family: &str) -> Option<&'static str> {
    let known = |listed: PackageFamily| Some(listed.label());
    match family {
        "debian" => known(PackageFamily::Debian),
        "fedora" => known(PackageFamily::Fedora),
        "arch" => known(PackageFamily::Arch),
        "alpine" => known(PackageFamily::Alpine),
        "suse" => Some("openSUSE"),
        "macos" => Some("macOS"),
        "freebsd" => Some("FreeBSD"),
        _ => None,
    }
}

/// Strictly parse every `PREREQ_FAMILIES` family's `c-toolchain` row out of
/// `install.sh`.
///
/// Fails — never defaults — when the family list is missing, a family is
/// unknown, or a family has no row or more than one. A row whose text begins
/// with `sudo` or `xcode-select` is a command; any other row is a note.
fn parse_host_c_toolchain(src: &str) -> Result<Vec<HostCToolchainRow>, String> {
    const FAMILIES: &str = "PREREQ_FAMILIES='";
    let families = src
        .lines()
        .find_map(|line| line.strip_prefix(FAMILIES))
        .and_then(|rest| rest.strip_suffix('\''))
        .ok_or_else(|| format!("cannot find a `{FAMILIES}...'` line in install.sh"))?;
    let mut rows = Vec::new();
    for family in families.split(' ') {
        let host = installer_family_label(family)
            .ok_or_else(|| format!("install.sh names the unknown family `{family}`"))?;
        let prefix = format!("c-toolchain:{family}) PREREQ_CMD='");
        let mut found = src
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix(prefix.as_str()))
            .map(|rest| rest.strip_suffix("' ;;"));
        let text = match (found.next(), found.next()) {
            (Some(Some(text)), None) if !text.is_empty() && !text.contains(['`', '|', '\'']) => {
                text
            }
            (None, _) => return Err(format!("install.sh has no `c-toolchain:{family}` row")),
            (Some(_), None) => {
                return Err(format!(
                    "install.sh's `c-toolchain:{family}` row is not one plain quoted value"
                ));
            }
            (Some(_), Some(_)) => {
                return Err(format!(
                    "install.sh has more than one `c-toolchain:{family}` row"
                ));
            }
        };
        let advice = if text.starts_with("sudo ") || text.starts_with("xcode-select ") {
            HostAdvice::Command(text.to_owned())
        } else {
            HostAdvice::Note(text.to_owned())
        };
        rows.push(HostCToolchainRow { host, advice });
    }
    Ok(rows)
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

    render_target_toolchains(&mut out, &facts.host_c_toolchain);

    out
}

/// Render the **Target toolchains** section from the target toolchain table
/// and the installer's host C toolchain rows.
fn render_target_toolchains(out: &mut String, host_c_toolchain: &[HostCToolchainRow]) {
    out.push_str(
        "## Target toolchains

",
    );
    out.push_str(
        "A static build (`--static`) produces a fully static Linux binary for one of the targets below. Each target needs its Rust standard library and a C compiler that targets musl, because the default dependency graph compiles C code. Every build, static or not, also needs the host's own C toolchain.

",
    );

    out.push_str(
        "### Host C toolchain

",
    );
    out.push_str(
        "| Host | Install |
",
    );
    out.push_str(
        "|------|---------|
",
    );
    for row in host_c_toolchain {
        match &row.advice {
            HostAdvice::Command(command) => {
                let _ = writeln!(out, "| {} | `{command}` |", row.host);
            }
            HostAdvice::Note(note) => {
                let _ = writeln!(out, "| {} | {note} |", row.host);
            }
        }
    }
    out.push('\n');

    for triple in StaticTriple::ALL {
        let row = triple.toolchain();
        let target = triple.as_str();
        let arch = triple.arch().as_str();
        let _ = writeln!(
            out,
            "### `{target}`
"
        );
        let _ = writeln!(
            out,
            "Rust standard library: `rustup target add {target}`.
"
        );
        let unaided: Vec<String> = row
            .cc_rs_unaided
            .iter()
            .map(|candidate| format!("`{}`", candidate.name()))
            .collect();
        let _ = writeln!(
            out,
            "C compiler on an `{arch}` host — the build looks for {} on `PATH`, and any other compiler is named through `{}`:
",
            unaided.join(", then "),
            row.cc_env
        );
        out.push_str(
            "| Host | Install | Verified by |
",
        );
        out.push_str(
            "|------|---------|-------------|
",
        );
        for family in PackageFamily::ALL {
            let install = row
                .same_arch_install(family)
                .map_or_else(String::new, |install| {
                    row.cc_env_value_after(install.compiler).map_or_else(
                        || format!("`{}`", install.command),
                        |value| format!("`{}`, then set `{}={value}`", install.command, row.cc_env),
                    )
                });
            let verified = match row.verified_by(family) {
                Some(Verified::CiJob(job)) => format!("CI job `{job}`"),
                Some(Verified::PackageIndex) => "the distribution's package index".to_owned(),
                None => String::new(),
            };
            let _ = writeln!(out, "| {} | {install} | {verified} |", family.label());
        }
        out.push('\n');
        match row.cross_arch {
            CrossArchAdvice::SetCcEnv => {
                let _ = writeln!(
                    out,
                    "On a host of another architecture no distribution package ships a musl cross compiler: set `{}` to the path of an `{arch}` musl C compiler.
",
                    row.cc_env
                );
            }
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn find_repo_root() -> Result<PathBuf, String> {
    let mut args = ipe_docs::argv::host_args()
        .map_err(|e| e.to_string())?
        .into_iter();
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
            host_c_toolchain: vec![
                HostCToolchainRow {
                    host: "Debian, Ubuntu",
                    advice: HostAdvice::Command("sudo apt install build-essential".to_owned()),
                },
                HostCToolchainRow {
                    host: "FreeBSD",
                    advice: HostAdvice::Note("cc ships in the FreeBSD base system".to_owned()),
                },
            ],
        }
    }

    const INSTALL_SH: &str = "PREREQ_FAMILIES='debian freebsd'\n\
        prereq_command() {\n\
            case \"$1:$2\" in\n\
            c-toolchain:debian) PREREQ_CMD='sudo apt install build-essential' ;;\n\
            c-toolchain:freebsd) PREREQ_CMD='cc ships in the FreeBSD base system' ;;\n\
            esac\n\
        }\n";

    #[test]
    fn host_c_toolchain_parses_every_family_in_order() {
        assert_eq!(
            parse_host_c_toolchain(INSTALL_SH),
            Ok(sample_facts().host_c_toolchain)
        );
    }

    #[test]
    fn host_c_toolchain_fails_closed() {
        let refused = [
            INSTALL_SH.replace("PREREQ_FAMILIES='debian freebsd'", "PREREQ_FAMILIES=debian"),
            INSTALL_SH.replace("debian freebsd", "debian beos"),
            INSTALL_SH.replace("c-toolchain:freebsd", "fetcher:freebsd"),
            INSTALL_SH.replace(
                "c-toolchain:freebsd) PREREQ_CMD='cc ships in the FreeBSD base system' ;;",
                "c-toolchain:freebsd) PREREQ_CMD='' ;;",
            ),
            INSTALL_SH.replace("build-essential' ;;", "build-essential`x` ;;"),
            format!("{INSTALL_SH}c-toolchain:debian) PREREQ_CMD='sudo apt install gcc' ;;\n"),
        ];
        for src in refused {
            assert!(parse_host_c_toolchain(&src).is_err(), "{src}");
        }
    }

    #[test]
    fn target_toolchains_render_every_triple_from_the_table() {
        let out = render_requirements_docs(&sample_facts());
        assert!(out.contains("## Target toolchains"));
        assert!(out.contains("| Debian, Ubuntu | `sudo apt install build-essential` |"));
        assert!(out.contains("| FreeBSD | cc ships in the FreeBSD base system |"));
        for triple in StaticTriple::ALL {
            let row = triple.toolchain();
            assert!(out.contains(&format!("### `{}`", triple.as_str())));
            assert!(out.contains(&format!("`rustup target add {}`", triple.as_str())));
            assert!(out.contains(&format!("`{}`", row.cc_env)));
            for family in PackageFamily::ALL {
                let command = row.install_command(family).unwrap_or("absent");
                assert!(
                    out.contains(&format!("`{command}`")),
                    "{triple:?} {family:?}"
                );
            }
        }
        assert!(out.contains("CI job `linux-static-arm64`"));
        assert!(!out.contains("-linux-gnu-gcc"));
    }

    /// cc-rs looks for `aarch64-linux-musl-gcc` under aarch64, never the
    /// `musl-gcc` the Debian package ships, so the row names the variable.
    #[test]
    fn an_install_cc_rs_cannot_find_renders_its_cc_env_value() {
        let out = render_requirements_docs(&sample_facts());
        assert!(out.contains(
            "| Debian, Ubuntu | `sudo apt install musl-tools`, then set \
             `CC_aarch64_unknown_linux_musl=musl-gcc` | CI job `linux-static-arm64` |"
        ));
        assert!(out.contains(
            "| Debian, Ubuntu | `sudo apt install musl-tools` | CI job `linux-static-x64` |"
        ));
        assert!(out.contains(
            "| Alpine | `sudo apk add build-base`, then set `CC_x86_64_unknown_linux_musl=cc` |"
        ));
    }

    /// Each CI job the table cites exists in `static.yml`, installs the
    /// Debian package the row names, and sets the variable the row advises.
    #[test]
    fn every_cited_ci_job_runs_the_row_it_verifies() {
        let path = workspace_path(".github/workflows/static.yml");
        let workflow = std::fs::read_to_string(&path).expect("static.yml");
        for triple in StaticTriple::ALL {
            let row = triple.toolchain();
            for family in PackageFamily::ALL {
                let Some(Verified::CiJob(job)) = row.verified_by(family) else {
                    continue;
                };
                let header = format!("  {job}:");
                let job_body: String = workflow
                    .lines()
                    .skip_while(|line| *line != header)
                    .skip(1)
                    .take_while(|line| {
                        line.is_empty() || line.starts_with("   ") || line.starts_with("  #")
                    })
                    .flat_map(|line| [line, "\n"])
                    .collect();
                assert!(!job_body.is_empty(), "static.yml has no job `{job}`");
                let install = row.same_arch_install(family).expect("install row");
                let package = install.command.rsplit(' ').next().expect("a package word");
                assert!(
                    job_body
                        .lines()
                        .any(|line| line.trim_start().starts_with("packages:")
                            && line.split_whitespace().any(|word| word == package)),
                    "`{job}` does not install `{package}`"
                );
                if let Some(value) = row.cc_env_value_after(install.compiler) {
                    assert!(
                        job_body.contains(&format!("{}: {value}\n", row.cc_env)),
                        "`{job}` does not set `{}={value}`",
                        row.cc_env
                    );
                } else {
                    assert!(
                        !job_body.contains(row.cc_env),
                        "`{job}` sets `{}` the row says is not needed",
                        row.cc_env
                    );
                }
            }
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
