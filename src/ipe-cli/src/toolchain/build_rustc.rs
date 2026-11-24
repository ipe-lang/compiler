//! The `rustc` a `cargo build` command would run, resolved as cargo resolves it.
//!
//! The toolchain floor must judge the compiler the build uses, so the query is
//! derived from the very `cargo` [`Command`] the build runs: its working
//! directory, its environment overrides over the process environment, and
//! cargo's own precedence for the compiler:
//!
//! 1. `RUSTC`, when it is valid Unicode (cargo ignores a non-Unicode value);
//! 2. `CARGO_BUILD_RUSTC`;
//! 3. `build.rustc` in the Cargo configuration files: `.cargo/config` or
//!    `.cargo/config.toml` in the working directory and each ancestor, the
//!    deepest winning, then the one in the Cargo home;
//! 4. `rustc` on the build's `PATH`.
//!
//! A value holding a path separator names a file: `RUSTC` and
//! `CARGO_BUILD_RUSTC` relative to the working directory, `build.rustc`
//! relative to the directory holding the `.cargo` directory that defines it.
//! Any other value is a program name looked up on `PATH`.
//!
//! Cargo reads every configuration file before it builds and stops on one it
//! cannot read or parse; so does this resolver, refusing instead of guessing.
//! Configuration `include`s, `--config` arguments (`ipe` passes none), and the
//! unstable search-stop path are not followed: a compiler they select is still
//! judged by cargo's own `rust-version` check, which `ipe` reports as the same
//! unsupported-toolchain diagnostic.

use std::ffi::{OsStr, OsString};
use std::io::{ErrorKind, Read as _};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The largest Cargo configuration file read, in bytes.
const CONFIG_CAP: u64 = 1 << 20;

/// Where the build's compiler comes from, with the program it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RustcSource {
    /// `rustc` on the build's `PATH`.
    Path,
    /// The `RUSTC` environment variable.
    RustcVar(PathBuf),
    /// The `CARGO_BUILD_RUSTC` environment variable.
    CargoBuildRustcVar(PathBuf),
    /// `build.rustc` in a Cargo configuration file.
    Config {
        /// The configuration file that sets it.
        file: PathBuf,
        /// The program it names.
        program: PathBuf,
    },
}

impl RustcSource {
    /// The program the build runs as its compiler.
    #[must_use]
    pub fn program(&self) -> &Path {
        match self {
            Self::Path => Path::new("rustc"),
            Self::RustcVar(program)
            | Self::CargoBuildRustcVar(program)
            | Self::Config { program, .. } => program,
        }
    }
}

/// Why the build's compiler could not be resolved: cargo would stop too.
#[derive(Debug, Clone)]
pub enum RustcUnresolved {
    /// The build's working directory cannot be resolved.
    Dir {
        /// The working directory.
        dir: PathBuf,
        /// Why it cannot be resolved.
        kind: ErrorKind,
    },
    /// `CARGO_BUILD_RUSTC` is not valid Unicode.
    NonUnicodeVar,
    /// A Cargo configuration file cannot be read.
    ConfigUnreadable {
        /// The file.
        file: PathBuf,
        /// Why it cannot be read.
        kind: ErrorKind,
    },
    /// A Cargo configuration file is larger than [`CONFIG_CAP`].
    ConfigTooLarge {
        /// The file.
        file: PathBuf,
    },
    /// A Cargo configuration file is not valid UTF-8 TOML.
    ConfigMalformed {
        /// The file.
        file: PathBuf,
    },
    /// A Cargo configuration file's `build` is not a table, or its
    /// `build.rustc` is not a string.
    ConfigNotAPath {
        /// The file.
        file: PathBuf,
    },
}

/// The compiler a `cargo build` command would run, and how to query it.
///
/// Built only by [`BuildRustc::of`], from the build's own [`Command`], so the
/// floor never judges a compiler the build does not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildRustc {
    source: RustcSource,
    dir: PathBuf,
    env: Vec<(OsString, Option<OsString>)>,
}

impl BuildRustc {
    /// Resolve the compiler the `cargo` command `build` would run.
    ///
    /// # Errors
    /// The [`RustcUnresolved`] that would stop cargo too.
    pub fn of(build: &Command) -> Result<Self, RustcUnresolved> {
        let dir = match build.get_current_dir() {
            Some(dir) => dir.to_path_buf(),
            None => std::env::current_dir().map_err(|e| RustcUnresolved::Dir {
                dir: PathBuf::from("."),
                kind: e.kind(),
            })?,
        };
        // Cargo's working directory is the physical one, so its walk and its
        // joins see no symbolic link.
        let cwd = std::fs::canonicalize(&dir).map_err(|e| RustcUnresolved::Dir {
            dir: dir.clone(),
            kind: e.kind(),
        })?;
        let env: Vec<(OsString, Option<OsString>)> = build
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(OsStr::to_os_string)))
            .collect();
        let var = |key: &str| build_var(&env, key);
        let config = config_rustc(&cwd, cargo_home(&cwd, var("CARGO_HOME")).as_deref())?;
        let source = if let Some(rustc) = var("RUSTC").and_then(|v| v.into_string().ok()) {
            RustcSource::RustcVar(program_at(&cwd, &rustc, true))
        } else if let Some(rustc) = var("CARGO_BUILD_RUSTC") {
            let rustc = rustc
                .into_string()
                .map_err(|_| RustcUnresolved::NonUnicodeVar)?;
            RustcSource::CargoBuildRustcVar(program_at(&cwd, &rustc, BACKSLASH_IS_PATH))
        } else if let Some((file, program)) = config {
            RustcSource::Config { file, program }
        } else {
            RustcSource::Path
        };
        Ok(Self { source, dir, env })
    }

    /// Where the compiler comes from.
    #[must_use]
    pub const fn source(&self) -> &RustcSource {
        &self.source
    }

    /// The compiler run as the build would run it: same program, working
    /// directory and environment overrides, so `rustup` resolves the same
    /// toolchain and `PATH` finds the same program.
    #[must_use]
    pub fn command(&self) -> Command {
        let mut rustc = Command::new(self.source.program());
        rustc.current_dir(&self.dir);
        for (key, value) in &self.env {
            match value {
                Some(value) => rustc.env(key, value),
                None => rustc.env_remove(key),
            };
        }
        rustc
    }
}

/// Whether a `\` marks a configured value as a path, as it does for cargo on
/// Windows only (`RUSTC` treats it as one on every host).
const BACKSLASH_IS_PATH: bool = cfg!(windows);

/// The program `value` names: a path joined to `base` when it holds a
/// separator, else a name looked up on `PATH`.
fn program_at(base: &Path, value: &str, backslash: bool) -> PathBuf {
    if value.contains('/') || (backslash && value.contains('\\')) {
        base.join(value)
    } else {
        PathBuf::from(value)
    }
}

/// The build's value of `key`: its override when the command sets or
/// removes it, else the process's own.
fn build_var(env: &[(OsString, Option<OsString>)], key: &str) -> Option<OsString> {
    env.iter()
        .find(|(name, _)| same_var(name, key))
        .map_or_else(|| ipe_env::var_os(key), |(_, value)| value.clone())
}

/// Whether the variable `name` is `key`; case-insensitive on Windows, as
/// its environment is.
fn same_var(name: &OsStr, key: &str) -> bool {
    if cfg!(windows) {
        name.to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(key))
    } else {
        name == key
    }
}

/// The Cargo home cargo reads its user configuration from: `CARGO_HOME`
/// (relative to the working directory, empty meaning unset), else `.cargo`
/// in the user's home. `None` when neither names one; cargo then cannot run.
fn cargo_home(cwd: &Path, raw: Option<OsString>) -> Option<PathBuf> {
    raw.filter(|raw| !raw.is_empty()).map_or_else(
        || crate::env_dir::home().ok().map(|home| home.join(".cargo")),
        |raw| Some(cwd.join(raw)),
    )
}

/// The deepest `build.rustc` in the configuration files cargo reads from
/// `cwd`, with the file setting it and the program it names.
///
/// Every file is read, as cargo reads every file before it builds.
fn config_rustc(
    cwd: &Path,
    cargo_home: Option<&Path>,
) -> Result<Option<(PathBuf, PathBuf)>, RustcUnresolved> {
    let mut deepest = None;
    let mut walked = Vec::new();
    for dir in cwd.ancestors() {
        let cargo_dir = dir.join(".cargo");
        if let Some(file) = config_file(&cargo_dir) {
            let found = read_rustc(&file)?;
            if deepest.is_none() {
                deepest = found.map(|value| (file, program_at(dir, &value, BACKSLASH_IS_PATH)));
            }
            walked.push(cargo_dir);
        }
    }
    if let Some(home) = cargo_home.filter(|home| !walked.iter().any(|dir| dir == home))
        && let Some(file) = config_file(home)
    {
        let found = read_rustc(&file)?;
        if deepest.is_none() {
            let root = home.parent().unwrap_or(home);
            deepest = found.map(|value| (file, program_at(root, &value, BACKSLASH_IS_PATH)));
        }
    }
    Ok(deepest)
}

/// The configuration file in `cargo_dir`: `config` when it opens, else
/// `config.toml` when it exists.
fn config_file(cargo_dir: &Path) -> Option<PathBuf> {
    let bare = cargo_dir.join("config");
    if std::fs::File::open(&bare).is_ok() {
        return Some(bare);
    }
    let toml = cargo_dir.join("config.toml");
    toml.exists().then_some(toml)
}

/// The `build.rustc` string `file` sets, if any.
fn read_rustc(file: &Path) -> Result<Option<String>, RustcUnresolved> {
    let unreadable = |e: std::io::Error| RustcUnresolved::ConfigUnreadable {
        file: file.to_path_buf(),
        kind: e.kind(),
    };
    let mut bytes = Vec::new();
    std::fs::File::open(file)
        .map_err(unreadable)?
        .take(CONFIG_CAP.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if !u64::try_from(bytes.len()).is_ok_and(|len| len <= CONFIG_CAP) {
        return Err(RustcUnresolved::ConfigTooLarge {
            file: file.to_path_buf(),
        });
    }
    let malformed = || RustcUnresolved::ConfigMalformed {
        file: file.to_path_buf(),
    };
    let text = String::from_utf8(bytes).map_err(|_| malformed())?;
    let table: toml::Table = text.parse().map_err(|_| malformed())?;
    let not_a_path = || RustcUnresolved::ConfigNotAPath {
        file: file.to_path_buf(),
    };
    match table.get("build") {
        None => Ok(None),
        Some(toml::Value::Table(build)) => match build.get("rustc") {
            None => Ok(None),
            Some(toml::Value::String(rustc)) => Ok(Some(rustc.clone())),
            Some(_) => Err(not_a_path()),
        },
        Some(_) => Err(not_a_path()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::toolchain::{
        FloorReading, PINNED_RELEASE, StubRustc, ToolchainFloorRefusal, require_floor,
        resolve_build_rustc,
    };

    /// A stub `rustc` reporting `release`.
    #[allow(clippy::expect_used)] // the test temp root is writable
    fn reporting(tag: &str, release: &str) -> StubRustc {
        StubRustc::new(
            tag,
            &format!("printf 'rustc {release} (x)\\nhost: a-b-c\\nrelease: {release}\\n'"),
        )
        .expect("write the stub rustc")
    }

    /// The release one minor below the pin.
    fn below_pin() -> String {
        format!(
            "{}.{}.0",
            PINNED_RELEASE.major,
            PINNED_RELEASE.minor.saturating_sub(1)
        )
    }

    /// A `cargo build` command in `dir` that removes every compiler override.
    fn build_in(dir: &Path) -> Command {
        let mut build = Command::new("cargo");
        build
            .current_dir(dir)
            .env_remove("RUSTC")
            .env_remove("CARGO_BUILD_RUSTC")
            .env("CARGO_HOME", dir.join("cargo-home"));
        build
    }

    /// The floor's verdict on the compiler `build` would run.
    fn judged(build: &Command) -> Result<(), ToolchainFloorRefusal> {
        require_floor(&resolve_build_rustc(build)?)
    }

    #[allow(clippy::expect_used)] // a test temp path holds no `PATH` separator
    fn path_of(stub: &StubRustc) -> OsString {
        stub.path().expect("join the stub PATH")
    }

    #[test]
    fn rustc_at_the_pin_overrides_a_path_rustc_below_it() {
        let good = reporting("var_good", &PINNED_RELEASE.to_string());
        let bad = reporting("path_bad", &below_pin());
        let mut build = build_in(good.dir());
        build
            .env("RUSTC", good.program())
            .env("PATH", path_of(&bad));
        let rustc = BuildRustc::of(&build);
        assert!(
            matches!(&rustc, Ok(r) if matches!(r.source(), RustcSource::RustcVar(_))),
            "{rustc:?}"
        );
        let verdict = judged(&build);
        assert!(verdict.is_ok(), "{verdict:?}");
    }

    #[test]
    fn rustc_below_the_pin_is_refused_though_path_rustc_meets_it() {
        let bad = reporting("var_bad", &below_pin());
        let good = reporting("path_good", &PINNED_RELEASE.to_string());
        let mut build = build_in(bad.dir());
        build
            .env("RUSTC", bad.program())
            .env("PATH", path_of(&good));
        let verdict = judged(&build);
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Below(_, RustcSource::RustcVar(_)),
                    ..
                })
            ),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_bare_rustc_name_is_looked_up_on_the_build_path() {
        let bad = reporting("bare_bad", &below_pin());
        let mut build = build_in(bad.dir());
        build.env("RUSTC", "rustc").env("PATH", path_of(&bad));
        let verdict = judged(&build);
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Below(_, RustcSource::RustcVar(_)),
                    ..
                })
            ),
            "{verdict:?}"
        );
    }

    #[test]
    fn cargo_build_rustc_is_used_when_rustc_is_unset() {
        let bad = reporting("cbr_bad", &below_pin());
        let good = reporting("cbr_path_good", &PINNED_RELEASE.to_string());
        let mut build = build_in(bad.dir());
        build
            .env("CARGO_BUILD_RUSTC", "./rustc")
            .env("PATH", path_of(&good));
        let verdict = judged(&build);
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Below(_, RustcSource::CargoBuildRustcVar(_)),
                    ..
                })
            ),
            "{verdict:?}"
        );
    }

    #[test]
    fn the_path_rustc_is_judged_without_an_override() {
        let bad = reporting("plain_bad", &below_pin());
        let mut build = build_in(bad.dir());
        build.env("PATH", path_of(&bad));
        let verdict = judged(&build);
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Below(_, RustcSource::Path),
                    ..
                })
            ),
            "{verdict:?}"
        );
    }

    /// Write `text` as `<dir>/.cargo/config.toml`.
    #[allow(clippy::expect_used)] // the test temp root is writable
    fn configure(dir: &Path, text: &str) {
        let cargo_dir = dir.join(".cargo");
        std::fs::create_dir_all(&cargo_dir).expect("create .cargo");
        std::fs::write(cargo_dir.join("config.toml"), text).expect("write config.toml");
    }

    #[test]
    #[allow(clippy::expect_used)] // the test temp root is writable
    fn a_deeper_config_rustc_wins_relative_to_its_directory() {
        let bad = reporting("cfg_bad", &below_pin());
        let good = reporting("cfg_path_good", &PINNED_RELEASE.to_string());
        let krate = bad.dir().join("krate");
        std::fs::create_dir_all(&krate).expect("create the crate dir");
        // The ancestor names the stub relative to itself; the crate dir's own
        // file would win, so it is absent here.
        configure(bad.dir(), "[build]\nrustc = \"./rustc\"\n");
        let mut build = build_in(&krate);
        build.env("PATH", path_of(&good));
        let verdict = judged(&build);
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Below(_, RustcSource::Config { .. }),
                    ..
                })
            ),
            "{verdict:?}"
        );
        configure(&krate, "build.rustc = \"rustc\"\n");
        let verdict = judged(&build);
        assert!(
            verdict.is_ok(),
            "the crate dir's own file wins: {verdict:?}"
        );
    }

    #[test]
    fn a_malformed_config_is_refused_not_skipped() {
        let good = reporting("cfg_malformed", &PINNED_RELEASE.to_string());
        configure(good.dir(), "[build\nrustc = ");
        let mut build = build_in(good.dir());
        build.env("RUSTC", good.program());
        let verdict = judged(&build);
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Unresolved(RustcUnresolved::ConfigMalformed { .. }),
                    ..
                })
            ),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_config_rustc_that_is_not_a_string_is_refused() {
        let good = reporting("cfg_not_string", &PINNED_RELEASE.to_string());
        configure(good.dir(), "[build]\nrustc = 3\n");
        let verdict = judged(&build_in(good.dir()));
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Unresolved(RustcUnresolved::ConfigNotAPath { .. }),
                    ..
                })
            ),
            "{verdict:?}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // the test temp root is writable
    fn an_oversized_config_is_refused() {
        let good = reporting("cfg_huge", &PINNED_RELEASE.to_string());
        let pad = " ".repeat(usize::try_from(CONFIG_CAP).expect("cap fits") + 1);
        configure(good.dir(), &format!("# {pad}\n"));
        let verdict = judged(&build_in(good.dir()));
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Unresolved(RustcUnresolved::ConfigTooLarge { .. }),
                    ..
                })
            ),
            "{verdict:?}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // the test temp root is writable
    fn the_cargo_home_config_is_read_below_the_tree() {
        let bad = reporting("home_bad", &below_pin());
        let home = bad.dir().join("cargo-home");
        std::fs::create_dir_all(&home).expect("create the cargo home");
        std::fs::write(
            home.join("config.toml"),
            format!(
                "[build]\nrustc = {:?}\n",
                bad.program().display().to_string()
            ),
        )
        .expect("write the home config");
        let verdict = judged(&build_in(bad.dir()));
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Below(_, RustcSource::Config { .. }),
                    ..
                })
            ),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_non_unicode_rustc_falls_through_but_cargo_build_rustc_is_refused() {
        use std::os::unix::ffi::OsStrExt as _;
        let good = reporting("non_unicode", &PINNED_RELEASE.to_string());
        let mut build = build_in(good.dir());
        build
            .env("RUSTC", OsStr::from_bytes(b"\xff"))
            .env("PATH", path_of(&good));
        let verdict = judged(&build);
        assert!(
            verdict.is_ok(),
            "a non-Unicode RUSTC is ignored: {verdict:?}"
        );
        build.env("CARGO_BUILD_RUSTC", OsStr::from_bytes(b"\xff"));
        let verdict = judged(&build);
        assert!(
            matches!(
                &verdict,
                Err(ToolchainFloorRefusal {
                    found: FloorReading::Unresolved(RustcUnresolved::NonUnicodeVar),
                    ..
                })
            ),
            "{verdict:?}"
        );
    }
}
