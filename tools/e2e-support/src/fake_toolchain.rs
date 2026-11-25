//! A fake `cargo` staged together with the `rustc` it builds with.
//!
//! A real `cargo` always finds a compiler: `ipe` resolves the one the build
//! would run (`RUSTC`, `CARGO_BUILD_RUSTC`, `build.rustc`, then `rustc` on the
//! `PATH`) and refuses the build before cargo runs when that compiler is
//! missing or older than the pin. A test that scrubs `PATH` down to a fake
//! `cargo` therefore stages its `rustc` beside it through [`stage`], naming
//! the compiler it models as a [`FakeRustc`] — never by omission.

use std::io;
use std::path::{Path, PathBuf};

/// The `rustc` a fake toolchain carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeRustc {
    /// A `rustc` answering `-vV` with the report of release `major.minor.patch`
    /// on this host; any other query exits 1.
    Reporting(String),
    /// No `rustc`: the build's compiler cannot be found.
    Absent,
}

/// The `-vV` host this test process runs on.
const HOST: &str = if cfg!(target_os = "macos") {
    if cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else {
        "x86_64-apple-darwin"
    }
} else if cfg!(target_arch = "aarch64") {
    "aarch64-unknown-linux-gnu"
} else {
    "x86_64-unknown-linux-gnu"
};

/// Write the executable fake `cargo` running `cargo_script` (a whole script,
/// shebang included) at `bin/cargo`, and the `rustc` that `rustc` names at
/// `bin/rustc`. Returns the `cargo` path.
///
/// The fake `rustc` uses `sh` builtins only, so it answers under a `PATH`
/// holding `bin` alone.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] when a [`FakeRustc::Reporting`] release is
/// not dot-separated digits, or the I/O error that kept a script from being
/// written.
pub fn stage(bin: &Path, cargo_script: &str, rustc: &FakeRustc) -> io::Result<PathBuf> {
    let cargo = bin.join("cargo");
    executable(&cargo, cargo_script)?;
    match rustc {
        FakeRustc::Reporting(release) => {
            let well_formed =
                !release.is_empty() && release.chars().all(|c| c.is_ascii_digit() || c == '.');
            if !well_formed {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("fake rustc release {release:?} is not `major.minor.patch`"),
                ));
            }
            executable(
                &bin.join("rustc"),
                &format!(
                    "#!/bin/sh\n\
                     case \"$1\" in\n\
                     -vV) printf '%s\\n' 'rustc {release} (00000000 2026-01-01)' \
                     'binary: rustc' 'host: {HOST}' 'release: {release}' ;;\n\
                     *) exit 1 ;;\n\
                     esac\n"
                ),
            )?;
        }
        FakeRustc::Absent => {
            if let Err(e) = std::fs::remove_file(bin.join("rustc"))
                && e.kind() != io::ErrorKind::NotFound
            {
                return Err(e);
            }
        }
    }
    Ok(cargo)
}

/// Write `script` at `path`, executable.
#[cfg(unix)]
fn executable(path: &Path, script: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, script)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

/// A shell script cannot be made executable off Unix.
#[cfg(not(unix))]
fn executable(_path: &Path, _script: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "a fake toolchain is a set of `sh` scripts, Unix only",
    ))
}
