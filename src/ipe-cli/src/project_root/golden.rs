//! The one build of a checked-in golden directory.
//!
//! `regen-goldens` and the golden tests both build a golden through
//! [`build_golden_dir`], so the blessed bytes and the bytes a test compares
//! them with come from one code path.

use std::path::Path;

use crate::package_manifest::PACKAGE_IPE;
use crate::project::IPE_TOML;
use crate::{BuildOptions, CliError, build_project_with_options, build_with_options};

/// The module a golden without a manifest builds.
const SINGLE_FILE_ENTRY: &str = "Main.ipe";

/// Build the golden directory `dir` into `out`, vendoring the runtime from `runtime`.
///
/// A golden with a `package.ipe` or `ipe.toml` is a project; any other golden
/// is the single file `Main.ipe`.
///
/// # Errors
/// As [`crate::build_project_with_options`] for a project and
/// [`crate::build_with_options`] for a single file.
pub fn build_golden_dir(
    dir: &Path,
    out: &Path,
    runtime: &Path,
    options: &BuildOptions,
) -> Result<(), CliError> {
    let package_ipe = dir.join(PACKAGE_IPE);
    let ipe_toml = dir.join(IPE_TOML);
    if package_ipe.is_file() {
        build_project_with_options(&package_ipe, out, runtime, options)
    } else if ipe_toml.is_file() {
        build_project_with_options(&ipe_toml, out, runtime, options)
    } else {
        build_with_options(&dir.join(SINGLE_FILE_ENTRY), out, runtime, options.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_root::fixture::RootFixture;

    const REGEN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/regen-goldens/src/main.rs"
    ));
    const TEST_SUPPORT: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/support/mod.rs"));

    #[test]
    fn a_directory_with_no_entry_is_refused() {
        let scratch =
            RootFixture::main("module Main exposing (main)\n\nmain =\n    1\n").expect("fixture");
        let empty = scratch.path().join("empty");
        std::fs::create_dir_all(&empty).expect("dir");
        let out = scratch.path().join("out");
        let result = build_golden_dir(&empty, &out, scratch.path(), &BuildOptions::default());
        assert!(result.is_err());
        assert!(!out.join("src").join("main.rs").exists());
    }

    /// A golden with a `package.ipe` is built from its `src/` root; one without
    /// that root is refused by the build, so no checked-in golden may be one.
    #[test]
    fn every_golden_manifest_has_a_source_root() {
        let goldens = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join("golden");
        let entries = std::fs::read_dir(&goldens).expect("read tests/golden");
        let mut scanned = 0_usize;
        let mut offenders = Vec::new();
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            scanned += 1;
            if dir.join(PACKAGE_IPE).is_file() && !dir.join("src").is_dir() {
                offenders.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        assert!(
            scanned > 100,
            "scanned only {scanned} golden directories under {}: the scan is not reading the golden tree",
            goldens.display()
        );
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "golden directories with a `package.ipe` and no `src/` root: {offenders:?}"
        );
    }

    #[test]
    fn the_regen_tool_and_the_golden_tests_build_through_this_function() {
        for (who, source) in [("regen-goldens", REGEN), ("tests/support", TEST_SUPPORT)] {
            assert!(
                source.contains("build_golden_dir("),
                "{who} must build a golden through build_golden_dir"
            );
        }
        for direct in ["ipe::build(", "ipe::build_project("] {
            assert!(
                !REGEN.contains(direct),
                "regen-goldens must not call {direct} on a golden directly"
            );
        }
    }
}
