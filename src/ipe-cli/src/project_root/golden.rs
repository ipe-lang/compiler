//! The one build of a checked-in golden directory.
//!
//! `regen-goldens` and the golden tests both build a golden through
//! [`build_golden_dir`], so the blessed bytes and the bytes a test compares
//! them with come from one code path.

use std::path::Path;

use crate::package_manifest::PACKAGE_IPE;
use crate::{BuildOptions, CliError, build_project_with_options};

/// Build the golden directory `dir` into `out`, vendoring the runtime from `runtime`.
///
/// A golden is a project: `dir` holds a `package.ipe` and its modules under
/// `src/`. A directory without a `package.ipe` is refused, never built from
/// whatever sources sit beside it.
///
/// # Errors
/// [`CliError::NoManifest`] when `dir` holds no `package.ipe`; otherwise as
/// [`crate::build_project_with_options`].
pub fn build_golden_dir(
    dir: &Path,
    out: &Path,
    runtime: &Path,
    options: &BuildOptions,
) -> Result<(), CliError> {
    let package_ipe = dir.join(PACKAGE_IPE);
    if !package_ipe.is_file() {
        return Err(CliError::NoManifest {
            dir: dir.to_path_buf(),
        });
    }
    build_project_with_options(&package_ipe, out, runtime, options)
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

    const MODULE: &str = "module Main exposing (main)\n\nmain =\n    1\n";

    /// A directory holding only `Main.ipe` is no golden: it is refused with the
    /// no-manifest text and nothing is emitted. The same sources as a project
    /// build.
    #[test]
    fn a_directory_without_package_ipe_is_refused_and_emits_nothing() {
        let scratch = RootFixture::main(MODULE).expect("fixture");
        let runtime = e2e_support::require_runtime().into_path_buf();

        let loose = scratch.path().join("loose");
        std::fs::create_dir_all(&loose).expect("dir");
        std::fs::write(loose.join("Main.ipe"), MODULE).expect("Main.ipe");
        let out = scratch.path().join("out-loose");
        let err = build_golden_dir(&loose, &out, &runtime, &BuildOptions::default())
            .expect_err("a manifestless directory is not a golden");
        assert!(matches!(&err, CliError::NoManifest { dir } if *dir == loose));
        assert_eq!(
            err.to_string(),
            format!(
                "error[IPE-E0004]: no package.ipe at {}; run `ipe init` there",
                loose.display()
            )
        );
        assert!(!out.exists(), "a refused golden must emit nothing");

        let project = scratch.path().join("project");
        std::fs::create_dir_all(project.join("src")).expect("dir");
        std::fs::write(project.join("src").join("Main.ipe"), MODULE).expect("Main.ipe");
        std::fs::write(
            project.join(PACKAGE_IPE),
            "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\npackage : Package\npackage =\n    { name = \"loose-neighbour\"\n    }\n",
        )
        .expect("package.ipe");
        let built = scratch.path().join("out-project");
        build_golden_dir(&project, &built, &runtime, &BuildOptions::default())
            .expect("the same sources as a project build");
        assert!(built.join("src").join("main.rs").is_file());
    }

    /// Every checked-in golden directory is a project: a regular `package.ipe`
    /// and a `src/` directory.
    #[test]
    fn every_golden_directory_is_a_project() {
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
            let manifest = std::fs::symlink_metadata(dir.join(PACKAGE_IPE));
            let sources = std::fs::symlink_metadata(dir.join("src"));
            if !manifest.is_ok_and(|m| m.is_file()) || !sources.is_ok_and(|m| m.is_dir()) {
                offenders.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        assert!(
            scanned > 700,
            "scanned only {scanned} golden directories under {}: the scan is not reading the golden tree",
            goldens.display()
        );
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "golden directories that are not a project (a regular `package.ipe` and a `src/` directory): {offenders:?}"
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
