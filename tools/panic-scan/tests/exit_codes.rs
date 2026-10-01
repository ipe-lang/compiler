//! Binary-level refusals: the exit code the CI gate keys on.
//!
//! `scan_str` returning `Err` is not enough — the guarantee is that the
//! *process* fails closed. A file the scanner cannot parse is unaudited, so the
//! run must exit non-zero rather than silently pass: "cannot analyze" must
//! never read as "no panics". These pin that boundary against regression.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The built scanner, proven to exist; fails the test otherwise.
fn bin() -> Command {
    Command::new(e2e_support::cargo_bin!("panic-scan"))
}

fn fixture(name: &str) -> PathBuf {
    e2e_support::manifest_dir!().join("fixtures").join(name)
}

/// Run the binary from the `fixtures` directory on the named fixture files.
#[allow(clippy::expect_used)] // a test that cannot spawn the binary has nothing to assert
fn scan_fixtures(args: &[&str]) -> std::process::Output {
    bin()
        .current_dir(e2e_support::manifest_dir!().join("fixtures"))
        .args(args)
        .output()
        .expect("run panic-scan")
}

/// An unparseable file (unterminated string literal) must fail the scan
/// closed, never pass green. This is the fail-open the gate exists to prevent.
#[test]
fn unparseable_file_fails_closed() {
    let out = scan_fixtures(&["unlexable.rstxt"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "unparseable file must exit 2 (hard error), not 0/1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("could not parse"),
        "the refusal must be the parse failure, got {stderr:?}"
    );
}

/// A clean, parseable file with no banned construct exits 0 — proving the gate
/// is not merely always-failing.
#[test]
fn clean_file_passes() {
    let out = scan_fixtures(&["negatives.rs"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "clean file must pass, got stderr {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A parseable file that DOES contain banned constructs exits 1 — the ordinary
/// "found panics" failure, distinct from the exit-2 hard error above.
#[test]
fn file_with_hits_exits_one() {
    let out = scan_fixtures(&["positives.rs"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "file with banned constructs must exit 1, got stderr {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Run the binary from the `test_paths` fixture root.
///
/// Every path it sees is then relative to that root, so no ancestor directory
/// can read as a test marker.
#[allow(clippy::expect_used)] // a test that cannot spawn the binary has nothing to assert
fn scan_test_paths(args: &[&str]) -> std::process::Output {
    bin()
        .current_dir(fixture("test_paths"))
        .args(args)
        .output()
        .expect("run panic-scan")
}

/// A `pub mod tests;` without `#[cfg(test)]` puts its `unwrap()` in production.
///
/// Skipping its `tests/` directory must be refused, naming the declaring file.
#[test]
fn ungated_tests_directory_fails_closed() {
    let out = scan_test_paths(&["ungated/src/tests/mod.rs"]);
    assert_eq!(out.status.code(), Some(2), "ungated tests/ must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ungated/src/lib.rs"),
        "the refusal must name the declaring file, got {stderr:?}"
    );
}

/// An ungated `mod tests;` backed by a `tests.rs` file is refused the same way.
#[test]
fn ungated_tests_module_file_fails_closed() {
    let out = scan_test_paths(&["ungated_file/src/tests.rs"]);
    assert_eq!(out.status.code(), Some(2), "ungated tests.rs must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ungated_file/src/lib.rs"),
        "the refusal must name the declaring file, got {stderr:?}"
    );
}

/// A `tests/` directory no module declares has no proof it is test-only.
#[test]
fn undeclared_tests_directory_fails_closed() {
    let out = scan_test_paths(&["undeclared/src/tests/mod.rs"]);
    assert_eq!(out.status.code(), Some(2), "undeclared tests/ must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("undeclared/src/tests"),
        "the refusal must name the test module, got {stderr:?}"
    );
}

/// The walk refuses an ungated test module it meets inside the tree.
#[test]
fn walk_fails_closed_on_an_ungated_tests_directory() {
    let out = scan_test_paths(&["--walk", "ungated/src"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "walk over ungated tests/ must exit 2"
    );
}

/// Gated `tests/` and `tests.rs` modules are skipped despite their `unwrap()`.
#[test]
fn gated_test_modules_are_skipped() {
    let out = scan_test_paths(&[
        "gated/src/lib.rs",
        "gated/src/unit.rs",
        "gated/src/tests/mod.rs",
        "gated/src/unit/tests.rs",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "gated test modules must be skipped, got stdout {:?} stderr {:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A production file whose name merely contains `tests` is still scanned.
#[test]
fn a_name_containing_tests_is_still_scanned() {
    let out = scan_test_paths(&["gated/src/contests.rs"]);
    assert_eq!(out.status.code(), Some(1), "contests.rs must be scanned");
}

/// The walk scans production files and skips gated test modules.
#[test]
fn walk_scans_production_and_skips_gated_tests() {
    let out = scan_test_paths(&["--walk", "gated/src"]);
    assert_eq!(out.status.code(), Some(1), "contests.rs hit must exit 1");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.is_empty()
            && stdout
                .lines()
                .all(|line| line.starts_with("gated/src/contests.rs:")),
        "only the contests.rs hit may be reported, got {stdout:?}"
    );
}

/// A walk that finds nothing to audit must not read as a pass.
#[test]
fn walk_of_a_missing_or_empty_tree_fails_closed() {
    for args in [&["--walk", "no-such-dir"][..], &["--walk"][..]] {
        let out = scan_test_paths(args);
        assert_eq!(out.status.code(), Some(2), "{args:?} must exit 2");
    }
}

/// A second, production `mod tests;` hidden behind a test-only one is refused.
#[test]
fn a_production_declaration_beside_a_test_only_one_fails_closed() {
    for args in [
        &["shadowed/src/tests/mod.rs"][..],
        &["--walk", "shadowed/src"][..],
    ] {
        let out = scan_test_paths(args);
        assert_eq!(out.status.code(), Some(2), "{args:?} must exit 2");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("shadowed/src/lib.rs"),
            "the refusal must name the declaring file, got {stderr:?}"
        );
    }
}

/// A production `#[path]` or `include!` naming test code is refused.
#[test]
fn a_production_include_of_test_code_fails_closed() {
    for file in ["includes/path_attr.rs", "includes/include_macro.rs"] {
        let out = scan_test_paths(&[file]);
        assert_eq!(out.status.code(), Some(2), "{file} must exit 2");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("tests/helper.rs"),
            "the refusal must name the included path, got {stderr:?}"
        );
    }
}

/// Naming no file at all audits nothing, so it must not read as a pass.
#[test]
#[allow(clippy::expect_used)] // a test that cannot spawn the binary has nothing to assert
fn no_input_fails_closed() {
    let status = bin().status().expect("run panic-scan");
    assert_eq!(status.code(), Some(2), "no argument must exit 2");
}

/// A fresh, empty directory under the test's scratch space.
#[allow(clippy::expect_used)] // a test without its scratch directory has nothing to assert
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("panic-scan-exit-codes")
        .join(name);
    // A leftover from an earlier run may be absent; the fresh contents written
    // afterwards are what the test relies on.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

/// Write `contents` to `root/rel`, creating its parent directories.
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn put(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture directory");
    }
    std::fs::write(path, contents).expect("write fixture file");
}

/// Run the binary from `root`, so every path it sees is relative to it.
#[allow(clippy::expect_used)] // a test that cannot spawn the binary has nothing to assert
fn scan_in(root: &Path, args: &[&str]) -> std::process::Output {
    bin()
        .current_dir(root)
        .args(args)
        .output()
        .expect("run panic-scan")
}

/// A clean library source.
const CLEAN_LIB: &str = "pub fn one() -> u8 {\n    1\n}\n";

/// A manifest whose production targets name no test code passes.
#[test]
fn a_manifest_with_production_targets_passes() {
    let root = scratch("manifest_ok");
    put(
        &root,
        "krate/Cargo.toml",
        "[package]\nname = \"krate\"\n\n[lib]\npath = \"src/lib.rs\"\n\n[[bin]]\nname = \"krate\"\npath = \"src/main.rs\"\n",
    );
    put(&root, "krate/src/lib.rs", CLEAN_LIB);
    for args in [&["krate/Cargo.toml"][..], &["--walk", "krate"][..]] {
        let out = scan_in(&root, args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?} must pass, got stderr {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A manifest whose production target lies in test code is refused.
#[test]
fn a_manifest_targeting_test_code_fails_closed() {
    for (name, manifest) in [
        ("manifest_lib", "[lib]\npath = \"src/tests/lib.rs\"\n"),
        (
            "manifest_bin",
            "[[bin]]\nname = \"b\"\npath = \"src/tests.rs\"\n",
        ),
        ("manifest_build", "[package]\nbuild = \"tests/build.rs\"\n"),
    ] {
        let root = scratch(name);
        put(&root, "krate/Cargo.toml", manifest);
        put(&root, "krate/src/lib.rs", CLEAN_LIB);
        for args in [&["krate/Cargo.toml"][..], &["--walk", "krate"][..]] {
            let out = scan_in(&root, args);
            assert_eq!(out.status.code(), Some(2), "{name} {args:?} must exit 2");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("krate/Cargo.toml"),
                "the refusal must name the manifest, got {stderr:?}"
            );
        }
    }
}

/// A symlinked directory the walk does not follow is refused, not skipped.
#[cfg(unix)]
#[test]
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn walk_fails_closed_on_a_symlinked_directory() {
    let root = scratch("symlinked_dir");
    put(
        &root,
        "outside/prod.rs",
        "pub fn f(x: Option<u8>) -> u8 {\n    x.unwrap()\n}\n",
    );
    put(&root, "tree/lib.rs", CLEAN_LIB);
    std::os::unix::fs::symlink("../outside", root.join("tree/linked"))
        .expect("create directory symlink");
    let out = scan_in(&root, &["--walk", "tree"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "symlinked directory must exit 2"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tree/linked"),
        "the refusal must name the symlink, got {stderr:?}"
    );
}

/// A directory the walk cannot read is refused, not skipped.
#[cfg(unix)]
#[test]
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn walk_fails_closed_on_an_unreadable_directory() {
    use std::os::unix::fs::PermissionsExt;

    let root = scratch("unreadable_dir");
    put(&root, "tree/lib.rs", CLEAN_LIB);
    put(&root, "tree/locked/prod.rs", CLEAN_LIB);
    let locked = root.join("tree/locked");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
        .expect("lock directory");
    // A privileged user reads the locked directory anyway: nothing to refuse.
    let readable = std::fs::read_dir(&locked).is_ok();
    let out = scan_in(&root, &["--walk", "tree"]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))
        .expect("unlock directory");
    if readable {
        return;
    }
    assert_eq!(
        out.status.code(),
        Some(2),
        "unreadable directory must exit 2"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tree/locked"),
        "the refusal must name the directory, got {stderr:?}"
    );
}

/// The stdout and stderr of `out`, for an assertion message.
fn streams(out: &std::process::Output) -> String {
    format!(
        "stdout {:?} stderr {:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A `#[cfg(test)]` arm never exempts the `,`-separated production arm after it.
#[test]
fn a_test_only_arm_does_not_exempt_its_sibling() {
    let root = scratch("comma_leak");
    put(
        &root,
        "leak.rs",
        "pub fn f(o: Option<u8>) -> u8 {\n    match 1 {\n        #[cfg(test)]\n        0 => 0,\n        _ => o.unwrap(),\n    }\n}\n",
    );
    let out = scan_in(&root, &["leak.rs"]);
    assert_eq!(out.status.code(), Some(1), "{}", streams(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("leak.rs:5:"), "{}", streams(&out));
}

/// A renamed `include` hides what it compiles in, so it is refused.
#[test]
fn a_renamed_include_fails_closed() {
    let root = scratch("renamed_include");
    put(
        &root,
        "lib.rs",
        "use core::include as grab;\ngrab!(\"tests/helper.rs\");\n",
    );
    let out = scan_in(&root, &["lib.rs"]);
    assert_eq!(out.status.code(), Some(2), "{}", streams(&out));
}

/// A production `mod Tests;` names test code on a case-insensitive file system.
#[test]
fn a_production_tests_module_in_any_case_fails_closed() {
    let root = scratch("mod_tests_case");
    put(&root, "src/lib.rs", "pub mod Tests;\n");
    put(&root, "src/Tests.rs", CLEAN_LIB);
    let out = scan_in(&root, &["src/lib.rs"]);
    assert_eq!(out.status.code(), Some(2), "{}", streams(&out));
}

/// A manifest does not excuse a `build.rs` that declares the tests module.
#[test]
fn a_build_script_declaring_tests_fails_closed() {
    let root = scratch("build_script_tests");
    put(
        &root,
        "krate/Cargo.toml",
        "[package]\nname = \"krate\"\n\n[lib]\npath = \"src/lib.rs\"\n",
    );
    put(&root, "krate/src/lib.rs", CLEAN_LIB);
    put(&root, "krate/tests/a.rs", CLEAN_LIB);
    let out = scan_in(&root, &["krate/tests/a.rs"]);
    assert_eq!(out.status.code(), Some(0), "{}", streams(&out));
    put(&root, "krate/build.rs", "pub mod tests;\nfn main() {}\n");
    let out = scan_in(&root, &["krate/tests/a.rs"]);
    assert_eq!(out.status.code(), Some(2), "{}", streams(&out));
}

/// Cargo builds every file in `src/bin` as a binary, whatever its name.
#[test]
fn an_auto_binary_named_tests_fails_closed() {
    for rel in ["krate/src/bin/tests.rs", "krate/src/bin/tests/main.rs"] {
        let root = scratch("auto_binary_tests");
        put(&root, "krate/src/lib.rs", CLEAN_LIB);
        put(&root, rel, "fn main() {}\n");
        let out = scan_in(&root, &[rel]);
        assert_eq!(out.status.code(), Some(2), "{rel}: {}", streams(&out));
    }
}

/// An included source inside the root is resolved and scanned in turn.
#[test]
fn an_include_inside_the_root_is_scanned() {
    let root = scratch("include_inside");
    put(
        &root,
        "crates/core/src/lib.rs",
        "include!(\"../../shared/src/core.rs\");\n",
    );
    put(&root, "crates/shared/src/core.rs", CLEAN_LIB);
    let out = scan_in(&root, &["crates/core/src/lib.rs"]);
    assert_eq!(out.status.code(), Some(0), "{}", streams(&out));
    put(
        &root,
        "crates/shared/src/core.rs",
        "pub fn f(o: Option<u8>) -> u8 {\n    o.unwrap()\n}\n",
    );
    let out = scan_in(&root, &["crates/core/src/lib.rs"]);
    assert_eq!(out.status.code(), Some(1), "{}", streams(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("crates/shared/src/core.rs:2:"),
        "{}",
        streams(&out)
    );
}

/// A `#[path]` module is resolved and scanned in turn.
#[test]
fn a_path_module_is_scanned() {
    let root = scratch("path_module");
    put(&root, "src/lib.rs", "#[path = \"other.rs\"]\nmod m;\n");
    put(
        &root,
        "src/other.rs",
        "pub fn f(o: Option<u8>) -> u8 {\n    o.unwrap()\n}\n",
    );
    let out = scan_in(&root, &["src/lib.rs"]);
    assert_eq!(out.status.code(), Some(1), "{}", streams(&out));
}

/// An included source the scan cannot audit is refused.
#[test]
fn an_unauditable_include_fails_closed() {
    for (name, lib, reason) in [
        (
            "include_missing",
            "include!(\"nope.rs\");\n",
            "names no existing file",
        ),
        ("include_not_rust", "include!(\"data.txt\");\n", "data.txt"),
        (
            "include_escapes",
            "include!(\"../../../x.rs\");\n",
            "escapes the scanned root",
        ),
        (
            "include_template",
            "include!(\"templates/t.rs\");\n",
            "templates/t.rs",
        ),
    ] {
        let root = scratch(name);
        put(&root, "src/lib.rs", lib);
        put(&root, "src/data.txt", "");
        put(&root, "src/templates/t.rs", CLEAN_LIB);
        let out = scan_in(&root, &["src/lib.rs"]);
        assert_eq!(out.status.code(), Some(2), "{name}: {}", streams(&out));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(reason), "{name}: {}", streams(&out));
    }
}

/// An include through a symlink that dangles or leaves the root is refused.
#[cfg(unix)]
#[test]
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn an_include_through_a_bad_symlink_fails_closed() {
    for (name, target, reason) in [
        ("include_dangling", "missing.rs", "names no existing file"),
        (
            "include_link_out",
            "../../outside.rs",
            "escapes the scanned root",
        ),
    ] {
        let base = scratch(name);
        put(&base, "outside.rs", CLEAN_LIB);
        let root = base.join("root");
        put(&root, "src/lib.rs", "include!(\"link.rs\");\n");
        std::os::unix::fs::symlink(target, root.join("src/link.rs")).expect("create symlink");
        let out = scan_in(&root, &["src/lib.rs"]);
        assert_eq!(out.status.code(), Some(2), "{name}: {}", streams(&out));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(reason), "{name}: {}", streams(&out));
    }
}

/// An argument outside the working directory is refused before any scan.
#[test]
fn an_argument_outside_the_working_directory_fails_closed() {
    let root = scratch("argument_outside");
    put(&root, "inner/lib.rs", CLEAN_LIB);
    let absolute = root.join("inner/lib.rs");
    let absolute = absolute.to_string_lossy();
    for args in [
        &["../argument_outside/inner/lib.rs"][..],
        &[&*absolute][..],
        &["--walk", ".."][..],
        &[""][..],
    ] {
        let out = scan_in(&root.join("inner"), args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", streams(&out));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("argument"), "{args:?}: {}", streams(&out));
    }
}

/// A test directory whose declaring directory cannot be listed is refused.
///
/// The same tree passes while readable, so the refusal is the lock's doing.
#[cfg(unix)]
#[test]
#[allow(clippy::expect_used)] // a test that cannot build its tree has nothing to assert
fn an_unlistable_declaring_directory_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    let root = scratch("unlistable_declaring_dir");
    put(&root, "krate/src/lib.rs", "#[cfg(test)]\nmod tests;\n");
    put(&root, "krate/src/tests/a.rs", CLEAN_LIB);
    let out = scan_in(&root, &["krate/src/tests/a.rs"]);
    assert_eq!(out.status.code(), Some(0), "{}", streams(&out));
    let src = root.join("krate/src");
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o300)).expect("lock directory");
    // A privileged user lists the locked directory anyway: nothing to refuse.
    let listable = std::fs::read_dir(&src).is_ok();
    let out = scan_in(&root, &["krate/src/tests/a.rs"]);
    std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o755))
        .expect("unlock directory");
    if listable {
        return;
    }
    assert_eq!(out.status.code(), Some(2), "{}", streams(&out));
}
