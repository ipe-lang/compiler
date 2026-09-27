//! `ipe add` / `ipe remove` end-to-end against a fixture index and a fixture
//! source git repo — no network, no real GitHub.
//!
//! A fixture index is a local git checkout with `packages/<name>.toml`; a
//! fixture source is a local git repo whose HEAD is the pinned revision. The
//! index entry's `sha256` is the real content hash of the source tree (computed
//! via `ipe::resolve::hash_source_tree`), so the resolver's verify-before-trust
//! check passes for a faithful fixture and fails for a tampered one.

// Test fixture setup: a failed `expect` IS the failure signal — the harness
// reports the panic as the test failure, which is the intended behaviour here.
#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ipe::lockfile::Lockfile;
use ipe::resolve::{self, hash_source_tree};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "ipe-add-resolve-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Run a git command in `cwd`, asserting success.
fn git(cwd: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .output()
        .expect("git runs")
        .status
        .success();
    assert!(ok, "git {args:?} must succeed");
}

/// Read the HEAD revision of a git repo.
fn head_rev(repo: &Path) -> String {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .expect("git rev-parse");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Build a fixture source git repo with one library file, returning its path.
fn fixture_source(tag: &str) -> PathBuf {
    let repo = temp_dir(&format!("source-{tag}"));
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("lib.ipe"), "module Lib\nvalue = 42\n").expect("write lib");
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "--quiet", "-m", "seed"]);
    repo
}

/// Build a fixture index with one package version pointing at `source`, pinned
/// to its HEAD, with the given capabilities and the *given* sha256 (a faithful
/// hash for a real fixture, a wrong one to exercise the mismatch path).
fn fixture_index(
    tag: &str,
    name: &str,
    version: &str,
    source: &Path,
    sha256: &str,
    capabilities: &str,
) -> PathBuf {
    let index = temp_dir(&format!("index-{tag}"));
    let packages = index.join("packages");
    std::fs::create_dir_all(&packages).expect("packages dir");
    let entry = format!(
        "name = \"{name}\"\npublisher = \"tester\"\n\n[[version]]\nversion = \"{version}\"\n\
         source = \"{}\"\nrev = \"{}\"\nsha256 = \"{sha256}\"\ncapabilities = {capabilities}\n",
        source.display(),
        head_rev(source),
    );
    std::fs::write(packages.join(format!("{name}.toml")), entry).expect("write entry");
    index
}

/// A minimal `package.ipe` for a freshly-scaffolded project: a single-field
/// record with no `dependencies` block, so `ipe add` must CREATE one.
const MINIMAL_MANIFEST: &str = "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\n\
     package : Package\npackage =\n    { name = \"app\" }\n";

/// Scaffold a minimal project directory whose manifest is a `package.ipe` — the
/// sole manifest the toolchain reads and `ipe add` writes.
fn scaffold_project(tag: &str) -> PathBuf {
    let proj = temp_dir(&format!("proj-{tag}"));
    std::fs::create_dir_all(proj.join("src")).expect("src");
    std::fs::write(proj.join("src").join("Main.ipe"), "module Main\n").expect("main");
    std::fs::write(proj.join("package.ipe"), MINIMAL_MANIFEST).expect("manifest");
    proj
}

/// Read the project's `package.ipe` source.
fn read_manifest(proj: &Path) -> String {
    std::fs::read_to_string(proj.join("package.ipe")).expect("package.ipe")
}

#[test]
fn add_resolves_verifies_and_locks() {
    let source = fixture_source("ok");
    let sha = hash_source_tree(&source).expect("hash source");
    let index = fixture_index(
        "ok",
        "http-extras",
        "1.2.0",
        &source,
        sha.as_str(),
        "[\"network\"]",
    );
    let proj = scaffold_project("ok");

    let req = "^1".parse().expect("valid req");
    resolve::resolve_and_add(&proj, "http-extras", &req, &index).expect("resolves");

    // The lockfile pins the resolved version and the verified hash.
    let lock = Lockfile::read(&proj).expect("lock");
    let locked = lock
        .packages()
        .iter()
        .find(|p| p.name.as_str() == "http-extras")
        .expect("locked");
    assert_eq!(locked.version.to_string(), "1.2.0");
    assert_eq!(locked.sha256, sha);

    // The manifest records the requirement as an index `dep` entry, and the
    // whole file re-parses through the reader (the round-trip SEAL).
    let manifest = read_manifest(&proj);
    assert!(
        manifest.contains("dep \"http-extras\""),
        "the manifest must record the dependency as a `dep` entry: {manifest}"
    );
    let reparsed = ipe::project::parse_manifest(&proj.join("package.ipe"))
        .expect("the rewritten package.ipe must re-parse through the reader");
    assert!(
        reparsed.dependencies.contains_key("http-extras"),
        "the reader must see the added dependency after the rewrite"
    );

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&index);
    let _ = std::fs::remove_dir_all(&proj);
}

#[test]
fn add_resolves_a_rev_held_alive_only_by_a_tag() {
    // The pinned rev is not the tip of any branch — the branch has advanced past
    // it, and it survives only under a tag (the immutable per-version ref the
    // publish smoke now pushes so an earlier version's rev is never orphaned).
    // The exact-SHA fetch / tag-aware fallback must still fetch and hash-verify
    // it, proving append-only re-verification of an older version stays sound.
    let source = fixture_source("tagged");
    let pinned = head_rev(&source); // commit C1 — the version's pinned rev
    let sha = hash_source_tree(&source).expect("hash C1 tree"); // C1's tree hash
    git(&source, &["tag", "smoke-pin"]); // immutable ref keeping C1 reachable
    // Advance the branch past C1 so C1 is no longer any branch tip.
    std::fs::write(source.join("lib.ipe"), "module Lib\nvalue = 99\n").expect("advance lib");
    git(&source, &["add", "."]);
    git(&source, &["commit", "--quiet", "-m", "advance"]);

    // An index entry pinned to C1 (the tagged, non-tip rev) with C1's tree hash.
    let index = temp_dir("index-tagged");
    let packages = index.join("packages");
    std::fs::create_dir_all(&packages).expect("packages dir");
    let entry = format!(
        "name = \"http-extras\"\npublisher = \"tester\"\n\n[[version]]\nversion = \"1.2.0\"\n\
         source = \"{}\"\nrev = \"{pinned}\"\nsha256 = \"{sha}\"\ncapabilities = [\"network\"]\n",
        source.display(),
    );
    std::fs::write(packages.join("http-extras.toml"), entry).expect("write entry");
    let proj = scaffold_project("tagged");

    let req = "^1".parse().expect("valid req");
    resolve::resolve_and_add(&proj, "http-extras", &req, &index)
        .expect("a tag-reachable, non-tip rev must still resolve and hash-verify");

    let lock = Lockfile::read(&proj).expect("lock");
    let locked = lock
        .packages()
        .iter()
        .find(|p| p.name.as_str() == "http-extras")
        .expect("locked");
    assert_eq!(
        locked.sha256, sha,
        "the C1 tree hash must verify against the pinned rev"
    );

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&index);
    let _ = std::fs::remove_dir_all(&proj);
}

#[test]
fn add_rejects_a_hash_mismatch() {
    // The index pins a hash the fetched source does not match: verify-before-
    // trust must reject it, and write nothing.
    let source = fixture_source("bad");
    let index = fixture_index(
        "bad",
        "http-extras",
        "1.2.0",
        &source,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "[\"network\"]",
    );
    let proj = scaffold_project("bad");

    let req = "^1".parse().expect("valid req");
    let err = resolve::resolve_and_add(&proj, "http-extras", &req, &index).unwrap_err();
    assert!(matches!(err, ipe::CliError::HashMismatch { .. }));

    // Nothing was written: no lockfile entry, no manifest dependency.
    let lock = Lockfile::read(&proj).expect("lock");
    assert!(lock.packages().is_empty(), "a mismatch must lock nothing");
    let manifest = read_manifest(&proj);
    assert!(
        !manifest.contains("http-extras"),
        "a mismatch must add nothing: {manifest}"
    );

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&index);
    let _ = std::fs::remove_dir_all(&proj);
}

#[test]
fn add_then_remove_leaves_both_files_clean() {
    let source = fixture_source("cycle");
    let sha = hash_source_tree(&source).expect("hash");
    let index = fixture_index("cycle", "json-tools", "0.4.0", &source, sha.as_str(), "[]");
    let proj = scaffold_project("cycle");

    let req = "^0.4".parse().expect("valid req");
    resolve::resolve_and_add(&proj, "json-tools", &req, &index).expect("add");
    assert!(
        read_manifest(&proj).contains("json-tools"),
        "add must record the dependency in the manifest"
    );

    resolve::resolve_and_remove(&proj, "json-tools").expect("remove");
    let lock = Lockfile::read(&proj).expect("lock");
    assert!(lock.packages().is_empty(), "remove clears the lockfile");
    let manifest_after = read_manifest(&proj);
    assert!(
        !manifest_after.contains("json-tools"),
        "remove drops the manifest dependency: {manifest_after}"
    );
    // The manifest still re-parses cleanly (a dangling entry would break it).
    ipe::project::parse_manifest(&proj.join("package.ipe"))
        .expect("the manifest re-parses after a remove");

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&index);
    let _ = std::fs::remove_dir_all(&proj);
}

/// `ipe add` on a manifest that ALREADY has a `dependencies` block must APPEND
/// without disturbing sibling entries, and a re-add of the same package must
/// UPDATE its requirement in place (idempotent — no duplicate). A hand-authored
/// `depPath` escape sharing the same name is left untouched, and an index add
/// that collides with an escape is refused (never overwritten).
#[test]
fn add_appends_updates_and_never_overwrites_an_escape() {
    let source = fixture_source("block");
    let sha = hash_source_tree(&source).expect("hash");
    let index = fixture_index(
        "block",
        "http-extras",
        "1.2.0",
        &source,
        sha.as_str(),
        "[\"network\"]",
    );
    let proj = temp_dir("proj-block");
    std::fs::create_dir_all(proj.join("src")).expect("src");
    std::fs::write(proj.join("src").join("Main.ipe"), "module Main\n").expect("main");
    // A hand-authored manifest with an existing dependencies block: one index
    // sibling and one path escape. The escape is author-owned, lockfile-only.
    std::fs::write(
        proj.join("package.ipe"),
        "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\n\
         package : Package\npackage =\n    { name = \"app\"\n\
         \x20   , dependencies =\n\
         \x20       [ dep \"sibling\" \"^2\"\n\
         \x20       , depPath \"locallib\" \"../locallib\"\n\
         \x20       ]\n    }\n",
    )
    .expect("manifest");

    // Append a new index dep: the sibling and the escape survive verbatim.
    let req = "^1".parse().expect("req");
    resolve::resolve_and_add(&proj, "http-extras", &req, &index).expect("append add");
    let after = read_manifest(&proj);
    assert!(
        after.contains("dep \"sibling\" \"^2\""),
        "sibling kept: {after}"
    );
    assert!(
        after.contains("depPath \"locallib\" \"../locallib\""),
        "escape kept verbatim: {after}"
    );
    assert!(
        after.contains("dep \"http-extras\""),
        "new dep added: {after}"
    );
    let m = ipe::project::parse_manifest(&proj.join("package.ipe")).expect("re-parses");
    assert_eq!(m.dependencies.len(), 3, "sibling + escape + new = 3");

    // Re-add the same package with a new requirement: update in place, no dup.
    let req2 = "^1.2".parse().expect("req2");
    resolve::resolve_and_add(&proj, "http-extras", &req2, &index).expect("re-add updates");
    let after2 = read_manifest(&proj);
    assert_eq!(
        after2.matches("dep \"http-extras\"").count(),
        1,
        "no duplicate entry after re-add: {after2}"
    );
    let m2 = ipe::project::parse_manifest(&proj.join("package.ipe")).expect("re-parses");
    assert_eq!(
        m2.dependencies.len(),
        3,
        "still 3 deps after idempotent re-add"
    );

    // An index add that COLLIDES with the author-written escape is refused —
    // the escape is never converted to / overwritten by an index entry.
    let esc_index = fixture_index("esc", "locallib", "0.1.0", &source, sha.as_str(), "[]");
    let req3 = "^0.1".parse().expect("req3");
    let err = resolve::resolve_and_add(&proj, "locallib", &req3, &esc_index)
        .expect_err("adding an index dep over an escape name must be refused");
    assert!(
        matches!(err, ipe::CliError::Usage(_) | ipe::CliError::UsageOwned(_)),
        "the escape-collision refusal is a usage error: {err:?}"
    );
    // The escape is untouched and the file still parses.
    let after3 = read_manifest(&proj);
    assert!(
        after3.contains("depPath \"locallib\" \"../locallib\""),
        "escape must remain untouched after the refusal: {after3}"
    );
    ipe::project::parse_manifest(&proj.join("package.ipe")).expect("re-parses after refusal");

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&index);
    let _ = std::fs::remove_dir_all(&esc_index);
    let _ = std::fs::remove_dir_all(&proj);
}
