//! Registry publish + admission supply-chain gate.
//!
//! Proves the trust boundary end-to-end without touching the real registry:
//!
//! 1. **Admission corpus** — `validate_entry_file` ACCEPTS a valid entry and
//!    DENIES each malformed one (bad/absent sha256, unpinned/mutable rev,
//!    injection source, missing field, malformed manifest), and
//!    `admission_precheck` DENIES the structural attacks (name-squat via a
//!    divergent source, a rewritten immutable version, an over-long version list).
//! 2. **Ephemeral local git index E2E** — build a temp git index + a temp git
//!    source, insert an entry whose sha256 is the source tree's real hash, run the
//!    resolver → success; then tamper (an entry whose sha256 no longer matches) →
//!    the resolver rejects with `HashMismatch` and writes nothing.
//! 3. **Full `audit-entry` receiving gate** — the same call `admission.yml` runs
//!    (schema + fetch + integrity-verify + the Tier-1 audit) REJECTS a fetched
//!    package whose schema and integrity are sound but whose Tier-1 audit fails,
//!    naming the offending version and writing nothing to the index — the
//!    fail-closed proof that the deployed gate's audit leg actually fires.
//! 4. **`ipe package publish --dry-run`** (IPE_E2E-gated subprocess) — computes a
//!    correct entry (name, version, 40-hex rev, 64-hex sha256) touching no network.
//!
//! Everything lives in a temp dir and is torn down; no deletes against the real
//! registry are ever needed.

// A failed `expect` IS the failure signal — the harness reports the panic as the
// test failure, which is the intended behaviour for fixture setup here.
#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use ipe::index::{self, EntryVersion, IndexEntry, PinnedRev, SourceUrl};
use ipe::lockfile::Lockfile;
use ipe::publisher::{AttestedActor, SelfDeclaredPublisher};
use ipe::resolve::{self, hash_source_tree};

// ── temp / git helpers ──────────────────────────────────────────────────────

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ipe-registry-admission-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

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

fn head_rev(repo: &Path) -> String {
    let out = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .expect("git rev-parse");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// A fixture source git repo with one library file, returning its path.
fn fixture_source(tag: &str) -> PathBuf {
    let repo = temp_dir(&format!("source-{tag}"));
    git(&repo, &["init", "--quiet"]);
    std::fs::write(repo.join("lib.ipe"), "module Lib\nvalue = 42\n").expect("write lib");
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "--quiet", "-m", "seed"]);
    repo
}

/// A fixture index holding one package version pointing at `source`, pinned to
/// its HEAD, with the given `sha256`. Returns the index root.
fn fixture_index(tag: &str, name: &str, version: &str, source: &Path, sha256: &str) -> PathBuf {
    let index = temp_dir(&format!("index-{tag}"));
    let packages = index.join("packages");
    std::fs::create_dir_all(&packages).expect("packages dir");
    let entry = format!(
        "name = \"{name}\"\npublisher = \"tester\"\n\n[[version]]\nversion = \"{version}\"\n\
         source = \"{}\"\nrev = \"{}\"\nsha256 = \"{sha256}\"\ncapabilities = [\"network\"]\n",
        source.display(),
        head_rev(source),
    );
    std::fs::write(packages.join(format!("{name}.toml")), entry).expect("write entry");
    index
}

fn scaffold_project(tag: &str) -> PathBuf {
    let proj = temp_dir(&format!("proj-{tag}"));
    std::fs::create_dir_all(proj.join("src")).expect("src");
    std::fs::write(proj.join("src").join("Main.ipe"), "module Main\n").expect("main");
    std::fs::write(
        proj.join("package.ipe"),
        "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\n\
         package : Package\npackage =\n    { name = \"app\" }\n",
    )
    .expect("manifest");
    proj
}

const VALID_REV: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
const VALID_SHA: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Write a `packages/<name>.toml` entry with the given fields into a fresh temp
/// dir, returning the entry-file path.
fn write_entry(tag: &str, name: &str, body: &str) -> PathBuf {
    let dir = temp_dir(&format!("entry-{tag}"));
    let path = dir.join(format!("{name}.toml"));
    std::fs::write(&path, body).expect("write entry");
    path
}

/// A typed [`EntryVersion`] for the `admission_precheck` corpus (bypasses TOML
/// parsing — the structural checks operate on already-typed entries).
fn version(v: &str, source: &str, rev: &str) -> EntryVersion {
    EntryVersion {
        version: semver::Version::parse(v).expect("valid version"),
        source: SourceUrl::parse("pkg", source).expect("valid source"),
        rev: PinnedRev::from_full_sha("pkg", rev).expect("valid rev"),
        sha256: VALID_SHA.to_owned(),
        capabilities: BTreeSet::new(),
        signature: None,
    }
}

fn entry(name: &str, versions: Vec<EntryVersion>) -> IndexEntry {
    entry_with_publisher(name, "tester", versions)
}

fn entry_with_publisher(name: &str, publisher: &str, versions: Vec<EntryVersion>) -> IndexEntry {
    IndexEntry {
        name: name.to_owned(),
        publisher: SelfDeclaredPublisher::new(publisher.to_owned()),
        versions,
    }
}

/// The blessed first-party publisher — read from the SSOT so this corpus never
/// re-hardcodes the identity.
const BLESSED: &str = ipe_kernels::BLESSED_PUBLISHER;
/// The disposable reserved smoke-probe package name.
const RESERVED_PROBE: &str = "ipe-registry-smoke-probe";

// ── admission corpus: validate_entry_file (schema) ──────────────────────────

#[test]
fn schema_accepts_a_well_formed_entry() {
    let body = format!(
        "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
         source = \"https://example.invalid/pkg\"\nrev = \"{VALID_REV}\"\n\
         sha256 = \"{VALID_SHA}\"\ncapabilities = [\"network\"]\n"
    );
    let path = write_entry("ok", "pkg", &body);
    let parsed = index::validate_entry_file(&path).expect("a valid entry is accepted");
    assert_eq!(parsed.name, "pkg");
    let v = parsed.versions.first().expect("one version");
    assert_eq!(v.version.to_string(), "1.0.0");
    assert_eq!(v.rev.as_str().len(), 40);
    assert_eq!(v.sha256.len(), 64);
}

#[test]
fn schema_denies_a_bad_sha256() {
    // A short, non-64-hex content hash is a garbage integrity anchor: refused at
    // the cheap structural gate, not deferred to a fetch-time mismatch.
    for bad in [
        "00",
        "gg000000000000000000000000000000000000000000000000000000000000gg",
        "0000000000000000000000000000000000000000000000000000000000000000A",
        "ABCDEF0000000000000000000000000000000000000000000000000000000000",
    ] {
        let body = format!(
            "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/pkg\"\nrev = \"{VALID_REV}\"\n\
             sha256 = \"{bad}\"\ncapabilities = []\n"
        );
        let path = write_entry("bad-sha", "pkg", &body);
        let err = index::validate_entry_file(&path).expect_err("a bad sha256 must be denied");
        assert!(
            format!("{err}").contains("sha256"),
            "expected a sha256 refusal for {bad:?}, got: {err}"
        );
    }
}

#[test]
fn schema_denies_an_absent_sha256() {
    let body = format!(
        "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
         source = \"https://example.invalid/pkg\"\nrev = \"{VALID_REV}\"\ncapabilities = []\n"
    );
    let path = write_entry("no-sha", "pkg", &body);
    let err = index::validate_entry_file(&path).expect_err("an absent sha256 must be denied");
    assert!(format!("{err}").contains("sha256"), "{err}");
}

#[test]
fn schema_denies_an_unpinned_rev() {
    // A moving ref (a branch, a short hash) is not an immutable pin.
    for bad in [
        "main",
        "HEAD",
        "aabbcc",
        "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
    ] {
        let body = format!(
            "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/pkg\"\nrev = \"{bad}\"\n\
             sha256 = \"{VALID_SHA}\"\ncapabilities = []\n"
        );
        let path = write_entry("bad-rev", "pkg", &body);
        let err = index::validate_entry_file(&path).expect_err("an unpinned rev must be denied");
        assert!(
            format!("{err}").contains("rev"),
            "expected rev refusal for {bad:?}: {err}"
        );
    }
}

#[test]
fn schema_denies_an_injection_source() {
    // `ext::` transport helpers execute arbitrary commands; a leading `-` injects
    // a git flag. Both are refused before any value reaches git.
    for bad in ["ext::sh -c touch/**/pwned", "-oProxyCommand=evil", "fd::9"] {
        let body = format!(
            "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"{bad}\"\nrev = \"{VALID_REV}\"\nsha256 = \"{VALID_SHA}\"\n"
        );
        let path = write_entry("inj-src", "pkg", &body);
        let err =
            index::validate_entry_file(&path).expect_err("an injection source must be denied");
        assert!(
            format!("{err}").contains("source"),
            "expected source refusal for {bad:?}: {err}"
        );
    }
}

#[test]
fn schema_denies_a_missing_publisher() {
    let body = format!(
        "[[version]]\nversion = \"1.0.0\"\nsource = \"https://example.invalid/pkg\"\n\
         rev = \"{VALID_REV}\"\nsha256 = \"{VALID_SHA}\"\n"
    );
    let path = write_entry("no-pub", "pkg", &body);
    let err = index::validate_entry_file(&path).expect_err("a missing publisher must be denied");
    assert!(format!("{err}").contains("publisher"), "{err}");
}

#[test]
fn schema_denies_zero_versions() {
    let path = write_entry("no-ver", "pkg", "publisher = \"tester\"\n");
    let err =
        index::validate_entry_file(&path).expect_err("an entry with no version must be denied");
    assert!(format!("{err}").contains("version"), "{err}");
}

#[test]
fn schema_denies_an_unknown_capability() {
    let body = format!(
        "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
         source = \"https://example.invalid/pkg\"\nrev = \"{VALID_REV}\"\n\
         sha256 = \"{VALID_SHA}\"\ncapabilities = [\"telepathy\"]\n"
    );
    let path = write_entry("bad-cap", "pkg", &body);
    let err = index::validate_entry_file(&path).expect_err("an unknown capability must be denied");
    assert!(!format!("{err}").is_empty());
}

// ── admission corpus: admission_precheck (structural, no fetch) ──────────────

#[test]
fn precheck_accepts_a_faithful_new_version() {
    let src = "https://example.invalid/pkg";
    let baseline = entry("pkg", vec![version("1.0.0", src, VALID_REV)]);
    let submitted = entry(
        "pkg",
        vec![
            version("1.0.0", src, VALID_REV),
            version("1.1.0", src, VALID_REV),
        ],
    );
    index::admission_precheck(&submitted, Some(&baseline), None)
        .expect("a faithful new version passes");
}

#[test]
fn precheck_denies_a_name_squat_via_divergent_source() {
    // The established source is the baseline's; a new version pointing elsewhere is
    // a hijack of the package name.
    let baseline = entry(
        "pkg",
        vec![version("1.0.0", "https://example.invalid/real", VALID_REV)],
    );
    let submitted = entry(
        "pkg",
        vec![
            version("1.0.0", "https://example.invalid/real", VALID_REV),
            version("2.0.0", "https://example.invalid/attacker", VALID_REV),
        ],
    );
    let err = index::admission_precheck(&submitted, Some(&baseline), None)
        .expect_err("a divergent source must be denied");
    assert!(format!("{err}").contains("name-squat"), "{err}");
}

#[test]
fn precheck_denies_rewriting_a_published_version() {
    // A published version number is immutable: rewriting its rev is a mutation.
    let other_rev = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";
    let src = "https://example.invalid/pkg";
    let baseline = entry("pkg", vec![version("1.0.0", src, VALID_REV)]);
    let submitted = entry("pkg", vec![version("1.0.0", src, other_rev)]);
    let err = index::admission_precheck(&submitted, Some(&baseline), None)
        .expect_err("rewriting a published version must be denied");
    assert!(format!("{err}").contains("immutable"), "{err}");
}

#[test]
fn precheck_denies_an_over_long_version_list() {
    let src = "https://example.invalid/pkg";
    let mut versions = Vec::new();
    for n in 0..=(index::MAX_ENTRY_VERSIONS as u64 + 1) {
        versions.push(version(&format!("1.0.{n}"), src, VALID_REV));
    }
    let submitted = entry("pkg", versions);
    let err = index::admission_precheck(&submitted, None, None)
        .expect_err("an over-long version list must be denied");
    assert!(format!("{err}").contains("ceiling"), "{err}");
}

#[test]
fn precheck_first_publish_binds_the_source() {
    // On first publish (no baseline) the entry's own first version fixes the
    // source; a second version pointing elsewhere in the SAME first submission is
    // still a squat.
    let submitted = entry(
        "pkg",
        vec![
            version("1.0.0", "https://example.invalid/a", VALID_REV),
            version("1.1.0", "https://example.invalid/b", VALID_REV),
        ],
    );
    let err = index::admission_precheck(&submitted, None, None)
        .expect_err("a divergent source in a first publish must be denied");
    assert!(format!("{err}").contains("name-squat"), "{err}");
}

#[test]
fn precheck_denies_dropping_a_baseline_version_for_an_ordinary_package() {
    // Append-only: an ordinary package that omits a published version from the
    // submission is refused — a published version must never be removed.
    let src = "https://example.invalid/pkg";
    let baseline = entry(
        "pkg",
        vec![
            version("1.0.0", src, VALID_REV),
            version("2.0.0", src, VALID_REV),
        ],
    );
    let submitted = entry("pkg", vec![version("2.0.0", src, VALID_REV)]);
    let err = index::admission_precheck(&submitted, Some(&baseline), None)
        .expect_err("dropping a baseline version must be denied");
    let msg = format!("{err}");
    assert!(msg.contains("append-only"), "{msg}");
    assert!(
        msg.contains("1.0.0"),
        "the reject names the dropped version: {msg}"
    );
}

#[test]
fn precheck_allows_a_reserved_blessed_reset_dropping_versions() {
    // The carve-out: the reserved disposable smoke probe, published by the
    // blessed first-party identity, may reset to a single version — dropping the
    // accumulated history is the sanctioned smoke reset.
    let src = "https://example.invalid/pkg";
    let baseline = entry_with_publisher(
        RESERVED_PROBE,
        BLESSED,
        vec![
            version("0.0.0-smoke.1", src, VALID_REV),
            version("0.0.0-smoke.2", src, VALID_REV),
        ],
    );
    let submitted = entry_with_publisher(
        RESERVED_PROBE,
        BLESSED,
        vec![version("0.0.0-smoke.3", src, VALID_REV)],
    );
    index::admission_precheck(&submitted, Some(&baseline), Some(&attested(BLESSED)))
        .expect("a reserved + attested-blessed reset drops prior versions");
}

/// The admission workflow's attestation of the authenticated PR author `login`.
fn attested(login: &str) -> AttestedActor {
    AttestedActor::parse(login).expect("login-shaped attestation")
}

/// A reserved-probe reset (baseline smoke.1 + smoke.2 → submitted smoke.3 only)
/// whose entry claims `claimed`, checked under `attestation`.
fn reserved_reset(claimed: &str, attestation: Option<&AttestedActor>) -> Result<(), ipe::CliError> {
    let src = "https://example.invalid/pkg";
    let baseline = entry_with_publisher(
        RESERVED_PROBE,
        claimed,
        vec![
            version("0.0.0-smoke.1", src, VALID_REV),
            version("0.0.0-smoke.2", src, VALID_REV),
        ],
    );
    let submitted = entry_with_publisher(
        RESERVED_PROBE,
        claimed,
        vec![version("0.0.0-smoke.3", src, VALID_REV)],
    );
    index::admission_precheck(&submitted, Some(&baseline), attestation)
}

#[test]
fn precheck_denies_a_forged_blessed_reset_without_attestation() {
    // A committed entry declaring `publisher = "<blessed>"` is attacker-writable:
    // with no attested PR author the reset carve-out is refused.
    let err = reserved_reset(BLESSED, None)
        .expect_err("a self-declared blessed publisher alone must not license the reset");
    let msg = format!("{err}");
    assert!(msg.contains("append-only"), "{msg}");
    assert!(
        msg.contains("self-declared"),
        "the reject says why the claim was not trusted: {msg}"
    );
}

#[test]
fn precheck_denies_a_blessed_reset_attested_as_someone_else() {
    // The attested PR author is not the claimed (blessed) publisher: forged.
    let err = reserved_reset(BLESSED, Some(&attested("attacker")))
        .expect_err("an attestation not matching the claim must be denied");
    let msg = format!("{err}");
    assert!(msg.contains("append-only"), "{msg}");
    assert!(msg.contains("does not match"), "{msg}");
}

#[test]
fn precheck_denies_a_reset_with_a_non_blessed_attestation() {
    // Claim and attestation agree, but the identity is not the blessed one.
    let err = reserved_reset("tester", Some(&attested("tester")))
        .expect_err("a non-blessed attestation must be denied");
    let msg = format!("{err}");
    assert!(msg.contains("append-only"), "{msg}");
    assert!(msg.contains("not the first-party publisher"), "{msg}");
}

#[test]
fn precheck_denies_a_reserved_non_blessed_reset() {
    // Fail-closed: a reserved name alone does not license the drop — a non-blessed
    // publisher dropping versions still hits the append-only rejection.
    let src = "https://example.invalid/pkg";
    let baseline = entry_with_publisher(
        RESERVED_PROBE,
        "tester",
        vec![
            version("0.0.0-smoke.1", src, VALID_REV),
            version("0.0.0-smoke.2", src, VALID_REV),
        ],
    );
    let submitted = entry_with_publisher(
        RESERVED_PROBE,
        "tester",
        vec![version("0.0.0-smoke.2", src, VALID_REV)],
    );
    let err = index::admission_precheck(&submitted, Some(&baseline), None)
        .expect_err("a reserved but non-blessed reset must be denied");
    assert!(format!("{err}").contains("append-only"), "{err}");
}

#[test]
fn precheck_denies_a_reserved_blessed_rewrite() {
    // The carve-out is drop-only: reserved + blessed may reset (drop) versions,
    // but rewriting an EXISTING version's rev is still a supply-chain mutation and
    // stays forbidden everywhere.
    let src = "https://example.invalid/pkg";
    let other_rev = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";
    let baseline = entry_with_publisher(
        RESERVED_PROBE,
        BLESSED,
        vec![version("0.0.0-smoke.1", src, VALID_REV)],
    );
    let submitted = entry_with_publisher(
        RESERVED_PROBE,
        BLESSED,
        vec![version("0.0.0-smoke.1", src, other_rev)],
    );
    let err = index::admission_precheck(&submitted, Some(&baseline), Some(&attested(BLESSED)))
        .expect_err("rewriting a reserved+blessed version must still be denied");
    assert!(format!("{err}").contains("immutable"), "{err}");
}

// ── ephemeral local git index E2E: resolve + verify, then tamper ────────────

#[test]
fn ephemeral_index_resolves_and_verifies_a_faithful_entry() {
    let source = fixture_source("e2e-ok");
    let sha = hash_source_tree(&source).expect("hash source");
    let index = fixture_index("e2e-ok", "http-extras", "1.2.0", &source, &sha);
    let proj = scaffold_project("e2e-ok");

    let req = "^1".parse().expect("valid req");
    resolve::resolve_and_add(&proj, "http-extras", &req, &index).expect("resolves + verifies");

    let lock = Lockfile::read(&proj).expect("lock");
    let locked = lock
        .packages()
        .iter()
        .find(|p| p.name == "http-extras")
        .expect("locked");
    assert_eq!(locked.version.to_string(), "1.2.0");
    assert_eq!(locked.sha256, sha, "the verified tree hash is locked");

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&index);
    let _ = std::fs::remove_dir_all(&proj);
}

#[test]
fn ephemeral_index_rejects_a_tampered_tree() {
    // The index pins a (well-formed) hash the fetched source does not match:
    // verify-before-trust rejects it and writes nothing.
    let source = fixture_source("e2e-tamper");
    let index = fixture_index("e2e-tamper", "http-extras", "1.2.0", &source, VALID_SHA);
    let proj = scaffold_project("e2e-tamper");

    let req = "^1".parse().expect("valid req");
    let err = resolve::resolve_and_add(&proj, "http-extras", &req, &index)
        .expect_err("a hash mismatch must be rejected");
    assert!(matches!(err, ipe::CliError::HashMismatch { .. }), "{err:?}");

    let lock = Lockfile::read(&proj).expect("lock");
    assert!(lock.packages().is_empty(), "a mismatch must lock nothing");
    let manifest = std::fs::read_to_string(proj.join("package.ipe")).expect("manifest");
    assert!(
        !manifest.contains("http-extras"),
        "a mismatch must add nothing: {manifest}"
    );

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&index);
    let _ = std::fs::remove_dir_all(&proj);
}

// ── full audit-entry gate: a fetched package that fails the Tier-1 audit ─────

/// A fixture package source git repo whose `Main` uses the `network` capability
/// but whose `package.ipe` declares NOTHING — a hidden effect the Tier-1
/// capability-consistency check must reject. Returns `(repo_path, tree_sha256)`;
/// the sha256 is the real content hash of the committed tree, so the
/// fetch+integrity leg of `audit-entry` passes and the REJECT lands on the
/// audit, not on schema or a hash mismatch.
fn fixture_undeclared_network_package(tag: &str) -> (PathBuf, String) {
    let repo = temp_dir(&format!("audit-src-{tag}"));
    std::fs::create_dir_all(repo.join("src")).expect("src dir");
    std::fs::write(
        repo.join("package.ipe"),
        "module Package exposing (package)\n\n\n\
         package =\n    { name = \"leaky-entry-pkg\", version = \"1.0.0\" }\n",
    )
    .expect("write package.ipe");
    // A program that makes a network request — inferred capability set `{network}`,
    // declared capability set empty: a hidden effect.
    std::fs::write(
        repo.join("src").join("Main.ipe"),
        "module Main exposing (main)\n\n\
         import Ipe.Http as Http\n\
         import Ipe.Task as Task\n\
         import Ipe.Io as Io\n\
         import Ipe.Url as Url\n\n\
         main : Task ()\n\
         main =\n\
         \x20   case Url.fromString \"http://example.com\" of\n\
         \x20       Ok url ->\n\
         \x20           Http.get url\n\
         \x20               |> Task.andThen (\\_ -> Io.println \"done\")\n\n\
         \x20       Err e ->\n\
         \x20           Task.fail e\n",
    )
    .expect("write Main.ipe");
    git(&repo, &["init", "--quiet"]);
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "--quiet", "-m", "seed"]);
    let sha = hash_source_tree(&repo).expect("hash package tree");
    (repo, sha)
}

#[test]
fn audit_entry_rejects_a_package_that_fails_the_tier1_audit() {
    // The full receiving gate — `ipe package audit-entry`, the same call the
    // deployed `admission.yml` runs (schema + fetch + integrity-verify + the
    // Tier-1 audit) — must REJECT a fetched package whose SCHEMA is well-formed
    // and whose INTEGRITY verifies, but whose AUDIT fails. This is the every-PR,
    // network-free proof that the gate's fail-closed path actually fires: a
    // silently-disabled audit leg would still admit this package.
    let (source, sha) = fixture_undeclared_network_package("tier1");
    // A well-formed entry whose sha256 is the source tree's real hash and whose
    // rev is the committed HEAD: schema + fetch + integrity all pass, so the ONLY
    // reachable rejection is the Tier-1 audit.
    let index = fixture_index("audit-tier1", "leaky-entry-pkg", "1.0.0", &source, &sha);
    let entry_path = index.join("packages").join("leaky-entry-pkg.toml");

    let out = Command::new(ipe_bin())
        .args(["package", "audit-entry"])
        .arg(&entry_path)
        // No `--index`: an isolated (empty) baseline, so the version is "new" and
        // fully audited, and the enforced-semver check has no predecessor to fetch.
        .env("IPE_REGISTRY_URL", "")
        .output()
        .expect("ipe runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Fail-closed: the gate must exit non-zero (the typed CliError::PackageAudit
    // reaches the process boundary as a non-zero status).
    assert!(
        !out.status.success(),
        "audit-entry must REJECT a Tier-1-failing package; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The reject is the Tier-1 audit, not schema or a hash mismatch: it names the
    // capability check and the offending version.
    assert!(
        stderr.contains("capability consistency"),
        "the reject names the Tier-1 capability check; got:\n{stderr}"
    );
    assert!(
        stderr.contains("network") && stderr.contains("used but NOT declared"),
        "the diagnostic names the hidden `network` effect; got:\n{stderr}"
    );
    assert!(
        stderr.contains("1.0.0"),
        "the reject names the offending version; got:\n{stderr}"
    );
    // The certified-summary line is printed only on a full pass — it must be
    // absent when the audit rejects.
    assert!(
        !stdout.contains("new version(s) certified"),
        "a rejected entry must NOT print the certified summary; got:\n{stdout}"
    );

    // Defence in depth: a rejected entry writes nothing to the index. The gate
    // never mutates the index (it only reads the baseline), so the baseline
    // directory must be exactly the single entry file we seeded — no admission
    // artifact, no rewritten entry.
    let packages = index.join("packages");
    let written: Vec<String> = std::fs::read_dir(&packages)
        .expect("read packages dir")
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    assert_eq!(
        written,
        vec!["leaky-entry-pkg.toml".to_owned()],
        "a rejected entry must leave the index untouched; found: {written:?}"
    );

    let _ = std::fs::remove_dir_all(&source);
    let _ = std::fs::remove_dir_all(&index);
}

// ── publish --dry-run (IPE_E2E-gated subprocess) ────────────────────────────

/// The built `ipe` binary, archive-safe: nextest re-exports `CARGO_BIN_EXE_ipe`
/// at runtime pointing at the extracted binary; fall back to the baked path for a
/// plain (non-archive) run.
fn ipe_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_ipe")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_ipe")), PathBuf::from)
}

#[test]
fn publish_dry_run_computes_a_correct_entry_offline() {
    // Gated: the dry-run still runs the local audit gate, which builds the package.
    if std::env::var_os("IPE_E2E").is_none() {
        eprintln!("skipping publish_dry_run_computes_a_correct_entry_offline (set IPE_E2E=1)");
        return;
    }

    // A publishable package: a git repo with a committed package.ipe, its HEAD
    // pushed to a local bare "remote" so publish's committed+pushed precondition
    // holds without any network.
    let work = temp_dir("dry-run");
    let remote = work.join("remote.git");
    std::fs::create_dir_all(&remote).expect("remote dir");
    git(&remote, &["init", "--quiet", "--bare"]);

    let pkg = work.join("pkg");
    std::fs::create_dir_all(pkg.join("src")).expect("src");
    std::fs::write(
        pkg.join("package.ipe"),
        "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\npackage : Package\npackage =\n    { name = \"pkg\"\n    , version = \"1.0.0\"\n    }\n",
    )
    .expect("package.ipe");
    std::fs::write(
        pkg.join("src").join("Main.ipe"),
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\nmain =\n    Io.println \"pkg\"\n",
    )
    .expect("Main.ipe");
    git(&pkg, &["init", "--quiet"]);
    git(&pkg, &["add", "."]);
    git(&pkg, &["commit", "--quiet", "-m", "seed"]);
    git(
        &pkg,
        &["remote", "add", "origin", &remote.to_string_lossy()],
    );
    git(&pkg, &["push", "--quiet", "origin", "HEAD"]);

    let expected_rev = head_rev(&pkg);
    let expected_sha = hash_source_tree(&pkg).expect("hash pkg");

    let out = Command::new(ipe_bin())
        .args(["package", "publish", "--dry-run"])
        .current_dir(&pkg)
        // Air-gap the run: an empty registry URL disables the Pages fast-path.
        .env("IPE_REGISTRY_URL", "")
        .output()
        .expect("ipe runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "publish --dry-run must succeed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("1.0.0"), "the computed version:\n{stdout}");
    assert!(
        stdout.contains(&expected_rev),
        "the pinned HEAD rev:\n{stdout}"
    );
    assert!(
        stdout.contains(&expected_sha),
        "the source tree sha256:\n{stdout}"
    );
    assert!(
        stdout.contains("No network"),
        "the dry-run touches no network:\n{stdout}"
    );

    let _ = std::fs::remove_dir_all(&work);
}
