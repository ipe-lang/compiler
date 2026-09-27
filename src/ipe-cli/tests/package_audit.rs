#![forbid(unsafe_code)]
//! End-to-end `ipe package audit`: the SP4 Tier-1 package gate.
//!
//! A clean package passes; a package with (a) an undeclared `network`
//! capability, (b) a semver under-bump against a published predecessor, or (c) a
//! `panic!` in author-supplied FFI Rust each REJECT with that check's diagnostic.
//! The gate is a security boundary — a check that passed when it should reject
//! would be a hole — so every reject case asserts both the non-zero exit AND the
//! specific diagnostic, not just failure.

// A failed `expect` in test setup IS the failure signal the harness reports.
#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

/// A fresh, unique temp package directory with a `src/` subdir.
fn temp_pkg(tag: &str) -> PathBuf {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-audit-test-{}-{}-{}",
        std::process::id(),
        tag,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("create temp src dir");
    dir
}

/// Write `package.ipe` and `src/Main.ipe` for a package.
fn write_package(pkg: &Path, manifest: &str, main: &str) {
    std::fs::write(pkg.join("package.ipe"), manifest).expect("write package.ipe");
    std::fs::write(pkg.join("src").join("Main.ipe"), main).expect("write Main.ipe");
}

/// Write a native-FFI package: the `package.ipe` project manifest plus the legacy
/// `ipe.toml` sidecar carrying the `[rust.dependencies]` / `[[rust.define.*]]`
/// FFI vocabulary the binding-regeneration inspector reads (that vocabulary is
/// not yet expressible in `package.ipe` — the outstanding ergonomic Rust-FFI
/// work — so a native package keeps it in a sidecar).
fn write_native_package(pkg: &Path, manifest: &str, sidecar: &str, main: &str) {
    std::fs::write(pkg.join("package.ipe"), manifest).expect("write package.ipe");
    std::fs::write(pkg.join("ipe.toml"), sidecar).expect("write ipe.toml sidecar");
    std::fs::write(pkg.join("src").join("Main.ipe"), main).expect("write Main.ipe");
}

/// The `[rust.dependencies]` sidecar for the nonexistent-crate regen tests.
const NONEXISTENT_NATIVE_SIDECAR: &str = "\
[rust.dependencies]\n\
ipe_does_not_exist_xyz_q9z = \"*\"\n";

/// Run `ipe package audit <pkg>` with an isolated (empty) index directory unless
/// `index` overrides it, returning `(success, stdout, stderr)`.
fn run_audit(pkg: &Path, index: &Path) -> (bool, String, String) {
    let out = Command::new(support::ipe_bin())
        .arg("package")
        .arg("audit")
        .arg(pkg)
        .arg("--index")
        .arg(index)
        .current_dir(support::repo_root())
        .output()
        .expect("run ipe package audit");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A pure program that exercises no capability.
const PURE_MAIN: &str = "module Main exposing (main)\n\
                         \n\
                         import Ipe.String as String\n\
                         import Ipe.Io as Io\n\
                         \n\
                         main : Task ()\n\
                         main =\n\
                         \x20   Io.println (String.toUpper \"hello\")\n";

/// A program that makes a network request — its inferred capability set is
/// `{network}`.
const NETWORK_MAIN: &str = "module Main exposing (main)\n\
                            \n\
                            import Ipe.Http as Http\n\
                            import Ipe.Task as Task\n\
                            import Ipe.Io as Io\n\
                            import Ipe.Url as Url\n\
                            \n\
                            main : Task ()\n\
                            main =\n\
                            \x20   case Url.fromString \"http://example.com\" of\n\
                            \x20       Ok url ->\n\
                            \x20           Http.get url\n\
                            \x20               |> Task.andThen (\\_ -> Io.println \"done\")\n\
                            \n\
                            \x20       Err e ->\n\
                            \x20           Task.fail e\n";

/// A Web-shape TEA app that mounts one `CustomElement.node` — its inferred capability
/// set is `{custom-element}` because it ships author browser JS.
const WIDGET_MAIN: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.String as String

type alias WidgetState = { count : Int }

type WidgetUp = Bumped Int

type Msg = FromWidget WidgetUp

type alias Model = { count : Int }

counter : CustomElement WidgetState WidgetUp
counter = CustomElement.fromFile "js/counter.js"

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        FromWidget (Bumped n) ->
            ( { count = model.count + n }, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.column []
        [ CustomElement.node counter { count = model.count } FromWidget
        , Ui.text (String.fromInt model.count)
        ]

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = FromWidget (Bumped 0)
        }
"#;

/// A Web-shape TEA app that CONSTRUCTS a `customElement` handle at top level but
/// never mounts it in `view`. The emitter still serves the author JS, so the
/// package's honest capability set is `{custom-element}` — the served-but-unmounted
/// hole a mounted-only audit test never exercised.
const UNMOUNTED_WIDGET_MAIN: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Ffi.Js.CustomElement as CustomElement
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.String as String

type alias WidgetState = { count : Int }

type WidgetUp = Bumped Int

type Msg = Noop

type alias Model = { count : Int }

counter : CustomElement WidgetState WidgetUp
counter = CustomElement.fromFile "js/counter.js"

init : WebReq -> ( Model, Cmd.Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update msg model =
    case msg of
        Noop ->
            ( model, Cmd.none )

view : Model -> Element Msg
view model =
    Ui.column []
        [ Ui.text (String.fromInt model.count)
        ]

subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init, update = update, view = view, subscriptions = subscriptions
        , routes = [], notFound = Noop
        }
"#;

/// Write a widget package: `package.ipe` + `src/Main.ipe` + the author widget
/// JS the `customElement "js/counter.js"` literal names, so a build path that
/// resolves the widget file is satisfied.
fn write_widget_package(pkg: &Path, manifest: &str) {
    write_widget_package_with_main(pkg, manifest, WIDGET_MAIN);
}

/// Write a widget package with an explicit `Main` source (mounted or unmounted),
/// plus the author widget JS the `customElement "js/counter.js"` literal names.
fn write_widget_package_with_main(pkg: &Path, manifest: &str, main: &str) {
    std::fs::write(pkg.join("package.ipe"), manifest).expect("write package.ipe");
    std::fs::write(pkg.join("src").join("Main.ipe"), main).expect("write Main.ipe");
    std::fs::create_dir_all(pkg.join("src").join("js")).expect("create src/js");
    std::fs::write(
        pkg.join("src").join("js").join("counter.js"),
        "export function mount(host, emit) {\n  return { onState(s) {} };\n}\n",
    )
    .expect("write widget js");
}

/// An empty index checkout root (no `packages/` entries) — used when a package
/// has no published predecessor, so the enforced-semver check skips.
fn empty_index(tag: &str) -> PathBuf {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-audit-index-{}-{}",
        std::process::id(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("packages")).expect("create index packages dir");
    dir
}

#[test]
fn a_clean_package_passes() {
    let pkg = temp_pkg("clean");
    write_package(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"clean-pkg\", version = \"0.1.0\" }\n",
        PURE_MAIN,
    );
    let index = empty_index("clean");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        ok,
        "a clean package must pass the gate; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("all Tier-1 checks passed"),
        "the pass line is printed; got:\n{stdout}"
    );
}

#[test]
fn an_undeclared_network_capability_rejects() {
    let pkg = temp_pkg("undeclared-net");
    // The program uses `network` but declares NOTHING — a hidden effect.
    write_package(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"leaky-pkg\", version = \"0.1.0\" }\n",
        NETWORK_MAIN,
    );
    let index = empty_index("undeclared-net");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        !ok,
        "an undeclared network capability must reject; stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("capability consistency"),
        "the reject names the capability check; got:\n{stderr}"
    );
    assert!(
        stderr.contains("network") && stderr.contains("used but NOT declared"),
        "the diagnostic names the hidden `network` effect; got:\n{stderr}"
    );
}

#[test]
fn an_overdeclared_capability_rejects() {
    let pkg = temp_pkg("overdeclared");
    // The pure program declares `filesystem` it never uses — an over-broad claim.
    write_package(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n\
         \x20   { name = \"broad-pkg\"\n\
         \x20   , version = \"0.1.0\"\n\
         \x20   , capabilities = { declares = [ Filesystem ] }\n\
         \x20   }\n",
        PURE_MAIN,
    );
    let index = empty_index("overdeclared");

    let (ok, _stdout, stderr) = run_audit(&pkg, &index);
    assert!(!ok, "an over-broad declaration must reject");
    assert!(
        stderr.contains("declared but NOT used") && stderr.contains("filesystem"),
        "the diagnostic names the unused `filesystem` claim; got:\n{stderr}"
    );
}

#[test]
fn an_unimported_sibling_capability_rejects() {
    // The whole-package hole: `Main` is pure and never imports `Extra`, but the
    // package SHIPS `Extra`, which makes a network call. A downstream consumer
    // can `import Extra`, so the package's honest capability set is `{network}` —
    // declaring nothing is a hidden effect the gate must reject even though the
    // entry's own reachability closure is capability-free.
    let pkg = temp_pkg("sibling-cap");
    write_package(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"sibling-pkg\", version = \"0.1.0\" }\n",
        // Pure Main — does NOT import Extra.
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\
import Ipe.Io
         main : Task ()\nmain =\n\x20   Io.println \"hi\"\n",
    );
    // An exposed sibling that reaches the network, unimported by Main.
    std::fs::write(
        pkg.join("src").join("Extra.ipe"),
        "module Extra exposing (fetch)\n\nimport Ipe.Http as Http\n\
         import Ipe.Task as Task\nimport Ipe.Io as Io\nimport Ipe.Url as Url\n\n\
         fetch : Task ()\nfetch =\n\
         \x20   case Url.fromString \"http://example.com\" of\n\
         \x20       Ok url ->\n\
         \x20           Http.get url\n\
         \x20               |> Task.andThen (\\_ -> Io.println \"done\")\n\n\
         \x20       Err e ->\n\
         \x20           Task.fail e\n",
    )
    .expect("write Extra");
    let index = empty_index("sibling-cap");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        !ok,
        "a network-using sibling module must reject even when Main never imports \
         it; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("capability consistency")
            && stderr.contains("network")
            && stderr.contains("used but NOT declared"),
        "the diagnostic names the hidden sibling `network` effect; got:\n{stderr}"
    );
}

#[test]
fn a_semver_underbump_rejects() {
    let pkg = temp_pkg("underbump-new");
    // The new version is a BREAKING change (Lib.double's type changed) but only
    // bumps the patch — an under-bump the gate must reject.
    let manifest = "module Package exposing (package)\n\n\npackage =\n    { name = \"semver-pkg\", version = \"0.1.1\" }\n";
    std::fs::write(pkg.join("package.ipe"), manifest).expect("write package.ipe");
    std::fs::write(
        pkg.join("src").join("Main.ipe"),
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\
import Ipe.Io
         main : Task ()\nmain =\n\x20   Io.println \"hi\"\n",
    )
    .expect("write Main");
    std::fs::write(
        pkg.join("src").join("Lib.ipe"),
        "module Lib exposing (double)\n\n\n\n\
import Ipe.String
         double : Int -> String\ndouble n =\n\x20   String.fromInt (n + n)\n",
    )
    .expect("write new Lib");

    // The predecessor 0.1.0 exposes `double : Int -> Int`; publish it into a
    // git-backed index the audit fetches + hash-verifies as the baseline.
    let index = published_predecessor_index(
        "semver-pkg",
        "0.1.0",
        "module Lib exposing (double)\n\n\n\n\
         double : Int -> Int\ndouble n =\n\x20   n + n\n",
        "module Main exposing (main)\n\nimport Ipe.Io as Io\n\n\
import Ipe.Io
         main : Task ()\nmain =\n\x20   Io.println \"hi\"\n",
    );

    let (ok, stdout, stderr) = run_audit(&pkg, &index.index_root);
    assert!(
        !ok,
        "a breaking change under a patch bump must reject; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("enforced semver"),
        "the reject names the semver check; got:\n{stderr}"
    );
    assert!(
        stderr.contains("0.2.0"),
        "the diagnostic names the required floor; got:\n{stderr}"
    );
}

#[test]
fn a_panic_in_author_ffi_rust_rejects() {
    let pkg = temp_pkg("ffi-panic");
    write_package(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"ffi-pkg\", version = \"0.1.0\" }\n",
        PURE_MAIN,
    );
    // Plant an author-supplied FFI wrapper (`_bindings.rs`) that panics. It has
    // no `.consumer.json`, so the catalog loader ignores it (the build stays
    // clean) — but the provenance scan reads it as author Rust and rejects.
    let cache = pkg.join(".ipe/cache/ffi/rust");
    std::fs::create_dir_all(&cache).expect("create ffi cache dir");
    std::fs::write(
        cache.join("mycrate_bindings.rs"),
        "pub fn wrap() -> i64 {\n    panic!(\"author wrote an abrupt failure\");\n}\n",
    )
    .expect("write author bindings");
    let index = empty_index("ffi-panic");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        !ok,
        "an authored panic in FFI wrapper Rust must reject; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("provenance panic-scan"),
        "the reject names the provenance check; got:\n{stderr}"
    );
    assert!(
        stderr.contains("author-supplied FFI Rust") && stderr.contains("panic!"),
        "the diagnostic attributes the panic to author Rust and names it; got:\n{stderr}"
    );
    assert!(
        stderr.contains("mycrate_bindings.rs"),
        "the diagnostic points at the offending file; got:\n{stderr}"
    );
}

/// A native-bearing manifest with a nonexistent crate in `[rust.dependencies]`.
/// Used to verify that regeneration failure maps to the typed
/// `NativeBindingRegen` check, never leaks through as a capability or build error.
const NONEXISTENT_NATIVE_MANIFEST: &str = "\
module Package exposing (package)\n\n\n\
package =\n\
\x20   { name = \"native-regen-fail\"\n\
\x20   , version = \"0.1.0\"\n\
\x20   , rustDependencies = [ rustDep \"ipe_does_not_exist_xyz_q9z\" \"*\" ]\n\
\x20   , capabilities = { declares = [ NativeFfi ] }\n\
\x20   }\n";

/// The module for the regen-fail test: it references the nonexistent crate's
/// module, which the build would reject — but the regen check fires first.
const NONEXISTENT_NATIVE_MAIN: &str = "\
module Main exposing (main)\n\
import Ipe.Io as Io\n\n\
main : Task ()\n\
main =\n\
\x20   Io.println \"native\"\n";

#[test]
fn native_package_regeneration_failure_is_a_typed_reject() {
    // A package that declares `[rust.dependencies]` for a crate that does not
    // exist on crates.io. The audit gate must:
    //  (a) attempt sandboxed regeneration (same path as `ipe rust install`),
    //  (b) fail closed when the inspector errors,
    //  (c) name the `native FFI binding regeneration` check in the diagnostic,
    //  (d) never reach provenance / capability / Tier-2 checks.
    let pkg = temp_pkg("regen-fail");
    write_native_package(
        &pkg,
        NONEXISTENT_NATIVE_MANIFEST,
        NONEXISTENT_NATIVE_SIDECAR,
        NONEXISTENT_NATIVE_MAIN,
    );
    let index = empty_index("regen-fail");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        !ok,
        "a native package whose crate does not exist must reject at regen; \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("native FFI binding regeneration"),
        "the reject names the NativeBindingRegen check; got:\n{stderr}"
    );
    assert!(
        !stderr.contains("provenance panic-scan")
            && !stderr.contains("capability consistency")
            && !stderr.contains("native Tier-2"),
        "no later check ran after the regen failure; got:\n{stderr}"
    );
}

#[test]
fn pure_package_skips_regeneration_and_certifies() {
    // A pure Ipê package (no `[rust.dependencies]`) must skip the binding
    // regeneration step entirely and pass all Tier-1 checks unchanged. This
    // guards against a regression where the regen gate fires for pure packages
    // and either adds latency or spuriously fails.
    let pkg = temp_pkg("pure-regen-skip");
    write_package(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"pure-pkg\", version = \"0.1.0\" }\n",
        PURE_MAIN,
    );
    let index = empty_index("pure-regen-skip");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        ok,
        "a pure package must certify without regeneration; \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("all Tier-1 checks passed"),
        "the pass line is printed; got:\n{stdout}"
    );
    assert!(
        !stderr.contains("native FFI binding regeneration"),
        "no regeneration was attempted for a pure package; got:\n{stderr}"
    );
}

#[test]
fn committed_bindings_are_ignored_for_native_packages() {
    // A native package with a committed `_bindings.rs` that contains a panic —
    // the stale/hostile binding a publisher could commit. The gate must delete
    // that cache before regenerating, so the provenance check never sees the
    // committed panic. Because the nonexistent crate fails the regeneration
    // step first, the reject is `NativeBindingRegen`, NOT `provenance panic-scan`.
    // This proves the gate discards committed bindings before Tier-1 runs.
    let pkg = temp_pkg("committed-bindings");
    write_native_package(
        &pkg,
        NONEXISTENT_NATIVE_MANIFEST,
        NONEXISTENT_NATIVE_SIDECAR,
        NONEXISTENT_NATIVE_MAIN,
    );
    // Plant a committed `_bindings.rs` with a panic — what a hostile publisher
    // might submit to slip past the provenance scan if committed bindings were trusted.
    let cache = pkg.join(".ipe/cache/ffi/rust");
    std::fs::create_dir_all(&cache).expect("create committed ffi cache dir");
    std::fs::write(
        cache.join("ipe_does_not_exist_xyz_q9z_bindings.rs"),
        "pub fn wrap() -> i64 {\n    panic!(\"hostile committed binding\");\n}\n",
    )
    .expect("write hostile committed binding");
    let index = empty_index("committed-bindings");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        !ok,
        "a native package with a hostile committed binding must reject; \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The committed binding is deleted BEFORE Tier-1, so the reject is the regen
    // failure (nonexistent crate), not the provenance scan.
    assert!(
        stderr.contains("native FFI binding regeneration"),
        "the reject is regen failure, not provenance — committed bindings were discarded; \
         got:\n{stderr}"
    );
    assert!(
        !stderr.contains("provenance panic-scan"),
        "the provenance check must NOT have fired — the committed binding was discarded; \
         got:\n{stderr}"
    );
}

/// A published-predecessor index backed by a real git repo, so the audit's
/// semver check can fetch + hash-verify the baseline source exactly as it would
/// in production.
struct PublishedIndex {
    index_root: PathBuf,
}

/// Build a git repo holding version `version` of `name` (a `src/Lib.ipe` +
/// `src/Main.ipe`), then write an index entry pinning that commit and the tree's
/// content hash, so `ipe package audit --index <root>` resolves it as the
/// predecessor.
fn published_predecessor_index(name: &str, version: &str, lib: &str, main: &str) -> PublishedIndex {
    // The predecessor's source repo.
    let src_repo = temp_pkg(&format!("{name}-src-{version}"));
    std::fs::write(src_repo.join("src").join("Lib.ipe"), lib).expect("write baseline Lib");
    std::fs::write(src_repo.join("src").join("Main.ipe"), main).expect("write baseline Main");

    git(&src_repo, &["init", "--quiet"]);
    git(&src_repo, &["add", "-A"]);
    git(
        &src_repo,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "--quiet",
            "-m",
            "v",
        ],
    );
    let rev = git_stdout(&src_repo, &["rev-parse", "HEAD"]);
    let rev = rev.trim();

    // The content hash the resolver verifies against is computed over the
    // fetched tree; `ipe::resolve::hash_source_tree` computes the exact same hash
    // the gate re-derives, so the baseline verifies rather than tripping the
    // hash-mismatch boundary.
    let sha = ipe::resolve::hash_source_tree(&src_repo).expect("hash baseline tree");

    let index_root = empty_index(&format!("{name}-{version}"));
    let entry = format!(
        "name = \"{name}\"\npublisher = \"tester\"\n\n[[version]]\nversion = \"{version}\"\n\
         source = \"{}\"\nrev = \"{rev}\"\nsha256 = \"{sha}\"\ncapabilities = []\n",
        src_repo.display()
    );
    std::fs::write(
        index_root.join("packages").join(format!("{name}.toml")),
        entry,
    )
    .expect("write index entry");

    PublishedIndex { index_root }
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?} failed");
}

fn git_stdout(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run git");
    assert!(out.status.success(), "git {args:?} failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A native-bearing manifest whose `[rust.dependencies]` lists a nonexistent
/// crate, used in the symlink containment tests to trigger early-reject paths.
const SYMLINK_NATIVE_MANIFEST: &str = "\
module Package exposing (package)\n\n\n\
package =\n\
\x20   { name = \"symlink-native\"\n\
\x20   , version = \"0.1.0\"\n\
\x20   , rustDependencies = [ rustDep \"ipe_does_not_exist_xyz_q9z\" \"*\" ]\n\
\x20   , capabilities = { declares = [ NativeFfi ] }\n\
\x20   }\n";

/// A native package whose committed `.ipe/cache/ffi` is a symlink to an
/// out-of-tree directory REJECTS with `NativeBindingRegen` — the out-of-tree
/// target is never deleted or written through.
// Planting a symlink needs `std::os::unix::fs::symlink`; Windows symlink
// creation is privilege-gated.
#[cfg(unix)]
#[test]
fn intermediate_symlink_in_cache_path_rejects_and_does_not_delete_out_of_tree() {
    // Set up a victim directory outside the package tree.
    let victim = crate::support::scratch_root().join(format!(
        "ipe-audit-symlink-victim-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&victim).expect("create victim dir");
    // A sentinel file inside the victim — must survive the audit.
    let sentinel = victim.join("sentinel.txt");
    std::fs::write(&sentinel, b"must survive").expect("write sentinel");

    let pkg = temp_pkg("intermediate-symlink");
    write_native_package(
        &pkg,
        SYMLINK_NATIVE_MANIFEST,
        NONEXISTENT_NATIVE_SIDECAR,
        NONEXISTENT_NATIVE_MAIN,
    );

    // Create the `.ipe/cache` directory and plant `.ipe/cache/ffi` as a
    // symlink pointing at the out-of-tree victim.
    let cache_parent = pkg.join(".ipe").join("cache");
    std::fs::create_dir_all(&cache_parent).expect("create .ipe/cache");
    std::os::unix::fs::symlink(&victim, cache_parent.join("ffi"))
        .expect("create intermediate symlink .ipe/cache/ffi -> victim");

    let index = empty_index("intermediate-symlink");
    let (ok, stdout, stderr) = run_audit(&pkg, &index);

    // The audit must reject with NativeBindingRegen.
    assert!(
        !ok,
        "a package with a symlinked intermediate cache component must reject; \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("native FFI binding regeneration"),
        "the reject names NativeBindingRegen; got:\n{stderr}"
    );
    assert!(
        stderr.contains("symlink"),
        "the diagnostic mentions the symlink; got:\n{stderr}"
    );

    // The out-of-tree victim must be intact — no delete, no write-through.
    assert!(
        sentinel.exists(),
        "the out-of-tree victim sentinel must survive — no destructive traversal occurred"
    );

    // Cleanup.
    let _ = std::fs::remove_dir_all(&victim);
    let _ = std::fs::remove_dir_all(&pkg);
}

/// A package whose `.ipe/cache/ffi/rust` LEAF is a symlink (not an
/// intermediate component) also REJECTS with `NativeBindingRegen`.
// Planting a symlink needs `std::os::unix::fs::symlink`; Windows symlink
// creation is privilege-gated.
#[cfg(unix)]
#[test]
fn leaf_symlink_in_cache_path_rejects() {
    let pkg = temp_pkg("leaf-symlink");
    write_native_package(
        &pkg,
        SYMLINK_NATIVE_MANIFEST,
        NONEXISTENT_NATIVE_SIDECAR,
        NONEXISTENT_NATIVE_MAIN,
    );

    // Plant `.ipe/cache/ffi/rust` as a symlink (leaf).
    let cache_ffi = pkg.join(".ipe").join("cache").join("ffi");
    std::fs::create_dir_all(&cache_ffi).expect("create .ipe/cache/ffi");
    // Point the leaf at /tmp itself — an always-present target.
    std::os::unix::fs::symlink(crate::support::scratch_root(), cache_ffi.join("rust"))
        .expect("create leaf symlink .ipe/cache/ffi/rust -> temp_dir");

    let index = empty_index("leaf-symlink");
    let (ok, stdout, stderr) = run_audit(&pkg, &index);

    assert!(
        !ok,
        "a package with a leaf symlink at .ipe/cache/ffi/rust must reject; \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("native FFI binding regeneration"),
        "the reject names NativeBindingRegen; got:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&pkg);
}

/// The normal (no-symlink) path: a real `.ipe/cache/ffi/rust` committed dir is
/// deleted and regenerated. With a nonexistent crate the regen fails, but the
/// delete step must have run first (the planted bindings dir is gone).
#[test]
fn normal_cache_dir_is_deleted_before_regen() {
    let pkg = temp_pkg("normal-cache-delete");
    write_native_package(
        &pkg,
        SYMLINK_NATIVE_MANIFEST,
        NONEXISTENT_NATIVE_SIDECAR,
        NONEXISTENT_NATIVE_MAIN,
    );

    // Plant a real (no symlink) committed cache dir.
    let cache = pkg.join(".ipe").join("cache").join("ffi").join("rust");
    std::fs::create_dir_all(&cache).expect("create real cache dir");
    std::fs::write(cache.join("old_bindings.rs"), b"// stale").expect("write stale binding");

    let index = empty_index("normal-cache-delete");
    let (ok, stdout, stderr) = run_audit(&pkg, &index);

    // The nonexistent crate makes regen fail — that is expected.
    assert!(
        !ok,
        "regen of nonexistent crate must fail; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("native FFI binding regeneration"),
        "the reject names NativeBindingRegen; got:\n{stderr}"
    );
    // The committed cache dir must have been deleted before the regen attempt.
    assert!(
        !cache.exists(),
        "the committed cache dir must be deleted before regen runs"
    );

    let _ = std::fs::remove_dir_all(&pkg);
}

// ── index admission fail-closed on the `custom-element` axis ─────────────────

/// Admission (the same gate index-admission CI runs) is FAIL-CLOSED for a widget
/// package that hides the disclosure: a package shipping a `CustomElement.node` but
/// declaring NOTHING is rejected — a shipped-JS surface can never be admitted
/// without disclosing `custom-element`.
#[test]
fn a_widget_package_that_hides_custom_element_is_rejected() {
    let pkg = temp_pkg("undeclared-widget");
    write_widget_package(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"widget-pkg\", version = \"0.1.0\" }\n",
    );
    let index = empty_index("undeclared-widget");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        !ok,
        "a widget package that omits `custom-element` must reject; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("capability consistency"),
        "the reject names the capability check; got:\n{stderr}"
    );
    assert!(
        stderr.contains("custom-element") && stderr.contains("used but NOT declared"),
        "the diagnostic names the hidden `custom-element` effect; got:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&pkg);
}

/// Fail-closed on the unmounted-handle case: a package that CONSTRUCTS a
/// `customElement` handle but never mounts it still ships browser JS, so declaring
/// NOTHING is rejected with a `custom-element`-naming mismatch. Admission derives
/// the axis from the served-asset walk, not from a reachable `CustomElement.node` kernel —
/// so a served-but-unmounted widget can never be admitted undisclosed.
#[test]
fn an_unmounted_widget_package_that_hides_custom_element_is_rejected() {
    let pkg = temp_pkg("undeclared-unmounted-widget");
    write_widget_package_with_main(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"unmounted-widget-pkg\", version = \"0.1.0\" }\n",
        UNMOUNTED_WIDGET_MAIN,
    );
    let index = empty_index("undeclared-unmounted-widget");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        !ok,
        "an unmounted-handle widget package that omits `custom-element` must reject; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("capability consistency"),
        "the reject names the capability check; got:\n{stderr}"
    );
    assert!(
        stderr.contains("custom-element") && stderr.contains("used but NOT declared"),
        "the diagnostic names the hidden `custom-element` effect; got:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&pkg);
}

/// The other half: a widget package that HONESTLY declares
/// `Capability.customElement` passes the capability-consistency gate — the
/// disclosed shipped-JS surface is admitted with the axis on record.
#[test]
fn a_widget_package_that_declares_custom_element_passes() {
    let pkg = temp_pkg("declared-widget");
    write_widget_package(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"widget-pkg\", version = \"0.1.0\", capabilities = { declares = [ CustomElement ] } }\n",
    );
    let index = empty_index("declared-widget");

    let (ok, stdout, stderr) = run_audit(&pkg, &index);
    assert!(
        ok,
        "a widget package declaring `custom-element` must pass; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("all Tier-1 checks passed"),
        "the pass line is printed; got:\n{stdout}"
    );

    let _ = std::fs::remove_dir_all(&pkg);
}

/// Index→page hash pin, fail-closed: the index's per-version `sha256` is the
/// content hash of the whole source tree, which INCLUDES the shipped widget JS
/// file. A widget file tampered after the pin was recorded changes the tree hash,
/// so the recorded pin no longer names the tampered bytes — the admission
/// hash-verify (`verify_hash`) refuses it rather than serving a swapped file. The
/// same widget bytes back the served page SRI, so the pin the index records and
/// the SRI the page serves are one hash over one file: tamper is caught on both.
#[test]
fn a_tampered_widget_file_breaks_the_recorded_index_hash() {
    let pkg = temp_pkg("widget-hash-pin");
    write_widget_package(
        &pkg,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"widget-pkg\", version = \"0.1.0\", capabilities = { declares = [ CustomElement ] } }\n",
    );

    // The honest tree's content hash — exactly what `ipe publish` records and the
    // admission gate re-verifies (`resolve::fetch_and_verify_index_version`).
    let honest = ipe::resolve::hash_source_tree(&pkg).expect("hash honest widget tree");

    // Tamper the shipped widget JS after the pin was recorded.
    std::fs::write(
        pkg.join("src").join("js").join("counter.js"),
        "export function mount(host, emit) {\n  steal(document.cookie);\n  return { onState(s) {} };\n}\n",
    )
    .expect("tamper widget js");

    let tampered = ipe::resolve::hash_source_tree(&pkg).expect("hash tampered widget tree");

    // The recorded index pin no longer names the tampered bytes — fail-closed:
    // the admission hash-verify would reject this tree as a HashMismatch, so a
    // swapped widget file can never be served under the honest pin.
    assert_ne!(
        honest, tampered,
        "a tampered widget file must change the index-recorded tree hash, so the pin fails closed"
    );

    let _ = std::fs::remove_dir_all(&pkg);
}
