//! Acceptance: a real `package.ipe` fixture carrying dependencies, rust
//! dependencies, and declared capabilities parses into the typed
//! `ProjectManifest`, exercised through the public `parse_manifest` API.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ipe::project::{IpeDep, parse_manifest};
use ipe_ir::Capability;

/// The bundled multi-section manifest fixture.
fn fixture_manifest() -> PathBuf {
    e2e_support::manifest_dir!().join("tests/fixtures/sp2_manifest/package.ipe")
}

#[test]
fn full_manifest_round_trips_every_section() {
    let m = parse_manifest(&fixture_manifest()).expect("the fixture manifest must parse");

    assert_eq!(m.name, "sp2-manifest-fixture");

    // [dependencies]: an index dep, a git escape, and a path escape.
    let http = m.dependencies.get("http");
    assert!(
        matches!(http, Some(IpeDep::Index(req)) if req.matches(&semver::Version::new(1, 4, 0))),
        "http should be an Index dep admitting 1.4, got {http:?}"
    );
    assert_eq!(
        m.dependencies.get("mylib"),
        Some(&IpeDep::Git {
            url: "https://example.com/mylib.git".to_owned(),
            rev: Some("abc123".to_owned()),
        }),
        "mylib should be the git escape",
    );
    assert_eq!(
        m.dependencies.get("local"),
        Some(&IpeDep::Path(PathBuf::from("../local"))),
        "local should be the path escape",
    );

    // [rust.dependencies]: a bare version and an inline table with features.
    let uuid = m.rust_dependencies.get("uuid").expect("uuid present");
    assert_eq!(uuid.version, "1.10");
    let stripe = m.rust_dependencies.get("stripe").expect("stripe present");
    assert_eq!(stripe.version, "=1.0.0");
    assert_eq!(stripe.features, vec!["blocking", "webhooks"]);

    // [capabilities]: parsed into the same typed set the compiler infers.
    assert_eq!(
        m.capabilities,
        BTreeSet::from([Capability::Network, Capability::Clock])
    );
}

#[test]
fn icon_is_an_optional_project_contained_path() {
    // A manifest with no `icon` field parses with `icon = None`; a manifest that
    // declares one resolves it against the project root (the desktop packager's
    // single icon source). A path escaping the root is refused at parse time.
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("manifest_schema_icon");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("project src dir");
    std::fs::write(
        dir.join("src/Main.ipe"),
        "module Main exposing (main)\nmain = 0\n",
    )
    .expect("write Main.ipe");

    let without = "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\
                   package : Package\npackage =\n    { name = \"iconless\" }\n";
    std::fs::write(dir.join("package.ipe"), without).expect("write manifest");
    let m = parse_manifest(&dir.join("package.ipe")).expect("iconless manifest parses");
    assert_eq!(m.icon, None, "no icon field ⇒ None");

    let with = "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\
                package : Package\npackage =\n    { name = \"iconed\", icon = \"assets/logo.png\" }\n";
    std::fs::write(dir.join("package.ipe"), with).expect("write manifest");
    let m = parse_manifest(&dir.join("package.ipe")).expect("iconed manifest parses");
    let canon_dir = dir.canonicalize().expect("project dir canonicalizes");
    assert_eq!(
        m.icon,
        Some(canon_dir.join("assets/logo.png")),
        "icon resolves against the canonical project root"
    );

    let escaping = "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\
                    package : Package\npackage =\n    { name = \"esc\", icon = \"../secret.png\" }\n";
    std::fs::write(dir.join("package.ipe"), escaping).expect("write manifest");
    assert!(
        parse_manifest(&dir.join("package.ipe")).is_err(),
        "an icon path escaping the project root is refused"
    );
}
