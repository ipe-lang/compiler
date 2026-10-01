//! The `Ipe.Url.Parser` routing patterns are CALLABLE from user code and
//! complete the SEAL.
//!
//! A typed `Url` is matched through a `case` chain over `parse` of `s` / `int` /
//! `string` / `slash` / `top` / `withQuery` / `query` patterns, reading captures
//! with `firstInt` / `firstString` / `firstQuery`
//! (`tests/golden/url_parser_combinators/Main.ipe`). This pins ipe-0 ∧ cargo-0 ∧
//! run-0 (THE SEAL: ipe exit 0 ⇒ emitted Rust builds and runs) and the matched
//! routes are rendered (`blog:42 user:alice home search:rust nomatch`), proving
//! the pure-data patterns lower over the shipped `Ipe.Url` accessors. Path
//! segments decode under the path grammar and query values under the form
//! grammar (`user:a+b nomatch search:a b`).
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_url_parser_combinators`.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn url_parser_combinators_ipec_cargo_and_run_zero() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("url_parser_combinators");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_url_parser_combinators_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe-0: compiling a program that calls the routing combinators must succeed.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for url_parser_combinators: {:?}",
        built.err()
    );

    // cargo-0 ∧ run-0: the binary builds, matches the routes, exits 0.
    let outcome = crate::support::build_and_run_emitted("url_parser_combinators", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "url_parser_combinators binary must exit 0 on stdin EOF; got {:?}",
        outcome.exit_code
    );
    assert!(
        outcome
            .stdout
            .contains("blog:42 user:alice home search:rust nomatch"),
        "the matched routes must render (map0/map1int/map1str/map1query + oneOf); got: {:?}",
        outcome.stdout
    );
    // Each grammar decodes its own `+` (literal in a path, a space in a query),
    // and a malformed escape in a segment is no match, never the raw form.
    assert!(
        outcome.stdout.contains("user:a+b nomatch search:a b"),
        "path `+` must stay literal, `%zz` must not match, query `+` must be a space; got: {:?}",
        outcome.stdout
    );
}
