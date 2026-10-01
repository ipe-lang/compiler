//! `Ipe.Parser`'s composed combinators must LOWER and RUN, not merely
//! type-check.
//!
//! `map2`, `keep`, `ignore`, and a nested `andThen` chain each return a fresh
//! parser closure that threads the parse state through a captured polymorphic
//! function value. A stdlib combinator like `keep` forwards its element type into
//! `map2`'s RETURN-position tvar, which the boxed builder closure obliges
//! `Send + Sync`; without propagating that bound onto `keep`'s own tvar the
//! emitted Rust fails at `cargo` with `T cannot be shared between threads`
//! (E0277) after `ipe` exit 0 — a SEAL break. The `parser-demo` example composes
//! the full surface (`map2`, `keep`, `ignore`, nested `andThen`, `oneOf`), so a
//! green build is itself the lowering proof and a green run proves the state
//! threads correctly.

use std::path::PathBuf;

mod support;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn manifest() -> PathBuf {
    repo_root()
        .join("examples")
        .join("shapes")
        .join("script")
        .join("parser-demo")
        .join("package.ipe")
}

/// The project builds: every composed `Ipe.Parser` combinator lowers to emitted
/// Rust. A red `build_project` (exit 0 from `ipe`, then a `cargo` E0277) is the
/// exact SEAL break this guards.
#[test]
fn stdlib_parser_composed_combinators_lower() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("stdlib_parser_composed");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&manifest(), &out, &runtime());
    assert!(
        res.is_ok(),
        "parser-demo build_project must succeed (composed Ipe.Parser combinators must lower): {:?}",
        res.err()
    );
}

/// GREEN GATE end-to-end: under `IPE_E2E=1` the emitted binary runs and prints
/// the deterministic classification. A wrong state-thread would misparse a
/// command or fail to run at all.
#[test]
fn stdlib_parser_composed_combinators_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("stdlib_parser_composed_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&manifest(), &out, &runtime());
    assert!(res.is_ok(), "build must succeed: {:?}", res.err());

    let outcome = support::build_and_run_emitted("stdlib_parser_composed", &out);
    assert_eq!(
        outcome.stdout,
        "Parsing commands:\n  move (3,4)  ->  Move (3,4)\n  ping  ->  Ping\n  move (12,0)  ->  Move (12,0)\n  spin  ->  (parse error)\n",
        "the composed Ipe.Parser combinators must thread state correctly"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}
