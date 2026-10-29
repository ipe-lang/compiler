//! SEAL: generic record templates fold exactly when one renames the other's type variables.
//!
//! A field-name set synthesises one struct per generic template modulo
//! alpha-equivalence. `{ items : List b }` (a signature) and `{ items : List a }`
//! (a literal in another function) are one template, so the literal must build
//! the signature's struct; a second struct for the literal is a type mismatch
//! rustc rejects (E0308) after ipe accepted the program. Conversely
//! `{ x : List a, y : a }` and `{ x : List a, y : b }` are distinct templates (a
//! variable nested in `List` binds its sibling), so each keeps its own struct.
//!
//! The emit gate counts the structs per name set; under `IPE_E2E=1` each
//! emitted crate must build and print its result.

use std::path::PathBuf;

/// A generic signature template and an alpha-equivalent literal in another function.
const FOLDED: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String


count : { items : List b } -> Int
count r =
    List.length r.items


wrapCount : a -> Int
wrapCount x =
    count { items = [ x ] }


main : Task Error ()
main =
    Io.println (String.fromInt (wrapCount 1))
";

/// Two generic templates sharing a name set that no renaming makes one.
const DISTINCT: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String


same : { x : List a, y : a } -> Int
same r =
    List.length r.x


apart : { x : List a, y : b } -> Int
apart r =
    List.length r.x


callSame : a -> Int
callSame v =
    same { x = [ v ], y = v }


callApart : a -> b -> Int
callApart v w =
    apart { x = [ v, v ], y = w }


main : Task Error ()
main =
    Io.println (String.fromInt (callSame 1 + callApart 2 "s"))
"#;

/// Build `source` as a project fixture into a fresh `out` dir, returning the emitted dir.
fn build(name: &str, source: &str, suffix: &str) -> PathBuf {
    let fixture = crate::root_fixture::main(source);
    let out = crate::support::scratch_root().join(format!("ipec_{name}_{suffix}"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = crate::root_fixture::build(&fixture, &out, &runtime);
    assert!(
        matches!(built, Ok(())),
        "{name}: ipe dev build must accept the program, got: {built:?}"
    );
    out
}

/// The number of emitted struct declarations whose name starts with `stem`.
fn struct_count(emitted: &str, stem: &str) -> usize {
    emitted.matches(&format!("pub struct {stem}")).count()
}

/// Emit gate: alpha-equivalent templates share one struct.
#[test]
fn alpha_equivalent_templates_fold_emitted() {
    let out = build("alpha_record_folded", FOLDED, "emit");
    let emitted = crate::support::read_all_emitted_src(&out);
    assert_eq!(
        struct_count(&emitted, "RecItems"),
        1,
        "`{{ items : List b }}` and `{{ items : List a }}` must share one struct; got:\n{emitted}"
    );
}

/// Emit gate: templates no renaming relates keep a struct each.
#[test]
fn distinct_templates_stay_apart_emitted() {
    let out = build("alpha_record_distinct", DISTINCT, "emit");
    let emitted = crate::support::read_all_emitted_src(&out);
    assert_eq!(
        struct_count(&emitted, "RecXY"),
        2,
        "`{{ x : List a, y : a }}` and `{{ x : List a, y : b }}` must stay two structs; got:\n{emitted}"
    );
}

/// THE SEAL: under `IPE_E2E=1` each emitted crate must `cargo build` and print its result.
#[test]
fn alpha_equivalent_record_templates_seal_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    for (name, source, expected) in [
        ("alpha_record_folded", FOLDED, "1\n"),
        ("alpha_record_distinct", DISTINCT, "3\n"),
    ] {
        let out = build(name, source, "e2e");
        let run = crate::support::build_and_run_emitted(name, &out);
        assert_eq!(
            run.exit_code,
            Some(0),
            "{name}: the emitted program must exit 0"
        );
        assert_eq!(run.stdout, expected, "{name}: stdout");
    }
}
