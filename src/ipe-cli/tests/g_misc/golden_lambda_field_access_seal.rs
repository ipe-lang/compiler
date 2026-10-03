//! THE SEAL for a field read or update on a higher-order kernel's callback result.
//!
//! `Maybe.map (\u -> u.name) (Maybe.map (\e -> e.unit) m)` reads a field on a
//! value whose type is the inner callback's result, a variable that settles to
//! a record only after the outer access is first seen. The checker waits for
//! it rather than refusing with IPE-T0012; each fixture must be accepted, and
//! under `IPE_E2E` its emitted crate must `cargo build`, including the one whose
//! bases never settle and keep open rows.
//!
//! ```text
//! # emit check only (fast):
//! cargo test -p ipe --test g_misc golden_lambda_field_access_seal
//! # full (cargo build of the emitted program):
//! IPE_E2E=1 cargo test -p ipe --test g_misc golden_lambda_field_access_seal
//! ```

use std::path::PathBuf;

use ipe::CliError;

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(), …)`
/// reads as a deliberate unconditional failure rather than a suspicious constant
/// condition.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// The reported shape: a `List.find` result mapped to a nested record in a `do`.
const FIND_THEN_FIELD: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.List as List
import Ipe.Maybe as Maybe
import Ipe.Task as Task


ok : Task Error Bool
ok =
    do
        r <- Task.succeed { units = [ { uid = "a", unit = { name = "x" } } ] }
        Task.succeed
            (case Maybe.map (\e -> e.unit) (List.find (\e -> e.uid == "a") r.units) of
                Just u ->
                    u.name == "x"

                Nothing ->
                    False
            )


main : Task Error ()
main =
    do
        found <- ok
        Io.println (if found then "found" else "missing")
"#;

/// Two nested `Maybe.map`s, the inner one returning a record.
const NESTED_MAYBE_MAP: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.Maybe as Maybe


ok : Maybe String
ok =
    Maybe.map (\u -> u.name) (Maybe.map (\e -> e.unit) (Just { unit = { name = "x" } }))


main : Task Error ()
main =
    Io.println (Maybe.withDefault "none" ok)
"#;

/// The same chain through piped `List.map`s.
const PIPED_LIST_MAP: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String


names : List String
names =
    [ { unit = { name = "x" } }, { unit = { name = "y" } } ]
        |> List.map (\e -> e.unit)
        |> List.map (\u -> u.name)


main : Task Error ()
main =
    Io.println (String.join "," names)
"#;

/// A record update whose base is a callback result two `Maybe.map`s deep.
const UPDATE_THROUGH_MAP: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.Maybe as Maybe


renamed : Maybe String
renamed =
    Maybe.map (\u -> { u | name = "y" })
        (Maybe.map (\e -> e.unit)
            (Maybe.map (\d -> d.inner) (Just { inner = { unit = { name = "x" } } }))
        )
        |> Maybe.map (\u -> u.name)


main : Task Error ()
main =
    Io.println (Maybe.withDefault "none" renamed)
"#;

/// Bases no value ever settles: both accesses grow open rows.
const NEVER_SETTLED: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.Maybe as Maybe


h =
    Maybe.map (\u -> u.name) (Maybe.map (\e -> e.unit) Nothing)


main : Task Error ()
main =
    Io.println (Maybe.withDefault "none" h)
"#;

/// An equality-owing record base compared before its field is read: the deep
/// equality check must see the field type the later `== 1` defaults to `Int`.
const EQ_ON_DEFERRED_BASE: &str = r#"module Main exposing (main)

import Ipe.Io as Io


sameX a =
    a == a && a.x == 1


main : Task Error ()
main =
    Io.println (if sameX { x = 1 } then "same" else "differs")
"#;

/// An equality-owing base whose field type is never pinned inside the
/// function: the field's equality must be decided per call site.
const EQ_ON_UNPINNED_FIELD: &str = r#"module Main exposing (main)

import Ipe.Io as Io


pair a =
    a == a && a.x == a.x


main : Task Error ()
main =
    Io.println (if pair { x = "q" } then "same" else "differs")
"#;

#[test]
fn find_then_field_builds() {
    assert_accepted_and_builds("find_then_field", FIND_THEN_FIELD);
}

#[test]
fn nested_maybe_map_builds() {
    assert_accepted_and_builds("nested_maybe_map", NESTED_MAYBE_MAP);
}

#[test]
fn piped_list_map_builds() {
    assert_accepted_and_builds("piped_list_map", PIPED_LIST_MAP);
}

#[test]
fn update_through_map_builds() {
    assert_accepted_and_builds("update_through_map", UPDATE_THROUGH_MAP);
}

#[test]
fn never_settled_builds() {
    assert_accepted_and_builds("never_settled", NEVER_SETTLED);
}

#[test]
fn eq_on_deferred_base_builds() {
    assert_accepted_and_builds("eq_on_deferred_base", EQ_ON_DEFERRED_BASE);
}

/// `source` must be accepted by `ipe`, and under `IPE_E2E` its crate must `cargo build`.
#[test]
fn eq_on_unpinned_field_builds() {
    assert_accepted_and_builds("eq_on_unpinned_field", EQ_ON_UNPINNED_FIELD);
}

fn assert_accepted_and_builds(name: &str, source: &str) {
    let Some((built, out)) = build_fixture(name, source) else {
        return;
    };
    match built {
        Ok(()) => crate::support::assert_seal_builds(name, &out),
        Err(err) => assert!(
            false_marker(),
            "{name}: a field read on a callback result must be accepted, got: {err:?}"
        ),
    }
}

/// Build `source` as `name`, returning the build result and its output dir
/// (`None`, after a failed assertion, when scratch or runtime setup fails).
fn build_fixture(name: &str, source: &str) -> Option<(Result<(), CliError>, PathBuf)> {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("lambda-field-access");
    let src = root.join(name).join("src");
    let _ = std::fs::remove_dir_all(root.join(name));
    let entry = src.join("Main.ipe");
    if std::fs::create_dir_all(&src)
        .and_then(|()| std::fs::write(&entry, source))
        .is_err()
    {
        assert!(
            false_marker(),
            "{name}: could not write the fixture into the scratch dir"
        );
        return None;
    }
    let out = root.join(format!("{name}-out"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    Some((ipe::build(&entry, &out, &runtime), out))
}
