//! THE SEAL for a pattern that reads a boxed constructor field below the top.
//!
//! A cyclic self-edge field is `Box<…>` in the emitted enum. A pattern that
//! binds or destructures such a field must read it through the box at every
//! depth: under a `Maybe`, inside a tuple payload, as a list element, in an
//! or-pattern alternative. A binder left as `Box<Tree>` where the arm body
//! reads a `Tree` makes the emitted crate fail `cargo build` (E0308) AFTER
//! `ipe` already exited 0 — the SEAL break `PRINCIPLES.md` forbids.
//!
//! Every pattern renderer reads a constructor's fields through one field-aware
//! funnel, which unboxes a bound field, destructures a boxed tuple through a
//! temporary, and refuses (fail closed, at `ipe` time) a test that would have
//! to look through the box.
//!
//! | Fixture | Shape | Outcome |
//! |---|---|---|
//! | `maybe_wrapped_node` | `Just (Node l n r)` over `Maybe Tree` | builds + prints `12` |
//! | `boxed_tuple_payload` | `ChainNode (rest, n)` | builds + prints `5` |
//! | `borrowed_list_element` | `(Node l _ _) :: rest`, `Clone` element | builds + prints `8` |
//! | `owned_list_element` | `(Step k _) :: rest`, non-`Clone` element | builds + prints `2` |
//! | `alias_in_boxed_tuple` | `ChainNode ((rest as whole), n)` | builds + prints `8` |
//! | `or_same_boxed_binder` | `GoLeft next \| GoRight next` | builds + prints `3` |
//! | `boxed_ctor_test` | `Node Leaf _ _` + catch-all | fail-closed at `ipe` time |
//! | `boxed_tuple_ctor_test` | `ChainNode (ChainEnd, 0)` + catch-all | fail-closed at `ipe` time |
//! | `or_uneven_boxed_binder` | `(Node l _ _, _) \| (_, l)` | fail-closed at `ipe` time |
//! | `boxed_string_test` | `Pair (Plain "go") _ _` | fail-closed IPE-L0116 |
//!
//! The refusals assert a typed `ipe`-time diagnostic, never a cargo failure.
//! A test through the box is refused either by the lowerer (IPE-L0116) or, as
//! the emit boundary, by the backend funnel (IPE-I0001); both keep the program
//! from reaching cargo. The positives prove the funnel does not over-reject.
//!
//! ```text
//! # gate check only (fast):
//! cargo test -p ipe --test g_issues golden_3121
//! # full (cargo build + run the positive fixtures):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_3121
//! ```

use std::path::PathBuf;

use ipe::CliError;

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(), …)`
/// reads as a deliberate unconditional failure rather than a suspicious constant
/// condition.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// Write `source` as a single-file `Main.ipe` under a fresh scratch dir keyed by
/// `name`, returning the entry path (or `None` if scratch setup fails).
fn write_single(name: &str, source: &str) -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("g3121")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(&src).ok()?;
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, source).ok()?;
    Some(entry)
}

/// The scratch output dir for `name`, cleared.
fn out_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("g3121-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert that `source` is REJECTED by `ipe` with one of `expected`, never
/// accepted-then-cargo-failed. Runs without `IPE_E2E`: emission never happens.
#[track_caller]
fn assert_rejected(name: &str, source: &str, expected: &[ipe_diagnostics::Code]) {
    let entry = crate::support::expect_scratch_entry(name, write_single(name, source));
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build(&entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert!(
            expected.contains(&diag.code()),
            "{name}: expected a fail-closed {expected:?}, got {}",
            diag.code().as_str()
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED a test through a boxed field (exit 0) — the \
             emitted crate would fail cargo with E0308, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// Assert that `source` is ACCEPTED by `ipe` (exit 0) and — under `IPE_E2E` —
/// that the emitted crate `cargo build`s and runs to `expected_stdout`.
#[track_caller]
fn assert_accepted(name: &str, source: &str, expected_stdout: &str) {
    let entry = crate::support::expect_scratch_entry(name, write_single(name, source));
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build(&entry, &out, &runtime) {
        Ok(()) => {}
        Err(CliError::Pipeline { diag, .. }) => {
            assert!(
                false_marker(),
                "{name}: ipe REJECTED a well-formed program with {} — a false rejection",
                diag.code().as_str()
            );
            return;
        }
        Err(other) => {
            assert!(
                false_marker(),
                "{name}: non-pipeline build error: {other:?}"
            );
            return;
        }
    }

    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return; // emit-only fast pass
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must run to exit 0"
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// A refusal of a test through the box: the lowerer or the backend funnel.
const THROUGH_THE_BOX: &[ipe_diagnostics::Code] =
    &[ipe_diagnostics::IPE_L0116, ipe_diagnostics::IPE_I0001];

/// `Node`'s boxed fields bound under a `Just`. Prints `12` (3 + 4 + 5).
const MAYBE_WRAPPED_NODE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Tree = Leaf | Node Tree Int Tree


sumTree : Tree -> Int
sumTree t =
    case t of
        Leaf ->
            0

        Node l n r ->
            sumTree l + n + sumTree r


rootSum : Maybe Tree -> Int
rootSum mt =
    case mt of
        Just (Node l n r) ->
            sumTree l + n + sumTree r

        Just Leaf ->
            0

        Nothing ->
            100


main =
    Io.println (String.fromInt (rootSum (Just (Node (Node Leaf 3 Leaf) 4 (Node Leaf 5 Leaf)))))
";

/// A boxed tuple payload destructured into its parts. Prints `5` (2 + 3).
const BOXED_TUPLE_PAYLOAD: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Chain = ChainEnd | ChainNode (Chain, Int)


total : Chain -> Int
total c =
    case c of
        ChainEnd ->
            0

        ChainNode (rest, n) ->
            n + total rest


main =
    Io.println (String.fromInt (total (ChainNode (ChainNode (ChainEnd, 3), 2))))
";

/// A boxed field bound inside a borrowed list element. Prints `8` (3 + 5).
const BORROWED_LIST_ELEMENT: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Tree = Leaf | Node Tree Int Tree


sumTree : Tree -> Int
sumTree t =
    case t of
        Leaf ->
            0

        Node l n r ->
            sumTree l + n + sumTree r


leftSums : List Tree -> Int
leftSums ts =
    case ts of
        (Node l _ _) :: rest ->
            sumTree l + leftSums rest

        _ :: rest ->
            leftSums rest

        [] ->
            0


main =
    Io.println (String.fromInt (leftSums [ Node (Node Leaf 3 Leaf) 4 Leaf, Leaf, Node (Node Leaf 5 Leaf) 1 Leaf ]))
";

/// A boxed field bound inside an owned list element: the `Task` payload makes
/// `Job` non-`Clone`, so the consumed list is matched through its owned view.
/// Prints `2`.
const OWNED_LIST_ELEMENT: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


type Job = Stop | Step Job (Task Error Int)


depth : Job -> Int
depth j =
    case j of
        Stop ->
            0

        Step k _ ->
            1 + depth k


inners : List Job -> Int
inners js =
    case js of
        (Step k _) :: rest ->
            depth k + inners rest

        _ :: rest ->
            inners rest

        [] ->
            0


main =
    Io.println (String.fromInt (inners [ Step (Step (Step Stop (Task.succeed 1)) (Task.succeed 2)) (Task.succeed 3), Stop, Step Stop (Task.succeed 4) ]))
";

/// An alias inside the boxed tuple payload. Prints `8` (2 + 3 + 3).
const ALIAS_IN_BOXED_TUPLE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Chain = ChainEnd | ChainNode (Chain, Int)


weigh : Chain -> Int
weigh c =
    case c of
        ChainEnd ->
            0

        ChainNode ((rest as whole), n) ->
            n + weigh rest + weigh whole


main =
    Io.println (String.fromInt (weigh (ChainNode (ChainNode (ChainEnd, 3), 2))))
";

/// Both or-pattern alternatives bind the same boxed field. Prints `3`.
const OR_SAME_BOXED_BINDER: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Path = Tip | GoLeft Path | GoRight Path


len : Path -> Int
len p =
    case p of
        Tip ->
            0

        GoLeft next | GoRight next ->
            1 + len next


main =
    Io.println (String.fromInt (len (GoLeft (GoRight (GoLeft Tip)))))
";

/// A constructor test at a boxed field: the box must be looked through.
const BOXED_CTOR_TEST: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Tree = Leaf | Node Tree Int Tree


leftIsLeaf : Tree -> Int
leftIsLeaf t =
    case t of
        Node Leaf _ _ ->
            1

        _ ->
            0


main =
    Io.println (String.fromInt (leftIsLeaf (Node Leaf 1 Leaf)))
";

/// A constructor and a literal test inside a destructured boxed tuple.
const BOXED_TUPLE_CTOR_TEST: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Chain = ChainEnd | ChainNode (Chain, Int)


isLast : Chain -> Int
isLast c =
    case c of
        ChainNode (ChainEnd, 0) ->
            1

        _ ->
            0


main =
    Io.println (String.fromInt (isLast (ChainNode (ChainEnd, 0))))
";

/// Or-pattern alternatives binding `l` boxed in one and unboxed in the other.
const OR_UNEVEN_BOXED_BINDER: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Tree = Leaf | Node Tree Int Tree


sumTree : Tree -> Int
sumTree t =
    case t of
        Leaf ->
            0

        Node l n r ->
            sumTree l + n + sumTree r


pick : ( Tree, Tree ) -> Int
pick pair =
    case pair of
        ( Node l _ _, _ ) | ( _, l ) ->
            sumTree l


main =
    Io.println (String.fromInt (pick ( Node (Node Leaf 3 Leaf) 4 Leaf, Leaf )))
";

/// A string test two levels down, at a boxed field: the lowerer's refusal.
const BOXED_STRING_TEST: &str = r#"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Note = Plain String | Pair Note Int Note


isGo : Note -> Int
isGo t =
    case t of
        Pair (Plain "go") _ _ ->
            1

        _ ->
            0


main =
    Io.println (String.fromInt (isGo (Pair (Plain "go") 1 (Plain "x"))))
"#;

#[test]
fn maybe_wrapped_node_round_trips() {
    assert_accepted("maybe_wrapped_node", MAYBE_WRAPPED_NODE, "12");
}

#[test]
fn boxed_tuple_payload_round_trips() {
    assert_accepted("boxed_tuple_payload", BOXED_TUPLE_PAYLOAD, "5");
}

#[test]
fn borrowed_list_element_round_trips() {
    assert_accepted("borrowed_list_element", BORROWED_LIST_ELEMENT, "8");
}

#[test]
fn owned_list_element_round_trips() {
    assert_accepted("owned_list_element", OWNED_LIST_ELEMENT, "2");
}

#[test]
fn alias_in_boxed_tuple_round_trips() {
    assert_accepted("alias_in_boxed_tuple", ALIAS_IN_BOXED_TUPLE, "8");
}

#[test]
fn or_same_boxed_binder_round_trips() {
    assert_accepted("or_same_boxed_binder", OR_SAME_BOXED_BINDER, "3");
}

#[test]
fn boxed_ctor_test_fails_closed() {
    assert_rejected("boxed_ctor_test", BOXED_CTOR_TEST, THROUGH_THE_BOX);
}

#[test]
fn boxed_tuple_ctor_test_fails_closed() {
    assert_rejected(
        "boxed_tuple_ctor_test",
        BOXED_TUPLE_CTOR_TEST,
        THROUGH_THE_BOX,
    );
}

#[test]
fn or_uneven_boxed_binder_fails_closed() {
    assert_rejected(
        "or_uneven_boxed_binder",
        OR_UNEVEN_BOXED_BINDER,
        &[ipe_diagnostics::IPE_I0001],
    );
}

#[test]
fn boxed_string_test_fails_closed() {
    assert_rejected(
        "boxed_string_test",
        BOXED_STRING_TEST,
        &[ipe_diagnostics::IPE_L0116],
    );
}
