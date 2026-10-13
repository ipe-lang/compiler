//! SEAL tests for the or-pattern normal form.
//!
//! After lowering normalization an or-pattern exists only as a whole case-arm
//! head whose alternatives are each a constructor with every argument `_`, or an
//! `Int`/`Char`/`Bool` literal. Every other or-pattern arm is split into
//! consecutive single-pattern arms, first match wins, under a declared ceiling.
//!
//! | Test | Shape | Outcome |
//! |---|---|---|
//! | `p1_*` | `( Node l _ _, _ ) \| ( _, l )` | builds; each alternative binds its own `l` |
//! | `p2_str_or` | `"a" \| "b" -> 1`, `_ -> 0` | builds; prints `1,0` |
//! | `p3_bool_or_single_arm` | `True \| False -> 7` | builds; prints `7` |
//! | `p4_list_or_single_arm` | `[] \| _ :: _ -> 9` | builds; prints `9` |
//! | `p5_tuple_of_lists_or` | `( [], _ ) \| ( _, [] )` | builds; prints `1,0` |
//! | `p6_tuple_str_or` | `( "a", _ ) \| ( "b", _ )` | builds; prints `1,0` |
//! | `p7_diverging_alias_or` | `Square (n as w) \| Rect n w` | builds; prints `8,5` |
//! | `native_ctor_set_unchanged` | `Red \| Green -> 1` | builds; the emitted match keeps `\|` |
//! | `nested_or_in_ctor_arg` | `Just (Red \| Green) -> 1` | builds; prints `1,2,0` |
//! | `split_body_warning_once` | split arm whose body carries IPE-T0011 | the warning prints once |
//! | `arm_ceiling_*` | an arm expanding to 64 / 65 alternatives | 64 runs; 65 is IPE-L0116 at the arm |
//! | `node_ceiling_*` | splits adding exactly / one past `1 << 16` nodes | at the ceiling builds; past it is IPE-L0116 |
//! | `let_head_non_native_or` | `let ((x, _) \| (_, x)) = pair` | IPE-L0116 at the alternative; the `case` form builds |
//!
//! Every source is checked at `ipe` time here; under `IPE_E2E=1` the accepted
//! ones are also built with `cargo` and run (THE SEAL).
//!
//! ```text
//! cargo test -p ipe --test g_issues golden_3610
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_3610
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

use ipe::CliError;
use ipe_diagnostics::{Diagnostic, Feature, LowerError, Span};

/// The module header every source here shares.
const HEADER: &str = "module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


";

/// The `Tree` union and its sum, shared by the P1 sources.
const TREE: &str = "type Tree
    = Leaf
    | Node Tree Int Tree


sumTree : Tree -> Int
sumTree t =
    case t of
        Leaf ->
            0

        Node l v r ->
            sumTree l + v + sumTree r


pick : ( Tree, Tree ) -> Int
pick pair =
    case pair of
        ( Node l _ _, _ ) | ( _, l ) ->
            sumTree l


";

/// The three-constructor union the ceiling sources discriminate on.
const ABC: &str = "type T
    = A
    | B
    | C


";

fn out_dir(name: &str) -> PathBuf {
    let out = crate::support::scratch_root().join(format!("ipec_3610_{name}"));
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Write `HEADER` + `body` as a single-file `Main.ipe` under a fresh scratch dir.
#[allow(clippy::expect_used)] // a scratch-dir write failure is a test-environment fault
fn write_single(name: &str, body: &str) -> PathBuf {
    let dir = crate::support::scratch_root().join("3610-src").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the scratch source dir");
    let entry = dir.join("Main.ipe");
    std::fs::write(&entry, format!("{HEADER}{body}")).expect("write the scratch Main.ipe");
    entry
}

/// Build `entry` with `ipe`, returning its emitted directory, or failing the
/// test when `ipe` rejects it.
#[track_caller]
fn accept(name: &str, entry: &Path) -> PathBuf {
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{name}: ipe must accept the program; got {built:?}"
    );
    out
}

/// Build `body` with `ipe`, then (under `IPE_E2E=1`) `cargo build` and run it,
/// asserting exit 0 and `expected_stdout`. Returns the emitted directory.
#[track_caller]
fn accept_and_run(name: &str, body: &str, expected_stdout: &str) -> PathBuf {
    let entry = write_single(name, body);
    let out = accept(name, &entry);
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return out;
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must build and exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
    out
}

/// Assert `ipe` refuses `body` with IPE-L0116 from the or-pattern normal form,
/// returning the refusal's span.
#[track_caller]
fn refused_l0116(name: &str, body: &str) -> Option<Span> {
    let entry = write_single(name, body);
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let code = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        Ok(()) | Err(_) => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_L0116),
        "{name}: ipe must refuse with IPE-L0116; got {built:?}"
    );
    match &built {
        Err(CliError::Pipeline { diag, .. }) => match diag.as_ref() {
            Diagnostic::Lower {
                span,
                msg: LowerError::Unsupported(Feature::NestedCtorDiscrimination),
            } => Some(*span),
            _ => None,
        },
        Ok(()) | Err(_) => None,
    }
}

/// The byte offset of `needle` in `HEADER` + `body`, as a span start.
#[allow(clippy::expect_used)] // each needle is a literal taken from its own source
fn offset_of(body: &str, needle: &str) -> u32 {
    let at = format!("{HEADER}{body}")
        .find(needle)
        .expect("the needle is part of the source");
    u32::try_from(at).expect("the scratch sources are far below 4 GiB")
}

fn tree_main(arg: &str) -> String {
    format!("{TREE}main =\n    Io.println (String.fromInt (pick {arg}))\n")
}

/// The issue: alternative 1 matches and binds `l` under a boxed field.
#[test]
fn p1_tuple_ctor_or_binder() {
    accept_and_run(
        "p1_tuple_ctor_or_binder",
        &tree_main("( Node (Node Leaf 3 Leaf) 1 Leaf, Leaf )"),
        "3",
    );
}

/// Alternative 1 fails on `Leaf`, so alternative 2 binds `l` unboxed.
#[test]
fn p1b_second_alternative_taken() {
    accept_and_run(
        "p1b_second_alternative_taken",
        &tree_main("( Leaf, Node Leaf 5 Leaf )"),
        "5",
    );
}

/// Both alternatives match with different `l`: the first one wins.
#[test]
fn p1c_first_match_wins() {
    accept_and_run(
        "p1c_first_match_wins",
        &tree_main("( Node (Node Leaf 3 Leaf) 1 Leaf, Node Leaf 5 Leaf )"),
        "3",
    );
}

#[test]
fn p2_str_or() {
    accept_and_run(
        "p2_str_or",
        r#"classify : String -> Int
classify s =
    case s of
        "a" | "b" ->
            1

        _ ->
            0


main =
    Io.println (String.fromInt (classify "b") ++ "," ++ String.fromInt (classify "c"))
"#,
        "1,0",
    );
}

#[test]
fn p3_bool_or_single_arm() {
    accept_and_run(
        "p3_bool_or_single_arm",
        "always7 : Bool -> Int
always7 b =
    case b of
        True | False ->
            7


main =
    Io.println (String.fromInt (always7 False))
",
        "7",
    );
}

#[test]
fn p4_list_or_single_arm() {
    accept_and_run(
        "p4_list_or_single_arm",
        "always9 : List Int -> Int
always9 xs =
    case xs of
        [] | _ :: _ ->
            9


main =
    Io.println (String.fromInt (always9 [ 1 ]))
",
        "9",
    );
}

#[test]
fn p5_tuple_of_lists_or() {
    accept_and_run(
        "p5_tuple_of_lists_or",
        r#"either : ( List Int, List Int ) -> Int
either pair =
    case pair of
        ( [], _ ) | ( _, [] ) ->
            1

        _ ->
            0


main =
    Io.println (String.fromInt (either ( [ 1 ], [] )) ++ "," ++ String.fromInt (either ( [ 1 ], [ 2 ] )))
"#,
        "1,0",
    );
}

#[test]
fn p6_tuple_str_or() {
    accept_and_run(
        "p6_tuple_str_or",
        r#"tag : ( String, Int ) -> Int
tag pair =
    case pair of
        ( "a", _ ) | ( "b", _ ) ->
            1

        _ ->
            0


main =
    Io.println (String.fromInt (tag ( "b", 2 )) ++ "," ++ String.fromInt (tag ( "c", 2 )))
"#,
        "1,0",
    );
}

/// The alternatives mint `w` differently (an alias in one, a field in the other).
#[test]
fn p7_diverging_alias_or() {
    accept_and_run(
        "p7_diverging_alias_or",
        r#"type Shape
    = Square Int
    | Rect Int Int


measure : Shape -> Int
measure sh =
    case sh of
        Square (n as w) | Rect n w ->
            n + w


main =
    Io.println (String.fromInt (measure (Square 4)) ++ "," ++ String.fromInt (measure (Rect 2 3)))
"#,
        "8,5",
    );
}

/// A flat constructor set stays one native `|` arm; it is never split.
#[test]
fn native_ctor_set_unchanged() {
    let out = accept_and_run(
        "native_ctor_set_unchanged",
        r#"type Color
    = Red
    | Green
    | Blue


warm : Color -> Int
warm c =
    case c of
        Red | Green ->
            1

        Blue ->
            2


main =
    Io.println (String.fromInt (warm Green) ++ "," ++ String.fromInt (warm Blue))
"#,
        "1,2",
    );
    let emitted = crate::support::read_all_emitted_src(&out);
    assert!(
        emitted.contains("MainColor::Red | MainColor::Green"),
        "native_ctor_set_unchanged: the flat constructor set must stay one native `|` arm"
    );
}

/// An or-pattern nested in a constructor argument is split at the arm.
#[test]
fn nested_or_in_ctor_arg() {
    accept_and_run(
        "nested_or_in_ctor_arg",
        r#"type Color
    = Red
    | Green
    | Blue


warmish : Maybe Color -> Int
warmish m =
    case m of
        Just (Red | Green) ->
            1

        Just Blue ->
            2

        Nothing ->
            0


main =
    Io.println (String.fromInt (warmish (Just Green)) ++ "," ++ String.fromInt (warmish (Just Blue)) ++ "," ++ String.fromInt (warmish Nothing))
"#,
        "1,2,0",
    );
}

/// A split arm's body is lowered once per alternative, yet the warning its
/// body carries (IPE-T0011, a redundant branch) is printed exactly once.
#[test]
#[allow(clippy::expect_used)] // a missing `ipe` binary is a test-environment fault
fn split_body_warning_once() {
    let body = format!(
        "{TREE}type Color
    = Red
    | Green


redundant : Color -> ( Tree, Tree ) -> Int
redundant c pair =
    case pair of
        ( Node l _ _, _ ) | ( _, l ) ->
            case c of
                Red ->
                    sumTree l

                Green ->
                    0

                Red ->
                    1


main =
    Io.println (String.fromInt (redundant Red ( Leaf, Node Leaf 5 Leaf )))
"
    );
    let entry = write_single("split_body_warning_once", &body);
    let out = out_dir("split_body_warning_once");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let ran = Command::new(crate::support::ipe_bin())
        .args(["release", "eject"])
        .arg(&entry)
        .arg("--out")
        .arg(&out)
        .arg("--runtime")
        .arg(&runtime)
        .output()
        .expect("spawn the ipe binary");
    let stderr = String::from_utf8_lossy(&ran.stderr);
    assert!(
        ran.status.success(),
        "split_body_warning_once: ipe must accept the program; stderr:\n{stderr}"
    );
    assert_eq!(
        stderr.matches("IPE-T0011").count(),
        1,
        "split_body_warning_once: the body's warning must print exactly once; stderr:\n{stderr}"
    );
}

/// `( A | B, … ×6 )`, optionally followed by one more alternative.
fn arm_ceiling_source(extra_alternative: bool) -> String {
    let product = ["A | B"; 6].join(", ");
    let head = if extra_alternative {
        format!("( {product} ) | ( C, A, _, _, _, _ )")
    } else {
        format!("( {product} )")
    };
    format!(
        "{ABC}count : ( T, T, T, T, T, T ) -> Int
count t =
    case t of
        {head} ->
            1

        _ ->
            0


main =
    Io.println (String.fromInt (count ( B, A, B, A, B, A )) ++ \",\" ++ String.fromInt (count ( C, A, A, A, A, A )))
"
    )
}

/// The arm expands to exactly `OR_SPLIT_ARM_CEILING` (64) alternatives.
#[test]
fn arm_ceiling_at_limit_builds() {
    accept_and_run("arm_ceiling_at_limit", &arm_ceiling_source(false), "1,0");
}

/// One alternative past the arm ceiling is refused at the arm's pattern.
#[test]
fn arm_ceiling_plus_one() {
    let body = arm_ceiling_source(true);
    let span = refused_l0116("arm_ceiling_plus_one", &body);
    assert_eq!(
        span.map(|s| s.lo),
        Some(offset_of(&body, "( A | B, A | B")),
        "arm_ceiling_plus_one: the refusal must sit at the over-ceiling arm's pattern"
    );
}

/// One declaration whose splits add exactly `1 << 16` nodes, plus `past` more.
///
/// The 33-way arm copies its 2048-node body (a list node and 2047 elements) 32
/// times; the optional inner 2-way split copies its 1-node body once.
fn node_ceiling_source(past: bool) -> String {
    let product = ["A | B"; 5].join(", ");
    let elements = ["1"; 2047].join(", ");
    let fallback = if past {
        "case t of
                ( A, _, _, _, _ ) | ( B, _, _, _, _ ) ->
                    []

                _ ->
                    []"
    } else {
        "[]"
    };
    format!(
        "{ABC}big : ( T, T, T, T, T ) -> List Int
big t =
    case t of
        ( {product} ) | ( C, _, _, _, _ ) ->
            [ {elements} ]

        _ ->
            {fallback}


lengthOf : List Int -> Int
lengthOf xs =
    case xs of
        [] ->
            0

        _ :: rest ->
            1 + lengthOf rest


main =
    Io.println (String.fromInt (lengthOf (big ( A, A, A, A, A ))))
"
    )
}

/// Splits adding exactly `OR_SPLIT_NODE_CEILING` nodes are accepted.
#[test]
fn node_ceiling_at_limit_builds() {
    let entry = write_single("node_ceiling_at_limit", &node_ceiling_source(false));
    accept("node_ceiling_at_limit", &entry);
}

/// One node past `OR_SPLIT_NODE_CEILING` is refused.
#[test]
fn node_ceiling_plus_one() {
    let span = refused_l0116("node_ceiling_plus_one", &node_ceiling_source(true));
    assert!(
        span.is_some(),
        "node_ceiling_plus_one: the refusal must come from the or-pattern normal form"
    );
}

/// A non-native or-pattern in a `let` head has no sibling arm to split into.
#[test]
fn let_head_non_native_or() {
    let body = "first : ( Int, Int ) -> Int
first pair =
    let
        ((x, _) | (_, x)) =
            pair
    in
    x


main =
    Io.println (String.fromInt (first ( 1, 2 )))
";
    let span = refused_l0116("let_head_non_native_or", body);
    assert_eq!(
        span.map(|s| s.lo),
        Some(offset_of(body, "(x, _)")),
        "let_head_non_native_or: the refusal must sit at the alternative"
    );
}

/// The `case` form of the refused `let` head builds and runs.
#[test]
fn let_head_non_native_or_case_control() {
    accept_and_run(
        "let_head_non_native_or_case_control",
        "first : ( Int, Int ) -> Int
first pair =
    case pair of
        ( x, _ ) | ( _, x ) ->
            x


main =
    Io.println (String.fromInt (first ( 1, 2 )))
",
        "1",
    );
}
