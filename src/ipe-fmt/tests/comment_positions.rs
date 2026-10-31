//! Every comment position the grammar admits survives `ipe_fmt::format_source`.
//!
//! Each seed below is re-written once per position a comment can take — an
//! own-line `-- CMT` above every line, a trailing `-- CMT` and `{- CMT -}`
//! after every line, a `{- CMT -}` before every token that follows a space,
//! and one at the end of the file. That covers the comment before `module`, inside the exposing
//! list, between imports, between and inside declarations, inside
//! constructor arguments, `let`, `case`, records, lists, tuples, lambdas and
//! pipelines. Every variant the parser accepts must format, keep its one
//! comment, and be a fixed point of a second pass: a comment position with no
//! owner in the renderer turns this test red, rather than the `IPE-I0001`
//! guard refusing the user's file.
//!
//! The seeds are canonical, so every seed line end is an output line end: a
//! comment ending a line whose last token ends a node must stay exactly
//! there, and a composer with no slot for it fails by name.

use ipe_intern::Interner;
use ipe_parse::TokenClass;

/// A module header, imports, a union, a record alias, and a `case`.
const HEADER_SEED: &str = r"module Seed exposing
    ( Shape(..)
    , area
    , origin
    )

import Ipe.List as List exposing (map)
import Ipe.Maybe as Maybe
import Ipe.String as String


type Shape
    = Circle Float
    | Rect Float Float


type alias Point =
    { x : Float
    , y : Float
    }


origin : Point
origin =
    { x = 0, y = 0 }


area : Shape -> Float
area shape =
    case shape of
        Circle r ->
            r * r

        Rect w h ->
            w * h
";

/// Lambdas, `let` with a tuple binder, `if`, `case`, a pipeline, a record,
/// a list, a tuple, a doc above a signature, and a comment run above a
/// `case` arm.
const EXPRESSION_SEED: &str = r#"module Seed exposing (config, run)


run : List Int -> Maybe Int -> Int
run xs m =
    let
        total =
            List.foldl (\x acc -> x + acc) 0 xs

        ( a, b ) =
            ( 1, 2 )
    in
    if total > 10 then
        case m of
            Just v ->
                v + a

            Nothing ->
                b

    else
        xs
            |> List.map (\x -> x * 2)
            |> List.sum


config =
    { name = "seed"
    , items = [ 1, 2, 3 ]
    , pair = ( 1, "a" )
    }


-- | Pick a value.
pick : Int -> Int
pick n =
    case n of
        0 ->
            1

        -- one
        -- two
        _ ->
            n


step :
    Int
    -> Int
    -> Int
step a b =
    a
        + b
        + 1


main =
    do
        x <- Task.succeed 1
        Io.println "run"
        Task.succeed x


bump r =
    { r
        | a = 1
        , b = 2
    }
"#;

/// The fewest parser-accepted variants the seeds must yield.
///
/// Below it, the enumeration exercised too few positions to prove anything.
const MIN_ACCEPTED_VARIANTS: usize = 200;

/// The fewest end-of-line variants after a node's last token the seeds must
/// yield, each asserted kept in place byte-exact.
const MIN_KEPT_EOL_VARIANTS: usize = 94;

/// The source with `line` at index `at` replaced by `with` (or inserted
/// before it when `insert` holds).
fn splice(lines: &[&str], at: usize, with: &str, insert: bool) -> String {
    let rest = if insert { at } else { at + 1 };
    let mut out: Vec<&str> = lines.get(..at).unwrap_or_default().to_vec();
    out.push(with);
    out.extend_from_slice(lines.get(rest..).unwrap_or_default());
    out.join("\n")
}

/// One comment variant of a seed.
struct Variant {
    /// The comment's position.
    name: String,
    /// The seed with the comment.
    src: String,
    /// The comment ends a seed line whose last code token ends a node, so it
    /// must stay exactly there.
    kept: bool,
}

/// For each line of `src`, whether its last code token ends a node.
#[allow(clippy::expect_used)] // a seed that does not lex is a broken test
fn ends_node_by_line(src: &str) -> Vec<bool> {
    let tokens = ipe_parse::try_source_tokens(src).expect("seed lexes");
    let mut ends = Vec::new();
    let mut lo = 0usize;
    for line in src.split('\n') {
        let hi = lo + line.len();
        let last = tokens
            .iter()
            .filter(|t| (t.span.lo as usize) >= lo && (t.span.hi as usize) <= hi)
            .filter_map(|t| match t.class {
                TokenClass::Code(kind) => Some(kind),
                TokenClass::DocComment => None,
            })
            .last();
        ends.push(last.is_some_and(ipe_fmt::ends_node));
        lo = hi + 1;
    }
    ends
}

/// Every single-comment variant of `src`, each named by its position.
fn variants(src: &str) -> Vec<Variant> {
    let lines: Vec<&str> = src.split('\n').collect();
    let ends = ends_node_by_line(src);
    let mut out = Vec::new();
    let mut push = |name: String, src: String, kept: bool| out.push(Variant { name, src, kept });
    for (i, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        let own = format!("{}-- CMT", " ".repeat(indent));
        push(
            format!("own-line above L{}", i + 1),
            splice(&lines, i, &own, true),
            false,
        );
        let at_end = ends.get(i).copied().unwrap_or(false);
        for (what, cmt) in [("end", "-- CMT"), ("block end", "{- CMT -}")] {
            let eol = format!("{line} {cmt}");
            push(
                format!("{what} of L{}", i + 1),
                splice(&lines, i, &eol, false),
                at_end,
            );
        }
        for (j, pair) in line.as_bytes().windows(2).enumerate() {
            let col = j + 1;
            if col <= indent || !matches!(pair, [b' ', next] if *next != b' ') {
                continue;
            }
            let (head, tail) = line.split_at(col);
            let mid = format!("{head}{{- CMT -}} {tail}");
            push(
                format!("inline at L{}c{}", i + 1, col + 1),
                splice(&lines, i, &mid, false),
                false,
            );
        }
    }
    push(
        "end of file".to_owned(),
        format!("{}\n-- CMT\n", src.trim_end_matches('\n')),
        false,
    );
    out
}

fn parses(src: &str) -> bool {
    ipe_parse::parse_module(src, &mut Interner::new()).is_ok()
}

/// The canonical form of `src`, failing the test with `what` on a refusal.
#[allow(clippy::expect_used)] // a refusal is the failure this test reports
fn format(src: &str, what: &str) -> String {
    ipe_fmt::format_source(src)
        .map_err(|e| format!("{e}"))
        .expect(what)
}

#[test]
fn every_admitted_comment_position_is_kept_and_stable() {
    let mut accepted = 0usize;
    let mut kept = 0usize;
    let mut moved: Vec<String> = Vec::new();
    for seed in [HEADER_SEED, EXPRESSION_SEED] {
        assert_eq!(
            format(seed, "seed formats"),
            seed,
            "a seed must be canonical"
        );
        for Variant {
            name,
            src,
            kept: stays,
        } in variants(seed)
        {
            if !parses(&src) {
                continue;
            }
            accepted += 1;
            let once = format(&src, &format!("{name}: refused\n{src}"));
            if stays {
                kept += 1;
                if once != src {
                    moved.push(format!("{name}:\n{once}"));
                }
            }
            assert_eq!(
                once.matches("CMT").count(),
                1,
                "{name}: the comment was not kept exactly once\n{once}"
            );
            let twice = format(&once, &format!("{name}: second pass refused\n{once}"));
            assert_eq!(twice, once, "{name}: not a fixed point\n{src}");
        }
    }
    assert!(
        moved.is_empty(),
        "{} end-of-line comments moved off their line end:\n{}",
        moved.len(),
        moved.join("\n")
    );
    assert!(
        accepted >= MIN_ACCEPTED_VARIANTS,
        "only {accepted} variants parsed, below the floor of {MIN_ACCEPTED_VARIANTS}"
    );
    assert!(
        kept >= MIN_KEPT_EOL_VARIANTS,
        "only {kept} end-of-line variants kept, below the floor of {MIN_KEPT_EOL_VARIANTS}"
    );
}

/// One comment in each owner's territory keeps its source order.
const ORDERED: &str = r#"-- C01 before module
module Seed exposing
    ( Shape(..)
    -- C02 inside exposing
    , area
    , config
    )

-- C03 above the imports
import Ipe.List as List
-- C04 between imports
import Ipe.Maybe as Maybe


-- C05 above a declaration
type Shape
    = Circle Float
    -- C06 between constructors
    | Rect Float Float


area : Shape -> Float
area shape =
    let
        -- C07 inside let
        k =
            [ 1
            -- C08 inside a list
            , 2
            ]
    in
    case shape of
        -- C09 inside case
        Circle r ->
            r

        Rect w h ->
            w * h


config =
    { name = "seed"
    -- C10 inside a record
    , size = 2
    }

-- C11 at end of file
"#;

#[test]
fn comments_in_every_owner_keep_source_order() {
    let out = format(ORDERED, "formats");
    let mut last = 0usize;
    for n in 1..=11 {
        let tag = format!("C{n:02}");
        let at = out.find(&tag);
        assert!(at.is_some(), "{tag} lost\n{out}");
        let at = at.unwrap_or_default();
        assert!(at >= last, "{tag} moved before an earlier comment\n{out}");
        last = at;
    }
    assert_eq!(format(&out, "second pass"), out, "not a fixed point");
}

/// A comment between two `import` lines formats, keeps its import, and is
/// stable.
#[test]
fn a_comment_between_imports_formats() {
    let src = "module M exposing (x)\n\nimport A\n-- about B\nimport B\n\n\nx =\n    1\n";
    let out = format(src, "formats");
    assert_eq!(out, src);
}
