//! An end-of-line comment after a node's last token stays at the end of its
//! line; one after a token that leaves its construct open prints on its own
//! line above the code that follows.
//!
//! Every case is a fixed point of a second pass.

/// The canonical form of `src`, failing the test with `what` on a refusal.
#[allow(clippy::expect_used)] // a refusal is the failure this test reports
fn format(src: &str, what: &str) -> String {
    ipe_fmt::format_source(src)
        .map_err(|e| format!("{e}"))
        .expect(what)
}

/// Assert `src` formats to `expected` and that `expected` is a fixed point.
fn formats_to(src: &str, expected: &str) {
    let once = format(src, "formats");
    assert_eq!(once, expected, "input:\n{src}");
    assert_eq!(format(&once, "second pass"), once, "not a fixed point");
}

/// Assert `src` is canonical: it formats to itself.
fn kept(src: &str) {
    formats_to(src, src);
}

const FMT2: &str = r#"module M exposing (Shape(..), area, main, rec, xs)

import Ipe.List as List -- lists
import Ipe.String as String


type Shape
    = Circle Float -- round
    | Tri Float Float -- three sides
    | Rect Float Float


area : Shape -> Float
area s =
    case s of
        Circle r ->
            r * r -- circle

        Tri a b ->
            a * b

        Rect w h ->
            w * h


xs : List Int
xs =
    [ 1
    , 2 -- two
    , 3 -- last
    ]


rec : { a : Int, b : Int }
rec =
    { a = 1 -- first
    , b = 2
    }


main =
    xs
        |> List.map (\x -> x + 1) -- bump
        |> List.map String.fromInt
        |> String.join "," -- joined
"#;

/// Comments ending an import, a constructor, a case arm, a collection item,
/// a record field, a pipeline step and the declaration stay in place.
#[test]
fn end_of_line_comments_stay_in_place() {
    kept(FMT2);
}

/// An import's comment travels with it through the sort.
#[test]
fn an_import_comment_travels_with_the_sort() {
    formats_to(
        "module M exposing (f)\n\nimport B -- about B\nimport A\n\n\nf =\n    1\n",
        "module M exposing (f)\n\nimport A\nimport B -- about B\n\n\nf =\n    1\n",
    );
}

/// Each top-level and statement slot keeps its comment at its line end.
#[test]
fn every_line_end_slot_keeps_its_comment() {
    for src in [
        "module M exposing (f) -- api\n\n\nf =\n    1\n",
        "module M exposing\n    ( f -- eff\n    , g\n    )\n\n\nf =\n    1\n\n\ng =\n    2\n",
        "module M exposing (P)\n\n\ntype alias P =\n    { a : Int -- count\n    , b : Int\n    }\n",
        "module M exposing (f)\n\n\nf :\n    Int -- first\n    -> Int\nf x =\n    x\n",
        "module M exposing (f)\n\n\nf x =\n    let\n        y =\n            x + 1 -- next\n    in\n    y\n",
        "module M exposing (f)\n\n\nf a b =\n    if a > b then\n        a -- bigger\n\n    else\n        b\n",
        "module M exposing (main)\n\nimport Ipe.Io as Io\n\n\nmain =\n    do\n        Io.println \"a\" -- greet\n        Io.println \"b\"\n",
    ] {
        kept(src);
    }
}

/// A comment after an item of a collection that shares its line with other
/// items breaks the collection one item per line, the comment ending its
/// item's line.
#[test]
fn an_interior_comment_breaks_its_collection() {
    formats_to(
        "module M exposing (xs)\n\n\nxs =\n    [ 1, 2 -- two\n    ]\n",
        "module M exposing (xs)\n\n\nxs =\n    [ 1\n    , 2 -- two\n    ]\n",
    );
}

/// A call head owning a comment stays alone on its line: joining the first
/// argument would put that argument inside the comment.
#[test]
fn a_commented_call_head_stands_alone() {
    kept(
        "module M exposing (g)\n\n\ng x =\n    foo -- head\n        x\n        (bar x)\n        x\n",
    );
}

const HEAD: &str = "module M exposing (f)\n\n\n";

/// A comment after a token a head keeps on one line with the next code
/// prints on its own line, where the head's layout puts leading comments.
#[test]
fn head_position_comments_are_demoted() {
    let module = "module M -- c\n    exposing (f)\n\n\nf =\n    1\n";
    formats_to(module, "-- c\n\n\nmodule M exposing (f)\n\n\nf =\n    1\n");
    let cases = [
        (
            "f x =\n    case x of\n        Just -- inner\n            y ->\n            y\n\n        _ ->\n            0\n",
            "f x =\n    case x of\n        -- inner\n        Just y ->\n            y\n\n        _ ->\n            0\n",
        ),
        ("f -- p\n  x =\n    x\n", "f x =\n    -- p\n    x\n"),
        (
            "f : Maybe -- c\n    Int -> Int\nf x =\n    x\n",
            "f :\n    Maybe Int\n    -> Int\n-- c\nf x =\n    x\n",
        ),
        (
            "f x =\n    case x -- c\n    of\n        _ ->\n            0\n",
            "f x =\n    case x of\n        -- c\n        _ ->\n            0\n",
        ),
    ];
    for (src, expected) in cases {
        formats_to(&format!("{HEAD}{src}"), &format!("{HEAD}{expected}"));
    }
}

/// A block comment followed by code on its line is a leading comment; one
/// ending its line trails the token before it.
#[test]
fn a_block_comment_trails_only_at_a_line_end() {
    formats_to(
        &format!("{HEAD}f x y =\n    x {{- c -}} + y\n"),
        &format!("{HEAD}f x y =\n    x\n        {{- c -}}\n        + y\n"),
    );
    kept(&format!("{HEAD}f x =\n    x {{- c -}}\n"));
}

/// A comment after `=`, `of` or an operator leads the code below it.
#[test]
fn a_comment_after_an_open_token_leads_the_next_code() {
    let cases = [
        ("f x = -- c\n    1\n", "f x =\n    -- c\n    1\n"),
        (
            "f x =\n    case x of -- c\n        _ ->\n            0\n",
            "f x =\n    case x of\n        -- c\n        _ ->\n            0\n",
        ),
        (
            "f a b =\n    a + -- c\n        b\n",
            "f a b =\n    a\n        -- c\n        + b\n",
        ),
    ];
    for (src, expected) in cases {
        formats_to(&format!("{HEAD}{src}"), &format!("{HEAD}{expected}"));
    }
}

/// Assert each declaration body `src` formats to `expected` under `HEAD`.
fn bodies_format_to(cases: &[(&str, &str)]) {
    for (src, expected) in cases {
        formats_to(&format!("{HEAD}{src}"), &format!("{HEAD}{expected}"));
    }
}

/// A comment before a group's `)` trails the code the group holds where the
/// layout keeps the group's parentheses: it prints once, in place.
#[test]
fn a_comment_inside_a_kept_group_stays_once() {
    bodies_format_to(&[
        (
            "f =\n    g (h x -- c\n    ) x\n",
            "f =\n    g\n        (h x -- c\n        )\n        x\n",
        ),
        (
            "f =\n    g (h (k x -- c\n    )\n    )\n",
            "f =\n    g\n        (h\n            (k x -- c\n            )\n        )\n",
        ),
        (
            "f =\n    g (a + b -- c\n    ) y\n",
            "f =\n    g\n        (a\n            + b -- c\n        )\n        y\n",
        ),
    ]);
}

/// A comment after a `)` the layout drops trails the code the group held,
/// at the same line end.
#[test]
fn a_comment_after_a_dropped_paren_stays_at_its_line_end() {
    bodies_format_to(&[
        (
            "f =\n    (a + b) -- c\n\n\ng =\n    1\n",
            "f =\n    a + b -- c\n\n\ng =\n    1\n",
        ),
        (
            "f x =\n    case x of\n        A ->\n            (h y) -- c\n\n        B ->\n            2\n",
            "f x =\n    case x of\n        A ->\n            h y -- c\n\n        B ->\n            2\n",
        ),
        (
            "f =\n    [ (x) -- c\n    , y\n    ]\n",
            "f =\n    [ x -- c\n    , y\n    ]\n",
        ),
        (
            "f =\n    let\n        v =\n            (a + b) -- c\n    in\n    v\n",
            "f =\n    let\n        v =\n            a + b -- c\n    in\n    v\n",
        ),
        ("f =\n    g ([ 1, 2 ]) -- c\n", "f =\n    g [ 1, 2 ] -- c\n"),
    ]);
}

/// A comment above the `)` of a group around a list or a record update leads
/// the group: it prints once, above it, never again inside the brackets.
#[test]
fn a_comment_above_a_group_close_prints_once() {
    bodies_format_to(&[
        (
            "f =\n    g ([ 1, 2 ]\n    -- c\n    ) y\n",
            "f =\n    g\n        -- c\n        [ 1, 2 ]\n        y\n",
        ),
        (
            "f =\n    g ({ r | a = 1 }\n    -- c\n    ) y\n",
            "f =\n    g\n        -- c\n        { r | a = 1 }\n        y\n",
        ),
        (
            "f =\n    ([ 1, 2 ]\n    -- c\n    )\n",
            "f =\n    -- c\n    [ 1, 2 ]\n",
        ),
        (
            "f =\n    g ([ 1, 2 ] -- c\n    ) y\n",
            "f =\n    g\n        -- c\n        [ 1, 2 ]\n        y\n",
        ),
    ]);
}

/// A comment where the layout keeps the next code on the same line (after a
/// foreign declaration's type, a `<|` operand or a lambda parameter) prints
/// on its own line above that code.
#[test]
fn same_line_positions_demote_their_comment() {
    formats_to(
        "module M exposing (now)\n\n\nforeign now : Int -- c\n    = \"now\"\n",
        "module M exposing (now)\n\n\nforeign now : Int =\n    -- c\n    \"now\"\n",
    );
    bodies_format_to(&[
        (
            "f x =\n    g <| x -- c\n        <| y\n",
            "f x =\n    g <|\n        x <|\n        -- c\n        y\n",
        ),
        (
            "f =\n    \\x -- c\n        y -> x\n",
            "f =\n    -- c\n    \\x y ->\n        x\n",
        ),
    ]);
}
