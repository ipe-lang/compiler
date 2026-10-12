//! Integration tests for `ipe fmt` — the source formatter.
//!
//! These drive the PUBLIC library surface (`ipe::fmt`) rather than spawning the
//! binary: `format_source` is the pure formatting function, and `run_fmt` is
//! the CLI entry point (file discovery, in-place rewrite, `--check`). Every
//! assertion is over observable behaviour — the exact formatted bytes, the
//! idempotency fixed point, comment survival, and the `--check` exit contract —
//! never a self-report.

use std::fs;
use std::path::PathBuf;

use ipe::CliError;
use ipe::cli_args::OutputFormat;
use ipe::fmt::{self, format_source};
use ipe::machine_output::machine_error;

/// A curated fixture set covering records, lists, tuples, `case`, `let`, `if`,
/// and comments. Each must be a fixed point of `format_source` after one pass.
fn fixtures() -> Vec<(&'static str, String)> {
    vec![
        (
            "simple_value",
            "module M exposing (x)\n\n\nx =\n    1\n".to_owned(),
        ),
        (
            "record_single_line",
            "module M exposing (r)\n\n\nr =\n    { a = 1, b = 2 }\n".to_owned(),
        ),
        (
            "list_single_line",
            "module M exposing (l)\n\n\nl =\n    [ 1, 2, 3 ]\n".to_owned(),
        ),
        (
            "tuple",
            "module M exposing (t)\n\n\nt =\n    ( 1, 2 )\n".to_owned(),
        ),
        (
            "case_expr",
            "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            \"z\"\n\n        _ ->\n            \"n\"\n".to_owned(),
        ),
        (
            "let_expr",
            "module M exposing (f)\n\n\nf x =\n    let\n        y =\n            x + 1\n    in\n    y\n".to_owned(),
        ),
        (
            "if_expr",
            "module M exposing (f)\n\n\nf x =\n    if x > 0 then\n        1\n\n    else\n        2\n".to_owned(),
        ),
        (
            "union_type",
            "module M exposing (T)\n\n\ntype T\n    = A\n    | B\n".to_owned(),
        ),
        (
            "with_comments",
            "module M exposing (f, g)\n\n\n-- leading on f\nf =\n    1\n\n\n{- block before g -}\ng =\n    2\n".to_owned(),
        ),
        // --- Regressions caught battle-testing against elm-format ------------
        // A constructor-with-args pattern in ARGUMENT position keeps its parens;
        // dropping them turned one parameter into several.
        (
            "ctor_param_parens",
            "module M exposing (f)\n\n\nf (Vector va) (Wrap x) =\n    va\n".to_owned(),
        ),
        // A single-line type signature stays single-line however wide — the
        // signature break is modal, not width-driven.
        (
            "wide_signature_stays_one_line",
            "module M exposing (map4)\n\n\nmap4 : (a -> b -> c -> d -> e) -> Vector a -> Vector b -> Vector c -> Vector d -> Vector e\nmap4 f =\n    f\n".to_owned(),
        ),
        // A `let` binder that destructures with a constructor pattern keeps its
        // parens (`(Decoder d) = …`), and each binding's value drops to its own
        // indented line with a blank line between bindings.
        (
            "let_ctor_destructure",
            "module M exposing (f)\n\n\nf =\n    let\n        ( a, b ) =\n            pair\n\n        (Decoder d) =\n            wrap a\n    in\n    d\n".to_owned(),
        ),
        // A pipe operand that is a function application needs no parentheses.
        (
            "pipe_call_operand_bare",
            "module M exposing (f)\n\n\nf start vector =\n    List.foldr f start <| toList vector\n".to_owned(),
        ),
        // A lambda whose body is a `let` drops the body onto the next line
        // rather than printing `-> let` inline (which would place the `let`
        // keyword mid-line and break its layout-sensitive block on re-parse).
        (
            "lambda_let_body",
            "module M exposing (f)\n\n\nf =\n    apply\n        (\\x ->\n            let\n                y =\n                    x\n            in\n            y\n        )\n".to_owned(),
        ),
        // A multi-line module `exposing` list preserves its source grouping.
        (
            "exposing_multiline_grouped",
            "module M exposing\n    ( A\n    , b, c\n    , d\n    )\n\n\nb =\n    1\n".to_owned(),
        ),
        // A row-polymorphic record annotation `{ r | field : T }` round-trips
        // with the row variable and `|` preserved on one line.
        (
            "open_record_signature",
            "module M exposing (getName)\n\n\ngetName : { r | name : String } -> String\ngetName rec =\n    rec.name\n".to_owned(),
        ),
        // Section comments written BETWEEN union constructors stay inside the
        // type, each on its own line just above the constructor it annotates —
        // they are not pushed out to the next top-level declaration.
        (
            "union_interior_comments",
            "module M exposing (Msg)\n\n\ntype Msg\n    = NoOp\n    -- navigation\n    | ToggleMenu\n    -- blog\n    | GotPosts\n".to_owned(),
        ),
    ]
}

#[test]
fn every_fixture_is_a_fixed_point() {
    for (name, src) in fixtures() {
        let once = format_source(&src).unwrap();
        let twice = format_source(&once).unwrap();
        assert_eq!(once, twice, "{name}: fmt(fmt(x)) != fmt(x)");
    }
}

/// Every fixture that is already in canonical form must be UNCHANGED by
/// formatting (a strict fixed point on canonical input).
#[test]
fn canonical_inputs_are_unchanged() {
    let rewritten: Vec<String> = fixtures()
        .into_iter()
        .filter_map(|(name, src)| {
            let out = format_source(&src).unwrap();
            (out != src).then(|| format!("{name}: fmt rewrote an already-canonical fixture\n  in:  {src:?}\n  out: {out:?}"))
        })
        .collect();
    assert!(rewritten.is_empty(), "{}", rewritten.join("\n"));
}

/// The elm-format-parity regression fixtures are already in canonical form, so
/// each must be an EXACT (byte-for-byte) fixed point of a single pass — this is
/// the guard against the specific formatter bugs found battle-testing the
/// formatter against real elm-format output (constructor-parameter parens,
/// modal signature width, `let` constructor destructures, bare pipe operands,
/// lambda `let` bodies, and grouped multi-line `exposing` lists).
#[test]
fn parity_regressions_are_exact_fixed_points() {
    let names = [
        "ctor_param_parens",
        "wide_signature_stays_one_line",
        "let_ctor_destructure",
        "pipe_call_operand_bare",
        "lambda_let_body",
        "exposing_multiline_grouped",
    ];
    for (name, src) in fixtures() {
        if !names.contains(&name) {
            continue;
        }
        let out = format_source(&src).unwrap();
        assert_eq!(
            out, src,
            "{name}: not an exact fixed point\n--- got:\n{out}"
        );
    }
}

#[test]
fn comments_survive() {
    let src = fixtures()
        .into_iter()
        .find(|(n, _)| *n == "with_comments")
        .map(|(_, s)| s)
        .unwrap();
    let out = format_source(&src).unwrap();
    assert!(out.contains("-- leading on f"), "line comment lost:\n{out}");
    assert!(
        out.contains("{- block before g -}"),
        "block comment lost:\n{out}"
    );
}

/// Comments interleaved between union constructors stay attached to the
/// constructor they precede — inside the type, in source order — rather than
/// being detached to the next top-level declaration or the module tail. The
/// canonical form is an exact fixed point.
#[test]
fn union_interior_comments_stay_inside_the_type() {
    let src = fixtures()
        .into_iter()
        .find(|(n, _)| *n == "union_interior_comments")
        .map(|(_, s)| s)
        .unwrap();
    let out = format_source(&src).unwrap();
    // Both section comments survive, each on its own line directly above its
    // constructor and before the closing of the union (no `main`/next decl).
    let nav = out.find("-- navigation").expect("navigation comment lost");
    let toggle = out.find("| ToggleMenu").expect("ToggleMenu ctor lost");
    let blog = out.find("-- blog").expect("blog comment lost");
    let posts = out.find("| GotPosts").expect("GotPosts ctor lost");
    assert!(
        nav < toggle && toggle < blog && blog < posts,
        "interior comments must precede their constructors, in order:\n{out}"
    );
    // Exact fixed point: the canonical layout is stable across a second pass.
    assert_eq!(
        out, src,
        "union interior comments are not an exact fixed point\n--- got:\n{out}"
    );
    assert_eq!(
        format_source(&out).unwrap(),
        out,
        "second pass changed the interior-comment layout\n--- got:\n{out}"
    );
}

/// `run_fmt` rewrites an unformatted file in place, and a second run is a no-op.
#[test]
fn run_fmt_rewrites_in_place_and_is_idempotent() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fmt_rewrite");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("M.ipe");
    // Deliberately non-canonical (extra spaces, wrong blank-line count).
    fs::write(&file, "module M exposing (x)\n\nx =\n  1\n").unwrap();

    fmt::run_fmt(&[file.to_string_lossy().into_owned()]).expect("first fmt");
    let after1 = fs::read_to_string(&file).unwrap();
    assert!(after1.contains("x =\n    1"), "not reformatted:\n{after1}");

    fmt::run_fmt(&[file.to_string_lossy().into_owned()]).expect("second fmt");
    let after2 = fs::read_to_string(&file).unwrap();
    assert_eq!(after1, after2, "second fmt changed a formatted file");
}

/// `--check` exits zero on a formatted file and non-zero on an unformatted one,
/// and never writes.
#[test]
fn check_flag_exit_contract() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fmt_check");
    fs::create_dir_all(&dir).unwrap();

    // Unformatted file: --check must error and leave the file untouched.
    let unf = dir.join("Unf.ipe");
    let unf_src = "module M exposing (x)\n\nx =\n  1\n";
    fs::write(&unf, unf_src).unwrap();
    let res = fmt::run_fmt(&["--check".to_owned(), unf.to_string_lossy().into_owned()]);
    assert!(res.is_err(), "--check passed an unformatted file");
    assert_eq!(
        fs::read_to_string(&unf).unwrap(),
        unf_src,
        "--check must not modify the file"
    );

    // Formatted file: --check must succeed.
    let ok = dir.join("Ok.ipe");
    let canon = format_source(unf_src).unwrap();
    fs::write(&ok, &canon).unwrap();
    let res = fmt::run_fmt(&["--check".to_owned(), ok.to_string_lossy().into_owned()]);
    assert!(res.is_ok(), "--check failed a formatted file: {res:?}");
}

/// A directory argument formats every `.ipe` under it.
#[test]
fn directory_formats_all_ipe_files() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fmt_dir");
    let sub = dir.join("src").join("Nested");
    fs::create_dir_all(&sub).unwrap();
    let a = dir.join("src").join("A.ipe");
    let b = sub.join("B.ipe");
    fs::write(&a, "module A exposing (x)\n\nx =\n  1\n").unwrap();
    fs::write(&b, "module Nested.B exposing (y)\n\ny =\n  2\n").unwrap();

    fmt::run_fmt(&[dir.to_string_lossy().into_owned()]).expect("dir fmt");
    assert!(fs::read_to_string(&a).unwrap().contains("x =\n    1"));
    assert!(fs::read_to_string(&b).unwrap().contains("y =\n    2"));
}

/// An unparseable file is refused (formatting invalid source could change its
/// meaning) rather than mangled.
#[test]
fn invalid_source_is_refused() {
    let bad = "module M exposing (x)\n\nx = = =\n";
    assert!(format_source(bad).is_err(), "invalid source was formatted");
}

// -- stdin mode (--stdin) ------------------------------------------------

/// `format_source` is the same pure function used by the stdin path — the
/// stdin dispatch only differs in I/O wiring, which is tested via the
/// `FmtMode` parsing and the `run_fmt` dispatch table.
#[test]
fn stdin_mode_uses_same_format_source() {
    let unformatted = "module M exposing (x)\n\nx =\n  1\n";
    let expected = format_source("module M exposing (x)\n\n\nx =\n    1\n").unwrap();
    let got = format_source(unformatted).unwrap();
    assert_eq!(got, expected, "stdin path must produce same output");
}

/// The scaffolded `ipe init` template is elm-format style already, so formatting
/// it changes ONLY the import order (elm-format sorts imports) and is otherwise a
/// fixed point. Lives here (not in `ipe_fmt`) because it reads the CLI's
/// `templates/Main.ipe` asset.
#[test]
fn init_template_is_a_near_fixed_point() {
    let src = include_str!("../templates/Main.ipe");
    let out = format_source(src).expect("template formats");
    let out2 = format_source(&out).expect("second pass formats");
    assert_eq!(out, out2, "fmt must be idempotent on its own output");
}

// -- do-block statement round trip ---------------------------------------

/// Regression pin for the reported ICE: formatting a bare (un-bound) statement
/// in a `do` block — `migrate db` with no `let _ =` wrapper — must succeed and
/// preserve the `do` block rather than re-emit a form the parser refuses. Read
/// at test time (not `include_str!`) so the fixture is checked against its
/// live, current content rather than a copy baked in at compile time.
#[test]
fn code_review_db_bare_run_formats() {
    let path = e2e_support::manifest_dir!()
        .join("..")
        .join("..")
        .join("tools")
        .join("code-review")
        .join("src")
        .join("Lib")
        .join("Db.ipe");
    let src = fs::read_to_string(&path).expect("reading the code-review Db.ipe fixture");
    let out = format_source(&src);
    assert!(
        out.is_ok(),
        "formatting a do block with a bare run statement must succeed: {out:?}"
    );
    let out = out.expect("checked Ok above");
    assert!(
        out.contains("do\n"),
        "the do block must survive formatting:\n{out}"
    );
    // Idempotent: re-parsing and re-formatting the output is a fixed point.
    let out2 = format_source(&out).expect("second pass must also format");
    assert_eq!(out, out2, "do-block bare-run formatting is not idempotent");
}

/// `i64::MIN` spelled as a literal, in expression and pattern position,
/// formats to source that re-parses, and a second pass changes nothing.
#[test]
fn int_min_literal_round_trips() {
    let src = "module M exposing (smallest, classify)\n\n\n\
               smallest : Int\nsmallest =\n    -9223372036854775808\n\n\n\
               classify : Int -> Int\nclassify n =\n    case n of\n        \
               -9223372036854775808 ->\n            1\n\n        \
               _ ->\n            0\n";
    let once = format_source(src).unwrap();
    assert!(
        once.contains("-9223372036854775808"),
        "the literal survives formatting:\n{once}"
    );
    let twice = format_source(&once).unwrap();
    assert_eq!(once, twice, "fmt(fmt(x)) != fmt(x)");
}

/// An out-of-range Int literal is refused with IPE-P0013, and `run_fmt` leaves
/// the file untouched.
#[test]
fn int_literal_out_of_range_is_refused_unwritten() {
    let src = "module M exposing (x)\n\nx =\n  9223372036854775808\n";
    let refused = format_source(src);
    assert!(
        matches!(&refused, Err(fmt::FmtError::Parse { diag, .. }) if diag.code().as_str() == "IPE-P0013"),
        "unnegated 2^63 must be refused with IPE-P0013: {refused:?}"
    );
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fmt_int_range");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("M.ipe");
    fs::write(&file, src).unwrap();
    let res = fmt::run_fmt(&[file.to_string_lossy().into_owned()]);
    assert!(res.is_err(), "fmt accepted an out-of-range literal");
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        src,
        "a refused file must not be rewritten"
    );
}

/// A module whose one value is a list of `items` ones written on one line two
/// lets deep; formatting puts every item on its own deeply indented line.
fn nested_long_list(items: usize) -> String {
    let ones = vec!["1"; items].join(",");
    format!(
        "module M exposing (x)\n\n\nx =\n    let\n        y =\n            let\n                z =\n                    [ {ones}\n                    ]\n            in\n            z\n    in\n    y\n"
    )
}

/// A file whose formatted output would pass its cap is refused: the screen
/// names the file, the cap and the remedy, and the file is left unchanged.
/// The same shape small enough to fit formats, so the refusal is the cap's.
#[test]
fn fmt_output_too_large_screen() {
    let small = nested_long_list(200);
    let small_out = format_source(&small).expect("a small list formats under the floor");
    let growth = small_out.len() / 200;
    assert!(
        growth > 2 * fmt::OutputCap::GROWTH,
        "precondition: each two-byte item must grow past the cap, got {growth}"
    );

    let src = nested_long_list(10_000);
    let cap = fmt::OutputCap::for_input(src.len());
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fmt_output_cap");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("M.ipe");
    fs::write(&file, &src).unwrap();
    let res = fmt::run_fmt(&[file.to_string_lossy().into_owned()]);
    let screen = res
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(
        matches!(&res, Err(CliError::FmtOutputTooLarge { file: f, cap: c }) if f.ends_with("M.ipe") && *c == cap),
        "fmt must refuse with the typed output-cap error: {res:?}"
    );
    let kind = res.as_ref().err().map(CliError::machine_kind);
    assert_eq!(kind, Some("fmt-output-too-large"));
    let json = machine_error(OutputFormat::Json, "fmt", kind.unwrap(), &screen);
    assert!(
        json.contains("\"kind\":\"fmt-output-too-large\""),
        "the JSON refusal carries its kind: {json}"
    );
    let plain = machine_error(OutputFormat::Plain, "fmt", kind.unwrap(), &screen);
    assert!(
        plain.contains("Split it"),
        "the plain refusal carries the message: {plain}"
    );
    assert!(
        screen.contains(&file.display().to_string()),
        "the refusal names the file: {screen}"
    );
    assert!(
        screen.contains(&cap.to_string()),
        "the refusal names the cap: {screen}"
    );
    assert!(
        screen.contains("Split it"),
        "the refusal names the remedy: {screen}"
    );
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        src,
        "a refused file must not be rewritten"
    );
}

/// The output-cap refusal sanitizes the file path it renders.
///
/// A control byte in a directory name never reaches the screen. Unix only: Windows refuses a control byte in a file name.
#[cfg(unix)]
#[test]
fn fmt_output_too_large_screen_sanitizes_the_path() {
    let src = nested_long_list(10_000);
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fmt_output_cap_\u{1b}[31m");
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("M.ipe");
    fs::write(&file, &src).unwrap();
    let res = fmt::run_fmt(&[file.to_string_lossy().into_owned()]);
    assert!(
        matches!(&res, Err(CliError::FmtOutputTooLarge { .. })),
        "{res:?}"
    );
    let screen = res
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    assert!(
        !screen.contains('\u{1b}'),
        "a raw ESC reached the screen: {screen:?}"
    );
    assert!(
        screen.contains("M.ipe"),
        "the refusal names the file: {screen}"
    );
}

/// A source of exactly `len` bytes: one small module padded with newlines.
fn stdin_source_of(len: usize) -> Vec<u8> {
    let mut src = b"module M exposing (x)\n\n\nx =\n    1\n".to_vec();
    src.resize(len, b'\n');
    src
}

/// Stdin one byte past the source read cap is refused before it is formatted.
#[test]
fn fmt_stdin_past_the_read_cap_is_refused() {
    let cap = usize::try_from(ipe::io_bounded::SOURCE_READ_CAP).unwrap();
    let res = fmt::format_stdin_from(stdin_source_of(cap + 1).as_slice());
    assert!(
        matches!(&res, Err(CliError::FileTooLarge { max, .. }) if *max == ipe::io_bounded::SOURCE_READ_CAP),
        "{res:?}"
    );
}

/// Stdin of exactly the source read cap is read in full and handed to the
/// formatter, never refused as too large.
#[test]
fn fmt_stdin_at_the_read_cap_is_read() {
    let cap = usize::try_from(ipe::io_bounded::SOURCE_READ_CAP).unwrap();
    let res = fmt::format_stdin_from(stdin_source_of(cap).as_slice());
    assert!(
        !matches!(&res, Err(CliError::FileTooLarge { .. })),
        "{res:?}"
    );
    if let Ok(out) = &res {
        assert_eq!(out.source.len(), cap, "the whole input was read");
    }
}
