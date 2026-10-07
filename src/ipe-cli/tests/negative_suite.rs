//! Systematic negative-test suite: malformed Ipê programs that MUST be
//! rejected by `ipe` (a typed `Err(Diagnostic)`, never exit-0) and must never
//! emit Rust. This guards the CONTRAPOSITIVE of THE SEAL — a malformed program
//! rejected at parse/canon/type/effect/lower time can never reach emission and
//! ship broken Rust.
//!
//! Each test pins the SPECIFIC expected `IPE-####` code, so a wrong-reason
//! rejection is caught, not silently passed. One malformed case per language
//! feature, walking the taxonomy (`ipe_diagnostics::code`) as the coverage map:
//! parse (`IPE-P*`), name resolution / canon (`IPE-N*`), type (`IPE-T*`),
//! lowering / not-yet-supported (`IPE-L*`), plus the target/secret gates.
//!
//! Compile-only: every fixture is ill-formed, so there is nothing to run — no
//! oracle / `IPE_E2E` gate. Each test fails loudly (never skips) when the
//! embedded runtime or scratch dir is unavailable (the pipeline needs the
//! compiled stdlib source).

mod support;

use std::fmt::Write as _;
use std::path::PathBuf;

use ipe::{BuildOptions, CliError};
use ipe_ir::Target;

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(), …)`
/// reads as a deliberate unconditional failure rather than a suspicious
/// constant condition — mirrors the compiler crates' own test helper, and keeps
/// this file free of the `clippy::panic` deny (no bare `panic!`).
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// Write `source` as a single-file `Main.ipe` under a fresh scratch dir keyed
/// by `name`, returning the entry path (a failed scratch setup fails the
/// test). The scratch dir lives in the test
/// crate's `CARGO_TARGET_TMPDIR`, never the repo tree.
#[allow(clippy::expect_used)] // a failed scratch setup is the test failure
fn write_entry(name: &str, source: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("negsuite")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch setup must succeed");
    let entry = dir.join("Main.ipe");
    std::fs::write(&entry, source).expect("scratch setup must succeed");
    entry
}

/// The outcome of running the pipeline over a fixture.
#[derive(Debug)]
enum Outcome {
    /// Compilation was rejected — the pipeline diagnostic's wire code
    /// (e.g. `"IPE-N0028"`). The wire string is compared so codes not
    /// re-exported from the diagnostics crate root can still be pinned.
    Rejected(&'static str),
    /// Compilation SUCCEEDED (a potential SEAL hole for a malformed input) or
    /// failed for a non-pipeline reason (I/O, usage). Carries a description.
    Accepted(String),
}

fn compile(name: &str, source: &str, target: Target) -> Outcome {
    let entry = write_entry(name, source);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("negsuite-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let options = BuildOptions {
        target,
        intent: ipe_backend_rust::BuildIntent::Development,
        ..BuildOptions::default()
    };
    match ipe::build_with_options(&entry, &out, &runtime, options) {
        Ok(()) => Outcome::Accepted("compiled successfully (exit 0)".to_owned()),
        Err(CliError::Pipeline { diag, .. }) => Outcome::Rejected(diag.code().as_str()),
        Err(other) => Outcome::Accepted(format!("non-pipeline error: {other:?}")),
    }
}

/// Like [`compile`] but with the production flag set — simulates `ipe release`
/// so the `Debug.*` gate (IPE-L0140) fires without spawning a real release build.
fn compile_production(name: &str, source: &str) -> Outcome {
    let entry = write_entry(name, source);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("negsuite-prod-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let options = BuildOptions {
        intent: ipe_backend_rust::BuildIntent::Release,
        ..BuildOptions::default()
    };
    match ipe::build_with_options(&entry, &out, &runtime, options) {
        Ok(()) => Outcome::Accepted("compiled successfully (exit 0)".to_owned()),
        Err(CliError::Pipeline { diag, .. }) => Outcome::Rejected(diag.code().as_str()),
        Err(other) => Outcome::Accepted(format!("non-pipeline error: {other:?}")),
    }
}

/// Assert that `source`, compiled with the production flag, is rejected with
/// exactly `expected`. A wrong code, an accept (a SEAL hole), or a non-pipeline
/// failure fails the test.
#[track_caller]
fn assert_rejected_production(name: &str, source: &str, expected: &str) {
    match compile_production(name, source) {
        Outcome::Rejected(got) => assert_eq!(
            got, expected,
            "{name}: expected {expected}, got {got} — rejected for the WRONG reason"
        ),
        Outcome::Accepted(how) => fail_accepted(name, expected, &how),
    }
}

/// Run the full `ipe` pipeline over a multi-file project (sibling discovery):
/// `files` are written under a fresh `src/` keyed by `name`, and `Main.ipe` is
/// the entry. Needed for cross-module gates (e.g. duplicate import qualifier)
/// that the single-file path cannot observe.
fn compile_project(name: &str, files: &[(&str, &str)]) -> Outcome {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("negsuite-proj")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    crate::support::expect_scratch_step(name, std::fs::create_dir_all(&src));
    for (fname, contents) in files {
        crate::support::expect_scratch_step(name, std::fs::write(src.join(fname), contents));
    }
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("negsuite-proj-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let entry = src.join("Main.ipe");
    match ipe::build_loose_file(&entry, &out, &runtime) {
        Ok(()) => Outcome::Accepted("compiled successfully (exit 0)".to_owned()),
        Err(CliError::Pipeline { diag, .. }) => Outcome::Rejected(diag.code().as_str()),
        Err(other) => Outcome::Accepted(format!("non-pipeline error: {other:?}")),
    }
}

/// Fail the current test: the malformed program was ACCEPTED when `expected`
/// was the intended rejection — a potential SEAL hole. Uses [`false_marker`] so
/// no bare `panic!` is needed (clippy deny-set).
#[track_caller]
fn fail_accepted(name: &str, expected: &str, how: &str) {
    assert!(
        false_marker(),
        "{name}: expected rejection with {expected}, but ipe ACCEPTED the malformed program \
         ({how}) — a potential SEAL hole"
    );
}

/// Assert that `source`, compiled for `target`, is rejected by `ipe` with
/// exactly the wire code `expected`. A wrong code, an accept (a SEAL hole), or
/// a non-pipeline failure fails the test naming what happened.
#[track_caller]
fn assert_rejected_on(name: &str, source: &str, expected: &str, target: Target) {
    match compile(name, source, target) {
        Outcome::Rejected(got) => assert_eq!(
            got, expected,
            "{name}: expected {expected}, got {got} — a rejection for the WRONG reason"
        ),
        Outcome::Accepted(how) => fail_accepted(name, expected, &how),
    }
}

/// [`assert_rejected_on`] on the native target.
#[track_caller]
fn assert_rejected(name: &str, source: &str, expected: &str) {
    assert_rejected_on(name, source, expected, Target::Native);
}

/// [`assert_rejected_on`] under `--target wasm` (the wasm capability gate is
/// target-keyed).
#[track_caller]
fn assert_rejected_wasm(name: &str, source: &str, expected: &str) {
    assert_rejected_on(name, source, expected, Target::WasmClient);
}

/// Assert that `source` compiles cleanly (the CONTRAPOSITIVE of a rejection):
/// a well-formed program the pipeline must accept. Used to prove that a
/// tightened surface still admits its legitimate replacement.
#[track_caller]
fn assert_compiles(name: &str, source: &str) {
    match compile(name, source, Target::Native) {
        Outcome::Accepted(how) if how.starts_with("compiled successfully") => {}
        Outcome::Accepted(how) => assert!(
            false_marker(),
            "{name}: expected a clean compile, got a non-pipeline failure ({how})"
        ),
        Outcome::Rejected(got) => assert!(
            false_marker(),
            "{name}: expected a clean compile, but ipe REJECTED it with {got}"
        ),
    }
}

// A minimal well-formed prelude preamble reused across fixtures.
const HEAD: &str = "module Main exposing (main)\n";

// ===========================================================================
// Parse — IPE-P####
// ===========================================================================

/// A `case` with no arms cannot parse — malformed case expression.
#[test]
fn parse_malformed_case_no_arms() {
    let src = format!("{HEAD}main =\n    case 1 of\n");
    assert_rejected("parse_case_no_arms", &src, "IPE-P0060");
}

/// A `let` with no `in` cannot parse — malformed let expression.
#[test]
fn parse_malformed_let_no_in() {
    let src = format!("{HEAD}main =\n    let x = 1\n    x\n");
    assert_rejected("parse_let_no_in", &src, "IPE-P0061");
}

/// An `if` missing its `then`/`else` cannot parse — malformed if expression.
#[test]
fn parse_malformed_if() {
    let src = format!("{HEAD}main =\n    if True\n");
    assert_rejected("parse_if_incomplete", &src, "IPE-P0062");
}

/// An unterminated string literal is a lex error.
#[test]
fn parse_unterminated_string() {
    let src = format!("{HEAD}main =\n    \"unterminated\n");
    assert_rejected("parse_unterminated_string", &src, "IPE-P0014");
}

/// A definition missing its `=` cannot parse.
#[test]
fn parse_missing_equals() {
    let src = format!("{HEAD}main\n    1\n");
    assert_rejected("parse_missing_equals", &src, "IPE-P0030");
}

/// A malformed module header (garbage where `exposing` belongs).
#[test]
fn parse_malformed_module_header() {
    let src = "module Main whoops (main)\nmain = 1\n";
    assert_rejected("parse_module_header", src, "IPE-P0020");
}

/// An unclosed delimiter (open paren, never closed).
#[test]
fn parse_unclosed_delimiter() {
    let src = format!("{HEAD}main =\n    (1 + 2\n");
    assert_rejected("parse_unclosed_delim", &src, "IPE-P0050");
}

/// A malformed type declaration (`type` with no `=` body).
#[test]
fn parse_malformed_type_decl() {
    let src = format!("{HEAD}type Foo\nmain = 1\n");
    assert_rejected("parse_type_decl", &src, "IPE-P0031");
}

/// An unknown character in source (a raw control/garbage byte the lexer cannot
/// classify) — lexical rejection.
#[test]
fn parse_unknown_character() {
    let src = format!("{HEAD}main =\n    1 \u{0007} 2\n");
    assert_rejected("parse_unknown_char", &src, "IPE-P0010");
}

/// A malformed character literal (empty `''`).
#[test]
fn parse_malformed_char_literal() {
    let src = format!("{HEAD}main =\n    ''\n");
    assert_rejected("parse_malformed_char", &src, "IPE-P0015");
}

/// A stray `.` where a name/expression belongs.
#[test]
fn parse_stray_dot() {
    let src = format!("{HEAD}main =\n    . 1\n");
    assert_rejected("parse_stray_dot", &src, "IPE-P0011");
}

/// A number joined directly to a name (`1abc`) is a lex error, not a valid
/// identifier or literal.
#[test]
fn parse_number_joined_to_name() {
    let src = format!("{HEAD}main =\n    1abc\n");
    assert_rejected("parse_num_name", &src, "IPE-P0012");
}

/// An integer literal beyond the 64-bit range.
#[test]
fn parse_integer_out_of_range() {
    let src = format!("{HEAD}main =\n    99999999999999999999999999999999\n");
    assert_rejected("parse_int_range", &src, "IPE-P0013");
}

/// An unterminated block comment (`{-` never closed).
#[test]
fn parse_unterminated_block_comment() {
    let src = format!("{HEAD}main =\n    1\n{{- never closed\n");
    assert_rejected("parse_block_comment", &src, "IPE-P0017");
}

/// A malformed exposing list (a trailing comma with no name).
#[test]
fn parse_malformed_exposing_list() {
    let src = "module Main exposing (main,\nmain = 1\n";
    assert_rejected("parse_exposing", src, "IPE-P0021");
}

/// Source that ends before an expression is complete — unexpected EOF.
#[test]
fn parse_unexpected_eof() {
    let src = format!("{HEAD}main =\n    1 +");
    assert_rejected("parse_unexpected_eof", &src, "IPE-P0002");
}

/// In a type, only a type constructor may take arguments — a lowercase type var
/// cannot be applied to args.
#[test]
fn parse_only_ctor_takes_args() {
    let src = format!("{HEAD}main : a Int\nmain =\n    1\n");
    assert_rejected("parse_only_ctor_args", &src, "IPE-P0040");
}

/// A type annotation whose right-hand side is not a type at all.
#[test]
fn parse_expected_a_type() {
    let src = format!("{HEAD}main : 123\nmain =\n    1\n");
    assert_rejected("parse_expected_type", &src, "IPE-P0041");
}

// ===========================================================================
// Name resolution / canonicalisation — IPE-N####
// ===========================================================================

/// A bare name that is not bound anywhere in scope.
#[test]
fn canon_unbound_value() {
    let src = format!("{HEAD}main =\n    unboundName\n");
    assert_rejected("canon_unbound_value", &src, "IPE-N0001");
}

/// A type annotation referencing a type that does not exist.
#[test]
fn canon_unknown_type() {
    let src = format!("{HEAD}main : NoSuchType\nmain =\n    1\n");
    assert_rejected("canon_unknown_type", &src, "IPE-N0002");
}

/// A pattern naming a constructor that is not defined.
#[test]
fn canon_unknown_constructor() {
    let src = format!("{HEAD}type Msg = A\nmain =\n    case A of\n        Nonexistent -> 1\n");
    assert_rejected("canon_unknown_ctor", &src, "IPE-N0003");
}

/// A reference through a qualifier bound to a module that does not exist. The
/// An `import Ipe.NoSuchModule` names no kernel stdlib module and no compiled-source
/// dep — the import itself is rejected with IPE-N0020 (`ModuleNotFound`) at the import
/// boundary. The qualified reference `X.foo` never reaches name resolution.
#[test]
fn canon_unknown_module() {
    let src = "module Main exposing (main)\n\
               import Ipe.NoSuchModule as X\n\
               main = X.foo\n";
    assert_rejected("canon_unknown_module", src, "IPE-N0020");
}

/// Importing a member a real module does not expose.
#[test]
fn canon_member_not_exposed() {
    let src = "module Main exposing (main)\n\
               import Ipe.String exposing (thisFunctionDoesNotExist)\n\
               main = 1\n";
    assert_rejected("canon_member_not_exposed", src, "IPE-N0022");
}

/// SECURITY: the un-escaped raw-String→HTML surface `Html.raw` is REMOVED — its
/// only spelling is now the explicitly-marked `unsafeRaw` in the dedicated
/// `Ipe.Html.Unsafe` escape-hatch submodule, so a raw injection can never be
/// written under a name that looks safe. The old name no longer resolves.
#[test]
fn security_html_raw_unmarked_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Html as Html\n\
               main = Html.raw \"<b>x</b>\"\n";
    assert_rejected("security_html_raw_unmarked", src, "IPE-N0005");
}

/// SECURITY: `unsafeRaw` no longer lives on the plain `Ipe.Html` surface — it
/// relocated to `Ipe.Html.Unsafe`. A program that imports only `Ipe.Html` and
/// reaches for `Html.unsafeRaw` must be rejected, so the escape hatch cannot be
/// used without the disclosing `Ipe.Html.Unsafe` import.
#[test]
fn security_html_unsafe_raw_off_plain_html_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Html as Html\n\
               main = Html.unsafeRaw \"<b>x</b>\"\n";
    assert_rejected("security_html_unsafe_raw_off_plain", src, "IPE-N0005");
}

/// SECURITY (contrapositive): the marked replacement, now homed in
/// `Ipe.Html.Unsafe`, still compiles — the raw capability is preserved, only
/// relocated to the disclosing submodule that names the risk.
#[test]
fn security_html_unsafe_raw_compiles() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Html.Unsafe exposing (unsafeRaw)\n\
               main : Task Error ()\n\
               main =\n\
               \x20   do\n\
               \x20       unsafeRaw \"<b>x</b>\"\n\
               \x20       Io.println \"ok\"\n";
    assert_compiles("security_html_unsafe_raw", src);
}

/// A11Y (prove-the-refusals): the `role` attribute is over the CLOSED `Role`
/// sum, so an invalid/misspelled role has no constructor to build from. A
/// program reaching for a nonexistent role variant does not resolve — the typo
/// cannot ship as a bad `role="…"` string.
#[test]
fn a11y_invalid_role_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Html.Attributes as Attr\n\
               main = Attr.role Attr.Buton\n";
    assert_rejected("a11y_invalid_role", src, "IPE-N0005");
}

/// A11Y (prove-the-refusals): enumerated aria values (`aria-live`, …) are over
/// closed sums, so an out-of-vocabulary value is unrepresentable. A nonexistent
/// `AriaLive` variant does not resolve.
#[test]
fn a11y_invalid_aria_live_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Html.Attributes as Attr\n\
               main = Attr.ariaLive Attr.LiveShouty\n";
    assert_rejected("a11y_invalid_aria_live", src, "IPE-N0005");
}

/// A11Y (contrapositive): the typed role / aria helpers compile — the floor is
/// a real boundary, not a wall that also blocks the valid path.
#[test]
fn a11y_typed_role_and_aria_compile() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Html exposing (div, text, render)\n\
               import Ipe.Html.Attributes as Attr\n\
               main : Task Error ()\n\
               main =\n\
               \x20   Io.println\n\
               \x20       (render\n\
               \x20           (div\n\
               \x20               [ Attr.role Attr.Navigation\n\
               \x20               , Attr.ariaLabel \"main\"\n\
               \x20               , Attr.ariaExpanded True\n\
               \x20               , Attr.ariaLive Attr.LivePolite\n\
               \x20               ]\n\
               \x20               [ text \"x\" ]))\n";
    assert_compiles("a11y_typed_role_aria", src);
}

/// SECURITY: the inline-`<script>` hatch `unsafeScript` is homed ONLY in
/// `Ipe.Html.Unsafe`, never on the plain `Ipe.Html` surface. A program that
/// imports only `Ipe.Html` and reaches for `Html.unsafeScript` must be rejected,
/// so the trusted-code injection surface cannot be used without the disclosing
/// `Ipe.Html.Unsafe` import.
#[test]
fn security_html_unsafe_script_off_plain_html_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Html as Html\n\
               main = Html.unsafeScript \"x\"\n";
    assert_rejected("security_html_unsafe_script_off_plain", src, "IPE-N0005");
}

/// SECURITY (contrapositive): `unsafeScript`, homed in `Ipe.Html.Unsafe`, still
/// compiles — the inline-`<script>` capability is preserved, reached only
/// through the disclosing submodule that names the trusted-code risk.
#[test]
fn security_html_unsafe_script_compiles() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Html.Unsafe exposing (unsafeScript)\n\
               main : Task Error ()\n\
               main =\n\
               \x20   do\n\
               \x20       unsafeScript \"console.log(1)\"\n\
               \x20       Io.println \"ok\"\n";
    assert_compiles("security_html_unsafe_script", src);
}

/// SECURITY (untouched bridge): `Ui.html` — the typed `Html msg -> Element msg`
/// bridge — is NOT a raw-string hole and stays fully working. It carries a
/// typed tree built from the escaped `Html.text` path, so tightening the raw
/// surface leaves the typed bridge intact.
#[test]
fn security_ui_html_typed_bridge_compiles() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Ui as Ui\n\
               import Ipe.Html as Html\n\
               main : Task Error ()\n\
               main =\n\
               \x20   do\n\
               \x20       Ui.html (Html.text \"hello\")\n\
               \x20       Io.println \"ok\"\n";
    assert_compiles("security_ui_html_bridge", src);
}

/// SECURITY: the raw-SQL hatch `unsafeExecRaw` no longer lives on the plain
/// `Ipe.Db` surface — it relocated to `Ipe.Db.Unsafe`. A program that imports
/// only `Ipe.Db` and reaches for `Db.unsafeExecRaw` must be rejected, so the
/// verbatim-SQL injection surface cannot be used without the disclosing
/// `Ipe.Db.Unsafe` import.
#[test]
fn security_db_unsafe_exec_raw_off_plain_db_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Db as Db\n\
               import Ipe.Task as Task\n\
               main =\n\
                   Task.andThen (\\conn -> Db.unsafeExecRaw conn \"SELECT 1\") (Db.open \"sqlite\" \"sqlite::memory:\")\n";
    assert_rejected("security_db_unsafe_exec_raw_off_plain", src, "IPE-N0005");
}

/// SECURITY: the policy-checked writes behind `Store.insertAs` / `updateAs` take
/// the check as a bare `SqlFragment`. They are `Ipe.Db.Store`-private kernel
/// aliases, so user code reaches them neither as `Db.*` off a plain `Ipe.Db`
/// import nor as `Store.*` off `Ipe.Db.Store`: a caller cannot pass its own
/// check and bypass the policy.
#[test]
fn security_store_checked_write_kernels_are_unreachable() {
    for member in ["insertFieldsChecked", "updateWhereChecked"] {
        let via_db = format!(
            "module Main exposing (main)\n\
             import Ipe.Db as Db\n\
             import Ipe.Task as Task\n\
             main =\n\
             \x20   Task.andThen (\\conn -> Db.{member} conn \"t\" []) (Db.open \"sqlite\" \"sqlite::memory:\")\n"
        );
        assert_rejected(
            &format!("security_db_{member}_unreachable"),
            &via_db,
            "IPE-N0005",
        );
    }
    for member in ["insertFieldsChecked", "updateWhereChecked", "policyCheck"] {
        let via_store = format!(
            "module Main exposing (main)\n\
             import Ipe.Db.Store as Store\n\
             main = Store.{member}\n"
        );
        assert_rejected(
            &format!("security_store_{member}_unreachable"),
            &via_store,
            "IPE-N0005",
        );
    }
}

/// SECURITY: the untyped row read `unsafeGetField` no longer lives on the plain
/// `Ipe.Db` surface — it relocated to `Ipe.Db.Unsafe`. Reaching it off a plain
/// `Ipe.Db` import must be rejected, so the decoder-bypassing read cannot be
/// used without the disclosing submodule.
#[test]
fn security_db_unsafe_get_field_off_plain_db_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Db as Db\n\
               import Ipe.Dict as Dict\n\
               main = Db.unsafeGetField \"k\" (Dict.fromList [ ( \"k\", \"v\" ) ])\n";
    assert_rejected("security_db_unsafe_get_field_off_plain", src, "IPE-N0005");
}

/// SECURITY (contrapositive): the marked replacements, homed in `Ipe.Db.Unsafe`,
/// still compile — the raw-SQL and untyped-read capabilities are preserved, only
/// relocated to the disclosing submodule that names the risk.
#[test]
fn security_db_unsafe_members_compile_off_submodule() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Db.Unsafe as Unsafe\n\
               import Ipe.Dict as Dict\n\
               main : Task Error ()\n\
               main =\n\
               \x20   do\n\
               \x20       Unsafe.unsafeGetField \"k\" (Dict.fromList [ ( \"k\", \"v\" ) ])\n\
               \x20       Io.println \"ok\"\n";
    assert_compiles("security_db_unsafe_members", src);
}

/// SECURITY: `unsafeFragment` — the un-validated anti-`Sql.column` — is homed in
/// `Ipe.Db.Unsafe`, mints a `SqlFragment` from an unchecked string, and compiles
/// there. The deliberate skip of `Sql.column`'s `valid_sql_ident` gate is the
/// disclosed hatch: it is reachable ONLY through the `.Unsafe` import.
#[test]
fn security_db_unsafe_fragment_compiles_off_submodule() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Db.Sql as Sql\n\
               import Ipe.Db.Unsafe as Unsafe\n\
               main : Task Error ()\n\
               main =\n\
               \x20   do\n\
               \x20       Sql.eq (Unsafe.unsafeFragment \"users.id\") (Sql.int 1)\n\
               \x20       Io.println \"ok\"\n";
    assert_compiles("security_db_unsafe_fragment", src);
}

/// SECURITY: `unsafeFragment` did NOT leak onto the safe `Ipe.Db.Sql` surface —
/// it is a member of `Ipe.Db.Unsafe` only. Reaching `Sql.unsafeFragment` off a
/// plain `Ipe.Db.Sql` import must be rejected, so the un-validated mint cannot
/// be used without the disclosing submodule.
#[test]
fn security_db_unsafe_fragment_off_plain_sql_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Db.Sql as Sql\n\
               main = Sql.unsafeFragment \"users.id\"\n";
    assert_rejected(
        "security_db_unsafe_fragment_off_plain_sql",
        src,
        "IPE-N0005",
    );
}

/// SECURITY (untouched safe default): `Sql.column` — the VALIDATED identifier
/// path — stays on the plain `Ipe.Db.Sql` surface and compiles unchanged. Its
/// `valid_sql_ident` gate + poison-on-invalid behaviour is the safe default the
/// `unsafeFragment` hatch deliberately skips; tightening the raw surface leaves
/// the validated builder intact. (The runtime poison behaviour is proved by
/// `ipe_runtime::db::test_poisoned_column_surfaces_as_task_err`.)
#[test]
fn security_db_sql_column_still_validates_and_compiles() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Db.Sql as Sql\n\
               main : Task Error ()\n\
               main =\n\
               \x20   do\n\
               \x20       Sql.eq (Sql.column \"users.id\") (Sql.int 1)\n\
               \x20       Io.println \"ok\"\n";
    assert_compiles("security_db_sql_column_validates", src);
}

/// Every `Db` kernel taking a SQL bind list, as `(label, imports, probe)`.
///
/// `probe` is one function calling the kernel with `@binds@` in the bind-list
/// position; `imports` are the extra imports it needs.
const DB_BIND_LIST_KERNELS: [(&str, &str, &str); 6] = [
    (
        "exec",
        "import Ipe.Db as Db\n",
        r#"probe : Db -> Task Error Int
probe conn =
    Db.exec conn "SELECT 1" @binds@
"#,
    ),
    (
        "unsafe_query",
        "import Ipe.Db as Db\nimport Ipe.Db.Unsafe as Unsafe\n",
        r#"probe : Db -> Task Error (List (Dict String String))
probe conn =
    Unsafe.unsafeQuery conn "SELECT 1" @binds@
"#,
    ),
    (
        "query_decode",
        "import Ipe.Db as Db\nimport Ipe.Db.Decode\n",
        r#"probe : Db -> Task Error (List Int)
probe conn =
    Db.queryDecode conn "SELECT 1" @binds@ (Db.Decode.int "n")
"#,
    ),
    (
        "query_decode_on",
        "import Ipe.Db.Dsn as Dsn exposing (Connection, ReadOnly)\nimport Ipe.Db as Db\nimport Ipe.Db.Decode\n",
        r#"probe : Connection ReadOnly -> Task Error (List Int)
probe conn =
    Db.queryDecodeOn conn "SELECT 1" @binds@ (Db.Decode.int "n")
"#,
    ),
    (
        "find_projection",
        "import Ipe.Db as Db\nimport Ipe.Db.Sql as Sql\n",
        r#"probe : Db -> Task Error (List (Dict String String))
probe conn =
    Db.findProjection conn "t" "a0" "u" "a1" (Sql.eq (Sql.column "a0.id") (Sql.int 1)) [] @binds@
"#,
    ),
    (
        "find_projection_ordered",
        "import Ipe.Db as Db\nimport Ipe.Db.Sql as Sql\n",
        r#"probe : Db -> Task Error (List (Dict String String))
probe conn =
    Db.findProjectionOrdered conn "t" "a0" "u" "a1" (Sql.eq (Sql.column "a0.id") (Sql.int 1)) [] @binds@ "a0" "id" True
"#,
    ),
];

/// A program holding one probe over a `Db` kernel, with `binds` as its bind list.
fn db_bind_list_program(imports: &str, probe: &str, binds: &str) -> String {
    let probe = probe.replace("@binds@", binds);
    format!(
        "{HEAD}{imports}import Ipe.Task as Task\n\n{probe}\nmain : Task Error ()\nmain =\n    Task.succeed ()\n"
    )
}

/// SOUNDNESS (SEAL): a bind list whose elements are not `SqlParam` is rejected at
/// `ipe` time for every `Db` kernel that takes one. The runtime binds a
/// `Vec<SqlParam>`, so a record or function element would otherwise pass `ipe`
/// and fail `cargo` (E0277). Each kernel's `[ SqlInt 1 ]` control compiles, so
/// the refusal comes from the element type alone.
#[test]
fn security_db_bind_list_refuses_non_sql_param_elements() {
    for (label, imports, probe) in DB_BIND_LIST_KERNELS {
        let control = db_bind_list_program(imports, probe, "[ SqlInt 1 ]");
        assert_compiles(&format!("db_bind_list_{label}_control"), &control);
        for (shape, binds) in [("record", "[ { id = 1 } ]"), ("function", r"[ \x -> x ]")] {
            let src = db_bind_list_program(imports, probe, binds);
            assert_rejected(&format!("db_bind_list_{label}_{shape}"), &src, "IPE-T0001");
        }
    }
}

/// SECURITY: the verbatim JSON-LD `<script>` hatch `unsafeJsonLd` no longer
/// lives on the plain `Ipe.Web.Head` surface — it relocated to
/// `Ipe.Web.Head.Unsafe`. A program that imports only `Ipe.Web.Head` and reaches
/// for `Head.unsafeJsonLd` must be rejected, so the raw-script injection surface
/// cannot be used without the disclosing `Ipe.Web.Head.Unsafe` import.
#[test]
fn security_web_head_unsafe_json_ld_off_plain_head_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Web.Head as Head\n\
               main = Head.unsafeJsonLd \"{}\"\n";
    assert_rejected(
        "security_web_head_unsafe_json_ld_off_plain",
        src,
        "IPE-N0005",
    );
}

/// SECURITY (contrapositive): the marked member, homed in `Ipe.Web.Head.Unsafe`,
/// still compiles — the verbatim JSON-LD capability is preserved, only relocated
/// to the disclosing submodule that names the risk.
#[test]
fn security_web_head_unsafe_json_ld_compiles_off_submodule() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Web.Head.Unsafe as Unsafe\n\
               main : Task Error ()\n\
               main =\n\
               \x20   do\n\
               \x20       Unsafe.unsafeJsonLd \"{}\"\n\
               \x20       Io.println \"ok\"\n";
    assert_compiles("security_web_head_unsafe_json_ld", src);
}

/// SECURITY: the blunt raw secret-reveal `reveal` no longer lives on the plain
/// `Ipe.Secret` surface — it relocated to `Ipe.Secret.Unsafe.unsafeReveal`. A
/// program that imports only `Ipe.Secret` and reaches for `Secret.reveal` must
/// be rejected, so un-sealing a `Secret` into a bare `String` cannot happen
/// without the disclosing `Ipe.Secret.Unsafe` import.
#[test]
fn security_secret_reveal_off_plain_secret_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Secret as Secret\n\
               main =\n\
                   Secret.reveal (Secret.fromString \"sk\")\n";
    assert_rejected("security_secret_reveal_off_plain", src, "IPE-N0005");
}

/// SECURITY (contrapositive): the relocated `unsafeReveal`, homed in
/// `Ipe.Secret.Unsafe`, still compiles — the raw un-seal capability is
/// preserved, only relocated to the disclosing submodule that names the risk.
#[test]
fn security_secret_unsafe_reveal_compiles_off_submodule() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Secret as Secret\n\
               import Ipe.Secret.Unsafe as Unsafe\n\
               import Ipe.System as System\n\
               main : Task Error ()\n\
               main =\n\
               \x20   do\n\
               \x20       Unsafe.unsafeReveal (Secret.fromString (System.getenvOr \"K\" \"sk\"))\n\
               \x20       Io.println \"ok\"\n";
    assert_compiles("security_secret_unsafe_reveal", src);
}

/// SECURITY (the safe scoped default): `Secret.use` — the scoped consume — stays
/// on the native `Ipe.Secret` surface and compiles off a plain `import
/// Ipe.Secret`, WITHOUT any `Ipe.Secret.Unsafe` import. It is capability-neutral
/// (the disclosure half is proved in `ipe_lower::capabilities`'s
/// `importing_ipe_secret_unsafe_discloses_unsafe` and its no-unsafe partition):
/// the common scoped case never touches the `unsafe` axis.
#[test]
fn security_secret_use_compiles_off_plain_secret() {
    let src = "module Main exposing (main)\n\
               import Ipe.Io as Io\n\
               import Ipe.Secret as Secret\n\
               import Ipe.System as System\n\
               main : Task Error ()\n\
               main =\n\
               \x20   do\n\
               \x20       Secret.use (Secret.fromString (System.getenvOr \"K\" \"sk\")) (\\plain -> plain)\n\
               \x20       Io.println \"ok\"\n";
    assert_compiles("security_secret_use_scoped", src);
}

/// The same top-level value defined twice.
#[test]
fn canon_duplicate_value() {
    let src = format!("{HEAD}dup = 1\ndup = 2\nmain = dup\n");
    assert_rejected("canon_dup_value", &src, "IPE-N0010");
}

/// The same constructor name defined twice across types.
#[test]
fn canon_duplicate_constructor() {
    let src = format!("{HEAD}type A = Dup\ntype B = Dup\nmain = 1\n");
    assert_rejected("canon_dup_ctor", &src, "IPE-N0011");
}

/// The same type name declared twice.
#[test]
fn canon_duplicate_type() {
    let src = format!("{HEAD}type Foo = A\ntype Foo = B\nmain = 1\n");
    assert_rejected("canon_dup_type", &src, "IPE-N0012");
}

/// A type alias applied with the wrong number of arguments.
#[test]
fn canon_alias_wrong_arity() {
    let src =
        format!("{HEAD}type alias Pair a b = ( a, b )\nmain : Pair Int\nmain =\n    ( 1, 2 )\n");
    assert_rejected("canon_alias_arity", &src, "IPE-N0013");
}

/// A diamond alias chain that doubles the expansion work at every level
/// — 31 levels of `(Prev, Prev)` exceed the node budget (2^31 > 100 000) and
/// must be rejected at name resolution with IPE-N0032, not a stack overflow,
/// hang, or OOM. The program is otherwise well-typed; only the alias shape is
/// pathological.
#[test]
fn canon_type_alias_expansion_node_budget() {
    // Build 31 alias levels: A0 = Int, A1 = (A0, A0), ..., A30 = (A29, A29).
    // Level n produces 2^n expansion nodes, so A30 alone would need > 1 billion.
    let mut src = format!("{HEAD}type alias A0 = Int\n");
    for i in 1..=30_u32 {
        // Writing into a String is infallible.
        let _ = writeln!(src, "type alias A{i} = ( A{}, A{} )", i - 1, i - 1);
    }
    src.push_str("main : A30\nmain =\n    (1, 1)\n");
    assert_rejected("canon_alias_node_budget", &src, "IPE-N0032");
}

/// A straight alias chain of depth 300 — deeper than the 256 recursion-depth
/// cap — must be rejected with IPE-N0032 (depth limit), not a native-stack
/// overflow.
#[test]
fn canon_type_alias_expansion_depth_limit() {
    let mut src = format!("{HEAD}type alias A0 = Int\n");
    for i in 1..=300_u32 {
        // Writing into a String is infallible.
        let _ = writeln!(src, "type alias A{i} = A{}", i - 1);
    }
    src.push_str("main : A300\nmain =\n    1\n");
    assert_rejected("canon_alias_depth_limit", &src, "IPE-N0032");
}

/// A row alias applied to `{ age : Int }`, with its own fields.
const NAMED_AGE: &str = "type alias Named r = { r | name : String }\n\
                         f : Named { age : Int } -> Int\n\
                         f p =\n    p.age\n";

/// A record missing the alias's own `name` field is not a `Named { age : Int }`.
#[test]
fn alias_row_arg_missing_base_field() {
    let src = format!("{HEAD}{NAMED_AGE}main =\n    f {{ age = 1 }}\n");
    assert_rejected("alias_row_arg_missing_base_field", &src, "IPE-T0001");
}

/// A record missing the row argument's `age` field is not a `Named { age : Int }`.
#[test]
fn alias_row_arg_missing_extension_field() {
    let src = format!("{HEAD}{NAMED_AGE}main =\n    f {{ name = \"x\", other = True }}\n");
    assert_rejected("alias_row_arg_missing_extension_field", &src, "IPE-T0001");
}

/// A row alias argument that is not a record has no fields to extend.
#[test]
fn alias_row_arg_not_record() {
    let src = format!(
        "{HEAD}type alias Named r = {{ r | name : String }}\n\
         f : Named Int -> Int\nf p =\n    1\nmain =\n    1\n"
    );
    assert_rejected("alias_row_arg_not_record", &src, "IPE-N0053");
}

/// A row alias argument repeating one of the alias's own labels.
#[test]
fn alias_row_arg_label_clash() {
    let src = format!(
        "{HEAD}type alias Named r = {{ r | name : String }}\n\
         f : Named {{ name : Int }} -> Int\nf p =\n    1\nmain =\n    1\n"
    );
    assert_rejected("alias_row_arg_label_clash", &src, "IPE-N0053");
}

/// A record type naming the same label twice.
#[test]
fn record_type_duplicate_label() {
    let src = format!("{HEAD}f : {{ a : Int, a : String }} -> Int\nf p =\n    1\nmain =\n    1\n");
    assert_rejected("record_type_duplicate_label", &src, "IPE-N0010");
}

/// A user type that reuses a built-in type name (`Int`).
#[test]
fn canon_reserved_builtin_type_name() {
    let src = format!("{HEAD}type Int = MyInt\nmain = 1\n");
    assert_rejected("canon_reserved_builtin", &src, "IPE-N0026");
}

/// The JS-widget boundary type name `CustomElement` is reserved: a user
/// `type CustomElement …` declaration must be rejected exactly like any other
/// security-tier reserved builtin, so the typed seam cannot be shadowed by a
/// user-forged untyped widget type.
#[test]
fn canon_custom_element_definition_reserved() {
    let src = format!("{HEAD}type CustomElement d u = Ce\nmain = 1\n");
    assert_rejected("canon_custom_element_def", &src, "IPE-N0026");
}

/// The `Ipe.Server` opaque nominals (`Request` / `Response` / `Route` /
/// `Cookie`) are reserved: each lowers to a fixed runtime `IrType`
/// (`ServerRequest` / …) by a bare-name arm that sits above the lowerer's
/// program-enum guard, so a user `type Route = …` — accepted — would be
/// silently mis-lowered to the opaque handle, an `ipe`-exit-0-then-cargo-fail.
/// Reservation refuses the shadow at canon (IPE-N0026); the lowerer's empty-home
/// guard is the independent second gate. This pins the refusal for every name.
#[test]
fn canon_server_request_definition_reserved() {
    let src = format!("{HEAD}type Request = R\nmain = 1\n");
    assert_rejected("canon_server_request_def", &src, "IPE-N0026");
}

#[test]
fn canon_server_response_definition_reserved() {
    let src = format!("{HEAD}type Response = R\nmain = 1\n");
    assert_rejected("canon_server_response_def", &src, "IPE-N0026");
}

#[test]
fn canon_server_route_definition_reserved() {
    let src = format!("{HEAD}type Route = R\nmain = 1\n");
    assert_rejected("canon_server_route_def", &src, "IPE-N0026");
}

#[test]
fn canon_server_cookie_definition_reserved() {
    let src = format!("{HEAD}type Cookie = C\nmain = 1\n");
    assert_rejected("canon_server_cookie_def", &src, "IPE-N0026");
}

// ---------------------------------------------------------------------------
// Open (`exposing (..)`) stdlib imports defer a shared name's clash to a bare
// use — IPE-N0024 at the use, never at the import.
// ---------------------------------------------------------------------------

/// Two open imports of stdlib modules declaring a type or constructor of the
/// same name compile while no bare use names it.
#[test]
fn canon_open_imports_sharing_a_name_compile_unused() {
    for (name, first, second) in [
        (
            "canon_open_parser_transition",
            "Ipe.Parser",
            "Ipe.Ui.Transition",
        ),
        ("canon_open_ui_attributes", "Ipe.Ui", "Ipe.Html.Attributes"),
        (
            "canon_open_random_generator",
            "Ipe.Random",
            "Ipe.Random.Generator",
        ),
    ] {
        let src = format!(
            "{HEAD}\nimport Ipe.Io as Io\nimport {first} exposing (..)\nimport {second} exposing (..)\n\n\
             main = Io.println \"ok\"\n"
        );
        assert_compiles(name, &src);
    }
}

/// A bare `Step` annotation over the open `Ipe.Parser` and `Ipe.Ui.Transition`
/// is IPE-N0024.
#[test]
fn canon_open_imports_bare_type_use_is_ambiguous() {
    let src = format!(
        "{HEAD}\nimport Ipe.Io as Io\nimport Ipe.Parser exposing (..)\nimport Ipe.Ui.Transition exposing (..)\n\n\
         f : Step -> Int\nf _ =\n    0\n\n\
         main = Io.println \"ok\"\n"
    );
    assert_rejected("canon_open_bare_type_ambiguous", &src, "IPE-N0024");
}

/// A bare `Alert` (each module's own `Role` constructor) over the open `Ipe.Ui`
/// and `Ipe.Html.Attributes` is IPE-N0024.
#[test]
fn canon_open_imports_bare_ctor_use_is_ambiguous() {
    let src = format!(
        "{HEAD}\nimport Ipe.Io as Io\nimport Ipe.Ui exposing (..)\nimport Ipe.Html.Attributes exposing (..)\n\n\
         r = Alert\n\n\
         main = Io.println \"ok\"\n"
    );
    assert_rejected("canon_open_bare_ctor_ambiguous", &src, "IPE-N0024");
}

/// The open-import sweep: one program opens every compiled-source stdlib module
/// a plain `main` may import, and compiles, so no stdlib type or constructor
/// addition can reject an open importer that does not use the name.
///
/// The list is the registry the doc bundle reads. A module joins by rule: the
/// placement table admits it in a plain-`main` script, and it is not an
/// `Ipe.Tea.*` shape surface (a plain-`main` program importing one is
/// IPE-N0033).
#[test]
fn canon_open_import_sweep_over_the_stdlib_registry_compiles() {
    use ipe_canon::shape_runtime::{Admissibility, Placement, Shape, allowed_in, classify};
    let script = Placement::sole_for(Shape::Script);
    assert!(script.is_some(), "a plain-`main` script has one placement");
    #[allow(clippy::expect_used)] // `is_some` is asserted just above
    let script = script.expect("asserted present above");
    let mut src = format!("{HEAD}\nimport Ipe.Io as Io\n");
    let mut joined: Vec<&str> = Vec::new();
    for module in ipe_stdlib::COMPILED_STD_MODULES {
        let admitted = matches!(
            allowed_in(classify(module.dotted), script),
            Admissibility::Allow
        );
        if !admitted || module.dotted.starts_with("Ipe.Tea.") {
            continue;
        }
        let _ = writeln!(
            src,
            "import {} as Open{} exposing (..)",
            module.dotted,
            joined.len()
        );
        joined.push(module.dotted);
    }
    src.push_str("\nmain = Io.println \"ok\"\n");
    // Every module of a known shared-name pair must join, so the rule can never
    // filter the sweep down past the clashes it exists to pin.
    for pinned in [
        "Ipe.Parser",
        "Ipe.Ui.Transition",
        "Ipe.Ui",
        "Ipe.Html.Attributes",
        "Ipe.Codec",
        "Ipe.Random",
        "Ipe.Random.Generator",
    ] {
        assert!(
            joined.contains(&pinned),
            "the sweep must open `{pinned}`, opened {joined:?}"
        );
    }
    assert_compiles("canon_open_import_sweep", &src);
}

/// Build the `import {dotted} as OpenN exposing (..)` block admitted into
/// `placement`, skipping `Ipe.Tea.*` (a non-Script shape importing a
/// DIFFERENT shape's Tea surface is its own refusal, IPE-N0033, not this
/// sweep's concern). Mirrors the admission rule
/// `canon_open_import_sweep_over_the_stdlib_registry_compiles` hand-rolls for
/// `Shape::Script`, reused below for every OTHER shape with a sole placement.
fn open_import_sweep_block(
    placement: ipe_canon::shape_runtime::Placement,
) -> (String, Vec<&'static str>) {
    use ipe_canon::shape_runtime::{Admissibility, allowed_in, classify};
    let mut block = String::new();
    let mut joined: Vec<&'static str> = Vec::new();
    for module in ipe_stdlib::COMPILED_STD_MODULES {
        let admitted = matches!(
            allowed_in(classify(module.dotted), placement),
            Admissibility::Allow
        );
        if !admitted || module.dotted.starts_with("Ipe.Tea.") {
            continue;
        }
        let _ = writeln!(
            block,
            "import {} as Open{} exposing (..)",
            module.dotted,
            joined.len()
        );
        joined.push(module.dotted);
    }
    (block, joined)
}

/// Every `COMPILED_STD_MODULES` entry `allowed_in` the Tui
/// placement opens cleanly alongside a minimal well-typed Tui `main`. The one
/// axis that differs from Script is `BrowserHost` (`Allow` for Script,
/// `Deny` for Tui), so this also pins that no `Ipe.Browser.*` module sneaks
/// into a Tui sweep, and that `Ipe.Ui.Tui` / `Ipe.Ui.Cells` — Tui-only UI
/// helpers a stale per-shape list could otherwise miss — are admitted.
#[test]
fn canon_open_import_per_shape_sweep_tui_compiles() {
    use ipe_canon::shape_runtime::{Placement, Shape};
    let placement = Placement::sole_for(Shape::Tui);
    assert!(placement.is_some(), "Tui has one placement");
    #[allow(clippy::expect_used)] // `is_some` is asserted just above
    let placement = placement.expect("asserted present above");
    let (block, joined) = open_import_sweep_block(placement);

    let mut src = format!(
        "{HEAD}\n\
         import Ipe.Tea.Tui as Tui\n\
         import Ipe.Ui.Cells as Cells\n\
         import Ipe.Ui.Cells exposing (Screen)\n\
         import Ipe.Tea.Tui.Cmd\n\
         import Ipe.Tea.Tui.Sub\n"
    );
    src.push_str(&block);
    src.push_str(
        "\ntype Msg = NoOp\n\n\
         type alias Model = { count : Int }\n\n\
         init : () -> ( Model, Cmd Msg )\n\
         init _unit =\n    ( { count = 0 }, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    ( model, Cmd.none )\n\n\
         view : Model -> Screen Msg\n\
         view _model =\n    Cells.text \"hello\"\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    Sub.none\n\n\
         main =\n    Tui.tea\n        { init = init, update = update, view = view\n        , subscriptions = subscriptions\n        }\n",
    );

    for pinned in ["Ipe.Ui.Tui", "Ipe.Ui.Cells"] {
        assert!(
            joined.contains(&pinned),
            "the Tui sweep must open `{pinned}`, opened {joined:?}"
        );
    }
    assert!(
        joined.iter().all(|m| !m.starts_with("Ipe.Browser.")),
        "Tui must not admit any Ipe.Browser.* module (BrowserHost denied for Tui); \
         admitted {joined:?}"
    );
    assert_compiles("canon_open_import_per_shape_sweep_tui", &src);
}

/// Parallel to the Tui sweep above, for the Cli placement. Pins
/// `Ipe.Ui.Cli` (the Cli-only UI helper module) and the same `BrowserHost`
/// exclusion.
#[test]
fn canon_open_import_per_shape_sweep_cli_compiles() {
    use ipe_canon::shape_runtime::{Placement, Shape};
    let placement = Placement::sole_for(Shape::Cli);
    assert!(placement.is_some(), "Cli has one placement");
    #[allow(clippy::expect_used)] // `is_some` is asserted just above
    let placement = placement.expect("asserted present above");
    let (block, joined) = open_import_sweep_block(placement);

    let mut src = format!(
        "{HEAD}\n\
         import Ipe.Tea.Cli as Cli\n\
         import Ipe.Tea.Cli.Cmd\n\
         import Ipe.Tea.Cli.Sub\n\
         import Ipe.Ui.Cli as Ui\n\
         import Ipe.Ui.Cli exposing (Lines)\n"
    );
    src.push_str(&block);
    src.push_str(
        "\ntype Msg = NoOp\n\n\
         type alias Model = { count : Int }\n\n\
         init : () -> ( Model, Cmd Msg )\n\
         init _unit =\n    ( { count = 0 }, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    ( model, Cmd.none )\n\n\
         view : Model -> Lines Msg\n\
         view _model =\n    Ui.text \"ok\"\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    Sub.none\n\n\
         main =\n    Cli.tea\n        { init = init, update = update, view = view\n        , subscriptions = subscriptions\n        }\n",
    );

    assert!(
        joined.contains(&"Ipe.Ui.Cli"),
        "the Cli sweep must open `Ipe.Ui.Cli`, opened {joined:?}"
    );
    assert!(
        joined.iter().all(|m| !m.starts_with("Ipe.Browser.")),
        "Cli must not admit any Ipe.Browser.* module (BrowserHost denied for Cli); \
         admitted {joined:?}"
    );
    assert_compiles("canon_open_import_per_shape_sweep_cli", &src);
}

/// Parallel to the Tui/Cli sweeps above, for the view-less
/// Worker placement (no `view` field in its `tea` record).
#[test]
fn canon_open_import_per_shape_sweep_worker_compiles() {
    use ipe_canon::shape_runtime::{Placement, Shape};
    let placement = Placement::sole_for(Shape::Worker);
    assert!(placement.is_some(), "Worker has one placement");
    #[allow(clippy::expect_used)] // `is_some` is asserted just above
    let placement = placement.expect("asserted present above");
    let (block, joined) = open_import_sweep_block(placement);

    let mut src = format!(
        "{HEAD}\n\
         import Ipe.Tea.Worker as Worker\n\
         import Ipe.Tea.Worker.Cmd\n\
         import Ipe.Tea.Worker.Sub\n"
    );
    src.push_str(&block);
    src.push_str(
        "\ntype Msg = NoOp\n\n\
         type alias Model = { ticks : Int }\n\n\
         init : () -> ( Model, Cmd Msg )\n\
         init _unit =\n    ( { ticks = 0 }, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    ( model, Cmd.none )\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    Sub.none\n\n\
         main =\n    Worker.tea { init = init, update = update, subscriptions = subscriptions }\n",
    );

    assert!(
        joined.iter().all(|m| !m.starts_with("Ipe.Browser.")),
        "Worker must not admit any Ipe.Browser.* module (BrowserHost denied for Worker); \
         admitted {joined:?}"
    );
    assert_compiles("canon_open_import_per_shape_sweep_worker", &src);
}

/// Staleness guard: the per-shape sweeps cover Script and Tui/Cli/Worker —
/// every `Shape` with a sole
/// `Placement`. `Shape::Web` is deliberately excluded (it admits both
/// `Served` and `Solo` runtimes, so `sole_for` returns `None`, see
/// `shape_runtime`'s own `sole_placement_is_none_for_web_some_otherwise`
/// unit test). If `Web` ever gains a sole placement this assertion goes red,
/// so the exclusion cannot go silently stale.
#[test]
fn canon_open_import_per_shape_sweep_excludes_web_for_cause() {
    use ipe_canon::shape_runtime::{Placement, Shape};
    assert!(
        Placement::sole_for(Shape::Web).is_none(),
        "Shape::Web now has a sole placement — add it to the per-shape open-import \
         sweep alongside Script/Tui/Cli/Worker instead of leaving it excluded"
    );
}

/// `Ipe.Ui.Tui` and `Ipe.Ui.Cells` both expose `column` (each defined as the
/// one kernel `UiCells_column`) and `Screen` (Cells re-exports Tui's). Two
/// open imports of ONE definition are one origin, never a clash: a bare
/// `column` and a bare `Screen` in a Tui program resolve without IPE-N0024.
/// Keying an origin by its importing module instead of its definition makes
/// this program a false ambiguity.
#[test]
fn canon_open_imports_tui_and_cells_share_column_and_compile() {
    let mut src = HEAD.to_owned();
    src.push_str(
        "\nimport Ipe.Tea.Tui as Tui\n\
         import Ipe.Ui.Tui exposing (..)\n\
         import Ipe.Ui.Cells exposing (..)\n\
         import Ipe.Tea.Tui.Cmd\n\
         import Ipe.Tea.Tui.Sub\n\n\
         type Msg = NoOp\n\n\
         type alias Model = { count : Int }\n\n\
         init : () -> ( Model, Cmd Msg )\n\
         init _unit =\n    ( { count = 0 }, Cmd.none )\n\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n    ( model, Cmd.none )\n\n\
         view : Model -> Screen Msg\n\
         view _model =\n    column [] []\n\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n    Sub.none\n\n\
         main =\n    Tui.tea\n        { init = init, update = update, view = view\n        , subscriptions = subscriptions\n        }\n",
    );
    assert_compiles("canon_open_tui_cells_column", &src);
}

/// The shape app-leaf names (`WebApp` / `TuiApp` / `CliApp`) are
/// deliberately NOT reserved — a user program may soundly declare
/// `type WebApp = …` and use it, and the lowerer's empty-home guard keeps that
/// user union winning over the opaque runtime leaf (see the `ipe_lower`
/// `opaque_home_guard` static goldens). Here we pin the CONTRAPOSITIVE at the
/// full-pipeline level: such a program is ACCEPTED (exit 0), never refused —
/// proving the guard does not over-reserve a legitimate user name.
#[test]
fn shape_leaf_user_type_webapp_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         type WebApp = W\n\
         tag : WebApp -> Int\n\
         tag w =\n\
         \x20   0\n\
         main : Task Error ()\n\
         main =\n\
         \x20   Io.println \"ok\"\n"
    );
    assert_compiles("shape_leaf_user_webapp", &src);
}

#[test]
fn shape_leaf_user_type_tuiapp_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         type TuiApp = T\n\
         tag : TuiApp -> Int\n\
         tag t =\n\
         \x20   0\n\
         main : Task Error ()\n\
         main =\n\
         \x20   Io.println \"ok\"\n"
    );
    assert_compiles("shape_leaf_user_tuiapp", &src);
}

/// A `CustomElement down up` annotation whose two parameters are plain, closed
/// value types (here two primitives) TYPE-RESOLVES at canon — the arity and SEAL
/// gates pass — and, with the WP4 transport shipped, now LOWERS to the opaque
/// widget handle rather than being refused at emission. With the binding unused
/// (`main = 1`), the program compiles cleanly. That it neither errors at canon
/// (no `IPE-N0xxx`) nor ICEs proves the annotation resolves AND the handle type
/// has a real denotation.
#[test]
fn canon_custom_element_use_resolves_and_lowers() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         editor : CustomElement Int String\n\
         editor = editor\n\
         main : Task Error ()\n\
         main =\n\
         \x20   Io.println \"ok\"\n"
    );
    assert_compiles("canon_custom_element_use", &src);
}

/// A QUALIFIED spelling of the boundary type (`D.CustomElement …` through an
/// imported module) is checked by NAME regardless of its non-empty home: the
/// arity + SEAL gates pass for two primitives, so it too type-RESOLVES at canon
/// and now lowers — never slipping past a home gate into a build-time ICE.
#[test]
fn canon_custom_element_qualified_use_resolves_and_lowers() {
    let src = format!(
        "{HEAD}import Ipe.Dict as D\n\
         import Ipe.Io as Io\n\
         editor : D.CustomElement Int String\n\
         editor = editor\n\
         main : Task Error ()\n\
         main =\n\
         \x20   Io.println \"ok\"\n"
    );
    assert_compiles("canon_custom_element_qualified", &src);
}

/// The boundary SEAL accepts plain, closed, concrete value types transitively:
/// a `CustomElement` whose down-state is a user record alias and whose up-event
/// is a user ADT over primitives type-RESOLVES at canon (arity + seal pass) and
/// lowers. This is the POSITIVE seal case — the intended
/// `CustomElement EditorState EditorEvent` shape is admitted end to end.
#[test]
fn canon_custom_element_plain_user_seal_resolves() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         type alias EditorState = {{ text : String, cursor : Int }}\n\
         type EditorEvent = TextChanged String | CursorMoved Int\n\
         editor : CustomElement EditorState EditorEvent\n\
         editor = editor\n\
         main : Task Error ()\n\
         main =\n\
         \x20   Io.println \"ok\"\n"
    );
    assert_compiles("canon_custom_element_plain_seal", &src);
}

/// `CustomElement` demands EXACTLY two type parameters — the sealed down-state
/// and the up-event. Too FEW is a clean arity error (IPE-N0031, the same code the
/// closed built-in containers use), checked before the seal so a mis-shaped
/// annotation never reaches emission.
#[test]
fn canon_custom_element_arity_too_few() {
    let src = format!("{HEAD}x : CustomElement Int\nx = x\nmain = 1\n");
    assert_rejected("canon_custom_element_arity1", &src, "IPE-N0031");
}

/// Too MANY type parameters is the same arity rejection (IPE-N0031).
#[test]
fn canon_custom_element_arity_too_many() {
    let src = format!("{HEAD}x : CustomElement Int String Bool\nx = x\nmain = 1\n");
    assert_rejected("canon_custom_element_arity3", &src, "IPE-N0031");
}

/// `Ipe.Db`'s external-connection handle is `Connection mode` — EXACTLY one
/// phantom access-mode argument. A bare `Connection` (too few) is a clean arity
/// error (IPE-N0031), NOT the empty-home lowerer ICE (IPE-I0001) it produced
/// before the arity gate covered the parametric reserved builtin.
#[test]
fn canon_connection_arity_too_few() {
    let src = format!("{HEAD}x : Connection\nx = x\nmain = 1\n");
    assert_rejected("canon_connection_arity0", &src, "IPE-N0031");
}

/// Too MANY arguments (`Connection a b`) is the same clean arity rejection
/// (IPE-N0031), again never the empty-home ICE.
#[test]
fn canon_connection_arity_too_many() {
    let src = format!("{HEAD}x : Connection ReadOnly ReadWrite\nx = x\nmain = 1\n");
    assert_rejected("canon_connection_arity2", &src, "IPE-N0031");
}

/// The SEAL rejects a function-carrying boundary parameter (IPE-N0039): a
/// function is behaviour, not a serialisable value, and must never cross the
/// Ipê↔JS seam. Fail-closed at the type level, before emission.
#[test]
fn canon_custom_element_seal_rejects_function() {
    let src = format!("{HEAD}x : CustomElement (Int -> Int) String\nx = x\nmain = 1\n");
    assert_rejected("canon_custom_element_seal_fn", &src, "IPE-N0039");
}

/// The SEAL rejects a `Secret`-carrying boundary parameter (IPE-N0039): a
/// secret-tier value must never be serialised across the JS seam. This is the
/// security-critical exclusion the seal adds over the plain-value gate.
#[test]
fn canon_custom_element_seal_rejects_secret() {
    let src = format!("{HEAD}x : CustomElement Secret String\nx = x\nmain = 1\n");
    assert_rejected("canon_custom_element_seal_secret", &src, "IPE-N0039");
}

/// The SEAL rejects a `Secret` in the DOWN slot regardless of the UP type
/// (IPE-N0039). Pins that the secret exclusion holds independent of the sibling
/// parameter — a secret-tier value must never be serialised down to browser JS.
#[test]
fn canon_custom_element_seal_rejects_secret_down_int_up() {
    let src = format!("{HEAD}x : CustomElement Secret Int\nx = x\nmain = 1\n");
    assert_rejected("canon_custom_element_seal_secret_int", &src, "IPE-N0039");
}

/// The SEAL rejects a reserved SINK type (`SqlFragment`) in the UP slot
/// (IPE-N0039). Pins that the sink exclusion covers the up-event parameter too,
/// not only the down-state one: a sink-privileged value crossing the seam would
/// launder its sink privilege to untrusted browser JS.
#[test]
fn canon_custom_element_seal_rejects_sink_up() {
    let src = format!("{HEAD}x : CustomElement Int SqlFragment\nx = x\nmain = 1\n");
    assert_rejected("canon_custom_element_seal_sink_up", &src, "IPE-N0039");
}

/// The SEAL rejects a reserved sink-privileged handle (`Url`) as a boundary
/// parameter (IPE-N0039). Pins that the exclusion set spans the sink-privileged
/// handles, not just `Secret`/`SqlFragment`.
#[test]
fn canon_custom_element_seal_rejects_url() {
    let src = format!("{HEAD}x : CustomElement Url Int\nx = x\nmain = 1\n");
    assert_rejected("canon_custom_element_seal_url", &src, "IPE-N0039");
}

/// The SEAL rejects a type-variable boundary parameter (IPE-N0039): the seal is
/// monomorphic and concrete, so a bare type variable — which has no single
/// generated codec — is refused fail-closed.
#[test]
fn canon_custom_element_seal_rejects_type_variable() {
    let src = format!("{HEAD}x : CustomElement a String\nx = x\nmain = 1\n");
    assert_rejected("canon_custom_element_seal_tyvar", &src, "IPE-N0039");
}

// ── The `customElement` constructor (WP2, IPE-N0044 / IPE-P0063) ──
//
// The reserved `customElement "<js-path>"` constructor is legal ONLY as the whole
// body of a `CustomElement`-annotated binding, applied to a single string literal
// naming a widget-hook JS file inside the project. These pin every refusal, plus
// the positive case that type-checks and lowers cleanly (transport shipped).

/// A single-file program whose `Main.ipe` sits beside the given extra files
/// (relative path → contents), built through the full pipeline. Returns the same
/// [`Outcome`] the shared harness produces — used for the widget-file-exists path,
/// which needs a real JS file on disk next to the entry.
fn compile_with_files(name: &str, source: &str, extra: &[(&str, &str)]) -> Outcome {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("negsuite-ce")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    crate::support::expect_scratch_step(name, std::fs::create_dir_all(&dir));
    for (rel, contents) in extra {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            crate::support::expect_scratch_step(name, std::fs::create_dir_all(parent));
        }
        crate::support::expect_scratch_step(name, std::fs::write(&path, contents));
    }
    let entry = dir.join("Main.ipe");
    crate::support::expect_scratch_step(name, std::fs::write(&entry, source));
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("negsuite-ce-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build_with_options(&entry, &out, &runtime, BuildOptions::default()) {
        Ok(()) => Outcome::Accepted("compiled successfully (exit 0)".to_owned()),
        Err(CliError::Pipeline { diag, .. }) => Outcome::Rejected(diag.code().as_str()),
        Err(other) => Outcome::Accepted(format!("non-pipeline error: {other:?}")),
    }
}

/// Assert a fixture with the given extra files is rejected with exactly `expected`.
#[track_caller]
fn assert_rejected_with_files(name: &str, source: &str, extra: &[(&str, &str)], expected: &str) {
    match compile_with_files(name, source, extra) {
        Outcome::Rejected(got) => assert_eq!(
            got, expected,
            "{name}: expected {expected}, got {got} — a rejection for the WRONG reason"
        ),
        Outcome::Accepted(how) => fail_accepted(name, expected, &how),
    }
}

/// (a) `customElement` applied to a NON-literal (a variable) is rejected: the JS
/// path must be a string literal so it can be read at build time (IPE-N0044).
#[test]
fn custom_element_ctor_non_literal_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
         src : String\n\
         src = \"js/x.js\"\n\
         editor : CustomElement Int String\n\
         editor = CustomElement.fromFile src\n\
         main = 1\n"
    );
    assert_rejected("custom_element_non_literal", &src, "IPE-N0044");
}

/// (b) A bare `customElement` value (referenced without its literal argument) is
/// rejected — the constructor must be applied to its widget path (IPE-N0044).
#[test]
fn custom_element_ctor_bare_value_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
         editor : CustomElement Int String\n\
         editor = CustomElement.fromFile\n\
         main = 1\n"
    );
    assert_rejected("custom_element_bare", &src, "IPE-N0044");
}

/// `customElement` outside a `CustomElement`-annotated binding body is rejected:
/// here it heads an ordinary (differently-typed) binding, so the reserved name
/// resolves nowhere legal (IPE-N0044).
#[test]
fn custom_element_ctor_wrong_position_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
         oops = CustomElement.fromFile \"js/x.js\"\n\
         main = 1\n"
    );
    assert_rejected("custom_element_wrong_pos", &src, "IPE-N0044");
}

/// (c) `customElement "does/not/exist.js"` with no such file is rejected: a widget
/// cannot register against a file that is not there (IPE-N0044, checked at the
/// build stage that owns the project root).
#[test]
fn custom_element_ctor_missing_file_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
         editor : CustomElement Int String\n\
         editor = CustomElement.fromFile \"js/does-not-exist.js\"\n\
         main = 1\n"
    );
    // No extra files written — the named path is absent.
    assert_rejected_with_files("custom_element_missing_file", &src, &[], "IPE-N0044");
}

/// (d) `customElement "../escape.js"` is rejected by the shared path seal — a `..`
/// that climbs out of the project root is refused at build (IPE-P0063).
#[test]
fn custom_element_ctor_path_traversal_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
         editor : CustomElement Int String\n\
         editor = CustomElement.fromFile \"../escape.js\"\n\
         main = 1\n"
    );
    assert_rejected("custom_element_traversal", &src, "IPE-P0063");
}

/// A `CustomElement.fromFile` path carrying a NUL byte is refused at build
/// (IPE-P0063) before it can reach a syscall.
#[test]
fn custom_element_ctor_nul_path_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
         editor : CustomElement Int String\n\
         editor = CustomElement.fromFile \"js/a\\0b.js\"\n\
         main = 1\n"
    );
    assert_rejected("custom_element_nul", &src, "IPE-P0063");
}

/// Refusal: a widget path the Unix seal accepts but the Windows seal refuses
/// is still IPE-P0063 — the compiler does not know the build host's separator
/// regime, so the literal must be safe under every regime.
#[test]
fn custom_element_ctor_windows_only_traversal_rejected() {
    for (i, literal) in [
        "..\\\\secret",
        ".. .",
        ".. \\\\x",
        "C:..\\\\x",
        "a\\\\..\\\\..\\\\b",
    ]
    .iter()
    .enumerate()
    {
        let src = format!(
            "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
             editor : CustomElement Int String\n\
             editor = CustomElement.fromFile \"{literal}\"\n\
             main = 1\n"
        );
        assert_rejected(&format!("custom_element_win_{i}"), &src, "IPE-P0063");
    }
}

/// Refusal: `path "…"` is no literal form, so with no `path` in scope it is an
/// unresolved name (IPE-N0001).
#[test]
fn path_before_a_string_with_no_path_binder_is_unresolved() {
    let src = format!("{HEAD}main = path \"src/Main.ipe\"\n");
    assert_rejected("path_is_an_ordinary_name", &src, "IPE-N0001");
}

/// (e) A well-formed `customElement "js/x.js"` with the file PRESENT type-checks
/// (the shape + path + existence gates all pass) and — with the WP4 transport
/// shipped — now LOWERS to the opaque widget handle rather than being refused at
/// emission. Here the binding is unused (a bare `main = 1`, no `CustomElement.node`), so
/// it is DCE'd and the program compiles cleanly. A real Web-shape program that
/// PLACES the widget is the WP4 SEAL golden (`custom_element_widget` fixture).
#[test]
fn custom_element_ctor_present_file_lowers_and_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Ffi.Js.CustomElement as CustomElement\n\
         editor : CustomElement Int String\n\
         editor = CustomElement.fromFile \"js/x.js\"\n\
         main : Task Error ()\n\
         main =\n\
         \x20   Io.println \"ok\"\n"
    );
    let outcome = compile_with_files(
        "custom_element_present",
        &src,
        &[(
            "js/x.js",
            "export function mount(host, emit) { return {}; }\n",
        )],
    );
    match outcome {
        Outcome::Accepted(how) if how.starts_with("compiled successfully") => {}
        other => assert!(
            false_marker(),
            "custom_element_present: expected a clean compile once WP4 ships the \
             transport, got {other:?}"
        ),
    }
}

/// (f) A `CustomElement` value is an opaque, non-serialisable handle, so it can
/// never live in a Web `Model` (session state), exactly like a function value.
/// With the transport shipped, the handle type lowers; enforcement is the
/// plain-Model gate:
/// `IrType::CustomElement` is non-serde, so a Web Model carrying one is rejected
/// with IPE-L0120. That end-to-end proof — a real `Web.tea` whose Model has a
/// `CustomElement` field — lives in `model_admissibility.rs`
/// (`live_model_with_custom_element_field_is_rejected`). Here, in a bare
/// `main = 1` script with no app entry, no Model gate runs; the unused Model
/// alias is DCE'd and the program compiles cleanly — confirming the opacity is a
/// Model-gate concern, not a blanket ban on naming the type.
#[test]
fn custom_element_in_unused_binding_compiles_no_model_gate() {
    // A `CustomElement`-typed binding that never flows into a Web `Model` (no app
    // entry here — a plain `Task` `main`) has no Model gate to run. The type
    // lowers to the opaque handle and, being unused, is DCE'd; the program
    // compiles cleanly. This confirms the opacity is a Model-gate concern, not a
    // blanket ban on naming the type. (A divergent `editor = editor` body keeps
    // the fixture free of the `customElement` constructor, whose own annotation
    // gate — WP2, IPE-N0044 — is exercised separately above.)
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         editor : CustomElement Int String\n\
         editor = editor\n\
         main : Task Error ()\n\
         main =\n\
         \x20   Io.println \"ok\"\n"
    );
    assert_compiles("custom_element_unused_binding", &src);
}

/// (g) `customElement "/etc/passwd"` (an ABSOLUTE path) is rejected at CANON with
/// IPE-N0044 — the widget path must be project-root-relative. An absolute literal
/// would survive the shared `ipe_path_core` seal (which legitimately accepts absolute
/// paths) yet, joined at the build gate, `Path::join` discards the project root
/// and stats an arbitrary out-of-project file. This closes that escape at the name
/// stage, before any filesystem access.
///
/// Verdict-does-not-flip proof: an absolute path whose target EXISTS on the host
/// (`/etc/passwd`) and one that does NOT (`/nonexistent-…`) must BOTH reject with
/// the SAME canon code (IPE-N0044), never flipping to a build-stage
/// existence/emission verdict on whether the outside file happens to be present —
/// the exact verdict-flip the guardian exercised.
#[test]
fn custom_element_ctor_absolute_path_rejected_at_canon() {
    for (label, abs) in [
        ("present", "/etc/passwd"),
        ("absent", "/nonexistent-ipe-widget-\u{2603}.js"),
    ] {
        let src = format!(
            "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
             editor : CustomElement Int String\n\
             editor = CustomElement.fromFile \"{abs}\"\n\
             main = 1\n"
        );
        // Single-file `compile` reaches canon and stops there on rejection, so no
        // JS file is written — the verdict must be identical for both the
        // host-existing and the host-missing absolute target.
        assert_rejected(
            &format!("custom_element_absolute_{label}"),
            &src,
            "IPE-N0044",
        );
    }
}

/// A Windows-rooted spelling (`C:\\…` drive designator and a `\\\\server\\share`
/// UNC prefix) is ALSO rejected at canon with IPE-N0044, independent of the
/// compiling host's OS. `Path::is_absolute` on a Unix host would read `C:\x` as
/// relative, so the all-targets lexical check — not the host's own path logic —
/// is what turns these back.
#[test]
fn custom_element_ctor_windows_rooted_path_rejected_at_canon() {
    for (label, rooted) in [
        ("drive", "C:\\\\widgets\\\\evil.js"),
        ("drive_relative", "C:evil.js"),
        ("unc", "\\\\\\\\server\\\\share\\\\evil.js"),
        ("backslash_root", "\\\\evil.js"),
    ] {
        let src = format!(
            "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
             editor : CustomElement Int String\n\
             editor = CustomElement.fromFile \"{rooted}\"\n\
             main = 1\n"
        );
        assert_rejected(
            &format!("custom_element_win_rooted_{label}"),
            &src,
            "IPE-N0044",
        );
    }
}

/// (h) A SYMLINK escape: an in-tree `js` directory entry is a symlink pointing to
/// a directory OUTSIDE the project, and `customElement "js/evil.js"` names a file
/// that really EXISTS at the symlink target. The lexical seals cannot see the
/// symlink (the literal is a clean relative path), so this is the case the
/// build-gate containment check must close: canonicalising the join resolves the
/// symlink to its out-of-project target, and the `starts_with` root-containment
/// assertion refuses it (IPE-N0044) instead of a bare `is_file` FOLLOWING the link
/// and accepting an arbitrary outside file.
///
/// The refusal must NOT depend on the outside file's presence for its SECURITY
/// verdict — the file is deliberately made to exist here so the check is proven to
/// reject a genuinely-readable out-of-project target, not merely a dangling link.
#[cfg(unix)]
#[test]
fn custom_element_ctor_symlink_escape_rejected_at_build_gate() {
    use std::path::PathBuf;

    let name = "custom_element_symlink_escape";
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("negsuite-ce-symlink");
    let _ = std::fs::remove_dir_all(&base);
    let project = base.join("project");
    let outside = base.join("outside");
    // The out-of-project directory and a real file inside it (the escape target).
    crate::support::expect_scratch_step(name, std::fs::create_dir_all(&outside));
    crate::support::expect_scratch_step(
        name,
        std::fs::write(
            outside.join("evil.js"),
            "export function mount(host, emit) { return {}; }\n",
        ),
    );
    crate::support::expect_scratch_step(name, std::fs::create_dir_all(&project));
    // In-tree `js` is a SYMLINK to the outside directory.
    crate::support::expect_scratch_step(
        name,
        std::os::unix::fs::symlink(&outside, project.join("js")),
    );
    let src = format!(
        "{HEAD}import Ipe.Ffi.Js.CustomElement as CustomElement\n\
         editor : CustomElement Int String\n\
         editor = CustomElement.fromFile \"js/evil.js\"\n\
         main = 1\n"
    );
    let entry = project.join("Main.ipe");
    crate::support::expect_scratch_step(name, std::fs::write(&entry, &src));
    let out = base.join("out");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let outcome = match ipe::build_with_options(&entry, &out, &runtime, BuildOptions::default()) {
        Ok(()) => Outcome::Accepted("compiled successfully (exit 0)".to_owned()),
        Err(CliError::Pipeline { diag, .. }) => Outcome::Rejected(diag.code().as_str()),
        Err(other) => Outcome::Accepted(format!("non-pipeline error: {other:?}")),
    };
    let _ = std::fs::remove_dir_all(&base);
    match outcome {
        Outcome::Rejected(got) => assert_eq!(
            got, "IPE-N0044",
            "custom_element_symlink_escape: expected IPE-N0044 (containment), got {got}"
        ),
        Outcome::Accepted(how) => fail_accepted("custom_element_symlink_escape", "IPE-N0044", &how),
    }
}

/// WP4 SEAL golden (ipe-accept half): a real Web-shape program that PLACES a
/// widget with `CustomElement.node`. `codeEditor : CustomElement {a record} {a closed
/// ADT}` — a record down-state and a closed-ADT up-event — with a present
/// in-project `js/x.js` hook. The full seam lowers: the down-state renders as an
/// entity-escaped `state` attribute, the up-event decodes fail-closed over
/// `/_ipe/event`. This asserts the pipeline ACCEPTS (exit 0). The cargo-build
/// half of the SEAL (the emitted crate compiles) is exercised by the same
/// fixture under `IPE_E2E=1`; here we prove acceptance without invoking cargo.
#[test]
fn custom_element_widget_program_ipe_accepts() {
    let src = format!(
        "{HEAD}import Ipe.Tea.Web as Web\n\
         import Ipe.Ffi.Js.CustomElement as CustomElement\n\
         import Ipe.Tea.Web.Cmd\n\
         import Ipe.Tea.Web.Sub\n\
         type alias EditorState = {{ text : String, line : Int }}\n\
         type EditorEvent = Changed String | Saved\n\
         type Msg = Edited EditorEvent\n\
         type alias Model = {{ state : EditorState }}\n\
         codeEditor : CustomElement EditorState EditorEvent\n\
         codeEditor = CustomElement.fromFile \"js/x.js\"\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req =\n\
         \x20   ( {{ state = {{ text = \"\", line = 0 }} }}, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model =\n\
         \x20   ( model, Cmd.none )\n\
         view : Model -> Element Msg\n\
         view model =\n\
         \x20   CustomElement.node codeEditor model.state Edited\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model =\n\
         \x20   Sub.none\n\
         main =\n\
         \x20   Web.tea\n\
         \x20       {{ init = init, update = update, view = view, subscriptions = subscriptions\n\
         \x20       , routes = [], notFound = Edited Saved\n\
         \x20       }}\n"
    );
    let outcome = compile_with_files(
        "custom_element_widget",
        &src,
        &[(
            "js/x.js",
            "export function mount(host, emit) { return {}; }\n",
        )],
    );
    match outcome {
        Outcome::Accepted(how) if how.starts_with("compiled successfully") => {}
        other => assert!(
            false_marker(),
            "custom_element_widget: expected ipe-accept (exit 0), got {other:?}"
        ),
    }
}

/// Two imports registering the same qualifier for DIFFERENT sibling modules.
/// The clash is only observable across a multi-file project (sibling
/// discovery), so this uses the project harness rather than the single-file
/// path — the qualifier is referenced so it reaches a use site.
#[test]
fn canon_duplicate_qualifier() {
    match compile_project(
        "canon_dup_qualifier",
        &[
            ("A.ipe", "module A exposing (label)\nlabel = \"from A\"\n"),
            ("B.ipe", "module B exposing (label)\nlabel = \"from B\"\n"),
            (
                "Main.ipe",
                "module Main exposing (main)\n\
                 import A as Utils\n\
                 import B as Utils\n\
                 main = Utils.label\n",
            ),
        ],
    ) {
        Outcome::Rejected(got) => assert_eq!(
            got, "IPE-N0027",
            "canon_dup_qualifier: expected IPE-N0027, got {got} — WRONG reason"
        ),
        Outcome::Accepted(how) => fail_accepted("canon_dup_qualifier", "IPE-N0027", &how),
    }
}

/// An `Kernel.kernel "Name"` alias in USER source — minting a kernel is reserved to
/// the vouched stdlib / FFI interface, so it is rejected by the origin gate
/// (IPE-N0042) before the registry is consulted, whether or not the named kernel
/// is registered.
#[test]
fn canon_user_kernel_alias_is_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Ffi.Kernel as Kernel\n\
         bogus : Int -> Int\n\
         bogus = Kernel.kernel \"No_such_kernel_at_all\"\n\
         main = bogus 1\n"
    );
    assert_rejected("canon_user_kernel_alias_is_rejected", &src, "IPE-N0042");
}

// ── Ipe.Ffi.Js ports — raw typed Ipê↔JS transport (IPE-L0148 boundary seal) ──
//
// A port (`Js.send` / `Js.subscribe`) reuses the same seal the `CustomElement`
// boundary enforces, but on the CONCRETE inferred crossing type (a port's `a` is
// inferred, not annotated). A seal-legal port lowers through the uniform kernel
// path to the `js_send` / `js_subscribe` runtime transport — outbound
// seal-encodes the payload to the browser, inbound decodes an untrusted payload
// through the fail-closed bounded seal decoder. A `Secret` payload and an untyped
// `Value` decoder are both rejected fail-closed (IPE-L0148) — a secret must never
// cross to JS, and the untyped channel cannot be spelled.
//
// A port CALL must be REACHABLE for its lowering gate to fire, so every fixture
// wires the port into a real Web-shape TEA app (`update` / `subscriptions`), not a
// dead top-level binding (which DCE would drop before lowering).

/// A minimal Web-shape TEA app that wires a reachable `Js.send` outbound port with
/// an `Int` payload (through `update`) and a reachable `Js.subscribe` inbound port
/// with `decoder_expr` producing a value fed to `Got` (through `subscriptions`), so
/// both port lowering gates fire.
fn js_port_app(decoder_expr: &str) -> String {
    format!(
        "module Main exposing (main)\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Ffi.Js as Js\n\
         import Ipe.Json.Decode as Decode\n\
         type alias Model = {{ n : Int }}\n\
         type Msg = Tick | Got Int\n\
         init : WebReq -> ( Model, Cmd.Cmd Msg )\n\
         init _r =\n\
         \x20   ( {{ n = 0 }}, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd.Cmd Msg )\n\
         update msg model =\n\
         \x20   case msg of\n\
         \x20       Tick ->\n\
         \x20           ( model, Js.send model.n )\n\
         \x20       Got k ->\n\
         \x20           ( {{ n = k }}, Cmd.none )\n\
         view : Model -> Element Msg\n\
         view _model =\n\
         \x20   Ui.text \"ok\"\n\
         subscriptions : Model -> Sub.Sub Msg\n\
         subscriptions _model =\n\
         \x20   Js.subscribe {decoder_expr} Got\n\
         main =\n\
         \x20   Web.tea\n\
         \x20       {{ init = init, update = update, view = view, subscriptions = subscriptions\n\
         \x20       , routes = [], notFound = Tick\n\
         \x20       }}\n"
    )
}

/// A seal-LEGAL port (an `Int` payload out, an `Int` decoder in) type-checks,
/// passes the boundary seal, and lowers through the uniform kernel path to the
/// `js_send` / `js_subscribe` transport — so `ipe` ACCEPTS it (exit 0) and the
/// emitted Rust is well-formed. This is the port twin of the shipped
/// custom-element emission golden; the full `ipe`-accept ⇒ `cargo build` SEAL
/// round-trip is pinned by the `js_port` e2e golden (`webview_e2e`), and the
/// `js-port` capability disclosure by the `capabilities` suite.
#[test]
fn js_port_seal_legal_lowers_and_builds() {
    let src = js_port_app("Decode.int");
    assert_compiles("js_port_seal_legal", &src);
}

/// A `Js.subscribe` whose decoder is `Decoder Value` (an untyped JSON hole) is
/// rejected fail-closed at lowering with IPE-L0148: the untyped channel cannot be
/// spelled, so an undecoded value can never travel inward. Parse-don't-validate at
/// the trust boundary — a genuinely free-form payload must be NAMED with a declared
/// ADT, never left as `Value`. The inbound handler is typed `Value -> Msg` so the
/// program is otherwise well-typed; only the seal turns it away.
#[test]
fn js_port_subscribe_value_decoder_rejected() {
    let src = "module Main exposing (main)\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Ffi.Js as Js\n\
         import Ipe.Json.Decode as Decode\n\
         type alias Model = { n : Int }\n\
         type Msg = Tick | GotV Value\n\
         init : WebReq -> ( Model, Cmd.Cmd Msg )\n\
         init _r =\n\
         \x20   ( { n = 0 }, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd.Cmd Msg )\n\
         update _msg model =\n\
         \x20   ( model, Cmd.none )\n\
         view : Model -> Element Msg\n\
         view _model =\n\
         \x20   Ui.text \"ok\"\n\
         subscriptions : Model -> Sub.Sub Msg\n\
         subscriptions _model =\n\
         \x20   Js.subscribe Decode.value GotV\n\
         main =\n\
         \x20   Web.tea\n\
         \x20       { init = init, update = update, view = view, subscriptions = subscriptions\n\
         \x20       , routes = [], notFound = Tick\n\
         \x20       }\n";
    assert_rejected("js_port_subscribe_value", src, "IPE-L0148");
}

/// A `Js.send` whose payload is a `Secret` is rejected fail-closed at lowering with
/// IPE-L0148: a secret-tier value must NEVER be serialised across the Ipê↔JS seam.
/// The same security exclusion the custom-element seal enforces (IPE-N0039), here
/// on the concrete inferred payload type of a port.
#[test]
fn js_port_send_secret_rejected() {
    let src = "module Main exposing (main)\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Ffi.Js as Js\n\
         import Ipe.Secret as Secret\n\
         import Ipe.System as System\n\
         type alias Model = { s : Secret }\n\
         type Msg = Tick\n\
         init : WebReq -> ( Model, Cmd.Cmd Msg )\n\
         init _r =\n\
         \x20   ( { s = Secret.fromString (System.getenvOr \"K\" \"x\") }, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd.Cmd Msg )\n\
         update _msg model =\n\
         \x20   ( model, Js.send model.s )\n\
         view : Model -> Element Msg\n\
         view _model =\n\
         \x20   Ui.text \"ok\"\n\
         subscriptions : Model -> Sub.Sub Msg\n\
         subscriptions _model =\n\
         \x20   Sub.none\n\
         main =\n\
         \x20   Web.tea\n\
         \x20       { init = init, update = update, view = view, subscriptions = subscriptions\n\
         \x20       , routes = [], notFound = Tick\n\
         \x20       }\n";
    assert_rejected("js_port_send_secret", src, "IPE-L0148");
}

/// A `Js.send` whose payload is a user ADT with a `Secret` buried in one of its
/// variants (`type Payload = Wrap Secret | Empty`) is rejected fail-closed at
/// lowering with IPE-L0148: the boundary seal walks the ADT's transitive variant
/// payloads, so a secret hidden one constructor deep can never cross to JS. Absent
/// this transitive check the bare "accept every user ADT" seal oracle would admit
/// the crossing — the exact hole this pins closed.
#[test]
fn js_port_send_nested_secret_in_adt_rejected() {
    let src = "module Main exposing (main)\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Ffi.Js as Js\n\
         import Ipe.Secret as Secret\n\
         import Ipe.System as System\n\
         type Payload = Wrap Secret | Empty\n\
         type alias Model = { p : Payload }\n\
         type Msg = Tick\n\
         init : WebReq -> ( Model, Cmd.Cmd Msg )\n\
         init _r =\n\
         \x20   ( { p = Wrap (Secret.fromString (System.getenvOr \"K\" \"x\")) }, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd.Cmd Msg )\n\
         update _msg model =\n\
         \x20   ( model, Js.send model.p )\n\
         view : Model -> Element Msg\n\
         view _model =\n\
         \x20   Ui.text \"ok\"\n\
         subscriptions : Model -> Sub.Sub Msg\n\
         subscriptions _model =\n\
         \x20   Sub.none\n\
         main =\n\
         \x20   Web.tea\n\
         \x20       { init = init, update = update, view = view, subscriptions = subscriptions\n\
         \x20       , routes = [], notFound = Tick\n\
         \x20       }\n";
    assert_rejected("js_port_nested_secret_adt", src, "IPE-L0148");
}

/// A `Js.send` whose payload is a polymorphic wrapper ADT instantiated at a
/// `Secret` (`type Box a = Box a` used as `Box Secret`) is rejected fail-closed at
/// lowering with IPE-L0148: the seal instantiates the wrapper's type parameter and
/// re-checks the concrete payload, so `Box Secret` is refused even though `Box a`
/// itself is a legal shape for a non-secret `a`.
#[test]
fn js_port_send_polymorphic_wrapper_secret_rejected() {
    let src = "module Main exposing (main)\n\
         import Ipe.Tea.Web as Web\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Ffi.Js as Js\n\
         import Ipe.Secret as Secret\n\
         import Ipe.System as System\n\
         type Box a = Box a\n\
         type alias Model = { b : Box Secret }\n\
         type Msg = Tick\n\
         init : WebReq -> ( Model, Cmd.Cmd Msg )\n\
         init _r =\n\
         \x20   ( { b = Box (Secret.fromString (System.getenvOr \"K\" \"x\")) }, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd.Cmd Msg )\n\
         update _msg model =\n\
         \x20   ( model, Js.send model.b )\n\
         view : Model -> Element Msg\n\
         view _model =\n\
         \x20   Ui.text \"ok\"\n\
         subscriptions : Model -> Sub.Sub Msg\n\
         subscriptions _model =\n\
         \x20   Sub.none\n\
         main =\n\
         \x20   Web.tea\n\
         \x20       { init = init, update = update, view = view, subscriptions = subscriptions\n\
         \x20       , routes = [], notFound = Tick\n\
         \x20       }\n";
    assert_rejected("js_port_poly_wrapper_secret", src, "IPE-L0148");
}

// ===========================================================================
// Type — IPE-T####
// ===========================================================================

/// Adding an `Int` and a `String` — a plain HM unification failure.
#[test]
fn type_mismatch_int_plus_string() {
    let src = format!("{HEAD}main =\n    1 + \"two\"\n");
    assert_rejected("type_mismatch", &src, "IPE-T0001");
}

/// A declared signature contradicted by the body's type.
#[test]
fn type_signature_body_mismatch() {
    let src = format!("{HEAD}main : Int\nmain =\n    \"not an int\"\n");
    assert_rejected("type_sig_mismatch", &src, "IPE-T0001");
}

/// A higher-order kernel program: `Main` printing the length of `expr`.
fn hof_program(expr: &str) -> String {
    format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         add : Int -> Int -> Int\n\
         add a b =\n    a + b\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (List.length ({expr})))\n"
    )
}

/// `List.map add xs`: each element would be the partial application `Int -> Int`,
/// which the exact-arity runtime kernel cannot build — the callback-result
/// obligation (`hof_kernel_result`) refuses it at type time.
#[test]
fn type_list_map_curried_callback_refused() {
    let src = hof_program("List.map add [ 1, 2, 3 ]");
    assert_rejected("type_list_map_curried_callback", &src, "IPE-T0001");
}

/// A curried lambda callback (`\n -> \x -> x + n`) is the same hazard spelled inline.
#[test]
fn type_list_map_curried_lambda_refused() {
    let src = hof_program("List.map (\\n -> \\x -> x + n) [ 1, 2, 3 ]");
    assert_rejected("type_list_map_curried_lambda", &src, "IPE-T0001");
}

/// A fold whose accumulator is a function returns an arrow from its step callback.
#[test]
fn type_list_foldl_function_accumulator_refused() {
    let src = hof_program(
        "List.map (List.foldl (\\x f -> \\y -> f y + x) (\\y -> y) [ 1, 2 ]) [ 1, 2, 3 ]",
    );
    assert_rejected("type_list_foldl_function_accumulator", &src, "IPE-T0001");
}

/// Contrapositive: a plain-result callback (`\x -> x + 1`) still compiles.
#[test]
fn type_list_map_plain_callback_compiles() {
    let src = hof_program("List.map (\\x -> x + 1) [ 1, 2, 3 ]");
    assert_compiles("type_list_map_plain_callback", &src);
}

/// Contrapositive: `List.map2 add` passes both arguments at once and compiles.
#[test]
fn type_list_map2_full_arity_callback_compiles() {
    let src = hof_program("List.map2 add [ 1, 2, 3 ] [ 10, 20, 30 ]");
    assert_compiles("type_list_map2_full_arity_callback", &src);
}

/// A `List.map5` program over stored functions: four of arity `first`, the last of arity `last`.
///
/// `applyAll` calls every stored function; `mapper` is the mapper expression
/// passed to `List.map5` (`applyAll` itself, or a lambda).
fn eta_site_program(first: usize, last: usize, mapper: &str) -> String {
    let arrow = |arity: usize| vec!["Int"; arity + 1].join(" -> ");
    let def = |name: &str, arity: usize| {
        let params: Vec<String> = (0..arity).map(|i| format!("a{i}")).collect();
        format!(
            "{name} : {}\n{name} {} =\n    a0\n",
            arrow(arity),
            params.join(" ")
        )
    };
    let call = |f: &str, arity: usize| format!("{f} {}", vec!["1"; arity].join(" "));
    let body = ["p", "q", "r", "s"]
        .into_iter()
        .map(|f| call(f, first))
        .chain(std::iter::once(call("t", last)))
        .collect::<Vec<_>>()
        .join(" + ");
    let (a, b) = (arrow(first), arrow(last));
    format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         {}{}\
         applyAll : ({a}) -> ({a}) -> ({a}) -> ({a}) -> ({b}) -> Int\n\
         applyAll p q r s t =\n    {body}\n\
         useFirst : ({a}) -> Int\n\
         useFirst g =\n    {}\n\
         useLast : ({b}) -> Int\n\
         useLast g =\n    {}\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (List.length \
         (List.map5 ({mapper}) [ fa ] [ fa ] [ fa ] [ fa ] [ fb ])))\n",
        def("fa", first),
        def("fb", last),
        call("g", first),
        call("g", last),
    )
}

/// At the per-site eta ceiling: the named-mapper adapter draws 1 + 5 + 5 * 2 = 16 names.
#[test]
fn lower_named_mapper_at_eta_site_limit_compiles() {
    let src = eta_site_program(2, 2, "applyAll");
    assert_compiles("lower_named_mapper_at_eta_site_limit", &src);
}

/// One past the ceiling: 1 + 5 + 4 * 2 + 3 = 17 names is refused, never drawn.
#[test]
fn lower_named_mapper_past_eta_site_limit_refused() {
    let src = eta_site_program(2, 3, "applyAll");
    assert_rejected("lower_named_mapper_past_eta_site_limit", &src, "IPE-L0155");
}

/// Far past the ceiling (1 + 5 + 5 * 16 = 86 names) is the same typed refusal, not an internal error.
#[test]
fn lower_named_mapper_far_past_eta_site_limit_refused() {
    let src = eta_site_program(16, 16, "applyAll");
    assert_rejected(
        "lower_named_mapper_far_past_eta_site_limit",
        &src,
        "IPE-L0155",
    );
}

/// A lambda mapper passing its stored functions on at the ceiling: 4 * 3 + 4 = 16 names.
#[test]
fn lower_lambda_mapper_at_eta_site_limit_compiles() {
    let src = eta_site_program(3, 4, "\\p q r s t -> applyAll p q r s t");
    assert_compiles("lower_lambda_mapper_at_eta_site_limit", &src);
}

/// One past the ceiling for a lambda mapper: 4 * 3 + 5 = 17 names is refused.
#[test]
fn lower_lambda_mapper_past_eta_site_limit_refused() {
    let src = eta_site_program(3, 5, "\\p q r s t -> applyAll p q r s t");
    assert_rejected("lower_lambda_mapper_past_eta_site_limit", &src, "IPE-L0155");
}

/// Past the ceiling, a lambda mapper that only calls a stored function draws no names for it.
///
/// `p` is passed on (3 names), so the 16-argument `t` would reach 19; `t` is
/// only called, so it needs no adapter and the site stays at 3.
#[test]
fn lower_lambda_mapper_calling_wide_stored_function_compiles() {
    let src = eta_site_program(
        3,
        16,
        "\\p q r s t -> useFirst p + t 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1",
    );
    assert_compiles("lower_lambda_mapper_calling_wide_stored_function", &src);
}

/// The same lambda passing the wide stored function on needs 3 + 16 = 19 names and is refused.
#[test]
fn lower_lambda_mapper_passing_wide_stored_function_refused() {
    let src = eta_site_program(3, 16, "\\p q r s t -> useFirst p + useLast t");
    assert_rejected(
        "lower_lambda_mapper_passing_wide_stored_function",
        &src,
        "IPE-L0155",
    );
}

/// A `case` that does not cover every constructor is non-exhaustive.
#[test]
fn type_non_exhaustive_case() {
    let src = format!(
        "{HEAD}type Color = Red | Green | Blue\n\
         describe : Color -> Int\n\
         describe c =\n    case c of\n        Red -> 1\n        Green -> 2\n"
    );
    assert_rejected("type_non_exhaustive", &src, "IPE-T0010");
}

/// A tuple `case` whose arms use refutable list-pattern columns is still
/// exhaustiveness-checked: dropping the empty-list possibility on a
/// `( List Int, List Int )` scrutinee is non-exhaustive. The lowerer synthesises
/// a literal-tuple scrutinee for such cases, but exhaustiveness (IPE-T0010) runs
/// BEFORE lowering, so the missing `([], _)` branch is rejected, never emitted.
#[test]
fn type_non_exhaustive_tuple_refutable_column() {
    let src = format!(
        "{HEAD}firstOrNothing : ( List Int, List Int ) -> Int\n\
         firstOrNothing pair =\n    case pair of\n        ( [ x ], _ ) -> x\n"
    );
    assert_rejected("type_non_exhaustive_tuple_refutable", &src, "IPE-T0010");
}

/// A `case` over a Prelude built-in ADT (`ErrorKind` NESTED under `Maybe`) that
/// omits variants must be caught as non-exhaustive at `ipe` time (IPE-T0010),
/// not slip to cargo as E0004. Guards CO-TYPES-001 — `types::exhaust` must
/// analyse EVERY built-in union (via the shared `ipe_canon::builtins` table),
/// not just Maybe/Result. Before the fix the nested `ErrorKind` arm set was
/// skipped as an "unknown constructor" and the missing 9 variants shipped to
/// rustc.
#[test]
fn exhaust_builtin_adt_nested_nonexhaustive() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         describe : Maybe ErrorKind -> String\n\
         describe m =\n    case m of\n        \
         Just Io      -> \"io\"\n        \
         Just Network -> \"net\"\n        \
         Nothing      -> \"none\"\n\n\
         main = Io.println (describe Nothing)\n"
    );
    assert_rejected("exhaust_builtin_adt_nested", &src, "IPE-T0010");
}

/// A TOP-level `case` over a Prelude built-in ADT (`ErrorKind`) that omits
/// variants must ALSO be IPE-T0010 — not a `Diagnostic::CompilerBug` ("top
/// constructors cover 2 of 11"), the shape the pre-fix lower backstop produced.
/// Guards the second CO-TYPES-001 variant.
#[test]
fn exhaust_builtin_adt_toplevel_nonexhaustive() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         classify : ErrorKind -> String\n\
         classify k =\n    case k of\n        \
         Io      -> \"io\"\n        Network -> \"net\"\n\n\
         main = Io.println (classify Io)\n"
    );
    assert_rejected("exhaust_builtin_toplevel", &src, "IPE-T0010");
}

/// A fold over the inbound `Ipe.Browser.Geolocation.Internals` `JsMsg` that omits
/// a denial variant (`Denied`) is non-exhaustive (IPE-T0010) — the compiler-level
/// guarantee that a browser permission denial can never be silently swallowed by a
/// `case`. This is the structural half of MUST-FIX #5: the inbound ADT enumerates
/// every denial, so an incomplete fold is a type error, not a dropped frame.
#[test]
fn geolocation_inbound_fold_missing_a_denial_is_non_exhaustive() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Browser.Geolocation.Internals as Geo exposing (JsMsg(..))\n\
         describe : JsMsg -> String\n\
         describe m =\n    case m of\n        \
         Position _lat _lng _acc -> \"pos\"\n        \
         Unavailable             -> \"unavailable\"\n        \
         Timeout                 -> \"timeout\"\n\n\
         main = Io.println (describe Timeout)\n"
    );
    assert_rejected("geolocation_inbound_missing_denied", &src, "IPE-T0010");
}

/// A fold over the inbound `Ipe.Browser.Notification.Internals` `JsMsg` that omits
/// the `Denied` variant is non-exhaustive (IPE-T0010) — the same compiler-level
/// guarantee for the notification permission-denial variant: an incomplete inbound
/// fold is a type error, not a silently dropped frame.
#[test]
fn notification_inbound_fold_missing_a_denial_is_non_exhaustive() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Browser.Notification.Internals as Note exposing (JsMsg(..))\n\
         describe : JsMsg -> String\n\
         describe m =\n    case m of\n        \
         Granted     -> \"granted\"\n        \
         Shown       -> \"shown\"\n        \
         Unavailable -> \"unavailable\"\n\n\
         main = Io.println (describe Shown)\n"
    );
    assert_rejected("notification_inbound_missing_denied", &src, "IPE-T0010");
}

/// The `RequestPermission` reply vocabulary (`PermissionReply`) is a SEPARATE
/// type from the display-path `JsMsg`, so a `Shown` display acknowledgement has
/// NO representation as a permission outcome: a fold over `PermissionReply` that
/// names `Shown` is an unknown constructor (IPE-N0003), not a silently accepted
/// grant. This is the fail-closed-by-construction half of #2635 — a display ack
/// cannot be treated as a permission grant because the type cannot express it.
#[test]
fn notification_permission_reply_cannot_name_the_display_ack() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Browser.Notification.Internals as Note exposing (PermissionReply(..))\n\
         describe : PermissionReply -> String\n\
         describe r =\n    case r of\n        \
         PermGranted     -> \"granted\"\n        \
         PermDenied      -> \"denied\"\n        \
         PermUnavailable -> \"unavailable\"\n        \
         Shown           -> \"shown\"\n\n\
         main = Io.println (describe PermGranted)\n"
    );
    assert_rejected("notification_permission_reply_no_shown", &src, "IPE-N0003");
}

/// A fold over the inbound `Ipe.Browser.Storage.Internals` `JsMsg` that omits the
/// `Unavailable` variant is non-exhaustive (IPE-T0010) — the compiler-level
/// guarantee that a storage unavailability can never be silently swallowed.
#[test]
fn storage_inbound_fold_missing_unavailable_is_non_exhaustive() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Browser.Storage.Internals as Storage exposing (JsMsg(..))\n\
         describe : JsMsg -> String\n\
         describe m =\n    case m of\n        \
         Got _v  -> \"got\"\n        \
         Stored  -> \"stored\"\n        \
         Removed -> \"removed\"\n        \
         Cleared -> \"cleared\"\n\n\
         main = Io.println (describe Stored)\n"
    );
    assert_rejected("storage_inbound_missing_unavailable", &src, "IPE-T0010");
}

/// A fold over the inbound `Ipe.Browser.Vibration.Internals` `JsMsg` that omits the
/// `Unavailable` variant is non-exhaustive (IPE-T0010) — the compiler-level
/// guarantee that a vibration unavailability can never be silently swallowed.
#[test]
fn vibration_inbound_fold_missing_unavailable_is_non_exhaustive() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Browser.Vibration.Internals as Vib exposing (JsMsg(..))\n\
         describe : JsMsg -> String\n\
         describe m =\n    case m of\n        \
         Vibrated -> \"vibrated\"\n\n\
         main = Io.println (describe Vibrated)\n"
    );
    assert_rejected("vibration_inbound_missing_unavailable", &src, "IPE-T0010");
}

/// A fold over the inbound `Ipe.Browser.Share.Internals` `JsMsg` that omits the
/// `Cancelled` variant is non-exhaustive (IPE-T0010) — the compiler-level
/// guarantee that a user cancellation can never be silently swallowed.
#[test]
fn share_inbound_fold_missing_cancelled_is_non_exhaustive() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Browser.Share.Internals as Share exposing (JsMsg(..))\n\
         describe : JsMsg -> String\n\
         describe m =\n    case m of\n        \
         Shared      -> \"shared\"\n        \
         Unavailable -> \"unavailable\"\n\n\
         main = Io.println (describe Shared)\n"
    );
    assert_rejected("share_inbound_missing_cancelled", &src, "IPE-T0010");
}

/// A fold over the inbound `Ipe.Browser.Battery.Internals` `JsMsg` that omits the
/// `Unavailable` variant is non-exhaustive (IPE-T0010) — the compiler-level
/// guarantee that a battery unavailability can never be silently swallowed.
#[test]
fn battery_inbound_fold_missing_unavailable_is_non_exhaustive() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Browser.Battery.Internals as Battery exposing (JsMsg(..))\n\
         describe : JsMsg -> String\n\
         describe m =\n    case m of\n        \
         Reading _c _l _ct _dt -> \"reading\"\n\n\
         main = Io.println (describe (Reading False 1.0 0.0 0.0))\n"
    );
    assert_rejected("battery_inbound_missing_unavailable", &src, "IPE-T0010");
}

/// A fold over the inbound `Ipe.Browser.NetworkInfo.Internals` `JsMsg` that omits
/// the `Unavailable` variant is non-exhaustive (IPE-T0010) — the compiler-level
/// guarantee that a network-info unavailability can never be silently swallowed.
#[test]
fn network_info_inbound_fold_missing_unavailable_is_non_exhaustive() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Browser.NetworkInfo.Internals as Net exposing (JsMsg(..))\n\
         describe : JsMsg -> String\n\
         describe m =\n    case m of\n        \
         Reading _t _d _r _s -> \"reading\"\n\n\
         main = Io.println (describe (Reading \"4g\" 10.0 50.0 False))\n"
    );
    assert_rejected(
        "network_info_inbound_missing_unavailable",
        &src,
        "IPE-T0010",
    );
}

// NOTE: IPE-T0011 (redundant case branch) is intentionally `Severity::Warning`
// (see `types::exhaust` — "collect it but do not abort"), so a redundant arm
// does NOT reject compilation. It is therefore out of scope for a
// rejection-suite; it belongs to a warnings test, not a negative gate.

/// A record accessed on a field it does not have.
#[test]
fn type_record_no_such_field() {
    let src = format!("{HEAD}main =\n    let r = {{ x = 1 }} in\n    r.y\n");
    assert_rejected("type_no_such_field", &src, "IPE-T0012");
}

/// A field the record settled through a higher-order kernel's callback result
/// does not have: waiting on the result variable never invents the field.
#[test]
fn type_field_missing_after_hof_result() {
    let src = format!(
        "{HEAD}import Ipe.Maybe\n\n\
         main =\n    Maybe.map (\\u -> u.nope) (Maybe.map (\\e -> e.unit) \
         (Just {{ unit = {{ name = \"x\" }} }}))\n"
    );
    assert_rejected("type_field_missing_after_hof_result", &src, "IPE-T0012");
}

/// A callback result that settles to `Int` has no field: waiting on the
/// result variable ends in a decided "no field", never an acceptance.
#[test]
fn type_field_on_hof_result_pinned_to_int() {
    let src = format!(
        "{HEAD}import Ipe.Maybe\n\n\
         main =\n    Maybe.map (\\u -> u.name) (Maybe.map (\\e -> e.unit) (Just {{ unit = 3 }}))\n"
    );
    assert_rejected("type_field_on_hof_result_pinned_to_int", &src, "IPE-T0012");
}

/// A record update on a callback result that settles to `Int` is a decided
/// "no field", never a deferral that runs out.
#[test]
fn type_update_on_hof_result_pinned_to_int() {
    let src = format!(
        "{HEAD}import Ipe.Maybe\n\n\
         main =\n    Maybe.map (\\u -> {{ u | name = 1 }}) \
         (Maybe.map (\\e -> e.unit) (Just {{ unit = 3 }}))\n"
    );
    assert_rejected("type_update_on_hof_result_pinned_to_int", &src, "IPE-T0012");
}

/// The nested spelling constrains the outer callback before the inner one;
/// the outer read waits for the inner result instead of refusing.
#[test]
fn type_field_access_nested_list_map_compiles() {
    let src = format!(
        "{HEAD}\
import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String

names : List String
names =
    List.map (\\u -> u.name) (List.map (\\e -> e.unit) [ {{ unit = {{ name = \"x\" }} }} ])

main : Task Error ()
main =
    Io.println (String.join \",\" names)
"
    );
    assert_compiles("type_field_access_nested_list_map", &src);
}

/// A field access whose result is its own base is an infinite type (the
/// occurs check), never a cyclic record the read-back trips over.
#[test]
fn type_self_referential_field_access() {
    let src = format!("{HEAD}g r =\n    g r.next\n\nmain =\n    0\n");
    assert_rejected("type_self_referential_field_access", &src, "IPE-T0002");
}

/// An equality-constrained variable pinned to a list of itself is an infinite
/// type, never a solver spin to the step budget.
#[test]
fn type_super_occurs_check() {
    let src = format!("{HEAD}f a =\n    a == [ a ]\n\nmain =\n    0\n");
    assert_rejected("type_super_occurs_check", &src, "IPE-T0002");
}

/// A field read on a value a lambda returned through `Maybe.map` type-checks
/// once the record flows in from `List.find`'s argument.
#[test]
fn type_field_access_hof_result_compiles() {
    let src = format!(
        "{HEAD}\
import Ipe.Io as Io
import Ipe.List as List
import Ipe.Maybe as Maybe
import Ipe.Task as Task

ok : Task Error Bool
ok =
    do
        r <- Task.succeed {{ units = [ {{ uid = \"a\", unit = {{ name = \"x\" }} }} ] }}
        Task.succeed
            (case Maybe.map (\\e -> e.unit) (List.find (\\e -> e.uid == \"a\") r.units) of
                Just u ->
                    u.name == \"x\"

                Nothing ->
                    False
            )

main : Task Error ()
main =
    do
        found <- ok
        Io.println (if found then \"found\" else \"missing\")
"
    );
    assert_compiles("type_field_access_hof_result", &src);
}

/// A constructor pattern binding the wrong number of payload fields.
#[test]
fn type_ctor_pattern_wrong_arity() {
    let src = format!(
        "{HEAD}type Box = Box Int\n\
         unwrap : Box -> Int\n\
         unwrap b =\n    case b of\n        Box x y -> x\n"
    );
    assert_rejected("type_ctor_pat_arity", &src, "IPE-T0013");
}

/// A parameter pattern that is refutable (a constructor pattern in a function
/// head, where an irrefutable binder is required). `f (Just x) = x` cannot bind
/// every input, so the parameter position rejects it.
#[test]
fn type_refutable_param_pattern() {
    let src = format!(
        "{HEAD}f : Maybe Int -> Int\n\
         f (Just x) =\n    x\n\
         main = f (Just 1)\n"
    );
    assert_rejected("type_refutable_param", &src, "IPE-T0015");
}

/// More parameters than the signature's arrow chain describes.
#[test]
fn type_too_many_params() {
    let src = format!(
        "{HEAD}f : Int -> Int\n\
         f a b =\n    a\n\
         main = f 1\n"
    );
    assert_rejected("type_too_many_params", &src, "IPE-T0004");
}

/// A record update on a nominal built-in type. The field IS readable
/// (`p.message`), but a nominal builtin has no user-writable update form — the
/// dedicated IPE-T0017, distinct from the "no such field" IPE-T0012.
#[test]
fn type_record_update_on_builtin() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         f : PanicInfo -> PanicInfo\n\
         f p =\n    {{ p | message = \"x\" }}\n\
         main =\n    Io.println \"never\"\n"
    );
    assert_rejected("type_update_builtin", &src, "IPE-T0017");
}

// ===========================================================================
// Effect boundary + secret + event-handler gates
// ===========================================================================

/// An `Ipe.Html.Events` handler whose payload shape is wrong (a `Bool` handler
/// on a `String`-payload event) is a type mismatch, never an exit-0 deferral.
#[test]
fn effect_illtyped_event_handler() {
    let src = format!(
        "{HEAD}import Ipe.Html as Html\n\
         import Ipe.Html.Events as Event\n\
         type Msg = SetChecked Bool\n\
         view : Html.Html Msg\n\
         view =\n    Html.input [ Event.onInput (\\b -> SetChecked b) ] []\n\
         main = 1\n"
    );
    assert_rejected("effect_illtyped_event", &src, "IPE-T0001");
}

/// A `Secret` concatenated with `++` into a plain `String` — `Secret` does not
/// satisfy the append obligation, so the accidental-leak path is a compile-time
/// type mismatch, never a silent stringification of a secret.
#[test]
fn effect_secret_concat_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Secret as Secret\n\
         main =\n    \"using key \" ++ Secret.fromString \"sk_live_abc123\"\n"
    );
    assert_rejected("effect_secret_concat", &src, "IPE-T0001");
}

/// A `Secret` in a `Ipe.Web` app Model must be rejected — `Secret` is non-serde
/// by design, so it can never round-trip through the session store. IPE-L0120
/// (Model not admissible) at compile time, never a runtime session-store leak.
#[test]
fn effect_secret_in_live_model() {
    let src = "module Main exposing (main)\n\
         import Ipe.Secret as Secret\n\
         import Ipe.System as System\n\
         import Ipe.Tea.Web exposing (tea)\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         \n\
         type Page = HomePage\n\
         type Msg = Noop\n\
         type alias Model = { count : Int, apiKey : Secret }\n\
         \n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( { count = 0, apiKey = Secret.fromString (System.getenvOr \"K\" \"sk_live_x\") }, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model = ( model, Cmd.none )\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.none\n\
         view : Model -> Element Msg\n\
         view _model = Ui.text \"hi\"\n\
         \n\
         main =\n\
         \x20   tea\n\
         \x20       { init = init\n\
         \x20       , update = update\n\
         \x20       , view = view\n\
         \x20       , subscriptions = subscriptions\n\
         \x20       , routes = []\n\
         \x20       , notFound = HomePage\n\
         \x20       }\n";
    assert_rejected("effect_secret_live_model", src, "IPE-L0120");
}

// ===========================================================================
// Target capability gate (--target wasm) — IPE-N0029 / IPE-L0129
// ===========================================================================

/// A server-only kernel (`File.readFile`) named under `--target wasm` has no
/// browser denotation — IPE-N0029 at compile time, never a cargo failure.
#[test]
fn wasm_server_only_kernel_rejected() {
    let src = format!(
        "{HEAD}import Ipe.File as File\n\
         import Ipe.Path as Path\n\
         import Ipe.Task as Task\n\
         main =\n\
         \x20   case Path.fromString \"/etc/passwd\" of\n\
         \x20       Ok p -> File.readFile p\n\
         \x20       Err e -> Task.fail e\n"
    );
    assert_rejected_wasm("wasm_server_only_kernel", &src, "IPE-N0029");
}

/// The same server-only program builds cleanly for the NATIVE target — the gate
/// is target-keyed, not a global ban. (Positive control for the wasm gate.)
#[test]
fn wasm_server_only_kernel_native_ok() {
    let src = format!(
        "{HEAD}import Ipe.File as File\n\
         import Ipe.Path as Path\n\
         import Ipe.Task as Task\n\
         main =\n\
         \x20   case Path.fromString \"/etc/passwd\" of\n\
         \x20       Ok p -> File.readFile p\n\
         \x20       Err e -> Task.fail e\n"
    );
    if let Outcome::Rejected(got) = compile("wasm_native_control", &src, Target::Native) {
        assert!(
            false_marker(),
            "the native build of a server-only program must stay green, got rejection {got}"
        );
    }
}

// ===========================================================================
// Lowering / not-yet-supported — IPE-L####
// ===========================================================================

/// A `Float` used as a `Dict` key has no valid backend rendering (`f64` is not
/// `Ord`/`Hash` on the Rust backend) — IPE-L0117.
#[test]
fn lower_float_dict_key() {
    let src = format!(
        "{HEAD}import Ipe.Dict as Dict\n\
         main =\n    Dict.insert 1.5 \"x\" Dict.empty\n"
    );
    assert_rejected("lower_float_dict_key", &src, "IPE-L0117");
}

/// A `Float` used as a `Set` element — same backend restriction, IPE-L0117.
#[test]
fn lower_float_set_element() {
    let src = format!(
        "{HEAD}import Ipe.Set as Set\n\
         main =\n    Set.insert 1.5 Set.empty\n"
    );
    assert_rejected("lower_float_set_elem", &src, "IPE-L0117");
}

// A `List` element / `Dict` value CAN store a function on the `Arc<dyn Fn>`
// carrier. A higher-order kernel whose every stored-element mapper parameter the
// lowerer re-carriers to that `Arc` (derived from the kernel scheme) is sound
// over it and must compile; a kernel that compares/orders its element, or feeds
// a stored element into a parameter the lowerer cannot re-carrier (`Dict.update`'s
// `Maybe v`, every `Set` higher-order kernel), must fail closed at `ipe` time
// with IPE-L0134 — never `ipe`-accept then `cargo`-fail (THE SEAL).

/// `List.member` over a `List (Int -> Int)`: the element is a stored function,
/// which is `Clone` but not `PartialEq` — membership needs `==` on the element,
/// so it must fail closed with IPE-L0134 (the equality-requiring case).
#[test]
fn lower_list_member_over_function_element_gated() {
    let src = format!(
        "{HEAD}import Ipe.List\n\
         steps : List (Int -> Int)\n\
         steps =\n    [ \\n -> n + 1, \\n -> n * 2 ]\n\
         main =\n\
         \x20   let found = List.member (\\n -> n + 1) steps\n\
         \x20   in\n\
         \x20   steps\n"
    );
    assert_rejected("lower_list_member_fn_elem", &src, "IPE-L0134");
}

/// `Dict.map` over a `Dict String (Int -> Int)`: the mapper's value parameter
/// binds the stored function and is re-carriered to `Arc` — accepted.
#[test]
fn lower_dict_map_over_function_value_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Dict as Dict\n\
         import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         table : Dict String (Int -> Int)\n\
         table =\n    Dict.fromList [ ( \"inc\", \\n -> n + 1 ) ]\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (List.foldl (\\x acc -> x + acc) 0 (Dict.values (Dict.map (\\_ f -> f 1) table))))\n"
    );
    assert_compiles("lower_dict_map_fn_value", &src);
}

/// `Dict.foldl` over a function-valued dict: the fold closure's value
/// parameter binds the stored function on `Arc` — accepted.
#[test]
fn lower_dict_foldl_over_function_value_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Dict as Dict\n\
         import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         table : Dict String (Int -> Int)\n\
         table =\n    Dict.fromList [ ( \"inc\", \\n -> n + 1 ) ]\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (Dict.foldl (\\_ f acc -> f acc) 0 table))\n"
    );
    assert_compiles("lower_dict_foldl_fn_value", &src);
}

/// `Dict.filter` over a function-valued dict: the predicate's value parameter
/// binds the stored function on `Arc` — accepted.
#[test]
fn lower_dict_filter_over_function_value_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Dict as Dict\n\
         import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         table : Dict String (Int -> Int)\n\
         table =\n    Dict.fromList [ ( \"inc\", \\n -> n + 1 ) ]\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (Dict.size (Dict.filter (\\_ f -> f 0 > 0) table)))\n"
    );
    assert_compiles("lower_dict_filter_fn_value", &src);
}

/// `Dict.partition` over a function-valued dict: same re-carriered value
/// parameter — accepted.
#[test]
fn lower_dict_partition_over_function_value_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Dict as Dict\n\
         import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         table : Dict String (Int -> Int)\n\
         table =\n    Dict.fromList [ ( \"inc\", \\n -> n + 1 ) ]\n\
         kept : Dict String (Int -> Int)\n\
         kept =\n    case Dict.partition (\\_ f -> f 0 > 0) table of\n        ( yes, _ ) ->\n            yes\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (Dict.size kept))\n"
    );
    assert_compiles("lower_dict_partition_fn_value", &src);
}

/// `List.sortBy` over a `List (Int -> Int)`: the key extractor's parameter
/// binds the stored function on `Arc` — accepted.
#[test]
fn lower_list_sort_by_over_function_element_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         steps : List (Int -> Int)\n\
         steps =\n    [ \\n -> n + 1, \\n -> n * 2 ]\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (List.foldl (\\f acc -> f acc) 0 (List.sortBy (\\f -> f 0) steps)))\n"
    );
    assert_compiles("lower_list_sort_by_fn_elem", &src);
}

/// `List.map5` with a named mapper over five `List (Int -> Int -> Int -> Int)`:
/// the mapper wrap would draw 21 eta symbols (holder, five parameters, five
/// three-parameter demote adapters), past the per-site ceiling, so it is
/// refused with IPE-L0155 before any symbol is drawn.
#[test]
fn lower_list_map5_named_mapper_over_function_elements_refused() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         steps : List (Int -> Int -> Int -> Int)\n\
         steps =\n    [ \\a b c -> a + b + c ]\n\
         pick : (Int -> Int -> Int -> Int) -> (Int -> Int -> Int -> Int) -> (Int -> Int -> Int -> Int) -> (Int -> Int -> Int -> Int) -> (Int -> Int -> Int -> Int) -> Int\n\
         pick _ _ _ _ _ =\n    0\n\
         results : List Int\n\
         results =\n    List.map5 pick steps steps steps steps steps\n\
         count : Int\n\
         count =\n    List.length results\n\
         label : String\n\
         label =\n    String.fromInt count\n\
         main : Task Error ()\n\
         main =\n    Io.println label\n"
    );
    assert_rejected("lower_list_map5_named_fn_elem", &src, "IPE-L0155");
}

/// A point-free `List.map2 pick fs` over stored functions of `arity`
/// arguments: the supplied named mapper's wrap (1 + 2 + `arity` names) and the
/// residual `ys` parameter (1 name) are charged to the one call site.
fn partial_map2_program(arity: usize) -> String {
    let arrow = vec!["Int"; arity + 1].join(" -> ");
    let params: Vec<String> = (0..arity).map(|i| format!("a{i}")).collect();
    format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         wide : {arrow}\n\
         wide {} =\n    a0\n\
         fs : List ({arrow})\n\
         fs =\n    [ wide ]\n\
         pick : ({arrow}) -> Int -> Int\n\
         pick _ n =\n    n\n\
         partial : List Int -> List Int\n\
         partial =\n    List.map2 pick fs\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (List.length (partial [ 1 ])))\n",
        params.join(" ")
    )
}

/// At the per-site eta ceiling: 1 + 2 + 12 wrap names plus 1 residual = 16.
#[test]
fn lower_partial_map2_wrap_and_residual_at_eta_site_limit_compiles() {
    let src = partial_map2_program(12);
    assert_compiles("lower_partial_map2_at_eta_site_limit", &src);
}

/// One past the ceiling: the wrap alone (1 + 2 + 13 = 16) fits, but the
/// residual parameter drawn at the same site makes 17, refused.
#[test]
fn lower_partial_map2_wrap_and_residual_past_eta_site_limit_refused() {
    let src = partial_map2_program(13);
    assert_rejected("lower_partial_map2_past_eta_site_limit", &src, "IPE-L0155");
}

/// `Dict.update` over a function-valued dict: its updater reads the stored
/// value wrapped in `Maybe`, a parameter the lowerer does not re-carrier —
/// the frontier stays open, so it must fail closed with IPE-L0134.
#[test]
fn lower_dict_update_over_function_value_gated() {
    let src = format!(
        "{HEAD}import Ipe.Dict as Dict\n\
         import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         table : Dict String (Int -> Int)\n\
         table =\n    Dict.fromList [ ( \"inc\", \\n -> n + 1 ) ]\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (Dict.size (Dict.update \"inc\" (\\m -> m) table)))\n"
    );
    assert_rejected("lower_dict_update_fn_value", &src, "IPE-L0134");
}

/// A PARTIAL `Dict.update` over a function-valued dict, bound point-free:
/// the collection arrives only through the residual closure, so the gate reads
/// the callee's solved arrow, and the open frontier still fails closed with
/// IPE-L0134. Every top-level def is lowered, referenced from `main` or not.
#[test]
fn lower_dict_update_partial_over_function_value_gated() {
    let src = format!(
        "{HEAD}import Ipe.Dict as Dict\n\
         import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.String as String\n\
         table : Dict String (Int -> Int)\n\
         table =\n    Dict.fromList [ ( \"inc\", \\n -> n + 1 ) ]\n\
         upd : Dict String (Int -> Int) -> Dict String (Int -> Int)\n\
         upd =\n    Dict.update \"inc\" (\\m -> m)\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (Dict.size table))\n"
    );
    assert_rejected("lower_dict_update_partial_fn_value", &src, "IPE-L0134");
}

/// A `Set` element is `Ord`-bound, so it never holds a function and no `Set`
/// mapper parameter binds a stored function: `Set.foldl` threading a
/// `List (Int -> Int)` accumulator compiles.
#[test]
fn lower_set_foldl_with_function_accumulator_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.List\n\
         import Ipe.Set as Set\n\
         import Ipe.String as String\n\
         steps : List (Int -> Int)\n\
         steps =\n    [ \\n -> n + 1, \\n -> n * 2 ]\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (List.length (Set.foldl (\\_ acc -> acc) steps (Set.fromList [ 1, 2 ]))))\n"
    );
    assert_compiles("lower_set_foldl_fn_acc", &src);
}

/// A generic union `Wrap a` at a non-`Clone` concrete payload (`Task Error Int`)
/// reused across two value-consuming positions: the union derives
/// `Clone where T: Clone`, but a `Task` is never `Clone`, so the value-reuse
/// rewrite cannot duplicate it — fail closed with IPE-L0135 rather than emit
/// Rust that fails cargo (E0382/E0277) after `ipe` exit 0.
#[test]
fn lower_union_task_reuse_gated() {
    let src = format!(
        "{HEAD}import Ipe.Task as Task\n\
         type Wrap a = Wrap a\n\
         unwrap : Wrap a -> a\n\
         unwrap w =\n\
         \x20   case w of\n\
         \x20       Wrap x -> x\n\
         pair : Wrap (Task Error Int) -> ( Task Error Int, Task Error Int )\n\
         pair w =\n    ( unwrap w, unwrap w )\n\
         main =\n    pair (Wrap (Task.succeed 7))\n"
    );
    assert_rejected("lower_union_task_reuse", &src, "IPE-L0135");
}

/// CONTRAPOSITIVE: a function-valued `Dict` used only through move/clone kernels
/// (`Dict.get`, projected out and applied) is sound over the `Arc` carrier and
/// must still compile — the fail-closed gate rejects only the open-frontier
/// higher-order kernels, never the storable-value path (the `dict_fn_dispatch`
/// golden shape).
#[test]
fn lower_dict_function_value_get_and_apply_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Dict as Dict\n\
         import Ipe.Io as Io\n\
         import Ipe.String as String\n\
         table : Dict String (Int -> Int)\n\
         table =\n    Dict.fromList [ ( \"inc\", \\n -> n + 1 ) ]\n\
         applyNamed : String -> Int -> Int\n\
         applyNamed name x =\n\
         \x20   case Dict.get name table of\n\
         \x20       Just f ->\n\
         \x20           f x\n\
         \n\
         \x20       Nothing ->\n\
         \x20           x\n\
         main : Task Error ()\n\
         main =\n    Io.println (String.fromInt (applyNamed \"inc\" 41))\n"
    );
    assert_compiles("lower_dict_fn_value_get_apply", &src);
}

// A program's `main` is the single effect it runs, so it must be a `Task Error ()`
// — written directly (a script) or produced by an app entry (`Web.tea` /
// `Tui.tea` / `Cli.tea`, each of which is itself a `Task Error ()`).
// A `main` of any other type (an `Int`, a `String`, a function) has no effect to
// run: the emitted entry wraps `main` in the runtime's single run site, which needs
// a `Task`, so a non-`Task` `main` would ship a crate that cannot build. That must
// fail closed at `ipe` time with IPE-L0136, never `ipe`-accept then cargo-fail on
// `block_on(<non-task>)` (THE SEAL for the program entry).

/// A `main` annotated `Int` is a value, not an effect — rejected with IPE-L0136
/// rather than accepted and emitted as `block_on(i64)` (which cannot build).
#[test]
fn lower_non_task_main_int_rejected() {
    let src = format!("{HEAD}main : Int\nmain = 42\n");
    assert_rejected("lower_non_task_main_int", &src, "IPE-L0136");
}

/// A `main` annotated `String` is likewise a value, not an effect — IPE-L0136.
#[test]
fn lower_non_task_main_string_rejected() {
    let src = format!("{HEAD}main : String\nmain = \"hello\"\n");
    assert_rejected("lower_non_task_main_string", &src, "IPE-L0136");
}

/// A `main` that is a bare function has no effect to run — IPE-L0136.
#[test]
fn lower_non_task_main_function_rejected() {
    let src = format!("{HEAD}main = \\x -> x\n");
    assert_rejected("lower_non_task_main_function", &src, "IPE-L0136");
}

/// A `main` that TAKES a parameter is a function, not the single effect the
/// program runs — the emitted entry calls `ipe_main()` with no arguments, so a
/// parameterised `main` (even one that returns a `Task`) cannot build. IPE-L0136.
#[test]
fn lower_parameterised_main_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         main : Int -> Task Error ()\n\
         main n =\n    Io.println \"hi\"\n"
    );
    assert_rejected("lower_parameterised_main", &src, "IPE-L0136");
}

/// CONTRAPOSITIVE: a `main : Task Error ()` script is a runnable entry and must be
/// accepted — the gate rejects only a `main` that is NOT a `Task` (nor an app
/// entry, which is itself a `Task`), never a genuine effect entry.
#[test]
fn lower_task_main_script_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         main : Task Error ()\n\
         main =\n    Io.println \"hello\"\n"
    );
    assert_compiles("lower_task_main_script", &src);
}

// An effect is a `Task`: it runs only through `Task.run`, or by being sequenced
// inside a function whose own return type is a `Task`. The parser rejects
// user-written `let _ = e` at source level (IPE-P0064). The do-desugared
// synthetic `LetBinding { pat: PAnything }` bypasses IPE-P0064, so the
// IPE-L0141 gate in the lowerer is the last line of defence for bare-run
// effects in a sync `do` block. Both paths are covered below.

/// A `Task`-typed effect (`Io.println`) discarded with `let _ = …` is rejected
/// at parse time (IPE-P0064) before lower can assess the sync/Task context.
#[test]
fn lower_effect_discard_in_sync_context_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         shout : String -> String\n\
         shout s =\n\
         \x20   let _ = Io.println s\n\
         \x20   in\n\
         \x20   s\n\
         main : Task Error ()\n\
         main =\n    Io.println (shout \"hi\")\n"
    );
    assert_rejected("lower_effect_discard_sync", &src, "IPE-P0064");
}

/// CONTRAPOSITIVE: sequencing an effect via a `do` bare-run line (the sanctioned
/// form) inside a `Task`-returning `main` still compiles. The do-desugared
/// synthetic `LetBinding { pat: PAnything }` is not gated by IPE-P0064 — only
/// user-written `let _ = e in rest` is.
#[test]
fn lower_effect_discard_in_task_context_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         main : Task Error ()\n\
         main =\n\
         \x20   do\n\
         \x20       Io.println \"step one\"\n\
         \x20       Io.println \"step two\"\n"
    );
    assert_compiles("lower_effect_discard_task", &src);
}

/// A bare-run effect in a `do` block whose result is pure (no `Task Error ()`
/// annotation, body evaluates to `()`) must be rejected as IPE-L0141. The
/// do-desugar produces a synthetic `LetBinding { pat: PAnything, body: task }`
/// that bypasses IPE-P0064, so the L0141 gate in the lowerer is the last
/// line of defence.
///
/// Regression guard: previously the synthetic outer `Let` node shared its span
/// with the inner task expression, causing the type-checker's region table to
/// overwrite the task's `Task`-typed region entry with the continuation type
/// (`()`). `is_task_typed` then returned `false` and the effect was silently
/// dropped instead of raising L0141.
#[test]
fn lower_sync_do_bare_effect_run_rejected() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         main =\n\
         \x20   do\n\
         \x20       Io.println \"hello\"\n\
         \x20       ()\n"
    );
    assert_rejected("lower_sync_do_bare_effect_run", &src, "IPE-L0141");
}

/// CONTRAPOSITIVE: a `do` block whose non-final statements are PURE lets
/// (no Task type) followed by a pure result must still compile cleanly —
/// the L0141 gate must not fire on pure discards.
#[test]
fn lower_sync_do_pure_lets_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.String\n\
         main : Task Error ()\n\
         main =\n\
         \x20   do\n\
         \x20       x = String.fromInt 42\n\
         \x20       Io.println x\n"
    );
    assert_compiles("lower_sync_do_pure_lets", &src);
}

/// CONTRAPOSITIVE: a `do` block with a Task-annotated `main` where the final
/// statement IS the effect compiles cleanly — the effect is the body, not
/// a discarded non-final statement.
#[test]
fn lower_task_do_effect_as_body_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         main : Task Error ()\n\
         main =\n\
         \x20   do\n\
         \x20       Io.println \"first\"\n\
         \x20       Io.println \"second\"\n"
    );
    assert_compiles("lower_task_do_effect_as_body", &src);
}

/// CONTRAPOSITIVE: `Debug.log` is the sanctioned debug print — it returns its
/// value (`String -> a -> a`), not a `Task`, so it is usable inside a pure
/// function without escaping the effect discipline. A development build accepts
/// it (`ipe release` rejects it with IPE-L0140, covered separately).
#[test]
fn lower_debug_log_in_sync_context_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Debug as Debug\n\
         shout : String -> String\n\
         shout s =\n    Debug.log \"shout\" s\n\
         main : Task Error ()\n\
         main =\n    Io.println (shout \"hi\")\n"
    );
    assert_compiles("lower_debug_log_sync", &src);
}

/// CONTRAPOSITIVE: `Debug.todo` is accepted in a development build — `String ->
/// a` diverges at runtime but compiles anywhere.  `ipe release` gates it with
/// IPE-L0140 (covered in the release-gate suite).
#[test]
fn lower_debug_todo_compiles_in_dev_build() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Debug as Debug\n\
         describe : Int -> String\n\
         describe n =\n    Debug.todo \"not implemented\"\n\
         main : Task Error ()\n\
         main =\n    Io.println (describe 1)\n"
    );
    assert_compiles("lower_debug_todo_dev", &src);
}

/// `ipe release` (production flag) must reject `Debug.todo` with IPE-L0140 —
/// membership in `Ipe.Debug` is the gate, regardless of app kind or target.
/// Companion to [`lower_debug_todo_compiles_in_dev_build`]: the same program
/// that a dev build accepts must be blocked by a production build.
#[test]
fn release_rejects_debug_todo() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Debug as Debug\n\
         describe : Int -> String\n\
         describe n =\n    Debug.todo \"not ready\"\n\
         main : Task Error ()\n\
         main =\n    Io.println (describe 1)\n"
    );
    assert_rejected_production("release_rejects_debug_todo", &src, "IPE-L0140");
}

/// `ipe release` (production flag) must reject `Debug.explain` with IPE-L0140 —
/// module membership alone gates it, independent of `Debug.todo`. The attribute
/// is reachable from `main` through the rendered `Web.tea` view, so the
/// kernel-usage scan sees it and sets `uses_debug`. Dev build accepts it (a
/// dev-only construct is permitted by `build` / `run`); production blocks it.
#[test]
fn release_rejects_debug_explain() {
    let src = explain_reachable_src();
    assert_rejected_production("release_rejects_debug_explain", &src, "IPE-L0140");
}

/// The same reachable-`Debug.explain` program a `release` build rejects builds
/// cleanly under a development build — the gate is production-only.
#[test]
fn dev_build_accepts_reachable_debug_explain() {
    let src = explain_reachable_src();
    assert_compiles("dev_build_accepts_reachable_debug_explain", &src);
}

/// A `Debug._` catch-all arm over a closed union COMPILES in a development
/// build: it satisfies exhaustiveness like `_` and is exempt from the
/// closed-union catch-all error (IPE-T0018), letting a developer defer some
/// variants. It needs no `import Ipe.Debug` — the pattern is a reserved
/// spelling. Companion to [`release_rejects_debug_wildcard_pattern`].
#[test]
fn dev_build_accepts_debug_wildcard_pattern() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         type Color = Red | Green | Blue\n\
         name : Color -> String\n\
         name c =\n    case c of\n        Red ->\n            \"red\"\n\n        Debug._ ->\n            \"todo\"\n\
         main : Task Error ()\n\
         main =\n    Io.println (name Green)\n"
    );
    assert_compiles("dev_build_accepts_debug_wildcard_pattern", &src);
}

/// `ipe release` (production flag) must reject a reachable `Debug._` catch-all
/// with IPE-L0140 — the pattern lowers to a plain wildcard, but the canon scan
/// marks the module `uses_debug`, so the SAME production gate that turns back
/// `Debug.log` / `Debug.todo` / `Debug.explain` turns this back too. The
/// dev-only escape must never ship in a release binary.
#[test]
fn release_rejects_debug_wildcard_pattern() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         type Color = Red | Green | Blue\n\
         name : Color -> String\n\
         name c =\n    case c of\n        Red ->\n            \"red\"\n\n        Debug._ ->\n            \"todo\"\n\
         main : Task Error ()\n\
         main =\n    Io.println (name Green)\n"
    );
    assert_rejected_production("release_rejects_debug_wildcard_pattern", &src, "IPE-L0140");
}

/// A bare `_ ->`-only catch-all over a closed union is rejected in BOTH build
/// postures (it is IPE-T0018, an ordinary type error, not a build-posture
/// gate). Pinning it at the CLI level proves the error is not swallowed by the
/// warning channel — a developer sees the failure at `ipe dev build` / `type-check`.
#[test]
fn bare_wildcard_over_closed_union_is_rejected_at_cli() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         type Color = Red | Green | Blue\n\
         name : Color -> String\n\
         name c =\n    case c of\n        _ ->\n            \"other\"\n\
         main : Task Error ()\n\
         main =\n    Io.println (name Green)\n"
    );
    assert_rejected(
        "bare_wildcard_over_closed_union_is_rejected_at_cli",
        &src,
        "IPE-T0018",
    );
}

/// A `Debug.explain` in genuinely DEAD code (a top-level binding never reachable
/// from `main`) ships nothing — it is DCE'd — so even a production build accepts
/// it. Only a REACHABLE dev-only construct is rejected, mirroring `Debug.todo`.
#[test]
fn release_accepts_dead_debug_explain() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Debug as Debug\n\
         unused : Element msg\n\
         unused =\n    Ui.el [ Debug.explain ] (Ui.text \"hi\")\n\
         main : Task Error ()\n\
         main =\n    Io.println \"ok\"\n"
    );
    match compile_production("release_accepts_dead_debug_explain", &src) {
        Outcome::Accepted(how) if how.starts_with("compiled successfully") => {}
        Outcome::Accepted(how) => assert!(
            false_marker(),
            "release_accepts_dead_debug_explain: expected a clean compile, \
             got a non-pipeline failure ({how})"
        ),
        Outcome::Rejected(got) => assert!(
            false_marker(),
            "release_accepts_dead_debug_explain: a DEAD Debug.explain must be \
             DCE'd and accepted, but ipe REJECTED it with {got}"
        ),
    }
}

/// A rendered `Web.tea` view carrying `Debug.explain` on an element — the
/// attribute is reachable from `main` through the app config record's `view`
/// field. Shared by the reject/accept companions above.
fn explain_reachable_src() -> String {
    format!(
        "{HEAD}import Ipe.Tea.Web as Web\n\
         import Ipe.Ui as Ui\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Debug as Debug\n\
         type Msg = Noop\n\
         type alias Model = {{}}\n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( {{}}, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model = ( model, Cmd.none )\n\
         view : Model -> Element Msg\n\
         view _model = Ui.el [ Debug.explain ] (Ui.text \"hi\")\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.none\n\
         main =\n    \
         Web.tea {{ init = init, update = update, view = view, subscriptions = subscriptions, routes = [], notFound = Noop }}\n"
    )
}

/// A `case` missing an arm is non-exhaustive (IPE-T0010) even when another arm
/// contains `Debug.todo`. `todo` is a value-level expression that inhabits any
/// type; it is NOT a wildcard pattern and does NOT satisfy exhaustiveness.
#[test]
fn case_with_todo_arm_still_requires_all_constructors() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Debug as Debug\n\
         type Color = Red | Green | Blue\n\
         describe : Color -> String\n\
         describe c =\n\
         \x20   case c of\n\
         \x20       Red   -> \"done\"\n\
         \x20       Green -> Debug.todo \"pending\"\n\
         main : Task Error ()\n\
         main =\n    Io.println (describe Red)\n"
    );
    assert_rejected("case_todo_does_not_excuse_missing_arm", &src, "IPE-T0010");
}

/// The applicative record-codec builder seed — `object ctor` for a `Builder`
/// wrapping a `{} -> Decoder ctor` factory — routes a curried constructor
/// through a decoder field by a type variable. The generic accumulator emits a
/// `Clone`-bounded carrier the boxed constructor cannot satisfy, so it must
/// fail closed with IPE-L0107 (the sanctioned form is the direct
/// `Decode.succeed ctor |> Pipeline.required …` pipeline, covered by the
/// `lower_pipeline_curried_constructor_compiles` contrapositive below).
#[test]
fn lower_codec_builder_seed_fn_through_type_var_gated() {
    let src = format!(
        "{HEAD}import Ipe.Json.Encode as Encode\n\
         import Ipe.Json.Decode as Decode\n\
         type Builder a\n\
         \x20   = Builder\n\
         \x20       {{ enc : a -> Value\n\
         \x20       , dec : Decoder a\n\
         \x20       }}\n\
         object : ctor -> Builder ctor\n\
         object ctor =\n\
         \x20   Builder\n\
         \x20       {{ enc = \\_ -> Encode.null\n\
         \x20       , dec = Decode.succeed ctor\n\
         \x20       }}\n\
         type alias Person =\n    {{ name : String, age : Int }}\n\
         mkPerson : String -> Int -> Person\n\
         mkPerson name age =\n    {{ name = name, age = age }}\n\
         personBuilder : Builder (String -> Int -> Person)\n\
         personBuilder =\n    object mkPerson\n\
         main =\n    personBuilder\n"
    );
    assert_rejected("lower_codec_builder_seed", &src, "IPE-L0107");
}

/// The full applicative builder chain — `object ctor |> field … |> field …`
/// applying the curried constructor one argument at a time through the
/// accumulator's decoder — requires nested-closure lowering of a curried
/// constructor across a generic carrier frontier that is not implemented (the
/// `and_map_curried_stays_gated` boundary). It must fail closed with IPE-L0107,
/// never a silent accept that later `cargo`-fails (probed: bypassing the gate
/// emits a curry-arity `E0308` plus a `Box`/`Arc` decoder-payload frontier
/// `E0308`).
#[test]
fn lower_codec_builder_field_chain_gated() {
    let src = format!(
        "{HEAD}import Ipe.Json.Encode as Encode\n\
         import Ipe.Json.Decode as Decode\n\
         type Codec a\n\
         \x20   = Codec {{ enc : a -> Value, mkDec : {{}} -> Decoder a }}\n\
         type ObjectCodec rec fn\n\
         \x20   = ObjectCodec\n\
         \x20       {{ encField : rec -> List ( String, Value )\n\
         \x20       , mkDecPartial : {{}} -> Decoder fn\n\
         \x20       }}\n\
         object : fn -> ObjectCodec rec fn\n\
         object ctor =\n\
         \x20   ObjectCodec {{ encField = \\_ -> [], mkDecPartial = \\_ -> Decode.succeed ctor }}\n\
         field : String -> (rec -> f) -> Codec f -> ObjectCodec rec (f -> fn) -> ObjectCodec rec fn\n\
         field key get valueCodec acc =\n\
         \x20   case acc of\n\
         \x20       ObjectCodec a ->\n\
         \x20           case valueCodec of\n\
         \x20               Codec v ->\n\
         \x20                   ObjectCodec\n\
         \x20                       {{ encField = \\rec -> ( key, v.enc (get rec) ) :: a.encField rec\n\
         \x20                       , mkDecPartial = \\_ -> Decode.map2 (\\fn x -> fn x) (a.mkDecPartial {{}}) (Decode.field key (v.mkDec {{}}))\n\
         \x20                       }}\n\
         intCodec : Codec Int\n\
         intCodec =\n    Codec {{ enc = \\n -> Encode.int n, mkDec = \\_ -> Decode.int }}\n\
         type alias P =\n    {{ a : Int, b : Int }}\n\
         mkP : Int -> Int -> P\n\
         mkP a b =\n    {{ a = a, b = b }}\n\
         acc : ObjectCodec P P\n\
         acc =\n\
         \x20   object mkP\n\
         \x20       |> field \"a\" .a intCodec\n\
         \x20       |> field \"b\" .b intCodec\n\
         main =\n    acc\n"
    );
    assert_rejected("lower_codec_builder_chain", &src, "IPE-L0107");
}

/// CONTRAPOSITIVE: the sanctioned record-codec decode form — a monomorphic
/// `Decode.succeed ctor` threading a curried constructor through the
/// `Pipeline.required` chain — must still compile. This is the working shape the
/// `Ipe.Codec` module doc and the IPE-L0107 explain page point users to; the two
/// gated cases above must reject WITHOUT closing this door.
#[test]
fn lower_pipeline_curried_constructor_compiles() {
    let src = format!(
        "{HEAD}import Ipe.Io as Io\n\
         import Ipe.Json.Decode as Decode\n\
         import Ipe.Json.Decode.Pipeline as Pipeline\n\
         type alias User =\n    {{ id : String, age : Int }}\n\
         mkUser : String -> Int -> User\n\
         mkUser id age =\n    {{ id = id, age = age }}\n\
         userDecoder : Decoder User\n\
         userDecoder =\n\
         \x20   Decode.succeed mkUser\n\
         \x20       |> Pipeline.required \"id\" Decode.string\n\
         \x20       |> Pipeline.required \"age\" Decode.int\n\
         main : Task Error ()\n\
         main =\n\
         \x20   do\n\
         \x20       userDecoder\n\
         \x20       Io.println \"ok\"\n"
    );
    assert_compiles("lower_pipeline_curried_constructor", &src);
}

/// An app-entry cfg must be an inline record literal, never a let-bound
/// variable — IPE-L0119.
#[test]
fn lower_let_bound_app_cfg() {
    let src = "module Main exposing (main)\n\
         import Ipe.Tea.Web exposing (tea)\n\
         import Ipe.Tea.Web.Cmd as Cmd\n\
         import Ipe.Tea.Web.Sub as Sub\n\
         import Ipe.Ui as Ui\n\
         \n\
         type Page = HomePage\n\
         type Msg = Noop\n\
         type alias Model = { count : Int }\n\
         \n\
         init : WebReq -> ( Model, Cmd Msg )\n\
         init _req = ( { count = 0 }, Cmd.none )\n\
         update : Msg -> Model -> ( Model, Cmd Msg )\n\
         update _msg model = ( model, Cmd.none )\n\
         subscriptions : Model -> Sub Msg\n\
         subscriptions _model = Sub.none\n\
         view : Model -> Element Msg\n\
         view _model = Ui.text \"hi\"\n\
         \n\
         main =\n\
         \x20   let cfg =\n\
         \x20           { init = init\n\
         \x20           , update = update\n\
         \x20           , view = view\n\
         \x20           , subscriptions = subscriptions\n\
         \x20           , routes = []\n\
         \x20           , notFound = HomePage\n\
         \x20           }\n\
         \x20   in\n\
         \x20   tea cfg\n";
    assert_rejected("lower_let_bound_cfg", src, "IPE-L0119");
}

/// A `Web.tea` `init` annotated with a free type variable (`init : a -> …`)
/// is a false promise — the runtime always passes `WebReq` — so it must be
/// rejected with IPE-N0046.
#[test]
fn name_web_init_poly_var() {
    let src = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Page = HomePage
type Msg = Noop
type alias Model = { page : Page }
init : a -> ( Model, Cmd Msg )
init _ = ( { page = HomePage }, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> any
view _model = Ui.text "hi"
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [ Web.route "/" HomePage ]
        , notFound = HomePage
        }
"#;
    assert_rejected("name_web_init_poly_var", src, "IPE-N0046");
}

// ===========================================================================
// Literal route paths follow the runtime's grammar — IPE-L0156. A `:name` is
// `[A-Za-z_][A-Za-z0-9_]*` and unique per path; a `Web.route` literal segment
// is strictly percent-decodable. A literal that breaks it is refused at ipe
// time rather than at listener startup.
// ===========================================================================

/// A `Web.tea` app whose second route pattern is `pattern`, built by the
/// one-field `PostPage` or the two-field `PairPage` constructor.
fn web_route_fixture(pattern: &str, ctor: &str) -> String {
    format!(
        r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Page = HomePage | PostPage String | PairPage String String
type Msg = Noop
type alias Model = {{ count : Int }}
init : WebReq -> ( Model, Cmd Msg )
init _req = ( {{ count = 0 }}, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> Element Msg
view _model = Ui.text "hi"
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        {{ init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [ Web.route "/" HomePage, Web.route "{pattern}" {ctor} ]
        , notFound = HomePage
        }}
"#
    )
}

/// A `Server.listen` program with one route built by `route`.
fn server_route_fixture(route: &str) -> String {
    format!(
        r#"module Main exposing (main)
import Ipe.Http.Server as Server
import Ipe.Task
main =
    Server.listen 8000
        [ {route} (\_ -> Task.succeed (Server.text "hi")) ]
"#
    )
}

#[test]
fn lower_web_route_param_not_identifier() {
    let src = web_route_fixture("/posts/:post-id", "PostPage");
    assert_rejected("lower_web_route_param_not_identifier", &src, "IPE-L0156");
}

#[test]
fn lower_web_route_param_empty() {
    let src = web_route_fixture("/posts/:", "PostPage");
    assert_rejected("lower_web_route_param_empty", &src, "IPE-L0156");
}

#[test]
fn lower_web_route_param_duplicate() {
    let src = web_route_fixture("/users/:id/posts/:id", "PairPage");
    assert_rejected("lower_web_route_param_duplicate", &src, "IPE-L0156");
}

#[test]
fn lower_web_route_malformed_escape() {
    let src = web_route_fixture("/files/100%zz", "HomePage");
    assert_rejected("lower_web_route_malformed_escape", &src, "IPE-L0156");
}

#[test]
fn lower_server_route_param_not_identifier() {
    let src = server_route_fixture(r#"Server.get "/:post-id""#);
    assert_rejected("lower_server_route_param_not_identifier", &src, "IPE-L0156");
}

#[test]
fn lower_server_route_param_duplicate() {
    let src = server_route_fixture(r#"Server.get "/:id/:id""#);
    assert_rejected("lower_server_route_param_duplicate", &src, "IPE-L0156");
}

#[test]
fn lower_server_route_param_empty() {
    let src = server_route_fixture(r#"Server.post "/:""#);
    assert_rejected("lower_server_route_param_empty", &src, "IPE-L0156");
}

#[test]
fn lower_server_api_path_param_not_identifier() {
    let src = server_route_fixture(r#"Server.api "GET /v1/:a-b""#);
    assert_rejected(
        "lower_server_api_path_param_not_identifier",
        &src,
        "IPE-L0156",
    );
}

/// A routed `Web.tea` app (its Model has a `page` field) over `page_ty`,
/// with `routes` as the table, `not_found` as `notFound`, and `extra` cfg
/// fields appended (e.g. `, onNavigate = Navigated`).
fn routed_fixture(page_ty: &str, routes: &str, not_found: &str, extra: &str) -> String {
    format!(
        r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
{page_ty}
type Msg = Noop | Navigated Page
type alias Model = {{ page : Page }}
init : WebReq -> ( Model, Cmd Msg )
init _req = ( {{ page = {not_found} }}, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> Element Msg
view _model = Ui.text "hi"
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        {{ init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = {routes}
        , notFound = {not_found}{extra}
        }}
"#
    )
}

const ROUTED_PAGES: &str =
    "type Page = HomePage | APage String | BPage String | NPage Int | SPage String | NewPage";

/// A routed table over [`ROUTED_PAGES`] whose every constructor has a route,
/// preceded by `head` (the routes under test).
fn routed_table(head: &str) -> String {
    format!(
        "[ {head}Web.route \"/\" HomePage, Web.route \"/za/:x\" APage, \
         Web.route \"/zb/:x\" BPage, Web.route \"/zn/:n\" NPage, \
         Web.route \"/zs/:s\" SPage, Web.route \"/znew\" NewPage ]"
    )
}

/// Equivalent patterns (same segments up to parameter names, types, and
/// percent-encoding) that build different pages are refused with IPE-L0157.
#[test]
fn lower_routed_equivalent_patterns_are_ambiguous() {
    for (name, head) in [
        (
            "param_names",
            r#"Web.route "/a/:x" APage, Web.route "/a/:y" BPage, "#,
        ),
        (
            "percent_decoded",
            r#"Web.route "/a/%41" HomePage, Web.route "/a/A" NewPage, "#,
        ),
        (
            "param_types",
            r#"Web.route "/a/:n" NPage, Web.route "/a/:s" SPage, "#,
        ),
    ] {
        let src = routed_fixture(ROUTED_PAGES, &routed_table(head), "HomePage", "");
        assert_rejected(&format!("lower_routed_ambiguous_{name}"), &src, "IPE-L0157");
    }
}

/// A route an earlier route always matches first is refused with IPE-L0158:
/// the same pattern for the same page, or a literal under an earlier
/// parameter whose decode accepts it (`String` always, `Int` for `7`).
#[test]
fn lower_routed_shadowed_route_is_unreachable() {
    for (name, head) in [
        (
            "duplicate",
            r#"Web.route "/about" NewPage, Web.route "/about" NewPage, "#,
        ),
        (
            "string_param_first",
            r#"Web.route "/apps/:s" SPage, Web.route "/apps/new" NewPage, "#,
        ),
        (
            "int_param_first",
            r#"Web.route "/n/:n" NPage, Web.route "/n/7" NewPage, "#,
        ),
    ] {
        let src = routed_fixture(ROUTED_PAGES, &routed_table(head), "HomePage", "");
        assert_rejected(
            &format!("lower_routed_unreachable_{name}"),
            &src,
            "IPE-L0158",
        );
    }
}

/// A page constructor with no route (here the `notFound` page) is refused
/// with IPE-L0159.
#[test]
fn lower_routed_page_without_route() {
    let src = routed_fixture(
        "type Page = HomePage | MissingPage",
        r#"[ Web.route "/" HomePage ]"#,
        "MissingPage",
        "",
    );
    assert_rejected("lower_routed_page_without_route", &src, "IPE-L0159");
}

/// A routed literal segment no URL carries back (empty, `.` or `..`, plain or
/// percent-encoded) is refused with IPE-L0156: its page could never render.
#[test]
fn lower_routed_unrenderable_literal() {
    for (name, pattern) in [
        ("empty", "/a//b"),
        ("dot", "/a/./b"),
        ("dot_dot_encoded", "/a/%2E%2E"),
    ] {
        let src = routed_fixture(
            "type Page = HomePage | APage",
            &format!(r#"[ Web.route "/" HomePage, Web.route "{pattern}" APage ]"#),
            "HomePage",
            "",
        );
        assert_rejected(
            &format!("lower_routed_unrenderable_literal_{name}"),
            &src,
            "IPE-L0156",
        );
    }
}

/// A routed app whose `Model.page` is not a custom type is refused with
/// IPE-L0161: no constructor can render a page path.
#[test]
fn lower_routed_page_not_custom_type() {
    let src = routed_fixture("type alias Page = String", "[]", "\"home\"", "");
    assert_rejected("lower_routed_page_not_custom_type", &src, "IPE-L0161");
}

/// A function page builder (lambda, named, partially applied, let-bound) in a
/// routed table is refused with IPE-L0123: it has no inverse, so the page's
/// canonical path cannot be rendered.
#[test]
fn lower_routed_function_builders() {
    for (name, builder, decl) in [
        ("lambda", r"(\x -> APage x)", ""),
        (
            "named",
            "buildA",
            "buildA : String -> Page\nbuildA x = APage x\n",
        ),
        ("partial", "(PairPage \"k\")", ""),
    ] {
        let src = routed_fixture(
            "type Page = HomePage | APage String | PairPage String String",
            &format!(
                r#"[ Web.route "/" HomePage, Web.route "/a/:x" {builder}, Web.route "/p/:a/:b" PairPage ]"#
            ),
            "HomePage",
            "",
        )
        .replacen("type Msg", &format!("{decl}type Msg"), 1);
        assert_rejected(&format!("lower_routed_{name}_builder"), &src, "IPE-L0123");
    }
    let let_bound = routed_fixture(
        "type Page = HomePage | APage String",
        r#"[ Web.route "/" HomePage, Web.route "/a/:x" b ]"#,
        "HomePage",
        "",
    )
    .replacen(
        "main =\n    Web.tea",
        "main =\n    let b = APage in\n    Web.tea",
        1,
    );
    assert_rejected("lower_routed_let_bound_builder", &let_bound, "IPE-L0123");
}

/// A routed table that is not a literal list of `Web.route` calls is refused
/// with IPE-L0160.
#[test]
fn lower_routed_computed_table() {
    let src = routed_fixture(
        "type Page = HomePage",
        r#"(List.reverse [ Web.route "/" HomePage ])"#,
        "HomePage",
        "",
    )
    .replace(
        "import Ipe.Tea.Web.Sub\n",
        "import Ipe.Tea.Web.Sub\nimport Ipe.List as List\n",
    );
    assert_rejected("lower_routed_computed_table", &src, "IPE-L0160");
}

/// `onNavigate` in an app whose Model has no `page` field is refused with
/// IPE-L0162, and an `onNavigate` that is not `Page -> Msg` in a routed app is
/// a type mismatch (IPE-T0001).
#[test]
fn lower_on_navigate_refusals() {
    let unrouted = web_route_fixture("/posts/:id", "PostPage").replace(
        "        , notFound = HomePage\n",
        "        , notFound = HomePage\n        , onNavigate = \\_ -> Noop\n",
    );
    assert_rejected("lower_on_navigate_without_page", &unrouted, "IPE-L0162");
    let mistyped = routed_fixture(
        "type Page = HomePage",
        r#"[ Web.route "/" HomePage ]"#,
        "HomePage",
        "\n        , onNavigate = Noop",
    );
    assert_rejected("type_on_navigate_not_page_to_msg", &mistyped, "IPE-T0001");
}

/// The contrapositive: aliases, a literal before a parameter, an `Int`
/// parameter beside a literal, distinct arities, and a typed `onNavigate`
/// still compile.
#[test]
fn well_formed_routed_tables_compile() {
    let head = concat!(
        r#"Web.route "/home" HomePage, Web.route "/apps/new" NewPage, "#,
        r#"Web.route "/apps/:s" SPage, Web.route "/n/:n" NPage, Web.route "/n/latest" NewPage, "#,
        r#"Web.route "/search" HomePage, Web.route "/search/:q" APage, "#,
    );
    assert_compiles(
        "routed_table_well_formed",
        &routed_fixture(ROUTED_PAGES, &routed_table(head), "HomePage", ""),
    );
    assert_compiles(
        "routed_on_navigate_well_typed",
        &routed_fixture(
            "type Page = HomePage",
            r#"[ Web.route "/" HomePage ]"#,
            "HomePage",
            "\n        , onNavigate = Navigated",
        ),
    );
}

/// The contrapositive: well-formed literal paths still compile.
#[test]
fn well_formed_route_paths_compile() {
    assert_compiles(
        "web_route_well_formed",
        &web_route_fixture("/users/:user_id/posts/:post_id", "PairPage"),
    );
    assert_compiles(
        "server_route_well_formed",
        &server_route_fixture(r#"Server.get "/files/:_dir/*rest""#),
    );
    assert_compiles(
        "server_api_well_formed",
        &server_route_fixture(r#"Server.api "POST /v1/:id""#),
    );
}

// ===========================================================================
// App entries need a concrete Model / Msg — IPE-N0051. Every app entry's
// runtime function bounds the cfg's model and message types with traits a
// Rust generic does not carry, so an entry built inside a definition generic
// over a type variable the cfg mentions is refused at ipe time — one refusal
// per entry kind, plus the concrete contrapositive.
// ===========================================================================

/// The `Web` cfg preamble shared by the `Web.tea` / `Web.appWith` fixtures: a
/// concrete app whose `main` is a valid entry, so the only defect is the
/// msg-generic helper each fixture appends.
const WEB_ENTRY_PREAMBLE: &str = r#"module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
type Page = HomePage
type Msg = Noop
type alias Model = { count : Int }
initialModel : Model
initialModel = { count = 0 }
init : WebReq -> ( Model, Cmd Msg )
init _req = ( initialModel, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> Element Msg
view _model = Ui.text "hi"
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none
main =
    Web.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [], notFound = HomePage
        }
"#;

/// A `Web.tea` built by a helper generic over its message type is refused.
#[test]
fn generic_msg_web_tea_rejected() {
    let src = format!(
        "{WEB_ENTRY_PREAMBLE}\
         appOf step render =\n\
         \x20   Web.tea\n\
         \x20       {{ init = \\_ -> ( initialModel, Cmd.none )\n\
         \x20       , update = step\n\
         \x20       , view = render\n\
         \x20       , subscriptions = \\_ -> Sub.none\n\
         \x20       , routes = []\n\
         \x20       , notFound = HomePage\n\
         \x20       }}\n"
    );
    assert_rejected("generic_msg_web_tea", &src, "IPE-N0051");
}

/// A `Web.appWith` built by a helper generic over its message type is refused.
#[test]
fn generic_msg_web_app_with_rejected() {
    let src = format!(
        "{WEB_ENTRY_PREAMBLE}\
         appOf step render =\n\
         \x20   Web.appWith []\n\
         \x20       {{ init = \\_ -> ( initialModel, Cmd.none )\n\
         \x20       , update = step\n\
         \x20       , view = render\n\
         \x20       , subscriptions = \\_ -> Sub.none\n\
         \x20       , routes = []\n\
         \x20       , notFound = HomePage\n\
         \x20       }}\n"
    );
    assert_rejected("generic_msg_web_app_with", &src, "IPE-N0051");
}

/// A server mounting a `Web.embed` app, built by a helper whose annotation
/// keeps `msg` generic: `embedOf` would emit as a Rust generic the runtime's
/// `Serialize + PartialEq + Sync` bounds cannot reach.
const WEB_EMBED_GENERIC: &str = r#"module Main exposing (main)
import Ipe.Server.Http as Server
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
type alias Model = { count : Int }
type Msg = Noop
initialModel : Model
initialModel = { count = 0 }
update : Msg -> Model -> ( Model, Cmd.Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> Element Msg
view _model = Ui.text "hi"
embedOf : (msg -> Model -> ( Model, Cmd.Cmd msg )) -> (Model -> Element msg) -> msg -> Web.WebApp
embedOf step render fallback =
    Web.embed
        { init = \_ -> ( initialModel, Cmd.none )
        , update = step
        , view = render
        , subscriptions = \_ -> Sub.none
        , routes = []
        , notFound = fallback
        }
main : Task Error ()
main =
    Server.listen 8000 [ Server.mountApp "/" (embedOf update view Noop) ]
"#;

/// A mounted `Web.embed` built by a msg-generic helper is refused.
#[test]
fn generic_msg_web_embed_rejected() {
    assert_rejected("generic_msg_web_embed", WEB_EMBED_GENERIC, "IPE-N0051");
}

/// The contrapositive: the same helper annotated with the concrete `Msg` is accepted.
#[test]
fn concrete_msg_web_embed_compiles() {
    let src = WEB_EMBED_GENERIC.replace(
        "embedOf : (msg -> Model -> ( Model, Cmd.Cmd msg )) -> (Model -> Element msg) -> msg -> Web.WebApp",
        "embedOf : (Msg -> Model -> ( Model, Cmd.Cmd Msg )) -> (Model -> Element Msg) -> Msg -> Web.WebApp",
    );
    assert!(
        src != WEB_EMBED_GENERIC,
        "the fixture must carry the generic annotation this test concretises"
    );
    assert_compiles("concrete_msg_web_embed", &src);
}

/// A mounted `Web.embed` whose only open generic is the row variable of its
/// model: `embedRow` quantifies `r`, the open tail of `{ r | count : Int }`,
/// and the entry's solved cfg type reaches it only through that tail.
const WEB_EMBED_ROW_GENERIC: &str = r#"module Main exposing (main)
import Ipe.Server.Http as Server
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
type alias Model = { count : Int }
type Msg = Noop
initialModel : Model
initialModel = { count = 0 }
embedRow : { r | count : Int } -> Web.WebApp
embedRow start =
    Web.embed
        { init = \_ -> ( start, Cmd.none )
        , update = \_ m -> ( m, Cmd.none )
        , view = \_ -> Ui.text "hi"
        , subscriptions = \_ -> Sub.none
        , routes = []
        , notFound = Noop
        }
main : Task Error ()
main =
    Server.listen 8000 [ Server.mountApp "/" (embedRow initialModel) ]
"#;

/// A mounted `Web.embed` whose model is generic only through an open row tail is refused.
#[test]
fn generic_row_model_web_embed_rejected() {
    assert_rejected(
        "generic_row_model_web_embed",
        WEB_EMBED_ROW_GENERIC,
        "IPE-N0051",
    );
}

/// A mounted `Web.embed` built inside a definition whose annotation carries a
/// row generic the entry's model does not visibly use: the model is the
/// concrete `Model`, and `r` is only the open tail of the `cfg` parameter the
/// view reads a label from. Region types carry no record row tails, so whether
/// the entry reaches `r` cannot be determined, and the entry is refused
/// fail-closed.
const WEB_EMBED_ROW_IN_SCOPE: &str = r#"module Main exposing (main)
import Ipe.Server.Http as Server
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
type alias Model = { count : Int }
type Msg = Noop
initialModel : Model
initialModel = { count = 0 }
embedLabelled : { r | label : String } -> Web.WebApp
embedLabelled cfg =
    Web.embed
        { init = \_ -> ( initialModel, Cmd.none )
        , update = \_ m -> ( m, Cmd.none )
        , view = \_ -> Ui.text cfg.label
        , subscriptions = \_ -> Sub.none
        , routes = []
        , notFound = Noop
        }
main : Task Error ()
main =
    Server.listen 8000 [ Server.mountApp "/" (embedLabelled { label = "hi" }) ]
"#;

/// An app entry under an annotation row generic is refused with IPE-N0051,
/// reported as an undetermined reach of `r` rather than an entry built over it.
#[test]
fn row_generic_in_scope_web_embed_refused_undetermined() {
    let name = "row_generic_in_scope_web_embed";
    let entry = write_entry(name, WEB_EMBED_ROW_IN_SCOPE);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("negsuite-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build_with_options(&entry, &out, &runtime, BuildOptions::default()) {
        Err(CliError::Pipeline { diag, .. }) => match *diag {
            ipe_diagnostics::Diagnostic::Name {
                msg:
                    ipe_diagnostics::NameError::GenericAppEntry {
                        type_var, reach, ..
                    },
                ..
            } => {
                assert_eq!(
                    &*type_var, "r",
                    "{name}: the refusal must name the row generic"
                );
                assert_eq!(
                    reach,
                    ipe_diagnostics::GenericAppEntryReach::Undetermined,
                    "{name}: a row generic in scope is an undetermined reach, not a proven mention"
                );
            }
            other => assert!(
                false_marker(),
                "{name}: expected IPE-N0051 for the row generic in scope, got {}",
                other.code().as_str()
            ),
        },
        Ok(()) => fail_accepted(name, "IPE-N0051", "compiled successfully (exit 0)"),
        Err(other) => fail_accepted(name, "IPE-N0051", &format!("non-pipeline error: {other:?}")),
    }
}

/// A mounted `Web.embed` in a definition with no generics whose message type
/// nothing fixes: `update` ignores its message, the view emits none, and
/// `notFound` is the route fallback, so `msg` stays a type variable.
const WEB_EMBED_UNPINNED_MSG: &str = r#"module Main exposing (main)
import Ipe.Server.Http as Server
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
type alias Model = { count : Int }
type Msg = Noop
app : Web.WebApp
app =
    Web.embed
        { init = \_ -> ( { count = 0 }, Cmd.none )
        , update = \_ m -> ( m, Cmd.none )
        , view = \_ -> Ui.text "hi"
        , subscriptions = \_ -> Sub.none
        , routes = []
        , notFound = Noop
        }
main : Task Error ()
main =
    Server.listen 8000 [ Server.mountApp "/" app ]
"#;

/// An app entry whose message type the program never fixes is refused with
/// IPE-N0051 at the entry, before any cfg value reaches the polymorphic-value
/// check (IPE-L0102).
#[test]
fn unpinned_msg_web_embed_refused() {
    let name = "unpinned_msg_web_embed";
    let entry = write_entry(name, WEB_EMBED_UNPINNED_MSG);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("negsuite-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build_with_options(&entry, &out, &runtime, BuildOptions::default()) {
        Err(CliError::Pipeline { diag, .. }) => match *diag {
            ipe_diagnostics::Diagnostic::Name {
                msg: ipe_diagnostics::NameError::UnpinnedAppEntry { entry },
                ..
            } => assert_eq!(
                &*entry, "Web.embed",
                "{name}: the refusal must name the entry"
            ),
            other => assert!(
                false_marker(),
                "{name}: expected IPE-N0051 for the unpinned message type, got {}",
                other.code().as_str()
            ),
        },
        Ok(()) => fail_accepted(name, "IPE-N0051", "compiled successfully (exit 0)"),
        Err(other) => fail_accepted(name, "IPE-N0051", &format!("non-pipeline error: {other:?}")),
    }
}

/// The contrapositive: the same app with `update` matching on its `Msg` is accepted.
#[test]
fn pinned_msg_web_embed_compiles() {
    let src = WEB_EMBED_UNPINNED_MSG.replace(
        "        , update = \\_ m -> ( m, Cmd.none )\n",
        "        , update = \\msg m -> case msg of\n            Noop -> ( m, Cmd.none )\n",
    );
    assert!(
        src != WEB_EMBED_UNPINNED_MSG,
        "the fixture must carry the message-ignoring update this test replaces"
    );
    assert_compiles("pinned_msg_web_embed", &src);
}

/// A server program mounting a well-typed `Web.embed` app; `{main}` is the
/// `main` binding under test.
fn mounted_web_app_with(main: &str) -> String {
    format!(
        r#"module Main exposing (main)
import Ipe.Server.Http as Server
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui
type alias Model = {{ count : Int }}
type Msg = Noop
app : Web.WebApp
app =
    Web.embed
        {{ init = \_ -> ( {{ count = 0 }}, Cmd.none )
        , update = \msg m -> case msg of
            Noop -> ( m, Cmd.none )
        , view = \_ -> Ui.text "hi"
        , subscriptions = \_ -> Sub.none
        , routes = []
        , notFound = Noop
        }}
{main}"#
    )
}

/// A `do` block that binds before its `Server.listen` tail is the same server
/// program as its bind-free spelling, so its `Ipe.Tea.Web` import is admitted.
#[test]
fn server_listen_after_do_bind_with_mounted_web_app_compiles() {
    let src = mounted_web_app_with(
        "main : Task Error ()
main =
    do
        port <- Task.succeed 8000
        Server.listen port [ Server.mountApp \"/\" app ]
",
    );
    assert_compiles("server_listen_after_do_bind", &src);
}

/// A `do` bind whose tail is a plain `Task` is a Program; importing
/// `Ipe.Tea.Web` stays IPE-N0033.
#[test]
fn do_bind_tail_plain_task_importing_tea_web_rejected_n0033() {
    let src = mounted_web_app_with(
        "main : Task Error ()
main =
    do
        port <- Task.succeed 8000
        Task.succeed ()
",
    );
    assert_rejected("do_bind_tail_plain_task", &src, "IPE-N0033");
}

/// The bare-run spelling of the same Program is refused the same way.
#[test]
fn do_run_tail_plain_task_importing_tea_web_rejected_n0033() {
    let src = mounted_web_app_with(
        "main : Task Error ()
main =
    do
        Task.succeed 8000
        Task.succeed ()
",
    );
    assert_rejected("do_run_tail_plain_task", &src, "IPE-N0033");
}

/// Only the `Task.andThen` kernel is followed: a user function of the same
/// name and shape leaves `main`'s head on that function.
#[test]
fn user_and_then_to_listen_importing_tea_web_rejected_n0033() {
    let src = mounted_web_app_with(
        "andThen : (a -> Task Error b) -> Task Error a -> Task Error b
andThen f t = Task.andThen f t
main : Task Error ()
main =
    andThen (\\port -> Server.listen port [ Server.mountApp \"/\" app ]) (Task.succeed 8000)
",
    );
    assert_rejected("user_and_then_to_listen", &src, "IPE-N0033");
}

/// `Server.listen` as the task `Task.andThen` runs first is not `main`'s
/// result: only the continuation body is followed.
#[test]
fn listen_in_and_then_task_position_importing_tea_web_rejected_n0033() {
    let src = mounted_web_app_with(
        "main : Task Error ()
main =
    Task.andThen (\\_ -> Task.succeed ()) (Server.listen 8000 [ Server.mountApp \"/\" app ])
",
    );
    assert_rejected("listen_in_and_then_task_position", &src, "IPE-N0033");
}

/// A point-free `let` alias of `Web.embed` inside a msg-generic helper is refused.
///
/// The alias is monomorphic (no let-generalization), so its `Web.embed`
/// reference is instantiated at the helper's `msg` and refused at that
/// reference, not only at a direct call.
#[test]
fn generic_msg_web_embed_let_alias_rejected() {
    let src = WEB_EMBED_GENERIC.replace(
        "embedOf step render fallback =\n    Web.embed\n",
        "embedOf step render fallback =\n    let\n        mk = Web.embed\n    in\n    mk\n",
    );
    assert!(
        src != WEB_EMBED_GENERIC,
        "the fixture must carry the direct `Web.embed` call this test aliases"
    );
    assert_rejected("generic_msg_web_embed_let_alias", &src, "IPE-N0051");
}

/// A `Web.appRouted` built by a msg-generic helper is refused before lowering.
///
/// `Web.appRouted` carries no type scheme, so every reference to it is refused
/// by the type checker (IPE-L0108) and never reaches the generic-entry check.
#[test]
fn generic_msg_web_app_routed_rejected() {
    let src = format!(
        "{WEB_ENTRY_PREAMBLE}\
         appOf step render =\n\
         \x20   Web.appRouted\n\
         \x20       {{ init = \\_ -> ( initialModel, Cmd.none )\n\
         \x20       , update = step\n\
         \x20       , view = render\n\
         \x20       , subscriptions = \\_ -> Sub.none\n\
         \x20       , routes = []\n\
         \x20       , notFound = HomePage\n\
         \x20       }}\n"
    );
    assert_rejected("generic_msg_web_app_routed", &src, "IPE-L0108");
}

/// A `Tui.tea` built by a helper generic over its message type is refused.
#[test]
fn generic_msg_tui_tea_rejected() {
    let src = r#"module Main exposing (main)
import Ipe.Tea.Tui as Tui
import Ipe.Ui.Cells as Cells
import Ipe.Ui.Cells exposing (Screen)
import Ipe.Tea.Tui.Cmd
import Ipe.Tea.Tui.Sub
type Msg = NoOp
type alias Model = { count : Int }
type alias KeyEvent = { kind : String, value : String }
initialModel : Model
initialModel = { count = 0 }
init : () -> ( Model, Cmd Msg )
init _unit = ( initialModel, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> Screen Msg
view _model = Cells.text "hello"
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.onKey onKey
onKey : KeyEvent -> Msg
onKey _event = NoOp
main =
    Tui.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        }
appOf step render toMsg =
    Tui.tea
        { init = \_ -> ( initialModel, Cmd.none )
        , update = step
        , view = render
        , subscriptions = \_ -> Sub.onKey toMsg
        }
"#;
    assert_rejected("generic_msg_tui_tea", src, "IPE-N0051");
}

/// A `Cli.tea` built by a helper generic over its message type is refused.
#[test]
fn generic_msg_cli_tea_rejected() {
    let src = r#"module Main exposing (main)
import Ipe.Tea.Cli as Cli
import Ipe.Tea.Cli.Cmd
import Ipe.Tea.Cli.Sub
import Ipe.Ui.Cli as Ui
import Ipe.Ui.Cli exposing (Lines)
type Msg = Line String
type alias Model = { count : Int }
initialModel : Model
initialModel = { count = 0 }
init : () -> ( Model, Cmd Msg )
init _unit = ( initialModel, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
view : Model -> Lines Msg
view _model = Ui.text "ok"
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.onLine onLine
onLine : String -> Msg
onLine s = Line s
main =
    Cli.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        }
appOf step render toMsg =
    Cli.tea
        { init = \_ -> ( initialModel, Cmd.none )
        , update = step
        , view = render
        , subscriptions = \_ -> Sub.onLine toMsg
        }
"#;
    assert_rejected("generic_msg_cli_tea", src, "IPE-N0051");
}

/// A `Worker.tea` built by a helper generic over its message type is refused.
#[test]
fn generic_msg_worker_tea_rejected() {
    let src = r"module Main exposing (main)
import Ipe.Tea.Worker
import Ipe.Tea.Worker.Cmd as Cmd
import Ipe.Tea.Worker.Sub as Sub
type Msg = Tick
type alias Model = { ticks : Int }
initialModel : Model
initialModel = { ticks = 0 }
init : () -> ( Model, Cmd Msg )
init _unit = ( initialModel, Cmd.none )
update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )
subscriptions : Model -> Sub Msg
subscriptions _model = Sub.every 100 Tick
main =
    Worker.tea { init = init, update = update, subscriptions = subscriptions }
workerOf step =
    Worker.tea
        { init = \_ -> ( initialModel, Cmd.none )
        , update = step
        , subscriptions = \_ -> Sub.none
        }
";
    assert_rejected("generic_msg_worker_tea", src, "IPE-N0051");
}

// ===========================================================================
// FFI trust boundary (T1) — the decode/emit gate rejects injection-bearing
// inspector data, and the warm-cache load re-derives `_bindings.rs` from the
// validated inspection document so a planted `_bindings.rs` is inert. These
// guard the CONTRAPOSITIVE of THE SEAL at the FFI seam: an injection-bearing
// type/path/selector string can never reach the unsandboxed `<slug>_bindings.rs`
// that compiles into the user crate, and a representable-but-illegal type (an
// unbalanced `<`) rejects at decode rather than exit-0-then-cargo-fail.
// ===========================================================================

use ipe_ffi::diag::{Diagnostic, WireDefect};
use ipe_ffi::driver::{FfiCache, load_catalog};
use ipe_ffi::pkginfo::PkgInfo;

/// A `PkgInfo` inspection document with one function carrying the given
/// `rustType` on its sole parameter.
fn pkg_json_with_param_rust_type(rust_type: &str) -> String {
    format!(
        "{{\"pkg\":\"x\",\"name\":\"x\",\"version\":\"1.0.0\",\
          \"functions\":[{{\"name\":\"f\",\
          \"params\":[{{\"name\":\"a\",\"type\":\"u64\",\"rustType\":{rt}}}],\
          \"results\":[{{\"name\":\"\",\"type\":\"u64\"}}],\
          \"effect\":\"pure\"}}],\"errors\":[]}}",
        rt = serde_json::to_string(rust_type).unwrap_or_else(|_| "\"\"".to_owned())
    )
}

/// An injection-bearing `rustType` drops its binding at decode with the typed
/// `InvalidType` defect — the raw string never reaches emission.
#[test]
fn ffi_injection_bearing_rust_type_is_refused_at_decode() {
    let doc = pkg_json_with_param_rust_type("u64; std::process::Command::new(\"sh\")");
    let pkg = PkgInfo::decode_json(&doc).expect("package header survives");
    assert!(
        pkg.fns().is_empty(),
        "the injection-bearing binding must be dropped"
    );
    assert!(
        matches!(
            pkg.dropped().first(),
            Some(Diagnostic::WireMalformed {
                defect: WireDefect::InvalidType { .. },
                ..
            })
        ),
        "expected InvalidType, got {:?}",
        pkg.dropped().first()
    );
}

/// SEAL corollary: an unbalanced `<` in a `rustType` is a representable but
/// illegal Rust type. It rejects at DECODE (drops the binding), never
/// producing an `ipe`-exit-0 emission that a later `cargo build` would reject.
#[test]
fn ffi_unbalanced_angle_rust_type_rejects_at_decode_not_cargo() {
    let doc = pkg_json_with_param_rust_type("Vec<u64");
    let pkg = PkgInfo::decode_json(&doc).expect("package header survives");
    assert!(
        pkg.fns().is_empty(),
        "the unbalanced type drops its binding"
    );
    assert!(
        matches!(
            pkg.dropped().first(),
            Some(Diagnostic::WireMalformed {
                defect: WireDefect::InvalidType { .. },
                ..
            })
        ),
        "expected InvalidType at decode, got {:?}",
        pkg.dropped().first()
    );
}

/// A hand-planted `_bindings.rs` carrying an injected wrapper body is INERT:
/// `load_catalog` re-derives the wrappers from the validated `pkg.json`, so the
/// planted text never reaches the emitted `src/ffi.rs`.
#[test]
fn ffi_planted_bindings_file_is_ignored_on_load() {
    let doc = "{\"pkg\":\"semver\",\"name\":\"semver\",\"version\":\"1.0.0\",\
        \"functions\":[{\"name\":\"parse\",\
        \"params\":[{\"name\":\"text\",\"type\":\"String\",\"ipeType\":\"String\",\"rustType\":\"&str\"}],\
        \"results\":[{\"name\":\"\",\"type\":\"Result Error Version\",\"rustType\":\"Result<Version, Error>\"}],\
        \"effect\":\"fallible\"}],\"errors\":[]}";
    let dir = write_entry("ffi_planted_cache", "");
    let root = dir
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or(dir);
    let cache = FfiCache::at_project_root(&root);
    let (_pkg, paths) = ipe_ffi::driver::install_from_inspection(&cache, doc)
        .expect("a well-formed inspection document installs");
    // Plant an injected item into a reached wrapper region of _bindings.rs.
    if let Ok(text) = std::fs::read_to_string(&paths.bindings) {
        let planted = text.replace(
            "pub fn semver_parse",
            "pub fn pwned(){ std::process::Command::new(\"sh\"); } pub fn semver_parse",
        );
        let _ = std::fs::write(&paths.bindings, planted);
    }
    let catalog = load_catalog(cache.root()).expect("loads");
    for c in &catalog {
        assert!(
            !c.bindings_source.contains("pwned"),
            "a planted _bindings.rs must not survive re-derivation:\n{}",
            c.bindings_source
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

// ===========================================================================
// Maybe.isJust / Maybe.isNothing — export reachability
// ===========================================================================

// `Maybe.isJust` and `Maybe.isNothing` are listed in `Ipe.Maybe`'s `exposing`
// clause. These tests lock qualified access, explicit `exposing` injection, and
// the full set of `Ipe.Maybe` exports.

/// Qualified `Maybe.isJust` and `Maybe.isNothing` on `Just`/`Nothing` values.
#[test]
fn maybe_is_just_is_nothing_qualified_compiles() {
    let src = format!(
        "{HEAD}\
import Ipe.Maybe
import Ipe.Io as Io
import Ipe.String as String

main : Task Error ()
main =
    let
        j = Just 1
        n = Nothing
        a = Maybe.isJust j
        b = Maybe.isNothing n
        c = Maybe.isJust n
        d = Maybe.isNothing j
        result = if a then \"ok\" else \"fail\"
    in
    Io.println result
"
    );
    assert_compiles("maybe_is_just_is_nothing_qualified", &src);
}

/// Explicit `exposing (isJust, isNothing)` brings both into unqualified scope.
#[test]
fn maybe_is_just_is_nothing_exposing_compiles() {
    let src = format!(
        "{HEAD}\
import Ipe.Maybe exposing (isJust, isNothing)
import Ipe.Io as Io

main : Task Error ()
main =
    let
        j = Just 42
        n = Nothing
        a = isJust j
        b = isNothing n
        result = if a then \"ok\" else \"fail\"
    in
    Io.println result
"
    );
    assert_compiles("maybe_is_just_is_nothing_exposing", &src);
}

/// All other `Ipe.Maybe` exports (`withDefault`, `map`, `andThen`, `andMap`,
/// `combine`, `map2`…`map5`) still resolve correctly after the fix.
#[test]
fn maybe_all_other_exports_still_compile() {
    let src = format!(
        "{HEAD}\
import Ipe.Maybe exposing (withDefault, map, andThen, andMap, combine, map2, map3, map4, map5)
import Ipe.Io as Io
import Ipe.String as String

main : Task Error ()
main =
    let
        x = withDefault 0 (Just 1)
        y = map (\\n -> n + 1) (Just 2)
        z = andThen (\\n -> Just (n * 2)) (Just 3)
    in
    Io.println (String.fromInt x)
"
    );
    assert_compiles("maybe_other_exports_compile", &src);
}
