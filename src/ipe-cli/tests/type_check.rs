//! `ipe type-check` — type-check a program with no build, no run, no emit.
//!
//! Exit 0 with a friendly framed success line when the program type-checks;
//! non-zero with the rendered diagnostic on any parse/canon/type error. A
//! program importing a
//! compiled-source stdlib module (`Ipe.Test`) resolves through the same
//! injection-aware source graph the build path uses.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

use ipe::project_root::{ScratchRoot, SourceTree};

mod support;

type TestResult = Result<(), Box<dyn Error>>;

/// Absolute path to a fixture under this crate's `tests/fixtures/type_check`.
fn fixture(name: &str) -> PathBuf {
    support::manifest_dir()
        .join("tests/fixtures/type_check")
        .join(name)
}

/// A project holding the fixture `name`.
///
/// A lone `.ipe` fixture is the project's `src/Main.ipe`; a fixture directory
/// contributes every module of its `src/` tree.
fn fixture_project(name: &str) -> Result<ScratchRoot, Box<dyn Error>> {
    let at = fixture(name);
    let tree = if at.is_dir() {
        add_modules(SourceTree::new(), &at.join("src"), "")?
    } else {
        SourceTree::main(&std::fs::read_to_string(&at)?)
    };
    Ok(tree.resolve()?)
}

/// `tree` with every `.ipe` file under `dir` added as a `src/` module, its path prefixed by `prefix`.
fn add_modules(tree: SourceTree, dir: &Path, prefix: &str) -> Result<SourceTree, Box<dyn Error>> {
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut tree = tree;
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let module = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}.{name}")
        };
        if entry.file_type()?.is_dir() {
            tree = add_modules(tree, &entry.path(), &module)?;
        } else if let Some(stem) = module.strip_suffix(".ipe") {
            tree = tree.module(stem, &std::fs::read_to_string(entry.path())?);
        }
    }
    Ok(tree)
}

/// The directory of `project`, spelled as a process whose current directory it is reports it.
fn project_dir(project: &ScratchRoot) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(project.root().path())
}

/// Run `ipe type-check` with no argument in the project at `dir`, capturing `(success, stdout, stderr)`.
fn type_check_in(dir: &Path) -> Result<(bool, String, String), Box<dyn Error>> {
    let out = Command::new(support::ipe_bin())
        .arg("type-check")
        .current_dir(dir)
        .output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Run `ipe type-check` over a project holding the fixture `name`, capturing `(success, stdout, stderr)`.
fn check_fixture(name: &str) -> Result<(bool, String, String), Box<dyn Error>> {
    let project = fixture_project(name)?;
    type_check_in(&project_dir(&project)?)
}

/// Run the built `ipe` binary and capture `(success, stdout, stderr)`.
fn run_ipe(args: &[&str]) -> Result<(bool, String, String), Box<dyn Error>> {
    let out = Command::new(support::ipe_bin()).args(args).output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

#[test]
fn well_typed_program_exits_zero_with_ok() -> TestResult {
    let (ok, stdout, _) = check_fixture("well_typed.ipe")?;
    assert!(ok, "a well-typed program must exit 0");
    assert!(
        stdout.contains("type-checks"),
        "a clean check prints a friendly success message, got:\n{stdout}"
    );
    // The human default is framed: a blank line opens and closes the block.
    assert!(
        stdout.starts_with('\n') && stdout.ends_with('\n'),
        "check success must be framed with top/bottom blank lines, got:\n{stdout:?}"
    );
    Ok(())
}

#[test]
fn type_error_program_exits_nonzero_with_the_diagnostic() -> TestResult {
    let (ok, _, stderr) = check_fixture("type_error.ipe")?;
    assert!(!ok, "a type-error program must exit non-zero");
    assert!(
        stderr.contains("IPE-T0001") && stderr.contains("TYPE MISMATCH"),
        "the rendered type diagnostic must be shown, got:\n{stderr}"
    );
    Ok(())
}

/// SOUNDNESS: a user `type Order` is a distinct type from the built-in
/// comparison `Order` returned by `compare`. Feeding the built-in `Order` into a
/// function annotated with the user `Order` must be a TYPE MISMATCH — the two
/// carry different lowered representations (`MainOrder` vs `IpeOrder`), so
/// unifying them would let a wrong program type-check and then fail `cargo build`
/// (an ipe-exit-0-then-cargo-fail SEAL break). Negative proof that the shadowed
/// builtin does not silently unify with its empty-home kernel spelling.
#[test]
fn shadowable_builtin_shadow_is_a_type_error() -> TestResult {
    let (ok, _, stderr) = check_fixture("shadowable_builtin_shadow_is_type_error.ipe")?;
    assert!(
        !ok,
        "a user `type Order` fed the built-in comparison `Order` must NOT type-check"
    );
    assert!(
        stderr.contains("IPE-T0001") && stderr.contains("TYPE MISMATCH"),
        "the rendered nominal-mismatch diagnostic must be shown, got:\n{stderr}"
    );
    Ok(())
}

/// SECURITY: the raw-`String`-key crypto path is unrepresentable. `Ipe.Crypto`
/// exposes no bare-`String`-key entry point — every keyed operation requires the
/// typed `Key`. Passing a plaintext `String` where `hmacSha256` expects a `Key`
/// (the key/message confusion the typed `Key` was built to eliminate) is a
/// compile-time TYPE MISMATCH, not a silent wrong MAC. Negative proof that a
/// program supplying a raw `String` in the key role does not compile.
#[test]
fn crypto_raw_string_key_is_a_type_error() -> TestResult {
    let (ok, _, stderr) = check_fixture("crypto_raw_key_is_type_error.ipe")?;
    assert!(
        !ok,
        "passing a bare String where a Crypto.Key is expected must NOT type-check"
    );
    assert!(
        stderr.contains("IPE-T0001") && stderr.contains("TYPE MISMATCH"),
        "the rendered key/message role-confusion diagnostic must be shown, got:\n{stderr}"
    );
    Ok(())
}

/// SECURITY: a stored tag reaches `verifyHmacSha256` only through `macFromHex`.
/// Passing an unparsed hex `String` where the verifier expects a `Mac` is a
/// compile-time TYPE MISMATCH. Its positive counterpart,
/// `crypto_parsed_tag_verify_path_type_checks`, proves both names resolve, so
/// this rejection is the type error and not an unknown name.
#[test]
fn crypto_raw_hex_tag_is_a_type_error() -> TestResult {
    let (ok, _, stderr) = check_fixture("crypto_raw_hex_tag_is_type_error.ipe")?;
    assert!(
        !ok,
        "passing a bare String where a Crypto.Mac is expected must NOT type-check"
    );
    assert!(
        stderr.contains("IPE-T0001") && stderr.contains("TYPE MISMATCH"),
        "the rendered tag-role mismatch diagnostic must be shown, got:\n{stderr}"
    );
    Ok(())
}

/// SECURITY: the verifier's three slots are three distinct roles. A `Key` in
/// the tag slot and a `Mac` in the message slot are each a compile-time TYPE
/// MISMATCH, so a secret cannot stand in for a tag nor a tag for a message.
#[test]
fn crypto_verify_slot_roles_are_not_interchangeable() -> TestResult {
    for fixture_name in [
        "crypto_key_in_tag_slot_is_type_error.ipe",
        "crypto_mac_in_message_slot_is_type_error.ipe",
    ] {
        let (ok, _, stderr) = check_fixture(fixture_name)?;
        assert!(!ok, "{fixture_name} must NOT type-check");
        assert!(
            stderr.contains("IPE-T0001") && stderr.contains("TYPE MISMATCH"),
            "{fixture_name}: the role-mismatch diagnostic must be shown, got:\n{stderr}"
        );
    }
    Ok(())
}

/// SECURITY: the parsed stored-tag path type-checks. `macFromHex` parses the
/// stored hex once into a `Mac`, and `verifyHmacSha256` consumes that `Mac`.
#[test]
fn crypto_parsed_tag_verify_path_type_checks() -> TestResult {
    let (ok, stdout, stderr) = check_fixture("crypto_verify_tag_ok.ipe")?;
    assert!(
        ok,
        "the parsed-tag verify path must type-check, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("type-checks"),
        "a clean check prints a friendly success message, got:\n{stdout}"
    );
    Ok(())
}

/// SECURITY: the typed-`Key` path type-checks. A `Key` built once at the parse
/// boundary (`keyFromString`) flows into both `hmacSha256` and the AEAD
/// `aesGcmEncrypt` — the only sanctioned way to supply key material. This is the
/// positive counterpart to `crypto_raw_string_key_is_a_type_error`.
#[test]
fn crypto_typed_key_path_type_checks() -> TestResult {
    let (ok, stdout, stderr) = check_fixture("crypto_typed_key_ok.ipe")?;
    assert!(
        ok,
        "the typed-Key crypto path must type-check, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("type-checks"),
        "a clean check prints a friendly success message, got:\n{stdout}"
    );
    Ok(())
}

/// A program importing `Ipe.Test` — a compiled-source stdlib module that
/// declares its own `Test` type — must resolve through injection and type-check,
/// exactly as `ipe dev build` would. A bare single-module path fails name
/// resolution here (IPE-N0004) because the module's source is never injected.
#[test]
fn program_using_ipe_test_resolves_and_type_checks() -> TestResult {
    let (ok, stdout, stderr) = check_fixture("uses_ipe_test.ipe")?;
    assert!(
        ok,
        "an Ipe.Test-using program must type-check, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("type-checks"),
        "a clean check prints a friendly success message, got:\n{stdout}"
    );
    Ok(())
}

/// `String.fromBool`, the typed replacement for the removed prelude
/// `toString`, resolves through the compiled-source `Ipe.String` and
/// type-checks. The negative leg (bare `toString` unbound) lives in canon.
#[test]
fn string_from_bool_type_checks() -> TestResult {
    let (ok, stdout, stderr) = check_fixture("string_from_bool.ipe")?;
    assert!(
        ok,
        "`String.fromBool` must type-check, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("type-checks"),
        "a clean check prints a friendly success message, got:\n{stdout}"
    );
    Ok(())
}

/// A signature wildcard the body solves to a structure that still leaves part
/// of the type open has no sound lowering, so `type-check` refuses it with
/// IPE-T0021: a bare `any` passed to `List.length`, a `List any` passed to
/// `List.concat`, a tuple `any` holding a field-read record, and a bare record
/// `any` whose field-read `List` element is left open.
#[test]
fn wildcard_with_a_partial_solved_structure_is_refused() -> TestResult {
    for name in [
        "wildcard_list_length.ipe",
        "wildcard_nested_concat.ipe",
        "wildcard_tuple_open_record.ipe",
        "wildcard_record_list_field.ipe",
    ] {
        let (ok, _, stderr) = check_fixture(name)?;
        assert!(!ok, "{name} must be refused");
        assert!(
            stderr.contains("IPE-T0021"),
            "{name} must be refused as IPE-T0021, got:\n{stderr}"
        );
    }
    Ok(())
}

/// The acceptance side: a wildcard the body pins to one ground type through
/// the stdlib, and a bare record wildcard it field-reads, both type-check.
#[test]
fn wildcard_pinned_through_the_stdlib_type_checks() -> TestResult {
    let (ok, stdout, stderr) = check_fixture("wildcard_pinned_ok.ipe")?;
    assert!(
        ok,
        "pinned and row-record wildcards must type-check, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("type-checks"),
        "a clean check prints a friendly success message, got:\n{stdout}"
    );
    Ok(())
}

/// `check` type-checks and stops: no emitted project is written next to the
/// entry (a build would create `out/`). The entry is copied into a fresh,
/// otherwise-empty directory so any emission would be unmistakable.
#[test]
fn check_writes_no_emitted_project() -> TestResult {
    let project = fixture_project("well_typed.ipe")?;
    let dir = project_dir(&project)?;

    let (ok, _, _) = type_check_in(&dir)?;
    let out_present = dir.join("out").exists();
    let siblings: Vec<_> = std::fs::read_dir(&dir)?
        .flatten()
        .map(|e| e.path())
        .collect();

    assert!(ok, "the well-typed program must check");
    assert!(
        !out_present,
        "check must not emit an out/ directory, dir held: {siblings:?}"
    );
    Ok(())
}

/// The location line (`--> file:line:col`) and the caret/underline line of the
/// FIRST diagnostic in a rendered report — the two things a reader's eye lands
/// on. `None` if the report has no snippet band.
fn location_and_caret(report: &str) -> Option<(String, String)> {
    let mut lines = report.lines();
    let loc = lines.find(|l| l.trim_start().starts_with("--> "))?;
    // The caret line is the underline row: it carries `^` glyphs after the `|`.
    let caret = lines.find(|l| l.contains('^'))?;
    Some((loc.trim().to_owned(), caret.to_owned()))
}

/// Run `ipe dev build` on a fixture project directory, returning its combined stderr. Skips the
/// caller's assertions (returns `None`) when no runtime tree is resolvable in
/// this environment — the diagnostic under test fires at compile time, before
/// any runtime is read, so a resolvable runtime is only needed to get `build`
/// as far as the compiler.
fn build_stderr(project: &Path) -> Option<String> {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let out = Command::new(support::ipe_bin())
        .args(["dev", "build", &project.to_string_lossy()])
        .arg("--out")
        .arg(crate::support::scratch_root().join(format!("ipe_caret_build_{}", std::process::id())))
        .env("IPE_RUNTIME_DIR", &runtime)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stderr).into_owned())
}

/// `ipe type-check` must frame an unresolved-import diagnostic against the DEPENDENCY
/// module that owns it, with the caret under the real import token — identical
/// to `ipe dev build`. The fixture's error lives in `src/Lib/Helper.ipe`, one line
/// below a comment; a report framed against the entry file (the caret bug) would
/// point at an unrelated `src/Main.ipe` line instead.
#[test]
fn check_caret_matches_build_for_unresolved_import_in_dependency() -> TestResult {
    let project = fixture_project("multi_unresolved_import")?;
    let dir = project_dir(&project)?;
    let (ok, _, check_err) = type_check_in(&dir)?;
    assert!(!ok, "an unresolved import must exit non-zero");
    assert!(
        check_err.contains("IPE-N0020") && check_err.contains("Lib/Helper.ipe"),
        "check must blame the dependency module, got:\n{check_err}"
    );
    let (loc, caret) = location_and_caret(&check_err)
        .ok_or_else(|| format!("check report has no snippet band:\n{check_err}"))?;
    assert!(
        loc.contains("Lib/Helper.ipe:4:8"),
        "caret must land on the import line in the dependency, got location `{loc}`"
    );
    assert!(
        caret.contains("^^^^^^^^^^^^^^"),
        "the caret must underline `Rust.Firestore`, got:\n{caret}"
    );

    if let Some(build_err) = build_stderr(&dir) {
        let build_lc = location_and_caret(&build_err)
            .ok_or_else(|| format!("build report has no snippet band:\n{build_err}"))?;
        assert_eq!(
            (loc, caret),
            build_lc,
            "check and build must produce the identical caret"
        );
    }
    Ok(())
}

/// `ipe type-check` must frame a stdlib-qualifier-without-import diagnostic against
/// the dependency module that owns it, caret under the qualifier — identical to
/// `ipe dev build`. The fixture uses `Crypto.sha256` in `src/Lib/Calc.ipe` without
/// importing `Ipe.Crypto`.
#[test]
fn check_caret_matches_build_for_missing_qualifier_in_dependency() -> TestResult {
    let project = fixture_project("multi_missing_qualifier")?;
    let dir = project_dir(&project)?;
    let (ok, _, check_err) = type_check_in(&dir)?;
    assert!(!ok, "an unimported stdlib qualifier must exit non-zero");
    assert!(
        check_err.contains("IPE-N0034") && check_err.contains("Lib/Calc.ipe"),
        "check must blame the dependency module, got:\n{check_err}"
    );
    let (loc, caret) = location_and_caret(&check_err)
        .ok_or_else(|| format!("check report has no snippet band:\n{check_err}"))?;
    assert!(
        loc.contains("Lib/Calc.ipe:8:21"),
        "caret must land on the `Crypto` usage in the dependency, got location `{loc}`"
    );
    assert!(
        caret.contains("^^^^^^^^"),
        "the caret must underline `Crypto`, got:\n{caret}"
    );

    if let Some(build_err) = build_stderr(&dir) {
        let build_lc = location_and_caret(&build_err)
            .ok_or_else(|| format!("build report has no snippet band:\n{build_err}"))?;
        assert_eq!(
            (loc, caret),
            build_lc,
            "check and build must produce the identical caret"
        );
    }
    Ok(())
}

/// FAIL-CLOSED at the compile boundary: a `case` over a closed union with a
/// top-level catch-all (`_ ->`) that absorbs a named constructor must make
/// `ipe type-check` exit NON-ZERO with the rendered IPE-T0018 error. A mere printed
/// warning that still exits 0 would be fail-open — the exact silent-accept this
/// diagnostic exists to prevent.
#[test]
fn closed_union_catch_all_fails_check_nonzero() -> TestResult {
    let (ok, _, stderr) = check_fixture("closed_union_catch_all.ipe")?;
    assert!(
        !ok,
        "a closed-union catch-all must exit non-zero (fail-closed), got success"
    );
    assert!(
        stderr.contains("IPE-T0018"),
        "the rendered IPE-T0018 error must be shown, got:\n{stderr}"
    );
    Ok(())
}

/// FAIL-CLOSED, no artifact: the same closed-union catch-all through `ipe dev build`
/// must exit non-zero and write NO emitted crate. The entry is copied into a
/// fresh project so any `out/` emission would be unmistakable. This proves the
/// error stops the pipeline before code generation, not merely at print time.
#[test]
fn closed_union_catch_all_build_emits_no_crate() -> TestResult {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let dir = crate::support::scratch_root().join(format!(
        "ipe_t0018_no_emit_{}_{}",
        std::process::id(),
        "closed_union"
    ));
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(
        dir.join("package.ipe"),
        support::package_ipe("closed-union"),
    )?;
    std::fs::copy(
        fixture("closed_union_catch_all.ipe"),
        dir.join("src").join("Main.ipe"),
    )?;
    let out_dir = dir.join("out");

    let output = Command::new(support::ipe_bin())
        .args(["dev", "build", &dir.to_string_lossy()])
        .arg("--out")
        .arg(&out_dir)
        .env("IPE_RUNTIME_DIR", &runtime)
        .output()?;
    let ok = output.status.success();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let main_rs_present = out_dir.join("rust").join("src").join("main.rs").exists();
    std::fs::remove_dir_all(&dir)?;

    assert!(
        !ok,
        "a closed-union catch-all build must exit non-zero, got success:\n{stderr}"
    );
    assert!(
        stderr.contains("IPE-T0018"),
        "the build must render IPE-T0018, got:\n{stderr}"
    );
    assert!(
        !main_rs_present,
        "a failed compile must emit NO crate (no src/main.rs)"
    );
    Ok(())
}

/// FAIL-CLOSED on `type-check`: the reverse-associated hand-nested decoder
/// pipeline (`required "a" da (required "b" db (succeed ctor))`) silently swaps
/// same-typed fields with no type error. `ipe type-check` — the earliest
/// feedback surface, and the one that previously missed this — must reject it
/// with IPE-N0040, not print "No type errors".
#[test]
fn decoder_nested_direct_fails_check_with_n0040() -> TestResult {
    let (ok, stdout, stderr) = check_fixture("decoder_nested_direct.ipe")?;
    assert!(
        !ok,
        "a hand-nested decoder pipeline must fail type-check (fail-closed), got:\n{stdout}"
    );
    assert!(
        stderr.contains("IPE-N0040"),
        "the rendered IPE-N0040 diagnostic must be shown on the type-check path, got:\n{stderr}"
    );
    Ok(())
}

/// The binder-indirected reverse nesting — the accumulator reached through a
/// `let` binder rather than a syntactically-nested call — must ALSO be rejected
/// by `type-check` with IPE-N0040 (the binder-resolution gap).
#[test]
fn decoder_nested_through_binder_fails_check_with_n0040() -> TestResult {
    let (ok, stdout, stderr) = check_fixture("decoder_nested_binder.ipe")?;
    assert!(
        !ok,
        "a binder-indirected hand-nested decoder must fail type-check, got:\n{stdout}"
    );
    assert!(
        stderr.contains("IPE-N0040"),
        "the binder-indirected nesting must reject with IPE-N0040, got:\n{stderr}"
    );
    Ok(())
}

/// NO false positive: the idiomatic `|>` pipe form binds fields top-to-bottom
/// and must type-check clean — the gate rejects only the reverse-nested
/// spelling, never the pipe.
#[test]
fn decoder_idiomatic_pipe_form_checks_clean() -> TestResult {
    let (ok, stdout, stderr) = check_fixture("decoder_pipe_clean.ipe")?;
    assert!(
        ok,
        "the idiomatic |> decoder pipe must type-check, got stderr:\n{stderr}"
    );
    assert!(
        stdout.contains("type-checks"),
        "a clean check prints the success message, got:\n{stdout}"
    );
    Ok(())
}

#[test]
fn check_help_page_names_the_command() -> TestResult {
    let (ok, stdout, _) = run_ipe(&["type-check", "--help"])?;
    assert!(ok, "--help exits 0");
    assert!(
        stdout.contains("type-check") && stdout.contains("Type-check"),
        "help page names the command, got:\n{stdout}"
    );
    Ok(())
}

#[test]
fn check_rejects_an_unexpected_option() -> TestResult {
    // `--json` is now a valid flag; use a genuinely unknown flag here.
    let (ok, _, stderr) = run_ipe(&["type-check", "--definitely-unknown-flag-xyz"])?;
    assert!(!ok, "an unknown flag is misuse");
    assert!(
        stderr.contains("unknown flag"),
        "the misuse reason must name the flag, got:\n{stderr}"
    );
    Ok(())
}

/// Write a manifest-governed project whose nested `src/Api/Handlers.ipe`
/// imports `Api.Types` by its full module path, and return its root.
fn nested_import_project(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let root = support::scratch_root().join(name);
    let _ = std::fs::remove_dir_all(&root);
    let api = root.join("src").join("Api");
    std::fs::create_dir_all(&api)?;
    std::fs::write(root.join("package.ipe"), support::package_ipe("app"))?;
    std::fs::write(
        root.join("src").join("Main.ipe"),
        "module Main exposing (main)\nmain = 1\n",
    )?;
    std::fs::write(
        api.join("Types.ipe"),
        "module Api.Types exposing (id)\nid = 1\n",
    )?;
    std::fs::write(
        api.join("Handlers.ipe"),
        "module Api.Handlers exposing (handler)\nimport Api.Types as Types\nhandler = Types.id\n",
    )?;
    Ok(root)
}

/// Run `ipe type-check <arg>` from `cwd`, capturing `(success, stderr)`.
fn type_check_from(cwd: &Path, arg: &str) -> Result<(bool, String), Box<dyn Error>> {
    let out = Command::new(support::ipe_bin())
        .args(["type-check", arg])
        .current_dir(cwd)
        .output()?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// A cwd-relative file argument is project-rooted: the nested import resolves
/// against the whole `src/` tree, which only a source-rooted analysis sees
/// (the loose closure rooted at `src/Api/` cannot find `Api.Types`). The root
/// is the current directory alone, so the same file named from `src/` — a
/// directory with no `package.ipe` — is refused, never walked up from.
#[test]
fn relative_nested_src_file_argument_is_analysed_against_the_src_tree() -> TestResult {
    let root = nested_import_project("type_check_relative_nested_src_arg")?;
    let relative = type_check_from(&root, "src/Api/Handlers.ipe");
    let dotted = type_check_from(&root.join("src"), "../src/Api/Handlers.ipe");
    let _ = std::fs::remove_dir_all(&root);
    let (ok, stderr) = relative?;
    assert!(
        ok,
        "a cwd-relative nested src file must type-check, got:\n{stderr}"
    );
    let (ok, stderr) = dotted?;
    assert!(
        !ok && stderr.contains("IPE-E0004") && stderr.contains("no package.ipe at"),
        "a subdirectory of a project is no root, got:\n{stderr}"
    );
    Ok(())
}

/// A cwd-relative file argument that does not exist is refused, never
/// substituted for the project's default entry.
#[test]
fn relative_missing_file_argument_is_refused() -> TestResult {
    let root = nested_import_project("type_check_relative_missing_arg")?;
    let result = type_check_from(&root, "src/Missing.ipe");
    let _ = std::fs::remove_dir_all(&root);
    let (ok, stderr) = result?;
    assert!(
        !ok,
        "a missing file argument must be refused, got:\n{stderr}"
    );
    assert!(
        stderr.contains("src/Missing.ipe"),
        "the refusal must name the missing path, not another error, got:\n{stderr}"
    );
    Ok(())
}

/// Run `ipe dev build` over a fresh project holding the fixture `name` as its
/// `src/Main.ipe`, returning `(success, stderr, main_rs_emitted)`.
fn build_fixture(name: &str, tag: &str) -> Result<(bool, String, bool), Box<dyn Error>> {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let dir =
        crate::support::scratch_root().join(format!("ipe_http_alias_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(dir.join("src"))?;
    std::fs::write(dir.join("package.ipe"), support::package_ipe(tag))?;
    std::fs::copy(fixture(name), dir.join("src").join("Main.ipe"))?;
    let out_dir = dir.join("out");
    let output = Command::new(support::ipe_bin())
        .args(["dev", "build", &dir.to_string_lossy()])
        .arg("--out")
        .arg(&out_dir)
        .env("IPE_RUNTIME_DIR", &runtime)
        .output()?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let main_rs = out_dir.join("rust").join("src").join("main.rs").exists();
    std::fs::remove_dir_all(&dir)?;
    Ok((output.status.success(), stderr, main_rs))
}

/// Whether the fixture `name` type-checks, then builds and emits a crate with
/// no IPE-I0001 (an empty-home head reaching the lowerer).
fn assert_checks_and_builds(name: &str, tag: &str) -> TestResult {
    let (ok, stdout, stderr) = check_fixture(name)?;
    assert!(ok, "{name} must type-check:\n{stdout}\n{stderr}");
    let (built, stderr, main_rs) = build_fixture(name, tag)?;
    assert!(
        built && main_rs && !stderr.contains("IPE-I0001"),
        "{name} must build and emit a crate, got:\n{stderr}"
    );
    Ok(())
}

/// A kernel type alias spelled through its module's qualifier type-checks AND
/// builds: canon expands `Http.HttpResponse` to its record body.
#[test]
fn http_response_alias_qualified_builds() -> TestResult {
    assert_checks_and_builds("http_response_alias_qualified.ipe", "http-alias-qualified")
}

/// The `exposing` spelling of the kernel alias, `import Ipe.Http exposing
/// (HttpResponse)` then a bare `HttpResponse`, type-checks AND builds.
#[test]
fn http_response_alias_exposing_builds() -> TestResult {
    assert_checks_and_builds("http_response_alias_exposing.ipe", "http-alias-exposing")
}

/// FAIL-CLOSED: a type the kernel module does not export is IPE-N0005 on both
/// `type-check` and `dev build`, never an empty-home head the lowerer trips on.
#[test]
fn unknown_type_under_kernel_qualifier_is_no_such_member() -> TestResult {
    let (ok, _, stderr) = check_fixture("http_response_alias_unknown_member.ipe")?;
    assert!(
        !ok && stderr.contains("IPE-N0005"),
        "`Http.Bogus` must fail type-check with IPE-N0005, got:\n{stderr}"
    );
    let (built, stderr, main_rs) = build_fixture(
        "http_response_alias_unknown_member.ipe",
        "http-alias-unknown",
    )?;
    assert!(
        !built && !main_rs && stderr.contains("IPE-N0005") && !stderr.contains("IPE-I0001"),
        "`Http.Bogus` must fail the build with IPE-N0005 and emit no crate, got:\n{stderr}"
    );
    Ok(())
}

/// A program every stage before lowering accepts and lowering refuses with
/// IPE-L0116: a string literal two constructor levels deep in a pattern.
const LOWERING_REFUSAL: &str = "module Main exposing (main)

import Ipe.Io as Io


f : Maybe (Maybe String) -> String
f nested =
    case nested of
        Just (Just \"x\") ->
            \"matched\"

        Nothing ->
            \"other\"

        Just _ ->
            \"other\"


main : Task Error ()
main =
    Io.println (f (Just (Just \"x\")))
";

/// The first `IPE-<letter><4 digits>` code in a rendered report.
fn first_code(report: &str) -> Option<&str> {
    report.match_indices("IPE-").find_map(|(at, _)| {
        let code = report.get(at..at.checked_add(9)?)?;
        let mut tail = code.get(4..)?.chars();
        let letter = tail.next().is_some_and(|c| c.is_ascii_uppercase());
        (letter && tail.all(|c| c.is_ascii_digit())).then_some(code)
    })
}

/// `ipe type-check` refuses a program lowering refuses, under lowering's own
/// code, so it never reports a program `ipe dev build` refuses as clean.
#[test]
fn type_check_refuses_a_lowering_refusal() -> TestResult {
    let project = SourceTree::main(LOWERING_REFUSAL).resolve()?;
    let (ok, stdout, stderr) = type_check_in(&project_dir(&project)?)?;
    assert!(
        !ok,
        "a program lowering refuses must fail type-check, got:\n{stdout}"
    );
    assert_eq!(
        first_code(&stderr),
        Some("IPE-L0116"),
        "the refusal must carry lowering's code, got:\n{stderr}"
    );
    Ok(())
}

/// A library module with the lowering refusal of [`LOWERING_REFUSAL`].
const LIBRARY_LOWERING_REFUSAL: &str = "module Lib exposing (f)


f : Maybe (Maybe String) -> String
f nested =
    case nested of
        Just (Just \"x\") ->
            \"matched\"

        Nothing ->
            \"other\"

        Just _ ->
            \"other\"
";

/// A library package is judged through lowering too: a library module lowering
/// refuses fails type-check with IPE-L0116.
#[test]
fn type_check_library_runs_lowering() -> TestResult {
    let project = SourceTree::new()
        .module("Lib", LIBRARY_LOWERING_REFUSAL)
        .field("exposedModules = [ \"Lib\" ]")
        .resolve()?;
    let (ok, stdout, stderr) = type_check_in(&project_dir(&project)?)?;
    assert!(
        !ok,
        "a library lowering refuses must fail type-check, got:\n{stdout}"
    );
    assert_eq!(
        first_code(&stderr),
        Some("IPE-L0116"),
        "the library refusal must carry lowering's code, got:\n{stderr}"
    );
    Ok(())
}

/// `ipe type-check` and the build front end give one verdict.
///
/// For each program, the first code `ipe type-check` reports equals the one
/// [`ipe::front_check`] (the `ipe dev build` pipeline short of cargo) reports,
/// and both accept the same programs.
#[test]
fn type_check_and_build_agree() -> TestResult {
    let programs = [
        ("lowering refusal", LOWERING_REFUSAL.to_owned()),
        (
            "hand-nested decoder",
            std::fs::read_to_string(fixture("decoder_nested_direct.ipe"))?,
        ),
        (
            "well-typed",
            std::fs::read_to_string(fixture("well_typed.ipe"))?,
        ),
        (
            "decoder pipe",
            std::fs::read_to_string(fixture("decoder_pipe_clean.ipe"))?,
        ),
    ];
    for (label, source) in &programs {
        let project = SourceTree::main(source).resolve()?;
        let (ok, _, stderr) = type_check_in(&project_dir(&project)?)?;
        assert!(
            ok || first_code(&stderr).is_some(),
            "{label}: a failed type-check must name a code, got:\n{stderr}"
        );
        let checked = if ok { None } else { first_code(&stderr) };
        let built = match ipe::front_check(project.root()) {
            Ok(()) => None,
            Err(ipe::CliError::Pipeline { diag, .. }) => Some(diag.code().as_str()),
            Err(other) => {
                return Err(format!("{label}: the front check could not run: {other}").into());
            }
        };
        assert_eq!(
            checked, built,
            "{label}: `ipe type-check` and the build front end disagree, type-check stderr:\n{stderr}"
        );
    }
    Ok(())
}

/// `ipe verify` stops at its type-check stage on a program lowering refuses,
/// never reaching the build stage.
#[test]
fn verify_fails_at_type_check_on_a_lowering_refusal() -> TestResult {
    let project = SourceTree::main(LOWERING_REFUSAL).resolve()?;
    let out = Command::new(support::ipe_bin())
        .args(["verify", "--json", "src/Main.ipe"])
        .current_dir(project_dir(&project)?)
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "verify must fail on a program lowering refuses, got:\n{stdout}"
    );
    assert!(
        stdout.contains(r#""stage":"type-check""#),
        "verify must fail at the type-check stage, got:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// The F18 shape: `Ipe.Time` imports `Timestamp` into its scope without
/// exporting it.
const REIMPORTED_TYPE: &str = "module Main exposing (main)

import Ipe.Io as Io
import Ipe.Time as Time


f : Time.Timestamp -> String
f _ =
    \"t\"


main : Task Error ()
main =
    Io.println \"x\"
";

/// A type a module imports into its scope but does not re-export is IPE-N0005
/// at type-check through that module's qualifier, never an internal error.
#[test]
fn qualified_reimported_type_is_refused_at_type_check() -> TestResult {
    let project = SourceTree::main(REIMPORTED_TYPE).resolve()?;
    let (ok, stdout, stderr) = type_check_in(&project_dir(&project)?)?;
    assert!(
        !ok,
        "`Time.Timestamp` is not exported by `Ipe.Time` and must fail type-check, got:\n{stdout}"
    );
    assert!(
        stderr.contains("IPE-N0005") && !stderr.contains("IPE-I0001"),
        "the refusal must be IPE-N0005 and never an internal error, got:\n{stderr}"
    );
    Ok(())
}
