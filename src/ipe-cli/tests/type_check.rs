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

mod support;

type TestResult = Result<(), Box<dyn Error>>;

/// Absolute path to a fixture under this crate's `tests/fixtures/type_check`.
fn fixture(name: &str) -> PathBuf {
    support::manifest_dir()
        .join("tests/fixtures/type_check")
        .join(name)
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
    let (ok, stdout, _) = run_ipe(&["type-check", &fixture("well_typed.ipe").to_string_lossy()])?;
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
    let (ok, _, stderr) = run_ipe(&["type-check", &fixture("type_error.ipe").to_string_lossy()])?;
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
    let (ok, _, stderr) = run_ipe(&[
        "type-check",
        &fixture("shadowable_builtin_shadow_is_type_error.ipe").to_string_lossy(),
    ])?;
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
    let (ok, _, stderr) = run_ipe(&[
        "type-check",
        &fixture("crypto_raw_key_is_type_error.ipe").to_string_lossy(),
    ])?;
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

/// SECURITY: the typed-`Key` path type-checks. A `Key` built once at the parse
/// boundary (`keyFromString`) flows into both `hmacSha256` and the AEAD
/// `aesGcmEncrypt` — the only sanctioned way to supply key material. This is the
/// positive counterpart to `crypto_raw_string_key_is_a_type_error`.
#[test]
fn crypto_typed_key_path_type_checks() -> TestResult {
    let (ok, stdout, stderr) = run_ipe(&[
        "type-check",
        &fixture("crypto_typed_key_ok.ipe").to_string_lossy(),
    ])?;
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
/// exactly as `ipe build` would. A bare single-module path fails name
/// resolution here (IPE-N0004) because the module's source is never injected.
#[test]
fn program_using_ipe_test_resolves_and_type_checks() -> TestResult {
    let (ok, stdout, stderr) = run_ipe(&[
        "type-check",
        &fixture("uses_ipe_test.ipe").to_string_lossy(),
    ])?;
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

/// `check` type-checks and stops: no emitted project is written next to the
/// entry (a build would create `out/`). The entry is copied into a fresh,
/// otherwise-empty directory so any emission would be unmistakable.
#[test]
fn check_writes_no_emitted_project() -> TestResult {
    let dir =
        crate::support::scratch_root().join(format!("ipe_check_no_emit_{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let src = dir.join("Main.ipe");
    std::fs::copy(fixture("well_typed.ipe"), &src)?;

    let (ok, _, _) = run_ipe(&["type-check", &src.to_string_lossy()])?;
    let out_present = dir.join("out").exists();
    let siblings: Vec<_> = std::fs::read_dir(&dir)?
        .flatten()
        .map(|e| e.path())
        .collect();
    std::fs::remove_dir_all(&dir)?;

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

/// Run `ipe build` on a fixture entry, returning its combined stderr. Skips the
/// caller's assertions (returns `None`) when no runtime tree is resolvable in
/// this environment — the diagnostic under test fires at compile time, before
/// any runtime is read, so a resolvable runtime is only needed to get `build`
/// as far as the compiler.
fn build_stderr(entry: &Path) -> Option<String> {
    let runtime = ipe::resolve_runtime().ok()?;
    let out = Command::new(support::ipe_bin())
        .args(["build", &entry.to_string_lossy()])
        .arg("--out")
        .arg(crate::support::scratch_root().join(format!("ipe_caret_build_{}", std::process::id())))
        .env("IPE_RUNTIME_DIR", &runtime)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stderr).into_owned())
}

/// `ipe type-check` must frame an unresolved-import diagnostic against the DEPENDENCY
/// module that owns it, with the caret under the real import token — identical
/// to `ipe build`. The fixture's error lives in `src/Lib/Helper.ipe`, one line
/// below a comment; a report framed against the entry file (the caret bug) would
/// point at an unrelated `src/Main.ipe` line instead.
#[test]
fn check_caret_matches_build_for_unresolved_import_in_dependency() -> TestResult {
    let entry = fixture("multi_unresolved_import/src/Main.ipe");
    let (ok, _, check_err) = run_ipe(&["type-check", &entry.to_string_lossy()])?;
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

    if let Some(build_err) = build_stderr(&entry) {
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
/// `ipe build`. The fixture uses `Crypto.sha256` in `src/Lib/Calc.ipe` without
/// importing `Ipe.Crypto`.
#[test]
fn check_caret_matches_build_for_missing_qualifier_in_dependency() -> TestResult {
    let entry = fixture("multi_missing_qualifier/src/Main.ipe");
    let (ok, _, check_err) = run_ipe(&["type-check", &entry.to_string_lossy()])?;
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

    if let Some(build_err) = build_stderr(&entry) {
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
    let (ok, _, stderr) = run_ipe(&[
        "type-check",
        &fixture("closed_union_catch_all.ipe").to_string_lossy(),
    ])?;
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

/// FAIL-CLOSED, no artifact: the same closed-union catch-all through `ipe build`
/// must exit non-zero and write NO emitted crate. The entry is copied into a
/// fresh directory so any `out/` emission would be unmistakable. This proves the
/// error stops the pipeline before code generation, not merely at print time.
#[test]
fn closed_union_catch_all_build_emits_no_crate() -> TestResult {
    let Ok(runtime) = ipe::resolve_runtime() else {
        // No resolvable runtime in this environment; the compile-time error
        // fires before any runtime is read, and the `check` test above already
        // pins the non-zero exit. Skip the build-artifact assertion.
        return Ok(());
    };
    let dir = crate::support::scratch_root().join(format!(
        "ipe_t0018_no_emit_{}_{}",
        std::process::id(),
        "closed_union"
    ));
    std::fs::create_dir_all(&dir)?;
    let src = dir.join("Main.ipe");
    std::fs::copy(fixture("closed_union_catch_all.ipe"), &src)?;
    let out_dir = dir.join("out");

    let output = Command::new(support::ipe_bin())
        .args(["build", &src.to_string_lossy()])
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
    let (ok, stdout, stderr) = run_ipe(&[
        "type-check",
        &fixture("decoder_nested_direct.ipe").to_string_lossy(),
    ])?;
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
    let (ok, stdout, stderr) = run_ipe(&[
        "type-check",
        &fixture("decoder_nested_binder.ipe").to_string_lossy(),
    ])?;
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
    let (ok, stdout, stderr) = run_ipe(&[
        "type-check",
        &fixture("decoder_pipe_clean.ipe").to_string_lossy(),
    ])?;
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
