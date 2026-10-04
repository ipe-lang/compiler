//! Integration tests for `ipe init`.
//!
//! The scaffolding tests run unconditionally (no network, no cargo). The
//! build test that verifies the scaffold compiles is gated on `IPE_E2E=1`, in
//! line with the other CLI E2E tests (see `run_subcommand.rs`).

use std::fs;
use std::path::PathBuf;

/// A fresh, unique temp directory for one test (removed first if present).
fn fresh_dir(tag: &str) -> PathBuf {
    let dir =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("ipe_init_test_{tag}"));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// `ipe init <name>` scaffolds the four project files, with the project name
/// threaded into `package.ipe`.
#[test]
fn init_scaffolds_project_files() {
    let dir = fresh_dir("scaffold");
    let target = dir.join("my-app");
    let args = vec!["init".to_owned(), target.to_string_lossy().into_owned()];
    let result = ipe::run_cli(&args);
    assert!(result.is_ok(), "init must succeed: {result:?}");

    for rel in [
        "package.ipe",
        "src/Main.ipe",
        "README.md",
        ".gitignore",
        "AGENTS.md",
    ] {
        assert!(
            target.join(rel).is_file(),
            "expected scaffold file {rel} to exist"
        );
    }

    let manifest = fs::read_to_string(target.join("package.ipe")).unwrap_or_default();
    assert!(
        manifest.contains("name = \"my-app\""),
        "package.ipe must carry the project name, got:\n{manifest}"
    );

    let main = fs::read_to_string(target.join("src/Main.ipe")).unwrap_or_default();
    assert!(
        main.contains("Ipe.Tea.Web") && main.contains("Increment") && main.contains("Decrement"),
        "Main.ipe must be the Ipe.Tea.Web counter"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// A second `ipe init` on an already-scaffolded directory never clobbers the
/// user's project. In this non-interactive harness (no TTY) it succeeds without
/// prompting and leaves every existing managed file byte-for-byte untouched;
/// `--force` overwrites them.
#[test]
fn init_reconciles_existing_project_without_clobbering() {
    let dir = fresh_dir("guard");
    let target = dir.join("app");
    let target_str = target.to_string_lossy().into_owned();

    let first = ipe::run_cli(&["init".to_owned(), target_str.clone()]);
    assert!(first.is_ok(), "first init must succeed: {first:?}");

    // A user edit to a managed file must survive a bare re-init.
    let main_path = target.join("src").join("Main.ipe");
    let edited = "-- my own program\nmodule Main exposing (main)\n";
    fs::write(&main_path, edited).expect("edit Main.ipe");

    let second = ipe::run_cli(&["init".to_owned(), target_str.clone()]);
    assert!(
        second.is_ok(),
        "re-init in an existing dir must not error (no TTY: it reconciles), got: {second:?}"
    );
    let after = fs::read_to_string(&main_path).unwrap_or_default();
    assert_eq!(
        after, edited,
        "a bare re-init must not overwrite an existing managed file"
    );

    // A missing managed file IS restored by a non-interactive re-init.
    let gitignore = target.join(".gitignore");
    fs::remove_file(&gitignore).expect("remove .gitignore");
    let third = ipe::run_cli(&["init".to_owned(), target_str.clone()]);
    assert!(third.is_ok(), "re-init must succeed: {third:?}");
    assert!(
        gitignore.is_file(),
        "a missing managed file must be restored by re-init"
    );

    // `--force` overwrites even an edited managed file.
    let forced = ipe::run_cli(&["init".to_owned(), target_str, "--force".to_owned()]);
    assert!(forced.is_ok(), "init --force must succeed: {forced:?}");
    let restored = fs::read_to_string(&main_path).unwrap_or_default();
    assert!(
        restored.contains("Increment") && restored.contains("Decrement"),
        "init --force must overwrite the managed file with the scaffold"
    );
    // ...but never destroys the user's version: it is backed up first.
    let backups: Vec<String> = fs::read_dir(target.join("src").join(".ipe-backup"))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| fs::read_to_string(e.path()).ok())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        backups.iter().any(|b| b == edited),
        "init --force must back up the edited Main.ipe before overwriting it"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// A fresh `ipe init` keeps the user's own files already in the target.
///
/// A fresh `ipe init` scaffolds around them and never overwrites one.
#[test]
fn init_keeps_existing_user_files_in_a_fresh_target() {
    let dir = fresh_dir("keep_user_files");
    let target = dir.join("app");
    fs::create_dir_all(&target).expect("make target");
    let readme = target.join("README.md");
    fs::write(&readme, "my notes\n").expect("write user README");

    let result = ipe::run_cli(&["init".to_owned(), target.to_string_lossy().into_owned()]);
    assert!(result.is_ok(), "init must succeed: {result:?}");
    assert_eq!(
        fs::read_to_string(&readme).unwrap_or_default(),
        "my notes\n",
        "a pre-existing README must be kept byte-for-byte"
    );
    assert!(
        target.join("src").join("Main.ipe").is_file(),
        "the scaffold is still written around the kept file"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// `ipe init` with an unrecognised flag returns a command-usage error for
/// `init` — so the caller shows init's help — never a panic.
#[test]
fn init_unknown_flag_returns_usage_error() {
    let result = ipe::run_cli(&["init".to_owned(), "--bogus".to_owned()]);
    assert!(
        matches!(
            &result,
            Err(ipe::CliError::CommandUsage { command, .. }) if *command == "init"
        ),
        "unknown flag must yield a command-usage error, got: {result:?}"
    );
}

/// Every application shape's fresh scaffold lints clean — no unused import, no
/// other finding at the gate severity. Driven from `InitShape::ALL` so a newly
/// added shape's template is swept into this proof by the same
/// exhaustiveness guard that binds it into the scaffold-build SEAL.
#[test]
fn init_scaffold_is_lint_clean_for_every_shape() {
    for shape in ipe::init::InitShape::ALL {
        let dir = fresh_dir(&format!("lint_{}", shape.label()));
        let target = dir.join("proj");
        let target_str = target.to_string_lossy().into_owned();

        let init = ipe::run_cli(&[
            "init".to_owned(),
            target_str.clone(),
            "--shape".to_owned(),
            shape.label().to_owned(),
        ]);
        assert!(
            init.is_ok(),
            "[{}] init must succeed: {init:?}",
            shape.label()
        );

        let linted = ipe::run_cli(&["lint".to_owned(), target_str]);
        assert!(
            linted.is_ok(),
            "[{}] a fresh scaffold must lint clean, got: {linted:?}",
            shape.label()
        );

        let _ = fs::remove_dir_all(&dir);
    }
}

/// The `--lib` scaffold also lints clean.
#[test]
fn init_lib_scaffold_is_lint_clean() {
    let dir = fresh_dir("lint_lib");
    let target = dir.join("libproj");
    let target_str = target.to_string_lossy().into_owned();

    let init = ipe::run_cli(&["init".to_owned(), target_str.clone(), "--lib".to_owned()]);
    assert!(init.is_ok(), "init --lib must succeed: {init:?}");

    let linted = ipe::run_cli(&["lint".to_owned(), target_str]);
    assert!(
        linted.is_ok(),
        "a fresh library scaffold must lint clean, got: {linted:?}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// E2E (gated on `IPE_E2E=1`): scaffold, `ipe dev build`, and `cargo build` a fresh
/// project of a single shape (or the `--lib` library), asserting THE SEAL —
/// `ipe`-accepts must imply `cargo`-builds. `init_args` are the `ipe init` args
/// after the target; `entry_rel` is the module entry the emitter starts from.
fn assert_scaffold_builds(
    runtime_dir: &std::path::Path,
    tag: &str,
    init_args: &[String],
    entry_rel: &std::path::Path,
) {
    let dir = fresh_dir(tag);
    let target = dir.join(tag);

    let mut argv = vec!["init".to_owned(), target.to_string_lossy().into_owned()];
    argv.extend(init_args.iter().cloned());
    let init = ipe::run_cli(&argv);
    assert!(init.is_ok(), "[{tag}] init must succeed: {init:?}");

    let entry = target.join(entry_rel);
    assert!(
        entry.is_file(),
        "[{tag}] scaffold must write the entry module {}",
        entry.display()
    );
    let out_dir = target.join("out");
    let built = ipe::build(&entry, &out_dir, runtime_dir);
    assert!(
        built.is_ok(),
        "[{tag}] ipe dev build on the scaffold must succeed: {built:?}"
    );

    let cargo_status = std::process::Command::new("cargo")
        .arg("build")
        .current_dir(&out_dir)
        .env("CARGO_TARGET_DIR", out_dir.join("target"))
        .status();
    assert!(
        matches!(&cargo_status, Ok(s) if s.success()),
        "[{tag}] cargo build on the emitted scaffold must succeed (SEAL: \
         ipe-accepts must imply cargo-builds): {cargo_status:?}"
    );

    let _ = fs::remove_dir_all(out_dir.join("target"));
    let _ = fs::remove_dir_all(&dir);
}

/// A library scaffold (`--lib`) has no runnable entry, so the compiler refuses
/// to *build* it and directs the author to `type-check` (see
/// `build_pipeline::build_project_with_options`). Its accept-side SEAL is
/// therefore a clean `ipe type-check` of the public surface — there is no
/// binary to `cargo build`.
fn assert_library_type_checks(tag: &str, init_args: &[String], entry_rel: &std::path::Path) {
    let dir = fresh_dir(tag);
    let target = dir.join(tag);

    let mut argv = vec!["init".to_owned(), target.to_string_lossy().into_owned()];
    argv.extend(init_args.iter().cloned());
    let init = ipe::run_cli(&argv);
    assert!(init.is_ok(), "[{tag}] init must succeed: {init:?}");

    let entry = target.join(entry_rel);
    assert!(
        entry.is_file(),
        "[{tag}] scaffold must write the entry module {}",
        entry.display()
    );
    let checked = ipe::run_cli(&[
        "type-check".to_owned(),
        entry.to_string_lossy().into_owned(),
    ]);
    assert!(
        checked.is_ok(),
        "[{tag}] ipe type-check on the library scaffold must succeed \
         (SEAL: ipe-accepts the library's public surface): {checked:?}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// E2E (gated on `IPE_E2E=1`): EVERY application scaffold shape compiles end to
/// end — `ipe::build` emits a Rust project and `cargo build` on it must succeed
/// (THE SEAL) — and the `--lib` library type-checks (a library has no runnable
/// entry to build). Driven from [`ipe::init::InitShape::ALL`] so a
/// newly added shape cannot silently escape the accept-then-build proof: the
/// shape's own compile-time exhaustiveness guard forces it into `ALL`, and this
/// loop then forces it through the SEAL.
#[test]
fn init_scaffold_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let runtime_dir = e2e_support::require_runtime().into_path_buf();

    // Every application shape: `ipe init <target> --shape <shape>`, entry is
    // `src/Main.ipe`. The label doubles as the temp-dir tag.
    let main_rel = PathBuf::from("src").join("Main.ipe");
    for shape in ipe::init::InitShape::ALL {
        assert_scaffold_builds(
            &runtime_dir,
            shape.label(),
            &["--shape".to_owned(), shape.label().to_owned()],
            &main_rel,
        );
    }

    // The library scaffold: `ipe init <target> --lib`. A library has no runnable
    // entry — the compiler refuses to build it and directs to `type-check` — so
    // its SEAL is a clean type-check of the public surface. The public module is
    // derived from the project name (`libproj` → `Libproj`), so the entry is
    // `src/Libproj.ipe`.
    assert_library_type_checks(
        "libproj",
        &["--lib".to_owned()],
        &PathBuf::from("src").join("Libproj.ipe"),
    );
}
