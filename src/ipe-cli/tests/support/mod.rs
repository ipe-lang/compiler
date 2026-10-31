//! Shared end-to-end build/run support for the golden parity gate.
//!
//! Every golden's emitted Rust project is built into ONE shared cargo target —
//! the machine-global `~/.cache/ipe-lang-target`, configured in the global
//! `~/.cargo/config.toml` (`target-dir = …`). cargo reads that file on every
//! invocation, including builds launched from an emitted project under
//! `std::env::temp_dir()`, so heavy dependencies (tokio / rsa / serde / …)
//! compile ONCE and are reused across all goldens and across runs. The target
//! is never deleted; reuse is the whole point.
//!
//! To let the per-golden root binaries coexist in that single target without
//! clobbering one another, this helper rewrites the emitted manifest to a unique
//! package (and therefore binary) name per golden before building.
//!
//! The produced binary is located ROBUSTLY by parsing
//! `cargo build --message-format=json` for the artifact's `executable` field —
//! never a hard-coded `target/debug/<name>` path, which would silently break the
//! moment the target dir moves (exactly the breakage the per-test
//! `CARGO_TARGET_DIR` override existed to paper over).
//!
//! Rigour: a build failure FAILS the test (the build assert carries cargo's
//! stderr); it is never skipped and never reported as a false green.
//!
//! The build/run plumbing lives in the shared [`e2e_support`] crate so every
//! test binary uses the same cargo-JSON parsing logic to locate the produced
//! binary.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// This crate's manifest directory, proven to exist; fails the test otherwise.
///
/// Archive-safe: the run-time `CARGO_MANIFEST_DIR` (re-rooted by
/// `nextest --workspace-remap`) wins over the compile-time path.
#[must_use]
#[allow(dead_code)] // shared across test binaries; not every one calls it
pub fn manifest_dir() -> PathBuf {
    e2e_support::manifest_dir!()
}

/// The built `ipe` binary, proven to be a regular file; fails the test otherwise.
///
/// Archive-safe: the run-time `CARGO_BIN_EXE_ipe` (re-exported by nextest)
/// wins over the compile-time path.
#[must_use]
#[allow(dead_code)] // shared across test binaries; not every one calls it
pub fn ipe_bin() -> PathBuf {
    e2e_support::cargo_bin!("ipe").into_path_buf()
}

/// Per-binary scratch root for e2e output, isolated per `CARGO_TARGET_DIR` pool
/// so two gates building from different pools never share `/tmp` and clobber
/// each other's fixed-name output (cargo sets `CARGO_TARGET_TMPDIR` at compile
/// time for integration test binaries, rooted inside that binary's own target
/// dir).
#[must_use]
#[allow(dead_code)] // adopted file-by-file as tests migrate to the shared helper
pub fn scratch_root() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// Unwrap a refusal/acceptance test's scratch-dir setup, failing the test loudly
/// when it is `None` instead of letting the caller skip silently.
///
/// A vacuous skip here would let a rejection/acceptance test pass without ever
/// running the pipeline — defeating the very SEAL coverage the test exists to
/// prove. The placeholder `PathBuf` returned after the assertion is unreachable:
/// the assertion above it already failed the test on that path.
#[must_use]
#[allow(dead_code)] // adopted file-by-file as refusal/acceptance tests migrate
#[track_caller]
pub fn expect_scratch_entry(test_name: &str, entry: Option<PathBuf>) -> PathBuf {
    assert!(
        entry.is_some(),
        "{test_name}: scratch dir setup failed — a refusal/acceptance test must \
         fail loudly, never skip silently"
    );
    entry.unwrap_or_default()
}

/// Assert a refusal/acceptance test's scratch-dir setup step (a directory
/// create, file write, or symlink) succeeded, failing the test loudly instead
/// of letting the caller skip silently on an `Err`.
///
/// See [`expect_scratch_entry`] for why a silent skip here is unacceptable.
#[allow(dead_code)] // adopted file-by-file as refusal/acceptance tests migrate
#[track_caller]
pub fn expect_scratch_step(test_name: &str, result: std::io::Result<()>) {
    assert!(
        result.is_ok(),
        "{test_name}: scratch dir setup step failed — a refusal/acceptance test \
         must fail loudly, never skip silently: {:?}",
        result.err()
    );
}

/// The `ipe-lang` workspace root (two levels up from this crate's manifest).
///
/// Shared so every golden test resolves the golden tree the same way, rather
/// than each file carrying its own hand-rolled duplicate. Derived from
/// [`manifest_dir`] so it is archive-safe. Canonicalises the `../..` join so
/// downstream path comparisons see a normalised absolute path; if
/// canonicalisation fails (e.g. a component does not exist), the un-normalised
/// join is returned unchanged — the directory the tests read always exists in a
/// checked-out tree, so the fallback is never the green path.
#[must_use]
#[allow(dead_code)] // adopted file-by-file as goldens migrate to the shared helper
pub fn repo_root() -> PathBuf {
    let joined = manifest_dir().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// The source file of module `module` (dotted, `Lib.Rows`) in the golden
/// project `dir`: `dir/src/Lib/Rows.ipe`.
///
/// Every golden is a project whose modules live under `src/`; this is the one
/// place a test spells that layout.
#[must_use]
#[allow(dead_code)] // shared helper: not every golden test binary reads a golden source
pub fn golden_source(dir: &Path, module: &str) -> PathBuf {
    let mut path = dir.join("src");
    path.extend(module.split('.'));
    path.set_extension("ipe");
    path
}

/// Render a minimal `package.ipe` manifest body naming `name` — the project
/// manifest the toolchain discovers and builds. Fixtures that only need a named
/// package write this instead of a legacy `ipe.toml`.
#[must_use]
#[allow(dead_code)] // adopted file-by-file as fixtures migrate to package.ipe
pub fn package_ipe(name: &str) -> String {
    format!("module Package exposing (package)\n\n\npackage =\n    {{ name = {name:?} }}\n")
}

/// Collapse rustfmt's whitespace-driven line-wrap noise out of emitted Rust
/// source, so a golden substring assertion tracks *token adjacency*, not one
/// specific line layout.
///
/// Once a call, type, or struct literal exceeds rustfmt's line-width limit it
/// wraps: every run of whitespace becomes a newline + indentation, and a
/// wrapped call/generic/struct list gets a trailing comma before its closing
/// `)`/`]`/`}`/`>` that the compact single-line rendering never has. Neither
/// changes the code's meaning, so both are erased here — every whitespace run
/// collapses away, and a comma immediately preceding a closing bracket is
/// dropped. The compact and wrapped renderings of the same code converge on
/// one identical normalized string, so `contains` on the normalized text
/// checks the thing that actually matters (this token sequence occurs,
/// adjacent, in this order) rather than a rustfmt version's specific wrap
/// point — the stale-substring-assertion class fixed piecemeal for #269,
/// #191, #193, #195, #175 (`Ipe.Ui.Transition`) before this helper existed.
#[must_use]
#[allow(dead_code)] // adopted incrementally as fragile golden substring checks migrate to it
pub fn normalize_rustfmt_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_whitespace() {
            continue;
        }
        if matches!(c, ')' | ']' | '}' | '>') && out.ends_with(',') {
            out.pop();
        }
        out.push(c);
    }
    out
}

/// The placeholder a blessed golden `Cargo.toml` stores in place of the
/// dependency-model runtime `path`. Aliased to the single `e2e_support`
/// definition so the CLI golden harness and the emit-corpus harness pin the
/// same token from one source of truth.
#[allow(dead_code)] // referenced by intra-doc links; the golden token, sourced from the SSOT
pub const RUNTIME_PATH_PLACEHOLDER: &str = e2e_support::RUNTIME_PATH_PLACEHOLDER;

/// Normalize an emitted `Cargo.toml`'s machine-specific bytes to their stable
/// golden placeholders — the runtime dependency `path` (→
/// [`RUNTIME_PATH_PLACEHOLDER`]) AND the per-project crate-identity hash suffix.
/// Delegates to the single `e2e_support` implementation so the compare and
/// bless paths here can never drift from it (the drift this consolidation
/// closes: a normalization change landing in one copy and not the others,
/// leaving a machine-specific value in a byte-compared golden).
#[must_use]
#[allow(dead_code)] // used by the Cargo.toml arm of the directory-diff helper
pub fn normalize_runtime_dep_path(manifest: &str) -> String {
    e2e_support::normalize_runtime_dep_path(manifest)
}

/// Collect the `.rs` filenames present in a directory, returning an empty set
/// when the directory does not exist or cannot be read.
fn rs_filenames_in(dir: &Path) -> std::collections::BTreeSet<String> {
    std::fs::read_dir(dir).map_or_else(
        |_| std::collections::BTreeSet::new(),
        |entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|e| {
                    let p = e.path();
                    if p.extension().is_some_and(|x| x == "rs") {
                        p.file_name().and_then(|n| n.to_str()).map(str::to_owned)
                    } else {
                        None
                    }
                })
                .collect()
        },
    )
}

/// Write `pairs` into `golden_dir`, normalizing `Cargo.toml` paths, and prune
/// stale `ipe_mods/*.rs` the emitted set no longer contains.
fn bless_golden_dir(
    golden_dir: &Path,
    pairs: &[(String, PathBuf)],
    emitted_mod_names: &std::collections::BTreeSet<String>,
) {
    for (rel, emitted_path) in pairs {
        let Ok(text) = std::fs::read_to_string(emitted_path) else {
            continue; // emitted file absent — nothing to bless
        };
        let blessed = if rel == "Cargo.toml" {
            normalize_runtime_dep_path(&text)
        } else {
            text
        };
        let dest = golden_dir.join(rel);
        if let Some(parent) = dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let wrote = std::fs::write(&dest, blessed);
        assert!(
            wrote.is_ok(),
            "IPE_BLESS: failed to write golden {}: {:?}",
            dest.display(),
            wrote.err()
        );
    }

    // Prune stale golden ipe_mods/*.rs the emitted set no longer contains.
    let golden_mods_dir = golden_dir.join("ipe_mods");
    if let Ok(entries) = std::fs::read_dir(&golden_mods_dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.extension().is_some_and(|x| x == "rs") {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(str::to_owned)
                    .unwrap_or_default();
                if !emitted_mod_names.contains(&name) {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}

/// Assert every byte-comparable golden output under `golden_dir` matches its
/// counterpart in the emitted project rooted at `emitted_out`, byte-for-byte.
///
/// This is the directory-diff replacement for each golden's former ad hoc
/// `read_to_string(<out>/src/main.rs)` + `assert_eq!(_, <golden>/main.rs)`
/// pair. It preserves that assertion's discriminating power exactly — a golden
/// `main.rs` is always compared — and, where a golden dir ALSO checks in a
/// root `Cargo.toml`, it additionally compares that manifest, catching
/// manifest drift the single-file assertion could not.
///
/// **Scope is manifest-authoritative, not a blind recursive diff.** A golden
/// dir carries OTHER, non-emitted fixture files (`Main.ipe`, `expected_go.txt`,
/// `oracle.meta`, and a partial `ipe_runtime/` reference tree) that the emitted
/// project does not reproduce at those paths; the walk is scoped to exactly the
/// golden's byte-diffable emitted artifacts (`main.rs` -> `<out>/src/main.rs`,
/// and `Cargo.toml` -> `<out>/Cargo.toml` WHEN the golden dir checks one in),
/// so an unrelated fixture file can never be misread as a mismatch. Both
/// under-emission (a missing emitted file) and content drift fail loudly, each
/// with the offending relative path.
///
/// **This compares `Cargo.toml` too, not only `main.rs`.** Because
/// `Cargo.toml` is compared whenever the golden dir checks one in, a test using
/// this helper gets a `Cargo.toml` comparison in addition to `main.rs`. That is
/// usually desirable (it catches manifest drift), but a stale golden
/// `Cargo.toml` surfaces as a `Cargo.toml` mismatch — a genuine finding to fix
/// at root (refresh the stale manifest), not a helper bug to route around.
///
/// **Bless mode:** if `IPE_BLESS=1` is set in the environment, instead of
/// asserting, the function writes every emitted file into `golden_dir` (creating
/// parent directories as needed), normalizing `Cargo.toml`'s machine-specific
/// runtime path to [`RUNTIME_PATH_PLACEHOLDER`] before writing so the golden
/// stays portable across machines; stale `ipe_mods/*.rs` files that the emitted
/// set no longer contains are deleted; then returns without asserting. Use to
/// regenerate golden files after an intentional emit change.
///
/// # Panics
///
/// Fails the calling test (via `assert!`) if any compared file is
/// missing/unreadable or differs from its golden counterpart, surfacing every
/// offending path in one message.
#[allow(dead_code)] // adopted file-by-file as goldens migrate to the shared helper
pub fn assert_emitted_project_matches_golden_dir(emitted_out: &Path, golden_dir: &Path) {
    // (golden-relative name, emitted path). `main.rs` is always compared;
    // `Cargo.toml` only when the golden dir checks one in — mirroring what the
    // hand-rolled per-file assertions did (all compared `main.rs`; only `basics`
    // carried a golden manifest, other goldens do not).
    let mut pairs: Vec<(String, PathBuf)> = vec![(
        "main.rs".to_owned(),
        emitted_out.join("src").join("main.rs"),
    )];
    if golden_dir.join("Cargo.toml").is_file() {
        pairs.push(("Cargo.toml".to_owned(), emitted_out.join("Cargo.toml")));
    }

    // Per-Ipê-module split files: when the emitted project splits into
    // `src/ipe_mods/<mod>.rs`, each is compared byte-for-byte against
    // `<golden_dir>/ipe_mods/<mod>.rs`. The comparison is SYMMETRIC — the
    // union of the emitted set and the golden set is walked, so an emitted file
    // the golden lacks (under-checked-in) AND a golden file the split no longer
    // emits (stale/over-checked-in) both fail loudly. A program that collapses
    // to a single file (the §3.3 Spine-collapse invariant) has no `ipe_mods/`
    // on EITHER side, so this adds nothing for those goldens.
    let emitted_mods_dir = emitted_out.join("src").join("ipe_mods");
    let emitted_mod_names = rs_filenames_in(&emitted_mods_dir);
    let golden_mod_names = rs_filenames_in(&golden_dir.join("ipe_mods"));
    let all_mod_names: std::collections::BTreeSet<&String> =
        emitted_mod_names.union(&golden_mod_names).collect();
    for name in &all_mod_names {
        pairs.push((
            format!("ipe_mods/{name}"),
            emitted_out.join("src").join("ipe_mods").join(name),
        ));
    }

    if ipe_env::var_os("IPE_BLESS").is_some() {
        bless_golden_dir(golden_dir, &pairs, &emitted_mod_names);
        return;
    }

    let normalize = |rel: &str, text: String| -> String {
        if rel == "Cargo.toml" {
            normalize_runtime_dep_path(&text)
        } else {
            text
        }
    };

    let mut mismatches = Vec::new();
    for (rel, emitted_path) in &pairs {
        let want_path = golden_dir.join(rel);
        match (
            std::fs::read_to_string(&want_path),
            std::fs::read_to_string(emitted_path).map(|t| normalize(rel, t)),
        ) {
            (Ok(want_text), Ok(got_text)) if want_text == got_text => {}
            (Ok(want_text), Ok(got_text)) => mismatches.push(format!(
                "{rel}: emitted != golden ({} vs {} bytes)\n  emitted: {}\n  golden:  {}",
                got_text.len(),
                want_text.len(),
                emitted_path.display(),
                want_path.display(),
            )),
            (Err(e), _) => mismatches.push(format!(
                "{rel}: golden missing or unreadable at {}: {e}",
                want_path.display()
            )),
            (_, Err(e)) => mismatches.push(format!(
                "{rel}: emitted missing or unreadable at {}: {e}",
                emitted_path.display()
            )),
        }
    }
    assert!(
        mismatches.is_empty(),
        "golden mismatch under {}:\n{}",
        golden_dir.display(),
        mismatches.join("\n")
    );
}

/// Concatenate the text of every emitted Ipê-side `.rs` file under
/// `<emitted_out>/src` — `src/main.rs` plus every `src/ipe_mods/*.rs` the
/// per-Ipê-module split may have written — into ONE
/// string, so a substring assertion is robust to WHICH file the split placed
/// a symbol in.
///
/// The vendored `src/ipe_runtime/` tree is deliberately EXCLUDED: it is the
/// fixed kernel runtime, identical for every program, and a substring test
/// asserting "the emitted program carries symbol X" means X in the emitted
/// USER/stdlib-source code, never a coincidental match inside the runtime
/// shim. Scoping to `main.rs` + `ipe_mods/*.rs` keeps that discrimination
/// exactly as sharp as the old `read_to_string(src/main.rs)` had it while no
/// longer caring whether the split relocated X out of `main.rs` into a
/// `ipe_mods/<mod>.rs` file (the correct new multi-file behaviour).
///
/// # Panics
///
/// Fails the calling test (via `assert!`) if `src/main.rs` is missing or
/// unreadable — a green path always emits it, so its absence is a real
/// failure, never silently a no-op empty haystack. A missing `ipe_mods/`
/// directory is NOT a failure: the Spine-collapse invariant (§3.3) legitimately
/// emits no `ipe_mods/` for a single-home program.
/// The emitted signature of the function spelled `ipe_name`, from its `fn`
/// line through the line that opens its body.
///
/// Matches the emitted `main_<snake_case>` name with its underscores removed
/// against the lower-cased Ipê name, so a check does not re-derive the
/// backend's snake-casing. Generics wrapped over several lines stay whole.
#[must_use]
#[allow(dead_code)] // used by the generic-bound goldens only
pub fn emitted_signature(emitted: &str, ipe_name: &str) -> Option<String> {
    let wanted = format!("main{}", ipe_name.to_lowercase());
    let lines = emitted.lines().skip_while(|line| {
        !line.split_once("fn ").is_some_and(|(_, rest)| {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .filter(|c| *c != '_')
                .collect();
            name == wanted
        })
    });
    let mut signature = String::new();
    for line in lines {
        signature.push_str(line);
        signature.push('\n');
        if line.contains('{') {
            return Some(signature);
        }
    }
    None
}

#[must_use]
#[allow(dead_code)] // adopted file-by-file as substring goldens migrate to the shared helper
pub fn read_all_emitted_src(emitted_out: &Path) -> String {
    let src = emitted_out.join("src");
    let main_rs = src.join("main.rs");
    let main_text = std::fs::read_to_string(&main_rs);
    assert!(
        main_text.is_ok(),
        "emitted main.rs must exist and be readable at {}: {:?}",
        main_rs.display(),
        main_text.as_ref().err(),
    );
    let mut combined = main_text.unwrap_or_default();

    // Append every `src/ipe_mods/*.rs` the split may have written, in a
    // deterministic (sorted) order so the concatenation is stable across
    // filesystems that hand back directory entries in arbitrary order. If the
    // program collapsed to a single file, this directory does not exist and
    // the loop is a no-op.
    let ipe_mods = src.join("ipe_mods");
    if let Ok(entries) = std::fs::read_dir(&ipe_mods) {
        let mut files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "rs"))
            .collect();
        files.sort();
        for path in files {
            if let Ok(text) = std::fs::read_to_string(&path) {
                combined.push('\n');
                combined.push_str(&text);
            }
        }
    }
    combined
}

/// Outcome of building and running an emitted Ipê project.
// Fields are only accessed from E2E test functions (`build_and_run_emitted`
// callers), which are absent from test binaries that skip the E2E suite (e.g.
// `golden_mm`).  `build_and_run_emitted` itself carries its own allow;
// the struct-level allow keeps the field warnings silent in those binaries.
#[allow(dead_code)]
pub struct RunOutcome {
    /// The program's standard output, decoded lossily from UTF-8.
    pub stdout: String,
    /// The process exit code (`None` if the process was killed by a signal).
    pub exit_code: Option<i32>,
}

/// Emit the checked-in golden directory `golden_dir` into `out`.
///
/// The same `ipe::build_golden_dir` `regen-goldens` blesses with, so a test
/// compares against bytes built by one code path.
///
/// # Errors
/// As `ipe::build_golden_dir`.
#[allow(dead_code)] // not every golden test binary builds a golden directory
pub fn build_golden(golden_dir: &Path, out: &Path, runtime: &Path) -> Result<(), ipe::CliError> {
    ipe::build_golden_dir(golden_dir, out, runtime, &ipe::BuildOptions::from_env())
}

/// Build the emitted project at `emitted_dir` into the shared target WITHOUT
/// running it, returning `Ok(())` on a successful `cargo build` or `Err` with
/// cargo's stderr. Used by SEAL goldens whose kernel is network-effectful (e.g.
/// `Email.send`) so a run has no deterministic stdout — the SEAL proof there is
/// that ipe-0 ⇒ the emitted crate `cargo build`s. Delegates to
/// [`e2e_support::build_rust_binary`].
#[allow(dead_code)] // not every golden test binary exercises every helper
pub fn build_emitted(golden_name: &str, emitted_dir: &Path) -> Result<(), String> {
    e2e_support::build_rust_binary(golden_name, emitted_dir).map(|_| ())
}

/// Assert the SEAL for a positive-acceptance test: the program was accepted by
/// `ipe` (callers pass an already-asserted `Ok(())` from `ipe::build`) AND,
/// under `IPE_E2E=1`, the emitted crate at `emitted_dir` must `cargo build`.
///
/// This is the mandatory routing point for every test that claims
/// "ipe-accept ⇒ the emitted crate `cargo build`s" (THE SEAL). A test that
/// only asserts `ipe::build(…).is_ok()` proves only that the frontend accepts
/// the program — it gives no evidence that the emitted Rust compiles. Routing
/// through this helper closes that gap: without `IPE_E2E` it is a fast emit
/// assertion; with it, the cargo build step runs and a cargo failure fails the
/// test loudly.
///
/// Convention: every test whose doc or assertion claims THE SEAL / "ipe-accept
/// ⇒ cargo-builds" MUST call this helper or [`build_and_run_emitted`] /
/// [`build_emitted`] directly. A SEAL assertion satisfied by `is_ok()` alone
/// is a false green.
///
/// # Panics
///
/// Fails the calling test (via `assert!`) if `cargo build` fails under
/// `IPE_E2E=1`, surfacing cargo's stderr so the accept-then-cargo-fail is
/// immediately visible.
#[track_caller]
#[allow(dead_code)] // not every test binary exercises this helper
pub fn assert_seal_builds(seal_name: &str, emitted_dir: &Path) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return; // fast default gate: emit-only pass
    }
    let outcome = build_emitted(seal_name, emitted_dir);
    assert!(
        outcome.is_ok(),
        "{seal_name}: ipe accepted (exit 0) but the emitted crate FAILED to \
         `cargo build` — a SEAL break (ipe-accept ⇒ cargo-builds violated):\n{}",
        outcome.err().unwrap_or_default()
    );
}

/// Build the emitted project at `emitted_dir` into the shared target and run the
/// resulting binary, returning its captured stdout and exit code.
///
/// Delegates to [`e2e_support::build_and_run_rust`] (the same core the refresh tool
/// uses) and wraps its `Result` in a test assertion.
///
/// # Panics
///
/// Fails the calling test (via `assert!`) if the manifest cannot be retargeted,
/// if `cargo build` fails (surfacing cargo's stderr), if the produced binary
/// cannot be located in the JSON output, or if the binary cannot be executed.
/// It never returns a placeholder on a green path — a broken golden cannot pass.
#[must_use]
#[allow(dead_code)] // not every golden test binary exercises every helper
pub fn build_and_run_emitted(golden_name: &str, emitted_dir: &Path) -> RunOutcome {
    let result = e2e_support::build_and_run_rust(golden_name, emitted_dir);
    assert!(
        result.is_ok(),
        "{}",
        result.as_ref().err().map_or("", String::as_str)
    );
    let Ok(result) = result else {
        // Unreachable on a green path: the assert above already failed the test.
        return RunOutcome {
            stdout: String::new(),
            exit_code: None,
        };
    };
    RunOutcome {
        stdout: result.stdout,
        exit_code: result.exit_code,
    }
}

/// Build the emitted project and run its binary with `stdin_bytes` piped to its
/// stdin, then closed (signalling EOF), returning its captured stdout and exit
/// code.
///
/// Used by goldens that drive an interactive/line-oriented loop (e.g.
/// `Cli.tea`) past its first stdin read, which [`build_and_run_emitted`]
/// cannot exercise since it runs the binary with stdin already at EOF.
///
/// # Panics
/// Fails the calling test if the binary cannot be located (surfacing cargo's
/// stderr), or cannot be spawned with a piped stdin.
#[must_use]
#[allow(dead_code)] // only stdin-driven goldens exercise this helper
pub fn build_and_run_emitted_with_stdin(
    golden_name: &str,
    emitted_dir: &Path,
    stdin_bytes: &[u8],
) -> RunOutcome {
    let exe = e2e_support::build_rust_binary(golden_name, emitted_dir);
    assert!(
        exe.is_ok(),
        "{}",
        exe.as_ref().err().map_or("", String::as_str)
    );
    let Ok(exe) = exe else {
        return RunOutcome {
            stdout: String::new(),
            exit_code: None,
        };
    };

    let child = Command::new(&exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();
    assert!(
        child.is_ok(),
        "{golden_name}: failed to spawn `{}`: {:?}",
        exe.display(),
        child.as_ref().err()
    );
    let Ok(mut child) = child else {
        return RunOutcome {
            stdout: String::new(),
            exit_code: None,
        };
    };

    let stdin = child.stdin.take();
    assert!(stdin.is_some(), "{golden_name}: child stdin must be piped");
    let Some(mut stdin) = stdin else {
        return RunOutcome {
            stdout: String::new(),
            exit_code: None,
        };
    };
    let wrote = stdin.write_all(stdin_bytes);
    assert!(
        wrote.is_ok(),
        "{golden_name}: failed to write stdin: {wrote:?}"
    );
    drop(stdin); // close stdin so the child's reader sees EOF after these bytes

    let output = child.wait_with_output();
    assert!(
        output.is_ok(),
        "{golden_name}: failed to wait on `{exe}`: {:?}",
        output.as_ref().err()
    );
    let Ok(output) = output else {
        return RunOutcome {
            stdout: String::new(),
            exit_code: None,
        };
    };
    RunOutcome {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        exit_code: output.status.code(),
    }
}

/// Outcome of one deadline-bounded run of an emitted binary.
#[allow(dead_code)]
pub struct TimedRunOutcome {
    /// The program's standard output, decoded lossily from UTF-8.
    pub stdout: String,
    /// The program's standard error, decoded lossily from UTF-8.
    pub stderr: String,
    /// The process exit code (`None` if it was killed by a signal or at the
    /// deadline).
    pub exit_code: Option<i32>,
    /// Wall time from spawn to the observed exit.
    pub elapsed: std::time::Duration,
    /// CPU time the child used; `None` off Linux or when `/proc` is unreadable.
    pub cpu: Option<CpuTime>,
}

impl TimedRunOutcome {
    #[allow(dead_code)] // reached only from the deadline-bounded runner
    const fn failed() -> Self {
        Self {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            elapsed: std::time::Duration::ZERO,
            cpu: None,
        }
    }
}

/// User plus system CPU time of one exited child, summed over its threads.
///
/// Only the runner reads one, from the kernel's own accounting of the child
/// (elsewhere only the zero `Default` can be built), so a wall-clock reading
/// cannot stand in for it: it measures work, which the host's load (scheduler
/// delay, sibling processes) does not inflate.
#[allow(dead_code)] // only work-measuring goldens read it
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CpuTime(std::time::Duration);

#[allow(dead_code)] // only work-measuring goldens read it
impl CpuTime {
    /// The CPU time as a duration.
    #[must_use]
    pub const fn as_duration(self) -> std::time::Duration {
        self.0
    }

    /// The CPU time left after `other`, zero when `other` is larger.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

/// The kernel's clock-tick rate, `AT_CLKTCK` from this process's auxiliary vector.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // reached only from the deadline-bounded runner
fn clock_ticks_per_second() -> Option<u64> {
    const AT_CLKTCK: usize = 17;
    let auxv = std::fs::read("/proc/self/auxv").ok()?;
    let word = std::mem::size_of::<usize>();
    let word_of = |bytes: &[u8]| bytes.try_into().ok().map(usize::from_ne_bytes);
    auxv.chunks_exact(word * 2)
        .find_map(|pair| {
            let (key, value) = pair.split_at_checked(word)?;
            if word_of(key)? == AT_CLKTCK {
                word_of(value)
            } else {
                None
            }
        })
        .and_then(|hz| u64::try_from(hz).ok())
        .filter(|&hz| hz > 0)
}

/// The CPU time of the exited, not yet reaped child `pid`, from `/proc/<pid>/stat`.
///
/// The zombie keeps the kernel's whole-process `utime` and `stime` (fields 14
/// and 15, in clock ticks) until it is reaped.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // reached only from the deadline-bounded runner
fn zombie_cpu_time(pid: u32) -> Option<CpuTime> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` (field 2) may hold spaces and parentheses; the fields after its
    // last `)` start at `state` (field 3).
    let (_, after_comm) = stat.rsplit_once(')')?;
    let mut fields = after_comm.split_whitespace().skip(11);
    let utime: u64 = fields.next()?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    let nanos = utime
        .checked_add(stime)?
        .checked_mul(1_000_000_000)?
        .checked_div(clock_ticks_per_second()?)?;
    Some(CpuTime(std::time::Duration::from_nanos(nanos)))
}

/// One non-blocking poll of `child`: its exit status and CPU time once exited.
///
/// The exit is observed with `waitid(WNOWAIT)`, which leaves the child a zombie
/// whose CPU time is still readable, and only then reaped.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // reached only from the deadline-bounded runner
fn poll_exit(
    child: &mut std::process::Child,
) -> std::io::Result<Option<(std::process::ExitStatus, Option<CpuTime>)>> {
    use rustix::process::{Pid, WaitId, WaitidOptions, waitid};
    let options = WaitidOptions::EXITED | WaitidOptions::NOHANG | WaitidOptions::NOWAIT;
    if waitid(WaitId::Pid(Pid::from_child(child)), options)?.is_none() {
        return Ok(None);
    }
    let cpu = zombie_cpu_time(child.id());
    child.wait().map(|status| Some((status, cpu)))
}

/// One non-blocking poll of `child`: its exit status; no CPU time off Linux.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)] // reached only from the deadline-bounded runner
fn poll_exit(
    child: &mut std::process::Child,
) -> std::io::Result<Option<(std::process::ExitStatus, Option<CpuTime>)>> {
    child
        .try_wait()
        .map(|status| status.map(|status| (status, None)))
}

/// Build the emitted project at `emitted_dir` and return the guard holding its
/// binary; the binary's artifacts go when the guard drops.
///
/// # Panics
/// Fails the calling test if `cargo build` fails, surfacing cargo's stderr.
#[must_use]
#[allow(dead_code)] // only deadline-bounded goldens build once and run many times
pub fn build_emitted_binary_checked(
    golden_name: &str,
    emitted_dir: &Path,
) -> Option<e2e_support::SharedBuild> {
    let exe = e2e_support::build_rust_binary(golden_name, emitted_dir);
    assert!(
        exe.is_ok(),
        "{}",
        exe.as_ref().err().map_or("", String::as_str)
    );
    exe.ok()
}

/// Run `exe` with `stdin_bytes` on stdin, killing and reaping it at `deadline`.
///
/// The child is polled without blocking; its stdout and stderr drain on reader
/// threads so a full pipe never stalls it. Past `deadline` the child is killed
/// and reaped, so no process outlives the call.
///
/// # Panics
/// Fails the calling test if the binary cannot be spawned, its stdin cannot be
/// written, or it has not exited by `deadline` ("superlinear or hung").
#[must_use]
#[allow(dead_code)] // only deadline-bounded goldens exercise this helper
pub fn run_with_stdin_deadline(
    golden_name: &str,
    exe: &Path,
    stdin_bytes: &[u8],
    deadline: std::time::Duration,
) -> TimedRunOutcome {
    let child = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    assert!(
        child.is_ok(),
        "{golden_name}: failed to spawn `{}`: {:?}",
        exe.display(),
        child.as_ref().err()
    );
    let Ok(mut child) = child else {
        return TimedRunOutcome::failed();
    };
    let started = std::time::Instant::now();
    let stdout = child.stdout.take().map(drain_on_thread);
    let stderr = child.stderr.take().map(drain_on_thread);
    // The write runs on its own thread so a child that stops reading cannot
    // hold the caller past `deadline`; the thread drops the handle after the
    // write, which closes stdin, so the child sees EOF.
    let feed = child.stdin.take().map(|mut stdin| {
        let bytes = stdin_bytes.to_vec();
        std::thread::Builder::new().spawn(move || stdin.write_all(&bytes))
    });

    let mut polled = Ok(None);
    while started.elapsed() < deadline {
        polled = poll_exit(&mut child);
        if !matches!(polled, Ok(None)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let elapsed = started.elapsed();
    let exited = polled.as_ref().ok().copied().flatten();
    let status = exited.map(|(status, _)| status);
    let cpu = exited.and_then(|(_, cpu)| cpu);
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stdout = stdout.map_or_else(String::new, join_drain);
    let stderr = stderr.map_or_else(String::new, join_drain);
    // The child has exited or been reaped, so a pending write returns
    // `BrokenPipe` instead of blocking the join.
    let wrote = feed.map(|spawned| {
        spawned
            .map_err(|e| format!("stdin writer not spawned: {e}"))
            .and_then(|h| h.join().map_err(|_| String::from("stdin writer panicked")))
            .and_then(|w| w.map_err(|e| e.to_string()))
    });
    assert!(
        polled.is_ok(),
        "{golden_name}: failed to poll `{}`: {:?}",
        exe.display(),
        polled.err()
    );
    assert!(
        status.is_some(),
        "{golden_name}: no exit within {deadline:?}, superlinear or hung; stderr:\n{stderr}"
    );
    assert!(
        wrote.as_ref().is_none_or(Result::is_ok),
        "{golden_name}: failed to write stdin: {wrote:?}"
    );
    TimedRunOutcome {
        stdout,
        stderr,
        exit_code: status.and_then(|s| s.code()),
        elapsed,
        cpu,
    }
}

/// Build the emitted project and run it once under [`run_with_stdin_deadline`].
///
/// # Panics
/// Fails the calling test on a failed build, or as [`run_with_stdin_deadline`]
/// does.
#[must_use]
#[allow(dead_code)] // only deadline-bounded goldens exercise this helper
pub fn build_and_run_emitted_with_stdin_deadline(
    golden_name: &str,
    emitted_dir: &Path,
    stdin_bytes: &[u8],
    deadline: std::time::Duration,
) -> TimedRunOutcome {
    build_emitted_binary_checked(golden_name, emitted_dir)
        .map_or_else(TimedRunOutcome::failed, |exe| {
            run_with_stdin_deadline(golden_name, &exe, stdin_bytes, deadline)
        })
}

type Drain = std::thread::JoinHandle<Vec<u8>>;

#[allow(dead_code)] // reached only from the deadline-bounded runner
#[allow(clippy::expect_used)] // a failed precondition is the test failure
fn drain_on_thread(mut pipe: impl std::io::Read + Send + 'static) -> Drain {
    std::thread::Builder::new()
        .spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
        .expect("the OS spawns a drain thread")
}

#[allow(dead_code)] // reached only from the deadline-bounded runner
fn join_drain(handle: Drain) -> String {
    handle.join().map_or_else(
        |_| String::new(),
        |bytes| String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// Build the emitted project and run its binary with the MAIN-THREAD stack
/// capped to `stack_kib` KiB, via `bash -c 'ulimit -s <kib>; exec "$0"' <bin>`.
///
/// A deep non-TCO recursion then overflows deterministically at a few thousand
/// frames instead of needing ~10^6, so the constant-stack proof is fast and
/// robust. A stack overflow trips the guard page and `abort()`s (SIGABRT) — NOT
/// a catchable panic — so the child dies by signal and `exit_code` is `None`;
/// the TCO'd binary instead exits cleanly with `Some(0)`. Linux/macOS only (the
/// Rust backend's target).
///
/// # Panics
/// Fails the calling test if `cargo build` fails (surfacing cargo's stderr), the
/// binary cannot be located, or the `bash`/`ulimit` runner cannot be spawned.
#[must_use]
#[allow(dead_code)] // only the constant-stack golden exercises this helper
pub fn build_and_run_stack_limited(
    golden_name: &str,
    emitted_dir: &Path,
    stack_kib: u32,
) -> RunOutcome {
    let exe = e2e_support::build_rust_binary(golden_name, emitted_dir);
    assert!(
        exe.is_ok(),
        "{}",
        exe.as_ref().err().map_or("", String::as_str)
    );
    let Ok(exe) = exe else {
        return RunOutcome {
            stdout: String::new(),
            exit_code: None,
        };
    };
    // `exec "$0"` replaces the shell after `ulimit -s` lowers the soft stack
    // limit, so the child binary runs under the capped main-thread stack.
    let output = Command::new("bash")
        .arg("-c")
        .arg(format!("ulimit -s {stack_kib}; exec \"$0\""))
        .arg(&exe)
        .output();
    assert!(
        output.is_ok(),
        "{golden_name}: failed to spawn stack-limited runner: {:?}",
        output.as_ref().err()
    );
    let Ok(output) = output else {
        return RunOutcome {
            stdout: String::new(),
            exit_code: None,
        };
    };
    RunOutcome {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        exit_code: output.status.code(),
    }
}

/// Outcome of building and running an emitted project, additionally capturing
/// stderr — the channel the recursion-guard trip logs its classified line to.
#[allow(dead_code)]
pub struct RunOutcomeWithStderr {
    /// The program's standard output, decoded lossily from UTF-8.
    pub stdout: String,
    /// The program's standard error, decoded lossily from UTF-8.
    pub stderr: String,
    /// The process exit code (`None` if the process was killed by a signal —
    /// which is exactly how an UNGUARDED stack overflow presents: SIGABRT).
    pub exit_code: Option<i32>,
}

/// Build the emitted project and run its binary on the default stack, capturing
/// stdout, stderr, AND the exit code.
///
/// The recursion-guard `DoS` proof runs here: on the normalized 8 MiB stack the
/// depth budget (default `10000`) trips an unbounded recursion and unwinds into
/// the panic classifier, so the process exits with a code (`Some(1)`) after
/// logging the classified `RecursionLimit` line to stderr — never the SIGABRT
/// (`exit_code == None`, no classified line) an unguarded stack overflow would
/// produce.
///
/// # Panics
/// Fails the calling test if `cargo build` fails (surfacing cargo's stderr), the
/// binary cannot be located, or it cannot be spawned.
#[must_use]
#[allow(dead_code)] // only the recursion-guard goldens (DoS proof, `Task.loop` control) use it
pub fn build_and_run_emitted_capturing_stderr(
    golden_name: &str,
    emitted_dir: &Path,
) -> RunOutcomeWithStderr {
    build_and_run_emitted_capturing_stderr_with_env(golden_name, emitted_dir, &[])
}

/// Build the emitted project and run its binary with `env` added to its
/// environment, capturing stdout, stderr, AND the exit code.
///
/// The variables are set on the spawned child only, never on the test process.
///
/// # Panics
/// Fails the calling test if `cargo build` fails (surfacing cargo's stderr), the
/// binary cannot be located, or it cannot be spawned.
#[must_use]
#[allow(dead_code)] // only the recursion-guard and regex-ceiling goldens use it
pub fn build_and_run_emitted_capturing_stderr_with_env(
    golden_name: &str,
    emitted_dir: &Path,
    env: &[(&str, &str)],
) -> RunOutcomeWithStderr {
    let exe = e2e_support::build_rust_binary(golden_name, emitted_dir);
    assert!(
        exe.is_ok(),
        "{}",
        exe.as_ref().err().map_or("", String::as_str)
    );
    let Ok(exe) = exe else {
        return RunOutcomeWithStderr {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
        };
    };
    let output = Command::new(&exe).envs(env.iter().copied()).output();
    assert!(
        output.is_ok(),
        "{golden_name}: failed to spawn `{}`: {:?}",
        exe.display(),
        output.as_ref().err()
    );
    let Ok(output) = output else {
        return RunOutcomeWithStderr {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
        };
    };
    RunOutcomeWithStderr {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code(),
    }
}

/// Assert ipe's stdout matches the golden's captured expected output.
///
/// Reads `tests/golden/<name>/expected.txt` (the self-regression anchor) and
/// fails loudly if the file is absent or the output differs. A missing file is
/// always a hard failure — never a skip — so a golden without a captured
/// expected output cannot pass silently.
#[allow(dead_code)] // exercised by goldens with a captured expected output
#[allow(clippy::expect_used)] // a failed precondition is the test failure
pub fn assert_self_regression(golden_name: &str, golden_dir: &Path, ipe_stdout: &str) {
    // Bless mode: overwrite `expected.txt` with the compiler's actual stdout
    // instead of asserting. The counterpart to `IPE_BLESS` in the byte-diff
    // golden path, so an intentional render change is re-captured with the same
    // tooling — never hand-edited bytes.
    if ipe_env::var_os("IPE_BLESS").is_some() {
        let path = golden_dir.join(e2e_support::EXPECTED_FILE);
        let wrote = std::fs::write(&path, ipe_stdout);
        assert!(
            wrote.is_ok(),
            "IPE_BLESS: failed to write {}: {:?}",
            path.display(),
            wrote.err()
        );
        return;
    }
    let expected = e2e_support::read_expected(golden_dir);
    assert!(
        expected.is_ok(),
        "{golden_name}: {}",
        expected.as_ref().err().map_or("", String::as_str)
    );
    let expected = expected.expect("`expected` must succeed");
    assert_eq!(
        ipe_stdout, expected,
        "{golden_name}: stdout does not match expected.txt"
    );
}

/// Compatibility alias: callers that previously used `assert_go_parity` now get
/// the self-regression check (`expected.txt` instead of `expected_go.txt` +
/// `oracle.meta`). Keeping the name avoids a mass-rename across the ~72 call
/// sites — the semantics are identical: hard-fail on mismatch or missing file.
#[allow(dead_code)]
pub fn assert_go_parity(golden_name: &str, golden_dir: &Path, ipec_stdout: &str) {
    assert_self_regression(golden_name, golden_dir, ipec_stdout);
}
