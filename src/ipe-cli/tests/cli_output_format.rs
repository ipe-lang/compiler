//! Integration tests for the human-first output model: the `--plain` / `--json`
//! machine forms on the data-producing commands (`capabilities`, `diff`,
//! `version`, `explain` with no code), the reject-both-flags usage error, and
//! the flush-left / stable-schema guarantees pipelines depend on.
//!
//! These run the built binary as a subprocess (with `NO_COLOR=1` so the captured
//! non-terminal output is deterministic plain text) to observe the real streams,
//! exit codes, and byte-level output shape.
#![forbid(unsafe_code)]
// Test fixture setup: a failed `expect` IS the failure signal — the harness
// reports it as the test failure, which is the intended behaviour here.
#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

mod support;

/// One `ipe` run's observable result.
struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Run `ipe <args>` with `NO_COLOR=1`. A spawn failure folds into a non-`ok`
/// result carrying the error on stderr, surfaced through an ordinary assertion.
fn run(args: &[&str]) -> Run {
    match Command::new(support::ipe_bin())
        .args(args)
        .env("NO_COLOR", "1")
        .output()
    {
        Ok(output) => Run {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(e) => Run {
            ok: false,
            stdout: String::new(),
            stderr: format!("failed to spawn ipe {args:?}: {e}"),
        },
    }
}

/// A source file whose inferred capability set is a known, non-empty pair
/// (`network`, `clock`), for the capabilities-form assertions.
fn sample_entry() -> String {
    let path = support::manifest_dir().join("tests/fixtures/capabilities/uses_http_and_clock.ipe");
    path.to_string_lossy().into_owned()
}

// ---- version ---------------------------------------------------------------

#[test]
fn version_default_is_human_and_guttered() {
    let r = run(&["version"]);
    assert!(r.ok);
    // Human form is a screen like every other: a blank line, the guttered
    // product header, then the guttered (two-space indent) `ipe …` line.
    let mut lines = r.stdout.lines().filter(|l| !l.trim().is_empty());
    assert_eq!(
        lines.next(),
        Some(format!("  {}", ipe::style::header_line(env!("CARGO_PKG_VERSION"))).as_str()),
        "human version must open with the product header: {:?}",
        r.stdout
    );
    assert!(
        lines.next().is_some_and(|l| l.starts_with("  ipe ")),
        "human version must be guttered: {:?}",
        r.stdout
    );
    // The frame: output starts and ends with a newline.
    assert!(
        r.stdout.starts_with('\n'),
        "human version must open with a newline: {:?}",
        r.stdout
    );
}

#[test]
fn version_plain_is_the_bare_flush_left_string() {
    let r = run(&["version", "--plain"]);
    assert!(r.ok);
    let out = r.stdout.trim_end();
    assert!(!out.starts_with(' '), "--plain must be flush-left: {out:?}");
    // Exactly the version, nothing else.
    assert_eq!(out, env!("CARGO_PKG_VERSION"));
}

#[test]
fn version_json_carries_the_version_field() {
    let r = run(&["version", "--json"]);
    assert!(r.ok);
    let out = r.stdout.trim();
    assert_eq!(
        out,
        format!(
            "{{\"schema\":\"ipe.cli.version/1\",\"status\":\"ok\",\
             \"command\":\"version\",\"payload\":{{\"version\":\"{}\"}}}}",
            env!("CARGO_PKG_VERSION")
        ),
        "--json must be the shared machine envelope carrying the version payload"
    );
    assert!(!out.starts_with(' '), "--json must be flush-left");
}

// ---- capabilities ----------------------------------------------------------

#[test]
fn capabilities_default_is_human_labelled() {
    let r = run(&["capabilities", &sample_entry()]);
    assert!(r.ok, "stderr: {}", r.stderr);
    // Human form is a guttered, labelled report, not the bare list.
    assert!(
        r.stdout.contains("security capabilit"),
        "human capabilities must be labelled: {:?}",
        r.stdout
    );
    assert!(
        r.stdout
            .lines()
            .all(|l| l.is_empty() || l.starts_with("  ")),
        "human capabilities must be guttered"
    );
}

#[test]
fn capabilities_plain_is_the_bare_scriptable_list() {
    let r = run(&["capabilities", "--plain", &sample_entry()]);
    assert!(r.ok, "stderr: {}", r.stderr);
    // The historical scriptable output: bare names, one per line, flush-left.
    // This is the migration guarantee — pipelines adopt `--plain` unchanged.
    assert_eq!(r.stdout, "network\nclock\n");
}

#[test]
fn capabilities_json_is_a_stable_object() {
    let r = run(&["capabilities", "--json", &sample_entry()]);
    assert!(r.ok, "stderr: {}", r.stderr);
    assert_eq!(
        r.stdout.trim(),
        "{\"schema\":\"ipe.cli.capabilities/1\",\"status\":\"ok\",\
         \"command\":\"capabilities\",\"payload\":{\"capabilities\":[\"network\",\"clock\"]}}"
    );
}

/// Regression: `ipe capabilities` with no positional, run inside a project
/// directory (a `package.ipe` present), must resolve the project's entry `.ipe`
/// rather than trying to read the directory itself. The prior bug surfaced as a
/// raw `io error at .: Is a directory` because the bare `.` default was passed
/// straight to the source reader instead of through the same directory→entry
/// resolution `ipe type-check` uses.
#[test]
fn capabilities_in_a_project_dir_resolves_the_entry() {
    // A known-valid example project (a `package.ipe` + `src/Main.ipe`). Run
    // `capabilities` with NO positional and the project dir as the working
    // directory, exactly as the bug report did.
    let proj = support::manifest_dir().join("../../examples/shapes/non-tea/hello-world");
    assert!(
        proj.join("package.ipe").is_file(),
        "the hello-world example must exist"
    );
    let r = match Command::new(support::ipe_bin())
        .arg("capabilities")
        .current_dir(&proj)
        .env("NO_COLOR", "1")
        .output()
    {
        Ok(o) => Run {
            ok: o.status.success(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => Run {
            ok: false,
            stdout: String::new(),
            stderr: format!("spawn failed: {e}"),
        },
    };
    assert!(
        r.ok,
        "capabilities in a project dir must succeed; stderr: {}",
        r.stderr
    );
    // The prior bug surfaced as this raw io error; it must not recur.
    assert!(
        !r.stderr.contains("Is a directory"),
        "the directory-read bug must not recur; stderr: {}",
        r.stderr
    );
    // The human report is framed (opens with a blank line) and names capabilities
    // (either the "pure" line or the "security capabilit…" heading).
    assert!(
        r.stdout.starts_with('\n')
            && (r.stdout.contains("pure") || r.stdout.contains("security capabilit")),
        "capabilities in a project dir must render the framed human report, got: {:?}",
        r.stdout
    );
}

/// Regression sibling of the capabilities bug: `ipe dev build --emit-ir` with no
/// positional, run inside a project dir, must resolve the project's entry `.ipe`
/// (a directory / bare `.` default routed to its `Main.ipe`) rather than reading
/// the directory itself and failing with a raw "Is a directory" io error.
#[test]
fn emit_ir_in_a_project_dir_resolves_the_entry() {
    let proj = support::manifest_dir().join("../../examples/shapes/non-tea/hello-world");
    assert!(
        proj.join("package.ipe").is_file(),
        "the hello-world example must exist"
    );
    let r = match Command::new(support::ipe_bin())
        .args(["dev", "build", "--emit-ir"])
        .current_dir(&proj)
        .env("NO_COLOR", "1")
        .output()
    {
        Ok(o) => Run {
            ok: o.status.success(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => Run {
            ok: false,
            stdout: String::new(),
            stderr: format!("spawn failed: {e}"),
        },
    };
    assert!(
        r.ok,
        "emit-ir in a project dir must succeed; stderr: {}",
        r.stderr
    );
    assert!(
        !r.stderr.contains("Is a directory"),
        "the directory-read bug must not recur; stderr: {}",
        r.stderr
    );
    // The IR dump is machine output: flush-left, unframed, and it names the
    // lowered program tree.
    assert!(
        r.stdout.starts_with("program"),
        "emit-ir must print the lowered IR tree, got: {:?}",
        &r.stdout[..r.stdout.len().min(40)]
    );
}

// ---- ipe doc <key> lookup --------------------------------------------------

/// `ipe explain` is retired — invoking it emits a pointer to `ipe doc`.
#[test]
fn explain_is_retired_and_points_at_doc() {
    let r = run(&["explain"]);
    assert!(!r.ok, "`ipe explain` must exit non-zero");
    assert!(
        r.stderr.contains("ipe doc"),
        "`ipe explain` must mention `ipe doc` in its message, got: {:?}",
        r.stderr
    );
}

/// `ipe doc IPE-L0131` — human output is framed, guttered, and contains the code.
#[test]
fn doc_lookup_diagnostic_human_is_framed_and_guttered() {
    let r = run(&["doc", "IPE-L0131"]);
    assert!(r.ok, "ipe doc IPE-L0131 must succeed: {}", r.stderr);
    assert!(
        r.stdout.starts_with('\n') && r.stdout.ends_with('\n'),
        "lookup output must be framed, got: {:?}",
        &r.stdout[..r.stdout.len().min(40)]
    );
    assert!(
        r.stdout.contains("IPE-L0131"),
        "lookup output must mention the resolved code"
    );
}

/// `ipe doc IPE-L0131 --plain` emits flush-left, ANSI-free text.
#[test]
fn doc_lookup_diagnostic_plain_is_ansi_free() {
    let r = run(&["doc", "IPE-L0131", "--plain"]);
    assert!(r.ok, "ipe doc IPE-L0131 --plain must succeed: {}", r.stderr);
    assert!(!r.stdout.contains('\x1b'), "--plain must not contain ANSI");
    let first = r.stdout.lines().next().unwrap_or_default();
    assert!(
        !first.starts_with("  "),
        "--plain output must be flush-left, got: {first:?}"
    );
}

/// `ipe doc IPE-L0131 --json` emits the `{kind,key,text}` object.
#[test]
fn doc_lookup_diagnostic_json_emits_object() {
    let r = run(&["doc", "IPE-L0131", "--json"]);
    assert!(r.ok, "ipe doc IPE-L0131 --json must succeed: {}", r.stderr);
    let out = r.stdout.trim();
    assert!(
        out.starts_with("{\"kind\":"),
        "json must start with {{\"kind\":, got: {out:?}"
    );
    assert!(
        out.contains("\"key\":") && out.contains("\"text\":"),
        "json must carry key and text fields"
    );
    assert!(
        out.contains("\"diagnostic\""),
        "kind must be diagnostic for IPE-L0131"
    );
}

/// `ipe doc case` — construct lookup renders successfully.
#[test]
fn doc_lookup_construct_renders() {
    let r = run(&["doc", "case"]);
    assert!(r.ok, "ipe doc case must succeed: {}", r.stderr);
    assert!(
        r.stdout.contains("case"),
        "output must mention the resolved construct"
    );
}

/// `ipe doc version` — command lookup renders successfully.
#[test]
fn doc_lookup_command_renders() {
    let r = run(&["doc", "version"]);
    assert!(r.ok, "ipe doc version must succeed: {}", r.stderr);
    assert!(
        r.stdout.contains("version"),
        "output must mention the resolved command"
    );
}

// ---- reject both flags -----------------------------------------------------

#[test]
fn plain_and_json_together_is_a_usage_error_showing_help() {
    for cmd in [
        vec!["version", "--plain", "--json"],
        vec!["capabilities", "--plain", "--json"],
        vec!["doc", "IPE-L0131", "--plain", "--json"],
    ] {
        let r = run(&cmd);
        assert!(!r.ok, "`ipe {cmd:?}` must fail on both flags");
        assert!(r.stdout.is_empty(), "misuse must not write to stdout");
        assert!(
            r.stderr.contains("mutually exclusive"),
            "the reason must name the conflict for {cmd:?}: {}",
            r.stderr
        );
        // Error-shows-help: the command's own page follows the reason.
        let name = cmd.first().copied().unwrap_or_default();
        assert!(
            r.stderr.contains(&format!("ipe {name}")),
            "misuse must show the command's --help for {cmd:?}"
        );
    }
}

#[test]
fn a_repeated_format_flag_is_rejected() {
    let r = run(&["version", "--plain", "--plain"]);
    assert!(!r.ok);
    assert!(r.stderr.contains("more than once"));
}

// ---- diff ------------------------------------------------------------------

/// Write two tiny package trees — the second adds an exposed value, a compatible
/// change — and return their paths for a `diff` in report mode.
fn compatible_pkg_pair(tag: &str) -> (PathBuf, PathBuf) {
    let base = crate::support::scratch_root().join(format!(
        "ipe-fmt-diff-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let old = base.join("old");
    let new = base.join("new");
    for dir in [&old, &new] {
        std::fs::create_dir_all(dir.join("src")).expect("create temp src dir");
    }
    let v1 = "module Lib exposing (double)\n\n\n\n\
              double : Int -> Int\ndouble n =\n    n + n\n";
    let v2 = "module Lib exposing (double, triple)\n\n\n\n\
              double : Int -> Int\ndouble n =\n    n + n\n\n\n\
              triple : Int -> Int\ntriple n =\n    n + n + n\n";
    std::fs::write(old.join("src").join("Lib.ipe"), v1).expect("write old Lib");
    std::fs::write(new.join("src").join("Lib.ipe"), v2).expect("write new Lib");
    (old, new)
}

#[test]
fn diff_plain_emits_flush_left_records() {
    let (old, new) = compatible_pkg_pair("plain");
    let r = run(&[
        "diff",
        "--plain",
        &old.to_string_lossy(),
        &new.to_string_lossy(),
    ]);
    assert!(r.ok, "stderr: {}", r.stderr);
    // A flush-left `change<TAB>…` row for the added value, then a `bump` verdict.
    assert!(
        r.stdout.lines().any(|l| l.starts_with("change\t")),
        "plain diff must carry a flush-left change record:\n{}",
        r.stdout
    );
    let bump = r
        .stdout
        .lines()
        .find(|l| l.starts_with("bump\t"))
        .unwrap_or_default();
    assert!(
        bump.contains("compatible") && bump.contains("patch"),
        "plain diff must carry a bump verdict record: {bump:?}"
    );
    assert!(
        !r.stdout.lines().any(|l| l.starts_with(' ')),
        "plain diff must be flush-left"
    );
}

#[test]
fn diff_json_is_a_stable_object() {
    let (old, new) = compatible_pkg_pair("json");
    let r = run(&[
        "diff",
        "--json",
        &old.to_string_lossy(),
        &new.to_string_lossy(),
    ]);
    assert!(r.ok, "stderr: {}", r.stderr);
    let out = r.stdout.trim();
    for field in [
        "\"compatibility\":\"compatible\"",
        "\"required\":\"patch\"",
        "\"floor\":",
        "\"changes\":[",
    ] {
        assert!(out.contains(field), "json diff missing {field}:\n{out}");
    }
    assert!(!out.starts_with(' '), "json diff must be flush-left");
}

// ---- gutter + frame: human commands ----------------------------------------

/// `ipe init <dir>` prints a next-steps message: every non-blank line is
/// indented by the two-space gutter and the output opens and closes with a
/// blank line (the frame).
#[test]
fn init_human_output_is_guttered_and_framed() {
    let dir = crate::support::scratch_root().join(format!(
        "ipe-148-init-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let target = dir.join("my-app");
    let r = run(&["init", &target.to_string_lossy()]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(r.ok, "init must succeed; stderr: {}", r.stderr);
    // Every non-blank stdout line sits in the two-space gutter.
    for line in r.stdout.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("  "),
            "init output must be guttered, got: {line:?}"
        );
    }
    // The frame: output opens and closes with a blank line.
    assert!(
        r.stdout.starts_with('\n'),
        "init output must open with a newline, got: {:?}",
        &r.stdout[..r.stdout.len().min(20)]
    );
    assert!(
        r.stdout.ends_with('\n'),
        "init output must close with a newline"
    );
}

/// `ipe upgrade --dry-run` is a human-facing confirmation: guttered + framed,
/// flush stdout (not machine output).
#[test]
fn upgrade_dry_run_is_guttered_and_framed() {
    let r = run(&["upgrade", "--dry-run"]);
    assert!(r.ok, "upgrade --dry-run must exit 0; stderr: {}", r.stderr);
    // Every non-blank line is indented by the gutter.
    for line in r.stdout.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("  "),
            "upgrade --dry-run output must be guttered, got: {line:?}"
        );
    }
    assert!(
        r.stdout.starts_with('\n'),
        "upgrade --dry-run must open with a newline"
    );
    assert!(
        r.stdout.ends_with('\n'),
        "upgrade --dry-run must close with a newline"
    );
    // The actual command is in the output.
    assert!(
        r.stdout.contains("would run:"),
        "upgrade --dry-run must name the command it would run"
    );
}

// ---- upgrade no-prebuilt-binary error rendering ----------------------------

/// A genuine CLI misuse (`ipe upgrade --bad-flag`) must print the `upgrade`
/// command's `--help` page — a bad flag IS misuse, so help is appropriate.
#[test]
fn upgrade_bad_flag_shows_help() {
    let r = run(&["upgrade", "--bad-flag"]);
    assert!(!r.ok, "a bad upgrade flag must exit non-zero");
    // The help page for `upgrade` must appear on stderr.
    assert!(
        r.stderr.contains("upgrade"),
        "bad upgrade flag must print upgrade help; stderr: {}",
        r.stderr
    );
    assert!(
        r.stderr.contains("--dry-run") || r.stderr.contains("Options"),
        "bad upgrade flag must include options/help text; stderr: {}",
        r.stderr
    );
}

// ---- type-check success output ---------------------------------------------

/// `ipe type-check` on a well-typed program exits 0 and prints a guttered, framed
/// success confirmation — the human success line must not be flush-left.
#[test]
fn check_success_output_is_guttered_and_framed() {
    // Use the examples tree as a known well-typed source so no fixture is needed.
    let entry =
        support::manifest_dir().join("../../examples/shapes/non-tea/hello-world/src/Main.ipe");
    assert!(entry.is_file(), "the hello-world example must exist");
    let r = run(&["type-check", &entry.to_string_lossy()]);
    assert!(
        r.ok,
        "type-check on a well-typed program must exit 0; stderr: {}",
        r.stderr
    );
    // The success `ok` must be framed (leading newline) and guttered.
    assert!(
        r.stdout.starts_with('\n'),
        "check ok output must open with a newline: {:?}",
        r.stdout
    );
    for line in r.stdout.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("  "),
            "check ok output must be guttered, got: {line:?}"
        );
    }
}

// ---- login --status output -------------------------------------------------

/// `ipe login --status` when no token is stored must print a guttered
/// "not logged in" message — not flush-left prose.
#[test]
fn login_status_not_logged_in_is_guttered() {
    // Run with a temp HOME so no stored token is found.
    let tmp = crate::support::scratch_root().join(format!(
        "ipe-login-status-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&tmp).expect("create temp HOME");
    let r = match std::process::Command::new(support::ipe_bin())
        .args(["login", "--status"])
        .env("NO_COLOR", "1")
        .env("HOME", &tmp)
        .env_remove("XDG_CONFIG_HOME")
        .output()
    {
        Ok(o) => Run {
            ok: o.status.success(),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => Run {
            ok: false,
            stdout: String::new(),
            stderr: format!("spawn failed: {e}"),
        },
    };
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(r.ok, "login --status must exit 0; stderr: {}", r.stderr);
    assert!(
        r.stdout.contains("not logged in"),
        "login --status must report the not-logged-in state; got: {:?}",
        r.stdout
    );
    for line in r.stdout.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("  "),
            "login --status output must be guttered, got: {line:?}"
        );
    }
    assert!(
        r.stdout.starts_with('\n'),
        "login --status must open with a newline"
    );
}

/// `ipe login --signing-key` without a terminal is refused before any prompt,
/// authorization, or key file: consent cannot be given non-interactively.
#[test]
fn login_signing_key_without_a_terminal_is_refused() {
    let tmp = crate::support::scratch_root().join(format!(
        "ipe-login-signing-key-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&tmp).expect("create temp HOME");
    let output = Command::new(support::ipe_bin())
        .args(["login", "--signing-key"])
        .env("NO_COLOR", "1")
        .env("HOME", &tmp)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("IPE_PUBLISH_SIGNING_KEY")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn ipe");
    let config_dir_created = tmp.join(".config").join("ipe").exists();
    let _ = std::fs::remove_dir_all(&tmp);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "login --signing-key must fail without a terminal"
    );
    assert!(
        stderr.contains("interactive terminal"),
        "the refusal names the missing terminal; got: {stderr:?}"
    );
    assert!(
        !config_dir_created,
        "no key file or config dir is written by a refused setup"
    );
}

/// `CliError::UpgradeNoPrebuilt` must render as a self-contained diagnostic
/// — no `--help` page, no `ipe: ` prefix — because it is an operational
/// failure (the release exists but the CI artifacts are still uploading), not
/// CLI misuse.
#[test]
fn upgrade_no_prebuilt_renders_message_without_help() {
    let err = ipe::CliError::UpgradeNoPrebuilt {
        version: ipe::style::TerminalSafe::sanitize("v9.9.9"),
        platform: ipe::style::TerminalSafe::sanitize("linux-x64"),
    };
    let msg = err.to_string();
    // The message names the version and platform.
    assert!(
        msg.contains("v9.9.9"),
        "UpgradeNoPrebuilt message must name the version; got: {msg:?}"
    );
    assert!(
        msg.contains("linux-x64"),
        "UpgradeNoPrebuilt message must name the platform; got: {msg:?}"
    );
    // The message includes the "still being generated" hint.
    assert!(
        msg.contains("still being generated"),
        "UpgradeNoPrebuilt message must include the generation hint; got: {msg:?}"
    );
    // The message points at building from source.
    assert!(
        msg.contains("cargo install"),
        "UpgradeNoPrebuilt message must point at cargo install; got: {msg:?}"
    );
    // The error MUST NOT contain the `--help` / options block that misuse shows.
    assert!(
        !msg.contains("--dry-run") && !msg.contains("Options:"),
        "UpgradeNoPrebuilt must not include the --help options page; got: {msg:?}"
    );
    // Every non-blank line must be guttered (2-space indent) — same as all
    // other human-facing output.
    for line in msg.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("  "),
            "UpgradeNoPrebuilt message must be guttered; got line: {line:?}"
        );
    }
}

// ---- misuse discipline -----------------------------------------------------

/// A representative set of commands whose unknown-flag path must exit non-zero
/// and show that command's `--help` page — never swallow the flag and exit 0.
#[test]
fn unknown_flag_shows_help_and_exits_nonzero() {
    for name in ["capabilities", "diff", "doc"] {
        let r = run(&[name, "--nope"]);
        assert!(
            !r.ok,
            "`ipe {name} --nope` must exit non-zero, not swallow the flag"
        );
        assert!(
            r.stderr
                .contains(&format!("ipe {name}: unknown flag `--nope`")),
            "`ipe {name} --nope` must use the shared misuse phrasing, got:\n{}",
            r.stderr
        );
    }
}

/// `ipe remove --nope` must reject the flag, not treat it as a package name and
/// exit 0 with "nothing to remove".
#[test]
fn remove_unknown_flag_is_rejected() {
    let r = run(&["remove", "--nope"]);
    assert!(!r.ok, "`ipe remove --nope` must exit non-zero");
    assert!(
        r.stderr.contains("ipe remove: unknown flag `--nope`"),
        "got:\n{}",
        r.stderr
    );
}

/// The top-level unknown-command screen renders fully guttered — every line,
/// header included, carries the shared gutter, so it reads identically to the
/// plain top-level page.
#[test]
fn unknown_command_screen_is_fully_guttered() {
    let r = run(&["frobnicate"]);
    assert!(!r.ok, "an unknown command must exit non-zero");
    let header = format!(
        "\n  {}\n\n",
        ipe::style::header_line(env!("CARGO_PKG_VERSION"))
    );
    assert!(
        r.stderr
            .strip_prefix(&header)
            .is_some_and(|rest| rest.starts_with("  unknown command `frobnicate`")),
        "the product header, then the guttered advice line, must open the screen, got:\n{}",
        r.stderr
    );
    for line in r.stderr.lines().filter(|l| !l.is_empty()) {
        assert!(
            line.starts_with("  "),
            "every non-empty line of the unknown-command screen must be guttered, offending: {line:?}"
        );
    }
}

/// A missing source file renders a styled, actionable message — no `os error N`
/// errno tail, no `io error` jargon.
#[test]
fn missing_file_error_is_styled_without_errno() {
    let r = run(&["type-check", "/no/such/file.ipe"]);
    assert!(!r.ok, "a missing entry must exit non-zero");
    assert!(
        r.stderr.contains("no such file `/no/such/file.ipe`"),
        "styled NotFound message, got:\n{}",
        r.stderr
    );
    assert!(!r.stderr.contains("os error"), "leaks errno:\n{}", r.stderr);
    assert!(
        !r.stderr.contains("io error"),
        "leaks jargon:\n{}",
        r.stderr
    );
}

// ---- JSON uniformity -------------------------------------------------------

/// `ipe doc list --json` is byte-compact — no space after a comma — matching the
/// `capabilities` / `version` compact form.
#[test]
fn doc_list_json_is_compact() {
    let r = run(&["doc", "list", "--json"]);
    assert!(r.ok, "doc list --json must succeed, got:\n{}", r.stderr);
    let line = r.stdout.trim();
    assert!(line.starts_with("{\"modules\":["), "shape, got:\n{line}");
    assert!(
        !line.contains(", "),
        "the JSON array must be compact (no comma-space), got:\n{line}"
    );
}

// ---- machine-flag breadth --------------------------------------------------

/// `ipe fmt --check --json` emits a compact `{"unformatted":[…]}` verdict. A
/// freshly-formatted file is a clean empty array (exit 0); an unformatted file
/// is listed (exit non-zero). Both are byte-compact.
#[test]
fn fmt_check_json_emits_compact_verdict() {
    let dir = crate::support::scratch_root().join(format!("ipe-fmt-json-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let file = dir.join("Main.ipe");

    // Format a copy in place first, so the subsequent --check is a clean scan.
    std::fs::copy(sample_entry(), &file).expect("seed the fixture");
    let fmt = run(&["fmt", file.to_str().expect("utf8")]);
    assert!(fmt.ok, "seeding format must succeed, got:\n{}", fmt.stderr);

    let clean = run(&["fmt", "--check", "--json", file.to_str().expect("utf8")]);
    assert!(
        clean.ok,
        "a formatted file passes --check, got:\n{}",
        clean.stderr
    );
    assert_eq!(clean.stdout.trim(), "{\"unformatted\":[]}");

    // Now restore the raw (unformatted) fixture and confirm the verdict lists
    // the file, compact, exit non-zero.
    std::fs::copy(sample_entry(), &file).expect("restore the unformatted fixture");
    let dirty = run(&["fmt", "--check", "--json", file.to_str().expect("utf8")]);
    assert!(!dirty.ok, "an unformatted file fails --check");
    let line = dirty.stdout.trim();
    assert!(
        line.starts_with("{\"unformatted\":[\"") && !line.contains(", "),
        "dirty verdict lists the file, compact, got:\n{line}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--plain --json` together is still rejected on a machine-flag command.
#[test]
fn fmt_check_rejects_plain_and_json_together() {
    let r = run(&["fmt", "--check", "--plain", "--json"]);
    assert!(!r.ok, "`--plain --json` together must be a usage error");
}
