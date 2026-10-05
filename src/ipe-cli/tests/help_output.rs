//! Integration tests for the `ipe` help system: the sectioned top-level
//! screen, per-command `--help` pages, exit codes, and stream routing.
//!
//! These run the built binary as a subprocess (with `NO_COLOR=1`, so the
//! captured, non-terminal output is deterministic plain text) to observe real
//! exit codes and the stdout/stderr split — properties the library API alone
//! cannot show.

use std::process::Command;

mod support;

/// One `ipe` run's observable result: exit success plus decoded streams.
struct Run {
    /// Whether the process exited zero.
    ok: bool,
    /// Decoded stdout (lossy, so a decode failure never aborts a test).
    stdout: String,
    /// Decoded stderr (lossy).
    stderr: String,
}

/// Run `ipe <args>` with `NO_COLOR=1` and a non-terminal stdout. A spawn
/// failure is folded into a non-`ok` result carrying the error on stderr, so
/// callers surface it through an ordinary assertion rather than a panic.
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

/// Top-level command names shown directly on the overview screen, for coverage
/// assertions. The dev-loop verbs (`build`/`run`/`watch`) are NOT here — they
/// are advertised under the `dev` group node, exercised separately.
const COMMANDS: &[&str] = &["init", "fix", "fmt", "rust", "doc", "lsp", "version"];
/// The `dev` group's verbs — advertised via `ipe dev`, not as top-level lines.
const DEV_VERBS: &[&str] = &["build", "run", "watch"];
const SECTIONS: &[&str] = &[
    "Development",
    "Quality",
    "Package authoring",
    "Foreign-function interface (FFI)",
    "Tools",
];

#[test]
fn top_level_help_lists_every_command_and_section() {
    let r = run(&["--help"]);
    assert!(r.ok, "`--help` must exit 0");

    // The header must carry the real "Ipê" bytes, not a filtered spelling.
    assert!(
        r.stdout.contains("Ipê language"),
        "header must read `Ipê language`"
    );
    assert!(
        r.stdout.contains(env!("CARGO_PKG_VERSION")),
        "header must carry the version"
    );

    for section in SECTIONS {
        assert!(
            r.stdout.contains(section),
            "top-level help missing section `{section}`"
        );
    }
    for cmd in COMMANDS {
        assert!(
            r.stdout.contains(&format!("ipe {cmd}")),
            "top-level help missing `ipe {cmd}`"
        );
    }
    // The `dev` group is advertised as its own node; its verbs are not top-level.
    assert!(
        r.stdout.contains("ipe dev"),
        "top-level help must advertise the `dev` group node"
    );
    for verb in DEV_VERBS {
        assert!(
            !r.stdout.contains(&format!("ipe {verb} ")),
            "dev verb `{verb}` must be grouped under `ipe dev`, not shown top-level"
        );
    }

    // With NO_COLOR set, the output is clean plain text.
    assert!(
        !r.stdout.contains('\x1b'),
        "NO_COLOR output must carry no ANSI escapes"
    );

    // The old "Run any line above…" footer sentence is gone — the screen ends at
    // the report-bugs footer, which alone remains.
    assert!(
        !r.stdout.contains("Run any line above"),
        "the how-to-read footer sentence must be removed"
    );
    assert!(
        r.stdout
            .contains("If you find any bugs, please report them at"),
        "the report-bugs footer must remain"
    );
}

#[test]
fn package_authoring_section_holds_package_and_external_packages_holds_add_remove() {
    let r = run(&["--help"]);
    assert!(r.ok);

    // Slice the two adjacent sections out of the screen by their headings so we
    // can assert which commands live under each.
    let authoring = section_body(&r.stdout, "Package authoring");
    assert!(
        authoring.contains("ipe package"),
        "`package` must sit under `Package authoring`, got:\n{authoring}"
    );

    // `add`/`remove` are de-advertised: still dispatchable, but never shown on
    // the top-level screen.
    assert!(
        !r.stdout.contains("ipe add ") && !r.stdout.contains("ipe remove "),
        "`add`/`remove` must not be advertised on the top-level screen, got:\n{}",
        r.stdout
    );
}

/// The lines belonging to the section titled `heading`: everything from the
/// heading up to the next blank line (sections are separated by a blank line).
fn section_body(screen: &str, heading: &str) -> String {
    screen
        .lines()
        .skip_while(|l| l.trim() != heading)
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn command_misuse_shows_that_commands_help_on_stderr() {
    // An unknown flag to a known command is misuse: the command's OWN `--help`
    // page goes to stderr, exit is non-zero, and stdout stays empty.
    let r = run(&["dev", "build", "--definitely-not-a-flag"]);
    assert!(!r.ok, "a misused command must exit non-zero");
    assert!(r.stdout.is_empty(), "misuse must not write to stdout");
    assert!(
        r.stderr.contains("unknown flag"),
        "the specific reason must lead the misuse output"
    );
    assert!(
        r.stderr.contains("ipe dev build") && r.stderr.contains("[--emit-ir]"),
        "misuse must show the command's full --help page on stderr"
    );
    // It is the command's page, not the top-level screen.
    assert!(
        !r.stderr.contains("Most used commands"),
        "a command misuse shows the command page, not the top-level screen"
    );
}

#[test]
fn command_help_page_is_indented_by_the_gutter() {
    // Every non-blank line of a command's `--help` page sits in the two-space
    // gutter (this page IS a command's misuse output).
    let r = run(&["fix", "--help"]);
    assert!(r.ok);
    for line in r.stdout.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("  "),
            "help line must start in the gutter: {line:?}"
        );
    }
}

#[test]
fn no_args_prints_top_level_help_and_succeeds() {
    let r = run(&[]);
    assert!(r.ok, "no args must exit 0");
    assert!(r.stdout.contains("Ipê language"));
    assert!(r.stdout.contains("Development"));
}

#[test]
fn unknown_command_shows_help_on_stderr_and_fails() {
    let r = run(&["definitely-not-a-command"]);
    assert!(!r.ok, "an unknown command must exit non-zero");
    assert!(r.stdout.is_empty(), "misuse must not write help to stdout");
    assert!(
        r.stderr.contains("Ipê language"),
        "misuse must show the help on stderr"
    );
    assert!(
        r.stderr.contains("Development"),
        "misuse help must include the sections"
    );
}

#[test]
fn mistyped_command_suggests_the_nearest_match() {
    let r = run(&["verfy"]);
    assert!(!r.ok, "a mistyped command must exit non-zero");
    assert!(
        r.stderr.contains("unknown command `verfy`"),
        "the typed token must be echoed, got:\n{}",
        r.stderr
    );
    assert!(
        r.stderr.contains("maybe `verify`?"),
        "a near-miss must suggest the closest command, got:\n{}",
        r.stderr
    );
}

#[test]
fn wildly_unknown_command_offers_no_misleading_guess() {
    let r = run(&["definitely-not-a-command"]);
    assert!(
        !r.stderr.contains("maybe `"),
        "a token far from every command must not guess, got:\n{}",
        r.stderr
    );
}

#[test]
fn every_command_has_a_help_page_via_flag_and_via_help_word() {
    for cmd in COMMANDS {
        for form in [[*cmd, "--help"], ["help", *cmd]] {
            let r = run(&form);
            assert!(r.ok, "`ipe {form:?}` must exit 0");
            assert!(
                r.stdout.contains(&format!("ipe {cmd}")),
                "`ipe {form:?}` must show the `{cmd}` synopsis"
            );
            assert!(!r.stdout.contains('\x1b'), "NO_COLOR page must be plain");
        }
    }
}

#[test]
fn command_help_lists_that_commands_options() {
    let r = run(&["dev", "build", "--help"]);
    assert!(r.ok);
    // A flag unique to `build` and its description must appear on the page.
    assert!(
        r.stdout.contains("[--emit-ir]"),
        "build --help must list --emit-ir"
    );
    assert!(
        r.stdout.contains("intermediate representation"),
        "and describe it"
    );
    // A flag that is NOT a build flag must not appear.
    assert!(
        !r.stdout.contains("--features"),
        "build --help must not list add's flags"
    );
}

#[test]
fn release_run_intercepts_its_own_help() {
    // The `release` group is advertised on the top-level screen; its `run` verb
    // is reached through it.
    let top = run(&["--help"]);
    assert!(top.ok);
    assert!(
        top.stdout.contains("ipe release"),
        "top-level help must advertise the `release` group"
    );

    // `ipe release run --help` must be intercepted as a help request: it prints
    // the command page to stdout and exits 0, rather than treating `--help` as
    // an artifact directory.
    let r = run(&["release", "run", "--help"]);
    assert!(r.ok, "`ipe release run --help` must exit 0");
    assert!(
        r.stdout.contains("ipe release run"),
        "`ipe release run --help` must show the release run synopsis"
    );
    assert!(
        r.stderr.is_empty(),
        "`ipe release run --help` must not error, got:\n{}",
        r.stderr
    );
}

#[test]
fn help_word_alone_and_help_of_unknown_both_succeed() {
    assert!(run(&["help"]).ok, "`ipe help` must exit 0");
    let r = run(&["help", "no-such-command"]);
    assert!(
        r.ok,
        "`ipe help <unknown>` must fall back to the top-level, exit 0"
    );
    assert!(r.stdout.contains("Ipê language"));
}

#[test]
fn dev_group_bare_refuses_and_its_help_flag_lists_the_verbs() {
    // A bare group names no command: it exits non-zero with nothing on stdout.
    // `ipe dev --help` is the request that teaches its verbs, exit 0.
    let bare = run(&["dev"]);
    assert!(!bare.ok, "a bare `ipe dev` must exit non-zero");
    assert!(bare.stdout.is_empty(), "a refusal must not write to stdout");

    let r = run(&["dev", "--help"]);
    assert!(r.ok, "`ipe dev --help` must exit 0");
    assert!(
        r.stderr.is_empty(),
        "`ipe dev --help` must not write to stderr"
    );
    assert!(
        r.stdout.contains("ipe dev <verb>"),
        "must show the synopsis"
    );
    for verb in DEV_VERBS {
        assert!(
            r.stdout.contains(&format!("ipe dev {verb}")),
            "`ipe dev --help` must list the `{verb}` verb"
        );
    }
}

#[test]
fn dev_unknown_verb_shows_the_subpage_on_stderr_and_fails() {
    // git-style: `ipe dev <unknown>` reports the unknown verb, then the group's
    // subpage, on stderr, and exits non-zero.
    let r = run(&["dev", "definitely-not-a-verb"]);
    assert!(!r.ok, "an unknown group verb must exit non-zero");
    assert!(r.stdout.is_empty(), "misuse must not write to stdout");
    assert!(
        r.stderr.contains("unknown `ipe dev` verb"),
        "the reason must lead the misuse output, got:\n{}",
        r.stderr
    );
    assert!(
        r.stderr.contains("ipe dev <verb>"),
        "the group subpage must follow the reason"
    );
}

#[test]
fn dev_mistyped_verb_suggests_the_nearest_member() {
    let r = run(&["dev", "biuld"]);
    assert!(!r.ok);
    assert!(
        r.stderr.contains("maybe `ipe dev build`?"),
        "a near-miss verb must suggest the closest member, got:\n{}",
        r.stderr
    );
}

#[test]
fn release_is_not_a_dev_verb_so_a_hot_reloaded_release_is_unrepresentable() {
    // The dev/release posture is a namespace, not a flag: `release` is its own
    // group with no `watch` member, so no spelling reaches a hot-reloaded
    // release build.
    let r = run(&["dev", "release"]);
    assert!(
        !r.ok,
        "`release` is not a `dev` verb — hot-reloading a shipping build is unrepresentable"
    );
    assert!(
        r.stderr.contains("unknown `ipe dev` verb `release`"),
        "routing a non-member through the group must be refused, got:\n{}",
        r.stderr
    );
}

#[test]
fn dev_verb_help_resolves_to_the_verbs_own_page_not_the_group() {
    // `ipe dev run --help` must show the RUN command page, not the group
    // subpage — help guides forward at each step.
    let grouped = run(&["dev", "run", "--help"]);
    assert!(grouped.ok, "`ipe dev run --help` must exit 0");
    assert!(
        grouped.stdout.contains("run the resulting binary"),
        "must show the `run` synopsis, got:\n{}",
        grouped.stdout
    );
}

#[test]
fn bare_dev_verbs_refuse_naming_the_grouped_form() {
    // A legacy verb name has no handler: it refuses, naming the grouped form,
    // where the grouped form reaches the verb itself.
    for verb in DEV_VERBS {
        let bare = run(&[verb]);
        assert!(!bare.ok, "a bare `ipe {verb}` must exit non-zero");
        assert!(
            bare.stderr.contains(&format!("`ipe dev {verb}`")),
            "`ipe {verb}` must name `ipe dev {verb}`, got:\n{}",
            bare.stderr
        );
        let grouped = run(&["dev", verb]);
        assert!(
            !grouped.stderr.contains("is not a command on its own"),
            "`ipe dev {verb}` must reach the verb, got:\n{}",
            grouped.stderr
        );
    }
}

/// The one frame for an error: the product header leads and every line sits in
/// the gutter. A user error (here, misuse) never invites a bug report — the
/// report-bugs footer is for ipe's own faults only.
#[test]
fn a_user_error_screen_is_framed_without_the_bug_footer() {
    let r = run(&["dev", "build", "--definitely-not-a-flag"]);
    assert!(!r.ok);
    let header = format!(
        "\n  Ipê language - v{} - {}\n",
        env!("CARGO_PKG_VERSION"),
        ipe::style::REPO_URL
    );
    assert!(r.stderr.starts_with(&header), "header leads:\n{}", r.stderr);
    assert!(
        !r.stderr.contains("please report"),
        "a user error carries no bug footer:\n{}",
        r.stderr
    );
    for line in r.stderr.lines().filter(|l| !l.is_empty()) {
        assert!(line.starts_with("  "), "line outside the gutter: {line:?}");
    }
    assert!(!r.stderr.contains('\x1b'), "NO_COLOR error is plain");
}

/// `--help --json` is machine output: no frame, no header, flush JSON.
#[test]
fn help_json_is_never_framed() {
    let r = run(&["--help", "--json"]);
    assert!(r.ok);
    assert!(r.stdout.starts_with('{'), "flush JSON:\n{}", r.stdout);
    assert!(!r.stdout.contains("Ipê language - v"), "no frame header");
}
