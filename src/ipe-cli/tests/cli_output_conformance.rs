#![forbid(unsafe_code)]
//! The four-quadrant output conformance gate.
//!
//! Every `ipe` command renders in two output modes — human (the default) and
//! machine (`--plain` / `--json`) — across two outcomes (success / failure),
//! giving four output quadrants per command. The visual and machine vocabulary
//! has an SSOT (`ipe::style` for the human look, `cli_args::json` for the machine
//! form), but which command routes which quadrant through that SSOT was, before
//! this gate, honoured only by convention.
//!
//! This file is the standing four-quadrant table AND the build-time relation
//! that keeps it honest:
//!
//! * a **registry** (`MACHINE_CONFORMANCE`) names, per machine-capable command,
//!   how to drive its machine-success and machine-failure quadrants;
//! * a **completeness relation** asserts that every command advertising
//!   `--plain`/`--json` in the help SSOT (`help::all_command_specs`) is either in
//!   the registry or in an explicit, reasoned exemption list — so a new machine
//!   command cannot silently escape the gate;
//! * uniform **SSOT invariants** are asserted over every driven quadrant: machine
//!   output never carries an ANSI escape (the disclosure/robustness boundary a
//!   human banner leaking into a `--json` stream would breach), `--json` output
//!   parses as JSON, and a machine-mode failure writes nothing to stdout and
//!   exits non-zero.
//!
//! The commands run as the built binary as a subprocess (with `NO_COLOR=1` so a
//! captured non-terminal stream is deterministic plain text), observing the real
//! streams and exit codes. Only self-contained, deterministic commands (no cargo
//! build, no network, no git) drive their success quadrant here; the heavy /
//! environment-dependent ones are exempted with a reason and covered by their own
//! integration tests — but their machine-*failure* quadrant, driven by the
//! universal `--plain --json` conflict, is still gated for every one of them.
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

/// A well-typed source file the self-contained success quadrants type-check /
/// inspect.
fn well_typed_entry() -> PathBuf {
    support::manifest_dir().join("../../examples/shapes/non-tea/hello-world/src/Main.ipe")
}

/// A fixture whose inferred capability set is a known, non-empty pair, for the
/// `capabilities` success quadrant.
fn capabilities_entry() -> PathBuf {
    support::manifest_dir().join("tests/fixtures/capabilities/uses_http_and_clock.ipe")
}

/// How a machine-capable command's success quadrant is driven, or that it is not
/// driven here (heavy / environment-dependent) and why.
enum MachineSuccess {
    /// The command's `--plain` / `--json` success is not driven in this gate
    /// (it needs a cargo build, the network, git, or a live login); the reason
    /// documents the exemption. Its machine-*failure* quadrant is still gated.
    ExemptWithReason(&'static str),
    /// Drive `--plain` and `--json` success with these extra args after the
    /// command name (the format flag is appended by the harness). `None` args
    /// entry means "no positional needed"; a `Some` closure yields the args or
    /// `None` to skip on a sparse checkout.
    Drive(fn() -> Option<Vec<String>>),
}

/// One machine-capable command's four-quadrant contract.
struct MachineConformance {
    /// The command name, matching a `help::COMMANDS` entry.
    command: &'static str,
    /// How its machine-success quadrant is driven (or why it is exempt).
    success: MachineSuccess,
}

/// The four-quadrant registry over every machine-capable command. The
/// completeness test below asserts this set equals the machine-capable commands
/// the help SSOT advertises, so the table cannot drift out of sync with the CLI.
const MACHINE_CONFORMANCE: &[MachineConformance] = &[
    MachineConformance {
        command: "version",
        success: MachineSuccess::Drive(|| Some(vec![])),
    },
    MachineConformance {
        command: "release capabilities",
        success: MachineSuccess::Drive(|| {
            Some(vec![capabilities_entry().to_string_lossy().into_owned()])
        }),
    },
    MachineConformance {
        command: "type-check",
        success: MachineSuccess::Drive(|| {
            Some(vec![well_typed_entry().to_string_lossy().into_owned()])
        }),
    },
    MachineConformance {
        command: "diff",
        success: MachineSuccess::ExemptWithReason(
            "diff needs two package trees; its machine quadrants are driven in diff_cli.rs",
        ),
    },
    MachineConformance {
        command: "lint",
        success: MachineSuccess::ExemptWithReason(
            "lint runs against a project tree; machine quadrants covered in lint.rs",
        ),
    },
    MachineConformance {
        command: "fmt",
        success: MachineSuccess::ExemptWithReason(
            "fmt --check needs a project/file context; machine quadrants covered in fmt.rs",
        ),
    },
    MachineConformance {
        command: "clean",
        success: MachineSuccess::ExemptWithReason(
            "clean mutates a project tree; machine quadrants covered in cli_output_format.rs",
        ),
    },
    MachineConformance {
        command: "package",
        success: MachineSuccess::ExemptWithReason(
            "package resolution touches the registry/network; covered in package_* tests",
        ),
    },
    MachineConformance {
        command: "doc",
        success: MachineSuccess::ExemptWithReason(
            "doc renders a bundle/serves; machine quadrants covered in doc_subcommand.rs",
        ),
    },
    MachineConformance {
        command: "upgrade",
        success: MachineSuccess::ExemptWithReason(
            "upgrade reaches the release feed; machine quadrants covered in cli_output_format.rs",
        ),
    },
    MachineConformance {
        command: "health",
        success: MachineSuccess::ExemptWithReason(
            "health probes the host toolchain; output varies with the environment",
        ),
    },
    MachineConformance {
        command: "dev build",
        success: MachineSuccess::ExemptWithReason(
            "dev build runs cargo; heavy, covered by the build_* integration tests",
        ),
    },
    MachineConformance {
        command: "dev run",
        success: MachineSuccess::ExemptWithReason(
            "dev run builds and executes; heavy, covered by run_subcommand.rs",
        ),
    },
    MachineConformance {
        command: "release build",
        success: MachineSuccess::ExemptWithReason(
            "release build runs cargo; heavy, covered by release_subcommand.rs",
        ),
    },
    MachineConformance {
        command: "test",
        success: MachineSuccess::ExemptWithReason(
            "test builds and runs the project test binary; heavy, covered by test_command.rs",
        ),
    },
    MachineConformance {
        command: "verify",
        success: MachineSuccess::ExemptWithReason(
            "verify runs the full gate (fmt/build/test); heavy, covered by verify.rs",
        ),
    },
];

/// Whether `flag` (a synopsis token like `"[--check --json|--plain]"`) advertises
/// a machine output flag.
fn advertises_machine_flag(flag: &str) -> bool {
    flag.contains("--json") || flag.contains("--plain")
}

/// The machine-capable command set the help SSOT advertises: every command whose
/// flag list mentions `--json` or `--plain`.
fn advertised_machine_commands() -> Vec<String> {
    ipe::help::all_command_specs()
        .into_iter()
        .filter(|spec| spec.options.iter().any(|o| advertises_machine_flag(o.flag)))
        .map(|spec| spec.name.to_owned())
        .collect()
}

/// A minimal structural JSON well-formedness check: the trimmed text is a single
/// balanced JSON value with matched brackets and balanced quotes, no trailing
/// garbage. Enough to catch a machine stream that leaked human banner prose or a
/// truncated object into a `--json` quadrant, without pulling in a JSON crate.
fn is_well_formed_json(text: &str) -> bool {
    let s = text.trim();
    if s.is_empty() {
        return false;
    }
    let mut depth: i64 = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut saw_top_value = false;
    for c in s.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                if depth == 0 {
                    saw_top_value = true;
                }
            }
            '{' | '[' => {
                depth += 1;
                saw_top_value = true;
            }
            '}' | ']' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            // A bare top-level scalar (number/true/false/null) also counts as a value.
            c if !c.is_whitespace() && depth == 0 => saw_top_value = true,
            _ => {}
        }
    }
    depth == 0 && !in_string && saw_top_value
}

/// The registry must name exactly the machine-capable commands the help SSOT
/// advertises — no missing entry (a new machine command that escaped the gate)
/// and no stale entry (a registry row for a command that no longer takes a
/// machine flag). This is the build-time relation that keeps the four-quadrant
/// table from rotting: adding `--json`/`--plain` to a command in `help::COMMANDS`
/// forces a conformance entry here.
#[test]
fn registry_covers_exactly_the_advertised_machine_commands() {
    use std::collections::BTreeSet;
    let advertised: BTreeSet<String> = advertised_machine_commands().into_iter().collect();
    let registered: BTreeSet<String> = MACHINE_CONFORMANCE
        .iter()
        .map(|c| c.command.to_owned())
        .collect();

    let missing: Vec<&String> = advertised.difference(&registered).collect();
    let stale: Vec<&String> = registered.difference(&advertised).collect();

    assert!(
        missing.is_empty(),
        "these commands advertise --json/--plain in the help SSOT but have no \
         four-quadrant conformance entry (wire their quadrants into \
         MACHINE_CONFORMANCE): {missing:?}",
    );
    assert!(
        stale.is_empty(),
        "these MACHINE_CONFORMANCE entries name a command that no longer \
         advertises --json/--plain — remove the stale row: {stale:?}",
    );

    // Every exemption carries a non-empty reason: an exempt command's machine
    // success is not driven here, so the reason is the record of why and where
    // it is covered instead — an empty reason is an untracked gap.
    for entry in MACHINE_CONFORMANCE {
        if let MachineSuccess::ExemptWithReason(reason) = &entry.success {
            assert!(
                !reason.trim().is_empty(),
                "exempt command `{}` must document why its machine-success \
                 quadrant is not driven here",
                entry.command,
            );
        }
    }
}

/// The machine-failure quadrant, driven uniformly for EVERY machine-capable
/// command by the `--plain --json` conflict (a usage error every command shares):
/// the run exits non-zero, writes nothing to stdout (the machine stream stays
/// clean — no half-formed record), and its stderr carries no ANSI escape under
/// `NO_COLOR`. This is the exact path a regression or an attacker walks in on: a
/// human banner or ANSI bleeding into a machine stream.
#[test]
fn machine_failure_quadrant_is_clean_for_every_command() {
    for entry in MACHINE_CONFORMANCE {
        let cmd = entry.command;
        // `doc` and `explain` take a leading positional before flags; a bare
        // `--plain --json` still resolves to the format conflict for the others.
        // A grouped verb's name (`dev build`) is its argv words.
        let args: Vec<&str> = match cmd {
            "doc" => vec!["doc", "IPE-L0131", "--plain", "--json"],
            _ => cmd.split(' ').chain(["--plain", "--json"]).collect(),
        };
        let r = run(&args);
        assert!(
            !r.ok,
            "`ipe {cmd} --plain --json` must exit non-zero (mutually exclusive): stderr={:?}",
            r.stderr
        );
        assert!(
            r.stdout.is_empty(),
            "`ipe {cmd}` machine-failure must write nothing to stdout, got: {:?}",
            r.stdout
        );
        assert!(
            !r.stdout.contains('\x1b') && !r.stderr.contains('\x1b'),
            "`ipe {cmd}` machine-failure must carry no ANSI under NO_COLOR",
        );
    }
}

/// The machine-success quadrants (`--plain` and `--json`) for the self-contained,
/// deterministic commands: exit 0, no ANSI on the machine stream, the stream is
/// flush-left (no human gutter), and `--json` parses as JSON. The heavy /
/// environment-dependent commands are exempt here (with a reason) and covered by
/// their own integration tests.
#[test]
fn machine_success_quadrants_route_through_the_ssot() {
    for entry in MACHINE_CONFORMANCE {
        let cmd = entry.command;
        let MachineSuccess::Drive(mk_args) = &entry.success else {
            continue;
        };
        let Some(extra) = mk_args() else {
            continue; // sparse checkout without the fixture — skip, never a false red
        };

        for format in ["--plain", "--json"] {
            // A grouped verb's name (`release capabilities`) is its argv words.
            let mut args: Vec<&str> = cmd.split(' ').collect();
            for a in &extra {
                args.push(a);
            }
            args.push(format);
            let r = run(&args);
            assert!(
                r.ok,
                "`ipe {cmd} {format}` must exit 0; stderr: {}",
                r.stderr
            );
            assert!(
                !r.stdout.contains('\x1b'),
                "`ipe {cmd} {format}` machine output must carry no ANSI: {:?}",
                r.stdout
            );
            // Machine output is flush-left — no two-space human gutter, no
            // leading blank frame line.
            assert!(
                !r.stdout.starts_with(' ') && !r.stdout.starts_with('\n'),
                "`ipe {cmd} {format}` machine output must be flush-left and unframed: {:?}",
                r.stdout
            );
            if format == "--json" {
                assert!(
                    is_well_formed_json(&r.stdout),
                    "`ipe {cmd} --json` must emit well-formed JSON: {:?}",
                    r.stdout
                );
            }
        }
    }
}

/// The machine-success *envelope schema* per driven `--json` command: beyond
/// well-formedness, every success record must carry the invariant envelope
/// fields the machine-output SSOT guarantees — `"schema":"ipe.cli.<x>/N"`,
/// `"status":"ok"`, `"command":"<name>"`, and a `"payload"` key. The failure
/// quadrant's envelope (`ipe.cli.error/1`, `status:error`) is already gated
/// elsewhere; this pins the *success* shape per command, which was pinned only
/// as "parses as JSON" before. A command that hand-rolled a subtly different
/// success object — a missing `status`, a renamed `command`, no `payload` — is
/// the drift this closes.
#[test]
fn machine_success_json_carries_the_envelope_schema_per_command() {
    for entry in MACHINE_CONFORMANCE {
        let cmd = entry.command;
        let MachineSuccess::Drive(mk_args) = &entry.success else {
            continue;
        };
        let Some(extra) = mk_args() else {
            continue; // sparse checkout without the fixture — skip, never a false red
        };

        let mut args: Vec<&str> = cmd.split(' ').collect();
        for a in &extra {
            args.push(a);
        }
        args.push("--json");
        let r = run(&args);
        assert!(r.ok, "`ipe {cmd} --json` must exit 0; stderr: {}", r.stderr);

        let json = r.stdout.trim();
        assert!(
            is_well_formed_json(json),
            "`ipe {cmd} --json` success must be well-formed JSON: {json:?}",
        );
        // status = ok: the success discriminant a consumer branches on.
        assert!(
            json.contains("\"status\":\"ok\""),
            "`ipe {cmd} --json` success envelope must carry status=ok: {json:?}",
        );
        // command names the producing command (the exact name from the SSOT).
        assert!(
            json.contains(&format!("\"command\":\"{cmd}\"")),
            "`ipe {cmd} --json` success envelope must name its command: {json:?}",
        );
        // A stable schema tag of the shape `ipe.cli.<x>/N` (the version-suffixed
        // contract), and a `payload` key carrying the command's own result.
        assert!(
            json.contains("\"schema\":\"ipe.cli.") && json.contains('/'),
            "`ipe {cmd} --json` success envelope must carry a versioned schema tag: {json:?}",
        );
        assert!(
            json.contains("\"payload\":"),
            "`ipe {cmd} --json` success envelope must carry a payload key: {json:?}",
        );
    }
}

/// A machine-mode operational failure that is NOT a compile diagnostic (here an
/// I/O error: `type-check --json` on a path that does not exist) must render the
/// shared machine-error envelope on stderr — never the human `Ipê lang` banner
/// leaking into a `--json` invocation. This is the disclosure boundary the
/// machine-output SSOT closes: before it, any non-`Pipeline` error under a
/// machine format fell through to the human banner path. stdout stays clean, the
/// stream carries no ANSI, and the envelope names the error schema, status, and
/// command without exposing a raw internal string.
#[test]
fn machine_mode_operational_error_routes_through_the_error_envelope() {
    let r = run(&["type-check", "--json", "/does-not-exist/nope.ipe"]);
    assert!(!r.ok, "a missing file under --json must exit non-zero");
    assert!(
        r.stdout.is_empty(),
        "a machine failure must write nothing to stdout, got: {:?}",
        r.stdout
    );
    // The human error banner (its version lead-in) must never reach the machine
    // stream — that is the exact leak the SSOT prevents.
    assert!(
        !r.stderr.contains("Ipê lang"),
        "the human banner must never leak into a --json stream: {:?}",
        r.stderr
    );
    assert!(
        !r.stdout.contains('\x1b') && !r.stderr.contains('\x1b'),
        "the machine-error stream must carry no ANSI under NO_COLOR",
    );
    let line = r.stderr.trim();
    assert!(
        is_well_formed_json(line),
        "the machine error must be well-formed JSON: {line:?}"
    );
    assert!(
        line.contains("\"schema\":\"ipe.cli.error/1\"")
            && line.contains("\"status\":\"error\"")
            && line.contains("\"command\":\"type-check\""),
        "the machine error must be the shared envelope with schema/status/command: {line:?}"
    );
}

/// The human-success quadrant for a self-contained command (`type-check` on a
/// well-typed program): the default (no machine flag) output is framed (opens
/// with a blank line) and guttered (every non-blank line indented two spaces) —
/// the human vocabulary from the style SSOT, never flush-left machine text.
#[test]
fn human_success_quadrant_is_framed_and_guttered() {
    let entry = well_typed_entry();
    let r = run(&["type-check", &entry.to_string_lossy()]);
    assert!(
        r.ok,
        "type-check on a well-typed program must exit 0; stderr: {}",
        r.stderr
    );
    assert!(
        r.stdout.starts_with('\n'),
        "human success must open with a framing newline: {:?}",
        r.stdout
    );
    for line in r.stdout.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("  "),
            "human success must be guttered, got: {line:?}",
        );
    }
}

/// The human-failure quadrant: a bad invocation with no machine flag renders the
/// human diagnostic surface — non-zero exit, nothing on stdout, and the stderr
/// carries the command's own `--help` page (the misuse-shows-help contract),
/// guttered, never a flush-left machine record.
#[test]
fn human_failure_quadrant_shows_the_guttered_help_surface() {
    // An unknown flag with no `--plain`/`--json` is a human-mode misuse.
    let r = run(&["version", "--nope"]);
    assert!(!r.ok, "an unknown flag must exit non-zero");
    assert!(
        r.stdout.is_empty(),
        "human-failure must write nothing to stdout, got: {:?}",
        r.stdout
    );
    assert!(
        r.stderr.contains("ipe version"),
        "human-failure must show the command's --help page: {:?}",
        r.stderr
    );
}

/// A parse error under `--json` is itself a machine outcome: because the output
/// format is resolved in a first, infallible pass BEFORE the fallible parse, an
/// unknown flag on a machine-mode invocation renders through the `ipe.cli.error/1`
/// envelope on stderr — never the human `--help` banner. The stdout stream stays
/// clean, the output carries no ANSI, and the JSON is well-formed. This is the
/// exact leak issue #2591 closed: a parse error must not fall to the human banner
/// when the caller asked for a machine surface. `dev build` and `type-check` are two
/// independent machine-mode command bodies, both proven.
#[test]
fn parse_error_under_json_renders_the_machine_envelope() {
    for cmd in ["dev build", "type-check"] {
        // The unknown flag makes the parse fail; `--json` was resolved first.
        let args: Vec<&str> = cmd.split(' ').chain(["--bad-flag", "--json"]).collect();
        let r = run(&args);
        assert!(
            !r.ok,
            "`ipe {cmd} --bad-flag --json` must exit non-zero on the parse error",
        );
        assert!(
            r.stdout.is_empty(),
            "`ipe {cmd}` machine parse-error must write nothing to stdout, got: {:?}",
            r.stdout,
        );
        assert!(
            !r.stdout.contains('\x1b') && !r.stderr.contains('\x1b'),
            "`ipe {cmd}` machine parse-error must carry no ANSI under NO_COLOR: {:?}",
            r.stderr,
        );
        // No human banner: the error banner (`Ipê lang - …`) and the help page
        // header (`Ipê language …`) both carry `Ipê lang`, so its absence proves
        // neither leaked into the machine stream.
        assert!(
            !r.stderr.contains("Ipê lang"),
            "`ipe {cmd}` machine parse-error must not show the human banner/help: {:?}",
            r.stderr,
        );
        assert!(
            is_well_formed_json(&r.stderr),
            "`ipe {cmd} --json` parse-error stderr must be well-formed JSON: {:?}",
            r.stderr,
        );
        assert!(
            r.stderr.contains("\"ipe.cli.error/1\""),
            "`ipe {cmd} --json` parse-error must carry the ipe.cli.error/1 schema tag: {:?}",
            r.stderr,
        );
    }
}

/// The `--plain` counterpart: a parse error under `--plain` renders a flush-left,
/// unstyled reason line on stderr — not the framed, guttered human help page and
/// not a JSON object. Same first-pass format resolution, the plain machine
/// surface. Proven for the same two command bodies.
#[test]
fn parse_error_under_plain_renders_a_flush_left_reason() {
    for cmd in ["dev build", "type-check"] {
        let args: Vec<&str> = cmd.split(' ').chain(["--bad-flag", "--plain"]).collect();
        let r = run(&args);
        assert!(
            !r.ok,
            "`ipe {cmd} --bad-flag --plain` must exit non-zero on the parse error",
        );
        assert!(
            r.stdout.is_empty(),
            "`ipe {cmd}` plain parse-error must write nothing to stdout, got: {:?}",
            r.stdout,
        );
        assert!(
            !r.stdout.contains('\x1b') && !r.stderr.contains('\x1b'),
            "`ipe {cmd}` plain parse-error must carry no ANSI under NO_COLOR: {:?}",
            r.stderr,
        );
        // Flush-left: no two-space human gutter, no leading framing blank line.
        let stderr = r.stderr.trim_end_matches('\n');
        assert!(
            !stderr.is_empty() && !stderr.starts_with(' ') && !stderr.starts_with('\n'),
            "`ipe {cmd}` plain parse-error must be a flush-left reason line: {:?}",
            r.stderr,
        );
        // Not the human help page and not a JSON envelope.
        assert!(
            !r.stderr.contains("Ipê lang"),
            "`ipe {cmd}` plain parse-error must not show the human banner/help: {:?}",
            r.stderr,
        );
        assert!(
            !r.stderr.contains("\"ipe.cli.error/1\""),
            "`ipe {cmd} --plain` parse-error must be plain text, not JSON: {:?}",
            r.stderr,
        );
    }
}
