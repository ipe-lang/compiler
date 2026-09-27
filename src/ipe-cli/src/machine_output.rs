//! The machine-output SSOT — one envelope shape for every `--json` / `--plain`
//! record the CLI writes, and one renderer for a machine-mode failure.
//!
//! # Why one shape
//!
//! Every `ipe` command runs in two output modes: the human default (guttered,
//! framed, coloured) and a machine mode (`--plain` / `--json`) a pipeline
//! consumes. The human vocabulary has an SSOT in [`crate::style`]; the machine
//! vocabulary is this module. A machine record is a [`MachineOutput`] — a
//! `{schema, status, command, payload}` envelope — so the surface a consumer
//! parses has exactly one representable shape, per make-invalid-states-
//! unrepresentable. A command cannot hand-roll a subtly different object: it
//! builds the payload and the envelope carries the invariant fields.
//!
//! # The disclosure boundary
//!
//! A machine stream is read by another program, not a person. Two leaks are the
//! regression this module exists to prevent, and both are closed here in one
//! audited place:
//!
//! * **No human banner in a machine stream.** The soft-yellow `Ipê lang` error
//!   banner ([`crate::screen::error_screen`]) is human furniture; it must never
//!   reach a `--json` / `--plain` consumer. A machine failure renders through
//!   [`machine_error`], never the banner.
//! * **No raw internal string.** A machine error carries only the error's
//!   curated [`std::fmt::Display`] text, run through [`crate::style::TerminalSafe`]
//!   so no ANSI escape or control byte survives — never a `Debug` dump or an
//!   un-sanitised internal string.
//!
//! # Schema stability
//!
//! A schema is a contract with a downstream `jq`. Fields are **added, never
//! renamed or removed** — the envelope adds `status` and `command` alongside a
//! command's own `payload`, and a new field is always additive. The version
//! suffix on [`MachineOutput::schema`] (`ipe.cli.<x>/N`) bumps only on a genuine
//! incompatible change, which this module's additive discipline avoids.

use crate::cli_args::{OutputFormat, json};
use crate::style::TerminalSafe;

/// The schema tag of the shared machine-error envelope. A distinct family from a
/// command's own success schema so a consumer can branch on the failure shape
/// without parsing a per-command union.
pub const ERROR_SCHEMA: &str = "ipe.cli.error/1";

/// The outcome a machine record reports.
///
/// A record is either a success carrying a command's payload or a failure
/// carrying a diagnostic message — never an ambiguous in-between, so a consumer
/// branches on one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineStatus {
    /// The command succeeded; the payload is its result data.
    Ok,
    /// The command failed; the payload carries the human-readable reason.
    Error,
}

impl MachineStatus {
    /// The stable lowercase word a consumer matches on.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// One machine-output record: the `{schema, status, command, payload}` envelope
/// every `--json` / `--plain` write shares.
///
/// `payload` is a pre-encoded JSON *object body* — the comma-joined
/// `"key":value` fragment a command builds with [`json::object`] — carried as a
/// string so the envelope stays agnostic about a command's own shape while still
/// nesting it under one key. Building the payload with [`json::object`] keeps the
/// escaping and compaction in the shared encoder, never re-derived per command.
pub struct MachineOutput<'a> {
    /// The stable schema tag, `ipe.cli.<command>/N`.
    schema: &'a str,
    /// Whether this record reports success or failure.
    status: MachineStatus,
    /// The command that produced the record (`type-check`, `lint`, …).
    command: &'a str,
    /// The command's own result, a JSON object rendered by [`json::object`].
    payload: String,
}

impl<'a> MachineOutput<'a> {
    /// A success record carrying `command`'s `payload` under `schema`.
    #[must_use]
    pub const fn ok(schema: &'a str, command: &'a str, payload: String) -> Self {
        Self {
            schema,
            status: MachineStatus::Ok,
            command,
            payload,
        }
    }

    /// Render the envelope as a compact `{schema, status, command, payload}` JSON
    /// object on a single line ending in a newline.
    ///
    /// The envelope is inherently the `--json` shape — the `--plain` machine
    /// surface is a command's own historical flush-left line form, not this
    /// object, so a `--plain` caller emits its bare lines directly rather than
    /// routing through here.
    #[must_use]
    pub fn render_json(&self) -> String {
        let obj = json::object(&[
            ("schema", json::string(self.schema)),
            ("status", json::string(self.status.word())),
            ("command", json::string(self.command)),
            ("payload", self.payload.clone()),
        ]);
        format!("{obj}\n")
    }
}

/// Render a machine-mode failure for `command` in `format` as the shared error
/// surface. This is the single home for a machine error's on-wire shape.
///
/// The message is the error's curated [`std::fmt::Display`] text — the same
/// one-line reason a human sees, never a `Debug` dump — passed through
/// [`TerminalSafe`] so no ANSI escape or control byte can ride into the machine
/// stream. The result carries no gutter, no frame, and no colour: it is
/// flush-left machine text, never the human [`error_banner`].
///
/// * `--json` yields the `{schema, status, command, payload}` error envelope,
///   the message [`json::string`]-escaped under `payload.message` and the stable
///   per-variant `kind` tag under `payload.kind` so a consumer can branch on the
///   failure class without parsing the prose message.
/// * `--plain` yields the flush-left sanitised reason, one record per line — the
///   pipe-friendly form, matching `--plain` success output.
/// * [`OutputFormat::Human`] is a caller bug (a human failure is the
///   [`error_banner`], not this module); it degrades to the plain form rather
///   than inventing a third shape or leaking the banner.
///
/// `kind` is the caller's stable classification of the error (the `CliError`
/// variant word); it is a fixed vocabulary, never user-controlled input, so it
/// carries no disclosure risk and is emitted verbatim.
///
/// The returned string ends in a newline so a caller can write it straight to a
/// stream. The caller writes it to **stderr** (a machine failure keeps stdout
/// clean — no half-formed record) and returns
/// [`crate::CliError::DiagnosticJsonEmitted`] so the process exits non-zero with
/// nothing more printed.
///
/// [`error_banner`]: crate::screen::error_screen
#[must_use]
pub fn machine_error(format: OutputFormat, command: &str, kind: &str, message: &str) -> String {
    // Sanitise first: the Display text is trusted furniture, but a diagnostic can
    // interpolate user-controlled source (a file path, an identifier), so strip
    // any ANSI/control bytes before it enters the machine stream. Defence in
    // depth — the JSON encoder escapes structurally, this closes the
    // terminal-control channel the encoder does not police, and it is the ONLY
    // defence on the `--plain` branch, which does no structural escaping.
    let safe = TerminalSafe::sanitize(message);
    match format {
        OutputFormat::Json => {
            let payload = json::object(&[
                ("kind", json::string(kind)),
                ("message", json::string(safe.as_str())),
            ]);
            MachineOutput {
                schema: ERROR_SCHEMA,
                status: MachineStatus::Error,
                command,
                payload,
            }
            .render_json()
        }
        // Plain (and the never-taken Human fallback): the flush-left reason, no
        // banner, no frame. A trailing newline the writer relies on.
        OutputFormat::Plain | OutputFormat::Human => format!("{}\n", safe.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_is_a_compact_object_with_every_invariant_field() {
        let payload = json::object(&[("version", json::string("0.1.0"))]);
        let out = MachineOutput::ok("ipe.cli.version/1", "version", payload).render_json();
        assert_eq!(
            out,
            "{\"schema\":\"ipe.cli.version/1\",\"status\":\"ok\",\
             \"command\":\"version\",\"payload\":{\"version\":\"0.1.0\"}}\n"
        );
    }

    #[test]
    fn status_words_are_the_stable_lowercase_tags() {
        assert_eq!(MachineStatus::Ok.word(), "ok");
        assert_eq!(MachineStatus::Error.word(), "error");
    }

    #[test]
    fn json_machine_error_never_leaks_ansi_or_a_banner() {
        // A hostile message carrying an ANSI reset and the human banner's own
        // lead-in must reach the machine stream with the escapes stripped and no
        // banner framing/gutter.
        let hostile = "boom \u{1b}[1;31mred\u{1b}[0m at \u{7}path";
        let line = machine_error(OutputFormat::Json, "type-check", "pipeline", hostile);
        assert!(!line.contains('\x1b'), "no ESC survives: {line:?}");
        assert!(!line.contains('\u{7}'), "no bell survives: {line:?}");
        // Envelope shape, flush-left, no leading gutter/frame newline.
        assert!(
            line.starts_with("{\"schema\":\"ipe.cli.error/1\""),
            "must be the flush-left error envelope: {line:?}"
        );
        assert!(
            !line.contains("Ipê lang"),
            "the human banner text must never reach a machine stream: {line:?}"
        );
        // The visible reason survives, escaped.
        assert!(line.contains("boom"), "the reason text survives: {line:?}");
    }

    #[test]
    fn json_machine_error_escapes_a_quote_in_the_message() {
        let line = machine_error(
            OutputFormat::Json,
            "lint",
            "pipeline",
            "unexpected \"token\"",
        );
        // The embedded quotes are JSON-escaped, keeping the envelope well-formed.
        assert!(
            line.contains("unexpected \\\"token\\\""),
            "quotes must be escaped: {line:?}"
        );
    }

    #[test]
    fn json_machine_error_carries_the_kind_tag_a_consumer_branches_on() {
        // A non-pipeline failure class reaches the machine stream as a schema
        // object carrying BOTH a stable `kind` and the prose `message` — the
        // consumer branches on `kind` without parsing the sentence.
        let line = machine_error(
            OutputFormat::Json,
            "build",
            "static-refusal",
            "static build refused",
        );
        assert!(
            line.starts_with("{\"schema\":\"ipe.cli.error/1\""),
            "the flush-left error envelope: {line:?}"
        );
        assert!(
            line.contains("\"status\":\"error\""),
            "status is error: {line:?}"
        );
        assert!(
            line.contains("\"kind\":\"static-refusal\""),
            "the stable kind tag is present: {line:?}"
        );
        assert!(
            line.contains("\"message\":\"static build refused\""),
            "the prose message is present: {line:?}"
        );
    }

    #[test]
    fn plain_machine_error_is_the_flush_left_reason_with_no_banner_or_ansi() {
        // The `--plain` failure surface: the bare sanitised reason, flush-left,
        // one line — never the human banner, never an ANSI escape.
        let hostile = "boom \u{1b}[1;31mred\u{1b}[0m at path";
        let line = machine_error(OutputFormat::Plain, "type-check", "pipeline", hostile);
        assert!(!line.contains('\x1b'), "no ESC survives: {line:?}");
        assert!(
            !line.contains("Ipê lang"),
            "the human banner must never reach a --plain stream: {line:?}"
        );
        assert!(
            !line.starts_with(' ') && !line.starts_with('\n'),
            "the plain error must be flush-left and unframed: {line:?}"
        );
        assert_eq!(line, "boom red at path\n", "the visible reason, flush-left");
    }
}
