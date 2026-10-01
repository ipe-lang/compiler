//! `Ipe.Debug` — the development-only escape hatch.
//!
//! `Debug.log label value` prints `"<label>: <value>"` to stderr as a side
//! effect and returns `value` UNCHANGED, so it can be spliced into any
//! expression without altering its result. The value is stringified through the
//! same total `IpeStringify` path `{{expr}}` interpolation uses, so any
//! Ipê-representable value renders (a `String` unquoted, scalars like `%v`,
//! records/ADTs via their codegen-emitted impl).
//!
//! This is the ONE deliberate impure escape hatch in the language — NOT a
//! `Task`. `ipe release` rejects any `Debug.*` use at compile time (IPE-L0140),
//! so this function is only ever reached from a development build.

use crate::stringify::IpeStringify;

/// Build the scrubbed `"<label>: <value>"` line `debug_log` writes. Both
/// `label` and the stringified `value` are routed through
/// `system::scrub_log_controls` — `value` renders through the same
/// `IpeStringify` path any downstream driver, remote request, or file could
/// have shaped, so an ESC/CR/LF/bidi-control sequence in either can neither
/// forge extra terminal lines nor reorder/hide the ones already there. Split
/// out from `debug_log` so the scrub can be asserted directly, without
/// capturing the real stderr side effect.
fn debug_log_line<T: IpeStringify>(label: &str, value: &T) -> String {
    let label = crate::system::scrub_log_controls(label);
    let shown = value.ipe_show();
    let shown = crate::system::scrub_log_controls(&shown);
    format!("{label}: {shown}")
}

/// `Debug.log : String -> a -> a`. Writes `"<label>: <value>"` + a newline to
/// stderr (fallibly, through `system::write_stderr_line`, so a broken pipe
/// never panics), then returns `value`
/// unchanged.
#[must_use]
pub fn debug_log<T: IpeStringify>(label: String, value: T) -> T {
    crate::system::write_stderr_line(&debug_log_line(&label, &value));
    value
}

/// `Debug.todo : String -> a`. Prints `"TODO at <file>:<line>: <note>"` to
/// stderr then exits with a non-zero code.  Returns `!` (the never type),
/// which coerces to any `A` at the call site — no Rust `panic!` is used.
///
/// `location` is a `"<file>:<line>"` string injected by the lowerer at
/// compile time from the call-site source span; it is never computed at
/// runtime.  `note` is the developer-supplied string argument.
pub fn debug_todo<A>(location: String, note: String) -> A {
    crate::system::write_stderr_line(&format!("TODO at {location}: {note}"));
    crate::system::system_exit(1)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::debug_log_line;

    /// Both the label and the value can carry attacker-influenced text (a
    /// spliced-in driver error, a request field, a trace value) — pin that
    /// neither an ESC sequence, a bare CR/LF, nor a bidi-reorder control
    /// survives into the line handed to `write_stderr_line`.
    #[test]
    fn scrubs_esc_cr_lf_and_bidi_controls_from_label_and_value() {
        let label = "label\r\n\x1b[2J".to_string();
        let value = "value\u{2066}\u{202e}bidi".to_string();
        let line = debug_log_line(&label, &value);
        assert!(
            !line.chars().any(|c| c == '\x1b' || c == '\r' || c == '\n'),
            "ESC/CR/LF survived scrubbing: {line:?}"
        );
        assert!(
            !line.contains('\u{2066}') && !line.contains('\u{202e}'),
            "a bidi control survived scrubbing: {line:?}"
        );
    }
}
