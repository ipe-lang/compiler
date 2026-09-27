// Ipe.Trace — opt-in app-level tracing spans / events / attributes.
//
// `span name task` runs `task` and
// returns its result UNCHANGED (the value/error flow through untouched), plus a
// span around it; `event` / `attr` mark a point / annotate the active span.
// Output is opt-in via IPE_TRACE (off by default → zero noise), but the wrapped
// task ALWAYS runs regardless, so spans never change program behaviour.
use super::*;
use std::time::Instant;

/// Scrub control characters (CR/LF, ESC, other C0/C1) from a trace string before
/// it is written to the stderr trace log. `Trace.attr` / `event` / `span` names
/// and values are app/user-supplied, so an attacker-influenced value could
/// otherwise inject forged log records (CR/LF) or terminal escape sequences into
/// the operator's console. Reuses the crate-wide plain-log scrubber.
fn scrub(s: &str) -> String {
    crate::core::scrub_log_controls(s)
}

fn trace_enabled() -> bool {
    crate::system::read_env_var("IPE_TRACE")
        .map(|v| !v.is_empty() && v != "0" && v != "false")
        .unwrap_or(false)
}

// Trace.span : String -> Task e a -> Task e a
pub fn trace_span<E: EffectSend, A: EffectSend>(
    name: String,
    task: IpeTask<E, A>,
) -> IpeTask<E, A> {
    Box::pin(async move {
        let on = trace_enabled();
        let start = Instant::now();
        if on {
            eprintln!("[trace] span start {}", scrub(&name));
        }
        let result = task.await;
        let elapsed = start.elapsed();
        let ok = matches!(result, IpeResult::Ok(_));
        // Always record the span into the telemetry ring (the Ipê Console reads
        // it); the stderr line stays opt-in via IPE_TRACE.
        super::telemetry::record_span(&name, elapsed.as_micros() as u64, ok);
        if on {
            let outcome = if ok { "ok" } else { "err" };
            eprintln!(
                "[trace] span end {} ({} ms, {})",
                scrub(&name),
                elapsed.as_millis(),
                outcome
            );
        }
        result
    })
}

// Trace.event : String -> Task Error ()
pub fn trace_event<E: Send + 'static>(name: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        if trace_enabled() {
            eprintln!("[trace] event {}", scrub(&name));
        }
        ok_res(())
    })
}

// Trace.attr : String -> String -> Task Error ()
// Keys are namespaced under `ipe.trace.`.
pub fn trace_attr<E: Send + 'static>(key: String, value: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        if trace_enabled() {
            eprintln!("[trace] attr ipe.trace.{} = {}", scrub(&key), scrub(&value));
        }
        ok_res(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_strips_log_and_terminal_injection() {
        // A trace value carrying CRLF + an ANSI escape must not survive into the
        // emitted line — control chars become spaces so it can neither forge a
        // log record nor inject a terminal control sequence.
        let evil = "ok\r\n[error] forged record\x1b[2J\x07";
        let cleaned = scrub(evil);
        assert!(!cleaned.contains('\r'));
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
        // Printable content is preserved (only controls are replaced).
        assert!(cleaned.contains("forged record"));
        assert!(cleaned.starts_with("ok"));
    }
}
