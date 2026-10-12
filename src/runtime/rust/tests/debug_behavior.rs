//! Behavioral tests for the `Ipe.Debug` development escape hatches.
//!
//! - `Debug.explain : Attribute msg` — a depth-aware debug overlay emitted on
//!   the parent element and propagated to every descendant via the renderer.
//! - `Debug.todo : String -> a` — writes `TODO at <file>:<line>: <note>` to
//!   stderr and exits non-zero via `system_exit`, never via `panic!`.

// ── Test 4: Debug.explain outline on parent AND nested child ─────────────────

/// `Debug.explain` on a parent element emits the debug overlay on the parent
/// AND propagates it to every direct and indirect descendant — without altering
/// layout. The overlay is the A7 depth-hued outline (`outline:2px solid hsl(…)`),
/// so both the parent (depth 0) and the nested child (depth 1) carry one.
#[test]
fn explain_outline_emitted_on_parent_and_nested_child() {
    use ipe_runtime_rust::ui::element::{Attribute, Description, Element};
    use ipe_runtime_rust::ui::render::ui_layout;

    let child_elem: Element<()> = Element::Node(
        Description::NoDescription,
        vec![],
        vec![Element::Text("inner".to_owned())],
    );

    let parent_elem: Element<()> = Element::Node(
        Description::NoDescription,
        vec![Attribute::AttrExplain],
        vec![child_elem],
    );

    let html = ui_layout(vec![], parent_elem);
    let serialised = ipe_runtime_rust::render_html(&html);

    // The A7 overlay emits a depth-hued outline on every explained box; count
    // the propagated occurrences (parent + nested child ⇒ at least 2).
    let outline_marker = "outline:2px solid hsl(";
    let count = serialised.matches(outline_marker).count();

    assert!(
        count >= 2,
        "expected the depth-hued explain outline on both the parent and a \
         nested child (at least 2 occurrences); found {count} in:\n{serialised}"
    );
    // The former uniform solid-blue outline must be gone.
    assert!(
        !serialised.contains("outline:2px solid rgba(0,100,255,0.5)"),
        "the old uniform blue explain outline must no longer appear:\n{serialised}"
    );
}

// ── Test 5: Debug.todo stderr message + non-zero exit, not a panic ───────────

/// Sentinel env-var: when set, the subprocess arm calls `debug_todo` directly.
/// The main test spawns a child process with this var set and inspects the
/// child's stderr and exit code.
const SUBPROCESS_SENTINEL: &str = "IPE_DEBUG_TODO_SUBPROCESS";

/// Called only in the child process (when `SUBPROCESS_SENTINEL` is set).
/// `debug_todo` diverges via `system_exit`; the child process never returns.
/// The return type is `()` because `debug_todo<A>` is generic over `A` and
/// the divergence is supplied by `system_exit(1)` inside the runtime.
fn run_todo_subprocess() {
    ipe_runtime_rust::debug_todo::<()>("testfile.ipe:42".to_owned(), "subprocess note".to_owned())
}

/// Reaching a `Debug.todo` at runtime writes `TODO at <file>:<line>: <note>`
/// to stderr, exits non-zero, and is never a Rust `panic!` (no panicked-at
/// line on stderr).
///
/// Implemented as a subprocess round-trip: the test spawns itself with
/// `SUBPROCESS_SENTINEL` set, which causes `run_todo_subprocess()` to execute
/// inside the child, then the parent inspects the child's stderr and exit code.
#[test]
fn todo_writes_located_message_to_stderr_and_exits_nonzero() {
    // Guard: if we are the subprocess, run the todo — `system_exit` terminates
    // the child process.  The test runner never reaches this in the parent.
    #[expect(
        clippy::disallowed_methods,
        reason = "an integration test has no crate-private env accessor"
    )]
    let is_child = std::env::var_os(SUBPROCESS_SENTINEL).is_some();
    if is_child {
        run_todo_subprocess();
    }

    let exe = std::env::current_exe().expect("the test binary must locate itself");

    let output = std::process::Command::new(&exe)
        .env(SUBPROCESS_SENTINEL, "1")
        .args([
            "--test-threads=1",
            "todo_writes_located_message_to_stderr_and_exits_nonzero",
        ])
        .env("RUST_TEST_NOCAPTURE", "1")
        .output()
        .expect("the test binary must re-spawn itself");

    // The child must exit non-zero.
    assert!(
        !output.status.success(),
        "debug_todo must exit non-zero; child exited with: {:?}",
        output.status.code()
    );

    let stderr =
        String::from_utf8(output.stderr.clone()).expect("the child's stderr must be UTF-8");

    // The expected located message must appear on stderr.
    let expected = "TODO at testfile.ipe:42: subprocess note";
    assert!(
        stderr.contains(expected),
        "expected stderr to contain {expected:?}; got:\n{stderr}"
    );

    // Must NOT contain a Rust panic header — this is a clean process exit.
    assert!(
        !stderr.contains("panicked at"),
        "debug_todo must not panic; found panic text in stderr:\n{stderr}"
    );
}
