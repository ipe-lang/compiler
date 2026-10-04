//! E2E golden for `Ui.mediaQuery` (see
//! `docs/adr/0003-security-render-and-data-access-invariants.md`). Also exercises
//! `Ui.breakpoint`, which delegates to the same marker-emitting mechanism
//! rather than an eager-passthrough stub.
//!
//! ## Oracle provenance
//!
//! `oracle_divergence = true` — verified by direct assertions against the
//! semantics documented in `../ipe`'s `Ipe.Ui.ipe` `mediaQuery` (wrapper
//! `<div>` carrying `data-ipe-mq-q` / `data-ipe-mq-rules` markers), not a
//! cached oracle file.
//!
//! ## What is tested
//!
//! * `ipe dev build` compiles `tests/golden/ui_mediaquery/Main.ipe`
//!   (canon → types → lower → Rust backend) — i.e. `Ui.mediaQuery` is a
//!   backed kernel end to end, not a reachable-but-unbacked reserved member.
//! * The emitted Rust project `cargo build`s and the binary runs and exits 0.
//! * `Ui.mediaQuery "(min-width: 768px)" [Background.color …] child` renders
//!   the wrapper with BOTH markers: the verbatim query and the
//!   collector-built CSS rules string.
//! * `Ui.breakpoint Ui.mobile [...] child` emits the `(max-width: 767px)`
//!   marker pair (delegation, not passthrough).
//! * SECURITY: a `</style><script>` breakout query is dropped fail-closed at
//!   the producer — neither marker renders, no `<script>` appears, and the
//!   child still renders.
//!
//! (Plain `Html.render` keeps the markers visible; the Web/WebView pipelines
//! expand them via `apply_style_injections` into the ipe-id-scoped
//! `<style data-ipe-mq="<sid>">@media <q> { [ipe-id="<sid>"] { <rules> } }
//! </style>` block — that half is pinned by the runtime unit tests in
//! `src/runtime/rust/src/live/style_inject.rs`.)
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_ui_mediaquery
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn ui_mediaquery_compiles_builds_and_renders_markers() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("ui_mediaquery");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_ui_mediaquery_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for ui_mediaquery: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("ui_mediaquery", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "binary must exit 0\n--- stdout ---\n{}",
        outcome.stdout
    );

    let mut lines = outcome.stdout.lines();
    let mq = lines.next().unwrap_or_default();
    let evil = lines.next().unwrap_or_default();

    // ── Ui.mediaQuery — wrapper with the marker pair ──────────────────────
    assert!(
        mq.contains("data-ipe-mq-q=\"(min-width: 768px)\""),
        "Ui.mediaQuery must emit the verbatim query marker\n--- mq ---\n{mq}"
    );
    assert!(
        mq.contains("data-ipe-mq-rules=\"background-color:rgba(18,18,24,1)\""),
        "Ui.mediaQuery must emit the collector-built rules marker\n--- mq ---\n{mq}"
    );
    assert!(
        mq.contains("responsive"),
        "Ui.mediaQuery child must render\n--- mq ---\n{mq}"
    );

    // ── Ui.breakpoint — delegates to the same mechanism ───────────────────
    assert!(
        mq.contains("data-ipe-mq-q=\"(max-width: 767px)\""),
        "Ui.breakpoint Ui.mobile must emit the mobile query marker\n--- mq ---\n{mq}"
    );
    assert!(
        mq.contains("data-ipe-mq-rules=\"background-color:rgba(1,2,3,1)\""),
        "Ui.breakpoint rules marker missing\n--- mq ---\n{mq}"
    );

    // ── SECURITY: breakout query dropped fail-closed at the producer ──────
    assert!(
        !evil.contains("data-ipe-mq-q") && !evil.contains("data-ipe-mq-rules"),
        "breakout query must drop BOTH markers\n--- evil ---\n{evil}"
    );
    assert!(
        !evil.to_ascii_lowercase().contains("<script"),
        "script must never render\n--- evil ---\n{evil}"
    );
    assert!(
        evil.contains("gated"),
        "child must still render after the gate drops the styling\n--- evil ---\n{evil}"
    );
}
