//! `Ipe.Http.Server` request-accessor clone-emit golden.
//!
//! This test pins the `.clone()` insertion behaviour for request accessor
//! kernels (`Server.body` / `Server.path` / `Server.method` /
//! `Server.header` / `Server.queryParam` / `Server.getCookie` /
//! `Server.param`).
//!
//! When a handler calls multiple accessor kernels on the same `req` binding,
//! the emitter MUST insert `.clone()` on each call so the first call does not
//! move the `ServerRequest` binding and prevent subsequent calls (E0382).
//!
//! This is a compile-only golden: we compile the fixture with `ipe`, read
//! the emitted `src/main.rs`, and assert each accessor call site contains
//! `.clone()`.  We do NOT run the compiled binary (the program is a Ipê HTTP
//! server that would block).
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m6_server
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// The emitter inserts `.clone()` on the `ServerRequest` argument for every
/// request accessor kernel.
///
/// Reads the emitted `src/main.rs` from `server_request_accessors/Main.ipe`
/// and asserts each accessor call site contains `req.clone()` (or some
/// expression ending in `.clone()`), preventing E0382 "use of moved value"
/// when multiple accessors are called on the same binding in a single handler.
///
/// Checks all seven accessor families:
/// * `server_body(…clone())` / `server_path(…clone())` / `server_method(…clone())`
/// * `server_header(…, …clone())` / `server_query_param(…, …clone())`
/// * `server_param(…, …clone())` / `server_get_cookie(…, …clone())`
#[test]
fn server_request_accessor_emit_inserts_clone() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join("server_request_accessors")
        .join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m6_server_request_accessors");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe::build failed for server_request_accessors: {:?}",
        built.err()
    );

    let main_rs_path = out.join("src").join("main.rs");
    let main_rs_result = std::fs::read_to_string(&main_rs_path);
    assert!(
        main_rs_result.is_ok(),
        "cannot read emitted main.rs at {}: {:?}",
        main_rs_path.display(),
        main_rs_result.err()
    );
    let main_rs = main_rs_result.expect("`main_rs_result` must succeed");

    // Each accessor must appear at a call site that includes `.clone()`.
    // The fixture calls all seven on the same `req` binding — without `.clone()`
    // all but the first would fail to compile (E0382).
    //
    // Match on rustfmt-normalized text (`crate::support::normalize_rustfmt_whitespace`)
    // rather than a per-line scan: a multi-arg call (e.g. `server_header("x-
    // probe".to_string(), req.clone().clone())`) wraps one argument per line
    // once it exceeds rustfmt's width limit, so `.clone()` lands on a
    // DIFFERENT line than `accessor(` — the same stale-assertion class as
    // #269/#191/#193/#195/#190/Ipe.Ui.Transition, here hitting a per-line
    // rather than a single-line-substring check.
    let normalized = crate::support::normalize_rustfmt_whitespace(&main_rs);
    for accessor in &[
        "server_body",
        "server_path",
        "server_method",
        "server_header",
        "server_query_param",
        "server_param",
        "server_get_cookie",
    ] {
        let call_prefix = format!("{accessor}(");
        // `.clone()` must appear within the call's argument list — scan a
        // window after `accessor(` rather than requiring same-line adjacency.
        // Every fixture call site has a short (<=2-arg) argument list, so 200
        // normalized (whitespace-free) chars comfortably covers it without
        // reaching into an unrelated later call.
        let has_clone = normalized.match_indices(&call_prefix).any(|(idx, _)| {
            let window_end = (idx + call_prefix.len() + 200).min(normalized.len());
            normalized[idx..window_end].contains(".clone()")
        });
        assert!(
            has_clone,
            "emitted main.rs: {accessor}(…) call must include `.clone()` on the request arg \
             to prevent E0382 — check emit_server_call in emit_expr.rs\n\
             relevant lines:\n{}",
            main_rs
                .lines()
                .filter(|l| l.contains(*accessor))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
