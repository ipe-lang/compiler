//! `Ipe.Http` gate —
//! `Http.parseQuery` (pure), `defaultRequest` + `with*` builder chain (pure),
//! and `HttpResponse` record literal / field access (pure struct path).
//!
//! Every test compiles a Ipê program through `ipe`, builds the emitted Rust
//! project with the shared cargo target, runs the binary, and checks its stdout
//! against the cached oracle (`tests/golden/m5b_http_*/oracle.meta` +
//! `expected_go.txt`). All tests are gated on `IPE_E2E=1`; without it they
//! return early.
//!
//! ## Oracle provenance
//!
//! All three goldens are TRUE golden-verified goldens (`oracle_divergence = false`):
//! the reference compiler compiled the identical `Main.ipe` and produced the
//! captured `expected_go.txt`.  The test asserts byte-identity of stdout with
//! the cached output.
//!
//! ## Golden catalogue
//!
//! * `http_parse_query` — `Http.parseQuery "a=1&b=two%20words&a=ignored&c"`
//!   first-key-wins, percent-decodes, empty-value for key-only, probed via
//!   `Dict.get`; then `Http.parseQuery "a=1&b=%zz"` is refused whole as `Err`.
//!   Output: four probed values, then `refused`.
//!
//! * `http_builders` — `defaultRequestFromString "http://example.com"` (the
//!   marked parse-at-the-boundary helper) then, on the `Ok` branch,
//!   `withMethod Post |> withTimeout 5000 |> withHeader "A" "1" |>
//!   withHeader "B" "2" |> withBody "hello"`. Prints `.url`, `.timeout`,
//!   `.body`, and `.headers` (comma-joined). Confirms the builder chain,
//!   record-update syntax, and that `withHeader` prepends (latest-added
//!   first). Byte-identical stdout to the cached oracle.
//!
//! * `http_response_fields` — constructs an `HttpResponse` literal
//!   `{ status = 200, body = "ok", headers = Dict.fromList […] }`, reads back
//!   `.status`, `.body`, and `Dict.get "X-Test"`. Proves the
//!   `{body, headers, status}` fieldset synthesises correctly.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m5b_http
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe` through ipe, build the emitted Rust
/// project with the shared cargo target, run the binary, and return the golden
/// directory plus the run outcome. Gated on `IPE_E2E=1`.
fn build_run(name: &str) -> (PathBuf, crate::support::RunOutcome) {
    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    (dir, outcome)
}

/// Compile/build/run the golden and assert its stdout matches the cached
/// oracle. Gated on `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (dir, outcome) = build_run(name);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "{name}: must exit 0");
}

// ── Http.parseQuery ───────────────────────────────────────────────────────────

/// `Http.parseQuery "a=1&b=two%20words&a=ignored&c"` — first-key-wins,
/// percent-decodes spaces, empty-value for bare key; a malformed escape
/// (`a=1&b=%zz`) is refused whole as `Err`.  Output: four probed values, then
/// `refused`.
#[test]
fn http_parse_query() {
    assert_runs_and_matches_oracle("http_parse_query");
}

// ── Http builder chain ────────────────────────────────────────────────────────

/// `defaultRequestFromString |> withMethod |> withTimeout |> withHeader "A" |>
/// withHeader "B" |> withBody` chain prints 4 lines.  `withHeader` prepends
/// (B before A).
#[test]
fn http_builders() {
    assert_runs_and_matches_oracle("http_builders");
}

// ── HttpMethod ADT surface: value + total pattern match + converters ──────────

/// Exercises the full `HttpMethod` surface that the ADT rewrite (`#343`)
/// introduced: constructors as values (qualified `Http.Post` and unqualified
/// `Get`), a TOTAL `case` over every constructor with no wildcard,
/// `Http.methodToString`, and the `Http.methodFromString` parse boundary
/// round-trip. Locks the resolve → exhaustiveness → lower → emit path for the
/// closed verb union.
#[test]
fn http_method_match() {
    assert_runs_and_matches_oracle("http_method_match");
}

// ── HttpResponse record literal + field access ────────────────────────────────

/// Construct `{ status = 200, body = "ok", headers = Dict.fromList […] }`
/// and read back fields.  Proves the `{body, headers, status}` fieldset
/// synthesises and that `Dict.get` inside `.headers` resolves.  golden-verified
/// oracle.
#[test]
fn http_response_fields() {
    assert_runs_and_matches_oracle("http_response_fields");
}

// ── `HttpRequest` opaque-type regression (no signature ever spells the
// ── fieldset out) ─────────────────────────────────────────────────────────

/// IPE-I0001 regression: an `HttpRequest` built via
/// `Http.defaultRequestFromString url` whose ONLY consumer is a field read
/// (`req.url`) — no `Http.request` call, and no OTHER function signature in the
/// program spells out the
/// `{body, headers, method, redirects, timeout, url}`
/// fieldset as an explicit annotation — must still emit and build.
///
/// `ipe_lower::lower::ir_type_from_ty` folds any solved record matching that
/// exact 6-field shape into the opaque `IrType::HttpRequest` (so
/// `Http.request` / `HttpStream.open` call sites see the runtime type),
/// regardless of the value's OTHER consumers. The typed-target builder is now
/// backed by the runtime fn `http_default_request_from_string`, which
/// constructs the canonical `ipe_runtime::HttpRequest` internally and returns
/// `Result Error HttpRequest` — so the emitter never needs to synthesise a
/// record struct for the fieldset, and the IPE-I0001 lookup that the old
/// inline struct-literal emission risked cannot arise.
///
/// This is the default-gate (emit-only, no `IPE_E2E`) companion to
/// `http_response_fields` above: it needs only `ipe::build` to succeed and
/// inspects the emitted Rust text, so it runs without a cargo build and
/// cannot be silently reintroduced without failing `cargo nextest` (unlike
/// the `IPE_E2E`-gated golden, which is invisible to the default gate).
#[test]
fn http_default_request_emits_without_signature_consumer() {
    let root = repo_root();
    let entry = golden_dir(&root, "http_response_fields").join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_m5b_http_default_request_no_sig_emit");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for a HttpRequest built via \
         Http.defaultRequestFromString whose only consumer is a field read (no \
         Http.request call, no signature spelling out the fieldset); \
         got: {:?}",
        built.err()
    );

    let main_rs = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted src/main.rs must exist");
    assert!(
        main_rs.contains("http_default_request_from_string"),
        "the typed-target builder must lower to a call to the runtime fn \
         `http_default_request_from_string` (which performs the fail-closed \
         scheme narrowing and constructs the canonical HttpRequest), not an \
         inline struct literal.\n--- src/main.rs ---\n{main_rs}"
    );
}
