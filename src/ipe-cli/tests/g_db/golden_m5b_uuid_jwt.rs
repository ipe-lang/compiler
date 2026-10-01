//! `Ipe.Uuid` + `Ipe.Jwt` gate —
//! UUID generation/parsing and JWT HS256/RS256 encode/decode.
//!
//! Every test compiles a Ipê program through `ipe`, builds the emitted Rust
//! project with the shared cargo target, runs the binary, and checks its stdout
//! against the cached oracle (`tests/golden/m5b_*/oracle.meta` +
//! `expected_go.txt`). All tests are gated on `IPE_E2E=1`; without it they
//! return early.
//!
//! ## Oracle provenance — what is and isn't oracle-compared here
//!
//! These goldens are NOT shared-`Main.ipe` oracle-parity goldens. Two distinct
//! reasons (both recorded as `oracle_divergence = true` with a tagged reason in
//! each golden's `sanctioned.divergence` marker):
//!
//! * **JWT (`m5b_jwt_*`) — API-surface divergence.** The Rust backend surfaces
//!   FLAT kernels (`Jwt.encodeHs256` / `decodeHs256` / `encodeRs256` /
//!   `decodeRs256`); the reference compiler exposes only the builder API
//!   (`Jwt.encode` / `hs256` / `rs256` / `claims` / `decode`). So this exact
//!   `Main.ipe` does not compile on the reference compiler and the cached
//!   expected is ipe's own output.
//!
//! * **UUID (`m5b_uuid_*`) — soundness divergence.** `Uuid.v4` / `Uuid.v7` are
//!   typed on the EFFECT tier (`() -> Task Error String`) because entropy is not
//!   a memoizable pure value; the reference compiler still types them as bare
//!   `Uuid.v4 : String` (Limitation #7), so these Task-sequenced programs are
//!   not co-typable with the reference and cannot be oracle-compared. The cached
//!   expected is ipe's (semantically correct) output. `Uuid.parse` is the pure
//!   `String -> Maybe String` parser on both.
//!
//! ## Byte-parity IS proven — separately and explicitly
//!
//! Although the shared-`Main.ipe` oracle cannot run the flat-kernel program,
//! the produced JWT bytes ARE byte-identical to the reference implementation.
//! The `jwt_hs256_bytes` / `jwt_rs256_bytes` goldens print the token, and
//! [`jwt_hs256_bytes`] / [`jwt_rs256_bytes`] assert that printed token equals a
//! token captured verbatim from the reference running the equivalent builder-API
//! program (`Jwt.encode (Jwt.hs256 secret) (claims …)`). The same constants
//! are byte-checked at the unit level in `src/runtime/rust/src/jwt.rs`.
//!
//! ## Golden catalogue
//!
//! * `uuid_format` — `Uuid.v4`/`v7` (each `() -> Task Error String`)
//!   sequenced with `Task.andThen`: length is 36 and the version nibble is
//!   `4`/`7`; a fresh `v4` round-trips through `Uuid.parse`.  Output: `"ok"`.
//! * `uuid_distinct` — SOUNDNESS regression: two `Uuid.v4 ()` calls yield
//!   DIFFERENT ids (entropy is an effect, not a CSE-able pure value).  Output:
//!   `"ok-distinct"`.
//! * `uuid_parse` — `Uuid.parse "not-a-uuid"` → `Nothing`;
//!   `Uuid.parse "<valid-uuid>"` → `Just _`.  Output: `"ok"`.
//! * `jwt_hs256_roundtrip` — `encodeHs256` then `decodeHs256` with the same
//!   32-byte key succeeds.  Output: `"ok"`.
//! * `jwt_hs256_tamper` — appending `"x"` to an HS256 token makes
//!   `decodeHs256` reject it.  Output: `"tamper-detected"`.
//! * `jwt_rs256_roundtrip` — `encodeRs256` (PKCS#8 RSA-2048) then
//!   `decodeRs256` (SPKI public key) round-trips.  Output: `"ok"`.
//! * `jwt_hs256_bytes` — prints the HS256 token; asserted byte-identical to
//!   the canonical captured token.
//! * `jwt_rs256_bytes` — prints the RS256 token; asserted byte-identical to
//!   the canonical captured token (RS256/PKCS#1 v1.5 is deterministic).
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m5b
//! ```

use std::path::{Path, PathBuf};

/// Canonical HS256 token for the equivalent builder-API program
/// `Jwt.encode (Jwt.hs256 "test-secret-key-0123456789abcdef")
///  (claims |> subject "alice" |> expiresAt 9999999999)`, captured from the
/// reference implementation. `jwt_hs256_bytes` must reproduce it.
const GO_HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTksInN1YiI6ImFsaWNlIn0.O6u4Zgjn9lL3myvfLfP5QFaGIHx-KBfzZ7lgkbJL_N0";

/// Canonical RS256 token for the equivalent builder-API program over the same
/// fixed RSA-2048 key and `claims |> subject "bob" |> expiresAt …`, captured
/// from the reference implementation. RS256 (PKCS#1 v1.5) is deterministic,
/// so `jwt_rs256_bytes` must reproduce it byte for byte.
const GO_RS256_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTksInN1YiI6ImJvYiJ9.GJ29fLyt4u8M_CMSvhSizRpjWXEDsrVtDL92QOX27HwB9YvKI4_ksftEN8-wK1xiT5y1tmrWmUs3_UHPTepyCJ9Y02JDphZ5X4k0784CIKxNvdr1RcAn-V24Wyc_rTFOELDR9XeBPNIhYRzVuQnaQ27PbmpF3skoyH40eOI7emrTVlbPhkgnWsoULuKOEI3yF9VU62QFoPDEuio_59LMcuk2EZrnh-Rql1zF5cNixt30_Vu5mUwBHkYZ2J2ZEm_S2VIrXvIluIfp5pzNmOK1TdLv9yQHY1PPcfcvHizHK4IKnMNTXrkk8W0NCaP5faf4hzaZVPIoqJ7D220PHPgWEg";

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project, run
/// it, and return the golden directory plus the run outcome. The caller gates on
/// `IPE_E2E`. Fails the test on any build/runtime error.
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

/// Compile/build/run the golden and assert its stdout matches the cached oracle.
/// Gated on `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (dir, outcome) = build_run(name);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

/// Compile/build/run a byte-parity golden and assert its emitted token equals
/// the `canonical_token` captured from the reference — the explicit
/// byte-equality proof — AND that it still matches the cached oracle.
fn assert_token_byte_identical_to_go(name: &str, go_token: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (dir, outcome) = build_run(name);
    assert_eq!(
        outcome.stdout.trim_end(),
        go_token,
        "{name}: emitted token must be byte-identical to the captured canonical token"
    );
    // Keep the cached-oracle gate honest too (expected holds the same bytes).
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

// ── UUID format + version nibble ─────────────────────────────────────────────

/// `Uuid.v4` / `Uuid.v7` (each `() -> Task Error String`) sequenced with
/// `Task.andThen`: a generated id is 36 chars with version nibble `4` / `7`, and
/// a fresh `v4` round-trips through the pure `Uuid.parse`.  Output: `"ok"`.
///
/// Recorded soundness divergence: the reference compiler types `Uuid.v4`
/// as a bare `String` (Limitation #7) and cannot express this Task-sequenced
/// program. Expected holds ipe's correct output.
#[test]
fn uuid_format() {
    assert_runs_and_matches_oracle("uuid_format");
}

// ── UUID distinctness (entropy-is-an-effect soundness proof) ─────────────────

/// SOUNDNESS regression: two `Uuid.v4 ()` calls in one program yield
/// DIFFERENT ids. `Uuid.v4 : () -> Task Error String`, so the two references are
/// distinct effect evaluations — NOT a memoizable pure `String` the optimizer
/// could CSE into one shared value (which would print `"fail-same"`).  Output:
/// `"ok-distinct"`.
#[test]
fn uuid_distinct() {
    assert_runs_and_matches_oracle("uuid_distinct");
}

// ── UUID parse ────────────────────────────────────────────────────────────────

/// `Uuid.parse "not-a-uuid"` → `Nothing`; `Uuid.parse "<valid-uuid>"` → `Just _`.
/// Output: `"ok"`.
///
/// Recorded divergence: the reference compiler returns `Nothing` for
/// the canonical UUID on this shape. Expected holds ipe's correct output.
#[test]
fn uuid_parse() {
    assert_runs_and_matches_oracle("uuid_parse");
}

// ── JWT HS256 round-trip ──────────────────────────────────────────────────────

/// `encodeHs256 secret claims` then `decodeHs256 secret token` with the same
/// 32-byte key succeeds.  Output: `"ok"`.
///
/// Recorded API-surface divergence (the flat kernel does not exist in the
/// reference compiler); token bytes verified identical — see [`jwt_hs256_bytes`].
#[test]
fn jwt_hs256_roundtrip() {
    assert_runs_and_matches_oracle("jwt_hs256_roundtrip");
}

// ── JWT HS256 tamper detection ────────────────────────────────────────────────

/// Appending `"x"` to a valid HS256 token makes `decodeHs256` reject it.
/// Output: `"tamper-detected"`. Recorded API-surface divergence.
#[test]
fn jwt_hs256_tamper() {
    assert_runs_and_matches_oracle("jwt_hs256_tamper");
}

// ── JWT RS256 round-trip ──────────────────────────────────────────────────────

/// `encodeRs256 privKeyPem claims` then `decodeRs256 pubKeyPem token` with a
/// matching RSA-2048 PKCS#8/SPKI key pair round-trips.  Output: `"ok"`.
///
/// Recorded API-surface divergence; token bytes verified identical — see
/// [`jwt_rs256_bytes`].
#[test]
fn jwt_rs256_roundtrip() {
    assert_runs_and_matches_oracle("jwt_rs256_roundtrip");
}

// ── JWT HS256 byte-parity ─────────────────────────────────────────────────────

/// The HS256 token `encodeHs256` emits is byte-identical to the canonical
/// reference token. This is the explicit byte-equality proof the flat-kernel
/// goldens otherwise can't express through the shared-`Main.ipe` oracle.
#[test]
fn jwt_hs256_bytes() {
    assert_token_byte_identical_to_go("jwt_hs256_bytes", GO_HS256_TOKEN);
}

// ── JWT RS256 byte-parity ─────────────────────────────────────────────────────

/// The RS256 token `encodeRs256` emits is byte-identical to the canonical
/// reference token (RS256 is deterministic).
#[test]
fn jwt_rs256_bytes() {
    assert_token_byte_identical_to_go("jwt_rs256_bytes", GO_RS256_TOKEN);
}

// ── JWT builder-API Jwt.decode with caller-supplied now ───────────────────────

/// Regression: `Jwt.decode : Algorithm -> Int -> String -> Result Error String`.
/// Exercises caller-supplied `now` boundary semantics against RFC 7519 exp/nbf:
///   r1: now=500, exp=1000, nbf=100  → ok  (valid window)
///   r2: now=1000, exp=1000          → err (expired: now >= exp)
///   r3: now=99, nbf=100             → err (not yet valid: now < nbf)
///   r4: now=100, nbf=100            → ok  (boundary: now == nbf → accept)
///   r5: now=999, exp=1000           → ok  (boundary: now < exp → accept)
///   r6: now=500, no exp/nbf         → ok  (absent claims accepted)
///   r7: wrong-key, now=500          → err (invalid signature)
/// Output: `"ok err err ok ok ok err"`.
#[test]
fn jwt_decode_now() {
    assert_runs_and_matches_oracle("m_jwt_decode_now");
}
