//! Stdlib import aliases must not silently merge member tables or unlock the
//! must-import gate for an unrelated qualifier — while two bare imports whose
//! last path segment merely coincides stay legitimate.
//!
//! Defects on the `import Ipe.* as Alias` path:
//! - two stdlib imports EXPLICITLY aliased to one name (or an explicit alias
//!   naming a different module's canonical qualifier) used to extend-merge member
//!   tables last-wins with no diagnostic;
//! - marking that raw alias as imported let `import Ipe.Json.Encode as Crypto`
//!   unlock the unrelated `Crypto` gate, resolving `Crypto.hmacSha256` without
//!   ever importing `Ipe.Crypto`.
//!
//! The collision gate is keyed on the EXPLICIT alias only: a bare
//! `import Ipe.Json.Decode` speaks under its canonical `JsonDec`, never the last
//! segment `Decode`, so it does not collide with a bare `import Ipe.Db.Decode`.
//!
//! These use `ipe_canon::canonicalise` directly, so a body may reference only
//! qualifiers the base environment pre-installs (`JsonEnc` via `J`, the gated
//! `Crypto`); compiled-source modules such as `Ipe.Io` are injected by the CLI
//! project pipeline this harness does not run.

use ipe_diagnostics::{Diagnostic, NameError};
use ipe_intern::Interner;

fn canon(src: &str) -> Result<(), Diagnostic> {
    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(src, &mut interner)?;
    ipe_canon::canonicalise(&parsed, &mut interner).map(drop)
}

/// Two distinct stdlib modules EXPLICITLY aliased to one name must be rejected
/// with `DuplicateQualifier`, never silently resolve `J.member` last-wins.
#[test]
fn two_stdlib_imports_sharing_an_alias_is_rejected() {
    let src = "module Main exposing (main)\n\
               import Ipe.Json.Encode as J\n\
               import Ipe.Json.Decode as J\n\n\
               main =\n    J.string \"x\"\n";
    let err = canon(src).expect_err("two imports aliased to `J` must be rejected");
    assert!(
        matches!(
            err,
            Diagnostic::Name {
                msg: NameError::DuplicateQualifier { .. },
                ..
            }
        ),
        "expected DuplicateQualifier, got: {err:?}"
    );
}

/// An explicit alias equal to a DIFFERENT pre-installed canonical qualifier must
/// be rejected rather than extend-merge over that qualifier's members.
#[test]
fn alias_colliding_with_a_different_canonical_qualifier_is_rejected() {
    // `Crypto` is a pre-installed (gated) canonical qualifier; aliasing an
    // unrelated stdlib module to it must not merge into its member table.
    let src = "module Main exposing (main)\n\
               import Ipe.Json.Encode as Crypto\n\n\
               main =\n    Crypto.string \"x\"\n";
    let err = canon(src).expect_err("alias colliding with `Crypto` must be rejected");
    assert!(
        matches!(
            err,
            Diagnostic::Name {
                msg: NameError::DuplicateQualifier { .. },
                ..
            }
        ),
        "expected DuplicateQualifier, got: {err:?}"
    );
}

/// Two BARE imports whose last path segment merely coincides (`Ipe.Json.Decode`
/// and `Ipe.Db.Decode`, both segment `Decode`) must NOT be treated as an alias
/// collision: each speaks under its own canonical qualifier (`JsonDec`,
/// `Db.Decode`), so both are accepted. Regression guard for the over-broad gate
/// that rejected the generic-optional-decoder golden.
#[test]
fn two_bare_imports_sharing_a_last_segment_are_accepted() {
    let src = "module Main exposing (main)\n\
               import Ipe.Json.Decode\n\
               import Ipe.Db.Decode\n\n\
               main =\n    JsonDec.string\n";
    let r = canon(src);
    assert!(
        r.is_ok(),
        "bare imports sharing only a last segment must not collide, got: {r:?}"
    );
}

/// Aliasing an unrelated import to a non-canonical name must NOT unlock the
/// `Crypto` gate: a `Crypto.sha256` use with no `import Ipe.Crypto` still raises
/// the must-import diagnostic. `J` aliases `Ipe.Json.Encode` (canonical
/// `JsonEnc`), so the alias plainly never keyed the `Crypto` gate.
#[test]
fn unrelated_alias_does_not_unlock_the_crypto_gate() {
    let src = "module Main exposing (main)\n\
               import Ipe.Json.Encode as J\n\n\
               main =\n    Crypto.sha256 \"m\"\n";
    let err = canon(src).expect_err("un-imported `Crypto` use must be gated");
    assert!(
        matches!(
            err,
            Diagnostic::Name {
                msg: NameError::ImportRequired { .. },
                ..
            }
        ),
        "expected ImportRequired for un-imported Crypto, got: {err:?}"
    );
}

/// Positive control: a legitimate explicit stdlib alias still resolves its
/// members.
#[test]
fn legitimate_stdlib_alias_still_resolves() {
    let src = "module Main exposing (main)\n\
               import Ipe.Json.Encode as J\n\n\
               main =\n    J.encode 0 (J.string \"x\")\n";
    let r = canon(src);
    assert!(
        r.is_ok(),
        "a legitimate `import Ipe.Json.Encode as J` must still resolve J.string, got: {r:?}"
    );
}

/// Capability smuggle: a bare `import Ipe.Http.Stream` exposes the module under
/// its last path segment `Stream`, which equals the DIFFERENT server-`Stream`
/// module's gated canonical qualifier. Marking that segment as imported would
/// unlock server `Stream.emit` / `Stream.finish` (privileged server kernels)
/// with no import of `Ipe.Http.Server.Stream`. The gate must fail closed:
/// `Stream.emit` under only `import Ipe.Http.Stream` still raises the teachable
/// must-import diagnostic.
#[test]
fn bare_http_stream_import_does_not_unlock_server_stream_gate() {
    let src = "module Main exposing (main)\n\
               import Ipe.Http.Stream\n\n\
               main =\n    Stream.emit \"x\"\n";
    let err =
        canon(src).expect_err("server `Stream.emit` must stay gated under bare Ipe.Http.Stream");
    assert!(
        matches!(
            err,
            Diagnostic::Name {
                msg: NameError::ImportRequired { .. },
                ..
            }
        ),
        "expected ImportRequired for smuggled server `Stream`, got: {err:?}"
    );
}

/// Capability smuggle: a bare `import Ipe.Server.Http` exposes the module under
/// its last path segment `Http`, which equals the DIFFERENT client-`Http`
/// module's gated canonical qualifier. Marking it would unlock client `Http.get`
/// with no `import Ipe.Http`. The gate must fail closed.
#[test]
fn bare_server_http_import_does_not_unlock_client_http_gate() {
    let src = "module Main exposing (main)\n\
               import Ipe.Server.Http\n\n\
               main =\n    Http.get\n";
    let err = canon(src).expect_err("client `Http.get` must stay gated under bare Ipe.Server.Http");
    assert!(
        matches!(
            err,
            Diagnostic::Name {
                msg: NameError::ImportRequired { .. },
                ..
            }
        ),
        "expected ImportRequired for smuggled client `Http`, got: {err:?}"
    );
}

/// Control: server `Stream.emit` with NO import at all is already gated — the
/// baseline the smuggle probe above must not weaken.
#[test]
fn bare_server_stream_use_is_gated_without_import() {
    let src = "module Main exposing (main)\n\n\
               main =\n    Stream.emit \"x\"\n";
    let err = canon(src).expect_err("un-imported server `Stream.emit` must be gated");
    assert!(
        matches!(
            err,
            Diagnostic::Name {
                msg: NameError::ImportRequired { .. },
                ..
            }
        ),
        "expected ImportRequired for un-imported `Stream`, got: {err:?}"
    );
}

/// Positive: a bare `import Ipe.Http.Stream` still resolves its OWN canonical
/// qualifier `HttpStream` — the fail-closed foreign-segment guard must not lock
/// the module's legitimate members.
#[test]
fn bare_http_stream_import_resolves_its_own_canonical() {
    let src = "module Main exposing (main)\n\
               import Ipe.Http.Stream\n\n\
               main =\n    HttpStream.open\n";
    let r = canon(src);
    assert!(
        r.is_ok(),
        "bare `import Ipe.Http.Stream` must still resolve HttpStream.open, got: {r:?}"
    );
}

/// Positive: an explicit `import Ipe.Server.Http as Server` still resolves
/// `Server.get` — an explicit alias onto its own canonical is legitimate and the
/// guard (which only skips a BARE foreign-segment) leaves it untouched.
#[test]
fn explicit_server_http_alias_resolves_server_members() {
    let src = "module Main exposing (main)\n\
               import Ipe.Server.Http as Server\n\n\
               main =\n    Server.get\n";
    let r = canon(src);
    assert!(
        r.is_ok(),
        "`import Ipe.Server.Http as Server` must resolve Server.get, got: {r:?}"
    );
}
