//! A qualifier spelling holds members only once an import of this module
//! installs it, under exactly the spellings that import writes.
//!
//! - Two stdlib imports explicitly aliased to one name, or an alias naming a
//!   different module's canonical qualifier, are refused (IPE-N0027).
//! - An alias installs only itself: it never unlocks another module's
//!   qualifier, nor its own module's canonical or dotted spelling (IPE-N0034
//!   names the alias to write).
//! - `Cmd` / `Sub` follow the one shape the module imports (IPE-N0035).
//! - An interpolated qualified reference obeys the same gate.
//! - Two bare imports whose last segment merely coincides stay legitimate.
//!
//! These use `ipe_canon::canonicalise` directly, so a body may reference only
//! kernel modules; compiled-source modules such as `Ipe.Io` are injected by
//! the CLI project pipeline this harness does not run.

use ipe_canon::{STDLIB_MODULE_QUALIFIERS, bare_import_binds};
use ipe_diagnostics::{Diagnostic, NameError, StdlibReach};
use ipe_intern::Interner;

fn canon(src: &str) -> Result<(), Diagnostic> {
    canon_module(src).map(drop)
}

fn canon_module(src: &str) -> Result<ipe_canon::ast::Module, Diagnostic> {
    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(src, &mut interner)?;
    ipe_canon::canonicalise(&parsed, &mut interner)
}

/// `module Main exposing (x)`, then `imports`, then `x = body`.
///
/// The one definition is not `main`, so the app-entry gates stay out of the
/// way of the import gate under test.
fn program(imports: &str, body: &str) -> String {
    format!("module Main exposing (x)\n{imports}\nx =\n    {body}\n")
}

/// Whether `result` is IPE-N0034 reached through `qualifier`, listing `module`,
/// naming `alias` as the import's alias (`None`: no alias named).
fn is_import_required(
    result: &Result<(), Diagnostic>,
    qualifier: &str,
    module: &str,
    alias: Option<&str>,
) -> bool {
    matches!(
        result,
        Err(Diagnostic::Name {
            msg: NameError::ImportRequired {
                reached: StdlibReach::Qualifier(reached),
                candidates,
                imported_as,
            },
            ..
        }) if &**reached == qualifier
            && candidates.iter().any(|c| &**c == module)
            && imported_as.as_deref().map(|i| &*i.alias) == alias
    )
}

/// Whether `result` reached the qualifier's member table (only the member is missing).
const fn is_no_such_member(result: &Result<(), Diagnostic>) -> bool {
    matches!(
        result,
        Err(Diagnostic::Name {
            msg: NameError::NoSuchMember { .. },
            ..
        })
    )
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

/// A dotted module spelling (`Ipe.Auth.member`) holds members only once its
/// module is imported: with no import it is IPE-N0034 naming that module, and
/// a bare `import` of it installs the spelling.
#[test]
fn dotted_spelling_without_import_is_refused() {
    let mut checked = 0usize;
    for (path, _) in STDLIB_MODULE_QUALIFIERS {
        let module = path.join(".");
        if path.len() < 2 || !bare_import_binds(&module, &module) {
            continue;
        }
        checked += 1;
        let use_site = format!("{module}.zzAbsentMember");
        let without = canon(&program("", &use_site));
        assert!(
            is_import_required(&without, &module, &module, None),
            "{use_site} with no import: {without:?}"
        );
        let with = canon(&program(&format!("import {module}\n"), &use_site));
        assert!(
            is_no_such_member(&with),
            "import {module}; {use_site}: {with:?}"
        );
    }
    assert!(checked > 0, "no dotted qualifier spelling was exercised");
}

/// Importing one shape never installs another shape's dotted spelling.
#[test]
fn dotted_spelling_of_another_module_is_refused() {
    let result = canon(&program("import Ipe.Tea.Tui\n", "Ipe.Tea.Web.tea"));
    assert!(
        is_import_required(&result, "Ipe.Tea.Web", "Ipe.Tea.Web", None),
        "{result:?}"
    );
}

/// A module imported under an alias is reachable only under that alias; its
/// canonical spelling is IPE-N0034 naming the alias.
#[test]
fn aliased_import_names_the_alias() {
    let refused = canon(&program("import Ipe.Auth as A\n", "Auth.hashPassword"));
    assert!(
        is_import_required(&refused, "Auth", "Ipe.Auth", Some("A")),
        "{refused:?}"
    );
    let accepted = canon(&program("import Ipe.Auth as A\n", "A.hashPassword"));
    assert!(accepted.is_ok(), "{accepted:?}");
}

/// An aliased import does not install the module's dotted spelling either; a
/// bare import does.
#[test]
fn aliased_import_hides_the_dotted_spelling() {
    let refused = canon(&program("import Ipe.Auth as A\n", "Ipe.Auth.hashPassword"));
    assert!(
        is_import_required(&refused, "Ipe.Auth", "Ipe.Auth", Some("A")),
        "{refused:?}"
    );
    let accepted = canon(&program("import Ipe.Auth\n", "Ipe.Auth.hashPassword"));
    assert!(accepted.is_ok(), "{accepted:?}");
}

/// Two paths of one kernel module install only the spelling the import wrote.
#[test]
fn sibling_dotted_path_is_not_installed() {
    let refused = canon(&program(
        "import Ipe.Http.Server\n",
        "Ipe.Server.Http.listen",
    ));
    assert!(
        is_import_required(&refused, "Ipe.Server.Http", "Ipe.Server.Http", None),
        "{refused:?}"
    );
    let accepted = canon(&program(
        "import Ipe.Server.Http\n",
        "Ipe.Server.Http.listen",
    ));
    assert!(accepted.is_ok(), "{accepted:?}");
}

/// `Cmd` / `Sub` hold members only once a shape (or a shape's own `Cmd` /
/// `Sub` module) is imported.
#[test]
fn cmd_sub_without_shape_import_is_refused() {
    for family in ["Cmd", "Sub"] {
        let use_site = format!("{family}.none");
        let refused = canon(&program("", &use_site));
        assert!(
            is_import_required(&refused, family, "Ipe.Tea.Web", None),
            "{use_site} with no shape import: {refused:?}"
        );
        for shape in ["Web", "Tui", "Cli", "Worker"] {
            let accepted = canon(&program(&format!("import Ipe.Tea.{shape}\n"), &use_site));
            assert!(
                accepted.is_ok(),
                "import Ipe.Tea.{shape}; {use_site}: {accepted:?}"
            );
        }
        let aliased = canon(&program(
            &format!("import Ipe.Tea.Web.{family} as {family}\n"),
            &use_site,
        ));
        assert!(aliased.is_ok(), "aliased shape {family}: {aliased:?}");
    }
}

/// `Cmd` / `Sub` follow the one shape a module imports: a second shape, or
/// another shape's `Cmd` module, is IPE-N0035.
#[test]
fn cmd_sub_follow_the_shape_reached() {
    let src = program("import Ipe.Tea.Web\nimport Ipe.Tea.Tui\n", "Cmd.none");
    let two = canon(&src);
    let second = src
        .find("Ipe.Tea.Tui")
        .and_then(|lo| u32::try_from(lo).ok());
    assert!(
        matches!(
            &two,
            Err(Diagnostic::Name {
                span,
                msg: NameError::TwoShapeImports { first_module, second_module, .. },
            }) if &**first_module == "Ipe.Tea.Web"
                && &**second_module == "Ipe.Tea.Tui"
                && Some(span.lo) == second
        ),
        "{two:?}"
    );
    let foreign = canon(&program(
        "import Ipe.Tea.Web\nimport Ipe.Tea.Tui.Cmd as Cmd\n",
        "Cmd.none",
    ));
    assert!(
        matches!(
            &foreign,
            Err(Diagnostic::Name {
                msg: NameError::WrongShapeCmdSub(_),
                ..
            })
        ),
        "{foreign:?}"
    );
    for imports in [
        "import Ipe.Tea.Tui\nimport Ipe.Tea.Terminal.Cmd as Cmd\n",
        "import Ipe.Tea.Web\nimport Ipe.Tea.Web.Cmd as Cmd\n",
    ] {
        let accepted = canon(&program(imports, "Cmd.none"));
        assert!(accepted.is_ok(), "{imports}: {accepted:?}");
    }
}

/// `module Main exposing (f)` with `imports` and `f s = """{{body}}"""`.
fn interp_program(imports: &str, body: &str) -> String {
    format!("module Main exposing (f)\n{imports}\nf s =\n    \"\"\"{{{{{body}}}}}\"\"\"\n")
}

/// Whether a canonical module still carries an interpolation as literal text.
fn keeps_literal(module: &ipe_canon::ast::Module) -> bool {
    format!("{module:?}").contains("{{")
}

/// An interpolated qualified reference obeys the import gate exactly as the
/// same reference outside a string does.
#[test]
fn interpolated_qualified_name_obeys_the_import_gate() {
    let refused = canon(&interp_program("", "Crypto.sha256 s"));
    assert!(
        is_import_required(&refused, "Crypto", "Ipe.Crypto", None),
        "{refused:?}"
    );
    let accepted = canon_module(&interp_program("import Ipe.Crypto\n", "Crypto.sha256 s"));
    assert!(
        accepted.as_ref().is_ok_and(|m| !keeps_literal(m)),
        "{accepted:?}"
    );
}

/// An interpolated reference to an unknown qualifier or member is refused,
/// never printed as literal text; a dotted qualifier resolves.
#[test]
fn interpolated_unknown_qualifier_is_refused() {
    let unknown = canon(&interp_program("import Ipe.Crypto\n", "Crypt.sha256 s"));
    assert!(
        matches!(
            &unknown,
            Err(Diagnostic::Name {
                msg: NameError::UnknownModule { suggestions, .. },
                ..
            }) if suggestions.names.iter().any(|n| &**n == "Crypto")
        ),
        "{unknown:?}"
    );
    let missing = canon(&interp_program("import Ipe.Crypto\n", "Crypto.nope s"));
    assert!(is_no_such_member(&missing), "{missing:?}");
    for (import, body) in [
        ("import Ipe.Crypto\n", "Crypto.sha256 s"),
        ("import Ipe.Auth\n", "Ipe.Auth.hashPassword s"),
    ] {
        let accepted = canon_module(&interp_program(import, body));
        assert!(
            accepted.as_ref().is_ok_and(|m| !keeps_literal(m)),
            "{body}: {accepted:?}"
        );
    }
}
