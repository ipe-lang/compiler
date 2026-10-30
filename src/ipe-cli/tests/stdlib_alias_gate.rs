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

use ipe_canon::{STDLIB_MODULE_QUALIFIERS, bare_import_binds, builtin_empty_home_arity};
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
            }) if suggestions.names().any(|n| n == "Crypto")
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

/// The annotation of `x` in `module Main exposing (x)`, `imports`, `x : ty`,
/// canonicalised with `interner` so two calls compare symbol for symbol.
fn annotation(
    imports: &str,
    ty: &str,
    interner: &mut Interner,
) -> Result<ipe_canon::ast::Type, Diagnostic> {
    let src = format!("module Main exposing (x)\n{imports}\nx : {ty}\nx _ =\n    0\n");
    let parsed = ipe_parse::parse_module(&src, interner)?;
    let module = ipe_canon::canonicalise(&parsed, interner)?;
    module
        .defs
        .iter()
        .find_map(|def| match def {
            ipe_canon::ast::Def::Typed { ty, .. } => Some(ty.clone()),
            ipe_canon::ast::Def::Untyped { .. } => None,
        })
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: "stdlib_alias_gate::annotation",
            detail: "the program has no typed definition".into(),
        })
}

/// `x : ty` under `imports`, canonicalised with a fresh interner.
fn annotation_alone(imports: &str, ty: &str) -> Result<ipe_canon::ast::Type, Diagnostic> {
    annotation(imports, ty, &mut Interner::new())
}

/// The diagnostic code of a refused `result`.
fn code_of<T>(result: &Result<T, Diagnostic>) -> Option<ipe_diagnostics::Code> {
    result.as_ref().err().map(Diagnostic::code)
}

/// `ty` with the fields of each record argument of an arrow in one order.
fn fields_sorted(ty: ipe_canon::ast::Type) -> ipe_canon::ast::Type {
    use ipe_canon::ast::Type;
    match ty {
        Type::Lambda(arg, ret) => {
            Type::Lambda(Box::new(fields_sorted(*arg)), Box::new(fields_sorted(*ret)))
        }
        Type::Record(mut fields) => {
            fields.sort_by_key(|(name, _)| *name);
            Type::Record(fields)
        }
        other => other,
    }
}

/// Every type a kernel module exports canonicalises to one value whether it is
/// spelled through the module's qualifier or bound by an `exposing` list.
#[test]
fn qualified_and_exposed_kernel_types_canonicalise_identically() -> Result<(), Diagnostic> {
    let mut interner = Interner::new();
    let env = ipe_canon::Env::initial(Vec::new(), &mut interner)?;
    let mut checked = 0_usize;
    for (module, types) in env.kernel_types.iter() {
        let canonical = interner.resolve(module.symbol()).map(str::to_owned);
        let path = STDLIB_MODULE_QUALIFIERS
            .iter()
            .find(|(_, qualifier)| Some(*qualifier) == canonical.as_deref())
            .map(|(path, _)| path.join("."));
        let Some(path) = path else {
            return Err(Diagnostic::CompilerBug {
                where_: "qualified_and_exposed_kernel_types_canonicalise_identically",
                detail: format!("{canonical:?} exports types but no import path names it"),
            });
        };
        for name in types.keys() {
            let args = " Int".repeat(builtin_empty_home_arity(Some(*name)).unwrap_or(0));
            let qualified = annotation(
                &format!("import {path} as K\n"),
                &format!("K.{name}{args} -> Int"),
                &mut interner,
            );
            let exposed = annotation(
                &format!("import {path} exposing ({name})\n"),
                &format!("{name}{args} -> Int"),
                &mut interner,
            );
            assert!(
                matches!((&qualified, &exposed), (Ok(q), Ok(e)) if q == e),
                "{path} exports `{name}`: {qualified:?} / {exposed:?}"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "the kernel modules export types");
    Ok(())
}

/// The kernel `HttpResponse` alias expands to the body `Ipe.Http`'s reference
/// source declares, so the source, the alias table and the scheme are one value.
#[test]
fn http_response_alias_body_matches_reference_source() -> Result<(), Diagnostic> {
    let source = ipe_stdlib::source("Ipe.Http").unwrap_or_default();
    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(source, &mut interner)?;
    assert!(
        parsed
            .aliases
            .iter()
            .any(|alias| interner.resolve(alias.value.name.value) == Some("HttpResponse")),
        "`Ipe.Http` declares `type alias HttpResponse`"
    );
    let body = source
        .split_once("type alias HttpResponse =")
        .and_then(|(_, rest)| rest.split_once("\n\n"))
        .map(|(body, _)| body.trim());
    assert!(
        body.is_some(),
        "the alias body is delimited by a blank line"
    );
    let reference = annotation(
        "",
        &format!("{} -> Int", body.unwrap_or_default()),
        &mut interner,
    )?;
    let expanded = annotation(
        "import Ipe.Http\n",
        "Http.HttpResponse -> Int",
        &mut interner,
    )?;
    assert_eq!(fields_sorted(reference), fields_sorted(expanded));
    Ok(())
}

/// Every type a kernel module's reference source exposes is a type export.
///
/// No source-declared type of a kernel module is served by anything else.
#[test]
fn every_reference_source_type_is_exported() -> Result<(), Diagnostic> {
    let mut interner = Interner::new();
    let env = ipe_canon::Env::initial(Vec::new(), &mut interner)?;
    for module in ipe_stdlib::MODULES {
        let parsed = ipe_parse::parse_module(module.source, &mut interner)?;
        let canonical = STDLIB_MODULE_QUALIFIERS
            .iter()
            .find(|(path, _)| path.join(".") == module.name)
            .map(|(_, canonical)| *canonical);
        let kernel = canonical
            .and_then(|canonical| interner.lookup(canonical))
            .and_then(|symbol| env.kernel_module_of(symbol));
        let Some(kernel) = kernel else {
            // A compiled-source module declares its own types.
            continue;
        };
        let exports = env.kernel_types.get(&kernel);
        assert!(
            matches!(parsed.exposing.value, ipe_syntax::Exposing::List(_)),
            "{} exposes an explicit list",
            module.name
        );
        let ipe_syntax::Exposing::List(items) = &parsed.exposing.value else {
            continue;
        };
        for item in items {
            if let ipe_syntax::Exposed::Type(name, _) = &item.value {
                let name = interner.resolve(*name).unwrap_or_default();
                assert!(
                    exports.is_some_and(|types| types.contains_key(name)),
                    "{} exposes `{name}`, which its kernel module does not export",
                    module.name
                );
            }
        }
    }
    Ok(())
}

/// `exposing (RedirectPolicy(..))` binds the type as well as its constructors,
/// at the head `Http.RedirectPolicy` names.
#[test]
fn redirect_policy_exposing_binds_the_type() -> Result<(), Diagnostic> {
    let mut interner = Interner::new();
    let exposed = annotation(
        "import Ipe.Http exposing (RedirectPolicy(..))\n",
        "RedirectPolicy -> Int",
        &mut interner,
    )?;
    let qualified = annotation(
        "import Ipe.Http\n",
        "Http.RedirectPolicy -> Int",
        &mut interner,
    )?;
    assert_eq!(exposed, qualified);
    Ok(())
}

/// An `as` alias reaches the module's type exports, and owns the qualifier:
/// the canonical spelling under an alias-only import is IPE-N0034.
#[test]
fn aliased_kernel_import_reaches_exports() {
    let aliased = annotation_alone("import Ipe.Http as H\n", "H.HttpResponse -> Int");
    assert!(
        matches!(&aliased, Ok(ipe_canon::ast::Type::Lambda(arg, _))
            if matches!(**arg, ipe_canon::ast::Type::Record(_))),
        "{aliased:?}"
    );
    let canonical = canon(
        "module Main exposing (x)\nimport Ipe.Http as H\n\nx : Http.HttpResponse -> Int\nx _ =\n    0\n",
    );
    assert!(
        is_import_required(&canonical, "Http", "Ipe.Http", Some("H")),
        "{canonical:?}"
    );
}

/// Two kernel imports exposing the one `Cmd` row bind one definition.
#[test]
fn two_shape_imports_exposing_cmd_are_not_ambiguous() {
    let both = annotation_alone(
        "import Ipe.Tea.Web.Cmd exposing (Cmd)\nimport Ipe.Tea.Tui.Cmd exposing (Cmd)\n",
        "Cmd Int -> Int",
    );
    assert!(both.is_ok(), "{both:?}");
}

/// FAIL-CLOSED: a qualified type the kernel module does not export is
/// IPE-N0005, never an empty-home head.
#[test]
fn unknown_type_under_kernel_qualifier_is_no_such_member() {
    let bogus = annotation_alone("import Ipe.Http\n", "Http.Bogus -> Int");
    assert_eq!(
        code_of(&bogus),
        Some(ipe_diagnostics::IPE_N0005),
        "{bogus:?}"
    );
}

/// A builtin the module does not export is refused under its qualifier, even
/// though the bare name is ambient.
#[test]
fn builtin_not_exported_by_qualifier_is_refused() {
    for (import, ty) in [
        ("import Ipe.Http\n", "Http.Int -> Int"),
        ("import Ipe.Db\n", "Db.String -> Int"),
    ] {
        let refused = annotation_alone(import, ty);
        assert_eq!(
            code_of(&refused),
            Some(ipe_diagnostics::IPE_N0005),
            "{ty}: {refused:?}"
        );
    }
}

/// A kernel qualifier reads only its module's exports: a union an open import
/// binds bare is not reachable as `Http.Foo`.
#[test]
fn qualifier_does_not_reach_an_open_import_union() -> Result<(), Diagnostic> {
    let mut interner = Interner::new();
    let foo_path = vec![interner.intern("Foo")?];
    let foo_src = ipe_parse::parse_module(
        "module Foo exposing (Foo(..))\n\ntype Foo\n    = Foo\n",
        &mut interner,
    )?;
    let empty = std::collections::BTreeMap::new();
    let (_, foo_exports) =
        ipe_canon::canonicalise_module(&foo_src, &foo_path, &empty, &mut interner)?;
    let mut deps = std::collections::BTreeMap::new();
    deps.insert(foo_path, foo_exports);
    let main_path = vec![interner.intern("Main")?];
    let main_src = ipe_parse::parse_module(
        "module Main exposing (x)\nimport Foo exposing (..)\nimport Ipe.Http\n\nx : Http.Foo -> Int\nx _ =\n    0\n",
        &mut interner,
    )?;
    let reached = ipe_canon::canonicalise_module(&main_src, &main_path, &deps, &mut interner);
    assert_eq!(
        code_of(&reached),
        Some(ipe_diagnostics::IPE_N0005),
        "{reached:?}"
    );
    Ok(())
}

/// An `exposing` item the kernel module does not export is IPE-N0022, and
/// `(..)` on a type without constructors is refused the same way.
#[test]
fn exposing_unknown_kernel_type_is_refused() {
    for import in [
        "import Ipe.Http exposing (Bogus)\n",
        "import Ipe.Http exposing (HttpResponse(..))\n",
    ] {
        let refused = annotation_alone(import, "Int -> Int");
        assert_eq!(
            code_of(&refused),
            Some(ipe_diagnostics::IPE_N0022),
            "{import}: {refused:?}"
        );
    }
}

/// A kernel alias takes no type argument: applying one is IPE-N0013.
#[test]
fn kernel_alias_arity_is_checked() {
    let applied = annotation_alone("import Ipe.Http\n", "Http.HttpResponse Int -> Int");
    assert_eq!(
        code_of(&applied),
        Some(ipe_diagnostics::IPE_N0013),
        "{applied:?}"
    );
}
