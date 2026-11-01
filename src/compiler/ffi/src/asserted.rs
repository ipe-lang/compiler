//! The asserted-call surface (`Rust.Ffi.call`).
//!
//! Validates an author-asserted signature against the installed-crate catalog
//! and emits its two artifacts — the `Rust.Ffi` interface module and the
//! `_bindings.rs` shim region.
//!
//! The discipline (§5.2 escape-hatch design): the
//! escape hatch skips ceremony, never soundness. The path is a parsed
//! [`ipe_canon::asserted::AssertedPath`], never text; the signature may only
//! name carriers the boundary already admits; the shim carries the asserted
//! types verbatim under the **exact-carrier rule** — this module never calls
//! into `num_coerce`, so no clamp or widening can hide between the Ipê type
//! and the Rust type. When the target is in the cached inspection, the
//! assertion is checked here at build preparation; when it is not, the shim's
//! `rustc` check is the checker of record and a wrong assertion fails the
//! emitted build inside the shim's commented region, attributed to the
//! assertion — never undefined behavior, never a silent success.
//!
//! Every shim body executes the foreign call under
//! `std::panic::catch_unwind`, folding a foreign panic into the wrapper's
//! typed `Err` — the same panic boundary every inspected wrapper is born
//! inside — which is why an asserted signature must end in `Result Error T`:
//! that result is the error channel the boundary needs.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};

use ipe_canon::asserted::{AssertedPath, LocalTypeKind, LocalTypeNames};
use ipe_intern::{Interner, Symbol};
use ipe_kernels::{BuiltinTag, BuiltinType};
use ipe_syntax::TypeAnnotation;

use crate::carrier::ScalarCarrier;
use crate::diag::{AssertedCompilerBug, AssertedDefect, AssertedRefusal, InspectedShapeReason};
use crate::driver::{InspectedSig, InstalledCrate};
use crate::pkginfo::Effect;
use crate::unify::UnifyReport;

/// A foreign opaque type identified by its home module, never by its spelling.
///
/// The only constructor is [`CarrierScope`]'s resolution against the target
/// crate, so every value names a type an installed interface module declares:
/// the target's own module for an inspected or `define` type, the unify home
/// for a demoted re-export.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OpaqueRef {
    home: String,
    nominal: String,
    rust_path: String,
}

impl OpaqueRef {
    /// The interface module that declares the type (`Rust.Semver`).
    #[must_use]
    pub fn home(&self) -> &str {
        &self.home
    }

    /// The type's name inside its home module (`Version`).
    #[must_use]
    pub fn nominal(&self) -> &str {
        &self.nominal
    }

    /// The Rust type the shim names (`::semver::Version`).
    #[must_use]
    pub fn rust_path(&self) -> &str {
        &self.rust_path
    }

    /// The fully qualified Ipê spelling (`Rust.Semver.Version`).
    #[must_use]
    pub fn qualified(&self) -> String {
        format!("{}.{}", self.home, self.nominal)
    }
}

/// One carrier an asserted signature admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertedCarrier {
    /// A reserved scalar builtin.
    Scalar(ScalarCarrier),
    /// A foreign opaque type, identified by its home.
    Opaque(OpaqueRef),
}

impl AssertedCarrier {
    /// The Ipê spelling the generated `Rust.Ffi` module writes.
    ///
    /// An opaque is always fully qualified, so the generated module's own
    /// scope can neither capture the name nor clash on it.
    #[must_use]
    pub fn ipe_spelling(&self) -> String {
        match self {
            Self::Scalar(scalar) => scalar.ipe_surface().to_owned(),
            Self::Opaque(opaque) => opaque.qualified(),
        }
    }

    /// The Rust type the shim carries verbatim.
    #[must_use]
    pub fn rust_type(&self) -> &str {
        match self {
            Self::Scalar(scalar) => scalar.rust_owned(),
            Self::Opaque(opaque) => opaque.rust_path(),
        }
    }

    const fn opaque(&self) -> Option<&OpaqueRef> {
        match self {
            Self::Opaque(opaque) => Some(opaque),
            Self::Scalar(_) => None,
        }
    }
}

/// What an asserted signature is classified against.
///
/// It holds the installed-crate catalog, the unify report whose demotion edges
/// name the home of a re-exported opaque, and the type names the calling
/// module declares itself.
#[derive(Debug, Clone, Copy)]
pub struct CarrierScope<'a> {
    catalog: &'a [InstalledCrate],
    unify: &'a UnifyReport,
    local_types: &'a LocalTypeNames,
}

impl<'a> CarrierScope<'a> {
    /// Bundle the catalog, its unify report and the caller's local type names.
    #[must_use]
    pub const fn new(
        catalog: &'a [InstalledCrate],
        unify: &'a UnifyReport,
        local_types: &'a LocalTypeNames,
    ) -> Self {
        Self {
            catalog,
            unify,
            local_types,
        }
    }

    fn target(&self, path: &AssertedPath) -> Option<&'a InstalledCrate> {
        self.catalog.iter().find(|c| c.slug == path.crate_ident())
    }

    /// Resolve an opaque name through the target crate to its home.
    ///
    /// An inspected opaque absolutizes its recorded path; a `define` nominal
    /// resolves crate-locally where `_bindings.rs` defines it; a name unify
    /// demoted out of the target resolves to the home that kept it. Anything
    /// else is no foreign type of this crate.
    fn resolve_opaque(&self, target: &InstalledCrate, name: &str) -> Option<OpaqueRef> {
        let opaque = |home: &str, rust_path: String| OpaqueRef {
            home: home.to_owned(),
            nominal: name.to_owned(),
            rust_path,
        };
        if let Some(recorded) = target.opaque_types.get(name) {
            return Some(opaque(&target.module_name, absolute_path(recorded)));
        }
        if target.define_types.contains(name) {
            return Some(opaque(
                &target.module_name,
                format!("crate::ffi::{}::{name}", target.slug),
            ));
        }
        let edge = self
            .unify
            .unified
            .iter()
            .find(|u| u.name == name && u.demoted_modules.contains(&target.module_name))?;
        let home = self
            .catalog
            .iter()
            .find(|c| c.module_name == edge.home_module)?;
        home.opaque_types
            .get(name)
            .map(|recorded| opaque(&home.module_name, absolute_path(recorded)))
    }
}

/// A recorded Rust path, absolutized (`::semver::Version`).
fn absolute_path(recorded: &str) -> String {
    format!("::{}", recorded.trim_start_matches(':'))
}

/// Where an asserted definition is written: the user file, the span of its
/// call, and the 1-based line that span starts on.
///
/// The line is read from the file's text once, here, so a refusal naming a
/// second definition in another file needs no access to that file's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertedSite {
    file: PathBuf,
    span: ipe_diagnostics::Span,
    line: u32,
}

impl AssertedSite {
    /// The site of `span` in `file`, whose text is `source`.
    #[must_use]
    pub fn new(file: PathBuf, span: ipe_diagnostics::Span, source: &str) -> Self {
        let before = usize::try_from(span.lo).unwrap_or(usize::MAX);
        let breaks = source.bytes().take(before).filter(|&b| b == b'\n').count();
        let line = u32::try_from(breaks).unwrap_or(u32::MAX).saturating_add(1);
        Self { file, span, line }
    }

    /// The user file that holds the definition.
    #[must_use]
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// The span of the definition's asserted call in [`Self::file`].
    #[must_use]
    pub const fn span(&self) -> ipe_diagnostics::Span {
        self.span
    }

    /// The 1-based line [`Self::span`] starts on.
    #[must_use]
    pub const fn line(&self) -> u32 {
        self.line
    }
}

impl fmt::Display for AssertedSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file.display(), self.line)
    }
}

/// One validated asserted call: the parsed path, the parsed signature, the
/// derived names, and every Rust type the emitters render — all resolved
/// here, so emission is a total function over this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertedSpec {
    /// The validated target path.
    pub path: AssertedPath,
    /// The definition that asserts it.
    pub site: AssertedSite,
    /// The parsed asserted signature.
    pub sig: AssertedSig,
    /// The Ipê definition name in the generated `Rust.Ffi` module.
    pub def_name: String,
    /// The `_bindings.rs` shim identifier.
    pub wrapper_ident: String,
    /// Rendered Rust parameter types, aligned with the forwarder arity (a
    /// unit-param signature renders `()`).
    pub param_rust: Vec<String>,
    /// The rendered Rust result type (the `Ok` payload).
    pub result_rust: String,
    /// The home module of every opaque the signature names, each imported
    /// bare by the generated interface.
    pub opaque_homes: BTreeSet<String>,
}

/// A parsed asserted signature: owned carriers in, `Result Error <carrier>`
/// out. Parsing is the only constructor, so an out-of-set type is
/// unrepresentable downstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertedSig {
    /// The parameter carriers. Empty exactly when [`Self::unit_param`].
    pub params: Vec<AssertedCarrier>,
    /// `true` for the `() -> Result Error T` shape (a zero-argument target;
    /// the forwarder stays unary over the unit value, like every zero-param
    /// inspected wrapper).
    pub unit_param: bool,
    /// The `Ok` payload carrier of the `Result Error` return.
    pub result: AssertedCarrier,
}

impl AssertedSig {
    /// The forwarder arity (a unit-param signature is unary).
    #[must_use]
    pub const fn arity(&self) -> usize {
        if self.unit_param {
            1
        } else {
            self.params.len()
        }
    }

    /// The canonical Ipê signature string for the generated interface def.
    #[must_use]
    pub fn ipe_sig(&self) -> String {
        let mut parts: Vec<String> = if self.unit_param {
            vec!["()".to_owned()]
        } else {
            self.params
                .iter()
                .map(AssertedCarrier::ipe_spelling)
                .collect()
        };
        parts.push(format!("Result Error {}", self.result.ipe_spelling()));
        parts.join(" -> ")
    }

    /// Parse an author's annotation into the asserted shape.
    ///
    /// # Errors
    /// The [`AssertedDefect`] naming the first rule broken (the caller wraps
    /// it with the offending path).
    pub fn from_annotation(
        annotation: &TypeAnnotation,
        interner: &Interner,
        scope: &CarrierScope<'_>,
        target: &InstalledCrate,
    ) -> Result<Self, AssertedDefect> {
        // Split the arrow spine: `A -> B -> R` ⇒ params [A, B], result R.
        let mut segments: Vec<&TypeAnnotation> = Vec::new();
        let mut cursor = annotation;
        while let TypeAnnotation::TLambda(param, rest) = cursor {
            segments.push(param);
            cursor = rest;
        }
        if segments.is_empty() {
            return Err(AssertedDefect::NotAFunction);
        }
        let unit_param = matches!(segments.as_slice(), [TypeAnnotation::TUnit]);
        let mut params = Vec::with_capacity(segments.len());
        if !unit_param {
            for seg in &segments {
                if matches!(seg, TypeAnnotation::TUnit) {
                    return Err(AssertedDefect::UnitParamNotSole);
                }
                params.push(parse_carrier(seg, interner, scope, target)?);
            }
        }
        let result = parse_result(cursor, interner, scope, target)?;
        Ok(Self {
            params,
            unit_param,
            result,
        })
    }

    fn carriers(&self) -> impl Iterator<Item = &AssertedCarrier> {
        self.params.iter().chain(std::iter::once(&self.result))
    }
}

/// What an annotation type head names, decided before any carrier arm.
///
/// A reserved builtin row is claimed first: no user module can declare one,
/// so its spelling is the builtin. Only a reserved row is claimed — a
/// non-reserved builtin name (`Decimal`) may also be a crate's opaque, so it
/// falls through to the opaque resolution. A local type is checked only for an
/// unqualified spelling: a qualified one cannot name the caller's own
/// declaration, and HM unification against the qualified forwarder checks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Head<'s> {
    /// A reserved scalar row.
    Scalar(ScalarCarrier),
    /// The reserved `Result` row.
    Result,
    /// The reserved `Error` row.
    Error,
    /// Any other reserved row: never an asserted carrier.
    NonCarrierBuiltin,
    /// A type the calling module declares.
    Local(LocalTypeKind),
    /// A candidate foreign opaque name.
    Nominal(&'s str),
}

/// Classify an annotation type head by its builtin row or its declaration.
fn classify_head<'i>(
    segments: &[Symbol],
    interner: &'i Interner,
    local_types: &LocalTypeNames,
) -> Result<Head<'i>, AssertedDefect> {
    let name = last_segment(segments, interner)?;
    if let Some(head) = reserved_head(name) {
        return Ok(head);
    }
    if segments.len() == 1
        && let Some(kind) = local_types.kind(name)
    {
        return Ok(Head::Local(kind));
    }
    Ok(Head::Nominal(name))
}

/// The head a reserved builtin row names, keyed on the row's tag.
fn reserved_head(name: &str) -> Option<Head<'static>> {
    let row = BuiltinType::of_bare_name(name)?.row();
    row.role()
        .forbids_user_declaration()
        .then(|| row.tag().map_or(Head::NonCarrierBuiltin, tag_head))
}

/// The asserted-call role of every builtin tag.
///
/// The match is exhaustive with no wildcard arm, so a tag added later is
/// classified here before it compiles.
#[allow(clippy::too_many_lines)] // one exhaustive `BuiltinTag` match
const fn tag_head(tag: BuiltinTag) -> Head<'static> {
    match tag {
        BuiltinTag::Int => Head::Scalar(ScalarCarrier::Int),
        BuiltinTag::Float => Head::Scalar(ScalarCarrier::Float),
        BuiltinTag::Bool => Head::Scalar(ScalarCarrier::Bool),
        BuiltinTag::Char => Head::Scalar(ScalarCarrier::Char),
        BuiltinTag::String => Head::Scalar(ScalarCarrier::Str),
        BuiltinTag::Bytes => Head::Scalar(ScalarCarrier::Bytes),
        BuiltinTag::Result => Head::Result,
        BuiltinTag::Error => Head::Error,
        BuiltinTag::List
        | BuiltinTag::Maybe
        | BuiltinTag::Set
        | BuiltinTag::Dict
        | BuiltinTag::Order
        | BuiltinTag::ErrorKind
        | BuiltinTag::ErrorDetails
        | BuiltinTag::BackoffStrategy
        | BuiltinTag::TaskStep
        | BuiltinTag::Decimal
        | BuiltinTag::Task
        | BuiltinTag::Cmd
        | BuiltinTag::Sub
        | BuiltinTag::Topic
        | BuiltinTag::Decoder
        | BuiltinTag::Db
        | BuiltinTag::SqlValue
        | BuiltinTag::SqlField
        | BuiltinTag::SqlFragment
        | BuiltinTag::ProjectionTerm
        | BuiltinTag::ProjectionOperand
        | BuiltinTag::Secret
        | BuiltinTag::Path
        | BuiltinTag::Regex
        | BuiltinTag::Url
        | BuiltinTag::UrlRelative
        | BuiltinTag::Dsn
        | BuiltinTag::DbLocation
        | BuiltinTag::Connection
        | BuiltinTag::ConnReadOnly
        | BuiltinTag::ConnReadWrite
        | BuiltinTag::Setting
        | BuiltinTag::ShapeWeb
        | BuiltinTag::ShapeWebView
        | BuiltinTag::ShapeTerminal
        | BuiltinTag::Program
        | BuiltinTag::ProgramShapeWeb
        | BuiltinTag::ProgramShapeTui
        | BuiltinTag::ProgramShapeCli
        | BuiltinTag::ProgramShapeWorker
        | BuiltinTag::HostMode
        | BuiltinTag::LogLevel
        | BuiltinTag::CsrfMode
        | BuiltinTag::RevocationMode
        | BuiltinTag::Locale
        | BuiltinTag::HttpMethod
        | BuiltinTag::RedirectPolicy
        | BuiltinTag::DbFailure
        | BuiltinTag::AuthError
        | BuiltinTag::Duration
        | BuiltinTag::CryptoKey
        | BuiltinTag::CryptoMac
        | BuiltinTag::EmailAddress
        | BuiltinTag::Principal
        | BuiltinTag::Claims
        | BuiltinTag::Algorithm
        | BuiltinTag::JsonValue
        | BuiltinTag::StreamId
        | BuiltinTag::StreamWriter
        | BuiltinTag::WsServer
        | BuiltinTag::WsServerCfg
        | BuiltinTag::ServerRequest
        | BuiltinTag::ServerCookie
        | BuiltinTag::ServerRoute
        | BuiltinTag::AuthConfig
        | BuiltinTag::TokenSource
        | BuiltinTag::UiAttribute
        | BuiltinTag::HtmlAttribute
        | BuiltinTag::View
        | BuiltinTag::UiElement
        | BuiltinTag::Cells
        | BuiltinTag::TuiAttr
        | BuiltinTag::CliLines
        | BuiltinTag::CliAttr
        | BuiltinTag::Color
        | BuiltinTag::ColorError
        | BuiltinTag::TermProfile
        | BuiltinTag::AnsiColor
        | BuiltinTag::WcagLevel
        | BuiltinTag::TextSize
        | BuiltinTag::Deficiency
        | BuiltinTag::CustomElement
        | BuiltinTag::Html
        | BuiltinTag::UiLength
        | BuiltinTag::UiColor
        | BuiltinTag::UiDescription
        | BuiltinTag::UiPseudoClass
        | BuiltinTag::InputLabel
        | BuiltinTag::InputPlaceholder
        | BuiltinTag::InputRadioOption
        | BuiltinTag::WebReq
        | BuiltinTag::SessionHandle
        | BuiltinTag::WebRoute
        | BuiltinTag::EmailProvider
        | BuiltinTag::WebApp
        | BuiltinTag::TuiApp
        | BuiltinTag::CliApp
        | BuiltinTag::DbStore
        | BuiltinTag::DbDraft
        | BuiltinTag::DbJoined
        | BuiltinTag::DbSelect
        | BuiltinTag::DbPolicy
        | BuiltinTag::DbCond
        | BuiltinTag::DbPred
        | BuiltinTag::DbSecured
        | BuiltinTag::DbOrder
        | BuiltinTag::Codec
        | BuiltinTag::Remote
        | BuiltinTag::RemoteAuth => Head::NonCarrierBuiltin,
    }
}

/// The refusal of a carrier the calling module declares itself.
fn local_refusal(
    node: &TypeAnnotation,
    interner: &Interner,
    kind: LocalTypeKind,
) -> AssertedDefect {
    AssertedDefect::LocalTypeNotACarrier {
        ty: render_ty(node, interner),
        alias: matches!(kind, LocalTypeKind::Alias),
    }
}

/// Parse one leaf carrier from an annotation node: a reserved scalar row or a
/// resolved opaque. Everything else — type variables, tuples, records, nested
/// functions, applied constructors, other builtins — is outside the closed set.
fn parse_carrier(
    node: &TypeAnnotation,
    interner: &Interner,
    scope: &CarrierScope<'_>,
    target: &InstalledCrate,
) -> Result<AssertedCarrier, AssertedDefect> {
    let outside = || AssertedDefect::CarrierOutsideClosedSet {
        ty: render_ty(node, interner),
    };
    let TypeAnnotation::TType(_, segments, args) = node else {
        return Err(outside());
    };
    let head = classify_head(segments, interner, scope.local_types)?;
    if let Head::Local(kind) = head {
        return Err(local_refusal(node, interner, kind));
    }
    if !args.is_empty() {
        return Err(outside());
    }
    match head {
        Head::Scalar(scalar) => Ok(AssertedCarrier::Scalar(scalar)),
        Head::Nominal(name) => scope
            .resolve_opaque(target, name)
            .map(AssertedCarrier::Opaque)
            .ok_or_else(|| AssertedDefect::OpaqueNotDeclared {
                name: name.to_owned(),
            }),
        Head::Result | Head::Error | Head::NonCarrierBuiltin | Head::Local(_) => Err(outside()),
    }
}

/// Parse the result position: exactly `Result Error <carrier>`, both heads
/// matched on their reserved builtin rows.
fn parse_result(
    node: &TypeAnnotation,
    interner: &Interner,
    scope: &CarrierScope<'_>,
    target: &InstalledCrate,
) -> Result<AssertedCarrier, AssertedDefect> {
    let shape = || AssertedDefect::ResultShape {
        ty: render_ty(node, interner),
    };
    let TypeAnnotation::TType(_, segments, args) = node else {
        return Err(shape());
    };
    match classify_head(segments, interner, scope.local_types)? {
        Head::Result => {}
        Head::Local(kind) => return Err(local_refusal(node, interner, kind)),
        Head::Scalar(_) | Head::Error | Head::NonCarrierBuiltin | Head::Nominal(_) => {
            return Err(shape());
        }
    }
    let [err_arg, ok_arg] = args.as_slice() else {
        return Err(shape());
    };
    let TypeAnnotation::TType(_, err_segments, err_args) = err_arg else {
        return Err(shape());
    };
    let err_head = classify_head(err_segments, interner, scope.local_types)?;
    if !err_args.is_empty() || !matches!(err_head, Head::Error) {
        return Err(shape());
    }
    parse_carrier(ok_arg, interner, scope, target)
}

/// The final dotted name segment, resolved through the interner that parsed it.
///
/// # Errors
/// [`AssertedDefect::CompilerBug`] when the reference has no segment or the
/// symbol is missing from the interner — never a silent empty name.
fn last_segment<'i>(
    segments: &[Symbol],
    interner: &'i Interner,
) -> Result<&'i str, AssertedDefect> {
    let symbol = segments.last().ok_or(AssertedDefect::CompilerBug(
        AssertedCompilerBug::EmptyTypeName,
    ))?;
    interner.resolve(*symbol).ok_or(AssertedDefect::CompilerBug(
        AssertedCompilerBug::TypeNameNotInterned,
    ))
}

/// Render an annotation node for a diagnostic (best-effort, source-shaped).
fn render_ty(node: &TypeAnnotation, interner: &Interner) -> String {
    match node {
        TypeAnnotation::TLambda(a, b) => {
            format!("{} -> {}", render_ty(a, interner), render_ty(b, interner))
        }
        TypeAnnotation::TVar(v) => interner.resolve(*v).unwrap_or("?").to_owned(),
        TypeAnnotation::TType(_, segments, args) => {
            let mut out = segments
                .iter()
                .filter_map(|s| interner.resolve(*s))
                .collect::<Vec<_>>()
                .join(".");
            for a in args {
                let _ = write!(out, " {}", render_ty(a, interner));
            }
            out
        }
        TypeAnnotation::TUnit => "()".to_owned(),
        TypeAnnotation::TTuple(items) => format!(
            "({})",
            items
                .iter()
                .map(|t| render_ty(t, interner))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        TypeAnnotation::TRecord(_) | TypeAnnotation::TRecordOpen(..) => "{…}".to_owned(),
    }
}

/// Validate one asserted call against the installed-crate catalog, resolving
/// every name and Rust type the emitters need.
///
/// # Errors
/// [`AssertedRefusal`] (IPE-F4414) at `site`, carrying the closed
/// [`AssertedDefect`].
pub fn validate(
    site: AssertedSite,
    path: AssertedPath,
    annotation: &TypeAnnotation,
    interner: &Interner,
    scope: &CarrierScope<'_>,
) -> Result<AssertedSpec, AssertedRefusal> {
    let refused = |defect: AssertedDefect| AssertedRefusal {
        path: path.as_str().to_owned(),
        defect,
        site: site.clone(),
    };
    let Some(target) = scope.target(&path) else {
        return Err(refused(AssertedDefect::TargetCrateNotInstalled {
            crate_ident: path.crate_ident().to_owned(),
        }));
    };
    // Every carrier resolves here, through the builtin rows and the target
    // crate's own maps — an undeclared nominal dies in the classifier.
    let sig =
        AssertedSig::from_annotation(annotation, interner, scope, target).map_err(&refused)?;
    let param_rust = if sig.unit_param {
        vec!["()".to_owned()]
    } else {
        sig.params
            .iter()
            .map(|c| c.rust_type().to_owned())
            .collect()
    };
    let result_rust = sig.result.rust_type().to_owned();
    let opaque_homes = sig
        .carriers()
        .filter_map(AssertedCarrier::opaque)
        .map(|o| o.home().to_owned())
        .collect();

    // The compile-time checker (design §5.2 rule 1): when the target is in
    // the cached inspection, the assertion must match it exactly — identity
    // carriers only, never a clamp the shim would then have to hide.
    if path.is_crate_top_level()
        && let Some(fact) = target.inspected_free_fns.get(path.fn_name())
    {
        check_against_inspection(&path, &sig, fact).map_err(&refused)?;
    }

    Ok(AssertedSpec {
        def_name: path.def_name(),
        wrapper_ident: path.wrapper_ident(),
        path,
        site,
        sig,
        param_rust,
        result_rust,
        opaque_homes,
    })
}

/// The exact-carrier cross-check against an inspected free function.
fn check_against_inspection(
    path: &AssertedPath,
    sig: &AssertedSig,
    fact: &crate::driver::InspectedFnFact,
) -> Result<(), AssertedDefect> {
    let unsupported = |reason| AssertedDefect::InspectedShapeUnsupported { reason };
    if fact.effect != Effect::Pure {
        return Err(unsupported(InspectedShapeReason::NotPure));
    }
    let (params, result) = match &fact.signature {
        InspectedSig::Declared { params, result } => (params, result),
        InspectedSig::Undeclared => {
            return Err(unsupported(InspectedShapeReason::UndeclaredRustType));
        }
    };
    let Some(result_ty) = result else {
        return Err(unsupported(InspectedShapeReason::NoReturnValue));
    };
    let expected = || AssertedDefect::InspectedMismatch {
        expected: format!(
            "fn {}({}) -> {}",
            path.fn_name(),
            params.join(", "),
            result_ty
        ),
    };
    let declared_params: &[AssertedCarrier] = if sig.unit_param { &[] } else { &sig.params };
    if declared_params.len() != params.len() {
        return Err(expected());
    }
    for (carrier, foreign) in declared_params.iter().zip(params) {
        if !exact_carrier_match(carrier, foreign) {
            return Err(expected());
        }
    }
    if !exact_carrier_match(&sig.result, result_ty) {
        return Err(expected());
    }
    Ok(())
}

/// A Rust type spelling with whitespace and any leading `::` removed.
fn normalized_rust(ty: &str) -> String {
    let compact: String = ty.chars().filter(|c| !c.is_whitespace()).collect();
    compact.trim_start_matches(':').to_owned()
}

/// Whether an asserted carrier is EXACTLY the inspected Rust type.
///
/// A scalar matches its one owned spelling byte-for-byte (whitespace-
/// normalized). An opaque matches on the FULL Rust path, never a last segment:
/// the inspected spelling is compared as written, and a bare (unqualified)
/// inspected spelling never matches an opaque — the inspector qualifies every
/// nameable foreign type. No clamp, no widening — identity only.
fn exact_carrier_match(carrier: &AssertedCarrier, foreign_ty: &str) -> bool {
    let foreign = normalized_rust(foreign_ty);
    match carrier {
        AssertedCarrier::Scalar(scalar) => foreign == normalized_rust(scalar.rust_owned()),
        AssertedCarrier::Opaque(opaque) => {
            foreign.contains("::") && foreign == normalized_rust(opaque.rust_path())
        }
    }
}

/// Fold a batch of validated specs, deduplicating identical assertions and
/// refusing conflicting ones (two different signatures for one path).
///
/// Signatures compare on their carriers' identities, so two same-named opaques
/// from different homes are different signatures.
///
/// # Errors
/// [`AssertedRefusal`] with [`AssertedDefect::ConflictingAssertions`], at the
/// later definition's site and naming the earlier one's.
pub fn dedupe(specs: Vec<AssertedSpec>) -> Result<Vec<AssertedSpec>, AssertedRefusal> {
    let mut by_def: BTreeMap<String, AssertedSpec> = BTreeMap::new();
    for spec in specs {
        match by_def.get(&spec.def_name) {
            None => {
                by_def.insert(spec.def_name.clone(), spec);
            }
            // Identical path AND signature: one definition serves them all. A
            // path mismatch under one derived name is the (astronomically
            // unlikely) hash collision — refused loudly, never merged.
            Some(existing) if existing.sig == spec.sig && existing.path == spec.path => {}
            Some(existing) => {
                return Err(AssertedRefusal {
                    path: spec.path.as_str().to_owned(),
                    defect: AssertedDefect::ConflictingAssertions {
                        first: format!("{} : {}", existing.path.as_str(), existing.sig.ipe_sig()),
                        second: format!("{} : {}", spec.path.as_str(), spec.sig.ipe_sig()),
                        first_site: existing.site.clone(),
                    },
                    site: spec.site,
                });
            }
        }
    }
    Ok(by_def.into_values().collect())
}

/// Render the driver-generated `Rust.Ffi` interface module.
///
/// One annotated forwarder per asserted call, each body an `Ffi.asserted`
/// binding — mintable only under `ModuleOrigin::FfiInterface`, so the escape
/// hatch compiles down to the same gated interface entries as every other
/// surface. Every opaque's home is imported bare, and every signature spells
/// the opaque fully qualified through that import.
#[must_use]
pub fn render_asserted_interface(specs: &[AssertedSpec], consts: &[ConstSpec]) -> String {
    let mut exports: Vec<&str> = specs
        .iter()
        .map(|s| s.def_name.as_str())
        .chain(consts.iter().map(|c| c.def_name.as_str()))
        .collect();
    exports.sort_unstable();
    let mut out = format!(
        "module {} exposing ({})\n",
        ipe_canon::asserted::ASSERTED_MODULE,
        exports.join(", ")
    );
    let homes: BTreeSet<&str> = specs
        .iter()
        .flat_map(|s| s.opaque_homes.iter().map(String::as_str))
        .collect();
    for home in homes {
        let _ = write!(out, "\nimport {home}\n");
    }
    let mut ordered: Vec<&AssertedSpec> = specs.iter().collect();
    ordered.sort_unstable_by(|a, b| a.def_name.cmp(&b.def_name));
    for s in ordered {
        let args: Vec<String> = (0..s.sig.arity()).map(crate::naming::arg_name).collect();
        let args_joined = args.join(" ");
        let _ = write!(
            out,
            "\n{} : {}\n{} {} =\n    Ffi.asserted \"{}\" {}\n",
            s.def_name,
            s.sig.ipe_sig(),
            s.def_name,
            args_joined,
            s.wrapper_ident,
            args_joined
        );
    }
    out.push_str(&render_const_interface(consts));
    out
}

/// Render the asserted shim region appended to the assembled `src/ffi.rs`.
///
/// Exact-carrier by construction: parameters and the return are the resolved
/// carrier types verbatim, the call forwards the owned arguments untouched,
/// and the body's only transformation is the panic boundary. When the target
/// was not inspected, `rustc` checks this region against the real crate; the
/// comment above each shim attributes such a failure to the assertion.
#[must_use]
pub fn emit_asserted_shims(specs: &[AssertedSpec]) -> String {
    let mut ordered: Vec<&AssertedSpec> = specs.iter().collect();
    ordered.sort_unstable_by(|a, b| a.wrapper_ident.cmp(&b.wrapper_ident));
    let mut lines: Vec<String> = vec![
        "pub mod ipe_asserted {".to_owned(),
        "    //! Author-asserted foreign-call shims (`Rust.Ffi.call`): the exact".to_owned(),
        "    //! declared carriers, no numeric coercion, every call inside the".to_owned(),
        "    //! panic boundary.".to_owned(),
        "    #![allow(unused_imports)]".to_owned(),
        String::new(),
        "    use crate::*;".to_owned(),
    ];
    for s in ordered {
        let params: Vec<String> = s
            .param_rust
            .iter()
            .enumerate()
            .map(|(i, ty)| {
                if s.sig.unit_param {
                    format!("_: {ty}")
                } else {
                    format!("{}: {ty}", crate::naming::arg_name(i))
                }
            })
            .collect();
        let forwarded = if s.sig.unit_param {
            String::new()
        } else {
            (0..s.param_rust.len())
                .map(crate::naming::arg_name)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let call = format!("{}({forwarded})", s.path.rust_call_path());
        lines.push(String::new());
        lines.push(format!(
            "    // [asserted] {} : {} = Rust.Ffi.call \"{}\"",
            s.def_name,
            s.sig.ipe_sig(),
            s.path.as_str()
        ));
        lines.push(
            "    // A type error in this shim means the author-asserted signature does".to_owned(),
        );
        lines
            .push("    // not match the real Rust signature — fix the assertion at the".to_owned());
        lines.push(
            "    // definition above, or use the inspected import (`import Rust.<Crate>`)."
                .to_owned(),
        );
        lines.push(format!(
            "    pub fn {}({}) -> IpeResult<IpeError, {}> {{",
            s.wrapper_ident,
            params.join(", "),
            s.result_rust
        ));
        lines.push(format!(
            "        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {call})) \
             {{ Ok(v) => IpeResult::Ok(v), Err(__p) => IpeResult::Err(ipe_error_from_panic(\
             \"asserted foreign call panicked\", __p)) }}"
        ));
        lines.push("    }".to_owned());
    }
    lines.push("}".to_owned());
    lines.push("pub use ipe_asserted::*;".to_owned());
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

// ── native constants (`Rust.const`) ─────────────────────────────────────────

/// One validated native-constant read: the parsed path, the asserted scalar
/// type, the derived names, and the rendered Rust type — resolved here so
/// emission is a total function over this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstSpec {
    /// The validated target path.
    pub path: AssertedPath,
    /// The definition that reads it.
    pub site: AssertedSite,
    /// The asserted scalar carrier (never opaque, never a `Result`/arrow).
    pub scalar: crate::carrier::ScalarCarrier,
    /// The Ipê definition name in the generated `Rust.Ffi` module.
    pub def_name: String,
    /// The `_bindings.rs` const-read shim identifier.
    pub wrapper_ident: String,
}

impl ConstSpec {
    /// The Ipê surface type of the generated interface def (a bare scalar).
    #[must_use]
    pub const fn ipe_type(&self) -> &'static str {
        self.scalar.ipe_surface()
    }
}

/// Parse a `Rust.const` annotation into its bare scalar carrier.
///
/// The one accepted shape is a bare reserved scalar row (`Int`, `Float`,
/// `Bool`, `Char`, `String`, `Bytes`). An arrow, a `Result`, a tuple, a
/// record, an applied constructor, or an opaque nominal is refused — a native
/// constant is a single infallible value, never a fallible or compound one.
///
/// # Errors
/// [`AssertedDefect::ConstNotScalar`] naming the offending annotation, or
/// [`AssertedDefect::LocalTypeNotACarrier`] for a type the module declares.
fn parse_const_scalar(
    annotation: &TypeAnnotation,
    interner: &Interner,
    local_types: &LocalTypeNames,
) -> Result<ScalarCarrier, AssertedDefect> {
    let not_scalar = || AssertedDefect::ConstNotScalar {
        ty: render_ty(annotation, interner),
    };
    let TypeAnnotation::TType(_, name_segments, args) = annotation else {
        return Err(not_scalar());
    };
    match classify_head(name_segments, interner, local_types)? {
        Head::Local(kind) => Err(local_refusal(annotation, interner, kind)),
        Head::Scalar(scalar) if args.is_empty() => Ok(scalar),
        Head::Scalar(_)
        | Head::Result
        | Head::Error
        | Head::NonCarrierBuiltin
        | Head::Nominal(_) => Err(not_scalar()),
    }
}

/// Validate one `Rust.const` call against the installed-crate catalog.
///
/// The annotation must be a bare scalar, the target crate installed, and the
/// constant present in the crate's inspected constants with a matching type.
///
/// The introspection cross-check is MANDATORY here (unlike `Rust.fn`, whose
/// uninspected path falls back to the shim's `rustc` check): a native constant
/// carries no panic boundary, so its type is confirmed against the inspection
/// or the read is refused — the boundary never blind-trusts an unverifiable
/// value. The emitted `::crate::PATH` read is the `rustc` backstop for a
/// type the inspection recorded but the emit still mis-renders.
///
/// # Errors
/// [`AssertedRefusal`] at `site`, carrying the closed [`AssertedDefect`].
pub fn validate_const(
    site: AssertedSite,
    path: AssertedPath,
    annotation: &TypeAnnotation,
    interner: &Interner,
    scope: &CarrierScope<'_>,
) -> Result<ConstSpec, AssertedRefusal> {
    let refused = |defect: AssertedDefect| AssertedRefusal {
        path: path.as_str().to_owned(),
        defect,
        site: site.clone(),
    };
    let Some(target) = scope.target(&path) else {
        return Err(refused(AssertedDefect::TargetCrateNotInstalled {
            crate_ident: path.crate_ident().to_owned(),
        }));
    };
    let scalar = parse_const_scalar(annotation, interner, scope.local_types).map_err(&refused)?;
    // The constant is keyed in the inspection by its crate-RELATIVE path
    // (`f64::consts::PI`) — the asserted path with its leading crate segment
    // stripped. Absence is a fail-closed refusal: no unverified native read.
    let relative = path
        .as_str()
        .strip_prefix(path.crate_ident())
        .and_then(|r| r.strip_prefix("::"))
        .unwrap_or(path.as_str());
    let Some(fact) = target.inspected_consts.get(relative) else {
        return Err(refused(AssertedDefect::ConstNotIntrospectable {
            name: relative.to_owned(),
        }));
    };
    if !const_type_matches(scalar, &fact.ty) {
        return Err(refused(AssertedDefect::ConstTypeMismatch {
            expected: fact.ty.clone(),
        }));
    }
    Ok(ConstSpec {
        def_name: path.const_def_name(),
        wrapper_ident: path.const_wrapper_ident(),
        path,
        site,
        scalar,
    })
}

/// Whether an inspected constant's Rust type is EXACTLY the asserted scalar's
/// Rust rendering. A `&str`/`&'static str` constant matches the `String`
/// scalar (the shim owns it with `.to_owned()`); every other scalar matches
/// its owned spelling byte-for-byte (whitespace-normalized). Identity only —
/// no widening, no lossy conversion.
fn const_type_matches(scalar: crate::carrier::ScalarCarrier, foreign_ty: &str) -> bool {
    let normalized: String = foreign_ty.chars().filter(|c| !c.is_whitespace()).collect();
    if matches!(scalar, crate::carrier::ScalarCarrier::Str) {
        return matches!(normalized.as_str(), "&str" | "&'staticstr" | "String");
    }
    normalized == scalar.rust_owned().replace(' ', "")
}

/// Render the driver-generated `Rust.Ffi` const-read forwarders.
///
/// Each is a nullary value binding whose whole body is an `Ffi.asserted`
/// binding of the const-read shim — mintable only under
/// [`ipe_canon::ModuleOrigin::FfiInterface`], so a native constant compiles
/// down to the same gated interface entries as every other surface. The Ipê
/// type is a bare scalar (no `Result`), so the read is infallible.
#[must_use]
pub fn render_const_interface(specs: &[ConstSpec]) -> String {
    let mut ordered: Vec<&ConstSpec> = specs.iter().collect();
    ordered.sort_unstable_by(|a, b| a.def_name.cmp(&b.def_name));
    let mut out = String::new();
    for s in ordered {
        let _ = write!(
            out,
            "\n{} : {}\n{} =\n    Ffi.asserted \"{}\"\n",
            s.def_name,
            s.ipe_type(),
            s.def_name,
            s.wrapper_ident
        );
    }
    out
}

/// Render the native-constant shim region: one nullary `fn` per constant.
///
/// Each returns the inspected scalar BY VALUE. The body is a BARE
/// `::crate::PATH` read — no `catch_unwind`, no `IpeResult`, no call
/// parentheses — because a constant cannot panic or fail. A `String`-scalar
/// const owns its `&str` source with `.to_owned()`. A mis-typed emitted read
/// fails `cargo build`, the `rustc` backstop for the (inspection-confirmed)
/// type.
#[must_use]
pub fn emit_const_shims(specs: &[ConstSpec]) -> String {
    let mut ordered: Vec<&ConstSpec> = specs.iter().collect();
    ordered.sort_unstable_by(|a, b| a.wrapper_ident.cmp(&b.wrapper_ident));
    let mut lines: Vec<String> = vec![
        "pub mod ipe_asserted_const {".to_owned(),
        "    //! Author-asserted native-constant reads (`Rust.const`): a bare".to_owned(),
        "    //! value read of the inspected scalar type, no panic boundary and".to_owned(),
        "    //! no fallible wrapper (a constant cannot fail).".to_owned(),
        "    #![allow(unused_imports)]".to_owned(),
        String::new(),
        "    use crate::*;".to_owned(),
    ];
    for s in ordered {
        // The bare constant read: `::crate::PATH`, never called.
        let read = s.path.rust_call_path();
        let (ret, body) = match s.scalar {
            ScalarCarrier::Str => ("String".to_owned(), format!("{read}.to_owned()")),
            other => (other.rust_owned().to_owned(), read),
        };
        lines.push(String::new());
        lines.push(format!(
            "    // [asserted-const] {} : {} = Rust.const \"{}\" \"{}\"",
            s.def_name,
            s.ipe_type(),
            s.path.crate_ident(),
            s.path
                .as_str()
                .strip_prefix(s.path.crate_ident())
                .and_then(|r| r.strip_prefix("::"))
                .unwrap_or(s.path.as_str())
        ));
        lines.push(
            "    // A type error here means the asserted type does not match the real".to_owned(),
        );
        lines.push("    // Rust constant — fix the annotation at the definition above.".to_owned());
        lines.push(format!("    pub fn {}() -> {ret} {{", s.wrapper_ident));
        lines.push(format!("        {body}"));
        lines.push("    }".to_owned());
    }
    lines.push("}".to_owned());
    lines.push("pub use ipe_asserted_const::*;".to_owned());
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Fold a batch of validated const specs, deduplicating identical reads and
/// refusing conflicting ones (two different scalar types for one path).
///
/// # Errors
/// [`AssertedRefusal`] with [`AssertedDefect::ConflictingAssertions`], at the
/// later definition's site and naming the earlier one's.
pub fn dedupe_consts(specs: Vec<ConstSpec>) -> Result<Vec<ConstSpec>, AssertedRefusal> {
    let mut by_def: BTreeMap<String, ConstSpec> = BTreeMap::new();
    for spec in specs {
        match by_def.get(&spec.def_name) {
            None => {
                by_def.insert(spec.def_name.clone(), spec);
            }
            Some(existing) if existing.scalar == spec.scalar && existing.path == spec.path => {}
            Some(existing) => {
                return Err(AssertedRefusal {
                    path: spec.path.as_str().to_owned(),
                    defect: AssertedDefect::ConflictingAssertions {
                        first: format!("{} : {}", existing.path.as_str(), existing.ipe_type()),
                        second: format!("{} : {}", spec.path.as_str(), spec.ipe_type()),
                        first_site: existing.site.clone(),
                    },
                    site: spec.site,
                });
            }
        }
    }
    Ok(by_def.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkginfo::PkgInfo;
    use ipe_diagnostics::FfiError;

    fn intern(interner: &mut Interner, s: &str) -> Symbol {
        interner.intern(s).expect("interner has capacity")
    }

    /// Build a `TypeAnnotation` arrow chain from leaf names, e.g.
    /// `["Int", "Result Error Int"]` — leaves are built structurally.
    fn ann_leaf(interner: &mut Interner, name: &str) -> TypeAnnotation {
        if name == "()" {
            return TypeAnnotation::TUnit;
        }
        let empty = intern(interner, "");
        if let Some(rest) = name.strip_prefix("Result Error ") {
            let result = intern(interner, "Result");
            let error = intern(interner, "Error");
            let inner = ann_leaf(interner, rest);
            let err_node = TypeAnnotation::TType(empty, vec![error], vec![]);
            return TypeAnnotation::TType(empty, vec![result], vec![err_node, inner]);
        }
        let segments = name.split('.').map(|s| intern(interner, s)).collect();
        TypeAnnotation::TType(empty, segments, vec![])
    }

    fn arrow(interner: &mut Interner, names: &[&str]) -> TypeAnnotation {
        let mut nodes: Vec<TypeAnnotation> = names.iter().map(|n| ann_leaf(interner, n)).collect();
        let mut out = nodes.pop().expect("non-empty arrow");
        while let Some(param) = nodes.pop() {
            out = TypeAnnotation::TLambda(Box::new(param), Box::new(out));
        }
        out
    }

    fn semver_crate() -> InstalledCrate {
        let doc = serde_json::json!({
            "pkg": "semver", "name": "semver", "version": "1.0.26",
            "functions": [
                {
                    "name": "frobnicate",
                    "params": [{"name": "n", "type": "Int", "ipeType": "Int", "rustType": "i64"}],
                    "results": [{"name": "", "type": "Int", "rustType": "i64"}],
                    "effect": "pure"
                },
                {
                    "name": "clamped",
                    "params": [{"name": "n", "type": "Int", "ipeType": "Int", "rustType": "u32"}],
                    "results": [{"name": "", "type": "Int", "rustType": "u32"}],
                    "effect": "pure"
                },
                {
                    "name": "parse",
                    "params": [{"name": "text", "type": "String", "ipeType": "String",
                                "rustType": "&str"}],
                    "results": [{"name": "", "type": "Result Error Version",
                                 "rustType": "Result<semver::Version, semver::Error>"}],
                    "effect": "fallible"
                }
            ],
            "constants": [
                {"path": "MAX_MINOR", "type": "i64"},
                {"path": "consts::PI", "type": "f64"},
                {"path": "NAME", "type": "&'static str"},
                {"path": "BUILD", "type": "semver::Prerelease"}
            ],
            "errors": [],
            "transitiveDeps": [{"ident": "semver", "name": "semver", "version": "1.0.26"}],
            "foreignTypeIds": {"::semver::Version": "semver::version::Version"}
        })
        .to_string();
        let pkg = PkgInfo::decode_json(&doc).expect("decodes");
        crate::driver::installed_crate_from_pkg(
            "semver".to_owned(),
            &pkg,
            &crate::driver::FfiCache::at_project_root(std::path::Path::new(".")),
        )
        .expect("installs")
    }

    /// A site on line 3 of a fixture module.
    fn test_site() -> AssertedSite {
        site_at("src/Main.ipe", 3)
    }

    /// A site at the start of 1-based `line` in `file`.
    fn site_at(file: &str, line: usize) -> AssertedSite {
        let source = "x\n".repeat(line);
        let lo = u32::try_from(source.len().saturating_sub(2)).expect("small");
        AssertedSite::new(
            std::path::PathBuf::from(file),
            ipe_diagnostics::Span::new(lo, lo.saturating_add(1)),
            &source,
        )
    }

    fn validated_const(ty: &str, path: &str) -> Result<ConstSpec, AssertedRefusal> {
        let mut interner = Interner::new();
        let ann = ann_leaf(&mut interner, ty);
        let path = AssertedPath::parse(path).expect("path parses");
        let catalog = [semver_crate()];
        let unify = UnifyReport::default();
        let locals = LocalTypeNames::default();
        validate_const(
            test_site(),
            path,
            &ann,
            &interner,
            &CarrierScope::new(&catalog, &unify, &locals),
        )
    }

    fn validated_in(
        sig_names: &[&str],
        path: &str,
        catalog: &[InstalledCrate],
        unify: &UnifyReport,
        locals: &LocalTypeNames,
    ) -> Result<AssertedSpec, AssertedRefusal> {
        let mut interner = Interner::new();
        let ann = arrow(&mut interner, sig_names);
        let path = AssertedPath::parse(path).expect("path parses");
        validate(
            test_site(),
            path,
            &ann,
            &interner,
            &CarrierScope::new(catalog, unify, locals),
        )
    }

    fn validated(sig_names: &[&str], path: &str) -> Result<AssertedSpec, AssertedRefusal> {
        validated_in(
            sig_names,
            path,
            &[semver_crate()],
            &UnifyReport::default(),
            &LocalTypeNames::default(),
        )
    }

    #[test]
    fn a_matching_inspected_assertion_validates() {
        let spec =
            validated(&["Int", "Result Error Int"], "semver::frobnicate").expect("validates");
        assert_eq!(spec.sig.ipe_sig(), "Int -> Result Error Int");
        assert_eq!(spec.param_rust, vec!["i64".to_owned()]);
        assert_eq!(spec.result_rust, "i64");
        assert!(spec.def_name.starts_with("asserted_semver_frobnicate__"));
        assert!(
            spec.wrapper_ident
                .starts_with("ipe_asserted_semver_frobnicate__")
        );
    }

    #[test]
    fn a_refusal_carries_the_site_it_refuses() {
        let err = validated(&["Int", "Result Error Int"], "nope::f").expect_err("refused");
        assert_eq!(err.site, test_site());
        assert_eq!(err.site.line(), 3);
        let shared = FfiError::from(err.clone());
        assert!(
            matches!(&shared, FfiError::AssertedRefused { span, .. } if *span == err.site.span()),
            "the shared diagnostic keeps the site's span: {shared:?}"
        );
        let refused =
            validated_const("Result Error Int", "semver::MAX_MINOR").expect_err("not a scalar");
        assert_eq!(refused.site, test_site());
    }

    /// The refusal's own rendering holds no text of the site's file, so it
    /// names the site's line and draws no location computed from absent text.
    #[test]
    fn a_refusal_renders_its_site_line_without_a_located_snippet() {
        let err = validated(&["Int", "Result Error Int"], "nope::f").expect_err("refused");
        let text = err.to_string();
        assert!(text.contains("src/Main.ipe:3"), "{text}");
        assert!(text.contains("IPE-F4414"), "{text}");
        assert!(!text.contains("-->"), "{text}");
    }

    #[test]
    fn a_site_line_counts_from_one() {
        let path = std::path::PathBuf::from("src/A.ipe");
        let first = AssertedSite::new(path.clone(), ipe_diagnostics::Span::new(0, 1), "ab\ncd\n");
        assert_eq!(first.line(), 1);
        let second = AssertedSite::new(path.clone(), ipe_diagnostics::Span::new(3, 4), "ab\ncd\n");
        assert_eq!(second.line(), 2);
        assert_eq!(second.to_string(), "src/A.ipe:2");
        let past = AssertedSite::new(path, ipe_diagnostics::Span::new(99, 99), "ab\ncd\n");
        assert_eq!(past.line(), 3, "an offset past the text clamps to its end");
    }

    #[test]
    fn an_uninstalled_crate_is_refused() {
        let err = validated(&["Int", "Result Error Int"], "nope::f").expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::TargetCrateNotInstalled { crate_ident }, ..
                } if crate_ident == "nope"
            ),
            "{err}"
        );
    }

    #[test]
    fn a_clamp_requiring_target_is_refused_with_the_exact_carrier_named() {
        // `clamped` takes/returns u32 — Int (i64) would need a clamp, which the
        // exact-carrier rule forbids in an asserted shim.
        let err = validated(&["Int", "Result Error Int"], "semver::clamped").expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::InspectedMismatch { expected }, ..
                } if expected.contains("u32")
            ),
            "{err}"
        );
    }

    #[test]
    fn a_fallible_inspected_target_is_refused() {
        let err =
            validated(&["String", "Result Error Version"], "semver::parse").expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::InspectedShapeUnsupported { .. },
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn an_uninspected_symbol_passes_to_the_rustc_checker() {
        // Not in the inspection: no compile-time cross-check, the emitted shim
        // carries the asserted types and rustc is the checker of record.
        let spec = validated(&["Int", "Result Error Int"], "semver::not_inspected")
            .expect("passes to rustc");
        let shims = emit_asserted_shims(std::slice::from_ref(&spec));
        assert!(shims.contains("::semver::not_inspected(arg0)"), "{shims}");
    }

    #[test]
    fn a_total_result_is_refused() {
        let err = validated(&["Int", "Int"], "semver::frobnicate").expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::ResultShape { .. },
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn an_undeclared_opaque_is_refused() {
        let err =
            validated(&["Widget", "Result Error Int"], "semver::frobnicate").expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::OpaqueNotDeclared { name }, ..
                } if name == "Widget"
            ),
            "{err}"
        );
    }

    #[test]
    fn a_declared_opaque_resolves_and_imports() {
        let spec = validated(
            &["Version", "Result Error Version"],
            "semver::not_inspected",
        )
        .expect("validates");
        assert_eq!(spec.param_rust, vec!["::semver::Version".to_owned()]);
        assert!(spec.opaque_homes.contains("Rust.Semver"));
        let iface = render_asserted_interface(std::slice::from_ref(&spec), &[]);
        assert!(iface.contains("\nimport Rust.Semver\n"), "{iface}");
        assert!(
            iface.contains(": Rust.Semver.Version -> Result Error Rust.Semver.Version\n"),
            "{iface}"
        );
        assert!(!iface.contains("exposing (Version)"), "{iface}");
    }

    #[test]
    fn conflicting_assertions_for_one_path_are_refused() {
        let a = validated(&["Int", "Result Error Int"], "semver::frobnicate").expect("validates");
        let b =
            validated(&["Bool", "Result Error Int"], "semver::not_inspected").expect("validates");
        // Same path, different sig, another file: rebuild `b` on `a`'s path.
        let conflicting = AssertedSpec {
            def_name: a.def_name.clone(),
            site: site_at("src/Other.ipe", 7),
            ..b
        };
        let err = dedupe(vec![a, conflicting]).expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::ConflictingAssertions { first_site, .. },
                    site,
                    ..
                } if *first_site == test_site() && *site == site_at("src/Other.ipe", 7)
            ),
            "the conflict sits at the second definition and names the first: {err:?}"
        );
        let detail = err.defect.to_string();
        assert!(detail.contains("at src/Main.ipe:3 "), "{detail}");
        // Identical assertions deduplicate to one spec.
        let a2 = validated(&["Int", "Result Error Int"], "semver::frobnicate").expect("validates");
        let a3 = validated(&["Int", "Result Error Int"], "semver::frobnicate").expect("validates");
        assert_eq!(dedupe(vec![a2, a3]).expect("dedupes").len(), 1);
    }

    #[test]
    fn the_shim_is_exact_carrier_and_panic_bounded() {
        let spec = validated(&["Int", "Result Error Int"], "semver::frobnicate").expect("ok");
        let shims = emit_asserted_shims(std::slice::from_ref(&spec));
        assert!(shims.contains("catch_unwind"), "{shims}");
        assert!(shims.contains("ipe_error_from_panic"), "{shims}");
        assert!(
            shims.contains(&format!(
                "pub fn {}(arg0: i64) -> IpeResult<IpeError, i64>",
                spec.wrapper_ident
            )),
            "{shims}"
        );
        // The exact-carrier rule, textually: no coercion helper reaches an
        // asserted shim.
        assert!(!shims.contains("num_coerce"), "{shims}");
        assert!(!shims.contains("clamp"), "{shims}");
        assert!(!shims.contains(" as "), "{shims}");
    }

    #[test]
    fn the_interface_renders_the_gated_asserted_body() {
        let spec = validated(&["Int", "Result Error Int"], "semver::frobnicate").expect("ok");
        let iface = render_asserted_interface(std::slice::from_ref(&spec), &[]);
        assert!(iface.starts_with("module Rust.Ffi exposing ("), "{iface}");
        assert!(
            iface.contains(&format!(
                "{} : Int -> Result Error Int\n{} arg0 =\n    Ffi.asserted \"{}\" arg0\n",
                spec.def_name, spec.def_name, spec.wrapper_ident
            )),
            "{iface}"
        );
    }

    #[test]
    fn a_unit_param_signature_renders_the_zero_arg_shapes() {
        let spec =
            validated(&["()", "Result Error Int"], "semver::uninspected_zero").expect("validates");
        assert_eq!(spec.sig.ipe_sig(), "() -> Result Error Int");
        assert_eq!(spec.sig.arity(), 1);
        let shims = emit_asserted_shims(std::slice::from_ref(&spec));
        assert!(
            shims.contains("(_: ()) -> IpeResult<IpeError, i64>"),
            "{shims}"
        );
        assert!(shims.contains("::semver::uninspected_zero()"), "{shims}");
    }

    // ── native constants (`Rust.const`) ─────────────────────────────────────

    #[test]
    fn a_matching_scalar_const_validates_and_reads_bare() {
        let spec = validated_const("Float", "semver::consts::PI").expect("validates");
        assert_eq!(spec.ipe_type(), "Float");
        assert!(
            spec.def_name
                .starts_with("asserted_const_semver_consts_pi__")
        );
        assert!(
            spec.wrapper_ident
                .starts_with("ipe_asserted_const_semver_consts_pi__")
        );
        let shims = emit_const_shims(std::slice::from_ref(&spec));
        // The SEAL of the const read: a bare `::crate::PATH` value, no call
        // parentheses, no panic boundary, no `IpeResult` wrapper.
        assert!(shims.contains("-> f64 {"), "{shims}");
        assert!(shims.contains("::semver::consts::PI"), "{shims}");
        assert!(!shims.contains("::semver::consts::PI("), "{shims}");
        assert!(!shims.contains("catch_unwind"), "{shims}");
        assert!(!shims.contains("IpeResult"), "{shims}");
        assert!(!shims.contains("ipe_error_from_panic"), "{shims}");
    }

    #[test]
    fn a_string_const_owns_its_str_source() {
        let spec = validated_const("String", "semver::NAME").expect("validates");
        let shims = emit_const_shims(std::slice::from_ref(&spec));
        assert!(shims.contains("-> String {"), "{shims}");
        assert!(shims.contains("::semver::NAME.to_owned()"), "{shims}");
    }

    #[test]
    fn a_const_interface_is_a_nullary_bare_value_binding() {
        let spec = validated_const("Float", "semver::consts::PI").expect("validates");
        let iface = render_const_interface(std::slice::from_ref(&spec));
        // A bare scalar type (no `Result`), and a nullary binding (no args).
        assert!(
            iface.contains(&format!(
                "{} : Float\n{} =\n    Ffi.asserted \"{}\"\n",
                spec.def_name, spec.def_name, spec.wrapper_ident
            )),
            "{iface}"
        );
    }

    #[test]
    fn a_result_typed_const_is_refused_as_non_scalar() {
        let err = validated_const("Result Error Int", "semver::consts::PI").expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::ConstNotScalar { .. },
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn an_opaque_typed_const_is_refused_as_non_scalar() {
        // A native constant reads a bare scalar; an opaque handle has no bare
        // value shape, so `Rust.const : Version` is refused before any lookup.
        let err = validated_const("Version", "semver::BUILD").expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::ConstNotScalar { .. },
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn an_uninspected_const_is_refused_fail_closed() {
        // Not among the crate's inspected constants: its type cannot be
        // confirmed, so the read is refused rather than blind-trusted.
        let err = validated_const("Int", "semver::not_a_const").expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::ConstNotIntrospectable { .. },
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_wrong_typed_const_is_refused_under_exact_carrier() {
        // `MAX_MINOR` is inspected as `i64`; asserting `Float` mismatches.
        let err = validated_const("Float", "semver::MAX_MINOR").expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::ConstTypeMismatch { expected }, ..
                } if expected == "i64"
            ),
            "{err}"
        );
    }

    #[test]
    fn conflicting_const_types_for_one_path_are_refused() {
        let a = validated_const("Float", "semver::consts::PI").expect("validates");
        let b = validated_const("String", "semver::NAME").expect("validates");
        // Same derived name, different scalar, another file: rebuild `b` on
        // `a`'s def name.
        let conflicting = ConstSpec {
            def_name: a.def_name.clone(),
            site: site_at("src/Other.ipe", 7),
            ..b
        };
        let err = dedupe_consts(vec![a, conflicting]).expect_err("refused");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::ConflictingAssertions { first_site, .. },
                    site,
                    ..
                } if *first_site == test_site() && *site == site_at("src/Other.ipe", 7)
            ),
            "the conflict sits at the second definition and names the first: {err:?}"
        );
        let detail = err.defect.to_string();
        assert!(detail.contains("at src/Main.ipe:3 "), "{detail}");
        // Identical const reads deduplicate to one spec.
        let a2 = validated_const("Float", "semver::consts::PI").expect("validates");
        let a3 = validated_const("Float", "semver::consts::PI").expect("validates");
        assert_eq!(dedupe_consts(vec![a2, a3]).expect("dedupes").len(), 1);
    }

    // ── carrier identity: builtin rows and resolved opaque homes ────────────

    /// A crate stub with the given opaque types `(name, rust path, defid)`.
    fn stub_crate(
        module: &str,
        slug: &str,
        types: &[(&str, &str, Option<&str>)],
        dep_version: (&str, &str),
    ) -> InstalledCrate {
        InstalledCrate {
            kernel_name: module.replace('.', "_"),
            module_name: module.to_owned(),
            slug: slug.to_owned(),
            interface_source: String::new(),
            opaque_types: types
                .iter()
                .map(|(n, p, _)| ((*n).to_owned(), (*p).to_owned()))
                .collect(),
            opaque_type_ids: types
                .iter()
                .filter_map(|(n, _, d)| d.map(|d| ((*n).to_owned(), d.to_owned())))
                .collect(),
            define_types: BTreeSet::new(),
            bindings: Vec::new(),
            dep_versions: std::iter::once((dep_version.0.to_owned(), dep_version.1.to_owned()))
                .collect(),
            inspected_free_fns: BTreeMap::new(),
            inspected_consts: BTreeMap::new(),
            ..semver_crate()
        }
    }

    fn refused_with(outcome: Result<AssertedSpec, AssertedRefusal>) -> Option<AssertedDefect> {
        match outcome {
            Err(AssertedRefusal { defect, .. }) => Some(defect),
            _ => None,
        }
    }

    #[test]
    fn str_wire_spelling_is_not_a_carrier() {
        let defect = refused_with(validated(
            &["Str", "Result Error Int"],
            "semver::not_inspected",
        ));
        assert!(
            matches!(&defect, Some(AssertedDefect::OpaqueNotDeclared { name }) if name == "Str"),
            "{defect:?}"
        );
    }

    #[test]
    fn lowercase_wire_spellings_are_not_carriers() {
        for wire in ["i64", "f64", "bool", "char"] {
            let defect = refused_with(validated(
                &[wire, "Result Error Int"],
                "semver::not_inspected",
            ));
            assert!(
                matches!(&defect, Some(AssertedDefect::OpaqueNotDeclared { name }) if name == wire),
                "{wire}: {defect:?}"
            );
        }
        let spec = validated(&["String", "Result Error Int"], "semver::not_inspected")
            .expect("the String builtin row is a carrier");
        assert_eq!(spec.param_rust, vec!["String".to_owned()]);
    }

    #[test]
    fn demoted_reexport_resolves_to_home() {
        let mut catalog = vec![
            stub_crate(
                "Rust.Async_stripe",
                "async_stripe",
                &[(
                    "Client",
                    "::stripe::Client",
                    Some("stripe_client_core::client::Client"),
                )],
                ("stripe_client_core", "1.0.0-rc.6"),
            ),
            stub_crate(
                "Rust.Async_stripe_client_core",
                "async_stripe_client_core",
                &[(
                    "Client",
                    "::stripe_client_core::Client",
                    Some("stripe_client_core::client::Client"),
                )],
                ("stripe_client_core", "1.0.0-rc.6"),
            ),
        ];
        let unify = crate::unify::unify_foreign_nominals(&mut catalog);
        assert!(
            catalog
                .first()
                .is_some_and(|c| !c.opaque_types.contains_key("Client")),
            "{unify:?}"
        );
        let spec = validated_in(
            &["Client", "Result Error Int"],
            "async_stripe::from_client",
            &catalog,
            &unify,
            &LocalTypeNames::default(),
        )
        .expect("a demoted re-export resolves through its unify edge");
        assert!(
            matches!(spec.sig.params.first(), Some(AssertedCarrier::Opaque(_))),
            "{spec:?}"
        );
        let Some(AssertedCarrier::Opaque(client)) = spec.sig.params.first() else {
            return;
        };
        assert_eq!(client.home(), "Rust.Async_stripe_client_core");
        assert_eq!(client.rust_path(), "::stripe_client_core::Client");
        let iface = render_asserted_interface(std::slice::from_ref(&spec), &[]);
        assert!(
            iface.contains("\nimport Rust.Async_stripe_client_core\n"),
            "{iface}"
        );
        assert!(
            iface.contains(": Rust.Async_stripe_client_core.Client -> Result Error Int\n"),
            "{iface}"
        );
    }

    #[test]
    fn define_type_is_imported_from_its_home() {
        let mut semver = semver_crate();
        semver.define_types.insert("Counter".to_owned());
        let spec = validated_in(
            &["Counter", "Result Error Int"],
            "semver::not_inspected",
            &[semver],
            &UnifyReport::default(),
            &LocalTypeNames::default(),
        )
        .expect("a define type is a carrier");
        assert_eq!(
            spec.param_rust,
            vec!["crate::ffi::semver::Counter".to_owned()]
        );
        let iface = render_asserted_interface(std::slice::from_ref(&spec), &[]);
        assert!(iface.contains("\nimport Rust.Semver\n"), "{iface}");
        assert!(
            iface.contains(": Rust.Semver.Counter -> Result Error Int\n"),
            "{iface}"
        );
    }

    #[test]
    fn same_named_opaques_render_qualified() {
        let catalog = [
            stub_crate(
                "Rust.Reqwest",
                "reqwest",
                &[("Client", "::reqwest::Client", Some("reqwest::Client"))],
                ("reqwest", "0.12.0"),
            ),
            stub_crate(
                "Rust.Redis",
                "redis",
                &[("Client", "::redis::Client", Some("redis::Client"))],
                ("redis", "0.27.0"),
            ),
        ];
        let unify = UnifyReport::default();
        let locals = LocalTypeNames::default();
        let http = validated_in(
            &["Client", "Result Error Int"],
            "reqwest::status",
            &catalog,
            &unify,
            &locals,
        )
        .expect("validates");
        let cache = validated_in(
            &["Client", "Result Error Int"],
            "redis::ping",
            &catalog,
            &unify,
            &locals,
        )
        .expect("validates");
        let iface = render_asserted_interface(&[http, cache], &[]);
        assert!(iface.contains("\nimport Rust.Reqwest\n"), "{iface}");
        assert!(iface.contains("\nimport Rust.Redis\n"), "{iface}");
        assert!(iface.contains(": Rust.Reqwest.Client -> "), "{iface}");
        assert!(iface.contains(": Rust.Redis.Client -> "), "{iface}");
        assert!(!iface.contains("exposing (Client)"), "{iface}");
        assert!(!iface.contains(": Client -> "), "{iface}");
    }

    #[test]
    fn exact_match_compares_full_path() {
        let fact = |param: &str| crate::driver::InspectedFnFact {
            signature: InspectedSig::Declared {
                params: vec![param.to_owned()],
                result: Some("i64".to_owned()),
            },
            effect: Effect::Pure,
        };
        let check = |param: &str| {
            let mut semver = semver_crate();
            semver
                .inspected_free_fns
                .insert("takes_version".to_owned(), fact(param));
            validated_in(
                &["Version", "Result Error Int"],
                "semver::takes_version",
                &[semver],
                &UnifyReport::default(),
                &LocalTypeNames::default(),
            )
        };
        // Same last segment, different type: refused.
        let defect = refused_with(check("other::Version"));
        assert!(
            matches!(defect, Some(AssertedDefect::InspectedMismatch { .. })),
            "{defect:?}"
        );
        // The inspected full path is the carrier's own full path.
        assert!(check("semver::Version").is_ok());
        assert!(check("::semver::Version").is_ok());
    }

    #[test]
    fn a_bare_inspected_opaque_spelling_is_refused() {
        // The inspector qualifies every nameable foreign type, so a bare
        // spelling names no identity — even one that resolves to the carrier's
        // own nominal through the crate's maps. A recorded opaque path that is
        // itself one bare segment (`::Version`) must not make it match either.
        for recorded in [None, Some("Version")] {
            let mut semver = semver_crate();
            if let Some(path) = recorded {
                semver
                    .opaque_types
                    .insert("Version".to_owned(), path.to_owned());
            }
            semver.inspected_free_fns.insert(
                "takes_version".to_owned(),
                crate::driver::InspectedFnFact {
                    signature: InspectedSig::Declared {
                        params: vec!["Version".to_owned()],
                        result: Some("i64".to_owned()),
                    },
                    effect: Effect::Pure,
                },
            );
            let defect = refused_with(validated_in(
                &["Version", "Result Error Int"],
                "semver::takes_version",
                &[semver],
                &UnifyReport::default(),
                &LocalTypeNames::default(),
            ));
            assert!(
                matches!(defect, Some(AssertedDefect::InspectedMismatch { .. })),
                "recorded {recorded:?}: {defect:?}"
            );
        }
    }

    /// An installed crate whose inspection has the inspector's own shape:
    /// `type` holds the Ipê view, `rustType` the declared Rust type.
    fn inspector_shaped_crate(slug: &str, functions: &serde_json::Value) -> InstalledCrate {
        let doc = serde_json::json!({
            "pkg": slug, "name": slug, "version": "0.1.0",
            "functions": functions,
            "errors": [],
            "transitiveDeps": [{"ident": slug, "name": slug, "version": "0.1.0"}]
        })
        .to_string();
        let pkg = PkgInfo::decode_json(&doc).expect("decodes");
        crate::driver::installed_crate_from_pkg(
            slug.to_owned(),
            &pkg,
            &crate::driver::FfiCache::at_project_root(std::path::Path::new(".")),
        )
        .expect("installs")
    }

    fn ta_fn(name: &str, param: (&str, &str), result: (&str, &str)) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "params": [{"name": "x", "type": param.0, "ipeType": param.0, "rustType": param.1}],
            "results": [{"name": "", "type": result.0, "rustType": result.1}],
            "effect": "pure"
        })
    }

    fn validated_ta(sig_names: &[&str], path: &str) -> Result<AssertedSpec, AssertedRefusal> {
        let ta = inspector_shaped_crate(
            "ta",
            &serde_json::json!([
                ta_fn("open_client", ("Int", "i64"), ("Client", "ta::Client")),
                ta_fn("narrow", ("Int", "u32"), ("Int", "i64")),
                ta_fn(
                    "borrow_client",
                    ("Client", "&ta::Client"),
                    ("Client", "ta::Client")
                ),
                ta_fn("own_client", ("Client", "ta::Client"), ("Int", "i64")),
            ]),
        );
        validated_in(
            sig_names,
            path,
            &[ta],
            &UnifyReport::default(),
            &LocalTypeNames::default(),
        )
    }

    #[test]
    fn the_inspected_fact_is_the_declared_rust_type_not_the_ipe_view() {
        let spec = validated_ta(&["Int", "Result Error Client"], "ta::open_client")
            .expect("`Int -> Client` over `fn(i64) -> ta::Client` validates");
        assert_eq!(spec.param_rust, vec!["i64".to_owned()]);
        assert!(validated_ta(&["Client", "Result Error Int"], "ta::own_client").is_ok());
    }

    #[test]
    fn an_undeclared_rust_type_is_refused_not_read_from_the_ipe_view() {
        // The inspector omits `rustType` for a type it cannot render while the
        // Ipê view still reads `String`; the fact must not fall back to it.
        let ta = inspector_shaped_crate(
            "ta",
            &serde_json::json!([
                {
                    "name": "takes_callback",
                    "params": [{"name": "cb", "type": "String", "ipeType": "String"}],
                    "results": [{"name": "", "type": "Int", "rustType": "i64"}],
                    "effect": "pure"
                },
                {
                    "name": "yields_callback",
                    "params": [{"name": "n", "type": "Int", "ipeType": "Int", "rustType": "i64"}],
                    "results": [{"name": "", "type": "String"}],
                    "effect": "pure"
                }
            ]),
        );
        assert_eq!(
            ta.inspected_free_fns
                .get("takes_callback")
                .map(|fact| &fact.signature),
            Some(&InspectedSig::Undeclared)
        );
        for (sig, path) in [
            (["String", "Result Error Int"], "ta::takes_callback"),
            (["Int", "Result Error String"], "ta::yields_callback"),
        ] {
            let defect = refused_with(validated_in(
                &sig,
                path,
                std::slice::from_ref(&ta),
                &UnifyReport::default(),
                &LocalTypeNames::default(),
            ));
            assert_eq!(
                defect,
                Some(AssertedDefect::InspectedShapeUnsupported {
                    reason: InspectedShapeReason::UndeclaredRustType,
                }),
                "{path}"
            );
        }
    }

    #[test]
    fn a_submodule_function_is_not_the_top_level_fact() {
        // `ta::util::parse_num(u32)` must not stand in for `ta::parse_num`: the
        // asserted top-level path is left to the shim's rustc check.
        let mut nested = ta_fn("parse_num", ("Int", "u32"), ("Int", "i64"));
        if let Some(obj) = nested.as_object_mut() {
            obj.insert("callPath".to_owned(), serde_json::json!("util::parse_num"));
        }
        let ta = inspector_shaped_crate("ta", &serde_json::json!([nested]));
        assert_eq!(ta.inspected_free_fns.get("parse_num"), None);
        assert!(
            validated_in(
                &["Int", "Result Error Int"],
                "ta::parse_num",
                std::slice::from_ref(&ta),
                &UnifyReport::default(),
                &LocalTypeNames::default(),
            )
            .is_ok()
        );
    }

    #[test]
    fn an_ipe_view_match_over_a_different_rust_type_is_refused() {
        for (sig, path) in [
            (["Int", "Result Error Int"], "ta::narrow"),
            (["Client", "Result Error Client"], "ta::borrow_client"),
        ] {
            let defect = refused_with(validated_ta(&sig, path));
            assert!(
                matches!(defect, Some(AssertedDefect::InspectedMismatch { .. })),
                "{path}: {defect:?}"
            );
        }
    }

    #[test]
    fn a_same_named_opaque_of_another_crate_is_refused() {
        let mut ta = stub_crate(
            "Rust.Ta",
            "ta",
            &[("Client", "::ta::Client", Some("ta::Client"))],
            ("ta", "0.1.0"),
        );
        ta.inspected_free_fns.insert(
            "open_client".to_owned(),
            crate::driver::InspectedFnFact {
                signature: InspectedSig::Declared {
                    params: vec!["i64".to_owned()],
                    result: Some("tb::Client".to_owned()),
                },
                effect: Effect::Pure,
            },
        );
        let tb = stub_crate(
            "Rust.Tb",
            "tb",
            &[("Client", "::tb::Client", Some("tb::Client"))],
            ("tb", "0.1.0"),
        );
        let defect = refused_with(validated_in(
            &["Int", "Result Error Client"],
            "ta::open_client",
            &[ta, tb],
            &UnifyReport::default(),
            &LocalTypeNames::default(),
        ));
        assert!(
            matches!(defect, Some(AssertedDefect::InspectedMismatch { .. })),
            "{defect:?}"
        );
    }

    #[test]
    fn dedupe_distinguishes_homes() {
        let a = validated(&["Version", "Result Error Int"], "semver::not_inspected")
            .expect("validates");
        let mut b = a.clone();
        b.sig.params = vec![AssertedCarrier::Opaque(OpaqueRef {
            home: "Rust.Other".to_owned(),
            nominal: "Version".to_owned(),
            rust_path: "::semver::Version".to_owned(),
        })];
        let err = dedupe(vec![a, b]).expect_err("two homes are two signatures");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::ConflictingAssertions { .. },
                    ..
                }
            ),
            "{err}"
        );
    }

    fn locals(entries: &[(&str, LocalTypeKind)]) -> LocalTypeNames {
        entries
            .iter()
            .map(|(name, kind)| ((*name).to_owned(), *kind))
            .collect()
    }

    #[test]
    fn local_alias_is_refused_with_alias_defect() {
        let names = locals(&[
            ("Count", LocalTypeKind::Alias),
            ("Str", LocalTypeKind::Alias),
        ]);
        for (sig, ty) in [
            (["Count", "Result Error Int"], "Count"),
            (["Int", "Result Error Str"], "Str"),
        ] {
            let defect = refused_with(validated_in(
                &sig,
                "semver::not_inspected",
                &[semver_crate()],
                &UnifyReport::default(),
                &names,
            ));
            assert!(
                matches!(
                    &defect,
                    Some(AssertedDefect::LocalTypeNotACarrier { ty: got, alias: true }) if got == ty
                ),
                "{defect:?}"
            );
        }
        let mut interner = Interner::new();
        let ann = ann_leaf(&mut interner, "Count");
        let catalog = [semver_crate()];
        let unify = UnifyReport::default();
        let err = validate_const(
            test_site(),
            AssertedPath::parse("semver::MAX_MINOR").expect("path parses"),
            &ann,
            &interner,
            &CarrierScope::new(&catalog, &unify, &names),
        )
        .expect_err("a local alias is no constant carrier");
        assert!(
            matches!(
                &err,
                AssertedRefusal {
                    defect: AssertedDefect::LocalTypeNotACarrier { alias: true, .. },
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn local_nominal_shadowing_crate_opaque_is_refused() {
        let names = locals(&[("Version", LocalTypeKind::Union)]);
        let catalog = [semver_crate()];
        let unify = UnifyReport::default();
        let defect = refused_with(validated_in(
            &["Version", "Result Error Int"],
            "semver::not_inspected",
            &catalog,
            &unify,
            &names,
        ));
        assert!(
            matches!(
                &defect,
                Some(AssertedDefect::LocalTypeNotACarrier { ty, alias: false }) if ty == "Version"
            ),
            "{defect:?}"
        );
        // A qualified spelling never names the caller's own declaration.
        let spec = validated_in(
            &["Rust.Semver.Version", "Result Error Int"],
            "semver::not_inspected",
            &catalog,
            &unify,
            &names,
        )
        .expect("the qualified crate opaque resolves");
        assert_eq!(spec.param_rust, vec!["::semver::Version".to_owned()]);
    }

    #[test]
    fn interner_miss_is_compiler_bug() {
        let mut interner = Interner::new();
        let result = ann_leaf(&mut interner, "Result Error Int");
        let empty = intern(&mut interner, "");
        let mut other = Interner::new();
        for i in 0..4096 {
            intern(&mut other, &format!("pad{i}"));
        }
        let ghost = intern(&mut other, "Ghost");
        assert!(interner.resolve(ghost).is_none());
        let catalog = [semver_crate()];
        let unify = UnifyReport::default();
        let names = LocalTypeNames::default();
        let scope = CarrierScope::new(&catalog, &unify, &names);
        for (param, bug) in [
            (
                TypeAnnotation::TType(empty, vec![ghost], vec![]),
                AssertedCompilerBug::TypeNameNotInterned,
            ),
            (
                TypeAnnotation::TType(empty, vec![], vec![]),
                AssertedCompilerBug::EmptyTypeName,
            ),
        ] {
            let ann = TypeAnnotation::TLambda(Box::new(param), Box::new(result.clone()));
            let err = validate(
                test_site(),
                AssertedPath::parse("semver::not_inspected").expect("path parses"),
                &ann,
                &interner,
                &scope,
            )
            .expect_err("an interner miss is never an empty name");
            assert!(
                matches!(
                    &err,
                    AssertedRefusal {
                        defect: AssertedDefect::CompilerBug(got),
                        ..
                    } if *got == bug
                ),
                "{err}"
            );
        }
    }

    #[test]
    fn only_reserved_rows_are_claimed_by_the_builtin_table() {
        for (name, scalar) in [
            ("Int", ScalarCarrier::Int),
            ("Float", ScalarCarrier::Float),
            ("Bool", ScalarCarrier::Bool),
            ("Char", ScalarCarrier::Char),
            ("String", ScalarCarrier::Str),
            ("Bytes", ScalarCarrier::Bytes),
        ] {
            assert_eq!(reserved_head(name), Some(Head::Scalar(scalar)), "{name}");
        }
        assert_eq!(reserved_head("Result"), Some(Head::Result));
        assert_eq!(reserved_head("Error"), Some(Head::Error));
        for wire in ["Str", "i64", "f64", "bool", "char", "Version"] {
            assert_eq!(reserved_head(wire), None, "{wire}");
        }
        // Every reserved row is classified; only the six scalars, `Result` and
        // `Error` are anything but a non-carrier.
        for row in ipe_kernels::BUILTIN_TYPES {
            if !row.role().forbids_user_declaration() {
                continue;
            }
            let head = row.tag().map_or(Head::NonCarrierBuiltin, tag_head);
            assert!(
                matches!(head, Head::NonCarrierBuiltin)
                    || matches!(
                        row.tag(),
                        Some(
                            BuiltinTag::Int
                                | BuiltinTag::Float
                                | BuiltinTag::Bool
                                | BuiltinTag::Char
                                | BuiltinTag::String
                                | BuiltinTag::Bytes
                                | BuiltinTag::Result
                                | BuiltinTag::Error
                        )
                    ),
                "{head:?}"
            );
        }
    }
}
