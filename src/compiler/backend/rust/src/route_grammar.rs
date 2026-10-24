//! The route grammar the runtime enforces at startup, applied to literal paths
//! at `ipe` time.
//!
//! `Web.route` patterns are parsed by the runtime's `RoutePattern::parse` and
//! `Server.*` paths by its `ServerPattern::parse`; a malformed literal would pass
//! `ipe` and then refuse to start. The compiler cannot depend on the runtime,
//! so this module restates the same grammar, and `agreement_tests` drives one
//! case table through both sides and asserts identical verdicts.
//!
//! - A parameter name is `[A-Za-z_][A-Za-z0-9_]*`, distinct within one path.
//! - A `Web.route` pattern is split on raw `/` after trimming surrounding `/`,
//!   and each segment follows one grammar: a segment led by `*` (a catch-all)
//!   is refused, a segment led by `:` is a parameter, and any other segment
//!   holds no `:` or `*` and must strictly percent-decode (`%` + two hex
//!   digits, UTF-8 result, `+` literal).
//! - A `Server.*` path starts with `/` and is split and its segments read like
//!   a `Web.route` pattern's. It holds at most `MAX_SERVER_PARAMS` parameters,
//!   and its router spelling (each literal re-escaped by the runtime's one
//!   segment alphabet, each parameter `:p` and its ordinal) is within the
//!   length ceiling.
//! - A `Server.api` spec's method, when it names one, is a method the
//!   runtime's own `EndpointMethod::parse` admits.
//! - A `Server.static` or `Server.mountApp` prefix is a string literal parsed
//!   by the runtime's own `MountBase::parse`, and no two mounts of one literal
//!   `Server.listen` list share a prefix.

use std::collections::HashSet;

use ipe_diagnostics::terminal::is_display_hazard;
use ipe_diagnostics::{
    DResult, Diagnostic, LowerError, MountPrefixFault, RoutePatternDefect, Span,
};
use ipe_ir::{Callee, Expr, KernelFn, Program};
use ipe_runtime_rust::encoding::{EndpointMethod, MAX_MOUNT_BASE_LEN, MountBase, MountBaseRefusal};

/// The runtime's `MAX_URL_COMPONENT_LEN`: the longest pattern it parses.
pub const MAX_PATH_LEN: usize = 32 * 1024 * 1024;

/// The runtime's `MAX_SERVER_PARAMS`: the most parameters a `Server.*` path
/// holds.
pub const MAX_SERVER_PARAMS: usize = 25;

/// How many characters of an offending name or segment a diagnostic quotes.
const EXCERPT_CHARS: usize = 64;

/// A bounded, visibly escaped quote of `raw` for a diagnostic: control and
/// format characters are escaped, and text past [`EXCERPT_CHARS`] is elided.
pub fn excerpt(raw: &str) -> Box<str> {
    let mut out = String::new();
    let mut chars = raw.chars();
    for c in chars.by_ref().take(EXCERPT_CHARS) {
        if is_display_hazard(c) {
            out.extend(c.escape_debug());
        } else {
            out.push(c);
        }
    }
    if chars.next().is_some() {
        out.push('…');
    }
    out.into_boxed_str()
}

/// The parameter names one path has admitted so far.
#[derive(Default)]
struct Names<'a>(HashSet<&'a str>);

impl<'a> Names<'a> {
    /// Admit `raw` (the text after the sigil) as a new identifier name.
    fn admit(&mut self, raw: &'a str) -> Result<(), RoutePatternDefect> {
        let bytes = raw.as_bytes();
        let Some(&first) = bytes.first() else {
            return Err(RoutePatternDefect::ParamEmpty);
        };
        let bad = if first.is_ascii_alphabetic() || first == b'_' {
            bytes
                .iter()
                .position(|&b| !(b.is_ascii_alphanumeric() || b == b'_'))
        } else {
            Some(0)
        };
        if let Some(at) = bad {
            return Err(RoutePatternDefect::ParamNotIdentifier {
                name: excerpt(raw),
                at,
            });
        }
        if self.0.insert(raw) {
            Ok(())
        } else {
            Err(RoutePatternDefect::ParamDuplicate { name: excerpt(raw) })
        }
    }
}

/// The value of one ASCII hex digit, or `None` for any other byte.
const fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Strictly percent-decode one literal path segment (`+` stays literal).
fn literal_segment(raw: &str) -> Result<String, RoutePatternDefect> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c == b'%' {
            let hi = bytes.get(i + 1).copied().and_then(hex_value);
            let lo = bytes.get(i + 2).copied().and_then(hex_value);
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(RoutePatternDefect::MalformedEscape {
                    segment: excerpt(raw),
                    at: i,
                });
            };
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    match String::from_utf8(out) {
        Ok(decoded) => Ok(decoded),
        Err(e) => Err(RoutePatternDefect::InvalidUtf8 {
            segment: excerpt(raw),
            at: raw_offset_of(bytes, e.utf8_error().valid_up_to()),
        }),
    }
}

/// The raw offset that produced decoded byte number `decoded`. Called only
/// after every escape was accepted, so each `%` starts three raw bytes.
fn raw_offset_of(raw: &[u8], decoded: usize) -> usize {
    let mut i = 0;
    let mut produced = 0;
    while let Some(&c) = raw.get(i) {
        if produced == decoded {
            break;
        }
        i += if c == b'%' { 3 } else { 1 };
        produced += 1;
    }
    i
}

/// Check a literal `Web.route` pattern against the runtime's `RoutePattern`
/// grammar.
///
/// # Errors
///
/// The defect of the first malformed segment, or `TooLong` for a pattern over
/// [`MAX_PATH_LEN`] bytes.
pub fn web_route_pattern(pattern: &str) -> Result<(), RoutePatternDefect> {
    web_route_segments(pattern).map(drop)
}

/// One segment of a `Web.route` pattern, as the runtime matches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentShape {
    /// A `:name` parameter: matches any one segment its field type parses.
    Param,
    /// A literal segment, held percent-decoded.
    Literal(String),
}

/// Split a literal `Web.route` pattern into the segments the runtime matches.
/// A root pattern (`/`, or empty) has no segments.
///
/// # Errors
///
/// As [`web_route_pattern`].
pub fn web_route_segments(pattern: &str) -> Result<Vec<SegmentShape>, RoutePatternDefect> {
    if pattern.len() > MAX_PATH_LEN {
        return Err(RoutePatternDefect::TooLong { cap: MAX_PATH_LEN });
    }
    let trimmed = pattern.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut names = Names::default();
    trimmed
        .split('/')
        .map(|raw| route_segment(raw, &mut names))
        .collect()
}

/// Read one raw segment of a route pattern or path, the grammar the
/// runtime's route segment parser applies to both.
///
/// # Errors
///
/// `CatchAll` for a segment led by `*`, the name defect of a segment led by
/// `:`, `MidSegmentSigil` for a `:` or `*` later in a literal, then the
/// literal's decode defect.
fn route_segment<'a>(
    raw: &'a str,
    names: &mut Names<'a>,
) -> Result<SegmentShape, RoutePatternDefect> {
    if raw.starts_with('*') {
        return Err(RoutePatternDefect::CatchAll {
            segment: excerpt(raw),
        });
    }
    if let Some(name) = raw.strip_prefix(':') {
        return names.admit(name).map(|()| SegmentShape::Param);
    }
    if let Some(at) = raw.find([':', '*']) {
        return Err(RoutePatternDefect::MidSegmentSigil {
            segment: excerpt(raw),
            at,
        });
    }
    literal_segment(raw).map(SegmentShape::Literal)
}

/// Check a literal `Server.*` route path against the runtime's
/// `ServerPattern` grammar.
///
/// # Errors
///
/// `TooLong` for a path over [`MAX_PATH_LEN`] bytes, `NotAbsolute` for one
/// without a leading `/`, then the defect of the first malformed segment, then
/// `TooManyParams` past [`MAX_SERVER_PARAMS`] parameters, then `TooLong` when
/// the router spelling (each parameter `:p` and its ordinal) would pass the
/// ceiling.
pub fn server_route_path(path: &str) -> Result<(), RoutePatternDefect> {
    if path.len() > MAX_PATH_LEN {
        return Err(RoutePatternDefect::TooLong { cap: MAX_PATH_LEN });
    }
    if !path.starts_with('/') {
        return Err(RoutePatternDefect::NotAbsolute);
    }
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(());
    }
    let mut names = Names::default();
    let mut spelled: usize = 0;
    let mut params: usize = 0;
    for raw in trimmed.split('/') {
        let seg_len = match route_segment(raw, &mut names)? {
            SegmentShape::Param => {
                // `:p` and the ordinal; a path past `MAX_SERVER_PARAMS` (two
                // digits at most) is refused before its spelling is measured.
                let spelled_param = if params < 10 { 3 } else { 4 };
                params = params.saturating_add(1);
                spelled_param
            }
            SegmentShape::Literal(decoded) => canonical_len(&decoded),
        };
        spelled = spelled.saturating_add(1).saturating_add(seg_len);
    }
    if params > MAX_SERVER_PARAMS {
        return Err(RoutePatternDefect::TooManyParams {
            cap: MAX_SERVER_PARAMS,
        });
    }
    if path.len() > 1 && path.ends_with('/') {
        spelled = spelled.saturating_add(1);
    }
    if spelled > MAX_PATH_LEN {
        return Err(RoutePatternDefect::TooLong { cap: MAX_PATH_LEN });
    }
    Ok(())
}

/// The length of the runtime's canonical spelling of one decoded segment:
/// `.` and `..` spell as `%2E` and `%2E%2E`; an ASCII alphanumeric or one of
/// `-` `_` `.` `~` stays one byte; every other byte is a three-byte escape.
fn canonical_len(decoded: &str) -> usize {
    match decoded {
        "." => 3,
        ".." => 6,
        _ => decoded
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                    1
                } else {
                    3
                }
            })
            .sum(),
    }
}

/// The path part of a literal `Server.api` spec (`"METHOD /path"`, or a bare
/// path matching any verb), split exactly as the runtime's `server_api` does.
#[must_use]
pub fn server_api_path(spec: &str) -> &str {
    match spec.split_once(' ') {
        Some((method, path)) if !method.is_empty() => path.trim(),
        _ => spec.trim(),
    }
}

/// The method of a literal `Server.api` spec, split as [`server_api_path`]
/// splits it; `None` for a spec that names no method (every method).
#[must_use]
pub fn server_api_method(spec: &str) -> Option<&str> {
    match spec.split_once(' ') {
        Some((method, _)) if !method.is_empty() => Some(method.trim()),
        _ => None,
    }
}

/// Check a literal `Server.api` spec: its method against the runtime's own
/// method grammar, then its path as a `Server.*` route path.
///
/// # Errors
///
/// `UnknownMethod` for a method the server does not serve, else the defect
/// of [`server_route_path`].
pub fn server_api_spec(spec: &str) -> Result<(), RoutePatternDefect> {
    if let Some(method) = server_api_method(spec)
        && EndpointMethod::parse(method).is_none()
    {
        return Err(RoutePatternDefect::UnknownMethod {
            method: excerpt(method),
        });
    }
    server_route_path(server_api_path(spec))
}

/// Turn a grammar verdict for a literal path passed to `call` into the
/// IPE-L0156 refusal.
///
/// # Errors
///
/// `LowerError::RoutePatternMalformed` carrying the defect.
pub fn refuse_malformed(call: &str, verdict: Result<(), RoutePatternDefect>) -> DResult<()> {
    verdict.map_err(|defect| Diagnostic::Lower {
        span: Span::DUMMY,
        msg: LowerError::RoutePatternMalformed {
            call: call.into(),
            defect,
        },
    })
}

/// The mount-base rule `refusal` names.
const fn mount_fault(refusal: &MountBaseRefusal) -> MountPrefixFault {
    match refusal {
        MountBaseRefusal::TooLong { .. } => MountPrefixFault::TooLong {
            cap: MAX_MOUNT_BASE_LEN,
        },
        MountBaseRefusal::NoLeadingSlash => MountPrefixFault::NotAbsolute,
        MountBaseRefusal::TrailingSlash => MountPrefixFault::TrailingSlash,
        MountBaseRefusal::EmptySegment => MountPrefixFault::EmptySegment,
        MountBaseRefusal::DotSegment => MountPrefixFault::DotSegment,
        MountBaseRefusal::Reserved { byte } => MountPrefixFault::Reserved { byte: *byte },
    }
}

/// Parse a literal `Server.static` or `Server.mountApp` prefix with the
/// runtime's mount-base parser.
///
/// # Errors
///
/// `MountPrefix` naming the rule the prefix breaks.
pub fn mount_prefix(prefix: &str) -> Result<MountBase, RoutePatternDefect> {
    MountBase::parse(prefix).map_err(|refusal| RoutePatternDefect::MountPrefix {
        prefix: excerpt(prefix),
        fault: mount_fault(&refusal),
    })
}

/// Refuse a literal `Server.listen` route list in which two mounts serve one
/// prefix.
fn refuse_duplicate_mounts(routes: &[Expr]) -> DResult<()> {
    let mut seen: HashSet<MountBase> = HashSet::new();
    for route in routes {
        if let Expr::Call {
            callee: Callee::Kernel(k),
            args,
            ..
        } = route
            && matches!(route_path_of(*k), Some(RoutePath::Mount))
            && let Some(Expr::Str(lit)) = args.first()
            && let Ok(base) = MountBase::parse(lit)
            && !seen.insert(base)
        {
            return refuse_malformed(
                "Server.listen",
                Err(RoutePatternDefect::MountPrefixDuplicate {
                    prefix: excerpt(lit),
                }),
            );
        }
    }
    Ok(())
}

/// The grammar a route kernel holds its first (path) argument to.
#[derive(Clone, Copy)]
enum RoutePath {
    /// A `Web.route` pattern.
    Web,
    /// A `Server.*` route path.
    Server,
    /// A `Server.api` spec, whose path follows an optional method.
    ServerApi,
    /// A `Server.static` or `Server.mountApp` prefix: a literal mount base.
    Mount,
}

/// The path grammar of `k`'s first argument, or `None` for a kernel that
/// takes no route path.
const fn route_path_of(k: KernelFn) -> Option<RoutePath> {
    match k {
        KernelFn::WebRoute => Some(RoutePath::Web),
        KernelFn::ServerApi => Some(RoutePath::ServerApi),
        KernelFn::ServerGet
        | KernelFn::ServerPost
        | KernelFn::ServerPut
        | KernelFn::ServerDelete
        | KernelFn::ServerAny
        | KernelFn::ServerGetAuthed
        | KernelFn::ServerPostAuthed
        | KernelFn::ServerPutAuthed
        | KernelFn::ServerDeleteAuthed => Some(RoutePath::Server),
        KernelFn::ServerStatic | KernelFn::ServerMountApp => Some(RoutePath::Mount),
        _ => None,
    }
}

/// Hold one literal path passed to route kernel `k` to its grammar.
fn refuse_literal(k: KernelFn, grammar: RoutePath, lit: &str) -> DResult<()> {
    let d = k.decl();
    let call = format!("{}.{}", d.qualifier, d.name);
    let verdict = match grammar {
        RoutePath::Web => web_route_pattern(lit),
        RoutePath::Server => server_route_path(lit),
        RoutePath::ServerApi => server_api_spec(lit),
        RoutePath::Mount => mount_prefix(lit).map(drop),
    };
    refuse_malformed(&call, verdict)
}

/// Refuse mount kernel `k` reached with a prefix that is not a string literal.
fn refuse_unliteral_mount(k: KernelFn) -> DResult<()> {
    let d = k.decl();
    refuse_malformed(
        &format!("{}.{}", d.qualifier, d.name),
        Err(RoutePatternDefect::MountPrefixNotLiteral),
    )
}

/// Refuse every malformed literal route path anywhere in `program`.
///
/// The check walks the whole lowered program rather than riding on route
/// emission, so a route the emitted app never serves (an unrouted `Web.tea`
/// whose `routes` list is dropped, an unreachable helper) is refused the same
/// as one that is served.
///
/// # Errors
///
/// IPE-L0156 for the first malformed literal path.
pub fn refuse_malformed_literals(program: &Program) -> DResult<()> {
    program
        .modules
        .iter()
        .flat_map(|module| &module.funcs)
        .try_for_each(|func| literal_routes(&func.body))
}

/// Refuse every malformed literal route path inside `expr`.
fn literal_routes(expr: &Expr) -> DResult<()> {
    match expr {
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_) => Ok(()),
        Expr::FuncValue { callee, .. } => match callee {
            Callee::Kernel(k) if matches!(route_path_of(*k), Some(RoutePath::Mount)) => {
                refuse_unliteral_mount(*k)
            }
            _ => Ok(()),
        },
        Expr::Call { callee, args, .. } => {
            if let Callee::Kernel(k) = callee
                && let Some(grammar) = route_path_of(*k)
            {
                match (grammar, args.first()) {
                    (_, Some(Expr::Str(lit))) => refuse_literal(*k, grammar, lit.as_str())?,
                    (RoutePath::Mount, _) => refuse_unliteral_mount(*k)?,
                    (RoutePath::Web | RoutePath::Server | RoutePath::ServerApi, _) => {}
                }
            }
            if matches!(callee, Callee::Kernel(KernelFn::ServerListen))
                && let Some(Expr::List { items, .. }) = args.get(1)
            {
                refuse_duplicate_mounts(items)?;
            }
            args.iter().try_for_each(literal_routes)
        }
        Expr::Ctor { args, .. } | Expr::TailRecur { args } => {
            args.iter().try_for_each(literal_routes)
        }
        Expr::BinOp { lhs, rhs, .. } => {
            literal_routes(lhs)?;
            literal_routes(rhs)
        }
        Expr::Let { value, body, .. } | Expr::Destructure { value, body, .. } => {
            literal_routes(value)?;
            literal_routes(body)
        }
        Expr::If { cond, then_, else_ } => {
            literal_routes(cond)?;
            literal_routes(then_)?;
            literal_routes(else_)
        }
        Expr::Match(m) => {
            literal_routes(m.scrutinee())?;
            m.arms().iter().try_for_each(|arm| {
                if let Some(guard) = &arm.guard {
                    literal_routes(guard)?;
                }
                literal_routes(&arm.body)
            })
        }
        Expr::Tuple(items) | Expr::List { items, .. } => items.iter().try_for_each(literal_routes),
        Expr::Cons { head, tail } => {
            literal_routes(head)?;
            literal_routes(tail)
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => literal_routes(list),
        Expr::Record { fields, .. } => fields.iter().try_for_each(|(_, e)| literal_routes(e)),
        Expr::Access { record, .. } => literal_routes(record),
        Expr::Update { record, fields } => {
            literal_routes(record)?;
            fields.iter().try_for_each(|(_, e)| literal_routes(e))
        }
        Expr::Lambda { body, .. }
        | Expr::SharedLambda { body, .. }
        | Expr::OnceLambda { body, .. }
        | Expr::TailLoop { body, .. } => literal_routes(body),
        Expr::Apply { func, args } => {
            literal_routes(func)?;
            args.iter().try_for_each(literal_routes)
        }
        Expr::TaskSeq { effect, rest } => {
            literal_routes(effect)?;
            literal_routes(rest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PATH_LEN, MAX_SERVER_PARAMS, RoutePatternDefect, excerpt, server_api_path,
        server_api_spec, server_route_path, web_route_pattern,
    };

    /// Prove the refusal: a `Server.api` method the server does not serve is
    /// refused at compile time, as the server refuses it at listen.
    #[test]
    fn a_server_api_spec_with_an_unknown_method_is_refused() {
        for (spec, method) in [
            ("FETCH /x", "FETCH"),
            ("po\u{17f}t /x", "po\u{17f}t"),
            ("G-ET /x", "G-ET"),
        ] {
            assert_eq!(
                server_api_spec(spec),
                Err(RoutePatternDefect::UnknownMethod {
                    method: excerpt(method)
                }),
                "{spec:?}"
            );
        }
        for spec in [
            "GET /x",
            "GET\t /x",
            "patch /x",
            "Any /x",
            "/x",
            " /x",
            "TRACE  /a/:id",
        ] {
            assert_eq!(server_api_spec(spec), Ok(()), "{spec:?}");
        }
    }

    #[test]
    fn web_patterns_the_runtime_serves_are_accepted() {
        for ok in [
            "/",
            "",
            "/posts/:id/:slug",
            "/a+b",
            "/caf%C3%A9",
            "/_x/:_y1",
            "//a//",
        ] {
            assert_eq!(web_route_pattern(ok), Ok(()), "{ok:?}");
        }
    }

    #[test]
    fn web_pattern_non_identifier_name_is_refused_at_the_bad_byte() {
        assert_eq!(
            web_route_pattern("/:post-id"),
            Err(RoutePatternDefect::ParamNotIdentifier {
                name: "post-id".into(),
                at: 4
            })
        );
        assert_eq!(
            web_route_pattern("/:1st"),
            Err(RoutePatternDefect::ParamNotIdentifier {
                name: "1st".into(),
                at: 0
            })
        );
    }

    #[test]
    fn web_pattern_repeated_name_is_refused() {
        assert_eq!(
            web_route_pattern("/:id/:id"),
            Err(RoutePatternDefect::ParamDuplicate { name: "id".into() })
        );
    }

    #[test]
    fn web_pattern_empty_name_is_refused() {
        assert_eq!(web_route_pattern("/:"), Err(RoutePatternDefect::ParamEmpty));
        assert_eq!(
            web_route_pattern("/a/:/b"),
            Err(RoutePatternDefect::ParamEmpty)
        );
    }

    #[test]
    fn web_pattern_literal_must_strictly_decode() {
        assert_eq!(
            web_route_pattern("/a%zz"),
            Err(RoutePatternDefect::MalformedEscape {
                segment: "a%zz".into(),
                at: 1
            })
        );
        assert_eq!(
            web_route_pattern("/x/%4"),
            Err(RoutePatternDefect::MalformedEscape {
                segment: "%4".into(),
                at: 0
            })
        );
        assert_eq!(
            web_route_pattern("/ab%C0%AF"),
            Err(RoutePatternDefect::InvalidUtf8 {
                segment: "ab%C0%AF".into(),
                at: 2
            })
        );
    }

    #[test]
    fn web_pattern_one_past_the_ceiling_is_refused() {
        let at_cap = "a".repeat(MAX_PATH_LEN);
        assert_eq!(web_route_pattern(&at_cap), Ok(()));
        let past = "a".repeat(MAX_PATH_LEN + 1);
        assert_eq!(
            web_route_pattern(&past),
            Err(RoutePatternDefect::TooLong { cap: MAX_PATH_LEN })
        );
    }

    #[test]
    fn server_paths_the_runtime_serves_are_accepted() {
        for ok in ["/", "//", "/u/:id/f/:name", "/caf%C3%A9", "/a/%3Ax", "/a/"] {
            assert_eq!(server_route_path(ok), Ok(()), "{ok:?}");
        }
    }

    /// Prove the refusals: a catch-all, a mid-segment sigil, a relative path,
    /// a malformed escape and every malformed parameter name.
    #[test]
    fn malformed_server_paths_are_refused() {
        assert_eq!(
            server_route_path("/u/:id/f/*rest"),
            Err(RoutePatternDefect::CatchAll {
                segment: "*rest".into()
            })
        );
        assert_eq!(
            server_route_path("/f/*"),
            Err(RoutePatternDefect::CatchAll {
                segment: "*".into()
            })
        );
        assert_eq!(
            server_route_path("/v-:id"),
            Err(RoutePatternDefect::MidSegmentSigil {
                segment: "v-:id".into(),
                at: 2
            })
        );
        assert_eq!(
            server_route_path("api"),
            Err(RoutePatternDefect::NotAbsolute)
        );
        assert_eq!(server_route_path(""), Err(RoutePatternDefect::NotAbsolute));
        assert_eq!(
            server_route_path("/plain/100%zz"),
            Err(RoutePatternDefect::MalformedEscape {
                segment: "100%zz".into(),
                at: 3
            })
        );
        assert_eq!(
            server_route_path("/x/:a-b"),
            Err(RoutePatternDefect::ParamNotIdentifier {
                name: "a-b".into(),
                at: 1
            })
        );
        assert_eq!(
            server_route_path("/:id/:id"),
            Err(RoutePatternDefect::ParamDuplicate { name: "id".into() })
        );
        assert_eq!(
            server_route_path("/f/:"),
            Err(RoutePatternDefect::ParamEmpty)
        );
        let params = |n: usize| -> String {
            (0..n)
                .flat_map(|i| ["/:v".to_owned(), i.to_string()])
                .collect()
        };
        assert_eq!(server_route_path(&params(MAX_SERVER_PARAMS)), Ok(()));
        assert_eq!(
            server_route_path(&params(MAX_SERVER_PARAMS + 1)),
            Err(RoutePatternDefect::TooManyParams {
                cap: MAX_SERVER_PARAMS
            })
        );
    }

    /// A path within the parse ceiling whose router spelling grows past it is
    /// refused, as the runtime refuses it at listen.
    #[test]
    fn server_path_spelled_past_the_ceiling_is_refused() {
        let at_cap = format!("/{}", "a".repeat(MAX_PATH_LEN - 1));
        assert_eq!(server_route_path(&at_cap), Ok(()));
        let grows = format!("/{}", "+".repeat(MAX_PATH_LEN / 2));
        assert_eq!(
            server_route_path(&grows),
            Err(RoutePatternDefect::TooLong { cap: MAX_PATH_LEN })
        );
    }

    #[test]
    fn server_api_spec_splits_like_the_runtime() {
        assert_eq!(server_api_path("POST /u/:id"), "/u/:id");
        assert_eq!(server_api_path(" /u/:id "), "/u/:id");
        assert_eq!(server_api_path("/u/:id"), "/u/:id");
        assert_eq!(server_api_path("GET  /a "), "/a");
    }

    #[test]
    fn excerpt_escapes_controls_and_bounds_length() {
        assert_eq!(&*excerpt("a\u{1b}[2Jb"), "a\\u{1b}[2Jb");
        assert_eq!(&*excerpt("x\u{202e}y"), "x\\u{202e}y");
        let long = excerpt(&"n".repeat(1000));
        assert_eq!(long.chars().count(), super::EXCERPT_CHARS + 1);
    }
}

/// The whole-program walk refuses a malformed literal route wherever it sits,
/// including positions no route emission reaches.
#[cfg(test)]
mod walk_tests {
    use ipe_diagnostics::{Diagnostic, LowerError, MountPrefixFault, RoutePatternDefect};
    use ipe_ir::{CallPin, Callee, Expr, IrType, KernelFn, OnFormKind};
    use ipe_runtime_rust::encoding::MAX_MOUNT_BASE_LEN;

    use super::literal_routes;

    fn call(k: KernelFn, path: &str) -> Expr {
        Expr::Call {
            callee: Callee::Kernel(k),
            args: vec![Expr::Str(path.to_owned()), Expr::Unit],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    fn defect(expr: &Expr) -> Option<(Box<str>, RoutePatternDefect)> {
        match literal_routes(expr) {
            Err(Diagnostic::Lower {
                msg: LowerError::RoutePatternMalformed { call, defect },
                ..
            }) => Some((call, defect)),
            Ok(()) | Err(_) => None,
        }
    }

    #[test]
    fn a_route_in_an_unserved_routes_list_is_refused() {
        let routes = Expr::Tuple(vec![
            Expr::Unit,
            Expr::List {
                elem: IrType::Unit,
                items: vec![
                    call(KernelFn::WebRoute, "/"),
                    call(KernelFn::WebRoute, "/:"),
                ],
            },
        ]);
        assert_eq!(
            defect(&routes),
            Some(("Web.route".into(), RoutePatternDefect::ParamEmpty))
        );
    }

    #[test]
    fn a_server_api_path_under_a_lambda_is_refused() {
        let handler = Expr::Lambda {
            params: Vec::new(),
            ret: IrType::Unit,
            body: Box::new(call(KernelFn::ServerApi, "GET /v1/:id/:id")),
        };
        assert_eq!(
            defect(&handler),
            Some((
                "Server.api".into(),
                RoutePatternDefect::ParamDuplicate { name: "id".into() }
            ))
        );
    }

    fn listen(routes: Vec<Expr>) -> Expr {
        Expr::Call {
            callee: Callee::Kernel(KernelFn::ServerListen),
            args: vec![
                Expr::Int(8000),
                Expr::List {
                    elem: IrType::Unit,
                    items: routes,
                },
            ],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    /// Prove the refusals: a mount prefix that is not a mount base is refused
    /// with the rule it breaks.
    #[test]
    fn a_malformed_mount_prefix_is_refused() {
        for (prefix, fault) in [
            ("/a?b", MountPrefixFault::Reserved { byte: b'?' }),
            ("/a#b", MountPrefixFault::Reserved { byte: b'#' }),
            ("/a/%zz", MountPrefixFault::Reserved { byte: b'%' }),
            ("/a%62", MountPrefixFault::Reserved { byte: b'%' }),
            ("/a:b", MountPrefixFault::Reserved { byte: b':' }),
            ("/:id", MountPrefixFault::Reserved { byte: b':' }),
            ("/files/*rest", MountPrefixFault::Reserved { byte: b'*' }),
            ("/caf\u{e9}", MountPrefixFault::Reserved { byte: 0xC3 }),
            ("app", MountPrefixFault::NotAbsolute),
            ("/app/", MountPrefixFault::TrailingSlash),
            ("/a//b", MountPrefixFault::EmptySegment),
            ("/a/..", MountPrefixFault::DotSegment),
        ] {
            for k in [KernelFn::ServerStatic, KernelFn::ServerMountApp] {
                let Some((_, defect)) = defect(&call(k, prefix)) else {
                    assert!(defect(&call(k, prefix)).is_some(), "{prefix:?}");
                    return;
                };
                assert_eq!(
                    defect,
                    RoutePatternDefect::MountPrefix {
                        prefix: prefix.into(),
                        fault
                    },
                    "{prefix:?}"
                );
            }
        }
        let long = format!("/{}", "a".repeat(MAX_MOUNT_BASE_LEN));
        assert!(matches!(
            defect(&call(KernelFn::ServerStatic, &long)),
            Some((_, RoutePatternDefect::MountPrefix { fault: MountPrefixFault::TooLong { cap }, .. }))
                if cap == MAX_MOUNT_BASE_LEN
        ));
    }

    /// Prove the refusals: a mount prefix computed at run time, or a mount
    /// kernel passed as a value, is refused at compile time.
    #[test]
    fn a_computed_mount_prefix_is_refused() {
        for k in [KernelFn::ServerStatic, KernelFn::ServerMountApp] {
            let computed = Expr::Call {
                callee: Callee::Kernel(k),
                args: vec![Expr::Var(ipe_intern::Symbol::from_raw(1)), Expr::Unit],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            };
            let as_value = Expr::FuncValue {
                callee: Callee::Kernel(k),
                ty: IrType::Unit,
            };
            for expr in [computed, as_value] {
                assert!(
                    defect(&expr)
                        .is_some_and(|(_, d)| d == RoutePatternDefect::MountPrefixNotLiteral),
                    "{k:?}"
                );
            }
        }
    }

    /// Prove the refusal: two mounts of one literal route list on one prefix
    /// are refused, whatever spelling of the root they use.
    #[test]
    fn two_mounts_on_one_prefix_are_refused() {
        for (a, b) in [("/a", "/a"), ("/", ""), ("/", "/"), ("/app/v2", "/app/v2")] {
            for (ka, kb) in [
                (KernelFn::ServerStatic, KernelFn::ServerMountApp),
                (KernelFn::ServerMountApp, KernelFn::ServerMountApp),
            ] {
                let routes = listen(vec![
                    call(ka, a),
                    call(KernelFn::ServerGet, "/x"),
                    call(kb, b),
                ]);
                assert_eq!(
                    defect(&routes),
                    Some((
                        "Server.listen".into(),
                        RoutePatternDefect::MountPrefixDuplicate { prefix: b.into() }
                    )),
                    "{a:?} {b:?}"
                );
            }
        }
    }

    /// Nested mount prefixes, a handler on a mount's prefix, and the root
    /// beside a prefix are all accepted.
    #[test]
    fn distinct_mount_prefixes_pass() {
        let routes = listen(vec![
            call(KernelFn::ServerMountApp, "/billing"),
            call(KernelFn::ServerMountApp, "/billing/admin"),
            call(KernelFn::ServerGet, "/billing"),
            call(KernelFn::ServerStatic, "/"),
            call(KernelFn::ServerStatic, "/a-b/c.d~e_f"),
        ]);
        assert_eq!(literal_routes(&routes).ok(), Some(()));
    }

    #[test]
    fn well_formed_routes_and_non_route_kernels_pass() {
        let ok = Expr::Tuple(vec![
            call(KernelFn::WebRoute, "/posts/:id"),
            call(KernelFn::ServerGet, "/users/:id"),
            call(KernelFn::IoPrintln, "/:"),
        ]);
        assert_eq!(literal_routes(&ok).ok(), Some(()));
    }
}

/// The compiler-side grammar and the runtime's parsers agree on every case: a
/// pattern the runtime refuses is refused here with the same kind and offset,
/// and a pattern it accepts is accepted here.
#[cfg(test)]
mod agreement_tests {
    use ipe_runtime_rust::encoding::{
        DecodeRefusal, EncodeRefusal, ParamNameRefusal, ServerPattern, ServerPatternRefusal,
    };
    use ipe_runtime_rust::server::api_spec_parts;
    use ipe_runtime_rust::web::route::{
        DecodedPath, RoutePattern, RouteSegmentRefusal, match_route,
    };

    use super::{
        MAX_PATH_LEN, MAX_SERVER_PARAMS, RoutePatternDefect, SegmentShape, server_api_path,
        server_route_path, web_route_pattern, web_route_segments,
    };

    /// Kind + offset of a verdict, erasing the excerpt text only this side keeps.
    #[derive(Debug, PartialEq, Eq)]
    enum Verdict {
        Ok,
        Empty,
        NotIdentifier(usize),
        Duplicate(String),
        MalformedEscape(usize),
        InvalidUtf8(usize),
        TooLong(usize),
        Unrenderable,
        NotAbsolute,
        CatchAll,
        MidSegmentSigil(usize),
        TooManyParams(usize),
        /// A mount-prefix defect, which no route path parse yields.
        Mount,
        /// A `Server.api` method the server does not serve.
        UnknownMethod,
    }

    fn ours(r: Result<(), RoutePatternDefect>) -> Verdict {
        match r {
            Ok(()) => Verdict::Ok,
            Err(RoutePatternDefect::ParamEmpty) => Verdict::Empty,
            Err(RoutePatternDefect::ParamNotIdentifier { at, .. }) => Verdict::NotIdentifier(at),
            Err(RoutePatternDefect::ParamDuplicate { name }) => Verdict::Duplicate(name.into()),
            Err(RoutePatternDefect::MalformedEscape { at, .. }) => Verdict::MalformedEscape(at),
            Err(RoutePatternDefect::InvalidUtf8 { at, .. }) => Verdict::InvalidUtf8(at),
            Err(RoutePatternDefect::TooLong { cap }) => Verdict::TooLong(cap),
            Err(RoutePatternDefect::UnrenderableLiteral { .. }) => Verdict::Unrenderable,
            Err(RoutePatternDefect::NotAbsolute) => Verdict::NotAbsolute,
            Err(RoutePatternDefect::CatchAll { .. }) => Verdict::CatchAll,
            Err(RoutePatternDefect::MidSegmentSigil { at, .. }) => Verdict::MidSegmentSigil(at),
            Err(RoutePatternDefect::TooManyParams { cap }) => Verdict::TooManyParams(cap),
            Err(
                RoutePatternDefect::MountPrefixNotLiteral
                | RoutePatternDefect::MountPrefix { .. }
                | RoutePatternDefect::MountPrefixDuplicate { .. },
            ) => Verdict::Mount,
            Err(RoutePatternDefect::UnknownMethod { .. }) => Verdict::UnknownMethod,
        }
    }

    fn name_verdict(r: ParamNameRefusal) -> Verdict {
        match r {
            ParamNameRefusal::Empty => Verdict::Empty,
            ParamNameRefusal::NotIdentifier { at } => Verdict::NotIdentifier(at.get()),
            ParamNameRefusal::Duplicate { name } => Verdict::Duplicate(name.as_str().to_owned()),
        }
    }

    fn runtime_web(pattern: &str) -> Verdict {
        RoutePattern::parse(pattern).map_or_else(segment_verdict, |_| Verdict::Ok)
    }

    fn segment_verdict(r: RouteSegmentRefusal) -> Verdict {
        match r {
            RouteSegmentRefusal::ParamName(r) => name_verdict(r),
            RouteSegmentRefusal::Decode(DecodeRefusal::MalformedEscape { at }) => {
                Verdict::MalformedEscape(at.get())
            }
            RouteSegmentRefusal::Decode(DecodeRefusal::InvalidUtf8 { at }) => {
                Verdict::InvalidUtf8(at.get())
            }
            RouteSegmentRefusal::Decode(DecodeRefusal::TooLong { cap }) => {
                Verdict::TooLong(cap.get())
            }
            RouteSegmentRefusal::CatchAll => Verdict::CatchAll,
            RouteSegmentRefusal::MidSegmentSigil { at } => Verdict::MidSegmentSigil(at.get()),
        }
    }

    fn runtime_server(path: &str) -> Verdict {
        match ServerPattern::parse(path) {
            Ok(_) => Verdict::Ok,
            Err(ServerPatternRefusal::NotAbsolute) => Verdict::NotAbsolute,
            Err(ServerPatternRefusal::Segment(r)) => segment_verdict(r),
            Err(ServerPatternRefusal::TooManyParams { cap }) => Verdict::TooManyParams(cap),
            Err(ServerPatternRefusal::Render(EncodeRefusal::TooLong { cap })) => {
                Verdict::TooLong(cap.get())
            }
            Err(ServerPatternRefusal::Render(EncodeRefusal::Empty | EncodeRefusal::Dot)) => {
                Verdict::Unrenderable
            }
        }
    }

    const CASES: &[&str] = &[
        "",
        "/",
        "//",
        "/posts/:id/:slug",
        "/a+b",
        "/caf%C3%A9",
        "/:post-id",
        "/:id/:id",
        "/:",
        "/:1st",
        "/a/:/b",
        "/a%zz",
        "/x/%4",
        "/x/%",
        "/ab%C0%AF",
        "/%E2%82",
        "/ok/%ff/:n",
        "/f/*rest",
        "/f/*",
        "/:id/*id",
        "/x/:a-b",
        "/a:b/c",
        "/u/:éa",
        "/:_/:__",
        ":lead",
        "/tail:",
        "/e/%00",
        "api",
        "/*",
        "/v-:id",
        "/x/ab*",
        "/q/a*:b",
        "/:a*b",
        "/a/",
        "//a//",
        "/a//b",
        "/%2E/..",
        "/a+b~c.d_e-f",
    ];

    #[test]
    fn web_route_verdicts_match_runtime_route_pattern() {
        for case in CASES {
            assert_eq!(ours(web_route_pattern(case)), runtime_web(case), "{case:?}");
        }
    }

    #[test]
    fn server_path_verdicts_match_runtime_param_gate() {
        for case in CASES {
            assert_eq!(
                ours(server_route_path(case)),
                runtime_server(case),
                "{case:?}"
            );
        }
    }

    #[test]
    fn server_api_split_matches_runtime() {
        for spec in [
            "POST /u/:id",
            " /u/:id ",
            "/u/:id",
            "GET  /a ",
            "",
            " ",
            "PUT",
        ] {
            let (_, path) = api_spec_parts(spec);
            assert_eq!(server_api_path(spec), path, "{spec:?}");
        }
    }

    /// The compiler admits a literal `Server.api` method exactly when the
    /// server's listen-time parse does, whatever its case or bytes.
    #[test]
    fn server_api_method_matches_runtime() {
        use ipe_runtime_rust::encoding::EndpointMethod;
        for spec in [
            "POST /u/:id",
            "post /u",
            "FETCH /u",
            "po\u{17f}t /u",
            "GET\t /u",
            "\tGET /u",
            "Any /u",
            "/u",
            " /u",
            "",
        ] {
            let (method, _) = api_spec_parts(spec);
            let runtime = method.is_empty() || EndpointMethod::parse(&method).is_some();
            let ours =
                super::server_api_method(spec).is_none_or(|m| EndpointMethod::parse(m).is_some());
            assert_eq!(ours, runtime, "{spec:?}");
            assert_eq!(
                super::server_api_method(spec).unwrap_or("ANY"),
                if method.is_empty() {
                    "ANY"
                } else {
                    method.as_str()
                },
                "{spec:?}"
            );
        }
    }

    /// Whether a pattern read as `segments` matches a path of `decoded`
    /// segments, by shape alone: a parameter takes any one segment, a literal
    /// its decoded text.
    fn shape_matches(segments: &[SegmentShape], decoded: &[&str]) -> bool {
        segments.len() == decoded.len()
            && segments.iter().zip(decoded).all(|pair| match pair {
                (SegmentShape::Param, _) => true,
                (SegmentShape::Literal(l), seg) => l == seg,
            })
    }

    /// The compiler's segment reading (which the routed-table equivalence and
    /// coverage checks compare) matches exactly the paths the runtime's
    /// `RoutePattern` matches.
    #[test]
    #[allow(clippy::expect_used)] // test table: every pattern and probe is well-formed
    fn segment_reading_matches_runtime_matching() {
        let patterns = [
            "/",
            "/a",
            "/a/",
            "/A",
            "/a/:x",
            "/a/%41",
            "/a/A",
            "/a/b",
            "/:x",
            "/:x/:y",
            "/caf%C3%A9",
            "/a+b",
            "/%2F",
            "/a/%3Ax",
        ];
        let probes: &[(&str, &[&str])] = &[
            ("/", &[]),
            ("/a", &["a"]),
            ("/A", &["A"]),
            ("/a/A", &["a", "A"]),
            ("/a/%41", &["a", "A"]),
            ("/a/b", &["a", "b"]),
            ("/caf%C3%A9", &["café"]),
            ("/a+b", &["a+b"]),
            ("/%2F", &["/"]),
            ("/a/%3Ax", &["a", ":x"]),
            ("/x/y", &["x", "y"]),
        ];
        for pattern in patterns {
            let ours = web_route_segments(pattern).expect("well-formed pattern");
            let theirs = RoutePattern::parse(pattern).expect("well-formed pattern");
            for (raw, decoded) in probes {
                let path = DecodedPath::parse(raw).expect("well-formed probe");
                assert_eq!(
                    shape_matches(&ours, decoded),
                    match_route(&theirs, &path).is_some(),
                    "{pattern:?} against {raw:?}"
                );
            }
        }
    }

    #[test]
    fn ceilings_agree() {
        assert_eq!(
            MAX_PATH_LEN,
            ipe_runtime_rust::encoding::MAX_URL_COMPONENT_LEN.get()
        );
        assert_eq!(
            MAX_SERVER_PARAMS,
            ipe_runtime_rust::encoding::MAX_SERVER_PARAMS
        );
        let past = "a".repeat(MAX_PATH_LEN + 1);
        assert_eq!(ours(web_route_pattern(&past)), runtime_web(&past));
        assert_eq!(ours(server_route_path(&past)), runtime_server(&past));
        let params = |n: usize| -> String {
            (0..n)
                .flat_map(|i| ["/:v".to_owned(), i.to_string()])
                .collect()
        };
        for n in [MAX_SERVER_PARAMS, MAX_SERVER_PARAMS + 1] {
            let path = params(n);
            assert_eq!(ours(server_route_path(&path)), runtime_server(&path), "{n}");
        }
        let long_name = format!("/:{}", "a".repeat(MAX_PATH_LEN - 2));
        assert_eq!(
            ours(server_route_path(&long_name)),
            runtime_server(&long_name)
        );
        let pad = |n: usize, tail: &str| format!("/{}{tail}", "a".repeat(n));
        for tail in ["/:x", "/:a/:b/:c/:d/:e/:f/:g/:h/:i/:j/:k"] {
            for n in [
                MAX_PATH_LEN - 5,
                MAX_PATH_LEN - 4,
                MAX_PATH_LEN - 36,
                MAX_PATH_LEN - 37,
            ] {
                let grows = pad(n, tail);
                assert_eq!(
                    ours(server_route_path(&grows)),
                    runtime_server(&grows),
                    "{n} {tail}"
                );
            }
        }
        for grows in [
            format!("/{}", "+".repeat(MAX_PATH_LEN / 2)),
            format!("/{}", "a".repeat(MAX_PATH_LEN - 1)),
            format!("/{}/", "a".repeat(MAX_PATH_LEN - 2)),
            format!("/{}/", "a".repeat(MAX_PATH_LEN - 1)),
            format!("/{}", "%2E/".repeat(MAX_PATH_LEN / 4)),
        ] {
            assert_eq!(
                ours(server_route_path(&grows)),
                runtime_server(&grows),
                "{}",
                grows.len()
            );
        }
    }
}
