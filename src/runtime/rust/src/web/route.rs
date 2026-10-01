//! URL routing for `Web.tea` — `Route<Page>` + matching.
//!
//! Each `Web.route pattern ctor` lowers (codegen peephole) to a `Route` whose
//! `build` closure applies the captured `:param` strings to the page
//! constructor. `match_routes` picks the first matching route in declaration
//! order and builds its page, falling back to `not_found`.
//!
//! Matching happens entirely between decoded values. A request path is parsed
//! once per request into a [`DecodedPath`] (each segment decoded by the strict
//! core) and every matcher here takes that parsed path. A route pattern is
//! parsed once at registration into a [`RoutePattern`]: it is split by the same
//! rule as a request path, a `:name` segment is a parameter, and every other
//! segment is a literal decoded by the same strict path-segment decoder
//! (`crate::encoding::decode_path_segment`). A literal and a request segment are
//! therefore both compared after exactly one decode, so a literal `%41` in a
//! pattern and an `A` (or `%41`) in a request path name the same segment. A
//! literal that does not decode can never equal any request segment; it is
//! refused at registration (the route table fails to start, see
//! [`check_route_table`]) instead of silently never matching. A parameter
//! name is admitted through the runtime's one parameter-name grammar
//! ([`ParamNames`]): an empty, non-identifier or repeated name is refused the
//! same way, so no route captures a value under an ambiguous name.
//!
//! The builder returns `Option<Page>` so that a `:param` segment that fails to
//! decode into the expected payload type (e.g. `"abc"` for an `Int` param)
//! returns `None` and `match_routes` falls through to `not_found` rather than
//! silently substituting a default value. Sanctioned divergence §B-route-param.

use std::sync::Arc;

pub use crate::encoding::DecodedPath;
use crate::encoding::{
    DecodeRefusal, ParamName, ParamNameRefusal, ParamNames, decode_path_segment, raw_path_segments,
};

/// One segment of a parsed route pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatternSeg {
    /// A literal segment, already decoded: it must equal the decoded request
    /// segment.
    Literal(String),
    /// A `:name` segment: captures the decoded request segment as `name`.
    Param(ParamName),
}

/// A route pattern parsed once, at registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePattern(Vec<PatternSeg>);

impl RoutePattern {
    /// Split `pattern` by the request-path split rule and classify each raw
    /// segment: a leading `:` makes a parameter whose name is admitted by
    /// [`ParamNames::admit`]; anything else is a literal decoded by the strict
    /// path-segment decoder.
    ///
    /// # Errors
    ///
    /// The refusal of the first malformed segment: a literal that does not
    /// decode, a parameter name that is empty, not an identifier or a repeat,
    /// or `TooLong` for an oversized pattern.
    pub fn parse(pattern: &str) -> Result<Self, RouteSegmentRefusal> {
        let mut names = ParamNames::default();
        raw_path_segments(pattern)
            .map_err(RouteSegmentRefusal::Decode)?
            .into_iter()
            .map(|raw| match raw.strip_prefix(':') {
                Some(name) => names
                    .admit(name)
                    .map(PatternSeg::Param)
                    .map_err(RouteSegmentRefusal::ParamName),
                None => decode_path_segment(raw)
                    .map(PatternSeg::Literal)
                    .map_err(RouteSegmentRefusal::Decode),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// The parsed segments, in pattern order.
    #[must_use]
    pub fn segments(&self) -> &[PatternSeg] {
        &self.0
    }

    /// The `:name`s of the parameter segments, in pattern order.
    fn param_names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().filter_map(|seg| match seg {
            PatternSeg::Param(name) => Some(name.as_str()),
            PatternSeg::Literal(_) => None,
        })
    }
}

/// Why one segment of a route pattern was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteSegmentRefusal {
    /// A literal segment (or the whole pattern) does not decode.
    Decode(DecodeRefusal),
    /// A `:name` segment's name is empty, not an identifier, or a repeat.
    ParamName(ParamNameRefusal),
}

impl std::fmt::Display for RouteSegmentRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(refusal) => write!(f, "{refusal}"),
            Self::ParamName(refusal) => write!(f, "{refusal}"),
        }
    }
}

/// A route pattern refused at registration: the raw pattern text and why it
/// did not parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutePatternRefusal {
    /// The pattern text as registered.
    pub pattern: String,
    /// Why its first malformed segment was refused.
    pub refusal: RouteSegmentRefusal,
}

impl std::fmt::Display for RoutePatternRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "route pattern `{}` is malformed: {}",
            self.pattern, self.refusal
        )
    }
}

/// A declared route: a parsed URL pattern + a builder that applies the
/// captured `:param` strings (in pattern order) to the page constructor.
///
/// `build` returns `Option<Page>` — `None` when a `:param` segment cannot be
/// decoded into the constructor's expected payload type (e.g. `"abc"` for an
/// `Int` slot). `match_routes` treats `None` as a miss and falls through to the
/// next route or `not_found`.
///
/// `Page: Clone` at the match site because `not_found` is cloned on a miss.
#[derive(Clone)]
pub struct Route<Page> {
    pattern: Result<RoutePattern, RoutePatternRefusal>,
    pub build: Arc<dyn Fn(Vec<String>) -> Option<Page> + Send + Sync>,
}

impl<Page> Route<Page> {
    /// Register `pattern`, parsing it once ([`RoutePattern::parse`]).
    ///
    /// A pattern that does not parse is kept as its refusal: such a route
    /// matches nothing, and [`check_route_table`] refuses the whole table
    /// before any app serves it.
    pub fn new(
        pattern: &str,
        build: impl Fn(Vec<String>) -> Option<Page> + Send + Sync + 'static,
    ) -> Self {
        Route {
            pattern: RoutePattern::parse(pattern).map_err(|refusal| RoutePatternRefusal {
                pattern: pattern.to_owned(),
                refusal,
            }),
            build: Arc::new(build),
        }
    }

    /// The parsed pattern, or why it was refused.
    ///
    /// # Errors
    ///
    /// The registration refusal of a malformed pattern.
    pub fn pattern(&self) -> Result<&RoutePattern, &RoutePatternRefusal> {
        self.pattern.as_ref()
    }
}

/// Refuse a route table holding any malformed pattern.
///
/// Every routed app runs this before it serves, so a pattern whose literal
/// can never match, or whose parameter names are ambiguous, is a loud startup
/// failure, never a silently dead or ambiguous route.
///
/// # Errors
///
/// The refusal of the first malformed pattern, in declaration order.
pub fn check_route_table<Page>(routes: &[Route<Page>]) -> Result<(), RoutePatternRefusal> {
    routes
        .iter()
        .try_for_each(|rt| rt.pattern().map(drop).map_err(Clone::clone))
}

/// [`check_route_table`] as the startup refusal a routed app reports: the
/// server's `web_app_routed` and the browser's routed mount both fail with
/// this message, before any bind or DOM access.
///
/// # Errors
///
/// The rendered refusal of the first malformed pattern, in declaration order.
pub fn refuse_route_table<Page>(routes: &[Route<Page>]) -> Result<(), String> {
    check_route_table(routes).map_err(|refusal| refusal.to_string())
}

/// The decoded values a route pattern's `:param` segments captured, in
/// pattern order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteParams(Vec<String>);

impl RouteParams {
    /// The `i`-th captured value, if the pattern has that many params.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<&str> {
        self.0.get(i).map(String::as_str)
    }

    /// The captured values, for a route builder.
    #[must_use]
    pub fn into_segments(self) -> Vec<String> {
        self.0
    }
}

/// Match a decoded `path` against a parsed `pattern`: equal segment counts; a
/// `:name` segment captures the corresponding decoded segment; a literal
/// segment (decoded at registration) must equal it. Returns the captured
/// params in pattern order, or `None`.
#[must_use]
pub fn match_route(pattern: &RoutePattern, path: &DecodedPath) -> Option<RouteParams> {
    let pat = pattern.segments();
    let segs = path.segments();
    if pat.len() != segs.len() {
        return None;
    }
    let mut params = Vec::new();
    for (ps, us) in pat.iter().zip(segs) {
        match ps {
            PatternSeg::Param(_) => params.push(us.clone()),
            PatternSeg::Literal(lit) if lit == us => {}
            PatternSeg::Literal(_) => return None,
        }
    }
    Some(RouteParams(params))
}

/// The first route (declaration order) whose parsed pattern matches `path`,
/// with its captured params.
fn first_match<'r, Page>(
    routes: &'r [Route<Page>],
    path: &DecodedPath,
) -> impl Iterator<Item = (&'r Route<Page>, &'r RoutePattern, RouteParams)> {
    routes.iter().filter_map(move |rt| {
        let pattern = rt.pattern().ok()?;
        match_route(pattern, path).map(|params| (rt, pattern, params))
    })
}

/// First route (declaration order) whose pattern matches `path` AND whose
/// builder successfully decodes all `:param` segments → its built page; else
/// `not_found` (cloned).
///
/// A route whose pattern matches but whose builder returns `None` (a `:param`
/// segment failed to decode into the expected type, e.g. `"abc"` for an `Int`
/// slot) is skipped and matching continues. This mirrors how `match_routes`
/// handles a pattern-level miss, routing the user to `not_found` instead of
/// silently substituting a zero-value default.
pub fn match_routes<Page: Clone>(
    routes: &[Route<Page>],
    not_found: &Page,
    path: &DecodedPath,
) -> Page {
    first_match(routes, path)
        .find_map(|(rt, _, params)| (rt.build)(params.into_segments()))
        .unwrap_or_else(|| not_found.clone())
}

/// Does `path` match ANY declared route? With no
/// routes only the root ([`DecodedPath::is_root`]) is a page URL (the single-page `Web.tea` shape). The page
/// handler uses this to keep unrouted GETs (browser noise like
/// `/favicon.ico`, asset probes, unknown paths) from re-routing a live
/// session's model — an unrouted re-route would rebuild the handler index
/// from the `notFound` view and orphan every handler on the page the browser
/// is actually showing.
pub fn matches_any<Page>(routes: &[Route<Page>], path: &DecodedPath) -> bool {
    if routes.is_empty() {
        return path.is_root();
    }
    first_match(routes, path).next().is_some()
}

/// Name→value params for the first route matching `path` — for `req.params`.
/// Zips the matched pattern's `:name` segments with the decoded captured
/// values.
pub fn match_params<Page>(
    routes: &[Route<Page>],
    path: &DecodedPath,
) -> crate::dict::IpeDict<String> {
    use crate::dict::IpeDict;
    let mut d: IpeDict<String> = IpeDict::new();
    if let Some((_, pattern, values)) = first_match(routes, path).next() {
        for (n, v) in pattern.param_names().zip(values.into_segments()) {
            d.insert(n.to_owned(), v);
        }
    }
    d
}

/// The result of entering a routed page: the model to commit and the Cmd to run once.
///
/// `#[must_use]` so a caller that drops the entry (and with it the page's
/// load Cmd) is a denied warning, never a silently skipped page load.
///
/// Generic over the Cmd carrier `C` (the platform's `IpeCmd<Msg>`), so the
/// server-free render core shares it without the TEA loop.
#[must_use]
pub struct Entered<M, C> {
    pub model: M,
    pub cmd: C,
}

/// Enter `path`: match it against `routes` and apply the app's entry fn to the matched page.
///
/// The single URL-to-model entry every platform shares (server GET, SSE
/// reconnect, wasm mount, popstate, in-app navigation). The entry fn is the
/// app's `set_page` (`onNavigate` routed through `update`, or the implicit
/// `{ model | page }` paired with `Cmd.none`); its Cmd is returned, never dropped.
pub fn enter<Page: Clone, M, C>(
    routes: &[Route<Page>],
    not_found: &Page,
    path: &DecodedPath,
    model: M,
    entry: impl Fn(Page, M) -> (M, C),
) -> Entered<M, C> {
    let (model, cmd) = entry(match_routes(routes, not_found, path), model);
    Entered { model, cmd }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    enum Page {
        Home,
        App(String),
        Two(String, String),
        NF,
    }

    /// Parse a request path the way the request boundary does; a test path
    /// that does not parse is a test bug.
    fn dp(path: &str) -> DecodedPath {
        match DecodedPath::parse(path) {
            Ok(d) => d,
            Err(e) => panic!("test path {path} must parse: {e}"),
        }
    }

    fn at<P: Clone>(routes: &[Route<P>], nf: &P, path: &str) -> P {
        match_routes(routes, nf, &dp(path))
    }

    fn routes() -> Vec<Route<Page>> {
        vec![
            Route::new("/", |_| Some(Page::Home)),
            Route::new("/apps/:slug", |p| Some(Page::App(p[0].clone()))),
            Route::new("/x/:a/:b", |p| Some(Page::Two(p[0].clone(), p[1].clone()))),
        ]
    }

    #[test]
    fn matches_static_and_param_in_order() {
        let rs = routes();
        assert_eq!(at(&rs, &Page::NF, "/"), Page::Home);
        assert_eq!(at(&rs, &Page::NF, "/apps/foo"), Page::App("foo".into()));
        assert_eq!(at(&rs, &Page::NF, "/apps/foo/"), Page::App("foo".into())); // trailing slash
        assert_eq!(
            at(&rs, &Page::NF, "/x/1/2"),
            Page::Two("1".into(), "2".into())
        );
        assert_eq!(at(&rs, &Page::NF, "/nope"), Page::NF); // notFound
        assert_eq!(at(&rs, &Page::NF, "/apps"), Page::NF); // arity mismatch
        assert_eq!(at(&rs, &Page::NF, "/apps/"), Page::NF); // trailing slash trims -> 1 seg
    }

    /// A builder returning `None` (simulates a failed `:param` decode, e.g.
    /// `"abc"` for an `Int` slot) causes `match_routes` to fall through to
    /// `not_found` rather than returning a zero-value default.
    #[test]
    fn build_none_routes_to_not_found() {
        let routes: Vec<Route<Page>> = vec![
            Route::new("/items/:id", |_p| None), // always fails decode
            Route::new("/items/:id", |p| Some(Page::App(p[0].clone()))), // fallback
        ];
        assert_eq!(at(&routes, &Page::NF, "/items/42"), Page::App("42".into()));
        let only_failing: Vec<Route<Page>> = vec![Route::new("/items/:id", |_p| None)];
        assert_eq!(at(&only_failing, &Page::NF, "/items/abc"), Page::NF);
    }

    #[test]
    fn matches_any_routed_and_empty_table() {
        let rs = routes();
        assert!(matches_any(&rs, &dp("/")));
        assert!(matches_any(&rs, &dp("/apps/foo")));
        assert!(matches_any(&rs, &dp("/apps/foo/"))); // trailing slash tolerated
        assert!(!matches_any(&rs, &dp("/favicon.ico")));
        assert!(!matches_any(&rs, &dp("/nope")));

        // Empty route table (single-page `Web.tea`): only `/` is a page URL.
        let none: Vec<Route<Page>> = Vec::new();
        assert!(matches_any(&none, &dp("/")));
        assert!(!matches_any(&none, &dp("/favicon.ico")));
        assert!(!matches_any(&none, &dp("/about")));
    }

    fn user_routes() -> Vec<Route<Page>> {
        vec![
            Route::new("/u/:id", |p| p.first().cloned().map(Page::App)),
            Route::new("/u/:a/:b", |p| {
                Some(Page::Two(p.first()?.clone(), p.get(1)?.clone()))
            }),
        ]
    }

    /// A captured `:param` reaches the builder decoded under the path grammar:
    /// `%20` is a space and `+` stays a literal `+`.
    #[test]
    fn param_is_decoded_once_under_path_grammar() {
        let rs = user_routes();
        assert_eq!(at(&rs, &Page::NF, "/u/a%20b"), Page::App("a b".into()));
        assert_eq!(at(&rs, &Page::NF, "/u/a+b"), Page::App("a+b".into()));
        // One decode only: `%2541` is the text `%41`, never `A`.
        assert_eq!(at(&rs, &Page::NF, "/u/%2541"), Page::App("%41".into()));
        let params = match_params(&rs, &dp("/u/a%20b"));
        assert_eq!(params.get("id").map(String::as_str), Some("a b"));
    }

    /// An encoded `/` stays inside its segment: `/u/a%2Fb` is the one-param
    /// route with value `a/b`, never the two-param route.
    #[test]
    fn encoded_slash_is_one_segment() {
        let rs = user_routes();
        assert_eq!(at(&rs, &Page::NF, "/u/a%2Fb"), Page::App("a/b".into()));
        let decoded = dp("/u/a%2Fb");
        assert_eq!(decoded.segments(), &["u".to_owned(), "a/b".to_owned()][..]);
        let pattern = RoutePattern::parse("/u/:id").ok();
        let params = pattern.and_then(|p| match_route(&p, &decoded));
        assert_eq!(params.as_ref().and_then(|p| p.get(0)), Some("a/b"));
        assert_eq!(params.as_ref().and_then(|p| p.get(1)), None);
    }

    /// A malformed escape or a non-UTF-8 decode is refused by the one parse at
    /// the request boundary, so no matcher ever sees it.
    #[test]
    fn malformed_request_path_is_refused_by_the_parse() {
        for bad in ["/u/%zz", "/u/%", "/u/%4", "/u/%C0%AF", "/u/%FF", "/%zz/x"] {
            assert!(DecodedPath::parse(bad).is_err(), "{bad} must be refused");
        }
        assert!(matches!(
            DecodedPath::parse("/u/%zz"),
            Err(DecodeRefusal::MalformedEscape { .. })
        ));
    }

    /// A literal pattern segment is decoded once by the same path-segment
    /// decoder as a request segment, so a `%41` literal and a request `A` (or
    /// `%41`) are the same segment, and an encoded non-ASCII literal matches
    /// its decoded request form.
    #[test]
    fn literal_pattern_segment_is_decoded_like_a_request_segment() {
        let rs: Vec<Route<Page>> = vec![
            Route::new("/%41", |_| Some(Page::Home)),
            Route::new("/caf%C3%A9", |_| Some(Page::App("cafe".into()))),
        ];
        assert_eq!(check_route_table(&rs), Ok(()));
        assert_eq!(at(&rs, &Page::NF, "/A"), Page::Home);
        assert_eq!(at(&rs, &Page::NF, "/%41"), Page::Home);
        assert_eq!(at(&rs, &Page::NF, "/a"), Page::NF);
        // One decode: a request `%2541` is the text `%41`, not the literal `A`.
        assert_eq!(at(&rs, &Page::NF, "/%2541"), Page::NF);
        assert_eq!(at(&rs, &Page::NF, "/café"), Page::App("cafe".into()));
        assert_eq!(at(&rs, &Page::NF, "/caf%C3%A9"), Page::App("cafe".into()));
    }

    /// Only a raw leading `:` makes a parameter: an encoded `%3Aid` is the
    /// literal text `:id`.
    #[test]
    fn encoded_colon_is_a_literal_not_a_param() {
        assert_eq!(
            RoutePattern::parse("/u/%3Aid")
                .ok()
                .as_ref()
                .map(RoutePattern::segments),
            Some(
                &[
                    PatternSeg::Literal("u".into()),
                    PatternSeg::Literal(":id".into())
                ][..]
            )
        );
        let rs: Vec<Route<Page>> = vec![Route::new("/u/%3Aid", |_| Some(Page::Home))];
        assert_eq!(at(&rs, &Page::NF, "/u/:id"), Page::Home);
        assert_eq!(at(&rs, &Page::NF, "/u/42"), Page::NF);
        assert!(match_params(&rs, &dp("/u/:id")).is_empty());
    }

    #[test]
    fn identifier_param_names_are_admitted() {
        for ok in ["/:a_Z9", "/:_x", "/:A/:b", "/users/:id/posts/:post_id"] {
            assert!(RoutePattern::parse(ok).is_ok(), "{ok} must be admitted");
        }
    }

    /// Prove the refusals: an empty, non-identifier, or repeated name is
    /// refused with its typed cause.
    #[test]
    fn malformed_param_names_are_refused() {
        use crate::encoding::ParamNameRefusal as R;
        assert!(matches!(
            RoutePattern::parse("/:"),
            Err(RouteSegmentRefusal::ParamName(R::Empty))
        ));
        for (bad, at) in [
            ("/:1a", 0),
            ("/:9", 0),
            ("/:\u{e9}", 0),
            ("/:a-b", 1),
            ("/:a_Z9-", 4),
            ("/:a%41", 1),
        ] {
            let refused = RoutePattern::parse(bad);
            assert!(
                matches!(
                    &refused,
                    Err(RouteSegmentRefusal::ParamName(R::NotIdentifier { at: off }))
                        if off.get() == at
                ),
                "{bad} must break at byte {at}, got {refused:?}"
            );
        }
        for dup in ["/:id/:id", "/x/:a/y/:a"] {
            assert!(
                matches!(
                    RoutePattern::parse(dup),
                    Err(RouteSegmentRefusal::ParamName(R::Duplicate { .. }))
                ),
                "{dup} must be refused as a repeat"
            );
        }
        let rs: Vec<Route<Page>> = vec![
            Route::new("/ok", |_| Some(Page::Home)),
            Route::new("/u/:id/:id", |_| Some(Page::App("dead".into()))),
        ];
        let refusal = check_route_table(&rs).err();
        assert!(refusal.is_some_and(|r| {
            let msg = r.to_string();
            r.pattern == "/u/:id/:id"
                && msg.contains("route pattern `/u/:id/:id` is malformed")
                && msg.contains("parameter `id` appears twice")
        }));
    }

    /// A literal that does not decode is refused at registration: the route
    /// matches nothing and the route table as a whole is refused, naming the
    /// pattern and the reason.
    #[test]
    fn malformed_literal_pattern_is_refused() {
        for bad in ["/%zz", "/a/%", "/a/%4/:id", "/%C0%AF", "/%FF"] {
            assert!(RoutePattern::parse(bad).is_err(), "{bad} must be refused");
        }
        let rs: Vec<Route<Page>> = vec![
            Route::new("/ok", |_| Some(Page::Home)),
            Route::new("/%zz", |_| Some(Page::App("dead".into()))),
        ];
        let refusal = check_route_table(&rs).err();
        assert_eq!(refusal.as_ref().map(|r| r.pattern.as_str()), Some("/%zz"));
        assert!(matches!(
            refusal.as_ref().map(|r| &r.refusal),
            Some(RouteSegmentRefusal::Decode(
                DecodeRefusal::MalformedEscape { .. }
            ))
        ));
        assert!(
            refusal
                .map(|r| r.to_string())
                .is_some_and(|m| m.contains("route pattern `/%zz` is malformed"))
        );
        // Even if served, the refused route never matches: no request segment
        // equals a literal that has no decoded value.
        assert!(rs.get(1).is_some_and(|r| r.pattern().is_err()));
        assert_eq!(at(&rs, &Page::NF, "/ok"), Page::Home);
        assert!(!matches_any(&rs, &dp("/%25zz")));
        assert!(!matches_any(&rs, &dp("/zz")));
    }

    /// The startup refusal both routed hosts report names the first malformed
    /// pattern; a well-formed table is admitted.
    #[test]
    fn refuse_route_table_names_the_malformed_pattern() {
        let ok: Vec<Route<Page>> = vec![
            Route::new("/", |_| Some(Page::Home)),
            Route::new("/apps/:slug", |_| Some(Page::Home)),
        ];
        assert_eq!(refuse_route_table(&ok), Ok(()));
        let bad: Vec<Route<Page>> = vec![
            Route::new("/", |_| Some(Page::Home)),
            Route::new("/%zz", |_| Some(Page::Home)),
            Route::new("/:id/:id", |_| Some(Page::Home)),
        ];
        let refused = refuse_route_table(&bad);
        assert!(
            matches!(&refused, Err(message) if message.contains("route pattern `/%zz` is malformed")),
            "a malformed route table must be refused: {refused:?}"
        );
    }

    /// `enter` hands back the entry fn's Cmd beside its model, so no caller can
    /// commit the page and lose the page's load.
    #[test]
    fn enter_returns_the_entry_fns_cmd() {
        let rs = routes();
        let entry = |page: Page, count: u32| {
            let cmd = match page {
                Page::App(slug) => format!("load {slug}"),
                _ => String::new(),
            };
            (count + 1, cmd)
        };
        let entered = enter(&rs, &Page::NF, &dp("/apps/abc"), 0_u32, entry);
        assert_eq!(entered.model, 1);
        assert_eq!(
            entered.cmd, "load abc",
            "enter must return the entry fn's Cmd for the matched page"
        );
        let missed = enter(&rs, &Page::NF, &dp("/nope"), 5_u32, entry);
        assert_eq!(missed.model, 6, "an unknown path enters notFound");
        assert_eq!(missed.cmd, "");
    }

    /// Paths the request boundary splits alike parse to one `DecodedPath`;
    /// paths it splits apart never do, so comparing entered paths agrees with
    /// matching.
    #[test]
    fn decoded_path_equality_agrees_with_split_path() {
        let alike = [
            ("/", ""),
            ("/", "//"),
            ("/items/5", "items/5/"),
            ("/a//b", "a//b/"),
        ];
        for (a, b) in alike {
            assert_eq!(dp(a), dp(b), "{a:?} vs {b:?}");
        }
        let apart = [("/items", "/items/5"), ("/a/b", "/a//b"), ("/", "/x")];
        for (a, b) in apart {
            assert_ne!(dp(a), dp(b), "{a:?} vs {b:?}");
        }
    }

    /// A single-page app's root agrees with a routed app whose only route is
    /// `/`: every spelling the matcher splits to no segments is root, and no
    /// other path is.
    #[test]
    fn single_page_root_agrees_with_the_routed_matcher() {
        let none: Vec<Route<Page>> = Vec::new();
        let root_only = [Route::new("/", |_| Some(Page::Home))];
        for p in ["/", "", "//", "///"] {
            let path = dp(p);
            assert!(path.is_root(), "{p:?} is root");
            assert!(matches_any(&root_only, &path), "routed: {p:?} is root");
            assert!(matches_any(&none, &path), "single-page: {p:?} is root");
        }
        for p in ["/x", "x", "/x/", "//x", "/favicon.ico"] {
            let path = dp(p);
            assert!(!path.is_root(), "{p:?} is not root");
            assert!(!matches_any(&root_only, &path), "routed: {p:?} is not root");
            assert!(!matches_any(&none, &path), "single-page: {p:?} is not root");
        }
    }
}
