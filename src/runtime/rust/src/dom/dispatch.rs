use crate::html::{Attribute, Event, FormData, Html};
use std::collections::{HashMap, VecDeque};
use std::num::{NonZeroU64, NonZeroUsize};

/// Per-session handler index: maps `ipe-id` → (`event-name` → the cloneable
/// `Event` that owns the handler closure, via `Arc`).
///
/// Built once per `view` commit via [`build_index`]; thrown away and rebuilt
/// on every update cycle (the view function is the single source of truth).
///
/// The two-level shape lets [`Self::resolve`] / [`Self::resolve_form`] look up
/// by `&str` (`HashMap<String, _>: get(&str)` via `Borrow<str>`) without
/// heap-allocating throwaway key Strings on the wire-event hot path.
pub struct HandlerIndex<M> {
    map: HashMap<String, HashMap<String, Event<M>>>,
}

impl<M: Clone> HandlerIndex<M> {
    /// Resolve a wire event from the browser.
    ///
    /// - `OnMsg`   — returns the message directly (args ignored).
    /// - `OnString`— calls the closure with `args[0]` (or `""` if absent).
    /// - `OnBool`  — calls the closure with `args[0] == "true"` (or `false`).
    /// - `OnForm`  — dispatched via [`Self::resolve_form`]; returns `None` here.
    /// - `OnWidget`— a `CustomElement.node` up-event: runs the generated fail-closed seal
    ///   decode over `args[0]` (the posted encoded `up` value) and returns the
    ///   typed msg, or `None` when the payload does not decode to the declared
    ///   `up` type (the seal boundary's fail-closed drop — no partial value).
    ///
    /// Returns `None` when the ipe-id is unknown or the event name doesn't
    /// match any registered handler.
    #[must_use]
    pub fn resolve(&self, ipe_id: &str, event: &str, args: &[String]) -> Option<M> {
        match self.map.get(ipe_id)?.get(event)? {
            Event::OnMsg(_, m) => Some(m.clone()),
            Event::OnString(_, f) => Some(f(args.first().cloned().unwrap_or_default())),
            Event::OnBool(_, f) => Some(f(args.first().is_some_and(|s| s == "true"))),
            Event::OnForm(_, _) => None, // dispatched via resolve_form
            // `f` already returns `Option<M>` (`None` on a fail-closed seal
            // decode); a missing `args[0]` decodes the empty string, which the
            // total decoder rejects — still a clean drop, never a panic.
            Event::OnWidget(_, f) => f(args.first().cloned().unwrap_or_default()),
        }
    }

    /// Resolve a form-submit event. Distinct from [`Self::resolve`] because
    /// the `FormData` map arrives via the form-submission wire path, not the
    /// positional `args` slice.
    #[must_use]
    pub fn resolve_form(&self, ipe_id: &str, event: &str, fd: FormData) -> Option<M> {
        match self.map.get(ipe_id)?.get(event)? {
            Event::OnForm(_, f) => f(fd), // f already returns Option<M> (None on decode failure)
            _ => None,
        }
    }
}

/// Build a [`HandlerIndex`] by walking `root` and collecting every
/// `Attribute::Event` keyed by its element's `ipe-id` + event name.
///
/// Precondition: `assign_ipe_ids` must have been called on `root` first.
/// Elements without a `ipe-id` attribute (shouldn't happen after assignment)
/// are indexed under the empty-string key, which is harmless — no browser
/// event will carry an empty ipe-id.
#[must_use]
pub fn build_index<M: Clone>(root: &Html<M>) -> HandlerIndex<M> {
    let mut map = HashMap::new();
    walk(root, &mut map);
    HandlerIndex { map }
}

/// Walk the view tree iteratively with an explicit heap work-stack.
///
/// Native recursion here would overflow the (uncatchable) thread stack on a
/// deeply nested view — e.g. a comment/thread tree whose nesting depth scales
/// with attacker-influenced data. An explicit `Vec` work-list keeps
/// index-building O(nodes) in heap memory, bounded only by allocation.
fn walk<M: Clone>(root: &Html<M>, map: &mut HashMap<String, HashMap<String, Event<M>>>) {
    let mut stack: Vec<&Html<M>> = vec![root];
    while let Some(n) = stack.pop() {
        if let Html::HElement(_, attrs, kids) = n {
            let id = attrs
                .iter()
                .find_map(|a| match a {
                    Attribute::Attr(k, v) if k == "ipe-id" => Some(v.as_str()),
                    _ => None,
                })
                .unwrap_or_default();

            for a in attrs {
                if let Attribute::EventAttr(e) = a {
                    map.entry(id.to_string())
                        .or_default()
                        .insert(e.name().to_string(), e.clone());
                }
            }

            for c in kids {
                stack.push(c);
            }
        }
    }
}

// ─── render epochs ────────────────────────────────────────────────────────────

/// How many past renders keep their handler index: an event stamped with an
/// epoch older than this many commits refuses instead of resolving.
pub const RENDER_HISTORY_DEPTH: NonZeroUsize = NonZeroUsize::MIN.saturating_add(7);

/// The byte length of the longest well-formed epoch token.
///
/// That is 32 hex characters, a `.`, and at most 20 counter digits.
const EPOCH_TOKEN_MAX_LEN: usize = 53;

/// The number of hex characters that spell an [`Incarnation`].
const INCARNATION_HEX_LEN: usize = 32;

/// The random identity of one render history, minted when it starts.
///
/// The render counter restarts at 1 whenever a history is rebuilt (a store
/// restore, a process restart, a hot reload); the incarnation keeps a token
/// from an earlier history from aliasing a counter of the new one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Incarnation(u128);

impl Incarnation {
    /// An incarnation from 128 bits the caller drew from a CSPRNG.
    #[must_use]
    pub const fn from_random_bits(bits: u128) -> Self {
        Self(bits)
    }
}

/// The server-minted identity of one committed render.
///
/// The client echoes it with every event, and the event resolves only against
/// the handler index of that render.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RenderEpoch {
    incarnation: Incarnation,
    n: NonZeroU64,
}

/// Why a client-echoed epoch token is not a [`RenderEpoch`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EpochParseError {
    /// The token is the empty string.
    Empty,
    /// The token is longer than any well-formed token.
    TooLong,
    /// The token is not 32 characters, a `.`, and a counter.
    BadShape,
    /// The incarnation is not 32 lowercase hex characters.
    BadHex,
    /// The counter is not a canonical decimal in `1..=u64::MAX`.
    BadCounter,
}

impl RenderEpoch {
    /// Parse a client-echoed `"<32 lowercase hex>.<decimal counter>"` token.
    ///
    /// # Errors
    ///
    /// Returns the [`EpochParseError`] naming the first rule the token breaks;
    /// the length ceiling is checked before any other work.
    pub fn parse(token: &str) -> Result<Self, EpochParseError> {
        if token.is_empty() {
            return Err(EpochParseError::Empty);
        }
        if token.len() > EPOCH_TOKEN_MAX_LEN {
            return Err(EpochParseError::TooLong);
        }
        let Some((hex, counter)) = token.split_once('.') else {
            return Err(EpochParseError::BadShape);
        };
        if hex.len() != INCARNATION_HEX_LEN {
            return Err(EpochParseError::BadShape);
        }
        if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(EpochParseError::BadHex);
        }
        let bits = u128::from_str_radix(hex, 16).map_err(|_| EpochParseError::BadHex)?;
        let canonical = !counter.is_empty()
            && !counter.starts_with('0')
            && counter.bytes().all(|b| b.is_ascii_digit());
        if !canonical {
            return Err(EpochParseError::BadCounter);
        }
        let n = counter
            .parse::<u64>()
            .ok()
            .and_then(NonZeroU64::new)
            .ok_or(EpochParseError::BadCounter)?;
        Ok(Self {
            incarnation: Incarnation(bits),
            n,
        })
    }

    /// The wire token, `"<32 lowercase hex>.<decimal counter>"`.
    #[must_use]
    pub fn to_token(&self) -> String {
        format!("{:032x}.{}", self.incarnation.0, self.n)
    }
}

/// The render counter would pass `u64::MAX`; the history must be dropped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpochExhausted;

/// Why an epoch the client echoed has no handler index to resolve against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StaleEpoch {
    /// The epoch belongs to another render history.
    OtherIncarnation,
    /// The epoch is older than the retained history.
    Evicted,
    /// The epoch names a render that has not been committed.
    Future,
}

/// The epochs one [`Rendered::commit`] moved between.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpochStep {
    /// The epoch the client held before the commit.
    pub from: RenderEpoch,
    /// The epoch the commit minted.
    pub to: RenderEpoch,
}

/// The last committed view and the handler indexes of the retained renders.
///
/// The only way to install a new view is [`Self::commit`], which builds its
/// index and mints its epoch together, so no index can change without a new
/// epoch.
pub struct Rendered<M> {
    incarnation: Incarnation,
    current: NonZeroU64,
    last_view: Html<M>,
    history: VecDeque<(NonZeroU64, HandlerIndex<M>)>,
}

impl<M: Clone> Rendered<M> {
    /// The first render of a new history, at counter 1.
    #[must_use]
    pub fn first(incarnation: Incarnation, tree: Html<M>) -> Self {
        Self::starting_at(incarnation, NonZeroU64::MIN, tree)
    }

    fn starting_at(incarnation: Incarnation, n: NonZeroU64, tree: Html<M>) -> Self {
        let mut history = VecDeque::with_capacity(RENDER_HISTORY_DEPTH.get());
        history.push_back((n, build_index(&tree)));
        Self {
            incarnation,
            current: n,
            last_view: tree,
            history,
        }
    }

    /// Install `tree` as the current view under a newly minted epoch.
    ///
    /// The oldest retained index is evicted once the history holds
    /// [`RENDER_HISTORY_DEPTH`] renders.
    ///
    /// # Errors
    ///
    /// Returns [`EpochExhausted`] when the counter would overflow; the view is
    /// left unchanged and the caller drops the whole history.
    pub fn commit(&mut self, tree: Html<M>) -> Result<EpochStep, EpochExhausted> {
        let from = self.epoch();
        let next = self.current.checked_add(1).ok_or(EpochExhausted)?;
        self.history.push_back((next, build_index(&tree)));
        while self.history.len() > RENDER_HISTORY_DEPTH.get() {
            self.history.pop_front();
        }
        self.current = next;
        self.last_view = tree;
        Ok(EpochStep {
            from,
            to: self.epoch(),
        })
    }

    /// The epoch of the current view.
    #[must_use]
    pub const fn epoch(&self) -> RenderEpoch {
        RenderEpoch {
            incarnation: self.incarnation,
            n: self.current,
        }
    }

    /// The current view.
    #[must_use]
    pub const fn last_view(&self) -> &Html<M> {
        &self.last_view
    }

    fn index_at(&self, at: &RenderEpoch) -> Result<&HandlerIndex<M>, StaleEpoch> {
        if at.incarnation != self.incarnation {
            return Err(StaleEpoch::OtherIncarnation);
        }
        if at.n > self.current {
            return Err(StaleEpoch::Future);
        }
        self.history
            .iter()
            .find(|(n, _)| *n == at.n)
            .map(|(_, index)| index)
            .ok_or(StaleEpoch::Evicted)
    }

    /// Resolve a wire event against the handler index of the render `at`.
    ///
    /// # Errors
    ///
    /// Returns the [`StaleEpoch`] variant when `at` names no retained render;
    /// it never falls back to the current index.
    pub fn resolve(
        &self,
        at: &RenderEpoch,
        ipe_id: &str,
        event: &str,
        args: &[String],
    ) -> Result<Option<M>, StaleEpoch> {
        Ok(self.index_at(at)?.resolve(ipe_id, event, args))
    }

    /// Resolve a form submit against the handler index of the render `at`.
    ///
    /// # Errors
    ///
    /// Returns the [`StaleEpoch`] variant when `at` names no retained render;
    /// it never falls back to the current index.
    pub fn resolve_form(
        &self,
        at: &RenderEpoch,
        ipe_id: &str,
        event: &str,
        fd: FormData,
    ) -> Result<Option<M>, StaleEpoch> {
        Ok(self.index_at(at)?.resolve_form(ipe_id, event, fd))
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::assign_ipe_ids;

    #[derive(Clone, Debug, PartialEq)]
    enum Msg {
        Inc,
        Typed(String),
    }

    fn tree() -> Html<Msg> {
        let mut t = Html::HElement(
            "div".into(),
            vec![],
            vec![
                Html::HElement(
                    "button".into(),
                    vec![Attribute::EventAttr(Event::OnMsg("click".into(), Msg::Inc))],
                    vec![],
                ),
                Html::HElement(
                    "input".into(),
                    vec![Attribute::EventAttr(Event::OnString(
                        "input".into(),
                        std::sync::Arc::new(Msg::Typed),
                    ))],
                    vec![],
                ),
            ],
        );
        assign_ipe_ids(&mut t, "r");
        t
    }

    #[test]
    fn resolves_onmsg_and_onstring() {
        let idx = build_index(&tree());
        assert_eq!(idx.resolve("r_0_button", "click", &[]), Some(Msg::Inc));
        assert_eq!(
            idx.resolve("r_1_input", "input", &["hi".into()]),
            Some(Msg::Typed("hi".into()))
        );
        assert_eq!(idx.resolve("r_0_button", "input", &[]), None); // wrong event
        assert_eq!(idx.resolve("nope", "click", &[]), None); // unknown id
    }

    #[test]
    fn resolves_onbool() {
        let mut t = Html::HElement(
            "input".into(),
            vec![Attribute::EventAttr(Event::OnBool(
                "change".into(),
                std::sync::Arc::new(|b| {
                    if b {
                        Msg::Inc
                    } else {
                        Msg::Typed("off".into())
                    }
                }),
            ))],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);
        assert_eq!(idx.resolve("r", "change", &["true".into()]), Some(Msg::Inc));
        assert_eq!(
            idx.resolve("r", "change", &["false".into()]),
            Some(Msg::Typed("off".into()))
        );
    }

    #[test]
    fn resolves_onform() {
        let mut t = Html::HElement(
            "form".into(),
            vec![Attribute::EventAttr(Event::OnForm(
                "submit".into(),
                std::sync::Arc::new(|fd: FormData| {
                    Some(Msg::Typed(fd.get("name").cloned().unwrap_or_default()))
                }),
            ))],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);

        // resolve() returns None for OnForm; resolve_form() dispatches it.
        assert_eq!(idx.resolve("r", "submit", &[]), None);

        let mut fd = FormData::new();
        fd.insert("name".into(), "alice".into());
        assert_eq!(
            idx.resolve_form("r", "submit", fd),
            Some(Msg::Typed("alice".into()))
        );
    }

    // ui_on_submit_ only has a real impl under the `live` or `wasm-client`
    // feature; without it the stub returns NoAttribute and the test would panic.
    #[cfg(any(feature = "web", feature = "wasm-client"))]
    #[test]
    fn ui_on_submit_dispatches_via_onform_not_onraw() {
        use crate::ui::element::Attribute as UiAttribute;

        #[derive(serde::Deserialize, Default, PartialEq, Debug)]
        #[serde(default)]
        struct Creds {
            email: String,
            password: String,
        }

        let attr = crate::ui::helpers::ui_on_submit_(|c: Creds| {
            Msg::Typed(format!("{}:{}", c.email, c.password))
        });
        let html_attr = match attr {
            UiAttribute::AttrEvent(a) => a,
            other => panic!("expected AttrEvent, got {other:?}"),
        };
        let mut t = Html::HElement("form".into(), vec![html_attr], vec![]);
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);

        // Must dispatch via resolve_form (Event::OnForm), NOT resolve()
        // (which returns None for a submit event with no positional args).
        assert_eq!(idx.resolve("r", "submit", &[]), None);

        let mut fd = FormData::new();
        fd.insert("email".into(), "a@b.com".into());
        fd.insert("password".into(), "hunter2".into());
        assert_eq!(
            idx.resolve_form("r", "submit", fd),
            Some(Msg::Typed("a@b.com:hunter2".into()))
        );
    }

    // The `CustomElement.node` up-event: an `OnWidget` handler composes the fail-closed
    // seal decode over the posted string. A payload that decodes to the declared
    // `up` type dispatches the typed msg; one that does NOT is dropped whole
    // (`None`) — no partial value, no panic. This is the runtime proof of the
    // up-event seam's fail-closed contract (WP4, Security #2).
    #[cfg(feature = "json")]
    #[test]
    fn onwidget_up_event_decodes_fail_closed() {
        use crate::seal_codec::{SealLimits, seal_decode_serde};

        // A closed-ADT up type with serde derives (what a seal-legal type emits
        // in a Web program).
        #[derive(serde::Deserialize, Clone, Debug, PartialEq)]
        enum Up {
            Changed(String),
            Saved,
        }

        // The generated `OnWidget` closure shape: decode fail-closed, then map.
        let handler: std::sync::Arc<dyn Fn(String) -> Option<Msg> + Send + Sync> =
            std::sync::Arc::new(|payload: String| {
                match seal_decode_serde::<Up>(&payload, SealLimits::default()) {
                    Ok(Up::Changed(s)) => Some(Msg::Typed(s)),
                    Ok(Up::Saved) => Some(Msg::Inc),
                    Err(_) => None,
                }
            });

        let mut t = Html::HElement(
            "ipe-ce-deadbeef".into(),
            vec![Attribute::EventAttr(Event::OnWidget(
                "ipe-widget".into(),
                handler,
            ))],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);

        // A well-formed `Changed "hi"` payload decodes and dispatches.
        assert_eq!(
            idx.resolve("r", "ipe-widget", &[r#"{"Changed":"hi"}"#.into()]),
            Some(Msg::Typed("hi".into()))
        );
        // The nullary `Saved` variant.
        assert_eq!(
            idx.resolve("r", "ipe-widget", &[r#""Saved""#.into()]),
            Some(Msg::Inc)
        );
        // A payload that does NOT decode to `Up` is DROPPED — no partial value,
        // no panic. (Wrong tag, wrong shape, and a non-JSON string all drop.)
        assert_eq!(
            idx.resolve("r", "ipe-widget", &[r#"{"Bogus":1}"#.into()]),
            None
        );
        assert_eq!(idx.resolve("r", "ipe-widget", &["not json".into()]), None);
        assert_eq!(idx.resolve("r", "ipe-widget", &["{".into()]), None);
        // A missing arg decodes the empty string — still a clean drop.
        assert_eq!(idx.resolve("r", "ipe-widget", &[]), None);
    }

    #[test]
    fn onstring_empty_args_gives_default() {
        let mut t = Html::HElement(
            "input".into(),
            vec![Attribute::EventAttr(Event::OnString(
                "input".into(),
                std::sync::Arc::new(Msg::Typed),
            ))],
            vec![],
        );
        assign_ipe_ids(&mut t, "r");
        let idx = build_index(&t);
        // No args → closure receives ""
        assert_eq!(
            idx.resolve("r", "input", &[]),
            Some(Msg::Typed(String::new()))
        );
    }

    const INCARNATION: Incarnation =
        Incarnation::from_random_bits(0x0123_4567_89ab_cdef_0011_2233_4455_6677);

    /// A view whose first child button dispatches `Typed(label)` on click.
    fn labelled(label: &str) -> Html<Msg> {
        let mut t = Html::HElement(
            "div".into(),
            vec![],
            vec![Html::HElement(
                "button".into(),
                vec![Attribute::EventAttr(Event::OnMsg(
                    "click".into(),
                    Msg::Typed(label.into()),
                ))],
                vec![],
            )],
        );
        assign_ipe_ids(&mut t, "r");
        t
    }

    fn token_with_counter(counter: &str) -> String {
        format!("{:032x}.{counter}", 0xabc_u128)
    }

    #[test]
    #[allow(clippy::expect_used)] // a commit below u64::MAX always mints an epoch
    fn ring_evicts_the_oldest_render_and_keeps_the_rest() {
        let mut r = Rendered::first(INCARNATION, labelled("e1"));
        let e1 = r.epoch();
        let e2 = r.commit(labelled("e2")).expect("second commit").to;
        for k in 3..=RENDER_HISTORY_DEPTH.get() + 1 {
            r.commit(labelled(&format!("e{k}"))).expect("commit");
        }
        assert_eq!(
            r.resolve(&e1, "r_0_button", "click", &[]),
            Err(StaleEpoch::Evicted)
        );
        assert_eq!(
            r.resolve(&e2, "r_0_button", "click", &[]),
            Ok(Some(Msg::Typed("e2".into())))
        );
        let current = r.epoch();
        let latest = format!("e{}", RENDER_HISTORY_DEPTH.get() + 1);
        assert_eq!(
            r.resolve(&current, "r_0_button", "click", &[]),
            Ok(Some(Msg::Typed(latest)))
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // the tokens are built well-formed
    fn future_and_other_incarnation_refuse_with_their_own_variant() {
        let r = Rendered::first(INCARNATION, labelled("only"));
        let current = r.epoch().to_token();
        let (hex, _) = current.split_once('.').expect("a token has a dot");
        let future = RenderEpoch::parse(&format!("{hex}.2")).expect("future token");
        assert_eq!(
            r.resolve(&future, "r_0_button", "click", &[]),
            Err(StaleEpoch::Future)
        );
        let foreign = RenderEpoch::parse(&format!("{:032x}.1", 0xdead_u128)).expect("foreign");
        assert_eq!(
            r.resolve(&foreign, "r_0_button", "click", &[]),
            Err(StaleEpoch::OtherIncarnation)
        );
        assert_eq!(
            r.resolve_form(&foreign, "r_0_button", "submit", FormData::new()),
            Err(StaleEpoch::OtherIncarnation)
        );
    }

    #[test]
    fn epoch_parse_refuses_every_malformed_token_with_its_variant() {
        let hex = format!("{:032x}", 0xabc_u128);
        let cases: Vec<(String, EpochParseError)> = vec![
            (String::new(), EpochParseError::Empty),
            (format!("{}.1", hex.to_uppercase()), EpochParseError::BadHex),
            (format!("{:031x}A.1", 0xabc_u128), EpochParseError::BadHex),
            (format!("{:031x}.1", 0xabc_u128), EpochParseError::BadShape),
            (format!("{hex}0.1"), EpochParseError::BadShape),
            (format!("{hex}1"), EpochParseError::BadShape),
            (token_with_counter("0"), EpochParseError::BadCounter),
            (token_with_counter("01"), EpochParseError::BadCounter),
            (token_with_counter("+1"), EpochParseError::BadCounter),
            (token_with_counter(""), EpochParseError::BadCounter),
            (
                token_with_counter("18446744073709551616"),
                EpochParseError::BadCounter,
            ),
            (
                format!("{hex}.{}", "1".repeat(21)),
                EpochParseError::TooLong,
            ),
        ];
        for (token, want) in cases {
            assert_eq!(RenderEpoch::parse(&token), Err(want), "token {token:?}");
        }
        let longest = token_with_counter("18446744073709551615");
        assert_eq!(longest.len(), EPOCH_TOKEN_MAX_LEN);
        assert!(RenderEpoch::parse(&longest).is_ok());
    }

    #[test]
    #[allow(clippy::expect_used)] // the token was minted by `to_token`
    fn epoch_token_round_trips() {
        let mut r = Rendered::first(INCARNATION, labelled("a"));
        let first = r.epoch();
        assert_eq!(RenderEpoch::parse(&first.to_token()), Ok(first));
        let step = r.commit(labelled("b")).expect("commit");
        assert_eq!(step.from, first);
        assert_eq!(RenderEpoch::parse(&step.to.to_token()), Ok(step.to));
        assert_ne!(step.from, step.to);
    }

    #[test]
    fn commit_at_the_last_counter_is_exhausted_and_keeps_the_view() {
        let mut r = Rendered::starting_at(INCARNATION, NonZeroU64::MAX, labelled("last"));
        let before = r.epoch();
        assert_eq!(r.commit(labelled("past")), Err(EpochExhausted));
        assert_eq!(r.epoch(), before);
        assert_eq!(
            r.resolve(&before, "r_0_button", "click", &[]),
            Ok(Some(Msg::Typed("last".into())))
        );
    }
}
