//! Focus keep: where focus lands after a frame left nothing holding it.
//!
//! Each runtime brackets its one frame commit with this rule. Before the frame
//! it records the view chain of the focused node: the `ipe-id` and tag of each
//! element from the mount container's child down to the focused node, cut at
//! the first element with no `ipe-id`, and recorded only when the first one
//! carries one. After the frame, when nothing holds focus, focus goes to the
//! deepest node of that chain that still stands in the view and takes focus,
//! else to the mount container, else it stays on the body. The diff's choice
//! of patch (a subtree swap, an attribute written in place) never changes
//! where focus ends. `client.js` mirrors this rule; a scan test pins its
//! bracket and its constants against this module.

use crate::html::{Attribute, Html, MAX_HTML_DEPTH, STAMPED_ID_ATTR};

/// The deepest view chain recorded; a focused node nested deeper records none.
pub const FOCUS_CHAIN_MAX: usize = MAX_HTML_DEPTH;

/// The window events that count a focus move: focus leaving the document.
///
/// Only an event whose target is the window itself counts, never an element's
/// own `blur` bubbling through a capture listener.
pub const WINDOW_FOCUS_MOVES: [&str; 1] = ["blur"];

/// The event whose dispatch answers a focus drop the browser makes after S.
///
/// A node a patch made unfocusable may lose focus in a task the browser posts
/// after any number of frames, so the drop check is keyed on this event, never
/// on a frame or timer count. `client.js` mirrors it as
/// `__IPE_FOCUS_DROP_EVENT`.
pub const FOCUS_DROP_EVENT: &str = "focusout";

/// Whether a frame arms the drop check after its synchronous check S.
///
/// Armed only when focus is held, the held node is the node focused before
/// the frame, and either some patch of the frame targets an `ipe-id` on the
/// recorded chain or the check is `carried` (see [`carries`]): with neither,
/// no frame can have dropped focus, so a later drop is no frame's and is never
/// undone.
#[must_use]
pub fn arms(
    chain: &[FocusLink],
    patched: impl Fn(&str) -> bool,
    held_unchanged: bool,
    focus_held: bool,
    carried: bool,
) -> bool {
    focus_held && held_unchanged && (carried || chain.iter().any(|link| patched(&link.id)))
}

/// Whether the drop check an earlier frame armed carries into this frame.
///
/// It carries when it was armed on the node focused before this frame and no
/// focus move was counted since it was recorded. The browser's drop for a node
/// a patch made unfocusable may come after any number of later frames, so a
/// frame that does not touch the chain hands the armed check on rather than
/// expiring it: whether the drop is answered never depends on an unrelated
/// frame landing first.
#[must_use]
pub const fn carries(armed_on_held: bool, no_move_since: bool) -> bool {
    armed_on_held && no_move_since
}

/// Whether a drop event answers the armed check.
///
/// Only a drop on the held node itself to nothing (no `relatedTarget`): a move
/// to another node of the document is the user's or a script's.
#[must_use]
pub const fn drop_answers(target_is_held: bool, related_is_null: bool) -> bool {
    target_is_held && related_is_null
}

/// One element of a view chain: its stamped identity and its tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocusLink {
    pub id: String,
    pub tag: String,
}

/// An element the landing walks: its element children, `ipe-id` and tag.
pub trait FocusNode: Sized {
    /// The element children, in document order.
    fn element_children(&self) -> Vec<Self>;
    /// The `ipe-id` the element carries, if any.
    fn stamped_id(&self) -> Option<String>;
    /// The tag, spelled as the runtime that recorded the chain reads it.
    fn tag(&self) -> String;
}

/// The view chain of a focused node, from its ancestry read upward.
///
/// `upward` yields `(ipe-id, tag)` from the focused node up to the mount
/// container's child. The chain runs downward and stops before the first link
/// with no `ipe-id`. It is `None` when that first link is the top one (focus
/// outside the stamped view) or when the ancestry is deeper than
/// [`FOCUS_CHAIN_MAX`]; `upward` is read no further than one past that bound.
pub fn chain_from_ancestry<I>(upward: I) -> Option<Vec<FocusLink>>
where
    I: IntoIterator<Item = (Option<String>, String)>,
{
    let mut links: Vec<(Option<String>, String)> = upward
        .into_iter()
        .take(FOCUS_CHAIN_MAX.saturating_add(1))
        .collect();
    if links.len() > FOCUS_CHAIN_MAX {
        return None;
    }
    links.reverse();
    let chain: Vec<FocusLink> = links
        .into_iter()
        .map_while(|(id, tag)| id.map(|id| FocusLink { id, tag }))
        .collect();
    (!chain.is_empty()).then_some(chain)
}

/// The surviving nodes of `chain` below `root`, deepest first.
///
/// At each depth the ONE element child whose `ipe-id` and tag both equal the
/// link is taken; no match, or more than one, ends the descent. An equal id
/// under another tag or another chain never matches.
pub fn landing<N: FocusNode>(root: &N, chain: &[FocusLink]) -> Vec<N> {
    let mut found: Vec<N> = Vec::new();
    for link in chain.iter().take(FOCUS_CHAIN_MAX) {
        let children = found
            .last()
            .map_or_else(|| root.element_children(), FocusNode::element_children);
        let mut matching = children.into_iter().filter(|child| {
            child.stamped_id().as_deref() == Some(link.id.as_str()) && child.tag() == link.tag
        });
        let (Some(only), None) = (matching.next(), matching.next()) else {
            break;
        };
        found.push(only);
    }
    found.reverse();
    found
}

/// What a frame recorded as it committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recorded {
    /// The count of the user's focus moves when the frame committed.
    pub focus_epoch: u64,
    /// The frame's own token.
    pub frame: u64,
}

/// Where focus stands at a check point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    /// Some element other than the body holds focus.
    pub focus_held: bool,
    /// The count of the user's focus moves now.
    pub focus_epoch: u64,
    /// The token of the newest frame committed.
    pub newest_frame: u64,
    /// The runtime is moving focus itself.
    pub runtime_focusing: bool,
}

/// Whether the focus keep may put focus back for the frame `rec`.
///
/// Refused when something holds focus, the user moved focus since the frame
/// committed, a newer frame owns the check, or the runtime is already moving
/// focus.
#[must_use]
pub const fn settle_due(rec: &Recorded, now: &Now) -> bool {
    !now.focus_held
        && now.focus_epoch == rec.focus_epoch
        && now.newest_frame == rec.frame
        && !now.runtime_focusing
}

impl<M> FocusNode for &Html<M> {
    fn element_children(&self) -> Vec<Self> {
        match *self {
            Html::HElement(_, _, kids) => kids
                .iter()
                .filter(|kid| matches!(kid, Html::HElement(..)))
                .collect(),
            Html::HText(_) | Html::HRaw(_) => Vec::new(),
        }
    }

    fn stamped_id(&self) -> Option<String> {
        match *self {
            Html::HElement(_, attrs, _) => attrs.iter().rev().find_map(|a| match a {
                Attribute::Attr(k, v) if k == STAMPED_ID_ATTR => Some(v.clone()),
                _ => None,
            }),
            Html::HText(_) | Html::HRaw(_) => None,
        }
    }

    fn tag(&self) -> String {
        match *self {
            Html::HElement(tag, _, _) => tag.clone(),
            Html::HText(_) | Html::HRaw(_) => String::new(),
        }
    }
}

#[cfg(feature = "wasm-client")]
impl FocusNode for web_sys::Element {
    fn element_children(&self) -> Vec<Self> {
        std::iter::successors(
            self.first_element_child(),
            web_sys::Element::next_element_sibling,
        )
        .collect()
    }

    fn stamped_id(&self) -> Option<String> {
        self.get_attribute(STAMPED_ID_ATTR)
    }

    fn tag(&self) -> String {
        self.tag_name()
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    fn el(tag: &str, id: Option<&str>, kids: Vec<Html<()>>) -> Html<()> {
        let attrs = id.map_or_else(Vec::new, |id| {
            vec![Attribute::Attr(STAMPED_ID_ATTR.into(), id.into())]
        });
        Html::HElement(tag.into(), attrs, kids)
    }

    fn link(id: &str, tag: &str) -> FocusLink {
        FocusLink {
            id: id.into(),
            tag: tag.into(),
        }
    }

    fn ids(nodes: &[&Html<()>]) -> Vec<Option<String>> {
        nodes.iter().map(FocusNode::stamped_id).collect()
    }

    #[test]
    fn landing_takes_the_deepest_surviving_chain_node() {
        // The focused button moved from the first slot to the second: the
        // chain still names it, an index path would land on its sibling.
        let root = el(
            "body",
            None,
            vec![el(
                "div",
                Some("r"),
                vec![
                    el("p", Some("r_0_p"), vec![]),
                    el("button", Some("r_1_button:k"), vec![]),
                ],
            )],
        );
        let chain = [link("r", "div"), link("r_1_button:k", "button")];
        assert_eq!(
            ids(&landing(&&root, &chain)),
            [Some("r_1_button:k".into()), Some("r".into())]
        );
        let gone = [link("r", "div"), link("r_1_button:other", "button")];
        assert_eq!(ids(&landing(&&root, &gone)), [Some("r".into())]);
    }

    #[test]
    fn landing_never_matches_an_equal_id_under_another_tag_or_chain() {
        let root = el(
            "body",
            None,
            vec![el(
                "div",
                Some("r"),
                vec![el("section", Some("r_0_x"), vec![])],
            )],
        );
        let other_tag = [link("r", "div"), link("r_0_x", "button")];
        assert_eq!(ids(&landing(&&root, &other_tag)), [Some("r".into())]);
        let other_chain = [link("q", "div"), link("r_0_x", "section")];
        assert!(landing(&&root, &other_chain).is_empty());
    }

    #[test]
    fn landing_stops_at_a_duplicate_or_unstamped_link() {
        let twin = el(
            "body",
            None,
            vec![el(
                "div",
                Some("r"),
                vec![
                    el(
                        "div",
                        Some("r_0_div"),
                        vec![el("a", Some("r_0_div_0_a"), vec![])],
                    ),
                    el("div", Some("r_0_div"), vec![]),
                ],
            )],
        );
        let chain = [
            link("r", "div"),
            link("r_0_div", "div"),
            link("r_0_div_0_a", "a"),
        ];
        assert_eq!(ids(&landing(&&twin, &chain)), [Some("r".into())]);
        let raw = el(
            "body",
            None,
            vec![el("div", Some("r"), vec![el("div", None, vec![])])],
        );
        let into_raw = [link("r", "div"), link("", "div")];
        assert_eq!(ids(&landing(&&raw, &into_raw)), [Some("r".into())]);
    }

    #[test]
    fn settle_refuses_focus_held_epoch_moved_stale_token_or_runtime_focusing() {
        let rec = Recorded {
            focus_epoch: 4,
            frame: 9,
        };
        let due = Now {
            focus_held: false,
            focus_epoch: 4,
            newest_frame: 9,
            runtime_focusing: false,
        };
        assert!(settle_due(&rec, &due));
        let held = Now {
            focus_held: true,
            ..due
        };
        let moved = Now {
            focus_epoch: 5,
            ..due
        };
        let stale = Now {
            newest_frame: 10,
            ..due
        };
        let focusing = Now {
            runtime_focusing: true,
            ..due
        };
        for refused in [held, moved, stale, focusing] {
            assert!(!settle_due(&rec, &refused), "{refused:?}");
        }
    }

    #[test]
    fn arms_needs_a_patch_on_the_chain() {
        let chain = [link("a", "div"), link("b", "button")];
        assert!(!arms(&chain, |id| id == "c", true, true, false));
        assert!(arms(&chain, |id| id == "a", true, true, false));
        assert!(arms(&chain, |id| id == "b", true, true, false));
        assert!(!arms(&[], |_| true, true, true, false));
    }

    #[test]
    fn arms_refuses_a_moved_or_lost_focus() {
        let chain = [link("a", "div")];
        for carried in [false, true] {
            assert!(!arms(&chain, |_| true, false, true, carried));
            assert!(!arms(&chain, |_| true, true, false, carried));
            assert!(!arms(&chain, |_| true, false, false, carried));
        }
    }

    /// A frame that touches nothing on the chain keeps an earlier frame's
    /// armed check alive, so a drop the browser makes after it still lands.
    #[test]
    fn arms_carries_an_armed_check_through_an_untouched_frame() {
        let chain = [link("a", "div"), link("b", "button")];
        assert!(arms(&chain, |id| id == "c", true, true, true));
        assert!(arms(&chain, |_| false, true, true, true));
    }

    #[test]
    fn carries_only_on_the_same_node_with_no_move_since() {
        assert!(carries(true, true));
        assert!(!carries(true, false));
        assert!(!carries(false, true));
        assert!(!carries(false, false));
    }

    #[test]
    fn drop_answers_only_a_drop_to_nothing_on_the_held_node() {
        assert!(drop_answers(true, true));
        assert!(!drop_answers(true, false));
        assert!(!drop_answers(false, true));
        assert!(!drop_answers(false, false));
    }

    /// The body of the first `fn {name}(` in `src`, up to its closing brace at
    /// column 0; empty when absent.
    fn rust_fn<'a>(src: &'a str, name: &str) -> &'a str {
        src.split_once(&format!("fn {name}("))
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map_or("", |(body, _)| body)
    }

    /// The wasm client answers a focus drop by the drop event alone.
    ///
    /// No deferred check counts animation frames, the frame commit clears the
    /// pending check before it applies, the drop listener installs once beside
    /// the focus-move listeners, and the check runs in a posted task: a
    /// microtask would run between `focusout` and `focusin` and take back a
    /// Tab to the next control.
    #[test]
    fn wasm_keys_the_drop_check_on_the_drop_event() {
        let src = include_str!("../wasm/mod.rs");
        let code = src
            .split_once("\n#[cfg(test)]\nmod tests {")
            .map_or(src, |(code, _)| code);
        assert!(
            !code.contains("settle_later"),
            "no frame-count deferred check"
        );
        let frame = rust_fn(code, "apply_frame");
        let cleared = frame.find("let earlier = FOCUS_PENDING.take();");
        let applied = frame.find("apply(document, patches);");
        assert!(
            matches!((cleared, applied), (Some(c), Some(a)) if c < a)
                && !frame.contains("request_animation_frame"),
            "`apply_frame` clears the pending check before it applies and counts no frames: {cleared:?} {applied:?}"
        );
        assert!(
            frame.contains("carries(") && frame.contains("earlier"),
            "`apply_frame` hands an earlier frame's armed check on, never drops it unanswered"
        );
        let install = rust_fn(code, "install_focus_epoch");
        let guard = install.find("if FOCUS_EPOCH_INSTALLED.with(Cell::get) {");
        let drop = install.find("FOCUS_DROP_EVENT");
        assert!(
            matches!((guard, drop), (Some(g), Some(d)) if g < d),
            "the drop listener installs under `FOCUS_EPOCH_INSTALLED`: {guard:?} {drop:?}"
        );
        let answer = rust_fn(code, "on_focus_drop");
        assert!(
            answer.contains("set_timeout_with_callback_and_timeout_and_arguments_0")
                && answer.contains("drop_answers(")
                && !answer.contains("queue_microtask")
                && !answer.contains("Promise"),
            "the drop check runs in a posted task, never a microtask"
        );
    }

    #[test]
    fn chain_past_the_depth_bound_records_nothing() {
        let stamped = |n: usize| (0..n).map(|i| (Some(format!("n{i}")), "div".to_string()));
        let at_bound = chain_from_ancestry(stamped(FOCUS_CHAIN_MAX));
        assert_eq!(at_bound.as_ref().map(Vec::len), Some(FOCUS_CHAIN_MAX));
        assert_eq!(
            chain_from_ancestry(stamped(FOCUS_CHAIN_MAX.saturating_add(1))),
            None
        );
    }

    /// The wasm client installs a frame's view (handler index and tree) before
    /// it applies the frame, through the one committer.
    ///
    /// The focus keep and the addressed focus move raise `focus`/`focusin`
    /// synchronously inside the commit; resolved against the replaced view,
    /// such an event would send the Msg the previous render bound to that id.
    #[test]
    fn wasm_commits_a_frame_after_its_view_is_installed() {
        let src = include_str!("../wasm/mod.rs");
        assert_eq!(
            src.matches("commit_frame(&").count(),
            1,
            "`commit_view` is the one caller of `commit_frame`"
        );
        let body = src
            .split_once("fn commit_view<")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body)
            .unwrap_or_default();
        let at = |needle: &str| body.find(needle);
        let (index, tree, commit) = (
            at("*app.index.borrow_mut() = build_index(&new_tree);"),
            at("*app.tree.borrow_mut() = new_tree;"),
            at("commit_frame(&patches"),
        );
        assert!(
            matches!((index, tree, commit), (Some(i), Some(t), Some(c)) if i < c && t < c),
            "the view is installed before the frame applies: {index:?} {tree:?} {commit:?}"
        );
    }

    #[test]
    fn a_chain_cuts_at_raw_markup_and_needs_a_stamped_top() {
        // Upward: the focused raw node, its stamped host, the view root.
        let upward = [
            (None, "SPAN".to_string()),
            (Some("r_0_div".to_string()), "DIV".to_string()),
            (Some("r".to_string()), "DIV".to_string()),
        ];
        assert_eq!(
            chain_from_ancestry(upward),
            Some(vec![link("r", "DIV"), link("r_0_div", "DIV")])
        );
        let overlay = [
            (Some("x".to_string()), "BUTTON".to_string()),
            (None, "DIV".to_string()),
        ];
        assert_eq!(chain_from_ancestry(overlay), None);
    }
}
