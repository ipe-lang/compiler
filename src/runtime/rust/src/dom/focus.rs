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
    fn chain_past_the_depth_bound_records_nothing() {
        let stamped = |n: usize| (0..n).map(|i| (Some(format!("n{i}")), "div".to_string()));
        let at_bound = chain_from_ancestry(stamped(FOCUS_CHAIN_MAX));
        assert_eq!(at_bound.as_ref().map(Vec::len), Some(FOCUS_CHAIN_MAX));
        assert_eq!(
            chain_from_ancestry(stamped(FOCUS_CHAIN_MAX.saturating_add(1))),
            None
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
