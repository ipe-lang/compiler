//! The element a render moves keyboard focus to.
//!
//! A control carrying `autofocus` takes focus at page load; across renders it
//! takes focus when it newly appears. [`focus_target`] names that element, and
//! every applier (the Live web client, the browser-WASM sink) focuses only the
//! element it names, under the applier's own rule for which renders may move
//! focus at all.

use crate::html::{Attribute, Html, MAX_HTML_DEPTH};
use std::collections::HashSet;

/// The attribute whose element takes focus when it appears.
const AUTOFOCUS_ATTR: &str = "autofocus";

/// The attribute the stamper writes an element's identity to.
const STAMPED_ID_ATTR: &str = "ipe-id";

/// The `ipe-id` the stamper gave one element of a render.
///
/// Built only from the stamped `ipe-id` of an element the stamper reached, and
/// only when it holds the stamper's alphabet (`[A-Za-z0-9_.:-]`, non-empty), so
/// it quotes inside a CSS attribute selector without escaping.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct StampedId(String);

impl StampedId {
    /// The id as the stamper spelled it.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// The stamped id of an element with attributes `attrs`, when it has a well-formed one.
fn stamped_id<M>(attrs: &[Attribute<M>]) -> Option<&str> {
    attrs.iter().find_map(|attr| match attr {
        Attribute::Attr(name, id) if name == STAMPED_ID_ATTR && is_stamped_spelling(id) => {
            Some(id.as_str())
        }
        _ => None,
    })
}

/// Whether `id` is spelled in the stamper's alphabet.
fn is_stamped_spelling(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

/// Whether an element with attributes `attrs` carries `autofocus`.
fn is_autofocused<M>(attrs: &[Attribute<M>]) -> bool {
    attrs.iter().any(|attr| match attr {
        Attribute::Attr(name, _) | Attribute::BoolAttr(name, true) => {
            name.eq_ignore_ascii_case(AUTOFOCUS_ATTR)
        }
        Attribute::BoolAttr(_, false) | Attribute::EventAttr(_) | Attribute::NoAttr => false,
    })
}

/// The first stamped `autofocus` element of `root`, in document order, for
/// which `take` holds.
///
/// The walk is a heap worklist that descends no deeper than the stamper does
/// ([`MAX_HTML_DEPTH`]), so a node the stamper and the renderer leave out is
/// never a candidate. Text and raw markup are opaque: an `autofocus` or an
/// `ipe-id` spelled inside raw markup is never read.
fn first_autofocused<'a, M>(
    root: &'a Html<M>,
    mut take: impl FnMut(&'a str) -> bool,
) -> Option<&'a str> {
    let mut pending: Vec<(&'a Html<M>, usize)> = vec![(root, 0)];
    while let Some((node, depth)) = pending.pop() {
        if depth >= MAX_HTML_DEPTH {
            continue;
        }
        let Html::HElement(_, attrs, kids) = node else {
            continue;
        };
        if is_autofocused(attrs)
            && let Some(id) = stamped_id(attrs)
            && take(id)
        {
            return Some(id);
        }
        pending.extend(kids.iter().rev().map(|kid| (kid, depth + 1)));
    }
    None
}

/// The element of the stamped render `new` that takes focus when `new`
/// replaces the stamped render `old` on screen.
///
/// That is the first element of `new`, in document order, that carries
/// `autofocus` and whose `ipe-id` carried no `autofocus` in `old`; `None` when
/// there is none. The answer depends only on the two renders, never on how the
/// patches between them are split: an element re-rendered with the
/// `autofocus` it already had is never a target, so a render while the user
/// types into it never refocuses it.
#[must_use]
pub fn focus_target<M>(old: &Html<M>, new: &Html<M>) -> Option<StampedId> {
    let mut before = HashSet::new();
    first_autofocused(old, |id| {
        before.insert(id);
        false
    });
    first_autofocused(new, |id| !before.contains(id)).map(|id| StampedId(id.to_owned()))
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::assign_ipe_ids;
    use crate::dom::diff::diff;
    use crate::html::RenderCtx;

    fn el(tag: &str, attrs: Vec<Attribute<()>>, kids: Vec<Html<()>>) -> Html<()> {
        Html::HElement(tag.to_owned(), attrs, kids)
    }

    fn autofocus() -> Attribute<()> {
        Attribute::Attr(AUTOFOCUS_ATTR.to_owned(), String::new())
    }

    fn named(name: &str) -> Attribute<()> {
        Attribute::Attr("name".to_owned(), name.to_owned())
    }

    fn stamped(mut tree: Html<()>) -> Html<()> {
        assign_ipe_ids(&mut tree, "r");
        tree
    }

    /// A panel holding the given controls, below a heading.
    fn page(controls: Vec<Html<()>>) -> Html<()> {
        stamped(el(
            "main",
            vec![autofocus()],
            vec![
                el("h1", vec![], vec![Html::HText("t".to_owned())]),
                el("section", vec![], controls),
            ],
        ))
    }

    fn input(attrs: Vec<Attribute<()>>) -> Html<()> {
        el("input", attrs, vec![])
    }

    /// The stamped id of the first element of `tree` named `name`.
    fn id_named(tree: &Html<()>, name: &str) -> Option<String> {
        let mut pending = vec![tree];
        while let Some(node) = pending.pop() {
            if let Html::HElement(_, attrs, kids) = node {
                let is_named = attrs
                    .iter()
                    .any(|a| matches!(a, Attribute::Attr(k, v) if k == "name" && v == name));
                if is_named {
                    return stamped_id(attrs).map(str::to_owned);
                }
                pending.extend(kids.iter().rev());
            }
        }
        None
    }

    fn target(old: &Html<()>, new: &Html<()>) -> Option<String> {
        focus_target(old, new).map(|id| id.as_str().to_owned())
    }

    #[test]
    fn a_newly_appearing_autofocus_element_is_the_target() {
        let old = page(vec![]);
        let new = page(vec![input(vec![named("reason"), autofocus()])]);
        let want = id_named(&new, "reason");
        assert!(want.is_some(), "the input is stamped");
        assert_eq!(target(&old, &new), want);
    }

    #[test]
    fn an_element_already_autofocused_before_is_never_the_target() {
        let old = page(vec![input(vec![named("reason"), autofocus()])]);
        let new = page(vec![input(vec![
            named("reason"),
            autofocus(),
            Attribute::Attr("value".to_owned(), "abc".to_owned()),
        ])]);
        assert_eq!(
            target(&old, &new),
            None,
            "a re-render while typing never refocuses"
        );
        assert_eq!(target(&new, &new), None);
    }

    #[test]
    fn autofocus_moved_to_another_element_targets_the_new_one() {
        let old = page(vec![
            input(vec![named("a"), autofocus()]),
            input(vec![named("b")]),
        ]);
        let new = page(vec![
            input(vec![named("a")]),
            input(vec![named("b"), autofocus()]),
        ]);
        let want = id_named(&new, "b");
        assert!(want.is_some(), "the second input is stamped");
        assert_eq!(target(&old, &new), want);
    }

    #[test]
    fn of_two_new_targets_the_first_in_document_order_wins() {
        let old = page(vec![]);
        let new = page(vec![
            el(
                "div",
                vec![],
                vec![input(vec![named("first"), autofocus()])],
            ),
            input(vec![named("second"), autofocus()]),
        ]);
        let want = id_named(&new, "first");
        assert!(want.is_some(), "the nested input is stamped");
        assert_eq!(target(&old, &new), want);
    }

    #[test]
    fn autofocus_inside_raw_markup_is_never_a_target() {
        let old = page(vec![]);
        let new = page(vec![Html::HRaw(
            "<input autofocus ipe-id=\"r_1_section_0_input\">".to_owned(),
        )]);
        assert_eq!(target(&old, &new), None);
    }

    #[test]
    fn the_target_does_not_depend_on_how_the_patches_are_split() {
        // The same new render, reached once by an in-place attribute patch on a
        // kept input and once by replacing the section's children.
        let new = page(vec![input(vec![named("reason"), autofocus()])]);
        let in_place_from = page(vec![input(vec![named("reason")])]);
        let replaced_from = page(vec![el("p", vec![], vec![])]);
        let in_place = diff(&in_place_from, &new, &RenderCtx::Unstamped);
        let replaced = diff(&replaced_from, &new, &RenderCtx::Unstamped);
        assert!(
            in_place.iter().all(|p| p.html.is_none())
                && in_place.iter().any(|p| !p.attrs.is_empty()),
            "the first change is an attribute patch: {in_place:?}"
        );
        assert!(
            replaced.iter().any(|p| p.html.is_some()),
            "the second change replaces markup: {replaced:?}"
        );
        let want = id_named(&new, "reason");
        assert!(want.is_some(), "the input is stamped");
        assert_eq!(target(&in_place_from, &new), want);
        assert_eq!(target(&replaced_from, &new), want);
    }

    #[test]
    fn a_false_boolean_autofocus_is_never_a_target() {
        let old = page(vec![]);
        let new = page(vec![input(vec![
            named("reason"),
            Attribute::BoolAttr(AUTOFOCUS_ATTR.to_owned(), false),
        ])]);
        assert_eq!(target(&old, &new), None);
        let on = page(vec![input(vec![
            named("reason"),
            Attribute::BoolAttr(AUTOFOCUS_ATTR.to_owned(), true),
        ])]);
        assert_eq!(target(&old, &on), id_named(&on, "reason"));
    }

    #[test]
    fn an_element_the_stamper_never_reached_is_never_a_target() {
        // An unstamped tree carries no identity to focus by.
        let bare = el(
            "main",
            vec![],
            vec![input(vec![named("reason"), autofocus()])],
        );
        assert_eq!(target(&el("main", vec![], vec![]), &bare), None);
        // An element past the stamping depth is neither stamped nor rendered.
        let mut deep = input(vec![named("deep"), autofocus()]);
        for _ in 0..MAX_HTML_DEPTH {
            deep = el("div", vec![], vec![deep]);
        }
        let deep = stamped(deep);
        assert_eq!(target(&page(vec![]), &deep), None);
        // One level shallower, the same element is stamped and is the target.
        let mut reached = input(vec![named("deep"), autofocus()]);
        for _ in 1..MAX_HTML_DEPTH {
            reached = el("div", vec![], vec![reached]);
        }
        let reached = stamped(reached);
        assert!(target(&page(vec![]), &reached).is_some());
    }

    #[test]
    fn an_id_outside_the_stamper_alphabet_is_never_a_target() {
        let forged = el(
            "input",
            vec![
                autofocus(),
                Attribute::Attr(STAMPED_ID_ATTR.to_owned(), "r\"] , *[x=\"".to_owned()),
            ],
            vec![],
        );
        assert_eq!(target(&el("main", vec![], vec![]), &forged), None);
    }
}
