//! `Ipe.Ui.Keyed` kernel helpers — ipe-key diff identity.
//!
//! Each `(key, child)` pair has the key attached to the child element as a
//! `ipe-key` attribute.  The ipe-id stamper (`assign_ipe_ids_depth` /
//! `ipe_id_key` in `html.rs`) appends that key to the child's positional ipe-id,
//! so two items at the same position with different keys are different nodes and
//! the diff replaces their parent's children instead of patching one item in
//! place under the other's identity.  Without the attribute, same-tag items at
//! one position share an identity, and the diff patches one into the other.
//!
//! Sanctioned divergence §B-Keyed: ipe-key-stamp approach vs the reference VNode-key differ.
//!
//! Every function carries a trailing underscore per the `naming.rs` convention.

use super::element::{Attribute, Description, Element};
use super::helpers::{ui_column_, ui_row_};

/// Attach a `ipe-key` attribute to a child element so the ipe-id stamper can
/// stabilise its identity across list reorders.
///
/// `Node`/`TaggedNode` carry an attribute list; the key is prepended there.
/// `Text`/`Empty`/`Raw` have no attribute slot, so they are wrapped in a keyed
/// `el` (`Node` with one child) — the wrapper carries the key and the child
/// retains its own identity inside it.  This matches the /// keyed-wrapper behaviour.
fn attach_key<M: Clone>(key: String, mut child: Element<M>) -> Element<M> {
    let key_attr = Attribute::AttrAttribute("ipe-key".to_owned(), key.clone());
    // `Element` owns an iterative destructor, so an attributed node's list is
    // reached through a mutable borrow rather than moved out and rebuilt.
    match &mut child {
        Element::Node(_, attrs, _) | Element::TaggedNode(_, _, attrs, _) => {
            attrs.insert(0, key_attr);
            child
        }
        Element::Empty | Element::Text(_) | Element::Raw(_) | Element::Cells(_) => {
            // Wrap Text/Empty/Raw in a plain el so the key has a DOM node to
            // live on — identical to how `Ui.el [] child` renders.
            Element::Node(Description::NoDescription, vec![key_attr], vec![child])
        }
    }
}

/// `Keyed.column : List (Attribute msg) -> List (String, Element msg) -> Element msg`
///
/// Attaches each key as a `ipe-key` attribute on its child, then forwards to
/// `ui_column_`.  The `ipe-key` is consumed by `ipe_id_key` /
/// `assign_ipe_ids_depth` to produce stable ipe-ids across reorder.
#[must_use]
pub fn keyed_column_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    children: Vec<(String, Element<M>)>,
) -> Element<M> {
    ui_column_(
        attrs,
        children
            .into_iter()
            .map(|(k, e)| attach_key(k, e))
            .collect(),
    )
}

/// `Keyed.row : List (Attribute msg) -> List (String, Element msg) -> Element msg`
///
/// Attaches each key as a `ipe-key` attribute on its child, then forwards to
/// `ui_row_`.
#[must_use]
pub fn keyed_row_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    children: Vec<(String, Element<M>)>,
) -> Element<M> {
    ui_row_(
        attrs,
        children
            .into_iter()
            .map(|(k, e)| attach_key(k, e))
            .collect(),
    )
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::ui::element::{Attribute, Element};

    fn has_ipe_key(attrs: &[Attribute<()>], expected: &str) -> bool {
        attrs.iter().any(|a| {
            matches!(a, Attribute::AttrAttribute(k, v)
                if k == "ipe-key" && v == expected)
        })
    }

    /// Each child in a `keyed_column_` carries the `ipe-key` attribute.
    #[test]
    fn keyed_column_attaches_ipe_key_to_node_children() {
        let children = vec![
            (
                "alpha".to_string(),
                Element::Node(
                    crate::ui::element::Description::NoDescription,
                    vec![],
                    vec![],
                ),
            ),
            (
                "beta".to_string(),
                Element::Node(
                    crate::ui::element::Description::NoDescription,
                    vec![],
                    vec![],
                ),
            ),
        ];
        let mut col = keyed_column_(vec![], children);
        let kids = match &mut col {
            Element::Node(_, _, kids) => std::mem::take(kids),
            other => panic!("expected Node, got {other:?}"),
        };
        assert_eq!(kids.len(), 2);
        for (kid, key) in kids.iter().zip(["alpha", "beta"]) {
            match kid {
                Element::Node(_, attrs, _) => {
                    assert!(
                        has_ipe_key(attrs, key),
                        "expected ipe-key={key} on child, got {attrs:?}"
                    );
                }
                other => panic!("expected Node child, got {other:?}"),
            }
        }
    }

    /// `Text` children (no attribute slot) are wrapped in a keyed `el`.
    #[test]
    fn keyed_column_wraps_text_child_with_ipe_key() {
        let children = vec![("wrap-me".to_string(), Element::Text("hello".to_string()))];
        let mut col = keyed_column_(vec![], children);
        let kids = match &mut col {
            Element::Node(_, _, kids) => std::mem::take(kids),
            other => panic!("expected Node, got {other:?}"),
        };
        assert_eq!(kids.len(), 1);
        match &kids[0] {
            Element::Node(_, attrs, inner) => {
                assert!(
                    has_ipe_key(attrs, "wrap-me"),
                    "wrapper must carry ipe-key, got {attrs:?}"
                );
                assert_eq!(inner.len(), 1, "wrapper must have exactly one child");
                assert!(
                    matches!(&inner[0], Element::Text(s) if s == "hello"),
                    "inner child must be the original Text"
                );
            }
            other => panic!("expected wrapper Node, got {other:?}"),
        }
    }

    /// `keyed_row_` also attaches `ipe-key` attributes.
    #[test]
    fn keyed_row_attaches_ipe_key() {
        let children = vec![(
            "row-key".to_string(),
            Element::Node(
                crate::ui::element::Description::NoDescription,
                vec![],
                vec![],
            ),
        )];
        let mut row = keyed_row_(vec![], children);
        // The outer row Node has the `__row` style marker; its children carry keys.
        let kids = match &mut row {
            Element::Node(_, _, kids) => std::mem::take(kids),
            other => panic!("expected Node, got {other:?}"),
        };
        assert_eq!(kids.len(), 1);
        match &kids[0] {
            Element::Node(_, attrs, _) => {
                assert!(
                    has_ipe_key(attrs, "row-key"),
                    "expected ipe-key on row child, got {attrs:?}"
                );
            }
            other => panic!("expected Node child, got {other:?}"),
        }
    }
}
