//! Node keep: which live node a children swap keeps in place of the parsed one.
//!
//! A `Patch.html` swap replaces an element's children with freshly parsed
//! markup. A live child whose identity the new markup repeats — the same
//! non-empty `ipe-id` and the same HTML tag, below a parent that was itself
//! kept or is the swap's target — stays the same DOM node: its attributes are
//! written to the new ones in place and its children are swapped by this same
//! rule. A kept node never leaves the document unless the new order moves it,
//! so a field's typed value, selection and input-method composition survive.
//!
//! A form field (an `input`, `textarea` or `select`) is kept only while it
//! holds focus or its new markup leaves it uncontrolled: no [`CONTROLLED_ATTR`]
//! marker, no authority attribute, no `textarea` text, no `option[selected]`.
//! The render sink writes the marker on every field whose view names an
//! authority attribute, true or false, so a view-owned field whose value is
//! off or empty still reads as controlled. A controlled field that does not
//! hold focus is rebuilt from the new markup, so the program's value wins. A
//! kept field keeps its authority attributes and its `textarea` text, which
//! the user owns. `client.js` runs the same field rule when it splices live
//! fields into its swap; `tests/event_answer_single_table.rs` pins its tables to these.

/// A form field whose value the user edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// An `input`.
    Input,
    /// A `textarea`, whose text is its value.
    Textarea,
    /// A `select`, whose `option[selected]` is its value.
    Select,
}

impl Field {
    /// Every field, in [`FIELD_TAGS`] order.
    pub const ALL: [Self; 3] = [Self::Input, Self::Textarea, Self::Select];

    /// The field's lowercase tag name.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Textarea => "textarea",
            Self::Select => "select",
        }
    }

    /// The field an element `tag` names, ASCII case folded; `None` for any
    /// other element.
    #[must_use]
    pub fn parse(tag: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|field| field.tag().eq_ignore_ascii_case(tag))
    }
}

/// The form fields' lowercase tag names, as `client.js` lists them.
pub const FIELD_TAGS: [&str; 3] = [
    Field::Input.tag(),
    Field::Textarea.tag(),
    Field::Select.tag(),
];

/// The attributes that carry a field's value, which a kept field keeps.
pub const AUTHORITY_ATTRS: [&str; 3] = ["value", "checked", "selected"];

/// The reserved marker the render sink writes on a field whose view owns its
/// value.
///
/// It is written whenever the view names an authority attribute, whatever that
/// attribute's value: an unticked box carries the marker and no `checked`.
pub const CONTROLLED_ATTR: &str = "ipe-controlled";

/// The elements a swap always rebuilds: a frame keeps the sandbox its document
/// loaded under whatever its attribute now says, and a template's children
/// live in its inert content, out of the walk.
pub const REBUILT_TAGS: [&str; 5] = ["iframe", "embed", "object", "frame", "template"];

/// Whether `name` is one of [`AUTHORITY_ATTRS`].
#[must_use]
pub fn is_authority_attr(name: &str) -> bool {
    AUTHORITY_ATTRS
        .iter()
        .any(|attr| attr.eq_ignore_ascii_case(name))
}

/// Whether a field's new markup carries [`CONTROLLED_ATTR`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// The markup carries the marker: the view owns the value.
    Present,
    /// The markup carries no marker.
    Absent,
}

/// What the new markup says about a field's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// The markup sets the value: the [`CONTROLLED_ATTR`] marker, an authority
    /// attribute, `textarea` text, or an `option[selected]` below a `select`.
    Controlled,
    /// The markup sets none, so the user's state is the value.
    Uncontrolled,
}

impl Control {
    /// The control of a `field` whose new markup carries `marker`.
    ///
    /// The markup also holds an authority attribute when `authority`,
    /// non-empty text when `text`, and an `option[selected]` when
    /// `selected_option`.
    #[must_use]
    pub const fn of(
        field: Field,
        marker: Marker,
        authority: bool,
        text: bool,
        selected_option: bool,
    ) -> Self {
        let controlled = matches!(marker, Marker::Present)
            || authority
            || match field {
                Field::Input => false,
                Field::Textarea => text,
                Field::Select => selected_option,
            };
        if controlled {
            Self::Controlled
        } else {
            Self::Uncontrolled
        }
    }
}

/// How a swap treats a live child whose `ipe-id` and tag the new markup repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keep {
    /// Build the new node from the markup; the live one leaves.
    Rebuild,
    /// Keep the live node; write every attribute and swap its children.
    Node,
    /// Keep the live field; write every attribute but its authority ones, and
    /// keep a `textarea`'s text.
    Field(Field),
}

/// The keep for a live HTML element `tag` the new markup repeats, given
/// whether it holds focus and what the markup says about its value (read only
/// for a field).
#[must_use]
pub fn keep(tag: &str, focused: bool, control: impl FnOnce(Field) -> Control) -> Keep {
    if REBUILT_TAGS.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
        return Keep::Rebuild;
    }
    let Some(field) = Field::parse(tag) else {
        return Keep::Node;
    };
    if focused || control(field) == Control::Uncontrolled {
        Keep::Field(field)
    } else {
        Keep::Rebuild
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::{Control, FIELD_TAGS, Field, Keep, Marker, is_authority_attr, keep};

    #[test]
    fn a_plain_element_is_kept() {
        assert_eq!(keep("div", false, |_| Control::Controlled), Keep::Node);
        assert_eq!(keep("BUTTON", true, |_| Control::Controlled), Keep::Node);
    }

    #[test]
    fn a_frame_or_template_is_rebuilt() {
        for tag in ["iframe", "IFRAME", "embed", "object", "frame", "template"] {
            assert_eq!(keep(tag, true, |_| Control::Uncontrolled), Keep::Rebuild);
        }
    }

    #[test]
    fn a_focused_field_is_kept_even_when_controlled() {
        assert_eq!(
            keep("INPUT", true, |_| Control::Controlled),
            Keep::Field(Field::Input)
        );
    }

    #[test]
    fn an_unfocused_controlled_field_is_rebuilt() {
        for tag in FIELD_TAGS {
            assert_eq!(keep(tag, false, |_| Control::Controlled), Keep::Rebuild);
        }
    }

    #[test]
    fn an_unfocused_uncontrolled_field_is_kept() {
        assert_eq!(
            keep("textarea", false, |_| Control::Uncontrolled),
            Keep::Field(Field::Textarea)
        );
    }

    #[test]
    fn control_reads_each_fields_own_markup() {
        let of = |field, authority, text, selected| {
            Control::of(field, Marker::Absent, authority, text, selected)
        };
        assert_eq!(of(Field::Input, true, false, false), Control::Controlled);
        assert_eq!(of(Field::Input, false, true, true), Control::Uncontrolled);
        assert_eq!(of(Field::Textarea, false, true, false), Control::Controlled);
        assert_eq!(of(Field::Select, false, false, true), Control::Controlled);
        assert_eq!(of(Field::Select, false, true, false), Control::Uncontrolled);
    }

    /// A marked field whose view value is off or empty is still the view's.
    #[test]
    fn the_marker_alone_makes_a_field_controlled() {
        for field in Field::ALL {
            assert_eq!(
                Control::of(field, Marker::Present, false, false, false),
                Control::Controlled
            );
            assert_eq!(
                Control::of(field, Marker::Absent, false, false, false),
                Control::Uncontrolled
            );
        }
    }

    #[test]
    fn an_unfocused_marked_field_is_rebuilt() {
        for tag in FIELD_TAGS {
            let kept = keep(tag, false, |field| {
                Control::of(field, Marker::Present, false, false, false)
            });
            assert_eq!(kept, Keep::Rebuild);
        }
    }

    #[test]
    fn a_focused_marked_field_is_kept() {
        let kept = keep("input", true, |field| {
            Control::of(field, Marker::Present, false, false, false)
        });
        assert_eq!(kept, Keep::Field(Field::Input));
    }

    #[test]
    fn field_tags_round_trip() {
        for field in Field::ALL {
            assert_eq!(Field::parse(field.tag()), Some(field));
        }
        assert_eq!(Field::parse("button"), None);
    }

    #[test]
    fn authority_names_fold_ascii_case() {
        assert!(is_authority_attr("VALUE"));
        assert!(!is_authority_attr("name"));
    }
}
