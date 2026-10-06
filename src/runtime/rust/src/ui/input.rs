//! `Ipe.Ui.Input` kernel helpers -- typed form controls.
//!
//! Mirrors `ipe-stdlib/Std/Ui/Input.ipe` variant-for-variant.
//! Every public function carries a trailing underscore matching
//! the `naming.rs` convention for kernel helpers.

use super::element::{Attribute, Description, Element, Length, Portion};
use super::helpers::{
    ui_column_, ui_el_, ui_html_attribute_, ui_input_, ui_on_bool_, ui_on_input_, ui_row_,
    ui_spacing_,
};
use crate::core::IpeMaybe;
use std::sync::Arc;

// ---- Label + LabelPosition --------------------------------------------------

/// `LabelPosition` -- which side the visible label is placed relative to its
/// control. Mirrors `type LabelPosition = AbovePos | BelowPos | LeftPos | RightPos`
/// in `Ipe.Ui.Input`.
#[derive(Clone, Debug, PartialEq)]
pub enum LabelPosition {
    AbovePos,
    BelowPos,
    LeftPos,
    RightPos,
}

/// `Label msg` -- a label plus its position. Mirrors `type Label msg = Label
/// LabelPosition (List (Attribute msg)) (Element msg) | LabelHidden String`.
#[derive(Clone, Debug, PartialEq)]
pub enum Label<M> {
    /// `Label pos attrs el` -- a positioned, visible label.
    Label(LabelPosition, Vec<Attribute<M>>, Element<M>),
    /// `LabelHidden s` -- an accessibility-only label (invisible,
    /// SR-accessible via `aria-label`).
    LabelHidden(String),
}

/// `Placeholder msg` -- placeholder text + optional styling. Mirrors
/// `type Placeholder msg = Placeholder (List (Attribute msg)) (Element msg)`.
#[derive(Clone, Debug, PartialEq)]
pub struct Placeholder<M> {
    pub attrs: Vec<Attribute<M>>,
    pub content: Element<M>,
}

crate::stringify::show_row!("Label", Internals, [M] Label<M>, |_| "<Ipe.Ui.Label>".to_owned());

crate::stringify::show_row!("Placeholder", Internals, [M] Placeholder<M>, |_| "<Ipe.Ui.Placeholder>".to_owned());

// ---- Label constructors -----------------------------------------------------

/// `Input.labelAbove : List (Attribute msg) -> Element msg -> Label msg`
#[must_use]
pub fn input_label_above_<M>(attrs: Vec<Attribute<M>>, el: Element<M>) -> Label<M> {
    Label::Label(LabelPosition::AbovePos, attrs, el)
}

/// `Input.labelBelow : List (Attribute msg) -> Element msg -> Label msg`
#[must_use]
pub fn input_label_below_<M>(attrs: Vec<Attribute<M>>, el: Element<M>) -> Label<M> {
    Label::Label(LabelPosition::BelowPos, attrs, el)
}

/// `Input.labelLeft : List (Attribute msg) -> Element msg -> Label msg`
#[must_use]
pub fn input_label_left_<M>(attrs: Vec<Attribute<M>>, el: Element<M>) -> Label<M> {
    Label::Label(LabelPosition::LeftPos, attrs, el)
}

/// `Input.labelRight : List (Attribute msg) -> Element msg -> Label msg`
#[must_use]
pub fn input_label_right_<M>(attrs: Vec<Attribute<M>>, el: Element<M>) -> Label<M> {
    Label::Label(LabelPosition::RightPos, attrs, el)
}

/// `Input.labelHidden : String -> Label msg`
#[must_use]
pub fn input_label_hidden_<M>(s: String) -> Label<M> {
    Label::LabelHidden(s)
}

// ---- Placeholder constructor -------------------------------------------------

/// `Input.placeholder : List (Attribute msg) -> Element msg -> Placeholder msg`
#[must_use]
pub fn input_placeholder_<M>(attrs: Vec<Attribute<M>>, content: Element<M>) -> Placeholder<M> {
    Placeholder { attrs, content }
}

// ---- Internal helpers -------------------------------------------------------

/// Partition `attrs` into `(layout_attrs, control_attrs)`. Layout / size /
/// alignment attrs hoist to the `wrap_with_label` wrapper so `Ui.width fill`
/// etc. applies to the outer container. Visual / event attrs stay on the
/// inner `<input>` / `<textarea>`.
fn split_layout_attrs<M: Clone>(
    attrs: Vec<Attribute<M>>,
) -> (Vec<Attribute<M>>, Vec<Attribute<M>>) {
    let mut layout = Vec::new();
    let mut control = Vec::new();
    for attr in attrs {
        if is_layout_attr(&attr) {
            layout.push(attr);
        } else {
            control.push(attr);
        }
    }
    (layout, control)
}

fn is_layout_attr<M>(attr: &Attribute<M>) -> bool {
    matches!(
        attr,
        Attribute::AttrWidth(_)
            | Attribute::AttrHeight(_)
            | Attribute::AttrAlignX(_)
            | Attribute::AttrAlignY(_)
            | Attribute::AttrPadding(_, _, _, _)
            | Attribute::AttrSpacing(_)
            | Attribute::AttrNearby(_, _)
            | Attribute::AttrPointer
            | Attribute::AttrOverflow(_, _)
    )
}

/// If `layout_attrs` is non-empty, return `[AttrWidth Fill, AttrHeight Fill]`
/// so the hoisted wrapper inherits sensible defaults. Mirrors
/// `implicitFillIfHoisted` in `Ipe.Ui.Input`.
fn implicit_fill_if_hoisted<M>(layout_attrs: &[Attribute<M>]) -> Vec<Attribute<M>> {
    if layout_attrs.is_empty() {
        vec![]
    } else {
        vec![
            Attribute::AttrWidth(Length::Fill(Portion::ONE)),
            Attribute::AttrHeight(Length::Fill(Portion::ONE)),
        ]
    }
}

/// Extract placeholder text from the first `Element::Text` node. Non-`Text`
/// nodes are silently ignored (HTML `placeholder` is text-only).
fn placeholder_text_of<M>(content: &Element<M>) -> Option<String> {
    match content {
        Element::Text(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Wrap `control` in its label according to `LabelPosition`. Hidden labels
/// emit `aria-label` on the wrapper for screen-reader access.
fn wrap_with_label<M: Clone>(
    lbl: Label<M>,
    wrapper_attrs: Vec<Attribute<M>>,
    control: Element<M>,
) -> Element<M> {
    match lbl {
        Label::LabelHidden(text) => {
            let mut attrs = wrapper_attrs;
            attrs.insert(0, Attribute::AttrAttribute("aria-label".to_owned(), text));
            ui_el_(attrs, control)
        }
        Label::Label(pos, label_attrs, label_el) => {
            let labeled_el = ui_el_(label_attrs, label_el);
            match pos {
                LabelPosition::AbovePos => ui_column_(wrapper_attrs, vec![labeled_el, control]),
                LabelPosition::BelowPos => ui_column_(wrapper_attrs, vec![control, labeled_el]),
                LabelPosition::LeftPos => ui_row_(wrapper_attrs, vec![labeled_el, control]),
                LabelPosition::RightPos => ui_row_(wrapper_attrs, vec![control, labeled_el]),
            }
        }
    }
}

// ---- Text-family controls ---------------------------------------------------

/// Shared core for `text / email / username / search / currentPassword /
/// newPassword`. Mirrors `inputBase` in `Ipe.Ui.Input`.
fn input_base_<M: Clone>(
    input_type: &'static str,
    autocomplete: Option<&'static str>,
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    text: String,
    placeholder: IpeMaybe<Placeholder<M>>,
    label: Label<M>,
) -> Element<M> {
    let (layout_attrs, control_attrs) = split_layout_attrs(attrs);
    let mut base_attrs: Vec<Attribute<M>> = vec![
        ui_html_attribute_("type".into(), input_type.into()),
        ui_html_attribute_("value".into(), text),
    ];
    if let Some(ac) = autocomplete {
        base_attrs.push(ui_html_attribute_("autocomplete".into(), ac.into()));
    }
    base_attrs.push(ui_on_input_(on_change));
    if let IpeMaybe::Just(ph) = placeholder
        && let Some(ph_text) = placeholder_text_of(&ph.content)
    {
        base_attrs.push(ui_html_attribute_("placeholder".into(), ph_text));
    }
    base_attrs.extend(control_attrs);
    base_attrs.extend(implicit_fill_if_hoisted(&layout_attrs));
    let input_el = ui_input_(base_attrs);
    wrap_with_label(label, layout_attrs, input_el)
}

/// `Input.text`
pub fn input_text_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    text: String,
    placeholder: IpeMaybe<Placeholder<M>>,
    label: Label<M>,
) -> Element<M> {
    input_base_("text", None, attrs, on_change, text, placeholder, label)
}

/// `Input.email`
pub fn input_email_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    text: String,
    placeholder: IpeMaybe<Placeholder<M>>,
    label: Label<M>,
) -> Element<M> {
    input_base_("email", None, attrs, on_change, text, placeholder, label)
}

/// `Input.username`
pub fn input_username_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    text: String,
    placeholder: IpeMaybe<Placeholder<M>>,
    label: Label<M>,
) -> Element<M> {
    input_base_(
        "text",
        Some("username"),
        attrs,
        on_change,
        text,
        placeholder,
        label,
    )
}

/// `Input.search`
pub fn input_search_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    text: String,
    placeholder: IpeMaybe<Placeholder<M>>,
    label: Label<M>,
) -> Element<M> {
    input_base_("search", None, attrs, on_change, text, placeholder, label)
}

/// `Input.currentPassword`
pub fn input_current_password_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    text: String,
    placeholder: IpeMaybe<Placeholder<M>>,
    label: Label<M>,
) -> Element<M> {
    input_base_(
        "password",
        Some("current-password"),
        attrs,
        on_change,
        text,
        placeholder,
        label,
    )
}

/// `Input.newPassword`
pub fn input_new_password_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    text: String,
    placeholder: IpeMaybe<Placeholder<M>>,
    label: Label<M>,
) -> Element<M> {
    input_base_(
        "password",
        Some("new-password"),
        attrs,
        on_change,
        text,
        placeholder,
        label,
    )
}

// ---- Multiline --------------------------------------------------------------

/// `Input.multiline`
pub fn input_multiline_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    text: String,
    placeholder: IpeMaybe<Placeholder<M>>,
    label: Label<M>,
    spellcheck: bool,
) -> Element<M> {
    let (layout_attrs, control_attrs) = split_layout_attrs(attrs);
    let spell_val = if spellcheck { "true" } else { "false" };
    let mut base_attrs: Vec<Attribute<M>> = vec![
        ui_html_attribute_("spellcheck".into(), spell_val.into()),
        ui_html_attribute_("value".into(), text),
        ui_on_input_(on_change),
    ];
    if let IpeMaybe::Just(ph) = placeholder
        && let Some(ph_text) = placeholder_text_of(&ph.content)
    {
        base_attrs.push(ui_html_attribute_("placeholder".into(), ph_text));
    }
    base_attrs.extend(control_attrs);
    base_attrs.extend(implicit_fill_if_hoisted(&layout_attrs));
    // Emit a `<textarea>` via `TaggedNode` -- mirrors `Ui.TaggedNode "textarea" ...`
    let textarea_el = Element::TaggedNode(
        "textarea".into(),
        Description::NoDescription,
        base_attrs,
        vec![],
    );
    wrap_with_label(label, layout_attrs, textarea_el)
}

// ---- Checkbox ---------------------------------------------------------------

/// `Input.checkbox`
pub fn input_checkbox_<M: Clone + Send + Sync + 'static>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(bool) -> M + Send + Sync>,
    icon: Arc<dyn Fn(bool) -> Element<M> + Send + Sync>,
    checked: bool,
    label: Label<M>,
) -> Element<M> {
    let (layout_attrs, control_attrs) = split_layout_attrs(attrs);
    let toggle_msg = on_change(!checked);
    let check_val = if checked { "true" } else { "false" };
    // The checkbox change event delivers a Bool; we ignore it and always
    // toggle (matches the Ipê source's `cfg.onChange (not cfg.checked)`).
    let check_input_attrs = vec![
        ui_html_attribute_("type".into(), "checkbox".into()),
        ui_html_attribute_("value".into(), check_val.into()),
        ui_on_bool_(Arc::new(move |_b: bool| toggle_msg.clone())),
    ];
    let check_input = ui_input_(check_input_attrs);
    let icon_el = icon(checked);
    let mut row_attrs = vec![ui_spacing_(8)];
    row_attrs.extend(control_attrs);
    row_attrs.extend(implicit_fill_if_hoisted(&layout_attrs));
    let row_el = ui_row_(row_attrs, vec![check_input, icon_el]);
    wrap_with_label(label, layout_attrs, row_el)
}

/// `Input.slider`
///
/// Renders an `<input type="range">` with a label and oninput handler.
/// All numeric attributes (`value`, `min`, `max`, `step`) are passed as
/// `String` — the DOM's `<input type="range">` wire format; the caller parses
/// to a numeric type as needed.
///
/// The `onChange` callback receives the `String` representation of the current
/// slider position (fired on every `oninput` event while the user drags).
pub fn input_slider_<M: Clone>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    value: String,
    min: String,
    max: String,
    step: String,
    label: Label<M>,
) -> Element<M> {
    let (layout_attrs, control_attrs) = split_layout_attrs(attrs);
    let mut base_attrs: Vec<Attribute<M>> = vec![
        ui_html_attribute_("type".into(), "range".into()),
        ui_html_attribute_("value".into(), value),
        ui_html_attribute_("min".into(), min),
        ui_html_attribute_("max".into(), max),
        ui_html_attribute_("step".into(), step),
        ui_on_input_(on_change),
    ];
    base_attrs.extend(control_attrs);
    base_attrs.extend(implicit_fill_if_hoisted(&layout_attrs));
    let input_el = ui_input_(base_attrs);
    wrap_with_label(label, layout_attrs, input_el)
}

// ---- Radio ------------------------------------------------------------------

/// `RadioOption msg` — a single radio choice.
///
/// Mirrors `type RadioOption msg = RadioOption String (Element msg)` in
/// `Ipe.Ui.Input`. Constructed via [`input_option_`].
#[derive(Clone, Debug, PartialEq)]
pub struct RadioOption<M> {
    /// The wire value submitted when this option is selected.
    pub value: String,
    /// The visible label element rendered next to the radio button.
    pub label: Element<M>,
}

crate::stringify::show_row!("RadioOption", Internals, [M] RadioOption<M>, |_| "<Ipe.Ui.RadioOption>".to_owned());

/// `Input.option : String -> Element msg -> RadioOption msg`
///
/// Constructs a `RadioOption` from a wire value string and a label element.
#[must_use]
pub fn input_option_<M>(value: String, label: Element<M>) -> RadioOption<M> {
    RadioOption { value, label }
}

/// Shared core for `radio` / `radioRow`. Renders a group of `<input
/// type="radio">` controls. Each option is laid out according to `row_layout`:
/// `false` → vertical column (spacing 6), `true` → horizontal row (spacing 12).
fn radio_core_<M: Clone + Send + Sync + 'static>(
    row_layout: bool,
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    options: Vec<RadioOption<M>>,
    selected: String,
    label: Label<M>,
) -> Element<M> {
    let (layout_attrs, control_attrs) = split_layout_attrs(attrs);
    let mut option_els: Vec<Element<M>> = Vec::with_capacity(options.len());
    for opt in options {
        let is_checked = opt.value == selected;
        let check_val = if is_checked { "true" } else { "false" };
        let wire_value = opt.value.clone();
        let on_click_msg = on_change(opt.value);
        let radio_attrs = vec![
            ui_html_attribute_("type".into(), "radio".into()),
            ui_html_attribute_("value".into(), wire_value),
            ui_html_attribute_("checked".into(), check_val.into()),
            // Use on_bool_ (the bool-valued change event on radio) to deliver
            // the wire value. The closure ignores the Bool payload and always
            // emits the message for THIS option — matches Ipê's onClick-per-label
            // convention from AGENTS.md §Radio convention.
            ui_on_bool_(Arc::new(move |_b: bool| on_click_msg.clone())),
        ];
        let radio_input = ui_input_(radio_attrs);
        let option_row = ui_row_(vec![ui_spacing_(8)], vec![radio_input, opt.label]);
        option_els.push(option_row);
    }
    let spacing = if row_layout { 12 } else { 6 };
    let mut group_attrs: Vec<Attribute<M>> = vec![ui_spacing_(spacing)];
    group_attrs.extend(control_attrs);
    group_attrs.extend(implicit_fill_if_hoisted(&layout_attrs));
    let group_el = if row_layout {
        ui_row_(group_attrs, option_els)
    } else {
        ui_column_(group_attrs, option_els)
    };
    wrap_with_label(label, layout_attrs, group_el)
}

/// `Input.radio`
///
/// Renders a vertical column of radio buttons (spacing 6). Each option is a
/// row of `<input type="radio">` + label element.
pub fn input_radio_<M: Clone + Send + Sync + 'static>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    options: Vec<RadioOption<M>>,
    selected: String,
    label: Label<M>,
) -> Element<M> {
    radio_core_(false, attrs, on_change, options, selected, label)
}

/// `Input.radioRow`
///
/// Renders a horizontal row of radio buttons (spacing 12). Identical to
/// [`input_radio_`] but laid out with `Ui.row` instead of `Ui.column`.
pub fn input_radio_row_<M: Clone + Send + Sync + 'static>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    options: Vec<RadioOption<M>>,
    selected: String,
    label: Label<M>,
) -> Element<M> {
    radio_core_(true, attrs, on_change, options, selected, label)
}
