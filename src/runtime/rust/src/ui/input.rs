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
use crate::html::RADIO_GROUP_MARKER;
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
/// alignment attrs hoist to the `attach_label` wrapper so `Ui.width fill`
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

/// Attributes that belong on the native `<input>` of a composite control.
fn is_form_attr<M>(attr: &Attribute<M>) -> bool {
    matches!(
        attr,
        Attribute::AttrAttribute(_, _) | Attribute::AttrEvent(_) | Attribute::AttrDescribe(_)
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

/// A single labelable control, built only after its label is attached.
enum Control<M> {
    /// An `<input>`.
    Input(Vec<Attribute<M>>),
    /// A `<textarea>`.
    Textarea(Vec<Attribute<M>>),
    /// An `<input type="checkbox">` inside a row that also holds its icon.
    Checkbox {
        input: Vec<Attribute<M>>,
        row: Vec<Attribute<M>>,
        icon: Element<M>,
    },
}

impl<M: Clone> Control<M> {
    /// The attributes of the element a screen reader names.
    fn labelable_attrs_mut(&mut self) -> &mut Vec<Attribute<M>> {
        match self {
            Self::Input(attrs) | Self::Textarea(attrs) => attrs,
            Self::Checkbox { input, .. } => input,
        }
    }

    fn build(self) -> Element<M> {
        match self {
            Self::Input(attrs) => ui_input_(attrs),
            Self::Textarea(attrs) => {
                Element::TaggedNode("textarea".into(), Description::NoDescription, attrs, vec![])
            }
            Self::Checkbox { input, row, icon } => ui_row_(row, vec![ui_input_(input), icon]),
        }
    }
}

/// Give `control` its accessible name, by structure.
///
/// A visible label is a `<label>` element that contains the control, so the
/// pair is one clickable, named unit; a hidden label is an `aria-label` on the
/// labelable element itself. No label is ever a free sibling of its control.
fn attach_label<M: Clone>(
    lbl: Label<M>,
    layout: Vec<Attribute<M>>,
    mut control: Control<M>,
) -> Element<M> {
    match lbl {
        Label::LabelHidden(text) => {
            // An empty `aria-label` names nothing and hides the control from
            // name computation, so an empty text adds no attribute.
            if !text.is_empty() {
                control
                    .labelable_attrs_mut()
                    .insert(0, Attribute::AttrAttribute("aria-label".to_owned(), text));
            }
            ui_el_(layout, control.build())
        }
        Label::Label(pos, label_attrs, label_el) => {
            let labeled = ui_el_(label_attrs, label_el);
            let control_el = control.build();
            let (marker, label_first) = match pos {
                LabelPosition::AbovePos => ("__col", true),
                LabelPosition::BelowPos => ("__col", false),
                LabelPosition::LeftPos => ("__row", true),
                LabelPosition::RightPos => ("__row", false),
            };
            let kids = if label_first {
                vec![labeled, control_el]
            } else {
                vec![control_el, labeled]
            };
            let mut attrs = Vec::with_capacity(layout.len() + 1);
            attrs.push(Attribute::AttrStyle(marker.to_owned(), "true".to_owned()));
            attrs.extend(layout);
            Element::TaggedNode("label".into(), Description::NoDescription, attrs, kids)
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
    attach_label(label, layout_attrs, Control::Input(base_attrs))
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
    attach_label(label, layout_attrs, Control::Textarea(base_attrs))
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
    // The checkbox change event delivers a Bool; we ignore it and always
    // toggle (matches the Ipê source's `cfg.onChange (not cfg.checked)`).
    let mut check_input_attrs = vec![
        ui_html_attribute_("type".into(), "checkbox".into()),
        Attribute::AttrChecked(checked),
        ui_on_bool_(Arc::new(move |_b: bool| toggle_msg.clone())),
    ];
    // Form, ARIA and event attributes name or drive the native box, so they go
    // on the `<input>`; visual attributes style the row around it.
    let (form_attrs, visual_attrs): (Vec<_>, Vec<_>) =
        control_attrs.into_iter().partition(is_form_attr);
    check_input_attrs.extend(form_attrs);
    let mut row_attrs = vec![ui_spacing_(8)];
    row_attrs.extend(visual_attrs);
    row_attrs.extend(implicit_fill_if_hoisted(&layout_attrs));
    let control = Control::Checkbox {
        input: check_input_attrs,
        row: row_attrs,
        icon: icon(checked),
    };
    attach_label(label, layout_attrs, control)
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
    attach_label(label, layout_attrs, Control::Input(base_attrs))
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

/// Build one radio option: a `<label>` holding its `<input type="radio">`.
fn radio_option<M: Clone + Send + Sync + 'static>(
    opt: RadioOption<M>,
    on_change: &Arc<dyn Fn(String) -> M + Send + Sync>,
    selected: &str,
) -> Element<M> {
    let is_checked = opt.value == selected;
    let wire_value = opt.value.clone();
    let on_click_msg = on_change(opt.value);
    let radio_attrs = vec![
        ui_html_attribute_("type".into(), "radio".into()),
        ui_html_attribute_("value".into(), wire_value),
        Attribute::AttrChecked(is_checked),
        // The bool-valued change event delivers the wire value: the closure
        // ignores the payload and always emits the message for THIS option.
        ui_on_bool_(Arc::new(move |_b: bool| on_click_msg.clone())),
    ];
    Element::TaggedNode(
        "label".into(),
        Description::NoDescription,
        vec![axis_marker(true), ui_spacing_(8)],
        vec![ui_input_(radio_attrs), opt.label],
    )
}

/// The internal direction marker of a row (`true`) or column (`false`).
fn axis_marker<M>(row: bool) -> Attribute<M> {
    let key = if row { "__row" } else { "__col" };
    Attribute::AttrStyle(key.to_owned(), "true".to_owned())
}

/// Shared core for `radio` / `radioRow`: a named `<fieldset>` of radios.
///
/// The group's accessible name is a first-child `<legend>` for a visible label
/// or an `aria-label` on the fieldset for a hidden one, and each radio sits
/// inside its own `<label>`. `row_layout` lays the options out in a row
/// (spacing 12) rather than a column (spacing 6).
fn radio_group<M: Clone + Send + Sync + 'static>(
    row_layout: bool,
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    options: Vec<RadioOption<M>>,
    selected: String,
    label: Label<M>,
) -> Element<M> {
    let (layout_attrs, control_attrs) = split_layout_attrs(attrs);
    let option_els: Vec<Element<M>> = options
        .into_iter()
        .map(|opt| radio_option(opt, &on_change, &selected))
        .collect();
    let spacing = if row_layout { 12 } else { 6 };
    let options_container = |kids: Vec<Element<M>>| {
        if row_layout {
            ui_row_(vec![ui_spacing_(spacing)], kids)
        } else {
            ui_column_(vec![ui_spacing_(spacing)], kids)
        }
    };

    // The browser's fieldset chrome is reset first so the user's attributes,
    // which follow, win.
    let reset = |outer_row: bool| -> Vec<Attribute<M>> {
        let mut out = vec![axis_marker(outer_row)];
        for (k, v) in [
            ("border", "0"),
            ("margin", "0"),
            ("padding", "0"),
            ("min-width", "0"),
        ] {
            out.push(Attribute::AttrStyle(k.to_owned(), v.to_owned()));
        }
        out.push(Attribute::AttrAttribute(
            RADIO_GROUP_MARKER.to_owned(),
            String::new(),
        ));
        out
    };

    let (mut group_attrs, kids) = match label {
        Label::LabelHidden(text) => {
            let mut group_attrs = reset(row_layout);
            group_attrs.push(ui_spacing_(spacing));
            // An empty `aria-label` names nothing, so it adds no attribute.
            if !text.is_empty() {
                group_attrs.insert(0, Attribute::AttrAttribute("aria-label".to_owned(), text));
            }
            (group_attrs, option_els)
        }
        Label::Label(pos, label_attrs, label_el) => {
            let (outer_row, legend_last) = match pos {
                LabelPosition::AbovePos => (false, false),
                LabelPosition::BelowPos => (false, true),
                LabelPosition::LeftPos => (true, false),
                LabelPosition::RightPos => (true, true),
            };
            // A floated legend becomes an ordinary flex item of the fieldset.
            let mut legend_attrs = vec![
                Attribute::AttrStyle("float".to_owned(), "left".to_owned()),
                Attribute::AttrStyle("padding".to_owned(), "0".to_owned()),
            ];
            if legend_last {
                legend_attrs.push(Attribute::AttrStyle("order".to_owned(), "1".to_owned()));
            }
            legend_attrs.extend(label_attrs);
            let legend = Element::TaggedNode(
                "legend".into(),
                Description::NoDescription,
                legend_attrs,
                vec![label_el],
            );
            (
                reset(outer_row),
                vec![legend, options_container(option_els)],
            )
        }
    };
    group_attrs.extend(control_attrs);
    group_attrs.extend(implicit_fill_if_hoisted(&layout_attrs));
    group_attrs.extend(layout_attrs);
    Element::TaggedNode(
        "fieldset".into(),
        Description::NoDescription,
        group_attrs,
        kids,
    )
}

/// `Input.radio`
///
/// Renders a vertical column of radio buttons (spacing 6) in a `<fieldset>`. Each
/// option is a `<label>` holding its `<input type="radio">` and label element.
pub fn input_radio_<M: Clone + Send + Sync + 'static>(
    attrs: Vec<Attribute<M>>,
    on_change: Arc<dyn Fn(String) -> M + Send + Sync>,
    options: Vec<RadioOption<M>>,
    selected: String,
    label: Label<M>,
) -> Element<M> {
    radio_group(false, attrs, on_change, options, selected, label)
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
    radio_group(true, attrs, on_change, options, selected, label)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::color::Color;
    use crate::html::{Attribute as HtmlAttribute, Html};
    use crate::ui::helpers::{ui_background_color_, ui_fill_, ui_width_};
    use crate::ui::render::ui_layout;

    type Msg = u8;
    type TextHandler = Arc<dyn Fn(String) -> Msg + Send + Sync>;

    fn on_text() -> TextHandler {
        Arc::new(|_s: String| 0)
    }

    fn on_flag() -> Arc<dyn Fn(bool) -> Msg + Send + Sync> {
        Arc::new(|_b: bool| 0)
    }

    fn no_icon() -> Arc<dyn Fn(bool) -> Element<Msg> + Send + Sync> {
        Arc::new(|_b: bool| Element::Empty)
    }

    fn page(el: Element<Msg>) -> Html<Msg> {
        ui_layout(Vec::new(), el)
    }

    fn tag_of(h: &Html<Msg>) -> &str {
        match h {
            Html::HElement(tag, _, _) => tag.as_str(),
            Html::HText(_) | Html::HRaw(_) => "",
        }
    }

    fn kids_of(h: &Html<Msg>) -> &[Html<Msg>] {
        match h {
            Html::HElement(_, _, kids) => kids.as_slice(),
            Html::HText(_) | Html::HRaw(_) => &[],
        }
    }

    fn attr<'a>(h: &'a Html<Msg>, name: &str) -> Option<&'a str> {
        let Html::HElement(_, attrs, _) = h else {
            return None;
        };
        attrs.iter().find_map(|a| match a {
            HtmlAttribute::Attr(k, v) if k == name => Some(v.as_str()),
            HtmlAttribute::Attr(..)
            | HtmlAttribute::BoolAttr(..)
            | HtmlAttribute::EventAttr(_)
            | HtmlAttribute::NoAttr => None,
        })
    }

    /// An attribute is present as a string value or as a true boolean.
    fn has_attr(h: &Html<Msg>, name: &str) -> bool {
        let Html::HElement(_, attrs, _) = h else {
            return false;
        };
        attrs.iter().any(|a| match a {
            HtmlAttribute::Attr(k, _) => k == name,
            HtmlAttribute::BoolAttr(k, on) => k == name && *on,
            HtmlAttribute::EventAttr(_) | HtmlAttribute::NoAttr => false,
        })
    }

    fn text_of(h: &Html<Msg>) -> String {
        match h {
            Html::HText(t) => t.clone(),
            Html::HElement(_, _, kids) => kids.iter().map(text_of).collect(),
            Html::HRaw(_) => String::new(),
        }
    }

    /// The first element (document order) for which `pred` holds.
    fn find<'a>(h: &'a Html<Msg>, pred: &dyn Fn(&Html<Msg>) -> bool) -> Option<&'a Html<Msg>> {
        if matches!(h, Html::HElement(..)) && pred(h) {
            return Some(h);
        }
        kids_of(h).iter().find_map(|k| find(k, pred))
    }

    /// How many elements satisfy `pred`.
    fn count(h: &Html<Msg>, pred: &dyn Fn(&Html<Msg>) -> bool) -> usize {
        let own = usize::from(matches!(h, Html::HElement(..)) && pred(h));
        own + kids_of(h).iter().map(|k| count(k, pred)).sum::<usize>()
    }

    fn is_tag(name: &'static str) -> impl Fn(&Html<Msg>) -> bool {
        move |h| tag_of(h) == name
    }

    fn text_field(label: Label<Msg>) -> Element<Msg> {
        input_text_(
            Vec::new(),
            on_text(),
            String::new(),
            IpeMaybe::Nothing,
            label,
        )
    }

    fn hidden() -> Label<Msg> {
        input_label_hidden_("Name".to_owned())
    }

    fn text_kind(
        build: fn(
            Vec<Attribute<Msg>>,
            TextHandler,
            String,
            IpeMaybe<Placeholder<Msg>>,
            Label<Msg>,
        ) -> Element<Msg>,
        label: Label<Msg>,
    ) -> Element<Msg> {
        build(
            Vec::new(),
            on_text(),
            String::new(),
            IpeMaybe::Nothing,
            label,
        )
    }

    /// Every control kind built with `label`, paired with the tag that must carry
    /// its accessible name.
    fn every_kind(label: impl Fn() -> Label<Msg>) -> Vec<(&'static str, Element<Msg>)> {
        vec![
            ("input", text_kind(input_text_, label())),
            ("input", text_kind(input_email_, label())),
            ("input", text_kind(input_username_, label())),
            ("input", text_kind(input_search_, label())),
            ("input", text_kind(input_current_password_, label())),
            ("input", text_kind(input_new_password_, label())),
            (
                "textarea",
                input_multiline_(
                    Vec::new(),
                    on_text(),
                    String::new(),
                    IpeMaybe::Nothing,
                    label(),
                    false,
                ),
            ),
            (
                "input",
                input_slider_(
                    Vec::new(),
                    on_text(),
                    "5".to_owned(),
                    "0".to_owned(),
                    "10".to_owned(),
                    "1".to_owned(),
                    label(),
                ),
            ),
            (
                "input",
                input_checkbox_(Vec::new(), on_flag(), no_icon(), false, label()),
            ),
        ]
    }

    /// The accessible name is on the labelable element, never a wrapper. Red if
    /// `attach_label` puts `aria-label` on the wrapper element.
    #[test]
    fn hidden_label_names_the_input_not_the_wrapper() {
        let html = page(text_field(input_label_hidden_("Email".to_owned())));
        let found = find(&html, &is_tag("input"));
        assert!(found.is_some(), "an input is rendered");
        let Some(input) = found else {
            return;
        };
        assert_eq!(attr(input, "aria-label"), Some("Email"));
        let named_non_inputs = count(&html, &|h| {
            tag_of(h) != "input" && has_attr(h, "aria-label")
        });
        assert_eq!(named_non_inputs, 0, "no wrapper carries the name");
        assert_eq!(count(&html, &is_tag("label")), 0, "no label element");
    }

    /// Red if any control kind builds its element before the name is attached.
    #[test]
    fn hidden_label_on_each_control_kind() {
        for (labelable, el) in every_kind(hidden) {
            let html = page(el);
            let found = find(&html, &|h| attr(h, "aria-label") == Some("Name"));
            assert!(found.is_some(), "a {labelable} carries the name");
            let Some(named) = found else {
                return;
            };
            assert_eq!(tag_of(named), labelable);
            assert_eq!(count(&html, &|h| has_attr(h, "aria-label")), 1);
        }
    }

    /// An empty hidden label adds no `aria-label`, which would name nothing.
    /// Red if the empty-text guard in `attach_label` is removed.
    #[test]
    fn hidden_label_empty_emits_no_aria_label() {
        for (_, el) in every_kind(|| input_label_hidden_(String::new())) {
            let html = page(el);
            assert_eq!(count(&html, &|h| has_attr(h, "aria-label")), 0);
            assert_eq!(
                count(&html, &is_tag("input")) + count(&html, &is_tag("textarea")),
                1
            );
        }
    }

    /// Each visible label wraps its control in one `<label>` that also holds the
    /// label text, in the order the position asks for. Red if the label returns to
    /// a free sibling of its control.
    #[test]
    fn visible_label_contains_its_control() {
        let text = || Element::Text("Name".to_owned());
        let cases: [(&str, Label<Msg>, bool); 4] = [
            ("above", input_label_above_(Vec::new(), text()), true),
            ("left", input_label_left_(Vec::new(), text()), true),
            ("below", input_label_below_(Vec::new(), text()), false),
            ("right", input_label_right_(Vec::new(), text()), false),
        ];
        for (name, label, label_first) in cases {
            let html = page(text_field(label));
            assert_eq!(count(&html, &is_tag("label")), 1, "{name}: one label");
            let found = find(&html, &is_tag("label"));
            assert!(found.is_some(), "{name}: label found");
            let Some(wrapper) = found else {
                return;
            };
            assert_eq!(count(wrapper, &is_tag("input")), 1, "{name}: input inside");
            assert!(text_of(wrapper).contains("Name"), "{name}: text inside");
            let kids = kids_of(wrapper);
            assert_eq!(kids.len(), 2, "{name}: label text and control");
            let holds_input: Vec<bool> = kids
                .iter()
                .map(|k| count(k, &is_tag("input")) == 1)
                .collect();
            let expected = if label_first {
                vec![false, true]
            } else {
                vec![true, false]
            };
            assert_eq!(holds_input, expected, "{name}: order");
        }
    }

    /// Layout attributes stay on the outermost wrapper and visual attributes on
    /// the control. Red if the layout/control split moves.
    #[test]
    fn layout_attrs_still_hoist_to_the_label_wrapper() {
        let html = page(input_text_(
            vec![
                ui_width_(ui_fill_()),
                ui_background_color_(Color::rgb(10, 20, 30)),
            ],
            on_text(),
            String::new(),
            IpeMaybe::Nothing,
            input_label_above_(Vec::new(), Element::Text("Name".to_owned())),
        ));
        let found = find(&html, &is_tag("label"));
        assert!(found.is_some(), "label found");
        let Some(wrapper) = found else {
            return;
        };
        let wrapper_style = attr(wrapper, "style").unwrap_or_default();
        assert!(wrapper_style.contains("width:100%"), "{wrapper_style}");
        assert!(
            !wrapper_style.contains("background-color"),
            "{wrapper_style}"
        );
        let found = find(wrapper, &is_tag("input"));
        assert!(found.is_some(), "input found");
        let Some(input) = found else {
            return;
        };
        let input_style = attr(input, "style").unwrap_or_default();
        assert!(input_style.contains("background-color"), "{input_style}");
    }

    fn checkbox(attrs: Vec<Attribute<Msg>>, checked: bool) -> Html<Msg> {
        page(input_checkbox_(
            attrs,
            on_flag(),
            no_icon(),
            checked,
            input_label_hidden_("Agree".to_owned()),
        ))
    }

    /// Form and ARIA attributes reach the native checkbox, not the row around it.
    /// Red if the form/visual split in `input_checkbox_` is removed.
    #[test]
    fn checkbox_form_attrs_reach_the_input() {
        let html = checkbox(
            vec![
                ui_html_attribute_("aria-invalid".to_owned(), "true".to_owned()),
                ui_html_attribute_("aria-describedby".to_owned(), "err".to_owned()),
            ],
            false,
        );
        let found = find(&html, &|h| {
            tag_of(h) == "input" && attr(h, "type") == Some("checkbox")
        });
        assert!(found.is_some(), "a checkbox input is rendered");
        let Some(input) = found else {
            return;
        };
        assert_eq!(attr(input, "aria-invalid"), Some("true"));
        assert_eq!(attr(input, "aria-describedby"), Some("err"));
        let on_others = count(&html, &|h| {
            tag_of(h) != "input" && (has_attr(h, "aria-invalid") || has_attr(h, "aria-describedby"))
        });
        assert_eq!(on_others, 0, "no wrapper carries the form attributes");
    }

    /// The native box follows the model: `checked` is present only when true, and
    /// the strings "true"/"false" never encode it. Red if checkedness returns to
    /// a `value` attribute.
    #[test]
    fn checkbox_reflects_model() {
        let on = checkbox(Vec::new(), true);
        let found = find(&on, &is_tag("input"));
        assert!(found.is_some(), "an input is rendered");
        let Some(input_on) = found else {
            return;
        };
        assert!(has_attr(input_on, "checked"));
        assert_eq!(attr(input_on, "value"), None);

        let off = checkbox(Vec::new(), false);
        let found = find(&off, &is_tag("input"));
        assert!(found.is_some(), "an input is rendered");
        let Some(input_off) = found else {
            return;
        };
        assert!(!has_attr(input_off, "checked"));
        assert_eq!(attr(input_off, "value"), None);
    }

    fn radios(attrs: Vec<Attribute<Msg>>, label: Label<Msg>) -> Html<Msg> {
        let options = vec![
            input_option_("a".to_owned(), Element::Text("Alpha".to_owned())),
            input_option_("b".to_owned(), Element::Text("Beta".to_owned())),
        ];
        page(input_radio_(
            attrs,
            on_text(),
            options,
            "b".to_owned(),
            label,
        ))
    }

    fn is_radio(h: &Html<Msg>) -> bool {
        tag_of(h) == "input" && attr(h, "type") == Some("radio")
    }

    /// A visible label becomes the first-child `<legend>` of a `<fieldset>`, and
    /// each radio sits inside its own `<label>`. Red if the group returns to a
    /// plain `div` with a free-sibling label.
    #[test]
    fn radio_group_is_a_named_fieldset() {
        let html = radios(
            Vec::new(),
            input_label_above_(Vec::new(), Element::Text("Size".to_owned())),
        );
        let found = find(&html, &is_tag("fieldset"));
        assert!(found.is_some(), "a fieldset is rendered");
        let Some(group) = found else {
            return;
        };
        let first = kids_of(group).first();
        assert!(first.is_some_and(|k| tag_of(k) == "legend"), "legend first");
        assert!(first.is_some_and(|k| text_of(k) == "Size"));
        assert_eq!(count(group, &is_radio), 2);
        let own_labels = count(group, &|h| {
            tag_of(h) == "label" && count(h, &is_radio) == 1 && kids_of(h).len() == 2
        });
        assert_eq!(own_labels, 2, "each radio has its own label");
    }

    /// A hidden label names the fieldset itself and emits no legend. Red if the
    /// hidden branch of `radio_group` stops writing `aria-label` on the fieldset.
    #[test]
    fn radio_hidden_label_on_fieldset() {
        let html = radios(Vec::new(), input_label_hidden_("Size".to_owned()));
        let found = find(&html, &is_tag("fieldset"));
        assert!(found.is_some(), "a fieldset is rendered");
        let Some(group) = found else {
            return;
        };
        assert_eq!(attr(group, "aria-label"), Some("Size"));
        assert_eq!(count(&html, &is_tag("legend")), 0);
        assert_eq!(count(&html, &|h| has_attr(h, "aria-label")), 1);

        let unnamed = radios(Vec::new(), input_label_hidden_(String::new()));
        assert_eq!(count(&unnamed, &|h| has_attr(h, "aria-label")), 0);
    }

    /// Below and right labels keep the legend first in document order and push it
    /// last visually. Red if the legend is appended after the options.
    #[test]
    fn radio_legend_stays_first_for_below_and_right() {
        let text = || Element::Text("Size".to_owned());
        let cases: [(&str, Label<Msg>, bool); 4] = [
            ("above", input_label_above_(Vec::new(), text()), false),
            ("left", input_label_left_(Vec::new(), text()), false),
            ("below", input_label_below_(Vec::new(), text()), true),
            ("right", input_label_right_(Vec::new(), text()), true),
        ];
        for (name, label, ordered_last) in cases {
            let html = radios(Vec::new(), label);
            let found = find(&html, &is_tag("legend"));
            assert!(found.is_some(), "{name}: legend rendered");
            let Some(legend) = found else {
                return;
            };
            let style = attr(legend, "style").unwrap_or_default();
            assert_eq!(style.contains("order:1"), ordered_last, "{name}: {style}");
            let first = find(&html, &is_tag("fieldset"))
                .and_then(|g| kids_of(g).first())
                .map(tag_of);
            assert_eq!(first, Some("legend"), "{name}: legend is the first child");
        }
    }

    /// Only the selected option is checked, as a present boolean attribute, and
    /// no radio carries the string "false". Red if checkedness returns to a
    /// string-valued `checked` attribute.
    #[test]
    fn only_selected_radio_is_checked() {
        let html = radios(Vec::new(), input_label_hidden_("Size".to_owned()));
        assert_eq!(count(&html, &is_radio), 2);
        let checked = find(&html, &|h| is_radio(h) && has_attr(h, "checked"));
        assert!(checked.is_some(), "one radio is checked");
        assert_eq!(checked.and_then(|r| attr(r, "value")), Some("b"));
        assert_eq!(
            count(&html, &|h| is_radio(h) && has_attr(h, "checked")),
            1,
            "exactly one checked"
        );
        assert_eq!(count(&html, &|h| attr(h, "checked") == Some("false")), 0);
    }

    /// The fieldset reset precedes the user's padding, so the user's padding is
    /// the last declaration and wins. Red if the reset moves after the user
    /// attributes.
    #[test]
    fn fieldset_reset_does_not_override_user_padding() {
        let html = radios(
            vec![crate::ui::helpers::ui_padding_(7)],
            input_label_hidden_("Size".to_owned()),
        );
        let found = find(&html, &is_tag("fieldset"));
        assert!(found.is_some(), "a fieldset is rendered");
        let Some(group) = found else {
            return;
        };
        let style = attr(group, "style").unwrap_or_default();
        let paddings: Vec<&str> = style
            .split(';')
            .filter(|d| d.starts_with("padding:"))
            .collect();
        assert_eq!(paddings.first().copied(), Some("padding:0"), "{style}");
        assert_eq!(
            paddings.last().copied(),
            Some("padding:7px 7px 7px 7px"),
            "{style}"
        );
    }

    /// Form and ARIA attributes on a radio group land on the fieldset. Red if
    /// they are routed to a nested container or dropped.
    #[test]
    fn radio_form_attrs_land_on_fieldset() {
        let html = radios(
            vec![ui_html_attribute_(
                "aria-describedby".to_owned(),
                "err".to_owned(),
            )],
            input_label_hidden_("Size".to_owned()),
        );
        let found = find(&html, &|h| attr(h, "aria-describedby") == Some("err"));
        assert!(found.is_some_and(|h| tag_of(h) == "fieldset"));
        assert_eq!(count(&html, &|h| has_attr(h, "aria-describedby")), 1);
    }
}
