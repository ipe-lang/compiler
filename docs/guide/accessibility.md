# Accessibility

Accessibility is a core value of Ipê, not an add-on. PRINCIPLES.md commits the
project to *"Respecting diversity in all its forms … is MANDATORY"*, and
accessibility is how that value reaches disabled users. So the a11y surface is
*typed*: an element's role and its ARIA state are a closed vocabulary, and a
control that assistive tech cannot name is unrepresentable on the default path.

## The mental model

Three knots.

- **`Ipe.Ui` is accessible by construction.** `Ui` is Ipê's default UI library,
  and it leads on accessibility so an app built from `Ui` alone is accessible
  with no extra effort. `Ui` landmark builders carry their ARIA role
  automatically (a `describe descNavigation` region renders `role="navigation"`
  even on a non-`<nav>` element); `Ui.image` requires a `description` (the
  `alt`); and an icon-only control has no nameless form — `Ui.iconButton`
  demands a `label : String`.
- **Role and ARIA state are a closed vocabulary, so they are typed.** WAI-ARIA
  recognises a fixed set of role names and a fixed value shape per `aria-*`
  attribute. `Ipe.Html.Attributes` and `Ipe.Ui` model each as a closed sum:
  `role : Role -> Attribute msg`, `ariaLive : AriaLive -> Attribute msg`, and so
  on. A typo (`role "buton"`), an invalid role, or an out-of-vocabulary aria
  value has no value to build from — it is a type error, not a silent ship. This
  is [parse, don't validate][principles] at the a11y boundary: the vocabulary is
  parsed into a typed value once, so the wrong string never reaches the wire.
- **A landmark ELEMENT and a `role` are different tools.** Prefer the semantic
  element — `<nav>`, `<main>`, `<button>` — where one exists: it carries its role
  implicitly and needs nothing extra. In `Ui`, `describe descNavigation` &c. give
  you those landmarks. Reach for `role` only to *override* an element's implicit
  semantics, or for a role no element expresses. Setting `role` where a semantic
  element would do is redundant at best and conflicting at worst.

## The accessible-name floor

An interactive element with no accessible name is invisible to a screen reader —
the user hears "button" with no idea what it does. The floor closes that:

- **Icon-only buttons.** `Ui.button`'s `label` is an `Element` that may be a
  wordless icon, so it *can* be nameless. `Ui.iconButton { icon, label, onPress }`
  cannot: its `label : String` is required and becomes the `aria-label`. On the
  `Ui` path the nameless icon button has no representation.
- **Images.** `Ui.image` already requires a `description` — the text
  alternative — so a `Ui` image is never `alt`-less. A decorative image passes an
  empty description.
- **Inputs.** Pair a `Ui.input` with a `descLabel`, or an `ariaLabel` /
  `ariaLabelledby`, so the field has an associated name.

In raw `Ipe.Html` the same defects (a nameless `button`, an `alt`-less `img`, an
unlabeled `input`) are *possible* — `Html` is the lower-level parity/escape
substrate, and a hard type requirement there would break legitimate use (a button
whose text child *is* its name). The intended split is: **the `Ui` default path
makes the accessible form the only one; raw `Html` keeps the escape hatch.** A
markup-level lint (`IPE-A11Y-…`) that flags the nameless `Html` control is the
right complement and is tracked as follow-up work — it needs a view-expression
lint pass the current signature-shape lint framework does not yet have, and
shipping it half-wired would violate the no-shortcuts rule.

## A worked example

A status bar with a live region, a disclosure toggle, and an icon-only close
button — all named, all with the right ARIA state, no raw strings:

```ipe
import Ipe.Ui as Ui


statusBar : Bool -> Element Msg
statusBar open =
    Ui.row [ Ui.describe Ui.descNavigation ]
        [ Ui.el [ Ui.ariaLive Ui.LivePolite ] (Ui.text "Saved")
        , Ui.button [ Ui.ariaExpanded open, Ui.ariaControls "panel" ]
            { onPress = Just Toggle, label = Ui.text "Details" }
        , Ui.iconButton []
            { icon = closeIcon, label = "Close", onPress = Just Close }
        ]
```

`ariaExpanded` takes a `Bool`; `ariaLive` takes the closed `AriaLive`; the close
button cannot exist without its `"Close"` name. None of these can be misspelled.

## The why

Typed ARIA is [make invalid states unrepresentable][principles] and [parse,
don't validate][principles] applied to accessibility: the invalid role, the
wrong-shaped aria value, and the nameless control have no representation, so the
whole class of silent a11y bugs cannot ship on the default path. And it is
[security-adjacent][principles] in spirit — a closed vocabulary parsed at the
boundary is the same discipline that keeps a `javascript:` URL out of an `href`.

Rendering an aria STATE boolean writes the value out explicitly (`aria-expanded="false"`,
not an omitted attribute), because for a *state* the absent attribute and the
literal `"false"` mean different things to assistive tech: unsupported versus
supported-and-off. Correctness dictates the state is always written, so
`ariaExpanded`/`ariaChecked`/… render `"true"`/`"false"` rather than reusing the
omit-on-false `boolAttribute`.

[principles]: https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Html.Attributes` — `role`, the `aria*`
  helpers, and the closed `Role` / `AriaLive` / `AriaCurrent` / `AriaTristate` /
  `AriaHaspopup` / `AriaInvalid` sums. `ipe doc Ipe.Ui` — `iconButton` and the
  same vocabulary in `Ui` terms.
- **Sibling guides:** [HTML](html.md) — the element tree these attributes attach
  to. [HTML attributes](html-attributes.md) — the typed attribute family.
- **Concepts:** [Make invalid states unrepresentable](https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md) — the
  principle the closed vocabularies embody.
