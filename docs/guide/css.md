# CSS

`Ipe.Css` is a typed stylesheet DSL. You build declarations, rules, and a whole
stylesheet from typed values — a length from `px`, a colour from `hex`, a rule
from `rule` — and render them to a string. Every value is scanned as it is
built, so a rendered stylesheet is safe to drop into a `<style>` sink by
construction.

## The mental model

Three knots.

- **Declarations and rules are opaque, and gated at construction.** `CssProp`
  (one `key: value` declaration) and `CssRule` (a selector plus declarations)
  have no public constructor. A declaration exists only through a typed builder —
  `Css.color`, `Css.padding`, `Css.fontSize` — and a rule only through
  `Css.rule` / `Css.media` / `Css.keyframes`. Each builder scans its inputs, so
  you cannot hold a `CssProp` that was never checked.
- **A value that fails policy drops; it never half-emits.** A selector the
  sanitizer rejects yields the explicit `CssRuleDropped` state, which renders as
  the empty string. A raw `</style><script>` smuggled into a selector produces
  *nothing*, not a broken rule that breaks out of the style sink. The failure is
  a state in the type, checked exhaustively, not a silent partial write.
- **The typed builders are the safe default.** You never hand-format
  `"color: red"`. You write `Css.color (Css.hex "#e2e8f0")` and let the DSL join
  the declarations. `Css.stylesheet` renders a list of rules to a full
  stylesheet; `Css.styles` renders a list of declarations to one inline
  `style="..."` value.

## A worked example: a themed stylesheet

The example under
[`examples/shapes/script/css-theme-stylesheet`](../../examples/shapes/script/css-theme-stylesheet/src/Main.ipe)
builds a card rule, a responsive override, and — to show the gate — a rule with
an injected selector, then renders them.

A rule is a selector and a list of typed declarations:

```ipe
card : Css.CssRule
card =
    Css.rule ".card"
        [ Css.background (Css.hex "#1a1a2e")
        , Css.color (Css.hex "#e2e8f0")
        , Css.padding (Css.px 16)
        , Css.borderRadius (Css.px 8)
        , Css.fontSize (Css.rem 1.0)
        ]
```

The injected rule carries a selector that tries to break out of the `<style>`
sink. The sanitizer rejects it, so the whole rule becomes `CssRuleDropped` and
renders as nothing — the attempt never reaches the output:

```ipe
injected : Css.CssRule
injected =
    Css.rule ".card { } </style><script>alert(1)</script>"
        [ Css.color (Css.hex "#ff0000") ]
```

`Css.stylesheet` renders the list; the dropped rule contributes nothing:

```ipe
sheet : String
sheet =
    Css.stylesheet [ card, wideCard, injected ]
```

Running it (`ipe dev run`) prints the card rule and its media-query override, with
the injected rule absent from the output.

## The why

The opaque types plus a smart constructor are
[parse, don't validate][principles]: a `CssProp` is proof its name and value
passed policy, because there is no other way to build one. And dropping a
rejected rule rather than emitting a partial one is [security][principles] and
[make invalid states unrepresentable][principles] together — a stylesheet is a
classic injection sink (`</style>`, `@import` SSRF, `javascript:` URLs), and the
DSL closes it by construction: an unsafe value becomes an explicit `Dropped`
state in the type, not a broken string in the page.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Css` — every builder with its signature:
  the length units (`px`/`rem`/`pct`/`vh`), the colour builders
  (`hex`/`rgb`/`hsl`), the declaration builders, and `rule`/`media`/`keyframes`.
- **Sibling guides:** [HTML](html.md) — the typed element trees a stylesheet
  styles. [UI layout](ui.md) — the element surface a web view returns.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md).
  [Pure functions and immutability](pure-functions.md) — the whole DSL is pure;
  rendering the same rules yields the same string.
