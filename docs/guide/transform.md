# Transforms

`Ipe.Ui.Transform` describes a CSS `transform` — a translate, scale, rotate, or
skew — as a list of typed values, then lowers it to a CSS declaration. Each part is
a typed builder that supplies its own unit, so you never write the CSS text and
never forget a `px` or a `deg`.

## The mental model

Two ideas.

- **Each part is a typed builder with the right argument.** `translateX` and
  `translateY` take an `Int` of pixels; `scale` and `rotate` take a `Float`. The
  unit belongs to the builder — `translateY 4` becomes `translateY(4px)`, `rotate
  2.0` becomes `rotate(2deg)` — so you cannot pass an angle where a pixel count
  belongs, or emit a unitless length.
- **`propsToCss` lowers the whole list.** It joins a `List Prop` into one CSS
  `transform` declaration, in the order given. Composition is an ordinary list, so
  the sequence of transforms is explicit and the rendered parts cannot run together
  malformed.

## A worked example: a card lift

The example under
[`examples/shapes/script/transform-props`](../../examples/shapes/script/transform-props/src/Main.ipe)
builds a small "lift" transform — nudge up, shrink slightly, tilt — and renders it.

```ipe
lift : List Prop
lift =
    [ Transform.translateY (-4)
    , Transform.scale 0.98
    , Transform.rotate 2.0
    ]
```

Running it (`ipe dev run`):

```
The transform declaration (propsToCss emits the property name and value):
  transform:translateY(-4px) scale(0.98) rotate(2deg)
```

Each part rendered with its own unit, in list order.

## The why

Modelling each transform as a typed builder rather than a CSS fragment is [make
invalid states unrepresentable][principles]: a unitless length, a mistyped
function name, an argument of the wrong kind — none has a representation, so the
renderer only ever produces valid CSS. Putting the unit on the builder (`px` for
`translate*`, `deg` for `rotate`/`skew`) means the one place that knows the unit is
the one place that supplies it, so a caller cannot get it wrong.

The rendered string is scanned by the CSS sanitiser at the render sink when a
transform is applied to an interface element, so even a hand-built value cannot
smuggle an unexpected declaration through.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Ui.Transform` — the part builders
  (`translateX`, `translateY`, `translate`, `scale`, `scaleXY`, `rotate`, `skewX`,
  `skewY`, `opacity`) and the renderers (`propsToCss`, `propsToCssProps`), each with
  its signature.
- **Sibling guides:** [Grid tracks](grid.md) — the same typed-value-then-render
  discipline for CSS grid track lists. [Palette](palette.md) — closed token sets and
  named magnitudes as types.
- **Concepts:** [Types and inference](types.md) — how the `Prop` type keeps a
  transform list well-formed.
