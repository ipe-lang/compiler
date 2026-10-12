# Palette

`Ipe.Palette` is a small **design-token** module: a closed `Shade` set that maps
to hex strings, and a `Spacing` type that wraps a pixel count in a named value.
It is the smallest illustration of the pattern every design system in Ipê uses —
tokens are types, not loose strings and integers.

## The mental model

Two knots.

- **A token set is a closed union.** `Shade` is exactly `Dark` or `Light`, and
  `toHex` maps each to its colour. A `case` over a `Shade` is *exhaustive*: if the
  set ever grew, every reader that maps a `Shade` would be a compile error until
  it handled the new token. There is no "unknown shade" that renders to a blank or
  a guessed colour — the compiler enforces total coverage.
- **A magnitude is a named type, not a bare number.** `Spacing` is `Sp Int` — a
  pixel count wrapped in its own constructor. A `Spacing` can never be passed
  where an unrelated `Int` was expected, and an `Int` can never silently stand in
  for a spacing step. `spacingPx` is the single place the raw number is recovered,
  at the boundary where a real pixel count is genuinely needed.

## A worked example: shades and a spacing scale

The example under
[`examples/shapes/script/palette-shades`](../../examples/shapes/script/palette-shades/src/Main.ipe)
renders each `Shade` to its hex string and unwraps a three-step `Spacing` scale to
pixels.

Because `Shade` is closed, naming its constructors is exhaustive by construction —
the `case` cannot forget a token:

```ipe
shadeName : Shade -> String
shadeName shade =
    case shade of
        Dark ->
            "Dark"

        Light ->
            "Light"
```

The spacing scale is a list of named `Spacing` values; the raw pixel count is
recovered only at the render boundary through `spacingPx`:

```ipe
scale : List Spacing
scale =
    [ Sp 4, Sp 8, Sp 16 ]
```

Running it (`ipe dev run`) prints:

```
Dark -> #000
Light -> #fff
spacing px: 4, 8, 16
```

## The why

Modelling `Shade` as a closed union is [make invalid states
unrepresentable][principles]: a colour token that is neither `Dark` nor `Light`
has no value, so a stylesheet cannot reference a shade that was never defined. The
exhaustiveness of the `case` turns "did I handle every token?" from a review
question into a compile check — adding a token surfaces every unhandled site
mechanically.

Wrapping a pixel count in `Spacing` rather than passing a bare `Int` is [parse,
don't validate][principles] for magnitudes: the number's *meaning* (this is a
spacing step, in pixels) is carried in its type, so it cannot be added to a font
size or a z-index by accident. `spacingPx` is the one narrow un-wrap, at the edge
where the raw number is actually laid out.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Palette` — `Shade` / `toHex` and
  `Spacing` / `spacingPx`.
- **Sibling guides:** [Types and inference](types.md) — how a closed union and a
  wrapped magnitude are tracked. [Lists](list.md) — mapping a function over a
  scale of tokens.
- **Concepts:** design tokens as types generalise across the styling surface;
  the same closed-union discipline underpins every reserved token set in the
  standard library.
