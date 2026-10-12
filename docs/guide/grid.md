# Grid tracks

`Ipe.Ui.Grid` describes CSS grid track lists — the `grid-template-columns` and
`grid-template-rows` values — as typed data, then lowers them to a CSS string. A
track is a value you build and nest, not a string you concatenate, so a malformed
track list is unrepresentable.

## The mental model

Three ideas.

- **A track is a typed value.** `Grid.fr 1`, `Grid.px 200`, `Grid.auto`,
  `Grid.minContent`, `Grid.maxContent` build a `Track`. There is no stray-unit or
  typo'd-keyword track, because you never write the CSS text — you build the value
  and let `trackToCss` render it.
- **Composites nest by construction.** `Grid.minmax lo hi` and `Grid.repeat n
  inner` take `Track`s and return a `Track`, so `minmax(100px, 1fr)` and
  `repeat(3, 1fr)` are assembled from already-checked pieces. An unbalanced
  `minmax(` cannot occur, because the parenthesis is emitted by the renderer, not
  typed by you.
- **`tracksToCss` lowers the whole list.** It renders a `List Track` to the
  space-joined string a `grid-template-columns` value expects; `trackToCss` renders
  one track on its own.

## A worked example: a responsive column list

The example under
[`examples/shapes/script/grid-tracks`](../../examples/shapes/script/grid-tracks/src/Main.ipe)
builds a column list — a fixed sidebar, a flexible main column with a minimum, and
three equal cards — and renders it.

```ipe
columns : List Track
columns =
    [ Grid.px 200
    , Grid.minmax (Grid.px 100) (Grid.fr 1)
    , Grid.repeat 3 (Grid.fr 1)
    ]
```

Running it (`ipe dev run`):

```
grid-template-columns:
  200px minmax(100px, 1fr) repeat(3, 1fr)
single track (auto): auto
```

The nested `minmax` and `repeat` render with balanced parentheses and the right
units, assembled from the typed pieces.

## The why

Modelling a track as a typed value rather than a CSS string is [make invalid states
unrepresentable][principles]: the malformed track list — a bad unit, an unbalanced
`minmax(`, a `repeat` with no count — has no representation, so the renderer only
ever sees well-formed input and its output is always valid CSS. Composites that take
and return `Track` make the nesting checked at each step, so the structure is
correct by construction rather than by careful string-building.

The same track lists attach to an element as `grid-template` attributes through
`Grid.columns` / `Grid.rows` / `Grid.tracks`, which produce an `Attribute msg` for
an interface element.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Ui.Grid` — the track builders (`fr`, `px`,
  `auto`, `minContent`, `maxContent`, `minmax`, `repeat`, `repeatAutoFit`,
  `repeatAutoFill`), the renderers (`trackToCss`, `tracksToCss`), and the
  attribute builders (`columns`, `rows`, `tracks`), each with its signature.
- **Sibling guides:** [Palette](palette.md) — closed token sets and named
  magnitudes, the same typed-value-not-string discipline for design tokens.
  [HTML attributes](html-attributes.md) — how a rendered value becomes an element
  attribute.
- **Concepts:** [Types and inference](types.md) — how the `Track` type keeps a
  track list well-formed.
