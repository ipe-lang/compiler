# Transitions

`Ipe.Ui.Transition` describes a CSS transition as a list of typed `Step` values —
which property, how long, which easing, what delay — then lowers them to the CSS
`transition` shorthand. You assemble the transition from labelled parts, not a
positional string where the order of the numbers silently decides their meaning.

## The mental model

Two ideas.

- **Each facet is a named `Step`.** `property "opacity"`, `duration 200` (in
  milliseconds), `delay 50`, `easing Transition.easeInOut`. Because each part is
  labelled, there is no positional shorthand to get wrong — in raw CSS the *first*
  time value is the duration and the *second* is the delay, an ordering you have to
  remember; here they are distinct builders.
- **`buildShorthand` renders with defaults, fail-closed.** It lowers the list to
  the single CSS value, filling in a default for any facet you leave out, and scans
  the result — a rejected value renders as the empty string rather than an
  unchecked one.

## A worked example: a fade

The example under
[`examples/shapes/script/transition-shorthand`](../../examples/shapes/script/transition-shorthand/src/Main.ipe)
builds a fade — opacity, 200ms, a 50ms delay, ease-in-out — and renders it.

```ipe
fade : List Step
fade =
    [ Transition.property "opacity"
    , Transition.duration 200
    , Transition.delay 50
    , Transition.easing Transition.easeInOut
    ]
```

Running it (`ipe dev run`):

```
transition (shorthand value):
  opacity 200ms ease-in-out 50ms
```

Each labelled part rendered into the right slot of the shorthand.

## The why

Naming each facet with its own builder is [make invalid states
unrepresentable][principles]: the "I swapped the duration and the delay" bug of the
positional shorthand has no representation here, because duration and delay are
different functions. `buildShorthand` rendering a rejected value as the empty string
is [security][principles]'s fail-closed rule at the CSS boundary — the value is
scanned, and on rejection the reachable outcome is nothing, never an unchecked
string passed through. The easing constructors (`linear`, `easeInOut`,
`cubicBezier`) are a closed set, so an unknown timing function is a compile error,
not a silently-ignored typo.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Ui.Transition` — the `Step` builders
  (`property`, `duration`, `delay`, `easing`), the easing constructors (`linear`,
  `easeIn`, `easeOut`, `easeInOut`, `cubicBezier`), and the renderers
  (`buildShorthand`, `easingToCss`), each with its signature.
- **Sibling guides:** [Transforms](transform.md) — typed CSS transforms, often
  animated by a transition. [Grid tracks](grid.md) — the same typed-value-then-render
  discipline for layout. [Palette](palette.md) — closed token sets as types.
- **Concepts:** [Types and inference](types.md) — how the `Step` and `Easing` types
  keep a transition well-formed.
