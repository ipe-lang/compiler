# Animations

`Ipe.Ui.Animation` describes a CSS animation as a `Spec` value — its duration,
easing, delay, iteration count, and fill mode — built up from a named default with
labelled refinements, then lowered to the CSS animation shorthand. Each facet is
set by name, and the closed-set facets (iterations, fill mode, easing) rule out
typos at compile time.

## The mental model

Two ideas.

- **A `Spec` is built by pipeline.** `defaultSpec name` starts from sensible
  defaults, and each `withDuration` / `withEasing` / `withDelay` /
  `withIterations` / `withFillMode` overrides one facet. You never write a
  positional shorthand string where the order of the numbers decides which is
  duration and which is delay — every facet is a named refinement.
- **Closed sets rule out typos.** `iterations` is `once` / `infinite` /
  `times n`; `fillMode` is `none` / `forwards` / `backwards` / `both`; easing is
  `linear` / `easeInOut` / `cubicBezier` and friends. These are typed
  constructors, not free strings, so an unknown value is a compile error rather than
  a silently-ignored CSS token.

## A worked example: an infinite pulse

The example under
[`examples/shapes/script/animation-spec`](../../examples/shapes/script/animation-spec/src/Main.ipe)
builds a pulse — 600ms, ease-in-out, running forever, holding its final frame — and
renders the shorthand.

```ipe
pulse : Animation.Spec
pulse =
    Animation.defaultSpec "pulse"
        |> Animation.withDuration 600
        |> Animation.withEasing Animation.easeInOut
        |> Animation.withIterations Animation.infinite
        |> Animation.withFillMode Animation.forwards
```

Running it (`ipe dev run`):

```
animation shorthand tail (name is added by the render sink):
  600ms ease-in-out 0ms infinite forwards
```

Each facet rendered into its slot; the delay defaulted to `0ms` because we didn't
set it. The animation *name* is added by the render sink, which auto-suffixes it to
keep it unique.

## The why

Building a `Spec` from named refinements rather than a positional string is [make
invalid states unrepresentable][principles]: the "I swapped duration and delay" and
"I misspelled `infinite`" bugs have no representation, because each facet is its own
function and each closed-set value is its own constructor. `defaultSpec` also
defaults `respectReducedMotion` on, so an animation is accessibility-safe unless you
explicitly opt out — the safe choice is the one you get without asking.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Ui.Animation` — the spec pipeline
  (`defaultSpec`, `withDuration`, `withEasing`, `withDelay`, `withIterations`,
  `withFillMode`, `withKeyframes`, `withRespectReducedMotion`), the closed-set
  constructors (`once`, `infinite`, `times`, `none`, `forwards`, `backwards`,
  `both`), and the renderers (`buildShorthandTail`, `buildKeyframesBody`,
  `iterationsToCss`, `fillModeToCss`, `easingToCss`), each with its signature.
- **Sibling guides:** [Transitions](transition.md) — a simpler property-change
  animation. [Transforms](transform.md) — the transforms a keyframe animates.
  [Grid tracks](grid.md) — the same typed-value-then-render discipline.
- **Concepts:** [Types and inference](types.md) — how the `Spec`, `Iterations`,
  `FillMode`, and `Easing` types keep an animation well-formed.
