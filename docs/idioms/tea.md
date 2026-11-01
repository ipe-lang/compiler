# The Elm Architecture (TEA)

**The idiom:** structure any program that *reacts to input over time* — a web page,
a desktop window, a terminal UI — as four named parts, and let the runtime run the
loop. Do not hand-roll an event loop or a mutable state object; describe the state,
the events, the transition, and the view, and the runtime wires them together.

## The shape

- **`Model`** — one type holding all the program's state.
- **`Msg`** — one type listing every event that can happen.
- **`update : Msg -> Model -> Model`** — the pure transition: given an event and
  the current state, compute the next state. All change lives here, and it is a
  pure function — no event mutates the model in place.
- **`view : Model -> Element Msg`** — render the current state; the interface emits
  `Msg` values back when the user interacts.

Effects (fetch a URL, start a timer) are *described* as `Cmd` values that `update`
returns alongside the next `Model`; their eventual result comes back as another
`Msg`. Ongoing event sources are declared in `subscriptions`. Effects are still
values, never performed inline — the [pure functions](../guide/pure-functions.md)
rule holds even here.

## Why prefer it

Because `update` is pure, the whole logic of a reactive program is testable as a
plain function — apply a list of messages with `List.foldl` and check the result,
no loop and no runtime involved. State is one value, so there is no scattered
mutable field to reason about, and every change is one `case` arm in `update`.

## When not to reach for it

A script or one-shot tool with **no state loop** does not need TEA — write a plain
`main` driven by tasks instead (the `Program` shape; see the
[`Ipe.Task` guide](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/Task.md) and
[`examples/shapes/script/release-preflight`](https://github.com/ipe-lang/compiler/tree/main/examples/shapes/script/release-preflight)).
Reach for TEA when the program must react to input *over time*.

## References

- [The Elm Architecture](../guide/the-elm-architecture.md) — the full guide, with
  the counter example and the `Cmd` / `subscriptions` story per shape.
- `ipe doc Web`, `ipe doc Terminal`, `ipe doc WebView` — the runnable form of each
  interactive shape.
- [Pure functions](../guide/pure-functions.md) — why `update` and effects are pure.
