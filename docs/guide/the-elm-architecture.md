# The Elm Architecture

A program that reacts to input over time — a web page, a desktop window, a
terminal UI — cannot be a single pure function from input to output: it has
*state* that changes as events arrive. Ipê structures such programs with **The
Elm Architecture** (TEA), a pattern with four named parts. This page explains
the pattern; the shape guides (run `ipe doc Web`, `ipe doc Terminal`, etc.) show
the runnable form for each kind of program.

## The four parts

- **`Model`** — a type holding all of the program's state. One value describes
  everything the program currently knows.
- **`Msg`** — a type listing every event that can happen. Each constructor is
  one kind of event.
- **`update : Msg -> Model -> Model`** — given an event and the current state,
  compute the next state. This is where all change happens, and it is a pure
  function: no event ever mutates the model in place; `update` returns a new
  one.
- **`view : Model -> Element Msg`** — render the current state to a user
  interface. The interface emits `Msg` values back when the user interacts.

The runtime wires these together into a loop: it holds the current `Model`,
renders it with `view`, waits for a `Msg`, calls `update` to get the next
`Model`, and repeats. You write the four parts; the runtime runs the loop.

## The state and the events

State and events are ordinary types (see [types](types.md)). A counter:

```ipe
type alias Model =
    { count : Int }


type Msg
    = Increment
    | Decrement
```

## The update function is the whole logic

`update` maps each event to the next state. Because it is pure, you can reason
about it — and test it — as a plain function, with no loop and no runtime
involved:

```ipe
update : Msg -> Model -> Model
update msg model =
    case msg of
        Increment ->
            { model | count = model.count + 1 }

        Decrement ->
            { model | count = model.count - 1 }
```

`{ model | count = … }` is a [record update](glossary.md#record-update): a new
`Model` equal to the old one but with `count` replaced. The old `model` is
unchanged, as [immutability](pure-functions.md) requires.

Since `update` is pure, applying a sequence of events is a
[fold](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/List.md) over them:

```ipe
-- Apply a sequence of messages, oldest first, to a starting model.
applyAll : Model -> List Msg -> Model
applyAll start msgs =
    List.foldl (\msg model -> update msg model) start msgs
```

Folding `[ Increment, Increment, Decrement, Increment ]` over a starting
`{ count = 0 }` gives `{ count = 2 }`. The same `update` the runtime calls one
event at a time, you can drive by hand over a list — which is exactly how TEA
logic is tested.

## Effects: `Cmd` and `subscriptions`

Some events lead to effects — fetch a URL, read a file, start a timer. In the
full TEA loop `update` returns the next `Model` and also a
[`Cmd`](glossary.md#cmd): a description of an effect to run, whose eventual
result comes back as another `Msg`. A **`subscriptions`** function declares
ongoing sources of events (a clock tick, an incoming websocket message).
Effects are still *described* as values, never performed inline — the
[pure functions](pure-functions.md) rule holds even here; the runtime is the one
place effects run.

The shape guides show the exact `Cmd`, `subscriptions`, and `view` types for
each kind of program, since they differ by shape.

## The starting state: `init`

Before the first event the runtime needs a starting `Model`, usually with a
`Cmd` to run at once (load data, read the clock). That is **`init`**. Its
argument is context the runtime hands *in* at startup, and it is fixed by shape:

- **Web** — `init : WebReq -> ( Model, Cmd Msg )`. `WebReq` is the per-session
  request (URL, route, headers): different for every visitor, reachable no other
  way, so the runtime passes it in.
- **WebView, Terminal** — `init : () -> ( Model, Cmd Msg )`. There is no
  per-session context to hand in; anything ambient (window size, args, the
  environment) is read directly through [`Ipe.System`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/System.md).

Unlike Elm, Ipê has no startup `flags` — a native program reaches its
environment directly rather than receiving it at boot. **Which way the data
flows** tells you where each thing belongs:

| flows | is | e.g. |
|---|---|---|
| runtime → program (in, at start) | `init`'s argument | `WebReq` |
| program → runtime (set once) | a config field | a WebView's `window`, `title` |
| program → runtime (during the loop) | a `Cmd` | change the title, resize, fetch |

An *output* — which window to open — never goes in `init`'s *input* slot; it is
config.

## Choosing a shape

The four parts drive every interactive program; the shape sets where it runs and
what `view` produces. The `init` argument and `view` differ by shape:

| shape | `init` | `view` |
|---|---|---|
| **Web** (`ipe doc Web`) — server-driven web | `WebReq -> …` | `Model -> Element Msg` |
| **WebView** (`ipe doc WebView`) — native window | `() -> …` | `Model -> Element Msg` (+ `window`, `title`) |
| **Terminal** (`ipe doc Terminal`) — full-screen / lines | `() -> …` | `Model -> Element Msg` or `Model -> String` |

`update` is always `Msg -> Model -> ( Model, Cmd Msg )` and `subscriptions`
`Model -> Sub Msg`. A script or one-shot tool with no state loop is not TEA —
write a plain `main` (see [getting started](getting-started.md)).

## Where to go next

- [Views: Ui and Html](glossary.md#ui) — what `view` returns and how to build it.
- [Glossary](glossary.md) — `Model`, `Msg`, `Cmd`, `subscriptions`,
  `record update`.
```
