---
kind: topic
title: "state: managing application state with TEA"
summary: "How Ipê models mutable application state: the Model-update-view (TEA) pattern and why functions in records are not supported."
idiom: true
aliases: ["tea", "model-update-view", "the-elm-architecture", "mutable-state"]
see_also: ["effects", "shapes", "errors"]
---

# `state` — managing application state with TEA

The code examples in this page are illustrative Ipê source snippets, not shell commands.

Ipê programs have no mutable variables. Instead, state is held in an immutable
**Model** value. When something happens — a button click, a timer, a network
response — the runtime calls your `update` function with the current model and
a `Msg` describing the event. `update` returns a new model. The runtime then
calls your `view` function on the new model to produce fresh output.

This cycle — **Model → view → Msg → update → new Model** — is called the
Elm Architecture (TEA). It is the only sanctioned mechanism for application
state in Ipê.

## Minimal TEA example (Cli shape)

```ipe
module Main exposing (..)

import Terminal

type alias Model =
    { count : Int }

type Msg
    = Increment
    | Decrement

init : Model
init =
    { count = 0 }

update : Msg -> Model -> Model
update msg model =
    case msg of
        Increment ->
            { model | count = model.count + 1 }

        Decrement ->
            { model | count = model.count - 1 }

view : Model -> Lines Msg
view model =
    Ui.text ("Count: " ++ String.fromInt model.count)

main : Task Error ()
main =
    Cli.tea
        { init = init
        , update = update
        , view = view
        }
```

## The three functions you provide

- **`init`** — the starting model value.
- **`update : Msg -> Model -> Model`** — given a message and the current model,
  produce the next model. Pure function; no effects.
- **`view`** — render the model into output (a web `Element`, a terminal
  `Lines` view, etc.).

## Idiom: no functions in record fields

A record field may not hold a function value (IPE-L0107). This is a design
decision, not a limitation to work around. The reason: if behaviour can differ
because a function stored in a field differs, you need to track which function
is there — and that tracking is exactly what a union type does, more safely:

```ipe ipe:skip
-- Illustrative: IPE-L0107 (function in record field) is a project-build gate, not a standalone type error
-- Wrong: function in a record field
type alias Handler =
    { onEvent : String -> String }
```

```ipe
-- Correct: model the variation with a union type
type HandlerKind
    = UpperCase
    | LowerCase

applyHandler : HandlerKind -> String -> String
applyHandler kind input =
    case kind of
        UpperCase ->
            String.toUpper input

        LowerCase ->
            String.toLower input
```

The union type is explicit and exhaustive. Adding a new case means updating
every `case` over `HandlerKind`, so no branch is silently forgotten.

## Idiom: no non-TEA state

Do not model state with mutable references, global variables, or effect-level
mutation. All state lives in the `Model`; all state changes flow through
`update`. The runtime is the only entity that holds the current model — your
code only ever receives it as a parameter.

## Sending effects from update

When `update` needs to trigger an effect (fire an HTTP request, start a timer),
it returns a pair of the new model and a command:

```ipe
update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )

        FetchData ->
            ( model, Http.get { url = "/data", expect = … } )
```

The runtime executes the `Cmd`; your `update` stays pure.

## Glossary

- **Model** — the immutable record holding all application state.
- **Msg** — a union type whose constructors name every event the app can receive.
- **`update`** — the pure function that transitions from old model + message to new model.
- **TEA** — the Elm Architecture: Model → view → Msg → update cycle.
- **`Cmd`** — a description of an effect the runtime should execute after `update`.
