# Pure functions and immutability

Ipê is a *pure-functional* language. Two properties follow from that, and much
of how the language feels follows from these two. This page explains both, with
verified examples.

## A function depends only on its arguments

A [pure function](glossary.md#pure-function) computes its result from its
arguments alone. It reads no hidden state and writes none: given the same
arguments, it returns the same result every time.

```ipe
greeting : List String -> String
greeting people =
    "Hello, " ++ String.join " and " people ++ "!"
```

`greeting [ "Ada" ]` is `"Hello, Ada!"` — now, later, on any machine, in any
run. There is no global it could read, no clock it could consult, no field it
could have mutated between calls. This is what the [Correctness][principles]
principle means in practice: the same well-typed program with the same input
yields the same output.

[principles]: https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md

### Then how does anything happen?

Printing, reading a file, querying a database — these *do* depend on the outside
world, so they cannot be plain values. In Ipê they are
[`Task`](glossary.md#task) values: a `Task` *describes* an effect without
performing it. `Io.println "hi"` does not print; it produces a `Task` that, when
the runtime runs it, prints. Your program builds up a description of what should
happen, and the runtime is the single place that makes it happen. The
[`Ipe.Task`](../reference/stdlib/Task.md) module and the
[TEA concept page](the-elm-architecture.md) develop how effects are sequenced.

## A value never changes

Every value in Ipê is *immutable*: once built, it is never modified in place. A
function that "changes" a value returns a **new** value; the original is
untouched.

```ipe
original : List Int
original =
    [ 1, 2, 3 ]


doubled : List Int
doubled =
    List.map (\n -> n * 2) original
```

After this runs, `doubled` is `[ 2, 4, 6 ]` and `original` is **still**
`[ 1, 2, 3 ]`. [`List.map`](../reference/stdlib/List.md) did not alter `original`; it
produced a new list. Printing both confirms it:

```
original: [1, 2, 3]
doubled:  [2, 4, 6]
```

The same holds for records. A record update writes with the `|` syntax and
yields a new record:

```ipe
withCount : Model -> Int -> Model
withCount model n =
    { model | count = n }
```

`{ model | count = n }` is a new record equal to `model` but with `count`
replaced. `model` itself is unchanged.

## What immutability buys you

- **Sharing is safe.** Because no one can mutate a value, you can pass the same
  list to two functions without one affecting the other. There are no defensive
  copies to make and no "who owns this?" questions.
- **Reasoning is local.** To understand what a function does, you read the
  function. It cannot reach out and change something elsewhere, and nothing
  elsewhere can change its inputs mid-computation.
- **The soundness guarantee.** A well-typed Ipê program cannot fall over at
  runtime — no null dereference, no out-of-bounds access. Functions that might
  not have an answer say so in their type, returning a
  [`Maybe`](../reference/stdlib/Maybe.md) rather than a value-or-crash. The
  [types concept page](types.md) develops this.

## Where to go next

- [Types and inference](types.md) — how the compiler tracks the type of every
  value, and how `Maybe` and `Result` encode absence and failure.
- [The Elm Architecture](the-elm-architecture.md) — structuring a program that
  reacts to input over time.
- [Glossary](glossary.md) — `pure function`, `Task`, `immutable`, and the rest.
```
