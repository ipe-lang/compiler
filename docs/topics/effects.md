---
kind: topic
title: "effects: the Task discipline"
summary: "How Ipê models side effects as values, sequences them safely, and prevents accidental effect loss."
idiom: true
aliases: ["task", "task-discipline", "io", "side-effects"]
see_also: ["main", "state", "errors"]
---

# `effects` — the Task discipline

The code examples in this page are illustrative Ipê source snippets, not shell commands.

In Ipê, a side effect — printing output, reading input, making an HTTP request,
writing a file — is not executed immediately when your code reaches it. Instead,
it is represented as a **value** of type `Task Error result`. You build a
description of what should happen, and the runtime executes it exactly once when
your program runs.

## Why values, not statements?

Representing effects as values means:

- The type system tracks where effects happen. A function returning `String`
  cannot secretly print something; only a function returning `Task` can.
- Effects can be composed, passed around, and reasoned about like any other
  value — because they are values.
- The runtime is the only place effects actually run: `main` is the single
  `Task.run` site, and the rest of your program is pure computation.

## The shape of a Task

```ipe
Task Error result
```

`Error` is the type of failure (often a custom `type` you define). `result` is
the type of the success value — `()` when the task just does something without
returning a useful value.

## Sequencing effects

Use `Task.andThen` to run one task and then another, passing the result forward:

```ipe
main : Task Error ()
main =
    Io.readLine
        |> Task.andThen (\line -> Io.println ("You typed: " ++ line))
```

Or use a `do` block for the same thing in top-to-bottom order:

```ipe
main : Task Error ()
main =
    do
        line <- Io.readLine
        Io.println ("You typed: " ++ line)
```

Both forms are equivalent. See [`do`](do) for the full syntax.

## Idiom: never `let _ = task`

Binding a `Task` to `_` in a `let` expression silently discards the effect
outside the `Task` discipline. The compiler rejects it (IPE-L0141):

```ipe ipe:error IPE-L0141
-- Wrong: the effect is described but never run
main : Task Error ()
main =
    let
        _ = Io.println "this never runs"
    in
    Io.println "done"
```

Thread effects with `Task.andThen` or use a `do` block instead:

```ipe
-- Correct: both effects are sequenced and will run
main : Task Error ()
main =
    Io.println "this runs first"
        |> Task.andThen (\_ -> Io.println "done")
```

## Idiom: bare `Io.println` in multi-step logic

A trailing `Io.println` after other logic looks right but leaves the earlier
steps unconnected. Every step must be part of the same `Task.andThen` / `do`
chain:

```ipe ipe:error IPE-T0001
-- Wrong: the readLine Task is never connected to the println
badMain : Task Error ()
badMain =
    Io.readLine
    Io.println "done"
```

```ipe
-- Correct: chain them
goodMain : Task Error ()
goodMain =
    Io.readLine
        |> Task.andThen (\_ -> Io.println "done")
```

## Task.map for pure transformation

When you want to transform the *result* of a task without running another
effect, use `Task.map`:

```ipe
readUpperLine : Task Error String
readUpperLine =
    Task.map String.toUpper Io.readLine
```

## Glossary

- **Task** — a description of a side-effectful computation; a value, not an action.
- **`Task.andThen`** — sequences two Tasks, passing the first's result to the second.
- **`Task.map`** — transforms a Task's success value with a pure function.
- **effect discipline** — the rule that effects only run through `main`'s single `Task.run` site.
