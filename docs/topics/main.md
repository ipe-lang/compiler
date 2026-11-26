---
kind: topic
title: "main: the program entry point"
summary: "Every Ipê program's entry is a Task Error () value named main. This page explains what that means and what goes wrong when it isn't."
idiom: true
aliases: ["entry-point", "main-function", "task-error-unit"]
see_also: ["effects", "shapes", "errors"]
---

# `main` — the program entry point

The code examples in this page are illustrative Ipê source snippets, not shell commands.

Every Ipê program has exactly one top-level binding named `main`. The runtime
takes `main`, runs its effect, and exits. `main` must have type `Task Error ()`.

## The canonical shape

```ipe
main : Task Error ()
main =
    Io.println "Hello, world!"
```

`Task Error ()` means: a computation that can fail with an `Error`, and
produces `()` (unit — "nothing useful") on success.

## App entries are also Tasks

All four app shapes produce a `Task Error ()`. So `main` always has the same
type, regardless of which shape you use:

```ipe
main : Task Error ()
main =
    Web.tea { init = init, update = update, view = view, subscriptions = subscriptions }
```

```ipe
main : Task Error ()
main =
    Tui.tea { init = init, update = update, view = view }
```

The shape entry function (`Web.tea`, `Tui.tea`, etc.) returns a
`Task Error ()` — the runtime runs it the same way a plain script runs.

## Idiom: main must be `Task Error ()`

A `main` whose type is anything else — an `Int`, a `String`, a `Bool`, a
function — cannot be run. The compiler rejects it with IPE-L0136:

```ipe ipe:skip
-- Illustrative: IPE-L0136 fires when building a project; not a standalone type error
-- Wrong: main is an Int, not a Task
main : Int
main =
    42
```

```ipe ipe:skip
-- Illustrative: IPE-L0136 fires when building a project; not a standalone type error
-- Wrong: main is a function, not a Task
main : String -> Task Error ()
main greeting =
    Io.println greeting
```

```ipe
-- Correct: main is a Task Error ()
main : Task Error ()
main =
    Io.println "Hello!"
```

## The `Error` type

The `Error` in `Task Error ()` is your program's top-level error type. For
scripts and simple programs, `String` works; for structured programs, define a
custom `type`:

```ipe
type AppError
    = NetworkError String
    | ParseError String
    | NotFound

main : Task AppError ()
main =
    fetchData
        |> Task.andThen processData
```

When a `Task` fails, the runtime prints the error to stderr and exits non-zero.

## Type annotation is required

The top-level `main` binding requires a type annotation. Without one, the
compiler reports IPE-L0106 (top-level function needs a type signature). Always
annotate `main`:

```ipe ipe:skip
-- Illustrative: IPE-L0106 fires when building a project; standalone type-check accepts unannotated bindings
-- Wrong: no type annotation
main =
    Io.println "Hello!"
```

```ipe
-- Correct: annotated
main : Task Error ()
main =
    Io.println "Hello!"
```

## Single run site

`main` is the one and only place the runtime calls `Task.run`. All effects in
your program flow through `main`'s `Task`. Any effect that does not flow through
`main`'s `Task` chain will never execute — this is why `let _ = task` is
rejected (IPE-L0141). See [`effects`](effects).

## Glossary

- **`main`** — the mandatory top-level binding; the program's entry point.
- **`Task Error ()`** — the required type for `main`; a runnable effect.
- **`()`** — unit: the type with one value, used when a computation returns nothing useful.
- **run site** — the single point where the runtime executes the `Task` tree.
