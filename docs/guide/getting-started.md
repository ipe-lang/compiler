# Getting started

This page takes you from nothing to a running Ipê program. It assumes no prior
Ipê knowledge. Every command and every line of code here has been run as
written.

## What Ipê is

Ipê is a pure-functional programming language in the [Elm][elm] family. You
write programs as functions that transform values; the compiler translates them
to Rust and builds a native executable. "Pure-functional" means a function's
result depends only on its arguments and it changes nothing outside itself — the
same inputs always produce the same output. The [pure functions][pure] concept
page develops what that gives you.

[elm]: https://elm-lang.org
[pure]: pure-functions.md

## Create a project

A project is a directory with a `package.ipe` manifest and a `src/` directory.
Scaffold one with `ipe init`:

```
ipe init hello
cd hello
```

This creates `package.ipe` (the manifest — the project's name and version,
written in Ipê) and a starter `src/Main.ipe`.

## Your first program

Replace `src/Main.ipe` with the following. It builds a greeting from a list of
names and prints it.

```ipe
module Main exposing (main)

import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String


-- The program's entry point. `main` runs a task; this one prints a line.
main =
    Io.println (greeting names)


names : List String
names =
    [ "Ada", "Linus", "Grace" ]


-- Build one greeting line from a list of names.
greeting : List String -> String
greeting people =
    "Hello, " ++ String.join " and " people ++ "!"
```

Reading it top to bottom:

- **`module Main exposing (main)`** declares this file as the module `Main` and
  makes `main` visible to the runtime. Every program has a `main`.
- **`import Ipe.Io as Io`** brings the [`Ipe.Io`](../reference/stdlib/Io.md) module
  into scope under the short name `Io`; likewise `List` and `String`. You call a
  module's function through its qualifier: `Io.println`, `String.join`.
- **`main = Io.println (greeting names)`** is the entry point.
  [`Io.println`](../reference/stdlib/Io.md) takes a `String` and produces a
  [`Task`](glossary.md#task) — a description of an effect to run. The runtime
  runs `main`'s task; running this one prints the line.
- **`names : List String`** is a *type annotation* — it states that `names` is a
  list of strings. The next line is the value. Ipê infers types on its own, so
  annotations are optional, but writing them on top-level definitions documents
  the code and pins down mistakes early.
- **`greeting`** is an ordinary function. `people` is its parameter; the body
  joins the names with `" and "` between them ([`String.join`](../reference/stdlib/String.md))
  and wraps the result in `"Hello, "` and `"!"`. `++` concatenates strings.

## Run it

```
ipe dev run
```

The first run compiles the project and its dependencies, then executes it. The
output is:

```
Hello, Ada and Linus and Grace!
```

To build the executable without running it, use `ipe dev build`.

Every build, run, and watch command lives under one of two postures:

- `ipe dev` is for fast iteration on code you trust: it does not promise a capability check, a consent prompt, or a jail.
- `ipe release` is for production and for running external packages: it infers capabilities, asks your consent, gates Debug.*, and runs jailed.

Run a package someone else wrote only through `ipe release`; the
[capabilities](../reference/capabilities.md) reference lists what it can grant.

## Change it

Try editing the list — add a name, or remove one — and run again:

```ipe
names : List String
names =
    [ "Ada" ]
```

```
Hello, Ada!
```

`String.join` puts its separator only *between* elements, so a single name has
no `" and "`. That behaviour, and every other `Ipe.String` and `Ipe.List`
function, is in the [module reference](../reference/stdlib.md), each with a
verified example.

## Where to go next

- [Pure functions and immutability](pure-functions.md) — why an Ipê value never
  changes, and what that buys you.
- [Types and inference](types.md) — how the compiler knows the type of every
  value, and how `Maybe` and `Result` make absence and failure explicit.
- [The Elm Architecture](the-elm-architecture.md) — how a program that reacts
  to input over time (a web page, a terminal UI) is structured.
- [Faster builds](faster-builds.md) — a fast linker, sccache, and dev-profile
  flags that cut compile time; run `ipe health` to apply most of it in one step.
- [Publishing a package](publishing.md) — turn a library into a package other
  developers can `ipe add`: the registry, `ipe login`, the audit gate, and
  `ipe package publish`.
- [Glossary](glossary.md) — every term of art, defined once.
- [Module reference](../reference/stdlib.md) — every `Ipe.*` module, generated
  from its source doc-strings.
```
