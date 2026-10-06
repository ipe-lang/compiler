# Glossary

Every term of art, defined once. Each entry links to the page or module that
develops it. This is a seed set; the full glossary grows as the module reference
does.

Entries are alphabetical.

## capability

What a program is permitted to do — read the filesystem, open a network
connection, access a secret. Ipê infers a program's capabilities from the code
it actually uses; nothing is declared. Run `ipe capabilities --help` for the
full model.

## Cmd

A value describing an effect for the runtime to run, whose result returns as a
[`Msg`](#msg). In [The Elm Architecture](the-elm-architecture.md), `update`
returns a `Cmd` alongside the next [`Model`](#model). Like a [`Task`](#task), a
`Cmd` describes an effect rather than performing it.

## constructor

One of the named alternatives of a type. `Just` and `Nothing` are the
constructors of [`Maybe`](../reference/stdlib/Maybe.md); `Ok` and `Err` of
[`Result`](../reference/stdlib/Result.md). A constructor is how you *build* a value of
the type and, in a [`case`](#exhaustive-match), how you take it apart.

## doc-string

The `{-| … -}` (or `-- |`) comment immediately above a definition in `.ipe`
source. It is the single source of a symbol's documentation: `ipe doc`, the
Markdown reference, and the served site are all generated from it. Only the
`{-| … -}` form has its ```` ```ipe ```` examples checked by `ipe doc --check-examples`.

## exhaustive match

A `case … of` that covers every [constructor](#constructor) of the type it
matches. Ipê requires it: leaving a constructor unhandled is a compile error, not
a runtime surprise. See [types](types.md).

## immutable

Not changeable after creation. Every Ipê value is immutable: a function that
"changes" a value returns a new one and leaves the original untouched. See
[pure functions and immutability](pure-functions.md).

## kernel

A standard-library operation whose implementation is native (Rust) rather than
written in Ipê. A kernel-backed function still has a normal signature and
[doc-string](#doc-string); only its body lives in the runtime. Much of
[`Ipe.List`](../reference/stdlib/List.md) and [`Ipe.Maybe`](../reference/stdlib/Maybe.md)
is kernel-backed.

## Maybe

The type of a value that may be absent: `Just a` (present) or `Nothing`
(absent). Ipê's stand-in for null — a function that might have no answer returns
a `Maybe` and the caller must handle both cases. See
[`Ipe.Maybe`](../reference/stdlib/Maybe.md) and [types](types.md).

## Model

In [The Elm Architecture](the-elm-architecture.md), the type holding all of a
program's state — one value describing everything the program currently knows.

## Msg

In [The Elm Architecture](the-elm-architecture.md), the type listing every event
a program can respond to. Each constructor is one kind of event; the interface
emits `Msg` values, and [`update`](#the-elm-architecture) turns each into the
next [`Model`](#model).

## pure function

A function whose result depends only on its arguments and which changes nothing
outside itself — the same arguments always produce the same result. The default
in Ipê; effects are expressed as [`Task`](#task) values instead. See
[pure functions and immutability](pure-functions.md).

## record update

The `{ value | field = newValue }` syntax, producing a new record equal to
`value` but with `field` replaced. The original record is unchanged. See
[pure functions](pure-functions.md).

## Result

The type of a computation that may fail with a reason: `Ok a` (success) or
`Err e` (failure carrying an error). Where [`Maybe`](#maybe) says only "no
value", `Result` says why. See [`Ipe.Result`](../reference/stdlib/Result.md).

## shape

Which kind of program an entry point produces — Web, WebView, Terminal, or
Program. The compiler infers the shape from the function `main` is bound to.

## string interpolation

Substituting a value into text with `{{expr}}` inside a
[triple-quoted string](#triple-quoted-string). The value must be a `String`,
`Int`, `Float`, `Bool` or `Char`; it is rendered by the compiler's internal
renderer and joined with `++`; only a simple reference interpolates.
Prefer it over a long `++` chain. See
[`string-interpolation`](../constructs/string-interpolation.md).

## Task

A value describing an effect — printing, reading a file, querying a database —
without performing it. Your program builds a `Task`; the runtime is the single
place that runs it, which keeps the rest of the program [pure](#pure-function).
See [`Ipe.Task`](../reference/stdlib/Task.md).

## triple-quoted string

A multiline string literal written between `"""` delimiters. Its opening-line
indentation margin is stripped, and it is the only place
[string interpolation](#string-interpolation) applies. See
[`string-interpolation`](../constructs/string-interpolation.md).

## type annotation

A written type for a definition, such as `double : Int -> Int`. Optional, because
the compiler [infers](types.md) types on its own, but conventional on top-level
definitions: it documents the code and pins the type at the definition. A written
annotation must agree with the inferred type.

## type variable

A lowercase name in a signature (`a`, `msg`) standing for any type — the same one
everywhere it appears. `List.map : (a -> b) -> List a -> List b` works for any
`a` and `b`. Contrast an uppercase name, which is a concrete or named type. See
[types](types.md).
