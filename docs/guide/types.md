# Types and inference

Every value in Ipê has a type, and the compiler knows it before the program
runs. You rarely have to write types down — the compiler infers them — but they
are always there, and they are what rule out whole classes of mistake. This page
covers where types come from, how absence and failure are encoded as types, and
why "it type-checks" is a strong statement in Ipê.

## Inference: types you do not have to write

The compiler works out the type of every expression from how it is used. This
function has no annotation, yet its type is fully known:

```ipe
double n =
    n * 2
```

`*` is arithmetic, so `n` must be a number and `double` is `Int -> Int`. Call it
on a string and the compiler rejects the program before it builds — not at
runtime.

You can still write a [type annotation](glossary.md#type-annotation), and on
top-level definitions it is good practice:

```ipe
double : Int -> Int
double n =
    n * 2
```

The annotation documents the function and pins the type at the definition, so a
mistake is reported there rather than at some distant call site. A signature you
write must agree with what the compiler infers, or the program is rejected.

## Reading a type signature

A signature is read left to right, with `->` separating arguments from the
result:

- `Int -> Int` — takes an `Int`, returns an `Int`.
- `List String -> String` — takes a list of strings, returns a string.
- `(a -> b) -> List a -> List b` — takes a function and a list, returns a list.
  A **lowercase** name like `a` is a *type variable*: it stands for any type,
  the same one everywhere it appears. This is [`List.map`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/List.md):
  give it a function from `a` to `b` and a list of `a`, get back a list of `b`.

An **uppercase** name is a concrete type (`Int`, `String`, `Bool`) or a named
type you or the standard library declared (`Maybe`, `Result`, `Task`).

## Absence is a type: `Maybe`

Many languages let any value secretly be null, so any dereference can crash. Ipê
has no null. A function that might not have an answer says so in its type by
returning a [`Maybe a`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/Maybe.md) — either `Just a` (a value) or
`Nothing` (no value):

```ipe
-- Parse a port number, keeping only values in range.
parsePort : String -> Maybe Int
parsePort text =
    case String.toInt text of
        Just n ->
            if n >= 1 && n <= 65535 then Just n else Nothing

        Nothing ->
            Nothing
```

[`String.toInt`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/String.md) returns `Maybe Int` because not every
string is a number. To *use* the result you must handle both cases — the
compiler will not let you treat a `Maybe Int` as an `Int`:

```ipe
describe : String -> String
describe text =
    case parsePort text of
        Just n ->
            text ++ " -> port " ++ String.fromInt n

        Nothing ->
            text ++ " -> not a valid port"
```

Running `describe` on a few inputs:

```
8080 -> port 8080
99999 -> not a valid port
https -> not a valid port
```

The `case … of` is *exhaustive*: it must cover every constructor of the type. If
you handle `Just` and forget `Nothing`, the program does not compile. That is
how the type system forces the missing case to be considered rather than
discovered in production.

## Failure with a reason: `Result`

`Maybe` says "there is no value". When you also need to say *why* it failed, use
[`Result e a`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/Result.md) — either `Ok a` (success) or `Err e`
(failure carrying an error `e`). Parsing and validation typically return a
`Result` whose `Err` describes what was wrong. At the boundary where effects run
— a file read, a database query — the error type is
[`Ipe.Error`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/Error.md), a typed, matchable value rather than a
string.

## Making invalid states unrepresentable

Because you declare your own types, you can shape them so that impossible
combinations cannot even be written. A record with two independent boolean flags
admits four states, some of which may be nonsense; a single type with exactly
the valid cases admits only those:

```ipe
type Link
    = Disconnected
    | Connecting
    | Connected String
```

A `Link` is exactly one of these, and `Connected` always carries its address.
There is no "connected but no address" state to guard against, because it cannot
be constructed. Designing types this way moves error checking from runtime into
the compiler.

## Why "it type-checks" is strong here

Ipê's [Soundness][principles] guarantee is that a well-typed program cannot
trigger a runtime failure in the generated code — no null dereference, no
out-of-bounds index, no unchecked cast. The compiler will not accept a program
that could do those things. So a program that type-checks has already been
proven free of an entire category of crashes. That is the payoff for handling
every `Maybe`, covering every `case`, and shaping your types to exclude the
impossible.

[principles]: https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md

## Where to go next

- [The Elm Architecture](the-elm-architecture.md) — types in the large: how a
  whole interactive program is one `Model` type and one `Msg` type.
- [`Ipe.Maybe`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/Maybe.md) and
  [`Ipe.Result`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/Result.md) — the full combinator reference.
- [Glossary](glossary.md) — `type variable`, `constructor`, `exhaustive`, and
  more.
```
