---
kind: syntax
title: "let: local bindings"
summary: "Bind a name to an intermediate value inside an expression. Bindings are immutable."
aliases: ["let-in", "local-binding"]
see_also: ["case", "lambda", "do"]
---

# `let` — local bindings

The code examples in this page are illustrative Ipê source snippets, not shell commands.

A `let` expression gives a name to an intermediate result so you can use it
without repeating the computation. Every binding in Ipê is immutable — once
bound, the name always refers to the same value.

## Basic form

```ipe
let
    name = expression
in
anotherExpression
```

The `in` part is the body of the `let` — the expression where `name` is in
scope.

## Single binding

```ipe
greeting : String
greeting =
    let
        prefix = "Hello, "
    in
    prefix ++ "world!"
```

## Multiple bindings

Bindings stack inside one `let` block. Each one may refer to earlier bindings
in the same block:

```ipe
hypotenuse : Float -> Float -> Float
hypotenuse a b =
    let
        aSquared = a * a
        bSquared = b * b
        sumOfSquares = aSquared + bSquared
    in
    sqrt sumOfSquares
```

## Function bindings

A binding can itself have parameters, making it a local function:

```ipe
main : Task Error ()
main =
    let
        double n = n + n
        triple n = n + n + n
    in
    Io.println (String.fromInt (double 5 + triple 3))
```

## `let _ = task` is not allowed

Binding a `Task` to `_` discards its effect outside the effect discipline and
is rejected (IPE-L0141). Thread effects sequentially with `Task.andThen` or use
a `do` block instead:

```ipe ipe:error IPE-L0141
main : Task Error ()
main =
    let
        _ = Io.println "oops"
    in
    Io.println "done"
```

```ipe
main : Task Error ()
main =
    Io.println "step one"
        |> Task.andThen (\_ -> Io.println "done")
```

See [`effects`](effects) for the full picture.

## Scope

A `let` binding is only in scope inside the `in` body. It is not accessible
outside the enclosing expression.

## Glossary

- **binding** — a name given to a value via `=`.
- **immutable** — the value a name is bound to cannot be changed.
- **scope** — the region of code where a name is visible.
