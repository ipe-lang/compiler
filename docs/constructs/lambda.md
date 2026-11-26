---
kind: syntax
title: "lambda: anonymous functions"
summary: "Write an inline function with \\param -> body without giving it a name."
aliases: ["anonymous-function", "closure", "backslash-lambda"]
see_also: ["let", "pipe", "case"]
---

# `lambda` — anonymous functions

The code examples in this page are illustrative Ipê source snippets, not shell commands.

A lambda is an unnamed function written inline. Use it when a function is only
needed once — for a `List.map` callback, a `Task.andThen` continuation, or any
spot where naming the function separately would be more ceremony than clarity.

## Basic form

```ipe
\param -> body
```

The backslash `\` introduces the lambda. One or more parameter names follow,
then `->`, then the body expression.

## Single parameter

```ipe
double : List Int -> List Int
double xs =
    List.map (\n -> n * 2) xs
```

## Multiple parameters

```ipe
add : List Int -> List Int -> List Int
add xs ys =
    List.map2 (\x y -> x + y) xs ys
```

## Lambdas as values

A lambda is a value. Bind it to a name with `let` or pass it directly:

```ipe
main : Task Error ()
main =
    let
        greet name = "Hello, " ++ name
    in
    Io.println (greet "world")
```

## In Task.andThen chains

The most common use of `\_ ->` is discarding the result of one `Task` step
before running the next:

```ipe
main : Task Error ()
main =
    Io.println "first"
        |> Task.andThen (\_ -> Io.println "second")
        |> Task.andThen (\_ -> Io.println "third")
```

## Lambdas cannot be stored in record fields

A function value in a record field is not supported (IPE-L0107). Use a union
type and `case` to model varying behaviour. See [`state`](state).

## Glossary

- **lambda** — an anonymous function: `\param -> body`.
- **closure** — a lambda that captures names from its surrounding scope.
- **continuation** — a lambda passed to `Task.andThen` to run after a `Task` completes.
