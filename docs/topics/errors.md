---
kind: topic
title: "errors: typed error handling with Result"
summary: "How Ipê models failure with Result and Task, and why Result Error beats Result String."
idiom: true
aliases: ["error-handling", "result", "result-error", "failure"]
see_also: ["effects", "main", "state"]
---

# `errors` — typed error handling with Result

The code examples in this page are illustrative Ipê source snippets, not shell commands.

Ipê has no exceptions. A function that can fail returns a `Result` — a value
that is either `Ok result` (success) or `Err error` (failure). The compiler
forces you to handle both cases, so a failure can never be silently ignored.

## The Result type

```ipe
type Result err ok
    = Err err
    | Ok ok
```

`Result` is a built-in union type with two type parameters: the error type and
the success type.

## A simple fallible function

```ipe
divide : Int -> Int -> Result String Int
divide numerator denominator =
    if denominator == 0 then
        Err "cannot divide by zero"
    else
        Ok (numerator // denominator)
```

The caller must handle both `Err` and `Ok`:

```ipe
showDivision : Int -> Int -> String
showDivision a b =
    case divide a b of
        Ok result ->
            String.fromInt result

        Err message ->
            "Error: " ++ message
```

## Idiom: `Result Error`, not `Result String`

Use a custom `type` for your error, not `String`. A `String` error loses
the structure that lets callers handle each failure mode differently:

```ipe ipe:skip
-- Illustrative anti-pattern: compiles, but callers cannot distinguish error kinds
safeDivide : Int -> Int -> Result String Int
safeDivide a b =
    if b == 0 then Err "division by zero" else Ok (a // b)
```

```ipe
-- Correct: each failure mode is a named constructor
type MathError
    = DivisionByZero
    | Overflow

safeDivide : Int -> Int -> Result MathError Int
safeDivide a b =
    if b == 0 then
        Err DivisionByZero
    else
        Ok (a // b)
```

With a typed error, a caller can `case` on the error and respond
differently to `DivisionByZero` vs `Overflow` — impossible with a `String`.

## Chaining with Result.andThen

When several steps can each fail, chain them with `Result.andThen`:

```ipe
type ParseError
    = EmptyInput
    | NotANumber

parsePositive : String -> Result ParseError Int
parsePositive input =
    if String.isEmpty input then
        Err EmptyInput
    else
        case String.toInt input of
            Nothing ->
                Err NotANumber

            Just n ->
                Ok n

doublePositive : String -> Result ParseError Int
doublePositive input =
    parsePositive input
        |> Result.andThen (\n -> Ok (n * 2))
```

## Task and errors

A `Task Error result` is like a `Result` that also runs effects. The `Error`
type parameter is the same idea: a named type, not a `String`. When a `Task`
fails, it carries a typed `Error` value that you handle in `Task.onError` or
at the top-level `main` boundary.

## Result.map for pure transformation

When you want to transform only the success value, use `Result.map`:

```ipe
parsed : Result ParseError Int
parsed =
    parsePositive "42"
        |> Result.map (\n -> n + 1)
```

## Glossary

- **`Result err ok`** — a value that is either `Ok ok` or `Err err`.
- **`Result.andThen`** — chains two fallible operations; short-circuits on `Err`.
- **`Result.map`** — transforms the `Ok` value; passes `Err` through unchanged.
- **typed error** — a `type` whose constructors name each failure mode, enabling exhaustive handling.
