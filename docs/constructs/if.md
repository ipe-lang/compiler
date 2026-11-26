---
kind: syntax
title: "if: conditional expression"
summary: "Choose between two expressions based on a Bool condition."
aliases: ["if-then-else", "conditional"]
see_also: ["case", "let"]
---

# `if` — conditional expression

The code examples in this page are illustrative Ipê source snippets, not shell commands.

An `if` expression picks one of two branches based on a `Bool`. Both branches
must have the same type, because `if` is an expression — it always produces
a value.

## Basic form

```ipe
if condition then
    trueResult
else
    falseResult
```

## Simple example

```ipe
classify : Int -> String
classify n =
    if n > 0 then
        "positive"
    else
        "non-positive"
```

## Nesting

`if` expressions can nest in the `else` branch to check a sequence of
conditions:

```ipe
sign : Int -> String
sign n =
    if n > 0 then
        "positive"
    else if n < 0 then
        "negative"
    else
        "zero"
```

## Both branches must agree in type

The compiler checks that `then` and `else` produce the same type. If they
disagree you get IPE-T0001 (type mismatch):

```ipe ipe:error IPE-T0001
badBranch : Bool -> Int
badBranch flag =
    if flag then
        42
    else
        "oops"
```

Fix by giving both branches the same type:

```ipe
goodBranch : Bool -> Int
goodBranch flag =
    if flag then
        42
    else
        0
```

## `if` vs `case`

For a `Bool`, `if` is the right tool. For a union with more than two
constructors, prefer `case` — it enumerates every constructor and the compiler
checks exhaustiveness.

## Glossary

- **condition** — the `Bool` expression between `if` and `then`.
- **branch** — the `then` or `else` expression.
- **expression** — `if` always produces a value; it is not a statement.
