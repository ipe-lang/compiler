---
kind: syntax
title: "|>: the pipe operator"
summary: "Pass a value to a function left-to-right, turning nested calls into a readable top-to-bottom chain."
aliases: ["pipe", "pipe-operator", "forward-pipe", "andThen-pipe"]
see_also: ["lambda", "do", "effects"]
---

# `|>` — the pipe operator

The code examples in this page are illustrative Ipê source snippets, not shell commands.

The pipe operator `|>` passes the value on its left as the last argument to the
function on its right. It lets you write a data-transformation pipeline in the
order the steps happen, without nesting function calls inside one another.

## Basic form

```ipe
value |> function
```

is exactly the same as:

```ipe
function value
```

## Chaining transformations

Without `|>` you read inside-out:

```ipe
result : String
result =
    String.toUpper (String.trim (String.replace "o" "0" "  hello world  "))
```

With `|>` you read top-to-bottom:

```ipe
result : String
result =
    "  hello world  "
        |> String.replace "o" "0"
        |> String.trim
        |> String.toUpper
```

Both expressions produce the same value.

## Piping into Task.andThen

`|>` is the standard way to sequence `Task` effects without a `do` block:

```ipe
main : Task Error ()
main =
    Io.readLine
        |> Task.andThen (\line -> Io.println ("You typed: " ++ line))
```

See [`effects`](effects) and [`do`](do) for the full effect-sequencing picture.

## Multi-argument functions

`|>` passes the value as the **last** argument. Design your own functions with
the "data last" convention so they chain naturally:

```ipe
-- data-last: list comes last
keepPositive : List Int -> List Int
keepPositive xs =
    List.filter (\n -> n > 0) xs

result : List Int
result =
    [ -3, 1, -1, 4, -1, 5 ]
        |> keepPositive
        |> List.map (\n -> n * 2)
```

## Glossary

- **`|>`** — passes the left-hand value as the last argument to the right-hand function.
- **pipeline** — a chain of `|>` expressions transforming data step by step.
- **data-last convention** — designing functions so the primary data argument is last, enabling clean `|>` chains.
