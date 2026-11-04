---
kind: topic
title: "arithmetic: Int and Float totality"
summary: "What Int and Float arithmetic guarantee in Ipê: an out-of-range or non-finite result is always a typed error, never a wrapped, saturated, or truncated number."
idiom: true
aliases: ["overflow", "int-overflow", "division-by-zero", "non-finite", "output-ceiling", "totality"]
see_also: ["errors", "main"]
---

# `arithmetic` — Int and Float totality

The code examples in this page are illustrative Ipê source snippets, not shell commands.

`Int` is 64-bit two's-complement; `Float` is IEEE 754 double precision. Every
arithmetic operation is total: it either returns its exact result, or the
program ends in a typed error. No operation wraps, saturates, or truncates a
result that does not fit — a wrong number never stands in for the right one.

## The three ways arithmetic can end in error

- **`IntOverflow`** — an `Int` operation's exact result lies outside the
  64-bit range. Raised by `+`, `-`, `*`, `//`, `negate`, `abs`, `List.sum`,
  and `List.product`, and by `floor`, `ceil`, `round`, and `trunc` when a
  finite `Float` lies outside the `Int` range.
- **`NonFiniteToInt`** — `floor`, `ceil`, `round`, or `trunc` meets a `Float`
  that is NaN or an infinity, which has no `Int` value.
- **`OutputCeiling`** — a kernel whose output size an `Int` argument chooses
  (`List.repeat`, `List.range`, `String.repeat`, `String.padLeft`,
  `String.padRight`, `String.pad`) is asked for more than its declared
  ceiling.

An `IntOverflow` or `NonFiniteToInt` carries the `InvalidInput` error kind:
the operands admit no `Int` result at any bound, so no larger limit would
accept them. An `OutputCeiling` carries `LimitExceeded`: a larger declared
bound would accept the same input. Both surface the same way — see
[`errors`](errors) for how a `Task` failure reaches your program.

## `Int` arithmetic

`Int` ranges from `-9223372036854775808` to `9223372036854775807` (64-bit
two's-complement). `+`, `-`, `*`, and `//` either return the exact result or
end in a typed `IntOverflow` error — never a wrapped number. This also covers
the least `Int` divided by `-1`, and `negate` or `abs` of the least `Int`,
each of which has no result in range:

```ipe
addChecked : Int -> Int -> Int
addChecked a b =
    a + b
```

## Division and modulo by zero are not range errors

`x // 0` is `0`, and `Basics.modBy 0 x` is `0` — both match Elm. Only a
result that falls outside the 64-bit range trips `IntOverflow`; dividing by
zero never does:

```ipe
divideByZero : Int -> Int
divideByZero x =
    x // 0
```

## Idiom: let the error surface through `Task`

An arithmetic trip raised while building a value a `Task` step computes
reaches your program the same way any other `Task` failure does — as a typed
`Error` your `main` chain can observe. Compute values that might overflow as
part of a `Task` step, not as a bare top-level expression, so a failure
reaches the typed-error contract rather than aborting the process outright:

```ipe
import Ipe.Io as Io
import Ipe.String as String
import Ipe.Task as Task


divide : Int -> Int -> Task Error Int
divide a b =
    Task.succeed (a // b)


main : Task Error ()
main =
    divide 10 2
        |> Task.andThen (\result -> Io.println (String.fromInt result))
```

## `Float` to `Int`

`floor`, `ceil`, `round`, and `trunc` take a `Float` to an `Int`. A non-finite
`Float` (NaN or an infinity) ends in a typed `NonFiniteToInt` error; a finite
`Float` outside the `Int` range ends in `IntOverflow`. Neither saturates to
the nearest representable `Int`:

```ipe
import Ipe.Math as Math


roundToNearest : Float -> Int
roundToNearest x =
    Math.round x
```

`round` ties toward positive infinity: `Math.round 2.5 == 3` and
`Math.round (-3.5) == -3`.

## Bitwise shifts are total

`Bitwise.shiftLeftBy`, `shiftRightBy`, and `shiftRightZfBy` mask their offset
to the low 6 bits (`offset & 63`) before shifting, so every offset is total —
`shiftLeftBy 65 1` and `shiftLeftBy 1 1` give the same result. A shift never
traps and never needs a range check on its offset.

## Size ceilings on input-chosen output

`List.repeat`, `List.range`, `String.repeat`, and the `String` padding
functions build output whose size an `Int` argument chooses. Each refuses a
request past its declared ceiling with a typed `OutputCeiling` error, before
allocating anything — never a truncated list or string:

| Kernel | Ceiling |
|---|---|
| `List.repeat`, `List.range` | 10,000,000 elements |
| `String.repeat` | 67,108,864 bytes (64 MiB of UTF-8) |
| `String.padLeft`, `String.padRight`, `String.pad` | 16,000,000 characters |

```ipe
import Ipe.List as List


repeated : Int -> List Int
repeated n =
    List.repeat n 0
```

The full table, and how it compares to the Elm functions it mirrors, is
recorded in `docs/divergences-from-elm.md`.

## Glossary

- **`IntOverflow`** — an `Int` operation's exact result lies outside the
  64-bit range; error kind `InvalidInput`.
- **`NonFiniteToInt`** — a `Float`-to-`Int` conversion met NaN or an
  infinity; error kind `InvalidInput`.
- **`OutputCeiling`** — a size-choosing kernel was asked for more output
  than its declared ceiling; error kind `LimitExceeded`.
- **total** — defined for every input in its type; no input reaches an
  unchecked panic, a silent wrap, or a silent truncation.
