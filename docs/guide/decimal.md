# Decimal

`Ipe.Decimal` is arbitrary-precision decimal arithmetic — the number type for
money, tax, and any quantity where a lost or invented fraction is a bug. Unlike a
binary `Float`, a `Decimal` represents `0.1` *exactly*, so decimal sums and
percentages come out right.

## The mental model

Three knots.

- **A `Decimal` from a string is exact.** `Decimal.fromString "0.1"` is exactly
  one tenth, so `0.1 + 0.2` is `0.3` — not the `0.30000000000000004` a `Float`
  gives, because `0.1` has no exact binary representation. Build a decimal from a
  string (or `fromInt` / `fromMinor`) rather than `fromFloat` when exactness
  matters; `fromFloat` inherits the float's imprecision.
- **Fallible operations return a `Result`.** `Decimal.fromString` returns
  `Result Error Decimal` (a malformed literal is a typed failure at the boundary),
  and `Decimal.div` / `Decimal.mod` return `Result` too — division by zero is an
  `Err` value, never a runtime trap. The failure is data you handle, not a crash.
- **Rounding is explicit — you pick the mode.** `Decimal.round n` is banker's
  rounding (round-half-to-even, which avoids the upward bias of always rounding
  0.5 up); `Decimal.roundHalfUp n` rounds 0.5 away from zero; `Decimal.truncate n`
  drops the tail with no rounding. Which one is correct depends on the domain — tax
  rules, accounting standards — so the choice is a named function, never a silent
  default.

## A worked example: exactness, safe division, and rounding

The example under
[`examples/shapes/script/decimal-rounding`](../../examples/shapes/script/decimal-rounding/src/Main.ipe)
shows the three knots in a few lines.

The classic float trap, avoided — `0.1 + 0.2` is exactly `0.3`:

```ipe
exactSum : String
exactSum =
    Decimal.add (dec "0.1") (dec "0.2")
        |> Decimal.toString
```

Division returns a `Result`, so a zero divisor is an `Err` value that a `case`
handles — the program can't be tripped into a trap by a runtime-supplied divisor:

```ipe
safeDivide : Decimal -> Decimal -> String
safeDivide a b =
    case Decimal.div a b of
        Ok q ->
            Decimal.toStringFixed 4 q

        Err _ ->
            "<undefined: division by zero>"
```

Rounding `2.5` at zero places two ways shows why the mode is explicit — banker's
rounds to the even `2`, half-up rounds away to `3`:

```ipe
roundingContrast =
    "banker's " ++ Decimal.toString (Decimal.round 0 half)
        ++ ", half-up " ++ Decimal.toString (Decimal.roundHalfUp 0 half)
```

Running it (`ipe dev run`):

```
0.1 + 0.2 = 0.3 (exact, not 0.3000…04)
10 / 3 = 3.3333
10 / 0 = <undefined: division by zero>
round 2.5 → banker's 2, half-up 3
```

## The why

Exact decimal arithmetic is [correctness][principles] where a `Float` cannot be:
binary floating point can't represent most decimal fractions, so a running total
of monetary amounts drifts. A `Decimal` represents the value the user typed, so
the sum is the sum. This is why financial and tax code never uses `Float` for an
amount.

`div` returning a `Result` rather than trapping on a zero divisor is
[soundness][principles]: a divisor a program computes or receives can be zero, and
the safe outcome — a handled `Err` — is the only reachable one; there is no path
where a division silently aborts the process. And making the rounding mode an
explicit function is [ease of use][principles] in service of correctness: a
"round" that silently picked one convention would be right for one domain and a
subtle bug in another, so the choice is surfaced, not hidden.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Decimal` — every function with a verified
  example. `ipe doc Ipe.Decimal.fromMinor` / `ipe doc Ipe.Decimal.toMinor` cover
  the integer-cents boundary; `ipe doc Ipe.Decimal.formatWith` locale-style output.
- **Sibling guides:** [Money](money.md) — currency-typed amounts built directly on
  `Decimal`. [Result](result.md) — the failure type `fromString`, `div`, and `mod`
  return. [Math](math.md) — `Float`-based numerics for scientific quantities where
  binary precision is fine and decimal exactness is not the point.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — `fromString` turns an untyped literal into a typed `Decimal` once, at the
  boundary.
