# Money

`Ipe.Money` is a currency-typed amount: a [`Decimal`](decimal.md) magnitude and an
ISO-4217 `Currency` in one value. The currency is part of the *type*, so the
operations that would silently produce a wrong number — adding two different
currencies, losing a cent in a split — are turned into typed errors or made
impossible.

## The mental model

Three knots.

- **A `Money` carries its currency, so a cross-currency add is a typed `Err`.**
  `Money.add : Money -> Money -> Result Error Money` returns `Err` when the two
  currencies differ, never a meaningless sum of dollars and euros. To combine
  across currencies you `Money.convert` first, at a rate you set explicitly — the
  conversion is a visible step, not a hidden coercion.
- **`allocate n` splits an amount into parts that sum back *exactly*.**
  `Money.allocate 3 total` divides a value across `n` recipients as evenly as
  possible and distributes the leftover cent(s) so the parts add up to the input to
  the penny — no money is lost or invented. The part count is bounded, so a
  caller-controlled `n` can't exhaust memory.
- **The magnitude is a `Decimal`, so percentages and sums are exact.** There is no
  float drift: 18% of `$100.00` is `$18.00`, computed on the arbitrary-precision
  [`Decimal`](decimal.md) underneath, then rendered by `Money.format` with the
  currency's own minor-unit rules.

## A worked example: splitting a restaurant bill

The example under
[`examples/shapes/script/money-split-bill`](../../examples/shapes/script/money-split-bill/src/Main.ipe)
adds an 18% tip to a bill, splits it three ways, verifies the parts re-sum to the
total, and shows a cross-currency add being rejected.

The bill is a `Money` in USD; the tipped total is exact decimal arithmetic wrapped
back into the same currency:

```ipe
bill : Money
bill =
    Money.fromMajor USD 100


withTip : Money
withTip =
    Money.mul (Decimal.fromString "1.18" |> Result.withDefault Decimal.one) bill
```

`allocate` splits the tipped total three ways. The residue lands on the first
share, so the three parts sum to the input *exactly* — `Money.sumOf` recovers it
to the penny:

```ipe
shares =
    Money.allocate 3 withTip

resummed =
    Money.sumOf USD shares
```

Adding a euro amount to the dollar bill is a currency mismatch — `Money.add`
returns `Err`, so the impossible sum has no value to leak downstream:

```ipe
crossCurrency =
    Money.add bill (Money.fromMajor EUR 50)
```

Running it (`ipe dev run`):

```
Bill + 18% tip: $118.00
Split 3 ways (parts sum to the total exactly):
  diner 1: $39.34
  diner 2: $39.33
  diner 3: $39.33
Re-summed shares: $118.00
USD + EUR: rejected (currency mismatch — a typed Err, not a bad number)
```

The shares are `$39.34 + $39.33 + $39.33 = $118.00` — the extra cent is placed,
not dropped.

## The why

Carrying the currency in the type is [make invalid states
unrepresentable][principles] applied to money: a value's *role* — which currency
it is — lives in its type, so a dollar amount and a euro amount are different
types that can't be added by accident. The cross-currency add has no meaningful
result, so the API gives it none; it returns `Err`, and the wrong number never
exists.

`allocate` summing back to the input exactly is [correctness][principles] at the
cent: a naïve `total / n` rounded per share silently loses or invents money, a
real bug in any billing system. The fair-residue split makes the sum-preservation
an invariant of the function, not something each caller must re-check. And the
`Decimal` magnitude keeps every percentage and total [correct][principles] where
binary floats would drift — the reason financial code never uses `Float` for an
amount.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Money` — every function with a verified
  example. `ipe doc Ipe.Money.convert`, `ipe doc Ipe.Money.setRate`, and
  `ipe doc Ipe.Money.getRate` cover the FX-rate registry;
  `ipe doc Ipe.Money.allocate` the fair split.
- **Sibling guides:** [Decimal](decimal.md) — the exact-arithmetic magnitude every
  `Money` is built on. [Result](result.md) — the failure type a currency mismatch
  or a bad conversion returns. [Lists](list.md) — `allocate` returns a list of
  shares; `sumOf` folds one back. [Strings](string.md) — formatting the rendered
  amounts.
- **Concepts:** [Types and inference](types.md) — how the `Currency` in a `Money`'s
  type is tracked. [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — `Money.fromString` at the boundary.
