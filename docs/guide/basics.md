# The prelude (`Ipe.Basics`)

A handful of names are in scope in *every* Ipê module with no import: `identity`,
`always`, `not`, `fst`, `snd`, `clamp`, `modBy`, `negate`, `abs`, `sqrt`,
`min`, `max`, and `compare`. This is the implicit prelude — the smallest
set of helpers a program reaches for constantly, so common code stays free of
ceremony.

## The mental model

Three knots.

- **`clamp lo hi x` pins a value into a range.** It returns `lo` if `x` is below
  the band, `hi` if above, and `x` otherwise — the fail-closed way to admit a
  possibly-out-of-bounds value without an `if lo <= x && x <= hi then … else …`
  ladder. An unexpected spike becomes a boundary value, never an escape.
- **`compare a b : Order` is the one ordering primitive.** It yields `LT`, `EQ`,
  or `GT`. Sorting (`List.sortWith`), `min`, and `max` are all phrased in terms of
  it — when you need a custom order, you return an `Order` from `compare`, you
  don't invent a `<`-and-`>` pair. `compare` carries an implicit `Comparable`
  bound, so it works on `Int`, `Float`, `String`, `Char`, and `Bool` but rejects a
  list, tuple, record, or function.
- **Rendering to text is explicit and lives in `Ipe.String`.** The prelude has
  no generic stringifier: `String.fromInt`, `String.fromFloat`, and
  `String.fromBool` each name the type they render, so the call site shows what
  becomes text. A serialized payload uses a real encoder
  ([Text encodings](encoding.md)) instead.

A note on negative literals: `clamp -40 …` parses as the *subtraction* `clamp - 40`.
Write a negative with the prelude's own `negate`: `clamp (negate 40) 125 x`.

## A worked example: normalizing sensor readings

The example under
[`examples/shapes/script/basics-clamp-normalize`](../../examples/shapes/script/basics-clamp-normalize/src/Main.ipe)
takes a list of raw thermostat readings — some physically impossible — and pins
each into the trusted band, sorts them coldest-first, and reports the range.

A thermostat only trusts a reading in `[ -40, 125 ]`. `clamp` pins each one into
that band, so a stuck-high or stuck-low sensor becomes a boundary value rather
than poisoning the result — the conservative, in-range outcome by construction:

```ipe
normalize : Reading -> Reading
normalize reading =
    { reading | celsius = clamp (negate 40) 125 reading.celsius }
```

Sorting is one `sortWith` over `compare`, which returns the `Order` the sort
needs — no bespoke comparison operators:

```ipe
byTemp : Reading -> Reading -> Order
byTemp a b =
    compare a.celsius b.celsius
```

`min` and `max` collapse the list to its extremes inside a `foldl`, and
`String.fromInt` renders each `Int` for the report:

```ipe
render : Reading -> String
render reading =
    String.padRight 8 ' ' reading.sensor ++ String.fromInt reading.celsius ++ " C"
```

Running it (`ipe dev run`) clamps the two impossible readings to the band edges,
orders the rest, and prints the range:

```
Sensor readings (clamped to [-40, 125], coldest first):
  cellar  -40 C
  hall    21 C
  attic   125 C
Range: -40 C .. 125 C
```

## The why

`clamp` is [security][principles] and [soundness][principles] in one small
function: given an input a remote party could set, it guarantees the value that
flows onward is within a declared bound — the fail-closed default the principles
demand, with no branch to forget. The out-of-range case has no path past it.

A single `compare` returning an `Order` is [make invalid states
unrepresentable][principles]: an ordering is one of exactly three outcomes, so a
comparator can't return a nonsensical "both greater and less" — and every ordered
operation (`sort`, `min`, `max`) builds on that one primitive rather than each
re-deriving comparison. The prelude stays to the few names
worth having everywhere; anything larger earns its own import, which is
[ease of use][principles]: the common path is ceremony-free, the specialized path
is explicit.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Basics` — every prelude member with a
  verified example. `ipe doc Ipe.Basics.clamp`, `ipe doc Ipe.Basics.compare`, and
  `ipe doc String.fromInt` cover the three idioms above.
- **Sibling guides:** [Lists](list.md) — `sortWith`, `foldl`, and `map`, which the
  example threads the readings through. [Maybe](maybe.md) and [Result](result.md) —
  the absence and failure types the prelude deliberately leaves out, imported when
  needed. [Math](math.md) — `sqrt`, `abs`, and the numeric functions beyond the
  prelude's core.
- **Concepts:** [Types and inference](types.md) — how the `Comparable` bound on
  `compare` is checked. [Pure functions and
  immutability](pure-functions.md) — why `normalize` returns a fresh record rather
  than mutating one.
