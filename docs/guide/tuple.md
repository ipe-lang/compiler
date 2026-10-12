# Tuples

A pair `( a, b )` bundles two values of possibly different types into one. It is
Ipê's lightweight, anonymous product — and `Ipe.Tuple` gives the handful of
helpers for building and transforming pairs without unpacking them by hand.

## The mental model

Three knots.

- **A pair is an anonymous, positional bundle — reach for it for the *transient*
  case.** `( min, max )`, `( key, value )`, one element of a zip: two things
  travelling together for a moment. There are no field names, so a reader tells
  the components apart by position. When the two things are a *lasting domain
  concept*, a record with named fields is the better home; a pair is for the
  passing value that does not deserve a type of its own.
- **`mapFirst`/`mapSecond`/`mapBoth` transform in place.** Rather than destructure
  a pair, change a component, and rebuild it, `Tuple.mapBoth f g` applies `f` to
  the first and `g` to the second and hands back the new pair — one expression, no
  unpacking.
- **`Tuple.pair` is a constructor function.** `Tuple.pair a b` is `( a, b )`, but
  as a *named function* it slots straight into combinators that want a
  two-argument builder — `Maybe.map2 Tuple.pair`, `List.map2 Tuple.pair` — where
  the bare `( , )` syntax cannot go.

## A worked example: coldest and warmest in one pass

The example under
[`examples/shapes/script/tuple-minmax`](../../examples/shapes/script/tuple-minmax/src/Main.ipe)
finds the minimum and maximum of a list of readings in a single fold, carrying
both in a pair.

The accumulator *is* a pair — the transient two-things bundle a tuple is for.
`Tuple.mapBoth` updates both components at once: shrink the running minimum, grow
the running maximum, in one step, without taking the pair apart:

```ipe
extremes xs =
    case xs of

        first :: rest ->
            List.foldl widen ( first, first ) rest
                |> Just

        [] ->
            Nothing


widen x range =
    Tuple.mapBoth (min x) (max x) range
```

Reading the result back is positional — `Tuple.first`/`Tuple.second`, no field
names, because the pair is a passing value rather than a declared type:

```ipe
report range =
    "coldest "
        ++ String.fromFloat (Tuple.first range)
        ++ "°C, warmest "
        ++ String.fromFloat (Tuple.second range)
        ++ "°C"
```

Running it (`ipe dev run`) prints:

```
coldest 14.2°C, warmest 27.3°C
```

## The why

Returning a `Maybe ( Float, Float )` rather than a pair of sentinels keeps [make
invalid states unrepresentable][principles] in play: an empty list has no min or
max, so the *absence* is modelled by `Nothing`, not by a `( 0, 0 )` that a caller
might mistake for a real reading.

Keeping the pair *anonymous* is a deliberate [ease of use][principles] boundary:
the tuple is cheap and nameless precisely because it is transient, which is also
the signal for *when not to use one* — the moment the two values gain meaning that
outlives the fold, they earn a record with named fields, and the compiler-checked
names stop a reader from mixing up "first" and "second". `Tuple.pair` as a first
-class function is [composition][principles]: it lets the pair constructor flow
into `map2`-style combinators just like any other builder.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Tuple` — every helper with a verified
  example. `ipe doc Ipe.Tuple.mapBoth` and `ipe doc Ipe.Tuple.pair` cover the two
  idioms above.
- **Sibling guides:** [Lists](list.md) — `List.partition` and `List.map2` produce
  and consume pairs; `foldl` here carries one as its accumulator. [Strings](string.md)
  — the `String.indexes` delimiters were combined into a pair with
  `Maybe.map2 Tuple.pair`. [Maybe](maybe.md) — the absence wrapper the fold returns.
- **Concepts:** [Types and inference](types.md) — how a pair's two component types
  are tracked, and when a record with named fields is the better tool.
