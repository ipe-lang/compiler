# Math

`Ipe.Math` is the numeric toolkit: roots and powers, logs and exponentials,
trigonometry, rounding, and the constants (`pi`, `e`). This guide is not a tour of
the function list — `ipe doc Ipe.Math` is that. It is the handful of ideas that
decide *which* function you reach for.

## The mental model

Three knots.

- **Float in, Float out — rounding is the bridge to `Int`.** `sqrt`, `pow`,
  `hypot`, the trig and log families all take and return `Float`. When you need a
  whole number back, that is a deliberate *conversion*, and there are four of them
  that differ only in direction: `floor` (down), `ceil` (up), `round` (nearest),
  `trunc` (toward zero). All four are `Float -> Int`. Picking the wrong direction
  is the classic off-by-one; picking on purpose is the point.
- **NaN is a Float value, not an error — and it is not equal to itself.**
  `sqrt (-1)` does not crash and does not throw; it produces `NaN`, an ordinary
  `Float`. The trap: `NaN == NaN` is `False`, so an equality check will *miss* it.
  Test with `Math.isNaN`, the only correct way. The same holds for `inf`/`nan` as
  values you can name and compare structurally.
- **`min`/`max` are polymorphic; the arithmetic operators are not `Math`.**
  `Math.min`/`Math.max` work on any comparable type, not just numbers. But
  everyday `+`, `-`, `*`, and integer `//`/`modBy` are language operators (see
  `Ipe.Basics`), not `Math` functions — reach into `Math` for the
  *scientific* operations, not for addition.

## A worked example: the length of a path

The example under
[`examples/shapes/script/math-path-length`](../../examples/shapes/script/math-path-length/src/Main.ipe)
measures the total length of a 2-D path and reports it four ways, then shows NaN
detection.

The segment distance is `Math.hypot` — `sqrt(dx² + dy²)` computed without
intermediate overflow, the idiomatic 2-D distance:

```ipe
distance : Point -> Point -> Float
distance a b =
    Math.hypot (b.x - a.x) (b.y - a.y)
```

The four rounding functions on one value make their directions visible at a
glance — the first knot, concretely:

```ipe
roundingReport : Float -> String
roundingReport v =
    String.join "  "
        [ "floor=" ++ String.fromInt (Math.floor v)
        , "ceil=" ++ String.fromInt (Math.ceil v)
        , "round=" ++ String.fromInt (Math.round v)
        , "trunc=" ++ String.fromInt (Math.trunc v)
        ]
```

And NaN is detected structurally — `sqrt (-1)` is `NaN`, caught by `isNaN`, never
by `==`:

```ipe
sqrtReport : Float -> String
sqrtReport v =
    let
        r =
            Math.sqrt v
    in
    if Math.isNaN r then
        "sqrt " ++ String.fromFloat v ++ " = NaN (no real root)"

    else
        "sqrt " ++ String.fromFloat v ++ " = " ++ String.fromFloat r
```

Running it (`ipe dev run`) prints — note the four rounding directions differ on a
fractional length, and the negative square root is caught:

```
path length: 8.60555127546399
rounded: floor=8  ceil=9  round=9  trunc=8
sqrt 2 = 1.4142135623730951
sqrt -1 = NaN (no real root)
```

## The why

Returning `NaN` as a value rather than throwing is [soundness][principles] in the
numeric domain: a well-typed program cannot fall over on `sqrt (-1)` or `log 0` —
the result is a `Float` you can inspect with `isNaN` and handle, not a panic that
takes the process down. That is the whole reason `sqrt : Float -> Float` is total
rather than `Float -> Result`.

The four separate rounding functions are [ease of use][principles] and
[correctness][principles] together: rather than one `round` with a hidden
mode argument you might set wrong, each direction is its own named function, so
the code *says* which rounding it means and a reader cannot misread it.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Math` — every function and constant with
  a verified example. `ipe doc Ipe.Math.atan2` covers the quadrant-aware
  arctangent (two arguments, unlike unary `atan`).
- **Sibling guides:** [Lists](../reference/stdlib/List.md) — `sum`, `map2`, and the
  folds this example builds on. The everyday arithmetic operators live in
  `Ipe.Basics` (see `ipe doc Ipe.Basics`).
- **Concepts:** [Types and inference](types.md) — how `Int` and `Float` are kept
  distinct, and why rounding is an explicit conversion between them.
