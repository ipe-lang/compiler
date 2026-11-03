# Parse, don't validate

**The idiom:** at every boundary where untyped input enters your program, turn it
into a **typed value once** with a function that returns `Maybe`/`Result` — rather
than checking the raw value repeatedly and passing it along untyped. A value that
type-checks is then known-good everywhere downstream.

## The shape

A *validator* answers a yes/no question and hands the raw value back unchanged, so
every later user has to trust that the check happened — and re-check to be safe. A
*parser* answers the same question but returns a **new type** that can only exist
when the check passed. The proof of validity travels in the type.

## Why prefer it

From [`examples/shapes/script/parse-port`](https://github.com/ipe-lang/compiler/tree/main/examples/shapes/script/parse-port).
The boundary parser turns a `String` into a `Maybe Port`:

```ipe
parsePort : String -> Maybe Port
parsePort raw =
    case String.toInt raw of

        Nothing ->
            Nothing

        Just n ->
            if n > 0 && n <= 65535 then
                Just { number = n }

            else
                Nothing
```

The `Maybe` in the return type is the whole point: an un-parsable or out-of-range
string *cannot* produce a `Port`. Downstream code takes a `Port`, never a raw
`String` or `Int`, so it does no checking of its own:

```ipe
describe : Port -> String
describe port_ =
    "listening on " ++ String.fromInt port_.number
```

`describe` cannot be handed an invalid port — there is no way to construct one. The
range check exists in exactly one place; every function that holds a `Port` already
knows it is `1..65535`. This is
[make invalid states unrepresentable](../guide/types.md) applied at the input edge.

## When not to reach for it

The parser earns its keep when the parsed type is *used* — when several places rely
on the invariant. For a one-off check with no value carried onward, a plain
`Bool`-returning test is enough. And do not smuggle a validator in parser's
clothing: if the function returns the input unchanged, it is still a validator.

## References

- [Types and inference](../guide/types.md) — `Maybe`, `Result`, and making invalid
  states unrepresentable.
- [`Ipe.String`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/String.md) — the `toInt` / `toFloat` / `isEmail`
  parsers this idiom builds on.
- [`PRINCIPLES.md`](https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md) — parse-don't-validate as a project
  principle.
