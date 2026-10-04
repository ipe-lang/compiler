# Dictionaries

A `Dict k v` maps **keys to values** — one value per key, looked up by key rather
than by position. Reach for it whenever you are keeping "the value *for* this
thing": a count per word, a price per SKU, a session per token.

## The mental model

Three knots, three ideas.

- **A lookup that might miss returns `Maybe`.** `Dict.get k d` is `Maybe v`, not
  `v`. An absent key yields `Nothing`, so the compiler forces you to decide what
  a miss means *before* you can touch a value — there is no "key not found"
  crash and no silent default you forgot to set. This is the whole reason a
  `Dict` cannot fall over: absence is a value you handle, not an exception you
  hope never fires.
- **Upsert is one call: `update`.** `Dict.update k f d` hands `f` the current
  value as a `Maybe v` and takes back a `Maybe v`: `Just` re-binds the key,
  `Nothing` removes it. "Increment the count for this key, starting at 1 if it's
  new" is a single `update` with no "does the key exist yet?" branch — the
  `Nothing` case *is* the fresh-key case. Folding a stream into per-key
  aggregates is the archetypal `Dict` job, and `update` is its verb.
- **Keys have no order.** `Dict.toList`, `keys`, and `values` return their
  entries in an unspecified order that can vary run to run. When a human reads the
  output, **sort it** (`List.sortBy Tuple.first`). Merging two dictionaries with
  `Dict.union` is left-biased: the left dictionary's binding wins on a key
  collision — worth remembering, because it is not symmetric.

## A worked example: a checkout tally

The example under
[`examples/shapes/script/dict-inventory`](../../examples/shapes/script/dict-inventory/src/Main.ipe)
turns a flat stream of scanned SKUs into a priced receipt. Two `Dict` idioms
carry it: `update` to tally, `get` to price.

The price book is a `Dict String Int` (SKU to cents), built with `fromList`:

```ipe
priceBook : Dict String Int
priceBook =
    Dict.fromList
        [ ( "APPLE", 60 )
        , ( "BREAD", 250 )
        , ( "MILK", 180 )
        ]
```

The scanner emits repeats. Tallying them is a `List.foldl` threading a growing
`Dict`, with `Dict.update` doing the upsert — the `Nothing` branch handles a
never-seen SKU, the `Just` branch bumps a running count:

```ipe
counts : List String -> Dict String Int
counts skus =
    List.foldl bump Dict.empty skus


bump : String -> Dict String Int -> Dict String Int
bump sku tally =
    Dict.update sku increment tally


increment : Maybe Int -> Maybe Int
increment current =
    case current of

        Nothing ->
            Just 1

        Just n ->
            Just (n + 1)
```

Pricing a line is a `Dict.get`, whose `Maybe Int` result forces the missing-SKU
case into the open. Here `"GUM"` is scanned but absent from the book, so it takes
the `Nothing` branch and is flagged rather than silently priced at zero:

```ipe
lineItem : ( String, Int ) -> String
lineItem pair =
    let
        qty =
            Tuple.second pair

        label =
            String.padRight 8 ' ' (Tuple.first pair) ++ "x" ++ String.fromInt qty ++ "  "
    in
    case priced pair of

        Just cents ->
            label ++ money (cents * qty)

        Nothing ->
            label ++ "(no price on file)"
```

Running it (`ipe dev run`) prints a receipt sorted by SKU — `Dict.toList` order is
unspecified, so the rows are sorted before printing:

```
Receipt
-------
APPLE   x3  $1.80
BREAD   x1  $2.50
GUM     x1  (no price on file)
MILK    x2  $3.60
-------
Total   $7.90
```

## The why

The `Maybe` return on `get` is [parse, don't validate][principles] at the lookup
boundary: the one place a key might be absent is the one place you handle it, and
every downstream line already holds a real value. A `Dict` that returned a bare
`v` with a "sentinel" for missing keys would push that check onto every caller and
invite the one that forgets. Returning `Maybe` makes the miss impossible to
ignore.

`update` embodies [make invalid states unrepresentable][principles] for the
common "aggregate into a map" loop: the "key absent" and "key present" cases are
the two constructors of the `Maybe` it hands you, so you cannot write the tally
that forgets to initialise a new key — the `Nothing` arm is required.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Dict` — every function with its signature
  and a verified example. `ipe doc Ipe.Dict.update` drills into the upsert verb.
- **Sibling guides:** [Sets](set.md) — a `Set` is a `Dict` with no values; use it
  when you only care whether a key is present. [Lists](../reference/stdlib/List.md) for
  ordered, positional, possibly-duplicated data.
- **Concepts:** [Types and inference](types.md) — how `Maybe` encodes a lookup
  that might miss. [Pure functions and immutability](pure-functions.md) — why
  `insert`/`update` return a new dictionary rather than mutating.
