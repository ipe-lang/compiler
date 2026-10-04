# Maybe

A `Maybe a` is either `Just a` (a value is present) or `Nothing` (it is absent).
It is how Ipê says "there might not be an answer" *without a null*: a function
that can fail to produce a value returns a `Maybe`, and the caller must handle
both cases before using the value.

## The mental model

Three knots.

- **`Nothing` is a value you handle, not a null that bites.** There is no null and
  no null-pointer crash. `Dict.get`, `List.head`, and `String.toInt` return
  `Maybe` precisely because they might have no answer — and the type stops you
  from reaching for a value that isn't there. This is the soundness guarantee in
  one type: absence is represented, so it cannot be dereferenced by accident.
- **Chain lookups that might miss with `andThen`.** When the next step needs the
  previous value *and* might itself be absent, `Maybe.andThen` threads them: the
  first `Nothing` short-circuits and the rest never runs. A chain of dependent
  `Dict.get`s becomes a flat `|>` pipeline instead of a staircase of nested
  `case`.
- **`map` decorates, `withDefault` lands.** `Maybe.map` transforms the value
  inside a `Just` and leaves `Nothing` alone — use it when the step *cannot*
  fail. `Maybe.withDefault` is the exit: it turns a `Maybe a` back into a plain
  `a` by supplying the fallback. `andThen` is for a step that can fail; `map` is
  for one that can't; `withDefault` ends the chain.

## A worked example: resolving a theme through nested lookups

The example under
[`examples/shapes/script/maybe-settings-lookup`](../../examples/shapes/script/maybe-settings-lookup/src/Main.ipe)
resolves a user's display theme through three lookups, any of which may come up
empty: user id -> their settings row -> the `"theme"` key.

Each hop is a `Dict.get` returning `Maybe`, and `andThen` threads them into one
pipeline. If any link is absent — an unknown user, a settings row that isn't
there, a row with no theme — the whole chain is `Nothing` and the later hops
never run:

```ipe
lookupTheme : String -> Maybe String
lookupTheme userId =
    Dict.get userId userSettings
        |> Maybe.andThen (\rowId -> Dict.get rowId settingsRows)
        |> Maybe.andThen (\row -> Dict.get "theme" row)
```

The report line shows `map` and `withDefault` finishing the job: `map` decorates
a present theme, and `withDefault` supplies the fallback for every absent case at
once:

```ipe
describe : String -> String
describe userId =
    let
        resolved =
            lookupTheme userId
                |> Maybe.map (\theme -> "theme=" ++ theme)
                |> Maybe.withDefault "no theme set, using system"
    in
    userId ++ ": " ++ resolved
```

Running it (`ipe dev run`) over four users prints — one resolves, three miss at three
*different* links, and all three land on the same fallback:

```
u1: theme=dark
u2: no theme set, using system
u3: no theme set, using system
ghost: no theme set, using system
```

`u1` has a row with a theme; `u2`'s row exists but has no `"theme"` key; `u3`
points at a settings row that isn't there; `ghost` is not a user at all. One
`andThen` chain handles every one of those absences the same way.

## The why

`Maybe` is [make invalid states unrepresentable][principles] for absence. A
language with null lets *every* reference be secretly absent, so every use is a
potential crash the type never warned about. `Maybe` moves absence into the type:
only a `Maybe a` can be missing, and the compiler will not let you treat one as an
`a` without handling the `Nothing`. There is no forgotten null check because the
check is not optional.

`Maybe` and [`Result`](result.md) are the same shape with one difference: `Maybe`
says *whether* a value is there, `Result` also says *why* it isn't. Use `Maybe`
when absence needs no explanation (a key simply isn't in the dictionary); reach
for `Result` when the caller needs to know the reason it failed.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Maybe` — every combinator with a verified
  example. `ipe doc Ipe.Maybe.andThen` and `ipe doc Ipe.Maybe.withDefault` cover
  the chain and the exit.
- **Sibling guides:** [Result](result.md) — absence *with* a reason.
  [Dictionaries](dict.md), whose `get` returns the `Maybe` this example chains.
- **Concepts:** [Types and inference](types.md) — how `Just`/`Nothing` and the
  element type `a` are tracked. [Pure functions and immutability](pure-functions.md).
