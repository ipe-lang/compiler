# Lists

A `List a` is an ordered sequence of values that all share one type: `[ 1, 2, 3 ]`
is a `List Int`, `[ "a", "b" ]` a `List String`. Lists are Ipê's workhorse
collection, and almost every program is a pipeline that reshapes one.

## The mental model

Three knots.

- **A list is immutable — you never change one, you build a new one.** Every
  function here *returns a fresh list*; none edits its argument. So the same list
  can be passed to two callers with no fear that one's transformation leaks into
  the other's. "Update an element" is really "produce a new list that differs in
  one place", and that reframing is what makes list code compose into pipelines.
- **`foldl` is the general reducer — everything else is a special case of it.**
  When you need to collapse a whole list into *one* value (a sum, a max, a running
  table), `foldl step initial list` threads an accumulator left to right, calling
  `step element accumulator` at each element. `sum`, `maximum`, and friends are
  named folds; when none fits, reach for `foldl` directly.
- **`filterMap` fuses "test then extract" into one pass.** `filter` keeps
  elements; `map` transforms them; `filterMap : (a -> Maybe b) -> List a -> List b`
  does both at once — the function returns `Just` to keep-and-transform or
  `Nothing` to drop. Any "select some elements *and* change them" is one
  `filterMap`, not a `filter` piped into a `map`.

## A worked example: a league scoreboard

The example under
[`examples/shapes/script/list-scoreboard`](../../examples/shapes/script/list-scoreboard/src/Main.ipe)
turns a flat list of match results into a ranked standings table — the shape of a
great many real programs: ingest rows, reduce them, sort, present.

The reduction is one `foldl`: it threads the growing `table` through every match,
then a `sortWith` ranks it. Because `creditTeam` returns a *new* table each time,
the fold is a pure left-to-right accumulation with no shared mutable state:

```ipe
standings : List Match -> List Standing
standings matches =
    List.foldl addMatch [] matches
        |> List.sortWith byRank
```

"Update one team's row" is a rebuild, not a mutation. `List.partition` splits the
table into (this team's row, everyone else); the row is rebuilt with updated
points and consed back on. Here the tuple is destructured first, then the list is
matched.

```ipe
creditTeam team earned table =
    let
        ( mine, rest ) =
            List.partition (\row -> row.team == team) table
    in
    case mine of

        row :: _ ->
            { row | points = row.points + earned, played = row.played + 1 } :: rest

        [] ->
            { team = team, points = earned, played = 1 } :: rest
```

Ranking is a `sortWith` over a full comparator — most points first, ties broken
alphabetically — so a compound sort key is one `Order`-returning function:

```ipe
byRank a b =
    case compare b.points a.points of

        EQ ->
            compare a.team b.team

        LT ->
            LT

        GT ->
            GT
```

The leaders are picked with `filterMap`: the lambda returns `Just team` for a
top-scoring row and `Nothing` otherwise, so the test and the field extraction are
a single traversal:

```ipe
leaderNames table topPoints =
    List.filterMap
        (\row ->
            if row.points == topPoints then
                Just row.team

            else
                Nothing
        )
        table
```

Presentation fans a list of values out to a list of effects: `indexedMap` numbers
each row, `List.map Io.println` turns each into a print task, and `Task.sequence`
runs them in order (the idiom for "print a whole list"):

```ipe
printTable table =
    List.indexedMap renderRow table
        |> List.map Io.println
        |> Task.sequence
        |> Task.map (\_ -> ())
```

Running it (`ipe dev run`) prints the ranked table and the leader:

```
Standings
 1. Lions     5 pts (4 played)
 2. Bears     4 pts (3 played)
 3. Wolves    4 pts (3 played)
Leaders: Lions
```

## The why

The immutable list is [soundness][principles] at the collection level: because no
function edits its argument, sharing a list is always safe, and a pipeline's
stages cannot interfere. There is no aliasing bug where one transformation
corrupts another's view — the type is the guarantee.

`foldl` and `filterMap` are [ease of use][principles] through composition: rather
than a bespoke loop with a mutable accumulator and an `if`-guarded append, the
reduction and the select-and-transform each become one named combinator whose type
says exactly what it does. And returning a `Maybe` from `head`, `find`, and the
`filterMap` callback keeps [make invalid states unrepresentable][principles] in
play — the empty and absent cases are values the compiler forces you to handle,
never a silent out-of-bounds.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.List` — every function with a verified
  example. `ipe doc Ipe.List.foldl`, `ipe doc Ipe.List.filterMap`, and
  `ipe doc Ipe.List.sortWith` cover the three idioms above.
- **Sibling guides:** [Strings](string.md) — the row rendering uses `String.join`
  and the `padLeft`/`padRight` alignment helpers. [Tasks](task.md) — `Task.sequence`
  turns the list of print effects into one. [Maybe](maybe.md) — the absence type
  `filterMap`, `head`, and `find` return. [Dict](dict.md) and [Set](set.md) —
  key-value and membership collections when order is not the point.
- **Concepts:** [Types and inference](types.md) — how the element type `a` is
  tracked through every transform. [The pipe idiom](../idioms/pipe.md) — why list
  code reads as a top-to-bottom pipeline.
