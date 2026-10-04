# UUIDs

`Ipe.Uuid` mints and validates universally unique identifiers — the standard way
to give a new record a globally unique name without a central counter.

## The mental model

Three knots.

- **Generation is an effect — `v4`/`v7` return a `Task`.** Minting a UUID draws
  fresh entropy, so it is not a pure computation; `Uuid.v4 ()` and `Uuid.v7 ()`
  have type `Task Error String`, the same tier as reading the clock. You *run*
  them through the runtime; you do not evaluate them inline.
- **`v4` is random; `v7` is time-ordered — and that difference is a design
  choice.** A v4 UUID is fully random. A v7 UUID puts a timestamp in its leading
  bits, so v7 IDs minted in sequence *sort into creation order*. Pick v7 when you
  want database keys that cluster by insertion time (better index locality); pick
  v4 when you want no correlation between IDs at all.
- **`parse` is pure validation returning a `Maybe`.** Checking that a string is a
  well-formed UUID draws no entropy, so `Uuid.parse : String -> Maybe String` is
  pure: `Just` for a valid canonical UUID, `Nothing` for garbage. It is the typed
  boundary for IDs arriving from a request, a file, or a database.

## A worked example: minting record ids

The example under
[`examples/shapes/script/uuid-record-ids`](../../examples/shapes/script/uuid-record-ids/src/Main.ipe)
mints a batch of time-ordered ids and checks the properties that hold for *any*
entropy, so it is deterministic despite the randomness.

Minting three v7 ids is a `Task.sequence` of three effects — each `Uuid.v7 ()` is
a task, run in order:

```ipe
mintBatch =
    Task.sequence
        [ Uuid.v7 ()
        , Uuid.v7 ()
        , Uuid.v7 ()
        ]
```

The v7 time-ordering is testable without knowing the exact ids: because later ids
compare greater, sorting the batch leaves it unchanged:

```ipe
isOrdered ids =
    List.sort ids == ids
```

And `parse` is the pure boundary check — every minted id parses, and obvious
garbage is rejected:

```ipe
allValid ids =
    List.all (\id -> Maybe.isJust (Uuid.parse id)) ids
```

Running it (`ipe dev run`) confirms the structural facts — 36-character canonical
form, all parse, v7 batch already in creation order, and a non-UUID rejected:

```
minted 3 v7 ids
all 36 chars: yes
all parse as UUIDs: yes
v7 batch in creation order: yes
a v4 id also parses: yes
rejects 'not-a-uuid': yes
```

## The why

Typing generation as a `Task` is [soundness][principles]: minting an id reads
entropy, an effect, and the type refuses to pretend otherwise — you cannot get a
fresh UUID from a pure function, so the non-determinism is confined to the
runtime's run site where every effect lives.

`parse` returning a `Maybe` rather than a raw string is [parse, don't
validate][principles]: an id from the outside world is turned into a *known-valid*
value once, at the boundary, and the `Nothing` case is impossible to ignore. And
offering `v4` *and* `v7` as distinct functions is [correctness][principles] made
explicit — the sortability trade-off is a named choice in the code, not a hidden
property a reader has to know to reason about.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Uuid` — `v4`, `v7`, and `parse` with
  verified examples.
- **Sibling guides:** [Randomness](random.md) — UUID generation is the entropy
  tier applied to identifiers; the two are the "give me an unpredictable value"
  pair. [Tasks](task.md) — the effect type `v4`/`v7` return, sequenced here with
  `Task.sequence`. [Maybe](maybe.md) — what `parse` returns. [Strings](string.md)
  — a UUID is canonical text; `String.length` checks its 36-character form.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — why `parse` returns a typed result. [Types and inference](types.md) — how the
  `Task` effect tier is tracked.
