# Sets

A `Set a` is an **unordered collection of unique values**. Reach for it whenever
the question you keep asking a collection is *"is this in there?"* or *"what do
these two collections have in common?"* — membership and set algebra, not
position.

## The mental model

Three knots trip up a first-time reader; each is one idea.

- **Uniqueness is structural, not a step you run.** A `Set` cannot hold a value
  twice. `Set.fromList [ "read", "read", "write" ]` is the two-element set
  `{ read, write }` — the duplicate never existed, so there is no de-dup pass to
  remember. If a collection's defining property is "each thing at most once," the
  `Set` type *is* that property; a `List` you promise to keep unique is not.
- **There is no order, so never depend on one.** Iteration order is unspecified.
  `Set.toList` may hand back elements in any order, and it can differ run to run.
  When a human will read the output, **sort after `toList`** — the guide's example
  does exactly this. Relying on set order is a correctness bug the type is trying
  to prevent.
- **Subset questions are `diff`, not a bespoke loop.** "Does A contain everything
  in B?" is `Set.diff b a` being empty: the elements of B not in A. "What do A and
  B share?" is `Set.intersect`. "Everything in either?" is `Set.union`. The four
  algebra operations — `union`, `intersect`, `diff`, and `member` — replace the
  hand-written membership loops you would otherwise write and get subtly wrong.

## A worked example: role-based access control

The example under
[`examples/shapes/script/set-access-control`](../../examples/shapes/script/set-access-control/src/Main.ipe)
decides whether a user may perform an action, using nothing but set algebra. Each
role grants a set of permissions; a user's *effective* permissions are the union
of their roles; an action *requires* a set; access is a subset test.

Each role's grants are a set built with `fromList`, which de-duplicates as it
builds:

```ipe
roleGrants : String -> Set String
roleGrants role =
    case role of

        "viewer" ->
            Set.fromList [ "read" ]

        "editor" ->
            Set.fromList [ "read", "write" ]

        "admin" ->
            Set.fromList [ "read", "write", "delete", "grant" ]

        _ ->
            Set.empty
```

A user holds several roles, so their effective permissions are the **union** of
each role's grants. `List.foldl` threads the growing set as its accumulator — the
immutable stand-in for a "keep adding to the set" loop:

```ipe
effectivePermissions : List String -> Set String
effectivePermissions roles =
    List.foldl mergeRole Set.empty roles


mergeRole : String -> Set String -> Set String
mergeRole role acc =
    Set.union acc (roleGrants role)
```

The access check is the third knot made concrete. `Set.diff required effective`
is exactly the permissions the action needs but the user lacks; if that set
`isEmpty`, nothing is missing, so access is granted. The subset relation is never
spelled out by hand — it falls out of the difference being empty:

```ipe
decide : String -> List String -> Set String -> String
decide action roles required =
    let
        effective =
            effectivePermissions roles

        missing =
            Set.diff required effective
    in
    if Set.isEmpty missing then
        action ++ ": GRANTED"

    else
        action ++ ": DENIED (missing " ++ showSet missing ++ ")"
```

Because order is unspecified, the report sorts the elements before joining them —
a human-facing string must not depend on hash order:

```ipe
showSet : Set String -> String
showSet s =
    s
        |> Set.toList
        |> List.sort
        |> String.join ", "
```

Running it (`ipe dev run`) prints:

```
alice reads: GRANTED
alice deletes: DENIED (missing delete)
bob reads: GRANTED
viewer∩admin floor: read
alice's permission count: 2
```

The `viewer∩admin floor` line comes from `Set.intersect (roleGrants "viewer")
(roleGrants "admin")` — the permissions those two roles both grant.

## The why

A `Set` makes an invariant **unrepresentable to break**. "These permissions are
unique and their order is meaningless" is not a comment you hope callers respect;
it is the type. A downstream function handed a `Set String` cannot be given a
duplicate and cannot be tempted to index by position, because neither operation
exists. That is [make invalid states unrepresentable][principles] applied to a
collection: the difference between a `Set` and a `List` you *treat* as a set is
the difference between a guarantee and a convention.

The set algebra is also where correctness lives. A hand-rolled "does the user have
every required permission?" loop is easy to get wrong at the boundaries — the
empty case, the duplicate, the off-by-one. `Set.diff` and `Set.isEmpty` state the
intent directly and carry no boundaries to fumble.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Set` — every function with its signature
  and a verified example. `ipe doc Ipe.Set.diff` drills into one.
- **Sibling guides:** [Dictionaries](dict.md) — a `Set` is a `Dict` with no
  values; when you need a value *per* key, reach for `Dict`.
  [Lists](../reference/stdlib/List.md) when order or duplicates matter.
- **Concepts:** [Pure functions and immutability](pure-functions.md) — why every
  `Set` operation returns a new set. [Types and inference](types.md) — how the
  element type `a` is tracked.
