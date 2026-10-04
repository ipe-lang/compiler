# The unsafe Store surface

`Ipe.Db.Store.Unsafe` holds the string-named column builders and query leaves for
[`Ipe.Db.Store`](db-store.md). The safe surface names a column by an accessor
literal, checked against the row type at compile time. A *dynamic* table — one with
no record type — has no accessor to check, so its columns can only be named by a
bare string, and those live here behind a disclosed `unsafe` capability.

## The mental model

The word "unsafe" here is narrow, and worth stating precisely.

- **It means an unchecked string, not injection.** A safe column reference like
  `Store.primaryKey .id` is a `.field` accessor the compiler checks against the row
  type. The unsafe form `StoreU.primaryKey "id"` names the column by a string, so a
  typo is caught when the query or DDL is built, not at compile time. That is the
  entire hazard: a *later* error instead of a *compile* error.
- **The injection guarantee is unchanged.** Every string-named column is still
  validated against the store's own columns when the query is built, and every
  value still binds as a parameter, never interpolated. A column absent from the
  store fails closed with an `Err`; no caller string reaches the SQL text.
- **The capability is disclosed.** Importing the module discloses the `unsafe`
  capability program-wide, so an audit sees the narrower guarantee before the
  program runs. A project accepts it once in its manifest with
  `capabilities = { accepts = [ Unsafe ] }`.

## A worked example: a dynamic table

The example under
[`examples/shapes/script/store-raw-columns`](../../examples/shapes/script/store-raw-columns/src/Main.ipe)
builds a raw-column table (no record type), names its primary key by string, and
shows that an invalid identifier still fails closed.

```ipe
events : Result Error (Store Store.Row)
events =
    Store.fromColumns "events"
        [ Store.textColumn "id"
        , Store.textColumn "kind"
        , Store.intColumn "weight"
        ]
        |> Result.map (StoreU.primaryKey "id")
        |> Result.map Store.public
```

Its manifest pre-accepts the capability:

```ipe
package : Package
package =
    { name = "store-raw-columns"
    , version = "0.1.0"
    , capabilities = { accepts = [ Unsafe ] }
    }
```

Running it (`ipe dev run`):

```
columns: id, kind, weight
bad column name -> rejected (invalid identifier — fail-closed)
```

## The why

Naming the whole module `Unsafe` and gating it behind a disclosed capability is
[security][principles] made visible: the residual hazard — a column named by an
unchecked string — is not hidden inside the safe API, it is a separate import a
reviewer can grep for. The injection defence does *not* relax across that boundary:
the identifier is still validated and the value still bound, so [soundness][principles]
holds on both surfaces. The `unsafe` name marks exactly what changed — compile-time
checking became query-time checking — and nothing more.

Reach for this only for a dynamic or non-codec table the safe accessor surface
cannot express.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Db.Store.Unsafe` — the string-named
  column-spec builders (`primaryKey`, `serial`, `defaultNow`, …) and query leaves
  (`eq`, `neq`, `like`, `inList`, …), each with its signature.
- **Sibling guides:** [Store](db-store.md) — the safe, accessor-typed surface this
  extends. [The unsafe database surface](db-unsafe.md) — raw SQL and untyped column
  reads. [The secret-reveal hatch](secret-unsafe.md) — another disclosed-capability
  escape hatch.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — identifier validation as a fail-closed parse, even on the unsafe surface.
