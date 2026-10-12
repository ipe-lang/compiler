# Database codecs

`Ipe.Db.Codec` is the seam where one `Codec a` becomes a database row and back.
A [codec](codec.md) already carries a JSON encoder, a JSON decoder, and a
structural `Shape`; this module is the single place that `Shape` meets a stored
row — deriving the column list, binding the writes, and decoding the reads from
that *one* codec. The row you write and the value you read back cannot drift,
because both directions reuse the codec's own seam.

## The mental model

Three knots.

- **One codec is the source of truth for the wire form, the columns, AND the
  row.** `Ipe.Codec` knows nothing about SQL. `Ipe.Db.Codec` bridges a codec to
  the reserved `SqlValue` type without re-encoding, without a string round-trip,
  and without a second decoder: `codecToBinds` runs the codec's encoder once and
  reads each declared column out of that value as a bound `SqlValue`;
  `codecFromRow` assembles the row's cells into one in-memory value and runs the
  codec's *own* decoder on it. A field renamed or retyped changes exactly one
  place.
- **Schema drift is fail-closed.** A row missing a declared column, a SQL
  `NULL` in a column whose field is not a `Maybe`, or a cell that is not the
  declared shape (a non-integer where an `Int` column was declared), is a typed
  `Err` — never a wrong value silently threaded onward. The
  read either yields a real, fully-typed value or a typed error; there is no
  ragged half-decoded row.
- **A non-record codec has no columns, so it is rejected.** `codecToBinds` /
  `codecFromRow` require an `SRecord`-shaped codec — one that names columns. A
  bare scalar, a blob, or a container codec has no column list, so both
  directions return a typed `Err` rather than guess. (`toSqlValue` is the scalar
  counterpart, for a single enum or newtype column.)

## A worked example: a row round-trip and two fail-closed drifts

The example under
[`examples/shapes/script/db-codec-row`](../../examples/shapes/script/db-codec-row/src/Main.ipe)
derives a codec from a record witness, reads a well-formed row back into a
typed value, and rejects three drifted rows.

The codec is derived from a named, annotated witness — the field names become
the columns, one derivation:

```ipe
type alias User =
    { id : String
    , age : Int
    , active : Bool
    }


blankUser : User
blankUser =
    { id = "", age = 0, active = False }


userCodec : Codec User
userCodec =
    Codec.auto blankUser
```

A database row is a `Dict String (Maybe String)` keyed by column name: `Just`
the cell text, or `Nothing` for SQL `NULL`, so `NULL` and the empty string stay
apart and a `Maybe` field reads `Nothing` only from a real `NULL`. Reading it
runs the codec's own decoder — on success the result is a real `User`; on
drift, a typed `Err`:

```ipe
readRow : Dict String (Maybe String) -> String
readRow row =
    case DbCodec.codecFromRow userCodec row of
        Ok user ->
            "Ok User { id = " ++ user.id ++ ", … }"

        Err _ ->
            "rejected (schema drift — fail-closed)"
```

Running it (`ipe dev run`) reads the good row and turns the three drifted rows away:

```
well-formed row -> Ok User { id = u-42, age = 30, active = True }
missing column  -> rejected (schema drift — fail-closed)
bad cell type   -> rejected (schema drift — fail-closed)
NULL in an Int  -> rejected (schema drift — fail-closed)
```

## The why

Deriving the columns, the binds, and the reads from one codec is [single source
of truth][principles] applied to persistence: the class of bug where the schema,
the writer, and the reader disagree cannot be written, because there is only one
fact to change. A missing column or a mistyped cell surfacing as a typed `Err`
is [soundness][principles] — schema drift is a value the caller handles, never a
panic or a wrong value read on. And building the binds through the codec's
encoder rather than any SQL text is [security][principles]: `Ipe.Db.Codec`
constructs no query string, so it adds no injection surface over the
already-parameterised binds it feeds.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Db.Codec` — `codecToBinds` (a record
  value to its `(column, SqlValue)` binds), `codecFromRow` (a row back to the
  value), and `toSqlValue` (a scalar enum/newtype column's bound value).
- **Sibling guides:** [Codec](codec.md) — the bidirectional codec this bridges
  to a row; the `Shape` it declares is what names the columns here. [Result](result.md)
  — the typed failure both directions return. [Dictionaries](dict.md) — the
  `Dict String (Maybe String)` a row arrives as.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — a row read is the boundary where untyped cell text becomes a typed value.
