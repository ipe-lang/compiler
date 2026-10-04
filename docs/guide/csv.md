# CSV

`Ipe.Csv` reads and writes comma-separated documents. A parsed document is a
plain record — a `header` row and a list of `rows` — that you transform with
ordinary list functions, then encode back out with correct quoting.

## The mental model

Three knots.

- **`parse` is a boundary that can fail; the result is a typed record.**
  `Csv.parse` returns `Result Error Csv`. A malformed document is one typed `Err`,
  not a ragged half-parsed table. What you get on success is a `Csv` record —
  `header : List String`, `rows : List (List String)` — so past the parse the data
  is ordinary typed values you manipulate with `List.filter`, `List.map`, and the
  rest.
- **Encoding quotes for you — never hand-join commas.** `Csv.encode` follows RFC
  4180: a cell that itself contains a comma, a quote, or a newline is quoted
  correctly on the way out. Building a CSV line with `String.join ","` would
  silently corrupt any value containing a comma; `encode` is the single correct
  way to serialise, and the parser round-trips it.
- **Rows are positional — read cells safely.** A row is a `List String` indexed by
  column position, and a real-world export can have a short or ragged row. Read a
  cell as a `Maybe` (drop to the column, take the head) rather than assuming it is
  there — a missing cell should make a row *not match*, not crash.

## A worked example: filtering an export

The example under
[`examples/shapes/script/csv-report`](../../examples/shapes/script/csv-report/src/Main.ipe)
parses an orders export, keeps only the shipped rows, and re-encodes them.

Filtering is an ordinary `List.filter` over the typed `rows`, rebuilt into the
document with `withRows`:

```ipe
shippedOnly : Csv -> Csv
shippedOnly csv =
    Csv.withRows (List.filter isShipped csv.rows) csv


isShipped : List String -> Bool
isShipped row =
    elementAt 2 row == Just "shipped"
```

The cell read is deliberately safe — `elementAt` returns a `Maybe`, so a ragged
row without a status column simply fails the match instead of indexing out of
bounds:

```ipe
elementAt : Int -> List a -> Maybe a
elementAt n xs =
    List.head (List.drop n xs)
```

Parsing is the boundary: the whole pipeline runs only inside the `Ok` branch, so
every downstream step holds a real `Csv`:

```ipe
main =
    case Csv.parse export of

        Err _ ->
            Io.eprintln "the CSV export was malformed"

        Ok csv ->
            do
                Io.println ("parsed rows: " ++ String.fromInt (List.length csv.rows))
                Io.println "shipped orders re-encoded:"
                Io.println (Csv.encode (shippedOnly csv))
```

The export includes a quoted cell containing a comma — `"Doe, Jane"` — which the
parser reads as a single field. Running it (`ipe dev run`) prints:

```
parsed rows: 4
shipped orders re-encoded:
id,customer,status,total
1,Ada,shipped,42.00
3,Linus,shipped,8.99
```

## The why

`Csv.parse` returning a `Result` is [parse, don't validate][principles]: the raw
text becomes a typed `Csv` at one point, and the rest of the program works with
`header`/`rows`, never re-splitting the string. And using `encode` rather than
hand-joining is [security][principles] and [correctness][principles] together — a
value with an embedded comma or quote is a classic injection/corruption vector for
a hand-rolled CSV writer; the library's RFC-4180 quoting closes it by
construction, and guarantees the output parses back to the same rows.

[principles]: ../../PRINCIPLES.md

## Configuration

Two env vars tune CSV limits at runtime. Use `ipe doc <VAR>` for the full entry.

| Variable | Default | Effect |
|----------|---------|--------|
| `IPE_CSV_MAX_ROWS` | 10000000 (10 M) | Maximum rows parsed from a single CSV input. |
| `IPE_CSV_SANITIZE_FORMULAS` | unset (false) | Prefix formula-injection characters in output to block spreadsheet injection. |

See the [**CSV** subsystem](../reference/env.md#csv) in the
environment variable reference.

## References

- **Per-symbol reference:** `ipe doc Ipe.Csv` — every function with its signature.
  `ipe doc Ipe.Csv.parseStreamFromFile` reads a large file row-by-row through a
  validated `Path` without materialising it whole.
- **Sibling guides:** [Files](file.md) — `parseStreamFromFile` builds on the typed
  `Path` boundary. [Lists](../reference/stdlib/List.md) — the `filter`/`map` you
  transform rows with. [Result](result.md), which `parse` returns.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md).
  [Pure functions and immutability](pure-functions.md) — why transforming rows
  yields a new document.
