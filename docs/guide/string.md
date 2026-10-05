# Strings

A `String` is immutable UTF-8 text. `Ipe.String` is the toolkit that builds,
slices, searches, and reshapes it — and, crucially, the place where raw text
crosses the boundary into typed values.

## The mental model

Three knots.

- **A String is immutable — every function returns a new one.** `toUpper`,
  `trim`, `replace`, `slice` never edit their argument; they hand back a fresh
  string. So normalising text is a *pipeline of transforms*, and the original is
  always still around, unchanged, for anyone else who holds it.
- **Parsers return a `Maybe`, not a crash.** `String.toInt "12"` is `Just 12`;
  `String.toInt "x"` is `Nothing`. `isEmail`/`isUrl` answer a `Bool`. Text is the
  outside world's format, so turning it into an `Int` or a validated address is a
  *fallible* step, and the type says so — the un-parsable case is a value the
  caller must handle at the boundary, never a surprise later.
- **`split` and `join` are inverses; you rarely index characters by hand.** The
  idiom for "reshape delimited text" is `split` → transform each piece → `join`
  back. `words`/`lines` are `split` on whitespace/newlines; `join sep` is the
  undo. Reaching for `slice`/`left`/`right` with hand-computed offsets is the
  exception, for when you genuinely need a fixed window.

## A worked example: normalising a contact roster

The example under
[`examples/shapes/script/string-contacts`](../../examples/shapes/script/string-contacts/src/Main.ipe)
turns a block of raw `Name <email>` lines — mixed case, ragged whitespace, a
couple of malformed entries — into a clean, validated roster.

Parsing one line finds the `<`/`>` delimiters with `String.indexes` (each a
`Maybe Int`), combines them with `Maybe.map2`, then slices the fields out. Every
step returns a new string; a line without both delimiters falls out as `Nothing`
rather than crashing:

```ipe
parseLine line =
    Maybe.map2 Tuple.pair
        (List.head (String.indexes "<" line))
        (List.head (String.indexes ">" line))
        |> Maybe.andThen (\( open, close ) -> toContact line open close)
```

The field extraction is a chain of pure transforms — `slice` the window, `trim`
the whitespace, `toLower` the address — and the parse *rejects* rather than
returns on a bad address, because `isEmail` is the typed boundary check:

```ipe
toContact line open close =
    let
        name =
            String.trim (String.left open line)

        email =
            String.slice (open + 1) close line
                |> String.trim
                |> String.toLower
    in
    if String.isEmpty name || not (String.isEmail email) then
        Nothing

    else
        Just { name = name, email = email }
```

The whole roster is `lines` → `filterMap parseLine`: split the block, parse each
line, and keep only the successes in one pass:

```ipe
roster block =
    String.lines block
        |> List.filterMap parseLine
```

Running it (`ipe dev run`) drops the two malformed lines, lowercases `Ada@Example.COM`,
and prints the clean roster:

```
parsed 2 contacts:
  Ada Lovelace <ada@example.com>
  Grace Hopper <grace@navy.mil>
```

## Multiline strings and `{{}}` interpolation

A **triple-quoted string** `"""…"""` spans multiple lines, and its opening-line
indentation margin is stripped — the block's layout in the source does not enter
the value. Inside one, `{{expr}}` **interpolation** substitutes a scalar
(`String`, `Int`, `Float`, `Bool` or `Char`), rendered exactly as its
`String.from*` conversion, so an `Int` needs no `String.fromInt`. Any other
type is refused at type-check (IPE-T0014) — interpolate its fields instead:

```ipe
banner : String -> Int -> String
banner name count =
    """
    Hello, {{name}}!
    You have {{count}} messages.
    """
```

An interpolation body may be a bare identifier, a field access, a qualified
name, or a single function application; anything more complex stays as literal
`{{…}}` text. Interpolation works **only** in triple-quoted strings — in a
single-line `"…"` string `{{x}}` is literal. Prefer an interpolated
`"""…"""` over a long `++` chain when stitching text and values together. See
[`string-interpolation`](../constructs/string-interpolation.md) for the full
grammar and the [interpolation idiom](../idioms/string-interpolation.md).

## The why

The parse-returning-`Maybe` step is [parse, don't validate][principles] at the
text boundary: the messy string becomes a typed `Contact` *once*, and every
function downstream takes a `Contact`, never the raw line, so the whitespace and
casing are dealt with exactly one time. A bare `isEmail : String -> Bool` used as
a gate that let the raw string flow onward would invite the re-check-or-forget
bug this structure removes.

Immutability is [soundness][principles] for text: because no transform edits its
input, a string can be shared without any aliasing hazard, and a normalisation
pipeline cannot corrupt another caller's copy. And returning `Maybe`/`Bool` from
the parsers keeps [make invalid states unrepresentable][principles] in force — an
un-parsable integer or a bad email is a value you handle, not a panic.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.String` — every function with a verified
  example. `ipe doc Ipe.String.split`, `ipe doc Ipe.String.slice`, and
  `ipe doc Ipe.String.isEmail` cover the idioms above.
- **Sibling guides:** [Lists](list.md) — `filterMap` and the pipeline shape the
  roster is built from; a `String` is text, a `List` is its element sequence.
  [Maybe](maybe.md) — the absence type every parser returns, combined here with
  `map2`/`andThen`. [Regex](regex.md) — when the delimiter grammar outgrows
  `split`/`indexes`. [Encoding](encoding.md) — bytes ↔ text at the I/O edge.
- **Concepts:** [Types and inference](types.md) — how `String`, `Int`, and the
  `Maybe` a parser returns are tracked. [The parse-don't-validate
  idiom](../idioms/parse-dont-validate.md).
