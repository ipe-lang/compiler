# string interpolation

A triple-quoted string `"""…"""` is a string literal that may span lines, and
inside one `{{expr}}` interpolation substitutes a value into the text. Interpolation
renders a scalar — a `String`, `Int`, `Float`, `Bool` or `Char` — so you build
readable text without a chain of `++`.

## Syntax

```ipe ipe:skip a syntax shape with placeholder names, not valid Ipê
"""
<text, spanning as many lines as you like>
{{<expression>}}   -- substitutes the value, stringified
\{{                -- a literal `{{` (no interpolation)
"""
```

A triple-quoted string has exactly two forms:

- **One line:** `"""text"""` — the value is the text between the quotes.
- **A block:** the opening `"""` ends its line, and the closing `"""` stands
  alone on its own line in the opener's column. That column is the block's
  **margin**: every body line is indented at least to it, and the margin is not
  part of the value. The value is the body lines, margin removed, joined with
  line breaks — the line break after the opener and the one before the closer
  are not part of it.

Any other shape is refused: text after a block's opener, a closer that ends a
content line, or a closer outside the opener's column is IPE-P0075; a body line
or a tab left of the margin is IPE-P0076. Because the margin is the opener's
column, a block moved to another column keeps its value once its body moves
with it.

An interpolation body is any Ipê expression — a name, a field path, a call,
an operator, a parenthesised or record expression — parsed and resolved exactly
as it would be outside the string. Each body's value goes through the internal
interpolation renderer, and the whole literal is joined with `++`.

```ipe ipe:skip a syntax shape with placeholder names, not valid Ipê
{{name}}                              -- a name
{{record.field.sub}}                  -- a field path
{{String.join ", " (List.map f xs)}}  -- a call
{{a + b}}                             -- an operator
```

A body ends at the **first** `}}` after its `{{`. A record expression whose
closing braces would meet there is cut short — write `{a = {b = 1} }` with a
space, or bind the value to a name first.

A body that is not one whole expression is refused with IPE-P0077
(`ipe doc IPE-P0077`), never kept as literal text: an empty `{{}}`, a `{{` with
no `}}`, a token after the expression, an expression still open at the `}}`,
or an interpolation inside a pattern string.

## Example

```ipe
report : Int -> String -> String
report count tag =
    """
    tag={{tag}}
    count={{count}}
    done
    """
```

`{{count}}` where `count : Int` renders as its decimal digits — no manual
`String.fromInt`. The three content lines carry no leading indentation into the
value even though the block is indented in the source.

## Notes

- **Only the five scalars interpolate.** The value must be a `String`, `Int`,
  `Float`, `Bool` or `Char`; each renders exactly as its `String.from*`
  conversion. A record, custom type, `List`, `Maybe`, tuple, `Dict` or opaque
  runtime value (a `Request`, a `Secret`) is refused at type-check with
  IPE-T0014 (`ipe doc IPE-T0014`) — interpolate
  its fields, or convert it first (`Error.toString`, `Secret.redacted`).
- **Interpolation is only in triple-quoted strings.** A single-line `"…"` string
  does NOT interpolate — `{{x}}` there is literal text. This is the common trap.
- A body resolves exactly as the same expression outside a string: an
  unknown name or qualifier is refused at that name (IPE-N0001, IPE-N0004,
  IPE-N0034), and a name used only inside a body counts as used.
- A long body reads better bound to a `let` name first and interpolated by that
  name.
- `\{{` emits a literal `{{`. A `{{` with no matching `}}` is IPE-P0077.
- Interpolation joins with `++`, so an interpolated string is exactly the
  concatenation you would write by hand — prefer it over a long `++` chain for
  readability.

## See also

- [String interpolation over `++`](../idioms/string-interpolation.md) — the idiom.
- [Strings](../guide/string.md) — the `String` toolkit and text boundary.
- `ipe doc String.fromInt`, `ipe doc String.fromBool` — the explicit conversions
  that render the same forms outside a `"""…"""` string.
