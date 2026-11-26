# string interpolation

A triple-quoted string `"""…"""` is a multiline string literal, and inside one
`{{expr}}` interpolation substitutes a value into the text. Interpolation
renders a scalar — a `String`, `Int`, `Float`, `Bool` or `Char` — so you build
readable text without a chain of `++`.

## Syntax

    """
    <text, spanning as many lines as you like>
    {{<simple-ref>}}   -- substitutes the value, stringified
    \{{                -- a literal `{{` (no interpolation)
    """

The opening-line margin is stripped: the block's indentation lays out the source
but does not enter the value. Each `{{…}}` body is trimmed, wrapped in
the internal interpolation renderer, and the whole literal is joined with `++`.

An interpolation body may be one of exactly **four simple shapes**:

    {{name}}           -- a bare identifier
    {{record.field}}   -- a field access
    {{Module.value}}   -- a qualified name
    {{fn arg}}         -- a single function application

Anything more complex — operators, multi-argument calls, parenthesised
expressions — is left as **literal `{{…}}` text**, a deliberate signal that only
simple references interpolate. Compute the value into a `let` binding first and
interpolate the name.

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
- The four body shapes above are the whole grammar; a more complex body stays
  literal `{{…}}` rather than failing — bind it to a name and interpolate that.
- A qualified body `{{Module.value}}` resolves exactly as it does outside a
  string: the module must be imported under that qualifier, or the body is
  refused (IPE-N0034, or IPE-N0004 for an unknown qualifier), never printed as
  literal text.
- `\{{` emits a literal `{{`. An unclosed `{{` with no matching `}}` is treated
  as literal content.
- Interpolation joins with `++`, so an interpolated string is exactly the
  concatenation you would write by hand — prefer it over a long `++` chain for
  readability.

## See also

- [String interpolation over `++`](../idioms/string-interpolation.md) — the idiom.
- [Strings](../guide/string.md) — the `String` toolkit and text boundary.
- `ipe doc String.fromInt`, `ipe doc String.fromBool` — the explicit conversions
  that render the same forms outside a `"""…"""` string.
