# String interpolation over `++`

**The idiom:** when you build a string out of several pieces of text and values,
reach for a triple-quoted string with `{{…}}` interpolation, not a long `++`
chain. The interpolated form reads as the text it produces; the `++` chain reads
as plumbing.

## The shape

A `"""…"""` string spans multiple lines and its source indentation is stripped,
so you lay the text out where it is written without that layout leaking into the
value. Inside it, `{{expr}}` substitutes a scalar (`String`, `Int`, `Float`,
`Bool` or `Char`) — rendered by the compiler's internal interpolation renderer,
so an `Int` needs no `String.fromInt`. A record, custom type or container is
refused at type-check: interpolate its fields instead.

A gnarly concatenation like this:

```ipe ipe:skip the string-concatenation chain the interpolated form below replaces; not a standalone declaration
"Deploying " ++ service ++ " v" ++ String.fromInt version ++ " to " ++ region ++ "\n"
```

becomes one readable interpolated string:

```ipe
summary : String -> Int -> String -> String
summary service version region =
    """
    Deploying {{service}} v{{version}} to {{region}}
    """
```

Both produce the same text. The interpolated form puts the values where they
land in the output, and `{{version}}` stringifies the `Int` on its own.

## Name a long body

An interpolation body is any expression — `{{a + b}}`, `{{user.name}}` and
`{{String.join ", " tags}}` all interpolate. When a body grows past a short
call, compute it into a `let` binding and interpolate the name, so the text
still reads as the text it produces:

```ipe
line : Int -> Int -> String
line done total =
    let
        pct = done * 100 // total
    in
    """
    progress: {{pct}}%
    """
```

## When not to reach for it

Interpolation lives **only** in triple-quoted strings; in a single-line `"…"`
string `{{x}}` is literal text. For a short one-piece string with no
substitution, a plain `"…"` is clearest — the idiom pays off once you are
stitching text and values together.

## References

- [`string-interpolation`](../constructs/string-interpolation.md) — the construct
  reference: the full `{{…}}` grammar, escaping, and margin rules.
- [Strings](../guide/string.md) — the `String` toolkit.
- `ipe doc String.fromInt`, `ipe doc String.fromFloat`, `ipe doc String.fromBool` —
  the explicit conversions for a value built outside a `"""…"""` string.
