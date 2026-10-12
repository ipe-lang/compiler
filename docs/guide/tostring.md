# Rendering values to String

Every primitive has a total "render this value to a `String`" path: the typed
`String.fromInt` / `String.fromFloat` / `String.fromBool` for their own type,
and `{{expr}}` interpolation inside a `"""…"""` string for stitching several
rendered values into one line. There is no generic stringifier: a standalone
conversion always names the type it renders.

## The mental model

Two ideas.

- **One typed renderer per type.** `String.fromInt`, `String.fromFloat`, and
  `String.fromBool` each render exactly their own type, so the call site says
  what becomes text. `Bool` renders lowercase (`"true"` / `"false"`), the same
  form `{{flag}}` interpolation produces.
- **Rendering is total.** Every `Int`, `Float`, and `Bool` has a String form,
  so these functions never fail — no `Maybe` to unwrap, no `Result` to
  handle. The direction that *can* fail is the other one, *parsing* a String
  back into a number, which lives in `Ipe.String` (`toInt` / `toFloat`) and
  returns a `Maybe`.

## A worked example: a summary row

The example under
[`examples/shapes/script/tostring-render`](../../examples/shapes/script/tostring-render/src/Main.ipe)
renders one row of mixed-type fields by interpolating each straight into a
triple-quoted string:

```ipe
row : String -> Int -> Float -> Bool -> String
row label count ratio enabled =
    """{{label}}: count={{count}} ratio={{ratio}} enabled={{enabled}}"""
```

Running it (`ipe dev run`):

```
alpha: count=3 ratio=0.75 enabled=true
beta: count=128 ratio=1.5 enabled=false
```

Each `{{expr}}` body is rendered by the compiler's interpolation renderer, so
`count` (an `Int`) and `enabled` (a `Bool`) need no explicit `String.fromInt`
or `String.fromBool` — only `label`, already a `String`, passes through
unchanged. Interpolation takes exactly these scalars — `String`, `Int`,
`Float`, `Bool` and `Char` — and a record, custom type or container is refused
at type-check, so render its fields one by one. Outside a `"""…"""` string,
the same row is built with the explicit conversions:

```ipe ipe:skip
label ++ ": count=" ++ String.fromInt count ++ " enabled=" ++ String.fromBool enabled
```

## The why

Rendering a primitive to text is total by nature — a number is always some
sequence of digits — so `String.fromInt`, `fromFloat`, and `fromBool`
return a bare `String`, not a `Maybe`. This is the asymmetry
[parse-don't-validate][parse] names: going *to* a String throws away structure
and cannot fail, while going *from* one recovers structure and can, so only
the parse direction carries a failure type. Keeping the two directions in
different shapes (a total renderer, a fallible `String.toInt`) makes that
asymmetry visible in the types.

[parse]: ../idioms/parse-dont-validate.md

## References

- **Per-symbol reference:** `ipe doc String.fromInt`, `ipe doc String.fromFloat`,
  `ipe doc String.fromBool`.
- **Sibling guides:** [Strings](string.md) — the home of the parse direction
  (`String.toInt` / `String.toFloat`), richer text building, and the full
  `{{expr}}` interpolation syntax. [Basics](basics.md) — the auto-imported
  prelude. [Characters](char.md) — code points and classification.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — why rendering is total but parsing is fallible.
  [String interpolation](../constructs/string-interpolation.md) — the full
  `{{expr}}` grammar.
