# case

Pattern-match a value against one or more branches. Each branch specifies a
pattern and an expression that produces the result when the pattern matches.
Every variant of the matched type must be covered; the compiler rejects a
non-exhaustive `case` at compile time.

## Syntax

    case <expr> of
        <pattern> -> <result>
        <pattern> -> <result>

## Example

    describe : Maybe Int -> String
    describe m =
        case m of
            Just n  -> "got " ++ String.fromInt n
            Nothing -> "absent"

## Notes

- All branches must produce the same type.
- Patterns are matched top-to-bottom; the first match wins.
- Wildcard `_` matches any value without binding it.
- Constructor patterns may bind inner values: `Just n`, `Err msg`.

## See also

- `Ipe.Maybe`, `Ipe.Result` — the ADTs most often matched with `case`.
