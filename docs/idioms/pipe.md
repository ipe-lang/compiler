# The pipe: `|>`

**The idiom:** when a value flows through several transformations, thread it with
`|>` so the steps read left to right in the order they happen, instead of nesting
function calls that read inside out.

## The shape

`x |> f` is `f x`. Chained, `x |> f |> g |> h` is `h (g (f x))` — but written in
the order the data moves. Each stage takes the previous result as its **last**
argument, so partially-applied functions (`List.map f`, `String.join sep`) slot in
naturally.

## Why prefer it

Nested, a multi-step transform reads inside-out — you find the start in the middle:

```ipe
report text =
    String.join "\n" (List.map formatRow (List.take 3 (ranked (tally (tokenize text)))))
```

As a pipeline it reads as a recipe, top to bottom — from
[`examples/shapes/script/word-frequency`](https://github.com/ipe-lang/compiler/tree/main/examples/shapes/script/word-frequency):

```ipe
report : String -> String
report text =
    text
        |> tokenize
        |> tally
        |> ranked
        |> List.take 3
        |> List.map formatRow
        |> String.join "\n"
```

Same computation, but the reader follows the text through split → tally → rank →
take → format → join without unwinding nested parentheses.

## When not to reach for it

A single call needs no pipe — `f x` is clearer than `x |> f`. A pipe also wants
its stages to each take the threaded value *last*; when an argument order fights
that, a named intermediate (`let step = … in`) reads better than forcing the pipe.

## References

- `ipe doc |>` — the operator reference.
- [`Ipe.List`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/List.md) — the pipeline stages in the example.
- [Pure functions](../guide/pure-functions.md) — why each stage is a pure
  transformation of the last.
