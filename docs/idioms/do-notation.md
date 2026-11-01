# `do`-notation

**The idiom:** when a computation is two or more effects run in order — each
possibly using the previous result — write a `do` block instead of a chain of
`Task.andThen`.

## The shape

A `do` block is a sequence of steps, read top to bottom. Three statement forms:

- **`name <- task`** — run `task`, bind its success value to `name`, continue.
- **`name = expr`** — bind a pure value to `name` (no task run). Desugars to
  `let name = expr in` around the rest of the block.
- **`task`** — run `task` for its effect and discard the result (a `()`).

The block's value is its last step. A failure anywhere short-circuits the rest —
you never thread the error by hand.

Every `do` block must contain at least one `<-` bind or bare-run step. A block
whose every line is a pure `=` binding is a compile error — use `let … in`
there instead. `do` and `let … in` are disjoint by construction: `let … in` is
for pure binding sequences; `do` is for Task sequencing with at least one real
effect step.

## Why prefer it

Written with `Task.andThen`, a three-step chain drifts to the right in a pyramid:

```ipe
main =
    let version = "1.4.0" in
    Io.println ("Preflight for v" ++ version)
        |> Task.andThen (\_ ->
            Task.parallel [ checkBuild, checkChangelog, checkGitClean ]
                |> Task.andThen (\results ->
                    Io.println (report version results)))
```

The same logic as a `do` block reads straight down —
from [`examples/shapes/script/release-preflight`](https://github.com/ipe-lang/compiler/tree/main/examples/shapes/script/release-preflight):

```ipe
main =
    let version = "1.4.0" in
    do
        Io.println ("Preflight for v" ++ version)   -- bare : run for its effect, discard the ()
        results <- Task.parallel                    -- `<-` : run all three at once, bind the List
            [ checkBuild
            , checkChangelog
            , checkGitClean
            ]
        Io.println (report version results)
```

The two are the *same* program — `do` desugars to that `andThen` chain. The block
form makes the order of effects, and each binding, plain.

## Bare-run over `_ <- task`

When a task's result is `()` and you don't use it, run it as a **bare line** —
never bind it to `_`:

```ipe ipe:skip
_ <- Io.println "starting"    -- avoid: the discard is noise
Io.println "starting"         -- prefer: a bare line already discards
```

Both forms discard the `()`; the bare line just says so with less ceremony. A
`do` block full of `_ <-` prefixes reads worse for no gain. Reserve `_ <- task`
for the one case where making the discard *visible* genuinely helps a reader —
otherwise drop the prefix.

## When not to reach for it

A single effect needs no `do` — just return the task. One `andThen` is fine
inline; the payoff starts at two chained steps. For *independent* values combined
at the end (not a dependent sequence), `Task.map2`..`map5` or `Task.parallel` say
that better than a `do` block.

For a block that is entirely pure — no task runs, just a few name bindings
followed by an expression — use `let … in`, not `do`. A `do` whose every
statement is a `=` binding and has no `<-` or bare-run step is a compile error;
the compiler will direct you to `let … in`.

## References

- [`Ipe.Task`](https://github.com/ipe-lang/compiler/blob/main/docs/reference/stdlib/Task.md) — the combinators `do` sequences.
- `ipe doc do` — the construct reference.
- [The Elm Architecture](../guide/the-elm-architecture.md) — where a task's result
  returns as a `Msg` in an interactive program.
