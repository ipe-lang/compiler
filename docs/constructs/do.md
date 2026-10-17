# do

A syntactic shorthand for chaining `Task.andThen` calls. The block sequences
one or more effect steps; the final expression is the overall `Task` result.
The desugaring is mechanical: every `name <- task` becomes a
`Task.andThen (\name -> …)` wrapping the rest of the block.

## Syntax

Three statement forms are available inside a `do` block:

    do
        <name> <- <task-expr>   -- bind: run the task, name its result
        <name> = <pure-expr>    -- pure let: bind a pure value, no task run
        <task-expr>             -- run: run the task, discard the ()

To run a task only for its effect and discard its `()` result, write it as a
bare line — do NOT write `_ <- task`. The `_ <-` bind is redundant noise:

    _ <- Io.println x           -- avoid
    Io.println x                -- prefer

A `do` block must contain at least one `<-` bind or bare-run step. A block
whose every statement is a `=` pure-let binding is rejected at compile time
(`IPE-P0065`); use `let … in` for an all-pure block.

## Import

A module that writes `do` must import `Ipe.Task`, under any spelling:
`import Ipe.Task`, `import Ipe.Task as T`, or `import Ipe.Task exposing (..)`.
Every `<-` sequences through `Ipe.Task`'s `andThen`, whatever name the import
gives the module, so an alias never changes what `do` means and another module
aliased `Task` never stands in for it. Without the import each `<-` is
`IPE-N0034`: "`<-` comes from `Ipe.Task`, which you haven't imported yet."

## Example

    import Ipe.Io as Io
    import Ipe.Task

    greet : Task Error ()
    greet =
        do
            name <- Io.readLine
            greeting = "Hello, " ++ name ++ "!"
            Io.println greeting

## Desugaring

The `do` block above is equivalent to:

    greet : Task Error ()
    greet =
        Io.readLine
            |> Task.andThen (\name ->
                let greeting = "Hello, " ++ name ++ "!" in
                Io.println greeting)

## Notes

- Only `Task`-typed expressions may appear on the right-hand side of `<-` or
  as a bare-run step.
- The right-hand side of `=` must be a pure (non-`Task`) expression.
- The final line must be a `Task` expression (not a plain value).
- A block with no `<-` or bare-run step is a compile error. Use `let … in`
  for pure binding sequences; `do` and `let … in` are disjoint by construction.
- Run a task for its effect alone as a **bare line**, not `_ <- task` — the
  discard is implied and the prefix only adds noise. Reserve `_ <- task` for the
  rare case where making the discard visible genuinely aids clarity.
- `do` is notation — it generates no runtime overhead beyond the `andThen` chain.

## See also

- `Ipe.Task` — the full `Task` combinator surface.
- `Ipe.Io` — standard-I/O tasks.
