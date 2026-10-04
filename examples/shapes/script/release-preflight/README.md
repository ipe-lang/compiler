# release-preflight

A **Program-shape** script (a plain `main` you drive with tasks — no TEA loop)
that shows `do` notation and concurrent fan-out with `Task.parallel`:

- A bare line runs a task for its effect and discards the result.
- `<-` binds a task's result for the rest of the block.
- `Task.parallel [a, b, c]` runs its elements concurrently and collects results
  as a `List`; bind it inside a `do` with `results <- Task.parallel [...]`.

`src/Main.ipe` carries the hand-written `Task.andThen` equivalent in a comment,
so you can see exactly what the block desugars to.

```sh
ipe dev run src/Main.ipe
```
