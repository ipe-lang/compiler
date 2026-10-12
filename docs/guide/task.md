# Tasks

A `Task Error a` is a *description* of work that, when the runtime runs it, either
succeeds with an `a` or fails with a typed `Error`. It is how an Ipê program talks
about effects — reading a file, calling a service, printing a line — as ordinary
values you build and compose before anything happens.

## The mental model

Three knots.

- **A Task is a description, not the effect. Building one runs nothing.** `Io.println "hi"`
  does not print; it *builds a task that would print*. The runtime is the single
  place an effect actually happens, and it runs exactly one task: `main`.
  Everything else is plumbing that assembles that one task. This is why effects
  stay referentially transparent — you can pass a task around, put it in a list,
  run it twice, without it firing early.
- **`do` sequences dependent steps, and the first failure short-circuits.** When
  step two needs step one's result, `do` (sugar over `Task.andThen`) binds each
  with `<-` and reads top to bottom. If any step fails, the `<-` stops there — the
  steps below simply never run. You write the happy path once; failure falls
  through on its own, no per-step error check.
- **The error channel is a typed, matchable `Error` — recovery is composition.**
  A failure carries an `Error` value (classified by kind, not a bare string).
  `Task.onError` catches it and returns a *new* task, so "try, and on failure do
  X" is ordinary function composition — there is no separate `try`/`catch`
  mechanism bolted onto the language.

## A worked example: a deploy runner with rollback

The example under
[`examples/shapes/script/task-deploy-steps`](../../examples/shapes/script/task-deploy-steps/src/Main.ipe)
runs a deploy as a chain of dependent steps, then catches a failure and rolls
back.

Each step is a task that either succeeds with a log line or *fails with a typed
error* — the failure is a value, built where the check is:

```ipe
check label ok =
    if ok then
        Task.succeed ("ok   — " ++ label)

    else
        Task.fail (Error.invalidInput ("failed — " ++ label))
```

The deploy is a `do` block: each `<-` binds the previous step's success, and if a
step fails the chain short-circuits — the steps below it never run. Read it top to
bottom, not as a nested `andThen` pyramid:

```ipe
deploy migrationsOk =
    do
        build <- check "build compiled" True
        _ <- Io.println ("  " ++ build)
        migrated <- check "migrations applied" migrationsOk
        _ <- Io.println ("  " ++ migrated)
        released <- check "traffic shifted" True
        _ <- Io.println ("  " ++ released)
        Task.succeed "deploy succeeded"
```

Recovery is `Task.onError`: it catches a failure on the typed channel and hands
back a rollback task, turning a failed deploy into a clean result instead of a
crash:

```ipe
attempt name migrationsOk =
    do
        _ <- Io.println (name ++ ":")
        outcome <-
            deploy migrationsOk
                |> Task.onError rollback
        Io.println ("  => " ++ outcome)
```

And `main` is itself the one task the runtime runs — everything above merely
*described* work:

```ipe
main =
    do
        _ <- attempt "green deploy" True
        attempt "bad deploy" False
```

Running it (`ipe dev run`) shows the green deploy running every step, and the bad
deploy short-circuiting at the failed migration (the traffic-shift step never
runs) then rolling back:

```
green deploy:
  ok   — build compiled
  ok   — migrations applied
  ok   — traffic shifted
  => deploy succeeded
bad deploy:
  ok   — build compiled
  ! InvalidInput: failed — migrations applied
  rolling back
  => rolled back
```

## Repeating a step

Some work repeats one step until it is finished: draining a queue, paging
through an API, polling a job, counting up to a target. `Task.loop` runs such a
step:

- **The step returns a `Step`.** `Continue state` runs the step again from the
  new state; `Done result` ends the loop with that result. A failing step ends
  the loop with its error unchanged. `Step` comes from
  `import Ipe.Task as Task exposing (Step(..))`.
- **The ceiling is required.** `Task.loop limit init step` runs the step at most
  `limit` times. A loop that needs one more step fails with an `InvalidInput`
  error naming the ceiling, so a runaway loop stops with a typed error rather
  than spinning forever.

Four shapes come up often enough to walk through.

**Paging through an API by cursor.** The state is the cursor plus what has been
collected so far; the loop is done once a page reports no next cursor. The
ceiling is the most pages the call is willing to fetch:

```ipe
fetchPage : Maybe String -> Task Error Page

pageStep :
    ( Maybe String, List String )
    -> Task Error (Step ( Maybe String, List String ) (List String))
pageStep ( cursor, items ) =
    do
        page <- fetchPage cursor
        let
            collected =
                items ++ page.items
        in
        case page.nextCursor of
            Nothing ->
                Task.succeed (Done collected)

            Just next ->
                Task.succeed (Continue ( Just next, collected ))


fetchAll : Task Error (List String)
fetchAll =
    Task.loop 50 ( Nothing, [] ) pageStep
```

`Task.loop` fits because the number of pages isn't known up front — only the
server's "no next cursor" signal ends it — and 50 is an honest cap on how much
one call may fetch, not a guess at stack depth.

**Draining a queue, one batch at a time.** The state is what's left to process;
the step takes one batch off the front and reports whether the queue is now
empty:

```ipe
processBatch : List String -> Task Error (List String)

drainStep : ( List String, Int ) -> Task Error (Step ( List String, Int ) Int)
drainStep ( queue, processed ) =
    case queue of
        [] ->
            Task.succeed (Done processed)

        _ ->
            do
                remaining <- processBatch queue
                Task.succeed (Continue ( remaining, processed + 1 ))


drainQueue : List String -> Task Error Int
drainQueue queue =
    Task.loop 10000 ( queue, 0 ) drainStep
```

The queue shrinks by one batch per step, so the ceiling only has to exceed the
queue's largest realistic size — a generous 10000 here — and the loop still
ends the instant the queue empties.

**Polling a job until it reports done, with a bounded number of attempts.** The
state is the attempt count; the step asks the job once and either reports
`Done` with the result or `Continue` to try again:

```ipe
checkJobStatus : Int -> Task Error JobStatus

pollStep : Int -> Task Error (Step Int String)
pollStep attempt =
    do
        status <- checkJobStatus attempt
        case status of
            Finished result ->
                Task.succeed (Done result)

            Running ->
                Task.succeed (Continue (attempt + 1))


pollUntilDone : Task Error String
pollUntilDone =
    Task.loop 20 0 pollStep
```

Here the ceiling *is* the retry policy: "poll at most 20 times" is the whole
attempt budget, stated once as the limit argument instead of hand-rolled as a
counter threaded through the step.

**The anti-pattern it replaces: a function that calls itself inside `andThen`.**
Without `Task.loop`, the way to repeat a step is a function calling itself
through `andThen`:

```ipe
countRecursive : Int -> Int -> Task Error Int
countRecursive target n =
    if n >= target then
        Task.succeed n

    else
        Task.andThen (\_ -> countRecursive target (n + 1)) (Task.succeed n)
```

Each recursive call nests one more pending task inside the last, so the stack
grows with `target` — a few thousand steps trip the runtime's recursion limit,
and the function has no declared bound, only whatever depth the stack happens to
allow. The same count written as a loop makes the bound explicit and typed:

```ipe
countStep : Int -> Int -> Task Error (Step Int Int)
countStep target n =
    if n >= target then
        Task.succeed (Done n)

    else
        Task.succeed (Continue (n + 1))


countTo : Int -> Int -> Task Error Int
countTo limit target =
    Task.loop limit 0 (countStep target)
```

`countTo 150000 150000` succeeds with `150000`, running at the same stack depth
whether it takes 10 steps or 150,000. `countTo 5 150000` fails fast with
`InvalidInput: Task.loop ran its step 5 times, its ceiling, without reaching
Done` — a typed error naming the ceiling, not a stack overflow. `Task.loop`
turns "how many times might this run" from a guess about the stack into a
number you write and the runtime enforces.

## The why

Task-as-a-value is [soundness][principles] for effects: because building a task
does nothing, the type `Task Error a` fully describes *what could happen* before
anything does, and the runtime is the single, auditable place an effect fires.
There is no hidden side effect lurking in an innocent-looking expression.

The typed `Error` channel is [make invalid states unrepresentable][principles]
carried into failure: a task cannot fail with an untyped, unmatchable value, so a
handler like `onError` can classify and route the failure by kind. And `do`'s
automatic short-circuit is [ease of use][principles] — the happy path is written
once, failures propagate for free, and the code reads as a straight sequence
rather than a pyramid of nested error checks.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Task` — every combinator with a verified
  example. `ipe doc Ipe.Task.andThen`, `ipe doc Ipe.Task.onError`, and
  `ipe doc Ipe.Task.parallel` cover sequencing, recovery, and concurrency;
  `ipe doc Ipe.Task.loop` covers repeating a step under a ceiling.
- **Sibling guides:** [Results](result.md) — `Result` is a task that has already
  settled; `Task.fromResult` bridges them. [Lists](list.md) — `Task.sequence`
  turns a `List (Task Error a)` into one task. The typed failure type lives in
  `Ipe.Error` (see `ipe doc Ipe.Error`).
- **Concepts:** [The do-notation idiom](../idioms/do-notation.md) — how `<-` and
  the bare-statement form desugar to `andThen`. [The Elm Architecture](the-elm-architecture.md)
  — where tasks fit in a full `init`/`update`/`view` app. The
  [`release-preflight`](../../examples/shapes/script/release-preflight/src/Main.ipe)
  example shows `Task.parallel` for independent, concurrent steps.
