# Testing

`Ipe.Test` is a lightweight, **in-process test framework**. A test is an ordinary
value; an assertion returns a result carrying its reason; and a runner prints a
summary and sets the process exit code, so a suite is a runnable program CI can
gate on.

## The mental model

Three knots.

- **A test is a value.** `Test.test name thunk` builds a single test; `Test.suite
  name children` groups tests (and sub-suites) into a tree. Tests are data you
  compose with ordinary list and function tools — there is no special
  test-declaration syntax, so a suite can be built, filtered, and passed around
  like any other value.
- **An assertion returns a `TestResult`, never throws.** `Test.equal`, `Test.ok`,
  `Test.err`, `Test.isTrue`, `Test.expectErr` each yield `Passed` or a `Failed`
  that *carries the reason* — "expected 4 but got 5". A failing assertion is a
  value, so the runner can report every failure in one pass rather than aborting
  at the first.
- **`runMain` is the whole program.** `Test.runMain tests` runs the tree, prints a
  pass/fail summary, and exits `0` when everything passed and non-zero otherwise.
  A test module's `main` is just `Test.runMain [...]`, which is exactly what a CI
  step needs: run it, trust the exit code.

## A worked example: an arithmetic suite

The example under
[`examples/shapes/script/test-suite`](../../examples/shapes/script/test-suite/src/Main.ipe)
tests a couple of pure helpers, exercising the equality, `Result`, and boolean
assertions, and wires the tree to `runMain`.

Each test is a `name` paired with a thunk that returns a `TestResult`; the suite
is a plain list of them:

```ipe
suite : Test
suite =
    Test.suite "arithmetic"
        [ Test.test "doubling two is four" (\_ -> Test.equal 4 (doubled 2))
        , Test.test "positive parse succeeds" (\_ -> Test.ok (parsePositive 7))
        , Test.test "non-positive parse fails" (\_ -> Test.err (parsePositive 0))
        , Test.test "membership is true" (\_ -> Test.isTrue (List.member 2 [ 1, 2, 3 ]))
        ]
```

`main` is nothing but the runner over the tree:

```ipe
main =
    Test.runMain [ suite ]
```

Running it (`ipe dev run`) prints the summary and exits `0` because every assertion
passed:

```
6 passed, 0 failed (6 total)
```

A failing `Test.equal` would print a `FAIL` line naming the test and the
"expected … but got …" reason, and `runMain` would exit non-zero — the signal CI
reads.

## The why

Modelling a test as a value and an assertion as a returned `TestResult` rather
than a thrown exception is [make invalid states unrepresentable][principles]
applied to a test run: there is no "the harness fell over on test 3 and we don't
know about 4–6" state, because a failure is a `Failed reason` in the results list,
not control flow that unwinds the runner. Every failure is collected and reported.

Tying the outcome to the process exit code through `runMain` is [correctness][principles]
made mechanical: "did the suite pass?" is answered by an integer CI already knows
how to check, not by scraping printed text. And because the assertions are total
functions over the values under test, the framework itself has no I/O and no
hidden state — a suite is as pure and reproducible as the code it exercises.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Test` — every builder
  (`test` / `suite`), assertion (`equal` / `notEqual` / `ok` / `err` /
  `expectErr` / `isTrue` / `isFalse`), and runner (`run` / `summarise` /
  `runMain`).
- **Sibling guides:** [Result](result.md) — the type `Test.ok` / `Test.err`
  assert over. [Error](error.md) — the classified failure `Test.expectErr` matches
  on by kind. [Lists](list.md) — a suite is a list of tests, composed with the
  ordinary list tools. [Tasks](task.md) — `runMain` and `summarise` are tasks,
  sequenced before the process exits.
- **Concepts:** [Pure functions and immutability](pure-functions.md) — why a
  total, value-returning assertion makes a suite reproducible.
