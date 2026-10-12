# Results

A `Result e a` is either `Ok a` (a success carrying a value) or `Err e` (a
failure carrying an error). It is Ipê's typed alternative to exceptions: a
function that can fail says so *in its return type*, and the caller must deal with
both outcomes before touching the success value.

## The mental model

Three knots.

- **The error is a value, not a thrown thing.** There is no `try`/`catch`. A
  failure is an ordinary `Err e` you pattern-match, `map` over, or pass along.
  Because the type is `Result e a` — not `a` with a hidden exception channel —
  the compiler will not let you use the success value without first confronting
  the failure. A function whose type is `Result` cannot surprise a caller with an
  error the caller forgot could happen.
- **Chain fallible steps with `andThen`, not nested `case`.** When step two needs
  step one's success *and* can itself fail, `Result.andThen` threads them: the
  `Err` short-circuits, so you write the happy path once and failures fall through
  untouched. Hand-nesting `case Ok/Err` around every step is the anti-pattern
  `andThen` exists to delete.
- **Combine independent results with `map2`..`map5`; the first `Err` wins.** When
  several fields are parsed *independently* and you want to build one value from
  all of them, `Result.map3 f ra rb rc` applies `f` only when every argument is
  `Ok`, and yields the first `Err` otherwise. This is how you assemble a typed
  record from a form: one combinator, no field-order boilerplate. (`combine` and
  `traverse` do the same across a *list* of results.)

## A worked example: a signup-form parser

The example under
[`examples/shapes/script/result-signup-form`](../../examples/shapes/script/result-signup-form/src/Main.ipe)
parses a raw three-field form into a typed `Account`. The `Account` type is the
target — and its existence is proof the input was valid, because it can only be
built from already-parsed fields:

```ipe
type alias Account =
    { username : String
    , age : Int
    , email : String
    }
```

Each field has its own parser returning `Result String field`. The age parser
shows `andThen` chaining a fallible step onto another: `String.toInt` gives a
`Maybe`, `Result.fromMaybe` lifts the absent case into a typed error, and
`andThen` runs the range check only on a parsed number:

```ipe
parseAge : String -> Result String Int
parseAge raw =
    String.toInt (String.trim raw)
        |> Result.fromMaybe "age must be a whole number"
        |> Result.andThen inHumanRange


inHumanRange : Int -> Result String Int
inHumanRange n =
    if n >= 13 && n <= 120 then
        Ok n

    else
        Err "age must be between 13 and 120"
```

The whole-form parse is one `map3`: it applies the `Account` constructor to the
three parsed fields, short-circuiting on the first failure. No nested `case`, no
field-order bookkeeping:

```ipe
parseForm : RawForm -> Result String Account
parseForm form =
    Result.map3 Account
        (parseUsername form.username)
        (parseAge form.age)
        (parseEmail form.email)
```

Running it (`ipe dev run`) over five forms — one valid, four each tripping a
different check — prints:

```
OK: ada <ada@example.com> age 36
REJECTED: username is required
REJECTED: age must be a whole number
REJECTED: age must be between 13 and 120
REJECTED: email is not a valid address
```

## The why

`Result` is [parse, don't validate][principles] made into a type. The raw form is
turned into a typed `Account` **once**, at the boundary; every function
downstream takes an `Account`, so it never re-encounters the unvalidated strings
and never re-checks them. A validator that returned a bool and left the caller
holding the raw strings would invite exactly the re-check-or-forget bug this
avoids.

It is also [make invalid states unrepresentable][principles]: there is no
half-built `Account` with a validated username but an unparsed age. `map3`
produces either a complete `Account` or an `Err` — never a partial one. And the
[soundness][principles] guarantee follows from the type: because failure is an
`Err` value rather than a panic, no bad input can make the program fall over.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Result` — every combinator with a
  verified example. `ipe doc Ipe.Result.andThen` and `ipe doc Ipe.Result.map3`
  cover the two idioms above.
- **Sibling guides:** [Maybe](maybe.md) — absence *without* an error; `Result`
  is `Maybe` that also says *why*. [Tasks](../reference/stdlib/Task.md) for effects
  that may fail asynchronously (a `Task` settles to a `Result`).
- **Concepts:** [Types and inference](types.md) — how `Ok`/`Err` and the error
  type `e` are tracked. [The parse-don't-validate idiom](../idioms/parse-dont-validate.md).
