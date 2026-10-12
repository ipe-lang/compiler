# System

`Ipe.System` is the program's window onto its process: the command-line
arguments, the environment variables, the working directory, and the exit code.
Almost all of it is *effectful* — process-global state can change between reads —
so most functions return a `Task Error _` you sequence like any other effect.

## The mental model

Three knots.

- **A read of mutable process state is an effect.** `System.args ()`,
  `System.getenv key`, and `System.cwd ()` return a `Task Error _`, not a bare
  value, because the environment they read is global and mutable — two reads can
  disagree. You bind them with `<-` in a `do` block, exactly like a file read or a
  network call. This keeps [pure functions](pure-functions.md) pure: a function
  that needs the environment takes an effect, it doesn't reach into a global.
- **`getenvOr` is the one sync read — because it can't fail.** `System.getenvOr
  key default` returns a bare `String`, no `Task`, because the supplied default
  resolves the missing-variable case at the call site. When you have a sensible
  fallback, this is the ceremony-free path; when a *missing* variable is an error,
  reach for `getenv` (which fails) or `getenvInt`/`getenvBool` (which also parse).
- **`args ()` gives the user arguments; the program name is already dropped.**
  `System.args ()` returns just the arguments the user typed — the executable path
  at argv index 0 is gone. The whole-argv `System.getArg n` is the escape hatch for
  the rare case that wants index 0. Because `args` is a `List String`, the first
  argument is `List.head`, which returns a `Maybe` — absence is a value, never an
  out-of-bounds.

## A worked example: a greeting CLI

The example under
[`examples/shapes/script/system-greet-cli`](../../examples/shapes/script/system-greet-cli/src/Main.ipe)
reads its name from the first user argument, its greeting word from an environment
variable, and writes the result to stdout with a diagnostic on stderr.

The first argument is `List.head` of `args ()` — a `Maybe`, defaulted to `"world"`,
so no argument is a normal case rather than a crash:

```ipe
firstName : List String -> String
firstName argv =
    List.head argv
        |> Maybe.withDefault "world"
```

The greeting word comes from `getenvOr` — the sync read, because the default
handles an unset `GREETING`, so it is a bare `String` with no `<-`:

```ipe
greeting : String
greeting =
    System.getenvOr "GREETING" "Hello"
```

`main` binds the effectful `args ()` with `<-`, then writes: the argument count to
*stderr* (a diagnostic) and the greeting to *stdout* (the result), so a caller can
capture one stream without the other:

```ipe
main =
    do
        argv <- System.args ()
        Io.eprintln ("user args: " ++ String.fromInt (List.length argv))
        Io.println (greeting ++ ", " ++ firstName argv ++ "!")
```

Running it with no arguments (`ipe dev run`) prints:

```
user args: 0
Hello, world!
```

(the first line on stderr, the second on stdout).

## The why

Making every environment read an effect is [correctness][principles] by
construction: a program's output depends only on its explicit inputs, and a read
of global mutable state *is* an input, so it must be visible in the type. A
function that silently read an environment variable would be a hidden input that
breaks the "same input, same output" guarantee; a `Task` in the signature makes
that dependency honest.

`getenvOr` returning a bare `String` rather than a `Task` is [ease of
use][principles] serving [make invalid states unrepresentable][principles]: when a
default is supplied there is no failure to represent, so the type carries none —
the caller isn't forced to handle an `Err` that can't occur. And `getArg` / `head`
returning a `Maybe` rather than panicking on a short argument list is
[soundness][principles]: a missing argument is a value the compiler makes you
handle, never an index that falls off the end.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.System` — every function with a verified
  example. `ipe doc Ipe.System.getenvInt` and `ipe doc Ipe.System.getenvBool`
  parse-and-fetch in one step; `ipe doc Ipe.System.exit` terminates with a code.
  For a *wasm* build with no process environment, `ipe doc Ipe.Env` covers
  `Env.public` — the build-time, allowlisted public-config substitute.
- **Sibling guides:** [Io](io.md) — the stdout/stderr/stdin effects the example
  writes to. [Maybe](maybe.md) — the absence type `head` and `getArg` return.
  [Tasks](task.md) — how the effectful reads are sequenced and their errors
  recovered. [Lists](list.md) — `head` and `length` over the argument list.
- **Concepts:** [Pure functions and immutability](pure-functions.md) — why an
  environment read must be an effect.
