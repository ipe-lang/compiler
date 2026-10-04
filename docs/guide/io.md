# Standard I/O (`Ipe.Io`)

`Ipe.Io` is the program's line to the terminal: reading a line (or a password)
from stdin, and writing to stdout or stderr. Every function is a `Task Error _` —
I/O is an effect, sequenced like any other.

## The mental model

Three knots.

- **stdout is the result; stderr is the commentary.** `Io.println` / `Io.writeStdout`
  write the program's *output* — the thing a caller pipes into the next command.
  `Io.eprintln` / `Io.writeStderr` write *diagnostics* — progress, warnings, a
  banner — to a separate stream, so `mytool | grep …` filters the result without
  the noise. Choosing the right stream is a real interface decision, not a
  formatting one.
- **`println` adds a newline; `writeStdout` does not.** The `*ln` pair terminates
  the line for you; the raw `writeStdout` / `writeStderr` pair writes exactly the
  bytes you give, for when you are composing a line piece by piece or emitting
  something without a trailing newline.
- **A password read returns a `Secret`, not a `String`.** `Io.readSecret prompt`
  suppresses terminal echo, restores the terminal mode even if the read fails, and
  hands back an opaque `Secret`. The plaintext is reachable only through the scoped
  `Secret.use secret (\plain -> …)`, so a freshly-read password cannot slip into a
  log, an error, or a serialized payload by accident. A plain line is `Io.readLine`.

## A worked example: the write side of a CLI

The greeting CLI under
[`examples/shapes/script/system-greet-cli`](../../examples/shapes/script/system-greet-cli/src/Main.ipe)
(walked through in full in the [System guide](system.md)) shows the stream split.
It writes its diagnostic — the argument count — to stderr, and its actual result —
the greeting — to stdout:

```ipe
main =
    do
        argv <- System.args ()
        Io.eprintln ("user args: " ++ String.fromInt (List.length argv))
        Io.println (greeting ++ ", " ++ firstName argv ++ "!")
```

Running it (`ipe dev run`) with the streams shown separately:

```
user args: 0          # stderr
Hello, world!         # stdout
```

Because the count went to stderr, `ipe dev run … | cat` would show only
`Hello, world!` — the result — while the diagnostic still reaches the terminal.
Printing a whole *list* of lines is the `List.map Io.println` then `Task.sequence`
idiom shown in the [List guide](list.md).

## The why

Two separate streams is [ease of use][principles] as an honest interface: a tool
that mixed diagnostics into stdout would corrupt whatever consumed its output, so
the type-level `println`/`eprintln` split guides you to the composable design by
default. It costs nothing and prevents a whole class of "why is my pipeline
output full of progress messages" bug.

`readSecret` returning a `Secret` rather than a `String` is [security][principles]
and [make invalid states unrepresentable][principles] at the input boundary: the
plaintext has no representation outside the scoped `Secret.use`, so the code path
that would log or serialize a password simply doesn't type-check. The safe outcome
is the only reachable one — parse, don't validate, applied to a secret at the
moment it is read.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Io` — every function with a verified
  example. `ipe doc Ipe.Io.readSecret` covers the password read;
  `ipe doc Ipe.Io.readLine` the plain line read.
- **Sibling guides:** [System](system.md) — arguments, environment, and exit
  codes, the input side of the same CLI. [Tasks](task.md) — how the I/O effects are
  sequenced with `do` and their errors handled. [Lists](list.md) — printing a whole
  list with `List.map Io.println` and `Task.sequence`. [Strings](string.md) —
  building the lines you print.
- **Concepts:** [Pure functions and immutability](pure-functions.md) — why writing
  to a terminal is an effect, not a plain function call.
