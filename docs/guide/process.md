# Subprocesses

`Ipe.Process` runs a child process — and never through a shell. The command and
its arguments are handed to the operating system as a direct argument vector, so a
caller-controlled string can never be reinterpreted as shell syntax. That single
design choice removes command injection from the surface entirely.

## The mental model

Three knots.

- **No shell, ever — arguments are literal.** `Process.run cmd argv` executes
  `cmd` with `argv` as separate `argv` entries; there is no `sh -c`, no
  word-splitting, no glob or variable expansion. An argument like `"$HOME"` or
  `"a; rm -rf /"` is passed verbatim as one literal string. A command built from
  untrusted input cannot escape into shell syntax, because there is no shell to
  escape into.
- **`run` for the common case; `runWith` for the details.** `Process.run` succeeds
  with the child's captured stdout and fails the Task on a non-zero exit or a spawn
  failure. `Process.runWith` is the richer form: it captures `exitCode`, `stdout`,
  and `stderr` independently, supports a per-child working directory and
  environment overrides, and treats a non-zero exit as a *normal* result carried in
  `exitCode` — only a spawn failure fails the Task. Reach for `runWith` when a
  non-zero exit is expected and you want to inspect it.
- **It is a server-only, capability-tagged effect.** Running a child process is
  default-denied under `--target wasm` (a browser bundle has no process surface),
  and a program that spawns one is tagged with the `subprocess` capability so a
  sandbox can isolate it. Both entry points return a `Task`, so a spawn is
  sequenced in the Task discipline like any other effect.

## A worked example: capturing a child's output

The example under
[`examples/shapes/script/process-run`](../../examples/shapes/script/process-run/src/Main.ipe)
runs two children: the simple `run` for a successful command, then `runWith` to
show an argument passed literally and the exit code captured.

`run` binds the child's stdout with `<-`, like any effect:

```ipe
greeting <- Process.run "echo" [ "hello", "from", "a", "child" ]
Io.println ("run -> " ++ String.trim greeting)
```

`runWith` takes a config record and returns exit code, stdout, and stderr — and
the `$HOME`-shaped argument comes back verbatim, proving no shell expanded it:

```ipe
result <-
    Process.runWith
        { command = "printf"
        , args = [ "%s\n", "$HOME is not expanded" ]
        , cwd = Nothing
        , env = []
        }
Io.println ("exit=" ++ String.fromInt result.exitCode)
Io.println ("stdout -> " ++ String.trim result.stdout)
```

Running it (`ipe dev run`) prints:

```
run -> hello from a child
exit=0
stdout -> $HOME is not expanded
```

## The why

Passing an argument vector rather than a command string is
[deny-by-default][principles] against injection: the class of "a value flowed into
a string that a shell then parsed" cannot occur, because no string is ever handed
to a shell. This is stronger than escaping — there is nothing to escape, so there
is no escaping bug to get wrong.

Tagging the spawn as a `subprocess` capability and denying it on wasm is the same
principle at the boundary: a capability a program does not need is one it does not
get, and a sandbox can see exactly which programs reach for a child process.
`runWith` treating a non-zero exit as data rather than a Task failure serves
[make invalid states unrepresentable][principles] — "the command ran and exited
7" is a normal outcome with a value, distinct from "the command could not be
started", which is the failure.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Process` — `run` and `runWith`, with the
  full config record.
- **Sibling guides:** [Tasks](task.md) — how the spawn is sequenced and its errors
  recovered. [Paths](path.md) — the typed `Path` that `runWith`'s `cwd` takes.
  [System](system.md) — the current process's own environment and arguments.
  [Standard I/O](io.md) — writing the captured output to stdout.
