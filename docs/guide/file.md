# Files

`Ipe.File` reads and writes the filesystem. Two ideas shape the whole module: a
path is a **typed, validated value** (not a raw string), and every operation is an
**effect** — a `Task Error _` the runtime performs, never a plain function that
reaches out and touches the disk on its own.

## The mental model

Three knots.

- **A path is parsed once, at `Path.fromString`.** `Ipe.Path.Path` is opaque; the
  only way to build one is `Path.fromString`, which normalises the path and
  **rejects** a `..` traversal escape or a NUL byte, returning `Result Error
  Path`. Every `File` entry point takes a `Path`, not a `String` — so an
  unvalidated, attacker-influenced string can never reach a syscall. The check
  happens at construction, once; downstream code holds a value that is already
  safe.
- **File operations are `Task`s, so you sequence them.** `readFile`, `writeFile`,
  `exists`, `readDir` each return `Task Error _`. Nothing happens when you name
  one; it happens when the runtime runs the task. Chain several with a `do` block:
  bare lines run for their effect, `<-` binds a task's success value. This is the
  same shape every effectful program uses.
- **Bridge a `Result` into the chain with `Task.fromResult`.**
  `Path.fromString` returns a `Result`, but the `do` block threads `Task`s. Lift
  the one into the other: `Task.fromResult (Path.fromString raw)` fails the whole
  task on a bad path, so a later step only ever sees a validated `Path`.

## A worked example: a temp-dir scratchpad

The example under
[`examples/shapes/script/file-scratchpad`](../../examples/shapes/script/file-scratchpad/src/Main.ipe)
creates a fresh temp directory, writes two notes, reads one back, and lists the
directory — a whole session as one `do` block:

```ipe
main =
    do
        dir <- File.tempDir "scratchpad"
        Io.println ("scratch dir: " ++ dir)

        notePath <- toPath (dir ++ "/note.txt")
        todoPath <- toPath (dir ++ "/todo.txt")

        File.writeFile notePath "remember to water the plants\n"
        File.writeFile todoPath "- ship the docs\n- rest\n"

        contents <- File.readFile notePath
        Io.println ("note.txt says: " ++ String.trim contents)

        present <- File.exists todoPath
        Io.println ("todo.txt exists: " ++ boolText present)

        dirPath <- toPath dir
        entries <- File.readDir dirPath
        Io.println ("entries: " ++ String.join ", " (List.sort entries))
```

The `toPath` helper is the parse-don't-validate boundary. Every raw path string
passes through it, becoming a `Path` or failing the task — so `writeFile`,
`readFile`, and the rest never see an unvalidated string:

```ipe
toPath : String -> Task Error Path
toPath raw =
    Task.fromResult (Path.fromString raw)
```

Running it (`ipe dev run`) prints the session (the temp path varies per run):

```
scratch dir: /tmp/scratchpad<unique>
note.txt says: remember to water the plants
todo.txt exists: yes
entries: note.txt, todo.txt
```

## The why

The typed `Path` is [defend in depth][principles] against path traversal made
structural. A `readFile : String -> ...` would let `"../../etc/passwd"` — assembled
from user input three call-sites away — reach the filesystem, and every call site
would have to remember to sanitise. Routing every path through `Path.fromString`
means the `..`/NUL check happens once, at construction, and the type system
guarantees no unchecked string can slip past it: there is simply no `File`
function that accepts a `String` path.

Modelling I/O as `Task` is what keeps the rest of the language
[pure](pure-functions.md). A function that returned the file's contents directly
would depend on the disk — its result would change run to run, breaking the
[correctness][principles] guarantee that the same program with the same input
yields the same output. A `Task` *describes* the read; the runtime is the single
place that performs it, so purity holds everywhere else.

[principles]: ../../PRINCIPLES.md

## Writing the working tree under the jail

A program granted the filesystem capability runs with its working tree
writable, except the version-control metadata in it: `.git`, `.hg`, `.jj`, and
`_darcs` stay read-only, as does the git directory a `.git` file points to when
it lies in a writable path. That holds at any depth: a submodule's or a nested
checkout's metadata is found and kept read-only as well. Your version-control
tools run code that metadata names (hooks, filters, configured commands), so a
jailed program that could write it could run code outside the jail the next
time you commit. The program still reads the repository, so `git status` and
friends work inside it.

Finding nested metadata means reading every directory of the tree once at each
start of the jail. A tree too large to read in full (too many entries, nested
too deep, or holding too many repositories), a directory in it that cannot be
read, or a directory on another filesystem refuses the jail, since metadata
past it could go unprotected. The refusal names the place and the limit: run `ipe clean` to drop build output, run from a directory
that holds fewer files, or run without the filesystem grant.

Keeping the metadata read-only is not enough when its configuration points
back into a writable path: a `core.hooksPath` of `.husky`, a hook that is a
symlink to a script in the tree, or a configured command or included file kept
in the tree. Each build of the jail reads that configuration, and the jail
refuses to start while any setting names, or may name, code the program could
write. The refusal names the file and the setting. Point the setting outside
the writable paths, or run without the filesystem grant. Only the repository's
own configuration is read; your global and system configuration lie outside
the jail's writable paths.

On Windows and FreeBSD the jail cannot yet keep that metadata read-only, so it
refuses to run a granted program from a tree that holds it: run without the
filesystem grant, or from a tree without version-control metadata, nested
repositories included. Metadata the program creates while it runs is not
covered; review a tree a program wrote before running your version-control
tools over it.

## Configuration

`IPE_FILE_READ_MAX` sets the per-call byte ceiling of `File.readFile`, and
`IPE_PROCESS_OUTPUT_MAX` the ceiling on a subprocess's buffered output. Their
defaults and exact rules live in the [**File** subsystem](../reference/env.md#file)
of the environment variable reference; `ipe doc <VAR>` prints the same entry.
For a per-call cap of your own, `File.readFileLimit` takes a `ByteSize`:
`ByteSize.zero` admits only an empty file.

## References

- **Per-symbol reference:** `ipe doc Ipe.File` and `ipe doc Ipe.Path` — every
  function with its signature. `ipe doc Ipe.File.walk` covers recursive directory
  traversal.
- **Sibling guides:** [Tasks](../reference/stdlib/Task.md) — sequencing, concurrency,
  and error handling for the effects `File` returns. [Result](result.md), which
  `Path.fromString` returns and `Task.fromResult` bridges.
- **Concepts:** [Pure functions and immutability](pure-functions.md) — why disk
  access is a `Task`. [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — why a `Path` is a parsed value. [The `do` notation](../idioms/do-notation.md).
