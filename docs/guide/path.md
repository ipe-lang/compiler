# Filesystem paths

`Ipe.Path` is the opaque, validated filesystem path — the small type that stops a
`..` traversal or a NUL byte from ever reaching a syscall. Every `Ipe.File` entry
point takes a `Path`, not a raw `String`, so the validation happens once, at
construction, and no file operation re-checks it.

## The mental model

Four knots.

- **`Path` is opaque — `fromString` is the only door, and it rejects.** The single
  constructor is `Path.fromString`, which normalises separators and returns `Err`
  for a path containing a NUL byte or one that escapes its root via `..`. The
  constructor for the type is not exported, so a value of type `Path` is *proof*
  it is a clean, in-root path — there is no unchecked `Path`.
- **The accessors are total.** `base`, `dir`, `ext`, and `isAbsolute` take a
  `Path` and return a component with no failure case, because the value is already
  known clean. `ext` returns `""` (no extension) rather than a `Maybe` — absence
  is the empty string, and there is nothing to fail.
- **`Path` is the currency of the filesystem API.** `Ipe.File` reads and writes
  take a `Path`, and `Ipe.Process.runWith` takes a `Path` for its working
  directory. So the traversal check moves to the boundary where a raw string
  enters the program, and everything downstream holds an already-safe value.
- **Compose with `under`, never with `++`.** `Path.under root child` joins a
  relative `child` beneath `root` and returns `Err` when the child is empty,
  absolute, carries a `..` element, or the join would not lie below the root —
  `/repo2/x` is not under `/repo`, because containment is checked per component,
  not as a string prefix. `Path.absolute` resolves a relative path against the
  working directory through the same join (a `filesystem` read). Both are
  lexical: they never follow or forbid a symlink, so a link below the root can
  still point outside it; confining a program against links is the capability
  jail's job.

## A worked example: parsing upload paths

The example under
[`examples/shapes/script/path-safe-join`](../../examples/shapes/script/path-safe-join/src/Main.ipe)
runs a mix of candidate strings — some clean, one a traversal attack — through the
single gate, then reads components off the parsed paths.

`fromString` is the one gate: a clean string becomes `Ok Path`, a traversal
escape a typed `Err`, and only a parsed `Path` reaches the accessors:

```ipe
describe raw =
    case Path.fromString raw of

        Ok path ->
            String.join "  "
                [ Path.toString path
                , "base=" ++ Path.base path
                , "ext=" ++ ext path
                , "abs=" ++ boolString (Path.isAbsolute path)
                ]

        Err _ ->
            raw ++ "  ->  REJECTED (traversal or NUL)"
```

Running it (`ipe dev run`) accepts the clean paths, reads their components, and
rejects the `..` escape:

```
uploads/report.csv  base=report.csv  ext=.csv  abs=no
uploads/../../etc/passwd  ->  REJECTED (traversal or NUL)
/var/log/app.log  base=app.log  ext=.log  abs=yes
notes  base=notes  ext=(none)  abs=no
```

## The why

The opaque `Path` is [parse, don't validate][principles] applied to the
filesystem: the traversal and NUL checks happen once, in `fromString`, and produce
a type that *cannot* hold an unsafe path — so `Ipe.File` never re-checks and can
never be handed a `../../etc/passwd`. A bare-`String` path passed to a read would
force every file-facing function to re-validate or trust; the opaque type removes
that ambiguity.

Rejecting the escape at construction rather than at open time is
[deny-by-default][principles]: the failure surfaces where the untrusted string
*enters*, close to the handler that received it, not deep in a syscall that is
harder to trace back to its source.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Path` — `fromString`, `toString`, `base`,
  `dir`, `ext`, `isAbsolute`, `under`, `absolute`, and the opaque `Path` type.
- **Sibling guides:** [Files](file.md) — the effectful read/write side that takes a
  `Path`. [Subprocesses](process.md) — `runWith` takes a `Path` for the child's
  working directory. [Results](result.md) — what `fromString` returns.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — the discipline the opaque `Path` embodies.
