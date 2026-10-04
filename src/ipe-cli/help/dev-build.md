Compile a program to a native or WebAssembly development artifact, with Debug.* on.

```
ipe dev build [<path>] [<shape>] [<runtime>] [<host>] [<target>]
```

## Arguments

path: a source file, a project directory, or a package.ipe (default: the current project). shape is derived from `main` and, if written, only cross-checked. runtime/host apply to `web` only: `web` = served (served is the unnamed default, never written), `web solo` = self-contained browser client, and a host is desktop/ios/android. A `desktop`/`ios`/`android` host lays out the app bundle for that host (a fast dev bundle; `release build web <host>` produces the production distributable). With no delivery args, `dev build` builds the default delivery — the fast one-artifact inner loop; `release build` builds every declared delivery. Delivery args select a subset or override for this invocation only and never edit package.ipe.

## Options

- @--out
- @--runtime
- `[--emit-ir]` — also emit the intermediate representation
- `[--fix]` — apply machine-applicable fixes before building
- @--accept-risks
- @--static
- @--target
- @--allocator
- @--cfree
- `[--debugger]` — compile the in-app time-travelling debugger overlay into the built app
- @--quiet
- @--json

## Output

a native build lands the runnable binary at `out/bin/<project-name>` under the project (copied there within the build), so it is findable even when a shared `CARGO_TARGET_DIR` places cargo's own output outside the project.
