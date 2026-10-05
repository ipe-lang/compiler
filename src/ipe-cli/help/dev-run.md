Compile a program as a development build and run the resulting binary.

```
ipe dev run [<path>]
```

## Arguments

A source file, a project directory, or a package.ipe. Defaults to the current project.

## Options

- @--out
- @--runtime
- @--static
- @--target
- @--allocator
- @--cfree
- `[--debugger]` — compile the in-app time-travelling debugger overlay into the run app
- `[--record]` — cli/worker apps: record the TEA session to out/session.ipelog (one plain `<msg> => <model>` line per step) and, when its Msg is encodable, a replayable out/session.ipemsgs
- `[--replay [<log>]]` — cli/worker apps: re-fold a recorded session (default: out/session.ipemsgs) from init with no Cmd fired, printing each step and the final model; a log from a changed program is refused. A plain trace (.ipelog, the default when no typed log was recorded, e.g. a Msg carrying a Secret) is shown instead, labelled, with every control character stripped and nothing re-run
- @--quiet
- @--json
- `[-- <args>...]` — forward <args> to the compiled program
