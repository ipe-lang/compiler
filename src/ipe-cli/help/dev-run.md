Compile a program as a development build and run the resulting binary.

```
ipe dev run [<dir>]
```

## Arguments

A project directory (default: the current directory). With no delivery args, `dev run` runs the one delivery declared in `ships` in package.ipe (the served default when `ships` is absent); when `ships` declares several, it refuses and lists the command for each. A `web client` delivery has no binary to run: `dev run` publishes its bundle to out/www/ and serves it, read-only, on 127.0.0.1 — on the port `IPE_WEB_PORT` names, else a free one — then prints the URL and opens it in a browser. Ctrl-C stops it.

## Options

- @--out
- @--runtime
- @--static
- @--target
- @--allocator
- @--cfree
- `[--debugger]` — compile the in-app time-travelling debugger overlay into the run app
- `[--record]` — cli/worker apps: record the TEA session to out/session.ipelog (one plain `<msg> => <model>` line per step and, when the process ended inside `update`, a last line naming the message that was running) and, when its Msg is encodable, a replayable out/session.ipemsgs
- `[--replay [<log>]]` — cli/worker apps: re-fold a recorded session (default: out/session.ipemsgs) from init with no Cmd fired, printing each step and the final model; a log from a changed program is refused. A plain trace (.ipelog, the default when no typed log was recorded, e.g. a Msg carrying a Secret) is shown instead, labelled, with every control character stripped and nothing re-run
- @--quiet
- @--json
- `[-- <args>...]` — forward <args> to the compiled program
