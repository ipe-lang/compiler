# http-shell — an HTTP query shell over `Cli.tea`

A line-driven REPL. `subscriptions` subscribes with `Cli.Sub.onLine`, so
`Cli.tea` reads one line of standard input at a time, turns it into a
command, and re-renders `view : Model -> Lines Msg`.

- `get <url>` performs a real `Http.get`, then prints the response status and
  body. The request runs as a `Task`, so the input loop never blocks.
- `quit` exits (end-of-input also exits).

Anything else prints a friendly hint and leaves the state unchanged.

## Run

```
ipe dev run examples/shapes/terminal/http-shell
```

Then type, for example:

```
get https://example.com
```

You can also drive it non-interactively by piping commands in:

```
printf 'get https://example.com\nquit\n' | ipe dev run examples/shapes/terminal/http-shell
```
