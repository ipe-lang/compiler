# Environment config

`Ipe.Env` reads *public* configuration that is baked into the compiled artifact at
build time — not the live process environment. Its one function, `Env.public`,
resolves only a name on the project's allowlist and returns a `Maybe String`. It
is the narrow, safe substitute for `System.getenv` in a browser bundle, which has
no process environment at all.

## The mental model

Three knots.

- **`public` reads build-time config, not the live environment.** `Env.public
  "API_BASE_URL"` returns a value embedded when the artifact was compiled, not a
  read of the host's environment at run time. On a wasm target there *is* no
  process environment to read; on the native target it reads the live environment
  through the same allowlist, so a config module shared between a server-side path
  and a browser client type-checks — and behaves identically — against both.
- **Only allowlisted names resolve; everything else is `Nothing`.** A name
  resolves only if it is on the project's `publicEnv` allowlist in `package.ipe`.
  Any other key returns `Nothing` — there is no way to reach the raw host
  environment through this function. Because the result is a `Maybe`, a missing or
  non-allowlisted key is a value you handle, never a crash.
- **Secret names are refused at build time.** The allowlist is validated against a
  secret-name denylist when the manifest is *parsed*: the name is upper-cased and
  rejected if it equals `DATABASE_URL`, begins with the `IPE_` namespace, or has any
  `_`-separated component that is a secret word (`SECRET`, `TOKEN`, `KEY`,
  `PASSWORD`, `PASSWD`, `CREDENTIAL`, `AUTH`, `APIKEY`). Component matching means a
  bare `SECRET` or `APIKEY` is refused as surely as `DB_SECRET`, while an ordinary
  name that merely embeds those letters (`AUTHOR`, `KEYBOARD`, `TOKENIZER`) stays
  allowed. Allowlisting a secret-shaped name is a build error, not a run-time
  refusal — so a credential cannot be embedded into a shipped browser bundle even by
  mistake.
- **Path-root names, repeats and malformed names are refused too.** The temp-root
  variables (`TMPDIR`, `TMP`, `TEMP`) steer where the runtime creates scratch
  directories and the home variables (`HOME`, `USERPROFILE`, `HOMEDRIVE`,
  `HOMEPATH`) steer where caches live, so neither can be allowlisted, in any case.
  An entry must be a portable name (ASCII letters, digits and `_`, not starting
  with a digit), and listing one name twice (ignoring case) is a build error.

## A worked example: public config in a browser app

The example under
[`examples/wasm/env-public`](../../examples/wasm/env-public/src/Main.ipe) is a wasm
web app. Its `package.ipe` allowlists exactly one name:

```ipe
package : Package
package =
    { name = "wasm-env-public"
    , version = "0.1.0"
    , wasm = On { mode = Solo, publicEnv = [ "API_BASE_URL" ] }
    }
```

`init` reads the allowlisted name — which resolves — and also probes a
secret-shaped name that is *not* allowlisted, to show it reads as absent:

```ipe
init _req =
    ( { apiBaseUrl = Maybe.withDefault "(none)" (Env.public "API_BASE_URL")
      , secretProbe = Maybe.withDefault "(none)" (Env.public "IPE_AUTH_TOKEN_SECRET")
      }
    , Cmd.none
    )
```

`API_BASE_URL` shows its embedded value; `IPE_AUTH_TOKEN_SECRET` reads as `(none)` —
it is not on the allowlist, and its `IPE_*` shape would be refused at parse time if
someone tried to add it.

## The why

Restricting embedded config to an explicit, denylist-checked allowlist is
[deny-by-default][principles]: a browser bundle is shipped to every user, so
anything embedded in it is public, and the only names that reach it are the ones
the author named on purpose. Returning `Maybe` rather than a bare `String` keeps
[make invalid states unrepresentable][principles] honest — a config value that
might be absent has a type that says so, and the caller supplies the default at the
call site.

For a native program that *should* read the live process environment — command-line
tools, servers — reach for [System](system.md) (`getenv`, `getenvOr`) instead;
`Ipe.Env` is specifically the build-time, wasm-safe surface.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Env` — the single `public` function.
- **Sibling guides:** [System](system.md) — the live process environment for
  native programs. [Maybe](maybe.md) — the absence type `public` returns.
- **Concepts:** [The Elm Architecture](the-elm-architecture.md) — the app shape the
  worked example is built in.
