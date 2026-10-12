# Publishing a package

This page takes you from a working library to a published package another
developer can `ipe add`. It assumes you have finished [Getting
started](getting-started.md) and can build and run an Ipê project.

## How the registry works

Ipê packages live in a single **curated public index** — a Git repository whose
`packages/` directory holds one entry file per package, listing every published
version with the exact source URL, pinned revision, and content hash. The index
is served as a read-only API over GitHub Pages, which is what `ipe add` queries.

You do not push to the index directly. `ipe package publish` opens a **pull
request** against it: a single **signed** commit that adds your new version to
your package's entry file. The index's admission CI re-runs the full receiving
gate on that PR — it re-fetches your source at the pinned revision, verifies the
hash, and re-runs the audit — and merges only when every check passes. Two
independent boundaries therefore stand between an attacker and a published
package: the commit signature (proving *who* published) and the admission gate
(proving *what* was published is sound). This is the model that lets the index
stay open to any GitHub user without a maintainer vetting each upload by hand.

## One-time setup

Publishing signs a commit as *you*, so the index can attribute every version to
a real, verified GitHub identity. Two one-time steps, none repeated per release:

1. **A GitHub account.** The index is hosted on GitHub; your account is your
   publisher identity. Nothing to configure — you already have one if you cloned
   this repo.

2. **`ipe login`.** This authorizes `ipe` with GitHub over the device flow — it
   prints a short code and a URL; you enter the code in your browser, and `ipe`
   stores a scoped token (`public_repo`, enough to fork the index and open the
   PR) at `~/.config/ipe/token` with `0600` permissions.

   ```sh
   ipe login               # authorize, store the token, offer signing-key setup
   ipe login --status      # show the stored token and the signing key publish uses
   ipe login --signing-key # set up the signing key on its own
   ipe login --logout      # remove the token
   ```

   The login token is also how `publish` learns your account's login and id, so
   it can sign the commit as `you`, using your account's GitHub `noreply` email —
   the address GitHub already treats as verified for you. That is why the signed
   commit comes out "Verified" for every publisher automatically, with no
   maintainer-side key curation.

   **The signing key.** The commit must be signed by an SSH key registered on
   your account as a **Signing Key** — that signature is what ties the commit to
   you. When none is configured, `ipe login` asks (default *no*) whether to set
   one up:
   - it generates a dedicated ed25519 key without a passphrase at
     `~/.config/ipe/signing_key` (`0600`; the public half beside it as
     `signing_key.pub`);
   - it registers the public half as a signing key through a **second, one-time**
     device-flow authorization with the `write:ssh_signing_key` scope. That token
     is used for this single request and never stored (the login token `ipe`
     stores is always requested with `public_repo` alone). Revoke the grant
     under *Authorized OAuth Apps* at <https://github.com/settings/applications>
     — that revokes the stored login token too;
   - if registration fails, the local key is removed — nothing half-configured
     is left behind.

   `ipe package publish` then signs with that key automatically. Review or revoke
   it at *Settings → SSH and GPG keys* on GitHub.

   **Bring your own key instead.** Register an existing key's **public** half at
   *Settings → SSH and GPG keys → New SSH key* with **Key type: Signing Key** (not
   the default *Authentication Key* — this distinction is what lets GitHub mark
   your commits "Verified"), and point `ipe` at the **private-key file**:

   ```sh
   export IPE_PUBLISH_SIGNING_KEY=~/.ssh/id_ed25519
   ```

   When set, `IPE_PUBLISH_SIGNING_KEY` always wins over the key `ipe login`
   stored; if it names no readable file, publish refuses rather than fall back.

> Without a registered signing key, `ipe package publish` **refuses** rather than
> producing an unverifiable commit the index would reject downstream. A refusal
> at your terminal, naming the fix, beats a rejected PR you have to debug.

## Author a library

An application has a `main`; a **library** exposes modules for other projects to
import. Scaffold one with `--lib`:

```sh
ipe init --lib mypackage
cd mypackage
```

This writes a `package.ipe` manifest whose shape differs from an app's — instead
of a delivery block it carries `exposedModules`, the list of modules other
projects may import:

```ipe
module Package exposing (package)

import Ipe.Package exposing (..)


package : Package
package =
    { name = "mypackage"
    , version = "0.1.0"
    , exposedModules = [ "Mypackage" ]
    }
```

- **`name`** is the package's name in the index — it must be unique there.
- **`version`** is a [semantic version](https://semver.org). The index enforces
  semver: from `1.0.0` on, a release whose public API changed incompatibly must
  bump the major version and an addition must bump the minor. On the initial
  `0.y.z` line the major is reserved, so an incompatible change bumps the minor
  and an addition the patch. The audit **rejects an under-bump** (see below).
- **`exposedModules`** lists every module a consumer may import. Add a public
  module under `src/` and list it here; a module not listed stays internal to the
  package.

Write your code under `src/`, keep each public module in `exposedModules`, and
verify it builds and its tests pass before you publish:

```sh
ipe dev build
ipe test
```

## Declare what your package can do

Ipê infers the **capabilities** a package exercises — filesystem, network,
subprocess, and so on — from its call graph. A published package must declare
that set in its manifest's `[capabilities]`, and the audit requires the declared
set to **equal** the inferred one exactly: a used-but-undeclared capability is a
hidden effect, and a declared-but-unused one is a misleading claim. Both reject.

See exactly what your package exercises:

```sh
ipe capabilities            # the inferred set, human-readable
ipe capabilities --json     # the same set as a JSON envelope
```

Declare that set in `package.ipe` so a consumer sees, up front, precisely what
the package is allowed to do.

## Audit before you publish

`ipe package audit` runs the same universal **Tier-1 gate** the index CI will
run on your PR — so you catch every rejection locally, before opening it:

```sh
ipe package audit
```

Its four checks, in order:

1. **Provenance panic-scan** — your own Rust (if the package binds native code)
   is free of panic-prone patterns.
2. **Capability consistency** — the inferred capability set equals the declared
   `[capabilities]` (above).
3. **Enforced semver** — `ipe diff` compares this version's public API against
   the previous published *stable* version and rejects an under-bump.
   Prereleases are never the baseline: they promise no compatibility, so a
   stable release answers to the stable release before it. A prerelease
   submission, or a first stable version (no stable predecessor), skips this
   check.
4. **Supply chain** — `cargo-deny` over the emitted project's dependency graph,
   plus a content-hash re-assertion over any Ipê package dependencies
   (verify-before-trust).

A package that binds native Rust (`[rust.dependencies]`) also runs a **native
Tier-2** check: its native code is built and exercised inside a jail scoped to
its declared capabilities, so a native dependency cannot quietly reach past what
the package claims. Tier-2 is enforced on Linux; other platforms are a
documented refuse-to-certify rather than a false pass.

A passing audit is the precondition for a clean publish — if `audit` rejects, the
index will too, so fix it here first.

## Publish

Preview exactly what will be submitted, touching no network, with `--dry-run`:

```sh
ipe package publish --dry-run
```

This prints the computed index entry (name, version, source URL, pinned
revision, content hash) and the pull request it would open. When it looks right,
publish for real:

```sh
ipe package publish
```

`publish` gates locally (it re-runs the audit and refuses on a failure), pins
your source URL and the committed `HEAD` revision — refusing a dirty tree or an
unpushed `HEAD`, so the index can never point at a revision nobody can fetch —
computes the content hash, signs the commit with your key, pushes to your fork of
the index, and opens the PR (through the GitHub API when a login token or
`GITHUB_TOKEN` is present, otherwise printing a browser link). From there the
index's admission CI takes over; when it merges, GitHub Pages serves your new
version within minutes.

Useful flags:

- `--fork <owner>` — the owner of *your* fork of the index to push to (defaults
  to the owner inferred from your source URL).
- `--source <url>` / `--rev <sha>` — pin a source URL or revision explicitly,
  overriding the git remote and committed `HEAD`.
- `--index <dir|repo>` — target a different index (for a private or staging
  registry).

## Consume a package

From any project, add a published package by name and version requirement:

```sh
ipe add mypackage@^0.1
```

`ipe add` resolves the version against the index, clones the source at its
pinned revision, **verifies the content hash** before trusting a byte of it, and
records the dependency in **both** `package.ipe` (the `dependencies` block, so a
fresh clone re-resolves it) and `ipe.lock` (the exact resolved revision, for a
reproducible build). Then import an exposed module and build as usual:

```ipe
import Mypackage
```

```sh
ipe dev build
```

## Troubleshooting

- **The index PR shows "Unverified", or `publish` refuses with an identity
  error.** Your commit is not signed by a key GitHub can attribute to you. Check
  that (a) the signing key publish uses — shown by `ipe login --status` — has
  its *public* half registered on your account as a **Signing Key** (the key
  `ipe login --signing-key` generates is registered for you), and (b) you have
  run `ipe login` so `publish` can resolve your identity.
- **`ipe login` says the token is missing or malformed.** Re-run `ipe login`; if
  a stored token is corrupt, `--status` reports it distinctly and re-authorizing
  overwrites it.
- **The audit rejects.** The reject header names the failing check — map it to
  the list [above](#audit-before-you-publish): a capability mismatch means your
  `[capabilities]` and `ipe capabilities` disagree; an enforced-semver reject
  means the version does not clear the bump `ipe diff` requires; a supply-chain
  reject comes from `cargo-deny` or a dependency hash mismatch.
- **`publish` refuses on a dirty tree or unpushed `HEAD`.** Commit and push your
  source first — the index pins a revision that must be fetchable, so an
  uncommitted or unpushed state fails closed by design.
- **The push to your fork fails.** git pushes over `https` without a terminal
  prompt, so it authenticates only through a git credential helper. Configure
  one (`gh auth setup-git` sets up GitHub's) and make sure your account can
  push to the fork.

## Where to go next

- [Delivering an app](delivery.md) — for an application (not a library), how a
  shape becomes a desktop or mobile distributable.
- [Testing](test.md) — the in-process test framework the audit expects to pass.
- [The `ipe` command reference](../reference/cli.md) — every command and flag,
  including `init`, `add`, `login`, and `package`.
