Audit a package against the Tier-1 quality gate, publish it to the index, validate an index entry file, or run the index CI's authoritative receiving gate on a submitted entry.

```
ipe package <audit|audit-entry|publish|validate-entry> [<path>]
```

## Arguments

The subcommand and its path: `audit`/`publish` take the project directory or `package.ipe` (defaults to the current project); `validate-entry` takes a `packages/<name>.toml` entry file (schema check only); `audit-entry` takes the same entry file and runs the full index CI receiving gate: schema, fetch+integrity-verify, and the complete Tier-1 (+ Tier-2) audit for every new version.

## Options

- `[--index <dir|repo>]` — audit: read the previous published version from this index checkout; publish: the index repo the PR targets
- `[--json|--plain]` — audit: emit a compact certify verdict on stdout ({"package":…,"certified":…}; non-zero exit on a failing audit)
- `[--dry-run]` — publish: print the computed entry and intended PR, touch no network
- `[--source <url>]` — publish: the source URL to pin (overrides the git remote)
- `[--rev <sha>]` — publish: the revision to pin (overrides the committed HEAD)
- `[--fork <owner>]` — publish: the owner of your index fork to push to (defaults to the source owner)
