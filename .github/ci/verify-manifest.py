#!/usr/bin/env python3
"""Drift gate for the CI check-disposition SSOT (ci/check-manifest.yml).

Fails (exit 1) when the manifest and reality disagree, so no check can exist
without a declared disposition and no `gate` can silently lose its producer.

Checks performed
  1. Every status context produced by .github/workflows/*.yml or *.yaml
     (matrix legs expanded) is present in the manifest.  An unclassified
     check is the exact "silent advisory red" this SSOT exists to forbid.
  2. Manifest self-consistency:
       - a known disposition (gate | nightly-gate | informational | delete);
       - `informational` entries name an `owner`;
       - an entry that `guards` a Security/Soundness/SEAL invariant is NOT
         `informational` (§0/§1/§3: a guarantee may not sit in an un-gated bucket);
       - a `gate`/`nightly-gate` entry has a producer workflow that exists;
       - a `delete` entry has no producer (an orphan), else it is a live check.
  3. Fail-closed dependency surfacing: GitHub reports a job whose `needs`
     failed as SKIPPED, and a skipped required check counts as passing.  So
     every job a gate transitively `needs` must itself surface in a gate (its
     own context is a gate, or a gate `aggregates` it); likewise a
     nightly-gate's ancestors must surface in a gate or nightly-gate.  A
     status context produced by two jobs is refused outright — a required
     context must resolve to exactly one producer.
  4. Required-set derivation: `check_required_set.derive` accepts the
     manifest (a `gate-external` names its `integration_id`; no other entry
     does) and `ci/required-set.json` is exactly the derived
     `{context, integration_id}` set.  The live ruleset is compared by
     `check_required_set.py --fetch` (see `ci/RECONCILIATION.md`).
  5. `ci/deterministic-checks.json` — the SSOT of (job, check step) pairs
     consumed by ci.yml's `cancel-on-cheap-red` watcher — is well-formed (exact keys, non-empty strings with
     no surrounding whitespace, no duplicate job), its job set equals the
     watcher's `needs:`, and each pair's step is a `name:` of that job's steps
     in ci.yml.
  6. rustc wiring and cache hygiene: no job wraps or replaces rustc, so
     every build compiles with the pinned toolchain's own rustc and no cache
     stands between the source and the artifact a gate vouches for. Every
     local `./` `uses:` (step or composite step) is resolved on disk
     (action.yml, then action.yaml) under a normalized, byte-exact id; an
     unresolved, ambiguous, case-variant, non-composite, cyclic, or
     over-deep local action is refused, as is a job-level `uses:` (reusable
     workflow). Refused anywhere: an `env:` key naming a rustc wrapper or a
     rustc replacement at any scope; any `env:` value, `run:`, `shell:`,
     `defaults.run.shell`, or `with:` text naming one (or cargo's
     `rustc-wrapper` config spelling), or assembling its target through a
     GitHub Actions expression function (`format(`, `join(`, `toJSON(`, or
     `fromJSON(` over a literal; any letter case) instead of naming it
     literally; and a `Swatinem/rust-cache` step whose `with.save-if` is not
     exactly `RUST_CACHE_SAVE_IF`, so only `main` writes the dependency cache
     and a pull request run restores it without evicting it. Every workflow,
     manifest, and local action is loaded through `strict_yaml` (see that
     module), so a duplicate mapping key, a `<<` merge key, an anchor/alias,
     or an explicit tag — each legal to a plain YAML loader but resolved
     differently, or not at all, from what GitHub Actions runs — is refused
     rather than silently resolved. Malformed shapes are refused, never
skipped. Limits are listed on `check_workflow_steps`. Likewise mold is
     installed only through `./.github/actions/mold`, which checks the pinned
     release digest; a raw `rui314/setup-mold` reference is refused.
  7. CI inputs and runner command files, over the same traversal as check 6:
     every third-party `uses:` is pinned to a 40-hex commit SHA (a `docker://`
     reference, and every job `container:`/`services:` image, to a sha256
     digest); pip installs only as the one canonical command
     `CANONICAL_PIP_INSTALL` (`PIP_CONFIG_FILE=/dev/null`, `--isolated`,
     `--require-hashes --only-binary :all: -r` the hashed requirements file),
     parsed into a `PipInvocation` and compared whole, with every other
     `PIP_*` name, pip config file, and non-pip installer refused; and the
     runner env file is written only through
     `ci/github-env.sh`, called in a step's `run:` in its one canonical form
     with a bare `CI_JOB_*` key listed in `ci/github-env-allowlist.txt`. Every
     string key and value of every workflow, job, step, and local action is
     scanned by one matcher: any spelling (any case, `$VAR`, `${VAR}`,
     `env.VAR`, an env key) of GITHUB_ENV/PATH/STATE/OUTPUT/STEP_SUMMARY, their
     on-disk command files, or the legacy `::set-env`/`::add-path`/
     `::save-state`/`::set-output` commands is refused, save an append to
     GITHUB_OUTPUT/GITHUB_STEP_SUMMARY by its exact name; inside an expression
     the `github`/`env` contexts are read only through a literal `.name`
     that is not a command-file property (`github.env`, `github['env']`,
     `toJSON(github)` are refused); and `GITHUB_WORKSPACE` is only ever read,
     never assigned. Every `${{ }}` body is parsed by `gha_expr`'s typed
     grammar (a `}}` inside a string literal does not end it; a body outside
     the grammar is refused). A `shell:` (step or `defaults.run.shell`) is
     one of bash/pwsh/powershell, bare. In a step's `run:`, an expression
     holds no string literal and never abuts a shell variable name; no shell
     function or alias is defined; and pip is matched on quote-removed words
     (`shell_lex`). The integrity of `.github/ci/**` itself rests on an
     ordering rule: a step naming the tree is itself a closed pre-tool shape
     and runs only after steps of one (a content-pinned checkout or
     setup-python with a closed literal `with:` and no `env:`, the canonical
     pip install with no `env:`, a typed `ToolRun` of a file that exists
     under `.github/ci`, its words split only on bash's blanks
     `shell_lex.BLANKS`; any `timeout-minutes` a positive integer literal).
     The job is parsed once into a `ToolJob`: a literal GitHub-hosted Ubuntu
     runner (a fresh machine per job), job keys from one closed allowlist
     (`TOOL_JOB_KEYS`: no container, services, strategy, concurrency, or
     environment — save one keyed job's literal `ADMIN_ENVIRONMENT_JOBS`
     environment), every `env:` key at workflow, job, and tool-step scope
     drawn from one allowlist (`TOOL_ENV_ALLOWLIST`), and a masking key
     (`MASKING_KEYS`: `if:`, `continue-on-error:`) on a step or on the job
     only where every tool's `ToolRole` admits it (`ROLE_MASKING`): a
     verdict tool admits none, an advisory tool's step a literal
     `continue-on-error: true`, an output tool's terminal job an `if:`. A
     job whose tool admits no job masking (verdict, advisory) also admits no
     `needs:`, so no skipped ancestor can skip it. No `working-directory` anywhere names
     `.github`. A quote-removed scan refusing writes into the tree is
     defence in depth under that rule, not its proof. The ordering rule and
     that scan guard a checked-out tree, so neither's step half applies to a
     head-free workflow (`head_free`: one check 12a admits), whose workspace
     never holds a checkout (no `uses:` anywhere, no `git`) and whose every
     command is its own `run:` text; its tree-naming jobs are still held to
     the `ToolJob` job half as verdict jobs (no masking key, no `needs:`),
     and every other rule of this check still applies to them.
  8. Merge-queue safety: every producer of a `gate` context triggers on both
     `pull_request` and `merge_group`, else the queue waits forever on a
     required context no merge-group run reports.  A merge-group run gets the
     base repository's secrets and token, so every `merge_group`-triggered
     workflow must be secret-free (no `secrets` word in its raw text, nor in
     any key or string scalar once parsed, which decodes escapes), may also
     trigger on `pull_request_target` only when check 12 admits it, and must
     declare a top-level
     `permissions:` value with no `write` scope.  A job-level `write` scope is
     admitted only on a job whose `if:` has no `||` and has, among its
     `&&`-conjuncts at parenthesis depth 0, exactly
     `github.event_name == 'pull_request'`.  A bare
     `github.event_name != 'pull_request'` full-tier test (either operand
     order) must be followed by `&& github.event_name != 'merge_group'`, so a
     merge-group run takes the PR tier rather than silently running the full
     tier; the canonical `changes` phase outputs (`PHASE_OUTPUTS`), which
     check 11 pins exactly, are the one exemption.
     A workflow naming a repository-admin secret (`SCHEDULE_ONLY_SECRETS`)
     triggers on `schedule` alone, and names it only inside its keyed job
     (`ADMIN_ENVIRONMENT_JOBS`), which declares exactly its literal
     environment. No other job declares that environment, nor an environment
     whose name is not a literal string. Every workflow reads a secret only
     by one literal name — `secrets.NAME` or `secrets['NAME']`, parsed, so
     escapes are decoded — never by a computed index, `secrets.*`, the bare
     context, or a non-mapping `secrets:` block (`inherit`); text outside the
     expression grammar may not mention `secrets`. A name scan is therefore
     complete: no spelling reaches a secret it does not see. The guarantee
     is the environment's deployment-branch policy (`main` only), which
     GitHub enforces; these rules are defence in depth under it, since a
     same-repository branch that edits the workflow runs its edit before
     this check can refuse it.
     Limit: this catches honest mistakes, not a hostile PR.  A merge-group run
     executes the workflow files of the queued commit, so a queued PR that
     edits `.github/**` runs its own edit with the base secrets.  The boundary
     is who may enqueue: only write-access maintainers, who review every
     `.github/**` diff before enqueueing.
  9. No release-only skip-as-pass: GitHub reports a skipped job as a passing
     status, so a `gate` context may go green only through an executed step.
     A `gate` producer's job-level `if:` may name `release_only` only as one
     top-level `||` disjunct `needs.<job>.outputs.release_only == 'true'`
     (forcing the job to run on a release-please PR), and such a job's first
     step must be the trivial-pass step: `if:` exactly that disjunct, with a
     `run:`.  Any other mention (`!= 'true'`, a negation, an `&&`-conjunct,
     an unparseable expression) is refused, as is the release-only disjunct
     with no leading trivial-pass step (every step skipped also reports a
     pass).  GitHub resolves context properties case-insensitively, so the
     name is matched without case, and a job output that re-exports
     `release_only` (to any depth) counts as `release_only`.  A `gate`
     producer whose every step carries an `if:` is held to the same
     trivial-pass shape whatever the steps test, since its steps can all skip.
  10. Fast gate first: in ci.yml, every heavy test-shard job (a matrix job
      that downloads the `nextest-archive` artifact; `test-run` and `e2e` must
      be among them) `needs` every fast deterministic gate (FAST_GATES), and
      its `if:` calls no status function (`always()`, `failure()`,
      `cancelled()`) that would start it behind a red need.  Each fast gate is
      a single unexpanded ci.yml job, a manifest `gate`, and `needs` nothing
      but `changes`, so it stays fast.  A format, lint, lock or panic-scan red
      therefore never launches the heavy tier on any event or fork.
  11. CI phases (contributing guide, "CI phases"): in every
      `merge_group`-triggered workflow with a `changes` job, each job runs in
      exactly one phase.  `changes` runs on every event and publishes the
      phase outputs `cheap`, `tests`, `post_merge` spelled exactly as
      `PHASE_OUTPUTS`, generated from `PHASE_EXCLUDES` (the events each phase
      skips: cheap skips `push`, tests skips `pull_request` and `push`,
      post_merge skips `pull_request` and `merge_group`).  Every other job is
      unconditional (no `needs:`, no `if:`), a phase verdict, or a work job
      whose `if:` is one `&&`-conjunction holding exactly one phase marker
      (`needs.changes.outputs.<phase> == 'true'`, or `github.event_name ==
      'pull_request'` for a PR-only job), plus on a cheap job at most the
      `|| needs.changes.outputs.release_only == 'true'` disjunct; no other
      conjunct names the event.  A job needs only jobs that run on every event
      it runs on, and never a verdict.  A skipped required check reads as
      passing, so a tests or post_merge work job never reports a `gate`
      context: it reports through a phase verdict, a job whose `if:` is
      exactly `always()`, whose `needs:` are `changes` then each aggregated
      job once, whose first two steps are the pinned sparse checkout and
      `uses: ./.github/actions/phase-verdict` (unmasked: no step or job
      `continue-on-error:`, no `env:`), whose `results` lists one
      `job=${{ needs.job.result }}` pair per need in order, whose `tier` is
      its phase's output and `scope` one scope output, and each of whose
      aggregated jobs has `if:` exactly that phase and scope.  The composite
      fails unless `changes` succeeded and the tier agrees with the event,
      fails on any failed or cancelled need, and on an event of its phase in
      scope fails on any skipped need; it passes vacuously only off-phase or
      out of scope.  Every tests-phase work job is a direct need of a phase
      verdict whose context is a `gate`, so a merge-queue red always blocks
      the merge; a tests-phase proof that is not to block runs post_merge.
  12. Gate integrity.  (a) A `pull_request_target` run holds the base
      repository's token beside a PR author's input, so every workflow
      triggering on it must provably run no head code: no `uses:` at step or
      job level (no checkout, no action at all), no `git`, no `gh` other
      than `gh api`, no `secrets` word, no word naming the PR head (`head`,
      `merge_commit_sha`, `refs/pull/`; any letter case, in the raw text, in
      any parsed key or scalar, or in its shell commands' quote-removed
      words, so `g""it` is `git`), no `${{ }}` expression other than
      `github.token`, and a top-level `permissions:` value with no `write`
      scope at the top or on any job.  A workflow (a) admits is head-free
      (`head_free`, the one predicate checks 7 and 8 read): its workspace
      never holds a checkout, so check 7's step ordering and write scan do
      not apply to it.  (b) `.github/CODEOWNERS` is the trust-root SSOT: it
      must parse under `trust_roots.py`'s accepted subset, every rule must
      match at least one tracked file, the trust-root machinery
      (`CODEOWNERS`, `trust_roots.py`, this verifier, `trust-root-diff.yml`)
      and every tracked file under `.github/` (workflows, actions, and the
      helpers the verifiers import) must be a trust root, every tracked
      script a workflow or local action names by path must be a trust root,
      and no second CODEOWNERS file may exist at the root or in `docs/`.  A
      workflow whose `on:` has no recognised shape but names
      `pull_request_target` is refused by (a).
      Limit: (a) is a text audit that catches honest mistakes (a fetch of
      head content spelled without a head word, such as a `curl` of a URL
      assembled at run time, is not seen, and check 7's head-free exemption
      rests on the same audit); a hostile edit to a workflow is a
      `.github/**` change, which (b) makes code-owned.
  13. Push and merge-group concurrency: GitHub keeps at most one queued run
      per concurrency group and replaces it when a newer run joins, whatever
      `cancel-in-progress` says, so a group two pushes to one branch share
      lets a newer commit discard an older one's run before it starts.  Every
      push-triggered workflow's workflow- and job-level `group` is evaluated
      for two pushes to the same branch (distinct `github.sha` and
      `github.run_id`) and must differ.  Every merge_group-triggered
      workflow's sites are evaluated for three merge-group runs (two on one
      queue ref with distinct `github.sha`/`github.run_id`, one on another
      ref; `github.head_ref`/`github.base_ref` unresolvable): the two refs'
      groups must differ, else the queue serializes; and a group the same-ref
      runs share must carry a `cancel-in-progress` (a YAML boolean or exactly
      one expression; absent is false) truthy under merge_group, else a
      re-queued run waits behind its stale one.  The evaluator reads string, boolean
      and null literals and a closed set of `github` properties with `==`,
      `!=`, `&&`, `||` and `!`; any other context, function, number literal
      or mixed-type comparison is refused.  `LATEST_WINS_PUSH_GROUPS` names the workflows whose run acts on the
      branch head it reads at run time, each with its reason, and every entry
      must be a push-triggered workflow.
  14. One lock per dependency graph: a tracked `Cargo.lock` other than the
      root one may resolve no path package (a workspace member or a path
      dependency) the root `Cargo.lock` also resolves, since two locks over
      one graph drift apart the first time an update rewrites only one of
      them.  Every Dependabot `cargo` directory is a literal path (no glob)
      holding a tracked `Cargo.lock` that passes that rule, and `/` is one of
      them, so every update lands in the lock that governs the graph.
  15. One `ipe` build: in ci.yml only `IPE_BUILD_PRODUCER` compiles the `ipe`
      package.  Every cargo command a job runs (its `run:` steps and those of
      each local composite action it `uses`) is read by
      `cargo_invocation`: its directory follows `working-directory`, job and
      workflow `defaults`, `cd`, subshells and `-C`; its selection is
      `-p`/`--package`, `--bin`, `--manifest-path`, `--workspace`/`--all`, or
      the package the directory holds (the virtual root, which has no
      `default-members`, selects every member).  A
      `build`/`run`/`rustc`/`install` selecting `ipe` in any other job is
      refused, as is a command this check cannot read (an unknown flag or
      subcommand, a package glob, `cargo` under an unread wrapper).  The
      producer must build it and upload `IPE_BUILD_ARTIFACTS`; a job that
      downloads one of them must list the producer in its own `needs:`.
      LIMIT: after a `cd` to a run-time path (a variable, `cd -`), or in a
      directory the checkout does not hold whose `Cargo.toml` its ignore
      rules reserve for build output (an emitted crate), the manifest is not
      known statically, so a command there that selects nothing by name is
      not attributed.
  16. Path-scoped coverage: a job whose `if:` reads a narrow
      `needs.changes.outputs.<scope>` (a `change_class.SCOPES` scope other
      than `code`) may skip on a PR only where that skip is proven harmless.
      Every package its cargo commands select (read as in check 15: by name,
      or by the member directory the command runs in or names) is closed
      over its path dependencies in the root `Cargo.lock` (dev ones
      included), and every tracked file under those crates' directories —
      plus every existing path a `../` string literal in them reaches — must
      force one of the job's scopes.  A scoped job that selects the whole
      workspace, selects by `--bin` alone, or runs a command or package spec
      this check cannot resolve, is refused.  Both `.yml` and `.yaml`
      workflows are read.  LIMIT: a path built at run time (a bare `"../.."`
      ancestor joined to a computed name, or no `../` literal at all), and a
      cargo command after a `cd` to a run-time path, are not seen.
  17. Drift checks see new files: no `run:` of a workflow (`.yml` or
      `.yaml`) or of a local composite action, and no manifest `local:`
      command, asserts regenerated output with a
      `git diff`/`diff-index`/`diff-files` carrying `--exit-code` or
      `--quiet`, which is blind to a file the generator writes that git does
      not track yet; `tools/scripts/generated-unchanged.sh` (tracked changes
      plus untracked files) is the one drift assertion.  Both spellings are
      read by `drift_assertion.parse`, the parser the PROSE guard shares.
      LIMIT: a `git diff` reached through an alias or a script is not seen.
  18. Dependabot PR budget: every `updates` entry declares its own integer
      `open-pull-requests-limit` of at least 1 (Dependabot's implicit
      default is 5, and 0 silently disables the ecosystem), and the limits
      summed over every entry's directories stay within
      `DEPENDABOT_OPEN_PR_BUDGET`, so update PRs cannot crowd the open-PR
      budget the merge queue is sized for.  LIMIT: security-update PRs obey
      Dependabot's own fixed ceiling, not this key, and are not bounded here.
  19. Workspace inheritance: every root `[workspace] members` entry (a
      literal path, no glob) sets `edition.workspace = true` and a `[lints]`
      table of only `workspace = true`, so the root edition and clippy policy
      govern it.  `WORKSPACE_INHERIT_EXEMPT` names the members that keep
      their own, each with its reason; an exempt member's literal edition
      must equal the workspace edition and it must carry its own `[lints]`
      table, and an entry that is no member or inherits anyway is refused.
  20. Every non-host test cell is run by the job that claims it: each cell of
      `ci/test-claims.yml` (read by `claims_table.load_cells`) is claimed by
      exactly one workflow step, in its `owner` job, read once into a
      `ClaimRun`.  The step's whole `run:` is `cargo test … | python3
      tools/scripts/wasm-test/wasm_test_count.py N`, with no workflow
      expression, `N` the cell's `expect_tests`, every word a
      `shell_lex.LiteralWord` (no parameter expansion, glob, brace or tilde
      expansion, quote or backslash, so the argv is the words as written),
      and a bare `cargo` (no env assignment, wrapper, path or `+toolchain`)
      passing no `--`, `--config`, `-C`, `-Z` or `--manifest-path`.  The cargo side tests the
      cell: the platform as `--target`, the package by one `-p` (no
      `--workspace`), only `--lib` or only `--test <name>`, the cell's
      features, no filter and no `--no-run`.  The step runs under `shell:
      bash` (so `pipefail` holds), with no `continue-on-error` on it or its
      job, no `working-directory` on it and no `defaults.run` one on its job
      or workflow, no `container:` on its job (whose image env this check
      cannot read), and no `if:` beyond the release-only guard.  Its
      effective env (workflow, then job, then step `env:`, each a literal
      mapping) sets the platform's runner key to the runner, and otherwise
      only the `_CLAIM_ENV` keys at their admitted values — so no
      `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, per-target rustflags,
      `CARGO_HOME` or other key can add a `--cfg` that swaps a test at an
      equal count.  The checkout's `.cargo/config.toml` holds only the
      `_CLAIM_CONFIG_*` tables and keys, and every rustflags of its
      `[build]` and of a `[target]` table applying to the platform passes
      only cfg-neutral `-C` codegen options; a legacy `.cargo/config` is
      refused.  The owner job installs the runner through
      `taiki-e/install-action` at the `Cargo.lock` version before the claim
      step; every `wasm-bindgen` tool pin in any workflow names that
      version, and no step `cargo install`s the runner.  A count piped from
      a command that tests no cell is refused.  The owner job's context is a
      required `gate` or a `nightly-gate` of the manifest, produced by that
      workflow.  Any other cargo test run on a wasm32 `--target` in any job
      is refused as unclaimed.  LIMIT: a target set through
      `CARGO_BUILD_TARGET` rather than `--target` is not seen as a run; a
      cargo config above the checkout or under `$CARGO_HOME`, a `Cargo.toml`
      `[profile]`/`[patch]`, and a config or env an earlier step or action
      writes (`GITHUB_ENV`) are not read;
      `src/runtime/rust/tests/wasm_cell_scan.rs` proves the tree declares no
      test outside the claimed cells.
  21. Every CI-tooling refusal suite runs in a required job: each
      `.github/ci/test_*.py` is the whole `run:` of a step, exactly
      `python3 .github/ci/<suite>` (optionally `-v`), in a job reporting a
      `gate` context of its own producer workflow.  The job carries no
      `if:` (a skipped required check reads as passing), and neither it
      nor the step carries `continue-on-error`; the step carries no `if:`
      and no `working-directory`.  A suite no required job runs is refused,
      so a refusal test cannot exist yet be advisory.  LIMIT: a suite
      outside `.github/ci/` is not inventoried.
  22. Every cargo feature is compiled by a required job: each `[features]`
      key of every workspace member is switched on by a cargo command of a
      required `ci.yml` job (one a `gate` entry produced by it names or
      aggregates; not behind a literal-false job `if:` or a job
      `continue-on-error`) in a step with no `if:` and no
      `continue-on-error`, at every local-action depth: check 11 governs job
      conditions only, and a step `if:` can skip the step while the job
      succeeds —
      through `--features`/`-F` (plain or `pkg/feat`), `--all-features`, a
      default feature, a feature another feature lists, or a
      `features = [..]` edge from a compiled member (a dev-dependency edge
      only when its crate's test targets are compiled; an optional edge
      never).  A misspelled `--features` value switches nothing on, so its
      feature stays uncovered and is refused; a command that names features
      and cannot be read is refused.  `FEATURE_COVERAGE_EXEMPT` names the
      members whose matrix another job owns (the runtime crate:
      `runtime-feature-combos`), with a refusal for a stale entry.  LIMIT: a
      `--workspace --exclude` run is not counted; `cfg(all(feature=a,
      not(feature=b)))` combinations are not enumerated.
  23. Release-target parity: ci.yml's `release-targets-run` and
      `release-targets-freebsd` check exactly what release.yml's `build` and
      `build-freebsd` build, and each of the four jobs is an allowlist, not
      a scan.  The `(os, target)` pairs of the two matrices are equal (a
      target missing from either side, or on another `os`, is refused); each
      matrix leg holds exactly its keys (`os`, `target`, plus release.yml's
      `artifact` and `ext`), every value a literal string of the runner-label
      and target-triple grammar (`ext` empty or `.exe`).  A native job's
      first three steps are exactly: its checkout (commit-pinned; on
      release.yml's side `with: ref: ${{ needs.resolve-tag.outputs.tag }}`
      and nothing else, in a job that needs `resolve-tag`); `uses:
      ./.github/actions/release-target-toolchain` with `target: ${{
      matrix.target }}`; and a `shell: bash` step whose `env` is exactly
      `TARGET: ${{ matrix.target }}` and whose `run` is exactly the one
      cargo line, `cargo <verb> --release --locked --features ipe/wasi_run
      --target "$TARGET" -p ipe -p ipe-ffi-inspector` (`check` in ci.yml,
      `build` in release.yml).  A FreeBSD job's first two steps are exactly
      its checkout and the FreeBSD VM step (`usesh: true`, `prepare: pkg
      install -y rust`), whose `run` is exactly the cargo line without
      `--target` in ci.yml and opens with it in release.yml.  ci.yml's jobs
      run nothing else.  Each pinned step is compared key for key both ways,
      typed (`1` is not `true`, nor `'1'`), a `name` that is a literal string
      the one key set aside; the shared loader refuses a plain scalar YAML
      1.1 and 1.2 read differently (`yes`, `0x2`, `010`).  Both local
      actions the shared step runs, it and `rust-toolchain-pinned`, are
      pinned the same way: their inputs (descriptions aside) and their steps
      (names aside) are exactly the toolchain channel read from
      `rust-toolchain.toml`, the commit-pinned `dtolnay/rust-toolchain`,
      `rustc --version`, the commit-pinned `Swatinem/rust-cache`, and the
      musl install on a musl target; nothing else runs before a cargo
      command.  The job keys are only `name`, `needs`, `if`,
      `timeout-minutes`, `strategy` (native jobs only, a boolean `fail-fast`
      and an `include` list) and `steps`, `runs-on` exactly `${{ matrix.os
      }}` or `ubuntu-latest`; the workflow keys are only `name`, `run-name`,
      `on`, `permissions`, `concurrency`, `jobs` and `env`, and each
      workflow's `env` is exactly its entries in the closed, value-pinned
      `ALLOWED_ENV_DIFFERENCES`, each named with its why.  The program a step
      runs is never read, so no spelling (a glob, an alias, a function, a
      `PATH` edit, a download) can reach the region: only the pinned text
      can.  After release.yml's cargo command, as defence in depth: the first
      step is each job's only checkout (`uses:` read with owner and repo
      case-folded, as GitHub reads them, in the job and its local actions
      alike), every `run` step names `shell: bash`, and a `cargo` or `rustc`
      word (as written, continuations joined, or as the shell reads it:
      `c""argo`, an `sh -c` body, `cargo-zigbuild`) is refused.
      release.yml's completeness `expected` list is exactly the artifacts
      its jobs publish.  Both release builds carry `--features
      ipe/wasi_run`, so the shipped `ipe` has the embedded WASI run its
      refusal text promises.
      LIMIT: `cargo check` does not link, so a link-time failure of a target
      is not seen; the FreeBSD toolchain is the VM's unpinned `pkg install
      rust`.  LIMIT: the internals of the third-party actions (checkout,
      rust-cache, the toolchain and VM actions) are not read: what they run,
      write to `$GITHUB_ENV`/`$GITHUB_PATH` or restore, and whether the VM
      shell stops on the cargo line's failure; rust-cache's `save-if` reads
      `github.ref`, so the cache a run restores depends on the event; a build
      script or proc-macro reading the environment or the runner is not
      proven absent.  LIMIT: steps after the cargo step (packaging, release
      VM lines after the cargo line) are unverified beyond the scans above
      and can replace or rebuild the shipped artifact (`curl -o dist/ipe`, a
      script, a compiler named at run time).  LIMIT: a job in release.yml
      outside the pinned set, or the publish job, can upload or replace an
      artifact under a shipped name.  LIMIT: a release run takes the local
      actions from the tag's checked-out tree, so a tag off main carries
      composite text that CI never verified.
  LIMIT (checks 15, 16, 20, 22): a cargo line is read as run, not proven
  to reach its step's exit status — `cargo .. || true`, an `exit 0` before
  it, `set +e`, `if ! cargo ..` or a pipeline without `pipefail` are not
  modelled — nor proven to run the toolchain's cargo — an earlier step's
  `$GITHUB_PATH` or `$GITHUB_ENV` write, a `cargo` shell function or alias,
  or a `shell:` that is not a shell.  Check 23 pins its cargo lines and
  every step before them instead (the one-line bash step stops on cargo's
  failure); its residue is the third-party LIMIT above.

Pure stdlib + PyYAML (already a CI dependency).  No network; check 12 runs
`git ls-files` locally to list tracked paths.
"""

from __future__ import annotations

import argparse
import fnmatch
import glob
import json
import os
import enum
import posixpath
import re
import subprocess
import sys
from dataclasses import dataclass, replace

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11; CI runs 3.11+
    import tomli as tomllib  # type: ignore[no-redef]

try:
    import yaml
except ImportError:  # pragma: no cover - CI always has PyYAML
    print("verify-manifest: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import strict_yaml  # noqa: E402  # the shared strict loader, SSOT for every YAML load below
import gha_expr  # noqa: E402  # the one GitHub Actions expression parser
import shell_lex  # noqa: E402  # the one quote-removing shell lexer
import change_class  # noqa: E402  # the path-scope classifier, SSOT for every scope's patterns
import trust_roots  # noqa: E402  # the CODEOWNERS trust-root parser, shared with trust-root-diff.yml
import drift_assertion  # noqa: E402  # the one drift-assertion parser, shared with change_class
import cargo_invocation  # noqa: E402  # the one cargo-invocation reader, checks 15 and 16
import check_required_set  # noqa: E402  # owns the admin-read environment's name
import claims_table  # noqa: E402  # the one reader of test-claims.yml, check 20

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Both extensions: a workflow (or, for check 6, a local composite action) is a
# workflow whichever suffix its YAML uses — a `*.yml`-only glob silently drops
# a `*.yaml` file from every check below it feeds.
WORKFLOW_GLOBS = (
    os.path.join(REPO_ROOT, "workflows", "*.yml"),
    os.path.join(REPO_ROOT, "workflows", "*.yaml"),
)
MANIFEST = os.path.join(REPO_ROOT, "ci", "check-manifest.yml")
DETERMINISTIC_CHECKS_FILE = os.path.join(REPO_ROOT, "ci", "deterministic-checks.json")
CANCEL_WATCHER_WORKFLOW = "ci.yml"
# Check 10: the fast deterministic gates every heavy test shard waits on, and
# the shard jobs the heavy-shard derivation must find.
FAST_GATE_WORKFLOW = "ci.yml"
FAST_GATES = ("fmt", "clippy", "manifest-lock-consistency", "panic-scan")
FAST_GATE_NEEDS_ALLOWED = frozenset({"changes"})
HEAVY_SHARD_ANCHORS = ("test-run", "e2e")
HEAVY_SHARD_ARTIFACT = "nextest-archive"
_STATUS_FN = re.compile(r"\b(always|failure|cancelled)\s*\(", re.IGNORECASE)
CANCEL_WATCHER_JOB_ID = "cancel-on-cheap-red"

# The dependency cache is written from `main` only: a pull request run
# restores it and never evicts it with a branch-local save.
RUST_CACHE_REPO = "Swatinem/rust-cache"
RUST_CACHE_SAVE_IF = "${{ github.ref == 'refs/heads/main' }}"
# mold is installed only by the local composite, which pins the release digest.
RAW_MOLD_ACTION_REPO = "rui314/setup-mold"
MOLD_COMPOSITE_USES = "./.github/actions/mold"
# The mold composite's one `run:` must verify the digest before it installs:
# every `case` arm pins a 64-hex digest (or refuses the arch), and the
# `sha256sum --check --strict` line precedes every `tar`/`ln` line.
MOLD_DIGEST_ARM_RE = re.compile(r"[a-z0-9_]+\)\s*digest=[0-9a-f]{64}\s*;;")
MOLD_VERIFY_LINE = "sha256sum --check --strict"
# `tar`/`ln` in command position: line start, after `sudo`, or after `|;&(`.
MOLD_INSTALL_WORD_RE = re.compile(r"(?:^|[|;&(]\s*|(?<![A-Za-z0-9_-])sudo\s+)(?:tar|ln)(?=\s)")
# `owner/repo` of a remote `uses:` — the repo segment ends at `@` (a ref) or
# `/` (a subpath), so `owner/repo/sub@ref` names the same action as
# `owner/repo@ref`.
USES_REPO_RE = re.compile(r"([^/@]+/[^/@]+)(?=[/@])")


def uses_action(uses: object, owner_repo: str) -> bool:
    """Whether a `uses:` value runs the remote action `owner_repo`, at any ref
    or subpath. GitHub reads owner and repo case-insensitively, so
    `Actions/Checkout@v4` is `actions/checkout`: every recogniser of a remote
    action goes through this one comparison."""
    if not isinstance(uses, str):
        return False
    m = USES_REPO_RE.match(uses.casefold())
    return m is not None and m[1] == owner_repo.casefold()
# No job wraps or replaces rustc. SSOT: every env-var name that hands rustc a
# wrapper.
RUSTC_WRAPPER_VAR = "RUSTC_WRAPPER"
RUSTC_WRAPPER_KEY_NAMES = (
    RUSTC_WRAPPER_VAR,
    "CARGO_BUILD_RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
)
# SSOT: every env-var name that replaces rustc itself.
RUSTC_REPLACING_KEY_NAMES = ("RUSTC", "CARGO_BUILD_RUSTC")
RUSTC_WIRING_ENV_KEYS = frozenset(k.casefold() for k in RUSTC_WRAPPER_KEY_NAMES + RUSTC_REPLACING_KEY_NAMES)
# Loose refusal predicate over free text (`run:`, `shell:`, `defaults.run.
# shell`, `with:` and `env:` values): any wrapper key above; cargo's own
# `rustc-wrapper`/`rustc-workspace-wrapper` config spelling (`cargo --config
# build.rustc-wrapper=...`, a written `.cargo/config.toml`); a rustc-replacing
# key (`CARGO_BUILD_RUSTC` in any case, `RUSTC` as an upper-case word, `rustc`
# in any case and after any character — a printf `\n` escape included —
# directly followed by `=` or `:`). No `$GITHUB_ENV` is required — an inline
# `KEY=v cmd`, an `export`, a `shell: env KEY=v bash {0}`, or an `env:` value a
# `run:` later expands into a write wires rustc just as well. Over-strict by
# design: a refused false positive is cheap, a missed wiring is not.
RUSTC_WIRING_TEXT_RE = re.compile(
    "(?:" + "|".join(re.escape(k) for k in RUSTC_WRAPPER_KEY_NAMES) + ")"
    + r"|rustc[-_](?:workspace[-_])?wrapper"
    + r"|CARGO_BUILD_RUSTC"
    + r"|(?-i:(?<![A-Za-z0-9_])RUSTC(?![A-Za-z0-9_]))"
    + r"|rustc\s*[=:]",
    re.IGNORECASE,
)
# Check 7 — a third-party input is identified by content, never by a movable
# name: an action by its full commit SHA (a tag or branch can be re-pointed
# upstream), a docker image by its sha256 digest.
PINNED_REMOTE_USES_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}\Z")
PINNED_DOCKER_USES_RE = re.compile(r"docker://[^\s@]+@sha256:[0-9a-f]{64}\Z")
PINNED_IMAGE_RE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}\Z")
# Every spelling of a runner file-command target: the variables naming the
# env/path/state/output/summary files (`$VAR`, `${VAR}`, `env.VAR`,
# `$env:VAR`, a bare key — any substring, so a suffix never hides one), the
# runner's on-disk command files they point at, and the legacy stdout workflow
# commands (plus the switch that re-enables them). Any letter case: Windows env
# names fold. The `github` context spellings are matched separately, inside
# expressions only (`GITHUB_NAMED_CONTEXTS`).
RUNNER_FILE_TEXT_RE = re.compile(
    r"GITHUB_(?:ENV|PATH|STATE|OUTPUT|STEP_SUMMARY)"
    r"|_runner_file|set_env_|add_path_|save_state_|set_output_|step_summary_"
    r"|ACTIONS_ALLOW_UNSECURE_COMMANDS|::\s*(?:set-env|add-path|save-state|set-output)",
    re.IGNORECASE,
)
# The one sanctioned use of an output/summary file: appending to it by its exact
# upper-case name (bash `>> "$VAR"`/`>> "${VAR}"`/`>> $VAR`, pwsh `Out-File
# -FilePath $env:VAR`). Anything else naming it — an assignment, a parameter
# expansion that rewrites it (`${GITHUB_OUTPUT/output/env}`), an env key — is
# refused like the env/path files, so no alias can repoint it at them.
RUNNER_APPEND_ONLY_TARGET_RE = re.compile(
    r'>>\s*"\$(?P<q>GITHUB_(?:OUTPUT|STEP_SUMMARY))"'
    r'|>>\s*"\$\{(?P<b>GITHUB_(?:OUTPUT|STEP_SUMMARY))\}"'
    r"|>>\s*\$(?P<u>GITHUB_(?:OUTPUT|STEP_SUMMARY))(?=[\s;&|)]|\Z)"
    r"|-FilePath\s+\$env:(?P<p>GITHUB_(?:OUTPUT|STEP_SUMMARY))(?=[\s;|)]|\Z)"
)
# Inside a GitHub Actions expression (parsed by `gha_expr`, never scanned as
# text) the `github` and `env` contexts may only be read through a literal
# `.name`; the `github` properties naming runner command files are refused. A
# bracket index (`github['env']`), a `.*` filter, or the whole context
# (`toJSON(github)`) could reach those files under an assembled name, so each
# is refused too.
GITHUB_NAMED_CONTEXTS = frozenset({"github", "env"})
GITHUB_RUNNER_FILE_PROPS = frozenset({"env", "path", "state", "output", "step_summary"})
# The action whose `with.script` is JavaScript source the runner assembles
# from `${{ }}` expansion before it runs, a shell-text position like `run:`.
GITHUB_SCRIPT_REPO = "actions/github-script"
# Action inputs, by case-folded name and for every action, that hold a script
# the action hands to an interpreter (`vmactions/*-vm`'s `run`/`prepare` run
# under `sh` in the guest; `script`, `command`, `entrypoint`, `args` are the
# names other actions give the same role). A `${{ }}` in one is a shell-text
# splice, as in a `run:`.
ACTION_SHELL_INPUTS = frozenset(
    {"run", "prepare", "script", "command", "commands", "cmd", "shell", "entrypoint", "args"}
)
# The words that re-parse their arguments as shell syntax: bash `eval`, pwsh
# `Invoke-Expression` and its alias `iex` (case-folded).
EVAL_WORDS = frozenset({"eval", "invoke-expression", "iex"})
# `GITHUB_WORKSPACE` roots the helper and requirements paths, so it may only be
# read (`$GITHUB_WORKSPACE`, `${GITHUB_WORKSPACE}`, exact case), never assigned,
# defaulted (`${GITHUB_WORKSPACE:=x}`), exported, or set as an env key.
GITHUB_WORKSPACE_MENTION_RE = re.compile(r"GITHUB_WORKSPACE", re.IGNORECASE)
GITHUB_WORKSPACE_READ_RE = re.compile(
    r"\$(?:GITHUB_WORKSPACE(?![A-Za-z0-9_])|\{GITHUB_WORKSPACE\})(?!\s*=)"
)
GITHUB_ENV_HELPER = "ci/github-env.sh"
# Positive shape of a key the helper may write: a job-local name that cannot
# collide with any runner, toolchain, loader, or interpreter variable.
GITHUB_ENV_KEY_RE = re.compile(r"CI_JOB_[A-Z0-9_]+\Z")
GITHUB_ENV_HELPER_MENTION_RE = re.compile(r"github[-_]env", re.IGNORECASE)
# The one canonical call: absolute helper path (a step may have `cd`'d), then a
# bare literal key — never a variable, a quoted or concatenated word.
GITHUB_ENV_HELPER_CALL_RE = re.compile(
    r'(?<![^\s;&|(])bash "\$GITHUB_WORKSPACE/\.github/ci/github-env\.sh" '
    r"(?P<key>[A-Z][A-Z0-9_]*) (?=\S)"
)
GITHUB_ENV_KEY_EXACT_REFUSED = frozenset(
    {"PATH", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "IFS", "HOME", "TMPDIR", "PS4"}
)
# Prefixes whose variables steer the runner, a toolchain, a loader, or an
# interpreter of every later step; none is ever a job-local value.
GITHUB_ENV_KEY_REFUSED_PREFIXES = (
    "GITHUB_", "RUNNER_", "ACTIONS_", "INPUT_", "STATE_", "CARGO", "RUST", "LD_",
    "DYLD_", "NODE_", "NPM_", "PYTHON", "PIP_", "PERL", "RUBY", "JAVA_", "GIT_",
    "BASH_", "SSL_", "CURL_", "HTTP", "HTTPS_", "NO_PROXY", "ALL_PROXY",
)
# `pip` runs only as the one canonical hash-checked install (or a read-only
# query). `PIP_CONFIG_FILE=/dev/null` stops pip reading any config file and
# `--isolated` stops it reading `PIP_*` environment variables, so no earlier
# step, `env:` key, or config write can add an index, a requirement, or a
# `no-binary` to it.
PIP_REQUIREMENTS_ARG = "$GITHUB_WORKSPACE/.github/ci/requirements.txt"
CANONICAL_PIP_INSTALL = (
    "PIP_CONFIG_FILE=/dev/null python3 -m pip install --isolated --require-hashes "
    f'--only-binary :all: -r "{PIP_REQUIREMENTS_ARG}"'
)
CANONICAL_PIP_INSTALL_RE = re.compile(
    r"(?<![^\s;&|(])" + re.escape(CANONICAL_PIP_INSTALL) + r"(?![^\s;&|)])"
)
PIP_MENTION_RE = re.compile(r"(?:(?<![A-Za-z0-9_])|(?<=-m))pip[0-9.]*(?![A-Za-z0-9_-])", re.IGNORECASE)
PIP_TOKEN_RE = re.compile(r"(?:.*[/\\])?(?:-m)?pip[0-9.]*(?:\.exe)?", re.IGNORECASE)
PIP_READ_ONLY_COMMANDS = frozenset({"--version", "-V", "list", "show", "freeze", "check", "help", "--help", "-h"})
# pip's environment and config-file inputs: any `PIP_*` name (text or key) and
# any pip config file are refused outside the canonical install's own prefix.
PIP_ENV_NAME_RE = re.compile(r"(?<![A-Za-z0-9_])PIP_[A-Za-z0-9_]*", re.IGNORECASE)
PIP_CONFIG_FILE_RE = re.compile(r"pip\.(?:conf|ini)", re.IGNORECASE)
# Installers outside pip's hash checking.
UNHASHED_INSTALLER_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:pipx|easy_install|uvx)(?![A-Za-z0-9_-])"
    r"|(?<![A-Za-z0-9_-])uv\s+(?:pip|tool)(?![A-Za-z0-9_-])"
    r"|setup\.py\s+(?:install|develop)(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
# `.github/ci/**` holds the verifier, its helper, and the hashed requirements:
# a `run:` may execute or read it, never write it. A word naming it is
# accepted only as the command itself or as an argument to a read/execute
# command; a redirect into it, or any other command naming it, is refused.
PROTECTED_TREE = ".github/ci"
PROTECTED_TREE_READERS = frozenset({
    "python3", "python", "bash", "sh", "cat", "ls", "test", "[", "[[", "diff", "cmp",
    "sha256sum", "sha512sum", "head", "tail", "rg", "grep", "jq", "source", ".",
    "wc", "stat", "echo", "printf", "shellcheck", "file",
})
SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
# A shell's own argv, as a closed set: single-letter options (`-euxvc`,
# clustered; each `o` takes a named option), and the startup-file opt-outs.
# Anything else (`-s`, `-i`, `-l`, `--rcfile`, ...) changes where its
# commands come from and is refused.
SHELL_LETTER_FLAG_RE = re.compile(r"[-+][euxvco]+")
SHELL_O_OPTIONS = frozenset({"pipefail", "errexit", "nounset", "xtrace"})
SHELL_LONG_FLAGS = frozenset({"--noprofile", "--norc"})
# The one sanctioned pipe into a shell: `cat <file> | sh`, a literal file
# outside the protected tree (the documented `curl ... | sh` delivery).
PIPE_TO_SHELL_SOURCE = "cat"
SHELL_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
# The step `shell:` (and `defaults.run.shell`) a check can read, as a closed
# set of names: a template (`bash -c '...{0}'`), another interpreter
# (`python {0}`), or `sh` is refused, since the text a step's `run:` becomes
# is then no longer the text these checks lex.
STEP_SHELLS = frozenset({"bash", "pwsh", "powershell"})


@dataclass(frozen=True)
class WrapperSpec:
    """How a command wrapper's argv reaches the command it runs: flags taking
    no argument, flags taking the next word (or `--flag=value`), a count of
    leading operands (`timeout`'s DURATION), whether `NAME=value` words are
    assignments, and whether `-<digits>` is a flag. A flag outside these is
    refused — the wrapped command cannot then be established."""

    bare: frozenset[str] = frozenset()
    valued: frozenset[str] = frozenset()
    operands: int = 0
    assignments: bool = False
    numeric_flag: bool = False


COMMAND_WRAPPERS: dict[str, WrapperSpec] = {
    "env": WrapperSpec(
        bare=frozenset({"-i", "-0", "--ignore-environment", "--null", "-"}),
        valued=frozenset({"-u", "--unset", "-C", "--chdir"}),
        assignments=True,
    ),
    "exec": WrapperSpec(bare=frozenset({"-c", "-l"}), valued=frozenset({"-a"})),
    "sudo": WrapperSpec(
        bare=frozenset({"-E", "-n", "-H", "--preserve-env", "--non-interactive"}),
        valued=frozenset({"-u", "-g", "--user", "--group"}),
    ),
    "nice": WrapperSpec(valued=frozenset({"-n", "--adjustment"}), numeric_flag=True),
    "timeout": WrapperSpec(
        bare=frozenset({"--preserve-status", "--foreground", "-v", "--verbose"}),
        valued=frozenset({"-s", "--signal", "-k", "--kill-after"}),
        operands=1,
    ),
    "command": WrapperSpec(bare=frozenset({"-p", "-v", "-V"})),
    "builtin": WrapperSpec(),
    "nohup": WrapperSpec(),
    "time": WrapperSpec(bare=frozenset({"-p"})),
    "xargs": WrapperSpec(
        bare=frozenset({"-0", "-r", "-t", "-x", "--null", "--no-run-if-empty", "--verbose"}),
        valued=frozenset({
            "-n", "-I", "-P", "-d", "-L", "-s", "-E", "-a", "--max-args", "--max-procs",
            "--delimiter", "--arg-file",
        }),
    ),
}
# `xargs` hands its command arguments no check ever sees, so it may run only
# a command that cannot write whatever those arguments name.
XARGS_READERS = frozenset({
    "cat", "ls", "test", "diff", "cmp", "sha256sum", "sha512sum", "head", "tail",
    "wc", "stat", "echo", "printf", "file",
})
# Brace expansion is expanded before a word is judged; a word expanding to
# more alternatives than this is taken to name the protected tree.
BRACE_ALTERNATIVES_LIMIT = 256
# A shell function or alias can shadow any command a check matched by name
# (`bash() { ...; }` before the helper call), so neither is written in a `run:`.
SHELL_SHADOWING_RE = re.compile(
    r"(?<![\w$.:-])[A-Za-z_][\w.:-]*[ \t]*\([ \t]*\)[ \t]*(?:[{(]|\n|\Z)"
    r"|(?<![\w-])function[ \t]+[A-Za-z_]"
    r"|(?<![\w-])(?:alias|unalias)(?![\w-])"
    r"|expand_aliases",
)
# Legacy workflow commands the runner reads from the output the shell prints,
# so matched after quote removal too (`::set-""env`).
LEGACY_COMMAND_RE = re.compile(r"::\s*(?:set-env|add-path|save-state|set-output)", re.IGNORECASE)
# Bound on YAML nesting walked for string scalars; deeper is refused.
STRING_SCALAR_DEPTH_LIMIT = 64

# Bound on local-action nesting (a composite whose steps use another local
# action); a chain deeper than this is refused, never assumed closed.
LOCAL_ACTION_DEPTH_LIMIT = 4


VALID_DISPOSITIONS = {"gate", "gate-external", "nightly-gate", "informational", "delete"}
# Workflows whose jobs are release/automation plumbing, never PR/promotion
# status gates — excluded from the "produced context" set so the drift gate does
# not demand a disposition for a release upload job.
PLUMBING_WORKFLOWS = {
    "release.yml",
    "release-please.yml",
    "rerun-failed-once.yml",
    "nightly-full-gate.yml",
    "ci-health.yml",
}


def expand_matrix_names(name: str, strategy: dict) -> list[str]:
    """Expand a job `name:` containing ${{ matrix.KEY }} over its matrix values.

    Only the simple `matrix: {KEY: [a, b, ...]}` form is expanded (that covers
    every matrix in this repo).  A name with no matrix ref returns [name]; an
    unexpandable ref falls back to a regex-friendly wildcard match later.
    """
    refs = re.findall(r"\$\{\{\s*matrix\.([a-zA-Z0-9_]+)\s*\}\}", name)
    if not refs:
        return [name]
    matrix = (strategy or {}).get("matrix") or {}
    result = [name]
    for key in refs:
        values = matrix.get(key)
        if not isinstance(values, list):
            return [name]  # cannot expand; keep the templated form
        expanded = []
        for base in result:
            for v in values:
                expanded.append(base.replace("${{ matrix.%s }}" % key, str(v)))
                expanded.append(
                    base.replace("${{ matrix.%s }}" % key.strip(), str(v))
                )
        # de-dup while preserving order
        seen = set()
        result = [x for x in expanded if not (x in seen or seen.add(x))]
    return result


class Job:
    """One workflow job: its status contexts and direct `needs`."""

    def __init__(self, workflow: str, job_id: str, contexts: list[str], needs: list[str]):
        self.workflow = workflow
        self.job_id = job_id
        self.contexts = contexts
        self.needs = needs


def workflow_jobs() -> list[Job]:
    """Every job of every non-plumbing workflow, matrix legs expanded."""
    jobs: list[Job] = []
    paths = sorted(p for g in WORKFLOW_GLOBS for p in glob.glob(g))
    for path in paths:
        fname = os.path.basename(path)
        if fname in PLUMBING_WORKFLOWS:
            continue
        try:
            doc = strict_yaml.safe_load(open(path))
        except yaml.YAMLError as e:
            print(f"verify-manifest: {fname} is not valid YAML: {e}", file=sys.stderr)
            sys.exit(2)
        if not isinstance(doc, dict):
            continue
        for job_id, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            name = job.get("name", job_id)
            needs = job.get("needs") or []
            if isinstance(needs, str):
                needs = [needs]
            contexts = expand_matrix_names(str(name), job.get("strategy") or {})
            jobs.append(Job(fname, str(job_id), contexts, [str(n) for n in needs]))
    return jobs


def produced_contexts(jobs: list[Job]) -> dict[str, list[str]]:
    """Map produced status-context string -> producing workflow filenames."""
    contexts: dict[str, list[str]] = {}
    for job in jobs:
        for ctx in job.contexts:
            contexts.setdefault(ctx, []).append(job.workflow)
    return contexts


def load_deterministic_checks(
    errors: list[str], root: str = REPO_ROOT
) -> list[tuple[str, str]] | None:
    """Parse `ci/deterministic-checks.json` into (context, step) pairs, or
    record why it is malformed.  Strict: the shell consumers match these
    strings byte-exactly, so anything a consumer could misread is rejected.
    """
    where = os.path.join(root, "ci", "deterministic-checks.json")
    try:
        with open(where) as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        errors.append(f"cannot read {where}: {e}")
        return None
    if not isinstance(doc, dict) or set(doc) != {"about", "checks"}:
        errors.append(f"{where}: top level must be an object with exactly the keys 'about' and 'checks'")
        return None
    checks = doc["checks"]
    if not isinstance(checks, list) or not checks:
        errors.append(f"{where}: 'checks' must be a non-empty list")
        return None
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for i, entry in enumerate(checks):
        if not isinstance(entry, dict) or set(entry) != {"context", "step"}:
            errors.append(f"{where}: checks[{i}] must be an object with exactly the keys 'context' and 'step'")
            continue
        ctx, step = entry["context"], entry["step"]
        bad = False
        for key, val in (("context", ctx), ("step", step)):
            if not isinstance(val, str) or not val or val != val.strip() or "\n" in val:
                errors.append(
                    f"{where}: checks[{i}].{key} = {val!r} must be a non-empty "
                    "single-line string with no leading/trailing whitespace"
                )
                bad = True
        if bad:
            continue
        if ctx in seen:
            errors.append(f"{where}: context {ctx!r} is listed more than once")
            continue
        seen.add(ctx)
        pairs.append((ctx, step))
    return pairs


def check_deterministic_set(jobs: list[Job], errors: list[str]) -> None:
    """`ci/deterministic-checks.json` is the one SSOT behind ci.yml's
    `cancel-on-cheap-red` watcher. Its job set must equal the watcher's `needs:`, and each pair's step must
    be a literal `name:` of that job's steps — a renamed or unnamed check step
    would otherwise never match and silently disable the watcher.

    This check reads `jobs` (the plain `Job` pass `main` shares across
    checks 1-4) for the watcher's `needs:` and contexts, but re-reads
    ci.yml as raw YAML for each listed job's own steps and masking keys —
    it does not consume the typed `ToolJob`/`ClosedStep` structures that
    `check_workflow_steps` parses for checks 6-7, since a deterministic
    check is not itself required to be a tool job.
    """
    pairs = load_deterministic_checks(errors)
    if pairs is None:
        return

    by_job_id = {
        j.job_id: j for j in jobs if j.workflow == CANCEL_WATCHER_WORKFLOW
    }
    watcher = by_job_id.get(CANCEL_WATCHER_JOB_ID)
    if watcher is None:
        errors.append(
            f"{CANCEL_WATCHER_WORKFLOW} has no {CANCEL_WATCHER_JOB_ID!r} job — "
            f"{DETERMINISTIC_CHECKS_FILE} has no watcher to check against"
        )
        return

    with open(
        os.path.join(REPO_ROOT, "workflows", CANCEL_WATCHER_WORKFLOW), encoding="utf-8"
    ) as f:
        raw_jobs = strict_yaml.safe_load(f).get("jobs") or {}

    # context -> job id, over single-context (non-matrix) jobs of ci.yml only:
    # a matrix leg's context cannot be tied to one check step unambiguously.
    ctx_to_job: dict[str, str] = {}
    for j in by_job_id.values():
        if len(j.contexts) == 1:
            ctx_to_job[j.contexts[0]] = j.job_id

    listed_ids: set[str] = set()
    for ctx, step in pairs:
        job_id = ctx_to_job.get(ctx)
        if job_id is None:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: context {ctx!r} is not the "
                f"context of a single-context job in {CANCEL_WATCHER_WORKFLOW}"
            )
            continue
        listed_ids.add(job_id)
        raw_job = raw_jobs.get(job_id) or {}
        if "strategy" in raw_job:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: job {job_id!r} has a `strategy:`; "
                "a deterministic check must be a single unexpanded job"
            )
        if "${{" in ctx or "${{" in step:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: {ctx!r}/{step!r} contains an "
                "expression; consumers match literal names only"
            )
        steps = raw_job.get("steps") or []
        named = [st for st in steps if isinstance(st, dict) and st.get("name") == step]
        if len(named) != 1:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: job {job_id!r} must have exactly "
                f"one step named {step!r} (found {len(named)})"
            )
            continue
        if MASKING_KEYS.intersection(named[0]):
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: step {step!r} of job {job_id!r} "
                "must run unconditionally: no `if:` and no `continue-on-error:`"
            )
        # A job-level `if:` is admitted: a path-filtered skip never fires the
        # cancel, the conservative outcome for the watcher. A failure-ignored
        # job would hand the watcher a red step under a green job.
        if "continue-on-error" in raw_job:
            errors.append(
                f"{DETERMINISTIC_CHECKS_FILE}: job {job_id!r} has a job-level "
                "`continue-on-error:`; a deterministic check's failure must fail its job"
            )

    needed = set(watcher.needs)
    unknown = needed - set(by_job_id)
    if unknown:
        errors.append(
            f"{CANCEL_WATCHER_WORKFLOW}: {CANCEL_WATCHER_JOB_ID!r} needs "
            f"unknown job(s) {sorted(unknown)}"
        )
    missing = listed_ids - needed
    extra = needed - listed_ids - unknown
    if missing:
        errors.append(
            f"{DETERMINISTIC_CHECKS_FILE} lists job(s) {sorted(missing)} but "
            f"{CANCEL_WATCHER_JOB_ID!r} does not `needs:` them"
        )
    if extra:
        errors.append(
            f"{CANCEL_WATCHER_JOB_ID!r} needs {sorted(extra)} but they are "
            f"missing from {DETERMINISTIC_CHECKS_FILE}"
        )


def _refuse_shape(loc: str, what: str, expected: str, got: object, errors: list[str]) -> None:
    errors.append(
        f"{loc}: {what} is not {expected} (got {type(got).__name__}: {got!r}) — "
        "cannot be audited; refused fail-closed"
    )


@dataclass(frozen=True)
class Step:
    """One workflow (or composite action) step, typed just enough for the
    step checks: `uses:`/`name:`/`run:`/`shell:` are read nowhere
    else in this module via raw `.get()`.
    """

    raw: dict

    def _str(self, key: str) -> str | None:
        v = self.raw.get(key)
        return v if isinstance(v, str) else None

    @property
    def name(self) -> str | None:
        return self._str("name")

    @property
    def uses(self) -> str | None:
        return self._str("uses")

    @property
    def run(self) -> str | None:
        return self._str("run")

    @property
    def shell(self) -> str | None:
        return self._str("shell")

    @property
    def label(self) -> str:
        return self.name or self.uses or "<unnamed>"


def _typed_steps(container: dict, loc: str, errors: list[str]) -> list[Step]:
    """`steps:` of a job or composite `runs:` as typed steps. Absent is empty;
    present but not a list, or an entry that is not a mapping, is refused —
    an unreadable step cannot be audited."""
    if "steps" not in container:
        return []
    raw = container["steps"]
    if not isinstance(raw, list):
        _refuse_shape(loc, "steps:", "a list", raw, errors)
        return []
    out: list[Step] = []
    for i, st in enumerate(raw):
        if isinstance(st, dict):
            out.append(Step(st))
        else:
            _refuse_shape(loc, f"steps[{i}]", "a mapping", st, errors)
    return out


@dataclass(frozen=True)
class WorkflowJob:
    job_id: str
    raw: dict


class Workspace(enum.Enum):
    """What a workflow's jobs may find in their workspace.

    `CHECKOUT` — a step may check out the repository, so `.github/ci/**` may
    sit in the workspace for an earlier step to rewrite; check 7's ordering
    rule and write scan guard it. `NONE` — the workflow is head-free
    (`head_free`): no step or job `uses:` anything and nothing runs `git`, so
    no checkout ever populates the workspace and every command is the
    workflow's own `run:` text.
    """

    CHECKOUT = "checkout"
    NONE = "none"


@dataclass(frozen=True)
class Workflow:
    fname: str
    doc: dict
    jobs: list[WorkflowJob]
    workspace: Workspace


def _load_workflows(root: str, errors: list[str]) -> list[Workflow]:
    """Every workflow (`*.yml` and `*.yaml`), typed. A document that is not a
    mapping, a `jobs:` that is not a non-empty mapping, or a job that is not a
    mapping is refused, never skipped."""
    out: list[Workflow] = []
    paths = sorted(
        p
        for pattern in ("*.yml", "*.yaml")
        for p in glob.glob(os.path.join(root, "workflows", pattern))
    )
    for path in paths:
        fname = os.path.basename(path)
        with open(path) as f:
            text = f.read()
        try:
            doc = strict_yaml.safe_load(text)
        except yaml.YAMLError as e:
            errors.append(f"{fname} is not valid YAML: {e}")
            continue
        if not isinstance(doc, dict):
            _refuse_shape(fname, "the workflow document", "a mapping", doc, errors)
            continue
        raw_jobs = doc.get("jobs")
        if not isinstance(raw_jobs, dict) or not raw_jobs:
            _refuse_shape(fname, "jobs:", "a non-empty mapping", raw_jobs, errors)
            continue
        jobs: list[WorkflowJob] = []
        for jid, j in raw_jobs.items():
            if isinstance(j, dict):
                jobs.append(WorkflowJob(str(jid), j))
            else:
                _refuse_shape(f"{fname}: job {str(jid)!r}", "the job", "a mapping", j, errors)
        workspace = Workspace.NONE if head_free(doc, text) else Workspace.CHECKOUT
        out.append(Workflow(fname, doc, jobs, workspace))
    return out


# A full-tier test that forgot the merge queue: `!= 'pull_request'` (either
# operand order) not followed by the matching `merge_group` exclusion. A
# spelling-bound lint: another spelling of the same test only costs the queue
# the full tier, since the secret-free and read-only checks stand apart.
_BARE_PR_TIER = re.compile(
    r"(?:event_name\s*!=\s*['\"]pull_request['\"]|['\"]pull_request['\"]\s*!=\s*github\.event_name)"
    r"(?!\s*&&\s*github\.event_name\s*!=\s*['\"]merge_group['\"])"
)
_SECRETS_WORD = re.compile(r"\bsecrets\b", re.IGNORECASE)
# Secrets carrying repository-admin read scope: only a `schedule`-triggered
# workflow, which runs the default branch's tree, may name one.
SCHEDULE_ONLY_SECRETS = ("RULESET_READ_TOKEN",)
_SCHEDULE_ONLY_SECRET = re.compile(r"\b(?:" + "|".join(SCHEDULE_ONLY_SECRETS) + r")\b", re.IGNORECASE)
# The one `(workflow file, job id)` that may declare a job `environment:`
# holding a schedule-only secret, and the literal environment it declares.
# GitHub hands that environment's secrets only to runs of the refs its
# deployment-branch policy admits (`main`); this pairing is defence in depth.
ADMIN_ENVIRONMENT_JOBS: dict[tuple[str, str], str] = {
    ("ruleset-admin-read.yml", "ruleset-admin-read"): check_required_set.ADMIN_READ_ENVIRONMENT,
}
_ADMIN_ENVIRONMENTS = frozenset(e.casefold() for e in ADMIN_ENVIRONMENT_JOBS.values())
_PR_ONLY = "github.event_name == 'pull_request'"


def _mentions(node: object, pattern: re.Pattern[str]) -> bool:
    """True when any key or string scalar of the parsed document matches
    `pattern`. Complements a raw-text scan: a double-quoted scalar can spell a
    word through `\\x`/`\\u` escapes that only the parser decodes."""
    if isinstance(node, dict):
        return any(_mentions(k, pattern) or _mentions(v, pattern) for k, v in node.items())
    if isinstance(node, list):
        return any(_mentions(e, pattern) for e in node)
    return isinstance(node, str) and pattern.search(node) is not None


def _mentions_secrets(node: object) -> bool:
    return _mentions(node, _SECRETS_WORD)


# A secret name GitHub admits: the one shape a `secrets` access may name.
_SECRET_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _secret_access_refusal(e: gha_expr.Expr) -> str | None:
    """Why an expression reads `secrets` other than by one literal name, or
    None. Admitted: `secrets.NAME` and `secrets['NAME']`. A bare `secrets`
    (`toJSON(secrets)`), `secrets.*`, a computed index, and a deeper path
    each could reach a secret no name scan sees."""
    for node in gha_expr.walk(e):
        if not isinstance(node, gha_expr.ContextRef) or node.ctx.casefold() != "secrets":
            continue
        if len(node.path) != 1:
            return "the whole `secrets` context" if not node.path else "a path deeper than one secret name"
        (seg,) = node.path
        if isinstance(seg, gha_expr.Prop) and _SECRET_NAME.fullmatch(seg.name):
            continue
        if (
            isinstance(seg, gha_expr.Index)
            and isinstance(seg.expr, gha_expr.Literal)
            and seg.expr.is_string
            and isinstance(seg.expr.value, str)
            and _SECRET_NAME.fullmatch(seg.expr.value)
        ):
            continue
        return "a secret whose name is not one literal"
    return None


def _check_secret_access(fname: str, node: object, errors: list[str], *, key: object = None) -> None:
    """Check 8's shape allowlist: every `secrets` access in any key or string
    scalar of a workflow names one literal secret, a `secrets:` block is a
    mapping (never `inherit`, which forwards every secret), and text outside
    the expression grammar never mentions `secrets`."""
    if isinstance(node, dict):
        for k, v in node.items():
            _check_secret_access(fname, k, errors)
            if str(k) == "secrets" and not isinstance(v, dict):
                errors.append(
                    f"{fname}: `secrets: {v!r}` forwards secrets no name scan sees — pass each one "
                    "by name in a mapping; refused"
                )
            _check_secret_access(fname, v, errors, key=k)
        return
    if isinstance(node, list):
        for item in node:
            _check_secret_access(fname, item, errors)
        return
    if not isinstance(node, str):
        return
    parsed = _parsed_expressions(node, bare_expression=key == "if")
    if isinstance(parsed, gha_expr.Refusal):
        if _SECRETS_WORD.search(node):
            errors.append(
                f"{fname}: {node!r} names `secrets` in text outside the expression grammar "
                f"({parsed.why}); refused"
            )
        return
    for e, (lo, hi) in zip(parsed.exprs, parsed.spans):
        why = _secret_access_refusal(e)
        if why is not None:
            errors.append(
                f"{fname}: {node[lo:hi]!r} reads {why}; only `secrets.NAME` or "
                "`secrets['NAME']` is admitted; refused"
            )


def _check_admin_environments(fname: str, doc: dict, errors: list[str]) -> None:
    """Check 8's environment half: a schedule-only secret is named only inside
    an `ADMIN_ENVIRONMENT_JOBS` job, which declares exactly its literal
    environment; no other job declares an admin environment, nor an
    environment whose name is computed at run time."""
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    outside = {k: v for k, v in doc.items() if k != "jobs"}
    if _mentions(outside, _SCHEDULE_ONLY_SECRET):
        errors.append(f"{fname}: names a schedule-only secret outside a job; only its keyed job may")
    for jid, job in jobs.items():
        if not isinstance(job, dict):
            continue
        keyed = ADMIN_ENVIRONMENT_JOBS.get((fname, str(jid)))
        where = f"{fname}: job {str(jid)!r}"
        if keyed is not None:
            if job.get("environment") != keyed:
                errors.append(f"{where} must declare `environment: {keyed}`, a literal name")
            continue
        if _mentions(job, _SCHEDULE_ONLY_SECRET):
            errors.append(
                f"{where} names a schedule-only secret but is not its keyed job "
                f"(ADMIN_ENVIRONMENT_JOBS); refused"
            )
        if "environment" not in job:
            continue
        env = job["environment"]
        name = env.get("name") if isinstance(env, dict) else env
        if not isinstance(name, str) or "${{" in name:
            errors.append(
                f"{where} declares environment {env!r}, whose name is not a literal string — "
                "it could name an admin environment at run time; refused"
            )
        elif name.strip().casefold() in _ADMIN_ENVIRONMENTS:
            errors.append(
                f"{where} declares the admin environment {name!r}; only its keyed job "
                "(ADMIN_ENVIRONMENT_JOBS) may; refused"
            )


def _top_level_conjuncts(cond: str) -> list[str] | None:
    """Split an `if:` expression on `&&` at parenthesis depth 0, outside string
    literals; whitespace-normalised conjuncts. None when the expression has a
    `||` anywhere, unbalanced parentheses, an unterminated string, or a
    `${{ }}` that does not wrap the whole condition (GitHub then evaluates the
    mix as a `format()` string, which is always truthy), since none of those
    can be proven to require its conjuncts."""
    expr = cond.strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2]
    if "${{" in expr or "}}" in expr:
        return None
    parts: list[str] = []
    depth = 0
    quote = False
    start = 0
    i = 0
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == "'":
                if expr[i + 1 : i + 2] == "'":
                    i += 1
                else:
                    quote = False
        elif c == "'":
            quote = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return None
        elif expr.startswith("||", i):
            return None
        elif expr.startswith("&&", i) and depth == 0:
            parts.append(expr[start:i])
            start = i + 2
            i += 1
        i += 1
    if quote or depth != 0:
        return None
    parts.append(expr[start:])
    return [" ".join(p.split()) for p in parts]


def _triggers(doc: dict) -> set[str] | None:
    """The workflow's event names, or None when `on:` has no recognised shape.
    PyYAML 1.1 reads the bare key `on` as boolean True."""
    on = doc.get(True, doc.get("on"))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list) and all(isinstance(e, str) for e in on):
        return set(on)
    if isinstance(on, dict):
        return {str(k) for k in on}
    return None


def _write_scopes(perms: object) -> bool:
    """True when a `permissions:` value grants any write scope."""
    if isinstance(perms, str):
        return perms.strip().casefold() != "read-all"
    if isinstance(perms, dict):
        return any(str(v).strip().casefold() == "write" for v in perms.values())
    return True


def check_merge_queue(gate_producers: set[str], errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 8 (see the module docstring). Unparseable workflows are refused by
    check 6; here they are skipped only after that refusal is on record."""
    paths = sorted(
        p
        for pattern in ("*.yml", "*.yaml")
        for p in glob.glob(os.path.join(root, "workflows", pattern))
    )
    seen: set[str] = set()
    for path in paths:
        fname = os.path.basename(path)
        seen.add(fname)
        with open(path) as f:
            text = f.read()
        try:
            doc = strict_yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        triggers = _triggers(doc)
        if triggers is None:
            errors.append(f"{fname}: `on:` is not a string, list of strings, or mapping")
            continue
        if (_SCHEDULE_ONLY_SECRET.search(text) or _mentions(doc, _SCHEDULE_ONLY_SECRET)) and triggers != {"schedule"}:
            errors.append(
                f"{fname}: names a schedule-only secret ({', '.join(SCHEDULE_ONLY_SECRETS)}) but "
                f"triggers on {sorted(triggers)} — only a `schedule`-only workflow may carry it"
            )
        _check_admin_environments(fname, doc, errors)
        _check_secret_access(fname, doc, errors)
        if fname in gate_producers:
            # A `pull_request_target` producer reports the PR-side context from
            # the base workflow; check 12 holds it to running no head code.
            if not triggers & {"pull_request", "pull_request_target"}:
                errors.append(
                    f"{fname} produces a required `gate` context but does not trigger "
                    "on `pull_request` (or `pull_request_target`) — no PR would report it"
                )
            if "merge_group" not in triggers:
                errors.append(
                    f"{fname} produces a required `gate` context but does not trigger "
                    "on `merge_group` — the merge queue would wait forever on it"
                )
        if "merge_group" not in triggers:
            continue
        if "pull_request_target" in triggers and not head_free(doc, text):
            errors.append(
                f"{fname}: a merge_group workflow may also trigger on "
                "`pull_request_target` only when it runs no head code (check 12)"
            )
        if _SECRETS_WORD.search(text) or _mentions_secrets(doc):
            errors.append(
                f"{fname}: a merge_group workflow must be secret-free — a merge-group "
                "run carries the base repository's secrets"
            )
        if "permissions" not in doc:
            errors.append(f"{fname}: a merge_group workflow must declare top-level `permissions:`")
        elif _write_scopes(doc["permissions"]):
            errors.append(
                f"{fname}: a merge_group workflow's top-level `permissions:` must be "
                f"read-only, got {doc['permissions']!r}"
            )
        jobs = doc.get("jobs")
        for jid, job in (jobs.items() if isinstance(jobs, dict) else ()):
            if not isinstance(job, dict) or "permissions" not in job:
                continue
            if not _write_scopes(job["permissions"]):
                continue
            conjuncts = _top_level_conjuncts(str(job.get("if", "")))
            if conjuncts is None or _PR_ONLY not in conjuncts:
                errors.append(
                    f"{fname}: job {str(jid)!r} holds a write scope in a merge_group "
                    "workflow; its `if:` must be a conjunction requiring "
                    "`github.event_name == 'pull_request'` at the top level"
                )
        # The canonical phase outputs are pinned by check 11; they exclude the
        # merge queue from no phase by accident.
        scan = text
        for value in PHASE_OUTPUTS.values():
            scan = scan.replace(value, "")
        for m in _BARE_PR_TIER.finditer(scan):
            line = scan.count("\n", 0, m.start()) + 1
            errors.append(
                f"{fname}:{line}: `github.event_name != 'pull_request'` without "
                "`&& github.event_name != 'merge_group'` — a merge-group run would "
                "take the full tier"
            )
    for fname in sorted(gate_producers - seen):
        errors.append(f"gate producer {fname!r} has no workflow file (check 8)")


_RELEASE_ONLY_OUTPUT = "release_only"
_RELEASE_ONLY_RUN = re.compile(r"needs\.[A-Za-z0-9_-]+\.outputs\.release_only == 'true'")


def _top_level_disjuncts(cond: str) -> list[str] | None:
    """Split an `if:` expression on `||` at parenthesis depth 0, outside string
    literals; whitespace-normalised disjuncts. None on unbalanced parentheses,
    an unterminated string, or a `${{ }}` that does not wrap the whole
    condition (see `_top_level_conjuncts`)."""
    expr = cond.strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2]
    if "${{" in expr or "}}" in expr:
        return None
    parts: list[str] = []
    depth = 0
    quote = False
    start = 0
    i = 0
    while i < len(expr):
        c = expr[i]
        if quote:
            if c == "'":
                if expr[i + 1 : i + 2] == "'":
                    i += 1
                else:
                    quote = False
        elif c == "'":
            quote = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return None
        elif expr.startswith("||", i) and depth == 0:
            parts.append(expr[start:i])
            start = i + 2
            i += 1
        i += 1
    if quote or depth != 0:
        return None
    parts.append(expr[start:])
    return [" ".join(p.split()) for p in parts]


def _release_only_mention(doc: dict) -> re.Pattern[str]:
    """Case-insensitive whole-word match of `release_only` and of every job
    output that re-exports it, directly or through another such output."""
    jobs = doc.get("jobs") if isinstance(doc.get("jobs"), dict) else {}
    names = {_RELEASE_ONLY_OUTPUT}
    while True:
        pattern = re.compile(
            r"\b(?:" + "|".join(re.escape(n) for n in sorted(names)) + r")\b", re.IGNORECASE
        )
        found = {
            str(key).lower()
            for job in jobs.values()
            if isinstance(job, dict) and isinstance(job.get("outputs"), dict)
            for key, value in job["outputs"].items()
            if pattern.search(str(value))
        }
        if found <= names:
            return pattern
        names |= found


def check_release_only_skips(gate_contexts: set[str], errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 9 (see the module docstring). Unparseable workflows are refused by
    check 6; here they are skipped only after that refusal is on record."""
    paths = sorted(
        p
        for pattern in ("*.yml", "*.yaml")
        for p in glob.glob(os.path.join(root, "workflows", pattern))
    )
    for path in paths:
        fname = os.path.basename(path)
        try:
            with open(path) as f:
                doc = strict_yaml.safe_load(f)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        mention = _release_only_mention(doc)
        jobs = doc.get("jobs")
        for jid, job in (jobs.items() if isinstance(jobs, dict) else ()):
            if not isinstance(job, dict):
                continue
            strategy = job.get("strategy")
            contexts = expand_matrix_names(
                str(job.get("name", jid)), strategy if isinstance(strategy, dict) else {}
            )
            if not gate_contexts.intersection(contexts):
                continue
            cond = str(job.get("if", ""))
            steps = job.get("steps")
            all_conditional = (
                isinstance(steps, list)
                and bool(steps)
                and all(isinstance(st, dict) and "if" in st for st in steps)
            )
            if not mention.search(cond) and not all_conditional:
                continue
            loc = f"{fname}: gate producer job {str(jid)!r}"
            disjuncts = _top_level_disjuncts(cond)
            runs = [d for d in disjuncts or () if _RELEASE_ONLY_RUN.fullmatch(d)]
            others = [d for d in disjuncts or () if mention.search(d) and d not in runs]
            if not mention.search(cond):
                errors.append(
                    f"{loc}: every step carries an `if:`, so all of them can skip and the "
                    "job reports a pass without executing anything; give it an "
                    "unconditional step or the release-only trivial-pass shape (check 9)"
                )
                continue
            if disjuncts is None or len(runs) != 1 or others:
                errors.append(
                    f"{loc}: job-level `if:` may name `release_only` only as one top-level "
                    "`|| needs.<job>.outputs.release_only == 'true'` disjunct — a skipped "
                    "required job reports a pass without executing anything (check 9)"
                )
                continue
            first = steps[0] if isinstance(steps, list) and steps else None
            if not (
                isinstance(first, dict)
                and " ".join(str(first.get("if", "")).split()) == runs[0]
                and isinstance(first.get("run"), str)
                and first["run"].strip()
            ):
                errors.append(
                    f"{loc}: runs on a release-only diff but its first step is not the "
                    f"trivial-pass `run:` step gated `if: {runs[0]}` — a job whose steps "
                    "all skip reports a pass without executing anything (check 9)"
                )


def _needs_list(job: dict) -> list[str] | None:
    needs = job.get("needs", [])
    if isinstance(needs, str):
        return [needs]
    if isinstance(needs, list) and all(isinstance(n, str) for n in needs):
        return list(needs)
    return None


def _downloads_archive(job: dict) -> bool:
    for st in job.get("steps") or []:
        if not isinstance(st, dict):
            continue
        uses = st.get("uses")
        with_ = st.get("with")
        if (
            uses_action(uses, "actions/download-artifact")
            and isinstance(with_, dict)
            and with_.get("name") == HEAVY_SHARD_ARTIFACT
        ):
            return True
    return False


def check_fast_gate_first(gate_contexts: set[str], errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 10 (see the module docstring). Refuses, never skips, a shape it
    cannot read."""
    where = os.path.join(root, "workflows", FAST_GATE_WORKFLOW)
    try:
        with open(where) as f:
            doc = strict_yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        errors.append(f"check 10: cannot read {where}: {e}")
        return
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if not isinstance(jobs, dict):
        errors.append(f"check 10: {FAST_GATE_WORKFLOW} has no `jobs:` mapping")
        return

    for gate in FAST_GATES:
        job = jobs.get(gate)
        if not isinstance(job, dict):
            errors.append(f"check 10: fast gate {gate!r} is not a job of {FAST_GATE_WORKFLOW}")
            continue
        if "strategy" in job:
            errors.append(f"check 10: fast gate {gate!r} has a `strategy:`; it must be one unexpanded job")
        ctx = job.get("name", gate)
        if ctx not in gate_contexts:
            errors.append(f"check 10: fast gate {gate!r} (context {ctx!r}) is not a manifest `gate`")
        needs = _needs_list(job)
        if needs is None:
            errors.append(f"check 10: fast gate {gate!r} has a malformed `needs:`")
        elif not set(needs) <= FAST_GATE_NEEDS_ALLOWED:
            errors.append(
                f"check 10: fast gate {gate!r} needs {sorted(set(needs) - FAST_GATE_NEEDS_ALLOWED)}; "
                f"a fast gate may need only {sorted(FAST_GATE_NEEDS_ALLOWED)}"
            )

    heavy = sorted(
        str(jid)
        for jid, job in jobs.items()
        if isinstance(job, dict)
        and isinstance(job.get("strategy"), dict)
        and "matrix" in job["strategy"]
        and _downloads_archive(job)
    )
    for anchor in HEAVY_SHARD_ANCHORS:
        if anchor not in heavy:
            errors.append(
                f"check 10: {anchor!r} is not a matrix job of {FAST_GATE_WORKFLOW} that downloads "
                f"{HEAVY_SHARD_ARTIFACT!r}; the heavy-shard derivation no longer finds it"
            )
    for jid in heavy:
        job = jobs[jid]
        needs = _needs_list(job)
        if needs is None:
            errors.append(f"check 10: heavy shard job {jid!r} has a malformed `needs:`")
        else:
            missing = [g for g in FAST_GATES if g not in needs]
            if missing:
                errors.append(
                    f"check 10: heavy shard job {jid!r} does not `needs:` fast gate(s) {missing}; "
                    "a fast red would still launch it"
                )
        cond = job.get("if")
        if cond is not None and (not isinstance(cond, str) or _STATUS_FN.search(cond)):
            errors.append(
                f"check 10: heavy shard job {jid!r} `if:` calls a status function "
                "(always/failure/cancelled) or is not a string; it would start behind a red need"
            )


# CI phases (CONTRIBUTING.md "CI phases"): the events each phase
# EXCLUDES. Every other trigger (including `workflow_dispatch` and `schedule`)
# runs every phase. The SSOT for the `changes` phase outputs and for the
# composite verdict's own event membership (pinned in tests).
PHASE_EXCLUDES: dict[str, tuple[str, ...]] = {
    "cheap": ("push",),
    "tests": ("pull_request", "push"),
    "post_merge": ("pull_request", "merge_group"),
}
# Phases whose required contexts go green only through a phase verdict.
VERDICT_PHASES = ("tests", "post_merge")


def _phase_output(phase: str) -> str:
    excluded = " && ".join(f"github.event_name != '{e}'" for e in PHASE_EXCLUDES[phase])
    return "${{ " + excluded + " }}"


PHASE_OUTPUTS: dict[str, str] = {p: _phase_output(p) for p in PHASE_EXCLUDES}
PHASE_VERDICT_ACTION = "./.github/actions/phase-verdict"
PHASE_VERDICT_CHECKOUT_WITH = {"persist-credentials": False, "sparse-checkout": ".github/actions/phase-verdict"}
_CHECKOUT_PIN = re.compile(r"actions/checkout@[0-9a-f]{40}")
_PHASE_MARKER = re.compile(r"needs\.changes\.outputs\.(cheap|tests|post_merge) == 'true'")
_SCOPE_MARKER = re.compile(r"needs\.changes\.outputs\.([a-z_]+) == 'true'")
_RELEASE_ONLY_DISJUNCT = "needs.changes.outputs.release_only == 'true'"
_EVENT_NAME = re.compile(r"event_name", re.IGNORECASE)
_AGGREGATOR_KEYS = frozenset({"name", "runs-on", "needs", "if", "steps", "timeout-minutes"})
_EVENTS = frozenset({"pull_request", "merge_group", "push", "schedule", "workflow_dispatch"})
# A PR-only job (`_PR_ONLY` conjunct): the cheap phase's narrowest member.
_PR_PHASE = "pull_request_only"


def _phase_events(phase: str | None) -> frozenset[str]:
    """The events a job of `phase` may run on; None is unconditional."""
    if phase is None:
        return _EVENTS
    if phase == _PR_PHASE:
        return frozenset({"pull_request"})
    return _EVENTS - frozenset(PHASE_EXCLUDES[phase])


def _strip_outer_parens(expr: str) -> str:
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")"):
        inner = expr[1:-1]
        if _top_level_conjuncts(inner) is None and _top_level_disjuncts(inner) is None:
            break
        depth = 0
        balanced = True
        for c in inner:
            depth += c == "("
            depth -= c == ")"
            if depth < 0:
                balanced = False
                break
        if not balanced or depth != 0:
            break
        expr = inner.strip()
    return expr


def _job_phase(where: str, job: dict, errors: list[str]) -> tuple[bool, str | None]:
    """(ok, phase) of a routed work job: phase None means unconditional.
    Refuses an `if:` naming the event or carrying no single phase marker."""
    needs = _needs_list(job)
    cond = job.get("if")
    if cond is None:
        if needs:
            errors.append(f"check 11: {where} has `needs:` but no phase `if:`; a job runs in exactly one phase")
            return False, None
        return True, None
    if not isinstance(cond, str):
        errors.append(f"check 11: {where} `if:` is not a string")
        return False, None
    disjuncts = _top_level_disjuncts(cond)
    if disjuncts is None or not 1 <= len(disjuncts) <= 2:
        errors.append(f"check 11: {where} `if:` is not one phase conjunction (plus at most the release-only disjunct)")
        return False, None
    main = _top_level_conjuncts(_strip_outer_parens(disjuncts[0]))
    if main is None:
        errors.append(f"check 11: {where} `if:` main disjunct is not a plain conjunction")
        return False, None
    phases: list[str] = []
    for c in main:
        m = _PHASE_MARKER.fullmatch(c)
        if m:
            phases.append(m.group(1))
        elif c == _PR_ONLY:
            phases.append(_PR_PHASE)
        elif _EVENT_NAME.search(c) or re.search(r"outputs\.(cheap|tests|post_merge)\b", c):
            errors.append(f"check 11: {where} `if:` conjunct {c!r} routes by event outside the phase markers")
            return False, None
    if len(phases) != 1:
        errors.append(f"check 11: {where} `if:` carries {len(phases)} phase markers; exactly one is required")
        return False, None
    phase = phases[0]
    if len(disjuncts) == 2:
        if _strip_outer_parens(disjuncts[1]) != _RELEASE_ONLY_DISJUNCT or phase != "cheap":
            errors.append(
                f"check 11: {where} `if:` second disjunct must be exactly {_RELEASE_ONLY_DISJUNCT!r} "
                "on a cheap job"
            )
            return False, None
    if phase != _PR_PHASE and (needs is None or "changes" not in needs):
        errors.append(f"check 11: {where} reads a `changes` phase output but does not need `changes`")
        return False, None
    if _EVENT_NAME.search(cond) and phase != _PR_PHASE:
        errors.append(f"check 11: {where} `if:` names the event; route through the `changes` phase outputs")
        return False, None
    return True, phase


def _check_aggregator(where: str, jobs: dict, job: dict, errors: list[str]) -> None:
    extra = set(job) - _AGGREGATOR_KEYS
    if extra:
        errors.append(f"check 11: {where} (phase verdict) carries {sorted(extra)}; only {sorted(_AGGREGATOR_KEYS)} are admitted")
    if job.get("if") != "always()":
        errors.append(f"check 11: {where} (phase verdict) `if:` must be exactly `always()`, so no need's state skips it")
    needs = _needs_list(job)
    if needs is None or len(needs) < 2 or needs[0] != "changes" or len(set(needs)) != len(needs):
        errors.append(f"check 11: {where} (phase verdict) `needs:` must list `changes` first, then each aggregated job once")
        return
    steps = job.get("steps")
    if not isinstance(steps, list) or len(steps) < 2 or not all(isinstance(s, dict) for s in steps):
        errors.append(f"check 11: {where} (phase verdict) must open with the checkout and verdict steps")
        return
    checkout, verdict = steps[0], steps[1]
    for i, st in enumerate(steps[2:], start=3):
        if "continue-on-error" in st:
            errors.append(f"check 11: {where} (phase verdict) step {i} carries `continue-on-error:`; a later step may only add a refusal")
    if (
        set(checkout) != {"uses", "with"}
        or not isinstance(checkout.get("uses"), str)
        or not _CHECKOUT_PIN.fullmatch(checkout["uses"])
        or checkout.get("with") != PHASE_VERDICT_CHECKOUT_WITH
    ):
        errors.append(f"check 11: {where} (phase verdict) step 1 must be the pinned sparse checkout of the verdict action")
    if set(verdict) - {"name"} != {"uses", "with"} or verdict.get("uses") != PHASE_VERDICT_ACTION:
        errors.append(f"check 11: {where} (phase verdict) step 2 must be `uses: {PHASE_VERDICT_ACTION}` with no `if:`/`continue-on-error:`/`env:`")
        return
    w = verdict.get("with")
    if not isinstance(w, dict) or set(w) != {"results", "phase", "tier", "scope"}:
        errors.append(f"check 11: {where} (phase verdict) `with:` must set exactly results, phase, tier, scope")
        return
    want = " ".join(f"{n}=${{{{ needs.{n}.result }}}}" for n in needs)
    if w["results"] != want:
        errors.append(f"check 11: {where} (phase verdict) `results` must be {want!r}, one pair per need in order")
    phase = w["phase"]
    if phase not in VERDICT_PHASES:
        errors.append(f"check 11: {where} (phase verdict) `phase` must be one of {list(VERDICT_PHASES)}")
        return
    if w["tier"] != f"${{{{ needs.changes.outputs.{phase} }}}}":
        errors.append(f"check 11: {where} (phase verdict) `tier` must be the `changes` output for {phase!r}")
    m = re.fullmatch(r"\$\{\{ needs\.changes\.outputs\.([a-z_]+) \}\}", str(w["scope"]))
    if not m or m.group(1) in PHASE_EXCLUDES or m.group(1) == "release_only":
        errors.append(f"check 11: {where} (phase verdict) `scope` must be one `changes` scope output")
        return
    run_if = f"needs.changes.outputs.{phase} == 'true' && needs.changes.outputs.{m.group(1)} == 'true'"
    for n in needs[1:]:
        dep = jobs.get(n)
        if not isinstance(dep, dict):
            errors.append(f"check 11: {where} (phase verdict) needs unknown job {n!r}")
        elif dep.get("if") != run_if:
            errors.append(
                f"check 11: {where} (phase verdict) aggregates {n!r}, whose `if:` must be exactly "
                f"{run_if!r} so the verdict's tier and scope are the job's own"
            )


def check_phase_routing(gate_contexts: set[str], errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 11 (see the module docstring). Unparseable workflows are refused
    by check 6."""
    paths = sorted(
        p for pattern in ("*.yml", "*.yaml") for p in glob.glob(os.path.join(root, "workflows", pattern))
    )
    for path in paths:
        fname = os.path.basename(path)
        try:
            with open(path) as f:
                doc = strict_yaml.safe_load(f)
        except (OSError, yaml.YAMLError):
            continue
        if not isinstance(doc, dict):
            continue
        triggers = _triggers(doc)
        jobs = doc.get("jobs")
        if triggers is None or "merge_group" not in triggers or not isinstance(jobs, dict):
            continue
        changes = jobs.get("changes")
        if not isinstance(changes, dict):
            continue
        if "if" in changes or "needs" in changes:
            errors.append(f"check 11: {fname}: `changes` must run on every event (no `if:`/`needs:`)")
        outputs = changes.get("outputs")
        for phase, value in PHASE_OUTPUTS.items():
            got = outputs.get(phase) if isinstance(outputs, dict) else None
            if got != value:
                errors.append(f"check 11: {fname}: `changes` output {phase!r} must be exactly {value!r}, got {got!r}")
        phases: dict[str, str | None] = {"changes": None}
        aggregators: list[str] = []
        for jid, job in jobs.items():
            jid = str(jid)
            if jid == "changes" or not isinstance(job, dict):
                continue
            where = f"{fname}: job {jid!r}"
            if any(isinstance(s, dict) and s.get("uses") == PHASE_VERDICT_ACTION for s in job.get("steps") or []):
                aggregators.append(jid)
                _check_aggregator(where, jobs, job, errors)
                continue
            ok, phase = _job_phase(where, job, errors)
            if not ok:
                continue
            phases[jid] = phase
            ctx = job.get("name", jid)
            if phase in VERDICT_PHASES and ctx in gate_contexts:
                errors.append(
                    f"check 11: {where} reports required context {ctx!r} from the {phase} phase; a skipped "
                    "check reads as passing, so it must report through a phase verdict"
                )
        # Direct aggregation only: a work job's `if:` may admit `always()`, so a
        # job reached through another work job's `needs` is not proven to gate.
        required = {
            n
            for a in aggregators
            if str(jobs[a].get("name", a)) in gate_contexts
            for n in _needs_list(jobs[a]) or []
            if n != "changes"
        }
        for jid, phase in phases.items():
            if phase == "tests" and jid not in required:
                errors.append(
                    f"check 11: {fname}: tests-phase job {jid!r} is aggregated by no required phase verdict; "
                    "its red never reaches the merge decision"
                )
        for jid, phase in phases.items():
            needs = _needs_list(jobs[jid]) or []
            own = _phase_events(phase)
            for n in needs:
                if n in aggregators:
                    errors.append(f"check 11: {fname}: job {jid!r} needs phase verdict {n!r}; need its work jobs")
                    continue
                if n not in phases:
                    continue
                if not own <= _phase_events(phases[n]):
                    errors.append(
                        f"check 11: {fname}: job {jid!r} ({phase or 'unconditional'}) needs {n!r} "
                        f"({phases[n] or 'unconditional'}), which does not run on every event it does"
                    )


# The ONLY expression a `pull_request_target` workflow may interpolate: the
# job's own read-only token. Every other `${{ }}` is refused, so no
# PR-controlled value (title, branch name, head commit) is spliced anywhere.
_PRT_ALLOWED_EXPRESSIONS = frozenset({"github.token"})


def _prt_disallowed_expressions(text: str) -> list[str]:
    """The `${{ }}` bodies in `text` that are not an admitted context
    reference, whitespace-normalised. Bodies are parsed by `gha_expr` and
    compared as context paths without case, as the Actions evaluator resolves
    them; a text whose expressions fall outside the grammar is refused whole."""
    parsed = gha_expr.parse_template(text)
    if isinstance(parsed, gha_expr.Refusal):
        return [f"an expression outside the grammar ({parsed.why})"]
    bad = []
    for e, (start, end) in zip(parsed.exprs, parsed.spans):
        if not (
            isinstance(e, gha_expr.ContextRef)
            and all(isinstance(seg, gha_expr.Prop) for seg in e.path)
            and ".".join([e.ctx, *(seg.name for seg in e.path)]).casefold() in _PRT_ALLOWED_EXPRESSIONS
        ):
            bad.append(" ".join(text[start + 3 : end - 2].split()))
    return bad
# Every spelling of the PR head a workflow could name: `head` covers
# `github.head_ref`, `$GITHUB_HEAD_REF`, the event's `pull_request.head.*`, and
# a `jq` path into it; the test-merge commit and `refs/pull/` refs carry head
# code too. A pull_request_target workflow has no reason to name any of them.
_PRT_HEAD_WORD = re.compile(r"head|merge_commit_sha|refs/pull/", re.IGNORECASE)
# A pull_request_target workflow has no working tree and needs no `git`; its
# only `gh` use is the REST API.
_PRT_GIT_WORD = re.compile(r"\bgit\b", re.IGNORECASE)
_PRT_GH_NON_API = re.compile(r"\bgh\s+(?!api\b)\S", re.IGNORECASE)
# Paths the trust-root machinery itself lives at: each must be a trust root,
# or an outside PR could rewrite the check that guards the others.
TRUST_ROOT_MACHINERY = (
    ".github/CODEOWNERS",
    ".github/ci/trust_roots.py",
    ".github/ci/verify-manifest.py",
    ".github/workflows/trust-root-diff.yml",
)
# GitHub reads the first CODEOWNERS of `.github/`, the root, `docs/`; only the
# first location is the SSOT, so a file at the others is refused as a
# misleading second list.
_STRAY_CODEOWNERS = ("CODEOWNERS", "docs/CODEOWNERS")
# A tracked file with one of these suffixes that a workflow or local action
# names is a script CI executes: editing it changes what a gate proves, so it
# must be a trust root wherever it lives.
_SCRIPT_SUFFIXES = (".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".ps1", ".pl", ".rb")


def _scalars(node: object):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _scalars(k)
            yield from _scalars(v)
    elif isinstance(node, list):
        for e in node:
            yield from _scalars(e)
    elif isinstance(node, str):
        yield node


def pull_request_target_violations(doc: dict, text: str) -> list[str]:
    """Check 12a's refusals for one `pull_request_target` workflow (see the
    module docstring); empty when it provably runs no head code."""
    out: list[str] = []
    scalars = list(_scalars(doc))
    texts = [text, *scalars, *_quote_removed(scalars)]
    if any(_SECRETS_WORD.search(t) for t in texts):
        out.append("names `secrets` — the base repository's secrets would sit next to untrusted input")
    if any(_PRT_HEAD_WORD.search(t) for t in texts):
        out.append("names the PR head (`head`, `merge_commit_sha`, or `refs/pull/`)")
    if any(_PRT_GIT_WORD.search(t) for t in texts):
        out.append("runs `git` — there is no working tree to need it, only head code to fetch")
    if any(_PRT_GH_NON_API.search(t) for t in texts):
        out.append("runs a `gh` subcommand other than `gh api`")
    bad_expr = sorted({b for t in texts for b in _prt_disallowed_expressions(t)})
    if bad_expr:
        out.append(
            f"interpolates {', '.join(repr(b) for b in bad_expr)} — only "
            f"{', '.join(sorted(_PRT_ALLOWED_EXPRESSIONS))} is admitted"
        )
    if "permissions" not in doc:
        out.append("declares no top-level `permissions:` (the default token may write)")
    elif _write_scopes(doc["permissions"]):
        out.append(f"top-level `permissions:` must be read-only, got {doc['permissions']!r}")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        out.append("`jobs:` is not a non-empty mapping")
        return out
    for jid, job in jobs.items():
        loc = f"job {str(jid)!r}"
        if not isinstance(job, dict):
            out.append(f"{loc} is not a mapping")
            continue
        if "uses" in job:
            out.append(f"{loc} calls a reusable workflow — its steps are not auditable here")
        if "permissions" in job and _write_scopes(job["permissions"]):
            out.append(f"{loc} `permissions:` must be read-only, got {job['permissions']!r}")
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            out.append(f"{loc} `steps:` is not a list")
            continue
        for i, st in enumerate(steps):
            if not isinstance(st, dict):
                out.append(f"{loc} step {i} is not a mapping")
            elif "uses" in st:
                out.append(
                    f"{loc} step {i} `uses: {st['uses']}` — no action runs under "
                    "pull_request_target (a checkout, local, or third-party action "
                    "can fetch and run head code)"
                )
    return out


def _quote_removed(scalars: list[str]) -> list[str]:
    """Each scalar's shell commands (here-document bodies included) as their
    quote-removed words joined by one space, so `g""it` reads `git` and
    `"gh" pr` reads `gh pr` to the word rules of check 12a."""
    return [
        " ".join(cmd.words)
        for t in scalars
        for part in _shell_texts(t)
        for cmd in shell_lex.split_commands(part)
    ]


def head_free(doc: dict, text: str) -> bool:
    """Whether the workflow is one check 12a admits: it triggers on
    `pull_request_target` and `pull_request_target_violations` finds nothing.
    Such a workflow has no `uses:` at step or job level and runs no `git`, so
    its workspace never holds a checkout (`Workspace.NONE`). The one predicate
    check 7 (which then exempts its jobs from the ordering rule's step half
    and the write scan) and check 8 read."""
    triggers = _triggers(doc)
    return (
        triggers is not None
        and "pull_request_target" in triggers
        and not pull_request_target_violations(doc, text)
    )


def check_pull_request_target(errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 12a (see the module docstring). Unparseable workflows are refused
    by check 6."""
    for path in sorted(p for pattern in ("*.yml", "*.yaml") for p in glob.glob(os.path.join(root, "workflows", pattern))):
        fname = os.path.basename(path)
        with open(path) as f:
            text = f.read()
        try:
            doc = strict_yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        triggers = _triggers(doc)
        if triggers is None:
            # Fail closed: an `on:` this reader cannot enumerate may still
            # hold `pull_request_target`.
            if "pull_request_target" in text or any("pull_request_target" in t for t in _scalars(doc)):
                errors.append(
                    f"{fname}: `on:` has no recognised shape but names `pull_request_target`; "
                    "check 12 cannot prove it runs no head code"
                )
            continue
        if "pull_request_target" not in triggers:
            continue
        for v in pull_request_target_violations(doc, text):
            errors.append(f"{fname}: a pull_request_target workflow {v}")


# Push workflows whose group is deliberately one per workflow: each run acts
# on the branch head it reads at run time, so a newer push's run supersedes an
# older queued one without losing any commit's outcome.
LATEST_WINS_PUSH_GROUPS = {
    "release-please.yml": "recomputes the release PR from the head of main",
    "docs-pages.yml": "deploys the head of main to Pages",
}

# The `github` properties a concurrency key may read, as two distinct pushes
# to the same branch see them; any other context or property is refused.
_PUSH_CONTEXTS = tuple(
    {
        "event_name": "push",
        "ref": "refs/heads/main",
        "ref_name": "main",
        "head_ref": "",
        "base_ref": "",
        "repository": "o/r",
        "workflow": "w",
        "sha": sha,
        "run_id": run_id,
    }
    for sha, run_id in (("a" * 40, "1"), ("b" * 40, "2"))
)

# The `github` properties a concurrency key may read, as three merge-group
# runs see them: M1 and M1' share a queue ref (a re-entered PR's stale run and
# its replacement), M2 is another PR's entry. `head_ref` and `base_ref` are
# absent, so a key reading them is refused.
_MERGE_GROUP_QUEUE_REFS = tuple(f"refs/heads/gh-readonly-queue/main/pr-{n}-{c * 40}" for n, c in ((1, "a"), (2, "c")))
_MERGE_GROUP_CONTEXTS = tuple(
    {
        "event_name": "merge_group",
        "ref": ref,
        "ref_name": ref.removeprefix("refs/heads/"),
        "repository": "o/r",
        "workflow": "w",
        "sha": sha,
        "run_id": run_id,
    }
    for ref, sha, run_id in (
        (_MERGE_GROUP_QUEUE_REFS[0], "a" * 40, "1"),
        (_MERGE_GROUP_QUEUE_REFS[0], "b" * 40, "2"),
        (_MERGE_GROUP_QUEUE_REFS[1], "c" * 40, "3"),
    )
)


class _Unevaluable(Exception):
    pass


def _truthy(v: object) -> bool:
    return v not in (False, None, "")


def _as_text(v: object) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _eval_event(e: gha_expr.Expr, ctx: dict[str, str]) -> object:
    """Evaluate `e` under one event context: literals, the `github` properties
    of `ctx`, `==`/`!=` on same-typed operands (strings compared
    without case), `&&`/`||` with the Actions value semantics, and `!`.
    Anything else raises `_Unevaluable`."""
    if isinstance(e, gha_expr.Literal):
        if not e.is_string and isinstance(e.value, str):
            raise _Unevaluable("uses a number literal, whose coercion this check does not evaluate")
        return e.value
    if isinstance(e, gha_expr.ContextRef):
        if (
            e.ctx.casefold() != "github"
            or len(e.path) != 1
            or not isinstance(e.path[0], gha_expr.Prop)
            or e.path[0].name.casefold() not in ctx
        ):
            raise _Unevaluable(f"reads a context this check cannot resolve for a {ctx['event_name']} run")
        return ctx[e.path[0].name.casefold()]
    if isinstance(e, gha_expr.Unary) and e.op == "!":
        return not _truthy(_eval_event(e.operand, ctx))
    if isinstance(e, gha_expr.Binary) and e.op in ("&&", "||"):
        left = _eval_event(e.left, ctx)
        if _truthy(left) == (e.op == "||"):
            return left
        return _eval_event(e.right, ctx)
    if isinstance(e, gha_expr.Binary) and e.op in ("==", "!="):
        left, right = _eval_event(e.left, ctx), _eval_event(e.right, ctx)
        if type(left) is not type(right):
            raise _Unevaluable("compares operands of different types")
        if isinstance(left, str) and isinstance(right, str):
            same = left.casefold() == right.casefold()
        else:
            same = left == right
        return same == (e.op == "==")
    raise _Unevaluable("uses an operator or function this check does not evaluate")


def _event_group(text: str, ctx: dict[str, str]) -> str:
    parsed = gha_expr.parse_template(text)
    if isinstance(parsed, gha_expr.Refusal):
        raise _Unevaluable(parsed.why)
    out: list[str] = []
    at = 0
    for e, (start, end) in zip(parsed.exprs, parsed.spans):
        out.append(text[at:start])
        out.append(_as_text(_eval_event(e, ctx)))
        at = end
    out.append(text[at:])
    return "".join(out)


def _event_cancels(value: object, ctx: dict[str, str]) -> bool:
    """Whether a `cancel-in-progress` value is truthy under `ctx`: absent is
    false, a YAML boolean is itself, a string must be exactly one `${{ }}`
    expression; any other shape raises `_Unevaluable`."""
    if value is None or isinstance(value, bool):
        return value is True
    if not isinstance(value, str):
        raise _Unevaluable("is neither a boolean nor an expression")
    parsed = gha_expr.parse_template(value)
    if isinstance(parsed, gha_expr.Refusal):
        raise _Unevaluable(parsed.why)
    if len(parsed.exprs) != 1 or parsed.spans[0] != (0, len(value)):
        raise _Unevaluable("is not exactly one `${{ }}` expression")
    return _truthy(_eval_event(parsed.exprs[0], ctx))


def _check_merge_group_site(fname: str, where: str, group: str, cancel: object, errors: list[str]) -> None:
    """Check 13 for one concurrency site of a merge_group-triggered workflow."""
    try:
        m1, m1_again, m2 = (_event_group(group, ctx) for ctx in _MERGE_GROUP_CONTEXTS)
    except _Unevaluable as why:
        errors.append(f"{fname}: {where} concurrency group {group!r} {why}; check 13 cannot prove merge-group runs never stall")
        return
    if m1 == m2:
        errors.append(
            f"{fname}: {where} concurrency group {group!r} is the same for merge-group runs of two queue refs — "
            "the whole merge queue runs one entry at a time; key merge-group groups by `github.ref` or `github.sha`"
        )
    if m1 != m1_again:
        return
    try:
        cancels = all(_event_cancels(cancel, ctx) for ctx in _MERGE_GROUP_CONTEXTS[:2])
    except _Unevaluable as why:
        errors.append(f"{fname}: {where} `cancel-in-progress` {cancel!r} {why}; check 13 cannot prove merge-group runs never stall")
        return
    if not cancels:
        errors.append(
            f"{fname}: {where} concurrency group {group!r} is the same for a re-queued merge-group run and its stale run "
            "and does not cancel in progress on merge_group — the new run waits behind the stale one; "
            "set `cancel-in-progress` true on merge_group or key the group by `github.sha`"
        )


def check_push_concurrency(errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 13 (see the module docstring). Unparseable workflows are refused
    by check 6."""
    seen: set[str] = set()
    for path in sorted(p for pattern in ("*.yml", "*.yaml") for p in glob.glob(os.path.join(root, "workflows", pattern))):
        fname = os.path.basename(path)
        try:
            with open(path) as f:
                doc = strict_yaml.safe_load(f)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        triggers = _triggers(doc)
        if triggers is None:
            errors.append(f"{fname}: `on:` has no recognised shape; check 13 cannot tell whether it runs on push or merge_group")
            continue
        on_push = "push" in triggers
        on_merge_group = "merge_group" in triggers
        if on_push:
            seen.add(fname)
        if not on_merge_group and (not on_push or fname in LATEST_WINS_PUSH_GROUPS):
            continue
        jobs = doc.get("jobs")
        sites = [("workflow", doc.get("concurrency"))] + [
            (f"job {jid!r}", job.get("concurrency"))
            for jid, job in (jobs.items() if isinstance(jobs, dict) else ())
            if isinstance(job, dict)
        ]
        for where, conc in sites:
            if conc is None:
                continue
            group = conc.get("group") if isinstance(conc, dict) else conc
            if not isinstance(group, str):
                errors.append(f"{fname}: {where} `concurrency:` has no string `group`")
                continue
            if on_merge_group:
                cancel = conc.get("cancel-in-progress") if isinstance(conc, dict) else None
                _check_merge_group_site(fname, where, group, cancel, errors)
            if not on_push or fname in LATEST_WINS_PUSH_GROUPS:
                continue
            try:
                a, b = (_event_group(group, ctx) for ctx in _PUSH_CONTEXTS)
            except _Unevaluable as why:
                errors.append(f"{fname}: {where} concurrency group {group!r} {why}; check 13 cannot prove each push commit gets its own group")
                continue
            if a == b:
                errors.append(
                    f"{fname}: {where} concurrency group {group!r} is the same for two pushes to one branch — "
                    "a newer push replaces the older commit's queued run, so that commit never reports; "
                    "key push groups by `github.sha`"
                )
    for fname in sorted(set(LATEST_WINS_PUSH_GROUPS) - seen):
        errors.append(f"check 13: LATEST_WINS_PUSH_GROUPS names {fname}, which is not a push-triggered workflow")


_LOCK_PACKAGE = re.compile(r"^\[\[package\]\]\s*$", re.M)
_LOCK_FIELD = re.compile(r'^(name|source) = "([^"]*)"\s*$', re.M)


def _lock_path_packages(text: str) -> set[str] | str:
    """The path packages (no `source`) a `Cargo.lock` resolves, or why the
    text is refused as a lock."""
    blocks = _LOCK_PACKAGE.split(text)
    if len(blocks) < 2:
        return "declares no [[package]]"
    names: set[str] = set()
    for i, block in enumerate(blocks[1:], 1):
        body = block.split("\n[", 1)[0]
        fields: dict[str, list[str]] = {}
        for m in _LOCK_FIELD.finditer(body):
            fields.setdefault(m.group(1), []).append(m.group(2))
        name = fields.get("name", [])
        if len(name) != 1 or len(fields.get("source", [])) > 1:
            return f"[[package]] #{i} has no single name/source"
        if not fields.get("source"):
            names.add(name[0])
    return names


def check_one_lock_per_graph(
    errors: list[str], root: str = REPO_ROOT, tracked: list[str] | None = None
) -> None:
    """Check 14 (see the module docstring). `tracked` defaults to the
    repository's `git ls-files`."""
    repo = os.path.dirname(root)
    if tracked is None:
        tracked = _tracked_paths(repo)
        if tracked is None:
            errors.append("check 14: `git ls-files` failed; cannot prove one lock per dependency graph")
            return
    tracked_set = set(tracked)
    locks = sorted(p for p in tracked if posixpath.basename(p) == "Cargo.lock")
    if "Cargo.lock" not in locks:
        errors.append("check 14: the root Cargo.lock is not tracked — the workspace graph has no lock")
        return
    packages: dict[str, set[str]] = {}
    for lock in locks:
        try:
            with open(os.path.join(repo, lock), encoding="utf-8") as f:
                parsed = _lock_path_packages(f.read())
        except (OSError, UnicodeDecodeError) as e:
            parsed = f"unreadable ({e})"
        if isinstance(parsed, str):
            errors.append(f"check 14: {lock}: {parsed}; refused")
            continue
        packages[lock] = parsed
    root_pkgs = packages.get("Cargo.lock")
    if root_pkgs is None:
        return
    authoritative = {"Cargo.lock"}
    for lock, pkgs in packages.items():
        if lock == "Cargo.lock":
            continue
        shared = sorted(pkgs.intersection(root_pkgs))
        if shared:
            errors.append(
                f"check 14: {lock} resolves {', '.join(shared)}, which the root Cargo.lock "
                "also resolves — one dependency graph with two locks drifts the first "
                "time an update rewrites only one; make the crate a workspace member "
                "and delete this lock"
            )
        else:
            authoritative.add(lock)

    path = os.path.join(root, "dependabot.yml")
    try:
        with open(path) as f:
            doc = strict_yaml.safe_load(f)
    except FileNotFoundError:
        errors.append("check 14: .github/dependabot.yml is missing — nothing proposes updates to the root Cargo.lock")
        return
    except (OSError, yaml.YAMLError) as e:
        errors.append(f"check 14: .github/dependabot.yml refused: {e}")
        return
    updates = doc.get("updates") if isinstance(doc, dict) else None
    if not isinstance(updates, list):
        errors.append("check 14: .github/dependabot.yml has no `updates` list; refused")
        return
    dirs: list[object] = []
    for i, u in enumerate(updates):
        if not isinstance(u, dict):
            errors.append(f"check 14: .github/dependabot.yml updates[{i}] is not a mapping; refused")
            continue
        if u.get("package-ecosystem") != "cargo":
            continue
        one, many = u.get("directory"), u.get("directories")
        if (one is None) == (many is None) or (many is not None and not isinstance(many, list)):
            errors.append(
                f"check 14: .github/dependabot.yml updates[{i}] (cargo) needs exactly one of "
                "`directory` or a `directories` list; refused"
            )
            continue
        dirs.extend([one] if many is None else many)
    for d in dirs:
        if not isinstance(d, str) or not d.startswith("/") or any(c in d for c in "*?[{"):
            errors.append(
                f"check 14: .github/dependabot.yml cargo directory {d!r} is not a literal "
                "absolute path; refused"
            )
            continue
        rel = d.strip("/")
        lock = posixpath.join(posixpath.normpath(rel), "Cargo.lock") if rel else "Cargo.lock"
        if lock not in tracked_set:
            errors.append(
                f"check 14: .github/dependabot.yml cargo directory {d!r} holds no tracked "
                "Cargo.lock — its updates would rewrite a manifest no lock of its own governs"
            )
        elif lock not in authoritative:
            errors.append(
                f"check 14: .github/dependabot.yml cargo directory {d!r} updates {lock}, a "
                "second lock over the root workspace graph; refused"
            )
    if "/" not in dirs:
        errors.append("check 14: .github/dependabot.yml proposes no cargo update for the root Cargo.lock")


# The most Dependabot version-update PRs open at once, over every ecosystem:
# the repository keeps at most three PRs open, so update PRs may hold all of
# that budget only when nothing else is in flight.
DEPENDABOT_OPEN_PR_BUDGET = 3


def check_dependabot_pr_budget(errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 18 (see the module docstring)."""
    path = os.path.join(root, "dependabot.yml")
    try:
        with open(path) as f:
            doc = strict_yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        errors.append(f"check 18: .github/dependabot.yml refused: {e}")
        return
    updates = doc.get("updates") if isinstance(doc, dict) else None
    if not isinstance(updates, list):
        errors.append("check 18: .github/dependabot.yml has no `updates` list; refused")
        return
    total = 0
    for i, u in enumerate(updates):
        eco = u.get("package-ecosystem") if isinstance(u, dict) else None
        limit = u.get("open-pull-requests-limit") if isinstance(u, dict) else None
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            errors.append(
                f"check 18: .github/dependabot.yml updates[{i}] ({eco}) needs an integer "
                f"`open-pull-requests-limit` of at least 1, not {limit!r} — an absent limit "
                "means 5 and 0 disables its updates; refused"
            )
            continue
        many = u.get("directories")
        total += limit * (len(many) if isinstance(many, list) and many else 1)
    if total > DEPENDABOT_OPEN_PR_BUDGET:
        errors.append(
            f"check 18: .github/dependabot.yml allows {total} open update PRs over its "
            f"directories, more than DEPENDABOT_OPEN_PR_BUDGET ({DEPENDABOT_OPEN_PR_BUDGET}); "
            "lower an `open-pull-requests-limit`"
        )


# Check 19: the workspace members that keep their own edition and lint table,
# each with its reason. Every other member inherits both from the root.
WORKSPACE_INHERIT_EXEMPT = {
    "src/runtime/rust": (
        "vendored verbatim into every emitted project, where no workspace root "
        "exists to inherit from; it carries its own stricter runtime lint table"
    ),
    "tools/ipe-ffi-inspector": (
        "a CLI whose exit-on-error paths use unwrap/expect/panic under the "
        "token-level panic-scan gate, so its own table relaxes those three lints"
    ),
}


def _load_toml(path: str) -> dict[str, object] | str:
    """`path` parsed as TOML, or the reason it cannot be."""
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return "is missing"
    except (OSError, tomllib.TOMLDecodeError) as e:
        return f"is unreadable ({e})"


def check_workspace_inheritance(errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 19 (see the module docstring)."""
    repo = os.path.dirname(root)
    top = _load_toml(os.path.join(repo, "Cargo.toml"))
    if isinstance(top, str):
        errors.append(f"check 19: the root Cargo.toml {top}; refused")
        return
    ws = top.get("workspace")
    members = ws.get("members") if isinstance(ws, dict) else None
    pkg = ws.get("package") if isinstance(ws, dict) else None
    edition = pkg.get("edition") if isinstance(pkg, dict) else None
    lints = ws.get("lints") if isinstance(ws, dict) else None
    if not isinstance(members, list) or not isinstance(edition, str) or not isinstance(lints, dict) or not lints:
        errors.append(
            "check 19: the root Cargo.toml needs a `[workspace] members` list, a "
            "`[workspace.package] edition` and a `[workspace.lints]` table; refused"
        )
        return
    seen: set[str] = set()
    for m in members:
        if not isinstance(m, str) or not m or any(c in m for c in "*?[{") or posixpath.normpath(m) != m:
            errors.append(f"check 19: workspace member {m!r} is not a literal normalized path; refused")
            continue
        seen.add(m)
        where = f"{m}/Cargo.toml"
        doc = _load_toml(os.path.join(repo, m, "Cargo.toml"))
        if isinstance(doc, str):
            errors.append(f"check 19: {where} {doc}; refused")
            continue
        package = doc.get("package")
        own_edition = package.get("edition") if isinstance(package, dict) else None
        own_lints = doc.get("lints")
        if m in WORKSPACE_INHERIT_EXEMPT:
            if own_edition == {"workspace": True} and own_lints == {"workspace": True}:
                errors.append(
                    f"check 19: WORKSPACE_INHERIT_EXEMPT names {m!r}, which inherits the "
                    "workspace edition and lints anyway; drop the stale exemption"
                )
            elif own_edition != edition:
                errors.append(
                    f"check 19: {where} is exempt from inheriting, so its literal edition "
                    f"must equal the workspace's {edition!r}, not {own_edition!r}"
                )
            elif not isinstance(own_lints, dict) or not own_lints or "workspace" in own_lints:
                errors.append(f"check 19: {where} is exempt from inheriting, so it must carry its own `[lints]` table")
            continue
        if own_edition != {"workspace": True}:
            errors.append(
                f"check 19: {where} sets edition {own_edition!r}; a workspace member "
                "inherits it (`edition.workspace = true`)"
            )
        if own_lints != {"workspace": True}:
            errors.append(
                f"check 19: {where} does not inherit the workspace lint policy; it needs "
                "`[lints]` with only `workspace = true`"
            )
    for m in sorted(set(WORKSPACE_INHERIT_EXEMPT) - seen):
        errors.append(f"check 19: WORKSPACE_INHERIT_EXEMPT names {m!r}, which is not a workspace member; drop it")


TEST_CLAIMS = ("ci", "test-claims.yml")
# The count harness runs after the build, so it lives outside the pre-tool
# `.github/ci` tree (check 7); this check proves its wiring from that tree.
WASM_COUNT_SCRIPT = "tools/scripts/wasm-test/wasm_test_count.py"
# Per claimable platform: the runner env key, its value, and the tool (a
# `Cargo.lock` package) whose install provides that runner.
WASM_RUNNERS: dict[str, tuple[str, str, str]] = {
    "wasm32-unknown-unknown": ("CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER", "wasm-bindgen-test-runner", "wasm-bindgen"),
}
WASM_RUNNER_CRATES = frozenset({"wasm-bindgen-cli"})
_TOOL_INSTALLER = "taiki-e/install-action"
# The one step `if:` a claim step may carry: the release-only trivial pass.
_CLAIM_STEP_GUARDS = frozenset({"needs.changes.outputs.release_only != 'true'"})
_TEST_RUNS = frozenset({"test", "nextest run", "bench"})
# Options that change the manifest, directory, or config a claimed run reads.
_CLAIM_REDIRECTING = frozenset({"--config", "-C", "-Z", "--manifest-path"})
# The env a claim step may run under, beyond its platform's runner key: per
# key, the values it may hold (`None`: any value). Every other key is refused,
# since cargo, rustc, a build script or the runner could read it to change
# which tests compile or run at an equal count.
_CLAIM_ENV: dict[str, frozenset[str] | None] = {
    "RUSTFLAGS": frozenset({""}),
    "CHROMEDRIVER": frozenset({"chromedriver"}),
    "CARGO_TERM_COLOR": frozenset({"always", "never", "auto"}),
    "CARGO_INCREMENTAL": frozenset({"0", "1"}),
    # Read by other steps of the job (the `ipe` CLI, the geo-clipboard and
    # layout-fill servers); neither cargo nor rustc reads them, and no build
    # script of the tree does (`test_inert_claim_env_unread_by_build_scripts`).
    "IPE_RUNTIME_DIR": None,
    "IPE_GEO_CLIPBOARD_PORT": None,
    "IPE_LAYOUT_FILL_PORT": None,
}
# The `.cargo/config.toml` a claimed run reads: its admitted tables, the keys
# of `[build]` and of a `[target]` table that applies to the claim platform,
# and the `-C` codegen options its rustflags may pass.  None sets a `cfg`
# (`opt-level` is out: rustc derives `debug_assertions` from it when cargo
# passes no `-C debug-assertions`).
_CLAIM_CONFIG_TABLES = frozenset({"build", "target", "term", "net", "http"})
_CLAIM_CONFIG_BUILD = frozenset({"rustflags", "target", "target-dir", "jobs", "incremental"})
_CLAIM_CONFIG_TARGET = frozenset({"rustflags"})
_CLAIM_CODEGEN = frozenset({"debuginfo", "strip", "codegen-units"})
_TOOL_SPLIT = re.compile(r"[,\s]+")


def _lock_versions(repo: str, name: str) -> list[str] | str:
    """Every `Cargo.lock` version of package `name`, or why the lock is unreadable."""
    lock = _load_toml(os.path.join(repo, "Cargo.lock"))
    if isinstance(lock, str):
        return f"Cargo.lock {lock}"
    pkgs = lock.get("package")
    if not isinstance(pkgs, list):
        return "Cargo.lock has no `[[package]]` list"
    return sorted({p["version"] for p in pkgs if isinstance(p, dict) and p.get("name") == name and isinstance(p.get("version"), str)})


def _claim_env(scopes: tuple[dict, ...]) -> dict[str, object] | str:
    """The env a step runs under: the `env:` of each scope, later scopes
    winning; why not, when an `env:` is no mapping."""
    out: dict[str, object] = {}
    for scope in scopes:
        env = scope.get("env", {})
        if not isinstance(env, dict):
            return "an `env:` of its workflow, job or step is not a literal mapping"
        out.update({str(k): v for k, v in env.items()})
    return out


def _codegen_only(flags: object) -> str | None:
    """Why the rustflags `flags` (a string or a list of strings) could pass
    more than the `_CLAIM_CODEGEN` options, else None."""
    if isinstance(flags, str):
        words = flags.split()
    elif isinstance(flags, list) and all(isinstance(f, str) for f in flags):
        words = [w for f in flags for w in f.split()]
    else:
        return "is not a string or a list of strings"
    i = 0
    while i < len(words):
        word = words[i]
        if word in ("-C", "--codegen"):
            option, i = (words[i + 1] if i + 1 < len(words) else ""), i + 2
        elif word.startswith("--codegen="):
            option, i = word.removeprefix("--codegen="), i + 1
        elif word.startswith("-C"):
            option, i = word.removeprefix("-C"), i + 1
        else:
            return f"passes {word!r}"
        if option.split("=", 1)[0] not in _CLAIM_CODEGEN:
            return f"passes `-C {option}`"
    return None


def _claim_config(repo: str, platform: str) -> str | None:
    """Why the checkout's cargo config could change what a claimed run on
    `platform` compiles, else None."""
    cargo_dir = os.path.join(repo, ".cargo")
    if os.path.lexists(os.path.join(cargo_dir, "config")):
        return "`.cargo/config` is a cargo config this check does not read"
    path = os.path.join(cargo_dir, "config.toml")
    if not os.path.lexists(path):
        return None
    cfg = _load_toml(path)
    if isinstance(cfg, str):
        return f"`.cargo/config.toml` {cfg}"
    extra = sorted(set(cfg) - _CLAIM_CONFIG_TABLES)
    if extra:
        return f"`.cargo/config.toml` sets {extra}, which this check does not read"
    build, targets = cfg.get("build", {}), cfg.get("target", {})
    if not isinstance(build, dict) or not isinstance(targets, dict):
        return "`.cargo/config.toml` [build] or [target] is not a table"
    tables: list[tuple[str, dict, frozenset[str]]] = [("[build]", build, _CLAIM_CONFIG_BUILD)]
    for triple, table in targets.items():
        if not isinstance(table, dict):
            return f"`.cargo/config.toml` [target.{triple}] is not a table"
        if triple == platform or triple.startswith("cfg("):
            tables.append((f"[target.{triple}]", table, _CLAIM_CONFIG_TARGET))
    for where, table, admitted in tables:
        extra = sorted(set(table) - admitted)
        if extra:
            return f"`.cargo/config.toml` {where} sets {extra}, which this check does not read"
        why = _codegen_only(table["rustflags"]) if "rustflags" in table else None
        if why is not None:
            return f"`.cargo/config.toml` {where} rustflags {why}, which could change the tests it compiles"
    return None


def _tool_pins(step: dict) -> list[str]:
    """The `tool:` items of a `taiki-e/install-action` step, else none."""
    uses = step.get("uses")
    if not uses_action(uses, _TOOL_INSTALLER):
        return []
    with_ = step.get("with")
    tool = with_.get("tool") if isinstance(with_, dict) else None
    return [t for t in _TOOL_SPLIT.split(tool) if t] if isinstance(tool, str) else []


@dataclass(frozen=True)
class ClaimRun:
    """A claim step, read once: the cell its bare `cargo test` runs exactly,
    under an env of only `_CLAIM_ENV` keys and the platform's runner, in the
    checkout root, with a cargo config that cannot change what it compiles."""

    cell: claims_table.Cell
    runner_crate: str


def _claimed_cell(
    cmd: shell_lex.Command, run: str, by_key: dict[tuple[str, str, str], claims_table.Cell]
) -> claims_table.Cell | str:
    """The cell the pipeline ending in `cmd` runs exactly, else why none."""
    if "${{" in run:
        return "its `run:` holds a workflow expression"
    src = cmd.pipe_source
    if src is None:
        return "its runner output is not piped into the count"
    if shell_lex.trim(run) != f"{' '.join(src)} | {' '.join(cmd.words)}":
        return "its `run:` is not exactly `cargo test … | python3 " + WASM_COUNT_SCRIPT + " N`"
    words = shell_lex.literal_words(src + cmd.words)
    if isinstance(words, str):
        return (
            f"its word {words!r} is not literal (only [{shell_lex.LITERAL_WORD_CHARS}]), "
            "so the shell could expand it into arguments this check does not read"
        )
    if src[:1] != ["cargo"]:
        return "its runner command is not a bare `cargo` (no env assignment, wrapper, or path)"
    args = [w.text for w in words[1 : len(src)]]
    if "--" in args:
        return "it passes arguments after `--`, which this check does not read"
    redirecting = next((w for w in args if cargo_invocation._option(w, _CLAIM_REDIRECTING, frozenset()) is not None), None)
    if redirecting is not None:
        return f"its {redirecting!r} changes what cargo reads, which this check does not follow"
    inv = cargo_invocation.parse(args)
    if isinstance(inv, str):
        return f"its runner command is unreadable: {inv}"
    if inv.toolchain is not None:
        return f"it picks toolchain `+{inv.toolchain}`, whose cfgs and build scripts may differ from the pinned one"
    if inv.subcommand not in _TEST_RUNS:
        return f"`cargo {inv.subcommand}` runs no test"
    if len(inv.packages) != 1 or inv.workspace:
        return "it does not select exactly one package by `-p`"
    sel = inv.selection
    if sel == cargo_invocation.ExplicitTargets(lib=True):
        target = "lib"
    elif isinstance(sel, cargo_invocation.ExplicitTargets) and len(sel.tests) == 1 and sel == cargo_invocation.ExplicitTargets(tests=sel.tests):
        target = "test:" + next(iter(sel.tests))
    else:
        return "it does not select exactly one target (`--lib` or one `--test`)"
    if not inv.target:
        return "it names no `--target`, so it tests the host"
    key = (inv.packages[0], target, inv.target)
    cell = by_key.get(key)
    if cell is None:
        return f"it tests {' '.join(key)}, which no cell of test-claims.yml lists"
    missing = cell.features - inv.features
    if missing and not inv.all_features:
        return f"it lacks feature(s) {sorted(missing)} the cell is counted under"
    if inv.filtered or inv.no_run:
        return "it filters or skips the tests it counts"
    if cmd.words[2:] != [str(cell.expect_tests)]:
        return f"it counts {' '.join(cmd.words[2:])!r}, but the cell claims {cell.expect_tests}"
    return cell


def _claim_run(
    cmd: shell_lex.Command,
    run: str,
    scopes: tuple[dict, dict, dict],
    job_id: str,
    repo: str,
    by_key: dict[tuple[str, str, str], claims_table.Cell],
) -> ClaimRun | str:
    """The claim the step `scopes[2]` (of job `job_id`, workflow and job
    `scopes[:2]`) makes with the pipeline ending in `cmd`, else the refusal."""
    cell = _claimed_cell(cmd, run, by_key)
    if isinstance(cell, str):
        return f"pipes a test run into the count, but {cell}"
    wf, job, st = scopes
    claim = f"claims {' '.join(cell.key)}, but"
    if cell.owner != job_id:
        return f"{claim} the cell's owner is {cell.owner!r}, not this job"
    if "container" in job:
        return f"{claim} its job runs in a `container:`, whose image and `container.env` env this check does not read"
    if st.get("shell") != "bash":
        return f"{claim} it lacks `shell: bash`, so a failing runner would not fail the pipeline"
    if st.get("continue-on-error", False) is not False or job.get("continue-on-error", False) is not False:
        return f"{claim} a `continue-on-error` would let a red count pass"
    if "working-directory" in st or _default_wd(job) is not None or _default_wd(wf) is not None:
        return f"{claim} it sets a `working-directory`, so cargo reads another directory's config"
    if "if" in st and st["if"] not in _CLAIM_STEP_GUARDS:
        return f"{claim} its `if: {st['if']}` could skip the count"
    runner = WASM_RUNNERS.get(cell.platform)
    if runner is None:
        return f"{claim} platform {cell.platform} has no runner this check proves"
    env = _claim_env(scopes)
    if isinstance(env, str):
        return f"{claim} {env}"
    if env.get(runner[0]) != runner[1]:
        return f"{claim} {runner[0]} is not {runner[1]!r} for this step"
    for key, value in sorted(env.items()):
        if key == runner[0]:
            continue
        if key not in _CLAIM_ENV:
            return f"{claim} its env sets {key}, which could change the tests cargo compiles or the runner runs"
        admitted = _CLAIM_ENV[key]
        if not isinstance(value, str) or (admitted is not None and value not in admitted):
            return f"{claim} its env sets {key} to {value!r}, not one of {sorted(admitted or ())}"
    why = _claim_config(repo, cell.platform)
    if why is not None:
        return f"{claim} {why}"
    return ClaimRun(cell, runner[2])


def check_test_claims(errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 20 (see the module docstring)."""
    repo = os.path.dirname(root)
    cells = claims_table.load_cells(os.path.join(root, *TEST_CLAIMS))
    if isinstance(cells, str):
        errors.append(f"check 20: {cells}; refused")
        return
    by_key = {c.key: c for c in cells}
    tool_versions: dict[str, str] = {}
    for tool in sorted({t for _, _, t in WASM_RUNNERS.values()}):
        got = _lock_versions(repo, tool)
        if isinstance(got, str) or len(got) != 1:
            errors.append(f"check 20: Cargo.lock must hold exactly one {tool} version, got {got!r}; refused")
            return
        tool_versions[tool] = got[0]
    claims: dict[tuple[str, str, str], list[str]] = {c.key: [] for c in cells}
    owner_jobs: dict[str, tuple[str, dict]] = {}
    for wf in _load_workflows(root, errors):
        for wj in wf.jobs:
            job, loc_job = wj.raw, f"{wf.fname}: job {wj.job_id!r}"
            steps = job.get("steps") if isinstance(job.get("steps"), list) else []
            claimed_lines: list[str] = []
            pinned: set[str] = set()
            for i, st in enumerate(steps):
                if not isinstance(st, dict):
                    continue
                loc = f"{loc_job} step {i} ({st.get('name') or st.get('uses') or '<unnamed>'})"
                for pin in _tool_pins(st):
                    name = pin.split("@", 1)[0]
                    if name in tool_versions:
                        if pin != f"{name}@{tool_versions[name]}":
                            errors.append(
                                f"check 20: {loc} installs {pin!r}; the runner must be "
                                f"{name}@{tool_versions[name]}, the Cargo.lock version; refused"
                            )
                        else:
                            pinned.add(name)
                run = st.get("run")
                if not isinstance(run, str):
                    continue
                for text in _shell_texts(run):
                    for cmd in shell_lex.split_commands(text):
                        if not any(os.path.basename(w) == "wasm_test_count.py" for w in cmd.words):
                            continue
                        words = cmd.words
                        if len(words) != 3 or words[:2] != ["python3", WASM_COUNT_SCRIPT]:
                            errors.append(
                                f"check 20: {loc} runs the count as {' '.join(words)!r}, not "
                                f"`python3 {WASM_COUNT_SCRIPT} N`; refused"
                            )
                            continue
                        claim = _claim_run(cmd, run, (wf.doc, job, st), wj.job_id, repo, by_key)
                        if isinstance(claim, str):
                            errors.append(f"check 20: {loc} {claim}; refused")
                            continue
                        key, crate = claim.cell.key, claim.runner_crate
                        if crate not in pinned:
                            errors.append(
                                f"check 20: {loc} claims {' '.join(key)}, but no earlier step of the job "
                                f"installs {crate}@{tool_versions.get(crate, '?')}; refused"
                            )
                            continue
                        claimed_lines.append(" ".join(cmd.pipe_source or []))
                        claims[key].append(loc)
                        owner_jobs[wj.job_id] = (wf.fname, job)
            for found in _job_cargo(job, repo, wf.doc):
                inv = found.invocation
                if isinstance(inv, str):
                    if "wasm32" in found.line:
                        errors.append(f"check 20: {loc_job} runs `{found.line}`, which this check cannot read: {inv}; refused")
                    continue
                if inv.subcommand == "install" and any(c.split("@", 1)[0] in WASM_RUNNER_CRATES for c in inv.install_crates):
                    errors.append(
                        f"check 20: {loc_job} runs `{found.line}`; install the runner through the pinned "
                        f"{_TOOL_INSTALLER} step instead; refused"
                    )
                if inv.subcommand not in _TEST_RUNS or inv.no_run or not (inv.target or "").startswith("wasm32"):
                    continue
                if found.line in claimed_lines:
                    claimed_lines.remove(found.line)
                    continue
                errors.append(
                    f"check 20: {loc_job} runs `{found.line}` on a wasm32 target outside a claim step; "
                    f"pipe it into {WASM_COUNT_SCRIPT} under a cell of test-claims.yml; refused"
                )
    for key, locs in claims.items():
        if not locs:
            errors.append(f"check 20: cell {' '.join(key)} is claimed by no step of its owner {by_key[key].owner!r}; refused")
        elif len(locs) > 1:
            errors.append(f"check 20: cell {' '.join(key)} is claimed by {len(locs)} steps ({'; '.join(locs)}); refused")
    if not owner_jobs:
        return
    try:
        with open(os.path.join(root, "ci", "check-manifest.yml")) as f:
            manifest = strict_yaml.safe_load(f)
        with open(os.path.join(root, "ci", "required-set.json")) as f:
            required = {c for c, _ in check_required_set.parse_pairs(json.load(f), "ci/required-set.json")}
    except (OSError, ValueError, yaml.YAMLError, check_required_set.Refused) as e:
        errors.append(f"check 20: the manifest or required set is unreadable: {e}; refused")
        return
    entries = manifest.get("checks") if isinstance(manifest, dict) else None
    entries = [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []
    for job_id, (fname, job) in sorted(owner_jobs.items()):
        name = job.get("name", job_id)
        if not isinstance(name, str) or "${{" in name:
            errors.append(f"check 20: owner job {job_id!r} has no literal context name; refused")
            continue
        # An owner job reports either as its own context or through the one
        # entry whose `aggregates:` names it (check 1), whose verdict it inherits.
        entry = next((e for e in entries if e.get("context") == name), None) or next(
            (e for e in entries if {name, job_id} & set(e.get("aggregates") or [])), None
        )
        disp = entry.get("disposition") if entry else None
        if entry is None or entry.get("producer") != fname:
            errors.append(f"check 20: owner job {job_id!r} ({name!r}) has no manifest entry produced by {fname}; refused")
        elif not (disp == "gate" and entry.get("context") in required) and disp != "nightly-gate":
            errors.append(
                f"check 20: owner job {job_id!r} ({name!r}) is {disp!r}, not a required gate or a "
                "nightly-gate, so its red count blocks nothing; refused"
            )


IPE_BUILD_PRODUCER = "build-tools"
IPE_BUILD_ARTIFACTS = frozenset({"ci-ipe-release", "ci-build-tools"})
IPE_RELEASE_ARTIFACT = "ci-ipe-release"
IPE_PACKAGE = "ipe"
IPE_PACKAGE_DIR = "src/ipe-cli"
# Cargo subcommands that compile the selected package's binary.
_CARGO_COMPILES = frozenset({"build", "run", "rustc", "install"})
WORKFLOW_PATTERNS = ("*.yml", "*.yaml")


def _workflow_files(root: str) -> list[str]:
    """Every workflow file under `root`, both extensions."""
    return sorted(f for pat in WORKFLOW_PATTERNS for f in glob.glob(os.path.join(root, "workflows", pat)))


def _local_action_files(root: str) -> list[str]:
    """Every local composite action definition under `root`, both extensions."""
    return sorted(
        f for name in ("action.yml", "action.yaml") for f in glob.glob(os.path.join(root, "actions", "*", name))
    )


def _names_ipe_dir(path: str) -> bool:
    """`path` (a manifest or a crate directory) is the `ipe` package's."""
    p = posixpath.normpath(path.removesuffix("/Cargo.toml") if path.endswith("/Cargo.toml") else path)
    return p == IPE_PACKAGE_DIR or p.endswith("/" + IPE_PACKAGE_DIR)


def _default_wd(container: dict) -> str | None:
    defaults = container.get("defaults")
    run = defaults.get("run") if isinstance(defaults, dict) else None
    wd = run.get("working-directory") if isinstance(run, dict) else None
    return wd if isinstance(wd, str) else None


def _steps_cargo(
    steps: object, repo: str, wd: str | None, depth: int = 0, unconditional: bool = False
) -> list[cargo_invocation.Found]:
    """Every cargo invocation `steps` run, each with its directory: every
    `run:` (here-document bodies included) from its `working-directory` (else
    `wd`), and the steps of each local composite action a step `uses`. With
    `unconditional`, a step (at any action depth) that has an `if:` or a
    masking `continue-on-error` is left out: it can be skipped or fail while
    its job succeeds."""
    out: list[cargo_invocation.Found] = []
    for st in steps if isinstance(steps, list) else []:
        if not isinstance(st, dict):
            continue
        if unconditional and not _unconditional_step(st):
            continue
        uses = st.get("uses")
        if isinstance(uses, str) and uses.startswith("./"):
            target = posixpath.normpath(uses.split("@", 1)[0])
            found = [os.path.join(repo, target, n) for n in ("action.yml", "action.yaml")]
            found = [f for f in found if os.path.isfile(f)]
            if depth >= LOCAL_ACTION_DEPTH_LIMIT or len(found) != 1:
                why = "nests local actions too deep" if found else "has no single action.yml/action.yaml"
                out.append(cargo_invocation.Found(uses, f"local action {uses!r} {why}", None))
                continue
            try:
                with open(found[0]) as f:
                    action = strict_yaml.safe_load(f)
            except (OSError, yaml.YAMLError) as e:
                out.append(cargo_invocation.Found(uses, f"local action {uses!r} is unreadable: {e}", None))
                continue
            runs = action.get("runs") if isinstance(action, dict) else None
            if isinstance(runs, dict) and runs.get("using") == "composite":
                out.extend(_steps_cargo(runs.get("steps"), repo, None, depth + 1, unconditional))
            continue
        run = st.get("run")
        if not isinstance(run, str):
            continue
        step_wd = st.get("working-directory")
        where = step_wd if isinstance(step_wd, str) else wd
        cwd = "" if where is None else cargo_invocation.resolve("", where)
        for text in _shell_texts(run):
            out.extend(cargo_invocation.in_shell(text, cwd))
    return out


def _job_cargo(job: dict, repo: str, doc: object, unconditional: bool = False) -> list[cargo_invocation.Found]:
    """Every cargo invocation of `job` (see `_steps_cargo`); its default
    directory is the job's `defaults.run.working-directory`, else the
    workflow's."""
    wd = _default_wd(job)
    if wd is None and isinstance(doc, dict):
        wd = _default_wd(doc)
    return _steps_cargo(job.get("steps"), repo, wd, unconditional=unconditional)


def _workspace_layout(repo: str, tracked: list[str] | None) -> cargo_invocation.Layout | str:
    """The root workspace `Layout`, or why it cannot be read."""
    if tracked is None:
        tracked = _tracked_paths(repo)
        if tracked is None:
            return "`git ls-files` failed"
    top = _load_toml(os.path.join(repo, "Cargo.toml"))
    if isinstance(top, str):
        return f"root Cargo.toml {top}"
    return cargo_invocation.layout(top, tracked, lambda d: _ignored(repo, posixpath.join(d, "Cargo.toml")))


def _ignored(repo: str, path: str) -> bool:
    """`path` matches the checkout's ignore rules; False when git cannot say
    (so a directory is never taken for build output without proof)."""
    try:
        done = subprocess.run(
            ["git", "-C", repo, "check-ignore", "-q", "--no-index", "--", path], capture_output=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def _ipe_build(found: cargo_invocation.Found, layout: cargo_invocation.Layout) -> bool | str:
    """Whether one invocation compiles the `ipe` package, or why that cannot
    be read."""
    inv = found.invocation
    if isinstance(inv, str):
        return inv
    if inv.subcommand not in _CARGO_COMPILES:
        return False
    if inv.subcommand == "install":
        if any(c.split("@", 1)[0] == IPE_PACKAGE for c in inv.install_crates):
            return True
        if inv.install_path is None:
            return False
        path = cargo_invocation.resolve(found.cwd, inv.install_path)
        return path == IPE_PACKAGE_DIR or _names_ipe_dir(inv.install_path)
    for spec in inv.packages:
        if any(c in spec for c in "*?["):
            return f"package spec {spec!r} is a pattern this check cannot resolve"
        name = spec.rsplit("#", 1)[-1].split("@", 1)[0]
        if name == IPE_PACKAGE or ("#" in spec and _names_ipe_dir(spec.split("#", 1)[0].split("://", 1)[-1])):
            return True
    if IPE_PACKAGE in inv.bins:
        return True
    if inv.manifest_path is not None and _names_ipe_dir(inv.manifest_path):
        return True
    sel = cargo_invocation.select(inv, found.cwd, layout)
    if isinstance(sel, str):
        return sel
    # `--workspace` where the manifest is unknown may be the root's: fail closed.
    return sel.whole_workspace or IPE_PACKAGE_DIR in sel.dirs or (inv.workspace and not sel.known)


def _builds_ipe(job: dict, repo: str, layout: cargo_invocation.Layout, doc: object = None) -> list[str]:
    """Each cargo command of `job` that compiles `ipe`, or a refusal for one
    this check cannot read."""
    hits: list[str] = []
    for found in _job_cargo(job, repo, doc):
        got = _ipe_build(found, layout)
        if got is True:
            hits.append(found.line)
        elif isinstance(got, str):
            hits.append(f"{found.line} (unreadable: {got})")
    return hits


def _artifact_steps(job: dict, action: str) -> set[str]:
    out: set[str] = set()
    for st in job.get("steps") or []:
        if not isinstance(st, dict):
            continue
        uses, with_ = st.get("uses"), st.get("with")
        if uses_action(uses, f"actions/{action}-artifact"):
            name = with_.get("name") if isinstance(with_, dict) else None
            out.add(name if isinstance(name, str) else "")
    return out


def check_one_ipe_build(errors: list[str], root: str = REPO_ROOT, tracked: list[str] | None = None) -> None:
    """Check 15 (see the module docstring). Refuses, never skips, a shape it
    cannot read."""
    repo = os.path.dirname(root)
    layout = _workspace_layout(repo, tracked)
    if isinstance(layout, str):
        errors.append(f"check 15: {layout}; cannot tell what a cargo command builds")
        return
    where = os.path.join(root, "workflows", FAST_GATE_WORKFLOW)
    try:
        with open(where) as f:
            doc = strict_yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        errors.append(f"check 15: cannot read {where}: {e}")
        return
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if not isinstance(jobs, dict):
        errors.append(f"check 15: {FAST_GATE_WORKFLOW} has no `jobs:` mapping")
        return
    producer = jobs.get(IPE_BUILD_PRODUCER)
    if not isinstance(producer, dict):
        errors.append(f"check 15: producer {IPE_BUILD_PRODUCER!r} is not a job of {FAST_GATE_WORKFLOW}")
    else:
        if not any("unreadable" not in h for h in _builds_ipe(producer, repo, layout, doc)):
            errors.append(f"check 15: producer {IPE_BUILD_PRODUCER!r} does not build the `ipe` package")
        if IPE_RELEASE_ARTIFACT not in _artifact_steps(producer, "upload"):
            errors.append(f"check 15: producer {IPE_BUILD_PRODUCER!r} does not upload {IPE_RELEASE_ARTIFACT!r}")
    for jid, job in jobs.items():
        if not isinstance(job, dict):
            errors.append(f"check 15: job {jid!r} is not a mapping; refused")
            continue
        if jid != IPE_BUILD_PRODUCER:
            for hit in _builds_ipe(job, repo, layout, doc):
                errors.append(
                    f"check 15: job {jid!r} compiles `ipe` ({hit!r}); only {IPE_BUILD_PRODUCER!r} "
                    f"builds it — download {IPE_RELEASE_ARTIFACT!r} instead"
                )
        downloads = _artifact_steps(job, "download")
        # A download with no literal `name` (all artifacts, or a `pattern`)
        # may fetch the producer's, so it needs the producer too.
        wanted = sorted(downloads.intersection(IPE_BUILD_ARTIFACTS) | ({"<unnamed>"} if "" in downloads else set()))
        if wanted:
            needs = _needs_list(job)
            if needs is None or IPE_BUILD_PRODUCER not in needs:
                errors.append(
                    f"check 15: job {jid!r} downloads {wanted} without `needs: {IPE_BUILD_PRODUCER}`; "
                    "it could start before the artifact exists"
                )


DRIFT_ASSERTION = drift_assertion.SCRIPT


def _untracked_blind_diffs(lines: list[str]) -> list[str]:
    """The drift assertions among the quote-removed commands in `lines` that
    are blind to a file git does not track yet (`drift_assertion.parse`)."""
    return [a.command for line in lines for a in drift_assertion.parse(line.split()) if not a.sees_untracked]


def check_drift_sees_untracked(errors: list[str], root: str = REPO_ROOT, manifest: str | None = None) -> None:
    """Check 17 (see the module docstring). Refuses, never skips, a file it
    cannot read."""
    fix = f"assert with {DRIFT_ASSERTION}, which also fails on untracked output"
    for wf in _workflow_files(root) + _local_action_files(root):
        name = os.path.relpath(wf, root)
        try:
            with open(wf) as f:
                doc = strict_yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            errors.append(f"check 17: cannot read {wf}: {e}")
            continue
        if not isinstance(doc, dict):
            errors.append(f"check 17: {name} is not a mapping; refused")
            continue
        jobs = doc.get("jobs")
        runs_ = doc.get("runs")
        groups = (
            [(f"job {jid!r}", job.get("steps") if isinstance(job, dict) else None) for jid, job in jobs.items()]
            if isinstance(jobs, dict)
            else [("composite steps", runs_.get("steps"))] if isinstance(runs_, dict) else []
        )
        for what, steps in groups:
            runs = [st["run"] for st in steps or [] if isinstance(st, dict) and isinstance(st.get("run"), str)]
            for line in _untracked_blind_diffs(_quote_removed(runs)):
                errors.append(f"check 17: {name} {what} runs `{line}`, blind to new generated files; {fix}")
    where = manifest or os.path.join(root, "ci", "check-manifest.yml")
    try:
        with open(where) as f:
            mdoc = strict_yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        errors.append(f"check 17: cannot read {where}: {e}")
        return
    checks = mdoc.get("checks") if isinstance(mdoc, dict) else None
    if not isinstance(checks, list):
        errors.append(f"check 17: {where} has no `checks:` list")
        return
    for entry in checks:
        local = entry.get("local") if isinstance(entry, dict) else None
        run = local.get("run") if isinstance(local, dict) else None
        cmds = [c.get("cmd") if isinstance(c, dict) else c for c in run or []]
        texts = [c for c in cmds if isinstance(c, str)]
        for line in _untracked_blind_diffs(_quote_removed(texts)):
            errors.append(f"check 17: manifest context {entry.get('context')!r} runs `{line}` locally, blind to new generated files; {fix}")


_SCOPE_REF = re.compile(r"needs\.changes\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)")
_LOCK_DEPS = re.compile(r"^dependencies = \[(.*?)^\]", re.M | re.S)
_MANIFEST_PACKAGE_NAME = re.compile(r'^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', re.M | re.S)
# A `../` literal that names something past its parents (`"../x"`, not `"../.."`).
_PARENT_LITERAL = re.compile(r'"(/?(?:\.\./)+[^"\\/.][^"\\]*)"')
# Cargo subcommands whose selection names packages to compile and run.
_CARGO_SELECTING = cargo_invocation.COMPILING - {"install", "package", "publish"}


def _lock_graph(text: str) -> dict[str, set[str]] | str:
    """Each path package of a `Cargo.lock` mapped to the path packages it
    depends on, or why the text is refused."""
    blocks = _LOCK_PACKAGE.split(text)
    if len(blocks) < 2:
        return "declares no [[package]]"
    deps: dict[str, list[str]] = {}
    for i, block in enumerate(blocks[1:], 1):
        name = re.search(r'^name = "([^"]+)"\s*$', block, re.M)
        if name is None:
            return f"[[package]] #{i} has no name"
        if re.search(r"^source = ", block, re.M):
            continue
        m = _LOCK_DEPS.search(block)
        listed = re.findall(r'"([^"]+)"', m.group(1)) if m else []
        deps.setdefault(name.group(1), []).extend(d.split(" ", 1)[0] for d in listed)
    return {n: {d for d in ds if d in deps} for n, ds in deps.items()}


def _selected_packages(
    job: dict, repo: str, layout: cargo_invocation.Layout, doc: object = None
) -> tuple[list[str], list[str]] | str:
    """The package names and member directories `job`'s cargo commands
    select, or why that selection cannot be read."""
    names: list[str] = []
    dirs: list[str] = []
    for found in _job_cargo(job, repo, doc):
        inv = found.invocation
        if isinstance(inv, str):
            return f"`{found.line}` is unreadable: {inv}"
        if inv.subcommand not in _CARGO_SELECTING:
            continue
        sel = cargo_invocation.select(inv, found.cwd, layout)
        if isinstance(sel, str):
            return sel
        if sel.whole_workspace:
            return f"`{found.line}` selects the whole workspace"
        if sel.bins and not sel.packages and not sel.dirs:
            return f"`{found.line}` selects by `--bin` alone; name its package with `-p`"
        for val in sel.packages:
            if not val or any(c in val for c in "*?[#") or "://" in val:
                return f"`{found.line}` has a package spec this check cannot resolve"
            names.append(val.split("@", 1)[0])
        dirs.extend(sel.dirs)
    return names, dirs


def check_scoped_package_coverage(
    errors: list[str], root: str = REPO_ROOT, tracked: list[str] | None = None
) -> None:
    """Check 16 (see the module docstring). Refuses, never skips, a shape it
    cannot read."""
    repo = os.path.dirname(root)
    if tracked is None:
        tracked = _tracked_paths(repo)
        if tracked is None:
            errors.append("check 16: `git ls-files` failed; cannot prove scoped jobs cover their packages")
            return
    layout = _workspace_layout(repo, tracked)
    if isinstance(layout, str):
        errors.append(f"check 16: {layout}; cannot tell what a cargo command compiles")
        return
    narrow = set(change_class.SCOPES) - {"code"}
    scoped: list[tuple[str, str, list[str], list[str], list[str]]] = []
    for wf in _workflow_files(root):
        name = os.path.basename(wf)
        try:
            with open(wf) as f:
                doc = strict_yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            errors.append(f"check 16: cannot read {wf}: {e}")
            continue
        jobs = doc.get("jobs") if isinstance(doc, dict) else None
        if not isinstance(jobs, dict):
            continue
        for jid, job in jobs.items():
            if not isinstance(job, dict) or not isinstance(job.get("if"), str):
                continue
            scopes = sorted(set(_SCOPE_REF.findall(job["if"])).intersection(narrow))
            if not scopes:
                continue
            got = _selected_packages(job, repo, layout, doc)
            if isinstance(got, str):
                errors.append(f"check 16: {name} job {jid!r} is scoped on {scopes} but {got}; refused")
                continue
            pkgs, pkg_dirs = got
            if pkgs or pkg_dirs:
                scoped.append((name, str(jid), scopes, pkgs, pkg_dirs))
    if not scoped:
        return

    try:
        with open(os.path.join(repo, "Cargo.lock"), encoding="utf-8") as f:
            graph = _lock_graph(f.read())
    except (OSError, UnicodeDecodeError) as e:
        graph = f"unreadable ({e})"
    if isinstance(graph, str):
        errors.append(f"check 16: root Cargo.lock: {graph}; refused")
        return
    dirs: dict[str, str] = {}
    for m in sorted(p for p in tracked if posixpath.basename(p) == "Cargo.toml"):
        try:
            with open(os.path.join(repo, m), encoding="utf-8") as f:
                found = _MANIFEST_PACKAGE_NAME.search(f.read())
        except (OSError, UnicodeDecodeError):
            found = None
        if found is None or found.group(1) not in graph:
            continue
        if found.group(1) in dirs:
            errors.append(f"check 16: package {found.group(1)!r} is declared by two manifests; refused")
            continue
        dirs[found.group(1)] = posixpath.dirname(m)

    by_dir = {d: n for n, d in dirs.items()}
    for wf, jid, scopes, pkgs, pkg_dirs in scoped:
        closure: set[str] = set()
        stack = list(pkgs)
        for d in pkg_dirs:
            if d not in by_dir:
                errors.append(f"check 16: {wf} job {jid!r} compiles {d!r}, not a path package of the root workspace")
                continue
            stack.append(by_dir[d])
        while stack:
            n = stack.pop()
            if n in closure:
                continue
            if n not in graph or n not in dirs:
                errors.append(f"check 16: {wf} job {jid!r} selects {n!r}, not a path package of the root workspace")
                closure.add(n)
                continue
            closure.add(n)
            stack.extend(graph[n])
        crate_dirs = sorted({dirs[n] for n in closure if n in dirs})
        reached: set[str] = set()
        for d in crate_dirs:
            prefix = d + "/" if d else ""
            for f in tracked:
                if not f.startswith(prefix):
                    continue
                reached.add(f)
                if not f.endswith(change_class.CODE_SUFFIXES):
                    continue
                try:
                    with open(os.path.join(repo, f), encoding="utf-8") as fh:
                        text = fh.read()
                except (OSError, UnicodeDecodeError):
                    continue
                for lit in _PARENT_LITERAL.findall(text):
                    for base in (d, posixpath.dirname(f)):
                        target = change_class._norm(posixpath.join(base, lit.lstrip("/")))
                        if target is None:
                            continue
                        under = target + "/" if target else ""
                        reached.update(t for t in tracked if t == target or t.startswith(under))
        # PROSE is proven unreachable by `change_class.guard()`, so it never counts.
        missed = sorted(
            f for f in reached if not change_class.is_prose(f) and not any(change_class.forces(sc, f) for sc in scopes)
        )
        if missed:
            shown = ", ".join(missed[:5]) + (f" (+{len(missed) - 5} more)" if len(missed) > 5 else "")
            errors.append(
                f"check 16: {wf} job {jid!r} skips unless {scopes} runs, yet it compiles or reads "
                f"{len(missed)} file(s) no such scope forces: {shown} — extend the scope in "
                ".github/ci/change_class.py"
            )


def _tracked_paths(repo: str) -> list[str] | None:
    try:
        out = subprocess.run(
            ["git", "-C", repo, "ls-files", "-z"], capture_output=True, check=True, timeout=60
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def check_trust_roots(errors: list[str], root: str = REPO_ROOT, tracked: list[str] | None = None) -> None:
    """Check 12b (see the module docstring). `tracked` defaults to the
    repository's `git ls-files`."""
    path = os.path.join(root, "CODEOWNERS")
    try:
        roots = trust_roots.load_codeowners(path)
    except FileNotFoundError:
        errors.append(".github/CODEOWNERS is missing — it is the trust-root SSOT")
        return
    except (OSError, trust_roots.CodeownersError) as e:
        errors.append(f".github/CODEOWNERS refused: {e}")
        return
    if tracked is None:
        tracked = _tracked_paths(os.path.dirname(root))
        if tracked is None:
            errors.append("check 12: `git ls-files` failed; cannot prove every CODEOWNERS rule is live")
            return
    for rule in roots.rules:
        if not any(rule.matches(p) for p in tracked):
            errors.append(
                f".github/CODEOWNERS line {rule.line}: {rule.pattern!r} matches no tracked file "
                "(a typo'd rule protects nothing)"
            )
    for p in TRUST_ROOT_MACHINERY:
        if not roots.is_trust_root(p):
            errors.append(f"{p} is not a trust root in .github/CODEOWNERS — the guard would not guard itself")
    for p in tracked:
        if p.startswith(".github/") and p not in TRUST_ROOT_MACHINERY and not roots.is_trust_root(p):
            errors.append(
                f"{p} is under .github/ but is not a trust root in .github/CODEOWNERS — "
                "GitHub reads workflows and actions from there, and the verifiers import "
                "their helpers from there"
            )
    for p in _STRAY_CODEOWNERS:
        if p in tracked:
            errors.append(f"{p}: a second CODEOWNERS file; .github/CODEOWNERS is the only trust-root list")
    for p in _ci_run_scripts(root, tracked):
        if not roots.is_trust_root(p):
            errors.append(
                f"{p} is run by CI but is not a trust root in .github/CODEOWNERS — "
                "an outside PR could rewrite what that gate proves"
            )


def _ci_run_scripts(root: str, tracked: list[str]) -> list[str]:
    """Tracked scripts (by `_SCRIPT_SUFFIXES`) that a workflow or local action
    names by their repository path, bare or `./`-prefixed. A script reached
    only through `working-directory:` plus a relative name is not seen."""
    scripts = [p for p in tracked if p.endswith(_SCRIPT_SUFFIXES)]
    if not scripts:
        return []
    texts: list[str] = []
    for pattern in ("workflows/*.yml", "workflows/*.yaml", "actions/**/*.yml", "actions/**/*.yaml"):
        for path in sorted(glob.glob(os.path.join(root, pattern), recursive=True)):
            with open(path, encoding="utf-8", errors="surrogateescape") as f:
                texts.append(f.read())
    found: set[str] = set()
    for p in scripts:
        pat = re.compile(r"(?:(?<=\./)|(?<![A-Za-z0-9_./-]))" + re.escape(p) + r"(?![A-Za-z0-9_./-])")
        if any(pat.search(t) for t in texts):
            found.add(p)
    return sorted(found)


def _env_keys_folded(env: dict) -> set[str]:
    return {str(k).casefold() for k in env}


def _scoped_env(container: dict, loc: str, errors: list[str]) -> dict:
    """Extract an `env:` mapping at one scope (workflow/job/step/container/
    service), failing CLOSED when `env:` is present but not a plain mapping
    (e.g. `env: ${{ fromJSON(vars.E) }}`) — such a value's keys cannot be
    determined statically, so "it does not set a rustc-wiring key" cannot
    be proven and must never be assumed (PRINCIPLES §1: fail closed absent
    proof of safety). A missing `env:` is simply empty, not an error.
    """
    if not isinstance(container, dict) or "env" not in container:
        return {}
    e = container["env"]
    if isinstance(e, dict):
        return e
    errors.append(
        f"{loc}: env: is not a plain mapping (got {type(e).__name__}: {e!r}) — "
        "cannot verify it does not set a rustc-wiring key; refused fail-closed"
    )
    return {}


@dataclass(frozen=True)
class StepPolicy:
    """Repo facts the per-step audits check against.

    `env_allowlist` holds the keys `ci/github-env.sh` may write; it is empty
    when the allowlist cannot be established, so every helper call is refused.
    `repo_top` is the checkout root a `working-directory:` resolves from.
    `workspace` is what the audited text's job may find in its workspace: the
    protected-tree write scan runs only where a checkout can exist.
    """

    env_allowlist: frozenset[str]
    repo_top: str
    workspace: Workspace


def _github_env_key_refusal(key: str) -> str | None:
    """Why `key` may never be an allowlisted env-file key, or None."""
    if not GITHUB_ENV_KEY_RE.match(key):
        return "is not a CI_JOB_-prefixed upper-case identifier"
    if RUSTC_WIRING_TEXT_RE.search(key):
        return "wraps or replaces rustc"
    if key in GITHUB_ENV_KEY_EXACT_REFUSED or key.startswith(GITHUB_ENV_KEY_REFUSED_PREFIXES):
        return "steers the runner, a toolchain, a loader, or an interpreter"
    return None


def load_github_env_allowlist(errors: list[str], root: str = REPO_ROOT) -> frozenset[str]:
    """The keys `ci/github-env.sh` may write, one per line.

    `#` comments and blank lines are skipped. A malformed, duplicate, or
    refused key is an error; an unreadable file is an error and yields the
    empty set (fail closed).
    """
    path = os.path.join(root, "ci", "github-env-allowlist.txt")
    where = os.path.relpath(path, os.path.dirname(root))
    try:
        with open(path) as f:
            lines = f.read().split("\n")
    except OSError as e:
        errors.append(f"{where}: cannot be read ({e}) — no env-file key can be allowed; refused")
        return frozenset()
    keys: set[str] = set()
    for n, line in enumerate(lines, 1):
        if line == "" or line.startswith("#"):
            continue
        why = _github_env_key_refusal(line)
        if why is not None:
            errors.append(f"{where}:{n}: key {line!r} {why}; refused")
        elif line in keys:
            errors.append(f"{where}:{n}: key {line!r} is listed twice; refused")
        else:
            keys.add(line)
    return frozenset(keys)


def _context_refusal(e: gha_expr.Expr) -> gha_expr.ContextRef | None:
    """The first `github`/`env` access in `e` that could reach a runner
    command file, or None: anything but a literal `.name`, and
    `github.<command-file property>`."""
    for node in gha_expr.walk(e):
        if not isinstance(node, gha_expr.ContextRef) or node.ctx.casefold() not in GITHUB_NAMED_CONTEXTS:
            continue
        first = node.path[0] if node.path else None
        if not isinstance(first, gha_expr.Prop):
            return node
        if node.ctx.casefold() == "github" and first.name.casefold() in GITHUB_RUNNER_FILE_PROPS:
            return node
    return None


def _parsed_expressions(text: str, bare_expression: bool) -> gha_expr.Template | gha_expr.Refusal:
    """Every expression in `text`; `bare_expression` marks an `if:` value."""
    return gha_expr.parse_condition(text) if bare_expression else gha_expr.parse_template(text)


def _runner_file_refusal(text: str, parsed: gha_expr.Template | gha_expr.Refusal) -> str | None:
    """The first spelling in `text` that reaches a runner command file, or None.

    Every match of `RUNNER_FILE_TEXT_RE` counts except an output/summary name
    inside its append-only shape; so does a legacy workflow command after
    quote removal, and every `github`/`env` access in a parsed expression
    other than a literal `.name` (and `github.<command-file property>`).
    """
    appends = [m.span() for m in RUNNER_APPEND_ONLY_TARGET_RE.finditer(text)]
    for m in RUNNER_FILE_TEXT_RE.finditer(text):
        if not any(lo <= m.start() and m.end() <= hi for lo, hi in appends):
            return m.group(0)
    for cmd in shell_lex.split_commands(text):
        m = LEGACY_COMMAND_RE.search(" ".join(cmd.words))
        if m is not None:
            return m.group(0)
    if isinstance(parsed, gha_expr.Template):
        for e, (lo, hi) in zip(parsed.exprs, parsed.spans):
            if _context_refusal(e) is not None:
                return text[lo:hi]
    return None


class ShellTextPosition(enum.Enum):
    """A step position whose text the runner expands `${{ }}` into before an
    interpreter parses it: a `run:` (shell), the `with.script` of
    `actions/github-script` (JavaScript), or an action input named in
    `ACTION_SHELL_INPUTS` (a script the action hands to a shell, e.g. the
    `with.run`/`with.prepare` a VM action runs inside the guest)."""

    RUN = "run"
    GITHUB_SCRIPT = "github-script"
    ACTION_INPUT = "action-input"


def _refuse_shell_expression(
    text: str, parsed: gha_expr.Template, position: ShellTextPosition, loc: str, what: str,
    errors: list[str],
) -> None:
    """Rule (j): no `${{ }}` in a shell-text position (`position`), whatever
    context it reads. The value enters as an `env:` entry the script reads by
    name, so no value, whoever controls it, becomes syntax."""
    match position:
        case ShellTextPosition.RUN:
            read = 'and read it as "$NAME" (bash) or $env:NAME (pwsh)'
        case ShellTextPosition.GITHUB_SCRIPT:
            read = "and read it as process.env.NAME"
        case ShellTextPosition.ACTION_INPUT:
            read = (
                "forward it with the action's own env input (e.g. `with.envs`), and read it "
                'as "$NAME"'
            )
    for lo, hi in parsed.spans:
        errors.append(
            f"{loc} {what} splices {text[lo:hi]!r} into shell text — the runner expands "
            f"`${{{{ }}}}` before the interpreter parses it; pass the value through the step's "
            f"`env:` {read}; refused"
        )


def _refuse_eval(text: str, loc: str, what: str, errors: list[str]) -> None:
    """Rule (j): no quote-removed word of `text` (here-document bodies
    included) is in `EVAL_WORDS` (case-folded): each re-parses an `env:`
    value as shell syntax."""
    for part in _shell_texts(text):
        for cmd in shell_lex.split_commands(part):
            if any(w.casefold() in EVAL_WORDS for w in cmd.words):
                errors.append(
                    f"{loc} {what} runs {' '.join(cmd.words)!r}, which names the `eval` builtin "
                    "(or pwsh `Invoke-Expression`) — it re-parses a value as shell syntax; refused"
                )


def _refuse_runner_file_text(
    text: str, parsed: gha_expr.Template | gha_expr.Refusal, loc: str, what: str,
    policy: StepPolicy, helper_ok: bool, errors: list[str],
) -> None:
    """Rule (f): the runner env file is written only by the canonical helper call.

    The call is honoured only in a step's `run:` (`helper_ok`) and must carry a
    bare allowlisted key; any other spelling of a runner command file, the
    legacy workflow commands, the helper itself, or a `GITHUB_WORKSPACE` write
    is refused.
    """
    if isinstance(parsed, gha_expr.Refusal):
        errors.append(
            f"{loc} {what} holds a `${{{{ }}}}` expression outside the expression grammar "
            f"({parsed.why}) — what it reads cannot be established; refused"
        )
    hit = _runner_file_refusal(text, parsed)
    if hit is not None:
        errors.append(
            f"{loc} {what} names {hit!r} — the runner env file is written only "
            f'through `bash "$GITHUB_WORKSPACE/.github/{GITHUB_ENV_HELPER}" KEY VALUE`, '
            "outputs/summaries only by appending to their exact variable; refused"
        )
    reads = [m.span() for m in GITHUB_WORKSPACE_READ_RE.finditer(text)]
    for m in GITHUB_WORKSPACE_MENTION_RE.finditer(text):
        if not any(lo <= m.start() and m.end() <= hi for lo, hi in reads):
            errors.append(
                f"{loc} {what} names {m.group(0)!r} other than as a plain read "
                "`$GITHUB_WORKSPACE` — it roots the env helper and requirements paths, "
                "so it is never assigned or overridden; refused"
            )
            break
    calls = list(GITHUB_ENV_HELPER_CALL_RE.finditer(text)) if helper_ok else []
    for mention in GITHUB_ENV_HELPER_MENTION_RE.finditer(text):
        if not any(c.start() <= mention.start() < c.end() for c in calls):
            errors.append(
                f"{loc} {what} references {GITHUB_ENV_HELPER} outside its one canonical call "
                f'`bash "$GITHUB_WORKSPACE/.github/{GITHUB_ENV_HELPER}" KEY VALUE` with a bare '
                "literal KEY in a step's run:; refused"
            )
            break
    for c in calls:
        key = c.group("key")
        if key not in policy.env_allowlist:
            errors.append(
                f"{loc} {what} writes env key {key!r}, which is not in "
                "ci/github-env-allowlist.txt; refused"
            )


def _pip_install_refusal(args: list[str]) -> str | None:
    """Why the `pip install` arguments `args` miss the hash-checked shape, or
    None when every argument is one the canonical install carries."""
    require_hashes = only_binary_all = False
    requirement_files = 0
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else None
        if a == "--require-hashes":
            require_hashes = True
        elif a == "--only-binary=:all:":
            only_binary_all = True
        elif a == "--only-binary" and nxt == ":all:":
            only_binary_all = True
            i += 1
        elif a in ("-r", "--requirement") and nxt is not None:
            if nxt != PIP_REQUIREMENTS_ARG:
                return f"requirements file {nxt!r} is not {PIP_REQUIREMENTS_ARG!r}"
            requirement_files += 1
            i += 1
        elif a != "--isolated":
            return f"argument {a!r} is outside the hash-checked shape"
        i += 1
    if requirement_files > 1:
        return f"it names -r/--requirement {requirement_files} times, not exactly once"
    if not (require_hashes and only_binary_all and requirement_files):
        return f"it lacks --require-hashes, --only-binary :all:, or -r {PIP_REQUIREMENTS_ARG}"
    return None


@dataclass(frozen=True)
class PipInvocation:
    """One shell command that runs pip, split at the pip token: the leading
    `NAME=value` assignments, the words up to and including pip (the
    interpreter and its flags), and pip's own arguments."""

    env_prefix: tuple[str, ...]
    interpreter: tuple[str, ...]
    args: tuple[str, ...]


def _parse_pip_invocation(tokens: list[str]) -> PipInvocation | None:
    """`tokens` as a pip invocation, or None when no word is pip."""
    at = next((i for i, t in enumerate(tokens) if PIP_TOKEN_RE.fullmatch(t)), None)
    if at is None:
        return None
    lead = 0
    while lead < at and SHELL_ASSIGNMENT_RE.match(tokens[lead]):
        lead += 1
    return PipInvocation(tuple(tokens[:lead]), tuple(tokens[lead : at + 1]), tuple(tokens[at + 1 :]))


def _canonical_pip() -> PipInvocation:
    """`CANONICAL_PIP_INSTALL` as a `PipInvocation`, lexed as the shell does."""
    cmds = shell_lex.split_commands(CANONICAL_PIP_INSTALL)
    inv = _parse_pip_invocation(cmds[0].words) if len(cmds) == 1 else None
    if inv is None:
        raise RuntimeError("CANONICAL_PIP_INSTALL is not one command naming pip")
    return inv


def _pip_invocation_refusal(inv: PipInvocation) -> str | None:
    """Why `inv` is not the canonical install nor a read-only query, or None."""
    canon = _canonical_pip()
    if not inv.args or inv.args[0].casefold() != "install":
        if len(inv.args) <= 1 and (not inv.args or inv.args[0] in PIP_READ_ONLY_COMMANDS):
            return None
        return f"pip subcommand {' '.join(inv.args)!r} is neither install nor a read-only query"
    why = _pip_install_refusal(list(inv.args[1:]))
    if why is not None:
        return why
    if inv.interpreter != canon.interpreter:
        return f"pip runs as {' '.join(inv.interpreter)!r}, not {' '.join(canon.interpreter)!r}"
    if inv.env_prefix != canon.env_prefix:
        return (
            f"its environment prefix {' '.join(inv.env_prefix)!r} is not "
            f"{' '.join(canon.env_prefix)!r} — config files and PIP_* would steer the install"
        )
    if inv.args != canon.args:
        return f"its arguments are not exactly {' '.join(canon.args)!r}"
    return None


def _shell_texts(text: str) -> list[str]:
    """`text` and every here-document body in it, nested bodies included
    (to `STRING_SCALAR_DEPTH_LIMIT` levels; each is strictly shorter)."""
    out, level = [text], [text]
    for _ in range(STRING_SCALAR_DEPTH_LIMIT):
        level = [body for t in level for body in shell_lex.heredoc_bodies(t)]
        if not level:
            break
        out.extend(level)
    return out


def _refuse_unhashed_pip(text: str, loc: str, what: str, errors: list[str]) -> None:
    """Rule (g): pip installs only as the one canonical, env-isolated command.

    `CANONICAL_PIP_INSTALL` is the only install: `PIP_CONFIG_FILE=/dev/null`
    and `--isolated` cut off every config file and `PIP_*` variable, and
    `--require-hashes --only-binary :all: -r <requirements>` hash-checks
    every byte with no build backend. Outside that exact text, a `PIP_*`
    name, a pip config file, or an installer outside pip's hash checking is
    refused. Every command of the text, and of each here-document body
    (lexed as shell too, since a body may be fed to one), is judged on its
    quote-removed words (`shell_lex`), so `p""ip` is `pip`: a command with
    a word naming pip is parsed as a `PipInvocation` and compared with the
    canonical one.
    """
    rest = CANONICAL_PIP_INSTALL_RE.sub(" ", text)
    for rx, why in (
        (PIP_ENV_NAME_RE, "sets or names a pip environment variable, which steers what pip installs"),
        (PIP_CONFIG_FILE_RE, "names a pip config file, which steers what pip installs"),
        (UNHASHED_INSTALLER_RE, "runs an installer outside pip's hash checking"),
    ):
        m = rx.search(rest)
        if m is not None:
            errors.append(
                f"{loc} {what} {why} ({m.group(0)!r}) — pip installs only as "
                f"`{CANONICAL_PIP_INSTALL}`; refused"
            )
    for part in _shell_texts(text):
        for cmd in shell_lex.split_commands(part):
            tokens = cmd.words
            if not any(PIP_MENTION_RE.search(t) for t in tokens):
                continue
            shown = " ".join(tokens)
            inv = _parse_pip_invocation(tokens)
            if inv is None:
                if any("install" in t.casefold() for t in tokens):
                    errors.append(
                        f"{loc} {what} mentions pip and install in {shown!r} outside the "
                        "hash-checked shape; refused"
                    )
                continue
            why = _pip_invocation_refusal(inv)
            if why is not None:
                errors.append(
                    f"{loc} {what} runs {shown!r}: {why} — pip installs only as "
                    f"`{CANONICAL_PIP_INSTALL}`; refused"
                )


def _brace_alternatives(word: str) -> list[str] | None:
    """`word` after bash brace expansion: every `{a,b}` expanded, nested
    ones included, and every `{x..y}` sequence (digits or letters, never `.`
    or `/`) taken as the glob `*`. None past `BRACE_ALTERNATIVES_LIMIT`."""
    todo, done = [word], []
    while todo:
        w = todo.pop()
        found = None
        start = w.find("{")
        while start >= 0 and found is None:
            depth, parts, at = 0, [], start + 1
            for j in range(start + 1, len(w)):
                c = w[j]
                if c == "{":
                    depth += 1
                elif c == "}" and depth:
                    depth -= 1
                elif c == "," and not depth:
                    parts.append(w[at:j])
                    at = j + 1
                elif c == "}":
                    parts.append(w[at:j])
                    if len(parts) > 1:
                        found = (start, j + 1, parts)
                    elif ".." in parts[0]:
                        found = (start, j + 1, ["*"])
                    break
            if found is None:
                start = w.find("{", start + 1)
        if found is None:
            done.append(w)
        else:
            lo, hi, alts = found
            todo.extend(w[:lo] + a + w[hi:] for a in alts)
        if len(done) + len(todo) > BRACE_ALTERNATIVES_LIMIT:
            return None
    return done


def _protected_word(word: str) -> bool:
    """Whether `word` (quote-removed) could name `.github/ci/**` or the
    `.github` directory holding it: after brace expansion, some path
    component matches `.github` (as a glob, when it is one — a shell glob
    reaches a dot name only from a literal leading `.`) and is last or
    followed by one matching `ci`. Any root is ignored — a variable or
    spliced expression before it could be the workspace. A word whose brace
    expansion is too large to enumerate is taken to name it."""
    for w in {word, word.rsplit("=", 1)[-1]}:
        alternatives = _brace_alternatives(w)
        if alternatives is None:
            return True
        for alt in alternatives:
            parts = posixpath.normpath(alt.casefold()).split("/")
            for i, part in enumerate(parts):
                if part.startswith(".") and fnmatch.fnmatchcase(".github", part) and (
                    i + 1 == len(parts) or fnmatch.fnmatchcase("ci", parts[i + 1])
                ):
                    return True
    return False


@dataclass(frozen=True)
class CommandVerb:
    """A simple command resolved past its assignments and wrappers: the
    command word (None for none), its arguments, and whether an `xargs`
    in front hands it further arguments no check sees."""

    verb: str | None
    args: list[str]
    via_xargs: bool


def _command_verb(words: list[str]) -> CommandVerb | str:
    """`words` resolved to the command they run, or why that cannot be
    established: every wrapper's flags are consumed by its `WrapperSpec`,
    and a flag outside it is refused (`env -S` splits a string into a
    command no check sees; `env -u python3 cp` is `cp`, not `python3`)."""
    i, n, via_xargs = 0, len(words), False
    while i < n:
        w = words[i]
        if SHELL_ASSIGNMENT_RE.match(w):
            i += 1
            continue
        base = posixpath.basename(w)
        spec = COMMAND_WRAPPERS.get(base)
        if spec is None:
            break
        via_xargs = via_xargs or base == "xargs"
        i += 1
        while i < n:
            a = words[i]
            if a == "--":
                i += 1
                break
            if spec.assignments and SHELL_ASSIGNMENT_RE.match(a):
                i += 1
                continue
            if not a.startswith("-") or (a == "-" and a not in spec.bare):
                break
            flag = a.split("=", 1)[0] if a.startswith("--") else a
            if a in spec.bare or (a.startswith("--") and "=" in a and flag in spec.bare | spec.valued):
                i += 1
            elif a in spec.valued:
                if i + 1 >= n:
                    return f"`{base} {a}` lacks its argument"
                i += 2
            elif spec.numeric_flag and a[1:].isdigit():
                i += 1
            else:
                return f"`{base}` flag {a!r} is outside the flags this check reads"
        if spec.operands:
            if i + spec.operands > n:
                return f"`{base}` lacks its operand"
            i += spec.operands
    if i >= n:
        return CommandVerb(None, [], via_xargs)
    return CommandVerb(words[i], words[i + 1 :], via_xargs)


def _shell_program(args: list[str]) -> tuple[str, str] | str | None:
    """Where a shell whose argv is `args` reads its commands: `("c", text)`
    for `-c text`, `("script", path)` for a script operand, None for
    standard input, or why its argv is outside the closed set."""
    i, c = 0, False
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a in SHELL_LONG_FLAGS:
            i += 1
            continue
        if SHELL_LETTER_FLAG_RE.fullmatch(a):
            if "c" in a:
                if a.startswith("+"):
                    return f"shell flag {a!r}"
                c = True
            i += 1
            for _ in range(a.count("o")):
                if i >= len(args) or args[i] not in SHELL_O_OPTIONS:
                    return f"shell `-o` without a named option in {sorted(SHELL_O_OPTIONS)}"
                i += 1
            continue
        if a.startswith(("-", "+")):
            return f"shell flag {a!r} is outside {{-e -u -x -v -c -o <opt> --noprofile --norc}}"
        break
    if i >= len(args):
        return "shell `-c` without its command text" if c else None
    return ("c" if c else "script", args[i])


def _protected_tree_refusal(text: str, depth: int = 0) -> str | None:
    """The first write into `.github/ci/**` in shell `text`, or None.

    The tree may be executed (`.github/ci/x.sh`, `source`), or read by a
    `PROTECTED_TREE_READERS` command; a redirect into it and any other
    command naming it are refused. A command whose wrapped verb cannot be
    established is refused, as is `xargs` running anything but a reader. A
    shell must read its commands from `-c <text>` (scanned in turn) or a
    script operand: a shell fed a here-document, a here-string, or standard
    input — save `cat <file> | sh` over a literal file outside the tree — is
    refused, since its commands are unseen."""
    if depth > STRING_SCALAR_DEPTH_LIMIT:
        return "shell -c nesting too deep"
    for cmd in shell_lex.split_commands(text):
        for target in cmd.writes:
            if _protected_word(target):
                return f"redirect into {target!r}"
        resolved = _command_verb(cmd.words)
        if isinstance(resolved, str):
            return f"{resolved} — the command it runs cannot be established"
        verb, args = resolved.verb, resolved.args
        if verb is None:
            continue
        base = posixpath.basename(verb)
        if resolved.via_xargs and base not in XARGS_READERS:
            return f"xargs runs {base!r} with arguments read from standard input (unseen)"
        if _protected_word(verb):
            continue
        if base in SHELLS:
            if cmd.heredoc:
                return f"{base} fed a here-document (its commands are unseen)"
            if cmd.herestring:
                return f"{base} fed a here-string (its commands are unseen)"
            program = _shell_program(args)
            if isinstance(program, str):
                return program
            if program is None:
                src = cmd.pipe_source
                if not (
                    src is not None and len(src) == 2 and src[0] == PIPE_TO_SHELL_SOURCE
                    and not src[1].startswith("-") and not _protected_word(src[1])
                ):
                    return f"{base} reads its commands from standard input (unseen)"
            elif program[0] == "c":
                inner = _protected_tree_refusal(program[1], depth + 1)
                if inner is not None:
                    return inner
        if base in PROTECTED_TREE_READERS:
            continue
        hit = next((a for a in args if _protected_word(a)), None)
        if hit is not None:
            return f"{base} {hit!r}"
    return None


def _string_scalars(node: object, loc: str, errors: list[str]) -> list[tuple[str, str, bool]]:
    """Every string key and value under `node`, as (label, text, is_if) triples.

    A key is scanned as written, `key:`, so a rule over `name:` sees it. The
    label names the path (`run:` for a top-level key, else `with.x`,
    `env.X`, `strategy.matrix.os[0]`); `is_if` marks an `if:` value, a bare
    expression. Nesting past `STRING_SCALAR_DEPTH_LIMIT` is refused.
    """
    out: list[tuple[str, str, bool]] = []
    stack: list[tuple[str, object, int, bool]] = [("", node, 0, False)]
    while stack:
        path, value, depth, is_if = stack.pop()
        if isinstance(value, str):
            out.append((path if "." in path or "[" in path else f"{path}:", value, is_if))
        elif isinstance(value, (dict, list)):
            if depth >= STRING_SCALAR_DEPTH_LIMIT:
                errors.append(
                    f"{loc} {path or 'document'} nests deeper than {STRING_SCALAR_DEPTH_LIMIT} — "
                    "its strings cannot all be scanned; refused"
                )
                continue
            items = (
                [(f"{path}.{k}" if path else str(k), k, v) for k, v in value.items()]
                if isinstance(value, dict)
                else [(f"{path}[{n}]", None, v) for n, v in enumerate(value)]
            )
            for child, key, v in reversed(items):
                if isinstance(key, str):
                    stack.append((child, f"{key}:", depth + 1, False))
                stack.append((child, v, depth + 1, key == "if"))
    return out


def _audit_text(
    text: str, loc: str, what: str, policy: StepPolicy, errors: list[str],
    helper_ok: bool = False, bare_expression: bool = False, is_run: bool = False,
) -> None:
    """Rules (c), (f), (g) over one string scalar outside the composite; a
    step's `run:` (`is_run`) is also shell text for rule (j) and the
    shadowing and protected-tree rules."""
    parsed = _parsed_expressions(text, bare_expression)
    _refuse_wiring_text(text, loc, what, errors)
    _refuse_runner_file_text(text, parsed, loc, what, policy, helper_ok, errors)
    _refuse_unhashed_pip(text, loc, what, errors)
    if not is_run:
        return
    _refuse_eval(text, loc, what, errors)
    if isinstance(parsed, gha_expr.Refusal):
        return
    _refuse_shell_expression(text, parsed, ShellTextPosition.RUN, loc, what, errors)
    shell = text
    for lo, hi in reversed(parsed.spans):
        shell = shell[:lo] + "__GHA_EXPR__" + shell[hi:]
    m = SHELL_SHADOWING_RE.search(shell_lex.without_heredoc_bodies(shell))
    if m is not None:
        errors.append(
            f"{loc} {what} defines a shell function or alias ({m.group(0).strip()!r}) — it "
            "could shadow a command every check matches by name; refused"
        )
    hit = _protected_tree_refusal(shell) if policy.workspace is Workspace.CHECKOUT else None
    if hit is not None:
        errors.append(
            f"{loc} {what} writes into {PROTECTED_TREE}/ ({hit}) — the verifier, its "
            "helper, and the hashed requirements are only executed or read; refused"
        )


def _audit_scalars(node: object, loc: str, policy: StepPolicy, errors: list[str], step: bool) -> None:
    """The text rules over every string scalar of `node`.

    The helper call and the shell-text rules apply to a step's own `run:`
    (`step`).
    """
    for label, text, is_if in _string_scalars(node, loc, errors):
        is_run = step and label == "run:"
        _audit_text(text, loc, label, policy, errors, is_run, is_if, is_run)


def _refuse_unpinned_uses(st: Step, loc: str, errors: list[str]) -> None:
    """Rule (e): a third-party `uses:` names its content, never a movable ref."""
    if "uses" not in st.raw:
        return
    uses = st.uses
    if uses is None:
        _refuse_shape(loc, "uses:", "a string", st.raw["uses"], errors)
        return
    if uses.startswith("./") or PINNED_REMOTE_USES_RE.match(uses) or PINNED_DOCKER_USES_RE.match(uses):
        return
    errors.append(
        f"{loc} uses {uses!r}, which is not pinned by content — a third-party action "
        "is `owner/repo[/path]@<40-hex commit sha>` (tag in a trailing comment), a "
        "docker image `docker://image@sha256:<digest>`; refused"
    )


def _refuse_unpinned_image(image: object, loc: str, errors: list[str]) -> None:
    """Rule (e) for a job `container:`/`services:` image."""
    if not isinstance(image, str):
        _refuse_shape(loc, "image", "a string", image, errors)
    elif not PINNED_IMAGE_RE.match(image):
        errors.append(
            f"{loc} image {image!r} is not pinned by sha256 digest (`image@sha256:<digest>`); refused"
        )


def _refuse_env_keys(env: dict, loc: str, errors: list[str]) -> None:
    """Rule (b) over the keys; their text is scanned with every other scalar."""
    for key in sorted(_env_keys_folded(env) & RUSTC_WIRING_ENV_KEYS):
        errors.append(f"{loc} env sets {key!r} — no job wraps or replaces rustc; refused")


def _refuse_wiring_text(text: str, loc: str, what: str, errors: list[str]) -> None:
    """Rule (c): free text that names any rustc wrapper or replacement key or
    cargo's `rustc-wrapper` spelling — or that
    assembles its target from a GitHub Actions expression function instead of
    naming it literally, which would otherwise dodge the scan above."""
    m = RUSTC_WIRING_TEXT_RE.search(text)
    if m:
        errors.append(
            f"{loc} {what} writes {RUSTC_WRAPPER_VAR}/rustc-wrapper-shaped wiring "
            f"({m.group(0)!r}: inline env, export, $GITHUB_ENV, `cargo --config`, or a "
            "cargo config file) — no job wraps or replaces rustc; refused"
        )
    expr_error = strict_yaml.refuse_expression_assembly(text, f"{loc} {what}")
    if expr_error:
        errors.append(expr_error)


def _audit_defaults(container: dict, loc: str, repo_top: str, errors: list[str]) -> None:
    """Shape of `defaults.run.shell` and `defaults.run.working-directory` at
    workflow or job scope.

    The shell wraps every `run:` step, so its text is scanned with the scope's
    other scalars; a working directory is refused as a step's is
    (`_refuse_working_directory`); a shape this check cannot read is refused.
    """
    if "defaults" not in container:
        return
    d = container["defaults"]
    if not isinstance(d, dict):
        _refuse_shape(loc, "defaults:", "a mapping", d, errors)
        return
    if "run" not in d:
        return
    r = d["run"]
    if not isinstance(r, dict):
        _refuse_shape(loc, "defaults.run:", "a mapping", r, errors)
        return
    if "shell" in r:
        _refuse_step_shell(r["shell"], loc, "defaults.run.shell", errors)
    _refuse_working_directory(r, loc, "defaults.run.working-directory", repo_top, errors)


def _refuse_step_shell(shell: object, loc: str, what: str, errors: list[str]) -> None:
    """A `shell:` names one of `STEP_SHELLS`, bare: GitHub then runs the
    step's script file with that interpreter's fixed argv. Any other value
    is a command template (`bash -c '<cmd>; bash {0}'`, `python {0}`, `sh`)
    whose program this check cannot read as the step's `run:`."""
    if not isinstance(shell, str):
        _refuse_shape(loc, what, "a string", shell, errors)
    elif shell not in STEP_SHELLS:
        errors.append(
            f"{loc} {what} is {shell!r} — a shell: is one of {sorted(STEP_SHELLS)}, bare; a "
            "command template runs a program the run: checks never see; refused"
        )


def _uses_repo(st: Step, owner_repo: str) -> bool:
    """Whether `st` runs the remote action `owner_repo` (case-folded), at any
    ref or subpath. A name ban is hygiene, not a trust boundary: a fork under
    another owner passes it, and check 7's SHA pin is what bounds that."""
    return uses_action(st.uses, owner_repo)


def _refuse_rust_cache_save(st: Step, loc: str, errors: list[str]) -> None:
    """Rule (a): a `Swatinem/rust-cache` step saves only on `main` — its
    `with.save-if` is exactly `RUST_CACHE_SAVE_IF`. Absent, the action saves
    from every ref, so pull request runs evict the `main` cache they restore."""
    w = st.raw.get("with")
    got = w.get("save-if") if isinstance(w, dict) else None
    if got != RUST_CACHE_SAVE_IF:
        errors.append(
            f"{loc} uses {RUST_CACHE_REPO} with save-if {got!r} — it must be exactly "
            f"{RUST_CACHE_SAVE_IF!r}, so only main writes the cache; refused"
        )


def _audit_step(st: Step, loc: str, policy: StepPolicy, errors: list[str]) -> None:
    """Rules (a)/(b)/(c)/(e)/(f)/(g)/(j) for one step."""
    _refuse_unpinned_uses(st, loc, errors)
    if _uses_repo(st, RUST_CACHE_REPO):
        _refuse_rust_cache_save(st, loc, errors)
    if _uses_repo(st, RAW_MOLD_ACTION_REPO):
        errors.append(
            f"{loc} runs the raw {RAW_MOLD_ACTION_REPO} action directly — use "
            f"{MOLD_COMPOSITE_USES} instead, which verifies the release digest"
        )
    _refuse_env_keys(_scoped_env(st.raw, f"{loc} env", errors), loc, errors)
    if "run" in st.raw and not isinstance(st.raw["run"], str):
        _refuse_shape(loc, "run:", "a string", st.raw["run"], errors)
    if "shell" in st.raw:
        _refuse_step_shell(st.raw["shell"], loc, "shell:", errors)
    _refuse_working_directory(st.raw, loc, "working-directory:", policy.repo_top, errors)
    if "with" in st.raw and not isinstance(st.raw["with"], dict):
        _refuse_shape(loc, "with:", "a mapping", st.raw["with"], errors)
    _audit_scalars(st.raw, loc, policy, errors, step=True)
    with_ = st.raw.get("with")
    if st.uses is None or not isinstance(with_, dict):
        return
    for key, value in with_.items():
        position = _action_input_position(st, key)
        if position is None:
            continue
        what = f"with.{key}"
        if not isinstance(value, str):
            _refuse_shape(loc, f"{what}:", "a string", value, errors)
            continue
        if position is ShellTextPosition.ACTION_INPUT:
            _refuse_eval(value, loc, what, errors)
        parsed = _parsed_expressions(value, bare_expression=False)
        if isinstance(parsed, gha_expr.Template):
            _refuse_shell_expression(value, parsed, position, loc, what, errors)


def _action_input_position(st: Step, key: object) -> ShellTextPosition | None:
    """The shell-text position `with.<key>` of `st` is, or None: the
    `script` of `actions/github-script`, or any input whose case-folded name
    is in `ACTION_SHELL_INPUTS`, for every action (remote or local). The name
    set is judged without the action's identity, so a new action whose
    script input carries one of these names is covered before anyone reads
    its `action.yml`."""
    if not isinstance(key, str):
        return None
    if key.casefold() == "script" and _uses_repo(st, GITHUB_SCRIPT_REPO):
        return ShellTextPosition.GITHUB_SCRIPT
    if key.casefold() in ACTION_SHELL_INPUTS:
        return ShellTextPosition.ACTION_INPUT
    return None


# The steps a job may run up to and including its last step naming
# `.github/ci/**` (the ordering rule of check 7): each is a closed shape whose
# effect on the runner is fixed — a checkout or interpreter setup by
# content-pinned action with a closed literal `with:` and no `env:`, the canonical
# hash-checked pip install with no `env:`, or a pure run of one tool file under
# `.github/ci` (`ToolRun`) with allowlisted `env:` (`ToolEnvKey`). Any other
# step is arbitrary code (a free-form `run:`, an action, a build script) that
# may rewrite the tree or the job's environment, so it may neither name the
# tree nor precede a step that does.
PINNED_CHECKOUT_USES = frozenset({
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
})
CHECKOUT_WITH_KEYS = frozenset({"fetch-depth", "persist-credentials", "sparse-checkout", "sparse-checkout-cone-mode"})
PINNED_SETUP_PYTHON_USES = frozenset({"actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"})
SETUP_PYTHON_WITH_KEYS = frozenset({"python-version"})
# The keys that can turn a red step or job green: a skipped step or job, and a
# failure-ignored one, both report success (GitHub counts a skipped required
# check as passing). On a setup step a skip or an ignored failure leaves the
# tool under the runner's own interpreter and packages, or over a partial
# checkout, a state the tool is not proven to fail red on. Every site that
# vouches for a verdict reads masking through this one set.
MASKING_KEYS = frozenset({"if", "continue-on-error"})
# The keys a closed shape may carry, masking keys excepted: those are admitted
# only per `ToolRole` (`ROLE_MASKING`).
PRE_TOOL_STEP_KEYS = frozenset({"name", "id", "env", "run", "uses", "with", "timeout-minutes", "shell"})
# The job keys a tool job may carry, masking keys excepted (admitted per
# `ToolRole`). Closed: `container:`/`services:` outlive the job's steps;
# `strategy:` expands legs (and a per-leg `continue-on-error`) from a matrix
# that may be chosen at run time and renames the job's status contexts;
# `concurrency:` lets another run cancel the job; `environment:` injects
# variables and secrets the tool env allowlist never sees (admitted only as
# the literal `ADMIN_ENVIRONMENT_JOBS` entry of its own keyed job); `uses:`
# runs a reusable workflow outside this check. None is needed by a tool job.
TOOL_JOB_KEYS = frozenset({"name", "runs-on", "steps", "needs", "permissions", "outputs", "env", "defaults", "timeout-minutes"})
# A tool job runs on a GitHub-hosted Ubuntu label: a fresh virtual machine per
# job (no earlier job's writes survive into it) whose default shell is bash, the
# only shell a `ToolRun` is read as. A self-hosted runner keeps its disk across
# jobs; an expression label is chosen at run time; a Windows or macOS label
# changes the shell and path rules the tool words are read under. Digits are
# ASCII only (`\d` would admit any Unicode decimal digit).
UBUNTU_HOSTED_RUNNER_RE = re.compile(r"ubuntu-(?:latest|[0-9]+(?:\.[0-9]+)?)(?:-arm|-arm64)?")


class ToolRole(enum.Enum):
    """What a tool's run means to the checks that read its job.

    VERDICT: its exit status is a check verdict. ADVISORY: its only effect is
    a step output that a crash leaves unset, read by every consumer as the
    conservative default (`release_only` unset runs every tier). OUTPUT: it
    publishes an SSOT to later steps of its own job, a terminal job no other
    job needs, so skipping the job only withholds an action (a cancel, a
    rerun) and never a verdict.
    """

    VERDICT = "verdict"
    ADVISORY = "advisory"
    OUTPUT = "output"


# The tools that are not verdicts; every other tool file is a VERDICT, so a new
# tool is verdict-bearing until it is listed here.
TOOL_ROLES: dict[str, ToolRole] = {
    "release_only.py": ToolRole.ADVISORY,
    "change_class.py": ToolRole.ADVISORY,
    "deterministic_checks_output.py": ToolRole.OUTPUT,
    "rerun_policy.py": ToolRole.OUTPUT,
}


@dataclass(frozen=True)
class RoleMasking:
    """The masking keys a role admits on its tool step and on its job."""

    step: frozenset[str]
    job: frozenset[str]


# Exhaustive over `ToolRole` (asserted by the test suite). A VERDICT admits no
# masking key anywhere. An ADVISORY step admits `continue-on-error: true`
# (its crash leaves the output unset) but its job admits none: the job's
# outputs steer other jobs' `if:`, so skipping or failure-ignoring the job
# would skip a verdict job downstream. An OUTPUT job admits `if:` (it is
# terminal: see `ToolJob`).
ROLE_MASKING: dict[ToolRole, RoleMasking] = {
    ToolRole.VERDICT: RoleMasking(frozenset(), frozenset()),
    ToolRole.ADVISORY: RoleMasking(frozenset({"continue-on-error"}), frozenset()),
    ToolRole.OUTPUT: RoleMasking(frozenset(), frozenset({"if"})),
}


def _masking_value_admitted(key: str, value: object) -> bool:
    """Whether an admitted masking key carries an admitted value: a
    `continue-on-error` only as the literal `true` (an expression is chosen at
    run time); an `if:` as any string (GitHub reads it as an expression)."""
    if key == "continue-on-error":
        return value is True
    return key == "if" and isinstance(value, str)


@dataclass(frozen=True)
class Timeout:
    """A `timeout-minutes:` value: a positive integer literal.

    Zero, a bool, a float, a string, and a `${{ }}` expression are refused:
    each is either chosen at run time or not a budget the job can meet.
    """

    minutes: int

    @staticmethod
    def parse(value: object) -> Timeout | None:
        if type(value) is int and value > 0:
            return Timeout(value)
        return None


def _optional_timeout(raw: dict) -> Timeout | None | str:
    """The `timeout-minutes:` of `raw`: absent is None, a `Timeout`, or the
    refusal text for a present value that is not one."""
    if "timeout-minutes" not in raw:
        return None
    t = Timeout.parse(raw["timeout-minutes"])
    return t if t is not None else f"timeout-minutes: {raw['timeout-minutes']!r} is not a positive integer literal"


@dataclass(frozen=True)
class RunnerLabel:
    """A `runs-on:` that is one literal GitHub-hosted Ubuntu label
    (`UBUNTU_HOSTED_RUNNER_RE`)."""

    label: str

    @staticmethod
    def parse(value: object) -> RunnerLabel | None:
        if isinstance(value, str) and UBUNTU_HOSTED_RUNNER_RE.fullmatch(value):
            return RunnerLabel(value)
        return None
# Raw-text words: split at quotes and shell metacharacters after every `\` is
# read as `/`, so a Windows-separated path is seen as the path it names. This
# detection scan splits on every whitespace character, a superset of
# `shell_lex.BLANKS`: seeing more candidate words only ever finds more tree
# references (it fails closed); the words a tool run is read as come from
# `ToolRunText` alone.
TREE_TOKEN_SPLIT_RE = re.compile(r"[\s'\"`;&|()<>=$]+")


class Interp(enum.Enum):
    """How a `ToolRun` starts its tool: `python3 <tool>.py`, `bash <tool>.sh`,
    or `<tool>.sh` executed directly (its shebang)."""

    PYTHON3 = "python3"
    BASH = "bash"
    DIRECT = ""


TOOL_SUFFIX = {Interp.PYTHON3: ".py", Interp.BASH: ".sh", Interp.DIRECT: ".sh"}
TREE_FILE_RE = re.compile(r"\.github/ci/([A-Za-z0-9_-]+\.(?:py|sh))")
TOOL_FLAG_RE = re.compile(r"--?[A-Za-z0-9][A-Za-z0-9-]*")
# The whole-text grammar of a tool run: plain words separated by bash's blanks
# (`shell_lex.BLANKS`), nothing else. Built from the one blank set, so the
# words this grammar sees are the words bash runs.
_TOOL_RUN_WORD = r"[A-Za-z0-9_./-]+"
_SHELL_BLANK = "[" + "".join(re.escape(c) for c in sorted(shell_lex.BLANKS)) + "]"
TOOL_RUN_TEXT_RE = re.compile(rf"{_TOOL_RUN_WORD}(?:{_SHELL_BLANK}+{_TOOL_RUN_WORD})*")
SHELL_BLANKS_RE = re.compile(rf"{_SHELL_BLANK}+")


@dataclass(frozen=True)
class TreeFile:
    """A regular file directly under `.github/ci`, present on disk (not a
    symlink); `name` is its file name."""

    name: str

    @staticmethod
    def parse(word: str, root: str) -> TreeFile | None:
        m = TREE_FILE_RE.fullmatch(word)
        if m is None:
            return None
        path = os.path.join(root, "ci", m.group(1))
        if os.path.islink(path) or not os.path.isfile(path):
            return None
        return TreeFile(m.group(1))


@dataclass(frozen=True)
class ToolRunText:
    """A `run:` text that is one line of plain words (`TOOL_RUN_TEXT_RE`).

    Parsed once, fullmatched after `shell_lex.trim`: no quote, expansion,
    `${{ }}`, redirection, separator, here-document, or character outside
    the word set, and words split only on `shell_lex.BLANKS`, so `words`
    are exactly the words bash runs.
    """

    words: tuple[str, ...]

    @staticmethod
    def parse(run: str) -> ToolRunText | None:
        text = shell_lex.trim(run)
        if TOOL_RUN_TEXT_RE.fullmatch(text) is None:
            return None
        words = tuple(SHELL_BLANKS_RE.split(text))
        # Defence in depth: the shell lexer reads the same one command.
        cmds = shell_lex.split_commands(text)
        if len(cmds) != 1:
            return None
        cmd = cmds[0]
        if cmd.writes or cmd.heredoc or cmd.herestring or cmd.pipe_source is not None:
            return None
        if tuple(cmd.words) != words:
            return None
        return ToolRunText(words)


@dataclass(frozen=True)
class ToolRun:
    """A `run:` that is exactly one tool invocation.

    An interpreter, one `TreeFile` whose suffix fits it, and bare literal
    flags, read from a `ToolRunText`, so the shell runs exactly those words.
    """

    interp: Interp
    tool: TreeFile
    flags: tuple[str, ...]

    @staticmethod
    def parse(run: str, root: str) -> ToolRun | None:
        text = ToolRunText.parse(run)
        if text is None:
            return None
        words = text.words
        interp = {"python3": Interp.PYTHON3, "bash": Interp.BASH}.get(words[0], Interp.DIRECT)
        rest = words if interp is Interp.DIRECT else words[1:]
        if not rest:
            return None
        tool = TreeFile.parse(rest[0], root)
        if tool is None or not tool.name.endswith(TOOL_SUFFIX[interp]):
            return None
        flags = tuple(rest[1:])
        if not all(TOOL_FLAG_RE.fullmatch(f) for f in flags):
            return None
        return ToolRun(interp, tool, flags)


class EnvScope(enum.Enum):
    WORKFLOW = "workflow"
    JOB = "job"
    STEP = "step"


_EVERY_SCOPE = frozenset(EnvScope)
# The one allowlist of `env:` keys a tool job may carry, with the scopes each
# is admitted at: data a tool reads, never a key that steers the runner, a
# loader, or an interpreter. `CARGO_*` is workflow-wide build output styling
# for the workflow's cargo jobs; no tool runs cargo.
TOOL_ENV_ALLOWLIST: dict[str, frozenset[EnvScope]] = {
    "EVENT_NAME": _EVERY_SCOPE,
    "HEAD_REPO": _EVERY_SCOPE,
    "PR_HEAD_SHA": _EVERY_SCOPE,
    "REPO": _EVERY_SCOPE,
    "GH_TOKEN": _EVERY_SCOPE,
    "HEAD_SHA": _EVERY_SCOPE,
    # Event data one tool step reads: the merge-group queue base commit and
    # the id of the run a `workflow_run` event names.
    "MERGE_GROUP_BASE_SHA": frozenset({EnvScope.STEP}),
    "RUN_ID": frozenset({EnvScope.STEP}),
    "CARGO_TERM_COLOR": frozenset({EnvScope.WORKFLOW}),
    "CARGO_INCREMENTAL": frozenset({EnvScope.WORKFLOW}),
}


@dataclass(frozen=True)
class ToolEnvKey:
    """An `env:` key admitted in a tool job at `scope` (`TOOL_ENV_ALLOWLIST`),
    byte-exact."""

    key: str
    scope: EnvScope

    @staticmethod
    def parse(key: object, scope: EnvScope) -> ToolEnvKey | None:
        if isinstance(key, str) and scope in TOOL_ENV_ALLOWLIST.get(key, frozenset()):
            return ToolEnvKey(key, scope)
        return None


def _unadmitted_env_keys(container: dict, scope: EnvScope) -> list[str]:
    """The `env:` keys of `container` that are not `ToolEnvKey`s at `scope`
    (an `env:` that is not a mapping is reported whole)."""
    env = container.get("env", {})
    if not isinstance(env, dict):
        return [f"<env: {type(env).__name__}>"]
    return sorted(str(k) for k in env if ToolEnvKey.parse(k, scope) is None)


def _github_component(part: str) -> bool:
    """Whether one path component could name `.github`: a glob with at least
    one literal character past its leading dot (`.*` alone is any dot name,
    most often a regular expression), case-folded, with the trailing dots and
    spaces Windows drops set aside; a `~` (a Windows short name) counts."""
    part = part.casefold().rstrip(". ") or part
    literal = re.sub(r"\[[^]]*]|[*?]", "", part)
    return "~" in part or (part.startswith(".") and len(literal) > 1 and fnmatch.fnmatchcase(".github", part))


def _names_tree(word: str) -> bool:
    """Whether `word` names a path under `.github/ci`: after brace expansion
    and with every `\\` read as `/`, a component that could name `.github`
    (`_github_component`) followed by one matching `ci`. A word whose brace
    expansion is too large to enumerate is taken to name it."""
    alternatives = _brace_alternatives(word)
    if alternatives is None:
        return True
    for alt in alternatives:
        parts = posixpath.normpath(alt.replace("\\", "/").casefold()).split("/")
        for part, nxt in zip(parts, parts[1:]):
            if _github_component(part) and fnmatch.fnmatchcase("ci", nxt):
                return True
    return False


@dataclass(frozen=True)
class WorkingDir:
    """A `working-directory:` value admitted anywhere.

    A plain path: a string of printable characters, assembled at no run
    time, with no `~` component, and no component (as written, or as
    resolved on disk through symlinks) that could name `.github`. `parse`
    returns the refusal reason instead of a `WorkingDir`; every text check
    runs before the path touches the filesystem.
    """

    path: str

    @staticmethod
    def parse(value: object, repo_top: str) -> WorkingDir | str:
        if not isinstance(value, str):
            return f"is not a string ({type(value).__name__})"
        if any(not c.isprintable() for c in value):
            return "holds a control or non-printing character"
        if "$" in value or "`" in value:
            return "is assembled at run time"
        path = value.replace("\\", "/")
        parts = posixpath.normpath(path).split("/")
        if any("~" in p for p in parts):
            return "has a `~` component (a home directory or a Windows short name)"
        if any(_github_component(p) for p in parts):
            return "has a .github component"
        top = os.path.realpath(repo_top)
        real = os.path.relpath(os.path.realpath(os.path.join(top, path)), top)
        if any(_github_component(p) for p in real.replace(os.sep, "/").split("/")):
            return "resolves on disk to a .github component"
        return WorkingDir(path)


def _refuse_working_directory(container: dict, loc: str, what: str, repo_top: str, errors: list[str]) -> None:
    """A `working-directory` naming `.github` makes a relative `ci/...` path a
    tree reference no word spells; refused at every scope, in every job."""
    if "working-directory" not in container:
        return
    why = WorkingDir.parse(container["working-directory"], repo_top)
    if isinstance(why, str):
        errors.append(
            f"{loc} {what} {container['working-directory']!r} {why} — a relative path "
            f"under it could reach {PROTECTED_TREE}/ unnamed; refused"
        )


class PreToolKind(enum.Enum):
    """Which closed setup shape a `PreToolStep` is."""

    CHECKOUT = "pinned checkout"
    SETUP_PYTHON = "pinned setup-python"
    PIP_INSTALL = "canonical pip install"


@dataclass(frozen=True)
class PreToolStep:
    """A closed setup step: a pinned checkout or setup-python with a literal
    `with:` and no `env:`, or the canonical pip install with no `env:`; no
    masking key, and a `Timeout` if any."""

    kind: PreToolKind
    timeout: Timeout | None


@dataclass(frozen=True)
class ToolStep:
    """A pure run of one `.github/ci` tool (`ToolRun`) with allowlisted
    `env:`, its `ToolRole`, a `Timeout` if any, and only the masking keys its
    role admits on a step (`ROLE_MASKING`), each with an admitted value."""

    run: ToolRun
    role: ToolRole
    timeout: Timeout | None
    masking: frozenset[str]


ClosedStep = PreToolStep | ToolStep


def parse_closed_step(st: Step, root: str) -> ClosedStep | None:
    """`st` as a closed shape, or None: a step whose effect on the runner is
    fixed and cannot rewrite `.github/ci/**` or steer the interpreters the
    tools run under, and whose failure cannot be masked unless its role says
    the failure carries no verdict."""
    raw = st.raw
    masking = frozenset(raw) & MASKING_KEYS
    if not set(raw) - masking <= PRE_TOOL_STEP_KEYS or raw.get("shell", "bash") != "bash":
        return None
    timeout = _optional_timeout(raw)
    if isinstance(timeout, str):
        return None
    uses, run, with_ = raw.get("uses"), raw.get("run"), raw.get("with", {})
    if not isinstance(with_, dict):
        return None
    if isinstance(uses, str) and run is None:
        if masking or "env" in raw or not _literal_with(with_):
            return None
        if uses in PINNED_CHECKOUT_USES and set(with_) <= CHECKOUT_WITH_KEYS:
            return PreToolStep(PreToolKind.CHECKOUT, timeout)
        if uses in PINNED_SETUP_PYTHON_USES and set(with_) <= SETUP_PYTHON_WITH_KEYS:
            return PreToolStep(PreToolKind.SETUP_PYTHON, timeout)
        return None
    if isinstance(run, str) and uses is None and "with" not in raw:
        if shell_lex.trim(run) == CANONICAL_PIP_INSTALL:
            return None if masking or "env" in raw else PreToolStep(PreToolKind.PIP_INSTALL, timeout)
        tool = ToolRun.parse(run, root)
        if tool is None or _unadmitted_env_keys(raw, EnvScope.STEP):
            return None
        role = TOOL_ROLES.get(tool.tool.name, ToolRole.VERDICT)
        admitted = ROLE_MASKING[role].step
        if not all(k in admitted and _masking_value_admitted(k, raw[k]) for k in masking):
            return None
        return ToolStep(tool, role, timeout, masking)
    return None


# The one expression a closed `with:` admits: a checkout `fetch-depth` chosen
# between two digit literals by the event name alone. Every value it can take
# is a literal depth, so the input stays fixed per event.
EVENT_KEYED_DEPTH_RE = re.compile(
    r"\$\{\{ github\.event_name == '[a-z_]+' && '[0-9]+' \|\| '[0-9]+' \}\}"
)


def _literal_with(with_: dict) -> bool:
    """Whether every `with:` entry of a closed shape is a string key with a
    literal scalar value: a bool, a number, or a string holding no `${{`
    (an expression would choose the input at run time) — save a
    `fetch-depth` of exactly `EVENT_KEYED_DEPTH_RE`'s shape."""
    for key, value in with_.items():
        if not isinstance(key, str):
            return False
        if isinstance(value, str):
            if "${{" in value and not (key == "fetch-depth" and EVENT_KEYED_DEPTH_RE.fullmatch(value)):
                return False
        elif not isinstance(value, (bool, int, float)):
            return False
    return True


def _tree_reference(node: object, run: str | None, loc: str) -> str | None:
    """The first word in any string of `node` (keys included) that could
    name `.github/ci/**`, or None. In the step's own `run:` the canonical
    helper call is set aside (see `check_workflow_steps`). Words are taken
    both quote-removed (`shell_lex`) and as raw text with every `\\` read as
    `/`, split at quotes and shell metacharacters, so neither spelling hides
    a reference. Shape errors are reported by the step audits, not here."""
    for label, text, _ in _string_scalars(node, loc, []):
        if label == "run:" and text is run:
            text = GITHUB_ENV_HELPER_CALL_RE.sub(" ", text)
        words = TREE_TOKEN_SPLIT_RE.split(text.replace("\\", "/"))
        for part in _shell_texts(text):
            for cmd in shell_lex.split_commands(part):
                words.extend(cmd.words)
                words.extend(cmd.writes)
        hit = next((w for w in words if w and _names_tree(w)), None)
        if hit is not None:
            return hit
    return None


CLOSED_SHAPES_NOTE = (
    "the closed pre-tool shapes (pinned checkout or setup-python with a literal with: and "
    "no env, the canonical pip install with no env, a pure .github/ci tool run with "
    "allowlisted env; any timeout-minutes: a positive integer literal; no if:, and "
    "continue-on-error: true only on an advisory tool)"
)


def _step_refusal_detail(st: Step) -> list[str]:
    """Why a tree-naming step is not a `ClosedStep`, as far as a single key
    says (the shape itself is named by `CLOSED_SHAPES_NOTE`)."""
    detail = []
    if "working-directory" in st.raw:
        detail.append("under a working-directory:")
    for key in sorted(MASKING_KEYS & set(st.raw)):
        detail.append(f"with {key}: (its verdict could be masked)")
    timeout = _optional_timeout(st.raw)
    if isinstance(timeout, str):
        detail.append(f"with {timeout}")
    bad = _unadmitted_env_keys(st.raw, EnvScope.STEP)
    if bad:
        detail.append(f"with env {bad}")
    return detail


def _needs_of(raw: dict) -> list[str]:
    needs = raw.get("needs") or []
    return [str(n) for n in ([needs] if isinstance(needs, str) else needs if isinstance(needs, list) else [needs])]


@dataclass(frozen=True)
class ToolJob:
    """A job that names `.github/ci/**`, parsed once.

    `steps` are the job's steps up to and including its last one naming the
    tree, every one a `ClosedStep`; `runner` a `RunnerLabel`; `timeout` a
    `Timeout` if any; every job key in `TOOL_JOB_KEYS` save `masking`, the
    job-level masking keys, which every `ToolStep`'s role must admit on a job
    (`ROLE_MASKING`; a job with no `ToolStep` admits none). A job carrying
    one is terminal: no job needs it, since a skipped job skips its
    dependents and each of them then reports success. A job with a VERDICT
    step carries no `needs:` at all — the same skip-then-report-success hole
    reopens transitively through any ancestor's `if:`, not only through this
    job's own masking, so a verdict job depends on nothing.
    """

    runner: RunnerLabel
    timeout: Timeout | None
    steps: tuple[ClosedStep, ...]
    masking: frozenset[str]

    @staticmethod
    def parse(
        wf: Workflow, job: WorkflowJob, steps: list[Step], jloc: str, root: str
    ) -> ToolJob | list[str] | None:
        """The job as a `ToolJob`, its refusals, or None when no step names
        the tree (the job is then not a tool job).

        In a head-free workflow (`Workspace.NONE`) no checkout exists for a
        step to rewrite, so the step half — each tree-naming step closed and
        after closed steps only — is not asked; the job half still is, with
        the job read as a verdict job (no masking key, no `needs:`), since
        nothing in it runs a `ToolStep` whose role could admit either."""
        head_free_job = wf.workspace is Workspace.NONE
        refusals: list[str] = []
        closed: list[ClosedStep] = []
        prefix: list[ClosedStep] = []
        tainted: Step | None = None
        referenced = False
        for st in steps:
            shape = parse_closed_step(st, root)
            if shape is not None and tainted is None:
                closed.append(shape)
            hit = _tree_reference(st.raw, st.run, jloc)
            if hit is not None:
                referenced = True
                if head_free_job:
                    continue
                prefix = list(closed)
                stloc = f"{jloc} step {st.label!r}"
                if tainted is not None:
                    refusals.append(
                        f"{stloc} names {hit!r} after step {tainted.label!r}, which is outside "
                        f"{CLOSED_SHAPES_NOTE} — an earlier step could have rewritten "
                        f"{PROTECTED_TREE}/ or the job's environment; refused"
                    )
                if shape is None:
                    detail = _step_refusal_detail(st)
                    note = f" ({', '.join(detail)})" if detail else ""
                    refusals.append(
                        f"{stloc} names {hit!r} but is not itself one of {CLOSED_SHAPES_NOTE}{note} "
                        f"— only those may name {PROTECTED_TREE}/; refused"
                    )
            if tainted is None and shape is None:
                tainted = st
        if not referenced:
            return None
        raw = job.raw
        runs_on = raw.get("runs-on")
        runner = RunnerLabel.parse(runs_on)
        if runner is None:
            refusals.append(
                f"{jloc} runs {PROTECTED_TREE}/ on runs-on {runs_on!r}, not one literal "
                "GitHub-hosted Ubuntu label (a fresh virtual machine per job, bash by default); refused"
            )
        for key in sorted(str(k) for k in raw):
            if key in TOOL_JOB_KEYS or key in MASKING_KEYS:
                continue
            keyed_env = ADMIN_ENVIRONMENT_JOBS.get((wf.fname, job.job_id))
            if key == "environment" and keyed_env is not None and raw[key] == keyed_env:
                # The one keyed exception: the environment's secret is the
                # tool's own token, and check 8 holds its name to this job.
                continue
            if key in ("container", "services"):
                refusals.append(
                    f"{jloc} runs {PROTECTED_TREE}/ with a job {key}: — its filesystem and "
                    "processes outlive this job's steps; refused"
                )
            else:
                refusals.append(
                    f"{jloc} runs {PROTECTED_TREE}/ with a job {key}:, outside the tool job keys "
                    "(TOOL_JOB_KEYS) — it could expand, cancel, re-scope, or re-home the job "
                    "outside this check; refused"
                )
        timeout = _optional_timeout(raw)
        if isinstance(timeout, str):
            refusals.append(f"{jloc} runs {PROTECTED_TREE}/ with a job {timeout}; refused")
            timeout = None
        masking = frozenset(raw) & MASKING_KEYS
        tools = [s for s in prefix if isinstance(s, ToolStep)]
        admitted = frozenset(MASKING_KEYS)
        for t in tools:
            admitted &= ROLE_MASKING[t.role].job
        if not tools:
            admitted = frozenset()
        for key in sorted(masking):
            if key in admitted and _masking_value_admitted(key, raw[key]):
                continue
            verdicts = sorted({t.run.tool.name for t in tools if not ROLE_MASKING[t.role].job >= {key}})
            refusals.append(
                f"{jloc} runs {PROTECTED_TREE}/ with a job {key}: {raw[key]!r} — a skipped or "
                "failure-ignored job reports success to required checks (and skips the jobs "
                f"that need it), so it may mask the verdict of {verdicts or 'its steps'}; "
                "only an output tool's terminal job admits a job if:; refused"
            )
        if masking:
            dependents = sorted(j.job_id for j in wf.jobs if job.job_id in _needs_of(j.raw))
            if dependents:
                refusals.append(
                    f"{jloc} runs {PROTECTED_TREE}/ with a job {'/'.join(sorted(masking))}: but "
                    f"job(s) {dependents} need it — a skipped job skips its dependents, which "
                    "then report success; refused"
                )
        job_needs = _needs_of(raw)
        if job_needs and (head_free_job or any(not ROLE_MASKING[t.role].job for t in tools)):
            refusals.append(
                f"{jloc} runs {PROTECTED_TREE}/ with needs: {job_needs!r} — a job whose tool "
                "admits no job masking (a verdict, or an advisory that steers other jobs) "
                "may depend on nothing: GitHub skips a job whose need is itself skipped, "
                "directly or through that need's own needs, the instant ANY job in the chain "
                "carries an if: (of any value), and a skipped required check reports success; "
                "refused"
            )
        for scope, container in ((EnvScope.WORKFLOW, wf.doc), (EnvScope.JOB, raw)):
            d = container.get("defaults")
            r = d.get("run") if isinstance(d, dict) else None
            if isinstance(r, dict) and "working-directory" in r:
                refusals.append(
                    f"{jloc} runs {PROTECTED_TREE}/ under a {scope.value} defaults.run.working-directory "
                    "— its relative paths would resolve outside the workspace; refused"
                )
            if isinstance(r, dict) and r.get("shell", "bash") != "bash":
                refusals.append(
                    f"{jloc} runs {PROTECTED_TREE}/ under a {scope.value} defaults.run.shell "
                    f"{r.get('shell')!r} — a tool run is read as bash; refused"
                )
            bad = _unadmitted_env_keys(container, scope)
            if bad:
                refusals.append(
                    f"{jloc} runs {PROTECTED_TREE}/ with {scope.value} env {bad}, outside the "
                    "tool env allowlist (TOOL_ENV_ALLOWLIST); refused"
                )
        if refusals or runner is None:
            return refusals
        return ToolJob(runner, timeout, tuple(prefix), masking)


def _check_tool_job(
    wf: Workflow, job: WorkflowJob, steps: list[Step], jloc: str, root: str, errors: list[str]
) -> None:
    """The ordering rule of check 7 for one job: a job naming `.github/ci/**`
    must parse as a `ToolJob` (closed steps up to its last tree reference, a
    fresh hosted Ubuntu runner, workspace-root paths, allowlisted env and job
    keys, and masking only where every tool's role admits it)."""
    parsed = ToolJob.parse(wf, job, steps, jloc, root)
    if isinstance(parsed, list):
        errors.extend(parsed)


@dataclass(frozen=True)
class LocalAction:
    """A resolved local composite action. `id` is its identity: the
    repo-root-relative path, normalized (`./x/`, `./x`, `./a/../x` are one
    path) and byte-exact — two paths case-fold-equal but not byte-equal are
    refused outright (macOS and Windows runners resolve them to one
    directory), so identity never needs folding. `display` is the path as
    written for messages, `doc` the parsed action document."""

    id: str
    display: str
    steps: list[Step]
    doc: dict


def _local_action_path(uses: str | None) -> str | None:
    """The normalized repo-root-relative path of a local `uses: ./...`
    reference, or None when `uses` is not local (a pinned third-party
    action, `docker://...`). GitHub resolves a local `uses:` against the
    repository root regardless of which file contains it."""
    if uses is None or not uses.startswith("./"):
        return None
    return posixpath.normpath(uses[2:])


class LocalActions:
    """Every local action reachable from a `uses: ./...`, resolved on disk
    the way GitHub does (repo root, then `action.yml`, then `action.yaml`).
    Resolution is the graph: nothing is discovered by glob, so no reference
    can point at an action this pass never read. Anything it cannot read as
    a composite is refused, never taken to be clean."""

    def __init__(self, root: str, policy: StepPolicy, errors: list[str]):
        self.root = root
        self.policy = policy
        self.errors = errors
        self._by_id: dict[str, LocalAction | None] = {}
        self._folded: dict[str, str] = {}
        self._closed: set[str] = set()

    def disk_dir(self, rel: str) -> str:
        # `root` is the `.github` directory; the repository root is its parent.
        return os.path.join(os.path.dirname(self.root), rel)

    def _exact_on_disk(self, rel: str, shown: str, loc: str) -> bool:
        """Every component of `rel` present on disk is present byte-exactly,
        with no case-fold-equal sibling. A missing tail is left to `_load`."""
        parent = os.path.dirname(self.root)
        for part in rel.split("/"):
            try:
                entries = os.listdir(parent)
            except OSError:
                return True
            twins = sorted(e for e in entries if e.casefold() == part.casefold())
            if len(twins) > 1:
                self.errors.append(
                    f"{loc}: local action {shown!r} passes through {parent!r}, which holds "
                    f"case-fold-equal entries {twins} — ambiguous on a case-insensitive "
                    "runner; refused"
                )
                return False
            if twins and twins[0] != part:
                self.errors.append(
                    f"{loc}: local action {shown!r} names {part!r} but the directory holds "
                    f"{twins[0]!r} — identity is byte-exact; refused"
                )
                return False
            parent = os.path.join(parent, part)
        return True

    def audit_case_collisions(self, top: str, loc: str) -> None:
        """Refuse any directory under `top` holding two case-fold-equal
        entries, referenced or not: a case-insensitive checkout merges them."""
        for d, dirs, files in os.walk(top):
            dirs.sort()
            seen: dict[str, str] = {}
            for e in sorted(dirs + files):
                first = seen.setdefault(e.casefold(), e)
                if first != e:
                    self.errors.append(
                        f"{loc}: {d!r} holds case-fold-equal entries {first!r} and {e!r} — "
                        "a case-insensitive runner resolves both to one path; refused"
                    )

    def resolve(self, uses: str | None, loc: str) -> LocalAction | None:
        """The composite behind a local `uses:`, or None (not local, or
        refused — the refusal is recorded)."""
        rel = _local_action_path(uses)
        if rel is None:
            return None
        if rel in self._by_id:
            return self._by_id[rel]
        self._by_id[rel] = None
        other = self._folded.setdefault(rel.casefold(), rel)
        if other != rel:
            self.errors.append(
                f"{loc}: local action {uses!r} is case-fold-equal to {other!r} but not "
                "byte-equal — a case-insensitive runner resolves both to one directory; refused"
            )
            return None
        if rel in (".", "..") or rel.startswith("../") or os.path.isabs(rel):
            self.errors.append(f"{loc}: local action {uses!r} escapes the repository root; refused")
            return None
        if not self._exact_on_disk(rel, uses or rel, loc):
            return None
        action = self._load(rel, uses or rel, loc)
        self._by_id[rel] = action
        if action is not None:
            outside_steps = {k: v for k, v in action.doc.items() if k != "runs"}
            outside_steps["runs"] = {k: v for k, v in action.doc["runs"].items() if k != "steps"}
            _audit_scalars(outside_steps, f"{action.display}/action.yml:", self.policy, self.errors, step=False)
            for st in action.steps:
                sloc = f"{action.display}/action.yml: step {st.label!r}"
                _audit_step(st, sloc, self.policy, self.errors)
                hit = _tree_reference(st.raw, st.run, sloc)
                if hit is not None:
                    self.errors.append(
                        f"{sloc} names {hit!r} — a composite step runs wherever the action "
                        f"is used, outside the ordering rule for {PROTECTED_TREE}/; refused"
                    )
        return action

    def _load(self, rel: str, shown: str, loc: str) -> LocalAction | None:
        d = self.disk_dir(rel)
        found = [
            os.path.join(d, n) for n in ("action.yml", "action.yaml") if os.path.isfile(os.path.join(d, n))
        ]
        if not found:
            self.errors.append(
                f"{loc}: local action {shown!r} does not exist (no action.yml/action.yaml "
                f"at {d}) — an unresolved action cannot be audited; refused"
            )
            return None
        if len(found) > 1:
            self.errors.append(
                f"{loc}: local action {shown!r} has both action.yml and action.yaml — "
                "ambiguous; refused"
            )
            return None
        path = found[0]
        try:
            with open(path) as f:
                doc = strict_yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.errors.append(f"{path} is not valid YAML: {e}")
            return None
        if not isinstance(doc, dict):
            _refuse_shape(path, "the action document", "a mapping", doc, self.errors)
            return None
        runs = doc.get("runs")
        if not isinstance(runs, dict):
            _refuse_shape(path, "runs:", "a mapping", runs, self.errors)
            return None
        if runs.get("using") != "composite":
            self.errors.append(
                f"{path}: `runs.using` must be 'composite' (got {runs.get('using')!r}) — a "
                "node/docker local action is opaque to this check; refused"
            )
            return None
        display = "./" + rel
        return LocalAction(rel, display, _typed_steps(runs, path, self.errors), doc)

    def close(self, action: LocalAction, loc: str) -> None:
        """Resolve, and so audit, every local action `action` transitively
        `uses:`. A cycle or a chain past `LOCAL_ACTION_DEPTH_LIMIT` is refused."""
        self._walk(action, loc, 0, frozenset())

    def _walk(self, action: LocalAction, loc: str, depth: int, stack: frozenset[str]) -> None:
        if action.id in self._closed:
            return
        if action.id in stack:
            self.errors.append(f"{loc}: local action cycle through {action.display}; refused")
            return
        if depth >= LOCAL_ACTION_DEPTH_LIMIT:
            self.errors.append(
                f"{loc}: local action nesting exceeds {LOCAL_ACTION_DEPTH_LIMIT} levels at "
                f"{action.display} — the chain cannot be audited; refused"
            )
            return
        for st in action.steps:
            child = self.resolve(st.uses, f"{action.display}/action.yml: step {st.label!r}")
            if child is not None:
                self._walk(child, loc, depth + 1, stack | {action.id})
        self._closed.add(action.id)


def _check_mold_composite(actions: LocalActions, repo: str, errors: list[str]) -> None:
    """The mold composite installs a linker every build job trusts, so its
    shape is pinned: one `bash` step whose `run:` opens with `set -euo
    pipefail`, pins a 64-hex digest in every `digest=` arm, and runs the one
    `sha256sum --check --strict` line before any `tar`/`ln` line. A reordered
    or dropped verification is refused. Skipped when the composite is absent
    (every `uses:` of it then fails to resolve on its own)."""
    if not os.path.isfile(os.path.join(repo, MOLD_COMPOSITE_USES[2:], "action.yml")):
        return
    action = actions.resolve(MOLD_COMPOSITE_USES, "mold composite self-check")
    if action is None:
        return
    where = f"{action.display}/action.yml"
    steps = action.doc["runs"].get("steps")
    if not isinstance(steps, list) or len(steps) != 1:
        errors.append(f"{where}: the mold composite has exactly one step, got {steps!r}; refused")
        return
    (step,) = steps
    run = step.get("run") if isinstance(step, dict) else None
    if not (isinstance(step, dict) and set(step) <= {"name", "shell", "run"} and step.get("shell") == "bash"):
        errors.append(f"{where}: the mold step must be {{name?, shell: bash, run}} (got {step!r}); refused")
        return
    if not isinstance(run, str):
        errors.append(f"{where}: the mold step's run: must be a string; refused")
        return
    lines = [ln.strip() for ln in run.splitlines()]
    if not lines or lines[0] != "set -euo pipefail":
        errors.append(f"{where}: the mold run: must open with `set -euo pipefail`; refused")
    arms = [ln for ln in lines if "digest=" in ln]
    if not arms or any(not MOLD_DIGEST_ARM_RE.fullmatch(ln) for ln in arms):
        errors.append(f"{where}: every mold `digest=` line must be `<arch>) digest=<64-hex> ;;` (got {arms!r}); refused")
    verify = [i for i, ln in enumerate(lines) if MOLD_VERIFY_LINE in ln]
    install = [i for i, ln in enumerate(lines) if MOLD_INSTALL_WORD_RE.search(ln)]
    if len(verify) != 1 or not install or min(install) < verify[0]:
        errors.append(
            f"{where}: the mold run: must hold one `{MOLD_VERIFY_LINE}` line before every "
            "`tar`/`ln` line — an unverified tarball would install; refused"
        )


def _job_sub_env_scopes(job_raw: dict, loc: str, errors: list[str]) -> list[tuple[str, dict]]:
    """(scope-name, raw-container) pairs for a job's `container:` and each
    `services.<id>:` sub-scope — each may carry its own `env:` a
    rustc-wiring key could hide in, same as the job's own `env:`. A
    string `container:` (image only) has no env; any other non-mapping
    shape is refused."""
    scopes: list[tuple[str, dict]] = []
    if "container" in job_raw:
        container = job_raw["container"]
        if isinstance(container, dict):
            scopes.append(("container", container))
            _refuse_unpinned_image(container.get("image"), f"{loc} container", errors)
        elif isinstance(container, str):
            _refuse_unpinned_image(container, f"{loc} container", errors)
        else:
            _refuse_shape(loc, "container:", "a mapping or image string", container, errors)
    if "services" in job_raw:
        services = job_raw["services"]
        if not isinstance(services, dict):
            _refuse_shape(loc, "services:", "a mapping", services, errors)
        else:
            for sid, svc in services.items():
                if isinstance(svc, dict):
                    scopes.append((f"service {sid!r}", svc))
                    _refuse_unpinned_image(svc.get("image"), f"{loc} service {sid!r}", errors)
                else:
                    _refuse_shape(loc, f"service {sid!r}", "a mapping", svc, errors)
    return scopes


def check_workflow_steps(errors: list[str], root: str = REPO_ROOT) -> None:
    """Checks 6 and 7 over every step of every workflow and reachable local action.

    No job wraps or replaces rustc, and only `main` saves the dependency
    cache. Refused:
      (a) a `Swatinem/rust-cache` step (case-folded, any ref or subpath) in a
          workflow or reachable local action whose `with.save-if` is not
          exactly `RUST_CACHE_SAVE_IF`;
      (b) an `env:` key naming a wrapper var or a rustc-replacing var
          (`RUSTC`, `CARGO_BUILD_RUSTC`) (case-folded) at workflow, job,
          container, service, or step scope, in a workflow or any reachable
          local action; an `env:` that is present but not a plain mapping is
          refused outright;
      (c) free text naming a wrapper var, a rustc-replacing var, or cargo's
          `rustc-wrapper` spelling in any string key or value of a workflow,
          job, step, or local action's metadata (`run:`, `shell:`, `env:`,
          `with:`, `name:`, `if:`, `strategy.matrix`, `on.*.inputs`,
          `defaults.run.shell`, any nesting up to STRING_SCALAR_DEPTH_LIMIT)
          — any syntax, `$GITHUB_ENV` or not (YAML comments are not values
          and are never read);
      (e) a third-party `uses:` not pinned to a 40-hex commit SHA, a
          `docker://` `uses:` or a job `container:`/`services:` image not
          pinned to a sha256 digest;
      (f) any text (every place (c) reads) naming, in any case or syntax,
          GITHUB_ENV/PATH/STATE/OUTPUT/STEP_SUMMARY (an append to
          GITHUB_OUTPUT/GITHUB_STEP_SUMMARY by exact name excepted), the
          runner's command files, `ACTIONS_ALLOW_UNSECURE_COMMANDS`, or a
          legacy `::` command; a `github`/`env` expression access other
          than a literal `.name`, or `github.<command-file property>`; a
          `GITHUB_WORKSPACE` other than a plain read; and any reference to
          `ci/github-env.sh` other than its canonical call in a step's
          `run:` with a bare key listed in `ci/github-env-allowlist.txt`
          (itself validated: `CI_JOB_[A-Z0-9_]+`, and no wiring, runner,
          toolchain, loader, or interpreter key);
      (g) a `pip install` other than `--require-hashes --only-binary :all:
          -r $GITHUB_WORKSPACE/.github/ci/requirements.txt` with that one
          file exactly once, and any `pipx`/`easy_install`, judged on
          quote-removed words (`p""ip` is `pip`);
      (h) a `shell:` or `defaults.run.shell` other than bash, pwsh, or
          powershell, bare (any other value is a command template);
      (i) the ordering rule (`_check_tool_job`): a step naming
          `.github/ci/**` that is not itself a `ClosedStep`
          (`parse_closed_step`), or that runs after any step outside them —
          any other step may rewrite the tree or the job's environment
          first, so the tools' trust is monotone taint, not a list of write
          spellings. Every shape is an allowlist: a tool step is one
          `ToolRun` (`python3`/`bash`/direct, one `TreeFile` present on
          disk, bare flags; no `${{ }}`, operator, redirection, or second
          line); an action or pip step carries no `env:`; every workflow,
          job, and tool-step `env:` key is a `ToolEnvKey` of
          `TOOL_ENV_ALLOWLIST` for its scope. A job that runs the tree must
          parse as a `ToolJob`: a runs-on other than one literal
          GitHub-hosted Ubuntu label (`RunnerLabel`), a job key outside
          `TOOL_JOB_KEYS`, a `timeout-minutes` that is not a positive integer
          literal (`Timeout`), a masking key its tools' roles do not admit,
          a job `if:` on a job another job needs, a `needs:` on a job with a
          VERDICT or ADVISORY step (a skipped ancestor, anywhere up the `needs:` chain,
          skips it too, and a skipped required check reports success), a
          `working-directory` at step or defaults scope, or a
          `defaults.run.shell` other than bash is refused. In every job, a
          `working-directory` (step, composite
          step, or defaults) assembled at run time or with a `.github`
          component, as written (`\\` read as `/`) or resolved on disk, is
          refused: a relative `ci/...` under it names the tree unspelled.
          The raw-text scan reads `\\` as `/`. The canonical
          `ci/github-env.sh` call is not a reference: a step after a
          non-closed step already runs arbitrary code with the env file
          open, so the helper grants it nothing, and the helper is not a
          verdict. A composite step naming the tree is refused (it runs
          wherever the action is used). Beneath (i), a quote-removed scan
          (brace expansion, wrapper flags, `xargs`, `sh -c` text, and a
          shell fed unseen standard input all resolved) refuses a write into
          the tree as defence in depth. Both guard a checked-out tree: in a
          head-free workflow (`Workspace.NONE`, from `head_free`) no step
          or job `uses:` anything and nothing runs `git`, so no checkout
          exists; there only the job half of (i) is asked, the job read as
          a verdict job (`ToolJob.parse`), and the write scan is not run;
      (j) any `${{ }}` in a shell-text position (`ShellTextPosition`): a
          step's `run:` (workflow or local composite), the `with.script`
          of an `actions/github-script` step (case-folded, any ref), and
          every action input named in `ACTION_SHELL_INPUTS` (a VM action's
          `with.run`/`with.prepare`, any action's `with.command`). The
          runner expands an expression before the interpreter parses the
          text, so its value, whatever context it reads, would become
          syntax; every value enters through `env:` and is read as
          `"$NAME"` (bash), `$env:NAME` (pwsh), or `process.env.NAME`.
          A quote-removed word in `EVAL_WORDS` (`eval`, pwsh
          `Invoke-Expression`/`iex`) in a `run:` or an action shell input
          (here-document bodies included) is refused too: it re-parses an
          `env:` value as shell.
    Every local `uses: ./...` is resolved on disk from the repo root
    (`action.yml`, then `action.yaml`); an unresolvable, ambiguous, non-
    composite (node/docker), cyclic, or over-deep (> LOCAL_ACTION_DEPTH_LIMIT)
    reference is refused. Identity is the normalized, byte-exact path: a
    reference, or any entry under `.github/actions/` referenced or not, that
    is case-fold-equal to another path but not byte-equal is refused. A
    job-level `uses:` (reusable workflow, local or remote) is refused. A
    malformed shape (`jobs:`, `steps:`, a job, a step, `env:`, `defaults:`,
    `container:`, `services:`) is refused, never skipped.

    LIMIT — static YAML cannot see, and this check does NOT prove absent:
      - a third-party action that itself exports a wrapper into the job, or
        a cache action other than `Swatinem/rust-cache` that saves from a
        pull request ref;
      - a repo script or interpreter snippet invoked from `run:` (`run:
        tools/ci/wire.sh`, `python -c ...`) that writes a wrapper or the env
        file under a name it assembles at run time, or a package manager
        (npm, cargo, apt, docker) fetching by a movable name;
      - an `env:`/`with:` value whose key name arrives only through `${{ }}`
        (`vars`, `secrets`, outputs);
      - a rustc replacement outside the named keys (a `PATH` entry shadowing
        `rustc`, a `rustup` toolchain override, a linker/runner setting);
      - run-time string assembly inside `run:` that builds a command-file
        name or a command the text scan never sees whole: a
        variable name concatenated from parts, `${!x}` indirection, a glob
        over the runner temp directory, a decoded payload piped to a shell;
      - what a step writes into GITHUB_OUTPUT (content, a multiline
        delimiter) and how a later `${{ steps.*.outputs.* }}` in a
        non-shell position (`with:`, `if:`) uses it;
      - under (j), an `env:` value a script hands to a program that parses
        its argument as code (`bash -c "$X"`, `sh -c`, `python -c`, a
        template engine): legitimate tools take author-written `-c` text,
        so the verifier cannot tell the two apart; and interpreter
        variables (`PYTHON*`) that steer the canonical pip install;
      - a `run:` that reads a runner variable (`$GITHUB_EVENT_NAME`,
        `$GITHUB_REF`, ..) in the shell rather than through `${{ }}`: the
        text scan here does not model it (check 23 refuses the literal names
        in its region only);
      - shadowing a checked command by means other than a shell function or
        alias written in the same `run:` (a `PATH` entry, `BASH_ENV`, a
        sourced file);
      - under (i), a runner that carries a GitHub-hosted label but is not
        one: the label test assumes the repository registers no self-hosted
        runner (it registers none; one labelled `ubuntu-latest` would keep
        its disk across jobs); a step that runs the tree spelled so no word
        names it (`${d}hub/ci`, a relative path after `cd .github`, a
        pure-wildcard `.*/ci`) is not seen as a tool step, so its verdict is
        not one this rule vouches for; and, for the same reason, a symlink
        to the tree created at run time by an unrecognised step earlier in
        the same job (a hosted runner is a fresh machine per job, so no
        other job's link survives into it) and then run through a path no
        word spells as the tree;
      - in the defence-in-depth write scan beneath (i) (these are closed
        only because (i) refuses the tool after any such step): a path the
        words do not spell (`d=.git; ${d}hub/ci`, a relative path after
        `cd`), an interpreter snippet, an archive extractor, `find -exec`,
        a whole-tree `git checkout`/`git reset`, an action's `with:`, and
        pwsh text (lexed as POSIX);
      - an attacker-controlled `${{ github.event.* }}` value interpolated
        straight into `run:` text (passing it through `env:` is the safe form);
      - a legacy `::set-env` command assembled by the shell at run time (the
        quote-concatenated `::set-""env` spelling is refused);
      - installers that fetch without pip's hash checking beyond the refused
        `setup.py install`, `uv pip`, `uv tool`, `uvx`, `pipx`, and
        `easy_install`;
      - `TOOL_FLAG_RE` admits any literal flag word, so `--help`/`-h` is an
        accepted tool invocation and exits 0 without running the tool's
        verdict logic;
      - a `.py`/`.sh` file under the tree is accepted as a tool by its
        filename suffix alone — a library module never meant to run
        standalone (`strict_yaml.py`, `release_only.py`) parses the same as
        a verdict script;
      - `run: true` (or any non-`run:` step form) is not a `ToolRun` and so
        is not a tool step at all — it neither names the tree nor is
        refused for failing to;
      - nothing here binds a branch-protection required context's name to
        the tool file it is meant to report; the mapping from context to
        script is trusted, not checked.
    Those are review-gated, not machine-gated.
    """
    start = len(errors)
    policy = StepPolicy(
        load_github_env_allowlist(errors, root), os.path.dirname(os.path.abspath(root)), Workspace.CHECKOUT
    )
    actions = LocalActions(root, policy, errors)
    _check_mold_composite(actions, os.path.dirname(os.path.abspath(root)), errors)

    # Defence in depth: every action on disk under `.github/actions/` is
    # audited even when nothing references it yet. Reachability never relies
    # on this list — it comes from resolving each `uses:`.
    actions.audit_case_collisions(os.path.join(root, "actions"), "local action audit")
    for pattern in ("action.yml", "action.yaml"):
        for path in sorted(glob.glob(os.path.join(root, "actions", "**", pattern), recursive=True)):
            rel = os.path.relpath(os.path.dirname(path), root).replace(os.sep, "/")
            actions.resolve(f"./.github/{rel}", "local action audit")

    base_policy = policy
    for wf in _load_workflows(root, errors):
        policy = replace(base_policy, workspace=wf.workspace)
        wloc = f"{wf.fname}: workflow-level"
        _refuse_env_keys(_scoped_env(wf.doc, f"{wloc} env", errors), wloc, errors)
        _audit_defaults(wf.doc, wf.fname, policy.repo_top, errors)
        _audit_scalars({k: v for k, v in wf.doc.items() if k != "jobs"}, wloc, policy, errors, step=False)
        for job in wf.jobs:
            jloc = f"{wf.fname}: job {job.job_id!r}"
            _refuse_env_keys(_scoped_env(job.raw, f"{jloc} env", errors), jloc, errors)
            _audit_defaults(job.raw, jloc, policy.repo_top, errors)
            _audit_scalars({k: v for k, v in job.raw.items() if k != "steps"}, jloc, policy, errors, step=False)
            for scope_name, scope_raw in _job_sub_env_scopes(job.raw, jloc, errors):
                sloc = f"{jloc} {scope_name}"
                _refuse_env_keys(_scoped_env(scope_raw, f"{sloc} env", errors), sloc, errors)
            if "uses" in job.raw:
                errors.append(
                    f"{jloc}: calls a reusable workflow ({job.raw['uses']!r}) — its jobs "
                    "are outside this check; refused"
                )
            steps = _typed_steps(job.raw, jloc, errors)
            for st in steps:
                stloc = f"{jloc} step {st.label!r}"
                _audit_step(st, stloc, policy, errors)
                action = actions.resolve(st.uses, stloc)
                if action is not None:
                    actions.close(action, stloc)
            _check_tool_job(wf, job, steps, jloc, root, errors)

    # One defect reached from several sites is reported once.
    own = list(dict.fromkeys(errors[start:]))
    del errors[start:]
    errors.extend(own)



def check_ci_suites_required(entries: list[dict], errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 21 (see the module docstring)."""
    gate_producer = {
        str(e["context"]): str(e["producer"])
        for e in entries
        if isinstance(e, dict) and e.get("disposition") == "gate" and e.get("context") and e.get("producer")
    }
    suites = sorted(os.path.basename(p) for p in glob.glob(os.path.join(root, "ci", "test_*.py")))
    run_by: dict[str, list[str]] = {s: [] for s in suites}
    for wf in _load_workflows(root, errors):
        for wj in wf.jobs:
            job = wj.raw
            context = str(job.get("name", wj.job_id))
            if gate_producer.get(context) != wf.fname:
                continue
            if "if" in job or "continue-on-error" in job:
                continue
            for step in job.get("steps") if isinstance(job.get("steps"), list) else []:
                if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                    continue
                if any(k in step for k in ("if", "continue-on-error", "working-directory")):
                    continue
                run = shell_lex.trim(step["run"])
                for suite, sites in run_by.items():
                    if run in (f"python3 .github/ci/{suite}", f"python3 .github/ci/{suite} -v"):
                        sites.append(f"{wf.fname}: job {wj.job_id!r}")
    for suite, sites in run_by.items():
        if not sites:
            errors.append(
                f"check 21: .github/ci/{suite} is run by no required job — add a step whose whole `run:` is "
                f"`python3 .github/ci/{suite} -v` to an unconditional `gate` job (ci.yml `artifact-guard`)"
            )


# Check 22: the workspace members whose feature matrix another check owns, each
# with its reason. Every other member's `[features]` keys must be compiled by a
# required ci.yml job.
FEATURE_COVERAGE_EXEMPT = {
    "src/runtime/rust": "its feature matrix is owned by the `runtime-feature-combos` job",
}
# Cargo's feature flags: a command naming one whose text cannot be read is refused.
_FEATURE_FLAG_TEXT = re.compile(r"--features|--all-features|--no-default-features|(?<![\w-])-F\b")
# Subcommands that compile a selected package's test targets.
_TEST_COMPILING = frozenset({"test", "bench", "nextest run", "nextest archive", "nextest list"})


@dataclass(frozen=True)
class _DepEdge:
    """A dependency of one workspace member on another."""

    target: str
    features: tuple[str, ...]
    default: bool
    optional: bool
    dev: bool


@dataclass
class _FeatureMember:
    name: str
    features: dict[str, list[str]]
    edges: list[_DepEdge]


def _str_list(value: object) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _feature_members(repo: str, errors: list[str]) -> dict[str, _FeatureMember] | None:
    """Each workspace member's package name, `[features]` table and
    dependency edges onto other members, keyed by directory; None (with the
    reason in `errors`) when the workspace cannot be read."""
    top = _load_toml(os.path.join(repo, "Cargo.toml"))
    if isinstance(top, str):
        errors.append(f"check 22: the root Cargo.toml {top}; refused")
        return None
    ws = top.get("workspace")
    dirs = ws.get("members") if isinstance(ws, dict) else None
    if not isinstance(dirs, list) or not all(isinstance(d, str) for d in dirs):
        errors.append("check 22: the root Cargo.toml needs a literal `[workspace] members` list; refused")
        return None
    ws_deps = ws.get("dependencies") if isinstance(ws, dict) else None
    ws_deps = ws_deps if isinstance(ws_deps, dict) else {}
    docs: dict[str, dict[str, object]] = {}
    for d in dirs:
        doc = _load_toml(os.path.join(repo, d, "Cargo.toml"))
        if isinstance(doc, str):
            errors.append(f"check 22: {d}/Cargo.toml {doc}; refused")
            return None
        docs[d] = doc
    names: dict[str, str] = {}
    dir_name: dict[str, str] = {}
    for d, doc in docs.items():
        pkg = doc.get("package")
        name = pkg.get("name") if isinstance(pkg, dict) else None
        if not isinstance(name, str):
            errors.append(f"check 22: {d}/Cargo.toml names no package; refused")
            return None
        names[name] = d
        dir_name[d] = name
    members: dict[str, _FeatureMember] = {}
    for d, doc in docs.items():
        raw = doc.get("features")
        table = {k: _str_list(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
        targets = doc.get("target")
        scopes = [doc] + [t for t in (targets.values() if isinstance(targets, dict) else []) if isinstance(t, dict)]
        edges: list[_DepEdge] = []
        for scope in scopes:
            for kind, dev in (("dependencies", False), ("build-dependencies", False), ("dev-dependencies", True)):
                deps = scope.get(kind)
                for key, spec in deps.items() if isinstance(deps, dict) else []:
                    if not isinstance(spec, dict):
                        continue
                    base = ws_deps.get(key) if spec.get("workspace") is True else None
                    base = base if isinstance(base, dict) else {}
                    package = spec.get("package", base.get("package", key))
                    target = names.get(package) if isinstance(package, str) else None
                    if target is None:
                        continue
                    edges.append(
                        _DepEdge(
                            target,
                            tuple(_str_list(base.get("features")) + _str_list(spec.get("features"))),
                            spec.get("default-features", base.get("default-features", True)) is not False,
                            spec.get("optional") is True,
                            dev,
                        )
                    )
        members[d] = _FeatureMember(dir_name[d], table, edges)
    return members


def _feature_closure(
    members: dict[str, _FeatureMember], roots: set[str], seeds: set[tuple[str, str]], tests: bool
) -> set[tuple[str, str]]:
    """Every `(member directory, feature)` active when `roots` compile with
    `seeds` switched on: the seeds, the `features = [..]` that the
    (non-optional) edges of each compiled member name, all closed over the
    members' feature tables. A root's dev-dependency edges count when `tests`
    compiles its test targets; an optional edge, and a weak `x?/f` entry, is
    never counted."""
    by_name = {m.name: d for d, m in members.items()}
    compiled: set[str] = set(roots)
    active: set[tuple[str, str]] = set()
    wanted: set[tuple[str, str]] = set(seeds)
    changed = True
    while changed:
        before = (len(compiled), len(active), len(wanted))
        for d in sorted(compiled):
            for edge in members[d].edges:
                if edge.optional or (edge.dev and not (tests and d in roots)):
                    continue
                compiled.add(edge.target)
                wanted.update((edge.target, f) for f in edge.features)
                if edge.default:
                    wanted.add((edge.target, "default"))
        for d, f in sorted(wanted):
            if d not in compiled or (d, f) in active or f not in members[d].features:
                continue
            active.add((d, f))
            for entry in members[d].features[f]:
                # `dep:x` names no feature; `x?/f` switches `f` on only when
                # the optional dependency `x` is already on, which an optional
                # edge never is here.
                if entry.startswith("dep:") or "?/" in entry:
                    continue
                if "/" in entry:
                    pkg, feat = entry.split("/", 1)
                    target = by_name.get(pkg)
                    if target is not None:
                        wanted.add((target, feat))
                else:
                    wanted.add((d, entry))
        changed = before != (len(compiled), len(active), len(wanted))
    return active


def _required_ci_jobs(entries: list[dict], wf: Workflow) -> list[dict]:
    """The jobs of `wf` whose outcome a required context reports: a `gate`
    entry produced by it names the job, or aggregates it."""
    gates = [e for e in entries if isinstance(e, dict) and e.get("disposition") == "gate" and e.get("producer") == wf.fname]
    out: list[dict] = []
    for wj in wf.jobs:
        ctx = str(wj.raw.get("name", wj.job_id))
        reported = any(
            str(e.get("context")) == ctx
            or any(a == wj.job_id or ctx == a or ctx.startswith(f"{a} (") for a in e.get("aggregates") or [])
            for e in gates
        )
        if reported:
            out.append(wj.raw)
    return out


def _always_runs(node: object) -> bool:
    """Whether a job or step is neither dead nor masked: no literal-false
    `if:` and no `continue-on-error` that could mask it."""
    if not isinstance(node, dict):
        return False
    if "continue-on-error" in node and node["continue-on-error"] is not False:
        return False
    return str(node.get("if", "true")).strip().lower() not in ("false", "${{ false }}")


def _unconditional_step(step: object) -> bool:
    """Whether a step runs whenever its job does: no `if:` at all and no
    masking `continue-on-error`. Check 11 governs job conditions only; a step
    `if:` can skip the step while the job, and the phase verdict reading it,
    succeeds — so a step with any `if:` proves nothing ran."""
    return _always_runs(step) and isinstance(step, dict) and "if" not in step


def _invocation_roots(
    inv: cargo_invocation.CargoInvocation, sel: cargo_invocation.Selection, members: dict[str, _FeatureMember]
) -> set[str]:
    """The member directories `inv` compiles at the top; empty for a
    `--workspace` run that excludes members (what stays is not read)."""
    if sel.whole_workspace:
        return set() if "--exclude" in inv.command else set(members)
    by_name = {m.name: d for d, m in members.items()}
    roots = set(sel.dirs)
    for spec in sel.packages:
        d = by_name.get(spec.rsplit("#", 1)[-1].split("@", 1)[0])
        if d is not None:
            roots.add(d)
    return roots.intersection(members)


def _invocation_seeds(
    inv: cargo_invocation.CargoInvocation, roots: set[str], members: dict[str, _FeatureMember]
) -> set[tuple[str, str]]:
    """The `(member directory, feature)` pairs `inv`'s feature flags switch on."""
    by_name = {m.name: d for d, m in members.items()}
    seeds: set[tuple[str, str]] = set()
    for d in roots:
        if inv.all_features:
            seeds.update((d, f) for f in members[d].features)
        elif not inv.no_default_features:
            seeds.add((d, "default"))
        for flag in inv.features:
            pkg, _, feat = flag.rpartition("/")
            if not pkg:
                seeds.add((d, feat))
                continue
            target = by_name.get(pkg.rstrip("?"))
            if target is not None:
                seeds.add((target, feat))
    return seeds


def check_feature_coverage(
    entries: list[dict], errors: list[str], root: str = REPO_ROOT, tracked: list[str] | None = None
) -> None:
    """Check 22 (see the module docstring)."""
    repo = os.path.dirname(root)
    members = _feature_members(repo, errors)
    layout = _workspace_layout(repo, tracked)
    if isinstance(layout, str):
        errors.append(f"check 22: {layout}; cannot tell what a cargo command compiles")
        return
    if members is None:
        return
    covered: set[tuple[str, str]] = set()
    for wf in _load_workflows(root, errors):
        if wf.fname != "ci.yml":
            continue
        for job in _required_ci_jobs(entries, wf):
            if not _always_runs(job):
                continue
            for found in _job_cargo(job, repo, wf.doc, unconditional=True):
                inv = found.invocation
                if isinstance(inv, str):
                    if _FEATURE_FLAG_TEXT.search(found.line):
                        errors.append(f"check 22: `{found.line}` names features but cannot be read ({inv}); refused")
                    continue
                if inv.subcommand not in cargo_invocation.COMPILING or inv.subcommand == "install":
                    continue
                sel = cargo_invocation.select(inv, found.cwd, layout)
                if isinstance(sel, str) or not sel.in_workspace:
                    continue
                roots = _invocation_roots(inv, sel, members)
                tests = inv.subcommand in _TEST_COMPILING or (
                    isinstance(inv.selection, cargo_invocation.ExplicitTargets)
                    and (inv.selection.all_tests or bool(inv.selection.tests))
                )
                covered.update(_feature_closure(members, roots, _invocation_seeds(inv, roots, members), tests))
    for d, m in sorted(members.items()):
        if d in FEATURE_COVERAGE_EXEMPT:
            continue
        for feature in sorted(m.features):
            if (d, feature) not in covered:
                errors.append(
                    f"check 22: feature {feature!r} of workspace member {d} ({m.name}) is enabled by no "
                    "command of a required ci.yml job — add it to a `--features` list of a required job's "
                    "cargo command (or a `features = [..]` dependency edge from a compiled member)"
                )
    for d in sorted(FEATURE_COVERAGE_EXEMPT):
        if d not in members or not members[d].features:
            errors.append(
                f"check 22: FEATURE_COVERAGE_EXEMPT names {d!r}, which is not a workspace member "
                "with features; drop it"
            )


# Check 23: the release workflow's jobs and the ci.yml jobs that check them.
RELEASE_WORKFLOW = "release.yml"
RELEASE_NATIVE_JOB = "build"
RELEASE_FREEBSD_JOB = "build-freebsd"
RELEASE_PUBLISH_JOB = "release"
CI_RELEASE_NATIVE_JOB = "release-targets-run"
CI_RELEASE_FREEBSD_JOB = "release-targets-freebsd"
_TOOLCHAIN_ACTION = "./.github/actions/rust-toolchain-pinned"
# The one step both native jobs run between their checkout and their cargo
# command: the toolchain, the dependency cache and the musl tools.
RELEASE_TARGET_ACTION = "./.github/actions/release-target-toolchain"
_RELEASE_EXPECTED = re.compile(r'expected="([^"]*)"')
# The feature release binaries ship: `ipe dev run --target wasi` needs it, and
# its refusal text promises it "in release packaging".
RELEASE_FEATURE = "ipe/wasi_run"
# The cargo command's argv, the one copy every pinned cargo line is built
# from; only the verb (`check` in ci.yml, `build` in release.yml) and the
# native jobs' `--target` differ.
_RELEASE_CARGO_FLAGS = f"--release --locked --features {RELEASE_FEATURE}"
_RELEASE_PACKAGES = "-p ipe -p ipe-ffi-inspector"
# The job that parses the release tag, and the one `ref` a release build
# checks out: the tag it parsed. ci.yml checks the tree under test instead.
RELEASE_TAG_JOB = "resolve-tag"
RELEASE_CHECKOUT_REF = "${{ needs.resolve-tag.outputs.tag }}"
_CHECKOUT_ACTION = "actions/checkout"
_MATRIX_TARGET = "${{ matrix.target }}"
# The one shell a release-target job's `run` steps name: a step left to the
# runner's default runs PowerShell on Windows, and `cmd` continues a line
# with `^`, which no scan below joins.
_RELEASE_TARGET_SHELL = "bash"
# Remote actions the pinned steps run, matched exactly (owner, repo and the
# 40-hex commit, case included): a case variant is another spelling no pin
# names, so it is refused rather than read.
_VM_ACTION_RE = re.compile(r"vmactions/freebsd-vm@[0-9a-f]{40}")
_RUST_CACHE_PIN_RE = re.compile(r"Swatinem/rust-cache@[0-9a-f]{40}")
_DTOLNAY_PIN_RE = re.compile(r"dtolnay/rust-toolchain@[0-9a-f]{40}")
# The FreeBSD VM step's inputs but `run`.
_VM_PRELUDE = {"usesh": True, "prepare": "pkg install -y rust"}
# A matrix `os` or `target`: a runner label or a target triple, nothing a
# shell or an expression can read as syntax.
_MATRIX_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_MATRIX_EXT_RE = re.compile(r"(?:\.exe)?")
# The keys each side's matrix legs carry: release.yml's `artifact` and `ext`
# are read only by its packaging steps, after the cargo command.
_CI_LEG_KEYS = frozenset({"os", "target"})
_RELEASE_LEG_KEYS = frozenset({"os", "target", "artifact", "ext"})
# The job keys a release-target job may hold; every other key (`env`,
# `defaults`, `container`, `services`, `permissions`, `continue-on-error`,
# ..) is refused, since each changes what the cargo command runs or lets the
# job succeed without it. `needs` and `if` place the job (check 11 governs
# ci.yml's); `runs-on` is pinned below.
_NATIVE_JOB_KEYS = frozenset({"name", "needs", "if", "timeout-minutes", "strategy", "runs-on", "steps"})
_FREEBSD_JOB_KEYS = _NATIVE_JOB_KEYS - {"strategy"}
_NATIVE_RUNS_ON = "${{ matrix.os }}"
_FREEBSD_RUNS_ON = "ubuntu-latest"
# The workflow keys that cannot reach a job's cargo command: the trigger,
# the token scope and run grouping, the display names, and the jobs checked
# one by one. `env` is held to `ALLOWED_ENV_DIFFERENCES`; any other key
# (`defaults`, ..) is refused.
_RELEASE_TARGET_WORKFLOW_KEYS = frozenset({"name", "run-name", "on", True, "permissions", "concurrency", "jobs", "env"})


def _release_cargo_line(verb: str, native: bool) -> str:
    """The one cargo line a release-target job runs, quotes as written: bash
    splits and globs `$TARGET`, never `"$TARGET"`."""
    target = ' --target "$TARGET"' if native else ""
    return f"cargo {verb} {_RELEASE_CARGO_FLAGS}{target} {_RELEASE_PACKAGES}"


# The body of `_TOOLCHAIN_ACTION`, which `RELEASE_TARGET_ACTION` runs first:
# its `run` texts line for line, its remote action and its inputs.
_TOOLCHAIN_CHANNEL_RUN = (
    "set -euo pipefail",
    'file="rust-toolchain.toml"',
    'if [[ ! -f "$file" ]]; then',
    '  echo "::error::${file} not found; cannot determine the pinned toolchain." >&2',
    "  exit 1",
    "fi",
    "channel=\"$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\\1/p' \"$file\" | head -n1)\"",
    'if [[ -z "$channel" ]]; then',
    "  echo \"::error::No 'channel = \\\"...\\\"' line in ${file}; cannot determine the pinned toolchain.\" >&2",
    "  exit 1",
    "fi",
    'echo "Pinned toolchain channel: ${channel}"',
    'echo "channel=${channel}" >> "$GITHUB_OUTPUT"',
)
_MUSL_INSTALL_RUN = ("sudo apt-get update && sudo apt-get install -y musl-tools",)


class _Pin:
    """A `uses:` value matched by an exact pattern, not by equality."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self.pattern = pattern


class _Lines:
    """A `run:` text pinned line for line: exactly these lines, one trailing
    newline aside, no line added, dropped or changed (a CR is a change)."""

    def __init__(self, lines: tuple[str, ...]) -> None:
        self.lines = lines


def _run_lines(text: str) -> list[str]:
    return text.removesuffix("\n").split("\n")


def _pin_refusal(value: object, pin: object, at: str) -> str | None:
    """Why `value` is not `pin` (a literal compared typed, a `_Pin`, a
    `_Lines`, or a mapping of these, key for key both ways), or None."""
    if isinstance(pin, _Pin):
        if isinstance(value, str) and pin.pattern.fullmatch(value):
            return None
        return f"{at} is {value!r}, which is not `{pin.pattern.pattern}`"
    if isinstance(pin, _Lines):
        if isinstance(value, str) and tuple(_run_lines(value)) == pin.lines:
            return None
        return f"{at} is {value!r}, which is not exactly {list(pin.lines)!r}"
    if isinstance(pin, dict):
        if not isinstance(value, dict):
            return f"{at} is {value!r}, which is not a mapping"
        keys = {(type(k), k) for k in value}
        want = {(type(k), k) for k in pin}
        if keys != want:
            extra = sorted(str(k) for _t, k in keys - want)
            missing = sorted(str(k) for _t, k in want - keys)
            return f"{at} has keys {sorted(map(str, value))!r} (extra {extra!r}, missing {missing!r})"
        for k, sub in pin.items():
            why = _pin_refusal(value[k], sub, f"{at}.{k}")
            if why is not None:
                return why
        return None
    if _same_value(value, pin):
        return None
    return f"{at} is {value!r}, which must be exactly {pin!r}"


def _step_pin_refusal(step: object, pin: dict, at: str) -> str | None:
    """`step` is `pin` but for a literal `name` holding no expression."""
    if not isinstance(step, dict):
        return f"{at} is {step!r}, which is not a step mapping"
    name = step.get("name")
    if "name" in step and not (isinstance(name, str) and "${{" not in name):
        return f"{at}.name is {name!r}, which must be a literal string"
    return _pin_refusal({k: v for k, v in step.items() if k != "name"}, pin, at)


def _pinned_step(step: object, pin: dict, at: str, why: str, errors: list[str]) -> bool:
    refusal = _step_pin_refusal(step, pin, at)
    if refusal is not None:
        errors.append(f"check 23: {refusal}: {why}; refused")
    return refusal is None


def _steps_of(job: dict) -> list[dict]:
    steps = job.get("steps")
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def _only(items: list, where: str, what: str, errors: list[str]) -> object | None:
    """The one of `items`, else a refusal naming `what`."""
    if len(items) != 1:
        errors.append(f"check 23: {where} must have exactly one {what}, has {len(items)}")
        return None
    return items[0]


def _same_value(a: object, b: object) -> bool:
    """`a` and `b` are one value as GitHub reads it: the same type at every
    level, then equal. Python's `==` holds `1 == True` and `1 == 1.0`, which
    GitHub stringifies apart (`1`, `true`, `1.0`)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict) and isinstance(b, dict):
        b_keys = {(type(k), k): v for k, v in b.items()}
        return len(a) == len(b) and all(
            (type(k), k) in b_keys and _same_value(v, b_keys[(type(k), k)]) for k, v in a.items()
        )
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same_value(x, y) for x, y in zip(a, b))
    return a == b


def _compare(what: str, ci_value: object, release_value: object, errors: list[str]) -> None:
    if not _same_value(ci_value, release_value):
        errors.append(
            f"check 23: ci.yml's {what} is {ci_value!r} but release.yml's is {release_value!r}; "
            "they must be equal"
        )


def _is_checkout(step: dict) -> bool:
    return uses_action(step.get("uses"), _CHECKOUT_ACTION)


class _Side(enum.Enum):
    """The workflow a value of a release-target pair comes from."""

    CI = "ci.yml"
    RELEASE = RELEASE_WORKFLOW


@dataclass(frozen=True)
class AllowedEnvDifference:
    """A workflow-level variable only one side sets, with one value, and why
    it cannot change what compiles."""

    side: _Side
    key: str
    value: str
    why: str


# The closed list of workflow `env` entries a release-target workflow sets:
# each side's workflow `env` is exactly its entries here, so a new variable
# must be named with its why, and an entry no longer set is refused.
ALLOWED_ENV_DIFFERENCES: tuple[AllowedEnvDifference, ...] = (
    AllowedEnvDifference(
        _Side.CI, "CARGO_TERM_COLOR", "always",
        "colours cargo's terminal output; it selects no code and no profile",
    ),
    AllowedEnvDifference(
        _Side.CI, "CARGO_INCREMENTAL", "0",
        "turns off the incremental cache, which `--release` already leaves off; it changes the build "
        "cache, never which code compiles or whether it does",
    ),
)


def _check_workflow_scope(side: _Side, doc: dict, errors: list[str]) -> None:
    """The workflow holds only the keys that cannot reach a job's cargo
    command, and its `env` is exactly its `ALLOWED_ENV_DIFFERENCES` entries."""
    for key in sorted(set(doc) - _RELEASE_TARGET_WORKFLOW_KEYS, key=str):
        errors.append(
            f"check 23: {side.value} has a workflow `{key}`, which reaches every release-target step; refused"
        )
    want = {a.key: a.value for a in ALLOWED_ENV_DIFFERENCES if a.side is side}
    env = doc.get("env", {})
    why = _pin_refusal(env, want, f"{side.value} workflow env")
    if why is not None:
        errors.append(
            f"check 23: {why}: a release-target workflow's `env` is exactly its ALLOWED_ENV_DIFFERENCES "
            "entries, each named with why it cannot change what compiles; refused"
        )


def _check_job_scope(job: dict, where: str, keys: frozenset[str], runs_on: str, errors: list[str]) -> None:
    for key in sorted(set(job) - keys, key=str):
        errors.append(
            f"check 23: {where} has a job `{key}`, which changes what its cargo command runs or lets the job "
            "succeed without it; refused"
        )
    if not _same_value(job.get("runs-on"), runs_on):
        errors.append(f"check 23: {where} runs on {job.get('runs-on')!r}; it must be exactly {runs_on!r}")
    steps = job.get("steps")
    if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
        errors.append(f"check 23: {where}'s `steps` must be a list of step mappings; refused")


def _matrix_legs(job: dict, where: str, keys: frozenset[str], errors: list[str]) -> dict[str, dict] | None:
    """`job`'s `strategy.matrix.include` legs keyed by target: each leg holds
    exactly `keys`, every value a string of its grammar."""
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    include = matrix.get("include") if isinstance(matrix, dict) else None
    if (
        not isinstance(strategy, dict)
        or not set(strategy) <= {"fail-fast", "matrix"}
        or not isinstance(strategy.get("fail-fast", False), bool)
        or not isinstance(matrix, dict)
        or set(matrix) != {"include"}
        or not isinstance(include, list)
        or not all(isinstance(leg, dict) for leg in include)
    ):
        errors.append(
            f"check 23: {where} must have a `strategy` of a boolean `fail-fast` and a matrix of only an "
            "`include` list of mappings; refused"
        )
        return None
    legs: dict[str, dict] = {}
    for leg in include:
        if set(leg) != keys or not all(isinstance(v, str) for v in leg.values()):
            errors.append(
                f"check 23: {where}: a matrix leg must hold exactly {sorted(keys)!r}, each a literal string, "
                f"and is {leg!r}; refused"
            )
            return None
        bad = sorted(
            k for k, v in leg.items() if not (_MATRIX_EXT_RE if k == "ext" else _MATRIX_WORD_RE).fullmatch(v)
        )
        if bad:
            errors.append(
                f"check 23: {where}: matrix leg {leg!r} has {bad!r} outside the runner-label and target-triple "
                "grammar, which a step could read as shell or expression syntax; refused"
            )
            return None
        target = leg["target"]
        if target in legs:
            errors.append(f"check 23: {where}: target {target!r} appears in more than one leg")
            return None
        legs[target] = leg
    return legs


def _checkout_pin(side: _Side) -> dict:
    """The first step of every release-target job: a commit-pinned checkout,
    of exactly the parsed tag on release.yml's side and of the tree under test
    on ci.yml's."""
    pin: dict = {"uses": _Pin(_CHECKOUT_PIN)}
    if side is _Side.RELEASE:
        pin["with"] = {"ref": RELEASE_CHECKOUT_REF}
    return pin


def _check_tag_need(job: dict, where: str, errors: list[str]) -> None:
    """release.yml's checkout reads the tag `RELEASE_TAG_JOB` parsed; without
    the `needs` the expression reads empty and the checkout falls back to the
    event's ref, a branch on a dispatch."""
    needs = job.get("needs")
    if not (needs == RELEASE_TAG_JOB or (isinstance(needs, list) and RELEASE_TAG_JOB in needs)):
        errors.append(f"check 23: {where} must need `{RELEASE_TAG_JOB}`, whose tag its checkout builds; refused")


def _native_pins(side: _Side) -> tuple[dict, dict, dict]:
    verb = "check" if side is _Side.CI else "build"
    return (
        _checkout_pin(side),
        {"uses": RELEASE_TARGET_ACTION, "with": {"target": _MATRIX_TARGET}},
        {
            "shell": _RELEASE_TARGET_SHELL,
            "env": {"TARGET": _MATRIX_TARGET},
            "run": _Lines((_release_cargo_line(verb, native=True),)),
        },
    )


def _check_native_job(side: _Side, job: dict, where: str, errors: list[str]) -> None:
    """The job's first three steps are exactly its checkout, the shared
    `RELEASE_TARGET_ACTION` and its one cargo line; ci.yml's job runs nothing
    else."""
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    pins = _native_pins(side)
    whys = (
        "a release-target job's first step is its one checkout, of the tag on release.yml's side",
        f"the second step is exactly `uses: {RELEASE_TARGET_ACTION}` with `target: {_MATRIX_TARGET}`, so "
        "nothing runs between the checkout and the shared step",
        "the third step runs exactly the job's one cargo line under bash, so nothing runs between the shared "
        "step and the cargo command",
    )
    for n, (pin, why) in enumerate(zip(pins, whys), start=1):
        step = steps[n - 1] if len(steps) >= n else None
        _pinned_step(step, pin, f"{where} step {n}", why, errors)
    if side is _Side.CI and len(steps) != len(pins):
        errors.append(
            f"check 23: {where} has {len(steps)} steps; it runs exactly the checkout, the shared step and the "
            "cargo line, and nothing after them; refused"
        )


def _vm_pin(side: _Side, run: object) -> dict:
    return {"uses": _Pin(_VM_ACTION_RE), "with": {**_VM_PRELUDE, "run": run}}


def _check_freebsd_job(side: _Side, job: dict, where: str, errors: list[str]) -> str | None:
    """The job's first two steps are exactly its checkout and the FreeBSD VM
    step, whose `run` is exactly the cargo line on ci.yml's side and opens
    with it on release.yml's; ci.yml's job runs nothing else. The VM step's
    `uses`, or None."""
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    first = steps[0] if steps else None
    _pinned_step(first, _checkout_pin(side), f"{where} step 1", "a release-target job's first step is its one checkout, of the tag on release.yml's side", errors)
    vm = steps[1] if len(steps) >= 2 else None
    line = _release_cargo_line("check" if side is _Side.CI else "build", native=False)
    run: object = _Lines((line,))
    if side is _Side.RELEASE and isinstance(vm, dict) and isinstance(vm.get("with"), dict):
        text = vm["with"].get("run")
        if isinstance(text, str) and _run_lines(text)[:1] == [line]:
            run = text
    ok = _pinned_step(
        vm,
        _vm_pin(side, run),
        f"{where} step 2",
        f"the second step is exactly the FreeBSD VM step with {_VM_PRELUDE!r}, its `run` opening with "
        f"`{line}` (and only that on ci.yml's side)",
        errors,
    )
    if side is _Side.CI and len(steps) != 2:
        errors.append(
            f"check 23: {where} has {len(steps)} steps; it runs exactly the checkout and the VM step, and "
            "nothing after them; refused"
        )
    return vm.get("uses") if ok and isinstance(vm, dict) else None


def _local_composite(uses: str, repo: str, where: str, depth: int, errors: list[str]) -> tuple[dict, list[dict]] | None:
    """The document and step mappings of the local composite action `uses`
    names, or None (refused) when it nests past `LOCAL_ACTION_DEPTH_LIMIT`
    levels or cannot be read as a composite of step mappings."""
    rel = posixpath.normpath(uses.split("@", 1)[0][2:])
    found = [os.path.join(repo, rel, n) for n in ("action.yml", "action.yaml") if os.path.isfile(os.path.join(repo, rel, n))]
    if depth >= LOCAL_ACTION_DEPTH_LIMIT or len(found) != 1:
        why = "nests local actions too deep" if found else "has no single action.yml/action.yaml"
        _refuse_once(errors, f"check 23: {where}: local action {uses!r} {why}, so what it runs cannot be read; refused")
        return None
    try:
        with open(found[0]) as f:
            doc = strict_yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        _refuse_once(errors, f"check 23: {where}: local action {uses!r} is unreadable ({e}); refused")
        return None
    runs = doc.get("runs") if isinstance(doc, dict) else None
    steps = runs.get("steps") if isinstance(runs, dict) and runs.get("using") == "composite" else None
    if not isinstance(steps, list) or not all(isinstance(st, dict) for st in steps):
        _refuse_once(errors, f"check 23: {where}: local action {uses!r} is not a composite of step mappings; refused")
        return None
    return doc, steps


def _refuse_once(errors: list[str], message: str) -> None:
    """Several scans read the same local action; its refusal is listed once."""
    if message not in errors:
        errors.append(message)


# The pinned body of each local action the pinned steps run: its inputs
# (descriptions aside) and its steps (names aside). An action outside this
# table is never reached before a cargo command.
_LOCAL_ACTION_PINS: dict[str, tuple[dict, list[dict]]] = {
    RELEASE_TARGET_ACTION: (
        {"target": {"required": True}},
        [
            {"uses": _TOOLCHAIN_ACTION, "with": {"targets": "${{ inputs.target }}"}},
            {"uses": _Pin(_RUST_CACHE_PIN_RE), "with": {"save-if": RUST_CACHE_SAVE_IF}},
            {"if": "contains(inputs.target, 'musl')", "shell": _RELEASE_TARGET_SHELL, "run": _Lines(_MUSL_INSTALL_RUN)},
        ],
    ),
    _TOOLCHAIN_ACTION: (
        {"components": {"required": False, "default": ""}, "targets": {"required": False, "default": ""}},
        [
            {"id": "channel", "shell": _RELEASE_TARGET_SHELL, "run": _Lines(_TOOLCHAIN_CHANNEL_RUN)},
            {
                "uses": _Pin(_DTOLNAY_PIN_RE),
                "with": {
                    "toolchain": "${{ steps.channel.outputs.channel }}",
                    "components": "${{ inputs.components }}",
                    "targets": "${{ inputs.targets }}",
                },
            },
            {"shell": _RELEASE_TARGET_SHELL, "run": _Lines(("rustc --version",))},
        ],
    ),
}
_ACTION_TOP_KEYS = frozenset({"name", "description", "inputs", "runs"})


def _check_local_action_pins(repo: str, errors: list[str]) -> None:
    """Every local action a pinned step runs is exactly its
    `_LOCAL_ACTION_PINS` body: the toolchain, cache and musl steps, and
    nothing else, before any release-target cargo command."""
    for uses, (inputs_pin, steps_pin) in _LOCAL_ACTION_PINS.items():
        where = f"local action {uses!r}"
        got = _local_composite(uses, repo, where, 0, errors)
        if got is None:
            continue
        doc, steps = got
        for key in sorted(set(doc) - _ACTION_TOP_KEYS, key=str):
            errors.append(f"check 23: {where} has a top-level `{key}`, which no pin names; refused")
        if not _same_value(doc.get("runs"), {"using": "composite", "steps": steps}):
            errors.append(f"check 23: {where}'s `runs` must hold only `using: composite` and `steps`; refused")
        inputs = doc.get("inputs")
        bare = (
            {k: {f: v for f, v in spec.items() if f != "description"} if isinstance(spec, dict) else spec for k, spec in inputs.items()}
            if isinstance(inputs, dict)
            else inputs
        )
        why = _pin_refusal(bare, inputs_pin, f"{where} inputs (descriptions aside)")
        if why is not None:
            errors.append(f"check 23: {why}; refused")
        if len(steps) != len(steps_pin):
            errors.append(
                f"check 23: {where} has {len(steps)} steps where its pin has {len(steps_pin)}: a step no pin "
                "names runs before the cargo command; refused"
            )
        for n, (step, pin) in enumerate(zip(steps, steps_pin), start=1):
            _pinned_step(step, pin, f"{where} step {n}", "a pinned local action runs exactly its pinned steps", errors)


@dataclass(frozen=True)
class _JobStep:
    """A step a job runs: one of its own (`top` is its 1-based number) or one
    of a local composite action that step uses, at any depth (`top` is the
    number of the job step that uses it)."""

    top: int
    where: str
    step: dict
    in_action: bool


def _job_steps(job: dict, where: str, repo: str, errors: list[str]) -> list[_JobStep]:
    """Every step `job` runs, its local actions' steps included."""
    out: list[_JobStep] = []

    def walk(uses: object, top: int, swhere: str, depth: int) -> None:
        if not (isinstance(uses, str) and uses.startswith("./")):
            return
        got = _local_composite(uses, repo, swhere, depth, errors)
        for n, st in enumerate(got[1] if got else [], start=1):
            inner = f"{swhere} -> {uses} step {n}"
            out.append(_JobStep(top, inner, st, True))
            walk(st.get("uses"), top, inner, depth + 1)

    for n, st in enumerate(_steps_of(job), start=1):
        swhere = f"{where} step {n}"
        out.append(_JobStep(n, swhere, st, False))
        walk(st.get("uses"), n, swhere, 0)
    return out


def _check_checkouts(job: dict, where: str, repo: str, errors: list[str]) -> None:
    """The first step is the job's only checkout: a second one, anywhere in
    the job or in a local action it uses (`uses:` read with owner and repo
    case-folded, as GitHub reads them), replaces the tree the job built or
    ships."""
    for js in _job_steps(job, where, repo, errors):
        if (js.top != 1 or js.in_action) and _is_checkout(js.step):
            errors.append(
                f"check 23: {js.where} runs `{js.step.get('uses')}`, a second checkout: it can replace the tree "
                "the job builds, and the first step is the job's only checkout; refused"
            )


def _check_shells(job: dict, where: str, repo: str, errors: list[str]) -> None:
    """Every `run` step of `job`, its local actions' included, names `shell:
    bash`, the shell the run-text scans read."""
    for js in _job_steps(job, where, repo, errors):
        if "run" in js.step and js.step.get("shell") != _RELEASE_TARGET_SHELL:
            errors.append(
                f"check 23: {js.where} runs under `shell: {js.step.get('shell')!r}`, which the run-text scans "
                f"do not read as written; it must name `shell: {_RELEASE_TARGET_SHELL}`; refused"
            )


# A line continuation the shell removes before it reads a name: bash's
# backslash-newline, pwsh's backtick-newline, either with a CR before the
# newline. `car\` + newline + `go` is `cargo` to bash.
_LINE_CONTINUATION_RE = re.compile(r"[\\`]\r?\n")
_SHELL_WORD_TEXT_RE = re.compile(r"[ \t;&|()\n`]")
_EXPRESSION_RE = re.compile(r"\$\{\{.*?\}\}", re.S)
# A build run outside the one pinned cargo line: after it, either can
# rebuild the artifact the job ships.
_REBUILDERS = frozenset({"cargo", "rustc"})


def _scanned_texts(text: str) -> tuple[str, ...]:
    """`text` as the name scans read it: as written and, when it differs,
    with every line continuation removed. Removing one where the shell would
    not (inside single quotes) only adds a text to scan, never drops one."""
    joined = _LINE_CONTINUATION_RE.sub("", text)
    return (text,) if joined == text else (text, joined)


def _word_re(names: frozenset[str]) -> re.Pattern[str]:
    """`names` as words of a text (`.exe` allowed after one), never part of
    a path component, a hyphenated or an underscored name: `~/.cargo/bin`
    and `CARGO_HOME` name no `cargo`; `cargo-zigbuild` does."""
    alt = "|".join(re.escape(n) for n in sorted(names))
    return re.compile(rf"(?<![A-Za-z0-9_.-])(?:{alt})(?:\.exe)?(?![A-Za-z0-9_])", re.IGNORECASE)


def _named_commands(text: str, names: frozenset[str], depth: int = 0) -> set[str]:
    """Which of `names` `text` can run, read two ways: as words of the text
    (as written and continuations joined) and as the shell reads it (quotes
    removed, so `c""argo` is `cargo`), every word of every command, the text
    of a quoted word that holds shell syntax (an `sh -c` body, an `echo .. |
    sh` feed) and of a here-document read again as shell, to
    `cargo_invocation.NESTING_LIMIT` levels. Past that limit every name is
    reported, so the caller refuses."""
    if depth > cargo_invocation.NESTING_LIMIT:
        return set(names)
    found = {m.group(0).casefold().removesuffix(".exe") for t in _scanned_texts(text) for m in _word_re(names).finditer(t)}
    joined = _EXPRESSION_RE.sub("$GITHUB_EXPRESSION", _scanned_texts(text)[-1])
    for body in (joined, *shell_lex.heredoc_bodies(joined)):
        for cmd in shell_lex.split_commands(body):
            for word in cmd.words:
                base = posixpath.basename(word).casefold().removesuffix(".exe")
                if base in names:
                    found.add(base)
                if _SHELL_WORD_TEXT_RE.search(word) and word != body:
                    found |= _named_commands(word, names, depth + 1)
    return {n for n in names if n.casefold() in found}


def _check_tail(job: dict, where: str, first_tail: int, vm_tail: str | None, repo: str, errors: list[str]) -> None:
    """Defence in depth over release.yml's steps after its cargo command
    (from step `first_tail`, and `vm_tail`, the VM `run` lines after the
    cargo line), which no pin holds: a `cargo` or `rustc` word, as written,
    continuations joined or as the shell reads it, is refused there."""
    texts: list[tuple[str, str]] = []
    if vm_tail is not None:
        texts.append((f"{where} step 2 with.run (after the cargo line)", vm_tail))
    for js in _job_steps(job, where, repo, errors):
        if js.top >= first_tail:
            body = {k: v for k, v in js.step.items() if k != "name"}
            texts.extend((f"{js.where} {label}", text) for label, text, _if in _string_scalars(body, js.where, errors))
    for at, text in texts:
        for name in sorted(_named_commands(text, _REBUILDERS)):
            errors.append(
                f"check 23: {at} runs `{name}` after the cargo command: a second build can rebuild what the job "
                "ships; refused"
            )


def check_release_target_parity(errors: list[str], root: str = REPO_ROOT) -> None:
    """Check 23 (see the module docstring)."""
    repo = os.path.dirname(root)
    by_file = {wf.fname: wf for wf in _load_workflows(root, errors)}
    jobs: dict[str, dict[str, dict]] = {}
    for fname, wanted in (
        ("ci.yml", (CI_RELEASE_NATIVE_JOB, CI_RELEASE_FREEBSD_JOB)),
        (RELEASE_WORKFLOW, (RELEASE_NATIVE_JOB, RELEASE_FREEBSD_JOB, RELEASE_PUBLISH_JOB)),
    ):
        wf = by_file.get(fname)
        if wf is None:
            errors.append(f"check 23: .github/workflows/{fname} is missing; refused")
            return
        have = {wj.job_id: wj.raw for wj in wf.jobs}
        for job_id in wanted:
            if job_id not in have:
                errors.append(f"check 23: {fname} has no job {job_id!r}, which the release-target parity needs")
                return
        jobs[fname] = {job_id: have[job_id] for job_id in wanted}
    ci, rel = jobs["ci.yml"], jobs[RELEASE_WORKFLOW]
    for side in _Side:
        _check_workflow_scope(side, by_file[side.value].doc, errors)
    _check_local_action_pins(repo, errors)

    ci_native, rel_native = ci[CI_RELEASE_NATIVE_JOB], rel[RELEASE_NATIVE_JOB]
    ci_bsd, rel_bsd = ci[CI_RELEASE_FREEBSD_JOB], rel[RELEASE_FREEBSD_JOB]
    for side, job, name, native in (
        (_Side.CI, ci_native, CI_RELEASE_NATIVE_JOB, True),
        (_Side.CI, ci_bsd, CI_RELEASE_FREEBSD_JOB, False),
        (_Side.RELEASE, rel_native, RELEASE_NATIVE_JOB, True),
        (_Side.RELEASE, rel_bsd, RELEASE_FREEBSD_JOB, False),
    ):
        where = f"{side.value} job {name!r}"
        _check_job_scope(
            job,
            where,
            _NATIVE_JOB_KEYS if native else _FREEBSD_JOB_KEYS,
            _NATIVE_RUNS_ON if native else _FREEBSD_RUNS_ON,
            errors,
        )
        if side is _Side.RELEASE:
            _check_tag_need(job, where, errors)
        _check_checkouts(job, where, repo, errors)
        _check_shells(job, where, repo, errors)
    for side, job, name in ((_Side.CI, ci_native, CI_RELEASE_NATIVE_JOB), (_Side.RELEASE, rel_native, RELEASE_NATIVE_JOB)):
        _check_native_job(side, job, f"{side.value} job {name!r}", errors)
    _check_tail(rel_native, f"{RELEASE_WORKFLOW} job {RELEASE_NATIVE_JOB!r}", 4, None, repo, errors)
    _compare("checkout action", (_steps_of(ci_native) or [{}])[0].get("uses"), (_steps_of(rel_native) or [{}])[0].get("uses"), errors)

    vm_uses = {}
    for side, job, name in ((_Side.CI, ci_bsd, CI_RELEASE_FREEBSD_JOB), (_Side.RELEASE, rel_bsd, RELEASE_FREEBSD_JOB)):
        vm_uses[side] = _check_freebsd_job(side, job, f"{side.value} job {name!r}", errors)
    if vm_uses[_Side.CI] is not None and vm_uses[_Side.RELEASE] is not None:
        _compare("FreeBSD VM action", vm_uses[_Side.CI], vm_uses[_Side.RELEASE], errors)
    rel_vm_run = next(iter(s.get("with", {}).get("run") for s in _steps_of(rel_bsd)[1:2] if isinstance(s.get("with"), dict)), None)
    vm_tail = "\n".join(_run_lines(rel_vm_run)[1:]) if isinstance(rel_vm_run, str) else None
    _check_tail(rel_bsd, f"{RELEASE_WORKFLOW} job {RELEASE_FREEBSD_JOB!r}", 3, vm_tail, repo, errors)
    _compare(
        "checkout action (FreeBSD)",
        (_steps_of(ci_bsd) or [{}])[0].get("uses"),
        (_steps_of(rel_bsd) or [{}])[0].get("uses"),
        errors,
    )

    ci_legs = _matrix_legs(ci_native, f"ci.yml job {CI_RELEASE_NATIVE_JOB!r}", _CI_LEG_KEYS, errors)
    rel_legs = _matrix_legs(rel_native, f"{RELEASE_WORKFLOW} job {RELEASE_NATIVE_JOB!r}", _RELEASE_LEG_KEYS, errors)
    if ci_legs is None or rel_legs is None:
        return
    for target, leg in sorted(rel_legs.items()):
        if target not in ci_legs:
            errors.append(
                f"check 23: {RELEASE_WORKFLOW} builds {target!r} but ci.yml's {CI_RELEASE_NATIVE_JOB} never checks it"
            )
        elif ci_legs[target]["os"] != leg["os"]:
            errors.append(
                f"check 23: target {target!r} runs on {ci_legs[target]['os']!r} in ci.yml but "
                f"{leg['os']!r} in {RELEASE_WORKFLOW}; they must be equal"
            )
    for target in sorted(set(ci_legs) - set(rel_legs)):
        errors.append(f"check 23: ci.yml checks {target!r}, which {RELEASE_WORKFLOW} does not build")

    published = {leg.get("artifact") for leg in rel_legs.values()}
    for step in _steps_of(rel_bsd):
        with_ = step.get("with")
        if uses_action(step.get("uses"), "actions/upload-artifact") and isinstance(with_, dict):
            published.add(with_.get("name"))
    expected_sets = [
        set(m.group(1).split())
        for step in _steps_of(rel[RELEASE_PUBLISH_JOB])
        for m in _RELEASE_EXPECTED.finditer(str(step.get("run", "")))
    ]
    expected = _only(expected_sets, f"{RELEASE_WORKFLOW} job {RELEASE_PUBLISH_JOB!r}", "`expected=\"..\"` list", errors)
    if isinstance(expected, set):
        for name in sorted(str(n) for n in published - expected):
            errors.append(f"check 23: {RELEASE_WORKFLOW} publishes {name!r} but its completeness gate does not expect it")
        for name in sorted(expected - published):
            errors.append(f"check 23: {RELEASE_WORKFLOW}'s completeness gate expects {name!r}, which no job publishes")


def load_manifest() -> dict:
    doc = strict_yaml.safe_load(open(MANIFEST))
    if not isinstance(doc, dict) or "checks" not in doc:
        print("verify-manifest: manifest missing top-level `checks:`", file=sys.stderr)
        sys.exit(2)
    return doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.parse_args()

    manifest = load_manifest()
    entries = manifest["checks"]
    by_context: dict[str, dict] = {}
    errors: list[str] = []

    # ---- 2. manifest self-consistency ----
    for e in entries:
        ctx = e.get("context")
        disp = e.get("disposition")
        if not ctx:
            errors.append(f"manifest entry without a context: {e!r}")
            continue
        if ctx in by_context:
            errors.append(f"duplicate manifest context: {ctx!r}")
        by_context[ctx] = e
        if disp not in VALID_DISPOSITIONS:
            errors.append(f"{ctx!r}: invalid disposition {disp!r} (want one of {sorted(VALID_DISPOSITIONS)})")
            continue
        if disp == "informational" and not e.get("owner"):
            errors.append(f"{ctx!r}: informational check must name an `owner`")
        if disp == "informational" and e.get("guards"):
            errors.append(
                f"{ctx!r}: guards {e['guards']!r} but is informational — a "
                "Security/Soundness/SEAL guarantee may not be un-gated"
            )
        if disp in ("gate", "nightly-gate") and not e.get("producer"):
            errors.append(f"{ctx!r}: {disp} entry has no producer workflow")
        if disp == "gate-external" and e.get("producer"):
            errors.append(
                f"{ctx!r}: disposition=gate-external must have no producer — the "
                "status is posted out-of-band, not by a CI workflow"
            )
        if disp == "delete" and e.get("producer"):
            errors.append(
                f"{ctx!r}: disposition=delete but a producer is set — a live "
                "check may not be marked delete"
            )

    # ---- 1. every produced context is classified ----
    jobs = workflow_jobs()
    produced = produced_contexts(jobs)
    manifest_ctxs = set(by_context)

    # A context named in some entry's `aggregates:` list is an internal matrix
    # leg / prep job whose result rolls up into that single promotable context;
    # it inherits the aggregator's disposition and is considered classified.
    # `aggregates:` names the job id or the leg-name PREFIX (matrix legs expand
    # to "<name> (i/n)"), so match by exact id or by prefix.
    aggregated_prefixes: list[str] = []
    aggregated_exact: set[str] = set()
    for e in by_context.values():
        for agg in e.get("aggregates") or []:
            aggregated_exact.add(agg)
            aggregated_prefixes.append(agg)

    def is_aggregated(ctx: str) -> bool:
        if ctx in aggregated_exact:
            return True
        # matrix leg "asan (1/6)" is aggregated by "asan"
        return any(ctx.startswith(p + " (") or ctx == p for p in aggregated_prefixes)

    for ctx, wfs in sorted(produced.items()):
        if len(wfs) > 1:
            errors.append(
                f"context {ctx!r} is produced by {len(wfs)} jobs ({', '.join(wfs)}) — "
                "a required context must resolve to exactly one producer; give "
                "each job a unique `name:`"
            )
        if ctx in manifest_ctxs or is_aggregated(ctx):
            continue
        errors.append(
            f"produced context {ctx!r} (from {wfs[0]}) has NO disposition in "
            "ci/check-manifest.yml — every check must be classified"
        )

    # ---- 5. ci/deterministic-checks.json vs the watcher + ci.yml steps ----
    check_deterministic_set(jobs, errors)

    # ---- 6+7. rustc wiring + cache saves; pinned CI inputs + env-file writes ----
    check_workflow_steps(errors)

    # ---- 8. merge queue: gate producers trigger on it; its runs stay secret-free ----
    check_merge_queue(
        {
            str(e["producer"])
            for e in by_context.values()
            if e.get("disposition") == "gate" and e.get("producer")
        },
        errors,
    )

    # ---- 9. no release-only skip-as-pass on a gate producer ----
    check_release_only_skips(
        {ctx for ctx, e in by_context.items() if e.get("disposition") == "gate"},
        errors,
    )

    # ---- 10. fast gate first: heavy test shards need every fast gate ----
    check_fast_gate_first(
        {ctx for ctx, e in by_context.items() if e.get("disposition") == "gate"},
        errors,
    )
    # ---- 11. CI phases: each job in one phase; later-phase contexts report a fail-closed verdict ----
    check_phase_routing(
        {ctx for ctx, e in by_context.items() if e.get("disposition") == "gate"},
        errors,
    )
    # ---- 12. gate integrity: pull_request_target runs no head code; trust roots live ----
    check_pull_request_target(errors)
    check_trust_roots(errors)

    # ---- 13. push runs: every push commit gets its own concurrency group ----
    check_push_concurrency(errors)

    # ---- 14. one lock per dependency graph; Dependabot updates that lock ----
    check_one_lock_per_graph(errors)

    # ---- 15. one `ipe` build in ci.yml; its consumers need the producer ----
    check_one_ipe_build(errors)

    # ---- 16. a path-scoped job's scope covers every file it compiles ----
    check_scoped_package_coverage(errors)

    # ---- 17. a drift check also sees untracked generated files ----
    check_drift_sees_untracked(errors)

    # ---- 18. Dependabot's open update PRs fit the open-PR budget ----
    check_dependabot_pr_budget(errors)

    # ---- 19. Every workspace member inherits the workspace edition and lints ----
    check_workspace_inheritance(errors)

    # ---- 20. Every non-host test cell is run by the job that claims it ----
    check_test_claims(errors)

    # ---- 21. Every CI-tooling refusal suite runs in a required job ----
    check_ci_suites_required(entries, errors)

    # ---- 22. Every cargo feature is compiled by a required job ----
    check_feature_coverage(entries, errors)

    # ---- 23. ci.yml checks exactly the targets release.yml builds ----
    check_release_target_parity(errors)

    # ---- 3. fail-closed dependency surfacing ----
    def surfaced_dispositions(job: Job) -> set[str]:
        """Dispositions of the manifest entries this job's outcome reaches."""
        disps: set[str] = set()
        for ctx in job.contexts:
            entry = by_context.get(ctx)
            if entry:
                disps.add(entry["disposition"])
        for entry in by_context.values():
            for agg in entry.get("aggregates") or []:
                if agg == job.job_id or any(
                    c == agg or c.startswith(agg + " (") for c in job.contexts
                ):
                    disps.add(entry["disposition"])
        return disps

    surfacing = {"gate": {"gate"}, "nightly-gate": {"gate", "nightly-gate"}}
    for job in jobs:
        direct = {by_context[c]["disposition"] for c in job.contexts if c in by_context}
        siblings = {j.job_id: j for j in jobs if j.workflow == job.workflow}
        for disp, allowed in surfacing.items():
            if disp not in direct:
                continue
            seen: set[str] = set()
            pending = list(job.needs)
            while pending:
                dep_id = pending.pop()
                if dep_id in seen:
                    continue
                seen.add(dep_id)
                dep = siblings.get(dep_id)
                if dep is None:
                    errors.append(f"{job.workflow}: job {job.job_id!r} needs unknown job {dep_id!r}")
                    continue
                if surfaced_dispositions(dep).isdisjoint(allowed):
                    errors.append(
                        f"{job.workflow}: {disp} {job.contexts[0]!r} needs {dep_id!r}, "
                        f"which surfaces in no {'/'.join(sorted(allowed))} context — its "
                        "failure would skip the gate, and a skipped required check "
                        "passes (fail-open)"
                    )
                pending.extend(dep.needs)

    # A manifest gate/nightly-gate that claims a live producer but is not
    # actually produced (an orphan the other way).  gate-external is excluded:
    # its whole purpose is to be required without a CI producer.
    for ctx, e in by_context.items():
        if e.get("internal"):
            continue
        if e["disposition"] in ("gate", "nightly-gate") and ctx not in produced:
            errors.append(
                f"{ctx!r}: disposition={e['disposition']} with producer "
                f"{e.get('producer')!r} but NO workflow produces this context "
                "(orphaned required context — wire it or set disposition:delete)"
            )

    # ---- 11. local gate: every `gate` declares one typed `local:` disposition,
    # and each local command mirrors its producer job's CI step ----
    import local_gate  # noqa: PLC0415  # sibling module; sys.path holds this dir

    local_gate.check_local_dispositions(entries, errors)

    # ---- 4. the committed required set is the manifest's derived set ----
    import check_required_set  # noqa: PLC0415  # sibling module; SSOT of the derivation

    try:
        derived = check_required_set.derive(manifest)
        with open(check_required_set.REQUIRED_SET, encoding="utf-8") as f:
            on_disk = check_required_set.parse_pairs(json.load(f), "ci/required-set.json")
    except (check_required_set.Refused, OSError, UnicodeDecodeError, ValueError) as e:
        errors.append(f"check 4: {e}")
    else:
        errors.extend(
            f"check 4: {line}"
            for line in check_required_set.diff(
                derived, on_disk, "ci/required-set.json",
                "regenerate it: python3 .github/ci/check_required_set.py --write",
            )
        )

    if errors:
        print("\nverify-manifest: FAIL\n", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(file=sys.stderr)
        return 1

    n_gate = sum(1 for e in entries if e["disposition"] == "gate")
    n_gate_ext = sum(1 for e in entries if e["disposition"] == "gate-external")
    n_nightly = sum(1 for e in entries if e["disposition"] == "nightly-gate")
    n_info = sum(1 for e in entries if e["disposition"] == "informational")
    n_del = sum(1 for e in entries if e["disposition"] == "delete")
    print(
        f"verify-manifest: OK — {len(entries)} checks classified "
        f"({n_gate} gate, {n_gate_ext} gate-external, {n_nightly} nightly-gate, "
        f"{n_info} informational, {n_del} delete); "
        f"{len(produced)} produced contexts, all covered."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
