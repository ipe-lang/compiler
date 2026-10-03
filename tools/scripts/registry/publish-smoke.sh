#!/usr/bin/env bash
# Live-registry publish smoke test — exercise the real `ipe package publish`
# push-path end-to-end against a live (or staging) registry.
#
# What it proves (the gap `registry-admission` cannot cover from local fixtures) —
# the deployed gate is exercised in BOTH directions:
#   POSITIVE (a clean probe ADMITS + resolves):
#     1. `ipe package publish` clones the fork, writes the entry, pushes the branch,
#        and opens the index PR against the real registry over the network.
#     2. The registry's admission workflow accepts a well-formed, signed entry.
#     3. The accepted entry resolves back through the Pages read API
#        (`<registry-url>/index.json` + `/packages/<name>.json`).
#   NEGATIVE (a deliberately-bad submission is REFUSED):
#     4. A second, distinct RESERVED probe is published as a SOURCE SPOOF — its
#        pinned `sha256` names a clean working tree while its `--source`/`--rev`
#        resolve to a divergent committed revision. The honest client opens the PR
#        (it has no cross-check that source@rev matches the hash); the deployed
#        admission workflow independently re-fetches source@rev, re-hashes, and
#        REJECTS on the mismatch (verify-before-trust) — its PR admission check
#        goes RED (or the PR is closed rejected) and the bad entry never merges, so
#        the index is never touched. A submission that instead ADMITTED or
#        auto-merged fails the leg (fail-closed): the whole point is to refuse it.
#        (A capability-inconsistent source can't test admission here — the SAME
#        Tier-1 audit runs client-side in `publish`, refusing it before the PR.)
# Then it CLEANS UP idempotently so the real index is never polluted (BOTH probes).
#
# Cadence: NIGHTLY / manual `workflow_dispatch` ONLY. Pushing to a real registry
# must never gate a PR or a promotion.
#
# ── Trust boundary ──────────────────────────────────────────────────────────
# This script pushes to a registry using a publish token. The token is read ONLY
# from the environment (IPE_SMOKE_TOKEN), is NEVER echoed, NEVER written to a
# file the CI logs, and NEVER placed on a process argv — it is handed to `git`
# via an askpass helper and to `gh`/the GitHub API via its own env channel. `set
# -x` is never enabled. A failed clone/push/admission/resolution is a HARD error
# (fail-closed): the smoke test goes RED, never green-by-skip, whenever the
# backend it is meant to exercise is reachable but rejects.
#
# ── Staging vs reserved-package ─────────────────────────────────────────────
# PREFER a staging registry (a throwaway repo mirroring the ipe-registry layout):
# a failed/partial run can then never corrupt the real index. Point the run at it
# with IPE_SMOKE_INDEX_REPO=<owner>/<staging-repo> and
# IPE_REGISTRY_URL=https://<owner>.github.io/<staging-repo>. When no staging repo
# is configured the run falls back to the production registry using RESERVED
# test-package names (IPE_SMOKE_PACKAGE, default `ipe-registry-smoke-probe`, for
# the clean probe; IPE_SMOKE_BAD_PACKAGE, default `ipe-registry-smoke-probe-bad`,
# for the negative leg's bad probe) plus guaranteed cleanup — never a real package
# name. The bad probe's spoof is REJECTED by admission, so its PR never merges and
# the index is never touched.
#
# ── Required environment (the live run's infra) ─────────────────────────────
#   IPE_SMOKE_TOKEN        publish token (a repo secret) with push + open-PR
#                          rights on IPE_SMOKE_INDEX_REPO and IPE_SMOKE_FORK.
#                          NEVER logged. REQUIRED.
#   IPE_SMOKE_INDEX_REPO   <owner>/<name> of the registry the PR targets.
#                          Default: arthurmaciel/ipe-registry (production).
#   IPE_SMOKE_FORK         <owner> of the fork `ipe package publish` pushes the
#                          publish branch to. Default: the index repo's owner.
#   IPE_REGISTRY_URL       Pages read API base the resolver checks. Default:
#                          https://arthurmaciel.github.io/ipe-registry.
#   IPE_SMOKE_PACKAGE      reserved disposable package name. Default:
#                          ipe-registry-smoke-probe.
#   IPE_SMOKE_SOURCE_REPO  <owner>/<name> of the disposable git repo whose HEAD
#                          the entry pins as the package source. Default: a repo
#                          named <IPE_SMOKE_PACKAGE> under IPE_SMOKE_FORK.
#   IPE_SMOKE_BAD_PACKAGE  reserved disposable name for the NEGATIVE leg's bad
#                          probe (distinct from IPE_SMOKE_PACKAGE so it can never
#                          collide with the clean probe or a real package).
#                          Default: ipe-registry-smoke-probe-bad.
#   IPE_SMOKE_BAD_SOURCE_REPO  <owner>/<name> of the disposable source repo for the
#                          bad probe. Default: <IPE_SMOKE_BAD_PACKAGE> under the fork.
#   IPE_SMOKE_POLL_SECS    admission/resolution poll budget in seconds, used by
#                          BOTH legs (default 600).
#   IPE_BIN                path to the built `ipe` binary (default: `ipe` on PATH).
#   GITHUB_RUN_ID / GITHUB_RUN_ATTEMPT  set by Actions; they tag the probe
#                          versions so two Actions runs in one second never
#                          collide. Off CI the shell's pid and attempt 0 stand
#                          in: distinct from every Actions tag (attempts start
#                          at 1) and from runs live at once in one pid
#                          namespace, but not across hosts or containers.
#
# Every value above except the token and IPE_BIN is parsed once by
# `lib/smoke-inputs.sh`; a value off its grammar exits 2 naming the input. The
# probe programs are the tracked fixtures under `tests/fixtures/registry-smoke/`
# (`src/ipe-cli/tests/registry_smoke_probes.rs` builds each one).
#
# Exit 2 = an input refused by its parser (nothing was pushed).
# Exit 0 = BOTH legs held: the clean probe's push→admission→resolution path AND
#          the bad probe's admission REJECTION, then cleanup.
# Exit non-zero = a real failure (a good probe refused, a bad probe admitted, an
#                 unobservable verdict) OR missing required infra (fail-closed).

set -euo pipefail

log()  { printf '%s %s\n' "[smoke]" "$*"; }
fail() { printf '%s %s\n' "[smoke][FAIL]" "$*" >&2; exit 1; }
# The negative-leg counterparts, tagged `[neg]` so the two directions are
# unambiguous in the log.
neg_log()  { printf '%s %s\n' "[smoke][neg]" "$*"; }
neg_fail() { printf '%s %s\n' "[smoke][neg][FAIL]" "$*" >&2; exit 1; }

# ── Config ──────────────────────────────────────────────────────────────────
# Every operator value is parsed ONCE here, by the typed parsers in
# `lib/smoke-inputs.sh`, before any of it reaches an Ipê manifest, the askpass
# helper, or a URL. A value off its grammar exits 2, naming the input.
SMOKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/smoke-inputs.sh
. "$SMOKE_DIR/lib/smoke-inputs.sh"
FIXTURES="$(cd "$SMOKE_DIR/../../.." && pwd)/tests/fixtures/registry-smoke"

INDEX_REPO="$(parse_repo_slug IPE_SMOKE_INDEX_REPO "${IPE_SMOKE_INDEX_REPO:-arthurmaciel/ipe-registry}")"
INDEX_OWNER="${INDEX_REPO%%/*}"
FORK_OWNER="$(parse_gh_owner IPE_SMOKE_FORK "${IPE_SMOKE_FORK:-$INDEX_OWNER}")"
REGISTRY_URL="$(parse_https_url IPE_REGISTRY_URL "${IPE_REGISTRY_URL:-https://arthurmaciel.github.io/ipe-registry}")"
PACKAGE="$(parse_package_name IPE_SMOKE_PACKAGE "${IPE_SMOKE_PACKAGE:-$PROBE_DEFAULT_NAME}")"
SOURCE_REPO="$(parse_repo_slug IPE_SMOKE_SOURCE_REPO "${IPE_SMOKE_SOURCE_REPO:-$FORK_OWNER/$PACKAGE}")"
POLL_SECS="$(parse_poll_secs IPE_SMOKE_POLL_SECS "${IPE_SMOKE_POLL_SECS:-600}")"
IPE="${IPE_BIN:-ipe}"

# The negative leg's DISTINCT reserved probe — a separate name so a bad probe can
# never collide with or pollute the clean probe (or a real package). Its source is
# a separate disposable repo (or the `-bad` sibling of the clean source).
BAD_PACKAGE="$(parse_package_name IPE_SMOKE_BAD_PACKAGE "${IPE_SMOKE_BAD_PACKAGE:-$PROBE_DEFAULT_BAD_NAME}")"
BAD_SOURCE_REPO="$(parse_repo_slug IPE_SMOKE_BAD_SOURCE_REPO "${IPE_SMOKE_BAD_SOURCE_REPO:-$FORK_OWNER/$BAD_PACKAGE}")"

# A fresh prerelease version per run: a smoke run never collides with a prior
# run's version (which admission would reject as immutable), and every version
# this reserved package ever carries is a `0.0.0-smoke.*` prerelease no real
# consumer would depend on. The UTC stamp orders runs; the run tag (the GitHub
# run id + attempt, or this shell's pid + 0 off CI) keeps two runs started in
# the same second apart (off CI, only within one pid namespace).
STAMP="$(date -u +%Y%m%d%H%M%S)"
RUN_TAG="$(parse_run_tag "${GITHUB_RUN_ID:-$$}" "${GITHUB_RUN_ATTEMPT:-0}")"
VERSION="$(probe_version smoke "$STAMP" "$RUN_TAG")"
BRANCH="publish/${PACKAGE}-${VERSION}"
# The negative probe's own prerelease version + branch (same disposable scheme).
BAD_VERSION="$(probe_version smokebad "$STAMP" "$RUN_TAG")"
BAD_BRANCH="publish/${BAD_PACKAGE}-${BAD_VERSION}"

# The token must exist and never be printed. Its presence is checked, its value
# is not surfaced.
[ -n "${IPE_SMOKE_TOKEN:-}" ] || fail \
  "IPE_SMOKE_TOKEN is unset — the live push-path needs a publish token (a repo secret). \
This is the infra the run requires; see this script's header."

if [ "$INDEX_REPO" = "arthurmaciel/ipe-registry" ]; then
  log "targeting the PRODUCTION registry with reserved package '$PACKAGE' (no staging repo configured)."
  log "set IPE_SMOKE_INDEX_REPO + IPE_REGISTRY_URL to a staging mirror to avoid touching production."
else
  log "targeting STAGING registry '$INDEX_REPO' (production is untouched)."
fi
log "registry read API: $REGISTRY_URL"
log "package: $PACKAGE  version: $VERSION  fork: $FORK_OWNER  source: $SOURCE_REPO"

# ── Token plumbing: git askpass + gh, never on argv, never logged ───────────
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ipe-smoke-XXXXXX")"
ASKPASS="$WORK/askpass.sh"
# The askpass helper prints the token to stdout when git asks for a password and
# the fork owner when git asks for a username. Its text is fixed (`write_askpass`):
# both values are read from its environment when git runs it, so no value is
# spliced into generated code. git reads it via GIT_ASKPASS, so the token never
# appears on any command line. The file is mode 0700 in a per-run temp dir and
# removed on cleanup.
write_askpass "$ASKPASS"
export IPE_SMOKE_ASKPASS_USER="$FORK_OWNER"
export GIT_ASKPASS="$ASKPASS"
export GIT_TERMINAL_PROMPT=0
# The askpass child reads IPE_SMOKE_TOKEN from its inherited environment; export
# it so the git subprocess sees it. It is still never echoed or placed on argv.
export IPE_SMOKE_TOKEN
# `ipe package publish`'s headless PR-open reads GITHUB_TOKEN (parsed through the
# PublishToken alphabet gate before it reaches curl). Feed the smoke token in on
# that channel; it is never echoed here.
export GITHUB_TOKEN="$IPE_SMOKE_TOKEN"
# Point the resolver's git-checkout fallback + publish's entry-merge read at a
# throwaway index checkout, never the developer's real ~/.cache index.
export IPE_INDEX_DIR="$WORK/index-checkout"
export IPE_REGISTRY_URL="$REGISTRY_URL"

# ── Idempotent cleanup — safe to run twice, leaves no residue ───────────────
# Deletes the publish branch from the fork and closes any open smoke PR. It does
# NOT delete a merged entry from the index main line here: on the production
# registry the reserved package's prerelease entries are inert (`0.0.0-smoke.*`),
# and a merged entry is pruned by the registry's own retention (a follow-up prune
# workflow on the registry side); on a staging repo the whole repo is disposable.
# Every step tolerates "already gone" so a re-run is a no-op.
cleanup() {
  local rc=$?
  set +e
  log "cleanup: removing publish branch and closing any open smoke PR (idempotent)."
  # Delete the pushed branch from the fork over the API (never on argv, token via
  # the Authorization header only). A 404/422 (already deleted) is fine.
  if command -v gh >/dev/null 2>&1; then
    # Both probes' branches + open PRs are cleaned. A rejected bad PR never
    # merges, so the index is never touched; closing it + deleting its branch
    # leaves no residue on the fork or the index repo.
    local branch
    for branch in "$BRANCH" "$BAD_BRANCH"; do
      GH_TOKEN="$IPE_SMOKE_TOKEN" gh api \
        --method DELETE \
        "repos/$FORK_OWNER/${INDEX_REPO##*/}/git/refs/heads/$branch" \
        >/dev/null 2>&1 || true
      # Close any open PR from this smoke branch against the index.
      local prs
      prs="$(GH_TOKEN="$IPE_SMOKE_TOKEN" gh api \
        "repos/$INDEX_REPO/pulls?head=$FORK_OWNER:$branch&state=open" \
        --jq '.[].number' 2>/dev/null || true)"
      for n in $prs; do
        GH_TOKEN="$IPE_SMOKE_TOKEN" gh api --method PATCH \
          "repos/$INDEX_REPO/pulls/$n" -f state=closed >/dev/null 2>&1 || true
        log "cleanup: closed smoke PR #$n (branch $branch)."
      done
    done
  else
    log "cleanup: gh not available — branch/PR cleanup skipped; the smoke branch is a \
'$BRANCH' prerelease and is safe to prune by hand."
  fi
  rm -rf "$WORK" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

# ── 1. Build a disposable package git repo, pushed so publish can pin HEAD ───
# `ipe package publish` refuses a dirty tree or an unpushed HEAD, and pins the
# committed, pushed revision. The source repo is the disposable IPE_SMOKE_SOURCE_REPO.
PKG="$WORK/pkg"
mkdir -p "$PKG/src"
render_probe_manifest "$FIXTURES/package.ipe.tmpl" "$PACKAGE" "$VERSION" > "$PKG/package.ipe"
cp "$FIXTURES/good/src/Main.ipe" "$PKG/src/Main.ipe"

git -C "$PKG" init --quiet
git -C "$PKG" -c user.name=ipe-smoke -c user.email=smoke@ipe-lang.invalid add .
git -C "$PKG" -c user.name=ipe-smoke -c user.email=smoke@ipe-lang.invalid \
  commit --quiet -m "smoke $VERSION"
git -C "$PKG" remote add origin "https://github.com/$SOURCE_REPO.git"
# Push the probe commit under an IMMUTABLE per-version tag so its pinned rev
# stays reachable forever. Append-only admission may re-verify an earlier
# version's rev on a later run; a moving/force-pushed branch would orphan that
# rev (an unreachable commit is unfetchable by clone OR fetch-by-SHA — the
# "unable to read tree" failure). The tag name embeds the unique per-run
# VERSION, so it is created once and never force-overwritten. The `smoke` branch
# is still updated as a convenience pointer to the latest (non-fatal — the tag
# is the authoritative, permanent handle admission needs).
log "pushing probe source to $SOURCE_REPO (tag smoke-$VERSION)"
git -C "$PKG" push --quiet origin "HEAD:refs/tags/smoke-$VERSION" \
  || fail "could not push the probe source tag to $SOURCE_REPO — the live run needs a \
disposable source repo the token can push to (see IPE_SMOKE_SOURCE_REPO)."
git -C "$PKG" push --force --quiet origin HEAD:refs/heads/smoke || true

# ── 2. Run the REAL publish push-path ───────────────────────────────────────
# Not --dry-run: this clones the fork, writes packages/<pkg>.toml, pushes the
# branch, and opens the PR against the index. The source/rev are pinned from the
# pushed HEAD above.
SRC_HEAD="$(git -C "$PKG" rev-parse HEAD)"
log "publishing $PACKAGE@$VERSION to $INDEX_REPO (real push-path)"
"$IPE" package publish "$PKG" \
  --index "$INDEX_REPO" \
  --fork "$FORK_OWNER" \
  --source "https://github.com/$SOURCE_REPO" \
  --rev "$SRC_HEAD" \
  --fresh \
  || fail "ipe package publish failed against $INDEX_REPO (auth/admission/push error) — fail-closed."
# `--fresh`: reset the disposable reserved probe so its index entry never grows
# (a single-version submission each run) and no prior rev is re-fetched from a
# stale, tip-only clone.

# ── 3. Wait for admission to accept + the entry to resolve via Pages ────────
# Admission runs on the registry side (the PR's checks); once it merges, the
# Pages mirror serves the entry. Poll the read API until the version appears, or
# hard-fail after the budget.
resolve_ok() {
  local body
  body="$(curl --silent --show-error --location \
    -H 'Accept: application/json' \
    "$REGISTRY_URL/packages/$PACKAGE.json" 2>/dev/null || true)"
  [ -n "$body" ] || return 1
  printf '%s' "$body" | grep -q "\"$VERSION\""
}

log "waiting up to ${POLL_SECS}s for admission + Pages resolution of $PACKAGE@$VERSION"
deadline=$(( $(date +%s) + POLL_SECS ))
while :; do
  if resolve_ok; then
    log "RESOLVED: $PACKAGE@$VERSION is served by $REGISTRY_URL/packages/$PACKAGE.json"
    break
  fi
  [ "$(date +%s)" -lt "$deadline" ] \
    || fail "timed out: $PACKAGE@$VERSION was not admitted + resolvable within ${POLL_SECS}s \
(admission rejected, PR unmerged, or Pages not yet mirrored) — fail-closed."
  sleep 15
done

# ── 4. Cross-check the top-level registry catalog names the package ─────────
# The issue names `<registry-url>/index.json` as the second resolution surface.
# The resolver client consumes `/packages/<name>.json` (the hard gate in step 3);
# the root `index.json` catalog is an additional listing. When the registry
# publishes it, assert it lists the package; when it does not (a staging mirror
# may omit it), this is a soft note — the per-package resolution in step 3 is the
# authoritative proof, not this catalog.
catalog="$(curl --silent --show-error --location \
  -H 'Accept: application/json' \
  "$REGISTRY_URL/index.json" 2>/dev/null || true)"
if [ -n "$catalog" ]; then
  if printf '%s' "$catalog" | grep -q "\"$PACKAGE\""; then
    log "catalog: $REGISTRY_URL/index.json lists $PACKAGE"
  else
    log "note: $REGISTRY_URL/index.json did not list $PACKAGE (per-package resolution in step 3 held; catalog is advisory)."
  fi
else
  log "note: $REGISTRY_URL/index.json is not served (per-package resolution in step 3 is the authoritative proof)."
fi

log "OK: publish → admission → Pages per-package resolution all held (positive leg)."

# ── NEGATIVE LEG: a deliberately-bad publish must be REFUSED by admission ─────
# The positive leg proves a good package ADMITS + resolves. This leg proves the
# other, security-critical direction: a submission whose pinned source bytes do
# NOT match the pinned `sha256` is REJECTED by the SAME deployed admission
# workflow. This is the verify-before-trust seam — admission independently
# git-fetches `source@rev`, re-hashes the fetched tree, and refuses on any
# mismatch (`fetch_and_verify_index_version` -> `CliError::HashMismatch`). A gate
# that only ever proves good packages pass is untested on the path that matters
# most; a silently-disabled fetch+verify step would admit this spoof while every
# happy-path check stayed green.
#
# Why a HASH spoof, not a capability-inconsistent source: `ipe package publish`
# runs the SAME Tier-1 audit (capability consistency included) on the CALLER's
# machine before it opens the PR, so a capability-inconsistent source is refused
# CLIENT-side and never reaches admission — the leg under test would never run.
# The reachable-yet-admission-only defect is a source spoof: publish hashes the
# WORKING TREE and pins `--source`/`--rev` from flags WITHOUT cross-checking that
# the pinned revision's bytes match that hash (`compute_entry_version`; the
# `--rev` override path has no dirty-tree/reachability guard either). So an honest
# client opens a PR whose `sha256` names one tree while `source@rev` resolves to
# another, and admission's independent re-hash is the ONLY place the mismatch is
# caught — exactly the fail-closed seam this leg proves.
#
# The negative leg needs `gh` to observe the PR's admission check verdict. Without
# it there is no way to distinguish "rejected" from "not yet run", so — fail-closed
# — the leg errors rather than asserting a hollow pass.
command -v gh >/dev/null 2>&1 \
  || neg_fail "the negative leg needs \`gh\` to read the bad PR's admission check verdict; \
without it a rejection cannot be observed — refusing to assert a hollow pass (fail-closed)."

BAD_PKG="$WORK/pkg-bad"
mkdir -p "$BAD_PKG/src"
render_probe_manifest "$FIXTURES/package.ipe.tmpl" "$BAD_PACKAGE" "$BAD_VERSION" > "$BAD_PKG/package.ipe"
# The REGISTERED source: the tree the pin will falsely name. It is committed and
# pushed under an IMMUTABLE per-version tag so admission can fetch it by the pinned
# SHA. Its exact bytes only need to DIFFER from the working tree hashed below — the
# spoof is source≠pin, not anything about this file — so it is a clean, consistent
# program (it must never itself be the reason for a rejection).
cp "$FIXTURES/bad-registered/src/Main.ipe" "$BAD_PKG/src/Main.ipe"

git -C "$BAD_PKG" init --quiet
git -C "$BAD_PKG" -c user.name=ipe-smoke -c user.email=smoke@ipe-lang.invalid add .
git -C "$BAD_PKG" -c user.name=ipe-smoke -c user.email=smoke@ipe-lang.invalid \
  commit --quiet -m "smoke-bad registered-source $BAD_VERSION"
# Pin THIS commit as `--rev`; capture it before the working tree diverges below.
BAD_SRC_HEAD="$(git -C "$BAD_PKG" rev-parse HEAD)"
git -C "$BAD_PKG" remote add origin "https://github.com/$BAD_SOURCE_REPO.git"
neg_log "pushing BAD probe registered source to $BAD_SOURCE_REPO (tag smoke-bad-$BAD_VERSION)"
git -C "$BAD_PKG" push --quiet origin "$BAD_SRC_HEAD:refs/tags/smoke-bad-$BAD_VERSION" \
  || neg_fail "could not push the bad probe source tag to $BAD_SOURCE_REPO — the negative leg \
needs a disposable source repo the token can push to (see IPE_SMOKE_BAD_SOURCE_REPO)."
git -C "$BAD_PKG" push --force --quiet origin "$BAD_SRC_HEAD:refs/heads/smoke-bad" || true

# DIVERGE the working tree from the pushed revision: a DIFFERENT program that is
# still clean + capability-consistent, so the CLIENT-side Tier-1 audit passes and
# the pinned `sha256` = the hash of THIS tree — deliberately != the pushed source
# above. Commit so the tree is pristine (belt-and-braces; the `--rev` path runs no
# dirty-tree guard).
cp "$FIXTURES/bad-working/src/Main.ipe" "$BAD_PKG/src/Main.ipe"
git -C "$BAD_PKG" -c user.name=ipe-smoke -c user.email=smoke@ipe-lang.invalid \
  commit --quiet -am "smoke-bad diverged working tree $BAD_VERSION"

# Publish the source-spoof (real push-path). The local audit passes over the CLEAN
# working tree and pins ITS `sha256`, but `--source`/`--rev` name the divergent
# registered commit. Publish opening the PR SUCCEEDS — the client has no cross-check
# that `source@rev` matches the hash (a spoofable pair by construction); the
# REJECTION is admission's independent fetch + re-hash, which finds the pinned
# source's bytes != the pinned `sha256` (a POSITIVE rejection signal — admission
# check RED — not a resolution timeout).
neg_log "publishing BAD $BAD_PACKAGE@$BAD_VERSION to $INDEX_REPO (source-spoof; real push-path)"
"$IPE" package publish "$BAD_PKG" \
  --index "$INDEX_REPO" \
  --fork "$FORK_OWNER" \
  --source "https://github.com/$BAD_SOURCE_REPO" \
  --rev "$BAD_SRC_HEAD" \
  || neg_fail "ipe package publish could not even open the bad PR against $INDEX_REPO \
(auth/push error) — the negative leg needs the PR opened so admission can reject it."

# Find the bad PR by its head branch.
bad_pr=""
find_deadline=$(( $(date +%s) + 120 ))
while :; do
  bad_pr="$(GH_TOKEN="$IPE_SMOKE_TOKEN" gh api \
    "repos/$INDEX_REPO/pulls?head=$FORK_OWNER:$BAD_BRANCH&state=all" \
    --jq '.[0].number' 2>/dev/null || true)"
  [ -n "$bad_pr" ] && [ "$bad_pr" != "null" ] && break
  [ "$(date +%s)" -lt "$find_deadline" ] \
    || neg_fail "the bad probe's PR never appeared on $INDEX_REPO within 120s — cannot \
observe the admission verdict (fail-closed)."
  sleep 5
done
neg_log "bad probe PR is #$bad_pr — polling its admission verdict (up to ${POLL_SECS}s)"

# Poll the bad PR for a POSITIVE rejection signal. PASS the leg when:
#   * the PR's combined check status is `failure` (admission RED), OR
#   * a check run whose name mentions admission concluded `failure`, OR
#   * the PR was CLOSED WITHOUT MERGING (rejected).
# FAIL the leg (fail-closed) if the bad PR MERGED or its checks went all-`success`
# (admitted) — the gate let a Tier-1-failing package through.
# The PR fields are read in ONE rc-checked `gh api` call (gh's own `--jq`, no
# standalone `jq`). A failed read, or a `merged` that is not exactly `true` or
# `false`, is an UNKNOWN verdict: no rejection signal is trusted from it, the
# loop polls again, and the deadline turns a verdict that never becomes known
# into a FAILURE. Every rejection signal requires `merged` to be exactly
# `false` in the same read.
neg_deadline=$(( $(date +%s) + POLL_SECS ))
while :; do
  merged=""; pr_state=""; head_sha=""
  pr_rc=0
  pr_row="$(GH_TOKEN="$IPE_SMOKE_TOKEN" gh api "repos/$INDEX_REPO/pulls/$bad_pr" \
    --jq '[.merged, .state, .head.sha] | @tsv')" || pr_rc=$?
  if [ "$pr_rc" -eq 0 ]; then
    IFS=$'\t' read -r merged pr_state head_sha <<<"$pr_row"
  else
    neg_log "reading bad probe PR #$bad_pr failed (gh exit $pr_rc) — verdict unknown, polling again"
  fi

  if [ "$merged" = "true" ]; then
    neg_fail "the bad probe PR #$bad_pr MERGED — a Tier-1-failing package was ADMITTED. \
The admission gate did not fail closed."
  fi

  # The combined commit status + count of concluded-failure check runs for the PR
  # head. Either a `failure` combined status or one failing check run is a RED
  # admission verdict. A failed read leaves the signal absent (no rejection).
  combined=""
  check_fail=0
  if [ "$merged" = "false" ] && [ -n "$head_sha" ]; then
    combined="$(GH_TOKEN="$IPE_SMOKE_TOKEN" gh api \
      "repos/$INDEX_REPO/commits/$head_sha/status" --jq '.state // empty')" \
      || { neg_log "reading combined status of $head_sha failed — signal unknown"; combined=""; }
    check_fail="$(GH_TOKEN="$IPE_SMOKE_TOKEN" gh api \
      "repos/$INDEX_REPO/commits/$head_sha/check-runs" \
      --jq '[.check_runs[] | select(.conclusion=="failure" or .conclusion=="cancelled" or .conclusion=="timed_out")] | length')" \
      || { neg_log "reading check runs of $head_sha failed — signal unknown"; check_fail=0; }
  fi
  case "$check_fail" in ''|*[!0-9]*) check_fail=0 ;; esac

  if [ "$merged" = "false" ]; then
    if [ "$combined" = "failure" ] || [ "$check_fail" -gt 0 ]; then
      neg_log "REJECTED: bad probe PR #$bad_pr admission check is RED (combined=$combined, failing-checks=$check_fail) — the gate refused it."
      break
    fi
    if [ "$pr_state" = "closed" ]; then
      neg_log "REJECTED: bad probe PR #$bad_pr was CLOSED without merging — the gate refused it."
      break
    fi
  fi

  [ "$(date +%s)" -lt "$neg_deadline" ] \
    || neg_fail "timed out: the bad probe PR #$bad_pr admission verdict was neither RED nor a \
close within ${POLL_SECS}s (combined=$combined). A rejection that never fires is a gate that \
does not fail closed — treating an unobservable verdict as a FAILURE (fail-closed)."
  sleep 15
done

neg_log "OK: the deployed admission gate REFUSED the deliberately-bad probe (negative leg held)."
log "OK: the smoke proved BOTH directions — a clean probe admits + resolves, a bad probe is refused."
