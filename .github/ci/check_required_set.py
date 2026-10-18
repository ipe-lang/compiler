#!/usr/bin/env python3
"""The branch-protection required set: derived from the manifest, checked
against `required-set.json` and against the live ruleset.

The required set is one `{context, integration_id}` pair per `gate` and
`gate-external` context of `ci/check-manifest.yml`, sorted by context — the
exact shape of a ruleset's `required_status_checks` parameter. A `gate` is
posted by a workflow, so its integration is GitHub Actions
(`GITHUB_ACTIONS_APP_ID`); a `gate-external` names the app that posts it in
its own `integration_id`. A required check without an integration is
satisfied by a status any app — or any token with `statuses: write` — posts,
so the pair, not the name, is the unit compared.

Modes:
  (none)      exit 0 iff `required-set.json` is the derived set.
  --write     regenerate `required-set.json` from the manifest.
  --live FILE also compare the ruleset JSON in FILE (as
              `gh api repos/OWNER/REPO/rulesets/ID` returns it).
  --fetch     also compare ruleset `RULESET_ID` read from the REST API
              ($REPO, $GH_TOKEN, optional $GITHUB_API_URL).
  --fetch-admin
              `--fetch` with a ruleset-admin token: the body must also carry
              `bypass_actors`, the list must be empty, and the token's
              environment must admit `main` alone.
  --render-put FILE
              print the ruleset PUT body that applies `required-set.json`:
              the admin-read ruleset JSON in FILE, parsed like `--live` save
              for its required pairs and its pinned rules' settings, with those
              pairs replaced by the set, those settings by `PINNED_RULES`, and
              only the writable keys (`PUT_KEYS`) kept. The body is printed
              only once it, re-parsed, passes `--live`.

The live ruleset is parsed into a closed `Ruleset`: every key the API
returns is either examined and pinned or named as display metadata, and any
other key, rule type, or parameter is refused, so a protection GitHub adds
or an owner toggles is never waved through unread.  It must be active on the
default branch with no exclusions and no bypass actors, carry exactly one
`required_status_checks` rule (strict policy off, enforced on create) whose
pairs equal the derived set in both directions, and exactly one
`pull_request` and one `merge_queue` rule whose every setting equals
`PULL_REQUEST` and `MERGE_QUEUE`. GitHub returns
`bypass_actors` only to a ruleset admin, so `--fetch` (a workflow token)
cannot see them: it refuses a non-empty list when
one is returned and otherwise leaves the bypass proof to an admin read.
`--fetch-admin` and `--live` are admin reads: a body without the list is
refused, so a token that cannot see bypass actors fails rather than passes.
`--fetch-admin` runs nightly in `ruleset-admin-read.yml` with the
`RULESET_READ_TOKEN` secret of the `ADMIN_READ_ENVIRONMENT` environment, and
first parses that environment's deployment-branch policy into a closed
`EnvPolicy` whose one variant is custom branch policies of exactly `main`;
any other policy (protected-branches mode included), or none, is refused. An
admin read GitHub refuses with 401, 403 or 404 says what that status means for
the token (401: invalid or expired; 403: a missing permission or an exhausted
rate limit; 404: a missing permission or a missing resource), naming the
permission that read needs; any other failed read says only what failed. The
token is never printed. Every unreadable or malformed input — a missing or empty token
included — fails closed (exit 1) with nothing printed to stdout.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

CI_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CI_DIR)
import strict_yaml  # noqa: E402
import yaml  # noqa: E402

MANIFEST = os.path.join(CI_DIR, "check-manifest.yml")
REQUIRED_SET = os.path.join(CI_DIR, "required-set.json")
# The GitHub App id of GitHub Actions: the integration every workflow-posted
# check run carries.
GITHUB_ACTIONS_APP_ID = 15368
# The `main-protection` ruleset that enforces the required set on `main`.
RULESET_ID = 22326541
MAIN_BRANCH = "main"
# The GitHub environment holding `RULESET_READ_TOKEN`: its deployment-branch
# policy admits `main` alone, so GitHub hands the token to no run of any other
# ref. `--fetch-admin` proves that policy before it reads the ruleset.
ADMIN_READ_ENVIRONMENT = "ruleset-admin-read"
# The fine-grained repository permissions `RULESET_READ_TOKEN` holds, and
# only these: the first reads the ruleset (`bypass_actors` included), the
# second the environment and its deployment-branch policies.
RULESET_READ_PERMISSION = "Administration: read"
ENV_READ_PERMISSION = "Actions: read"
ADMIN_READ_TOKEN_PERMISSIONS = (RULESET_READ_PERMISSION, ENV_READ_PERMISSION)
# What each HTTP status by which GitHub refuses a token its read says about
# the token; `{permission}` is the permission that read needs. GitHub answers
# 404, not 403, to a token missing the permission, so a 404 cannot tell that
# from a missing resource; a 403 may also be an exhausted rate limit.
_TOKEN_REFUSAL_HINTS: dict[int, str] = {
    401: "RULESET_READ_TOKEN is invalid or expired; regenerate it",
    403: "RULESET_READ_TOKEN lacks the fine-grained repository permission {permission}, or the API rate limit is exhausted",
    404: "it does not exist, or RULESET_READ_TOKEN lacks the fine-grained repository permission {permission}",
}

Pair = tuple[str, int]


class Refused(Exception):
    """An input this check cannot prove matches the derived set."""


def _is_app_id(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v > 0


def derive(man: object) -> list[Pair]:
    """The manifest's required `(context, integration_id)` pairs, sorted."""
    checks = man.get("checks") if isinstance(man, dict) else None
    if not isinstance(checks, list):
        raise Refused("the manifest is not a `checks` list")
    pairs: list[Pair] = []
    for e in checks:
        if not isinstance(e, dict):
            raise Refused(f"manifest entry {e!r} is not a mapping")
        ctx, disp = e.get("context"), e.get("disposition")
        if not isinstance(ctx, str) or not isinstance(disp, str):
            raise Refused(f"manifest entry {e!r} lacks a string `context` and `disposition`")
        app = e.get("integration_id")
        if disp == "gate-external":
            if not _is_app_id(app):
                raise Refused(f"{ctx!r}: a gate-external entry must name its posting app's `integration_id`")
            pairs.append((ctx, app))
        elif "integration_id" in e:
            raise Refused(f"{ctx!r}: only a gate-external entry declares `integration_id`")
        elif disp == "gate":
            pairs.append((ctx, GITHUB_ACTIONS_APP_ID))
    names = [c for c, _ in pairs]
    if len(set(names)) != len(names):
        raise Refused("the manifest declares a required context twice")
    return sorted(pairs)


def parse_pairs(data: object, what: str) -> list[Pair]:
    """A `[{context, integration_id}]` list as pairs; a missing integration,
    an extra key, or a repeated context is refused."""
    if not isinstance(data, list):
        raise Refused(f"{what} is not a list of {{context, integration_id}}")
    pairs: list[Pair] = []
    for item in data:
        if not isinstance(item, dict) or set(item) != {"context", "integration_id"}:
            raise Refused(f"{what}: {item!r} is not exactly {{context, integration_id}}")
        ctx, app = item["context"], item["integration_id"]
        if not isinstance(ctx, str) or not ctx or not _is_app_id(app):
            raise Refused(f"{what}: {item!r} needs a non-empty context and a positive integration_id")
        pairs.append((ctx, app))
    names = [c for c, _ in pairs]
    if len(set(names)) != len(names):
        raise Refused(f"{what} lists a context twice")
    return pairs


def render(pairs: list[Pair]) -> str:
    return json.dumps([{"context": c, "integration_id": a} for c, a in pairs], indent=2) + "\n"


def _closed(obj: object, what: str, keys: frozenset[str], optional: frozenset[str] = frozenset()) -> dict:
    """`obj` as a mapping holding every one of `keys` and nothing outside
    `keys | optional`: a key this check does not examine is refused."""
    if not isinstance(obj, dict):
        raise Refused(f"{what} is not an object")
    missing = sorted(keys - obj.keys())
    if missing:
        raise Refused(f"{what} lacks {', '.join(missing)}")
    unknown = sorted(str(k) for k in obj.keys() - keys - optional)
    if unknown:
        raise Refused(f"{what} carries {', '.join(unknown)}, which this check does not examine")
    return obj


def _pin(value: object, want: object, what: str) -> None:
    # The JSON text too: `False == 0` and `2.0 == 2`, at the top and nested in
    # a list or object alike, and a ruleset parameter's JSON type is part of it.
    if (
        type(value) is not type(want)
        or value != want
        or json.dumps(value, sort_keys=True) != json.dumps(want, sort_keys=True)
    ):
        raise Refused(f"{what} is {value!r}, not {want!r}")


def _typed(value: object, kind: type, what: str) -> None:
    if type(value) is not kind:
        raise Refused(f"{what} is {value!r}, not a {kind.__name__}")


# Top-level keys the API returns that carry no protection: they are display
# metadata, read by no comparison.
_RULESET_METADATA = frozenset({"name", "source", "node_id", "created_at", "updated_at", "_links"})
_RULESET_KEYS = frozenset({"id", "target", "enforcement", "conditions", "rules"})
# Keys present only in some responses; each is pinned when present.
_RULESET_VIEWER_KEYS = frozenset({"source_type", "current_user_can_bypass", "bypass_actors"})

# The pull-request rule's settings, pinned like `MERGE_QUEUE`: a review
# protection switched off by hand turns the parse red rather than passing typed.
PULL_REQUEST: dict[str, object] = {
    # No approval is required: the required checks and the queue gate a merge.
    "required_approving_review_count": 0,
    "dismiss_stale_reviews_on_push": True,
    "required_reviewers": [],
    "require_code_owner_review": False,
    "dismissal_restriction": {"enabled": False, "allowed_actors": []},
    "require_last_push_approval": False,
    # An unresolved review thread blocks the merge.
    "required_review_thread_resolution": True,
    "require_extra_approval_for_unattributed_changes": True,
    # The queue's `merge_method` decides how an entry lands on `main`.
    "allowed_merge_methods": ["merge", "squash", "rebase"],
}
# The merge queue's settings: every parameter the `merge_queue` rule carries,
# each pinned to its value here (its JSON type included), so the parse refuses
# a missing, unknown, retyped, or changed one. This table is the parse table:
# a parameter cannot be parsed without being pinned.
MERGE_QUEUE: dict[str, object] = {
    # Each entry lands as one commit on `main`.
    "merge_method": "SQUASH",
    # Every queued entry gets its own full run, so the runs in flight at once
    # are this many; past what the runner pool carries, every run slows.
    "max_entries_to_build": 2,
    "min_entries_to_merge": 1,
    # Under `ALLGREEN` a group merges only once each entry's own run is green,
    # so a larger group than the build width buys nothing.
    "max_entries_to_merge": 2,
    "min_entries_to_merge_wait_minutes": 5,
    # Each entry's own checks must pass: the strict policy stays off because
    # the queue builds every entry on the combined tree, and `HEADGREEN` would
    # land the group's inner commits with no green run of their own.
    "grouping_strategy": "ALLGREEN",
    # The longest full run fits inside it; a context that never reports fails
    # the entry rather than holding the queue.
    "check_response_timeout_minutes": 120,
}
_STATUS_PARAMS = frozenset(
    {"strict_required_status_checks_policy", "do_not_enforce_on_create", "required_status_checks"}
)
# The rules whose every parameter is pinned, by rule type; `render_put` writes
# these tables as it writes the required pairs.
PINNED_RULES: dict[str, dict[str, object]] = {"pull_request": PULL_REQUEST, "merge_queue": MERGE_QUEUE}
# Every rule type the ruleset must carry, exactly once each.  A type outside
# this set is one this check has not examined, so it is refused.
RULE_TYPES = frozenset({"deletion", "non_fast_forward", "pull_request", "required_status_checks", "merge_queue"})


@dataclass(frozen=True)
class Ruleset:
    """A live ruleset every key of which was examined: it applies, actively
    and without bypass, to the default branch and enforces `required`."""

    required: tuple[Pair, ...]


def _rule(rule: object) -> tuple[str, tuple[Pair, ...]]:
    """A rule's type, and the pairs it requires when it is the status rule."""
    head = rule.get("type") if isinstance(rule, dict) else None
    if not isinstance(head, str) or head not in RULE_TYPES:
        raise Refused(f"the ruleset carries a rule of type {head!r}, which this check does not examine")
    what = f"the {head} rule"
    if head in ("deletion", "non_fast_forward"):
        _closed(rule, what, frozenset({"type"}))
        return head, ()
    params = _closed(rule, what, frozenset({"type", "parameters"}))["parameters"]
    pinned = PINNED_RULES.get(head)
    if pinned is not None:
        params = _closed(params, f"{what}'s parameters", frozenset(pinned))
        for key, want in pinned.items():
            _pin(params[key], want, f"{what}'s {key}")
        return head, ()
    params = _closed(params, f"{what}'s parameters", _STATUS_PARAMS)
    _pin(params["strict_required_status_checks_policy"], False, f"{what}'s strict_required_status_checks_policy")
    _pin(params["do_not_enforce_on_create"], False, f"{what}'s do_not_enforce_on_create")
    pairs = parse_pairs(params["required_status_checks"], "the ruleset's required_status_checks")
    return head, tuple(pairs)


def parse_ruleset(rs: object, *, admin_read: bool) -> Ruleset:
    """The ruleset GET body as a `Ruleset`, or `Refused`.

    `admin_read` is whether the body was read by a ruleset admin, the only
    reader GitHub shows `bypass_actors` to; such a body must carry the list."""
    rs = _closed(rs, "the ruleset", _RULESET_KEYS, _RULESET_METADATA | _RULESET_VIEWER_KEYS)
    _pin(rs["id"], RULESET_ID, "the ruleset id")
    _pin(rs["target"], "branch", "the ruleset target")
    _pin(rs["enforcement"], "active", "the ruleset enforcement")
    if "source_type" in rs:
        _pin(rs["source_type"], "Repository", "the ruleset source_type")
    if "current_user_can_bypass" in rs:
        _pin(rs["current_user_can_bypass"], "never", "the ruleset current_user_can_bypass")
    if "bypass_actors" in rs:
        _pin(rs["bypass_actors"], [], "the ruleset bypass_actors")
    elif admin_read:
        raise Refused(
            "the ruleset lacks bypass_actors, which GitHub returns only to a token holding the "
            f"fine-grained repository permission {RULESET_READ_PERMISSION} — see .github/ci/RECONCILIATION.md"
        )
    cond = _closed(rs["conditions"], "the ruleset conditions", frozenset({"ref_name"}))
    ref = _closed(cond["ref_name"], "the ruleset ref_name condition", frozenset({"include", "exclude"}))
    include = ref["include"]
    if not isinstance(include, list) or "~DEFAULT_BRANCH" not in include:
        raise Refused("the ruleset does not apply to the default branch")
    _pin(ref["exclude"], [], "the ruleset ref_name exclude")
    rules = rs["rules"]
    if not isinstance(rules, list):
        raise Refused("the ruleset has no `rules` list")
    seen: dict[str, int] = {}
    required: tuple[Pair, ...] = ()
    for rule in rules:
        head, pairs = _rule(rule)
        seen[head] = seen.get(head, 0) + 1
        if head == "required_status_checks":
            required = pairs
    for head in sorted(RULE_TYPES):
        if seen.get(head, 0) != 1:
            raise Refused(f"the ruleset has {seen.get(head, 0)} {head} rules, not 1")
    return Ruleset(required=required)


# The keys of a ruleset PUT body: the writable part of the GET body.
PUT_KEYS = ("name", "target", "enforcement", "conditions", "bypass_actors", "rules")


def render_put(rs: object, required: list[Pair]) -> str:
    """The PUT body applying `required` and `PINNED_RULES` to the ruleset GET
    body `rs`, or `Refused`. `rs`, with its pinned rules' settings set to
    `PINNED_RULES`, must pass the admin-read parse (its own required pairs
    aside, which the body replaces); the body, re-read as the GET would
    return it, must pass the same parse with exactly `required`."""
    if not isinstance(rs, dict) or not isinstance(rs.get("rules"), list):
        raise Refused("the ruleset is not an object with a `rules` list")
    pinned = [
        {**r, "parameters": {**r["parameters"], **copy.deepcopy(PINNED_RULES[r["type"]])}}
        if isinstance(r, dict) and r.get("type") in PINNED_RULES and isinstance(r.get("parameters"), dict) else r
        for r in rs["rules"]
    ]
    rs = {**rs, "rules": pinned}
    parse_ruleset(rs, admin_read=True)
    want = json.loads(render(required))
    rules = [
        {**r, "parameters": {**r["parameters"], "required_status_checks": want}}
        if r["type"] == "required_status_checks" else r
        for r in rs["rules"]
    ]
    body = {k: rs[k] for k in PUT_KEYS if k in rs and k != "rules"} | {"rules": rules}
    got = parse_ruleset({**body, "id": RULESET_ID}, admin_read=True).required
    problems = diff(required, list(got), "the rendered PUT body", "this is a defect in render_put")
    if problems:
        raise Refused("; ".join(problems))
    return json.dumps(body, indent=2) + "\n"


def diff(expected: list[Pair], actual: list[Pair], what: str, fix: str) -> list[str]:
    """Lines naming each pair missing from and extra in `actual`, or []."""
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    if not missing and not extra:
        return []
    out = [f"{what} differs from the manifest's required set — {fix}:"]
    out += [f"  missing: {c!r} (integration {a})" for c, a in missing]
    out += [f"  extra:   {c!r} (integration {a})" for c, a in extra]
    return out


# The key only `parse_env_policy` holds: a `CustomMainOnly` built without it
# is refused, so the value is proof the environment read was parsed.
_KEY = object()


@dataclass(frozen=True)
class CustomMainOnly:
    """The one deployment-branch policy `ADMIN_READ_ENVIRONMENT` may carry:
    custom branch policies that are exactly the branch `main`, with no
    administrator bypass. Protected-branches mode is not admitted: with no
    classic protection rule on the repository, GitHub lets every branch deploy
    under it. An administrator bypass would let an admin deploy any branch.

    Only `parse_env_policy` mints one; any other construction is refused."""

    key: object = field(repr=False, compare=False, kw_only=True)

    def __post_init__(self) -> None:
        if self.key is not _KEY:
            raise Refused("a CustomMainOnly is minted only by parse_env_policy")


EnvPolicy = CustomMainOnly

ENV_POLICY_FIX = "set it up per .github/ci/RECONCILIATION.md"
RULESET_PATH = f"rulesets/{RULESET_ID}"
_ENV_PATH = f"environments/{ADMIN_READ_ENVIRONMENT}"
_ENV_WHERE = f"environment {ADMIN_READ_ENVIRONMENT!r}"
_BRANCH_POLICIES_KEYS = frozenset({"total_count", "branch_policies"})
_BRANCH_POLICY_KEYS = frozenset({"name", "type"})
# Identifiers the API adds to each branch policy; typed, compared by nothing.
_BRANCH_POLICY_IDS: dict[str, type] = {"id": int, "node_id": str}


def _main_only_branch_policies(policies: object) -> None:
    """Refuse custom deployment-branch policies other than exactly one rule
    naming the branch `MAIN_BRANCH`."""
    what = f"{_ENV_WHERE} deployment-branch policies"
    body = _closed(policies, what, _BRANCH_POLICIES_KEYS)
    _pin(body["total_count"], 1, f"{what} total_count")
    items = body["branch_policies"]
    if not isinstance(items, list) or len(items) != 1:
        raise Refused(f"{what} are {items!r}, not one policy")
    item = _closed(items[0], f"{what} entry", _BRANCH_POLICY_KEYS, frozenset(_BRANCH_POLICY_IDS))
    _pin(item["name"], MAIN_BRANCH, f"{what} entry name")
    _pin(item["type"], "branch", f"{what} entry type")
    for key, kind in _BRANCH_POLICY_IDS.items():
        if key in item:
            _typed(item[key], kind, f"{what} entry {key}")


def parse_env_policy(env: object, fetch_policies: Callable[[], object]) -> EnvPolicy:
    """The `ADMIN_READ_ENVIRONMENT` read (`env`) as its closed policy, or
    `Refused`. `fetch_policies` reads the custom branch policies; it is
    called only once `env` is in custom mode."""
    where = _ENV_WHERE
    if not isinstance(env, dict) or env.get("name") != ADMIN_READ_ENVIRONMENT:
        raise Refused(f"{where}: the API returned no environment of that name — {ENV_POLICY_FIX}")
    try:
        _pin(env.get("can_admins_bypass"), False, f"{where} can_admins_bypass")
    except Refused as e:
        raise Refused(f"{e}; administrators must not bypass its branch policy — {ENV_POLICY_FIX}") from e
    policy = env.get("deployment_branch_policy")
    if policy is None:
        raise Refused(f"{where}: no deployment-branch policy, so every branch may deploy — {ENV_POLICY_FIX}")
    try:
        mode = _closed(
            policy, f"{where} deployment-branch policy", frozenset({"protected_branches", "custom_branch_policies"})
        )
        _pin(mode["protected_branches"], False, f"{where} protected_branches")
        _pin(mode["custom_branch_policies"], True, f"{where} custom_branch_policies")
    except Refused as e:
        raise Refused(
            f"{e}; only custom branch policies of exactly {MAIN_BRANCH!r} are admitted — {ENV_POLICY_FIX}"
        ) from e
    try:
        _main_only_branch_policies(fetch_policies())
    except Refused as e:
        raise Refused(f"{e}; only the one branch {MAIN_BRANCH!r} is admitted — {ENV_POLICY_FIX}") from e
    return CustomMainOnly(key=_KEY)


def admin_read_refusal(e: Exception, where: str, permission: str) -> Refused:
    """The refusal for a failed admin read of `where`, which needs
    `permission`: an HTTP status by which GitHub refuses a token says what it
    means for the token; any other failure (a server error, a transport or
    size refusal) says only what failed, since no token change would fix it."""
    import trust_roots  # noqa: PLC0415

    if isinstance(e, trust_roots.HttpStatus) and e.status in _TOKEN_REFUSAL_HINTS:
        hint = _TOKEN_REFUSAL_HINTS[e.status].format(permission=permission)
        return Refused(f"cannot read {where} (HTTP {e.status}): {hint} — see .github/ci/RECONCILIATION.md")
    return Refused(f"cannot read {where}: {e}")


def env_read_refusal(e: Exception) -> Refused:
    """The refusal for a failed read of `ADMIN_READ_ENVIRONMENT`."""
    return admin_read_refusal(e, _ENV_WHERE, ENV_READ_PERMISSION)


def read_env_policy(api: object) -> EnvPolicy:
    """`ADMIN_READ_ENVIRONMENT` read through `api` and parsed into its policy."""
    import trust_roots  # noqa: PLC0415

    def read(path: str) -> object:
        try:
            return api.get(path)  # type: ignore[attr-defined]
        except trust_roots.Refused as e:
            raise env_read_refusal(e) from e

    return parse_env_policy(read(_ENV_PATH), lambda: read(f"{_ENV_PATH}/deployment-branch-policies"))


def read_ruleset(api: object, proof: EnvPolicy) -> object:
    """The admin read of the ruleset. `proof` is the parsed policy confining
    the token to `main`: the ruleset is not read without it. (The token's one
    other use is the environment reads that mint `proof`.)"""
    import trust_roots  # noqa: PLC0415

    if not isinstance(proof, CustomMainOnly):
        raise Refused(f"the admin read of ruleset {RULESET_ID} needs the parsed policy of {_ENV_WHERE}")
    try:
        return api.get(RULESET_PATH)  # type: ignore[attr-defined]
    except trust_roots.Refused as e:
        raise admin_read_refusal(e, f"ruleset {RULESET_ID}", RULESET_READ_PERMISSION) from e


def fetch_live(*, admin: bool) -> object:
    """The live ruleset. An admin read first parses `ADMIN_READ_ENVIRONMENT`
    into its `EnvPolicy`, refusing any other policy."""
    import trust_roots  # noqa: PLC0415  # the pinned-origin authenticated GET

    repo, token = os.environ.get("REPO", ""), os.environ.get("GH_TOKEN", "")
    if not repo or not token:
        raise Refused("reading the live ruleset needs $REPO and a non-empty $GH_TOKEN")
    try:
        api = trust_roots.Api(os.environ.get("GITHUB_API_URL") or "https://api.github.com", repo, token)
        if admin:
            return read_ruleset(api, read_env_policy(api))
        return api.get(RULESET_PATH)
    except trust_roots.Refused as e:
        raise Refused(str(e)) from e


def _load_manifest() -> object:
    try:
        with open(MANIFEST, encoding="utf-8") as f:
            return strict_yaml.safe_load(f)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise Refused(f".github/ci/check-manifest.yml is unreadable: {e}") from e


def _load_json(path: str, what: str) -> object:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise Refused(f"{what} is unreadable: {e}") from e


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--live", metavar="FILE")
    mode.add_argument("--fetch", action="store_true")
    mode.add_argument("--fetch-admin", action="store_true")
    mode.add_argument("--render-put", metavar="FILE")
    args = ap.parse_args(argv)
    try:
        required = derive(_load_manifest())
        if args.write:
            with open(REQUIRED_SET, "w", encoding="utf-8") as f:
                f.write(render(required))
            print(f"wrote .github/ci/required-set.json ({len(required)} required contexts).")
            return 0
        on_disk = parse_pairs(
            _load_json(REQUIRED_SET, ".github/ci/required-set.json"), ".github/ci/required-set.json"
        )
        problems = diff(
            required, on_disk, ".github/ci/required-set.json",
            "regenerate it: python3 .github/ci/check_required_set.py --write",
        )
        if args.render_put:
            if problems:
                raise Refused("; ".join(problems))
            sys.stdout.write(render_put(_load_json(args.render_put, args.render_put), required))
            return 0
        live = bool(args.live or args.fetch or args.fetch_admin)
        if live:
            rs = _load_json(args.live, args.live) if args.live else fetch_live(admin=bool(args.fetch_admin))
            admin_read = bool(args.live or args.fetch_admin)
            problems += diff(
                required, list(parse_ruleset(rs, admin_read=admin_read).required), f"ruleset {RULESET_ID}",
                "reconcile it per .github/ci/RECONCILIATION.md",
            )
    except Refused as e:
        print(f"check_required_set: {e}", file=sys.stderr)
        return 1
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    where = f"required-set.json and ruleset {RULESET_ID} match" if live else "required-set.json matches"
    print(f"{where} the manifest ({len(required)} required contexts).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
