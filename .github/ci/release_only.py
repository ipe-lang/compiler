#!/usr/bin/env python3
"""Classify the tested commit as a pure release-please version bump.

Writes `release_only=true` to "$GITHUB_OUTPUT" only when EVERY condition holds:
  * the event is a pull_request whose head repository is this repository (a
    fork can never qualify);
  * the tested commit (`HEAD`) is the PR merge commit — exactly two parents,
    the second being the PR head — and differs from its base parent
    (`HEAD^1`) only in RELEASE_FILES, and changes the manifest;
  * `Cargo.toml` differs only in `workspace.package.version`, which equals the
    manifest's root version;
  * `Cargo.lock` differs only in the `version` of workspace packages (those with
    no `source`) — no third-party version, source, checksum or dependency edge.
Such a commit is the already-gated base plus version metadata; the fast tiers
still check the new version, and the heavy emitted-build/SEAL/sandbox tiers
may skip (the push to main re-runs every tier).
The classification reads the tested tree, never the branch name or a live API,
so it describes exactly the commit whose checks it gates. Any other diff, and
any error, yields `release_only=false` (fail closed).

Inputs (env): EVENT_NAME, HEAD_REPO, REPO, PR_HEAD_SHA. Needs a checkout with fetch-depth 2.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass

try:
    import tomllib
except ImportError:  # Python < 3.11 outside CI.
    import tomli as tomllib  # type: ignore[no-redef]

MANIFEST = ".github/.release-please-manifest.json"
CARGO_TOML = "Cargo.toml"
CARGO_LOCK = "Cargo.lock"
RELEASE_FILES = frozenset({MANIFEST, "CHANGELOG.md", CARGO_TOML, CARGO_LOCK})
BASE = "HEAD^1"
HEAD = "HEAD"


@dataclass(frozen=True)
class ReleaseOnly:
    version: str


@dataclass(frozen=True)
class NotReleaseOnly:
    reason: str


Verdict = ReleaseOnly | NotReleaseOnly


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def read_at(rev: str, path: str) -> str:
    return git("show", f"{rev}:{path}").decode("utf-8")


def changed_files() -> list[str]:
    raw = git("diff", "--no-renames", "-z", "--name-only", BASE, HEAD)
    return [p.decode("utf-8") for p in raw.split(b"\0") if p]


def cargo_toml_verdict(version: str) -> Verdict | None:
    base = tomllib.loads(read_at(BASE, CARGO_TOML))
    head = tomllib.loads(read_at(HEAD, CARGO_TOML))
    head_version = head.get("workspace", {}).get("package", {}).pop("version", None)
    base.get("workspace", {}).get("package", {}).pop("version", None)
    if head_version != version:
        return NotReleaseOnly(
            f"Cargo.toml version {head_version!r} != manifest {version!r}"
        )
    if base != head:
        return NotReleaseOnly("Cargo.toml changes more than the workspace version")
    return None


def strip_workspace_versions(lock: dict) -> dict:
    packages = []
    for pkg in lock.get("package", []):
        if "source" not in pkg:
            pkg = {k: v for k, v in pkg.items() if k != "version"}
        packages.append(pkg)
    return {**lock, "package": packages}


def cargo_lock_verdict() -> Verdict | None:
    base = strip_workspace_versions(tomllib.loads(read_at(BASE, CARGO_LOCK)))
    head = strip_workspace_versions(tomllib.loads(read_at(HEAD, CARGO_LOCK)))
    if base != head:
        return NotReleaseOnly(
            "Cargo.lock changes more than workspace package versions"
        )
    return None


def classify() -> Verdict:
    if os.environ.get("EVENT_NAME") != "pull_request":
        return NotReleaseOnly("not a pull_request event")
    head_repo = os.environ.get("HEAD_REPO", "")
    if not head_repo or head_repo != os.environ.get("REPO", ""):
        return NotReleaseOnly(f"head repository {head_repo!r} is not this repository")

    parents = git("rev-list", "--parents", "-n1", HEAD).decode("ascii").split()[1:]
    pr_head = os.environ.get("PR_HEAD_SHA", "")
    if len(parents) != 2 or not pr_head or parents[1] != pr_head:
        return NotReleaseOnly("tested commit is not the base + PR-head merge commit")

    files = changed_files()
    outside = [f for f in files if f not in RELEASE_FILES]
    if outside:
        return NotReleaseOnly(f"changes {outside[0]!r}, outside the release file set")
    if MANIFEST not in files:
        return NotReleaseOnly(f"does not change {MANIFEST}")

    version = json.loads(read_at(HEAD, MANIFEST)).get(".")
    if not isinstance(version, str) or not version:
        return NotReleaseOnly("manifest has no root version")
    if CARGO_TOML in files and (v := cargo_toml_verdict(version)) is not None:
        return v
    if CARGO_LOCK in files and (v := cargo_lock_verdict()) is not None:
        return v
    return ReleaseOnly(version)


def main() -> int:
    try:
        verdict = classify()
    except Exception as err:  # noqa: BLE001 — any failure must classify false.
        verdict = NotReleaseOnly(f"classifier error: {err}")
    is_release = isinstance(verdict, ReleaseOnly)
    detail = f"version {verdict.version}" if is_release else verdict.reason
    out = os.environ.get("GITHUB_OUTPUT")
    line = f"release_only={'true' if is_release else 'false'}\n"
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(line)
    else:
        sys.stdout.write(line)
    print(f"release-only: {is_release} — {detail}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
