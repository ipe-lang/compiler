#!/usr/bin/env python3
"""Pick the static.yml caches a newer `Cargo.lock` superseded.

A static.yml cache key is `<family>-<lock>`: a family prefix and the 64-hex
`hashFiles('Cargo.lock')` of the tree that saved it. One lock generation lives
per family: an entry is superseded when its family also holds an entry keyed on
the current lock and its own lock differs. A family with no current entry (its
job did not save on this lock) keeps every entry, so a red job never leaves the
next run cold. Only `main`'s entries are judged, and a key with no trailing
lock hash names no family here and is never picked.

    cache_prune.py

Reads `$REPO`, `$CACHE_LOCK` (the current lock hash) and `$GITHUB_SHA`, and
writes `ids=<id> <id> ...` to `$GITHUB_OUTPUT`: the superseded entries of
`main`'s cache listing, read in full. It writes `ids=` (nothing to delete) when
main's head is no longer `$GITHUB_SHA` (the run would judge against an older
lock), and on any refusal: a malformed lock, a `gh api` failure or timeout, a
listing over its ceilings, a page that is not the expected shape, a duplicate
id, or a listing whose entry count differs from the `total_count` every page
reports (an entry saved or evicted mid-listing). An unset or unwritable
`$GITHUB_OUTPUT` exits 1 with no output set.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass

MAIN_REF = "refs/heads/main"
_LOCK = re.compile(r"[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_KEYED = re.compile(r"(?P<family>.+)-(?P<lock>[0-9a-f]{64})\Z")
# The repository holds at most 10 GB of caches; no listing of it comes near
# these, so reaching one means the input is not that listing.
MAX_LISTING_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 20_000
GH_TIMEOUT_S = 120
# One line per listing page: its `total_count` and its entries.
PAGE_JQ = "{total_count, actions_caches: [.actions_caches[] | {id, key, ref}]} | @json"


class Refused(Exception):
    """The input is not a well-formed, complete listing and lock; nothing is picked."""


@dataclass(frozen=True)
class Entry:
    """One cache entry of the listing."""

    id: int
    key: str
    ref: str


def parse_lock(raw: str) -> str:
    """The lock hash, refused unless it is 64 lowercase hex digits."""
    if not _LOCK.match(raw):
        raise Refused(f"lock hash {raw!r} is not 64 lowercase hex digits")
    return raw


def _parse_entry(raw: object, where: str) -> Entry:
    if not isinstance(raw, dict) or set(raw) != {"id", "key", "ref"}:
        raise Refused(f"{where} is not an object of exactly id, key, ref")
    eid, key, ref = raw["id"], raw["key"], raw["ref"]
    if not isinstance(eid, int) or isinstance(eid, bool) or eid <= 0:
        raise Refused(f"{where}: id {eid!r} is not a positive integer")
    if not isinstance(key, str) or not key or not isinstance(ref, str):
        raise Refused(f"{where}: key or ref is not a string")
    return Entry(eid, key, ref)


def parse_listing(text: str) -> list[Entry]:
    """Every entry of a paged listing (one `PAGE_JQ` line per page), refused
    unless every page agrees on one `total_count` and the pages hold exactly
    that many distinct entries."""
    if len(text.encode()) > MAX_LISTING_BYTES:
        raise Refused(f"listing is over {MAX_LISTING_BYTES} bytes")
    entries: list[Entry] = []
    seen: set[int] = set()
    totals: set[int] = set()
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            page = json.loads(line)
        except json.JSONDecodeError as e:
            raise Refused(f"page {n} is not JSON: {e}") from None
        if not isinstance(page, dict) or set(page) != {"total_count", "actions_caches"}:
            raise Refused(f"page {n} is not an object of exactly total_count, actions_caches")
        total, caches = page["total_count"], page["actions_caches"]
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise Refused(f"page {n}: total_count {total!r} is not a count")
        if not isinstance(caches, list):
            raise Refused(f"page {n}: actions_caches is not a list")
        totals.add(total)
        for raw in caches:
            entry = _parse_entry(raw, f"page {n}")
            if entry.id in seen:
                raise Refused(f"page {n}: id {entry.id} is listed twice")
            seen.add(entry.id)
            entries.append(entry)
            if len(entries) > MAX_ENTRIES:
                raise Refused(f"listing has over {MAX_ENTRIES} entries")
    if len(totals) > 1:
        raise Refused(f"pages disagree on total_count {sorted(totals)}: the listing changed mid-read")
    expected = totals.pop() if totals else 0
    if len(entries) != expected:
        raise Refused(f"listing holds {len(entries)} entries, not the {expected} total_count reports")
    return entries


def superseded(entries: list[Entry], lock: str) -> list[Entry]:
    """The `main` entries whose family holds a current-lock entry and whose own
    lock is another, in listing order."""
    keyed = [(e, m["family"], m["lock"]) for e in entries if e.ref == MAIN_REF and (m := _KEYED.match(e.key))]
    current = {family for _, family, got in keyed if got == lock}
    return [e for e, family, got in keyed if family in current and got != lock]


def _gh(args: list[str]) -> str:
    """`gh api` stdout, read up to `MAX_LISTING_BYTES`; a non-zero exit, a
    timeout, or an oversized reply is a refusal."""
    try:
        proc = subprocess.run(
            ["gh", "api", *args],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=GH_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Refused(f"`gh api {args[0]}` did not complete: {e}") from None
    if proc.returncode != 0:
        raise Refused(f"`gh api {args[0]}` exited {proc.returncode}")
    if len(proc.stdout.encode()) > MAX_LISTING_BYTES:
        raise Refused(f"`gh api {args[0]}` replied over {MAX_LISTING_BYTES} bytes")
    return proc.stdout


def pick(env: dict[str, str]) -> list[int]:
    """The ids to delete for the run `env` describes; empty when main moved."""
    repo = env.get("REPO", "")
    if not _REPO.match(repo):
        raise Refused(f"REPO {repo!r} is not owner/name")
    sha = env.get("GITHUB_SHA", "")
    if not _SHA.match(sha):
        raise Refused(f"GITHUB_SHA {sha!r} is not a commit id")
    lock = parse_lock(env.get("CACHE_LOCK", ""))
    head = _gh([f"repos/{repo}/commits/main", "--jq", ".sha"]).strip()
    if head != sha:
        print(f"cache prune: main is at {head!r}, not {sha}; deleting nothing", file=sys.stderr)
        return []
    listing = _gh(
        [
            "--paginate",
            f"repos/{repo}/actions/caches?ref={MAIN_REF}&per_page=100",
            "--jq",
            PAGE_JQ,
        ]
    )
    return [e.id for e in superseded(parse_listing(listing), lock)]


def write_output(path: str, line: str) -> int:
    """Append `line` to the step-output file; no file or a failed write is exit 1."""
    if not path:
        print("cache prune: GITHUB_OUTPUT is unset — nothing is deleted", file=sys.stderr)
        return 1
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as exc:
        print(f"cache prune: GITHUB_OUTPUT is unwritable: {exc} — nothing is deleted", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str], env: dict[str, str]) -> int:
    if argv:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        ids = pick(env)
    except Refused as e:
        print(f"cache prune: refused: {e} — deleting nothing", file=sys.stderr)
        ids = []
    return write_output(env.get("GITHUB_OUTPUT", ""), "ids=" + " ".join(str(i) for i in ids))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], dict(os.environ)))
