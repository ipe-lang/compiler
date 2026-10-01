#!/usr/bin/env python3
"""The one reader of `test-claims.yml`, the non-host test cell table.

`verify-manifest` check 20 reads the table through `load_cells`; the Rust
scanner `src/runtime/rust/tests/wasm_cell_scan.rs` reads the same file with
its own line parser and is pinned to it by its own tests.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import strict_yaml
import yaml

CLAIMS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-claims.yml")
_CELL_KEYS = frozenset({"package", "target", "platform", "features", "owner", "expect_tests"})
# The table covers the wasm32 platforms only; any other non-host platform
# needs its own runner proof before a cell can claim it.
_PLATFORM = re.compile(r"wasm32-[a-z0-9_-]+\Z")
_NAME = re.compile(r"[A-Za-z0-9_-]+\Z")


@dataclass(frozen=True)
class Cell:
    """One (package, test target, platform) cell and the job that runs it.

    `target` is `lib` or `test:<name>`."""

    package: str
    target: str
    platform: str
    features: frozenset[str]
    owner: str
    expect_tests: int

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.package, self.target, self.platform)


def _cell(raw: object, at: str) -> Cell | str:
    if not isinstance(raw, dict) or set(raw) != _CELL_KEYS:
        return f"{at} is not a mapping of exactly {sorted(_CELL_KEYS)}"
    package, target, platform = raw["package"], raw["target"], raw["platform"]
    features, owner, expect = raw["features"], raw["owner"], raw["expect_tests"]
    if not isinstance(package, str) or not _NAME.match(package):
        return f"{at}: package {package!r} is not a package name"
    if target == "lib":
        key = "lib"
    elif isinstance(target, dict) and set(target) == {"test"} and isinstance(target["test"], str) and _NAME.match(target["test"]):
        key = "test:" + target["test"]
    else:
        return f"{at}: target {target!r} is neither `lib` nor `{{test: <name>}}`"
    if not isinstance(platform, str) or not _PLATFORM.match(platform):
        return f"{at}: platform {platform!r} is not a wasm32 triple"
    if not isinstance(features, list) or not all(isinstance(f, str) and _NAME.match(f) for f in features):
        return f"{at}: features {features!r} is not a list of feature names"
    if len(set(features)) != len(features):
        return f"{at}: features {features!r} names a feature twice"
    if not isinstance(owner, str) or not _NAME.match(owner):
        return f"{at}: owner {owner!r} is not a job id"
    if not isinstance(expect, int) or isinstance(expect, bool) or expect < 1:
        return f"{at}: expect_tests {expect!r} is not a positive integer"
    return Cell(package, key, platform, frozenset(features), owner, expect)


def load_cells(path: str = CLAIMS) -> list[Cell] | str:
    """Every cell of the claims table at `path`, or why it is refused.

    A cell listed twice is refused: each has exactly one owner."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = strict_yaml.safe_load(f)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        return f"{os.path.basename(path)} is unreadable: {e}"
    raw = doc.get("cells") if isinstance(doc, dict) and set(doc) == {"cells"} else None
    if not isinstance(raw, list) or not raw:
        return f"{os.path.basename(path)} is not a mapping of exactly a non-empty `cells` list"
    cells: list[Cell] = []
    seen: set[tuple[str, str, str]] = set()
    for i, entry in enumerate(raw):
        got = _cell(entry, f"cell {i}")
        if isinstance(got, str):
            return got
        if got.key in seen:
            return f"cell {i}: {' '.join(got.key)} is claimed twice"
        seen.add(got.key)
        cells.append(got)
    return cells
