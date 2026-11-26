#!/usr/bin/env python3
"""Judge the Kotlin stdlib a generated Android shell resolves.

Usage: `android_resolution.py <dependencies report> <app/build.gradle>`.

The report is the output of
`./gradlew -q :app:dependencies --configuration debugRuntimeClasspath`. The
verdict is green only when `build.gradle` applies exactly one
`kotlin-bom:<version>` platform, the report resolves that platform, and every
`org.jetbrains.kotlin:kotlin-stdlib*` row resolves to exactly that version.
Anything else is refused: a stdlib row at another version (a skewed
`kotlin-stdlib-jdk7`/`-jdk8` the platform failed to align), a row upgraded past
the platform (`1.8.22 -> 1.9.0`), a failed resolution, a row this judge cannot
read, an empty report, or one with no stdlib row at all.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass

# A report or build file larger than this is refused unread.
MAX_BYTES = 16 * 1024 * 1024

_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_BOM_LINE = re.compile(
    r"\s*implementation platform\('org\.jetbrains\.kotlin:kotlin-bom:([0-9]+\.[0-9]+\.[0-9]+)'\)\s*"
)
# The tree drawing Gradle puts before a coordinate: `+--- `, `\--- `, `|    `.
_TREE = re.compile(r"[ |+\\-]*")
_STDLIB_PREFIX = "org.jetbrains.kotlin:kotlin-stdlib"
_STDLIB_ROW = re.compile(
    r"org\.jetbrains\.kotlin:(kotlin-stdlib(?:-[a-z0-9]+)*)"
    r"(?::(\S+))?"
    r"(?: -> (\S+))?"
    r"(?: \((?:\*|c)\))?"
)


@dataclass(frozen=True)
class Refused:
    reason: str


def read_bounded(path: str) -> str | Refused:
    """The text of `path`, or why it cannot be judged."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
    except OSError as err:
        return Refused(f"{path}: unreadable ({err})")
    if len(raw) > MAX_BYTES:
        return Refused(f"{path}: larger than {MAX_BYTES} bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as err:
        return Refused(f"{path}: not UTF-8 ({err})")


def bom_version(gradle: str) -> str | Refused:
    """The one `kotlin-bom` platform version `build.gradle` applies."""
    found = [m.group(1) for line in gradle.splitlines() if (m := _BOM_LINE.fullmatch(line))]
    mentions = gradle.count("kotlin-bom")
    if len(found) != 1 or mentions != 1:
        return Refused(
            f"build.gradle must apply exactly one `kotlin-bom` platform line; found {len(found)} "
            f"platform line(s) and {mentions} mention(s)"
        )
    return found[0]


def judge(report: str, bom: str) -> list[str]:
    """Every reason `report` does not resolve one Kotlin stdlib at `bom`
    (empty when it does)."""
    if not report.strip():
        return ["the dependencies report is empty"]
    errors: list[str] = []
    rows = 0
    bom_resolved = False
    for lineno, line in enumerate(report.splitlines(), 1):
        if "FAILED" in line:
            errors.append(f"line {lineno}: a dependency failed to resolve: {line.strip()}")
            continue
        coordinate = line[_TREE.match(line).end():].rstrip()
        if coordinate.startswith("org.jetbrains.kotlin:kotlin-bom:"):
            declared = coordinate.removeprefix("org.jetbrains.kotlin:kotlin-bom:").split(" ", 1)[0]
            bom_resolved = bom_resolved or declared == bom
            continue
        if not coordinate.startswith(_STDLIB_PREFIX):
            continue
        rows += 1
        row = _STDLIB_ROW.fullmatch(coordinate)
        if row is None:
            errors.append(f"line {lineno}: an unreadable kotlin-stdlib row: {coordinate}")
            continue
        artifact, declared, upgraded = row.group(1), row.group(2), row.group(3)
        resolved = upgraded if upgraded is not None else declared
        if resolved is None or not _VERSION.fullmatch(resolved):
            errors.append(f"line {lineno}: {artifact} resolves to no plain version: {coordinate}")
        elif resolved != bom:
            errors.append(f"line {lineno}: {artifact} resolves to {resolved}, not the kotlin-bom {bom}: {coordinate}")
    if rows == 0:
        errors.append("the report resolves no kotlin-stdlib row; it cannot prove the stdlib is aligned")
    if not bom_resolved:
        errors.append(f"the report does not resolve the kotlin-bom {bom} platform")
    return errors


def main(argv: Sequence[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    report_path, gradle_path = argv
    report = read_bounded(report_path)
    gradle = read_bounded(gradle_path)
    for text in (report, gradle):
        if isinstance(text, Refused):
            print(f"android_resolution: {text.reason}", file=sys.stderr)
            return 1
    assert isinstance(report, str) and isinstance(gradle, str)
    bom = bom_version(gradle)
    if isinstance(bom, Refused):
        print(f"android_resolution: {bom.reason}", file=sys.stderr)
        return 1
    errors = judge(report, bom)
    for err in errors:
        print(f"android_resolution: {err}", file=sys.stderr)
    if errors:
        return 1
    print(f"android_resolution: every kotlin-stdlib row resolves to the kotlin-bom {bom}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
