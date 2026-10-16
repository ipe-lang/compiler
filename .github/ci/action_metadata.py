#!/usr/bin/env python3
"""Proven declared inputs of every pinned third-party action (check 24).

A remote `uses: owner/repo[/path]@<sha>` names a git commit. A commit names
its root tree, a tree names each entry, and a blob is its bytes; each object's
id is `sha1("<type> <len>\\0" + data)`. A record under
`.github/ci/action-metadata/<owner>/<repo>/<sha>.json` holds exactly the raw
objects on the path from that commit to the action's `action.yml`. `prove`
re-hashes every object offline, walks commit -> tree -> path -> `action.yml`,
and reads the action's `inputs:` from the proven bytes, so a record cannot
claim an input the pinned commit does not declare without breaking a hash.

Verification never touches the network. `--write` (maintainer only, listed in
`MAINTAINER_TOOLS`) is the one networked path: it fetches each pinned commit,
writes the walk's objects as canonical JSON, deletes records no step uses,
and proves what it wrote. Records are generated, never hand-edited.

Refusals are typed (`Refusal`, `RefusalKind`); the verifier maps each kind to
its own `ErrorKind`.
"""

from __future__ import annotations

import base64
import dataclasses
import enum
import hashlib
import json
import os
import re
import selectors
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import strict_yaml  # noqa: E402  # the shared strict loader

import yaml  # noqa: E402  # strict_yaml's error type is a `yaml.YAMLError`

HERE = os.path.dirname(os.path.abspath(__file__))
RECORDS_DIR = os.path.join(HERE, "action-metadata")
WRITE_COMMAND = "python3 .github/ci/action_metadata.py --write"

# A third-party action pinned by content: owner, repo, an optional subpath,
# and the full commit SHA (a tag or branch can be re-pointed upstream).
PINNED_REMOTE_USES_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}\Z")
_NAME_RE = re.compile(r"[A-Za-z0-9_.-]+\Z")
_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
_RECORD_FILE_RE = re.compile(r"[0-9a-f]{40}\.json\Z")

OBJECT_CEILING = 1024 * 1024
RECORD_CEILING = 4 * 1024 * 1024
OBJECTS_CEILING = 64
# Tree-entry modes, as git writes them.
MODE_TREE = b"40000"
FILE_MODES = frozenset({b"100644", b"100755"})
ACTION_FILES = ("action.yml", "action.yaml")
OBJECT_TYPES = frozenset({"commit", "tree", "blob"})
# Inputs a `runs.using: docker` action reads without declaring them.
DOCKER_IMPLICIT_INPUTS = frozenset({"args", "entrypoint"})

GIT_TIMEOUT_SECONDS = 120
GIT_OUTPUT_CEILING = OBJECT_CEILING + 1


class RefusalKind(enum.Enum):
    """Why a pin or a record is refused."""

    MALFORMED = "malformed"
    UNPROVEN = "unproven"


@dataclasses.dataclass(frozen=True)
class Refusal:
    """A typed refusal: its kind and why."""

    kind: RefusalKind
    detail: str


RecordKey = tuple[str, str, str]


@dataclasses.dataclass(frozen=True)
class RemotePin:
    """A pinned remote `uses:` parsed once: owner, repo, subpath segments,
    commit SHA, and the record key GitHub's case-insensitive owner and repo
    resolve to."""

    owner: str
    repo: str
    path: tuple[str, ...]
    sha: str

    @property
    def key(self) -> RecordKey:
        return (self.owner.casefold(), self.repo.casefold(), self.sha)

    @staticmethod
    def parse(uses: str) -> RemotePin | Refusal:
        if not PINNED_REMOTE_USES_RE.match(uses):
            return Refusal(RefusalKind.MALFORMED, f"{uses!r} is not `owner/repo[/path]@<40-hex sha>`")
        ref, sha = uses.rsplit("@", 1)
        owner, repo, *path = ref.split("/")
        for seg in (owner, repo, *path):
            if seg in ("", ".", ".."):
                return Refusal(RefusalKind.MALFORMED, f"{uses!r} has an empty, `.` or `..` segment")
        return RemotePin(owner, repo, tuple(path), sha)


def record_path(key: RecordKey, records_dir: str = RECORDS_DIR) -> str:
    owner, repo, sha = key
    return os.path.join(records_dir, owner, repo, f"{sha}.json")


@dataclasses.dataclass(frozen=True)
class GitObject:
    type: str
    data: bytes


@dataclasses.dataclass(frozen=True)
class ActionRecord:
    """A record's objects by id, strictly decoded but not yet proven."""

    objects: dict[str, GitObject]

    @staticmethod
    def load(path: str) -> ActionRecord | Refusal:
        try:
            with open(path, "rb") as f:
                raw = f.read(RECORD_CEILING + 1)
        except OSError as e:
            return Refusal(RefusalKind.MALFORMED, f"cannot be read: {e}")
        if len(raw) > RECORD_CEILING:
            return Refusal(RefusalKind.MALFORMED, f"exceeds {RECORD_CEILING} bytes")
        return ActionRecord.parse(raw)

    @staticmethod
    def parse(raw: bytes) -> ActionRecord | Refusal:
        def bad(detail: str) -> Refusal:
            return Refusal(RefusalKind.MALFORMED, detail)

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            out: dict[str, object] = {}
            for k, v in pairs:
                if k in out:
                    raise ValueError(f"duplicate key {k!r}")
                out[k] = v
            return out

        try:
            doc = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
        except (UnicodeDecodeError, ValueError) as e:
            return bad(f"is not strict JSON: {e}")
        if not isinstance(doc, dict) or set(doc) != {"objects"}:
            return bad("top-level keys must be exactly {'objects'}")
        objs = doc["objects"]
        if not isinstance(objs, dict):
            return bad("`objects` must be a mapping")
        if len(objs) > OBJECTS_CEILING:
            return bad(f"holds {len(objs)} objects, over the {OBJECTS_CEILING} ceiling")
        out: dict[str, GitObject] = {}
        for oid, entry in objs.items():
            if not _SHA_RE.match(oid):
                return bad(f"object id {oid!r} is not 40 lowercase hex")
            if not isinstance(entry, dict) or set(entry) != {"type", "base64"}:
                return bad(f"object {oid} must hold exactly `type` and `base64`")
            otype, b64 = entry["type"], entry["base64"]
            if otype not in OBJECT_TYPES or not isinstance(b64, str):
                return bad(f"object {oid} has type {otype!r} (want commit, tree or blob) and a string `base64`")
            if len(b64) > (OBJECT_CEILING * 4) // 3 + 4:
                return bad(f"object {oid} exceeds the {OBJECT_CEILING}-byte object ceiling")
            try:
                data = base64.b64decode(b64.encode("ascii"), validate=True)
            except (ValueError, UnicodeEncodeError) as e:
                return bad(f"object {oid} is not strict base64: {e}")
            if len(data) > OBJECT_CEILING:
                return bad(f"object {oid} exceeds the {OBJECT_CEILING}-byte object ceiling")
            out[oid] = GitObject(otype, data)
        return ActionRecord(out)


def object_id(otype: str, data: bytes) -> str:
    """The git object id of `data` stored as `otype`."""
    return hashlib.sha1(f"{otype} {len(data)}\0".encode("ascii") + data).hexdigest()


def serialise(objects: dict[str, GitObject]) -> str:
    """A record's canonical JSON text: sorted keys, indent 2, final newline."""
    doc = {
        "objects": {
            oid: {"type": o.type, "base64": base64.b64encode(o.data).decode("ascii")}
            for oid, o in objects.items()
        }
    }
    return json.dumps(doc, sort_keys=True, indent=2) + "\n"


@dataclasses.dataclass(frozen=True)
class TreeEntry:
    mode: bytes
    oid: str


def parse_tree(data: bytes) -> dict[bytes, TreeEntry] | Refusal:
    """A tree object's entries by name (`<octal mode> SP <name> NUL <20
    bytes>`), each bounded against `len(data)`; a truncated entry, a
    non-octal mode, an empty name, or a repeated name is refused."""
    out: dict[bytes, TreeEntry] = {}
    pos = 0
    end = len(data)
    while pos < end:
        sp = data.find(b" ", pos, end)
        if sp == -1:
            return Refusal(RefusalKind.UNPROVEN, "tree entry truncated before its mode ends")
        mode = data[pos:sp]
        if not mode or any(c not in b"01234567" for c in mode):
            return Refusal(RefusalKind.UNPROVEN, f"tree entry mode {mode!r} is not octal")
        nul = data.find(b"\0", sp + 1, end)
        if nul == -1:
            return Refusal(RefusalKind.UNPROVEN, "tree entry truncated before its name ends")
        name = data[sp + 1 : nul]
        if not name:
            return Refusal(RefusalKind.UNPROVEN, "tree entry has an empty name")
        if nul + 21 > end:
            return Refusal(RefusalKind.UNPROVEN, f"tree entry {name!r} truncated in its object id")
        if name in out:
            return Refusal(RefusalKind.UNPROVEN, f"tree names {name!r} twice")
        out[name] = TreeEntry(mode, data[nul + 1 : nul + 21].hex())
        pos = nul + 21
    return out


def commit_tree(data: bytes) -> str | Refusal:
    """The root tree id a commit names on its first line, exactly `tree <40hex>\\n`."""
    head = data[:46]
    if len(head) != 46 or head[:5] != b"tree " or head[45:46] != b"\n":
        return Refusal(RefusalKind.UNPROVEN, "commit's first line is not `tree <40-hex>`")
    tid = head[5:45].decode("ascii", errors="replace")
    if not _SHA_RE.match(tid):
        return Refusal(RefusalKind.UNPROVEN, "commit's first line is not `tree <40-hex>`")
    return tid


@dataclasses.dataclass(frozen=True)
class ActionInputs:
    """What an action's metadata declares about its inputs."""

    declared: frozenset[str]
    required_no_default: frozenset[str]
    deprecated: frozenset[str]
    docker: bool

    @staticmethod
    def from_doc(doc: object) -> ActionInputs | Refusal:
        """The inputs of a parsed `action.yml` document: `inputs` absent or a
        mapping of string names to a mapping or null, `required` absent or a
        bool; two names that fold equal are refused (GitHub folds case)."""

        def bad(detail: str) -> Refusal:
            return Refusal(RefusalKind.UNPROVEN, f"action metadata {detail}")

        if not isinstance(doc, dict):
            return bad("is not a mapping")
        runs = doc.get("runs")
        if not isinstance(runs, dict) or not isinstance(runs.get("using"), str):
            return bad("has no `runs.using` string")
        raw = doc.get("inputs") if "inputs" in doc else {}
        if not isinstance(raw, dict):
            return bad(f"`inputs` is not a mapping (got {type(raw).__name__})")
        declared: set[str] = set()
        required: set[str] = set()
        deprecated: set[str] = set()
        folded: dict[str, str] = {}
        for name, spec in raw.items():
            if not isinstance(name, str):
                return bad(f"input name {name!r} is not a string")
            if not (spec is None or isinstance(spec, dict)):
                return bad(f"input {name!r} is not a mapping or null")
            other = folded.setdefault(name.casefold(), name)
            if other != name:
                return bad(f"inputs {other!r} and {name!r} fold equal; GitHub reads them as one")
            declared.add(name)
            spec = spec or {}
            req = spec.get("required", False)
            if not isinstance(req, bool):
                return bad(f"input {name!r} has a `required` that is not a bool (got {req!r})")
            if req and "default" not in spec:
                required.add(name)
            if "deprecationMessage" in spec:
                deprecated.add(name)
        return ActionInputs(frozenset(declared), frozenset(required), frozenset(deprecated), runs["using"] == "docker")


ObjectSource = Callable[[str, str], "bytes | Refusal"]


def walk(sha: str, paths: Iterable[tuple[str, ...]], get: ObjectSource) -> tuple[dict[tuple[str, ...], ActionInputs], dict[str, GitObject]] | Refusal:
    """The one walk from commit `sha` to each subpath's action metadata,
    reading objects through `get(id, type)`: every tree segment is a mode
    `40000` entry; the action directory holds exactly one of `action.yml`/
    `action.yaml`, a regular file; its UTF-8 bytes parse under `strict_yaml`.
    Returns each path's inputs and every object read."""
    seen: dict[str, GitObject] = {}

    def fetch(oid: str, otype: str) -> bytes | Refusal:
        got = get(oid, otype)
        if isinstance(got, Refusal):
            return got
        seen[oid] = GitObject(otype, got)
        return got

    commit = fetch(sha, "commit")
    if isinstance(commit, Refusal):
        return commit
    root = commit_tree(commit)
    if isinstance(root, Refusal):
        return root
    out: dict[tuple[str, ...], ActionInputs] = {}
    for path in sorted(set(paths)):
        tid = root
        shown = "/".join(path) or "<root>"
        tree = fetch(tid, "tree")
        if isinstance(tree, Refusal):
            return tree
        entries = parse_tree(tree)
        if isinstance(entries, Refusal):
            return entries
        for seg in path:
            entry = entries.get(seg.encode("utf-8"))
            if entry is None or entry.mode != MODE_TREE:
                return Refusal(RefusalKind.UNPROVEN, f"subpath {shown!r}: segment {seg!r} is not a directory at the pin")
            tree = fetch(entry.oid, "tree")
            if isinstance(tree, Refusal):
                return tree
            entries = parse_tree(tree)
            if isinstance(entries, Refusal):
                return entries
        found = [(n, entries[n.encode("ascii")]) for n in ACTION_FILES if n.encode("ascii") in entries]
        if len(found) != 1:
            which = "both action.yml and action.yaml" if found else "neither action.yml nor action.yaml"
            return Refusal(RefusalKind.UNPROVEN, f"subpath {shown!r} holds {which}")
        fname, entry = found[0]
        if entry.mode not in FILE_MODES:
            return Refusal(
                RefusalKind.UNPROVEN,
                f"subpath {shown!r}: {fname} has mode {entry.mode.decode('ascii', 'replace')}, not a regular file",
            )
        blob = fetch(entry.oid, "blob")
        if isinstance(blob, Refusal):
            return blob
        try:
            doc = strict_yaml.safe_load(blob.decode("utf-8"))
        except UnicodeDecodeError:
            return Refusal(RefusalKind.UNPROVEN, f"subpath {shown!r}: {fname} is not UTF-8")
        except yaml.YAMLError as e:
            return Refusal(RefusalKind.UNPROVEN, f"subpath {shown!r}: {fname} is outside strict YAML: {e}")
        inputs = ActionInputs.from_doc(doc)
        if isinstance(inputs, Refusal):
            return Refusal(inputs.kind, f"subpath {shown!r}: {inputs.detail}")
        out[path] = inputs
    return out, seen


def prove(sha: str, paths: Iterable[tuple[str, ...]], record: ActionRecord) -> dict[tuple[str, ...], ActionInputs] | Refusal:
    """Each subpath's proven inputs at commit `sha`: every object hashes to
    its id, the walk reads only objects the record holds, and the record
    holds no object the walk does not read."""
    for oid, obj in record.objects.items():
        if object_id(obj.type, obj.data) != oid:
            return Refusal(RefusalKind.UNPROVEN, f"object {oid} does not hash to its id")

    def get(oid: str, otype: str) -> bytes | Refusal:
        obj = record.objects.get(oid)
        if obj is None:
            return Refusal(RefusalKind.UNPROVEN, f"the walk needs {otype} {oid}, which the record does not hold")
        if obj.type != otype:
            return Refusal(RefusalKind.UNPROVEN, f"object {oid} is a {obj.type}, the walk needs a {otype}")
        return obj.data

    walked = walk(sha, paths, get)
    if isinstance(walked, Refusal):
        return walked
    inputs, seen = walked
    extra = sorted(set(record.objects) - set(seen))
    if extra:
        return Refusal(RefusalKind.UNPROVEN, f"holds objects no walk reads: {extra}")
    return inputs


def scan_records(records_dir: str = RECORDS_DIR) -> tuple[dict[RecordKey, str], list[Refusal]]:
    """Every record under `records_dir` by key, with a refusal for each
    misnamed entry: an owner or repo directory not lowercase or outside the
    name grammar, a file not `<40-hex>.json`, a stray file, or a symlink."""
    found: dict[RecordKey, str] = {}
    refusals: list[Refusal] = []

    def bad(path: str, why: str) -> None:
        rel = os.path.relpath(path, os.path.dirname(records_dir))
        refusals.append(Refusal(RefusalKind.MALFORMED, f"{rel} {why}"))

    def listing(d: str) -> list[str]:
        try:
            return sorted(os.listdir(d))
        except OSError as e:
            bad(d, f"cannot be listed: {e}")
            return []

    if not os.path.lexists(records_dir):
        return found, refusals
    if os.path.islink(records_dir) or not os.path.isdir(records_dir):
        bad(records_dir, "is not a directory")
        return found, refusals
    for owner in listing(records_dir):
        od = os.path.join(records_dir, owner)
        if os.path.islink(od) or not os.path.isdir(od) or not _NAME_RE.match(owner) or owner != owner.casefold() or owner in (".", ".."):
            bad(od, "is not a lowercase owner directory")
            continue
        for repo in listing(od):
            rd = os.path.join(od, repo)
            if os.path.islink(rd) or not os.path.isdir(rd) or not _NAME_RE.match(repo) or repo != repo.casefold() or repo in (".", ".."):
                bad(rd, "is not a lowercase repo directory")
                continue
            for fname in listing(rd):
                fp = os.path.join(rd, fname)
                if os.path.islink(fp) or not os.path.isfile(fp) or not _RECORD_FILE_RE.match(fname):
                    bad(fp, "is not a `<40-hex sha>.json` record file")
                    continue
                found[(owner, repo, fname[: -len(".json")])] = fp
    return found, refusals


def fetch_argv(owner: str, repo: str, sha: str) -> list[str] | Refusal:
    """The `git fetch` argv for one pinned commit; an owner, repo or SHA
    outside its grammar is refused before any argv is built."""
    for what, value in (("owner", owner), ("repo", repo)):
        if not _NAME_RE.match(value) or value in (".", "..") or value.startswith("-"):
            return Refusal(RefusalKind.MALFORMED, f"{what} {value!r} is outside `[A-Za-z0-9_.-]+`")
    if not _SHA_RE.match(sha):
        return Refusal(RefusalKind.MALFORMED, f"sha {sha!r} is not 40 lowercase hex")
    return [
        "git", "-c", "credential.helper=", "-c", "protocol.version=2", "fetch", "--quiet", "--depth=1",
        "--filter=blob:none", "--no-tags", f"https://github.com/{owner}/{repo}.git", sha,
    ]


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return env


def _run_git(argv: list[str], cwd: str) -> bytes | Refusal:
    """Run one git command with a wall ceiling and a stdout byte ceiling;
    stderr is merged so a failure carries git's reason."""
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    proc = subprocess.Popen(argv, cwd=cwd, env=_git_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    assert proc.stdout is not None
    chunks: list[bytes] = []
    total = 0
    with selectors.DefaultSelector() as sel:
        sel.register(proc.stdout, selectors.EVENT_READ)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                proc.kill()
                proc.wait()
                return Refusal(RefusalKind.UNPROVEN, f"{argv[-2:]!r} exceeded {GIT_TIMEOUT_SECONDS}s")
            if not sel.select(timeout=left):
                continue
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > GIT_OUTPUT_CEILING:
                proc.kill()
                proc.wait()
                return Refusal(RefusalKind.UNPROVEN, f"{argv[-2:]!r} wrote over {GIT_OUTPUT_CEILING} bytes")
            chunks.append(chunk)
    try:
        code = proc.wait(timeout=max(deadline - time.monotonic(), 1))
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return Refusal(RefusalKind.UNPROVEN, f"{argv[-2:]!r} exceeded {GIT_TIMEOUT_SECONDS}s")
    out = b"".join(chunks)
    if code != 0:
        return Refusal(RefusalKind.UNPROVEN, f"{argv[-2:]!r} failed ({code}): {out[-2000:]!r}")
    return out


def _git_source(cwd: str) -> ObjectSource:
    def get(oid: str, otype: str) -> bytes | Refusal:
        size = _run_git(["git", "-c", "credential.helper=", "cat-file", "-s", oid], cwd)
        if isinstance(size, Refusal):
            return size
        if not size.strip().isdigit() or int(size.strip()) > OBJECT_CEILING:
            return Refusal(RefusalKind.UNPROVEN, f"object {oid} exceeds the {OBJECT_CEILING}-byte object ceiling")
        return _run_git(["git", "-c", "credential.helper=", "cat-file", otype, oid], cwd)

    return get


def fetch_record(key: RecordKey, paths: set[tuple[str, ...]]) -> dict[str, GitObject] | Refusal:
    """The objects of one pin's walk, fetched over the network."""
    owner, repo, sha = key
    argv = fetch_argv(owner, repo, sha)
    if isinstance(argv, Refusal):
        return argv
    with tempfile.TemporaryDirectory(prefix="action-metadata-") as tmp:
        for step in (["git", "init", "--quiet"], argv):
            got = _run_git(step, tmp)
            if isinstance(got, Refusal):
                return got
        walked = walk(sha, paths, _git_source(tmp))
    if isinstance(walked, Refusal):
        return walked
    return walked[1]


def _load_verifier():
    """The verifier module, which owns the step traversal `remote_pins` reads."""
    import importlib.util  # noqa: PLC0415

    sys.modules.setdefault("action_metadata", sys.modules[__name__])
    if "verify_manifest" in sys.modules:
        return sys.modules["verify_manifest"]
    spec = importlib.util.spec_from_file_location("verify_manifest", os.path.join(HERE, "verify-manifest.py"))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["verify_manifest"] = mod
    spec.loader.exec_module(mod)
    return mod


def write(records_dir: str = RECORDS_DIR) -> int:
    """Refresh every record from the network, delete stale ones, and prove
    what was written. Exit status 0 only when every pin is proven."""
    pins = _load_verifier().remote_pins()
    by_key: dict[RecordKey, set[tuple[str, ...]]] = {}
    for pin in pins:
        by_key.setdefault(pin.key, set()).add(pin.path)
    failed = False
    for key in sorted(by_key):
        objects = fetch_record(key, by_key[key])
        if isinstance(objects, Refusal):
            print(f"action_metadata: {'/'.join(key)}: {objects.detail}", file=sys.stderr)
            failed = True
            continue
        path = record_path(key, records_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(serialise(objects))
    on_disk, refusals = scan_records(records_dir)
    for r in refusals:
        print(f"action_metadata: {r.detail}", file=sys.stderr)
        failed = True
    for key, path in sorted(on_disk.items()):
        if key not in by_key:
            os.remove(path)
            for d in (os.path.dirname(path), os.path.dirname(os.path.dirname(path))):
                if not os.listdir(d):
                    os.rmdir(d)
            continue
        record = ActionRecord.load(path)
        proven = record if isinstance(record, Refusal) else prove(key[2], by_key[key], record)
        if isinstance(proven, Refusal):
            print(f"action_metadata: {'/'.join(key)}: {proven.detail}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print(f"action_metadata: {len(by_key)} pins proven under {os.path.relpath(records_dir)}")
    return 0


def main(argv: list[str]) -> int:
    if argv != ["--write"]:
        print(f"usage: {WRITE_COMMAND}", file=sys.stderr)
        return 2
    return write()


if __name__ == "__main__":
    sys.modules.setdefault("action_metadata", sys.modules[__name__])
    sys.exit(main(sys.argv[1:]))
