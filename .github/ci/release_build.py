#!/usr/bin/env python3
"""The release build's feature set and packages, named once.

Every release binary is `cargo build --release --locked --features
<RELEASE_FEATURE> -p <each of RELEASE_PACKAGES>`. Three readers import these
names and never restate them: `verify-manifest.py` check 23 pins the release
cargo lines to them, check 28 asserts `deny.toml [graph]` covers
`RELEASE_FEATURE`, and `supply_chain_scope.py` proves the dependency scan
judges every crate that build links.
"""

from __future__ import annotations

# The feature release binaries ship: `ipe dev run --target wasi` needs it, and
# its refusal text promises it "in release packaging". A comma-separated list
# in cargo's `--features` grammar, each a bare feature name: cargo enables it on
# every selected package that declares it. A `<pkg>/<feature>` spelling is
# never used — `ipe`'s self dev-dependency is keyed `ipe`, so cargo would read
# `ipe/<feature>` as that dev edge's feature and leave the shipped binary
# without it (verify-manifest check 30).
RELEASE_FEATURE = "wasi_run"

# The packages a release build compiles, in the order the cargo lines name them.
RELEASE_PACKAGES = ("ipe", "ipe-ffi-inspector")


def release_features() -> tuple[str, ...]:
    """`RELEASE_FEATURE` split into its features, in order."""
    return tuple(f for f in RELEASE_FEATURE.split(",") if f)


def package_args() -> str:
    """The release cargo lines' package selection, `-p <pkg>` per package."""
    return " ".join(f"-p {p}" for p in RELEASE_PACKAGES)
