#!/usr/bin/env bash
# tools/scripts/fuzz-well-typed.sh — random run over the well-typed fuzz templates.
#
# The templates live in tests/fuzz/well-typed/; the harness is the `fuzz_templates`
# test of the `ipe` crate. Each iteration picks a template and a seeded fill, then
# requires the program to type-check, `cargo build`, and run clean (exit 0, no
# runtime-fault marker, no timeout). This script only maps flags to the harness
# knobs and runs `random_well_typed_run` with IPE_E2E=1.
#
# Flags:
#   --iters N        Iteration count (1..=10000; harness default 2)
#   --seed N         Start seed (u32; harness default fixed); iteration i uses seed+i
#   IPE_FUZZ_FULL=1  Shorthand for --iters 10000
#
# Exit: the test run's status; 2 on a bad flag.
#
# Reproduce a failure: ./tools/scripts/fuzz-well-typed.sh --seed N --iters 1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/env.sh
source "$SCRIPT_DIR/lib/env.sh"

usage() {
    echo "usage: $0 [--iters N] [--seed N]" >&2
    exit 2
}

if [[ -n "${IPE_FUZZ_FULL:-}" ]]; then
    export IPE_FUZZ_ITERS=10000
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iters)
            [[ $# -ge 2 ]] || usage
            export IPE_FUZZ_ITERS="$2"
            shift 2
            ;;
        --seed)
            [[ $# -ge 2 ]] || usage
            export IPE_FUZZ_SEED="$2"
            shift 2
            ;;
        -h | --help)
            echo "usage: $0 [--iters N] [--seed N]"
            exit 0
            ;;
        *)
            echo "$0: unknown flag: $1" >&2
            usage
            ;;
    esac
done

export IPE_E2E=1
cd "$REPO"
exec cargo nextest run -p ipe --test fuzz_templates --profile ci \
    -E 'test(=random_well_typed_run)'
