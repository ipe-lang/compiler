#!/usr/bin/env bash
# Install (or remove) an opt-in git pre-push hook that runs `tools/scripts/gate quick`.
#
# Usage:
#   tools/scripts/install-pre-push-hook.sh             # install
#   tools/scripts/install-pre-push-hook.sh --uninstall # remove
#
# Nothing installs this automatically. The hook lands where git looks for hooks
# (`core.hooksPath` honoured). A pre-push hook this script did not write is
# never overwritten or removed. Bypass one push with `git push --no-verify`.
set -euo pipefail

MARKER="# ipe-gate-pre-push-hook"

hooks_dir="$(git rev-parse --git-path hooks)"
hook="${hooks_dir}/pre-push"

ours() {
  [[ -f "$hook" ]] && head -n 2 "$hook" | tail -n 1 | { read -r line; [[ "$line" == "$MARKER" ]]; }
}

case "${1:-}" in
  "")
    if [[ -e "$hook" ]] && ! ours; then
      echo "install-pre-push-hook: $hook exists and was not written by this script; leaving it alone" >&2
      exit 1
    fi
    mkdir -p "$hooks_dir"
    cat > "$hook" <<EOF
#!/usr/bin/env bash
${MARKER}
# Runs the manifest-declared quick gate before every push. Remove with
# tools/scripts/install-pre-push-hook.sh --uninstall; skip once with --no-verify.
set -euo pipefail
exec "\$(git rev-parse --show-toplevel)/tools/scripts/gate" quick
EOF
    chmod +x "$hook"
    echo "install-pre-push-hook: installed $hook (runs tools/scripts/gate quick)"
    ;;
  --uninstall)
    if [[ ! -e "$hook" ]]; then
      echo "install-pre-push-hook: no pre-push hook installed"
      exit 0
    fi
    if ! ours; then
      echo "install-pre-push-hook: $hook was not written by this script; leaving it alone" >&2
      exit 1
    fi
    rm -- "$hook"
    echo "install-pre-push-hook: removed $hook"
    ;;
  *)
    echo "usage: $0 [--uninstall]" >&2
    exit 2
    ;;
esac
