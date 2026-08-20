#!/usr/bin/env bash
# M0's acceptance criterion (DEVELOPMENT_PLAN.md §6, test 14).
#
# The whole architecture rests on file_engine_core staying unaware that share
# links exist (spec §4, §13-R13). That is easy to state and easy to erode: one
# "just a small permission bit" and the core has share vocabulary in it again.
# So the claim is checked mechanically rather than by intention.
#
#   ./tools/check-core-untouched.sh            # compare against the core's default branch
#   CORE_BASE=main ./tools/check-core-untouched.sh
#
# Exits non-zero if the core has any change on its current branch relative to
# its base, or any uncommitted change. Run it before merging M0.
#
# When a CI system exists, this is the job to wire up; there is none in these
# repos today, which is why it ships as a script rather than a workflow file.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="${CORE_DIR:-$(cd "$HERE/../.." && pwd)/file_engine_core}"

if [[ ! -d "$CORE_DIR/.git" ]]; then
    echo "check-core-untouched: no core checkout at $CORE_DIR — set CORE_DIR" >&2
    exit 2
fi

cd "$CORE_DIR"

BASE="${CORE_BASE:-}"
if [[ -z "$BASE" ]]; then
    # The default branch differs per repo in this workspace, so ask git.
    BASE="$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)"
    BASE="${BASE#origin/}"
    BASE="${BASE:-main}"
fi

fail=0

# 1. Uncommitted changes in the core working tree.
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "FAIL: file_engine_core has uncommitted changes:" >&2
    git status --short --untracked-files=no >&2
    fail=1
fi

# 2. Committed changes on the current branch relative to its base.
current="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$current" != "$BASE" ]]; then
    if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
        echo "check-core-untouched: base branch '$BASE' not found in $CORE_DIR" >&2
        exit 2
    fi
    diff_stat="$(git diff --stat "$BASE...HEAD")"
    if [[ -n "$diff_stat" ]]; then
        echo "FAIL: file_engine_core branch '$current' differs from '$BASE':" >&2
        echo "$diff_stat" >&2
        echo >&2
        echo "share_service must not require a core change. If one is genuinely" >&2
        echo "needed, that is the signal to re-open spec §4 deliberately rather" >&2
        echo "than to make the change quietly." >&2
        fail=1
    fi
fi

if [[ $fail -eq 0 ]]; then
    echo "OK: file_engine_core is untouched (branch '$current' vs '$BASE', clean tree)"
fi
exit $fail
