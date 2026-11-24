#!/usr/bin/env bash
# Usage: apply.sh <owner/repo> [python-version] [--push]
#        apply.sh <owner/repo> --phase5-scrapi --export <path> [--layout native|flat] [--baseline <path>] [--push]
set -euo pipefail

KIT="$(cd "$(dirname "$0")" && pwd)"
REPO="${1:?usage: apply.sh owner/repo [python-version] [--push]}"
shift

if ! [[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || [[ "$REPO" == *"/."* ]] || [[ "$REPO" == *".."* ]]; then
  echo "Invalid repository identifier '$REPO' (expected owner/repo)" >&2
  exit 2
fi

PY="3.14"
PUSH=0
SCRAPI=0
EXPORT=""
LAYOUT="native"
BASELINE="docs/qa/scrapi-reviewed.json"

while [ $# -gt 0 ]; do
  case "$1" in
    --push) PUSH=1 ;;
    --phase5-scrapi) SCRAPI=1 ;;
    --export) EXPORT="$2"; shift ;;
    --layout) LAYOUT="$2"; shift ;;
    --baseline) BASELINE="$2"; shift ;;
    *) PY="$1" ;;
  esac
  shift
done

if [ "$SCRAPI" = 1 ]; then
  exec "$KIT/phase5/scrapi/apply_scrapi.sh" "$REPO" "$EXPORT" "$LAYOUT" "$BASELINE" "$PUSH"
fi

NAME="${REPO#*/}"
WORK_BASE="${CI_KIT_WORKDIR:-$(mktemp -d -t ces-ci-kit.XXXXXX)}"
mkdir -p "$WORK_BASE"
DIR="$WORK_BASE/$NAME"
rm -rf "$DIR"

gh repo clone "$REPO" "$DIR" -- -q
cd "$DIR"
DEF="$(gh repo view "$REPO" --json defaultBranchRef -q .defaultBranchRef.name)"
echo "Default branch: $DEF   Python: $PY"
git switch -q -c ci/phase1-basic "origin/$DEF"
mkdir -p .github/workflows
sed -e "s/branches: \[main\]/branches: [$DEF]/" -e "s/python-version: '[0-9.]*'/python-version: '$PY'/" \
  "$KIT/phase1/ci-basic.yml" > .github/workflows/ci-basic.yml

echo "== Running workflow checks locally (Python $PY via uv) =="
RC=0
uv python install -q "$PY" >/dev/null 2>&1 || true
PYBIN="$(uv python find --no-project "$PY")"
echo "Interpreter: $PYBIN"
git ls-files -z "*.py" | xargs -0 -r "$PYBIN" -m py_compile \
  && echo "PY: compiled $(git ls-files '*.py' | wc -l) files OK" \
  || { echo "PY: FAILED"; RC=1; }

"$PYBIN" - <<'PY' || RC=1
import json, subprocess, sys
out = subprocess.run(["git", "ls-files", "-z", "*.json"], capture_output=True, text=True, check=True).stdout
files = [f for f in out.split("\0") if f]
bad = 0
for f in files:
    try:
        with open(f, encoding="utf-8") as fh:
            json.load(fh)
    except Exception as exc:
        bad += 1
        print(f"JSON error {f}: {exc}")
print(f"JSON: parsed {len(files)} files, {bad} failed")
sys.exit(1 if bad else 0)
PY

find . -name __pycache__ -type d -prune -exec rm -rf {} +
git add .github/workflows/ci-basic.yml
git -c user.name="${GIT_NAME:-$(gh api user -q .login)}" \
    -c user.email="${GIT_EMAIL:-$(gh api user -q '"\(.id)+\(.login)@users.noreply.github.com"')}" \
    commit -qm "ci: add non-blocking Phase 1 syntax check (py_compile + JSON parse)"
echo "Committed on ci/phase1-basic in $DIR (local checks rc=$RC)"

if [ "$PUSH" = 1 ]; then
  gh auth status 2>&1 | grep -q "'workflow'" || {
    echo "gh token lacks 'workflow' scope: run gh auth refresh -h github.com -s workflow" >&2
    exit 2
  }
  git push -u origin ci/phase1-basic
else
  echo "Not pushed (pass --push to push)."
fi
exit $RC
