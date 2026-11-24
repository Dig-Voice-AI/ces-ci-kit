#!/usr/bin/env bash
# Called by ../../apply.sh --phase5-scrapi. Adds the SCRAPI audit on branch ci/phase5-scrapi-audit,
# runs it locally, writes CANDIDATE findings for human review, and does NOT auto-baseline anything.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$1"
EXPORT="${2:?--export <path to folder with app.json> is required}"
LAYOUT="$3"
BASELINE="$4"
PUSH="$5"

if ! [[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || [[ "$REPO" == *"/."* ]] || [[ "$REPO" == *".."* ]]; then
  echo "Invalid repository identifier '$REPO' (expected owner/repo)" >&2
  exit 2
fi
case "$LAYOUT" in
  native|flat) ;;
  *) echo "--layout must be native or flat" >&2; exit 2 ;;
esac

WORK_BASE="${CI_KIT_WORKDIR:-$(mktemp -d -t ces-ci-kit-scrapi.XXXXXX)}"
mkdir -p "$WORK_BASE"
DIR="$WORK_BASE/${REPO#*/}-scrapi"
rm -rf "$DIR"
gh repo clone "$REPO" "$DIR" -- -q
cd "$DIR"

DEF="$(gh repo view "$REPO" --json defaultBranchRef -q .defaultBranchRef.name)"
[ -f "$EXPORT/app.json" ] || { echo "No app.json under $EXPORT" >&2; exit 2; }
git switch -q -c ci/phase5-scrapi-audit "origin/$DEF"
mkdir -p .github/workflows scripts/ci "$(dirname "$BASELINE")"
sed "s/branches: \[main\]/branches: [$DEF]/" "$HERE/ci-scrapi-audit.yml" > .github/workflows/ci-scrapi-audit.yml
cp "$HERE/run_scrapi_audit.py" scripts/ci/
cp "$HERE/requirements-scrapi.txt" .

python3 - "$HERE/scrapi-audit.template.json" "$LAYOUT" "$EXPORT" "$BASELINE" <<'PY'
import json, pathlib, sys
cfg = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
cfg.pop("_layout_help", None)
cfg.update(layout=sys.argv[2], export=sys.argv[3], baseline=sys.argv[4])
pathlib.Path("scrapi-audit.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
PY

echo "== local run (isolated venv) =="
SCRAPI_VENV="$(mktemp -d -t scrapi-venv.XXXXXX)"
trap 'rm -rf "$SCRAPI_VENV"' EXIT
uv venv -q -p 3.14 "$SCRAPI_VENV"
uv pip install -q -p "$SCRAPI_VENV/bin/python" -r requirements-scrapi.txt
CANDIDATES="$WORK_BASE/scrapi-candidates.json"
"$SCRAPI_VENV/bin/python" scripts/ci/run_scrapi_audit.py --capture "$CANDIDATES"
echo "Review $CANDIDATES. Put ONLY clear false positives (each with review_reason) in $BASELINE, then rerun without --capture."

grep -q '^audit-output/' .gitignore 2>/dev/null || echo 'audit-output/' >> .gitignore
git add .github/workflows/ci-scrapi-audit.yml scripts/ci/run_scrapi_audit.py requirements-scrapi.txt scrapi-audit.json .gitignore
git -c user.name="${GIT_NAME:-$(gh api user -q .login)}" \
    -c user.email="${GIT_EMAIL:-$(gh api user -q '"\(.id)+\(.login)@users.noreply.github.com"')}" \
    commit -qm "ci: add Phase 5 offline SCRAPI audit gate"
echo "Committed on ci/phase5-scrapi-audit in $DIR"

if [ "$PUSH" = 1 ]; then
  gh auth status 2>&1 | grep -q "'workflow'" || {
    echo "gh token lacks 'workflow' scope: run gh auth refresh -h github.com -s workflow" >&2
    exit 2
  }
  git push -u origin ci/phase5-scrapi-audit
else
  echo "Not pushed (pass --push to push)."
fi
