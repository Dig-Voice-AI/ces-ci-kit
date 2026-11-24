# Phase 1: Syntax Gate

## What it does
`phase1/ci-basic.yml` is a GitHub Actions workflow. It runs on every PR into the default branch, on every push to it, and on demand. It:
1. Compiles every git-tracked `*.py` file (`python -m py_compile`), which catches syntax errors without running any code.
2. Parses every git-tracked `*.json` file, which catches broken config. Each failure shows up as an annotation on the PR.

It is **non-blocking** (`continue-on-error: true`, and not a required check). It needs **no secrets**, has read-only token permissions, and changes no settings.

## How to adopt
```
./apply.sh <owner/repo> [python-version (default 3.14)]          # clone, adapt, test locally, commit on ci/phase1-basic (no push)
./apply.sh <owner/repo> [python-version (default 3.14)] --push   # same, then push the branch
gh pr create -R <owner/repo> --head ci/phase1-basic --title "CI Phase 1: non-blocking syntax check"
```
Clones into an isolated temporary directory (`$CI_KIT_WORKDIR` or `mktemp -d`). The script switches `branches: [main]` to the repo's real default branch and sets the Python version.

## Gotchas
- **gh `workflow` scope:** a push that adds or changes `.github/workflows/*` is rejected unless the token has the `workflow` scope. Fix with `gh auth refresh -h github.com -s workflow`, which is interactive and must be done by the account owner.
- **Filenames with spaces:** always list files with `git ls-files -z` and split on NUL. Plain `split()` breaks on names like `Premier Plans Record Update.txt`.
- **Test on a fresh clone:** untracked local junk can hide or cause failures. apply.sh always clones fresh.
- **Non-blocking first:** watch it go green for a while before making it a required check. Making it required is a settings change that needs approval.
- `.jsonl` and `.yaml` files are not checked in Phase 1.
- A git identity is needed to commit. apply.sh uses the gh login's no-reply address unless `GIT_NAME`/`GIT_EMAIL` are set.
