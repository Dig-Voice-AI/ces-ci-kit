# Phase 5: SCRAPI audit (offline, non-blocking first)

Lints the CES app config that is **committed in the repo** with Google's
`cxas-scrapi` linter (86 rules at v1.9.1). It doesn't use the cloud or credentials,
and it never runs callback code. The gate fails only on findings that aren't in a
**reviewed false-positive baseline**. Real issues are never baselined, so they
stay visible.

| File | Copy to | What |
|---|---|---|
| `ci-scrapi-audit.yml` | `.github/workflows/` | PR + push to default branch + manual; concurrency; `continue-on-error` |
| `run_scrapi_audit.py` | `scripts/ci/` | Config-driven runner; `--capture` writes candidate findings for review |
| `scrapi-audit.template.json` | `scrapi-audit.json` (repo root) | `layout`, `export`, `evals`, `baseline`, `scrapi_commit`, `out` |
| `scrapi-reviewed.template.json` | the `baseline` path | Reviewed false positives, one `review_reason` per entry |
| `requirements-scrapi.txt` | repo root | Isolated, fully pinned audit env (SCRAPI pinned to a release commit) |

## Where is the CES export?
- **native** layout: the SCRAPI / `cxas pull` layout, i.e. `cxas_app/<app>/app.json` +
  `agents/<name>/<name>.json` + `instruction.txt`. Some repos use
  `samples/<sample>/cxas_app/<app_folder>`. Set `export` to the folder holding `app.json`.
- **flat** layout: a CES REST export with `app.json`, `agents/<id>.json` + `agents/<id>.md`,
  `callbacks/*.py` (referenced by `code_file`), `tools.json`, `toolsets.json`, and `guardrails.json`
  (for example `envs/dev/`). The runner projects it into native layout in a temp dir.
- One app per config. For several apps, add one config per app and one workflow step per config.

## Adopt in a new repo
1. Copy the files (or run `apply.sh owner/repo --phase5-scrapi --export <path> [--layout flat]`).
2. Install locally on the CI Python: `python3.14 -m venv .venv-scrapi && .venv-scrapi/bin/pip install -r requirements-scrapi.txt`.
3. `python scripts/ci/run_scrapi_audit.py --capture /tmp/candidates.json`, and check that `agents` > 0.
4. **Review every finding by hand.** Copy only **clear false positives** into the baseline, each with
   a concrete `review_reason`, like "rule misparses an Optional field" or "published number the agent must say".
   Leave real issues out. They keep the job red (non-blocking), and each one goes on the backlog.
5. Run without `--capture`. Exit 1 means there are unreviewed findings. They're printed as PR annotations.
6. Open the PR on a `ci/*` branch. If gitleaks flags the 40-hex `scrapi_commit`, allowlist that **exact
   SHA** (`'''^<sha>$'''`), not a hex pattern.
7. Once it's been green, or its red findings are all understood, for a week or more, add `SCRAPI audit` to the ruleset's required checks.

## Rules learned
- **Bump the pin and recapture the baseline in the same PR.** The runner fails fast on a mismatch. If they drift apart, every run fails with no report.
- **Don't write tests that replay a dated audit report against the live export.** They break the first time the export changes. Test contracts instead: the pin matches, the reasons aren't empty, and the source hashes match the current export.
- **Make a missing report a clear error.** Otherwise an `if: always()` summary step hides the real failure.
- **Check that a workflow is actually enabled.** A workflow that keeps failing tends to get *disabled manually*, so run `gh workflow list --all` before trusting "it's on every PR".
- **Never edit agent or app behavior just to quiet the linter.** Real findings get fixed in their own behavior PR.
- **Keep personal or feature branches out of `push:` triggers.**
