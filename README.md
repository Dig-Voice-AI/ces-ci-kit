# CES CI Kit — Google Cloud CX Agent Studio DevSecOps (Phases 1–5)

Config-driven GitHub Actions CI for CES / conversational-agent repos. Works on any git repo
hosted on GitHub. Every check starts **non-blocking**; you turn enforcement on deliberately.

| Phase | Folder | Check name | Needs GCP? |
|---|---|---|---|
| 1 Syntax gate | `phase1/` | Python compiles + JSON parses | No |
| 2 Guardrails | `phase2/` | Repo guardrails | No |
| 3 Secrets + PII | `phase3/` | Secrets + PII in new changes | No |
| 4 Unit tests (ratchet) | `phase4/` | Unit tests (ratchet) | No |
| 5 SCRAPI audit | `phase5/scrapi/` | SCRAPI audit | No (offline lint) |
| 5 Ruleset | `phase5/ruleset.template.json` | — | No |
| 5 Live smoke / drift / evals / deploy | `phase5/smoke/`, `phase5/*.yml` | not required | Yes (WIF, keyless) |

See `PHASES.md` for the roadmap and lessons, and each phase's `README.md` for details.

## Quickstart

Prereqs: `git`, `gh` (logged in, with the `workflow` scope: `gh auth refresh -h github.com -s workflow`),
`uv`, Python 3.14. Linux/macOS or Git Bash/WSL on Windows.

1. **Phase 1 on any repo** (clones fresh, adapts default branch + Python, runs the checks locally, commits on a branch, does not push):
   ```bash
   ./apply.sh <OWNER/REPO>            # add --push to push ci/phase1-basic
   gh pr create -R <OWNER/REPO> --head ci/phase1-basic --title "CI Phase 1: non-blocking syntax check"
   ```
2. **Phases 2-4**: copy the workflow into `.github/workflows/` and the scripts + filled templates into `.ci/`
   (or `scripts/ci/`). Fill every `<PLACEHOLDER>`. Prove each guard by planting a violation and seeing it fail.
3. **SCRAPI audit**: `./apply.sh <OWNER/REPO> --phase5-scrapi --export <path> [--layout flat]`, capture,
   review, and baseline only false positives.
4. **Watch it run non-blocking** (`continue-on-error: true`) until it is reliably green.
5. **Ruleset in evaluate mode**: create from `phase5/ruleset.template.json` with `enforcement: evaluate`
   (`gh api repos/<OWNER/REPO>/rulesets -X POST --input phase5/ruleset.template.json`). Read Rule Insights for about a week.
6. **Enforce**: switch the ruleset to `active`. Smoke, drift and evals are never required checks.
7. **Live checks (optional, needs client GCP access)**: have the GCP project administrator review and execute
   who runs `phase5/gcp/setup-gcp-ci.sh --project <GCP_PROJECT_ID> --repo <OWNER/REPO>` (dry run) then `--apply`.
   Then fill `phase5/smoke/ci-smoke.yml` and `.ci/smoke_expect.json`.

## Placeholders
Everything client-specific is written as `<UPPER_SNAKE>` (or `<lower_name>` in JSON) and/or marked `# PLACEHOLDER`.
Find what is left with: `rg -n '<[A-Za-z_]+>|PLACEHOLDER' .ci .github`

## Rules
- Merge only on a green CI and with no unresolved automated code review findings. automated code review is advisory, not a required check.
- Pin tool versions and verify checksums. Don't use the gitleaks Action (paid license on org repos).
- Run the workflow's exact `run:` commands on a fresh clone before pushing.
- Regenerate baselines, checksums and generated code in the same PR as the change.
- Never print secret values. Never commit service-account keys.
