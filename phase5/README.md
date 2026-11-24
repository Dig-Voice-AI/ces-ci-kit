# Phase 5: required checks + cloud jobs (DEV only, owner approval per step)

| File | What |
|---|---|
| `ruleset.template.json` | Branch ruleset on the default branch: PR required (0 approvals), no delete/force-push, 4 required checks (phases 1-4; add the SCRAPI audit as a 5th once it is green), admin bypass. Create with `enforcement: evaluate`, read Rule Insights, then switch to `active`. Expect would-be blocks only on PRs opened before all 4 checks were on main. |
| `ci-drift.yml` + `check_drift.example.py` (fill the PLACEHOLDER constants) | Nightly read-only drift: export live config via WIF SA `ci-readonly` (role ciConfigReader) and diff against the repo. |
| `ci-webchat-smoke.yml` | Live webchat health/index smoke (tests excluded from Phase 4). |
| `ci-evals.yml` + `summarize_evals.py` | Nightly + manual evals against the TEST deployment with tool fakes ON (`scripts/run_eval.py --deployed --tool-fakes`, overrideable via `CES_RUN_EVAL`), SA `ci-evals` (role ciEvalRunner), non-blocking, summary table without full bot replies. |
| `ces-deploy-dev.yml` | workflow_dispatch only, main only. Required `only` slug list (no `all`, no wildcard: never a full sync). Expects repo deploy helpers under `scripts/` (`sync.py`, `deploy.py`, `export.py`, `ces_client.py`; override module path with `CES_TOOLS_DIR`). Job 1 env `dev`: scoped sync + deploy to test deployment. Job 2 env `dev-live` (second approval): repoint live deployment to the same version via `--rollback`. SA `ci-deployer`. |
| `gcp/setup-gcp-ci.sh`, `perms.*.txt` | One generic GCP setup: APIs, custom roles, WIF pool/provider pinned to numeric repo IDs, keyless SAs, bindings, verification. Dry run by default (prints commands); `--apply` to execute. ciEvalRunner and ciDeployer are supersets of ciConfigReader. |
| `smoke/ci-smoke.yml` + `smoke/check_live_app.py` + `smoke/smoke_expect.template.json` | Generic live read-only smoke: keyless WIF as `ci-readonly`, GET-only check that the CES app, root agent, tools and deployments match expectations. Push to main, nightly, dispatch; never PRs. |
| `scrapi/` | SCRAPI offline lint audit on PRs with a reviewed-false-positive baseline (see `scrapi/README.md`). |

Rules learned:
- Never bind a write-capable SA to `attribute.ref/refs/heads/main`: any workflow on main could use it. Bind the OIDC **subject** `repo:OWNER/REPO:environment:<env>` and give the environment required reviewers + a main-only branch policy.
- ciDeployer has `agents.update`, `appVersions.create`, `deployments.update` only: no create/delete/export/import/conversations. New agents stay manual.
- A version cut snapshots the whole shared draft: announce before dispatching.
- Pass workflow inputs through `env:`, validate with a regex; never `${{ inputs.x }}` inside `run:`.
- Known-bug pattern: add a test module with `pytestmark = pytest.mark.xfail(strict=False, reason=...)` before the fix; drop the mark in the fix PR (example: `tests/test_known_bug.py`).
- Environments: required reviewer = owner, `prevent_self_review: false` (solo owner), custom branch policy `main`.
- Don't send the `x-goog-user-project` header from a config-read-only SA: it needs `serviceusage.services.use`.
- Smoke, drift and evals depend on live systems: never make them required checks.
