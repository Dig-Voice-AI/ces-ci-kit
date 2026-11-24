# CI roadmap

| Phase | What | Generic (kit) | Repo-specific |
|---|---|---|---|
| 1 Syntax gate | py_compile + JSON parse, non-blocking | Entire workflow | Default branch, Python version |
| 2 Guards (kit: `phase2/`, ready) | Static rules from `.ci/guardrails.json`, non-blocking | `check_guardrails.py`, `ci-guardrails.yml`, config schema, baseline writer | The rules: e.g. DEV-only telephony menu IDs and project IDs, no auth changes in protected toolsets, agent hygiene validators |
| 3 Secret + PII scan (kit: `phase3/`, ready) | Pinned gitleaks on new commits + office-doc text; stdlib PII scan of added lines; non-blocking | `ci-secrets-pii.yml`, `.gitleaks.toml` (Salesforce + GCP SA rules), `check_pii_diff.py`, `extract_office_text.py` | `scripts/ci/pii_allowlist.txt` (published phone numbers, email domains), known past leaks |
| 4 Unit tests + ratchet (kit: `phase4/`, ready) | Offline pytest -> JUnit; fail only on failures not in `test_baseline.json` or a test file that will not load; restores files tests rewrite; non-blocking | `ci-tests.yml`, `test_ratchet.py` (`--update-baseline`, `--strict-baseline`), `.ci/tests.json` schema | Test paths, deselected live/network tests, extra deps (`requirements-tests.txt`), the baseline itself |
| 5 Required checks + cloud (kit: `phase5/`, ready) | Ruleset (evaluate, then active) with 4-5 required checks; nightly drift + evals; approval-gated scoped DEV deploy, all via GCP WIF (no keys) | `ruleset.template.json`, `ci-drift.yml`, `ci-evals.yml`, `ces-deploy-dev.yml`, `ci-webchat-smoke.yml`, `smoke/`, `gcp/setup-gcp-ci.sh` + role perms, environment setup | GCP project, app/deployment IDs, service account, IAM. Each step needs owner approval; DEV only |

## Lessons from the reference repos
- Phase 2: guardrails follow name references (`project=VAR`, `PROJECT = _P`) to literals in the same file; unresolvable names fail. Optional per-rule `known_names`.
- Phase 3: fixture allowlists must use repo-specific prefixes (e.g. `sim__`, `golden_`), never generic snake_case.
- `roles/ces.viewer` can read conversations, assistant sessions and contact-center insights (incl. signed call audio): never use it for CI.
- `ces.apps.export` exists only in `roles/ces.appEditor` / `roles/ces.admin` (both can modify/delete apps). The drift check rebuilds the export from the appVersions snapshot instead of granting export.
- A deploy cuts an app version that snapshots everyone's draft edits in a shared app: announce deploys first.

## Phase 5 setup: Workload Identity Federation (keyless GitHub -> GCP)
Why: CI needs to read GCP config without a stored JSON key that could leak.
1. Custom role with get/list only on config resources (CES apps, agents, appVersions, deployments, tools, toolsets, guardrails, examples, changelogs, locations, operations + resourcemanager.projects.get). Do NOT use roles/ces.viewer: it includes conversations, sessions, and CCAI signed audio (PII).
2. WIF pool (`github-ci`, global) + OIDC provider, issuer https://token.actions.githubusercontent.com. Map sub, repository, repository_id, repository_owner_id, ref, event_name. Condition pins numeric ids: `assertion.repository_id=='<ID>' && assertion.repository_owner_id=='<OWNER_ID>'` (get via `gh api repos/OWNER/REPO --jq '.id, .owner.id'`).
3. Service account per job (`ci-readonly`, `ci-evals`, `ci-deployer`), no keys. Bind the custom role at project; grant extra viewer roles at resource level only (e.g. `gcloud run services add-iam-policy-binding`).
4. `roles/iam.workloadIdentityUser` on the SA to `principalSet://iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/github-ci/attribute.repository_id/<ID>`.
5. Verify: describe role/provider, SA IAM policy, `keys list` shows only SYSTEM_MANAGED. If iam.allowedPolicyMemberDomains rejects a binding, stop and escalate to org admin.
6. Workflow: `permissions: id-token: write`, `google-github-actions/auth` with workload_identity_provider + service_account.

Script: `phase5/gcp/setup-gcp-ci.sh` does steps 1-5 (dry run by default).

## Phase 5: SCRAPI audit (offline lint gate), kit in `phase5/scrapi/`
Generic: `ci-scrapi-audit.yml`, `run_scrapi_audit.py` (config `scrapi-audit.json`: native or flat export, pinned SCRAPI commit, baseline),
`scrapi-reviewed.template.json` (false positives ONLY, `review_reason` per entry), `requirements-scrapi.txt`. Non-blocking first.
Then add it as a required check. Adopt: `apply.sh owner/repo --phase5-scrapi --export <path> [--layout flat]`, then `--capture`, review, and baseline only the FPs.
Root causes seen in the field (an existing audit, disabled manually after it kept failing): a frozen dated-report test replayed against a changed export;
a SCRAPI pin bumped without recapturing the baseline; a stale source-hash review; an `always()` summary step crashing on the missing report and hiding the cause;
gitleaks generic-api-key on the pin SHA (allowlist the exact SHA).
