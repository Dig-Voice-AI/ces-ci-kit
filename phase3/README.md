# Phase 3: Secrets + PII scan (non-blocking)

Scans only what a change ADDS (PR base..head, or push before..after), so old content never floods results.

Copy into a repo:
- `ci-secrets-pii.yml` -> `.github/workflows/`
- `.gitleaks.toml` -> repo root (default gitleaks rules + Salesforce + GCP service-account rules)
- `check_pii_diff.py`, `extract_office_text.py` -> `scripts/ci/`
- `pii_allowlist.template.txt` -> `scripts/ci/pii_allowlist.txt`

Repo-specific: allowlist entries. To find candidates, count phone numbers repeated across the repo
(published help lines show up in dozens of files) and have the owner approve each one.

Pieces:
- gitleaks pinned binary (version + sha256 in the workflow). Not gitleaks-action: it needs a paid license for org repos.
- `extract_office_text.py`: gitleaks skips binaries; this pulls text out of new .docx/.xlsx/.pptx (a past real-world leak was in a .docx).
- `check_pii_diff.py`: stdlib; phones, SSN, email, Medicare MBI, DOB on added lines; `pii-allow` inline escape; values masked in output.
- Local run: `gitleaks git --config .gitleaks.toml --redact --log-opts="origin/main..HEAD" .` and
  `python scripts/ci/check_pii_diff.py --base origin/main`.

- Fixture allowlists: if test fixture IDs trip generic rules, allowlist them by the repo's specific prefixes only (see the commented `[[allowlists]]` block at the end of `.gitleaks.toml`). Never allowlist a generic shape like any snake_case; it hides real hits.

## Enforcement
`ci-secrets-pii.yml` ships with `continue-on-error: true` for initial baseline burn-in only. Remove `continue-on-error: true` and mark `Secrets + PII in new changes` as a required branch-ruleset check before enforcing Phase 5.
