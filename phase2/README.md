# Phase 2: Guardrails (config-driven)

Checks repo-specific rules statically (no secrets, no cloud access). Non-blocking, `contents: read`, Python 3.14.

Files: `check_guardrails.py` (stdlib only), `ci-guardrails.yml`, `guardrails.template.json`, `guardrails.example.json`.

## Config (`.ci/guardrails.json`)
- `constant_rules`: Python values found by AST: assignments whose name contains a string (`assign_name_contains`), dict literal keys (`dict_keys`), keyword args (`kwarg_contains`). Values must be in `allowed` (narrowed per name by `allowed_by_name`); `forbidden` values fail with a custom message. Name references (`project=VAR`, `PROJECT = _P`) are followed to their literal assignment(s) in the same file and those values are checked; a name with no literal assignment in the file (imports, env lookups, cycles) fails because CI can't verify it. Other non-literal values fail too. Optional `known_names`: the exact constant names expected for a rule; any other assignment matching `assign_name_contains` (e.g. a new `PROJECT_X`) fails until it is added with its allowed value.
- `json_baselines`: `{file, key_path}` blocks frozen by SHA-256 in `baseline_file`. Other keys in the file may change freely.
- `commands`: extra argv commands; `{python}` = current interpreter. Non-zero exit = failure.

## How to adopt
1. Copy into the repo: `check_guardrails.py` and your config to `.ci/`, `ci-guardrails.yml` to `.github/workflows/`.
2. Start from `guardrails.template.json` (or `guardrails.example.json`); set paths, values, messages.
3. Record baselines: `python .ci/check_guardrails.py --write-baseline`, then commit `.ci/guardrail_baseline.json`.
4. Run locally: `python .ci/check_guardrails.py`. Must PASS on main.
5. Prove each rule: plant a violation (e.g. a forbidden value), confirm FAIL, revert.
6. Adjust `branches:` and the `pip install` step, commit on a branch, open a PR. The push needs the gh `workflow` scope.

## Notes
- Checks the repo only, not the live app. Live drift needs GCP access (Phase 5).
- Changing a protected block means re-running `--write-baseline` in the same PR, so reviewers see it.
