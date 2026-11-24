# Phase 4 - offline unit tests with a failure ratchet

**Idea:** most repos already have failing tests. Blocking on "all green" would
block every PR, so we pin today's failures in a baseline and only fail on
*new* failures. As tests get fixed the baseline shrinks; it should never grow.

## Files (copy into the repo)
| Kit file | Goes to | What it does |
|---|---|---|
| `ci-tests.yml` | `.github/workflows/ci-tests.yml` | Python 3.14, pip cache, install deps, run ratchet, upload JUnit XML, job summary. Non-blocking, `contents: read`, PR + push main + manual. |
| `test_ratchet.py` | `scripts/ci/test_ratchet.py` | Runs pytest -> JUnit XML -> compares with baseline. Restores any tracked file the tests rewrote. |
| `tests.template.json` | `.ci/tests.json` | Repo-specific: test paths, ignores, and `deselect` for tests that need network/live services. |
| `requirements-tests.template.txt` | `scripts/ci/requirements-tests.txt` | Extra pinned packages tests import (pytest, pyyaml, ...). |
| (generated) | `scripts/ci/test_baseline.json` | Known-failing test IDs. Create with `--update-baseline`. |

## Setup on a new repo
1. Fill `.ci/tests.json` (see `tests.example.json`).
2. Run the suite with networking OFF to find tests that secretly call the
   internet: `unshare -rn python -m pytest ...` (Linux). Deselect those.
3. Fix collection errors by adding missing imports to requirements-tests.txt
   (collection errors are never baselined - they always fail the check).
4. `python scripts/ci/test_ratchet.py --update-baseline`, review, commit.
5. `python scripts/ci/test_ratchet.py` must print PASS. Then prove it: break a
   passing test's target (expect NEW REGRESSION, exit 1); pin a passing test in
   the baseline (expect FIXED); add a test file with a bad import (expect
   LOADER BROKEN). Revert.

## Outcomes
- PASS: no failures outside the baseline.
- FAIL: new regression, collection/load error, pytest crash/timeout, or no tests.
- FIXED / no-longer-found baseline entries are reported; they fail only with
  `--strict-baseline` (turn on once the team is used to the loop).

## Limits
- Ratchets per test function. `subTest` failures inside an already-failing
  test are not counted separately, so a known-failing test can get worse silently.
- Deselected live tests are not run in CI at all.
