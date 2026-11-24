#!/usr/bin/env python3
"""Phase 4 test ratchet: execute offline unit tests and compare against a known-failure baseline.

Behavior:
  * Pre-existing failures pinned in scripts/ci/test_baseline.json ("known_failures") are allowed.
  * NEW REGRESSION: any failing test NOT in the baseline -> exit 1.
  * LOADER BROKEN: collection/import errors, missing/malformed JUnit XML, or zero tests -> exit 1.
  * FIXED: a baselined test now passes -> reported for cleanup (exit 1 only with --strict-baseline).
  * Working-tree hygiene: any tracked file clean before pytest ran and rewritten during tests
    (e.g., generated index/schema fixtures) is restored via `git checkout --` while leaving prior
    developer edits untouched.

Usage:
  python scripts/ci/test_ratchet.py                         # run & check
  python scripts/ci/test_ratchet.py --update-baseline       # re-pin current failures
  python scripts/ci/test_ratchet.py --junit out/junit.xml   # evaluate an existing JUnit XML report
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "scripts" / "ci" / "test_baseline.json"
CONFIG = ROOT / ".ci" / "tests.json"


def pytest_targets(config_path: Path = CONFIG) -> list[str]:
    """Load target paths, ignores, and deselects from .ci/tests.json."""
    cfg: dict[str, Any] = (
        json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    )
    args = [str(p) for p in (cfg.get("paths") or ["tests"])]
    args.extend(f"--ignore={p}" for p in cfg.get("ignore", []))
    args.extend(f"--deselect={n}" for n in cfg.get("deselect", []))
    args.extend(str(x) for x in cfg.get("extra_args", []))
    return args


def git_dirty(root: Path = ROOT) -> set[str]:
    out = subprocess.run(
        ["git", "status", "--porcelain", "-z", "--no-renames", "--untracked-files=no"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {entry[3:] for entry in out.split("\0") if len(entry) > 3}


def run_pytest(junit: Path, timeout: int, extra: list[str], root: Path = ROOT) -> int:
    junit.parent.mkdir(parents=True, exist_ok=True)
    junit.unlink(missing_ok=True)
    before = git_dirty(root)
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "--continue-on-collection-errors",
        f"--junitxml={junit}",
        *pytest_targets(root / ".ci" / "tests.json"),
        *extra,
    ]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    print("+", " ".join(cmd), flush=True)
    try:
        rc = subprocess.run(cmd, cwd=root, env=env, timeout=timeout, check=False).returncode
    except subprocess.TimeoutExpired:
        print(f"::error title=Test ratchet::pytest exceeded {timeout}s")
        rc = 99
    finally:
        changed = sorted(git_dirty(root) - before)
        if changed:
            print(
                f"Restoring {len(changed)} file(s) rewritten during test run: {', '.join(changed)}"
            )
            subprocess.run(["git", "checkout", "--", *changed], cwd=root, check=True)
    return rc


def read_junit(path: Path) -> tuple[dict[str, str], set[str], dict[str, str]]:
    """Return (failures{id: message}, passed_ids, collection_errors{file: message})."""
    fails: dict[str, str] = {}
    passed: set[str] = set()
    collect: dict[str, str] = {}
    # JUnit XML is generated locally by pytest in the same CI job.
    tree = ET.parse(path)  # noqa: S314
    for tc in tree.iter("testcase"):
        cls = tc.get("classname", "")
        name = tc.get("name", "")
        bad = next((child for child in tc if child.tag in ("failure", "error")), None)
        skipped = any(child.tag == "skipped" for child in tc)
        if not cls:
            if bad is not None:
                collect[name] = (bad.get("message") or "").strip()[:200]
            continue
        node_id = f"{cls}::{name}"
        if bad is not None:
            raw_msg = (bad.get("message") or "").strip()
            fails[node_id] = raw_msg.splitlines()[0][:200] if raw_msg else bad.tag
        elif not skipped:
            passed.add(node_id)
    return fails, passed, collect


def emit_summary(lines: list[str]) -> None:
    text = "\n".join(lines) + "\n"
    print(text)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with Path(step_summary).open("a", encoding="utf-8") as fh:
            fh.write(text)


def main(
    argv: list[str] | None = None,
    baseline_path: Path = BASELINE,
    pytest_exit_code: int | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--junit", type=Path, help="evaluate an existing JUnit XML report")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(tempfile.gettempdir()) / "ci-tests" / "junit.xml",
    )
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument(
        "--strict-baseline",
        action="store_true",
        help="also fail when baseline lists tests that now pass or disappeared",
    )
    parser.add_argument("pytest_args", nargs="*")
    args = parser.parse_args(argv)

    rc: int | None = pytest_exit_code
    junit = args.junit
    if junit is None:
        rc = run_pytest(args.out, args.timeout, args.pytest_args)
        junit = args.out

    if not junit.exists():
        emit_summary(
            ["## Unit tests (ratchet)", "", f"LOADER BROKEN: no JUnit report (pytest exit {rc})"]
        )
        return 1

    try:
        fails, passed, collect = read_junit(junit)
    except ET.ParseError as exc:
        emit_summary(["## Unit tests (ratchet)", "", f"LOADER BROKEN: invalid JUnit XML ({exc})"])
        return 1

    loader_broken = bool(collect) or (rc is not None and rc not in (0, 1)) or not (fails or passed)

    if args.update_baseline:
        if loader_broken:
            emit_summary(
                [
                    "## Unit tests (ratchet)",
                    "",
                    f"Refusing `--update-baseline`: loader/collection is broken (pytest exit {rc}, "
                    f"{len(collect)} collection error(s), {len(fails) + len(passed)} test(s) ran).",
                ]
            )
            return 1
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "_about": (
                "Tests failing on main when pinned. CI fails on any failure NOT listed here. "
                "Remove entries as tests are fixed; never add new ones manually without review."
            ),
            "known_failures": sorted(fails),
        }
        baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"Baseline written: {len(fails)} known failures")
        return 0

    if not baseline_path.exists():
        emit_summary(
            [
                "## Unit tests (ratchet)",
                "",
                f"Baseline missing at `{baseline_path}`. Initialize with `--update-baseline`.",
            ]
        )
        return 1

    base = set(json.loads(baseline_path.read_text(encoding="utf-8")).get("known_failures", []))
    new_regressions = sorted(set(fails) - base)
    fixed = sorted(b for b in base if b in passed)
    gone = sorted(b for b in base if b not in passed and b not in fails)
    still = sorted(set(fails) & base)

    report = [
        "## Unit tests (ratchet)",
        "",
        "| Result | Count |",
        "|---|---|",
        f"| Passed | {len(passed)} |",
        f"| Known failures (baseline, allowed) | {len(still)} |",
        f"| **New regressions** | **{len(new_regressions)}** |",
        f"| Fixed (remove from baseline) | {len(fixed)} |",
        f"| Collection/load errors | {len(collect)} |",
        "",
    ]
    if loader_broken:
        report.append(f"### LOADER BROKEN (pytest exit {rc})")
        report.extend(
            [f"- `{f}`: {m}" for f, m in collect.items()]
            or ["- pytest crashed or collected no tests"]
        )
        report.append("")
    if new_regressions:
        report.append("### New regressions (not in baseline) - fix these")
        report.extend(f"- `{n}` - {fails[n]}" for n in new_regressions)
        report.append("")
    if fixed:
        report.append(
            "### Fixed - remove from scripts/ci/test_baseline.json (or run --update-baseline)"
        )
        report.extend(f"- `{n}`" for n in fixed)
        report.append("")
    if gone:
        report.append("### Baseline entries no longer found (renamed/deleted?) - remove them")
        report.extend(f"- `{n}`" for n in gone)
        report.append("")

    stale = bool(fixed or gone)
    failed = loader_broken or bool(new_regressions) or (args.strict_baseline and stale)
    status_str = "FAIL" if failed else "PASS"
    stale_note = " (baseline is stale - shrink it)" if stale else ""
    report.append(f"**Result: {status_str}**{stale_note}")
    emit_summary(report)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
