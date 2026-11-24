#!/usr/bin/env python3
"""Render run_eval.py JSON result files into a concise GitHub Step Summary Markdown table.

Usage: summarize_evals.py results1.json [results2.json ...] >> "$GITHUB_STEP_SUMMARY"
Outputs test name, PASS/FAIL, latency, and a truncated 160-character summary of the first
failing assertion—never full conversation turn transcripts. Missing, unreadable, or malformed
result files are reported gracefully without crashing the summary step.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _cell(text: Any) -> str:
    cleaned = str(text if text is not None else "").replace("\r", " ").replace("\n", " ")
    return cleaned.replace("|", "\\|")[:160]


def _safe_latency_ms(raw: Any) -> float:
    if raw is None:
        return 0.0
    try:
        return float(raw)
    except (TypeError, ValueError):
        return 0.0


def format_eval_summary(paths: list[str]) -> str:
    out = ["## CES evals (test widget, tool fakes ON)", ""]
    total = 0
    passed = 0
    for raw_path in paths:
        path = Path(raw_path)
        out.append(f"### {path.stem}")
        try:
            parsed: Any = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("Top-level JSON must be an object")
            data: dict[str, Any] = parsed
        except (OSError, ValueError) as err:
            out.extend(
                [
                    f"Could not read results: {err.__class__.__name__} "
                    "(the run likely errored before writing output).",
                    "",
                ]
            )
            continue

        out.extend(["| Test | Result | Latency (ms) | First failure |", "|---|---|---|---|"])
        results_list = data.get("results")
        if not isinstance(results_list, list):
            results_list = []
        for rec in results_list:
            if not isinstance(rec, dict):
                continue
            total += 1
            is_pass = bool(rec.get("passed"))
            passed += int(is_pass)
            first_failure = str(rec.get("error") or "")
            turns = rec.get("turns")
            if isinstance(turns, list):
                for turn in turns:
                    if not isinstance(turn, dict):
                        continue
                    assertions = turn.get("assertions")
                    if not isinstance(assertions, list):
                        continue
                    failed_assertions = [
                        a for a in assertions if isinstance(a, dict) and not a.get("passed")
                    ]
                    if failed_assertions and not first_failure:
                        first_bad = failed_assertions[0]
                        first_failure = f"[{first_bad.get('type')}] {first_bad.get('message')}"
            latency_ms = _safe_latency_ms(rec.get("total_latency_ms"))
            out.append(
                f"| {_cell(rec.get('test_name'))} | {'PASS' if is_pass else 'FAIL'} "
                f"| {latency_ms:.0f} | {_cell(first_failure)} |"
            )
        out.append("")

    out.insert(1, f"**{passed}/{total} passed**")
    return "\n".join(out)


def main(paths: list[str]) -> int:
    print(format_eval_summary(paths))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
