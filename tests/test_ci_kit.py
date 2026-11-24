"""Comprehensive offline unit tests for CES CI Kit Phases 2-5."""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

KIT_ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, rel_path: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, KIT_ROOT / rel_path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


guardrails = _load_module("check_guardrails", "phase2/check_guardrails.py")
pii_diff = _load_module("check_pii_diff", "phase3/check_pii_diff.py")
office_extract = _load_module("extract_office_text", "phase3/extract_office_text.py")
ratchet = _load_module("test_ratchet", "phase4/test_ratchet.py")
drift = _load_module("check_drift", "phase5/check_drift.example.py")
scrapi_audit = _load_module("run_scrapi_audit", "phase5/scrapi/run_scrapi_audit.py")
live_smoke = _load_module("check_live_app", "phase5/smoke/check_live_app.py")
eval_summary = _load_module("summarize_evals", "phase5/summarize_evals.py")


def test_guardrails_ast_negative_ints_bool_rejection_and_json_tamper(tmp_path: Path) -> None:
    (tmp_path / "cb.py").write_text(
        "MENU_ID = 19\nRETRY_SENTINEL = -1\nBAD_BOOL = True\n", encoding="utf-8"
    )
    (tmp_path / "app.json").write_text(
        json.dumps({"loggingSettings": {"redactionConfig": {"enableRedaction": True}}}),
        encoding="utf-8",
    )
    cfg: dict[str, Any] = {
        "baseline_file": ".ci/baseline.json",
        "constant_rules": [
            {
                "name": "menu_lock",
                "paths": ["cb.py"],
                "assign_name_contains": ["MENU_ID"],
                "allowed": ["19"],
                "forbidden": {"4": "DEV menu forbidden"},
            },
            {
                "name": "sentinel_lock",
                "paths": ["cb.py"],
                "assign_name_contains": ["RETRY_SENTINEL"],
                "allowed": [-1],
            },
        ],
        "json_baselines": [
            {"file": "app.json", "key_path": ["loggingSettings", "redactionConfig"]}
        ],
        "commands": [{"name": "ok_cmd", "run": ["{python}", "-c", "pass"]}],
    }
    ci_dir = tmp_path / ".ci"
    ci_dir.mkdir()
    (ci_dir / "guardrails.json").write_text(json.dumps(cfg), encoding="utf-8")

    assert guardrails.main(["--write-baseline"], root=tmp_path) == 0
    assert guardrails.main([], root=tmp_path) == 0

    # Strict int normalization must NOT coerce underscored or padded strings
    assert guardrails._norm_scalar("1_000") == "1_000"
    assert guardrails._norm_scalar(" 7 ") == " 7 "

    # Bool literal `True` must NOT pass as integer `1`
    cfg["constant_rules"] = [
        {
            "name": "bool_check",
            "paths": ["cb.py"],
            "assign_name_contains": ["BAD_BOOL"],
            "allowed": [1],
        }
    ]
    (ci_dir / "guardrails.json").write_text(json.dumps(cfg), encoding="utf-8")
    assert guardrails.main(["--skip-commands"], root=tmp_path) == 1

    # Tampering with protected JSON block must fail
    cfg["constant_rules"] = []
    (ci_dir / "guardrails.json").write_text(json.dumps(cfg), encoding="utf-8")
    (tmp_path / "app.json").write_text(
        json.dumps({"loggingSettings": {"redactionConfig": {"enableRedaction": False}}}),
        encoding="utf-8",
    )
    assert guardrails.main(["--skip-commands"], root=tmp_path) == 1

    # Path traversal outside repo root must raise ValueError
    with pytest.raises(ValueError, match="escapes repository root"):
        guardrails._safe_repo_file(tmp_path, "../outside.json")


def test_pii_scan_masks_and_git_diff_unicode_and_plus_spoof(tmp_path: Path) -> None:
    allow_file = tmp_path / "allow.txt"
    allow_file.write_text(
        "phone: 1-800-555-2200\nemail-domain: example.org\n",
        encoding="utf-8",
    )
    allow = pii_diff.load_allowlist(allow_file)
    assert (
        pii_diff.scan_line("Call 1-800-555-0199 or 800-555-2200 or help@sub.example.org", allow)
        == []
    )
    hits = pii_diff.scan_line("SSN 123-45-6789 email jane.doe@mail.invalid DOB: 1980-04-15", allow)
    assert [k for k, _ in hits] == ["ssn", "email", "dob"]
    assert pii_diff.mask("123-45-6789") == "12*****89"

    # Real temporary git repo test: non-ASCII filename (café.txt) + `++ b/decoy` content spoof
    repo = tmp_path / "gitrepo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    (repo / "seed.txt").write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "add", "seed.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

    (repo / "café.txt").write_text("++ b/decoy.txt\n++ x\nSSN 234-56-7890\n", encoding="utf-8")
    (repo / "my notes.txt").write_text("header\fpage2\u2028next\n", encoding="utf-8")
    subprocess.run(["git", "add", "café.txt", "my notes.txt"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "add unicode, spaces, formfeed & spoof"], cwd=repo, check=True
    )

    parsed = list(pii_diff.added_lines("HEAD~1", "HEAD", cwd=repo))
    assert ("café.txt", 3, "SSN 234-56-7890") in parsed
    assert ("my notes.txt", 1, "header\fpage2\u2028next") in parsed
    assert pii_diff.main(["--base", "HEAD~1", "--head", "HEAD"], cwd=repo) == 1


def test_office_extract_collision_free_and_fails_closed(tmp_path: Path) -> None:
    assert office_extract.safe_output_filename("a/b.docx") != office_extract.safe_output_filename(
        "a__b.docx"
    )

    repo = tmp_path / "officerepo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    (repo / "init.txt").write_text("ok\n", encoding="utf-8")
    subprocess.run(["git", "add", "init.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

    # Valid docx with split runs across two colliding-style paths + one corrupt docx
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "word/document.xml",
            "<w:p><w:r><w:t>SPLIT_</w:t></w:r><w:r><w:t>SECRET_99</w:t></w:r></w:p>",
        )
    (repo / "a").mkdir()
    (repo / "a" / "b.docx").write_bytes(buf.getvalue())
    (repo / "a__b.docx").write_bytes(buf.getvalue())
    (repo / "corrupt.docx").write_bytes(b"not-a-valid-zip")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "add office files"], cwd=repo, check=True)

    out_dir = tmp_path / "extracted"
    # Default fail-closed returns 1 because corrupt.docx could not be scanned
    assert office_extract.main(["HEAD~1", "HEAD", str(out_dir)], cwd=repo) == 1
    txt_files = list(out_dir.glob("*.txt"))
    assert len(txt_files) == 2
    assert all("SPLIT_SECRET_99" in f.read_text(encoding="utf-8") for f in txt_files)
    # With --allow-unreadable, returns 0
    assert (
        office_extract.main(["--allow-unreadable", "HEAD~1", "HEAD", str(out_dir)], cwd=repo) == 0
    )


def test_ratchet_refuses_broken_loader_baseline_and_enforces_strict(tmp_path: Path) -> None:
    broken_xml = tmp_path / "broken.xml"
    broken_xml.write_text(
        '<testsuite tests="1"><testcase classname="" name="tests/bad.py">'
        '<error message="SyntaxError"/></testcase></testsuite>',
        encoding="utf-8",
    )
    baseline = tmp_path / "test_baseline.json"
    # Must refuse to pin a broken collection run
    assert (
        ratchet.main(["--junit", str(broken_xml), "--update-baseline"], baseline_path=baseline) == 1
    )
    assert not baseline.exists()

    # Valid run with 1 pass + 1 known failure
    junit_xml = tmp_path / "junit.xml"
    junit_xml.write_text(
        '<testsuite tests="2">'
        '<testcase classname="suite.mod" name="test_ok"/>'
        '<testcase classname="suite.mod" name="test_known"><failure message="boom"/></testcase>'
        "</testsuite>",
        encoding="utf-8",
    )
    assert (
        ratchet.main(["--junit", str(junit_xml), "--update-baseline"], baseline_path=baseline) == 0
    )
    assert ratchet.main(["--junit", str(junit_xml)], baseline_path=baseline) == 0

    # New regression -> exit 1
    reg_xml = tmp_path / "reg.xml"
    reg_xml.write_text(
        '<testsuite tests="2">'
        '<testcase classname="suite.mod" name="test_ok"><failure message="regressed"/></testcase>'
        '<testcase classname="suite.mod" name="test_known"><failure message="boom"/></testcase>'
        "</testsuite>",
        encoding="utf-8",
    )
    assert ratchet.main(["--junit", str(reg_xml)], baseline_path=baseline) == 1

    # Fixed baseline entry -> passes normally, fails under --strict-baseline
    fixed_xml = tmp_path / "fixed.xml"
    fixed_xml.write_text(
        '<testsuite tests="2">'
        '<testcase classname="suite.mod" name="test_ok"/>'
        '<testcase classname="suite.mod" name="test_known"/>'
        "</testsuite>",
        encoding="utf-8",
    )
    assert ratchet.main(["--junit", str(fixed_xml)], baseline_path=baseline) == 0
    assert (
        ratchet.main(["--junit", str(fixed_xml), "--strict-baseline"], baseline_path=baseline) == 1
    )


def test_scrapi_project_flat_slug_collision_and_path_relativize(tmp_path: Path) -> None:
    export_dir = tmp_path / "export"
    (export_dir / "agents").mkdir(parents=True)
    (export_dir / "app.json").write_text(json.dumps({"displayName": "Demo"}), encoding="utf-8")
    (export_dir / "agents" / "a1.json").write_text(
        json.dumps({"displayName": "Root Agent"}), encoding="utf-8"
    )
    (export_dir / "agents" / "a1.md").write_text("<role>Root</role>", encoding="utf-8")
    (export_dir / "agents" / "a2.json").write_text(
        json.dumps({"displayName": "Root_Agent"}), encoding="utf-8"
    )
    (export_dir / "agents" / "a2.md").write_text("<role>Dup</role>", encoding="utf-8")

    with pytest.raises(ValueError, match="Slug collision"):
        scrapi_audit.project_flat(export_dir, tmp_path / "out")

    # Fix collision and verify flat projection + path traversal rejection
    (export_dir / "agents" / "a2.json").write_text(
        json.dumps({"displayName": "FAQ_Agent"}), encoding="utf-8"
    )
    scrapi_audit.project_flat(export_dir, tmp_path / "out")
    assert (tmp_path / "out" / "agents" / "Root_Agent" / "instruction.txt").is_file()
    assert (
        scrapi_audit.relativize_finding_path(
            str(tmp_path / "out" / "agents" / "Root_Agent" / "instruction.txt"), tmp_path
        )
        == "out/agents/Root_Agent/instruction.txt"
    )
    with pytest.raises(ValueError, match="escapes export root"):
        scrapi_audit.read_inside(export_dir, "../outside.txt")


def test_drift_helpers_port_registry_and_custom_labels() -> None:
    assert (
        drift.strip_image_tag_and_digest("us-central1-docker.pkg.dev:5000/proj/svc:v1@sha256:abcd")
        == "us-central1-docker.pkg.dev:5000/proj/svc"
    )
    assert drift.diff_paths(1, 2) == ["(value differs)"]
    res = drift.compare_sets(
        "agent",
        {"root": {"description": "v1"}, "old": {}},
        {"root": {"description": "v2"}, "new": {}},
        left_label="serving version",
        right_label="draft",
        only_left_desc="in serving version, deleted in draft",
        only_right_desc="in draft, not deployed",
    )
    assert "agent `old`: in serving version, deleted in draft" in res
    assert "agent `new`: in draft, not deployed" in res


def test_live_smoke_fixture_and_mismatch(tmp_path: Path) -> None:
    (tmp_path / "app.json").write_text(
        json.dumps(
            {
                "name": "projects/demo-proj/locations/us/apps/app-1",
                "rootAgent": "projects/demo-proj/locations/us/apps/app-1/agents/root-1",
                "displayName": "Demo Assistant",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "agents.json").write_text(
        json.dumps(
            {"agents": [{"name": "projects/demo-proj/locations/us/apps/app-1/agents/root-1"}]}
        ),
        encoding="utf-8",
    )
    (tmp_path / "tools.json").write_text(
        json.dumps(
            {"tools": [{"name": "projects/demo-proj/locations/us/apps/app-1/tools/lookup"}]}
        ),
        encoding="utf-8",
    )
    (tmp_path / "deployments.json").write_text(
        json.dumps(
            {"deployments": [{"name": "projects/demo-proj/locations/us/apps/app-1/deployments/d1"}]}
        ),
        encoding="utf-8",
    )
    expect_file = tmp_path / "expect.json"
    expect_payload: dict[str, Any] = {
        "project": "demo-proj",
        "location": "us",
        "app_id": "app-1",
        "root_agent": "root-1",
        "display_name_contains": "Demo",
        "agents": ["root-1"],
        "min_tools": 1,
        "required_tools": ["lookup"],
        "min_deployments": 1,
    }
    expect_file.write_text(json.dumps(expect_payload), encoding="utf-8")
    assert live_smoke.main(["--expect", str(expect_file), "--offline-fixture", str(tmp_path)]) == 0

    expect_payload["required_tools"] = ["missing_tool"]
    expect_file.write_text(json.dumps(expect_payload), encoding="utf-8")
    assert live_smoke.main(["--expect", str(expect_file), "--offline-fixture", str(tmp_path)]) == 1


def test_summarize_evals_handles_malformed_json_and_null_latency(tmp_path: Path) -> None:
    res = tmp_path / "eval_out.json"
    res.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "test_name": "greeting|smoke\r\n",
                        "passed": True,
                        "total_latency_ms": "not-a-float",
                        "turns": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    non_dict = tmp_path / "array_root.json"
    non_dict.write_text("[]", encoding="utf-8")
    md = eval_summary.format_eval_summary([str(res), str(non_dict)])
    assert "**1/1 passed**" in md
    assert "| greeting\\|smoke   | PASS | 0 |  |" in md
    assert "Could not read results: ValueError" in md
