#!/usr/bin/env python3
"""Generic, offline SCRAPI (cxas-scrapi) lint gate driven by scrapi-audit.json.

Guarantees:
  * Never calls cloud APIs, never executes callback code, never mutates the repo export.
  * Exits 1 only on findings NOT present in the reviewed false-positive baseline.
  * Every baseline entry MUST carry a non-empty human `review_reason`.
  * Fails fast if the installed `cxas-scrapi` commit SHA diverges from `scrapi_commit`.

Usage:
  python run_scrapi_audit.py [--config scrapi-audit.json] [--capture CANDIDATES.json]
"""

from __future__ import annotations

import argparse
import copy
import importlib.metadata
import json
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

KEY = ("file", "rule_id", "severity", "message")


def _esc_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(text: str) -> str:
    return _esc_data(text).replace(":", "%3A").replace(",", "%2C")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def safe_slug(display_name: str) -> str:
    slug = display_name.replace(" ", "_")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", slug):
        raise ValueError(f"Unsupported display name: {display_name!r}")
    return slug


def _register_unique_slug(seen: dict[str, str], slug: str, source_id: str, kind: str) -> None:
    prior = seen.get(slug)
    if prior is not None and prior != source_id:
        raise ValueError(
            f"Slug collision in {kind}: {source_id!r} and {prior!r} both map to {slug!r}"
        )
    seen[slug] = source_id


def read_inside(root: Path, rel: str) -> str:
    resolved_root = root.resolve()
    candidate = (resolved_root / rel).resolve()
    if not candidate.is_relative_to(resolved_root):
        raise ValueError(f"Path escapes export root: {rel!r}")
    return candidate.read_text(encoding="utf-8")


def relativize_finding_path(raw_file: str, base_dir: Path) -> str:
    """Normalize finding paths reliably across symlinks (e.g. macOS /var vs /private/var)."""
    resolved_base = base_dir.resolve()
    candidate = Path(raw_file)
    try:
        resolved_file = candidate.resolve()
        if resolved_file.is_relative_to(resolved_base):
            return resolved_file.relative_to(resolved_base).as_posix()
    except OSError:
        pass
    raw_posix = candidate.as_posix()
    for prefix in (f"{resolved_base.as_posix()}/", f"{base_dir.as_posix()}/"):
        if raw_posix.startswith(prefix):
            return raw_posix.removeprefix(prefix)
    return raw_posix


def project_flat(export: Path, target: Path) -> None:
    """Project a CES flat export into SCRAPI native directory layout without altering code bytes."""
    agents: dict[str, dict[str, Any]] = {
        p.stem: read_json(p) for p in sorted((export / "agents").glob("*.json"))
    }
    if not agents:
        raise ValueError("Export contains zero agents; refusing an empty lint pass")

    cols: dict[str, list[dict[str, Any]]] = {
        k: (read_json(export / f"{k}.json") if (export / f"{k}.json").exists() else [])
        for k in ("tools", "toolsets", "guardrails")
    }

    agent_slugs: dict[str, str] = {}
    names: dict[str, str] = {}
    for rid, agent in agents.items():
        slug = safe_slug(str(agent["displayName"]))
        _register_unique_slug(agent_slugs, slug, rid, "agents")
        names[rid] = slug
    names["end_session"] = "end_session"

    for col_name, col_items in cols.items():
        col_slugs: dict[str, str] = {}
        for item in col_items:
            item_id = str(item["name"]).rsplit("/", 1)[-1]
            slug = safe_slug(str(item["displayName"]))
            _register_unique_slug(col_slugs, slug, item_id, col_name)
            names[item_id] = slug

    def rewrite_refs(val: Any) -> Any:
        if isinstance(val, dict):
            return {k: rewrite_refs(v) for k, v in val.items()}
        if isinstance(val, list):
            return [rewrite_refs(x) for x in val]
        if isinstance(val, str) and val.startswith("projects/"):
            return names.get(val.rsplit("/", 1)[-1], val)
        return val

    app: dict[str, Any] = rewrite_refs(read_json(export / "app.json"))
    target.mkdir(parents=True, exist_ok=True)
    if "globalInstruction" in app:
        (target / "global_instruction.txt").write_text(
            str(app["globalInstruction"]), encoding="utf-8"
        )
        app["globalInstruction"] = "global_instruction.txt"
    write_json(target / "app.json", app)

    for rid, orig_agent in agents.items():
        agent_copy: dict[str, Any] = rewrite_refs(copy.deepcopy(orig_agent))
        alias = names[rid]
        agent_dir = target / "agents" / alias
        agent_dir.mkdir(parents=True, exist_ok=True)
        (agent_dir / "instruction.txt").write_text(
            read_inside(export, f"agents/{rid}.md"), encoding="utf-8"
        )
        agent_copy["instruction"] = f"agents/{alias}/instruction.txt"
        agent_copy.pop("toolsets_source", None)

        callbacks_map: dict[str, list[dict[str, Any]]] = agent_copy.pop("callbacks", {})
        for hook, entries in callbacks_map.items():
            snake_hook = re.sub(r"(?<!^)(?=[A-Z])", "_", hook).lower()
            agent_copy[hook] = []
            for idx, entry in enumerate(entries):
                rel_cb = f"{snake_hook}/{idx:02d}/python_code.py"
                cb_out = agent_dir / rel_cb
                cb_out.parent.mkdir(parents=True, exist_ok=True)
                cb_out.write_text(read_inside(export, str(entry["code_file"])), encoding="utf-8")
                agent_copy[hook].append(
                    {
                        "description": entry.get("description", ""),
                        "pythonCode": f"agents/{alias}/{rel_cb}",
                    }
                )
        write_json(agent_dir / f"{alias}.json", agent_copy)

    spec_extractors = (
        ("openApiToolset", "openApiSchema", "open_api_toolset/open_api_schema.yaml"),
        ("pythonFunction", "pythonCode", "python_function/python_code.py"),
    )
    for col_name, items in cols.items():
        for orig_item in items:
            item_copy: dict[str, Any] = rewrite_refs(copy.deepcopy(orig_item))
            alias = safe_slug(str(item_copy["displayName"]))
            item_dir = target / col_name / alias
            item_dir.mkdir(parents=True, exist_ok=True)
            for container_key, code_field, rel_out in spec_extractors:
                nested = item_copy.get(container_key)
                if isinstance(nested, dict) and code_field in nested:
                    out_file = item_dir / rel_out
                    out_file.parent.mkdir(parents=True, exist_ok=True)
                    out_file.write_text(str(nested[code_field]), encoding="utf-8")
                    nested[code_field] = f"{col_name}/{alias}/{rel_out}"
            write_json(item_dir / f"{alias}.json", item_copy)


def new_findings(
    current: dict[str, Any], baseline: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Perform count-aware matching on (file, rule_id, severity, message)."""
    if current["scrapi_commit"] != baseline.get("scrapi_commit"):
        raise ValueError("SCRAPI commit pin changed; re-review and recapture the baseline")

    missing_reasons = [
        f for f in baseline.get("findings", []) if not str(f.get("review_reason", "")).strip()
    ]
    if missing_reasons:
        raise ValueError(f"{len(missing_reasons)} baseline entries lack review_reason")

    remaining = Counter(tuple(f[k] for k in KEY) for f in baseline.get("findings", []))
    added: list[dict[str, Any]] = []
    for finding in current.get("findings", []):
        sig = tuple(finding[k] for k in KEY)
        if remaining[sig]:
            remaining[sig] -= 1
        else:
            added.append(finding)

    stale = [
        dict(zip(KEY, sig, strict=True)) for sig, count in remaining.items() for _ in range(count)
    ]
    return added, stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--config", default="scrapi-audit.json")
    parser.add_argument("--capture", help="write candidate findings JSON for human review")
    args = parser.parse_args(argv)

    cfg_path = Path(args.config).resolve()
    cfg: dict[str, Any] = read_json(cfg_path)
    repo = cfg_path.parent
    export = (repo / str(cfg["export"])).resolve()
    pin = str(cfg["scrapi_commit"])

    try:
        dist = importlib.metadata.distribution("cxas-scrapi")
    except importlib.metadata.PackageNotFoundError:
        sys.exit("cxas-scrapi is not installed; install requirements-scrapi.txt")

    direct_raw = dist.read_text("direct_url.json") or "{}"
    direct_info: dict[str, Any] = json.loads(direct_raw)
    if direct_info.get("vcs_info", {}).get("commit_id") != pin:
        sys.exit(
            "Installed cxas-scrapi does not match scrapi_commit; install requirements-scrapi.txt"
        )

    from cxas_scrapi.utils.linter import (  # type: ignore[import-not-found,unused-ignore]
        Discovery,
        LintConfig,
        LintReport,
        build_context,
        build_registry,
        run_rules,
    )

    with tempfile.TemporaryDirectory(prefix="scrapi-") as tmp:
        tmp_root = Path(tmp).resolve()
        if cfg.get("layout", "native") == "flat":
            app_dir = tmp_root / "app"
            project_flat(export, app_dir)
            base_dir = tmp_root
        else:
            app_dir = export
            base_dir = export.parent.resolve()

        evals_dir = repo / str(cfg.get("evals", "evals"))
        lint_cfg = LintConfig()
        disc = Discovery(app_dir, evals_dir if evals_dir.exists() else tmp_root / "evals")
        discovered_agents = disc.discover_agents()
        if not discovered_agents:
            sys.exit("SCRAPI discovered 0 agents; verify layout/export in scrapi-audit.json")

        reg = build_registry()
        rep = LintReport()
        run_rules(reg, lint_cfg, build_context(base_dir, lint_cfg, disc), disc, rep)
        findings: list[dict[str, Any]] = [r.to_dict() for r in rep.results]
        for item in findings:
            item["file"] = relativize_finding_path(str(item["file"]), base_dir)

    report: dict[str, Any] = {
        "scrapi_version": dist.version,
        "scrapi_commit": pin,
        "agents": len(discovered_agents),
        "errors": len(rep.errors),
        "warnings": len(rep.warnings),
        "findings": findings,
    }

    if args.capture:
        write_json(
            Path(args.capture),
            {
                "scrapi_commit": pin,
                "policy": (
                    "CANDIDATES ONLY - review each; keep only false positives, add review_reason"
                ),
                "findings": findings,
            },
        )
        print(f"Wrote {len(findings)} candidate findings to {args.capture}")
        return 0

    baseline_path = repo / str(cfg["baseline"])
    baseline: dict[str, Any] = (
        read_json(baseline_path)
        if baseline_path.exists()
        else {"scrapi_commit": pin, "findings": []}
    )
    added, stale = new_findings(report, baseline)
    report["gate"] = {
        "status": "FAIL" if added else "PASS",
        "new_findings": added,
        "stale_reviews": stale,
    }
    write_json(repo / str(cfg.get("out", "audit-output/scrapi.json")), report)

    reviewed_active = len(baseline.get("findings", [])) - len(stale)
    print(
        f"SCRAPI {report['scrapi_version']}: {len(findings)} findings "
        f"({report['errors']} errors, {report['warnings']} warnings); "
        f"reviewed false positives {reviewed_active}; NOT reviewed {len(added)}; "
        f"stale reviews {len(stale)}"
    )
    for f in added:
        msg = f"SCRAPI {f['rule_id']} ({f['severity']}): {f['message']}"
        print(f"::error file={_esc_prop(str(f['file']))},title=SCRAPI audit::{_esc_data(msg)}")
    return 1 if added else 0


if __name__ == "__main__":
    sys.exit(main())
