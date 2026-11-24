#!/usr/bin/env python3
"""Generic, config-driven Phase 2 CI guardrails. Standard library only.

Reads guardrails.json (default: .ci/guardrails.json, override with --config):
  constant_rules  Python constants/keywords whose values are restricted:
                  {name, paths:[globs], assign_name_contains:[..], known_names:[..],
                   dict_keys:[..], kwarg_contains:[..], allowed:[..],
                   allowed_by_name:[{contains, allowed}], forbidden:{value: message}, hint}
  json_baselines  JSON blocks frozen by SHA-256: {file, key_path:[..], message}
  baseline_file   where the hashes live (default .ci/guardrail_baseline.json)
  commands        extra commands: {name, run:[argv], message, timeout?: int}

Usage: check_guardrails.py [--config F] [--write-baseline] [--skip-commands]
Exit 1 on any error; errors use GitHub ::error annotations.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

_STRICT_INT_RE = re.compile(r"-?\d+")


def _esc_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(text: str) -> str:
    return _esc_data(text).replace(":", "%3A").replace(",", "%2C")


def _record_error(
    errors: list[str], msg: str, *, file_rel: str | None = None, line: int | None = None
) -> None:
    errors.append(msg)
    props = ["title=Guardrail"]
    if file_rel is not None:
        props.insert(0, f"file={_esc_prop(file_rel)}")
        if line is not None:
            props.insert(1, f"line={line}")
    print(f"::error {','.join(props)}::{_esc_data(msg)}")


def _norm_scalar(value: int | str) -> int | str:
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return value
    if _STRICT_INT_RE.fullmatch(value):
        return int(value)
    return value


def _extract_literal_scalar(node: ast.expr) -> tuple[bool, int | str]:
    """Extract an unambiguous int or str literal (including negative ints like -1)."""
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, (int, str))
        and not isinstance(node.value, bool)
    ):
        return True, node.value
    if (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
        and not isinstance(node.operand.value, bool)
    ):
        return True, -node.operand.value
    return False, ""


def _safe_repo_file(root: Path, rel: str) -> Path:
    resolved_root = root.resolve()
    candidate = (resolved_root / rel).resolve()
    if not candidate.is_relative_to(resolved_root):
        raise ValueError(f"Path escapes repository root: {rel!r}")
    return candidate


def _allowed_for(rule: dict[str, Any], name: str) -> set[int | str]:
    upper_name = name.upper()
    for override in rule.get("allowed_by_name", []):
        if str(override["contains"]).upper() in upper_name:
            return {_norm_scalar(x) for x in override["allowed"]}
    return {_norm_scalar(x) for x in rule.get("allowed", [])}


def literal_bindings(tree: ast.AST) -> dict[str, list[ast.expr]]:
    """Map every module/local identifier to its assigned AST value nodes in a file."""
    bindings: dict[str, list[ast.expr]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    bindings.setdefault(target.id, []).append(node.value)
    return bindings


def _check_value(
    errors: list[str],
    rule: dict[str, Any],
    rel: str,
    node: ast.expr,
    label: str,
    allowed: set[int | str],
    binds: dict[str, list[ast.expr]] | None = None,
    seen: tuple[str, ...] = (),
) -> None:
    hint = str(rule.get("hint", "")).strip()
    suffix = f" {hint}" if hint else ""

    if isinstance(node, ast.Name):
        vals = (binds or {}).get(node.id, [])
        if not vals or node.id in seen:
            _record_error(
                errors,
                f"[{rule['name']}] {label} = {node.id}, which is not assigned a literal "
                f"in this file, so CI cannot verify it.{suffix}",
                file_rel=rel,
                line=node.lineno,
            )
            return
        for val_node in vals:
            _check_value(
                errors,
                rule,
                rel,
                val_node,
                f"{label} (via {node.id})",
                allowed,
                binds,
                (*seen, node.id),
            )
        return

    ok, raw_val = _extract_literal_scalar(node)
    if not ok:
        _record_error(
            errors,
            f"[{rule['name']}] {label} is not an int/str literal, so CI cannot verify it.{suffix}",
            file_rel=rel,
            line=node.lineno,
        )
        return

    val = _norm_scalar(raw_val)
    forbidden = {_norm_scalar(k): str(m) for k, m in rule.get("forbidden", {}).items()}
    if val in forbidden:
        _record_error(
            errors,
            f"[{rule['name']}] {label} = {val}: {forbidden[val]}",
            file_rel=rel,
            line=node.lineno,
        )
    elif allowed and val not in allowed:
        want = " or ".join(str(a) for a in sorted(allowed, key=str))
        _record_error(
            errors,
            f"[{rule['name']}] {label} = {val} is not allowed (expected {want}).{suffix}",
            file_rel=rel,
            line=node.lineno,
        )


def check_constant_rule(root: Path, errors: list[str], rule: dict[str, Any]) -> None:
    resolved_root = root.resolve()
    files = sorted(
        {
            p.resolve()
            for glob_pat in rule["paths"]
            for p in resolved_root.glob(glob_pat)
            if p.is_file() and p.resolve().is_relative_to(resolved_root)
        }
    )
    names = [str(s).upper() for s in rule.get("assign_name_contains", [])]
    known = {str(s) for s in rule.get("known_names", [])}
    keys = set(rule.get("dict_keys", []))
    kws = [str(s).lower() for s in rule.get("kwarg_contains", [])]
    found = 0

    for path in files:
        rel = path.relative_to(resolved_root).as_posix()
        try:
            src = path.read_text(encoding="utf-8")
            tree = ast.parse(src, filename=rel)
        except (OSError, UnicodeDecodeError) as exc:
            _record_error(errors, f"[{rule['name']}] cannot read file: {exc}", file_rel=rel, line=1)
            continue
        except SyntaxError as exc:
            _record_error(
                errors,
                f"[{rule['name']}] cannot parse file: {exc.msg}",
                file_rel=rel,
                line=exc.lineno or 1,
            )
            continue

        binds = literal_bindings(tree)
        for node in ast.walk(tree):
            if names and isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and any(n in target.id.upper() for n in names):
                        found += 1
                        if known and target.id not in known:
                            known_list = ", ".join(sorted(known))
                            _record_error(
                                errors,
                                f"[{rule['name']}] unexpected constant name {target.id} "
                                f"(known: {known_list}). Add it to known_names in the guardrails "
                                "config with its allowed value if intended.",
                                file_rel=rel,
                                line=node.lineno,
                            )
                            continue
                        _check_value(
                            errors,
                            rule,
                            rel,
                            node.value,
                            target.id,
                            _allowed_for(rule, target.id),
                            binds,
                        )

            if keys and isinstance(node, ast.Dict):
                for key_node, val_node in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key_node, ast.Constant)
                        and isinstance(key_node.value, (int, str))
                        and not isinstance(key_node.value, bool)
                        and key_node.value in keys
                    ):
                        found += 1
                        _check_value(
                            errors,
                            rule,
                            rel,
                            val_node,
                            f'"{key_node.value}"',
                            _allowed_for(rule, ""),
                            binds,
                        )

            if kws and isinstance(node, ast.keyword) and node.arg:
                arg_lower = node.arg.lower()
                if any(kw in arg_lower for kw in kws):
                    found += 1
                    _check_value(
                        errors, rule, rel, node.value, node.arg, _allowed_for(rule, ""), binds
                    )

    print(f"[{rule['name']}] checked {found} sites in {len(files)} files")


def _block_key(block: dict[str, Any]) -> str:
    return f"{block['file']}#{'.'.join(block['key_path'])}"


def _block_hash(root: Path, block: dict[str, Any]) -> str:
    target = _safe_repo_file(root, str(block["file"]))
    data: Any = json.loads(target.read_text(encoding="utf-8"))
    cur: Any = data
    for key in block["key_path"]:
        cur = cur.get(key) if isinstance(cur, dict) else None
    section = {".".join(block["key_path"]): cur}
    canonical = json.dumps(section, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _line_of(root: Path, rel: str, key: str) -> int:
    target = _safe_repo_file(root, rel)
    needle = f'"{key}"'
    for lineno, line in enumerate(target.read_text(encoding="utf-8").splitlines(), 1):
        if needle in line:
            return lineno
    return 1


def check_baselines(root: Path, errors: list[str], cfg: dict[str, Any], bfile: Path) -> None:
    blocks: list[dict[str, Any]] = cfg.get("json_baselines", [])
    if not blocks:
        return
    resolved_root = root.resolve()
    if not bfile.exists():
        rel_bfile = bfile.resolve().relative_to(resolved_root).as_posix()
        _record_error(
            errors, "Baseline file missing. Run with --write-baseline.", file_rel=rel_bfile, line=1
        )
        return

    base: dict[str, str] = json.loads(bfile.read_text(encoding="utf-8")).get("sha256", {})
    for block in blocks:
        rel_file = str(block["file"])
        target = _safe_repo_file(root, rel_file)
        if not target.exists():
            _record_error(
                errors, "Protected file was deleted or renamed.", file_rel=rel_file, line=1
            )
            continue
        if _block_hash(root, block) != base.get(_block_key(block)):
            dotted = ".".join(block["key_path"])
            extra = str(block.get("message", "")).strip()
            msg = (
                f"Protected block {dotted} changed."
                + (f" {extra}" if extra else "")
                + " If approved, re-record with --write-baseline in the same PR."
            )
            _record_error(
                errors,
                msg,
                file_rel=rel_file,
                line=_line_of(root, rel_file, str(block["key_path"][-1])),
            )
    print(f"checked {len(blocks)} protected JSON blocks")


def write_baseline(root: Path, cfg: dict[str, Any], bfile: Path) -> None:
    bfile.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "_note": (
            "SHA-256 of protected JSON blocks only. "
            "Regenerate with check_guardrails.py --write-baseline (needs approval)."
        ),
        "sha256": {_block_key(b): _block_hash(root, b) for b in cfg.get("json_baselines", [])},
    }
    bfile.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {bfile}")


def run_commands(root: Path, errors: list[str], cfg: dict[str, Any]) -> None:
    for cmd_spec in cfg.get("commands", []):
        argv = [sys.executable if arg == "{python}" else str(arg) for arg in cmd_spec["run"]]
        timeout_s = int(cmd_spec.get("timeout", 300))
        extra = str(cmd_spec.get("message", "")).strip()
        suffix = f" {extra}" if extra else ""
        print(f"== command: {cmd_spec['name']} ==")
        try:
            proc = subprocess.run(
                argv, cwd=root, capture_output=True, text=True, timeout=timeout_s, check=False
            )
        except subprocess.TimeoutExpired:
            _record_error(errors, f"[{cmd_spec['name']}] timed out after {timeout_s}s.{suffix}")
            continue
        except OSError as exc:
            _record_error(errors, f"[{cmd_spec['name']}] could not execute: {exc}.{suffix}")
            continue

        if proc.stdout.strip():
            print(proc.stdout.rstrip())
        if proc.returncode != 0:
            if proc.stderr.strip():
                print(proc.stderr.rstrip())
            _record_error(errors, f"[{cmd_spec['name']}] failed (exit {proc.returncode}).{suffix}")


def main(argv: list[str] | None = None, root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--config", default=".ci/guardrails.json")
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--skip-commands", action="store_true")
    args = parser.parse_args(argv)

    repo_root = (root or Path.cwd()).resolve()
    cfg_path = _safe_repo_file(repo_root, args.config)
    cfg: dict[str, Any] = json.loads(cfg_path.read_text(encoding="utf-8"))
    bfile = _safe_repo_file(repo_root, str(cfg.get("baseline_file", ".ci/guardrail_baseline.json")))

    if args.write_baseline:
        write_baseline(repo_root, cfg, bfile)
        return 0

    errors: list[str] = []
    for rule in cfg.get("constant_rules", []):
        check_constant_rule(repo_root, errors, rule)
    check_baselines(repo_root, errors, cfg, bfile)
    if not args.skip_commands:
        run_commands(repo_root, errors, cfg)

    status = "FAIL" if errors else "PASS"
    print(f"\n{status}: {len(errors)} guardrail error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
