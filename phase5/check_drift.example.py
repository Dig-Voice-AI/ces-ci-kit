#!/usr/bin/env python3
"""Phase 5 drift check: verify live non-prod GCP state matches committed repository state.

Read-only: executes GET/list calls only (CES REST v1 + Cloud Run Admin v2). Never exports,
patches, or deploys. Reports field PATHS that differ—never secret or config values—so zero
sensitive payloads can enter CI logs.

Sections compared:
  1. Deployments  - live appVersion + channelProfile vs profiles.json deployments
  2. Capture      - serving appVersion snapshot vs env-snapshot/
  3. Draft        - live console draft vs serving appVersion (undeployed console edits)
  4. Source       - live draft agents vs agents/_src + callbacks/ (sync.py input)
  5. Cloud Run    - container image repo + env var NAMES & kind (plain|secret) vs baseline

Auth: $DRIFT_ACCESS_TOKEN (CI, via google-github-actions/auth WIF), falling back to
`gcloud auth print-access-token` for local developer checks.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
PROJECT = "<GCP_PROJECT_ID>"  # PLACEHOLDER
LOCATION = "us"
APP_ID = "<CES_APP_ID>"  # PLACEHOLDER
APP = f"projects/{PROJECT}/locations/{LOCATION}/apps/{APP_ID}"
CES = "https://ces.googleapis.com/v1"
DEPLOYMENTS: dict[str, str] = {
    "<LIVE_DEPLOYMENT_ID>": "Live deployment",  # PLACEHOLDER
    "<TEST_DEPLOYMENT_ID>": "Test deployment",  # PLACEHOLDER
}
SERVING_DEPLOYMENT = "<LIVE_DEPLOYMENT_ID>"  # PLACEHOLDER
RUN_REGION = "us-central1"
RUN_SERVICES = ("<CLOUD_RUN_SERVICE_1>", "<CLOUD_RUN_SERVICE_2>")  # PLACEHOLDER
CLOUDRUN_BASELINE = ROOT / "scripts/ci/drift_cloudrun_baseline.json"
COLLECTIONS = ("agents", "tools", "toolsets", "guardrails")

VOLATILE = frozenset(
    {
        "createTime",
        "updateTime",
        "etag",
        "generation",
        "uid",
        "reconciling",
        "observedGeneration",
        "latestReadyRevision",
        "latestCreatedRevision",
    }
)
HOOKS = (
    "beforeAgentCallbacks",
    "afterAgentCallbacks",
    "beforeModelCallbacks",
    "afterModelCallbacks",
    "beforeToolCallbacks",
    "afterToolCallbacks",
)
HOOK_SHORT = {h: h[0].lower() + h[1:].replace("Callbacks", "") for h in HOOKS}
_AUTHORING_COMMENT = re.compile(r"<!--.*?-->\s*", re.S)
_PLACEHOLDER_RE = re.compile(r"<[A-Za-z0-9_]+>")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Block HTTP redirects so Bearer tokens are never forwarded cross-host or downgraded."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        raise urllib.error.HTTPError(req.full_url, code, f"Redirect blocked ({msg})", headers, fp)


def _verify_placeholders_configured() -> None:
    values = [PROJECT, LOCATION, APP_ID, SERVING_DEPLOYMENT, *DEPLOYMENTS.keys(), *RUN_SERVICES]
    unreplaced = sorted({v for v in values if _PLACEHOLDER_RE.search(v)})
    if unreplaced:
        joined = ", ".join(unreplaced)
        raise ValueError(f"Unreplaced template placeholder(s) in check_drift.py: {joined}")


def strip_image_tag_and_digest(image: str) -> str:
    """Strip `@sha256:...` digest and `:tag` while preserving registry `host:port` prefixes."""
    no_digest = image.split("@", 1)[0]
    slash_idx = no_digest.rfind("/")
    colon_idx = no_digest.rfind(":")
    if colon_idx > slash_idx:
        return no_digest[:colon_idx]
    return no_digest


class Api:
    """Read-only HTTPS client for CES v1 and Cloud Run Admin v2 (redirects disabled)."""

    def __init__(self, token: str | None = None) -> None:
        tok = (token or os.environ.get("DRIFT_ACCESS_TOKEN", "")).strip()
        if not tok:
            tok = subprocess.run(
                ["gcloud", "auth", "print-access-token"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        if not tok:
            raise RuntimeError("Empty access token from DRIFT_ACCESS_TOKEN / gcloud")
        self._tok = tok
        self._opener = urllib.request.build_opener(_NoRedirectHandler)

    def get(self, url: str) -> dict[str, Any]:
        if not url.startswith("https://"):
            raise ValueError(f"Refusing non-HTTPS API URL: {url!r}")
        req = urllib.request.Request(  # noqa: S310
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self._tok}",
                "x-goog-user-project": PROJECT,
            },
        )
        try:
            with self._opener.open(req, timeout=60) as resp:
                data: dict[str, Any] = json.load(resp)
                return data
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"GET {url.split('?', 1)[0]} -> HTTP {exc.code}") from None

    def list_resources(self, coll: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page_token = ""
        seen_tokens: set[str] = set()
        while True:
            params: dict[str, str | int] = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token
            query = urllib.parse.urlencode(params)
            data = self.get(f"{CES}/{APP}/{coll}?{query}")
            out.extend(data.get(coll, []))
            page_token = str(data.get("nextPageToken") or "")
            if not page_token:
                return out
            if page_token in seen_tokens:
                raise RuntimeError(f"Pagination cycle detected on {coll}")
            seen_tokens.add(page_token)


def short(name: str) -> str:
    return (name or "").rstrip("/").rsplit("/", 1)[-1]


def strip_authoring_comments(text: str) -> str:
    return _AUTHORING_COMMENT.sub("", text or "").strip()


def strip_volatile(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {k: strip_volatile(v) for k, v in obj.items() if k not in VOLATILE}
        lps = out.get("llmPromptSecurity")
        if isinstance(lps, dict) and isinstance(lps.get("defaultSettings"), dict):
            ds = {k: v for k, v in lps["defaultSettings"].items() if k != "defaultPromptTemplate"}
            lps_copy = dict(lps)
            if ds:
                lps_copy["defaultSettings"] = ds
            else:
                lps_copy.pop("defaultSettings", None)
            out["llmPromptSecurity"] = lps_copy
        return out
    if isinstance(obj, list):
        return [strip_volatile(v) for v in obj]
    return obj


def diff_paths(
    left_val: Any,
    right_val: Any,
    path: str = "",
    *,
    left_label: str = "repo",
    right_label: str = "live",
) -> list[str]:
    """Return structural paths where left_val and right_val differ (never raw values)."""
    a = strip_volatile(left_val)
    b = strip_volatile(right_val)
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for k in sorted(set(a) | set(b)):
            sub = f"{path}.{k}" if path else str(k)
            if k not in a:
                out.append(f"{sub} (only {right_label})")
            elif k not in b:
                out.append(f"{sub} (only {left_label})")
            else:
                out.extend(
                    diff_paths(a[k], b[k], sub, left_label=left_label, right_label=right_label)
                )
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            prefix = f"{path} " if path else ""
            return [f"{prefix}(length {left_label} {len(a)} vs {right_label} {len(b)})"]
        list_out: list[str] = []
        for idx, (item_a, item_b) in enumerate(zip(a, b, strict=True)):
            list_out.extend(
                diff_paths(
                    item_a,
                    item_b,
                    f"{path}[{idx}]",
                    left_label=left_label,
                    right_label=right_label,
                )
            )
        return list_out
    if a != b:
        if isinstance(a, str) and isinstance(b, str):
            prefix = f"{path} " if path else ""
            return [
                f"{prefix}(text differs: {left_label} {len(a.splitlines())} lines "
                f"vs {right_label} {len(b.splitlines())} lines)"
            ]
        return [path or "(value differs)"]
    return []


def by_key(
    items: list[dict[str, Any]],
    key_fn: Callable[[dict[str, Any]], str] | None = None,
) -> dict[str, dict[str, Any]]:
    fn = key_fn or (lambda item: short(str(item.get("name", ""))))
    return {fn(item): item for item in items}


def compare_sets(
    label: str,
    left_map: dict[str, Any],
    right_map: dict[str, Any],
    *,
    left_label: str = "repo",
    right_label: str = "live",
    only_left_desc: str | None = None,
    only_right_desc: str | None = None,
) -> list[str]:
    missing_right = only_left_desc or f"in {left_label}, not {right_label}"
    missing_left = only_right_desc or f"{right_label}, not in {left_label}"
    out: list[str] = []
    for key in sorted(set(left_map) | set(right_map)):
        if key not in right_map:
            out.append(f"{label} `{key}`: {missing_right}")
        elif key not in left_map:
            out.append(f"{label} `{key}`: {missing_left}")
        else:
            out.extend(
                f"{label} `{key}`: {p}"
                for p in diff_paths(
                    left_map[key],
                    right_map[key],
                    left_label=left_label,
                    right_label=right_label,
                )
            )
    return out


def section_deployments(
    api: Api, profiles: dict[str, Any]
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    live = {short(str(d["name"])): d for d in api.list_resources("deployments")}
    repo = {str(v.get("id")): v for v in profiles.get("deployments", {}).values()}
    out: list[str] = []
    for dep_id, label in DEPLOYMENTS.items():
        live_dep = live.get(dep_id)
        repo_dep = repo.get(dep_id)
        if live_dep is None:
            out.append(f"{label}: deployment missing live")
            continue
        if repo_dep is None:
            out.append(f"{label}: not recorded in profiles.json")
            continue
        live_ver = short(str(live_dep.get("appVersion", "")))
        repo_ver = str(repo_dep.get("app_version") or "")
        if live_ver != repo_ver:
            out.append(
                f"{label}: serves version `{live_ver[:8]}`, profiles.json says `{repo_ver[:8]}`"
            )
        out.extend(
            f"{label}: channelProfile.{p}"
            for p in diff_paths(
                repo_dep.get("channel_profile") or {},
                live_dep.get("channelProfile") or {},
            )
        )
    for dep_id in sorted(set(live) - set(DEPLOYMENTS)):
        out.append(f"unexpected live deployment `{dep_id[:8]}` ({live[dep_id].get('displayName')})")
    return out, live


def export_like(snap: dict[str, Any], draft_toolsets: dict[str, list[Any]]) -> dict[str, Any]:
    """Rebuild export.py's projected file tree in memory for drift comparison."""
    files: dict[str, Any] = {}
    for agent in snap.get("agents", []):
        slug = short(str(agent["name"]))
        instr_raw = agent.get("instruction")
        instr = instr_raw if isinstance(instr_raw, str) else (instr_raw or {}).get("text", "")
        files[f"agents/{slug}.md"] = instr or ""
        wiring = {
            k: agent[k]
            for k in (
                "displayName",
                "description",
                "tools",
                "childAgents",
                "transferRules",
                "remoteDialogflowAgent",
                "guardrails",
                "modelSettings",
            )
            if k in agent
        }
        cb_meta: dict[str, list[dict[str, str]]] = {}
        for hook in HOOKS:
            specs: list[dict[str, str]] = []
            for idx, cb in enumerate(agent.get(hook) or []):
                fn = f"callbacks/{slug}.{HOOK_SHORT[hook]}.{idx}.py"
                files[fn] = cb.get("pythonCode", "")
                specs.append({"description": cb.get("description", ""), "code_file": fn})
            if specs:
                cb_meta[hook] = specs
        if cb_meta:
            wiring["callbacks"] = cb_meta
        wiring["toolsets"] = (
            agent["toolsets"] if "toolsets" in agent else (draft_toolsets.get(slug) or [])
        )
        files[f"agents/{slug}.json"] = wiring

    for coll in ("tools", "toolsets", "guardrails", "examples"):
        files[f"{coll}.json"] = snap.get(coll, [])
    files["app.json"] = snap.get("app", {})
    return files


def section_capture(
    api: Api, live_deps: dict[str, dict[str, Any]], draft: dict[str, list[dict[str, Any]]]
) -> tuple[list[str], dict[str, Any], str]:
    if SERVING_DEPLOYMENT not in live_deps:
        return (
            [f"Serving deployment `{SERVING_DEPLOYMENT}` missing live; cannot compare capture"],
            {},
            "",
        )

    snapdir = ROOT / "env-snapshot"
    prof: dict[str, Any] = json.loads((snapdir / "profile.json").read_text(encoding="utf-8"))
    ver_id = short(str(live_deps[SERVING_DEPLOYMENT].get("appVersion", "")))
    out: list[str] = []

    if prof.get("deployed_version_id") != ver_id:
        cap_id = str(prof.get("deployed_version_id") or "")[:8]
        out.append(
            f"env-snapshot/profile.json captured version `{cap_id}` "
            f"({prof.get('deployed_version_label')!r}); live deployment now serves `{ver_id[:8]}`. "
            "Re-run export.py and commit."
        )

    ver = api.get(f"{CES}/{APP}/versions/{ver_id}")
    snap: dict[str, Any] = ver.get("snapshot") or {}
    draft_ts = {short(str(a["name"])): a.get("toolsets", []) for a in draft["agents"]}
    live_files = export_like(snap, draft_ts)

    repo_files: dict[str, Any] = {}
    for p in sorted(snapdir.rglob("*")):
        rel = p.relative_to(snapdir).as_posix()
        if p.is_file() and rel != "profile.json":
            txt = p.read_text(encoding="utf-8")
            repo_files[rel] = json.loads(txt) if rel.endswith(".json") else txt

    for rel, content in list(repo_files.items()):
        if rel.startswith("agents/") and rel.endswith(".json") and isinstance(content, dict):
            repo_files[rel] = {k: v for k, v in content.items() if k != "toolsets_source"}

    for coll_file in ("tools.json", "toolsets.json", "guardrails.json", "examples.json"):
        for store in (repo_files, live_files):
            if isinstance(store.get(coll_file), list):
                store[coll_file] = by_key(store[coll_file])

    for rel in sorted(set(repo_files) | set(live_files)):
        if rel not in live_files:
            out.append(f"`{rel}`: in env-snapshot, not in the serving version")
        elif rel not in repo_files:
            out.append(f"`{rel}`: in the serving version, missing from env-snapshot")
        elif (
            isinstance(live_files[rel], dict)
            and rel.endswith("s.json")
            and rel != "app.json"
            and "/" not in rel
        ):
            out.extend(compare_sets(rel, repo_files[rel], live_files[rel]))
        else:
            out.extend(f"`{rel}`: {p}" for p in diff_paths(repo_files[rel], live_files[rel]))
    return out, snap, ver_id


def section_draft(draft: dict[str, list[dict[str, Any]]], snap: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for coll in COLLECTIONS:
        out.extend(
            compare_sets(
                coll[:-1],
                by_key(snap.get(coll, [])),
                by_key(draft[coll]),
                left_label="serving version",
                right_label="draft",
                only_left_desc="in serving version, deleted in draft",
                only_right_desc="in draft, not deployed",
            )
        )
    return out


def _src_agents() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for p in sorted((ROOT / "agents/_src").glob("*.json")):
        data: dict[str, Any] = json.loads(p.read_text(encoding="utf-8"))
        key = (
            data.get("_ces_agent_id")
            or short(str(data.get("name", "")))
            or data.get("agentId")
            or p.stem
        )
        md_path = p.with_suffix(".md")
        data["_md"] = md_path.read_text(encoding="utf-8") if md_path.exists() else None
        data["_file"] = p.name
        out[str(key)] = data
    return out


def section_source(draft: dict[str, list[dict[str, Any]]]) -> list[str]:
    out: list[str] = []
    live = by_key(draft["agents"])
    src = _src_agents()
    callbacks_root = (ROOT / "callbacks").resolve()

    for key in sorted(set(src) | set(live)):
        src_agent = src.get(key)
        live_agent = live.get(key)
        if live_agent is None and src_agent is not None:
            out.append(f"agents/_src/{src_agent['_file']}: no live draft agent `{key}`")
            continue
        if src_agent is None and live_agent is not None:
            out.append(
                f"live draft agent `{key}` ({live_agent.get('displayName')}): no agents/_src file"
            )
            continue
        if src_agent is None or live_agent is None:
            continue

        tag = f"agents/_src/{src_agent['_file']}"
        instr_raw = live_agent.get("instruction")
        instr = instr_raw if isinstance(instr_raw, str) else (instr_raw or {}).get("text", "")
        if src_agent["_md"] is not None and strip_authoring_comments(
            src_agent["_md"]
        ) != strip_authoring_comments(instr):
            out.append(f"{tag}: instruction (.md) differs from draft")

        for field_name in ("displayName", "description", "tools", "childAgents"):
            default_val: Any = [] if field_name in ("tools", "childAgents") else None
            if field_name in src_agent and strip_volatile(src_agent[field_name]) != strip_volatile(
                live_agent.get(field_name, default_val)
            ):
                out.append(f"{tag}: {field_name}")

        for hook in HOOKS:
            want = (src_agent.get("callbacks") or {}).get(hook)
            got = live_agent.get(hook) or []
            if want is None:
                if got:
                    out.append(
                        f"{tag}: {hook} has {len(got)} live draft callback(s) not in agents/_src"
                    )
                continue
            if len(want) != len(got):
                out.append(f"{tag}: {hook} count repo {len(want)} vs draft {len(got)}")
                continue
            for idx, (w_cb, g_cb) in enumerate(zip(want, got, strict=True)):
                cb_rel = str(w_cb.get("file") or "")
                cb_file = (callbacks_root / cb_rel).resolve()
                if not cb_file.is_relative_to(callbacks_root) or not cb_file.is_file():
                    out.append(f"{tag}: {hook}[{idx}] file callbacks/{cb_rel} missing or invalid")
                    continue
                if (
                    cb_file.read_text(encoding="utf-8").strip()
                    != str(g_cb.get("pythonCode") or "").strip()
                ):
                    out.append(f"{tag}: {hook}[{idx}] callbacks/{cb_rel} differs from draft code")
    return out


def cloudrun_live(api: Api) -> dict[str, dict[str, Any]]:
    res: dict[str, dict[str, Any]] = {}
    for svc in RUN_SERVICES:
        svc_enc = urllib.parse.quote(svc, safe="")
        data = api.get(
            f"https://run.googleapis.com/v2/projects/{PROJECT}/locations/{RUN_REGION}/services/{svc_enc}"
        )
        containers = []
        raw_containers = (data.get("template") or {}).get("containers") or []
        for cont in raw_containers:
            image_str = str(cont.get("image") or "")
            containers.append(
                {
                    "image_repository": strip_image_tag_and_digest(image_str),
                    "env": sorted(
                        f"{e['name']}={'secret' if 'valueSource' in e else 'plain'}"
                        for e in cont.get("env", [])
                    ),
                }
            )
        first_img = str((raw_containers[0] if raw_containers else {}).get("image") or "")
        res[svc] = {
            "containers": containers,
            "_revision": short(str(data.get("latestReadyRevision") or "")),
            "_image_digest": first_img.partition("@")[2][:19],
        }
    return res


def section_cloudrun(live: dict[str, dict[str, Any]]) -> tuple[list[str], list[str]]:
    base: dict[str, Any] = (
        json.loads(CLOUDRUN_BASELINE.read_text(encoding="utf-8"))
        if CLOUDRUN_BASELINE.exists()
        else {}
    )
    drift: list[str] = []
    info: list[str] = []
    for svc in RUN_SERVICES:
        base_svc = (base.get("services") or {}).get(svc)
        if base_svc is None:
            drift.append(f"{svc}: not in {CLOUDRUN_BASELINE.name}")
            continue
        live_svc = live[svc]
        if base_svc.get("containers") != live_svc["containers"]:
            drift.extend(
                f"{svc}: containers{p}"
                for p in diff_paths(base_svc.get("containers"), live_svc["containers"])
            )
            base_env = {e for c in base_svc.get("containers", []) for e in c.get("env", [])}
            live_env = {e for c in live_svc["containers"] for e in c.get("env", [])}
            drift.extend(f"{svc}: env `{e}` live only" for e in sorted(live_env - base_env))
            drift.extend(f"{svc}: env `{e}` repo only" for e in sorted(base_env - live_env))
        info.append(
            f"{svc}: revision `{live_svc['_revision']}`, image `{live_svc['_image_digest']}…`"
        )
    return drift, info


def main(argv: list[str] | None = None) -> int:
    first_line = (__doc__ or "Phase 5 drift check").splitlines()[0]
    parser = argparse.ArgumentParser(description=first_line)
    parser.add_argument("--strict", action="store_true", help="exit 1 when drift is found")
    parser.add_argument(
        "--write-cloudrun-baseline",
        action="store_true",
        help="write live Cloud Run image repo + env var names to baseline",
    )
    args = parser.parse_args(argv)

    try:
        _verify_placeholders_configured()
        api = Api()
    except (ValueError, RuntimeError, subprocess.CalledProcessError, OSError) as exc:
        print(f"::error title=Drift setup::{exc}")
        return 2

    if args.write_cloudrun_baseline:
        live_cr = cloudrun_live(api)
        CLOUDRUN_BASELINE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "_note": (
                "Expected Cloud Run shape for drift check: image repository (no tag/digest) "
                "and env var NAMES with kind (plain|secret). Never values. Refresh with "
                "check_drift.py --write-cloudrun-baseline after an approved deploy."
            ),
            "region": RUN_REGION,
            "services": {s: {"containers": v["containers"]} for s, v in live_cr.items()},
        }
        CLOUDRUN_BASELINE.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"wrote {CLOUDRUN_BASELINE.relative_to(ROOT)}")
        return 0

    try:
        raw_profiles = json.loads((ROOT / "profiles.json").read_text(encoding="utf-8"))
        profiles: dict[str, Any] = raw_profiles["environments"]["dev"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"::error file=profiles.json,title=Drift setup::Could not load dev profile: {exc}")
        return 2

    sections: list[tuple[str, list[str], str]] = []
    errors: list[str] = []

    def run_section(title: str, why: str, fn: Callable[[], list[str]]) -> None:
        try:
            sections.append((title, fn(), why))
        except Exception as exc:
            errors.append(f"{title}: {type(exc).__name__}: {exc}")

    live_deps: dict[str, dict[str, Any]] = {}

    def _check_deps() -> list[str]:
        out, deps = section_deployments(api, profiles)
        live_deps.update(deps)
        return out

    run_section(
        "Deployments vs profiles.json",
        "Which version each deployment serves, and its channel settings.",
        _check_deps,
    )

    draft: dict[str, list[dict[str, Any]]] = {}
    try:
        draft = {c: api.list_resources(c) for c in COLLECTIONS}
    except Exception as exc:
        errors.append(f"draft read: {exc}")

    snap_holder: dict[str, Any] = {}
    if live_deps and draft:

        def _check_capture() -> list[str]:
            out, snap, ver = section_capture(api, live_deps, draft)
            snap_holder["snap"] = snap
            snap_holder["ver"] = ver
            return out

        run_section(
            "Serving version vs env-snapshot/",
            "What is live vs the last committed capture.",
            _check_capture,
        )

    if draft and snap_holder.get("snap"):
        run_section(
            "Draft vs serving version",
            "Console edits not yet deployed.",
            lambda: section_draft(draft, snap_holder["snap"]),
        )
    if draft:
        run_section(
            "Draft vs agents/_src + callbacks/",
            "Live draft vs the source sync.py pushes.",
            lambda: section_source(draft),
        )

    cr_info: list[str] = []

    def _check_cr() -> list[str]:
        drift_items, info_items = section_cloudrun(cloudrun_live(api))
        cr_info.extend(info_items)
        return drift_items

    run_section(
        "Cloud Run (RUN_SERVICES) vs drift_cloudrun_baseline.json",
        "Image repository and env var names only.",
        _check_cr,
    )

    total = sum(len(s[1]) for s in sections)
    err_suffix = f", **{len(errors)} read error(s)**" if errors else ""
    lines = [
        "# DEV drift report",
        "",
        f"App `{APP_ID[:8]}` ({LOCATION}). Read-only. Shows *where* things differ, never values.",
        "",
        f"**{total} difference(s)**{err_suffix}.",
    ]
    for title, items, why in sections:
        lines.extend(["", f"## {title} — {len(items) or 'no'} difference(s)", f"_{why}_"])
        lines.extend(f"- {item}" for item in items[:60])
        if len(items) > 60:
            lines.append(f"- … {len(items) - 60} more")
    if cr_info:
        lines.extend(["", "Cloud Run info (not drift):", *[f"- {i}" for i in cr_info]])
    if errors:
        lines.extend(["", "## Read errors", *[f"- {e}" for e in errors]])

    report = "\n".join(lines) + "\n"
    print(report)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with Path(step_summary).open("a", encoding="utf-8") as fh:
            fh.write(report)
    if errors:
        return 2
    return 1 if (args.strict and total) else 0


if __name__ == "__main__":
    sys.exit(main())
