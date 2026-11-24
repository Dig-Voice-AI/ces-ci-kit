#!/usr/bin/env python3
"""Phase 5 live smoke: confirm the target CES app exists and matches expected structure.

Read-only: executes GET on apps/{id}, /agents, /tools, and /deployments only.
Never creates sessions, conversations, evaluations, or exports. Standard library only.

Token: $CES_ACCESS_TOKEN (from google-github-actions/auth token_format=access_token)
       or --token-cmd "gcloud auth print-access-token" for local checks.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[1]
API = "https://ces.googleapis.com/v1"
ALLOWED = frozenset({"", "/agents", "/tools", "/deployments"})


class AppSource(Protocol):
    def get(self, sub: str) -> dict[str, Any]: ...


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


def esc(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _ensure_allowed_subpath(sub: str) -> None:
    if sub not in ALLOWED:
        raise ValueError(f"Disallowed CES endpoint subpath: {sub!r}")


class Live:
    """Read-only CES REST v1 client restricted to ALLOWED config subpaths (redirects disabled)."""

    def __init__(self, base: str, token: str) -> None:
        if not base.startswith("https://"):
            raise ValueError(f"Refusing non-HTTPS base URL: {base!r}")
        self.base = base
        self.token = token
        self._opener = urllib.request.build_opener(_NoRedirectHandler)

    def get(self, sub: str) -> dict[str, Any]:
        _ensure_allowed_subpath(sub)
        out: dict[str, Any] = {}
        page: str | None = None
        seen_tokens: set[str] = set()
        while True:
            query = f"?{urllib.parse.urlencode({'pageToken': page})}" if page else ""
            url = f"{self.base}{sub}{query}"
            headers = {"Authorization": f"Bearer {self.token}"}
            quota_project = os.environ.get("QUOTA_PROJECT")
            if quota_project:
                headers["x-goog-user-project"] = quota_project
            req = urllib.request.Request(url, headers=headers)  # noqa: S310
            try:
                with self._opener.open(req, timeout=30) as resp:
                    data: dict[str, Any] = json.load(resp)
            except urllib.error.HTTPError as exc:
                raise RuntimeError(f"GET {sub or 'app'} -> HTTP {exc.code}") from None

            for key, val in data.items():
                if isinstance(val, list):
                    out.setdefault(key, []).extend(val)
                elif key != "nextPageToken":
                    out[key] = val
            page = str(data.get("nextPageToken") or "") or None
            if not page or not sub:
                return out
            if page in seen_tokens:
                raise RuntimeError(f"Pagination cycle detected on {sub}")
            seen_tokens.add(page)


class Fixture:
    """Offline fixture reader mirroring Live.get() for deterministic CI self-tests."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def get(self, sub: str) -> dict[str, Any]:
        _ensure_allowed_subpath(sub)
        stem = sub.strip("/") or "app"
        data: dict[str, Any] = json.loads(
            (self.directory / f"{stem}.json").read_text(encoding="utf-8")
        )
        return data


def resource_ids(payload: dict[str, Any], key: str) -> list[str]:
    return [str(item["name"]).rsplit("/", 1)[-1] for item in payload.get(key, [])]


def check(src: AppSource, expect: dict[str, Any]) -> list[str]:
    errs: list[str] = []
    app = src.get("")
    want = f"projects/{expect['project']}/locations/{expect['location']}/apps/{expect['app_id']}"
    if app.get("name") != want:
        errs.append(f"app name {app.get('name')!r} != {want!r}")
    if not str(app.get("rootAgent") or "").endswith(f"/agents/{expect['root_agent']}"):
        errs.append(f"rootAgent is {app.get('rootAgent')!r}, expected agent {expect['root_agent']}")
    name_substr = expect.get("display_name_contains")
    if name_substr and str(name_substr) not in str(app.get("displayName") or ""):
        errs.append(f"displayName missing {name_substr!r}")

    agents = resource_ids(src.get("/agents"), "agents")
    if sorted(agents) != sorted(expect["agents"]):
        errs.append(f"agents {sorted(agents)} != expected {sorted(expect['agents'])}")

    tools = resource_ids(src.get("/tools"), "tools")
    if len(tools) < int(expect["min_tools"]):
        errs.append(f"only {len(tools)} tools, expected >= {expect['min_tools']}")
    missing = [t for t in expect.get("required_tools", []) if t not in tools]
    if missing:
        errs.append(f"required tools missing: {missing}")

    deps = src.get("/deployments").get("deployments", [])
    if len(deps) < int(expect["min_deployments"]):
        errs.append(f"only {len(deps)} deployments, expected >= {expect['min_deployments']}")

    print(f"app={expect['app_id']} agents={len(agents)} tools={len(tools)} deployments={len(deps)}")
    return errs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--expect", type=Path, default=ROOT / ".ci" / "smoke_expect.json")
    parser.add_argument(
        "--offline-fixture", type=Path, help="dir with app/agents/tools/deployments .json"
    )
    parser.add_argument("--token-cmd", help="command printing an access token (local use)")
    args = parser.parse_args(argv)

    expect: dict[str, Any] = json.loads(args.expect.read_text(encoding="utf-8"))
    src: AppSource
    if args.offline_fixture:
        src = Fixture(args.offline_fixture)
    else:
        tok = os.environ.get("CES_ACCESS_TOKEN", "").strip()
        if args.token_cmd:
            tok = subprocess.run(
                shlex.split(args.token_cmd),
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        if not tok:
            print(
                "::error title=Live smoke::no CES_ACCESS_TOKEN "
                "(WIF auth step failed or not configured)"
            )
            return 1
        proj_q = urllib.parse.quote(str(expect["project"]), safe="")
        loc_q = urllib.parse.quote(str(expect["location"]), safe="")
        app_q = urllib.parse.quote(str(expect["app_id"]), safe="")
        base = f"{API}/projects/{proj_q}/locations/{loc_q}/apps/{app_q}"
        src = Live(base, tok)

    try:
        errs = check(src, expect)
    except Exception as exc:
        errs = [f"{type(exc).__name__}: {exc}"]

    for msg in errs:
        print(f"::error title=Live app smoke::{esc(msg)}")
    print("PASS" if not errs else f"FAIL ({len(errs)})")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
