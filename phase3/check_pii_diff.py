#!/usr/bin/env python3
"""Phase 3 PII scan: inspect ONLY lines added in a change (git diff BASE...HEAD).

Flags US phone numbers, SSNs, emails, Medicare MBIs, and date-of-birth values.
Known-public values belong in scripts/ci/pii_allowlist.txt; individual false-positive
lines can be excused with an inline comment containing 'pii-allow'.
Findings are emitted as GitHub ::error annotations with masked values.
Standard library only. Exits 1 if any unexcused finding is detected.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

PHONE = re.compile(
    r"(?<![\w.\-])(?:\+?1[\s.\-]?)?(?:\((\d{3})\)\s?|(\d{3})[\s.\-])(\d{3})[\s.\-](\d{4})(?![\w\-])"
)
PHONE_E164 = re.compile(r"(?<![\w.])\+1(\d{10})(?!\d)")
SSN = re.compile(r"(?<![\w\-])(?!000|666|9\d\d)(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})(?![\w\-])")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})\b")
_MBI_LETTER = "[AC-HJKMNP-RT-Y]"  # CMS MBI alphabet excludes S, L, O, I, B, Z
_MBI_ALNUM = "[AC-HJKMNP-RT-Y0-9]"
MBI = re.compile(
    rf"\b[1-9]{_MBI_LETTER}{_MBI_ALNUM}\d-?{_MBI_LETTER}{_MBI_ALNUM}\d-?{_MBI_LETTER}{_MBI_LETTER}\d\d\b"
)
DOB = re.compile(
    r"(?i)\b(?:dob|d\.o\.b\.?|date[\s_\-]*of[\s_\-]*birth|birth[\s_\-]*date|birthdate)\b"
    r"[\"'\s:=]*(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|\d{4}-\d{2}-\d{2})"
)
HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


@dataclass
class Allowlist:
    phones: set[str] = field(default_factory=set)
    email_domains: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    regexes: list[re.Pattern[str]] = field(default_factory=list)


def _esc_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(text: str) -> str:
    return _esc_data(text).replace(":", "%3A").replace(",", "%2C")


def mask(value: str) -> str:
    alnum = re.sub(r"\W", "", value)
    if len(alnum) <= 4:
        return "***"
    return f"{alnum[:2]}{'*' * (len(alnum) - 4)}{alnum[-2:]}"


def load_allowlist(path: Path) -> Allowlist:
    allow = Allowlist()
    if not path.exists():
        return allow
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        kind, val = (part.strip() for part in line.split(":", 1))
        if kind == "phone":
            digits = re.sub(r"\D", "", val)
            if len(digits) >= 10:
                allow.phones.add(digits[-10:])
        elif kind == "regex":
            allow.regexes.append(re.compile(val))
        elif kind == "email-domain":
            allow.email_domains.add(val.lower())
        elif kind == "email":
            allow.emails.add(val.lower())
    return allow


def _is_fictional_phone(digits10: str) -> bool:
    """NANP 555-0100 through 555-0199 are reserved for fictional/example use."""
    return digits10[3:6] == "555" and 100 <= int(digits10[6:]) <= 199


def _skip_phone(digits10: str, allow: Allowlist) -> bool:
    return (
        digits10[0] in "01"
        or digits10[3] in "01"
        or len(set(digits10)) == 1
        or _is_fictional_phone(digits10)
        or digits10 in allow.phones
    )


def scan_line(text: str, allow: Allowlist) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for match in PHONE.finditer(text):
        digits = (match.group(1) or match.group(2)) + match.group(3) + match.group(4)
        if not _skip_phone(digits, allow):
            hits.append(("phone", match.group(0)))
    for match in PHONE_E164.finditer(text):
        if not _skip_phone(match.group(1), allow):
            hits.append(("phone", match.group(0)))
    for match in SSN.finditer(text):
        hits.append(("ssn", match.group(0)))
    for match in EMAIL.finditer(text):
        domain = match.group(1).lower()
        full = match.group(0).lower()
        if full in allow.emails or any(
            domain == allowed_dom or domain.endswith(f".{allowed_dom}")
            for allowed_dom in allow.email_domains
        ):
            continue
        hits.append(("email", match.group(0)))
    for match in MBI.finditer(text):
        hits.append(("medicare-mbi", match.group(0)))
    for match in DOB.finditer(text):
        hits.append(("dob", match.group(1)))
    return [(kind, val) for kind, val in hits if not any(rx.search(val) for rx in allow.regexes)]


def _validate_git_ref(ref: str) -> str:
    if not ref or ref.startswith("-"):
        raise ValueError(f"Invalid git revision reference: {ref!r}")
    return ref


def parse_unified_zero_diff(diff_text: str) -> Iterator[tuple[str, int, str]]:
    """Statefully parse `git -c core.quotePath=false diff --unified=0` output.

    Consumes exact hunk `+count` lines so added content starting with `++ ` (which renders
    as `+++ ...` in unified diff) can never spoof or reset the active file header.
    """
    current_path: str | None = None
    awaiting_plus_header = False
    remaining_adds = 0
    lineno = 0

    lines = diff_text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()

    for raw_line in lines:
        line = raw_line[:-1] if raw_line.endswith("\r") else raw_line
        if remaining_adds > 0:
            if line.startswith("+") and current_path is not None:
                yield current_path, lineno, line[1:]
                lineno += 1
                remaining_adds -= 1
                continue
            if line.startswith(("-", "\\")):
                continue
            raise ValueError(f"Unexpected diff line inside active hunk: {line[:80]!r}")

        if line.startswith("diff --git "):
            current_path = None
            awaiting_plus_header = False
        elif line.startswith("--- "):
            awaiting_plus_header = True
        elif awaiting_plus_header and line.startswith("+++ "):
            awaiting_plus_header = False
            if line == "+++ /dev/null":
                current_path = None
            elif line.startswith("+++ b/"):
                current_path = line[6:].removesuffix("\t")
            else:
                raise ValueError(f"Unparseable diff target header: {line!r}")
        elif line.startswith("@@ "):
            m = HUNK_HEADER.match(line)
            if not m:
                raise ValueError(f"Malformed unified diff hunk header: {line!r}")
            lineno = int(m.group(1))
            remaining_adds = int(m.group(2)) if m.group(2) is not None else 1


def added_lines(base: str, head: str, cwd: Path | None = None) -> Iterator[tuple[str, int, str]]:
    safe_base = _validate_git_ref(base)
    rev_spec = f"{safe_base}...{_validate_git_ref(head)}" if head else safe_base
    out = subprocess.run(
        [
            "git",
            "-c",
            "core.quotePath=false",
            "diff",
            "--no-color",
            "--unified=0",
            "--no-renames",
            "--diff-filter=AMT",
            rev_spec,
            "--",
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
        errors="replace",
    ).stdout
    yield from parse_unified_zero_diff(out)


def main(argv: list[str] | None = None, cwd: Path | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base", required=True, help="base commit/ref (e.g. origin/main)")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--allowlist", default="scripts/ci/pii_allowlist.txt")
    parser.add_argument("--exclude", action="append", default=[], help="regex of paths to skip")
    args = parser.parse_args(argv)

    allowlist_path = (cwd / args.allowlist) if cwd else Path(args.allowlist)
    allow = load_allowlist(allowlist_path)
    skip_patterns = [re.compile(pat) for pat in [*args.exclude, f"{re.escape(args.allowlist)}$"]]

    found = 0
    try:
        for path, lineno, text in added_lines(args.base, args.head, cwd=cwd):
            if "pii-allow" in text or any(rx.search(path) for rx in skip_patterns):
                continue
            for kind, val in scan_line(text, allow):
                found += 1
                msg = (
                    f"Possible {kind} added: {mask(val)}. Redact it, add a published value to "
                    f"{args.allowlist}, or mark the line with 'pii-allow'."
                )
                print(
                    f"::error file={_esc_prop(path)},line={lineno},"
                    f"title={_esc_prop(f'PII ({kind})')}::{_esc_data(msg)}"
                )
    except (subprocess.CalledProcessError, ValueError) as exc:
        print(f"::error title=PII scan error::{_esc_data(str(exc))}")
        return 1

    print(f"PII scan: {found} finding(s) in added lines ({args.base}...{args.head}).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
