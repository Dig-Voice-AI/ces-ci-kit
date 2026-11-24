#!/usr/bin/env python3
"""Extract text of added/modified .docx/.xlsx/.pptx files into OUT_DIR for secret/PII scanning.

Binary Office archives are skipped by line-oriented scanners such as gitleaks. This helper
unpacks OpenXML entries in memory, joins adjacent text runs (<w:r>, <a:r>) so split tokens
remain contiguous, enforces actual streamed decompression limits, and writes collision-free
UTF-8 .txt mirrors. Fails closed (exit 1) if any archive is unreadable or exceeds size bounds.
Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import io
import re
import subprocess
import sys
import zipfile
from pathlib import Path

OFFICE_EXT = (".docx", ".xlsx", ".pptx")
MAX_XML_ENTRY_BYTES = 16 * 1024 * 1024  # 16 MiB per XML member
MAX_ARCHIVE_XML_BYTES = 64 * 1024 * 1024  # 64 MiB total per Office archive

BREAK = re.compile(r"</(?:w:p|a:p|w:tc|w:tr|c|row|si)>|<(?:w:br|w:cr|a:br|w:tab)\b[^>]*/?>")
TAG = re.compile(r"<[^>]+>")


def _esc_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(text: str) -> str:
    return _esc_data(text).replace(":", "%3A").replace(",", "%2C")


def xml_to_text(xml: str) -> str:
    return html.unescape(TAG.sub("", BREAK.sub("\n", xml)))


def _validate_git_ref(ref: str) -> str:
    if not ref or ref.startswith("-"):
        raise ValueError(f"Invalid git revision reference: {ref!r}")
    return ref


def safe_output_filename(rel_file: str) -> str:
    """Build a collision-free, length-bounded filename (< 200 chars) for any repo path."""
    digest = hashlib.sha256(rel_file.encode("utf-8")).hexdigest()[:16]
    leaf = re.sub(r"[^A-Za-z0-9._-]", "_", Path(rel_file).name)[:120]
    return f"{digest}_{leaf}.txt"


def extract_archive_bytes(blob: bytes) -> str:
    chunks: list[str] = []
    total_bytes = 0
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".xml"):
                continue
            if info.file_size > MAX_XML_ENTRY_BYTES:
                raise ValueError(
                    f"XML member {info.filename!r} exceeds {MAX_XML_ENTRY_BYTES} bytes"
                )
            with zf.open(info) as member:
                data = member.read(MAX_XML_ENTRY_BYTES + 1)
            if len(data) > MAX_XML_ENTRY_BYTES:
                raise ValueError(
                    f"Decompressed {info.filename!r} exceeds {MAX_XML_ENTRY_BYTES} bytes"
                )
            total_bytes += len(data)
            if total_bytes > MAX_ARCHIVE_XML_BYTES:
                raise ValueError(f"Total XML payload exceeds {MAX_ARCHIVE_XML_BYTES} bytes")
            chunks.append(xml_to_text(data.decode("utf-8", "replace")))
    joined = "\n".join(chunks)
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n", joined))


def changed_office_files(base: str, head: str, cwd: Path | None = None) -> list[str]:
    rev_spec = f"{_validate_git_ref(base)}...{_validate_git_ref(head)}"
    out = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", "--diff-filter=AMT", rev_spec, "--"],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [f for f in out.split("\0") if f and f.lower().endswith(OFFICE_EXT)]


def main(argv: list[str] | None = None, cwd: Path | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("base", help="base commit/ref (e.g. origin/main)")
    parser.add_argument("head", help="head commit/ref (e.g. HEAD)")
    parser.add_argument("out_dir", help="folder to write the extracted .txt files into")
    parser.add_argument(
        "--allow-unreadable",
        action="store_true",
        help="downgrade unreadable/corrupt archive errors to warnings instead of failing",
    )
    args = parser.parse_args(argv)

    safe_head = _validate_git_ref(args.head)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    extracted_count = 0
    failures = 0
    for rel_file in changed_office_files(args.base, safe_head, cwd=cwd):
        try:
            blob = subprocess.run(
                ["git", "show", f"{safe_head}:{rel_file}"],
                cwd=cwd,
                capture_output=True,
                check=True,
            ).stdout
            text = extract_archive_bytes(blob)
            (out_dir / safe_output_filename(rel_file)).write_text(text, encoding="utf-8")
            extracted_count += 1
        except (subprocess.CalledProcessError, zipfile.BadZipFile, ValueError, OSError) as exc:
            level = "warning" if args.allow_unreadable else "error"
            print(
                f"::{level} file={_esc_prop(rel_file)},title=Office text extract::"
                f"could not extract office file: {_esc_data(str(exc))}"
            )
            if not args.allow_unreadable:
                failures += 1

    print(f"extracted text from {extracted_count} office file(s) ({failures} failed)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
