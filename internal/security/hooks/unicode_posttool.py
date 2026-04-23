#!/usr/bin/env python3
"""Claude Code PostToolUse hook for unicode security scanning.

Intercepts tool results (Read, Bash, WebFetch) and scans for non-rendering
Unicode characters that can encode hidden instructions: steganographic
payloads (tag characters), invisible text (zero-width), Trojan Source
attacks (bidi overrides), and ANSI escape injection.

Critical findings (tag characters with decoded hidden text) block the tool
result. Non-critical findings strip the invisible characters and pass
through the sanitized text.

Protocol: reads JSON from stdin, writes JSON to stdout with modified
tool_result if findings detected.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unicodedata
from datetime import UTC, datetime

FINDINGS_PATH = "/tmp/workspace/.security/findings.jsonl"

# --- Unicode categories to detect ---

_CHECKS: list[tuple[str, str, re.Pattern]] = [
    (
        "tag_char",
        "critical",
        re.compile("[\U000e0000-\U000e007f]+"),
    ),
    (
        "zero_width",
        "high",
        re.compile("[\u200b-\u200d\ufeff\u00ad]+"),
    ),
    (
        "bidi_override",
        "high",
        re.compile("[\u202a-\u202e]+"),
    ),
    (
        "bidi_isolate",
        "high",
        re.compile("[\u2066-\u2069]+"),
    ),
    (
        "invisible_operator",
        "medium",
        re.compile("[\u2060-\u2064]+"),
    ),
    (
        "variation_selector",
        "medium",
        re.compile("[\ufe00-\ufe0f]+"),
    ),
    (
        "ansi_escape",
        "medium",
        re.compile(r"\x1b\[[0-9;]*[a-zA-Z]"),
    ),
    (
        "null_byte",
        "high",
        re.compile("\x00+"),
    ),
]


def log_finding(name: str, severity: str, detail: str, action: str):
    trace_id = os.environ.get("FULLSEND_TRACE_ID", "")
    finding = {
        "trace_id": trace_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "phase": "hook_posttool",
        "scanner": "unicode_posttool",
        "name": name,
        "severity": severity,
        "detail": detail,
        "action": action,
    }
    try:
        with open(FINDINGS_PATH, "a") as f:
            f.write(json.dumps(finding) + "\n")
    except OSError:
        pass


def decode_tag_chars(text: str) -> str:
    """Decode tag characters (U+E0000-U+E007F) to reveal hidden ASCII."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0000 <= ord(c) <= 0xE007F)


def scan_text(text: str) -> tuple[str, list[dict]]:
    findings: list[dict] = []
    result = text

    for name, severity, pattern in _CHECKS:
        matches = pattern.findall(result)
        if not matches:
            continue

        total_chars = sum(len(m) for m in matches)
        detail = f"{total_chars} {name.replace('_', ' ')} character(s) removed"

        if name == "tag_char":
            decoded = decode_tag_chars(result)
            if decoded.strip():
                detail += f" (decoded hidden text: {decoded.strip()})"

        findings.append(
            {
                "name": name,
                "severity": severity,
                "detail": detail,
            }
        )

        result = pattern.sub("", result)

    # NFKC normalization (fullwidth -> ASCII, compatibility decomposition).
    nfkc = unicodedata.normalize("NFKC", result)
    if nfkc != result:
        diff_count = sum(1 for a, b in zip(result, nfkc) if a != b)
        diff_count += abs(len(result) - len(nfkc))
        diff_count = max(diff_count, 1)
        findings.append(
            {
                "name": "fullwidth",
                "severity": "high",
                "detail": f"NFKC normalization applied ({diff_count} characters affected)",
            }
        )
        result = nfkc

    return result, findings


MAX_INPUT_BYTES = 10 * 1024 * 1024  # 10 MB


def main():
    try:
        raw = sys.stdin.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raw = raw[:MAX_INPUT_BYTES]
        if not raw.strip():
            sys.exit(0)
        hook_input = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        sys.exit(0)

    tool_result = hook_input.get("tool_result", "")
    if not tool_result or not isinstance(tool_result, str):
        sys.exit(0)

    try:
        sanitized, findings = scan_text(tool_result)
    except Exception as e:
        log_finding("scan_error", "high", f"Unicode scan failed (passing original): {e}", "warn")
        sys.exit(0)

    if not findings:
        sys.exit(0)

    has_critical = any(f["severity"] == "critical" for f in findings)

    for f in findings:
        action = "block" if f["severity"] == "critical" else "sanitize"
        log_finding(f["name"], f["severity"], f["detail"], action)

    if has_critical:
        json.dump(
            {
                "decision": "block",
                "reason": f"Critical unicode findings: {'; '.join(f['detail'] for f in findings if f['severity'] == 'critical')}",
            },
            sys.stdout,
        )
        sys.exit(1)

    json.dump(
        {
            "tool_result": sanitized,
            "metadata": {
                "unicode_findings": len(findings),
                "categories": [f["name"] for f in findings],
            },
        },
        sys.stdout,
    )

    sys.exit(0)


if __name__ == "__main__":
    main()
