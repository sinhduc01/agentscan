from __future__ import annotations

import re

from ..models import FileTarget, Finding, Severity

KINDS = frozenset({"code"})

_SEND = re.compile(
    r"(?i)\brequests\.(?:post|put)|\bhttpx\.(?:post|put)|"
    r"urllib\.request\.Request\([^)]*data=|\bfetch\([^)]*method\s*:\s*[\"'](?:POST|PUT)[\"']"
)

_SOURCES = [
    (re.compile(r"\bos\.environ\b|\bprocess\.env\b|\bos\.getenv\b"), "environment variables"),
    (re.compile(r"\bopen\s*\([^)]*\b[rw]\b|read_text\(|shutil\.(?:copy|read)|base64\."), "local files / encoded data"),
    (re.compile(r"subprocess\.(?:run|check_output)\s*\([^)]*capture_output"), "command output"),
]

_RAW_IP = re.compile(r"(?i)https?://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?")
_LOCAL_IP = re.compile(r"^(?:127\.|0\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)")
_TLD = re.compile(r"(?i)https?://[^\s\"')]*\.(?:tk|ml|ga|cf|gq|top|xyz|onion)(?:/|[\"')\s]|$)")


def check(t: FileTarget) -> list[Finding]:
    out: list[Finding] = []

    send_lines = [i for i, line in enumerate(t.lines, 1) if _SEND.search(line)]
    if send_lines:
        first = send_lines[0]
        sinks = [label for rx, label in _SOURCES if rx.search(t.text)]
        if sinks:
            out.append(
                Finding(
                    "exfil/possible-exfiltration", Severity.MEDIUM,
                    f"Network send on line {first} in a file that reads: {', '.join(sinks)}",
                    t.path, first,
                    "Verify no sensitive local data leaves the machine in the request body.",
                    t.lines[first - 1].strip()[:140],
                    "Send only explicit, non-sensitive payloads; log what is transmitted.",
                )
            )

    for m in _RAW_IP.finditer(t.text):
        ip = m.group(1)
        if _LOCAL_IP.match(ip):
            continue
        line_no = t.text.count("\n", 0, m.start()) + 1
        out.append(
            Finding(
                "exfil/raw-ip-url", Severity.MEDIUM,
                "URL pointing at a raw IP address",
                t.path, line_no,
                "Raw-IP endpoints are common in exfiltration tooling",
                t.lines[line_no - 1].strip()[:140],
                "Use a named domain you control and can vouch for.",
            )
        )

    m = _TLD.search(t.text)
    if m:
        line_no = t.text.count("\n", 0, m.start()) + 1
        out.append(
            Finding(
                "exfil/suspicious-tld", Severity.LOW,
                "URL on a short-lived / abuse-heavy TLD",
                t.path, line_no,
                "TLDs like .tk/.top/.xyz are frequently abused for data drops",
                t.lines[line_no - 1].strip()[:140],
                "Prefer established domains.",
            )
        )
    return out
