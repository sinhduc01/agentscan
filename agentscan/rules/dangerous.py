from __future__ import annotations

import re

from ..models import FileTarget, Finding, Severity

KINDS = frozenset({"code", "markdown", "agent-doc"})

# (rule_name, regex, severity, title, fix)
_PATTERNS = [
    (
        "pipe-to-shell",
        re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
        Severity.CRITICAL,
        "Remote script piped directly into a shell",
        "Download the artifact, verify a pinned checksum, then run it.",
    ),
    (
        "base64-execute",
        re.compile(r"(?i)base64\s+(?:-d|--decode)[^\n|]*\|\s*(?:ba)?sh\b"),
        Severity.CRITICAL,
        "Base64-decoded payload piped into a shell",
        "Remove the payload; ship readable, reviewable scripts.",
    ),
    (
        "remote-eval",
        re.compile(r"(?i)\beval\s*\(\s*(?:requests?\.|httpx\.|urllib\.|fetch\()"),
        Severity.CRITICAL,
        "eval() of network-fetched content",
        "Never execute fetched content; pin code in the repository.",
    ),
    (
        "system-remote-fetch",
        re.compile(r"(?i)\b(?:os\.system|subprocess\.(?:run|call|Popen))\s*\([^)]*\b(?:curl|wget)\b"),
        Severity.CRITICAL,
        "Shell command that fetches a remote script",
        "Pin the artifact and verify its checksum before execution.",
    ),
    (
        "no-preserve-root",
        re.compile(r"no-preserve-root"),
        Severity.CRITICAL,
        "rm --no-preserve-root (filesystem destruction)",
        "Remove the flag; it is never safe in agent code.",
    ),
    (
        "rm-rf-broad",
        re.compile(r"\brm\s+(?:-[a-z]*[rR][a-z]*f|[a-z]*f[a-z]*[rR])\s+(?:--\S+\s+)*(?:/|~|\$HOME|~/\*|\*)"),
        Severity.HIGH,
        "Recursive forced delete of a broad path",
        "Scope the delete to an explicit project directory.",
    ),
    (
        "chmod-world",
        re.compile(r"\bchmod\s+(?:-R\s+)?(?:777|666|a\+rwx)\b"),
        Severity.MEDIUM,
        "World-writable permissions",
        "Use 755 for directories, 644 for files.",
    ),
    (
        "ssh-write",
        re.compile(r">>?\s*[\w./~-]*\.ssh(?:/[\w.-]+)?|open\(\s*[\w\"']*(?:id_rsa|authorized_keys|id_ed25519)"),
        Severity.HIGH,
        "Write into SSH keys / authorized_keys",
        "Agent code must not modify SSH credentials.",
    ),
    (
        "crontab-persist",
        re.compile(r"\bcrontab\s+(?:-|~|/|[\"'])"),
        Severity.MEDIUM,
        "Modifies crontab (persistence mechanism)",
        "Remove persistence from skill scripts.",
    ),
]

_EXEC_OPEN = re.compile(r"\bexec\s*\(\s*open\s*\(")
_NETWORK = re.compile(r"(?i)\brequests?\.(?:get|post)|\burllib\.request\b|\bhttpx\.|\bfetch\(")


def check(t: FileTarget) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(t.lines, 1):
        for name, rx, sev, title, fix in _PATTERNS:
            if rx.search(line):
                out.append(
                    Finding(f"dangerous/{name}", sev, title, t.path, i, title,
                            line.strip()[:140], fix)
                )
    m = _EXEC_OPEN.search(t.text)
    if m and _NETWORK.search(t.text):
        line_no = t.text.count("\n", 0, m.start()) + 1
        out.append(
            Finding(
                "dangerous/exec-open-fetched", Severity.MEDIUM,
                "exec() of a local file in a script that also fetches from the network",
                t.path, line_no,
                "Combined exec(open(...)) with network access is a remote-execution pattern",
                t.lines[line_no - 1].strip()[:140],
                "Load code from pinned, reviewed files only.",
            )
        )
    return out
