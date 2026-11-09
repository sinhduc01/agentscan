from __future__ import annotations

import re

from ..models import FileTarget, Finding, Severity

KINDS = frozenset({"code", "markdown", "agent-doc"})

# Windows / PowerShell / Batch attack patterns
# (rule_name, regex, severity, title, fix)
_PATTERNS = [
    (
        "ps-pipe-shell",
        re.compile(r"(?i)\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(?:powershell|pwsh|iex|invoke-expression)\b"),
        Severity.CRITICAL,
        "Remote script piped directly into PowerShell",
        "Download the artifact, verify a pinned checksum, then run it.",
    ),
    (
        "certutil-fetch",
        re.compile(r"(?i)\bcertutil\s+(?:-urlcache\s+-split\s+|-decode\b|-verifyflag\b)"),
        Severity.CRITICAL,
        "certutil used to download or decode a payload",
        "certutil is a common LOLBin for fetching payloads; ship plain, reviewable scripts.",
    ),
    (
        "format-drive",
        re.compile(r"(?i)\bformat\s+[a-z]:"),
        Severity.CRITICAL,
        "Formats a disk volume",
        "Never acceptable in agent code; remove.",
    ),
    (
        "ps-encoded-command",
        re.compile(r"(?i)\bpowershell(?:\.exe)?\b[^\n]*\s-(?:enc|encodedcommand)\s+[a-z0-9+/=]{16,}"),
        Severity.HIGH,
        "Encoded PowerShell command (obfuscation)",
        "Decode and pin the real command in the repository.",
    ),
    (
        "invoke-expression",
        re.compile(r"(?i)\binvoke-expression\b|\biex\s*\("),
        Severity.HIGH,
        "Dynamic code execution (Invoke-Expression)",
        "Execute only pinned, reviewed scripts; never dynamic content.",
    ),
    (
        "mshta-exec",
        re.compile(r"(?i)\bmshta(?:\.exe)?\b[^\n]*(?:javascript|vbscript)"),
        Severity.HIGH,
        "Script execution via mshta",
        "mshta is a LOLBin for script execution; remove.",
    ),
    (
        "ps-registry-run",
        re.compile(r"(?i)currentversion\\run\b"),
        Severity.HIGH,
        "Registry Run key (startup persistence)",
        "Agent code must not install startup persistence.",
    ),
    (
        "ps-broad-remove",
        re.compile(r"(?i)\bremove-item\s+(?:-[a-z]+\s+)*c:(?=[\\/\s\"']|$)"),
        Severity.HIGH,
        "Recursive delete targeting the C: drive",
        "Scope deletes to an explicit project directory.",
    ),
    (
        "broad-del",
        re.compile(r"(?i)\bdel(?:ete)?\s+(?:/[a-z]+\s+)+[\"']?c:(?=[\\\"'\s]|$)"),
        Severity.HIGH,
        "Recursive delete targeting the C: drive",
        "Scope deletes to an explicit project directory.",
    ),
    (
        "ps-exec-bypass",
        re.compile(r"(?i)(?:set-executionpolicy|[-]\s*executionpolicy)\s+(?:-executionpolicy\s+)?(?:bypass|unrestricted)"),
        Severity.MEDIUM,
        "PowerShell execution policy weakened",
        "Keep the default policy; never bypass inside skill scripts.",
    ),
    (
        "ps-schtasks-persist",
        re.compile(r"(?i)\bschtasks\s+(?:\.exe\s+)?/(?:create|add)\b"),
        Severity.MEDIUM,
        "Scheduled task creation (persistence)",
        "Remove persistence from skill scripts.",
    ),
    (
        "bitsadmin-fetch",
        re.compile(r"(?i)\bbitsadmin\s+(?:\.exe\s+)?/(?:transfer|start|add-file)\b"),
        Severity.MEDIUM,
        "BITS transfer (background download primitive)",
        "Use a pinned, verified artifact instead.",
    ),
]

_WEBCLIENT = re.compile(r"(?i)system\.net\.webclient|new-object\s+webclient")
_DOWNLOAD = re.compile(r"(?i)\bdownload(?:string|data|file)\s*\(")



def check(t: FileTarget) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(t.lines, 1):
        for name, rx, sev, title, fix in _PATTERNS:
            if rx.search(line):
                out.append(
                    Finding(f"windows/{name}", sev, title, t.path, i, title,
                            line.strip()[:140], fix)
                )
    if _WEBCLIENT.search(t.text):
        for i, line in enumerate(t.lines, 1):
            if _DOWNLOAD.search(line):
                out.append(
                    Finding(
                        "windows/webclient-download", Severity.HIGH,
                        "Raw network download via .NET WebClient",
                        t.path, i,
                        "Raw network download via .NET WebClient",
                        line.strip()[:140],
                        "Use a pinned, verified artifact instead of an inline download.",
                    )
                )
                break
    return out
