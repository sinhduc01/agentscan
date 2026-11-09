from __future__ import annotations

import re

from ..models import FileTarget, Finding, Severity

KINDS = frozenset({"agent-doc", "markdown", "config"})

# (rule_name, regex, severity, title, fix)
_PATTERNS = [
    (
        "skip-permissions",
        re.compile(r"(?i)dangerously[-_ ]?(?:skip[-_ ]?)?permissions|dangerouslyallowbypass|--dangerously-skip"),
        Severity.HIGH,
        "Permission checks disabled for the agent",
        "Run the agent with permission prompts enabled; scope tools per task.",
    ),
    (
        "no-confirm",
        re.compile(r"(?i)(?:never|do\s*not|don'?t)\s+ask\s+(?:for\s+)?(?:user\s+|human\s+)?confirmation|skip\s+(?:all\s+)?confirmations|yolo\s+mode|without\s+(?:any\s+)?confirmation"),
        Severity.MEDIUM,
        "Agent told to act without confirmation",
        "Keep confirmation gates for destructive actions.",
    ),
    (
        "no-confirm-vi",
        re.compile(r"(?i)(?:không|khong|ko)\s+(?:cần\s+lấy\s+|cần\s+|can\s+)?(?:xin\s+)?(?:xác\s*nhận|xin\s*phép|hỏi\s*lại)"),
        Severity.MEDIUM,
        "Yêu cầu agent không cần xác nhận (vi)",
        "Giữ bước xác nhận cho thao tác phá hủy.",
    ),
]

_TOOL_LINE = re.compile(r"(?i)^\s*(?:allowed-tools?|tools?)\s*:\s*(.+)$")
_BROAD = re.compile(r"(?i)bash\s*\(\s*\*\s*\)|\bmcp__\*|\b\*(?![\w-])")


def check(t: FileTarget) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(t.lines, 1):
        for name, rx, sev, title, fix in _PATTERNS:
            if rx.search(line):
                out.append(
                    Finding(f"privilege/{name}", sev, title, t.path, i, title,
                            line.strip()[:140], fix)
                )
    if t.frontmatter:
        for j, fl in enumerate(t.frontmatter.splitlines(), start=t.frontmatter_start):
            m = _TOOL_LINE.match(fl)
            if m and _BROAD.search(m.group(1)):
                out.append(
                    Finding(
                        "privilege/skill-broad-tools", Severity.MEDIUM,
                        f"Skill requests broad tool access: {m.group(1).strip()}",
                        t.path, j,
                        "Unrestricted tool grants widen the blast radius of any prompt injection.",
                        fl.strip(),
                        "List the specific tools the skill actually needs.",
                    )
                )
    return out
