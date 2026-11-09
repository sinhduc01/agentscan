from __future__ import annotations

import re

from ..models import FileTarget, Finding, Severity

KINDS = frozenset({"agent-doc", "markdown", "config"})

# (rule_name, regex, severity, title, fix)
_PHRASES = [
    (
        "inject-ignore-previous",
        re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|preceding|earlier|above)\s+(?:instructions?|prompts?|directions?|rules?|context)"),
        Severity.CRITICAL,
        "Prompt injection: tells the agent to ignore prior instructions",
        "Remove the injected text; audit how this file entered the skill pack.",
    ),
    (
        "inject-disregard",
        re.compile(r"(?i)disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?|rules?)"),
        Severity.CRITICAL,
        "Prompt injection: tells the agent to disregard prior instructions",
        "Remove the injected text; audit how this file entered the skill pack.",
    ),
    (
        "hide-from-user",
        re.compile(r"(?i)(?:do\s+not\s+|don'?t\s+)(?:tell|inform|notify|alert|reveal)\s+(?:the\s+)?(?:user|human|developer)"),
        Severity.HIGH,
        "Instructs the agent to hide behavior from the user",
        "Remove the concealment instruction.",
    ),
    (
        "hide-from-user-2",
        re.compile(r"(?i)without\s+(?:telling|informing|notifying|asking)\s+(?:the\s+)?(?:user|human)"),
        Severity.HIGH,
        "Instructs the agent to act without telling the user",
        "Remove the concealment instruction.",
    ),
    (
        "hide-from-user-3",
        re.compile(r"(?i)(?:hide|conceal)\s+(?:this|it)\s+from\s+(?:the\s+)?(?:user|human)"),
        Severity.HIGH,
        "Instructs the agent to hide something from the user",
        "Remove the concealment instruction.",
    ),
    (
        "never-disclose",
        re.compile(r"(?i)never\s+(?:mention|reveal|disclose|show)\s+(?:this|the\s+(?:instruction|step|action|file))"),
        Severity.HIGH,
        "Instructs the agent never to disclose the instruction",
        "Remove the concealment instruction.",
    ),
    (
        "fetch-follow-url",
        re.compile(r"(?i)(?:read|fetch|get|load)\s+(?:the\s+)?(?:\w+\s+){0,2}(?:instructions?|commands?|prompts?|rules?)\s+at\s+https?://\S+"),
        Severity.CRITICAL,
        "Instruction to fetch remote commands and follow them",
        "Remove the remote-instruction reference; pin behavior in the file itself.",
    ),
    (
        "fetch-and-follow",
        re.compile(r"(?i)(?:read|fetch|get|load)\s+(?:the\s+)?(?:latest\s+|new\s+)?(?:instructions?|commands?|prompts?)\s+and\s+(?:follow|execute|run|do\s+(?:exactly\s+)?what)"),
        Severity.CRITICAL,
        "Instruction to fetch remote commands and follow them",
        "Remove the remote-instruction reference; pin behavior in the file itself.",
    ),
    (
        "visit-and-follow",
        re.compile(r"(?i)(?:visit|go\s+to|open)\s+https?://\S+\s+and\s+(?:follow|do|execute)"),
        Severity.CRITICAL,
        "Instruction to visit a URL and follow its content",
        "Remove the remote-instruction reference.",
    ),
    (
        "vi-ignore-previous",
        re.compile(r"(?i)bỏ\s*qua\s+(?:mọi\s+|tất\s*cả\s+)?(?:các\s+)?(?:lệnh|chỉ\s*dẫn|hướng\s*dẫn|yêu\s*cầu)\s+(?:trước|này)"),
        Severity.CRITICAL,
        "Prompt injection (vi): bỏ qua lệnh trước",
        "Xóa câu lệnh bị tiêm; kiểm tra nguồn file này vào skill pack.",
    ),
    (
        "vi-hide-from-user",
        re.compile(r"(?i)đừng\s+(?:kể|nói|báo|thông\s*báo)\s+cho\s+(?:người\s*dùng|user)"),
        Severity.HIGH,
        "Yêu cầu agent giấu hành vi khỏi người dùng (vi)",
        "Xóa chỉ dẫn che giấu.",
    ),
    (
        "vi-fetch-follow",
        re.compile(r"(?i)(?:đọc|làm\s+theo|xem)\s+(?:lệnh|hướng\s*dẫn|yêu\s*cầu)\s+(?:tại|ở|trong)\s+https?://\S+"),
        Severity.CRITICAL,
        "Yêu cầu đọc lệnh từ URL bên ngoài (vi)",
        "Xóa tham chiếu lệnh từ xa.",
    ),
    (
        "new-instructions",
        re.compile(r"(?i)^\s*new\s+instructions?\s*:"),
        Severity.MEDIUM,
        "'new instructions:' block inside a skill document",
        "Review the block; it overrides documented behavior.",
    ),
]

_HIDDEN = [
    (
        "zero-width",
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]{4,}"),
        Severity.HIGH,
        "Zero-width / invisible characters (possible hidden instructions)",
        "Remove the invisible text; it is not human-readable by design.",
    ),
    (
        "white-text",
        re.compile(r"(?i)<span[^>]*color\s*:\s*(?:white|#fff{3}|transparent)[^>]*>[^<]{8,}"),
        Severity.MEDIUM,
        "White-on-white text (possible hidden instructions)",
        "Remove the hidden span.",
    ),
    (
        "base64-blob",
        re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),
        Severity.MEDIUM,
        "Opaque base64 blob in instruction text",
        "Replace with readable content or remove.",
    ),
    (
        "paste-service",
        re.compile(r"(?i)https?://(?:pastebin\.com|pastec\.de|hastebin\.com|transfer\.sh|ngrok\.[a-z0-9-]+)/[A-Za-z0-9_.-]+"),
        Severity.MEDIUM,
        "External paste/relay service URL in instructions",
        "Pin the referenced content in the repository instead.",
    ),
]


def _html_comment_findings(t: FileTarget) -> list[Finding]:
    out: list[Finding] = []
    for m in re.finditer(r"<!--(.*?)-->", t.text, re.S):
        content = m.group(1)
        for name, rx, sev, title, fix in _PHRASES:
            if rx.search(content):
                start_line = t.text.count("\n", 0, m.start()) + 1
                out.append(
                    Finding(
                        f"injection/{name}-hidden-comment", sev,
                        f"{title} (inside hidden HTML comment)", t.path, start_line,
                        title, "Hidden comment content", fix,
                    )
                )
                break
    return out


def check(t: FileTarget) -> list[Finding]:
    out: list[Finding] = []
    comment_spans = [m.span() for m in re.finditer(r"<!--.*?-->", t.text, re.S)]

    def _in_comment(pos: int) -> bool:
        return any(s <= pos < e for s, e in comment_spans)

    offset = 0
    for i, line in enumerate(t.lines, 1):
        for name, rx, sev, title, fix in _PHRASES:
            for m in rx.finditer(line):
                if _in_comment(offset + m.start()):
                    break  # reported by the hidden-comment pass instead
                out.append(
                    Finding(f"injection/{name}", sev, title, t.path, i, title,
                            line.strip()[:140], fix)
                )
                break  # one finding per phrase per line
        for name, rx, sev, title, fix in _HIDDEN:
            if rx.search(line):
                out.append(
                    Finding(f"injection/{name}", sev, title, t.path, i, title,
                            line.strip()[:140], fix)
                )
        offset += len(line) + 1
    out.extend(_html_comment_findings(t))
    return out
