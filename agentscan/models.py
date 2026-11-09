from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "\x1b[90m",
            Severity.LOW: "\x1b[94m",
            Severity.MEDIUM: "\x1b[93m",
            Severity.HIGH: "\x1b[91m",
            Severity.CRITICAL: "\x1b[1;91m",
        }[self]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    path: str
    line: int
    message: str
    snippet: str = ""
    fix: str = ""

    def sort_key(self):
        return (-int(self.severity), self.path, self.line)


@dataclass
class FileTarget:
    path: str
    text: str
    lines: list[str]
    kind: str  # agent-doc | markdown | code | config | env
    frontmatter: str = ""
    frontmatter_start: int = 0  # 1-based line number of first frontmatter line
