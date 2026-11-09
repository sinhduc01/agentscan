from __future__ import annotations

import os
from pathlib import Path

from .models import FileTarget, Finding
from .rules import ALL_RULES

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", "dist", "build", ".idea", ".vscode", ".next",
    "target", ".mypy_cache", ".pytest_cache", "site-packages",
}
SKIP_EXT = {
    ".png", ".gif", ".jpg", ".jpeg", ".webp", ".ico", ".pdf", ".zip",
    ".tar", ".gz", ".whl", ".so", ".pyc", ".woff", ".woff2", ".mp4",
    ".mp3", ".sqlite", ".db", ".bin",
}
AGENT_DOC_NAMES = {
    "agents.md", "claude.md", "codex.md", "clinerules", "skill.md",
    "rules.md", "copilot-instructions.md",
}
CODE_EXT = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".sh", ".bash",
    ".zsh", ".rb", ".go", ".rs", ".java", ".php", ".c", ".cc", ".cpp",
    ".cs", ".kt", ".ps1", ".psm1", ".psd1", ".bat", ".cmd",
}
CONFIG_EXT = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf"}
DOC_EXT = {".md", ".markdown", ".rst", ".txt"}
MAX_BYTES = 1_500_000


def classify(name: str, ext: str) -> str | None:
    """Map a file to a scan kind, or None to skip it."""
    lower = name.lower()
    if ext in SKIP_EXT:
        return None
    if lower in AGENT_DOC_NAMES or lower == ".cursorrules":
        return "agent-doc"
    if ext == ".env" or lower.startswith(".env."):
        return "env"
    if ext in CODE_EXT:
        return "code"
    if ext in CONFIG_EXT:
        return "config"
    if ext in DOC_EXT:
        return "markdown"
    return None


def _frontmatter(lines: list[str]) -> tuple[str, int]:
    """Extract YAML frontmatter from a markdown document.

    Returns (frontmatter_text, first_frontmatter_line_number).
    """
    if not lines or lines[0].strip() != "---":
        return "", 0
    for i in range(1, min(len(lines), 60)):
        if lines[i].strip() == "---":
            return "\n".join(lines[1:i]), 2
    return "", 0


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            yield Path(dirpath) / fn


def _scan(root: Path, collect_docs: bool):
    root = root.resolve()
    findings: list[Finding] = []
    docs: list[tuple[str, str]] = []
    scanned = 0
    for p in iter_files(root):
        kind = classify(p.name, p.suffix.lower())
        if kind is None:
            continue
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if len(raw) > MAX_BYTES:
            continue
        text = raw.decode("utf-8", errors="replace")
        if text.count("\ufffd") > 50:  # binary file
            continue
        lines = text.splitlines()
        fm, fm_start = _frontmatter(lines)
        rel = p.name if root.is_file() else str(p.relative_to(root))
        t = FileTarget(
            path=rel, text=text, lines=lines, kind=kind,
            frontmatter=fm, frontmatter_start=fm_start,
        )
        scanned += 1
        if collect_docs and kind in ("agent-doc", "markdown") and len(docs) < 8:
            docs.append((rel, text[:12_000]))
        for rule in ALL_RULES:
            if kind in rule.KINDS:
                findings.extend(rule.check(t))
    return scanned, findings, docs


def scan(root: Path) -> tuple[int, list[Finding]]:
    """Scan a file or directory. Returns (files_scanned, findings)."""
    scanned, findings, _ = _scan(root, collect_docs=False)
    return scanned, findings


def scan_with_docs(root: Path) -> tuple[int, list[Finding], list[tuple[str, str]]]:
    """Scan and also return instruction-doc texts for LLM review."""
    return _scan(root, collect_docs=True)
