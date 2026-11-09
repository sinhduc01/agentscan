from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .models import Finding, Severity
from .scanner import scan

RESET = "\x1b[0m"


def _render(findings: list[Finding], scanned: int, root: Path, no_color: bool) -> str:
    sev = lambda s: "" if no_color else s.color  # noqa: E731
    out = [f"agentscan {__version__} — {scanned} files scanned in {root}"]
    if not findings:
        out.append("  No findings — PASS")
        return "\n".join(out)
    for f in findings:
        out.append(
            f"  {sev(f.severity)}{f.severity.name:<8}{RESET}  "
            f"{f.rule_id:<36} {f.path}:{f.line}"
        )
        out.append(f"  {'':<8}  {f.title}")
        if f.snippet:
            out.append(f"  {'':<8}  > {f.snippet[:140]}")
        if f.fix:
            out.append(f"  {'':<8}  fix: {f.fix}")
        out.append("")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.name] = counts.get(f.severity.name, 0) + 1
    summary = ", ".join(
        f"{n} {k.lower()}" for k, n in sorted(counts.items(), key=lambda kv: -Severity[kv[0]])
    )
    out.append(f"{len(findings)} findings ({summary}) — FAIL")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="agentscan",
        description="Static security scanner for AI agent skill packs, "
                    "MCP servers, and agent configs.",
    )
    ap.add_argument("path", nargs="?", default=".",
                    help="file or directory to scan (default: current directory)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="exit 1 when a finding at or above this severity "
                         "is present (default: high)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)
    threshold = Severity[args.fail_on.upper()]

    root = Path(args.path)
    if not root.exists():
        ap.error(f"path not found: {root}")

    scanned, findings = scan(root)
    findings.sort(key=Finding.sort_key)

    failed = any(f.severity >= threshold for f in findings)

    if args.json:
        payload = {
            "scanned_files": scanned,
            "result": "fail" if failed else "pass",
            "findings": [
                {
                    "rule": f.rule_id,
                    "severity": f.severity.name,
                    "title": f.title,
                    "path": f.path,
                    "line": f.line,
                    "message": f.message,
                    "fix": f.fix,
                }
                for f in findings
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(_render(findings, scanned, root, args.no_color))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
