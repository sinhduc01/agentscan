from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, llm
from .models import Finding, Severity
from .scanner import scan, scan_with_docs

RESET = "\x1b[0m"
_SEV = {s.name.lower(): s for s in Severity}


def _render(findings: list[Finding], scanned: int, root: Path, no_color: bool,
            llm_report: dict | None = None, model: str = "") -> str:
    sev = lambda s: "" if no_color else s.color  # noqa: E731
    out = [f"agentscan {__version__} — {scanned} files scanned in {root}"]
    if not findings:
        out.append("  No findings — PASS")
    else:
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
    if llm_report is not None:
        out.append("")
        out.append(f"  LLM review ({model}):")
        for e in llm_report.get("explanations", []):
            out.append(f"    {e.get('rule', '?')} — risk: {e.get('risk', '')}")
            rec = e.get("recommendation", "")
            if rec:
                out.append(f"    {'':<4}recommendation: {rec}")
        for x in llm_report.get("extra_findings", []):
            sev_name = str(x.get("severity", "?")).upper()
            out.append(
                f"    LLM-{sev_name:<5} {x.get('title', '?')}"
                f"  {x.get('path', '?')}:{x.get('line', 0)}"
            )
            if x.get("message"):
                out.append(f"    {'':<4}{x['message']}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="agentscan",
        description="Static security scanner for AI agent skill packs, "
                    "MCP servers, and agent configs.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("path", nargs="?", default=".",
                    help="file or directory to scan (default: current directory)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="exit 1 when a finding at or above this severity "
                         "is present (default: high)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--llm", action="store_true",
                    help="opt-in LLM deep review: explains findings and flags "
                         "semantic risks (needs OPENAI_API_KEY; OPENAI_BASE_URL "
                         "and AGENTSCAN_LLM_MODEL are honored)")
    ap.add_argument("--llm-model",
                    default=os.environ.get("AGENTSCAN_LLM_MODEL", llm.DEFAULT_MODEL),
                    help="model name for the LLM review (default: %(default)s)")
    ap.add_argument("--llm-fail", action="store_true",
                    help="let LLM extra findings at HIGH or above affect the exit code")
    args = ap.parse_args(argv)
    threshold = Severity[args.fail_on.upper()]

    root = Path(args.path)
    if not root.exists():
        ap.error(f"path not found: {root}")

    llm_report: dict | None = None
    docs: list[tuple[str, str]] = []
    if args.llm:
        scanned, findings, docs = scan_with_docs(root)
    else:
        scanned, findings = scan(root)
    findings.sort(key=Finding.sort_key)

    failed = any(f.severity >= threshold for f in findings)

    if args.llm:
        api_key = os.environ.get("OPENAI_API_KEY", "")
        base_url = os.environ.get("OPENAI_BASE_URL", llm.DEFAULT_BASE_URL)
        if not api_key:
            print("  warning: --llm set but OPENAI_API_KEY is not set; "
                  "skipping LLM review", file=sys.stderr)
        else:
            try:
                llm_report = llm.llm_review(findings, docs, args.llm_model,
                                            api_key, base_url)
            except llm.LLMError as e:
                print(f"  warning: LLM review unavailable: {e}", file=sys.stderr)
            if llm_report and args.llm_fail:
                for x in llm_report.get("extra_findings", []):
                    if _SEV.get(str(x.get("severity", "")).lower(), Severity.INFO) >= Severity.HIGH:
                        failed = True

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
        if llm_report is not None:
            payload["llm"] = {"model": args.llm_model, **llm_report}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(_render(findings, scanned, root, args.no_color,
                      llm_report, args.llm_model))

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
