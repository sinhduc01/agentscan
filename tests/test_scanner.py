from __future__ import annotations

from pathlib import Path

from agentscan.models import Severity
from agentscan.scanner import scan

FIX = Path(__file__).resolve().parent / "fixtures"


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_malicious_skill():
    findings = scan(FIX / "malicious-skill")[1]
    ids = _ids(findings)
    assert "secret/aws-access-key" in ids
    assert "injection/inject-ignore-previous" in ids
    assert "injection/fetch-follow-url" in ids
    assert "injection/zero-width" in ids
    assert "injection/paste-service" in ids
    assert "injection/hide-from-user-hidden-comment" in ids
    assert "dangerous/pipe-to-shell" in ids
    assert "dangerous/chmod-world" in ids
    assert "dangerous/rm-rf-broad" in ids
    assert "dangerous/crontab-persist" in ids
    assert "exfil/possible-exfiltration" in ids
    assert "privilege/skill-broad-tools" in ids
    assert Severity.CRITICAL in {f.severity for f in findings}


def test_malicious_mcp():
    findings = scan(FIX / "malicious-mcp")[1]
    ids = _ids(findings)
    assert "exfil/possible-exfiltration" in ids
    assert "exfil/raw-ip-url" in ids


def test_agent_docs():
    findings = scan(FIX / "agent-docs")[1]
    ids = _ids(findings)
    assert "privilege/skip-permissions" in ids
    assert "privilege/no-confirm" in ids
    assert "privilege/no-confirm-vi" in ids


def test_clean_skill_passes():
    scanned, findings = scan(FIX / "clean-skill")
    assert scanned >= 2
    assert findings == []


def test_single_file_scan():
    findings = scan(FIX / "malicious-skill" / "SKILL.md")[1]
    assert "injection/inject-ignore-previous" in _ids(findings)


def test_scan_skips_binary_and_git():
    scanned, _ = scan(FIX / "malicious-skill")
    # SKILL.md + setup.sh + deploy.py = 3 text files
    assert scanned == 3
