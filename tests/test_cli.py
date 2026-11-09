from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentscan.cli import main

FIX = Path(__file__).resolve().parent / "fixtures"


def test_cli_fails_on_malicious(capsys):
    rc = main([str(FIX / "malicious-skill"), "--no-color"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "CRITICAL" in out
    assert "FAIL" in out


def test_cli_passes_on_clean(capsys):
    rc = main([str(FIX / "clean-skill"), "--no-color"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "PASS" in out


def test_cli_json_output(capsys):
    rc = main([str(FIX / "malicious-skill"), "--json", "--no-color"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert payload["result"] == "fail"
    assert payload["scanned_files"] == 3
    assert all(f["rule"].startswith(("secret", "injection", "dangerous", "exfil", "privilege")) for f in payload["findings"])


def test_cli_fail_on_threshold(capsys):
    # clean at high threshold, but the malicious skill has only CRITICAL/HIGH/MEDIUM
    rc = main([str(FIX / "malicious-skill"), "--fail-on", "critical", "--no-color"])
    assert rc == 1
    rc = main([str(FIX / "clean-skill"), "--fail-on", "info", "--no-color"])
    assert rc == 0


def test_cli_missing_path(capsys):
    with pytest.raises(SystemExit):
        main(["/nonexistent/path/agentscan-test", "--no-color"])
