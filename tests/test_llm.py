from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentscan import llm
from agentscan.cli import main
from agentscan.llm import LLMError, _extract_json
from agentscan.models import Finding, Severity

FIX = Path(__file__).resolve().parent / "fixtures"

FAKE_CONTENT = (
    "```json\n"
    + json.dumps({
        "explanations": [
            {"rule": "secret/aws-access-key",
             "risk": "A live AWS key would let an attacker act as the account.",
             "recommendation": "Rotate the key in IAM."}
        ],
        "extra_findings": [
            {"severity": "high", "title": "staged exfil",
             "path": "SKILL.md", "line": 9,
             "message": "The doc tells the agent to follow remote instructions.",
             "fix": "Pin the instructions in-repo."}
        ],
    })
    + "\n```"
)

FAKE_BODY = {"choices": [{"message": {"content": FAKE_CONTENT}}]}


def test_extract_json_plain():
    assert _extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_fenced_with_prose():
    assert _extract_json('Here you go: ```json\n{"a": 1}\n``` hope that helps') == {"a": 1}


def test_extract_json_no_json_raises():
    with pytest.raises(LLMError):
        _extract_json("I cannot produce JSON here.")


def test_extract_json_invalid_raises():
    with pytest.raises(LLMError):
        _extract_json("{not json}")


def test_llm_review_request_and_parse(monkeypatch):
    captured = {}

    def fake_post(url, headers, payload, timeout=120.0):
        captured.update(url=url, headers=headers, payload=payload)
        return FAKE_BODY

    monkeypatch.setattr(llm, "_post", fake_post)
    f = Finding("secret/aws-access-key", Severity.CRITICAL, "AWS access key ID",
                "a.py", 1, "AWS key present", "snip", "rotate")
    report = llm.llm_review([f], [("SKILL.md", "# doc\ntext")], "qwen", "sk-test",
                            base_url="http://127.0.0.1:18000/v1")
    assert captured["url"] == "http://127.0.0.1:18000/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer sk-test"
    assert captured["payload"]["model"] == "qwen"
    assert captured["payload"]["messages"][0]["role"] == "system"
    assert "secret/aws-access-key" in captured["payload"]["messages"][1]["content"]
    assert report["explanations"][0]["rule"] == "secret/aws-access-key"
    assert report["extra_findings"][0]["severity"] == "high"


def test_cli_llm_missing_key_warns(monkeypatch, capsys):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    rc = main([str(FIX / "malicious-skill"), "--llm", "--no-color"])
    err = capsys.readouterr().err
    assert "OPENAI_API_KEY" in err
    assert rc == 1  # deterministic findings still drive the exit code


def test_cli_llm_unreachable_is_advisory(monkeypatch, capsys):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:18000/v1")

    def boom(*a, **k):
        raise LLMError("connection refused")

    monkeypatch.setattr(llm, "_post", boom)
    rc = main([str(FIX / "clean-skill"), "--llm", "--no-color"])
    err = capsys.readouterr().err
    assert "LLM review unavailable" in err
    assert rc == 0  # LLM failure must not break a clean scan


def test_cli_llm_fail_flag(monkeypatch, capsys):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:18000/v1")
    monkeypatch.setattr(llm, "_post", lambda *a, **k: FAKE_BODY)
    rc = main([str(FIX / "clean-skill"), "--llm", "--no-color"])
    assert rc == 0  # advisory by default
    rc = main([str(FIX / "clean-skill"), "--llm", "--llm-fail", "--no-color"])
    assert rc == 1  # LLM HIGH extra flips the result


def test_cli_llm_json_output(monkeypatch, capsys):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:18000/v1")
    monkeypatch.setattr(llm, "_post", lambda *a, **k: FAKE_BODY)
    main([str(FIX / "malicious-skill"), "--json", "--llm", "--no-color"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["llm"]["model"] == llm.DEFAULT_MODEL
    assert payload["llm"]["explanations"][0]["rule"] == "secret/aws-access-key"
    assert payload["llm"]["extra_findings"][0]["title"] == "staged exfil"
