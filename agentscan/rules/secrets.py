from __future__ import annotations

import re

from ..models import FileTarget, Finding, Severity

KINDS = frozenset({"agent-doc", "markdown", "code", "config", "env"})

# (rule_name, regex, severity, title, fix, skip_if_example)
_PATTERNS = [
    (
        "aws-access-key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        "AWS access key ID",
        "Rotate the key in IAM; move credentials to environment variables or a secret manager.",
        True,
    ),
    (
        "openai-api-key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
        Severity.CRITICAL,
        "OpenAI API key",
        "Revoke the key at platform.openai.com; load it from the environment instead.",
        False,
    ),
    (
        "anthropic-api-key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
        Severity.CRITICAL,
        "Anthropic API key",
        "Revoke the key; load it from the environment instead.",
        False,
    ),
    (
        "github-token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        Severity.CRITICAL,
        "GitHub personal access token",
        "Revoke the token in GitHub settings; use environment or CI secret injection.",
        False,
    ),
    (
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        Severity.CRITICAL,
        "Google API key",
        "Restrict and rotate the key in Google Cloud Console.",
        False,
    ),
    (
        "slack-token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        Severity.HIGH,
        "Slack token",
        "Revoke the token in the Slack app settings.",
        False,
    ),
    (
        "private-key",
        re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----"),
        Severity.CRITICAL,
        "PEM private key block",
        "Remove the key and rotate it; distribute via a secret manager.",
        False,
    ),
    (
        "service-account",
        re.compile(r'"type"\s*:\s*"service_account"'),
        Severity.CRITICAL,
        "GCP service account JSON",
        "Delete the key from source control and rotate the service account key.",
        False,
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"),
        Severity.HIGH,
        "JWT token",
        "Remove the token; it may still be valid until expiry.",
        False,
    ),
    (
        "hardcoded-credential",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|"
            r"passw(?:or)?d|client[_-]?secret)\b\s*[:=]\s*[\"'][A-Za-z0-9+/=._-]{16,}[\"']"
        ),
        Severity.HIGH,
        "Hardcoded credential",
        "Move the value to an environment variable or secret manager.",
        False,
    ),
]


def _mask(secret: str, line: str) -> str:
    idx = line.find(secret)
    if idx < 0:
        return line.strip()[:140]
    if len(secret) > 12:
        masked = secret[:6] + "…" + secret[-2:]
    else:
        masked = secret[:3] + "…"
    return (line[:idx] + masked).rstrip()[:160]


def check(t: FileTarget) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(t.lines, 1):
        for name, rx, sev, title, fix, skip_example in _PATTERNS:
            for m in rx.finditer(line):
                if skip_example and "EXAMPLE" in line.upper():
                    continue
                out.append(
                    Finding(
                        f"secret/{name}", sev, title, t.path, i,
                        f"{title} present in {t.path}",
                        _mask(m.group(0), line), fix,
                    )
                )
    return out
