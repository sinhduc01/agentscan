<p align="center">
  <img src="assets/demo.gif" alt="agentscan demo" width="880">
</p>

# agentscan

**Snyk for AI agents.** A static security scanner for AI agent assets: skill
packs (Claude Code / Codex / Cursor), MCP server code, and agent instruction
docs (`AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.mcp.json`, `.env`) —
including Windows skill scripts (`.ps1` / `.bat`).

Everyone is now installing skills into their agents. A skill is third-party
code *and* instructions. A malicious one ships prompt injection, hardcoded
keys, `curl | sh`, and exfiltration to a raw IP — and your agent runs it with
your permissions.

agentscan catches that **before** the skill is loaded: fast, offline,
deterministic rules — zero dependencies — and every rule is unit-tested
against a fixture corpus. An optional LLM pass adds semantic depth
(§ LLM deep-scan).

## What it detects

| Family | Severity | Examples |
|---|---|---|
| `secret/*` | CRITICAL | AWS access keys, OpenAI / Anthropic / GitHub / Google / Slack / ServiceNow tokens, PEM private keys, GCP service-account JSON, JWTs |
| `injection/*` | CRITICAL / HIGH | "ignore all previous instructions", fetch-and-follow remote commands (English **and Vietnamese**), zero-width / invisible text, hidden HTML comments, white-on-white spans, base64 blobs, pastebin / ngrok URLs |
| `dangerous/*` | CRITICAL | `curl \| sh`, base64-decode-then-execute, `eval` of network-fetched content, `rm -rf ~` / `--no-preserve-root`, `chmod 777`, crontab persistence |
| `windows/*` | CRITICAL / HIGH / MEDIUM | `iex (iwr …)`, `Invoke-Expression`, encoded commands (`-enc`), certutil / mshta / bitsadmin downloads, `Set-ExecutionPolicy Bypass`, schtasks / registry-Run persistence, `format d:` |
| `exfil/*` | MEDIUM | network sends in files that read env vars / local files, raw-IP URLs, abuse-prone TLDs (`.top` / `.xyz` / …) |
| `privilege/*` | HIGH / MEDIUM | `--dangerously-skip-permissions` in agent docs, "never ask for confirmation" (EN + VN), `allowed-tools: Bash(*)` in SKILL.md frontmatter |

The rule set is deliberately bilingual (EN/VN) and aimed at the
agentic-skill attack surface, not generic secret scanning.

## Install

```bash
pip install git+https://github.com/sinhduc01/agentscan.git
```

Python 3.10+. No other dependencies.

## Usage

```bash
agentscan ./path/to/skill-pack   # human-readable table
agentscan . --json               # machine-readable, for CI
agentscan . --fail-on medium     # exit 1 on >= medium (default: high)
```

Exit code `1` when a finding at or above the threshold is found, so it plugs
directly into CI, pre-install hooks, or a skill registry gate:

```yaml
- name: Scan agent assets
  run: agentscan skills/ .mcp.json AGENTS.md --fail-on medium
```

Example finding:

```
  CRITICAL  secret/aws-access-key              scripts/deploy.py:4
            AWS access key ID
            > AWS_KEY = "AKIAQ7…01
            fix: Rotate the key in IAM; move credentials to environment
                 variables or a secret manager.
```

## LLM deep-scan (opt-in)

The deterministic core is offline and free by design. `--llm` adds an
advisory second pass that (1) explains *why* each finding is dangerous and
(2) flags semantic risks patterns can't see — multi-stage injection chains,
social engineering, instructions that weaken safety controls:

```bash
export OPENAI_API_KEY=…            # any OpenAI-compatible endpoint
export OPENAI_BASE_URL=http://…    # optional — self-hosted vLLM works
export AGENTSCAN_LLM_MODEL=qwen    # optional — default gpt-4o-mini

agentscan ./skill --llm --json
```

- LLM results are **advisory by default**: the exit code is still driven
  only by deterministic findings. Add `--llm-fail` to let LLM findings at
  HIGH or above fail the scan.
- A missing API key or unreachable endpoint prints a warning and never
  breaks the scan.
- One chat-completion call: the scanner findings plus up to 8 instruction
  documents (12 KB each) are sent to the model; the reply is strict JSON.
- LLM severity labels are non-deterministic across runs — treat `--llm-fail`
  as a review signal, not a hard gate.

## GitHub Action

```yaml
- uses: sinhduc01/agentscan@main   # composite action, installs the tool itself
  with:
    path: skills/
    fail-on: high
    # version: 0.1.0   # pin a PyPI release instead of git@main
    # json: true       # machine-readable output
```

The repo's own CI runs the test suite and scans a clean skill fixture with
the action on every push/PR.

## Why deterministic rules first?

- **Testable**: every rule has a fixture; the suite runs in 0.1 s.
- **Offline & free**: a pre-install security gate that needs an API key or a
  network call is not a gate.
- **Reproducible**: same input, same findings, no model drift.

The LLM pass is therefore opt-in and advisory — it improves triage, it does
not change what "safe" means.

## Limitations (read before relying on this)

- Static analysis: obfuscated payloads (decode → exec in two stages across
  files) and purely semantic malice are out of scope for the deterministic
  core — the LLM pass narrows, but does not close, that gap.
- Heuristics produce false positives: a legitimate telemetry POST that reads
  an env var will be flagged `exfil/possible-exfiltration`.
- This is a first-pass filter, not a substitute for reviewing a skill's code.

## Development

```bash
pip install -e .
pytest
```

Layout: `agentscan/rules/` holds one module per rule family
(`secrets`, `injection`, `dangerous`, `exfil`, `privilege`, `windows`);
adding a rule is one tuple in a module's `_PATTERNS` list plus a fixture
line in `tests/fixtures/`. `agentscan/llm.py` holds the advisory LLM pass.

## Roadmap

- pre-commit hook
- more targets: Rust/Go MCP servers, `.mcp.json` tool-grant analysis
- ignore/allowlist file for repository-wide scans

## License

MIT — see [LICENSE](LICENSE).
