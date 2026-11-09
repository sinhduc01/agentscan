# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-11-10

### Added
- **Windows rule pack** (`windows/*`): `iex (iwr …)` pipe-to-PowerShell,
  `Invoke-Expression`, encoded commands, certutil / mshta / bitsadmin
  downloads, `Set-ExecutionPolicy Bypass`, schtasks and registry-Run
  persistence, broad recursive deletes, `format d:`. Scans `.ps1`,
  `.psm1`, `.psd1`, `.bat`, `.cmd`.
- **LLM deep-scan mode** (opt-in `--llm`): one chat-completion call that
  explains each deterministic finding and flags semantic risks (multi-stage
  injection chains, social engineering, tool-allowlist contradictions).
  Works with any OpenAI-compatible endpoint (`OPENAI_BASE_URL`,
  `AGENTSCAN_LLM_MODEL`). Advisory by default; `--llm-fail` lets LLM
  findings at HIGH+ affect the exit code.
- **GitHub Action** (`action/action.yml`): composite action that installs
  and runs agentscan; inputs `path`, `fail-on`, `version`, `json`.
- **CI workflow**: test suite + action scanning a clean skill fixture on
  every push/PR.
- `--version` flag.

## [0.1.0] - 2026-11-09

### Added
- Initial release: static security scanner for AI agent assets.
- Rule families: `secret/*`, `injection/*` (EN + VN), `dangerous/*`,
  `exfil/*`, `privilege/*`.
- CLI with `--json`, `--fail-on`, `--no-color`; exit code 1 on findings
  at or above the threshold (default: high).
- Fixture-based unit tests for every rule.
