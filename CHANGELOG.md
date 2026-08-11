# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffold
- Core data model (Evidence, Verdict, Receipt, Checker)
- Quarantine scanner with 20+ dangerous patterns
- ExecuteProof checker (runs code to verify correctness)
- LLM abstraction layer (OpenAI-compatible, MockLLM)
- Prosecutor and GroundTruth checkers (adversarial LLM pass)
- Receipt storage (JSONL append-only store)
- CLI with subcommands: check, quarantine, execute, receipt, stats
- Evaluation harness with golden dataset
- Test suite (core, quarantine, execute_proof, llm, store)

## [0.1.1] - Unreleased

### Added
- **Sandbox module** — code execution is now a real boundary, not a bare subprocess
  - `DockerSandbox`: no network, read-only filesystem, root dropped, caps dropped,
    memory/CPU/pids limits, hard timeout
  - `SubprocessSandbox`: explicit fallback — `isolated: False`, never labeled as safe
  - `get_sandbox()` factory with `VERDICT_SANDBOX` env override
  - `--sandbox {auto,docker,subprocess}` CLI flag on `check` and `execute`
  - Received evidence now records `sandbox` name and `isolated` flag
- Sandbox test suite (Docker flood, fallback behavior, timeout mapping, command hardening)
- **LLM client hardening**: retry with backoff on transient 5xx/429, graceful provider-error surfacing, configurable timeout via `VERDICT_LLM_TIMEOUT`
- Cloudflare User-Agent bypass (Python-urllib UA was being blocked)
- **Expanded eval corpus**: 88 cases across three datasets (`evals/data/*.json`) with honest metrics — precision, recall, F1, false-positive/false-negative rates
- **`verdict evals` command** with `--prosecutor` (judge reliability) and `--json` output
- **Evaluation-driven detector fixes** (the corpus found the bugs): code-block skip removed (was missing `curl|bash` in fences), setuid regex bug, `rm -rf /`, `~/.aws/` exfil, python exfil, cron-pipe, python3 http.server, symlink false-positive — quarantine went from 48% to 100% recall