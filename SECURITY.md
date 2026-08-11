# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✓         |

## Reporting a Vulnerability

If you find a security issue, please report it via GitHub Issues with the `security` label. Do NOT open a public issue.

We aim to respond within 48 hours.

## Security Model

### What Verdict Protects Against
- Shell injection in AI output
- File exfiltration attempts
- Persistence attacks (ssh keys, cron, etc)
- Obfuscated malicious code
- Code that doesn't actually work

### What Verdict Does NOT Claim to Protect Against
- Malicious AI models that produce convincing-safe output
- Side-channel attacks
- Operating system-level vulnerabilities
- Physical security

### Sandboxing

ExecuteProof runs code inside a **sandbox with two backends**:

- **Docker (isolated):** container with no network, read-only filesystem, root dropped (`--user nobody`), all Linux capabilities dropped, memory/CPU/pids capped, hard timeout, and `no-new-privileges`. This is the production boundary.
- **Subprocess (fallback):** runs with the same permissions as the user. It is **NOT** a security boundary — it verifies *correctness*, not safety.

Verdict never conflates the two: every result, every receipt, records `isolated: true|false`. A PASS from the subprocess fallback is a PASS about whether the code works, never a claim that it is safe to run. The Quarantine module handles the safety question.

## Verification

Every release is verified by the evaluation harness:

```bash
python -m verdict.evals
```

We publish precision/recall metrics for each checker category.