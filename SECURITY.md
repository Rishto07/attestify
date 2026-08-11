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

ExecuteProof runs code in a subprocess with the same permissions as the user. It is NOT a security sandbox — it verifies *correctness*, not safety. The Quarantine module handles the safety question.

## Verification

Every release is verified by the evaluation harness:

```bash
python -m verdict.evals
```

We publish precision/recall metrics for each checker category.