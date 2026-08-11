# Verdict Roadmap

## v0.1.0 — MVP (Current)

- [x] Quarantine scanner (static analysis)
- [x] ExecuteProof checker (run code to verify)
- [x] LLM abstraction (OpenAI-compatible)
- [x] Prosecutor (adversarial checking)
- [x] Receipt storage (JSONL)
- [x] CLI (check, quarantine, execute, receipt, stats)
- [x] Evaluation harness

## v0.2.0 — Expanded Detection

- [ ] More quarantine patterns:
  - [ ] AWS credentials detection
  - [ ] GitHub token patterns
  - [ ] SQL injection in generated queries
  - [ ] Path traversal in file operations
- [ ] Improved code extraction (handle more languages)
- [ ] Better false positive handling

## v0.3.0 — Sandboxing

- [x] Docker-based ExecuteProof sandbox (no network, read-only FS, non-root, caps dropped)
- [x] Network isolation for code execution
- [x] Filesystem restrictions (read-only mount)
- [x] Resource limits (CPU 0.5, memory 128m, pids 32)
- [x] Hard timeout via container `timeout` + outer safety net
- [x] Honest fallback to subprocess with `isolated: false` recorded in receipts
- [ ] Configurable resource limits via env vars

## v0.4.0 — Integrations

- [ ] Claude Code integration
- [ ] VS Code extension
- [ ] GitHub Action
- [ ] GitLab CI template
- [ ] Pre-commit hook

## v0.5.0 — Community

- [ ] Plugin registry
- [ ] Checker marketplace (in docs)
- [ ] Contributor recognition
- [ ] Regular evaluation benchmarks

## Future Considerations

- ZK proofs for receipts (verifiable without storing full evidence)
- Distributed verdict verification (multiple independent checkers)
- Custom checker DSL for domain-specific verification