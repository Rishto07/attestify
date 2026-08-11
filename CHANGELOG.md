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