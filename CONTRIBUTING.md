# Contributing to Verdict

Thank you for your interest in building the trust layer for AI output.

## How to Contribute

### Reporting Bugs
- Use GitHub Issues with the `bug` label
- Include minimal reproduction steps
- Include your environment (OS, Python version, verdict version)

### Suggesting Features
- Use GitHub Issues with the `enhancement` label
- Describe the problem you're solving
- Explain why this belongs in Verdict vs. a separate project

### Adding Checkers

The checker system is designed to be extensible. A checker is any class that:
1. Inherits from `verdict.core.Checker`
2. Implements `check(output, ctx) -> Evidence`

```python
from verdict.core import Checker, CheckContext, Evidence, VerdictValue

class MyChecker(Checker):
    name = "my_checker"
    weight = 1.0

    def check(self, output: str, ctx: CheckContext) -> Evidence:
        # Your logic here
        return Evidence(
            checker=self.name,
            conclusion=VerdictValue.PASS,
            detail="My check passed",
        )
```

### Adding Test Cases

Add test cases to `src/verdict/evals.py` in the `GOLDEN_CASES` list:

```python
{
    "id": "my-001",
    "category": "my_category",
    "description": "What I'm testing",
    "input": "The AI output to test",
    "expected": "PASS",  # or FAIL or UNKNOWN
}
```

## Development Setup

```bash
# Clone the repo
git clone https://github.com/yourfork/verdict.git
cd verdict

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run evaluation
python -m verdict.evals
```

## Code Style

- Follow PEP 8 (enforced by ruff)
- Add type hints where practical
- Keep dependencies to a minimum (stdlib first)
- Write tests for new checkers

## Pull Request Process

1. Fork the repo
2. Create a feature branch
3. Add tests for your changes
4. Ensure `pytest` passes
5. Update documentation if needed
6. Submit a PR with a clear description

## License

By contributing, you agree that your contributions will be licensed under Apache 2.0.