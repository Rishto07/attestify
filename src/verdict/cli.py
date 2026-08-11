"""Verdict CLI — the trust layer for AI output.

Usage:
    verdict check <output>       # Run all checkers on output
    verdict check --file <path>  # Run on file contents
    verdict quarantine <output>  # Just the quarantine scanner
    verdict execute <output>     # Just the ExecuteProof checker
    verdict receipt <id>         # Show a specific receipt
    verdict stats                # Show storage statistics

Environment:
    VERDICT_LLM_URL      OpenAI-compatible endpoint
    VERDICT_LLM_KEY      API key
    VERDICT_LLM_MODEL    Model to use for prosecutor (default: gpt-4o-mini)
    VERDICT_DATA_DIR     Where to store receipts (default: ./verdict-data)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .core import CheckContext, Verdict, VerdictValue
from .execute_proof import ExecuteProofChecker
from .llm import get_llm
from .prosecutor import ProsecutorChecker, GroundTruthChecker
from .quarantine import QuarantineChecker
from .sandbox import DockerSandbox, get_sandbox
from .storage import ReceiptStore


# === CHECKER REGISTRY ===

DEFAULT_CHECKERS = [
    QuarantineChecker(),
    ExecuteProofChecker(),
]

ADVANCED_CHECKERS = [
    QuarantineChecker(),
    ExecuteProofChecker(),
    ProsecutorChecker(),
    GroundTruthChecker(),
]


def run_checkers(
    output: str,
    checkers: list,
    ctx: CheckContext,
) -> Verdict:
    """Run all checkers and aggregate their evidence."""
    evidence = []
    for checker in checkers:
        try:
            e = checker.check(output, ctx)
            evidence.append(e)
            # Print individual checker result
            symbol = "[PASS]" if e.conclusion == VerdictValue.PASS else "[FAIL]" if e.conclusion == VerdictValue.FAIL else "[????]"
            print(f"  {symbol} {checker.name}: {e.detail}")
        except Exception as e:
            print(f"  ! {checker.name}: ERROR {e}", file=sys.stderr)

    return Verdict.aggregate(evidence)


def cmd_check(args: argparse.Namespace) -> int:
    """Run the full verification pipeline."""
    # Get output
    if args.file:
        output = Path(args.file).read_text(encoding="utf-8")
    elif args.stdin:
        output = sys.stdin.read()
    else:
        output = args.output
        if not output:
            print("Error: provide output via argument, --file, or --stdin", file=sys.stderr)
            return 1

    # Get LLM if needed
    llm = None
    if args.prosecutor or args.advanced:
        llm = get_llm()

    # Choose sandbox (auto / docker / subprocess) and say what we got
    sandbox = get_sandbox(getattr(args, "sandbox", None))

    # Build context
    ctx = CheckContext(
        timeout=args.timeout,
        llm=llm,
        model=args.model,
        workdir=args.workdir,
        sandbox=sandbox,
    )

    # Select checkers
    if args.quarantine_only:
        checkers = [QuarantineChecker()]
    elif args.execute_only:
        checkers = [ExecuteProofChecker()]
    elif args.prosecutor:
        checkers = [QuarantineChecker(), ExecuteProofChecker(), ProsecutorChecker(llm)]
    elif args.advanced:
        checkers = ADVANCED_CHECKERS
    else:
        checkers = DEFAULT_CHECKERS

    print(f"\n{'='*60}")
    print("Verdict Check")
    print(f"{'='*60}")
    print(f"Checkers: {[c.name for c in checkers]}")
    sandbox_label = "isolated" if isinstance(sandbox, DockerSandbox) else "NOT isolated"
    print(f"Sandbox:  {sandbox.name} ({sandbox_label})")
    if llm:
        print(f"LLM: {ctx.model or 'default'}")
    print()

    # Run
    verdict = run_checkers(output, checkers, ctx)

    print(f"\n{'='*60}")
    print(f"VERDICT: {verdict.value}")
    print(f"Confidence: {verdict.confidence:.2%}")
    print(f"{verdict.summary}")
    print(f"{'='*60}\n")

    # Save receipt if requested
    if args.save_receipt:
        from .core import Receipt

        store = ReceiptStore()
        receipt = Receipt.create(
            output=output,
            verdict_obj=verdict,
            pipeline=",".join(c.name for c in checkers),
            model=ctx.model,
        )
        store.save(receipt)
        print(f"Receipt saved: {receipt.receipt_id}")
        if args.show_receipt:
            print(json.dumps(receipt.to_dict(), indent=2))

    return 0 if verdict.value == VerdictValue.PASS else 1


def cmd_quarantine(args: argparse.Namespace) -> int:
    """Run just the quarantine scanner."""
    if args.file:
        output = Path(args.file).read_text(encoding="utf-8")
    elif args.stdin:
        output = sys.stdin.read()
    else:
        output = args.output or ""

    from .quarantine import scan

    findings = scan(output)

    if not findings:
        print("[PASS] No dangerous patterns detected.")
        return 0

    print(f"[FAIL] Found {len(findings)} finding(s):\n")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.category}")
        print(f"    {f.detail}")
        print(f"    {f.location}")
        print()

    return 2  # 2 = danger found, distinct from normal fail


def cmd_execute(args: argparse.Namespace) -> int:
    """Run just the ExecuteProof checker."""
    if args.file:
        output = Path(args.file).read_text(encoding="utf-8")
    elif args.stdin:
        output = sys.stdin.read()
    else:
        output = args.output or ""

    sandbox = get_sandbox(getattr(args, "sandbox", None))
    ctx = CheckContext(timeout=args.timeout, workdir=args.workdir, sandbox=sandbox)
    checker = ExecuteProofChecker()
    evidence = checker.check(output, ctx)

    sandbox_label = "isolated" if isinstance(sandbox, DockerSandbox) else "NOT isolated"
    print(f"Sandbox: {sandbox.name} ({sandbox_label})")
    symbol = "[PASS]" if evidence.conclusion == VerdictValue.PASS else "[FAIL]"
    print(f"{symbol} execute_proof: {evidence.detail}")
    print(json.dumps(evidence.data, indent=2))

    return 0 if evidence.conclusion == VerdictValue.PASS else 1


def cmd_receipt(args: argparse.Namespace) -> int:
    """Show a specific receipt."""
    store = ReceiptStore()
    receipt = store.load(args.id)

    if receipt is None:
        print(f"Receipt not found: {args.id}", file=sys.stderr)
        return 1

    print(json.dumps(receipt.to_dict(), indent=2))

    # Verify signature if requested
    if args.verify:
        valid = receipt.verify_signature()
        print(f"\nSignature valid: {valid}")
        if not valid:
            return 1

    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    """Show storage statistics."""
    store = ReceiptStore()
    stats = store.stats()

    print("Verdict Storage Statistics")
    print("=" * 40)
    print(f"Total receipts: {stats['total_receipts']}")
    print(f"Files: {stats['files']}")
    print(f"By verdict:")
    for v, count in stats['by_verdict'].items():
        print(f"  {v}: {count}")
    if stats['oldest_file']:
        print(f"Oldest: {stats['oldest_file']}")
        print(f"Newest: {stats['newest_file']}")

    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """Show recent receipts."""
    store = ReceiptStore()
    receipts = store.recent(args.n)

    print(f"Last {args.n} receipts:")
    print("=" * 80)
    for r in receipts:
        print(f"{r.created_at[:19]} | {r.verdict:7} | {r.confidence:.0%} | {r.summary[:50]}")
        print(f"  ID: {r.receipt_id}")

    return 0


def main():
    # Load secrets from a local .env (real environment wins). Called before any
    # parser code so the token is available to every subcommand.
    from .env import load_dotenv

    load_dotenv()

    parser = argparse.ArgumentParser(
        prog="verdict",
        description="The trust layer for AI output. Accept nothing on faith.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # verdict check
    check_parser = subparsers.add_parser("check", help="Run full verification pipeline")
    check_parser.add_argument("output", nargs="?", help="Output to verify")
    check_parser.add_argument("-f", "--file", help="Read output from file")
    check_parser.add_argument("--stdin", action="store_true", help="Read output from stdin")
    check_parser.add_argument("-q", "--quarantine-only", action="store_true", help="Run only quarantine scanner")
    check_parser.add_argument("-e", "--execute-only", action="store_true", help="Run only ExecuteProof")
    check_parser.add_argument("-p", "--prosecutor", action="store_true", help="Include adversarial prosecutor")
    check_parser.add_argument("-a", "--advanced", action="store_true", help="Run all checkers including ground truth")
    check_parser.add_argument("--timeout", type=float, default=10.0, help="Timeout for code execution (seconds)")
    check_parser.add_argument("--model", help="LLM model to use")
    check_parser.add_argument("--workdir", help="Working directory for execution")
    check_parser.add_argument("--sandbox", choices=["auto", "docker", "subprocess"], default=None, help="Code sandbox: docker (isolated), subprocess (NOT isolated), auto (default)")
    check_parser.add_argument("-s", "--save-receipt", action="store_true", default=True, help="Save receipt (default: true)")
    check_parser.add_argument("--show-receipt", action="store_true", help="Show receipt JSON after check")
    check_parser.set_defaults(func=cmd_check)

    # verdict quarantine
    quar_parser = subparsers.add_parser("quarantine", help="Run quarantine scanner only")
    quar_parser.add_argument("output", nargs="?", default="")
    quar_parser.add_argument("-f", "--file", help="Read output from file")
    quar_parser.add_argument("--stdin", action="store_true", help="Read output from stdin")
    quar_parser.set_defaults(func=cmd_quarantine)

    # verdict execute
    exec_parser = subparsers.add_parser("execute", help="Run ExecuteProof only")
    exec_parser.add_argument("output", nargs="?", default="")
    exec_parser.add_argument("-f", "--file", help="Read output from file")
    exec_parser.add_argument("--stdin", action="store_true", help="Read output from stdin")
    exec_parser.add_argument("--timeout", type=float, default=10.0, help="Timeout for code execution")
    exec_parser.add_argument("--workdir", help="Working directory")
    exec_parser.add_argument("--sandbox", choices=["auto", "docker", "subprocess"], default=None, help="Code sandbox: docker (isolated), subprocess (NOT isolated), auto (default)")
    exec_parser.set_defaults(func=cmd_execute)

    # verdict receipt
    receipt_parser = subparsers.add_parser("receipt", help="Show a specific receipt")
    receipt_parser.add_argument("id", help="Receipt ID")
    receipt_parser.add_argument("--verify", action="store_true", help="Verify receipt signature")
    receipt_parser.set_defaults(func=cmd_receipt)

    # verdict stats
    stats_parser = subparsers.add_parser("stats", help="Show storage statistics")
    stats_parser.set_defaults(func=cmd_stats)

    # verdict history
    hist_parser = subparsers.add_parser("history", help="Show recent receipts")
    hist_parser.add_argument("-n", type=int, default=10, help="Number of receipts to show")
    hist_parser.set_defaults(func=cmd_history)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())