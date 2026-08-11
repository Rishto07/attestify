"""Quarantine: static scanner for dangerous patterns in AI output.

This module does NOT execute code. It inspects text and reports what it *would*
do if executed. The goal is to be the "x-ray" before the "surgery" — show the
user what's hiding inside the AI's output, with proof.

The scanner looks for four categories of danger:

1. **Shell injection** — curl | bash, | sh, && with commands
2. **File exfiltration** — uploads, catting sensitive files to network
3. **Persistence** —写入 ssh keys, cron, startup items, .bashrc
4. **Obfuscation** — base64, hex encoding, unusual escaping

Every detector returns a Finding with severity, the exact match location,
and a human-readable explanation. The CLI aggregates them into a verdict.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Optional

from .core import Checker, CheckContext, Evidence, VerdictValue


class Severity(Enum):
    """How bad is what we found."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """One dangerous thing we found in the output."""

    severity: Severity
    category: str
    pattern: str
    location: str  # e.g. "line 3, chars 12-45"
    detail: str
    data: dict[str, Any]


# === DETECTORS ===

# Shell injection: curl|bash, |sh, && with remote URLs
_SHELL_INJECTION_PATTERNS = [
    (r"\bcurl\b[^\n]*\|\s*(?:bash|sh|zsh)\b", "curl-pipe", Severity.CRITICAL),
    (r"\bwget\b[^\n]*\|\s*(?:bash|sh|zsh)\b", "wget-pipe", Severity.CRITICAL),
    (r"\bfetch\b[^\n]*\|\s*(?:bash|sh|zsh)\b", "fetch-pipe", Severity.CRITICAL),
    (r"\|\s*(?:bash|sh|zsh)\s+-\s*[c]", "pipe-to-shell", Severity.HIGH),
    # Writing to system dirs. Deliberately EXCLUDES /dev/null, /dev/stdout,
    # /dev/stderr, /dev/fd — discarding output is ubiquitous and benign.
    # /dev/tcp/... is a bash exfil vector, kept as its own critical rule.
    (r">\s*/(?:proc/|sys/|etc/|root/)", "write-system-path", Severity.CRITICAL),
    (r">\s*/dev/tcp/", "dev-tcp-exfil", Severity.CRITICAL),
    (r"\$\([^)]+\)\s*\|\s*(?:bash|sh)", "command-subst-pipe", Severity.HIGH),
    (r"`[^`]+`\s*\|\s*(?:bash|sh)", "backtick-pipe", Severity.HIGH),
    (r"\brm\s+-[r]+f?\s+/(?:\s|$)", "destructive-rm", Severity.CRITICAL),
    (r"\|\s*crontab\s*-", "cron-inject", Severity.CRITICAL),
]

# Exfiltration: reading sensitive files and sending them out
_EXFIL_PATTERNS = [
    (r"cat\s+(?:~/.ssh/|/etc/passwd|/etc/shadow|/root/.aws/|~/.aws/)", "read-sensitive", Severity.CRITICAL),
    (r"tar\s+[cz].*\s+(?:/home/|/root/|/etc/|~/.aws/)", "archive-sensitive", Severity.HIGH),
    (r"zip\s+.*(?:/home/|/root/|/etc/|~/.aws/)", "compress-sensitive", Severity.HIGH),
    (r"(?:curl|wget|fetch)\s+.*(?:&&|,)\s*(?:cat|base64)\s+", "exfil-via-network", Severity.CRITICAL),
    (r"\bnc\s+-(?:e|i|exec)\s+\S+", "netcat-reverse", Severity.CRITICAL),
    (r"(?:python3?|perl|ruby)\s+-m\s+http\.server.*(?:\s+&|\s+0\.0\.0\.0)", "http-server-expose", Severity.HIGH),
    (r"nc\s+-l\s+-p\s+\d+\s*(?:-e|/|)\s*(?:/bin/|bash)", "netcat-listen", Severity.CRITICAL),
    # python one-liner that both opens a network connection AND reads a file:
    # the classic exfil shape (socket.connect + open(...).read()).
    (r"python3?\s+-c\s+['\"][^'\"]*(?:socket\.|urllib\.|http\.).*?(?:open\(|read\()", "python-exfil", Severity.CRITICAL),
]

# Persistence: staying on the machine after reboot
_PERSISTENCE_PATTERNS = [
    (r"(?:echo|cat)\s+.*>>\s*(?:~/.ssh/authorized_keys|\.ssh/authorized_keys)", "ssh-key-write", Severity.CRITICAL),
    (r"(?:echo|cat)\s+.*>>\s*~/.bashrc", "bashrc-persistence", Severity.HIGH),
    (r"(?:echo|cat)\s+.*>>\s*~/.profile", "profile-persistence", Severity.HIGH),
    (r"crontab\s+-r", "cron-remove", Severity.HIGH),
    (r"crontab\s+<<", "cron-inject", Severity.HIGH),
    (r"(?:systemctl|service)\s+(?:enable|start)\s+\S+", "service-persistence", Severity.MEDIUM),
    # Symlink hijack: the DESTINATION lives in a system bin dir, e.g.
    # `ln -s /tmp/evil /usr/bin/x`. A harmless `ln -s /usr/bin /tmp/evil`
    # (source in system dir) must NOT match.
    (r"ln\s+-[sT]\s+[^\s]+\s+(?:/usr/local/bin|/usr/bin|/bin|/sbin)", "symlink-hijack", Severity.MEDIUM),
    # setuid bit: leading octal digit 4 or 6 (setuid/setgid) then rwx bits,
    # e.g. 4755, 6755. `chmod 755` and `chmod 777` must NOT match.
    (r"chmod\s+[46][0-7]{3}\s+(?:/usr/|/bin/|/sbin/)", "setuid-root", Severity.CRITICAL),
    (r"chown\s+root:root\s+.*", "chown-root", Severity.HIGH),
]

# Obfuscation: hiding what you're doing
_OBFUSCATION_PATTERNS = [
    (r"base64\s+-d\s+<<<\s*['\"][A-Za-z0-9+/=]{8,}", "base64-decode-exec", Severity.HIGH),
    (r"echo\s+['\"][A-Za-z0-9+/=]{20,}['\"]\s*\|\s*base64\s+-d", "base64-pipe-exec", Severity.HIGH),
    # python -c "..." with eval() or exec() or compile() — arbitrary code exec
    (r"python3?\s+-c\s+['\"][^'\"]*(?:eval|exec)\s*\(", "python-eval-injection", Severity.HIGH),
    (r"perl\s+-e\s+['\"][^'\"]*eval\s*(?:\(|\"|')", "perl-eval-injection", Severity.HIGH),
    (r"ruby\s+-e\s+['\"][^'\"]*eval\s*(?:\(|\"|')", "ruby-eval-injection", Severity.HIGH),
    (r"sh\s+-c\s+['\"][^'\"]*\$\(", "sh-eval-subst", Severity.HIGH),
    (r"\\x[0-9a-fA-F]{2}", "hex-escape", Severity.LOW),
    (r"\\0[0-9]{2,3}", "octal-escape", Severity.LOW),
]


def _build_regex(pat: str) -> re.Pattern:
    return re.compile(pat, re.MULTILINE | re.IGNORECASE)


def _find_all(text: str, detectors: list[tuple[str, str, Severity]]) -> Iterable[Finding]:
    """Run all detectors against text and yield findings."""
    lines = text.splitlines()
    for detector_pattern, category, severity in detectors:
        regex = _build_regex(detector_pattern)
        for match in regex.finditer(text):
            # Find line number
            line_num = text[:match.start()].count("\n") + 1
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.start())
            if line_end == -1:
                line_end = len(text)
            line_content = lines[line_num - 1] if line_num <= len(lines) else ""
            # show a snippet
            snippet = line_content.strip()[:60]
            location = f"line {line_num}, chars {match.start() - line_start}-{match.end() - line_start}"

            # NOTE: we deliberately do NOT skip matches inside fenced code blocks.
            # AI delivers dangerous commands inside ``` fences more often than
            # anywhere else — that's the primary attack surface. Skipping code
            # blocks would skip exactly the command the user is about to run.
            yield Finding(
                severity=severity,
                category=category,
                pattern=detector_pattern,
                location=location,
                detail=f"[{severity.value}] {category}: found `{snippet}`",
                data={"match": match.group(0)[:100], "category": category},
            )


def scan(text: str) -> list[Finding]:
    """Run the full quarantine scan and return all findings."""
    findings = []
    findings.extend(_find_all(text, _SHELL_INJECTION_PATTERNS))
    findings.extend(_find_all(text, _EXFIL_PATTERNS))
    findings.extend(_find_all(text, _PERSISTENCE_PATTERNS))
    findings.extend(_find_all(text, _OBFUSCATION_PATTERNS))

    # Sort by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    findings.sort(key=lambda f: (severity_order[f.severity], f.location))
    return findings


class QuarantineChecker(Checker):
    """The checker that runs the quarantine scanner."""

    name = "quarantine"
    weight = 1.5  # quarantine findings are serious

    def check(self, output: str, ctx: CheckContext) -> Evidence:
        findings = scan(output)

        if not findings:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.PASS,
                detail="No dangerous patterns detected.",
                data={"findings": []},
                weight=self.weight,
            )

        # Categorize
        critical = [f for f in findings if f.severity is Severity.CRITICAL]
        high = [f for f in findings if f.severity is Severity.HIGH]
        medium = [f for f in findings if f.severity is Severity.MEDIUM]

        if critical:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.FAIL,
                detail=f"BLOCKED — {len(critical)} critical, {len(high)} high, {len(medium)} medium findings",
                data={"findings": [asdict(f) for f in findings]},
                weight=self.weight,
            )

        if high:
            return Evidence(
                checker=self.name,
                conclusion=VerdictValue.FAIL,
                detail=f"Blocked — {len(high)} high, {len(medium)} medium findings",
                data={"findings": [asdict(f) for f in findings]},
                weight=self.weight,
            )

        return Evidence(
            checker=self.name,
            conclusion=VerdictValue.UNKNOWN,
            detail=f"Caution — {len(medium)} medium, {len(findings) - len(critical) - len(high) - len(medium)} low/info findings",
            data={"findings": [asdict(f) for f in findings]},
            weight=self.weight * 0.5,  # lower weight for low-severity
        )


def asdict(f: Finding) -> dict:
    return {
        "severity": f.severity.value,
        "category": f.category,
        "location": f.location,
        "detail": f.detail,
    }