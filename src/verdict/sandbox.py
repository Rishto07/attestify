"""Sandbox — where untrusted code runs, locked down.

ExecuteProof verifies that code *works*. The sandbox answers a different,
harder question: can untrusted code run *without touching your machine*?

Two backends:

- ``DockerSandbox`` — runs code in a container with:
    no network, read-only filesystem, root disabled, memory + CPU capped,
    process limit, hard timeout. This is the production answer.
- ``SubprocessSandbox`` — runs code as the current user (the old behavior).
    Explicitly NOT isolated. Used as fallback when Docker is unavailable,
    and always reported as such in the verdict.

Design rule: the sandbox never decides PASS/FAIL. The checker does. The
sandbox only guarantees *boundaries*. We are deliberately honest in a class
of two: ``isolated=True`` means the container boundary held, and
``isolated=False`` means "I promise you I am not a security boundary."
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# === RESULTS ===

@dataclass
class ExecutionResult:
    """What happened when we tried to run the code.

    ``isolated`` is the honest flag: True only when a real boundary (container)
    wrapped the run. Everything downstream (receipts, UI) must surface it.
    """

    success: bool
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    error: str | None = None
    isolated: bool = False
    sandbox: str = "unknown"


# === SANDBOX PROTOCOL ===

class SandboxError(RuntimeError):
    """A sandbox-level failure (docker missing, pull failed, timeout)."""


class Sandbox:
    """Protocol: run untrusted code inside boundaries."""

    name = "sandbox"

    def run(
        self,
        language: str,
        code: str,
        timeout: float,
        workdir: Optional[Path] = None,
    ) -> Optional[ExecutionResult]:
        """Run ``code`` in the sandbox.

        Returns ``None`` when the language is unsupported (caller skips it),
        or an ExecutionResult otherwise. Never raises on user code — the
        sandbox *observes* failures, it does not fault on them.
        """
        raise NotImplementedError


# === SUBPROCESS SANDBOX (fallback, NOT isolated) ===

class SubprocessSandbox(Sandbox):
    """Runs code as the current user.

    This is the compatibility fallback. It carries the same lexical language
    handling as before, but since there is no boundary, ``isolated`` is False.
    """

    name = "subprocess"

    def run(
        self,
        language: str,
        code: str,
        timeout: float,
        workdir: Optional[Path] = None,
    ) -> Optional[ExecutionResult]:
        if language == "python":
            return self._run_python(code, timeout, workdir)
        if language in {"bash", "shell", "sh"}:
            return self._run_shell(code, timeout, workdir)
        if language == "javascript":
            return self._run_javascript(code, timeout, workdir)
        return None

    # All three runners share one shape; keep them private and short.
    def _spawn(
        self,
        argv: list[str],
        code: str,
        timeout: float,
        workdir: Optional[Path],
        not_found_msg: str,
    ) -> ExecutionResult:
        start = time.perf_counter()
        try:
            proc = subprocess.run(
                argv,
                input=code,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=workdir,
            )
            return ExecutionResult(
                success=proc.returncode == 0,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=(time.perf_counter() - start) * 1000,
                isolated=False,
                sandbox=self.name,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                exit_code=None,
                stdout="",
                stderr=f"Process timed out after {timeout}s",
                duration_ms=timeout * 1000,
                timed_out=True,
                isolated=False,
                sandbox=self.name,
            )
        except FileNotFoundError:
            return ExecutionResult(
                success=False,
                exit_code=None,
                stdout="",
                stderr=not_found_msg,
                duration_ms=0,
                error=not_found_msg,
                isolated=False,
                sandbox=self.name,
            )

    def _run_python(self, code: str, timeout: float, workdir: Optional[Path]) -> ExecutionResult:
        # Python reads the program from stdin (`-`), so we never write a temp file.
        return self._spawn(
            [sys.executable, "-B", "-"],
            code,
            timeout,
            workdir,
            f"{sys.executable} interpreter not found",
        )

    def _run_shell(self, code: str, timeout: float, workdir: Optional[Path]) -> ExecutionResult:
        # `sh -s` reads the script from stdin.
        sh = os.environ.get("SHELL", "sh") if os.name != "nt" else "sh"
        return self._spawn(
            [sh, "-s"],
            code,
            timeout,
            workdir,
            "shell interpreter not found",
        )

    def _run_javascript(self, code: str, timeout: float, workdir: Optional[Path]) -> ExecutionResult:
        # `node -` reads the program from stdin.
        return self._spawn(
            ["node", "-"],
            code,
            timeout,
            workdir,
            "node interpreter not found",
        )


# === DOCKER SANDBOX (isolated) ===

# language -> (image, [argv before the code, with {timeout} and {code} placeholders])
# {code} is fed on stdin; {timeout} becomes the hard k:process timeout.
_DOCKER_IMAGES = {
    "python": (
        "python:3.12-alpine",
        ["python", "-B", "-"],
    ),
    "bash": (
        "alpine:3.20",
        ["sh", "-s"],
    ),
    "javascript": (
        "node:20-alpine",
        ["node", "-"],
    ),
}

# Docker run flags that turn a plain container into a hard boundary.
# Deliberately the most conservative set we can defend. Order matters for
# humans reading the command in the receipt; docker does not care.
_DOCKER_SECURITY_FLAGS = [
    # --network none   -> no network at all. The single most important flag.
    "--network",
    "none",
    # --read-only      -> filesystem is a read-only mount; writes go nowhere.
    "--read-only",
    # --cap-drop ALL   -> drop every Linux capability (no raw sockets, no ptrace…).
    "--cap-drop",
    "ALL",
    # --security-opt no-new-privileges -> the process cannot gain privileges,
    #   even if setuid binaries existed (avoid setuid semantics entirely).
    "--security-opt",
    "no-new-privileges",
    # --user nobody    -> drop to the least-privileged account inside the box.
    "--user",
    "nobody",
    # --memory / --memory-swap   -> hard memory ceiling; swap disabled to avoid
    #   swapping out to the host.
    "--memory",
    "128m",
    "--memory-swap",
    "128m",
    # --cpus 0.5       -> at most half a CPU.
    "--cpus",
    "0.5",
    # --pids-limit 32  -> can't fork-bomb the box.
    "--pids-limit",
    "32",
    # --stop-timeout 2 -> give the runtime 2s to die before docker kills it.
    "--stop-timeout",
    "2",
]


def docker_available(timeout: float = 4.0) -> bool:
    """True when docker CLI exists AND the daemon is reachable.

    Runs `docker version` with a short timeout; a missing docker or a
    Windows-permission error both collapse to False (we degrade, not crash).
    """
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class DockerSandbox(Sandbox):
    """Runs code in a locked-down container. This is the real boundary."""

    name = "docker"

    def __init__(self, image_timeout: float = 120.0):
        self.image_timeout = image_timeout
        self._ready_check: dict[str, bool] = {}

    # --- helpers ---------------------------------------------------------

    def _resolve(self, language: str) -> Optional[tuple[str, list[str]]]:
        return _DOCKER_IMAGES.get(language)

    def _ensure_image(self, image: str) -> None:
        """Pull the image once, so the run itself is offline and fast."""
        if image in self._ready_check:
            if self._ready_check[image]:
                return
            raise SandboxError(f"docker image {image} was not pulled successfully")

        pull = subprocess.run(
            ["docker", "pull", image],
            capture_output=True,
            text=True,
            timeout=self.image_timeout,
        )
        self._ready_check[image] = pull.returncode == 0
        if pull.returncode != 0:
            raise SandboxError(
                f"could not pull docker image {image}: {pull.stderr.strip()[:200]}"
            )

    # --- main entry ------------------------------------------------------

    def run(
        self,
        language: str,
        code: str,
        timeout: float,
        workdir: Optional[Path] = None,
    ) -> Optional[ExecutionResult]:
        resolved = self._resolve(language)
        if resolved is None:
            return None
        image, argv = resolved

        if not docker_available():
            return ExecutionResult(
                success=False,
                exit_code=None,
                stdout="",
                stderr="docker is not available; nothing ran. Use --sandbox=subprocess to fall back.",
                duration_ms=0,
                error="docker unavailable",
                isolated=False,
                sandbox=self.name,
            )

        try:
            self._ensure_image(image)
        except SandboxError as e:
            return ExecutionResult(
                success=False,
                exit_code=None,
                stdout="",
                stderr=str(e),
                duration_ms=0,
                error=str(e),
                isolated=False,
                sandbox=self.name,
            )

        # The outer timeout is a safety net; the container's own `timeout`
        # binary is the hard kill inside the boundary.
        inner = int(timeout) or 1
        cmd = [
            "docker",
            "run",
            "--rm",
            "-i",
        ] + _DOCKER_SECURITY_FLAGS + [
            "--name",
            f"verdict-sbx-{int(time.time() * 1000)}",
            image,
            "timeout",
            f"{inner}s",
        ] + argv

        start = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                input=code,
                capture_output=True,
                text=True,
                timeout=timeout + 30.0,  # image pull + docker startup headroom
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                exit_code=None,
                stdout="",
                stderr=f"Docker run exceeded {timeout}s (sandbox) — hard kill",
                duration_ms=timeout * 1000,
                timed_out=True,
                isolated=True,
                sandbox=self.name,
            )

        duration_ms = (time.perf_counter() - start) * 1000

        # The `timeout` command inside the container exits 124 on timeout.
        timed_out = proc.returncode == 124
        success = proc.returncode == 0
        return ExecutionResult(
            success=success,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=(
                proc.stderr
                if not timed_out
                else f"Code timed out after {timeout}s inside the sandbox.\n{proc.stderr}"
            ),
            duration_ms=duration_ms,
            timed_out=timed_out,
            error=None if success else proc.stderr.strip()[:200] or None,
            isolated=True,
            sandbox=self.name,
        )


# === FACTORY ===

_SANDBOXES = {
    "docker": DockerSandbox,
    "subprocess": SubprocessSandbox,
}


def get_sandbox(kind: str | None = None) -> Sandbox:
    """Auto-select a sandbox.

    ``kind`` may be one of ``docker`` / ``subprocess``, or None to let the
    environment and Docker availability decide.

    Resolution order for ``kind=None`` (and ``VERDICT_SANDBOX`` unset):
    1. docker is available -> DockerSandbox (isolated)
    2. otherwise            -> SubprocessSandbox (explicit fallback)
    """
    if kind is None:
        kind = os.environ.get("VERDICT_SANDBOX", "")
    kind = (kind or "").strip().lower()

    if kind in _SANDBOXES:
        return _SANDBOXES[kind]()

    # Default: use docker when it exists; else degrade cleanly.
    if docker_available():
        return DockerSandbox()
    return SubprocessSandbox()


def _write_temp_file(code: str, suffix: str, workdir: Optional[Path]) -> Path:
    """Small helper kept for API compatibility with older callers."""
    f = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=suffix,
        delete=False,
        dir=workdir or None,
        encoding="utf-8",
    )
    f.write(code)
    f.flush()
    return Path(f.name)