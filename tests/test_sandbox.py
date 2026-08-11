"""Tests for the sandbox module."""

import os
from pathlib import Path
from unittest import mock

import pytest

from verdict.sandbox import (
    DockerSandbox,
    SandboxError,
    SubprocessSandbox,
    docker_available,
    get_sandbox,
)


class TestDockerAvailable:
    def test_returns_true_when_docker_reachable(self):
        with mock.patch("verdict.sandbox.subprocess.run") as run:
            run.return_value.returncode = 0
            assert docker_available() is True

    def test_returns_false_when_docker_missing(self):
        with mock.patch("verdict.sandbox.subprocess.run", side_effect=FileNotFoundError):
            assert docker_available() is False

    def test_returns_false_on_timeout(self):
        import subprocess

        with mock.patch("verdict.sandbox.subprocess.run", side_effect=subprocess.TimeoutExpired("docker", 4)):
            assert docker_available() is False


class TestGetSandbox:
    def test_default_uses_docker_when_available(self):
        with mock.patch("verdict.sandbox.docker_available", return_value=True):
            sb = get_sandbox()
        assert isinstance(sb, DockerSandbox)

    def test_falls_back_to_subprocess_without_docker(self):
        with mock.patch("verdict.sandbox.docker_available", return_value=False):
            sb = get_sandbox()
        assert isinstance(sb, SubprocessSandbox)

    def test_explicit_subprocess_overrides_env(self):
        with mock.patch("verdict.sandbox.docker_available", return_value=True):
            assert isinstance(get_sandbox("subprocess"), SubprocessSandbox)

    def test_explicit_docker(self):
        assert isinstance(get_sandbox("docker"), DockerSandbox)

    def test_invalid_kind_falls_back_to_availability(self):
        with mock.patch("verdict.sandbox.docker_available", return_value=True):
            assert isinstance(get_sandbox("bogus"), DockerSandbox)

    def test_env_var_selects_sandbox(self, monkeypatch):
        monkeypatch.setenv("VERDICT_SANDBOX", "subprocess")
        with mock.patch("verdict.sandbox.docker_available", return_value=True):
            assert isinstance(get_sandbox(), SubprocessSandbox)


class TestSubprocessSandbox:
    def test_runs_python(self):
        sb = SubprocessSandbox()
        result = sb.run("python", "print('hi')", timeout=5.0)
        assert result is not None
        assert result.success
        assert "hi" in result.stdout
        assert result.isolated is False
        assert result.sandbox == "subprocess"

    def test_python_syntax_error(self):
        sb = SubprocessSandbox()
        result = sb.run("python", "def broken(", timeout=5.0)
        assert result is not None
        assert not result.success
        assert result.exit_code != 0

    def test_unsupported_language_returns_none(self):
        sb = SubprocessSandbox()
        assert sb.run("ruby", "puts 'hi'", timeout=5.0) is None

    def test_timeout_is_reported(self):
        sb = SubprocessSandbox()
        result = sb.run("python", "import time; time.sleep(5)", timeout=0.5)
        assert result is not None
        assert result.timed_out
        assert not result.success

    def test_python_feeds_via_stdin(self):
        # Verify we do NOT write a temp file for python runs.
        sb = SubprocessSandbox()
        with mock.patch("verdict.sandbox.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            run.return_value.stderr = ""
            sb.run("python", "print(1)", timeout=5.0)
            args, kwargs = run.call_args
            assert args[0][0] == "python" or args[0][-1] == "-"
            assert kwargs.get("input") == "print(1)"


class TestDockerSandbox:
    def test_unsupported_language_returns_none(self):
        sb = DockerSandbox()
        assert sb.run("go", "package main", timeout=5.0) is None

    def test_reports_docker_unavailable(self):
        sb = DockerSandbox()
        with mock.patch("verdict.sandbox.docker_available", return_value=False):
            result = sb.run("python", "print(1)", timeout=5.0)
        assert result is not None
        assert not result.success
        assert "docker" in result.error

    def test_reports_failed_image_pull(self):
        sb = DockerSandbox()
        with mock.patch("verdict.sandbox.docker_available", return_value=True):
            with mock.patch("verdict.sandbox.subprocess.run") as run:
                run.return_value.returncode = 1  # docker pull fails
                run.return_value.stderr = "pull error"
                run.return_value.stdout = ""
                result = sb.run("python", "print(1)", timeout=5.0)
        assert result is not None
        assert not result.success
        assert "could not pull" in result.error

    def test_builds_isolated_docker_command(self):
        sb = DockerSandbox()

        # docker available + image already present -> no pull, run fires.
        # _ensure_image checks the disk cache; seed it so we skip the pull.
        sb._ready_check[sb._resolve("python")[0]] = True

        with mock.patch("verdict.sandbox.docker_available", return_value=True):
            with mock.patch("verdict.sandbox.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = "ok"
                run.return_value.stderr = ""
                result = sb.run("python", "print(1)", timeout=5.0)

        assert result is not None
        assert result.success
        assert result.isolated is True
        assert result.sandbox == "docker"

        cmd = run.call_args.args[0]
        assert cmd[0] == "docker"
        assert "run" in cmd
        # Security flags must all be present
        assert "--network" in cmd and "none" in cmd
        assert "--read-only" in cmd
        assert "--cap-drop" in cmd and "ALL" in cmd
        assert "--security-opt" in cmd and "no-new-privileges" in cmd
        assert "--user" in cmd and "nobody" in cmd
        # Code is fed on stdin, never written to disk
        assert run.call_args.kwargs.get("input") == "print(1)"

    def test_timeout_124_is_mapped(self):
        sb = DockerSandbox()
        sb._ready_check[sb._resolve("python")[0]] = True
        with mock.patch("verdict.sandbox.docker_available", return_value=True):
            with mock.patch("verdict.sandbox.subprocess.run") as run:
                run.return_value.returncode = 124  # container timeout
                run.return_value.stdout = ""
                run.return_value.stderr = "cmd timed out"
                result = sb.run("python", "print(1)", timeout=5.0)
        assert result.timed_out
        assert not result.success


class TestImageCache:
    def test_failed_pull_is_not_retried(self):
        sb = DockerSandbox()
        with mock.patch("verdict.sandbox.docker_available", return_value=True):
            with mock.patch("verdict.sandbox.subprocess.run") as run:
                run.return_value.returncode = 1
                run.return_value.stderr = "nope"
                sb.run("python", "x", timeout=2.0)
                assert run.call_count == 1  # (pull happened once)
                # Second run must not re-pull; it errors fast from cache.
                result = sb.run("python", "x", timeout=2.0)
                assert result.error and "not pulled" in result.error
                assert run.call_count == 1