"""Behavioral regression checks for the contributor-tool trust boundary."""

from __future__ import annotations

import io
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import tools


class CompilerGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / ".go-version").write_text("1.27.3\n")
        self.addCleanup(patch.stopall)
        patch.object(tools, "ROOT", self.root).start()
        patch.object(tools, "BIN", self.root / "bin").start()

    def fake_go(self, compiler_version: str) -> None:
        binary = self.root / "go"
        binary.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = version ]; then echo "go version go1.27.3 linux/amd64"; '
            f'else echo "compile version {compiler_version}"; fi\n'
        )
        binary.chmod(0o755)
        patch.dict(os.environ, {"PATH": str(self.root), "GOTOOLCHAIN": "local"}).start()

    def test_matching_driver_does_not_hide_wrong_goroot_compiler(self) -> None:
        self.fake_go("go1.25.8")
        with self.assertRaisesRegex(RuntimeError, "GOROOT"):
            tools.compiler()

    def test_matching_installed_compiler_is_accepted(self) -> None:
        self.fake_go("go1.27.3")
        tools.compiler()

    def test_malformed_pin_refuses_before_executing_go(self) -> None:
        (self.root / ".go-version").write_bytes(b"1.27.3\x00\n")
        with patch.object(tools, "run") as command:
            with self.assertRaisesRegex(RuntimeError, "exactly one"):
                tools.compiler()
            command.assert_not_called()

    def test_conflicting_toolchain_selection_is_refused(self) -> None:
        with patch.dict(os.environ, {"GOTOOLCHAIN": "auto"}):
            with self.assertRaisesRegex(RuntimeError, "GOTOOLCHAIN"):
                tools.compiler()

    def test_corrupt_distribution_archive_installs_no_executable(self) -> None:
        with (
            patch.object(tools, "compiler"),
            patch.object(tools.platform, "system", return_value="Linux"),
            patch.object(tools.platform, "machine", return_value="x86_64"),
            patch.object(
                tools.urllib.request,
                "urlopen",
                return_value=io.BytesIO(b"corrupt distribution archive"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "integrity mismatch"):
                tools.install()
        self.assertFalse((self.root / "bin" / "golangci-lint").exists())

    def test_empty_format_selection_does_not_pass(self) -> None:
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        with patch.object(tools, "verify"):
            with self.assertRaisesRegex(RuntimeError, "No Go sources"):
                tools.format_check()

    def test_format_scope_includes_untracked_sources_but_not_ignored_dependencies(
        self,
    ) -> None:
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        (self.root / ".gitignore").write_text("/.ci-native/\n")
        (self.root / "tracked.go").write_text("package tracked\n")
        subprocess.run(["git", "-C", str(self.root), "add", "tracked.go"], check=True)
        (self.root / "untracked.go").write_text("package untracked\n")
        dependency = self.root / ".ci-native"
        dependency.mkdir()
        (dependency / "foreign.go").write_text("package foreign\n")
        actual_run = tools.run
        formatted = []

        def command(args, **kwargs):
            if args[:2] == ["git", "ls-files"]:
                return actual_run(args, **kwargs)
            formatted.extend(args[2:])
            return ""

        with patch.object(tools, "verify"), patch.object(tools, "run", command):
            tools.format_check()
        self.assertEqual(formatted, ["tracked.go", "untracked.go"])

    def test_checkout_ancestor_named_bin_does_not_hide_go_sources(self) -> None:
        checkout = self.root / "bin" / "checkout"
        checkout.mkdir(parents=True)
        (checkout / "example.go").write_text("package example\n")
        subprocess.run(["git", "init", "--quiet", str(checkout)], check=True)
        actual_run = tools.run
        formatted = []

        def command(args, **kwargs):
            if args[:2] == ["git", "ls-files"]:
                return actual_run(args, **kwargs)
            formatted.extend(args[2:])
            return ""

        with (
            patch.object(tools, "ROOT", checkout),
            patch.object(tools, "verify"),
            patch.object(tools, "run", command),
        ):
            tools.format_check()
        self.assertEqual(formatted, ["example.go"])

    def test_empty_package_selection_does_not_pass_build_gate(self) -> None:
        with (
            patch.object(tools, "compiler"),
            patch.object(tools, "run", return_value=""),
        ):
            with self.assertRaisesRegex(RuntimeError, "No Go packages"):
                tools.packages()


if __name__ == "__main__":
    unittest.main()
