"""Origin checks protect owner selection without starting fixture processes."""

import importlib.machinery
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import e2e_native_capture as capture


class OwnerOriginTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.repository = self.base / "native"
        self.acceptance = self.repository / "scripts/acceptance"
        self.acceptance.mkdir(parents=True)
        (self.acceptance / "__init__.py").write_text("")
        processes = self.acceptance / "processes"
        processes.mkdir()
        (processes / "operations.py").write_text("")

    def namespace(self, paths):
        spec = importlib.machinery.ModuleSpec("scripts", loader=None, is_package=True)
        spec.submodule_search_locations = list(map(str, paths))
        return spec

    def test_gateway_namespace_and_same_checkout_cached_owners_are_allowed(self):
        gateway = Path(__file__).resolve().parent
        modules = {
            "scripts.acceptance": SimpleNamespace(
                __file__=str(self.acceptance / "__init__.py"),
                __path__=[str(self.acceptance)],
            ),
            "scripts.acceptance.processes.operations": SimpleNamespace(
                __file__=str(self.acceptance / "processes/operations.py")
            ),
        }
        with (
            mock.patch.object(capture.sys, "modules", modules),
            mock.patch.object(
                capture.importlib.util,
                "find_spec",
                return_value=self.namespace([gateway, self.repository / "scripts"]),
            ),
        ):
            capture.validate_acceptance_origin(self.repository)
            capture.validate_acceptance_origin(self.repository)

    def test_foreign_cached_owner_is_rejected_before_any_import(self):
        foreign = self.base / "foreign.py"
        foreign.write_text("raise AssertionError('must not execute')")
        modules = {
            "scripts.acceptance.processes.operations": SimpleNamespace(
                __file__=str(foreign)
            )
        }
        with (
            mock.patch.object(capture.sys, "modules", modules),
            mock.patch.object(capture.sys, "path", list(sys.path)),
            mock.patch.object(capture.importlib, "import_module") as importing,
        ):
            with self.assertRaisesRegex(ValueError, "foreign cached"):
                capture.load_owners(self.repository)
            importing.assert_not_called()

    def test_repeated_owner_loads_preserve_one_explicit_source_entry(self):
        source = str(self.repository)
        owners = SimpleNamespace(DirectoryOwner=object(), Processes=object())
        with (
            mock.patch.object(capture.sys, "modules", {"sys": sys}),
            mock.patch.object(capture.sys, "path", [source, str(self.base)]),
            mock.patch.object(
                capture.importlib.util,
                "find_spec",
                return_value=self.namespace([self.repository / "scripts"]),
            ),
            mock.patch.object(capture.importlib, "import_module", return_value=owners),
        ):
            before = list(capture.sys.path)
            first = capture.load_owners(self.repository)
            second = capture.load_owners(self.repository)
            self.assertEqual(first, second)
            self.assertEqual(capture.sys.path, before)
            self.assertEqual(capture.sys.path.count(source), 1)

    def test_foreign_namespace_acceptance_is_rejected_before_any_import(self):
        foreign = self.base / "foreign/scripts"
        (foreign / "acceptance").mkdir(parents=True)
        with (
            mock.patch.object(capture.sys, "modules", {"sys": sys}),
            mock.patch.object(capture.sys, "path", list(sys.path)),
            mock.patch.object(
                capture.importlib.util,
                "find_spec",
                return_value=self.namespace([self.repository / "scripts", foreign]),
            ),
            mock.patch.object(capture.importlib, "import_module") as importing,
        ):
            with self.assertRaisesRegex(ValueError, "foreign scripts namespace"):
                capture.load_owners(self.repository)
            importing.assert_not_called()

    def test_cached_source_symlink_cannot_escape_selected_checkout(self):
        outside = self.base / "outside.py"
        outside.write_text("")
        linked = self.acceptance / "linked.py"
        linked.symlink_to(outside)
        with mock.patch.object(
            capture.sys,
            "modules",
            {"scripts.acceptance.linked": SimpleNamespace(__file__=str(linked))},
        ):
            with self.assertRaisesRegex(ValueError, "foreign cached"):
                capture.validate_acceptance_origin(self.repository)

    def test_safe_spec_cannot_hide_a_foreign_cached_actual_search_path(self):
        foreign = self.base / "foreign/scripts"
        (foreign / "acceptance").mkdir(parents=True)
        spec = self.namespace([self.repository / "scripts"])
        module = SimpleNamespace(__spec__=spec, __path__=[str(foreign)])
        with (
            mock.patch.object(capture.sys, "modules", {"sys": sys, "scripts": module}),
            mock.patch.object(capture.sys, "path", list(sys.path)),
            mock.patch.object(capture.importlib.util, "find_spec", return_value=spec),
            mock.patch.object(capture.importlib, "import_module") as importing,
        ):
            with self.assertRaisesRegex(ValueError, "foreign scripts namespace"):
                capture.load_owners(self.repository)
            importing.assert_not_called()

    def test_foreign_acceptance_module_is_rejected_before_any_import(self):
        foreign = self.base / "foreign/scripts"
        foreign.mkdir(parents=True)
        (foreign / "acceptance.py").write_text(
            "raise AssertionError('must not execute')"
        )
        with (
            mock.patch.object(capture.sys, "modules", {"sys": sys}),
            mock.patch.object(capture.sys, "path", list(sys.path)),
            mock.patch.object(
                capture.importlib.util,
                "find_spec",
                return_value=self.namespace([foreign, self.repository / "scripts"]),
            ),
            mock.patch.object(capture.importlib, "import_module") as importing,
        ):
            with self.assertRaisesRegex(ValueError, "foreign scripts namespace"):
                capture.load_owners(self.repository)
            importing.assert_not_called()

    def test_missing_real_acceptance_initializer_is_rejected(self):
        (self.acceptance / "__init__.py").unlink()
        with self.assertRaisesRegex(ValueError, "acceptance package unavailable"):
            capture.validate_acceptance_origin(self.repository)


if __name__ == "__main__":
    unittest.main()
