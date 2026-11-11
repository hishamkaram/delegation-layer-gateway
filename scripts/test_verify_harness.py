"""Physical-root containment across symlinked repository and temporary paths."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_harness as harness


class CanonicalRootTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repository = Path(harness.__file__).resolve().parent.parent
        self.alias = self.base / "repository-alias"
        self.alias.symlink_to(self.repository, target_is_directory=True)

    def test_public_validation_accepts_a_symlinked_repository_root(self):
        self.assertEqual(harness.validate(self.alias, docs=True), [])

    def test_reference_helper_requires_the_entry_points_canonical_root(self):
        with self.assertRaisesRegex(ValueError, "canonical repository root required"):
            harness.references(self.alias, [self.repository / "AGENTS.md"])

    def test_real_self_test_accepts_symlinked_root_and_temporary_parent(self):
        physical = self.base / "physical-temporary-parent"
        physical.mkdir()
        alias = self.base / "temporary-parent-alias"
        alias.symlink_to(physical, target_is_directory=True)
        # macOS commonly returns /var/... while resolve() returns /private/var/...
        # Preserve that lexical/physical distinction on every test platform.
        with patch.object(tempfile, "tempdir", str(alias)):
            self.assertEqual(harness.self_test(self.alias), [])

    def test_relative_and_symlinked_targets_outside_root_remain_rejected(self):
        root = self.base / "contained"
        root.mkdir()
        outside = self.base / "outside.md"
        outside.write_text("# Outside\n")
        (root / "external.md").symlink_to(outside)
        source = root / "guide.md"
        source.write_text("[Relative](../outside.md)\n[Symlink](external.md)\n")
        self.assertEqual(
            harness.references(root, [source]),
            [
                "guide.md: reference escapes repository: ../outside.md",
                "guide.md: reference escapes repository: external.md",
            ],
        )

    def test_external_source_paths_are_rejected_without_relative_path_errors(self):
        root = self.base / "contained"
        root.mkdir()
        outside = self.base / "outside.md"
        outside.write_text("# Outside\n")
        linked = root / "external.md"
        linked.symlink_to(outside)
        for source in (outside, linked):
            with self.subTest(source=source.name):
                errors = harness.references(root, [source])
                self.assertEqual(
                    errors, [f"reference source escapes repository: {source.name}"]
                )


if __name__ == "__main__":
    unittest.main()
