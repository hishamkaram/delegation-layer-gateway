"""Protect the boundary between published assets and their evidence receipt."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import verify_diagrams


class DiagramReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name) / "diagrams"
        self.base.mkdir()
        patch = self.base.parent / "tools/archify-whitespace.patch"
        patch.parent.mkdir()
        patch.write_bytes(b"fixture patch")
        renderer = {
            "localPatch": "../tools/archify-whitespace.patch",
            "patchSha256": hashlib.sha256(patch.read_bytes()).hexdigest(),
        }
        for name, data in {
            "source.json": b"{}\n",
            "view.html": b"<!doctype html>\n",
            "view.svg": b"<svg/>\n",
        }.items():
            (self.base / name).write_bytes(data)
        descriptions = {}
        for name in ["source.json", "view.html", "view.svg"]:
            data = (self.base / name).read_bytes()
            descriptions[name] = {
                "path": name,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        summary = {
            "diagrams": [
                {
                    "renderer": renderer,
                    "source": descriptions["source.json"],
                    "html": descriptions["view.html"],
                    "svgExport": {"path": "view.svg"},
                }
            ]
        }
        export = dict(
            descriptions["view.svg"],
            artifact="view.svg",
            sourceHtmlSha256=descriptions["view.html"]["sha256"],
        )
        (self.base / "validation.json").write_text(json.dumps(summary))
        (self.base / "svg-exports.json").write_text(
            json.dumps({"renderer": renderer, "exports": [export]})
        )

    def test_patch_change_invalidates_evidence(self) -> None:
        (self.base.parent / "tools/archify-whitespace.patch").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "renderer patch changed"):
            verify_diagrams.verify(self.base)

    def test_html_without_receipt_cannot_pass(self) -> None:
        (self.base / "unreviewed.html").write_bytes(b"unreviewed")
        with self.assertRaisesRegex(ValueError, "exactly one receipt"):
            verify_diagrams.verify(self.base)

    def test_current_assets_pass_but_changed_html_invalidates_evidence(self) -> None:
        self.assertEqual(verify_diagrams.verify(self.base), 3)
        (self.base / "view.html").write_bytes(b"changed after browser validation")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            verify_diagrams.verify(self.base)

    def test_changed_svg_cannot_reuse_its_prior_export_receipt(self) -> None:
        (self.base / "view.svg").write_bytes(b"<svg><text>changed</text></svg>")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            verify_diagrams.verify(self.base)

    def test_receipt_cannot_name_a_path_outside_diagrams(self) -> None:
        with self.assertRaisesRegex(ValueError, "artifact path"):
            verify_diagrams.verify_file(
                self.base, {"path": "../private", "bytes": 0, "sha256": "0" * 64}
            )


if __name__ == "__main__":
    unittest.main()
