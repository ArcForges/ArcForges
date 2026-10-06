# SPDX-License-Identifier: AGPL-3.0-only
"""Offline contract negatives; these checks do not execute native binaries or prove codec/OS behavior."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eng/packaging"))
import native


class FunctionalNativeInventory(unittest.TestCase):
    def entry(self, prefix="arc_image"):
        return {"prefix": prefix, "library": "ArcImageNative" if prefix == "arc_image" else "ArcPdfNative"}

    def test_exact_functional_image_and_pdf_contracts(self):
        for prefix, count in (("arc_image", 6), ("arc_pdf", 8)):
            entry = self.entry(prefix)
            abi, exports = native.abi_contract(entry)
            self.assertEqual({"major": 1, "minor": 1}, abi)
            self.assertEqual(count, len(exports))
            self.assertEqual(abi, native.verify_abi(entry, sorted(exports), abi))

    def test_probe_only_missing_extra_duplicate_and_foreign_exports_refuse(self):
        entry = self.entry()
        _, exports = native.abi_contract(entry)
        for actual in ([], sorted(exports)[:3], sorted(exports)[:-1], sorted(exports) + ["upstream_cpp_symbol"],
                       sorted(exports) + [sorted(exports)[0]], [e.replace("arc_image", "arc_pdf") for e in exports]):
            with self.subTest(exports=actual), self.assertRaisesRegex(ValueError, "export set"):
                native.verify_abi(entry, actual)

    def test_library_family_and_unknown_family_refuse(self):
        for entry in ({"prefix": "arc_image", "library": "ArcPdfNative"}, {"prefix": "caller", "library": "ArcImageNative"},
                      {"prefix": [], "library": "ArcImageNative"}, {}):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                native.abi_contract(entry)

    def test_manifest_downgrades_major_drift_and_unadmitted_minor_refuse(self):
        entry = self.entry()
        _, exports = native.abi_contract(entry)
        for abi in ({"major": 1, "minor": 0}, {"major": 2, "minor": 1}, {"major": 1, "minor": 2}, {"major": 1},
                    {"major": True, "minor": 1}, {"major": 1, "minor": 1, "extra": 0}):
            with self.subTest(abi=abi), self.assertRaisesRegex(ValueError, "manifest version"):
                native.verify_abi(entry, sorted(exports), abi)


if __name__ == "__main__":
    unittest.main()
