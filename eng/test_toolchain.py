# SPDX-License-Identifier: AGPL-3.0-only
"""Use actual installed tools to reject mismatched current selector inputs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import baseline_sdk

ROOT = Path(__file__).resolve().parents[1]


class ToolchainSelectionTests(unittest.TestCase):
    def invoke(self, root=ROOT, *, tools=("python", "dotnet"), environment=None):
        return subprocess.run([sys.executable, str(root / "eng/check_toolchain.py"), "--tools", *tools], cwd=root,
                              env={**os.environ, **(environment or {})}, capture_output=True, text=True, timeout=90)

    def test_actual_managed_sdk_and_every_committed_lock_are_recorded(self):
        process = self.invoke()
        self.assertEqual(0, process.returncode, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(json.loads((ROOT / "global.json").read_text())["sdk"]["version"], report["dotnet"]["version"])
        locks = subprocess.check_output(["git", "ls-files", "--", "*packages.lock.json"], cwd=ROOT, text=True).splitlines()
        self.assertEqual(sorted(locks), sorted(report["lockSha256Lf"]))

    def test_invoking_python_cannot_be_skipped_by_requesting_only_dotnet(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "eng").mkdir()
            shutil.copyfile(ROOT / "eng/check_toolchain.py", root / "eng/check_toolchain.py")
            (root / ".python-version").write_text("0.0.0\n")
            process = self.invoke(root, tools=("dotnet",))
            self.assertNotEqual(0, process.returncode)
            self.assertIn("must both match", process.stderr)

    def test_conflicting_msbuild_sdk_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            process = self.invoke(environment={"MSBuildSDKsPath": directory})
            self.assertNotEqual(0, process.returncode)
            self.assertIn("toolchain mismatch:", process.stderr)

    def test_python_only_job_does_not_require_a_managed_sdk(self):
        process = self.invoke(tools=("python",), environment={"MSBuildSDKsPath": str(ROOT / "artifacts/not-an-sdk")})
        self.assertEqual(0, process.returncode, process.stderr)
        self.assertNotIn("dotnet", json.loads(process.stdout))

    def test_baseline_selects_the_sdk_of_its_own_global_json(self):
        executable, environment, report = baseline_sdk.select(ROOT)
        expected = json.loads((ROOT / "global.json").read_text())["sdk"]["version"]
        self.assertTrue(executable.is_file())
        self.assertEqual(expected, report["expected"])
        self.assertEqual(str(executable.parent), environment["DOTNET_ROOT"])
        self.assertNotIn("MSBuildSDKsPath", environment)

    def test_missing_baseline_sdk_fails_without_installing_a_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "global.json").write_text(json.dumps({"sdk": {"version": "0.0.0"}}))
            with self.assertRaisesRegex(ValueError, "retained SDK 0.0.0"):
                baseline_sdk.select(source)


if __name__ == "__main__":
    unittest.main()
