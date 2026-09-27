# SPDX-License-Identifier: AGPL-3.0-only
"""Release guards exercised against the actual candidate produced by pack."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

import packages


class PackageGuards(unittest.TestCase):
    def fixture(self):
        source = Path(os.environ.get("ARCFORGES_PACKAGE_DIRECTORY", packages.ROOT / "artifacts/packages"))
        target = Path(tempfile.mkdtemp(prefix="package-guard-", dir=packages.ROOT / "artifacts")).resolve()
        packages.require(target.is_relative_to(packages.ROOT / "artifacts"), "Fixture escapes artifacts.")
        self.addCleanup(shutil.rmtree, target)
        for path in source.iterdir():
            if path.is_file():
                shutil.copyfile(path, target / path.name)
        manifest = json.loads((target / "manifest.json").read_text())
        return target, manifest

    def mutate_native(self, change):
        target, manifest = self.fixture()
        row = next(row for row in manifest["packages"] if row["id"] == "ArcForges.Native.Image.Runtime.win-x64")
        path = target / row["file"]
        with zipfile.ZipFile(path) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        change(files, manifest)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)
        # Bypass only the outer archive checksum: the content/provenance checks must still reject the fixture.
        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        (target / "manifest.json").write_text(json.dumps(manifest))
        return target, manifest

    def test_canonical_versions(self):
        for value in ["1.0.0", "1.0.0-ci.123.2", "0.1.0-rc.1"]:
            self.assertEqual(value, packages.version(value))
        for value in ["v1.0.0", "1.0", "01.0.0", "1.0.0+build", "1.0.0-ci.01", "1.*", "../1.0.0", "1.0.0;echo unsafe"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                packages.version(value)

    def test_real_candidate_verifies(self):
        target, manifest = self.fixture()
        packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_altered_package_is_rejected(self):
        target, manifest = self.fixture()
        package = target / manifest["packages"][0]["file"]
        package.write_bytes(package.read_bytes() + b"altered")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_unlisted_package_is_rejected(self):
        target, manifest = self.fixture()
        (target / "Unexpected.1.0.0.nupkg").write_bytes(b"unreviewed")
        with self.assertRaisesRegex(ValueError, "Unexpected or missing"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_wrong_source_is_rejected(self):
        target, manifest = self.fixture()
        with self.assertRaisesRegex(ValueError, "source/version mismatch"):
            packages.verify(target, manifest["version"], "0" * 40)

    def test_candidate_cannot_be_overwritten(self):
        target, manifest = self.fixture()
        with self.assertRaisesRegex(ValueError, "never overwrite"):
            packages.pack(target, manifest["version"])

    def test_missing_transitive_dll_is_rejected(self):
        target, manifest = self.mutate_native(lambda files, _: files.pop("runtimes/win-x64/native/msvcp140.dll"))
        with self.assertRaisesRegex(ValueError, "DLL closure"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_changed_native_binary_is_rejected(self):
        def tamper(files, _):
            files["runtimes/win-x64/native/ArcImageNative.dll"] += b"altered"
        target, manifest = self.mutate_native(tamper)
        with self.assertRaisesRegex(ValueError, "Native DLL hash mismatch"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_wrong_native_rid_is_rejected(self):
        def tamper(files, _):
            data = json.loads(files["native-manifest.json"])
            data["rid"] = "win-arm64"
            files["native-manifest.json"] = json.dumps(data).encode()
        target, manifest = self.mutate_native(tamper)
        with self.assertRaisesRegex(ValueError, "source/RID/library"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_inexact_managed_runtime_pair_is_rejected(self):
        def tamper(files, manifest):
            name = next(name for name in files if name.endswith(".nuspec"))
            files[name] = files[name].replace(f'[{manifest["version"]}]'.encode(), manifest["version"].encode())
        target, manifest = self.mutate_native(tamper)
        with self.assertRaisesRegex(ValueError, "dependency closure/version"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_changed_header_is_rejected_against_native_artifact(self):
        def tamper(files, _):
            files["include/arc/arc_native_abi.h"] += b"// altered"
        target, manifest = self.mutate_native(tamper)
        with self.assertRaisesRegex(ValueError, "differs from the tested producer artifact"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_missing_upstream_notice_is_rejected(self):
        target, manifest = self.mutate_native(lambda files, _: files.pop("licenses/openimageio-x64-windows-static-md.txt"))
        with self.assertRaisesRegex(ValueError, "Missing upstream licence/source"):
            packages.verify(target, manifest["version"], manifest["sourceCommit"])

    def test_changed_axis_rejected_after_rehashing_archive(self):
        def tamper(files, _):
            report = json.loads(files['build-identity.json'])
            report['axes']['NativeAbiVersion']['values'][0]['version'] = '9.0'
            files['build-identity.json'] = json.dumps(report).encode()
        target, manifest = self.mutate_native(tamper)
        with self.assertRaisesRegex(ValueError, 'independent sources'):
            packages.verify(target, manifest['version'], manifest['sourceCommit'])

    def test_changed_run_rejected_after_rehashing_archive(self):
        def tamper(files, _):
            report = json.loads(files['build-identity.json'])
            report['build']['buildId'] = 'incorrect'
            files['build-identity.json'] = json.dumps(report).encode()
        target, manifest = self.mutate_native(tamper)
        with self.assertRaisesRegex(ValueError, 'identity'):
            packages.verify(target, manifest['version'], manifest['sourceCommit'])


if __name__ == "__main__":
    unittest.main()
