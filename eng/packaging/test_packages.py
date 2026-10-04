# SPDX-License-Identifier: AGPL-3.0-only
"""Release guards exercised against the actual candidate produced by pack."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

import packages


class ExternalDependencyGuards(unittest.TestCase):
    owned_version = "2.0.0-ci.20.1"
    external_version = "1.0.0-ci.113.1"

    def entry(self):
        return {"id": "ArcForges.Consumer", "kind": "managed", "dependencies": ["ArcForges.Foundation"],
                "externalDependencies": {"ArcForges.Contracts.Foundation": self.external_version},
                "requiredFiles": ["README.md"]}

    def metadata(self, rows):
        metadata = ET.Element("metadata")
        group = ET.SubElement(ET.SubElement(metadata, "dependencies"), "group", targetFramework="net10.0")
        for name, pin in rows:
            ET.SubElement(group, "dependency", id=name, version=pin)
        return metadata

    def test_mixed_dependencies_keep_independent_versions(self):
        expected = {"ArcForges.Foundation": self.owned_version,
                    "ArcForges.Contracts.Foundation": self.external_version}
        self.assertEqual(expected, packages.dependency_versions(self.entry(), self.owned_version))
        for external in [self.external_version, f"[{self.external_version}]"]:
            metadata = self.metadata([("ArcForges.Foundation", self.owned_version),
                                      ("ArcForges.Contracts.Foundation", external)])
            self.assertEqual(expected, packages.validate_generated_dependencies(metadata, self.entry(), self.owned_version))

    def test_invalid_external_pins_are_rejected(self):
        for pin in ["1.*", "[1.0.0,2.0.0)", "[1.0.0]", "1.0.0+build", "1.0.0-ci.01", "", 1]:
            entry = self.entry()
            entry["externalDependencies"]["ArcForges.Contracts.Foundation"] = pin
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                packages.dependency_versions(entry, self.owned_version)

    def test_duplicate_and_overlapping_ids_are_rejected(self):
        for mutation in [lambda entry: entry["dependencies"].append("arcforges.foundation"),
                         lambda entry: entry["externalDependencies"].update({"arcforges.foundation": "1.0.0"}),
                         lambda entry: entry["externalDependencies"].update({"arcforges.contracts.foundation": "1.0.0"})]:
            entry = self.entry()
            mutation(entry)
            with self.assertRaisesRegex(ValueError, "Duplicate or overlapping"):
                packages.dependency_versions(entry, self.owned_version)

    def test_nonmanaged_external_dependencies_are_rejected(self):
        for kind in ["build", "native"]:
            entry = self.entry()
            entry["kind"] = kind
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "managed"):
                packages.dependency_versions(entry, self.owned_version)

    def test_external_generated_version_cannot_be_rewritten_into_admission(self):
        for pin in [self.owned_version, "1.0.0", f"[{self.external_version}, )", "1.*"]:
            metadata = self.metadata([("ArcForges.Foundation", self.owned_version),
                                      ("ArcForges.Contracts.Foundation", pin)])
            with self.subTest(pin=pin), self.assertRaisesRegex(ValueError, "exact admitted pin"):
                packages.validate_generated_dependencies(metadata, self.entry(), self.owned_version)

    def test_generated_dependency_set_and_duplicate_ids_fail_closed(self):
        correct = [("ArcForges.Foundation", self.owned_version), ("ArcForges.Contracts.Foundation", self.external_version)]
        for rows in [correct[:1], correct + [("Unexpected", "1.0.0")],
                     correct + [("arcforges.contracts.foundation", self.external_version)]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                packages.validate_generated_dependencies(self.metadata(rows), self.entry(), self.owned_version)

    def test_native_owned_pairs_remain_injected_after_generation(self):
        entry = {"kind": "native", "dependencies": ["ArcForges.Native.Image"]}
        self.assertEqual({"ArcForges.Native.Image": self.owned_version},
                         packages.validate_generated_dependencies(self.metadata([]), entry, self.owned_version))

    def test_catalogue_separates_external_and_owned_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "eng/packaging").mkdir(parents=True)
            (root / "consumer.csproj").write_text("<Project />", encoding="utf-8")
            entry = self.entry()
            entry["project"] = "consumer.csproj"
            owned = {"id": "ArcForges.Foundation", "kind": "managed", "project": "consumer.csproj"}
            document = {"schemaVersion": 1, "packages": [entry, owned]}
            inventory = root / "eng/packaging/packages.json"
            with patch.object(packages, "ROOT", root):
                inventory.write_text(json.dumps(document), encoding="utf-8")
                self.assertEqual(2, len(packages.catalogue()))
                entry["externalDependencies"]["arcforges.consumer"] = "1.0.0"
                inventory.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "aliases an owned"):
                    packages.catalogue()
                del entry["externalDependencies"]["arcforges.consumer"]
                entry["dependencies"] = ["Missing"]
                inventory.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "absent from the publication"):
                    packages.catalogue()

    def test_synthetic_nuspec_inspection_enforces_exact_external_pin(self):
        entry = self.entry()
        commit = "a" * 40
        expected = [("ArcForges.Foundation", f"[{self.owned_version}]"),
                    ("ArcForges.Contracts.Foundation", f"[{self.external_version}]")]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.nupkg"
            for rows, valid in [(expected, True), (expected[:1], False),
                                ([expected[0], (expected[1][0], self.external_version)], False),
                                ([expected[0], (expected[1][0], f"[{self.owned_version}]")], False),
                                (expected + [("arcforges.contracts.foundation", expected[1][1])], False)]:
                metadata = self.metadata(rows)
                for name, value in [("id", entry["id"]), ("version", self.owned_version), ("readme", "README.md")]:
                    ET.SubElement(metadata, name).text = value
                ET.SubElement(metadata, "repository", url=packages.REPOSITORY, commit=commit)
                ET.SubElement(metadata, "license", type="expression").text = "AGPL-3.0-only"
                specification = ET.Element("package")
                specification.append(metadata)
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("fixture.nuspec", ET.tostring(specification))
                    archive.writestr("README.md", "Synthetic metadata guard fixture, not a compiled candidate.")
                with self.subTest(rows=rows):
                    if valid:
                        self.assertEqual(64, len(packages.inspect(path, entry, self.owned_version, commit)))
                    else:
                        with self.assertRaises(ValueError):
                            packages.inspect(path, entry, self.owned_version, commit)


class AssistantAbstractionsPackageGuards(unittest.TestCase):
    owned_version = "2.0.0-ci.20.1"
    external_version = "1.0.0-ci.113.1"
    owned_edges = ["ArcForges.Foundation", "ArcForges.Application.Abstractions"]

    def entry(self):
        return next(item for item in packages.catalogue() if item["id"] == "ArcForges.Assistant.Abstractions")

    def metadata(self, rows):
        metadata = ET.Element("metadata")
        group = ET.SubElement(ET.SubElement(metadata, "dependencies"), "group", targetFramework="net10.0")
        for name, pin in rows:
            ET.SubElement(group, "dependency", id=name, version=pin)
        return metadata

    def test_allowlist_is_exact_architecture_27_owned_edges_and_existing_external_closure(self):
        entry = self.entry()
        self.assertEqual("managed", entry["kind"])
        self.assertEqual("src/BuildingBlocks/ArcForges.Assistant.Abstractions/ArcForges.Assistant.Abstractions.csproj",
                         entry["project"])
        self.assertEqual(self.owned_edges, entry["dependencies"])
        self.assertEqual({"ArcForges.Contracts.Foundation": self.external_version}, entry["externalDependencies"])
        self.assertEqual({**{name: self.owned_version for name in self.owned_edges},
                          "ArcForges.Contracts.Foundation": self.external_version},
                         packages.dependency_versions(entry, self.owned_version))

    def test_nuspec_dependency_set_cannot_drop_add_or_repin_an_edge(self):
        entry = self.entry()
        correct = [(name, f"[{self.owned_version}]") for name in self.owned_edges]
        correct.append(("ArcForges.Contracts.Foundation", f"[{self.external_version}]"))
        expected = packages.dependency_versions(entry, self.owned_version)
        self.assertEqual(expected, packages.validate_generated_dependencies(self.metadata(correct), entry, self.owned_version))

        for rows in [correct[:-1], correct + [("ArcForges.Capabilities", f"[{self.owned_version}]")],
                     [*correct[:-1], ("ArcForges.Contracts.Foundation", "[1.0.0-ci.216.1]")]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                packages.validate_generated_dependencies(self.metadata(rows), entry, self.owned_version)

        altered = dict(entry)
        altered["dependencies"] = [*entry["dependencies"], "ArcForges.Capabilities"]
        with self.assertRaisesRegex(ValueError, "dependency set"):
            packages.validate_generated_dependencies(self.metadata(correct), altered, self.owned_version)

        altered = dict(entry)
        altered["externalDependencies"] = {"ArcForges.Contracts.Foundation": "1.0.0-ci.216.1"}
        with self.assertRaisesRegex(ValueError, "exact admitted pin"):
            packages.validate_generated_dependencies(self.metadata(correct), altered, self.owned_version)


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
