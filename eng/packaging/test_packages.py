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


class NonWireMetadataPackageGuards(unittest.TestCase):
    def test_actual_build_policy_catalogue_requires_the_nonwire_helper(self):
        entry = next(item for item in packages.catalogue() if item["id"] == "ArcForges.Build.Policy")
        helper = "tools/architecture/NonWireMetadataPolicy.cs"
        self.assertEqual(1, entry["requiredFiles"].count(helper))
        version, commit = "1.0.0-ci.1.1", "a" * 40
        specification = ET.Element("package")
        metadata = ET.SubElement(specification, "metadata")
        for name, value in [("id", entry["id"]), ("version", version), ("readme", "README.md")]:
            ET.SubElement(metadata, name).text = value
        ET.SubElement(metadata, "repository", url=packages.REPOSITORY, commit=commit)
        ET.SubElement(metadata, "license", type="expression").text = "AGPL-3.0-only"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metadata-content-guard.nupkg"
            for include_helper in [False, True]:
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("guard.nuspec", ET.tostring(specification))
                    for name in entry["requiredFiles"]:
                        if name != helper or include_helper:
                            archive.writestr(name, "Synthetic presence-guard fixture, not a production candidate.")
                if include_helper:
                    self.assertEqual(64, len(packages.inspect(path, entry, version, commit)))
                else:
                    with self.assertRaisesRegex(ValueError, "Missing package content"):
                        packages.inspect(path, entry, version, commit)


class ExternalDependencyGuards(unittest.TestCase):
    owned_version = "2.0.0-ci.20.1"
    external_version = "1.0.0-ci.216.1"

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
    external_version = "1.0.0-ci.324.1"
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
                     [*correct[:-1], ("ArcForges.Contracts.Foundation", "[1.0.0-ci.113.1]")]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                packages.validate_generated_dependencies(self.metadata(rows), entry, self.owned_version)

        altered = dict(entry)
        altered["dependencies"] = [*entry["dependencies"], "ArcForges.Capabilities"]
        with self.assertRaisesRegex(ValueError, "dependency set"):
            packages.validate_generated_dependencies(self.metadata(correct), altered, self.owned_version)

        altered = dict(entry)
        altered["externalDependencies"] = {"ArcForges.Contracts.Foundation": "1.0.0-ci.113.1"}
        with self.assertRaisesRegex(ValueError, "exact admitted pin"):
            packages.validate_generated_dependencies(self.metadata(correct), altered, self.owned_version)


class FunctionalNativeRegistryGuards(unittest.TestCase):
    """Offline registry contracts only; temporary metadata is not a compiled native artifact."""

    def test_actual_registry_declares_closed_functional_families(self):
        for entry in packages.catalogue():
            if entry["kind"] == "native":
                version, exports = packages.native.abi_contract(entry)
                self.assertEqual({"major": 1, "minor": 1}, version)
                self.assertEqual(version, entry["abi"])
                self.assertEqual(sorted(exports), entry["exports"])

    def test_registry_cannot_admit_probe_missing_duplicate_foreign_or_unversioned_exports(self):
        entry = {"id": "ArcForges.Native.Image.Runtime.win-x64", "kind": "native", "project": "fixture.csproj",
                 "prefix": "arc_image", "library": "ArcImageNative", "dependencies": []}
        version, exports = packages.native.abi_contract(entry)
        entry.update(abi=version, exports=sorted(exports))
        mutations = [{"exports": sorted(exports)[:3]}, {"exports": sorted(exports) + ["upstream_cpp_symbol"]},
                     {"exports": sorted(exports) + [sorted(exports)[0]]}, {"exports": None},
                     {"abi": {"major": 1, "minor": 0}}, {"abi": {"major": 1, "minor": 2}},
                     {"abi": {"major": True, "minor": 1}}, {"abi": {}},
                     {"prefix": "caller"}, {"library": "ArcPdfNative"}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "eng/packaging").mkdir(parents=True)
            (root / "fixture.csproj").write_text("<Project />", encoding="utf-8")
            inventory = root / "eng/packaging/packages.json"
            with patch.object(packages, "ROOT", root):
                inventory.write_text(json.dumps({"schemaVersion": 1, "packages": [entry]}), encoding="utf-8")
                self.assertEqual([entry], packages.catalogue())
                for mutation in mutations:
                    invalid = {**entry, **mutation}
                    inventory.write_text(json.dumps({"schemaVersion": 1, "packages": [invalid]}), encoding="utf-8")
                    with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                        packages.catalogue()


class ImageProductionAdapterGuards(unittest.TestCase):
    def test_portable_or_receipted_image_payload_cannot_fall_back_to_legacy_probe_validation(self):
        for rid, receipt in (("linux-x64", False), ("win-x64", True)):
            entry = {"id": "ArcForges.Native.Image.Runtime." + rid, "kind": "native", "rid": rid,
                     "library": "ArcImageNative", "requiredFiles": []}
            metadata = ET.Element("metadata")
            for name, value in (("id", entry["id"]), ("version", "1.0.0"), ("readme", "README.md")):
                ET.SubElement(metadata, name).text = value
            ET.SubElement(metadata, "repository", url=packages.REPOSITORY, commit="a" * 40)
            ET.SubElement(metadata, "license", type="expression").text = "AGPL-3.0-only"
            specification = ET.Element("package")
            specification.append(metadata)
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "untrusted.nupkg"
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("candidate.nuspec", ET.tostring(specification))
                    if receipt:
                        archive.writestr(packages.image_runtime.RECEIPT, "{}")
                with self.subTest(rid=rid), self.assertRaisesRegex(ValueError, "Image production"):
                    packages.inspect(path, entry, "1.0.0", "a" * 40)


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

    def test_native_manifest_requires_exact_functional_minor_and_closed_major(self):
        for abi in [{"major": 1, "minor": 0}, {"major": 1, "minor": 2}, {"major": 2, "minor": 1}, None]:
            def tamper(files, _, abi=abi):
                document = json.loads(files["native-manifest.json"])
                if abi is None:
                    document.pop("abi")
                else:
                    document["abi"] = abi
                encoded = json.dumps(document).encode()
                files["native-manifest.json"] = encoded
                files["runtimes/win-x64/native/ArcImageNative.manifest.json"] = encoded
            target, manifest = self.mutate_native(tamper)
            with self.subTest(abi=abi), self.assertRaisesRegex(ValueError, "ABI manifest version"):
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



class NativeActiveSubsetGuards(unittest.TestCase):
    def fixture(self):
        build = packages.build_identity.build_identity(packages.ROOT)
        return {'schemaVersion': 2, 'sourceCommit': build['sourceCommit'], 'rid': 'multi', 'build': build,
                'familyIndexSha256': 'a'*64,
                'packages': [{'id': 'ArcForges.Native.Image.Runtime.win-x64'}]}

    def test_all_managed_and_only_actual_native_coordinates_are_selected(self):
        artifact = self.fixture()
        selected = packages.publication_entries(artifact, artifact['sourceCommit'])
        catalogue = packages.catalogue()
        self.assertEqual({entry['id'] for entry in catalogue if entry['kind'] != 'native'},
                         {entry['id'] for entry in selected if entry['kind'] != 'native'})
        self.assertEqual({'ArcForges.Native.Image.Runtime.win-x64'},
                         {entry['id'] for entry in selected if entry['kind'] == 'native'})
        self.assertNotIn('ArcForges.Native.Pdf.Runtime.osx-arm64', {entry['id'] for entry in selected})

    def test_empty_duplicate_unregistered_foreign_source_and_index_refuse(self):
        for mode in ('empty', 'duplicate', 'unregistered', 'foreign-source', 'index'):
            artifact = self.fixture(); commit = artifact['sourceCommit']
            if mode == 'empty': artifact['packages'] = []
            elif mode == 'duplicate': artifact['packages'] *= 2
            elif mode == 'unregistered': artifact['packages'] = [{'id': 'Caller.Native.Runtime.win-x64'}]
            elif mode == 'foreign-source': artifact['sourceCommit'] = 'b'*40
            else: artifact['familyIndexSha256'] = 'invalid'
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                packages.publication_entries(artifact, commit)

    def test_catalogue_cannot_activate_a_managed_producer_with_an_absent_native_dependency(self):
        artifact = self.fixture()
        entries = json.loads(json.dumps(packages.catalogue()))
        next(entry for entry in entries if entry['id'] == 'ArcForges.Native.Image')['dependencies'].append(
            'ArcForges.Native.Pdf.Runtime.osx-arm64')
        with patch.object(packages, 'catalogue', return_value=entries), self.assertRaisesRegex(ValueError, 'mandatory owned dependency'):
            packages.publication_entries(artifact, artifact['sourceCommit'])


class NativePublicationHandoffGuards(unittest.TestCase):
    """Real filesystem receipt binding; synthetic records never claim native deployment."""
    def prepare(self, root):
        native = packages.native
        commit, build = "a" * 40, {"component-test-cohort": "not-a-deployment"}
        rows, entries = [], []
        for family in ("Image", "Pdf"):
            identifier = "ArcForges.Native." + family + ".Runtime.win-x64"
            package = {"id": identifier, "files": [{"path": "native-manifest.json", "sha256": "b" * 64}]}
            relative = ".native-inputs/" + family + "-win-x64"
            receipt = {"schemaVersion": 1, "sourceCommit": commit, "rid": "win-x64", "build": build, "packages": [package]}
            native.write_json(root / relative / "native-artifact.json", receipt)
            rows.append({"family": family, "rid": "win-x64", "directory": relative,
                         "artifactSha256": native.digest(root / relative / "native-artifact.json")})
            entries.append(package)
        index = {"schemaVersion": 1, "sourceCommit": commit, "inputs": rows}
        native.write_json(root / "native-family-index.json", index)
        artifact = {"schemaVersion": 2, "sourceCommit": commit, "rid": "multi", "build": build, "packages": entries,
                    "familyIndexSha256": native.digest(root / "native-family-index.json")}
        return artifact, index, commit

    def test_exact_records_and_package_inventory_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact, index, commit = self.prepare(root)
            self.assertEqual(index, packages.native.verify_package_handoff(root, artifact, commit))
            artifact["packages"][0]["files"][0]["sha256"] = "c" * 64
            with self.assertRaisesRegex(ValueError, "inventory"):
                packages.native.verify_package_handoff(root, artifact, commit)

    def test_index_tamper_and_rehashed_escaped_duplicate_coordinates_refuse(self):
        for mode in ("tamper", "escape", "duplicate", "source", "extra-field"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                artifact, index, commit = self.prepare(root)
                if mode == "escape": index["inputs"][0]["directory"] = "../foreign"
                elif mode == "duplicate": index["inputs"][1] = index["inputs"][0]
                elif mode == "source": index["sourceCommit"] = "d" * 40
                elif mode == "extra-field": index["publisher"] = "fake"
                else: index["inputs"][0]["artifactSha256"] = "e" * 64
                packages.native.write_json(root / "native-family-index.json", index)
                if mode != "tamper": artifact["familyIndexSha256"] = packages.native.digest(root / "native-family-index.json")
                with self.assertRaises(ValueError): packages.native.verify_package_handoff(root, artifact, commit)

    def test_receipt_changes_foreign_cohort_and_extra_material_refuse(self):
        for mode in ("bytes", "cohort", "coordinate", "extra"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                artifact, index, commit = self.prepare(root)
                path = root / index["inputs"][0]["directory"] / "native-artifact.json"
                if mode == "extra": (path.parent / "unexpected.json").write_text("{}", encoding="utf-8")
                else:
                    receipt = json.loads(path.read_text(encoding="utf-8"))
                    if mode == "cohort": receipt["build"] = {"foreign": "cohort"}
                    elif mode == "coordinate": receipt["packages"][0]["id"] = "ArcForges.Native.Pdf.Runtime.win-x64"
                    else: receipt["sourceCommit"] = "d" * 40
                    packages.native.write_json(path, receipt)
                    if mode != "bytes":
                        index["inputs"][0]["artifactSha256"] = packages.native.digest(path)
                        packages.native.write_json(root / "native-family-index.json", index)
                        artifact["familyIndexSha256"] = packages.native.digest(root / "native-family-index.json")
                with self.assertRaises(ValueError): packages.native.verify_package_handoff(root, artifact, commit)


if __name__ == "__main__":
    unittest.main()
