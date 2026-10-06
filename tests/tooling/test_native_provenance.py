# SPDX-License-Identifier: AGPL-3.0-only
"""Independent negative cases for the native package trust boundary."""

import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eng"))
import native_provenance as native
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eng/packaging"))
import native as producer


@unittest.skipUnless(os.environ.get("ARCFORGES_PDF_SEALED_TEST_INPUT"), "Actual source-bound PDF producer input is required; no mocked native proof.")
class PdfSealedCompositionTests(unittest.TestCase):
    def setUp(self):
        self.original = Path(os.environ["ARCFORGES_PDF_SEALED_TEST_INPUT"])
        self.source = json.loads((self.original / "pdfium-production-input.json").read_text(encoding="utf-8"))["sourceCommit"]

    def test_actual_complete_sdk_engine_legal_crt_and_source_handoff(self):
        result = native.verify_pdf_runtime_input(self.original, self.source)
        self.assertEqual("ArcPdfNative.dll", next(row["name"] for row in result["inspectedBinaries"] if row["name"] == "ArcPdfNative.dll"))
        self.assertEqual(15, len(native.pdfium_profile()["legalFiles"]))

    def test_changed_dependency_legal_attestation_and_header_refuse_even_when_inventory_is_rewritten(self):
        for path in ["provenance/pdfium-attestation.json", "licenses/pdfium/pdfium.txt", "include/arc/arc_pdf_abi.h",
                     "runtimes/win-x64/native/pdfium.dll", "runtimes/win-x64/native/msvcp140.dll"]:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temporary:
                candidate = Path(temporary) / "candidate"
                shutil.copytree(self.original, candidate)
                target = candidate / path
                target.write_bytes(target.read_bytes() + b"tampered")
                receipt = json.loads((candidate / "pdfium-production-input.json").read_text(encoding="utf-8"))
                next(row for row in receipt["files"] if row["path"] == path)["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
                (candidate / "pdfium-production-input.json").write_bytes(native.canonical(receipt))
                with self.assertRaises(ValueError):
                    native.verify_pdf_runtime_input(candidate, self.source)

    def test_mixed_source_forged_admission_and_extra_files_refuse(self):
        for mutation in ("source", "admission", "extra"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                candidate = Path(temporary) / "candidate"
                shutil.copytree(self.original, candidate)
                receipt_path = candidate / "pdfium-production-input.json"
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                if mutation == "source":
                    receipt["sourceCommit"] = "a" * 40
                elif mutation == "admission":
                    receipt["admission"]["recipeCommit"] = "b" * 40
                else:
                    (candidate / "extra.bin").write_bytes(b"undeclared")
                receipt_path.write_bytes(native.canonical(receipt))
                with self.assertRaises(ValueError):
                    native.verify_pdf_runtime_input(candidate, self.source)

    def test_duplicate_receipt_fields_are_rejected_before_any_native_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate"
            shutil.copytree(self.original, candidate)
            path = candidate / "pdfium-production-input.json"
            path.write_bytes(path.read_bytes().replace(b'"schemaVersion": 1,', b'"schemaVersion": 1,"schemaVersion": 1,', 1))
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                native.verify_pdf_runtime_input(candidate, self.source)


class NativeClosureTests(unittest.TestCase):
    def setUp(self):
        self.package = "Example.Runtime.win-x64"
        self.dll = "runtimes/win-x64/native/vcruntime140.dll"
        self.files = {
            "licenses/example-x64-windows.txt": b"Original full licence\n",
            "licenses/example-x64-windows.abi.txt": b"cmake 4.4.0\ntriplet x64-windows\n",
            "licenses/provenance/required.txt": b"Required subordinate copyright and permission.\n",
            "recipes/example/portfile.cmake": b"reviewed recipe\n",
            "recipes/toolchains/x64-windows.cmake": b"reviewed toolset pin\n",
            "recipes/toolchains/upstream-x64-windows.cmake": b"standard triplet\n",
            "licenses/provenance/vcpkg-LICENSE.txt": b"Original toolchain MIT permission and copyright\n",
            "sources/example.tar.gz": b"exact matching original source archive",
            self.dll: b"approved vendor object bytes",
            "runtimes/win-x64/native/Example.dll": b"owned compiled bytes",
        }
        self.runtime = {"sha256": hashlib.sha256(self.files[self.dll]).hexdigest(), "productVersion": "1.2.3.4",
                        "fileVersion": "1.2.3.4", "publisher": "Example Vendor"}
        self.dependency = {"name": "example", "triplet": "x64-windows", "version": "1.0", "features": []}
        resource = {"url": "https://example.org/src.tar.gz", "sha512": "a" * 128}
        self.component = {
            "record": "example-r1", "version": "1.0", "role": "runtime-input", "scope": "Reviewed selected scope.",
            "source": {"repository": "https://example.org/repo", "commit": "b" * 40, "spdx": "MIT"},
            "resources": [resource], "recipe": {"files": {"portfile.cmake": hashlib.sha256(self.files["recipes/example/portfile.cmake"]).hexdigest()}},
            "legal": [{"path": "licenses/example-x64-windows.txt", "sha256": hashlib.sha256(self.files["licenses/example-x64-windows.txt"]).hexdigest()}],
            "extras": [{"output": "licenses/provenance/required.txt", "sha256": hashlib.sha256(self.files["licenses/provenance/required.txt"]).hexdigest()}],
            "correspondingSource": {"path": "sources/example.tar.gz", "url": "https://example.org/src.tar.gz",
                                    "sha512": hashlib.sha512(self.files["sources/example.tar.gz"]).hexdigest()},
        }
        self.value = {"components": {"example": self.component}, "cachedResourceOmissions": ["vcpkg-tool-meson"],
                      "buildTools": {"ownedCMake": "4.3.3", "ownedNinja": "1.13.1", "vcpkgCMake": "4.4.0", "msvcToolset": "14.51.36231"},
                      "packages": {self.package: {"dependencies": [self.dependency], "dlls": ["Example.dll", "vcruntime140.dll"]}},
                      "platformRuntime": {"id": "vendor-r1", "files": {"vcruntime140.dll": self.runtime}, "legal": [],
                                          "distributionIdentity": {"directoryVersion": "1.2.3"}, "notice": "Separate vendor terms."}}
        triplet = {"sha256": hashlib.sha256(self.files["recipes/toolchains/x64-windows.cmake"]).hexdigest(),
                   "upstreamSha256": hashlib.sha256(self.files["recipes/toolchains/upstream-x64-windows.cmake"]).hexdigest(),
                   "upstreamLicenceSha256": hashlib.sha256(self.files["licenses/provenance/vcpkg-LICENSE.txt"]).hexdigest()}
        self.value["triplets"] = {"x64-windows": triplet}
        self.files["licenses/example-x64-windows.abi.txt"] += ("triplet_abi " + triplet["sha256"] + "-toolchain-compiler\n"
            + "additional_file_0 " + triplet["upstreamSha256"] + "\n").encode()
        self.sbom = {"sourceCommit": "c" * 40, "buildTools": dict(self.value["buildTools"]), "buildDependencies": [{**self.dependency,
            "license": "licenses/example-x64-windows.txt", "sbom": "licenses/example-x64-windows.spdx.json",
            "buildInfo": "licenses/example-x64-windows.abi.txt",
            "sourceArchive": "sources/example.tar.gz", "sourceUrl": "https://example.org/src.tar.gz"}],
            "visualCppRuntime": {"record": "vendor-r1", "redistributableDirectoryVersion": "1.2.3",
                                 "files": [{"name": "vcruntime140.dll", **self.runtime}]}}
        self.spdx = {"packages": [{"SPDXID": "SPDXRef-resource-0", "downloadLocation": resource["url"],
                                  "checksums": [{"algorithm": "SHA512", "checksumValue": resource["sha512"]}]}]}
        self.refresh()

    def refresh(self):
        self.files["sbom.json"] = json.dumps(self.sbom).encode()
        self.files["licenses/example-x64-windows.spdx.json"] = json.dumps(self.spdx).encode()
        self.files[native.NOTICE] = native.native_notice(self.value, self.package)
        self.files["NOTICE.md"] = b"Package attribution\n" + self.files[native.NOTICE]

    def inspect(self):
        return native.inspect_material(self.value, self.package, self.files.__getitem__, set(self.files))

    def test_accepts_complete_reviewed_closure(self):
        self.assertEqual(self.inspect()["records"], ["example-r1"])

    def test_rejects_unreviewed_upstream_generator_missing_or_duplicate_identity(self):
        for content in [b"cmake 4.4.3\ntriplet x64-windows\n", b"triplet x64-windows\n",
                        b"cmake 4.4.0\ncmake 4.4.0\ntriplet x64-windows\n",
                        b"cmake 4.4.0\ntriplet arm64-windows\n"]:
            with self.subTest(content=content):
                self.files["licenses/example-x64-windows.abi.txt"] = content
                with self.assertRaisesRegex(ValueError, "upstream build generator/triplet"):
                    self.inspect()

    def test_rejects_unreviewed_owned_tools_in_candidate(self):
        self.sbom["buildTools"]["ownedCMake"] = "4.4.3"
        self.refresh()
        with self.assertRaisesRegex(ValueError, "native build tools in SBOM"):
            self.inspect()

    def test_rejects_dependency_built_without_reviewed_toolset_overlay(self):
        name = "licenses/example-x64-windows.abi.txt"
        self.files[name] = self.files[name].replace(self.value["triplets"]["x64-windows"]["sha256"].encode(), b"0" * 64)
        with self.assertRaisesRegex(ValueError, "upstream compiler selection"):
            self.inspect()

    def test_rejects_missing_required_companion_and_changed_recipe(self):
        for path in ["licenses/provenance/required.txt", "recipes/example/portfile.cmake"]:
            with self.subTest(path=path):
                original = self.files.pop(path)
                with self.assertRaisesRegex(ValueError, "missing native legal/recipe"):
                    self.inspect()
                self.files[path] = original + b"changed"
                with self.assertRaisesRegex(ValueError, "native legal/recipe"):
                    self.inspect()
                self.files[path] = original

    def test_rejects_new_unclassified_legal_recipe_and_source_members(self):
        for path in ["licenses/new.txt", "recipes/new.cmake", "sources/unreviewed.tar.gz"]:
            with self.subTest(path=path):
                self.files[path] = b"unreviewed"
                with self.assertRaisesRegex(ValueError, "Unclassified native"):
                    self.inspect()
                del self.files[path]

    def test_rejects_changed_source_url_or_checksum(self):
        for field, value in [("downloadLocation", "https://other.example/source.tar.gz"),
                             ("checksums", [{"algorithm": "SHA512", "checksumValue": "d" * 128}])]:
            with self.subTest(field=field):
                original = self.spdx["packages"][0][field]
                self.spdx["packages"][0][field] = value
                self.refresh()
                with self.assertRaisesRegex(ValueError, "Changed native source archives"):
                    self.inspect()
                self.spdx["packages"][0][field] = original

    def test_rejects_changed_feature_version_and_duplicate_dependency(self):
        for field, value in [("features", ["gpl"]), ("version", "2.0"), ("triplet", "arm64-windows")]:
            with self.subTest(field=field):
                original = self.sbom["buildDependencies"][0][field]
                self.sbom["buildDependencies"][0][field] = value
                self.refresh()
                with self.assertRaisesRegex(ValueError, "dependency/version/feature closure"):
                    self.inspect()
                self.sbom["buildDependencies"][0][field] = original
        self.sbom["buildDependencies"].append(copy.deepcopy(self.sbom["buildDependencies"][0]))
        self.refresh()
        with self.assertRaisesRegex(ValueError, "dependency/version/feature closure"):
            self.inspect()

    def test_rejects_changed_corresponding_source_and_false_identity(self):
        original = self.files["sources/example.tar.gz"]
        self.files["sources/example.tar.gz"] = b"different source"
        with self.assertRaisesRegex(ValueError, "Changed corresponding-source archive"):
            self.inspect()
        self.files["sources/example.tar.gz"] = original
        self.sbom["buildDependencies"][0]["sourceUrl"] = "https://example.org/new.tar.gz"
        self.refresh()
        with self.assertRaisesRegex(ValueError, "corresponding-source identity"):
            self.inspect()

    def test_rejects_unapproved_vendor_bytes_and_false_version(self):
        original = self.files[self.dll]
        self.files[self.dll] += b"modification"
        with self.assertRaisesRegex(ValueError, "Unapproved compiler-runtime bytes"):
            self.inspect()
        self.files[self.dll] = original
        self.sbom["visualCppRuntime"]["files"][0]["productVersion"] = "0.0.0.0"
        self.refresh()
        with self.assertRaisesRegex(ValueError, "Compiler-runtime SBOM"):
            self.inspect()

    def test_rejects_unlisted_dll_and_case_collision(self):
        self.files["runtimes/win-x64/native/Unreviewed.dll"] = b"new vendor code"
        with self.assertRaisesRegex(ValueError, "binary membership"):
            self.inspect()
        del self.files["runtimes/win-x64/native/Unreviewed.dll"]
        self.files[self.dll.upper()] = b"ambiguous"
        with self.assertRaisesRegex(ValueError, "Case-colliding"):
            self.inspect()

    def test_rejects_removed_package_attribution(self):
        self.files["NOTICE.md"] = b"Only a licence hyperlink"
        with self.assertRaisesRegex(ValueError, "lost native provenance"):
            self.inspect()

    def test_signed_but_different_publisher_is_not_approved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vcruntime140.dll"
            path.write_bytes(self.files[self.dll])
            with patch.object(native, "signed_runtime", return_value={**self.runtime, "publisher": "Someone else", "signature": "valid"}):
                with self.assertRaisesRegex(ValueError, "publisher/version mismatch"):
                    native.approve_runtime(path, self.value)

    def test_candidate_receipt_does_not_self_authorize_unknown_member(self):
        material = self.inspect()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / native.PROFILE).parent.mkdir(parents=True)
            (root / native.PROFILE).write_bytes(b"approved profile")
            receipt = {"schemaVersion": 1, "sourceCommit": self.sbom["sourceCommit"], "package": self.package,
                       "profile": native.PROFILE, "profileSha256": hashlib.sha256(b"approved profile").hexdigest(),
                       **material, "signatureVerification": {"vcruntime140.dll": {**self.runtime, "signature": "valid"}},
                       "files": [{"path": p, "sha256": hashlib.sha256(data).hexdigest()} for p, data in self.files.items()]}
            self.files[native.RECEIPT] = json.dumps(receipt).encode()
            with patch.object(native, "profile", return_value=self.value):
                result = native.verify(self.package, self.files.__getitem__, set(self.files), root)
                self.assertEqual(result["result"], "passed")
                for path in ("unregistered/new-file.txt", "package/services/metadata/core-properties/extra.js", "unregistered/extra.nuspec"):
                    with self.subTest(path=path):
                        self.files[path] = b"unexpected resource"
                        with self.assertRaisesRegex(ValueError, "membership differs"):
                            native.verify(self.package, self.files.__getitem__, set(self.files), root)
                        del self.files[path]
                # Even forging the producer hash list cannot admit an unreviewed legal/resource file.
                self.files["licenses/unreviewed.txt"] = b"unreviewed"
                receipt["files"].append({"path": "licenses/unreviewed.txt", "sha256": hashlib.sha256(b"unreviewed").hexdigest()})
                self.files[native.RECEIPT] = json.dumps(receipt).encode()
                with self.assertRaisesRegex(ValueError, "Unclassified native"):
                    native.verify(self.package, self.files.__getitem__, set(self.files), root)


class ProducerBuildIdentityTests(unittest.TestCase):
    def test_actual_cache_versions_and_installed_root_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installed = root / "installed"
            profile = {"buildTools": {"ownedCMake": "4.3.3", "ownedNinja": "1.13.1", "vcpkgCMake": "4.4.0", "msvcToolset": "14.51.36231"}}
            cache_text = ("CMAKE_CACHE_MAJOR_VERSION:INTERNAL=4\nCMAKE_CACHE_MINOR_VERSION:INTERNAL=3\n"
                          "CMAKE_CACHE_PATCH_VERSION:INTERNAL=3\nCMAKE_MAKE_PROGRAM:FILEPATH=reviewed-ninja\n"
                          "CMAKE_C_COMPILER:STRING=C:/VS/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe\n"
                          "CMAKE_CXX_COMPILER:STRING=C:/VS/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe\n"
                          "VCPKG_INSTALLED_DIR:PATH=" + str(installed) + "\n")
            caches = []
            for name in ("shim-static",):
                cache = root / "artifacts/cmake/win-x64" / name / "CMakeCache.txt"
                cache.parent.mkdir(parents=True)
                cache.write_text(cache_text, encoding="utf-8")
                caches.append(cache)
            with patch.object(producer.subprocess, "check_output", return_value="1.13.1\n"):
                self.assertEqual(producer.owned_build_tools(profile, installed, root), profile["buildTools"])
                for old, new, error in [("MINOR_VERSION:INTERNAL=3", "MINOR_VERSION:INTERNAL=4", "CMake build generator"),
                                        (str(installed), str(root / "other"), "different installed dependency tree")]:
                    with self.subTest(error=error):
                        caches[0].write_text(cache_text.replace(old, new), encoding="utf-8")
                        with self.assertRaisesRegex(ValueError, error):
                            producer.owned_build_tools(profile, installed, root)
                        caches[0].write_text(cache_text, encoding="utf-8")
                caches[0].write_text(cache_text.replace("14.51.36231", "14.52.36725"), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "owned MSVC compiler"):
                    producer.owned_build_tools(profile, installed, root)
                caches[0].write_text(cache_text, encoding="utf-8")
            with patch.object(producer.subprocess, "check_output", return_value="1.13.2\n"):
                with self.assertRaisesRegex(ValueError, "Ninja build tool"):
                    producer.owned_build_tools(profile, installed, root)


class RetainedImageResourceTests(unittest.TestCase):
    def setUp(self):
        self.value = native.profile()
        self.name = "zlib"
        resource = self.value["components"][self.name]["resources"][0]
        self.resource = {"SPDXID": "SPDXRef-resource-0", "downloadLocation": resource["url"],
                         "checksums": [{"algorithm": "SHA512", "checksumValue": resource["sha512"]}]}

    def test_exact_retained_source_is_admitted(self):
        native.check_sources(self.value, self.name, {"packages": [self.resource]})
        self.assertEqual(self.value["cachedResourceOmissions"], [])
        self.assertEqual(set(self.value["packages"]), {"ArcForges.Native.Image.Runtime.win-x64"})

    def test_wrong_url_digest_extra_and_duplicate_resources_are_rejected(self):
        for field, changed in [("downloadLocation", "https://example.org/other.tar.gz"),
                               ("checksums", [{"algorithm": "SHA512", "checksumValue": "0" * 128}])]:
            value = copy.deepcopy(self.resource)
            value[field] = changed
            for packages in ([value], [self.resource, value]):
                with self.subTest(field=field, count=len(packages)), self.assertRaisesRegex(ValueError, "Changed native source archives"):
                    native.check_sources(self.value, self.name, {"packages": packages})
        with self.assertRaisesRegex(ValueError, "Changed native source archives"):
            native.check_sources(self.value, self.name, {"packages": [self.resource, self.resource]})

    def test_no_retained_source_omission_is_admitted(self):
        for name, component in self.value["components"].items():
            if component["resources"]:
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Changed native source archives"):
                    native.check_sources(self.value, name, {"packages": []})

class LegalExtractionTests(unittest.TestCase):
    def test_extracts_only_reviewed_legal_bytes_without_unpacking_links(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            file = base / "source.tar.gz"
            source = b"copyright \xa9 owner\r\nCODE MUST NOT BE COPIED"
            legal = "copyright © owner\n".encode()
            with tarfile.open(file, "w:gz") as archive:
                member = tarfile.TarInfo("source/include/header.h")
                member.size = len(source)
                archive.addfile(member, io.BytesIO(source))
            row = {"output": "licenses/provenance/terms.txt", "url": "https://example.org/source.tar.gz",
                   "sourceSha256": hashlib.sha256(file.read_bytes()).hexdigest(), "sourceSha512": None,
                   "cacheName": file.name, "member": "include/header.h", "memberSha256": hashlib.sha256(source).hexdigest(),
                   "start": 0, "end": source.index(b"CODE"), "encoding": "latin-1", "sha256": hashlib.sha256(legal).hexdigest(),
                   "description": "Legal preamble only."}
            native.asset(row)
            self.assertEqual(native.legal_bytes(row, base), legal)
            row["end"] = len(source)
            with self.assertRaisesRegex(ValueError, "Changed legal-text transformation"):
                native.legal_bytes(row, base)
            row["cacheName"] = "../source.tar.gz"
            with self.assertRaisesRegex(ValueError, "Escaping legal cache path"):
                native.asset(row)

    def test_source_cache_hash_must_match_before_use(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "source.tar.gz").write_bytes(b"altered cache")
            with self.assertRaisesRegex(ValueError, "Cached source bytes"):
                native.fetch("https://example.org/source.tar.gz", "0" * 64, "sha256", "source.tar.gz", base)

    def test_official_query_url_is_allowed_but_non_https_and_credentials_are_not(self):
        native.download_identity("https://github.com/example/source.patch?full_index=1")
        for value in ["http://example.org/source", "https://secret@example.org/source", "https://example.org/../source"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                native.download_identity(value)


class VendorLicenseFetchTests(unittest.TestCase):
    URLS = (
        "https://visualstudio.microsoft.com/wp-content/uploads/2025/10/Visual_Studio_2026-License-Community_ENU.docx",
        "https://visualstudio.microsoft.com/wp-content/uploads/2025/10/Visual-C-V14-License-Redistributable_and_Runtime_ENU.docx",
    )

    class Response(io.BytesIO):
        def __init__(self, content, url):
            super().__init__(content)
            self.url = url

    def test_only_the_two_exact_visual_studio_license_urls_receive_the_project_user_agent(self):
        payload = b"reviewed document bytes"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            for index, url in enumerate(self.URLS):
                with self.subTest(url=url):
                    response = self.Response(payload, url)
                    with patch.object(native.urllib.request, "urlopen", return_value=response) as open_source:
                        result = native.fetch(url, digest, "sha256", f"license-{index}.docx", Path(directory))
                    request = open_source.call_args.args[0]
                    self.assertIsInstance(request, native.urllib.request.Request)
                    self.assertEqual(request.full_url, url)
                    self.assertEqual(request.get_header("User-agent"), native.VISUAL_STUDIO_LICENSE_USER_AGENT)
                    self.assertEqual(result.read_bytes(), payload)

        unchanged_urls = (
            self.URLS[0] + "?download=1",
            self.URLS[0] + ".backup",
            "https://example.org/unrelated.docx",
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, url in enumerate(unchanged_urls):
                with self.subTest(url=url):
                    response = self.Response(payload, url)
                    with patch.object(native.urllib.request, "urlopen", return_value=response) as open_source:
                        native.fetch(url, digest, "sha256", f"other-{index}.docx", Path(directory))
                    self.assertEqual(open_source.call_args.args[0], url)

    def test_verified_cache_hit_skips_transport_for_visual_studio_license(self):
        url = self.URLS[0]
        payload = b"already verified"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            (cache / "license.docx").write_bytes(payload)
            with patch.object(native.urllib.request, "urlopen") as open_source:
                result = native.fetch(url, digest, "sha256", "license.docx", cache)
            open_source.assert_not_called()
            self.assertEqual(result.read_bytes(), payload)

    def test_http_403_propagates_without_promoting_a_cache_file(self):
        from urllib.error import HTTPError

        url = self.URLS[0]
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            error = HTTPError(url, 403, "Forbidden", {}, None)
            with patch.object(native.urllib.request, "urlopen", side_effect=error):
                with self.assertRaises(HTTPError):
                    native.fetch(url, "a" * 64, "sha256", "license.docx", cache)
            self.assertEqual(list(cache.iterdir()), [])

    def test_downloaded_checksum_mismatch_is_removed_not_cached(self):
        url = self.URLS[0]
        wrong = b"not the reviewed document"
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            response = self.Response(wrong, url)
            with patch.object(native.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(ValueError, "Downloaded source digest mismatch"):
                    native.fetch(url, "0" * 64, "sha256", "license.docx", cache)
            self.assertEqual(list(cache.iterdir()), [])


class PdfiumPrefixTests(unittest.TestCase):
    ARGS = b'pdf_enable_v8 = false\npdf_enable_xfa = false\ntarget_cpu = "x64"\ntarget_os = "win"\n'

    def test_complete_inventory_and_inactive_executable_features_are_required(self):
        with tempfile.TemporaryDirectory() as t:
            prefix=Path(t)
            args=prefix/'args.gn'
            args.write_bytes(self.ARGS)
            profile={'files':{'args.gn':native.sha(self.ARGS)},'configuration':{'target_cpu':'x64','target_os':'win'}}
            native.verify_pdfium_prefix(prefix,profile)
            extra=prefix/'unexpected.dll'
            extra.write_bytes(b'not admitted')
            with self.assertRaisesRegex(ValueError,'complete admitted archive'):
                native.verify_pdfium_prefix(prefix,profile)
            extra.unlink()
            for previous, replacement in ((b'pdf_enable_v8 = false',b'pdf_enable_v8 = true'),
                                          (b'pdf_enable_xfa = false',b'pdf_enable_xfa = true'),
                                          (b'target_cpu = "x64"',b'target_cpu = "arm64"')):
                with self.subTest(feature=previous):
                    changed=self.ARGS.replace(previous,replacement)
                    args.write_bytes(changed)
                    with self.assertRaisesRegex(ValueError,'features or RID'):
                        native.verify_pdfium_prefix(prefix,{'files':{'args.gn':native.sha(changed)},'configuration':{'target_cpu':'x64','target_os':'win'}})
            args.unlink()
            with self.assertRaisesRegex(ValueError,'complete admitted archive'):
                native.verify_pdfium_prefix(prefix,profile)

    def test_prefix_member_is_bounded_before_hashing(self):
        with tempfile.TemporaryDirectory() as t:
            prefix=Path(t)
            with (prefix/'args.gn').open('wb') as output:
                output.seek(8*1024*1024)
                output.write(b'x')
            with self.assertRaisesRegex(ValueError,'member exceeds'):
                native.verify_pdfium_prefix(prefix,{'files':{'args.gn':'0'*64}})

    def test_pdf_compiler_runtime_role_is_explicit_and_exact_existing_identity(self):
        profile=native.pdfium_profile()
        admission=profile['compilerRuntime']
        self.assertEqual(admission['target'],'pdfium-production-composition-input')
        self.assertEqual(admission['sha256'],native.sha((native.ROOT/admission['profile']).read_bytes(),'lf'))
        self.assertEqual(admission['review']['decision'],'approved')


class PdfiumTransferTests(unittest.TestCase):
    DATA = b'exact reviewed producer bytes'
    class Response(io.BytesIO):
        def __init__(self, data, url='https://example.org/pinned.tgz'):
            super().__init__(data)
            self.url = url
        def geturl(self):
            return self.url
    def identity(self, maximum=128):
        return {'url':'https://example.org/pinned.tgz','sha256':hashlib.sha256(self.DATA).hexdigest(),'maximumBytes':maximum}

    def test_matching_cache_never_fetches(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'bundle';path.write_bytes(self.DATA)
            with patch.object(native.urllib.request,'urlopen') as fetch:
                self.assertEqual(native.pdfium_download(self.identity(),path),path)
                fetch.assert_not_called()

    def test_oversized_cache_is_refused_before_read(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'bundle';path.write_bytes(self.DATA)
            with self.assertRaisesRegex(ValueError,'cache exceeds'):
                native.pdfium_download(self.identity(2),path)

    def test_transient_read_only_transfer_has_bounded_backoff(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'bundle'
            with patch.object(native.urllib.request,'urlopen',side_effect=[URLError('connection reset'),self.Response(self.DATA)]) as fetch, patch.object(native.time,'sleep') as sleep:
                native.pdfium_download(self.identity(),path)
                self.assertEqual(fetch.call_count,2);sleep.assert_called_once_with(0.5)
                self.assertEqual(path.read_bytes(),self.DATA)
                self.assertEqual(list(Path(t).iterdir()),[path])

    def test_repeated_transient_failure_stops_after_three_attempts(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'bundle'
            error=HTTPError('https://example.org/pinned.tgz',503,'unavailable',{},None)
            with patch.object(native.urllib.request,'urlopen',side_effect=error) as fetch, patch.object(native.time,'sleep') as sleep:
                with self.assertRaises(HTTPError):native.pdfium_download(self.identity(),path)
                self.assertEqual(fetch.call_count,3);self.assertEqual([x.args[0] for x in sleep.call_args_list],[0.5,2.0])
                self.assertEqual(list(Path(t).iterdir()),[])

    def test_permanent_denial_is_not_retried(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'bundle'
            error=HTTPError('https://example.org/pinned.tgz',403,'denied',{},None)
            with patch.object(native.urllib.request,'urlopen',side_effect=error) as fetch, patch.object(native.time,'sleep') as sleep:
                with self.assertRaises(HTTPError):native.pdfium_download(self.identity(),path)
                self.assertEqual(fetch.call_count,1);sleep.assert_not_called()
                self.assertFalse(path.exists())

    def test_integrity_failure_removes_partial_file_without_retry(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'bundle'
            with patch.object(native.urllib.request,'urlopen',return_value=self.Response(b'changed')) as fetch, patch.object(native.time,'sleep') as sleep:
                with self.assertRaisesRegex(ValueError,'digest mismatch'):native.pdfium_download(self.identity(),path)
                self.assertEqual(fetch.call_count,1);sleep.assert_not_called()
                self.assertEqual(list(Path(t).iterdir()),[])

    def test_streamed_size_overflow_removes_partial_file(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'bundle'
            with patch.object(native.urllib.request,'urlopen',return_value=self.Response(self.DATA)):
                with self.assertRaisesRegex(ValueError,'transfer exceeds'):native.pdfium_download(self.identity(2),path)
                self.assertEqual(list(Path(t).iterdir()),[])

    def test_https_downgrade_and_credentials_redirects_are_refused(self):
        for url in ('http://example.org/pinned.tgz', 'https://secret@example.org/pinned.tgz'):
            with self.subTest(url=url), tempfile.TemporaryDirectory() as t:
                with patch.object(native.urllib.request,'urlopen',return_value=self.Response(self.DATA,url)), patch.object(native.time,'sleep') as sleep:
                    with self.assertRaisesRegex(ValueError,'download URL'):
                        native.pdfium_download(self.identity(),Path(t)/'bundle')
                    sleep.assert_not_called()
                    self.assertEqual(list(Path(t).iterdir()),[])

    def test_pdf_producer_license_transfer_retains_exact_vendor_agent_and_tls_validation(self):
        with tempfile.TemporaryDirectory() as t:
            identity=self.identity()
            identity['url']=next(iter(native.VISUAL_STUDIO_LICENSE_URLS))
            with patch.object(native.urllib.request,'urlopen',return_value=self.Response(self.DATA,identity['url'])) as fetch:
                native.pdfium_download(identity,Path(t)/'license.docx')
            request=fetch.call_args.args[0]
            self.assertEqual(request.get_header('User-agent'),native.VISUAL_STUDIO_LICENSE_USER_AGENT)
            self.assertEqual(fetch.call_args.kwargs['context'].verify_mode,native.ssl.CERT_REQUIRED)
            self.assertTrue(fetch.call_args.kwargs['context'].check_hostname)

    def test_slow_progress_exhausts_deadline_and_tightens_read_timeout_without_retaining_partial_bytes(self):
        clock, timeouts = [0.0], []
        class SlowResponse(self.Response):
            def read1(self, size):
                clock[0] += 20
                return b'x'
        def fetch(*args, **kwargs):
            response = SlowResponse(b'')
            response.fp = SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(
                _closed=False, settimeout=timeouts.append)))
            return response
        def sleep(delay): clock[0] += delay
        with tempfile.TemporaryDirectory() as t, patch.object(native.time,'monotonic',side_effect=lambda:clock[0]), \
                patch.object(native.time,'sleep',side_effect=sleep), patch.object(native.urllib.request,'urlopen',side_effect=fetch) as open_request:
            with self.assertRaisesRegex(TimeoutError,'deadline exceeded'):
                native.pdfium_download(self.identity(),Path(t)/'bundle')
            self.assertEqual(open_request.call_count,3)
            self.assertTrue(all(0 < timeout <= 60 for timeout in timeouts))
            self.assertLessEqual(min(timeouts),20)
            self.assertEqual(list(Path(t).iterdir()),[])

class PdfiumAttestationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.archive = Path(self.directory.name) / 'pdfium-win-x64.tgz'
        self.bundle = Path(self.directory.name) / 'pdfium-attestation.json'
        self.value = native.pdfium_profile()
        self.statement = {'subject':[{'name':self.archive.name,'digest':{'sha256':self.value['archive']['sha256']}}],
                          'predicate':{'runDetails':{'metadata':{'invocationId':self.value['attestation']['invocation']}}}}
        self.refresh()
        self.result = subprocess.CompletedProcess([],0,stdout='[{}]',stderr='')

    def refresh(self):
        self.bundle.write_text(json.dumps({'dsseEnvelope':{'payload':base64.b64encode(json.dumps(self.statement).encode()).decode()}}))

    def verify(self):
        native.verify_pdfium_attestation(self.archive,self.bundle,self.value)

    def test_external_verifier_receives_every_strict_identity_constraint(self):
        with patch.object(native.subprocess,'run',return_value=self.result) as verifier:
            self.verify()
        args = verifier.call_args.args[0]
        self.assertIn('--deny-self-hosted-runners',args)
        self.assertEqual(args[args.index('--source-digest')+1],self.value['attestation']['recipeCommit'])
        self.assertEqual(args[args.index('--signer-workflow')+1],'bblanchon/pdfium-binaries/.github/workflows/build-all.yml')
        self.assertEqual(args[args.index('--repo')+1],'bblanchon/pdfium-binaries')
        self.assertTrue(verifier.call_args.kwargs['check'])

    def test_signed_subject_digest_must_match_the_admitted_archive(self):
        self.statement['subject'][0]['digest']['sha256']='0'*64;self.refresh()
        with patch.object(native.subprocess,'run',return_value=self.result):
            with self.assertRaisesRegex(ValueError,'admitted subject'):self.verify()

    def test_signed_producer_invocation_must_match(self):
        self.statement['predicate']['runDetails']['metadata']['invocationId']='changed';self.refresh()
        with patch.object(native.subprocess,'run',return_value=self.result):
            with self.assertRaisesRegex(ValueError,'invocation changed'):self.verify()

    def test_empty_success_response_is_not_an_approval(self):
        self.result.stdout='[]'
        with patch.object(native.subprocess,'run',return_value=self.result):
            with self.assertRaisesRegex(ValueError,'no receipt'):self.verify()

    def test_signature_or_authorization_rejection_is_not_retried(self):
        error=subprocess.CalledProcessError(1,['gh'],stderr='signature identity rejected')
        with patch.object(native.subprocess,'run',side_effect=error) as verifier,patch.object(native.time,'sleep') as sleep:
            with self.assertRaises(subprocess.CalledProcessError):self.verify()
            self.assertEqual(verifier.call_count,1);sleep.assert_not_called()

    def test_transient_verification_outage_retries_only_read_only_verification(self):
        error=subprocess.CalledProcessError(1,['gh'],stderr='HTTP 503: service unavailable')
        with patch.object(native.subprocess,'run',side_effect=[error,self.result]) as verifier,patch.object(native.time,'sleep') as sleep:
            self.verify();self.assertEqual(verifier.call_count,2);sleep.assert_called_once_with(0.5)
            self.assertEqual(verifier.call_args_list[0].args,verifier.call_args_list[1].args)

    def test_verification_timeouts_are_bounded_to_three_attempts(self):
        error=subprocess.TimeoutExpired(['gh'],120)
        with patch.object(native.subprocess,'run',side_effect=error) as verifier,patch.object(native.time,'sleep') as sleep:
            with self.assertRaises(subprocess.TimeoutExpired):self.verify()
            self.assertEqual(verifier.call_count,3);self.assertEqual([x.args[0] for x in sleep.call_args_list],[0.5,2.0])


class PdfiumAdmissionInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.value = copy.deepcopy(native.pdfium_profile())
        self.archive = self.directory / 'pdfium-win-x64.tgz'
        self.archive.write_bytes(b'first-party simulated external archive')
        self.value['archive']['sha256'] = native.sha(self.archive.read_bytes())
        statement = {'subject':[{'name':self.archive.name,'digest':{'sha256':self.value['archive']['sha256']}}],
                     'predicate':{'runDetails':{'metadata':{'invocationId':self.value['attestation']['invocation']}}}}
        self.bundle = self.directory / 'pdfium-attestation.json'
        self.bundle.write_bytes(json.dumps({'dsseEnvelope':{'payload':base64.b64encode(json.dumps(statement).encode()).decode()}}).encode())
        self.value['attestation']['sha256'] = native.sha(self.bundle.read_bytes())
        self.receipt = self.directory / 'pdfium-build-receipt.json'
        self.receipt.write_bytes(native.canonical(native.pdfium_admission_receipt(self.value)))
        self.result = subprocess.CompletedProcess([],0,stdout='[{}]',stderr='')

    def test_sealing_handoff_rechecks_actual_evidence_and_external_signature_verifier(self):
        with patch.object(native.subprocess,'run',return_value=self.result) as verifier:
            self.assertEqual(native.verify_pdfium_admission_input(self.directory,self.value),native.pdfium_admission_receipt(self.value))
            verifier.assert_called_once()
            self.assertIn('--deny-self-hosted-runners',verifier.call_args.args[0])

    def test_altered_actual_archive_or_bundle_is_refused_before_trust_claim(self):
        for path in (self.archive,self.bundle):
            with self.subTest(path=path):
                before = path.read_bytes()
                path.write_bytes(before+b'altered')
                with patch.object(native.subprocess,'run') as verifier:
                    with self.assertRaisesRegex(ValueError,'evidence digest changed'):
                        native.verify_pdfium_admission_input(self.directory,self.value)
                    verifier.assert_not_called()
                path.write_bytes(before)

    def test_forged_extra_duplicate_or_unbounded_receipt_is_refused(self):
        original = self.receipt.read_bytes()
        changed = native.pdfium_admission_receipt(self.value)
        changed['cryptographicVerification'] = 'self declared approval'
        for data in (native.canonical(changed), original.replace(b'\n}',b',\n  "extra": true\n}'),
                     original.replace(b'{',b'{"rid":"forged",',1), b'x'*(64*1024+1)):
            with self.subTest(size=len(data)), patch.object(native.subprocess,'run') as verifier:
                self.receipt.write_bytes(data)
                with self.assertRaises(ValueError): native.verify_pdfium_admission_input(self.directory,self.value)
                verifier.assert_not_called()


class PdfiumStagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.files = {'runtimes/win-x64/native/ArcPdfNative.dll': b'owned native bytes',
                      'provenance/pdfium-attestation.json': b'external signed bundle',
                      'provenance/pdfium-sbom.v1.json': b'{"sbom":true}\n',
                      'licenses/pdfium/legal.txt': b'complete legal text'}
        self.selected = {'arcpdfnative.dll': {'name':'ArcPdfNative.dll',
                                             'sha256':native.sha(self.files['runtimes/win-x64/native/ArcPdfNative.dll'])}}
        self.value = {'attestation':{'sha256':native.sha(self.files['provenance/pdfium-attestation.json']), 'maximumBytes':131072},
                      'sbom':{'sha256':native.sha(self.files['provenance/pdfium-sbom.v1.json'], 'lf')},
                      'legalFiles':{'third-party/pdfium/legal.txt':native.sha(self.files['licenses/pdfium/legal.txt'])}}
        self.receipt = {'profile':'exact reviewed receipt'}
        self.files['provenance/pdfium-build.v1.json'] = native.canonical(self.value)
        self.files['licenses/provenance/runtime-grant.docx'] = b'complete unmodified external grant'
        self.runtime_legal = [{'output':'licenses/provenance/runtime-grant.docx',
                               'sourceSha256':native.sha(self.files['licenses/provenance/runtime-grant.docx'])}]
        self.files['provenance/pdfium-build-receipt.json'] = native.canonical(self.receipt)
        for name, data in self.files.items():
            path = self.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def verify(self):
        native.verify_pdfium_staging(self.directory, self.selected, self.value, self.receipt, self.runtime_legal)

    def test_actual_copied_bytes_match_all_admitted_facts(self):
        self.verify()

    def test_mutated_copies_refuse_even_after_source_validation(self):
        for name, original in self.files.items():
            with self.subTest(name=name):
                path = self.directory / name
                path.write_bytes(original+b'changed after validation')
                with self.assertRaisesRegex(ValueError, 'changed during sealing'):
                    self.verify()
                path.write_bytes(original)

    def test_missing_or_unbounded_copied_evidence_refuses(self):
        path = self.directory / 'provenance/pdfium-attestation.json'
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'copied PDF evidence'): self.verify()
        path.write_bytes(b'x' * 131073)
        with self.assertRaisesRegex(ValueError, 'copied PDF evidence'): self.verify()


class PdfiumArchiveTests(unittest.TestCase):
    def extract(self, rows, expected=None):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'input.tgz'
            staging = Path(temporary) / 'prefix'
            staging.mkdir()
            with tarfile.open(archive, 'w:gz') as tar:
                for name, kind, data in rows:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.size = len(data) if kind == tarfile.REGTYPE else 0
                    member.linkname = 'bin/parser.dll' if kind == tarfile.SYMTYPE else ''
                    tar.addfile(member, io.BytesIO(data) if member.isfile() else None)
            value = {'files': expected or {'bin/parser.dll':'unused'}, 'archive':{'maximumBytes':8 * 1024 * 1024}}
            native.extract_pdfium_archive(archive, staging, value)
            return (staging / 'bin/parser.dll').read_bytes()

    def test_closed_complete_archive_extracts_exact_binary_bytes(self):
        self.assertEqual(b'actual bytes', self.extract([
            ('bin/',tarfile.DIRTYPE,b''), ('bin/parser.dll',tarfile.REGTYPE,b'actual bytes')]))

    def test_duplicate_extra_missing_directory_escape_and_link_members_are_refused(self):
        valid = ('bin/parser.dll',tarfile.REGTYPE,b'actual bytes')
        for rows in ([valid,valid], [valid,('extra',tarfile.REGTYPE,b'')],
                     [('bin/',tarfile.DIRTYPE,b'')], [valid,('unknown/',tarfile.DIRTYPE,b'')],
                     [valid,('../escape',tarfile.REGTYPE,b'')], [('bin/parser.dll',tarfile.SYMTYPE,b'')]):
            with self.subTest(rows=rows):
                with self.assertRaises(ValueError): self.extract(rows)


class PdfiumOwnedRecipeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.pdf = self.root / 'artifacts/pdfium-admission'
        self.prefix = self.root / 'artifacts/stage/native/win-x64'
        self.cache = self.root / 'artifacts/cmake/win-x64/shim-static/CMakeCache.txt'
        self.cache.parent.mkdir(parents=True)
        self.profile = {'buildTools': {'ownedCMake':'4.3.3', 'ownedNinja':'1.13.1', 'msvcToolset':'14.51.36231'}}
        self.values = {
            'CMAKE_CACHE_MAJOR_VERSION:INTERNAL':'4', 'CMAKE_CACHE_MINOR_VERSION:INTERNAL':'3',
            'CMAKE_CACHE_PATCH_VERSION:INTERNAL':'3',
            'CMAKE_C_COMPILER:FILEPATH':'C:/VS/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe',
            'CMAKE_CXX_COMPILER:FILEPATH':'C:/VS/VC/Tools/MSVC/14.51.36231/bin/Hostx64/x64/cl.exe',
            'VCPKG_INSTALLED_DIR:PATH':str(self.root / 'artifacts/vcpkg-installed'),
            'CMAKE_MAKE_PROGRAM:FILEPATH':'ninja', 'CMAKE_HOME_DIRECTORY:INTERNAL':str(self.root),
            'ARCFORGES_PDFIUM:BOOL':'ON', 'ARCFORGES_NATIVE_PROFILE:STRING':'shim-static',
            'CMAKE_BUILD_TYPE:STRING':'Release', 'VCPKG_TARGET_TRIPLET:STRING':'x64-windows-static-md',
            'PDFium_DIR:PATH':str(self.pdf / 'pdfium'), 'CMAKE_INSTALL_PREFIX:PATH':str(self.prefix)}

    def check(self):
        self.cache.write_text('\n'.join(k+'='+v for k,v in self.values.items()), encoding='utf-8')
        with patch.object(producer.subprocess, 'check_output', return_value='1.13.1\n'):
            return native.pdfium_owned_recipe(producer, self.profile, self.pdf, self.prefix, self.root)

    def test_actual_cache_is_bound_to_exact_tools_source_configuration_and_prefix(self):
        result = self.check()
        self.assertEqual(result['cacheSha256'], hashlib.sha256(self.cache.read_bytes()).hexdigest())
        self.assertEqual(result['buildTools'], self.profile['buildTools'])

    def test_unreviewed_tools_or_fixture_recipe_cannot_produce_sealed_input(self):
        for key, value in {
            'CMAKE_CACHE_PATCH_VERSION:INTERNAL':'4',
            'CMAKE_CXX_COMPILER:FILEPATH':'C:/VS/VC/Tools/MSVC/14.52/bin/Hostx64/x64/cl.exe',
            'VCPKG_INSTALLED_DIR:PATH':str(self.root / 'other-dependencies'),
            'CMAKE_HOME_DIRECTORY:INTERNAL':str(self.root / 'fixture-wrapper'),
            'ARCFORGES_PDFIUM:BOOL':'OFF', 'CMAKE_BUILD_TYPE:STRING':'Debug',
            'ARCFORGES_NATIVE_PROFILE:STRING':'other', 'VCPKG_TARGET_TRIPLET:STRING':'x64-windows',
            'PDFium_DIR:PATH':str(self.root / 'other-pdfium'),
            'CMAKE_INSTALL_PREFIX:PATH':str(self.root / 'other-prefix')}.items():
            with self.subTest(key=key):
                original = self.values[key]
                self.values[key] = value
                with self.assertRaises(ValueError): self.check()
                self.values[key] = original


if __name__ == "__main__":
    unittest.main()


class PortablePdfiumProfileTests(unittest.TestCase):
    def test_all_five_actual_profiles_have_full_sdk_legal_and_signed_producer_contracts(self):
        for rid in native.PORTABLE_PDFIUM_ARCHIVES:
            with self.subTest(rid=rid):
                value = native.portable_pdfium_profile(rid)
                self.assertEqual(value['rid'], rid)
                self.assertEqual(len(value['legalFiles']), 15)
                self.assertEqual(len(value['files']), 45 if rid.startswith('win-') else 44)
                self.assertEqual(value['configuration']['pdf_enable_v8'], False)
                self.assertEqual(value['configuration']['pdf_enable_xfa'], False)
                self.assertIn(value['inspection']['library'], value['files'])
                self.assertEqual(value['attestation']['recipeCommit'], '5453f3afc4785cbad82c05f6ceb4dabea0cb81a0')

    def test_unknown_rid_is_refused_before_any_file_or_transport_access(self):
        with patch.object(native.provenance, 'read') as read:
            for rid in ('linux-musl-x64', 'win-x86', 'osx-universal', '', '../win-x64'):
                with self.subTest(rid=rid), self.assertRaisesRegex(ValueError, 'Unadmitted PDFium RID'):
                    native.portable_pdfium_profile(rid)
            read.assert_not_called()

    def test_mutated_feature_archive_signer_inventory_or_legal_receipt_refuses(self):
        original = native.portable_pdfium_profile('linux-x64')
        actual_read = native.provenance.read
        path = 'eng/native/vcpkg/pdfium-build.linux-x64.v1.json'
        mutations = [
            lambda value: value['configuration'].update(pdf_enable_v8=True),
            lambda value: value['archive'].update(sha256='0' * 64),
            lambda value: value['attestation'].update(recipeCommit='0' * 40),
            lambda value: value['files'].pop('include/fpdfview.h'),
            lambda value: value['files'].update({'unexpected.so': '0' * 64}),
            lambda value: value['legalFiles'].pop('LICENSE'),
            lambda value: value['inspection'].update(systemPolicy='/etc/unsafe.json'),
            lambda value: value.update(extra='unapproved'),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(original)
            mutate(changed)
            with self.subTest(mutation=mutate):
                def read(root, name):
                    return native.canonical(changed) if name == path else actual_read(root, name)
                with patch.object(native.provenance, 'read', side_effect=read), self.assertRaises(ValueError):
                    native.portable_pdfium_profile('linux-x64')

    def test_portable_prefix_checks_actual_target_os_and_cpu(self):
        with tempfile.TemporaryDirectory() as temporary:
            prefix = Path(temporary)
            args = prefix / 'args.gn'
            content = b'pdf_enable_v8 = false\npdf_enable_xfa = false\ntarget_cpu = "arm64"\ntarget_os = "linux"\n'
            args.write_bytes(content)
            profile = {'files': {'args.gn': native.sha(content)}, 'configuration': {'target_cpu': 'arm64', 'target_os': 'linux'}}
            native.verify_pdfium_prefix(prefix, profile)
            for cpu, os in (('x64', 'linux'), ('arm64', 'win'), ('arm64', 'mac')):
                profile['configuration'] = {'target_cpu': cpu, 'target_os': os}
                with self.subTest(cpu=cpu, os=os), self.assertRaisesRegex(ValueError, 'features or RID changed'):
                    native.verify_pdfium_prefix(prefix, profile)
