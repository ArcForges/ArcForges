# SPDX-License-Identifier: AGPL-3.0-only
"""Real filesystem and offline contract tests; no substitute production decoder."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng/packaging"))
import image_runtime as image
import native_binary
import native_consumer


class ImageRuntimeTests(unittest.TestCase):
    def test_closed_profile_binds_all_six_actual_project_and_recipe_inputs(self):
        profile, material = image.profile(ROOT)
        self.assertEqual(set(native_binary.RIDS), set(material["recipes"]["rids"]))
        self.assertEqual({"major": 1, "minor": 1}, profile["abi"])
        self.assertEqual(image.EXPORTS, tuple(material["recipes"]["exports"]))
        for rid, recipe in material["recipes"]["rids"].items():
            self.assertEqual("ArcForges.Native.Image.Runtime." + rid, recipe["package"])
            self.assertTrue((ROOT / recipe["project"]).is_file())
            self.assertTrue(recipe["compiler"]["reviewedRuntimeProfileRequired"])
        self.assertEqual("AppleClang", material["recipes"]["rids"]["osx-arm64"]["compiler"]["family"])

    def test_profile_changes_fail_before_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = (ROOT / image.PROFILE).read_bytes()
            target = root / image.PROFILE
            target.parent.mkdir(parents=True)
            target.write_bytes(profile)
            self.assertRaises(ValueError, image.profile, root)

    def test_arm_prerequisite_and_portable_records_preserve_immutable_win_source_closure(self):
        value, material = image.profile(ROOT)
        original = material["sourceProfile"]["components"]
        for rid in native_binary.RIDS:
            selected, features = image._selection(rid, value, material)
            self.assertEqual(set(original) | ({"sse2neon"} if rid.endswith("arm64") else set()), set(selected["components"]))
            self.assertEqual(set(selected["components"]), set(features))
            for name in original:
                source = selected["components"][name]
                self.assertEqual(original[name]["source"], source["source"])
                self.assertEqual(original[name]["recipe"], source["recipe"])
                self.assertEqual(original[name]["legal"], source["legal"])
                if rid == "win-x64":
                    self.assertEqual(original[name]["record"], source["record"])
                else:
                    self.assertEqual("native-image-portable-" + name + "-r1", source["record"])
            self.assertEqual(21 if rid.endswith("x64") else 22, len(selected["components"]))
        self.assertEqual("native-imath-r4", original["imath"]["record"])

    def test_safe_material_paths_refuse_escape_and_ambiguous_names(self):
        for name in ("", "/file", "../file", "a/../file", "a//file", "a/./file", "C:/file", "a\\file"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                image._path(name)
        self.assertEqual("licenses/original.txt", str(image._path("licenses/original.txt")))

    def test_json_duplicate_fields_and_invalid_inputs_fail(self):
        for content in (b'{"rid":"win-x64","rid":"win-arm64"}', b'{', b'\xff', b'[]', b'null'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                image._json(content)

    def test_actual_copy_is_fsynced_hash_bound_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "original", root / "output/copied"
            content = bytes(range(256)) * 8193
            source.write_bytes(content)
            expected = hashlib.sha256(content).hexdigest()
            self.assertEqual(expected, image._copy(source, target, expected=expected))
            self.assertEqual(content, target.read_bytes())
            self.assertRaises(FileExistsError, image._copy, source, target)
            self.assertRaisesRegex(ValueError, "hash", image._copy, source, root / "mismatch", expected="0" * 64)
            self.assertFalse((root / "mismatch").exists())

    def test_cancellation_before_and_during_stream_copy_leaves_original_intact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "original", root / "copy"
            content = b"x" * (3 * 1024 * 1024)
            source.write_bytes(content)
            self.assertRaises(image.StageCancelled, image._copy, source, target, lambda: True)
            self.assertFalse(target.exists())
            calls = 0

            def cancelled():
                nonlocal calls
                calls += 1
                return calls >= 6

            self.assertRaises(image.StageCancelled, image._copy, source, target, cancelled)
            self.assertEqual(content, source.read_bytes())
            self.assertLess(target.stat().st_size, len(content))

    def test_real_promotion_replaces_complete_directory_and_removes_its_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination, staging = root / "release", root / "staging"
            destination.mkdir()
            staging.mkdir()
            (destination / "old").write_text("old")
            (staging / "new").write_text("new")
            image._promote(staging, destination)
            self.assertEqual("new", (destination / "new").read_text())
            self.assertFalse((destination / "old").exists())
            self.assertFalse(staging.exists())
            self.assertEqual(["release"], [path.name for path in root.iterdir()])

    def test_actual_failed_promotion_restores_the_previous_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "release"
            destination.mkdir()
            (destination / "original").write_text("preserve")
            with self.assertRaises(FileNotFoundError):
                image._promote(root / "missing-staging", destination)
            self.assertEqual("preserve", (destination / "original").read_text())
            self.assertEqual(["release"], [path.name for path in root.iterdir()])

    def test_concurrent_writers_have_one_owner_and_cancelled_waiter_does_not_release_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "release"
            result = []
            with image._stage_lock(destination):
                owner = (destination.parent / ".release.image-stage-lock/owner").read_text()

                def waiter():
                    try:
                        with image._stage_lock(destination, lambda: True):
                            result.append("incorrect admission")
                    except image.StageCancelled:
                        result.append("cancelled")

                thread = threading.Thread(target=waiter)
                thread.start()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(["cancelled"], result)
                self.assertEqual(owner, (destination.parent / ".release.image-stage-lock/owner").read_text())
            self.assertFalse((destination.parent / ".release.image-stage-lock").exists())

    def test_waiting_writer_receives_lock_after_owner_closes(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "release"
            started, finished = threading.Event(), threading.Event()

            def waiter():
                started.set()
                with image._stage_lock(destination):
                    finished.set()

            with image._stage_lock(destination):
                thread = threading.Thread(target=waiter)
                thread.start()
                self.assertTrue(started.wait(5))
                self.assertFalse(finished.is_set())
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertTrue(finished.is_set())

    def test_process_death_releases_kernel_lock_and_successor_replaces_stale_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "release"
            source = ('import os,sys; from pathlib import Path; '
                      'sys.path.insert(0,sys.argv[1]); import image_runtime as image; '
                      'scope=image._stage_lock(Path(sys.argv[2])); scope.__enter__(); '
                      'print("owned",flush=True); sys.stdin.readline(); os._exit(0)')
            child = subprocess.Popen([sys.executable, "-c", source, str(ROOT / "eng/packaging"), str(destination)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual("owned", child.stdout.readline().strip())
                child.stdin.write("exit\n")
                child.stdin.flush()
                self.assertEqual(0, child.wait(timeout=5))
                marker = destination.parent / ".release.image-stage-lock/owner"
                old_token = marker.read_text()
                with image._stage_lock(destination):
                    self.assertNotEqual(old_token, marker.read_text())
                self.assertFalse(marker.parent.exists())
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                child.stdin.close()
                child.stdout.close()

    def test_real_dependency_abi_tool_receipts_refuse_mismatched_or_duplicate_versions(self):
        base = {"buildTools": {"vcpkgCMake": "4.4.0"}}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "actual-abi-info.txt"
            path.write_text("cmake 4.4.0\ncompiler actualhash\n")
            image._abi_tools(path, base)
            for content in ("cmake 4.4.3\n", "compiler actualhash\n", "cmake 4.4.0\ncmake 4.4.0\n"):
                path.write_text(content)
                self.assertRaisesRegex(ValueError, "CMake", image._abi_tools, path, base)

    def test_inventory_refuses_case_collision_and_tracks_actual_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source").write_bytes(b"actual")
            self.assertEqual([{"path": "source", "sha256": hashlib.sha256(b"actual").hexdigest()}], image._inventory(root))
            if os.name != "nt":
                (root / "SOURCE").write_bytes(b"other")
                self.assertRaisesRegex(ValueError, "Colliding", image._inventory, root)

    def test_dependency_identity_and_search_paths_are_platform_specific(self):
        _, material = image.profile(ROOT)
        policies = material["systemPolicy"]["rids"]
        self.assertIsNone(image._dependency("KERNEL32.DLL", "win-arm64", policies["win-arm64"]))
        self.assertIsNone(image._dependency("api-ms-win-crt-runtime-l1-1-0.dll", "win-x64", policies["win-x64"]))
        self.assertEqual("engine.dll", image._dependency("Engine.DLL", "win-x64", policies["win-x64"]))
        self.assertIsNone(image._dependency("libc.so.6", "linux-x64", policies["linux-x64"]))
        self.assertEqual("LIBC.so.6", image._dependency("LIBC.so.6", "linux-x64", policies["linux-x64"]))
        self.assertEqual("libengine.dylib", image._dependency("@loader_path/libengine.dylib", "osx-arm64", policies["osx-arm64"]))
        for rid, name in (("win-x64", "../engine.dll"), ("linux-x64", "/tmp/libengine.so"),
                          ("osx-arm64", "./libengine.dylib"), ("osx-x64", "@rpath/../libengine.dylib"),
                          ("osx-x64", "/usr/local/lib/libengine.dylib")):
            with self.subTest(name=name), self.assertRaises(ValueError):
                image._dependency(name, rid, policies[rid])

    def test_runtime_floor_and_search_path_metadata_never_accept_unknown_namespaces(self):
        _, material = image.profile(ROOT)
        policy = material["systemPolicy"]["rids"]["linux-arm64"]
        good = native_binary.BinaryInfo("ELF64", "aarch64", image.EXPORTS, (), "libArcImageNative.so",
                                        ("$ORIGIN",), version_requirements=("GLIBC_2.34", "GLIBCXX_3.4.29"))
        image._searchpaths(good, "linux-arm64", policy)
        for bad in (native_binary.BinaryInfo("ELF64", "aarch64", (), (), "lib.so", ("/tmp",)),
                    native_binary.BinaryInfo("ELF64", "aarch64", (), (), "lib.so", version_requirements=("GLIBC_PRIVATE",))):
            with self.assertRaises(ValueError):
                image._searchpaths(bad, "linux-arm64", policy)

    def test_owned_contract_refuses_probe_data_forwarded_ordinal_and_wrong_identity(self):
        _, material = image.profile(ROOT)
        recipe = material["recipes"]["rids"]["win-x64"]
        good = native_binary.BinaryInfo("PE32+", "x86_64", image.EXPORTS, (), "ArcImageNative.dll")
        image._owned(good, recipe)
        for bad in (native_binary.BinaryInfo("PE32+", "x86_64", image.EXPORTS[:3], (), "ArcImageNative.dll"),
                    native_binary.BinaryInfo("PE32+", "x86_64", image.EXPORTS, (), "ArcImageNative.dll", forwarded_exports=("other",)),
                    native_binary.BinaryInfo("PE32+", "x86_64", image.EXPORTS, (), "ArcImageNative.dll", data_exports=("other",)),
                    native_binary.BinaryInfo("PE32+", "x86_64", image.EXPORTS, (), "ArcImageNative.dll", unnamed_exports=1),
                    native_binary.BinaryInfo("PE32+", "x86_64", image.EXPORTS, (), "another.dll")):
            with self.assertRaises(ValueError):
                image._owned(bad, recipe)

    def test_package_refuses_wrong_rid_source_or_missing_receipt(self):
        for entry in ({"rid": "unknown", "id": "wrong", "library": "ArcImageNative"},
                      {"rid": "win-x64", "id": "wrong", "library": "ArcImageNative"}):
            with self.assertRaises(ValueError):
                image.verify_package(entry, lambda path: b"{}", set(), "0" * 40)
        entry = {"rid": "win-x64", "id": "ArcForges.Native.Image.Runtime.win-x64", "library": "ArcImageNative"}
        self.assertRaisesRegex(ValueError, "receipt", image.verify_package, entry, lambda path: b"{}", set(), "0" * 40)

    def test_actual_host_diagnostic_refuses_foreign_execution_ci_and_unpublished_rids(self):
        if os.environ.get("GITHUB_ACTIONS") or os.environ.get("CI", "").lower() == "true":
            self.assertRaisesRegex(ValueError, "CI execution", native_consumer.image_diagnostic_admission, "win-x64")
            return
        host = native_consumer.image_host_rid()
        self.assertEqual(host, native_consumer.image_diagnostic_admission(host))
        foreign = "linux-x64" if host.startswith("win-") else "win-x64"
        self.assertRaisesRegex(ValueError, "foreign RID", native_consumer.image_diagnostic_admission, foreign)
        self.assertRaisesRegex(ValueError, "not admitted", native_consumer.image_diagnostic_admission, "unreviewed-rid")
        if host.startswith("win-"):
            other = "win-arm64" if host == "win-x64" else "win-x64"
            self.assertEqual(host, native_consumer.image_diagnostic_admission(other, True))
            if not any(row["id"] == "ArcForges.Native.Image.Runtime." + other
                       for row in native_consumer.packages.catalogue()):
                self.assertRaisesRegex(ValueError, "no admitted actual package", native_consumer.consume_image,
                                       Path("unavailable-candidate"), "1.0.0", "0" * 40, other, True)


@unittest.skipUnless(os.name == "nt" and os.environ.get("ARCFORGES_IMAGE_ARM_CRT"),
                     "Actual ARM64 Microsoft runtime admission requires explicit local input.")
class ActualArmRuntimeAdmissionTests(unittest.TestCase):
    def test_actual_signed_arm_crt_is_hash_architecture_publisher_and_version_bound(self):
        value, _ = image.profile(ROOT)
        directory = Path(os.environ["ARCFORGES_IMAGE_ARM_CRT"])
        for name, expected in value["compilerRuntime"]["win-arm64"]["files"].items():
            with self.subTest(name=name):
                path = directory / name
                self.assertEqual("aarch64", native_binary.inspect(path, "win-arm64").machine)
                self.assertEqual({**expected, "signature": "valid"}, image._compiler_runtime_signature(path, "win-arm64", value))
                self.assertRaises(ValueError, image._compiler_runtime_signature, path, "win-x64", value)
                with tempfile.TemporaryDirectory() as temporary:
                    tampered = Path(temporary) / name
                    tampered.write_bytes(path.read_bytes() + b"tampered")
                    self.assertRaisesRegex(ValueError, "hash", image._compiler_runtime_signature, tampered, "win-arm64", value)


if __name__ == "__main__":
    unittest.main()
