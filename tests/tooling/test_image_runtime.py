# SPDX-License-Identifier: AGPL-3.0-only
"""Real filesystem and offline contract tests; no substitute production decoder."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import subprocess
import ssl
import tarfile
import time
import urllib.error
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng/packaging"))
import image_runtime as image
import native_binary
import native_consumer


class ImageRuntimeTests(unittest.TestCase):
    def test_real_package_material_refuses_unbound_executable_and_changed_owned_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); ident = "ArcForges.Native.Image.Runtime.linux-x64"
            readme = root / "src/Native" / ident / "README.md"
            readme.parent.mkdir(parents=True); readme.write_bytes(b"actual owned README")
            (root / "LICENSE").write_bytes(b"actual owned original legal text")
            entry = {"id": ident, "rid": "linux-x64"}
            payload = {"buildTransitive/" + ident + ".targets": image._image_targets("linux-x64"),
                       "NOTICE.md": image._image_notice(), image.RECEIPT: b"unavailable compiled producer receipt",
                       "README.md": readme.read_bytes(), "LICENSE": (root / "LICENSE").read_bytes()}
            for name, content in payload.items():
                path = root / "package" / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
            read = lambda name: (root / "package" / name).read_bytes()
            declared = set(payload) - {image.RECEIPT, "README.md", "LICENSE"}
            image._image_payload_names(entry, read, set(payload), declared, root)
            for extra in ("build/foreign.props", "foreign.exe", "foreign.nuspec", "package/services/metadata/foreign.props"):
                with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "Unexpected"):
                    image._image_payload_names(entry, read, set(payload) | {extra}, declared, root)
            for name in ("buildTransitive/" + ident + ".targets", "NOTICE.md", "README.md", "LICENSE"):
                path = root / "package" / name; original = path.read_bytes(); path.write_bytes(original + b"unadmitted change")
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "differ"):
                    image._image_payload_names(entry, read, set(payload), declared, root)
                path.write_bytes(original)

    def test_cancellation_reaches_verification_before_and_after_actual_component_read(self):
        with patch.object(image, "_inventory") as inventory, self.assertRaises(image.StageCancelled):
            image.verify_stage(Path("unavailable"), "a" * 40, cancelled=lambda: True)
        inventory.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / image.RECEIPT).write_bytes(b"{}")
            cancelled = False

            def read(name):
                nonlocal cancelled
                content = (directory / name).read_bytes()
                cancelled = True
                return content

            entry = {"id": "ArcForges.Native.Image.Runtime.win-x64", "rid": "win-x64", "library": "ArcImageNative"}
            with self.assertRaises(image.StageCancelled):
                image.verify_package(entry, read, {image.RECEIPT}, "a" * 40, cancelled=lambda: cancelled)

    @unittest.skipUnless(os.environ.get("ARCFORGES_IMAGE_LINUX_LEGAL_COMPONENT"),
                         "Retained original archives/legal bytes only; unavailable Linux host tools are explicit fixtures.")
    def test_actual_original_linux_tool_legal_handoff_and_independent_tamper_refusal(self):
        cache = Path(os.environ["ARCFORGES_IMAGE_LINUX_LEGAL_COMPONENT"])
        value, _ = image.profile(ROOT)
        definitions = image._external_definitions(value)
        with tempfile.TemporaryDirectory() as temporary:
            module = image._external_module(cache, definitions["text-template"], Path(temporary), None)
            self.assertEqual(definitions["text-template"]["sha256"], image.digest(module))
            self.assertEqual(67982, module.stat().st_size)
            module.write_bytes(b"foreign utility")
            with self.assertRaisesRegex(ValueError, "differs"):
                image._external_module(cache, definitions["text-template"], Path(temporary), None)
        legal_bytes = {legal["output"]: image._legal_bytes(legal, cache)
                       for definition in definitions.values() for legal in definition["legal"]}
        identity = {"component-only": "not Linux execution or deployment"}
        rows = [image._external_row(ident, definitions[ident], {
            "name": "Template.pm" if ident == "text-template" else ident,
            "version": definitions[ident]["version"],
            "sha256": definitions[ident]["sha256"] if ident == "text-template" else
            hashlib.sha256(("unavailable Linux " + ident).encode()).hexdigest()})
                for ident in ("make", "perl", "text-template")]
        observation = {"schemaVersion": 1, "rid": "linux-x64", "build": identity,
                       "selectors": {"make": "/usr/bin/make", "perl": "/usr/bin/perl"},
                       "tools": rows, "releaseMakefileSha256": "e" * 64,
                       "loadedModule": {"version": "1.56", "path": "/owned/module/Text/Template.pm",
                                        "sha256": definitions["text-template"]["sha256"], "perl5lib": "/owned/module", "perl5opt": None},
                       "configureContexts": [{"sourceDirectory": "/actual/openssl-source", "Configure": "a" * 64,
                                              "util/perl/OpenSSL/fallback.pm": "b" * 64, "external/perl/MODULES.txt": "c" * 64}]}
        image._verify_external_handoff(observation, value, "linux-x64", identity, legal_bytes.__getitem__)
        for mutation in ("legal", "version", "module", "role", "source", "missing"):
            altered = copy.deepcopy(observation)
            content = dict(legal_bytes)
            if mutation == "legal":
                name = definitions["make"]["legal"][0]["output"]
                content[name] += b"tampered"
            elif mutation == "version":
                altered["tools"][0]["version"] = altered["tools"][0]["executable"]["version"] = "4.4"
            elif mutation == "module": altered["tools"][2]["executable"]["sha256"] = "f" * 64
            elif mutation == "role": altered["tools"][0]["role"] = "copied-template"
            elif mutation == "source": altered["build"] = {"foreign": True}
            else: altered["tools"].pop()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                image._verify_external_handoff(altered, value, "linux-x64", identity, content.__getitem__)

    def test_unavailable_linux_module_loader_binds_actual_path_version_hash_and_closed_environment(self):
        # Only the unavailable Linux Perl loader transport is a fixture. Actual
        # source bytes/hash, context arguments and environment refusal execute.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); module = root / "module/Text/Template.pm"
            module.parent.mkdir(parents=True); module.write_bytes(b"original external utility fixture")
            definition = {"version": "1.56", "sha256": image.digest(module)}
            foreign = root / "installed/Text/Template.pm"
            foreign.parent.mkdir(parents=True); foreign.write_bytes(b"foreign installed newer module")
            source = root / "actual Configure source"
            def transport(program, arguments, cancelled, environment):
                self.assertEqual(str(module.parent.parent), environment["PERL5LIB"])
                self.assertNotIn("PERL5OPT", environment)
                self.assertNotIn("LD_PRELOAD", environment)
                self.assertIn('OpenSSL::fallback', arguments[1])
                self.assertEqual(str(source), arguments[-1])
                return "1.56\t" + str(module.resolve())
            with patch.dict(os.environ, {"PERL5OPT": "-MForeign", "PERL5LIB": str(foreign.parent.parent), "LD_PRELOAD": "foreign.so"}), \
                    patch.object(image, "_external_probe", side_effect=transport):
                result = image._observe_loaded_module(Path("unavailable-linux-perl"), module, definition, configure_source=source)
                self.assertEqual(str(module), result["path"])
            for response in ("1.99\t" + str(module), "1.56\t" + str(foreign), "1.56\tmissing"):
                with self.subTest(response=response), patch.object(image, "_external_probe", return_value=response), self.assertRaises((ValueError, OSError)):
                    image._observe_loaded_module(Path("unavailable-linux-perl"), module, definition)
            module.write_bytes(b"changed actual loaded utility")
            with patch.object(image, "_external_probe", return_value="1.56\t" + str(module)), self.assertRaisesRegex(ValueError, "loaded"):
                image._observe_loaded_module(Path("unavailable-linux-perl"), module, definition)

    def test_external_module_partial_write_never_publishes_and_retry_preserves_foreign_final(self):
        # Only unavailable archived source acquisition is supplied; real file
        # creation/fsync/error cleanup/promotion/retry execute.
        content = b"original external utility component bytes"
        definition = {"legal": [{}], "member": "external/Template.pm", "sha256": hashlib.sha256(content).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); final = root / "artifacts/image-external-tools/module/Text/Template.pm"
            actual = os.fdopen
            class FailingOutput:
                def __init__(self, descriptor, mode): self.stream = actual(descriptor, mode)
                def __enter__(self): return self
                def __exit__(self, *args): self.stream.close()
                def write(self, material):
                    self.stream.write(material[:3]); self.stream.flush()
                    raise OSError("injected partial-write before promotion")
            with patch.object(image, "_legal_bytes", return_value=content), \
                    patch.object(image.os, "fdopen", side_effect=FailingOutput), self.assertRaisesRegex(OSError, "partial-write"):
                image._external_module(root, definition, root, None)
            self.assertFalse(final.exists())
            self.assertEqual([], list(final.parent.glob(".Template.pm.image-tool-*")))
            with patch.object(image, "_legal_bytes", return_value=content):
                self.assertEqual(content, image._external_module(root, definition, root, None).read_bytes())
                final.write_bytes(b"foreign preexisting utility")
                with self.assertRaisesRegex(ValueError, "Existing"):
                    image._external_module(root, definition, root, None)
                self.assertEqual(b"foreign preexisting utility", final.read_bytes())

    def test_actual_tool_process_output_errors_and_cancellation_drain_owned_child(self):
        self.assertEqual("component", image._external_probe(sys.executable, ["-c", "print('component')"]))
        for command in ("print('x'*5000)", "raise SystemExit(3)"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                image._external_probe(sys.executable, ["-c", command])
        children = []
        actual = subprocess.Popen
        calls = 0

        def launch(*args, **kwargs):
            child = actual(*args, **kwargs)
            children.append(child)
            return child

        def cancel():
            nonlocal calls
            calls += 1
            return calls >= 3

        with patch.object(image.subprocess, "Popen", side_effect=launch), self.assertRaises(image.StageCancelled):
            image._external_probe(sys.executable, ["-c", "import time;time.sleep(30)"], cancel)
        self.assertEqual(1, len(children))
        self.assertIsNotNone(children[0].poll())

    def test_linux_minimum_inputs_and_original_external_tool_expressions_are_closed(self):
        value, material = image.profile(ROOT)
        definitions = image._external_definitions(value)
        self.assertEqual({"make", "perl", "text-template"}, set(definitions))
        self.assertEqual(20, len(value["additionalComponents"]["openssl"]["component"]["recipe"]["files"]))
        self.assertEqual(6, len(value["additionalComponents"]["vcpkg-cmake-get-vars"]["component"]["recipe"]["files"]))
        for mutate in (lambda v: v["externalToolDefinitions"]["perl"].update(version="5.36.0"),
                       lambda v: v["externalToolDefinitions"]["make"].update(legal=[]),
                       lambda v: v["externalToolDefinitions"].update(foreign={})):
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.assertRaises(ValueError):
                image._external_definitions(changed)
        changed = copy.deepcopy(value)
        changed["featureOverrides"]["win-x64"] = {"minizip-ng": ["openssl"]}
        with self.assertRaisesRegex(ValueError, "feature override"):
            image._selection("win-x64", changed, material)
        if not sys.platform.startswith("linux"):
            with self.assertRaisesRegex(ValueError, "actual Linux producer"):
                image.observe_external_tools(Path("unavailable"), "linux-x64")

    @unittest.skipUnless(os.environ.get("ARCFORGES_IMAGE_C17_COMPONENT") and os.name == "nt",
                         "Explicit existing loaded-codec C17 component diagnostic only; never CI/package acceptance.")
    def test_actual_existing_c17_loaded_codec_refuses_wrong_build_suffix(self):
        native_consumer.image_diagnostic_admission("win-x64")
        component_root = Path(os.environ["ARCFORGES_IMAGE_C17_COMPONENT"])
        build = component_root / "artifacts/cmake/image"
        import ctypes
        library_path = build / "native/arcimage-abi/ArcImageNative.dll"
        diagnostic_manifest = json.loads((component_root / "artifacts/managed-image-diagnostics/ArcImageNative.manifest.json").read_text())
        self.assertEqual(diagnostic_manifest["files"][0]["sha256"], hashlib.sha256(library_path.read_bytes()).hexdigest())
        library = ctypes.CDLL(str(library_path))

        class Buffer(ctypes.Structure):
            _fields_ = [("data", ctypes.c_void_p), ("capacity", ctypes.c_size_t), ("required", ctypes.c_size_t)]

        text = ctypes.create_string_buffer(4096)
        buffer = Buffer(ctypes.cast(text, ctypes.c_void_p), len(text), 0)
        library.arc_image_get_build_info.argtypes = [ctypes.POINTER(Buffer)]
        self.assertEqual(0, library.arc_image_get_build_info(ctypes.byref(buffer)))
        observed = text.value.decode("ascii")
        suffix = observed[observed.index(";source="):]
        vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
        location = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                                           "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property",
                                           "installationPath"], text=True).strip()
        self.assertTrue(location)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            import shutil
            shutil.copyfile(build / "native/arcimage-abi/ArcImageNative.dll", output / "ArcImageNative.dll")
            for name, expected in (("actual", suffix), ("foreign", suffix + ";foreign=true")):
                source, executable = output / (name + ".c"), output / (name + ".exe")
                source.write_text(native_consumer._image_c_source(expected), encoding="utf-8")
                command = output / (name + ".cmd")
                command.write_text('@echo off\ncall "' + location + '\\VC\\Auxiliary\\Build\\vcvarsall.bat" x64 '
                                   '-vcvars_ver=14.51.36231 >nul || exit /b 1\ncl /nologo /TC /std:c17 /W4 /WX '
                                   '/I"' + str(component_root / "native/arcimage-abi/include") + '" '
                                   '/I"' + str(component_root / "native/shared/include") + '" "' + str(source) + '" '
                                   '/Fe:"' + str(executable) + '" /link "'
                                   + str(build / "native/arcimage-abi/ArcImageNative.lib") + '"\nexit /b %errorlevel%\n',
                                   encoding="utf-8")
                result = subprocess.run(["cmd", "/d", "/c", str(command)], cwd=output,
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                native_consumer._image_execute(executable, output, dict(os.environ), failure=name == "foreign")

    @unittest.skipUnless(os.environ.get("ARCFORGES_IMAGE_REAL_STAGE"),
                         "Explicit actual source-bound producer stage; no runtime/OS/signature acceptance.")
    def test_actual_full_stage_keeps_raw_binary_legal_and_refuses_newline_rewritten_grant(self):
        directory = Path(os.environ["ARCFORGES_IMAGE_REAL_STAGE"])
        source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=image.ROOT, text=True).strip()
        artifact = image.verify_stage(directory, source)
        value, material = image.profile()
        base, _ = image._selection(artifact["rid"], value, material)
        grant = next(row for row in base["components"]["tiff"]["extras"]
                     if row["output"].endswith("berkeley-bsd-amendment.pdf"))
        package = directory / artifact["packages"][0]["id"]
        original = (package / grant["output"]).read_bytes()
        self.assertEqual("raw", grant["encoding"])
        self.assertIn(b"\r\n", original)
        self.assertEqual(grant["sha256"], hashlib.sha256(original).hexdigest())
        rewritten = original.replace(b"\r\n", b"\n")
        self.assertNotEqual(grant["sha256"], hashlib.sha256(rewritten).hexdigest())
        names = {row["path"] for row in artifact["packages"][0]["files"]}
        entry = {"id": artifact["packages"][0]["id"], "rid": artifact["rid"], "library": "ArcImageNative"}

        def read(name):
            return (package / name).read_bytes()

        # Every library, source archive, recipe, SPDX document and legal positive is real.
        # The hostile read view changes only one original raw PDF; no dependency is mocked.
        image.verify_package(entry, read, names, source)
        with self.assertRaisesRegex(ValueError, "copied-byte receipt"):
            image.verify_package(entry, lambda name: rewritten if name == grant["output"] else read(name),
                                 names, source)
        # A self-declared copied hash cannot replace the independently admitted raw original.
        receipt = json.loads(read(image.RECEIPT))
        rows = [row for row in receipt["files"] if row["path"] == grant["output"]]
        self.assertEqual(1, len(rows))
        rows[0]["sha256"] = hashlib.sha256(rewritten).hexdigest()
        redeclared = json.dumps(receipt).encode("utf-8")

        def hostile_read(name):
            if name == grant["output"]:
                return rewritten
            return redeclared if name == image.RECEIPT else read(name)

        with self.assertRaisesRegex(ValueError, "original legal companion differs"):
            image.verify_package(entry, hostile_read, names, source)

    def test_cancellation_during_unavailable_producer_artifact_verification_cannot_return_warm_cache(self):
        # The finalized upstream producer artifact is unavailable during this source component check.
        # Only that artifact verifier is scripted; actual cache bytes and cancellation are retained.
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            (cache / "retained").write_bytes(b"existing producer bytes")
            cancelled = threading.Event()

            def unavailable_producer_verifier(*args, **kwargs):
                cancelled.set()
                return {"rid": "win-x64"}

            with patch.object(image, "verify_stage", unavailable_producer_verifier):
                self.assertRaises(image.StageCancelled, image._cached_stage,
                                  cache, "0" * 40, "win-x64", ROOT, cancelled.is_set)
            self.assertEqual(b"existing producer bytes", (cache / "retained").read_bytes())

    def test_runtime_copy_and_retained_handoff_bind_actual_bytes_to_closed_compiled_spdx(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dependency.dll"
            content = b"real compiled-material fixture bytes"
            source.write_bytes(content)
            checksum = hashlib.sha256(content).hexdigest()
            triplet, relative = "x64-windows-static-md", "bin/dependency.dll"
            sbom = {"files": [{"SPDXID": "SPDXRef-binary-file-1", "fileName": "./" + relative,
                               "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}]}]}
            compiled = {}
            image._compiled_inventory(sbom, triplet, compiled)
            binding = triplet + "/" + relative
            expected = image._compiled_expected(compiled, binding)
            source.write_bytes(b"changed after initial upstream validation")
            self.assertRaisesRegex(ValueError, "hash", image._copy, source, root / "runtime/dependency.dll",
                                   expected=expected)
            self.assertFalse((root / "runtime/dependency.dll").exists())
            self.assertRaisesRegex(ValueError, "absent", image._compiled_expected, compiled, triplet + "/bin/extra.dll")
            self.assertRaisesRegex(ValueError, "aliased", image._compiled_expected, compiled, triplet + "/bin/Dependency.dll")
            self.assertRaisesRegex(ValueError, "Ambiguous", image._compiled_inventory, sbom, triplet, compiled)
            row = {"name": "dependency.dll", "sha256": checksum, "sourceSpdxPath": binding}
            image._verify_compiled_runtime(row, triplet, compiled, content)
            self.assertRaisesRegex(ValueError, "differs", image._verify_compiled_runtime, row, triplet, compiled,
                                   source.read_bytes())
            self.assertRaisesRegex(ValueError, "absent", image._verify_compiled_runtime, row, triplet, {}, content)
            self.assertRaisesRegex(ValueError, "binding", image._verify_compiled_runtime,
                                   {"name": "dependency.dll", "sha256": checksum}, triplet, compiled, content)

    def test_actual_diagnostic_child_cannot_inherit_native_loader_injection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if os.name == "nt":
                program = root / "probe.cmd"
                program.write_text('@echo off\nif defined LD_PRELOAD exit /b 2\nif defined DYLD_LIBRARY_PATH exit /b 3\necho package-image-abi-ok\n', encoding="utf-8")
            else:
                program = root / "probe"
                program.write_text('#!/bin/sh\n[ -z "$LD_PRELOAD$DYLD_LIBRARY_PATH" ] || exit 2\necho package-image-abi-ok\n', encoding="utf-8")
                program.chmod(0o700)
            env = {**os.environ, "LD_PRELOAD": "foreign.so", "DYLD_LIBRARY_PATH": "/foreign"}
            native_consumer._image_execute(program, root, env)

    def test_inventory_bounds_actual_directory_entries_and_depth_before_collecting_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertRaisesRegex(ValueError, "root", image._inventory, root / "missing")
            wide = root / "wide"
            wide.mkdir()
            for count in range(image.MAX_FILES + 1):
                (wide / str(count)).mkdir()
            self.assertRaisesRegex(ValueError, "Unbounded", image._inventory, wide)
            deep = root / "deep"
            deep.mkdir()
            current = deep
            for _ in range(65):
                current = current / "d"
                current.mkdir()
            self.assertRaisesRegex(ValueError, "Unbounded", image._inventory, deep)
            if hasattr(os, "mkfifo"):
                pipe = root / "pipe"
                pipe.mkdir()
                os.mkfifo(pipe / "input")
                self.assertRaisesRegex(ValueError, "Non-regular", image._inventory, pipe)
            if os.name != "nt":
                aliases = root / "aliases"
                aliases.mkdir()
                (aliases / "Payload").mkdir()
                (aliases / "payload").mkdir()
                self.assertRaisesRegex(ValueError, "Colliding", image._inventory, aliases)

    @staticmethod
    def legal_asset(content):
        checksum = hashlib.sha256(content).hexdigest()
        return {"output": "licenses/provenance/test.txt", "url": "https://example.invalid/legal.txt",
                "sourceSha256": checksum, "sourceSha512": None, "cacheName": "legal.txt", "member": None,
                "memberSha256": None, "start": 0, "end": len(content), "encoding": "raw", "sha256": checksum,
                "description": "Component fixture for the unavailable external legal HTTP transport."}

    def test_legal_acquisition_retries_only_bounded_transport_failure_and_reuses_actual_cached_bytes(self):
        content = b"Full fixture legal text.\n"
        row = self.legal_asset(content)
        calls = []

        def opener(request, **kwargs):
            calls.append(request.full_url)
            self.assertLessEqual(kwargs["timeout"], 10)
            self.assertTrue(kwargs["context"].check_hostname)
            if len(calls) == 1:
                raise urllib.error.URLError("unavailable external transport")
            response = io.BytesIO(content)
            response.url = request.full_url
            return response

        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            image._acquire_legal_asset(row, cache, time.monotonic() + 10, None, opener, ssl.create_default_context())
            self.assertEqual(content, (cache / "legal.txt").read_bytes())
            self.assertEqual(2, len(calls))
            image._acquire_legal_asset(row, cache, time.monotonic() + 10, None,
                                      lambda *a, **k: self.fail("A valid cache must not retry an external read."), None)
            (cache / "legal.txt").write_bytes(b"other existing bytes")
            self.assertRaisesRegex(ValueError, "preserved", image._acquire_legal_asset, row, cache,
                                   time.monotonic() + 10, None, opener, None)
            self.assertEqual(b"other existing bytes", (cache / "legal.txt").read_bytes())

    def test_legal_acquisition_cancel_hash_failure_deadline_and_redirect_never_promote_partial_material(self):
        content = b"Fixture legal text.\n"
        row = self.legal_asset(content)
        for mode in ("cancel", "digest", "deadline", "during-deadline", "oversize", "redirect", "retry-exhaustion"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                cache, cancelled, calls = Path(temporary), [False], []

                class Response(io.BytesIO):
                    def read1(self, size):
                        if mode == "during-deadline":
                            time.sleep(0.03)
                        result = super().read1(size)
                        if mode == "cancel":
                            cancelled[0] = True
                        return result

                def opener(request, **kwargs):
                    calls.append(request.full_url)
                    if mode == "retry-exhaustion":
                        raise urllib.error.URLError("external failure")
                    response = Response(b"x" * 8_000_001 if mode == "oversize" else content if mode != "digest" else b"modified")
                    response.url = request.full_url if mode != "redirect" else "http://example.invalid/plaintext"
                    return response

                deadline = time.monotonic() - 1 if mode == "deadline" else time.monotonic() + (0.02 if mode == "during-deadline" else 10)
                self.assertRaises(ValueError, image._acquire_legal_asset, row, cache, deadline,
                                   lambda: cancelled[0], opener, None)
                self.assertFalse((cache / "legal.txt").exists())
                self.assertFalse(any(path.name.startswith(".image-legal-") for path in cache.iterdir()))
                self.assertEqual(0 if mode == "deadline" else 3 if mode == "retry-exhaustion" else 1, len(calls))

    def test_warm_binary_cache_acquires_pinned_original_sources_once_and_preserves_foreign_cache(self):
        content = b"Complete original source archive fixture.\n"
        row = {"url": "git+https://example.invalid/source@fixed", "downloadUrl": "https://example.invalid/source.tar.gz",
               "sha512": hashlib.sha512(content).hexdigest(), "cacheName": "source.tar.gz"}
        calls = []

        def opener(request, **kwargs):
            calls.append(request.full_url)
            response = io.BytesIO(content)
            response.url = request.full_url
            return response

        base = {"components": {"source": {"resources": [row], "extras": []}}, "platformRuntime": {"legal": []}}
        with tempfile.TemporaryDirectory() as temporary, patch.object(image, "profile", return_value=({}, {})), \
                patch.object(image, "_selection", return_value=(base, {})):
            cache = Path(temporary)
            result = image.acquire_legal_inputs(cache, "win-x64", opener=opener)
            self.assertEqual(["source.tar.gz"], result["verifiedSourceInputs"])
            self.assertEqual(content, (cache / "source.tar.gz").read_bytes())
            image.acquire_legal_inputs(cache, "win-x64", opener=lambda *a, **k: self.fail("Valid source cache was redownloaded."))
            self.assertEqual([row["downloadUrl"]], calls)
            (cache / "source.tar.gz").write_bytes(b"foreign original source bytes")
            self.assertRaisesRegex(ValueError, "preserved", image.acquire_legal_inputs, cache, "win-x64", opener=opener)
            self.assertEqual(b"foreign original source bytes", (cache / "source.tar.gz").read_bytes())

    def test_original_source_sha512_cancellation_and_invalid_resource_never_publish(self):
        content = b"Original archive fixture."
        row = {"url": "git+https://example.invalid/source@fixed", "downloadUrl": "https://example.invalid/source.tar.gz",
               "sha512": hashlib.sha512(content).hexdigest(), "cacheName": "source.tar.gz"}
        for mode in ("digest", "cancel", "path", "schema"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                cache, cancelled = Path(temporary), [False]
                selected = dict(row)
                if mode == "path":
                    selected["cacheName"] = "nested/source.tar.gz"
                if mode == "schema":
                    selected["foreign"] = True

                class Response(io.BytesIO):
                    def read1(self, size):
                        result = super().read1(size)
                        if mode == "cancel":
                            cancelled[0] = True
                        return result

                def opener(request, **kwargs):
                    response = Response(content if mode != "digest" else b"wrong archive")
                    response.url = request.full_url
                    return response

                self.assertRaises(ValueError, image._acquire_source_asset, selected, cache, time.monotonic() + 10,
                                  lambda: cancelled[0], opener, None)
                self.assertFalse((cache / "source.tar.gz").exists())
                self.assertFalse(any(path.name.startswith(".image-legal-") for path in cache.iterdir()))

    def test_offline_legal_archive_requires_one_regular_pinned_member(self):
        content = b"Complete fixture legal document.\n"
        for mode in ("valid", "duplicate", "symlink"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                cache = Path(temporary)
                archive = cache / "legal.tar"
                with tarfile.open(archive, "w") as output:
                    member = tarfile.TarInfo("upstream/LICENSE")
                    member.size = len(content)
                    if mode == "symlink":
                        member.type, member.linkname, member.size = tarfile.SYMTYPE, "outside", 0
                    output.addfile(member, io.BytesIO(content) if mode != "symlink" else None)
                    if mode == "duplicate":
                        output.addfile(member, io.BytesIO(content))
                row = self.legal_asset(content)
                row.update(cacheName="legal.tar", sourceSha256=image.digest(archive), member="LICENSE",
                           memberSha256=hashlib.sha256(content).hexdigest())
                if mode == "valid":
                    self.assertEqual(content, image._legal_bytes(row, cache))
                else:
                    self.assertRaises(ValueError, image._legal_bytes, row, cache)

    def test_actual_vcpkg_spdx_root_prefix_is_bound_without_admitting_traversal(self):
        for name in ("./lib/actual.lib", "lib/actual.lib"):
            self.assertEqual("lib/actual.lib", str(image._sbom_path(name)))
        for name in ("./../outside", "././lib/actual.lib", "/lib/actual.lib", "./C:/outside", "./lib\\actual.lib"):
            self.assertRaises(ValueError, image._sbom_path, name)

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
            additions = ({"sse2neon"} if rid.endswith("arm64") else set())
            if rid.startswith("linux-"):
                additions |= {"openssl", "vcpkg-cmake-get-vars"}
                self.assertIn("openssl", features["minizip-ng"])
            else:
                self.assertNotIn("openssl", features["minizip-ng"])
            self.assertEqual(set(original) | additions, set(selected["components"]))
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
            self.assertEqual(21 + len(additions), len(selected["components"]))
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
            destination, staging = root / "release", root / ".release.image-stage-test"
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
                image._promote(root / ".release.image-stage-missing", destination)
            self.assertEqual("preserve", (destination / "original").read_text())
            self.assertEqual(["release"], [path.name for path in root.iterdir()])

    def test_process_death_during_promotion_recovers_previous_or_completed_candidate(self):
        for phase in ("intent", "backup", "published"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                destination, staging = root / "release", root / ".release.image-stage-child"
                destination.mkdir()
                staging.mkdir()
                (destination / "old").write_text("previous")
                (staging / "new").write_text("successor")
                script = ('import os,sys; from pathlib import Path; '
                          'sys.path.insert(0,sys.argv[1]); import image_runtime as image; '
                          'd=Path(sys.argv[2]); s=d.parent/".release.image-stage-child"; '
                          'b=d.parent/(".release.previous-"+"a"*32); '
                          'image._promotion_intent(s,d,b,True); '
                          'os._exit(0) if sys.argv[3]=="intent" else None; '
                          'os.replace(d,b); image._directory_sync(d.parent); '
                          'os._exit(0) if sys.argv[3]=="backup" else None; '
                          'os.replace(s,d); image._directory_sync(d.parent); os._exit(0)')
                child = subprocess.run([sys.executable, "-c", script, str(ROOT / "eng/packaging"),
                                        str(destination), phase], timeout=10, capture_output=True)
                self.assertEqual(0, child.returncode, child.stderr.decode())
                with image._stage_lock(destination):
                    image._recover_promotion(destination)
                    image._recover_promotion(destination)  # Bounded retry is idempotent.
                expected = "new" if phase == "published" else "old"
                self.assertEqual([expected], [path.name for path in destination.iterdir()])
                self.assertEqual({"release", ".release.image-stage-lockfile"}, {path.name for path in root.iterdir()})

    def test_recovery_rejects_escaping_journal_without_touching_other_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "release"
            other = root / "other"
            other.mkdir()
            (other / "keep").write_text("preserve")
            journal = root / ".release.image-promotion.json"
            image._write(journal, {"schemaVersion": 1, "destination": "release", "staging": "../other",
                                   "backup": ".release.previous-" + "a" * 32, "hadPrevious": False})
            self.assertRaises(ValueError, image._recover_promotion, destination)
            self.assertEqual("preserve", (other / "keep").read_text())
            self.assertTrue(journal.exists())

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

    def test_build_tool_identity_binds_actual_executable_and_refuses_version_or_empty_output(self):
        # Actual installed Python proves the executable/version adapter, not a native CMake build.
        program = Path(sys.executable)
        observed = image._build_tool(program, sys.version.split()[0], "Python ", None)
        self.assertEqual({"name": program.resolve().name, "version": sys.version.split()[0],
                          "sha256": hashlib.sha256(program.read_bytes()).hexdigest()}, observed)
        self.assertRaisesRegex(ValueError, "version", image._build_tool, program, "0.0.0", "Python ", None)
        # Unavailable producer-tool response is scripted; actual file/hash admission remains real.
        for output in ("", "1.13.1\nforeign output", "wrong", "x" * 4097):
            with patch.object(image.subprocess, "check_output", return_value=output):
                self.assertRaisesRegex(ValueError, "version", image._build_tool, program, "1.13.1", "", None)

    def test_build_tool_admission_refuses_mid_probe_mutation_and_post_probe_cancel(self):
        with tempfile.TemporaryDirectory() as temporary:
            program = Path(temporary) / "unavailable-producer-tool"
            program.write_bytes(b"original fixture executable")

            def changed(*args, **kwargs):
                self.assertEqual(15, kwargs["timeout"])
                program.write_bytes(b"changed fixture executable")
                return "cmake version 4.3.3"

            with patch.object(image.subprocess, "check_output", side_effect=changed):
                self.assertRaisesRegex(ValueError, "changed", image._build_tool, program, "4.3.3", "cmake version ", None)
            cancelled = threading.Event()

            def cancelled_probe(*args, **kwargs):
                cancelled.set()
                return "cmake version 4.3.3"

            with patch.object(image.subprocess, "check_output", side_effect=cancelled_probe):
                self.assertRaises(image.StageCancelled, image._build_tool, program, "4.3.3", "cmake version ", cancelled.is_set)

    @unittest.skipIf(os.name == "nt", "Unix tool-alias filesystem regression; Windows existing tool junction is covered by actual Python probe.")
    def test_build_tool_alias_retarget_during_probe_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, replacement, alias = root / "old-tool", root / "new-tool", root / "selected-tool"
            original.write_bytes(b"original producer fixture")
            replacement.write_bytes(b"replacement producer fixture")
            alias.symlink_to(original)

            def retarget(*args, **kwargs):
                self.assertEqual(str(original.resolve()), args[0][0])
                alias.unlink()
                alias.symlink_to(replacement)
                return "cmake version 4.3.3"

            with patch.object(image.subprocess, "check_output", side_effect=retarget):
                self.assertRaisesRegex(ValueError, "changed", image._build_tool, alias, "4.3.3", "cmake version ", None)

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


    def test_consumer_binds_actual_restored_owned_transitives_and_rejects_extra_version_or_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidates, cache = root / "candidates", root / "cache"
            candidates.mkdir()
            cache.mkdir()
            version = "1.2.3-dev.4"
            rows = []
            for identity in ("ArcForges.Native.Image", "ArcForges.Native.Abstractions"):
                file = identity + ".nupkg"
                content = (identity + " test archive bytes").encode()
                (candidates / file).write_bytes(content)
                package = cache / identity.lower() / version
                package.mkdir(parents=True)
                (package / (identity.lower() + "." + version + ".nupkg")).write_bytes(content)
                rows.append({"id": identity, "file": file})
            manifest = {"packages": rows}
            native_consumer.image_restored_candidates(candidates, cache, version, manifest)
            transitive = cache / "arcforges.native.abstractions"
            extra = transitive / "9.9.9"
            extra.mkdir()
            self.assertRaisesRegex(ValueError, "version", native_consumer.image_restored_candidates,
                                   candidates, cache, version, manifest)
            extra.rmdir()
            restored = transitive / version / (transitive.name + "." + version + ".nupkg")
            content = restored.read_bytes()
            restored.write_bytes(content + b"tamper")
            self.assertRaisesRegex(ValueError, "bytes", native_consumer.image_restored_candidates,
                                   candidates, cache, version, manifest)
            restored.write_bytes(content)
            (cache / "arcforges.unadmitted").mkdir()
            self.assertRaisesRegex(ValueError, "unadmitted", native_consumer.image_restored_candidates,
                                   candidates, cache, version, manifest)


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
