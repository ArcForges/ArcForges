# SPDX-License-Identifier: AGPL-3.0-only
"""Produce and verify source-bound Image runtime packages without executing parsers.

These receipts bind production inputs and copied bytes. Publisher authorization
and release signing are a separate trust handoff; a self-declared manifest is not
a signature, and an unavailable producer never becomes a fabricated RID asset.
"""
import argparse
import copy
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import tarfile
import urllib.error
import urllib.request
import uuid

import native_binary

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng"))
import build_identity
import check_provenance
import native_provenance

PROFILE = "eng/provenance/artifact-profiles/image-runtime-producer-v1.json"
RECEIPT = "image-production-input.json"
MAX_FILES = 20000
MAX_MATERIAL = 512 * 1024 * 1024
EXPORTS = tuple(sorted("arc_image_" + suffix for suffix in
                       ("get_abi_version", "get_build_info", "get_last_error", "open", "read", "close")))
require = native_binary.require


class StageCancelled(ValueError):
    pass


@dataclass(frozen=True)
class ProducerInputs:
    prefix: Path
    build_directory: Path
    installed_directory: Path
    vcpkg: Path
    downloads: Path
    compiler_runtime: Path | None = None


def _cancel(cancelled):
    if cancelled is not None and cancelled():
        raise StageCancelled("Image production staging was cancelled.")


def _path(value):
    require(isinstance(value, str) and value and "\\" not in value and ":" not in value and
            not value.startswith("/") and all(part not in ("", ".", "..") for part in value.split("/")),
            "Unsafe Image material path.")
    return PurePosixPath(value)


def _link(path):
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _sbom_path(value):
    # vcpkg's actual SPDX inventory uses one './' package-root prefix. Strip
    # only that conventional prefix; nested traversal/absolute aliases remain
    # invalid material paths rather than being normalized into acceptance.
    require(isinstance(value, str), "Invalid Image SBOM material path.")
    return _path(value[2:] if value.startswith("./") else value)


def _regular(path, root=None):
    path = Path(path)
    current = path.absolute()
    stop = Path(root).absolute() if root is not None else current.anchor
    for part in (current, *current.parents):
        require(not _link(part), "Linked Image material is forbidden.")
        if str(part) == str(stop):
            break
    if root is not None:
        require(path.resolve().is_relative_to(Path(root).resolve()), "Image material escapes its input root.")
    require(path.is_file(), "Required Image production input is unavailable: " + str(path))
    return path


def digest(path, cancelled=None, algorithm="sha256", lf=False):
    _regular(path)
    require(Path(path).stat().st_size <= MAX_MATERIAL, "Unbounded Image production material.")
    if lf:
        content = Path(path).read_bytes()
        require(len(content) <= MAX_MATERIAL, "Unbounded Image text material.")
        _cancel(cancelled)
        return hashlib.new(algorithm, content.replace(b"\r\n", b"\n")).hexdigest()
    result = hashlib.new(algorithm)
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            _cancel(cancelled)
            result.update(block)
    return result.hexdigest()


def _json(content):
    require(isinstance(content, bytes) and len(content) <= 16 * 1024 * 1024, "Unbounded Image JSON material.")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate Image JSON field.")
            result[key] = value
        return result

    try:
        value = json.loads(content, object_pairs_hook=pairs)
        require(isinstance(value, dict), "Image JSON root must be an object.")
        return value
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid Image production JSON.") from error


def _document(path):
    with _regular(path).open("rb") as stream:
        return _json(stream.read(16 * 1024 * 1024 + 1))


def _write(path, value):
    _write_bytes(path, build_identity.canonical(value))


def _write_bytes(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _directory_sync(path):
    # Windows MoveFileEx/os.replace does not expose a directory fsync handle.
    # Every file is flushed there; Unix additionally persists directory entries.
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _abi_tools(path, base):
    rows = _regular(path).read_text(encoding="utf-8").splitlines()
    cmake = [line.split()[1:] for line in rows if line.startswith("cmake ")]
    require(cmake == [[base["buildTools"]["vcpkgCMake"]]],
            "Image installed dependency used an unreviewed vcpkg CMake version.")


def _legal_bytes(row, cache, cancelled=None):
    source = _regular(Path(cache) / row["cacheName"], cache)
    expected, algorithm = row["sourceSha256"] or row["sourceSha512"], "sha256" if row["sourceSha256"] else "sha512"
    require(digest(source, cancelled, algorithm) == expected, "Image legal source differs from admission.")
    if row["member"] is not None:
        matches = []
        with tarfile.open(source) as archive:
            for count, member in enumerate(archive):
                _cancel(cancelled)
                require(count < MAX_FILES and member.offset_data + member.size <= MAX_MATERIAL,
                        "Unbounded Image legal archive inventory.")
                if member.name.partition("/")[2] == row["member"]:
                    require(member.isfile() and member.size <= 8_000_000 and not matches,
                            "Invalid or duplicate Image legal archive member.")
                    stream = archive.extractfile(member)
                    require(stream is not None, "Missing Image legal archive member bytes.")
                    with stream:
                        matches.append(stream.read(8_000_001))
        require(len(matches) == 1 and hashlib.sha256(matches[0]).hexdigest() == row["memberSha256"],
                "Image legal archive member differs from admission.")
        content = matches[0]
    else:
        require(source.stat().st_size <= 8_000_000, "Unbounded Image legal document.")
        content = source.read_bytes()
    require(0 <= row["start"] < row["end"] <= len(content), "Invalid Image legal source range.")
    content = content[row["start"]:row["end"]]
    if row["encoding"] != "raw":
        content = content.decode(row["encoding"]).replace("\r\n", "\n").encode("utf-8")
    require(hashlib.sha256(content).hexdigest() == row["sha256"], "Image legal transformation differs.")
    return content


def _acquire_legal_asset(row, downloads, deadline, cancelled, opener, context):
    caller_cancelled = cancelled

    def operation_cancelled():
        require(time.monotonic() < deadline, "Image legal acquisition deadline expired.")
        return caller_cancelled is not None and caller_cancelled()

    cancelled = operation_cancelled
    native_provenance.asset(row)
    _path(row["cacheName"])
    target = downloads / row["cacheName"]
    expected = row["sourceSha256"] or row["sourceSha512"]
    algorithm = "sha256" if row["sourceSha256"] else "sha512"
    with _stage_lock(target, cancelled):
        for attempt in range(3):
            _cancel(cancelled)
            require(time.monotonic() < deadline, "Image legal acquisition deadline expired.")
            if target.exists():
                require(digest(_regular(target, downloads), cancelled, algorithm) == expected,
                        "Cached Image legal source differs; existing bytes are preserved.")
                break
            descriptor, temporary_name = tempfile.mkstemp(prefix=".image-legal-", dir=downloads)
            temporary = Path(temporary_name)
            try:
                request = urllib.request.Request(row["url"], headers={"User-Agent": native_provenance.VISUAL_STUDIO_LICENSE_USER_AGENT})
                timeout = min(10, max(0.001, deadline - time.monotonic()))
                with os.fdopen(descriptor, "wb") as output, opener(request, timeout=timeout, context=context) as response:
                    native_provenance.download_identity(response.url)
                    total, checksum = 0, hashlib.new(algorithm)
                    while True:
                        _cancel(cancelled)
                        require(time.monotonic() < deadline, "Image legal acquisition deadline expired.")
                        content = (response.read1 if hasattr(response, "read1") else response.read)(1024 * 1024)
                        if not content:
                            break
                        total += len(content)
                        require(total <= (MAX_MATERIAL if row["member"] is not None else 8_000_000),
                                "Unbounded Image legal acquisition.")
                        output.write(content)
                        checksum.update(content)
                    output.flush()
                    os.fsync(output.fileno())
                require(checksum.hexdigest() == expected, "Downloaded Image legal source digest mismatch.")
                try:
                    os.link(temporary, target)  # Atomic no-overwrite cache publication.
                except FileExistsError:
                    require(digest(_regular(target, downloads), cancelled, algorithm) == expected,
                            "Concurrent Image legal cache bytes differ.")
                _directory_sync(downloads)
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                if attempt == 2 or time.monotonic() >= deadline:
                    raise ValueError("Image legal acquisition failed after bounded attempts: " + target.name) from error
                delay = min(0.25 * (2 ** attempt), max(0, deadline - time.monotonic()))
                time.sleep(delay)
            finally:
                temporary.unlink(missing_ok=True)
    _legal_bytes(row, downloads, cancelled)


def acquire_legal_inputs(downloads, rid, root=ROOT, cancelled=None, opener=None):
    """Explicit bounded network acquisition; staging itself never downloads."""
    require(rid in native_binary.RIDS, "Image legal-input RID is not admitted.")
    value, material = profile(root)
    base, _ = _selection(rid, value, material)
    rows = [row for component in base["components"].values() for row in component["extras"]]
    if rid.startswith("linux-"):
        rows += [row for tool in value["externalToolDefinitions"].values() for row in tool["legal"]]
    if rid.startswith("win-"):
        rows += base["platformRuntime"]["legal"]
    downloads = Path(downloads).absolute()
    for parent in (downloads, *downloads.parents):
        require(not _link(parent), "Linked Image acquisition cache is forbidden.")
    downloads.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + 120
    context = ssl.create_default_context()
    opener = opener or urllib.request.urlopen
    completed = set()
    for row in rows:
        native_provenance.asset(row)
        _path(row["cacheName"])
        target = downloads / row["cacheName"]
        if target.name in completed:
            _legal_bytes(row, downloads, cancelled)
            continue
        _acquire_legal_asset(row, downloads, deadline, cancelled, opener, context)
        completed.add(target.name)
    return {"rid": rid, "verifiedLegalInputs": sorted(completed)}


def profile(root=ROOT):
    root = Path(root)
    value = _document(root / PROFILE)
    require(value.get("schemaVersion") == 1 and value.get("id") == "image-runtime-producer-v1" and
            value.get("family") == "arc_image" and value.get("abi") == {"major": 1, "minor": 1},
            "Unknown Image runtime profile.")
    materials = {}
    for key in ("sourceProfile", "recipes", "systemPolicy"):
        row = value[key]
        _path(row["path"])
        require(digest(root / row["path"], lf=True) == row["sha256Lf"], "Changed Image profile input: " + key)
        materials[key] = _document(root / row["path"])
    recipes = materials["recipes"]
    policy = materials["systemPolicy"]
    require(recipes.get("id") == "image-runtime-producers-v1" and recipes.get("family") == "arc_image" and
            recipes.get("abi") == value["abi"] and tuple(recipes.get("exports", ())) == EXPORTS and
            set(recipes["rids"]) == set(native_binary.RIDS) and
            policy.get("schemaVersion") == 2 and set(policy["rids"]) == set(native_binary.RIDS) and
            set(value["triplets"]) == set(native_binary.RIDS), "Image producer RID/ABI policy is not closed.")
    for rid, row in recipes["rids"].items():
        require(row["package"] == "ArcForges.Native.Image.Runtime." + rid and
                (policy["rids"][rid]["format"], row["architecture"]) == native_binary.RIDS[rid],
                "Image producer recipe identity mismatch.")
        for key in ("project", "buildDirectory", "installDirectory", "installedDirectory"):
            _path(row[key])
        _regular(root / row["project"], root)
        triplet = value["triplets"][rid]
        if triplet["ownedPath"] is not None:
            _path(triplet["ownedPath"])
            require(digest(root / triplet["ownedPath"], lf=True) == triplet["ownedSha256Lf"],
                    "Changed owned Image triplet.")
    require(set(value["componentRecords"]) == set(materials["sourceProfile"]["components"]),
            "Image portable source records are not closed.")
    for rows in value["componentRecords"].values():
        require(set(rows) == set(native_binary.RIDS) and all(re.fullmatch(r"[a-z0-9-]+", record) for record in rows.values()),
                "Image per-RID source records are invalid.")
    return value, materials


def _selection(rid, value, material):
    base = copy.deepcopy(material["sourceProfile"])
    features = {row["name"]: row["features"] for row in
                base["packages"]["ArcForges.Native.Image.Runtime.win-x64"]["dependencies"]}
    for name, component in base["components"].items():
        component["record"] = value["componentRecords"][name][rid]
    for name, row in value["additionalComponents"].items():
        require(set(row["rids"]).issubset(native_binary.RIDS) and len(row["rids"]) == len(set(row["rids"])),
                "Unreviewed Image prerequisite RID selection.")
        if rid in row["rids"]:
            require(name not in base["components"], "Colliding Image prerequisite input.")
            base["components"][name] = copy.deepcopy(row["component"])
            features[name] = row["features"]
    overrides = value.get("featureOverrides", {})
    require(set(overrides).issubset({"linux-x64", "linux-arm64"}) and
            all(set(rows) == {"minizip-ng"} for rows in overrides.values()),
            "Unreviewed Image feature override.")
    for name, selected in overrides.get(rid, {}).items():
        require(selected == sorted(features[name] + ["openssl"]) and "openssl" in base["components"],
                "Unreviewed Image Linux OpenSSL feature closure.")
        features[name] = selected
    return base, features


def _external_definitions(value):
    definitions = value["externalToolDefinitions"]
    require(set(definitions) == {"make", "perl", "text-template"}, "External Image tool catalogue is not closed.")
    for ident, definition in definitions.items():
        check_provenance.fields(definition, "repository commit version legal" +
                                (" member sha256" if ident == "text-template" else ""))
        check_provenance.repository(definition["repository"])
        check_provenance.digest(definition["commit"], (40,))
        require(definition["version"] == {"make": "4.3", "perl": "5.38.2", "text-template": "1.56"}[ident],
                "Unreviewed external Image tool version.")
        require(bool(definition["legal"]), "Missing external Image tool legal originals.")
        for legal in definition["legal"]:
            native_provenance.asset(legal)
        if ident == "text-template":
            require(definition["member"] == "external/perl/Text-Template-1.56/lib/Text/Template.pm",
                    "Unreviewed original external Image utility member.")
            check_provenance.digest(definition["sha256"])
    return definitions


def _external_row(ident, definition, executable):
    return {"id": ident, "repository": definition["repository"], "commit": definition["commit"],
            "version": definition["version"], "role": "noncopying-external-execution", "executable": executable,
            "licence": {"spdx": check_provenance.EXTERNAL_TOOL_LICENCES[ident], "category": "gpl-only",
                        "evidence": [{"path": row["output"], "sha256": row["sha256"],
                                      "finding": "Full original external tool legal document; not copied implementation/source/input/output permission."}
                                     for row in definition["legal"]],
                        "scope": "Noncopying OpenSSL build execution only. Tool implementations are not bundled or linked into runtime."}}


def _external_probe(program, arguments, cancelled=None, environment=None):
    """Bound output, time, cancellation and child lifetime for real host probes."""
    _cancel(cancelled)
    environment = {key: value for key, value in (os.environ if environment is None else environment).items()
                   if not key.startswith(("LD_", "DYLD_"))}
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen([str(program), *arguments], stdout=output, stderr=subprocess.STDOUT, env=environment)
        deadline = time.monotonic() + 15
        try:
            while process.poll() is None:
                _cancel(cancelled)
                require(time.monotonic() < deadline and os.fstat(output.fileno()).st_size <= 4096,
                        "Unbounded external Image tool probe.")
                time.sleep(0.025)
            _cancel(cancelled)
            require(process.returncode == 0 and os.fstat(output.fileno()).st_size <= 4096,
                    "External Image tool probe failed or exceeded output bound.")
            output.seek(0)
            return output.read(4097).decode("utf-8", errors="strict").strip()
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)


def _external_module(downloads, definition, root, cancelled):
    # This is an original utility used only for external execution, never copied
    # into the runtime or used as implementation/generation source permission.
    asset = {**definition["legal"][0], "member": definition["member"],
             "memberSha256": definition["sha256"], "sha256": definition["sha256"],
             "start": 0, "end": 67982, "encoding": "raw"}
    content = _legal_bytes(asset, downloads, cancelled)
    target = root / "artifacts/image-external-tools/module/Text/Template.pm"
    target.parent.mkdir(parents=True, exist_ok=True)
    require(all(not _link(parent) for parent in target.parents), "Linked external Image utility input directory.")
    with _stage_lock(target, cancelled):
        if target.exists():
            require(digest(_regular(target), cancelled) == definition["sha256"],
                    "Existing external Image module differs from its original source.")
        else:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".Template.pm.image-tool-", dir=target.parent)
            temporary = Path(temporary_name)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                _cancel(cancelled)
                require(digest(_regular(temporary), cancelled) == definition["sha256"],
                        "External Image utility temporary bytes differ.")
                try:
                    os.link(temporary, target)  # Atomic no-overwrite; partial bytes never become final.
                except FileExistsError:
                    require(digest(_regular(target), cancelled) == definition["sha256"],
                            "Concurrent external Image utility bytes differ.")
                _directory_sync(target.parent)
            finally:
                temporary.unlink(missing_ok=True)
    return _regular(target).resolve(strict=True)


def _perl_environment(module):
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("PERL5LIB", "PERL5OPT") and not key.startswith(("LD_", "DYLD_"))}
    environment["PERL5LIB"] = str(module.parent.parent)
    return environment


def _observe_loaded_module(perl, module, definition, cancelled=None, configure_source=None):
    environment = _perl_environment(module)
    if configure_source is None:
        setup = "use Text::Template 1.56;"
        arguments = []
    else:
        # Match Configure's original fallback ordering with the exact built
        # source context, while retaining the same closed pre-build PERL5LIB.
        setup = ('BEGIN { require lib; lib->import($ARGV[0].q{/util/perl}); '
                 'require OpenSSL::fallback; OpenSSL::fallback->import($ARGV[0].q{/external/perl/MODULES.txt}); } '
                 'use Text::Template 1.46;')
        arguments = [str(configure_source)]
    code = setup + ' use Cwd (); printf "%s\\t%s", $Text::Template::VERSION, Cwd::abs_path($INC{"Text/Template.pm"});'
    observed = _external_probe(perl, ["-e", code, *arguments], cancelled, environment)
    parts = observed.split("\t")
    require(len(parts) == 2 and parts[0] == definition["version"] and
            Path(parts[1]).resolve(strict=True) == module and
            digest(_regular(module), cancelled) == definition["sha256"],
            "Actual loaded external Image module differs from the admitted original.")
    return {"version": parts[0], "path": str(module), "sha256": definition["sha256"],
            "perl5lib": environment["PERL5LIB"], "perl5opt": None}


def observe_external_tools(downloads, rid, root=ROOT, cancelled=None):
    require(rid in ("linux-x64", "linux-arm64") and sys.platform.startswith("linux"),
            "External Image host observations require the actual Linux producer.")
    value, _ = profile(root)
    definitions = _external_definitions(value)
    module = _external_module(downloads, definitions["text-template"], Path(root), cancelled)
    environment = _perl_environment(module)
    tools, selectors = [], {}
    for ident in ("make", "perl"):
        selected = shutil.which(ident)
        require(selected is not None, "Missing actual external Image executable: " + ident)
        selector = Path(selected)
        binary = _regular(selector.resolve(strict=True))
        before = digest(binary, cancelled)
        observed = _external_probe(binary, ["--version"] if ident == "make" else
                                   ["-e", 'printf "%vd", $^V;'], cancelled, environment)
        expected = definitions[ident]["version"]
        require((observed.splitlines()[0] == "GNU Make " + expected) if ident == "make" else observed == expected,
                "Unreviewed actual external Image executable version.")
        require(selector.resolve(strict=True) == binary and digest(binary, cancelled) == before,
                "External Image executable changed during observation.")
        if ident == "make":
            gmake = shutil.which("gmake")
            require(gmake is None or Path(gmake).resolve(strict=True) == binary,
                    "OpenSSL configure/build select different make executables.")
        selectors[ident] = str(binary)
        tools.append(_external_row(ident, definitions[ident], {"name": ident, "version": expected, "sha256": before}))
    definition = definitions["text-template"]
    loaded = _observe_loaded_module(Path(selectors["perl"]), module, definition, cancelled)
    tools.append(_external_row("text-template", definition,
                              {"name": "Template.pm", "version": definition["version"], "sha256": definition["sha256"]}))
    for definition in definitions.values():
        for legal in definition["legal"]:
            _legal_bytes(legal, downloads, cancelled)
    check_provenance.external_tools(tools)
    identity = build_identity.build_identity(Path(root))
    require(not identity["dirty"], "Commit reviewed Image source before observing producer tools.")
    return {"schemaVersion": 1, "rid": rid, "build": identity, "selectors": selectors, "tools": tools,
            "loadedModule": loaded}


def _external_tool_handoff(inputs, rid, root, cancelled):
    before = _document(root / "artifacts/image-external-tools" / (rid + ".json"))
    actual = observe_external_tools(inputs.downloads, rid, root, cancelled)
    require(before == actual, "External Image tool identity/version/hash/legal observation differs from build start.")
    require(os.environ.get("PERL5LIB") == actual["loadedModule"]["perl5lib"] and not os.environ.get("PERL5OPT"),
            "Actual OpenSSL build environment differs from its closed external-module observation.")
    # The actual Release Configure output binds the interpreter selected by the pinned port.
    triplet = "x64-linux" if rid == "linux-x64" else "arm64-linux"
    makefile = _regular(inputs.vcpkg / "buildtrees/openssl" / (triplet + "-rel") / "Makefile")
    require(makefile.stat().st_size <= 8_000_000, "Unbounded OpenSSL tool configuration.")
    interpreters = re.findall(r"^PERL\s*=\s*(.+?)\s*$", makefile.read_text(encoding="utf-8"), re.MULTILINE)
    require(len(interpreters) == 1 and Path(interpreters[0]).resolve(strict=True) == Path(actual["selectors"]["perl"]),
            "Actual OpenSSL Configure interpreter differs from the observed external tool.")
    source_root = inputs.vcpkg / "buildtrees/openssl/src"
    candidates = list(source_root.glob("*/external/perl/Text-Template-1.56/lib/Text/Template.pm"))
    require(0 < len(candidates) <= 64, "Missing or ambiguous actual OpenSSL external utility input.")
    expected = next(row["executable"]["sha256"] for row in actual["tools"] if row["id"] == "text-template")
    contexts = []
    for candidate in candidates:
        require(digest(_regular(candidate, source_root), cancelled) == expected,
                "Actual OpenSSL external utility differs from original source.")
        configured = candidate.parents[5]
        require(_regular(configured / "Configure", source_root).is_file(), "Missing actual Configure source context.")
        require(_observe_loaded_module(Path(actual["selectors"]["perl"]), Path(actual["loadedModule"]["path"]),
                _external_definitions(profile(root)[0])["text-template"], cancelled,
                configured) == actual["loadedModule"], "Actual Configure module context differs from the pre-build observation.")
        contexts.append({"sourceDirectory": str(configured.resolve(strict=True)),
                         **{name: digest(_regular(configured / name, source_root), cancelled)
                            for name in ("Configure", "util/perl/OpenSSL/fallback.pm", "external/perl/MODULES.txt")}})
    return {**actual, "releaseMakefileSha256": digest(makefile, cancelled), "configureContexts": contexts}


def _verify_external_handoff(observation, value, rid, identity, read):
    check_provenance.fields(observation, "schemaVersion rid build selectors tools loadedModule releaseMakefileSha256 configureContexts")
    require(observation["schemaVersion"] == 1 and observation["rid"] == rid and observation["build"] == identity,
            "External Image tool producer/source/RID binding differs.")
    check_provenance.digest(observation["releaseMakefileSha256"])
    require(set(observation["selectors"]) == {"make", "perl"}, "External Image tool selectors differ.")
    for path in observation["selectors"].values():
        require(isinstance(path, str) and path.startswith("/") and len(path) <= 4096 and
                not any(part in (".", "..") for part in path.split("/")) and "\n" not in path,
                "Invalid actual external Image tool selector.")
    check_provenance.external_tools(observation["tools"])
    definitions = _external_definitions(value)
    loaded = observation["loadedModule"]
    check_provenance.fields(loaded, "version path sha256 perl5lib perl5opt")
    require(loaded["version"] == definitions["text-template"]["version"] and
            loaded["sha256"] == definitions["text-template"]["sha256"] and loaded["perl5opt"] is None and
            isinstance(loaded["path"], str) and loaded["path"].startswith("/") and
            len(loaded["path"]) <= 4096 and not any(part in (".", "..") for part in loaded["path"].split("/")) and
            "\n" not in loaded["path"] and PurePosixPath(loaded["path"]).name == "Template.pm" and
            loaded["perl5lib"] == str(PurePosixPath(loaded["path"]).parent.parent),
            "Loaded external Image module/profile/environment binding differs.")
    require(isinstance(observation["configureContexts"], list) and 0 < len(observation["configureContexts"]) <= 64,
            "Missing/unbounded actual Configure context.")
    seen = set()
    for context in observation["configureContexts"]:
        require(set(context) == {"sourceDirectory", "Configure", "util/perl/OpenSSL/fallback.pm", "external/perl/MODULES.txt"}
                and isinstance(context["sourceDirectory"], str) and context["sourceDirectory"].startswith("/")
                and context["sourceDirectory"] not in seen and len(context["sourceDirectory"]) <= 4096,
                "Invalid/repeated actual Configure context.")
        seen.add(context["sourceDirectory"])
        for name, checksum in context.items():
            if name != "sourceDirectory": check_provenance.digest(checksum)
    require([row["id"] for row in observation["tools"]] == ["make", "perl", "text-template"],
            "External Image tool inventory differs from the reviewed recipe.")
    for row in observation["tools"]:
        definition = definitions[row["id"]]
        require(row == _external_row(row["id"], definition, row["executable"]),
                "External Image tool source/legal identity differs from the reviewed recipe.")
        if row["id"] == "text-template":
            require(row["executable"]["sha256"] == definition["sha256"], "External Image utility source differs.")
        for legal in definition["legal"]:
            require(hashlib.sha256(read(legal["output"])).hexdigest() == legal["sha256"],
                    "External Image tool original legal bytes differ.")


def _owned(info, recipe):
    require(info.exports == EXPORTS and not info.forwarded_exports and not info.data_exports and
            info.unnamed_exports == 0 and
            set(info.absolute_exports).issubset({"ARCFORGES_1.0"} if info.format == "ELF64" else set()),
            "Image runtime does not implement the exact callable ABI1.1 export set.")
    require(info.identity == recipe["libraryIdentity"], "Image shared-library identity differs from its recipe.")


def _key(name, rid):
    return name.casefold() if rid.startswith("win-") else name


def _dependency(name, rid, policy):
    if rid.startswith("win-"):
        require("/" not in name and "\\" not in name and ":" not in name, "Escaping PE import identity.")
        key = name.casefold()
        if key in policy["systemImports"] or any(key.startswith(prefix) and key.endswith(".dll")
                                                 for prefix in policy["apiSetPrefixes"]):
            return None
        return key
    if rid.startswith("linux-"):
        require("/" not in name and "\\" not in name and name not in (".", ".."), "Escaping ELF dependency.")
        return None if name in policy["systemImports"] else name
    if name in policy["systemImports"]:
        return None
    for prefix in ("@loader_path/", "@rpath/"):
        if name.startswith(prefix):
            suffix = name[len(prefix):]
            require(suffix and "/" not in suffix and "\\" not in suffix and suffix not in (".", ".."),
                    "Escaping Mach-O bundled dependency.")
            return suffix
    raise ValueError("Unreviewed Mach-O dependency install-name: " + name)


def _searchpaths(info, rid, policy):
    require(all(path in policy["allowedRunpaths"] for path in info.runpaths), "Unreviewed native library search path.")
    if rid.startswith("linux-"):
        require(all(re.fullmatch(r"(?:" + "|".join(policy["versionNamespaces"]) + r")_[0-9]+(?:\.[0-9]+)*", value)
                    for value in info.version_requirements), "Unreviewed ELF system symbol version namespace.")


def _compiler_runtime_signature(path, rid, value):
    expected = value["compilerRuntime"][rid]["files"].get(path.name.casefold())
    require(expected is not None and digest(path) == expected["sha256"], "Image compiler runtime hash is not admitted.")
    signature = native_provenance.signed_runtime(path)
    require(signature == {**expected, "signature": "valid"}, "Image compiler runtime signature/publisher/version is not admitted.")
    return signature


def _copy(original, target, cancelled=None, expected=None, algorithm="sha256"):
    _regular(original)
    _cancel(cancelled)
    require(original.stat().st_size <= MAX_MATERIAL, "Unbounded Image production material.")
    original_hash = digest(original, cancelled, algorithm)
    require(expected is None or original_hash == expected, "Image input hash differs from its reviewed source.")
    target.parent.mkdir(parents=True, exist_ok=True)
    with original.open("rb") as source, target.open("xb") as destination:
        while block := source.read(1024 * 1024):
            _cancel(cancelled)
            destination.write(block)
        destination.flush()
        os.fsync(destination.fileno())
    require(digest(target, cancelled, algorithm) == original_hash and digest(original, cancelled, algorithm) == original_hash,
            "Image source/copy changed during staging.")
    return original_hash


def _build_tool(program, expected, prefix, cancelled):
    selection = Path(program)
    program = _regular(selection.resolve(strict=True))
    require(program.stat().st_size <= MAX_MATERIAL, "Unbounded Image build-tool executable.")
    _cancel(cancelled)
    before = digest(program, cancelled)
    observed = subprocess.check_output([str(program), "--version"], text=True, timeout=15).strip()
    _cancel(cancelled)
    require(bool(observed) and len(observed) <= 4096 and observed.splitlines()[0] == prefix + expected and
            (bool(prefix) or observed == expected), "Unreviewed Image build-tool executable version.")
    require(selection.resolve(strict=True) == program and digest(program, cancelled) == before,
            "Image build-tool executable changed during admission.")
    return {"name": program.name, "version": expected, "sha256": before}


def _tools(inputs, recipe, identity, root, cancelled):
    cache_file = _regular(inputs.build_directory / "CMakeCache.txt")
    cache = dict(line.split("=", 1) for line in cache_file.read_text(encoding="utf-8").splitlines()
                 if line and not line.startswith(("#", "//")) and "=" in line)

    def value(name):
        matches = [item for key, item in cache.items() if key.split(":", 1)[0] == name]
        require(len(matches) == 1, "Missing or ambiguous Image producer cache key: " + name)
        return matches[0]

    require(Path(value("CMAKE_HOME_DIRECTORY")).resolve() == root.resolve() and
            value("VCPKG_TARGET_TRIPLET") == recipe["triplet"] and
            Path(value("VCPKG_INSTALLED_DIR")).resolve() == inputs.installed_directory.resolve() and
            Path(value("CMAKE_INSTALL_PREFIX")).resolve() == inputs.prefix.resolve() and
            value("ARCFORGES_NATIVE_PROFILE") == "shim-static" and value("ARCFORGES_NATIVE_FAMILIES") == "Image" and
            value("CMAKE_BUILD_TYPE") == "Release",
            "Image binary was not produced by the admitted owning root/recipe/input tree.")
    version = ".".join(value("CMAKE_CACHE_" + part + "_VERSION") for part in ("MAJOR", "MINOR", "PATCH"))
    require(version == recipe["buildTools"]["cmake"], "Unreviewed Image CMake version.")
    cmake = _build_tool(value("CMAKE_COMMAND"), recipe["buildTools"]["cmake"], "cmake version ", cancelled)
    ninja = _build_tool(value("CMAKE_MAKE_PROGRAM"), recipe["buildTools"]["ninja"], "", cancelled)
    compilers = {}
    for language in ("C", "CXX"):
        selection = Path(value("CMAKE_" + language + "_COMPILER"))
        compiler = _regular(selection.resolve(strict=True))
        if recipe["host"] == "Windows":
            target = "x64" if recipe["architecture"] == "x86_64" else "arm64"
            require(compiler.as_posix().casefold().endswith(
                ("/VC/Tools/MSVC/" + recipe["compiler"]["toolset"] + "/bin/Hostx64/" + target + "/cl.exe").casefold()),
                "Image producer used an unreviewed MSVC target/toolset.")
        declarations = list((inputs.build_directory / "CMakeFiles").glob("*/CMake" + language + "Compiler.cmake"))
        require(len(declarations) == 1, "Missing actual Image compiler identity.")
        content = _regular(declarations[0]).read_text(encoding="utf-8")
        family = re.findall(r'set\(CMAKE_' + language + r'_COMPILER_ID "([^"]+)"\)', content)
        version = re.findall(r'set\(CMAKE_' + language + r'_COMPILER_VERSION "([^"]+)"\)', content)
        require(family == [recipe["compiler"]["family"]] and len(version) == 1, "Image compiler family is not admitted.")
        compilers[language] = {"name": compiler.name, "family": family[0], "version": version[0],
                               "sha256": digest(compiler, cancelled), "declarationSha256": digest(declarations[0], cancelled)}
        require(selection.resolve(strict=True) == compiler, "Image compiler selection changed during admission.")
    generated = _regular(inputs.build_directory / "native/identity/arc_build_identity.hpp")
    require(build_identity.native_suffix(identity) in generated.read_text(encoding="utf-8"),
            "Image build cache contains a different generated source identity.")
    return {"cmakeCacheSha256": digest(cache_file, cancelled), "cmake": recipe["buildTools"]["cmake"],
            "cmakeExecutable": cmake, "ninja": ninja["version"], "ninjaSha256": ninja["sha256"], "compilers": compilers,
            "generatedIdentitySha256": digest(generated, cancelled)}


def _compiled_inventory(sbom, triplet, admitted):
    require(isinstance(triplet, str) and re.fullmatch("[a-z0-9-]+", triplet), "Invalid compiled Image SPDX triplet.")
    require(isinstance(sbom.get("files"), list) and len(sbom["files"]) <= MAX_FILES,
            "Unbounded installed Image dependency inventory.")
    rows = []
    for item in sbom["files"]:
        if not item.get("SPDXID", "").startswith("SPDXRef-binary-file-"):
            continue
        relative = str(_sbom_path(item["fileName"]))
        if PurePosixPath(relative).parts[0] not in ("bin", "lib", "include", "share"):
            continue
        checksums = [value["checksumValue"] for value in item["checksums"] if value["algorithm"] == "SHA256"]
        require(len(checksums) == 1 and re.fullmatch("[0-9a-f]{64}", checksums[0]),
                "Missing or ambiguous compiled Image SPDX checksum.")
        path = triplet + "/" + relative
        require(path.casefold() not in admitted and len(admitted) < MAX_FILES,
                "Ambiguous, aliased or unbounded compiled Image SPDX material.")
        admitted[path.casefold()] = (path, checksums[0])
        rows.append((relative, checksums[0]))
    return rows


def _compiled_expected(admitted, path):
    _path(path)
    row = admitted.get(path.casefold())
    require(row is not None and row[0] == path, "Image dependency is absent or aliased in admitted compiled SPDX material.")
    return row[1]


def _verify_compiled_runtime(row, triplet, compiled, content):
    source_path = row.get("sourceSpdxPath")
    require(isinstance(source_path, str) and source_path.startswith(triplet + "/") and
            len(PurePosixPath(source_path).parts) >= 3 and PurePosixPath(source_path).parts[1] in ("bin", "lib"),
            "Missing Image runtime compiled-source binding.")
    require(_compiled_expected(compiled, source_path) == row["sha256"] and
            hashlib.sha256(content).hexdigest() == row["sha256"],
            "Packaged Image runtime differs from admitted compiled SPDX material.")


def _upstreams(staging, inputs, rid, recipe, base, expected_features, root, cancelled):
    # The pin and source tree are checked at their real producer trust handoff.
    actual = subprocess.check_output(["git", "-C", str(inputs.vcpkg), "rev-parse", "HEAD"], text=True).strip()
    require(actual == base["vcpkgCommit"] and not subprocess.check_output(
        ["git", "-C", str(inputs.vcpkg), "status", "--porcelain", "--untracked-files=no"], text=True).strip(),
        "Image vcpkg source differs from the reviewed pin.")
    sys.path.insert(0, str(ROOT / "eng/packaging"))
    import native
    database = native.installed_packages(inputs.installed_directory)
    closure = native.dependency_closure(database, ["opencolorio", "openimageio", "openexr", "imath"], recipe["triplet"])
    records, compiled = [], {}
    for name, triplet in closure:
        _cancel(cancelled)
        require(name in base["components"], "Unreviewed Image dependency/feature closure: " + name)
        component = base["components"][name]
        row = database[(name, triplet)]
        require(row["version"] == component["version"] and sorted(row["features"]) == expected_features[name],
                "Image dependency version/feature closure differs from the reviewed source.")
        share = inputs.installed_directory / triplet / "share" / name
        _abi_tools(share / "vcpkg_abi_info.txt", base)
        sbom = _document(share / "vcpkg.spdx.json")
        native_provenance.check_sources(base, name, sbom)
        require(isinstance(sbom.get("files"), list) and len(sbom["files"]) <= MAX_FILES,
                "Unbounded installed Image dependency inventory.")
        port = root / "eng/native/vcpkg/ports" / name
        if not port.is_dir():
            port = inputs.vcpkg / "ports" / name
        require(port.is_dir() and not _link(port), "Image dependency recipe is unavailable.")
        for relative, expected in component["recipe"]["files"].items():
            _path(relative)
            require(digest(_regular(port / relative, port), cancelled, lf=True) == expected,
                    "Image dependency recipe differs from approved source: " + name + "/" + relative)
            _copy(port / relative, staging / "recipes" / name / relative, cancelled)
        stem = name + "-" + triplet
        for original, target in ((share / "vcpkg.spdx.json", "licenses/" + stem + ".spdx.json"),
                                 (share / "copyright", "licenses/" + stem + ".txt"),
                                 (share / "vcpkg_abi_info.txt", "licenses/" + stem + ".abi.txt")):
            _copy(original, staging / target, cancelled)
        expected_legal = {item["sha256"] for item in component["legal"]}
        require(digest(share / "copyright", cancelled, lf=True) in expected_legal,
                "Image dependency legal material differs from reviewed originals: " + name)
        for relative, expected in _compiled_inventory(sbom, triplet, compiled):
            require(digest(_regular(inputs.installed_directory / triplet / relative,
                    inputs.installed_directory / triplet), cancelled) == expected,
                    "Actual compiled/header Image dependency differs from its SBOM: " + name + "/" + relative)
        for resource in component["resources"]:
            source = _regular(inputs.downloads / resource["cacheName"], inputs.downloads)
            require(digest(source, cancelled, "sha512") == resource["sha512"], "Image source archive integrity mismatch.")
            _copy(source, staging / "sources" / resource["cacheName"], cancelled,
                  resource["sha512"], "sha512") if not (staging / "sources" / resource["cacheName"]).exists() else None
        for extra in component["extras"]:
            source = _regular(inputs.downloads / extra["cacheName"], inputs.downloads)
            expected = extra["sourceSha256"] or extra["sourceSha512"]
            require(digest(source, cancelled, "sha256" if extra["sourceSha256"] else "sha512") == expected,
                    "Image legal companion source integrity mismatch.")
            legal = _legal_bytes(extra, inputs.downloads, cancelled)
            target = staging / extra["output"]
            target.parent.mkdir(parents=True, exist_ok=True)
            require(not target.exists(), "Colliding Image legal companions.")
            _write_bytes(target, legal)
        records.append({"name": name, "triplet": triplet, "version": row["version"], "features": sorted(row["features"]),
                        "record": component["record"], "license": "licenses/" + stem + ".txt",
                        "sbom": "licenses/" + stem + ".spdx.json", "buildInfo": "licenses/" + stem + ".abi.txt"})
    require({item["name"] for item in records} == set(base["components"]), "Image dependency closure omits approved inputs.")
    _copy(inputs.vcpkg / "LICENSE.txt", staging / "licenses/provenance/vcpkg-LICENSE.txt", cancelled)
    return records, compiled


def _inventory(directory, cancelled=None):
    directory = Path(directory)
    require(directory.is_dir() and not _link(directory), "Missing or linked Image inventory root.")
    rows, aliases, pending, count = [], set(), [(directory, 0)], 0
    while pending:
        parent, depth = pending.pop()
        require(not _link(parent), "Image inventory directory ownership changed.")
        with os.scandir(parent) as entries:
            for entry in entries:
                _cancel(cancelled)
                count += 1
                require(count <= MAX_FILES and depth < 64, "Unbounded Image artifact directory inventory.")
                path = Path(entry.path)
                require(not _link(path), "Linked Image output material.")
                name = path.relative_to(directory).as_posix()
                _path(name)
                require(name.casefold() not in aliases, "Colliding Image file inventory.")
                aliases.add(name.casefold())
                if entry.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                    continue
                require(entry.is_file(follow_symlinks=False), "Non-regular Image artifact material.")
                rows.append({"path": name, "sha256": digest(path, cancelled)})
    return sorted(rows, key=lambda row: row["path"])


@contextmanager
def _stage_lock(destination, cancelled=None):
    lock = destination.parent / ("." + destination.name + ".image-stage-lock")
    kernel_path = destination.parent / ("." + destination.name + ".image-stage-lockfile")
    require(not _link(kernel_path) and not _link(lock), "Linked Image staging lock is forbidden.")
    stream = kernel_path.open("a+b")
    acquired = False
    try:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        for attempt in range(40):
            _cancel(cancelled)
            stream.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except OSError as error:
                import errno
                if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                if attempt == 39:
                    raise ValueError("Image staging is busy; another writer owns the destination.") from error
                time.sleep(0.05)
        # Kernel ownership survives waiter races and is released on process death.
        # An old owner marker is replaced only after actual kernel admission.
        token = uuid.uuid4().hex
        lock.mkdir(exist_ok=True)
        require(not _link(lock), "Image staging lock ownership changed.")
        owner = lock / "owner"
        require(not _link(owner), "Linked Image lock owner is forbidden.")
        with owner.open("wb") as output:
            output.write(token.encode("ascii"))
            output.flush()
            os.fsync(output.fileno())
        yield
    finally:
        try:
            if acquired:
                require(not _link(lock), "Image staging lock ownership changed.")
                if (lock / "owner").exists():
                    require((lock / "owner").read_text(encoding="ascii") == token, "Image staging lock ownership changed.")
                    (lock / "owner").unlink()
                lock.rmdir()
        finally:
            # Closing the descriptor releases the OS lock even on cleanup errors.
            stream.close()


def _promotion_intent(staging, destination, backup, had_previous):
    journal = destination.parent / ("." + destination.name + ".image-promotion.json")
    require(not journal.exists() and not _link(journal), "Unrecovered Image promotion journal.")
    require(staging.parent == destination.parent and
            staging.name.startswith("." + destination.name + ".image-stage-") and
            re.fullmatch(re.escape("." + destination.name + ".previous-") + r"[a-f0-9]{32}", backup.name),
            "Image promotion paths are not owned siblings.")
    temporary = destination.parent / ("." + destination.name + ".image-journal-" + uuid.uuid4().hex)
    try:
        _write(temporary, {"schemaVersion": 1, "destination": destination.name, "staging": staging.name,
                           "backup": backup.name, "hadPrevious": had_previous})
        os.replace(temporary, journal)
    finally:
        if temporary.exists():
            temporary.unlink()
    _directory_sync(destination.parent)
    return journal


def _recover_promotion(destination):
    # Called with the destination's kernel lock held. The durable intent precedes
    # any rename. Presence of the owned paths distinguishes rollback from a
    # completed publication without trusting unvalidated staged contents.
    journal = destination.parent / ("." + destination.name + ".image-promotion.json")
    if not journal.exists():
        require(not _link(journal), "Linked Image promotion journal.")
        return
    value = _document(journal)
    require(set(value) == {"schemaVersion", "destination", "staging", "backup", "hadPrevious"} and
            value["schemaVersion"] == 1 and value["destination"] == destination.name and
            type(value["hadPrevious"]) is bool and isinstance(value["staging"], str) and
            isinstance(value["backup"], str), "Invalid Image promotion journal.")
    _path(value["staging"])
    _path(value["backup"])
    require("/" not in value["staging"] and "/" not in value["backup"] and
            value["staging"].startswith("." + destination.name + ".image-stage-") and
            re.fullmatch(re.escape("." + destination.name + ".previous-") + r"[a-f0-9]{32}", value["backup"]),
            "Image recovery paths are not owned siblings.")
    staging, backup = (destination.parent / value[key] for key in ("staging", "backup"))
    for path in (destination, staging, backup):
        require(not _link(path) and (not path.exists() or path.is_dir()), "Unsafe Image recovery material.")
    require(not backup.exists() or value["hadPrevious"], "Unexpected Image recovery backup.")
    require(not value["hadPrevious"] or destination.exists() or backup.exists(),
            "Image recovery cannot locate the previous candidate.")
    require(not (destination.exists() and backup.exists() and staging.exists()),
            "Image recovery has conflicting publication paths.")
    if backup.exists() and not destination.exists():
        os.replace(backup, destination)
        _directory_sync(destination.parent)
    # If destination and backup both exist, publication completed. Otherwise
    # retain the old destination; interrupted unpromoted material is rebuilt.
    for path in (backup, staging):
        if path.exists():
            shutil.rmtree(path)
            _directory_sync(destination.parent)
    journal.unlink()
    _directory_sync(destination.parent)


def _promote(staging, destination):
    backup = destination.parent / ("." + destination.name + ".previous-" + uuid.uuid4().hex)
    require(not _link(destination) and not backup.exists(), "Unsafe Image promotion destination.")
    had_previous = destination.exists()
    _promotion_intent(staging, destination, backup, had_previous)
    try:
        if had_previous:
            require(destination.is_dir(), "Image promotion would replace a non-directory.")
            os.replace(destination, backup)
            _directory_sync(destination.parent)
        os.replace(staging, destination)
        _directory_sync(destination.parent)
    except BaseException:
        _recover_promotion(destination)
        raise
    _recover_promotion(destination)


def _cached_stage(destination, source_commit, rid, root, cancelled):
    try:
        cached = verify_stage(destination, source_commit, root, cancelled=cancelled)
    except StageCancelled:
        raise
    except ValueError:
        _cancel(cancelled)
        return None  # A successor is fully verified before the old candidate is moved.
    _cancel(cancelled)
    return cached if cached["rid"] == rid else None


def stage(destination, rid, inputs, root=ROOT, cancelled=None):
    root, destination = Path(root).resolve(), Path(destination).absolute()
    value, material = profile(root)
    require(rid in native_binary.RIDS, "Image RID is not admitted.")
    recipe, policy = material["recipes"]["rids"][rid], material["systemPolicy"]["rids"][rid]
    require(isinstance(inputs, ProducerInputs), "Missing explicit Image production inputs.")
    require(destination.name and destination.name not in (".", "..") and not _link(destination), "Unsafe Image destination.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    for part in (destination.parent, *destination.parent.parents):
        require(not _link(part), "Linked Image promotion parent.")
    identity = build_identity.build_identity(root)
    require(not identity["dirty"], "Commit reviewed Image source before staging production artifacts.")
    audit = check_provenance.run(root, "DesktopPlatform")
    require(not audit["dirty"], "Image source/legal provenance is not clean.")
    with _stage_lock(destination, cancelled):
        _recover_promotion(destination)
        _cancel(cancelled)
        if destination.exists():
            cached = _cached_stage(destination, identity["sourceCommit"], rid, root, cancelled)
            if cached is not None:
                return cached
        staging = Path(tempfile.mkdtemp(prefix="." + destination.name + ".image-stage-", dir=destination.parent))
        try:
            package = staging / recipe["package"]
            runtime = package / "runtimes" / rid / "native"
            tools = _tools(inputs, recipe, identity, root, cancelled)
            if rid.startswith("linux-"):
                tools["externalTools"] = _external_tool_handoff(inputs, rid, root, cancelled)
            source_profile, features = _selection(rid, value, material)
            upstream, compiled = _upstreams(package, inputs, rid, recipe, source_profile, features, root, cancelled)
            if rid.startswith("linux-"):
                for definition in _external_definitions(value).values():
                    for legal in definition["legal"]:
                        content = _legal_bytes(legal, inputs.downloads, cancelled)
                        target = package / legal["output"]
                        if target.exists():
                            require(_regular(target, package).read_bytes() == content,
                                    "Conflicting external Image original legal material.")
                        else:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            _write_bytes(target, content)
            triplet = value["triplets"][rid]
            for kind, directory in (("owned", root), ("upstream", inputs.vcpkg)):
                if triplet[kind + "Path"] is not None:
                    original = _regular(directory / triplet[kind + "Path"], directory)
                    require(digest(original, cancelled, lf=True) == triplet[kind + "Sha256Lf"], "Changed Image triplet input.")
                    _copy(original, package / "recipes/toolchains" / (kind + "-" + recipe["triplet"] + ".cmake"), cancelled)
            available = {}
            directories = [inputs.prefix / "native", inputs.installed_directory / recipe["triplet"] / "bin",
                           inputs.installed_directory / recipe["triplet"] / "lib"]
            if inputs.compiler_runtime is not None:
                directories.append(inputs.compiler_runtime)
            for directory in directories:
                if not directory.exists():
                    continue
                require(not _link(directory), "Linked Image native input directory.")
                for path in directory.iterdir():
                    if path.suffix not in (".dll", ".so", ".dylib") and ".so." not in path.name:
                        continue
                    _regular(path, directory)
                    key = _key(path.name, rid)
                    if key in available:
                        require(digest(path, cancelled) == digest(available[key], cancelled), "Colliding Image library inputs.")
                    else:
                        available[key] = path
            pending, selected, signatures = [recipe["library"]], {}, {}
            while pending:
                _cancel(cancelled)
                name = pending.pop()
                key = _key(name, rid)
                if key in selected:
                    continue
                require(key in available, "Missing transitive Image native dependency: " + name)
                original = available[key]
                info = native_binary.inspect(original, rid)
                _searchpaths(info, rid, policy)
                expected, source_binding = None, {}
                if key == _key(recipe["library"], rid):
                    _owned(info, recipe)
                    require(build_identity.native_suffix(identity).encode("ascii") in original.read_bytes(),
                            "Image binary contains a different source/build identity.")
                elif rid.startswith("win-") and key in value["compilerRuntime"][rid]["files"]:
                    signatures[key] = _compiler_runtime_signature(original, rid, value)
                else:
                    require(original.resolve().is_relative_to((inputs.installed_directory / recipe["triplet"]).resolve()),
                            "Image bundled dependency has no admitted installed source.")
                    relative = original.resolve().relative_to(inputs.installed_directory.resolve()).as_posix()
                    expected = _compiled_expected(compiled, relative)
                    source_binding = {"sourceSpdxPath": relative}
                source_hash = _copy(original, runtime / original.name, cancelled, expected)
                selected[key] = {"name": original.name, "sha256": source_hash, **info.as_manifest(), **source_binding}
                for dependency in info.imports:
                    bundled = _dependency(dependency, rid, policy)
                    if bundled is not None:
                        pending.append(bundled)
            for relative in ("native/arcimage-abi/include/arc/arc_slate_image_abi.h", "native/shared/include/arc/arc_native_abi.h"):
                _copy(root / relative, package / "include/arc" / Path(relative).name, cancelled)
            if rid.startswith("win-"):
                _copy(inputs.prefix / "lib/ArcImageNative.lib", package / "sdk" / rid / "lib/ArcImageNative.lib", cancelled)
                for legal in material["sourceProfile"]["platformRuntime"]["legal"]:
                    original = _regular(inputs.downloads / legal["cacheName"], inputs.downloads)
                    require(digest(original, cancelled, "sha256" if legal["sourceSha256"] else "sha512") ==
                            (legal["sourceSha256"] or legal["sourceSha512"]), "Image Microsoft grant source differs.")
                    content = _legal_bytes(legal, inputs.downloads, cancelled)
                    path = package / legal["output"]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    _write_bytes(path, content)
            for binding in (PROFILE, value["sourceProfile"]["path"], value["recipes"]["path"], value["systemPolicy"]["path"]):
                _copy(root / binding, package / "provenance" / Path(binding).name, cancelled)
            rows = sorted(selected.values(), key=lambda item: item["name"])
            manifest = {"schemaVersion": 1, "sourceCommit": identity["sourceCommit"], "rid": rid, "library": "ArcImageNative",
                        "abi": {"major": 1, "minor": 1}, "vcpkgCommit": material["recipes"]["vcpkgCommit"], "files": rows}
            _write(package / "native-manifest.json", manifest)
            _write(runtime / "ArcImageNative.manifest.json", manifest)
            _write(package / "sbom.json", {"schemaVersion": 1, "sourceCommit": identity["sourceCommit"],
                                           "binaryFiles": rows, "buildDependencies": upstream, "buildTools": tools})
            targets = package / "buildTransitive" / (recipe["package"] + ".targets")
            targets.parent.mkdir(parents=True, exist_ok=True)
            _write_bytes(targets, ('<Project><!-- SPDX-License-Identifier: AGPL-3.0-only -->\n'
                               '<Target Name="RequireImageRuntimeRid" BeforeTargets="PrepareForBuild">\n'
                               '<Error Condition="\'$(RuntimeIdentifier)\' != \'' + rid + '\'" Text="Image runtime requires ' + rid + '." />\n'
                               '</Target></Project>\n').encode("utf-8"))
            _write_bytes(package / "NOTICE.md", b"# Image runtime notices\n\nOwned ABI: AGPL-3.0-only. Original dependency legal texts, SPDX/source identities, selected source archives and applied recipes are retained. OS libraries are prerequisites and are never redistributed as this package. Compiler/runtime floors are the actual inspected per-artifact metadata. Staging is not publisher authorization or OS acceptance.\n")
            receipt = {"schemaVersion": 1, "kind": "image-runtime-production-input", "sourceCommit": identity["sourceCommit"],
                       "rid": rid, "package": recipe["package"], "profile": PROFILE, "profileSha256Lf": digest(root / PROFILE, lf=True),
                       "recipeSha256Lf": value["recipes"]["sha256Lf"], "build": identity, "producer": tools,
                       "compilerRuntimeSignatures": signatures, "files": _inventory(package, cancelled)}
            _write(package / RECEIPT, receipt)
            artifact = {"schemaVersion": 1, "sourceCommit": identity["sourceCommit"], "rid": rid, "build": identity,
                        "packages": [{"id": recipe["package"], "files": _inventory(package, cancelled)}]}
            _write(staging / "native-artifact.json", artifact)
            verify_stage(staging, identity["sourceCommit"], root, cancelled=cancelled)
            _cancel(cancelled)
            for directory in sorted((path for path in staging.rglob("*") if path.is_dir()), reverse=True):
                _directory_sync(directory)
            _directory_sync(staging)
            _promote(staging, destination)
            return artifact
        finally:
            if staging.exists():
                require(staging.parent.resolve() == destination.parent.resolve() and
                        staging.name.startswith("." + destination.name + ".image-stage-") and not _link(staging),
                        "Image temporary ownership changed.")
                shutil.rmtree(staging)


def verify_package(entry, read, names, source_commit, root=ROOT, cancelled=None):
    _cancel(cancelled)
    original_read = read

    def read(path):
        _cancel(cancelled)
        _path(path)
        try:
            content = original_read(path)
        except (KeyError, FileNotFoundError) as error:
            raise ValueError("Missing Image production material: " + path) from error
        require(isinstance(content, bytes) and len(content) <= MAX_MATERIAL,
                "Unbounded Image package material.")
        _cancel(cancelled)
        return content

    value, material = profile(root)
    rid = entry["rid"]
    require(rid in native_binary.RIDS, "Unknown Image package RID.")
    recipe, policy = material["recipes"]["rids"][rid], material["systemPolicy"]["rids"][rid]
    require(entry["id"] == recipe["package"] and entry["library"] == "ArcImageNative", "Image package identity differs.")
    require(len(names) <= MAX_FILES and len(names) == len(set(names)), "Unbounded or duplicate Image package inventory.")
    for name in names:
        _path(name)
    receipt = _json(read(RECEIPT))
    require(receipt.get("schemaVersion") == 1 and receipt.get("kind") == "image-runtime-production-input" and
            receipt.get("sourceCommit") == source_commit and receipt.get("rid") == rid and
            receipt.get("package") == recipe["package"] and receipt.get("profile") == PROFILE and
            receipt.get("profileSha256Lf") == digest(Path(root) / PROFILE, lf=True) and
            receipt.get("recipeSha256Lf") == value["recipes"]["sha256Lf"], "Image production input receipt mismatch.")
    build_identity.verify_source_build(root, receipt["build"])
    declared = {}
    require(isinstance(receipt.get("files"), list) and len(receipt["files"]) <= MAX_FILES,
            "Unbounded Image receipt inventory.")
    for row in receipt["files"]:
        _path(row["path"])
        require(row["path"].casefold() not in declared, "Colliding Image receipt paths.")
        declared[row["path"].casefold()] = row["path"]
        require(row["path"] in names and hashlib.sha256(read(row["path"])).hexdigest() == row["sha256"],
                "Image production material differs from its copied-byte receipt.")
    bound_prefixes = ("runtimes/", "include/", "sdk/", "sources/", "recipes/", "licenses/", "provenance/", "buildTransitive/")
    require({name for name in names if name.startswith(bound_prefixes) or name in ("native-manifest.json", "sbom.json", "NOTICE.md")} ==
            set(declared.values()), "Image package has unbound/missing production material.")
    for binding in (PROFILE, value["sourceProfile"]["path"], value["recipes"]["path"], value["systemPolicy"]["path"]):
        require(hashlib.sha256(read("provenance/" + Path(binding).name).replace(b"\r\n", b"\n")).hexdigest() ==
                digest(Path(root) / binding, lf=True), "Copied Image admission/profile input differs from authority.")
    manifest = _json(read("native-manifest.json"))
    prefix = "runtimes/" + rid + "/native/"
    require(not any(name.startswith("runtimes/") and not name.startswith(prefix) for name in names),
            "Unexpected Image RID runtime assets.")
    require(manifest.get("schemaVersion") == 1 and manifest.get("sourceCommit") == source_commit and
            manifest.get("rid") == rid and manifest.get("library") == "ArcImageNative" and
            manifest.get("abi") == {"major": 1, "minor": 1} and
            read(prefix + "ArcImageNative.manifest.json") == read("native-manifest.json"), "Image native manifest mismatch.")
    files = {}
    for row in manifest["files"]:
        require(Path(row["name"]).name == row["name"] and "/" not in row["name"] and "\\" not in row["name"] and
                _key(row["name"], rid) not in files, "Colliding or escaping Image native files.")
        content = read(prefix + row["name"])
        require(hashlib.sha256(content).hexdigest() == row["sha256"], "Image native content hash mismatch.")
        info = native_binary.inspect_bytes(content, rid)
        require({key: row[key] for key in info.as_manifest()} == info.as_manifest(), "Image native inspection metadata mismatch.")
        _searchpaths(info, rid, policy)
        files[_key(row["name"], rid)] = info
    require(set(files) == {_key(name[len(prefix):], rid) for name in names
                           if name.startswith(prefix) and name != prefix + "ArcImageNative.manifest.json"},
            "Image native closure differs from actual payload.")
    require(_key(recipe["library"], rid) in files, "Image owned library is missing.")
    _owned(files[_key(recipe["library"], rid)], recipe)
    require(build_identity.native_suffix(receipt["build"]).encode("ascii") in read(prefix + recipe["library"]),
            "Packaged Image binary contains a different source/build identity.")
    for info in files.values():
        for name in info.imports:
            bundled = _dependency(name, rid, policy)
            require(bundled is None or _key(bundled, rid) in files, "Missing Image transitive native dependency.")
    sbom = _json(read("sbom.json"))
    require(sbom.get("sourceCommit") == source_commit and sbom.get("binaryFiles") == manifest["files"], "Image SBOM differs.")
    require(sbom.get("buildTools") == receipt["producer"], "Image compiler/tool receipt differs.")
    if rid.startswith("linux-"):
        require("externalTools" in receipt["producer"], "Missing actual external Image tool handoff.")
        _verify_external_handoff(receipt["producer"]["externalTools"], value, rid, receipt["build"], read)
    else:
        require("externalTools" not in receipt["producer"], "Foreign external Image tool handoff.")
    base, features = _selection(rid, value, material)
    require({row["name"] for row in sbom["buildDependencies"]} == set(base["components"]),
            "Image SBOM omits the reviewed dependency closure.")
    require(len(sbom["buildDependencies"]) == len(base["components"]),
            "Duplicate Image SBOM dependencies.")
    compiled = {}
    for dependency in sbom["buildDependencies"]:
        component = base["components"][dependency["name"]]
        require(dependency["version"] == component["version"] and dependency["features"] == features[dependency["name"]] and
                dependency["record"] == component["record"], "Image packaged dependency/source/feature identity differs.")
        dependency_spdx = _json(read(dependency["sbom"]))
        native_provenance.check_sources(base, dependency["name"], dependency_spdx)
        _compiled_inventory(dependency_spdx, dependency["triplet"], compiled)
        abi_content = read(dependency["buildInfo"]).decode("utf-8")
        require([line.split()[1:] for line in abi_content.splitlines() if line.startswith("cmake ")] ==
                [[base["buildTools"]["vcpkgCMake"]]], "Packaged Image dependency used an unreviewed vcpkg CMake version.")
        require(hashlib.sha256(read(dependency["license"]).replace(b"\r\n", b"\n")).hexdigest() in
                {item["sha256"] for item in component["legal"]}, "Packaged Image legal originals differ.")
        for name, expected in component["recipe"]["files"].items():
            require(hashlib.sha256(read("recipes/" + dependency["name"] + "/" + name).replace(b"\r\n", b"\n")).hexdigest() == expected,
                    "Packaged Image applied recipe differs from source.")
        for resource in component["resources"]:
            require(hashlib.sha512(read("sources/" + resource["cacheName"])).hexdigest() == resource["sha512"],
                    "Packaged Image corresponding source archive differs.")
        for extra in component["extras"]:
            require(hashlib.sha256(read(extra["output"])).hexdigest() == extra["sha256"],
                    "Packaged Image original legal companion differs.")
    for row in manifest["files"]:
        key = _key(row["name"], rid)
        if key == _key(recipe["library"], rid) or (rid.startswith("win-") and key in value["compilerRuntime"][rid]["files"]):
            require("sourceSpdxPath" not in row, "Unexpected compiled SPDX binding on owned/compiler Image binary.")
            continue
        _verify_compiled_runtime(row, recipe["triplet"], compiled, read(prefix + row["name"]))
    for relative in ("native/arcimage-abi/include/arc/arc_slate_image_abi.h", "native/shared/include/arc/arc_native_abi.h"):
        require(hashlib.sha256(read("include/arc/" + Path(relative).name).replace(b"\r\n", b"\n")).hexdigest() ==
                digest(Path(root) / relative, lf=True), "Packaged Image C17 header differs from source.")
    if rid.startswith("win-"):
        runtime_files = value["compilerRuntime"][rid]["files"]
        selected = {key for key in files if key in runtime_files}
        require(receipt["compilerRuntimeSignatures"] == {key: {**runtime_files[key], "signature": "valid"} for key in selected},
                "Image compiler-runtime signature receipt differs from admitted actual bytes.")
        for row in manifest["files"]:
            key = _key(row["name"], rid)
            if key in runtime_files:
                require(row["sha256"] == runtime_files[key]["sha256"], "Image compiler-runtime content differs from admission.")
        for legal in base["platformRuntime"]["legal"]:
            require(hashlib.sha256(read(legal["output"])).hexdigest() == legal["sha256"],
                    "Image Microsoft redistribution grant differs.")
    return receipt


def verify_stage(destination, source_commit, root=ROOT, cancelled=None):
    _cancel(cancelled)
    destination = Path(destination)
    actual = _inventory(destination, cancelled)
    artifact = _document(destination / "native-artifact.json")
    require(artifact.get("schemaVersion") == 1 and artifact.get("sourceCommit") == source_commit and
            artifact.get("rid") in native_binary.RIDS and len(artifact.get("packages", ())) == 1, "Image artifact identity differs.")
    build_identity.verify_source_build(root, artifact["build"])
    package = artifact["packages"][0]
    expected = "ArcForges.Native.Image.Runtime." + artifact["rid"]
    require(package["id"] == expected, "Image artifact package/RID differs.")
    directory = destination / expected
    require(package["files"] == _inventory(directory, cancelled), "Image artifact copied-byte inventory differs.")
    require({row["path"] for row in actual} == {"native-artifact.json"} |
            {expected + "/" + row["path"] for row in package["files"]}, "Unbound Image artifact files.")
    verify_package({"id": expected, "rid": artifact["rid"], "library": "ArcImageNative"},
                   lambda name: _regular(directory / str(_path(name)), directory).read_bytes(),
                   {row["path"] for row in package["files"]}, source_commit, root, cancelled=cancelled)
    _cancel(cancelled)
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "verify", "acquire-legal", "observe-tools"))
    parser.add_argument("--rid", choices=tuple(native_binary.RIDS), required=True)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--vcpkg-root", type=Path)
    parser.add_argument("--downloads", type=Path)
    parser.add_argument("--compiler-runtime", type=Path)
    parser.add_argument("--commit")
    args = parser.parse_args()
    if args.command == "acquire-legal":
        require(args.downloads is not None, "Image legal acquisition requires an explicit cache.")
        return acquire_legal_inputs(args.downloads, args.rid)
    if args.command == "observe-tools":
        require(args.downloads is not None, "External Image tool observation requires an explicit original cache.")
        result = observe_external_tools(args.downloads, args.rid)
        output = ROOT / "artifacts/image-external-tools" / (args.rid + ".json")
        output.parent.mkdir(parents=True, exist_ok=True)
        _write(output, result)
        return result
    require(args.directory is not None, "Image stage/verify requires an explicit directory.")
    if args.command == "verify":
        artifact = verify_stage(args.directory, args.commit or build_identity.git(ROOT, "rev-parse", "HEAD"))
        require(artifact["rid"] == args.rid, "Image CLI verification RID differs from the actual artifact.")
        return artifact
    require(args.vcpkg_root is not None and args.downloads is not None, "Image staging requires explicit pinned vcpkg/cache inputs.")
    _, material = profile()
    recipe = material["recipes"]["rids"][args.rid]
    inputs = ProducerInputs(ROOT / recipe["installDirectory"], ROOT / recipe["buildDirectory"],
                            ROOT / recipe["installedDirectory"], args.vcpkg_root, args.downloads, args.compiler_runtime)
    return stage(args.directory, args.rid, inputs)


if __name__ == "__main__":
    main()
