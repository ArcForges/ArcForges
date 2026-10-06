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
    return base, features


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
    ninja = _regular(Path(value("CMAKE_MAKE_PROGRAM")))
    _cancel(cancelled)
    observed = subprocess.check_output([str(ninja), "--version"], text=True, timeout=15).strip()
    require(observed == recipe["buildTools"]["ninja"], "Unreviewed Image Ninja version.")
    compilers = {}
    for language in ("C", "CXX"):
        compiler = _regular(Path(value("CMAKE_" + language + "_COMPILER")))
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
    generated = _regular(inputs.build_directory / "native/identity/arc_build_identity.hpp")
    require(build_identity.native_suffix(identity) in generated.read_text(encoding="utf-8"),
            "Image build cache contains a different generated source identity.")
    return {"cmakeCacheSha256": digest(cache_file, cancelled), "cmake": recipe["buildTools"]["cmake"],
            "ninja": observed, "ninjaSha256": digest(ninja, cancelled), "compilers": compilers,
            "generatedIdentitySha256": digest(generated, cancelled)}


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
    records = []
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
        for item in sbom.get("files", []):
            if not item.get("SPDXID", "").startswith("SPDXRef-binary-file-"):
                continue
            relative = str(_sbom_path(item["fileName"]))
            if PurePosixPath(relative).parts[0] not in ("bin", "lib", "include", "share"):
                continue
            checksums = [value["checksumValue"] for value in item["checksums"] if value["algorithm"] == "SHA256"]
            require(len(checksums) == 1 and digest(_regular(inputs.installed_directory / triplet / relative,
                    inputs.installed_directory / triplet), cancelled) == checksums[0],
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
    return records


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
            try:
                cached = verify_stage(destination, identity["sourceCommit"], root)
                if cached["rid"] == rid:
                    return cached
            except ValueError:
                pass  # A successor is fully staged/verified before the old candidate is moved.
        staging = Path(tempfile.mkdtemp(prefix="." + destination.name + ".image-stage-", dir=destination.parent))
        try:
            package = staging / recipe["package"]
            runtime = package / "runtimes" / rid / "native"
            tools = _tools(inputs, recipe, identity, root, cancelled)
            source_profile, features = _selection(rid, value, material)
            upstream = _upstreams(package, inputs, rid, recipe, source_profile, features, root, cancelled)
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
                if key == _key(recipe["library"], rid):
                    _owned(info, recipe)
                    require(build_identity.native_suffix(identity).encode("ascii") in original.read_bytes(),
                            "Image binary contains a different source/build identity.")
                elif rid.startswith("win-") and key in value["compilerRuntime"][rid]["files"]:
                    signatures[key] = _compiler_runtime_signature(original, rid, value)
                else:
                    require(original.resolve().is_relative_to((inputs.installed_directory / recipe["triplet"]).resolve()),
                            "Image bundled dependency has no admitted installed source.")
                source_hash = _copy(original, runtime / original.name, cancelled)
                selected[key] = {"name": original.name, "sha256": source_hash, **info.as_manifest()}
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
            verify_stage(staging, identity["sourceCommit"], root)
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


def verify_package(entry, read, names, source_commit, root=ROOT):
    original_read = read

    def read(path):
        _path(path)
        try:
            content = original_read(path)
        except (KeyError, FileNotFoundError) as error:
            raise ValueError("Missing Image production material: " + path) from error
        require(isinstance(content, bytes) and len(content) <= MAX_MATERIAL,
                "Unbounded Image package material.")
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
    base, features = _selection(rid, value, material)
    require({row["name"] for row in sbom["buildDependencies"]} == set(base["components"]),
            "Image SBOM omits the reviewed dependency closure.")
    require(len(sbom["buildDependencies"]) == len(base["components"]),
            "Duplicate Image SBOM dependencies.")
    for dependency in sbom["buildDependencies"]:
        component = base["components"][dependency["name"]]
        require(dependency["version"] == component["version"] and dependency["features"] == features[dependency["name"]] and
                dependency["record"] == component["record"], "Image packaged dependency/source/feature identity differs.")
        native_provenance.check_sources(base, dependency["name"], _json(read(dependency["sbom"])))
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
            require(hashlib.sha256(read(extra["output"]).replace(b"\r\n", b"\n")).hexdigest() == extra["sha256"],
                    "Packaged Image original legal companion differs.")
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
            require(hashlib.sha256(read(legal["output"]).replace(b"\r\n", b"\n")).hexdigest() == legal["sha256"],
                    "Image Microsoft redistribution grant differs.")
    return receipt


def verify_stage(destination, source_commit, root=ROOT):
    destination = Path(destination)
    actual = _inventory(destination)
    artifact = _document(destination / "native-artifact.json")
    require(artifact.get("schemaVersion") == 1 and artifact.get("sourceCommit") == source_commit and
            artifact.get("rid") in native_binary.RIDS and len(artifact.get("packages", ())) == 1, "Image artifact identity differs.")
    build_identity.verify_source_build(root, artifact["build"])
    package = artifact["packages"][0]
    expected = "ArcForges.Native.Image.Runtime." + artifact["rid"]
    require(package["id"] == expected, "Image artifact package/RID differs.")
    directory = destination / expected
    require(package["files"] == _inventory(directory), "Image artifact copied-byte inventory differs.")
    require({row["path"] for row in actual} == {"native-artifact.json"} |
            {expected + "/" + row["path"] for row in package["files"]}, "Unbound Image artifact files.")
    verify_package({"id": expected, "rid": artifact["rid"], "library": "ArcImageNative"},
                   lambda name: _regular(directory / str(_path(name)), directory).read_bytes(),
                   {row["path"] for row in package["files"]}, source_commit, root)
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "verify", "acquire-legal"))
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
