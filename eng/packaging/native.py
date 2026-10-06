# SPDX-License-Identifier: AGPL-3.0-only
"""Stage and audit the real Windows ABI binary and upstream dependency closure."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from contextlib import contextmanager
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng"))
import native_provenance
import build_identity
VCPKG_COMMIT = "36677bbd0b3bf11da7376e62e14bffcc54d2eaeb"
RIDS = frozenset(("win-x64", "win-arm64", "linux-x64", "linux-arm64", "osx-x64", "osx-arm64"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def abi_contract(entry):
    """Closed functional contracts, shared by staging and package verification. No arbitrary export allowlist is accepted."""
    families = {
        "arc_image": ("ArcImageNative", ("open", "read", "close")),
        "arc_pdf": ("ArcPdfNative", ("open", "page_info", "render", "text", "close")),
    }
    prefix = entry.get("prefix")
    require(isinstance(prefix, str) and prefix in families, "Unknown owned native ABI family.")
    library, operations = families[prefix]
    require(entry.get("library") == library, "Native ABI family/library mismatch.")
    exports = {prefix + "_" + suffix for suffix in ("get_abi_version", "get_build_info", "get_last_error", *operations)}
    return {"major": 1, "minor": 1}, exports


def verify_abi(entry, exports, abi=None):
    version, expected = abi_contract(entry)
    require(isinstance(exports, (list, tuple)) and all(isinstance(export, str) for export in exports) and
            len(exports) == len(expected) and set(exports) == expected,
            "Owned native export set differs from the admitted ABI.")
    if abi is not None:
        require(isinstance(abi, dict) and set(abi) == {"major", "minor"} and
                all(type(value) is int for value in abi.values()) and abi == version,
                "Native ABI manifest version differs from the admitted functional contract.")
    return version


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def pe(data):
    """Read x64 PE imports, delay imports and named exports without executing the DLL."""
    require(data[:2] == b"MZ", "Native asset is not a PE file.")
    start = struct.unpack_from("<I", data, 0x3c)[0]
    require(data[start:start + 4] == b"PE\0\0", "Invalid PE signature.")
    machine, sections = struct.unpack_from("<HH", data, start + 4)
    optional_size = struct.unpack_from("<H", data, start + 20)[0]
    optional = start + 24
    require(machine == 0x8664 and struct.unpack_from("<H", data, optional)[0] == 0x20b,
            "Native asset must be Windows x64 PE32+.")
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    table = optional + optional_size

    def offset(rva):
        for i in range(sections):
            virtual_size, address, raw_size, raw = struct.unpack_from("<IIII", data, table + i * 40 + 8)
            if address <= rva < address + max(virtual_size, raw_size):
                result = raw + rva - address
                require(result < len(data), "PE RVA escapes file.")
                return result
        raise ValueError(f"Unmapped PE RVA: {rva}")

    def string(rva):
        begin = offset(rva)
        end = data.find(b"\0", begin, min(len(data), begin + 4096))
        require(end >= begin, "Unterminated PE name.")
        return data[begin:end].decode("ascii")

    imports = set()
    for index, stride, name_offset in [(1, 20, 12), (13, 32, 4)]:
        rva, size = struct.unpack_from("<II", data, optional + 112 + index * 8)
        if not rva:
            continue
        cursor = offset(rva)
        for _ in range(min(size // stride + 1, 4096)):
            entry = data[cursor:cursor + stride]
            require(len(entry) == stride, "Truncated PE import table.")
            if not any(entry):
                break
            name_rva = struct.unpack_from("<I", entry, name_offset)[0]
            if index == 13 and not (struct.unpack_from("<I", entry)[0] & 1):
                name_rva -= image_base
            imports.add(string(name_rva).lower())
            cursor += stride
        else:
            raise ValueError("Unterminated PE import table.")
    exports = []
    rva, _ = struct.unpack_from("<II", data, optional + 112)
    if rva:
        export = offset(rva)
        count = struct.unpack_from("<I", data, export + 24)[0]
        names = struct.unpack_from("<I", data, export + 32)[0]
        require(count < 100000, "Unbounded PE export table.")
        exports = [string(struct.unpack_from("<I", data, offset(names) + i * 4)[0]) for i in range(count)]
    return {"machine": "x64", "imports": sorted(imports), "exports": sorted(exports)}


def system_dependency(name):
    policy = json.loads((ROOT / "eng/native/vcpkg/system-dependencies.v1.json").read_text())
    return name in policy["windowsDlls"] or any(name.startswith(prefix) for prefix in policy["windowsApiSetPrefixes"])


def installed_packages(installed_root):
    result = {}
    for paragraph in (installed_root / "vcpkg/status").read_text().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" "))
        if fields.get("Status") != "install ok installed":
            continue
        key = (fields["Package"], fields["Architecture"])
        row = result.setdefault(key, {"dependencies": set(), "features": []})
        if "Version" in fields:
            row["version"] = fields["Version"]
        if "Feature" in fields:
            row["features"].append(fields["Feature"])
        row["dependencies"].update(fields.get("Depends", "").split(", "))
        row["dependencies"].discard("")
    return result


def dependency_closure(database, roots, triplet):
    pending = [(name, triplet) for name in roots]
    result = set()
    while pending:
        key = pending.pop()
        if key in result:
            continue
        require(key in database, f"Missing installed dependency: {key}")
        result.add(key)
        for dependency in database[key]["dependencies"]:
            name, _, architecture = dependency.partition(":")
            pending.append((name, architecture or key[1]))
    return sorted(result)


def vc_runtime(directory_version):
    vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
    location = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires",
                                       "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip()
    require(location, "Visual C++ installation was not found.")
    directories = list((Path(location) / "VC/Redist/MSVC").glob("*/x64/Microsoft.VC*.CRT"))
    directories = [p for p in directories if p.parents[1].name == directory_version]
    require(len(directories) == 1, "The reviewed Visual C++ x64 redistributable directory is missing or ambiguous.")
    return directories[0]


def upstream_records(vcpkg, installed_root, database, entry, destination, profile):
    records = []
    for name, triplet in dependency_closure(database, entry["vcpkgRoots"], entry["triplet"]):
        installed = installed_root / triplet / "share" / name
        sbom_file = installed / "vcpkg.spdx.json"
        copyright_file = installed / "copyright"
        build_info = installed / "vcpkg_abi_info.txt"
        require(sbom_file.is_file() and copyright_file.is_file() and build_info.is_file(),
                f"Missing licence/SBOM/build provenance for {name}:{triplet}")
        source = json.loads(sbom_file.read_text())
        stem = f"{name}-{triplet}"
        for original, relative in [(sbom_file, f"licenses/{stem}.spdx.json"), (copyright_file, f"licenses/{stem}.txt"),
                                   (build_info, f"licenses/{stem}.abi.txt")]:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        toolchain = profile["triplets"][triplet]
        for original, relative in [(ROOT / toolchain["path"], f"recipes/toolchains/{triplet}.cmake"),
                                   (vcpkg / toolchain["upstreamPath"], f"recipes/toolchains/upstream-{triplet}.cmake"),
                                   (vcpkg / "LICENSE.txt", "licenses/provenance/vcpkg-LICENSE.txt")]:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        recipe = ROOT / "eng/native/vcpkg/ports" / name
        if not recipe.is_dir():
            recipe = vcpkg / "ports" / name
        require(recipe.is_dir(), f"Missing build recipe for {name}")
        recipe_manifest = json.loads((recipe / "vcpkg.json").read_text())
        recipe_version = next(value for key, value in recipe_manifest.items() if key in
                              {"version", "version-string", "version-semver", "version-date"})
        require(recipe_version == database[(name, triplet)]["version"], f"Installed dependency version differs from pinned recipe: {name}")
        for file in source.get("files", []):
            if file.get("SPDXID", "").startswith("SPDXRef-binary-file-"):
                relative = Path(file["fileName"])
                # Check the actual release libraries as well as their source recipe, including static inputs.
                if relative.parts[0] in {"bin", "lib"} and relative.suffix in {".dll", ".lib"}:
                    original = (installed_root / triplet / relative).resolve()
                    require(original.is_relative_to((installed_root / triplet).resolve()), "Installed library path escapes its triplet.")
                    checksum = next(c["checksumValue"] for c in file["checksums"] if c["algorithm"] == "SHA256")
                    require(original.is_file() and digest(original) == checksum, f"Installed library hash mismatch: {name}/{relative}")
            if not file.get("SPDXID", "").startswith("SPDXRef-port-file-"):
                continue
            original = (recipe / file["fileName"]).resolve()
            require(original.is_relative_to(recipe.resolve()), "Upstream recipe path escapes its port.")
            checksum = next(c["checksumValue"] for c in file["checksums"] if c["algorithm"] == "SHA256")
            require(original.is_file() and digest(original) == checksum, f"Installed dependency recipe hash mismatch: {name}/{file['fileName']}")
        shutil.copytree(recipe, destination / "recipes" / name, dirs_exist_ok=True)
        row = database[(name, triplet)]
        records.append({"name": name, "triplet": triplet, "version": row["version"],
                        "features": sorted(row["features"]), "sbom": f"licenses/{stem}.spdx.json",
                        "license": f"licenses/{stem}.txt", "buildInfo": f"licenses/{stem}.abi.txt"})
        # Keep actual matching LGPL source archives with the distributed DLLs, alongside every vcpkg patch.
        if name in {"ffmpeg", "libusb"}:
            resource = next(p for p in source["packages"] if p.get("SPDXID", "").startswith("SPDXRef-resource-")
                            and p.get("downloadLocation", "").startswith("git+https://github.com/"))
            repository, tag = resource["downloadLocation"][4:].rsplit("@", 1)
            checksum = next(c["checksumValue"] for c in resource["checksums"] if c["algorithm"] == "SHA512")
            url = repository + "/archive/" + tag + ".tar.gz"
            archive = destination / "sources" / f"{name}-{row['version']}.tar.gz"
            archive.parent.mkdir(parents=True, exist_ok=True)
            approved = profile["components"][name]["correspondingSource"]
            require(approved is not None and approved["url"] == url and approved["sha512"] == checksum,
                    "Unreviewed native corresponding source.")
            source_record = next(r for r in profile["components"][name]["resources"] if r["sha512"] == checksum)
            cached = native_provenance.fetch(url, checksum, "sha512", source_record["cacheName"],
                                            Path(os.environ.get("VCPKG_DOWNLOADS", str(vcpkg / "downloads"))))
            shutil.copyfile(cached, archive)
            with archive.open("rb") as stream:
                require(hashlib.file_digest(stream, "sha512").hexdigest() == checksum, f"Source checksum mismatch: {name}")
            records[-1]["sourceArchive"] = str(archive.relative_to(destination)).replace("\\", "/")
            records[-1]["sourceUrl"] = url
    return records


def owned_build_tools(profile, installed_root, root=ROOT):
    """Read the actual retained producer cache instead of asserting versions from PATH."""
    for name in ("shim-static",):
        cache = root / "artifacts/cmake/win-x64" / name / "CMakeCache.txt"
        values = dict(line.split("=", 1) for line in cache.read_text(encoding="utf-8").splitlines()
                      if line and not line.startswith(("#", "//")) and "=" in line)
        version = ".".join(values["CMAKE_CACHE_" + part + "_VERSION:INTERNAL"] for part in ("MAJOR", "MINOR", "PATCH"))
        require(version == profile["buildTools"]["ownedCMake"], "Unreviewed owned CMake build generator: " + name)
        for language in ("C", "CXX"):
            compilers = [v for k, v in values.items() if k.startswith("CMAKE_" + language + "_COMPILER:")]
            require(len(compilers) == 1 and
                    Path(compilers[0]).as_posix().casefold().endswith(("/VC/Tools/MSVC/" + profile["buildTools"]["msvcToolset"] + "/bin/Hostx64/x64/cl.exe").casefold()),
                    "Unreviewed owned MSVC compiler: " + name)
        require(Path(values["VCPKG_INSTALLED_DIR:PATH"]).resolve() == installed_root.resolve(),
                "Native producer used a different installed dependency tree: " + name)
        ninja = subprocess.check_output([values["CMAKE_MAKE_PROGRAM:FILEPATH"], "--version"], text=True).strip()
        require(ninja == profile["buildTools"]["ownedNinja"], "Unreviewed owned Ninja build tool: " + name)
    return dict(profile["buildTools"])


def stage(directory, vcpkg, installed_root):
    require(os.name == "nt", "Windows native staging must run on the Windows producer.")
    require(not directory.exists() or not any(directory.iterdir()), "Native stage already exists; choose a new empty directory.")
    audit = native_provenance.provenance.run(ROOT, "DesktopPlatform",
        base=os.environ.get("GITHUB_SHA") if os.environ.get("GITHUB_REF", "").startswith("refs/tags/") else None)
    require(not audit["dirty"], "Commit reviewed changes before producing a source-bound native artifact.")
    profile = native_provenance.profile()
    build_tools = owned_build_tools(profile, installed_root)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    actual = subprocess.check_output(["git", "-C", str(vcpkg), "rev-parse", "HEAD"], text=True).strip()
    require(actual == VCPKG_COMMIT, "Native toolchain source pin mismatch.")
    require(not subprocess.check_output(["git", "-C", str(vcpkg), "status", "--porcelain", "--untracked-files=no"], text=True).strip(),
            "Pinned vcpkg source has uncommitted changes.")
    database = installed_packages(installed_root)
    binary_root = ROOT / "artifacts/stage/native/win-x64"
    crt = vc_runtime(profile["platformRuntime"]["distributionIdentity"]["directoryVersion"])
    signatures = {}
    available = {path.name.lower(): path for path in (binary_root / "native").glob("*.dll")}
    available.update({path.name.lower(): path for path in crt.glob("*.dll")})
    entries = [p for p in json.loads((ROOT / "eng/packaging/packages.json").read_text())["packages"]
               if p["kind"] == "native" and p["id"] in profile["packages"]]
    identity = build_identity.build_identity(ROOT)
    artifact = {"schemaVersion": 1, "sourceCommit": commit, "rid": "win-x64", "packages": [], "build": identity}
    for entry in entries:
        destination = directory / entry["id"]
        runtime = destination / "runtimes/win-x64/native"
        runtime.mkdir(parents=True)
        selected = {}
        pending = [entry["library"].lower() + ".dll"]
        while pending:
            name = pending.pop()
            if name in selected:
                continue
            require(name in available, f"Missing non-system native dependency: {name}")
            original = available[name]
            if original.parent == crt and name not in signatures:
                signatures[name] = native_provenance.approve_runtime(original, profile)
            if name != entry["library"].lower() + ".dll":
                source = crt / original.name if original.parent == crt else installed_root / entry["triplet"] / "bin" / original.name
                require(source.is_file() and digest(original) == digest(source),
                        f"Staged dependency differs from the pinned installed input: {name}")
            details = pe(original.read_bytes())
            selected[name] = {"name": original.name, "sha256": digest(original), **details}
            shutil.copyfile(original, runtime / original.name)
            for dependency in details["imports"]:
                if not system_dependency(dependency):
                    pending.append(dependency)
        owned = selected[entry["library"].lower() + ".dll"]
        abi_version = verify_abi(entry, owned["exports"])
        for original, relative in [(ROOT / entry["header"], "include/arc/" + Path(entry["header"]).name),
                                   (ROOT / "native/shared/include/arc/arc_native_abi.h", "include/arc/arc_native_abi.h"),
                                   (binary_root / "lib" / (entry["library"] + ".lib"), "sdk/win-x64/lib/" + entry["library"] + ".lib")]:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        records = upstream_records(vcpkg, installed_root, database, entry, destination, profile)
        metadata = {"schemaVersion": 1, "sourceCommit": commit, "rid": "win-x64", "library": entry["library"],
                    "abi": abi_version, "vcpkgCommit": actual,
                    "files": sorted(selected.values(), key=lambda f: f["name"])}
        write_json(destination / "native-manifest.json", metadata)
        write_json(runtime / (entry["library"] + ".manifest.json"), metadata)
        write_json(destination / "sbom.json", {"schemaVersion": 1, "sourceCommit": commit, "buildTools": build_tools,
                   "binaryFiles": metadata["files"], "buildDependencies": records,
                   "visualCppRuntime": {"record": profile["platformRuntime"]["id"],
                                        "version": crt.parents[1].name,
                                        "redistributableDirectoryVersion": crt.parents[1].name,
                                        "files": [{"name": f["name"], **profile["platformRuntime"]["files"][f["name"].lower()]}
                                                  for f in metadata["files"] if f["name"].lower() in signatures],
                                        "source": "Microsoft Visual Studio x64 CRT redistributable directory",
                                        "redistributionTerms": "https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files"}})
        (destination / "NOTICE.md").write_text("# Native package notices\n\nArcForges owned ABI: AGPL-3.0-only.\n\n"
            + "All upstream build dependencies (including static inputs) have licence text and SPDX/source records under licenses/.\n"
            + "Every applied vcpkg recipe/patch and reviewed source identity accompany the retained Image package.\n"
            + "Build with the recorded vcpkg commit and the repository's shim-static CMake preset; dependency linkage follows the reviewed Image profile.\n"
            + "Visual C++ runtime files are redistributed unmodified from the Microsoft x64 CRT redist directory.\n"
            + "Microsoft redistribution terms: https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files\n"
            + "Windows API sets/system libraries are OS prerequisites; no system DLL is bundled.\n", encoding="utf-8")
        # Version equality is also enforced by the exact NuGet dependency written during packing.
        target = destination / "buildTransitive" / (entry["id"] + ".targets")
        target.parent.mkdir(parents=True)
        target.write_text(f'''<Project>
  <!-- SPDX-License-Identifier: AGPL-3.0-only -->
  <Target Name="Require_{entry['prefix']}_Rid" BeforeTargets="PrepareForBuild">
    <Error Condition="'$(RuntimeIdentifier)' != 'win-x64'" Text="{entry['id']} requires RuntimeIdentifier=win-x64 and its matching managed package version." />
  </Target>
</Project>
''', encoding="utf-8")
        native_provenance.seal(destination, entry["id"],
                               Path(os.environ.get("VCPKG_DOWNLOADS", str(vcpkg / "downloads"))), signatures)
        files = [{"path": str(f.relative_to(destination)).replace("\\", "/"), "sha256": digest(f)}
                 for f in sorted(destination.rglob("*")) if f.is_file()]
        artifact["packages"].append({"id": entry["id"], "files": files})
        print(f"Staged {entry['id']}: {len(selected)} DLLs, {len(records)} upstream records.", flush=True)
    write_json(directory / "native-artifact.json", artifact)
    verify_stage(directory, commit)


def _read_document(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
            "Missing, linked or unbounded native document.")
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    require(len(content) <= maximum, "Native document grew beyond its bound.")

    def unique(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate native document field.")
            result[key] = value
        return result
    result = json.loads(content, object_pairs_hook=unique)
    require(isinstance(result, dict), "Native document must be an object.")
    return result


def _relative(value):
    require(isinstance(value, str) and value and len(value) <= 1024 and "\\" not in value
            and ":" not in value and not value.startswith("/")
            and all(part not in ("", ".", "..") for part in value.split("/")),
            "Unsafe native artifact path.")
    return value


def _linked(path):
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _inventory(directory):
    directory = Path(directory).absolute()
    require(directory.is_dir() and not _linked(directory), "Missing or linked native artifact directory.")
    result, aliases, pending, count = {}, set(), [(directory, 0)], 0
    while pending:
        parent, depth = pending.pop()
        require(depth <= 64 and not _linked(parent), "Unsafe native artifact directory.")
        with os.scandir(parent) as entries:
            for entry in entries:
                count += 1
                require(count <= 200000, "Native file inventory exceeds its bound.")
                path = Path(entry.path)
                require(not _linked(path), "Linked native artifact material.")
                name = _relative(path.relative_to(directory).as_posix())
                require(name.casefold() not in aliases, "Colliding native artifact paths.")
                aliases.add(name.casefold())
                if entry.is_dir(follow_symlinks=False):
                    pending.append((path, depth + 1))
                else:
                    require(entry.is_file(follow_symlinks=False) and entry.stat().st_size <= 512 * 1024 * 1024,
                            "Nonregular or unbounded native artifact material.")
                    result[name] = digest(path)
    return result


@contextmanager
def _exclusive_stage(destination):
    # Persistent lockfile + kernel ownership recovers process death without a stale-marker waiver.
    path = destination.parent / ("." + destination.name + ".native-lock")
    require(not _linked(path), "Linked native staging lock.")
    with path.open("a+b") as stream:
        if stream.seek(0, os.SEEK_END) == 0:
            stream.write(b"0")
            stream.flush()
        for attempt in range(40):
            stream.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as error:
                import errno
                if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK) or attempt == 39:
                    raise ValueError("The native staging destination is owned by another writer.") from error
                time.sleep(0.05)
        yield


def _coordinate(family, rid):
    require(family in ("Image", "Pdf") and rid in RIDS, "Unadmitted native family/RID coordinate.")


def verify_family_stage(directory, commit, family, rid):
    _coordinate(family, rid)
    artifact = _read_document(Path(directory) / "native-artifact.json")
    require(artifact.get("rid") == rid and artifact.get("sourceCommit") == commit,
            "Native family stage source/RID mismatch.")
    expected = "ArcForges.Native." + family + ".Runtime." + rid
    require(len(artifact.get("packages", [])) == 1 and artifact["packages"][0].get("id") == expected,
            "Native family stage contains a mixed or unexpected package set.")
    if family == "Image":
        package = Path(directory) / expected
        if (package / "image-production-input.json").is_file():
            import image_runtime
            return image_runtime.verify_stage(Path(directory), commit, ROOT)
        require(rid == "win-x64", "Only the historical win-x64 Image stage has a legacy receipt.")
        return _verify_legacy_stage(Path(directory), commit)
    return native_provenance.verify_pdf_runtime_stage(Path(directory), commit, ROOT)


def combine(directory, inputs, commit):
    """Compose verified complete stages. This binds bytes; publisher signing is a separate handoff."""
    directory = Path(directory).absolute()
    require(0 < len(inputs) <= 12 and len({Path(path).resolve() for path in inputs}) == len(inputs),
            "Native composition needs distinct bounded producer stages.")
    directory.parent.mkdir(parents=True, exist_ok=True)
    require(all(not _linked(part) for part in (directory.parent, *directory.parent.parents)),
            "Linked native composition parent.")
    with _exclusive_stage(directory):
        require(not directory.exists(), "Native candidate already exists; never overwrite tested bytes.")
        with tempfile.TemporaryDirectory(prefix=".native-compose-", dir=directory.parent) as temporary:
            staging = Path(temporary) / "candidate"
            staging.mkdir()
            rows, packages, ids, coordinates = [], [], set(), set()
            build = None
            for original in inputs:
                original = Path(original).absolute()
                artifact = _read_document(original / "native-artifact.json")
                require(len(artifact.get("packages", [])) == 1, "A family input must contain exactly one package.")
                identifier = artifact["packages"][0].get("id", "")
                match = re.fullmatch(r"ArcForges\.Native\.(Image|Pdf)\.Runtime\.(.+)", identifier)
                require(match is not None, "Unrecognized native family input.")
                family, rid = match.groups()
                _coordinate(family, rid)
                require(identifier not in ids and (family, rid) not in coordinates, "Duplicate native producer coordinate.")
                ids.add(identifier)
                coordinates.add((family, rid))
                verify_family_stage(original, commit, family, rid)
                if build is None:
                    build = artifact["build"]
                require(artifact["build"] == build, "Native families have different source/build publication cohorts.")
                before = _inventory(original)
                retained = staging / ".native-inputs" / (family + "-" + rid)
                shutil.copytree(original, retained)
                require(_inventory(retained) == before, "Producer bytes changed during composition.")
                verify_family_stage(retained, commit, family, rid)
                destination = staging / identifier
                shutil.copytree(retained / identifier, destination)
                require(_inventory(destination) == _inventory(retained / identifier), "Native payload changed during handoff.")
                packages.append(artifact["packages"][0])
                rows.append({"family": family, "rid": rid, "directory": retained.relative_to(staging).as_posix(),
                             "artifactSha256": digest(retained / "native-artifact.json")})
            index = {"schemaVersion": 1, "sourceCommit": commit, "inputs": sorted(rows, key=lambda row: (row["family"], row["rid"]))}
            write_json(staging / "native-family-index.json", index)
            artifact = {"schemaVersion": 2, "sourceCommit": commit, "rid": "multi", "build": build,
                        "familyIndexSha256": digest(staging / "native-family-index.json"),
                        "packages": sorted(packages, key=lambda row: row["id"])}
            write_json(staging / "native-artifact.json", artifact)
            verify_stage(staging, commit)
            staging.replace(directory)
    return artifact


def verify_stage(directory, commit):
    directory = Path(directory)
    artifact = _read_document(directory / "native-artifact.json")
    if artifact.get("schemaVersion") != 2:
        packages = artifact.get("packages", [])
        if len(packages) == 1 and packages[0].get("id", "").startswith("ArcForges.Native.Pdf.Runtime."):
            return native_provenance.verify_pdf_runtime_stage(directory, commit, ROOT)
        if len(packages) == 1 and (directory / packages[0]["id"] / "image-production-input.json").is_file():
            import image_runtime
            return image_runtime.verify_stage(directory, commit, ROOT)
        return _verify_legacy_stage(directory, commit)
    verify_identity(artifact, commit)
    require(digest(directory / "native-family-index.json") == artifact["familyIndexSha256"],
            "Native family index differs from its bound artifact.")
    index = _read_document(directory / "native-family-index.json")
    require(set(index) == {"schemaVersion", "sourceCommit", "inputs"} and index["schemaVersion"] == 1
            and index["sourceCommit"] == commit and 0 < len(index["inputs"]) <= 12, "Invalid native family index.")
    expected = {"native-artifact.json": digest(directory / "native-artifact.json"),
                "native-family-index.json": digest(directory / "native-family-index.json")}
    verified, coordinates = {}, set()
    for row in index["inputs"]:
        require(set(row) == {"family", "rid", "directory", "artifactSha256"}, "Unknown native input-index fields.")
        _coordinate(row["family"], row["rid"])
        relative = ".native-inputs/" + row["family"] + "-" + row["rid"]
        require(row["directory"] == relative and relative not in coordinates, "Escaped or repeated native family input.")
        coordinates.add(relative)
        retained = directory / relative
        require(digest(retained / "native-artifact.json") == row["artifactSha256"], "Retained native input artifact changed.")
        source = verify_family_stage(retained, commit, row["family"], row["rid"])
        for name, checksum in _inventory(retained).items():
            expected[relative + "/" + name] = checksum
        for package in source["packages"]:
            require(package["id"] not in verified, "Repeated composed native package.")
            verified[package["id"]] = package
            require(_inventory(directory / package["id"]) == _inventory(retained / package["id"]),
                    "Composed native payload differs from its verified producer.")
            for name, checksum in _inventory(directory / package["id"]).items():
                expected[package["id"] + "/" + name] = checksum
    require(sorted(verified.values(), key=lambda row: row["id"]) == artifact["packages"], "Composed package records differ.")
    require(_inventory(directory) == expected, "Unexpected, missing or changed composed native material.")
    return artifact



def retain_package_handoff(source, destination, commit):
    """Retain source-bound family receipts without duplicating native binaries already in NuGet."""
    source, destination = Path(source), Path(destination)
    artifact = verify_stage(source, commit)
    if artifact["schemaVersion"] != 2:
        return
    index = _read_document(source / "native-family-index.json")
    require(not (destination / ".native-inputs").exists()
            and not (destination / "native-family-index.json").exists(), "Publication handoff already exists.")
    targets = ["native-family-index.json"] + [row["directory"] + "/native-artifact.json" for row in index["inputs"]]
    for name in targets:
        _relative(name)
        original = source / name
        expected = digest(original)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        require(all(not _linked(parent) for parent in (target.parent, *target.parent.parents)),
                "Linked publication handoff path.")
        require(original.is_file() and not _linked(original), "Linked publication producer receipt.")
        with original.open("rb") as incoming:
            content = incoming.read(16 * 1024 * 1024 + 1)
        require(len(content) <= 16 * 1024 * 1024, "Unbounded publication producer receipt.")
        with target.open("xb") as outgoing:
            outgoing.write(content)
        require(digest(target) == expected, "Publication receipt changed during handoff.")
    verify_package_handoff(destination, artifact, commit)


def verify_package_handoff(directory, artifact, commit):
    """Verify retained producer records; packed native bytes are checked against these exact records."""
    if artifact["schemaVersion"] != 2:
        return
    directory = Path(directory)
    require(digest(directory / "native-family-index.json") == artifact["familyIndexSha256"],
            "Published native family index hash mismatch.")
    index = _read_document(directory / "native-family-index.json")
    require(set(index) == {"schemaVersion", "sourceCommit", "inputs"}
            and type(index["schemaVersion"]) is int and index["schemaVersion"] == 1
            and index["sourceCommit"] == commit and isinstance(index["inputs"], list)
            and 0 < len(index["inputs"]) <= 12, "Invalid published native family index.")
    expected, packages, coordinates = {}, {}, set()
    for row in index["inputs"]:
        require(isinstance(row, dict) and set(row) == {"family", "rid", "directory", "artifactSha256"},
                "Invalid published family coordinate fields.")
        _coordinate(row["family"], row["rid"])
        name = ".native-inputs/" + row["family"] + "-" + row["rid"]
        require(row["directory"] == name and name not in coordinates, "Escaped or duplicate published family coordinate.")
        coordinates.add(name)
        path = directory / name / "native-artifact.json"
        require(digest(path) == row["artifactSha256"], "Published native producer receipt hash mismatch.")
        producer = _read_document(path)
        require(set(producer) == {"schemaVersion", "sourceCommit", "rid", "packages", "build"}
                and type(producer["schemaVersion"]) is int and producer["schemaVersion"] == 1
                and producer["sourceCommit"] == commit and producer["rid"] == row["rid"]
                and producer["build"] == artifact["build"] and isinstance(producer["packages"], list)
                and len(producer["packages"]) == 1, "Published producer source/build cohort mismatch.")
        package = producer["packages"][0]
        identifier = "ArcForges.Native." + row["family"] + ".Runtime." + row["rid"]
        require(isinstance(package, dict) and package.get("id") == identifier and identifier not in packages,
                "Published producer package coordinate mismatch.")
        packages[identifier] = package
        expected[name.removeprefix(".native-inputs/") + "/native-artifact.json"] = row["artifactSha256"]
    require(sorted(packages.values(), key=lambda row: row["id"]) == artifact["packages"],
            "Published family records differ from packed producer inventory.")
    require(_inventory(directory / ".native-inputs") == expected,
            "Unexpected, missing or changed published producer receipt.")
    return index


def _verify_legacy_stage(directory, commit):
    artifact = json.loads((directory / "native-artifact.json").read_text())
    verify_identity(artifact, commit)
    for package in artifact["packages"]:
        base = directory / package["id"]
        native_provenance.verify(package["id"], lambda path: native_provenance.provenance.read(base, path),
                                 {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()})
        require({str(p.relative_to(base)).replace("\\", "/") for p in base.rglob("*") if p.is_file()}
                == {p["path"] for p in package["files"]}, "Unexpected/missing native artifact file.")
        for row in package["files"]:
            path = (base / row["path"]).resolve()
            require(path.is_relative_to(base.resolve()) and digest(path) == row["sha256"], "Native artifact hash/path mismatch.")
    print("Native artifact source, package set and file hashes verified.", flush=True)
    return artifact


def verify_identity(artifact, commit):
    if artifact.get("schemaVersion") == 2:
        require(set(artifact) == {"schemaVersion", "sourceCommit", "rid", "packages", "build", "familyIndexSha256"}
                and artifact["sourceCommit"] == commit and artifact["rid"] == "multi", "Composed native identity mismatch.")
        require(isinstance(artifact["familyIndexSha256"], str) and re.fullmatch("[a-f0-9]{64}", artifact["familyIndexSha256"]),
                "Invalid native family-index digest.")
        expected = {p["id"] for p in json.loads((ROOT / "eng/packaging/packages.json").read_text())["packages"] if p["kind"] == "native"}
    else:
        require(artifact["schemaVersion"] == 1 and artifact["sourceCommit"] == commit and artifact["rid"] == "win-x64",
            "Native artifact source/RID mismatch.")
        expected = set(native_provenance.profile()["packages"])
    build_identity.verify_source_build(ROOT, artifact['build'])
    require(len(artifact["packages"]) == len(expected) and {p["id"] for p in artifact["packages"]} == expected,
            "Native artifact package set mismatch.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["stage", "verify", "combine"])
    parser.add_argument("--directory", type=Path, default=ROOT / "artifacts/native-packages")
    parser.add_argument("--vcpkg-root", type=Path, default=os.environ.get("VCPKG_ROOT", "C:/vcpkg"))
    parser.add_argument("--installed-root", type=Path, default=ROOT / "artifacts/vcpkg-installed")
    parser.add_argument("--commit")
    parser.add_argument("--family", choices=["Image", "Pdf"])
    parser.add_argument("--rid", choices=sorted(RIDS))
    parser.add_argument("--producer-prefix", type=Path)
    parser.add_argument("--producer-build-directory", type=Path)
    parser.add_argument("--downloads", type=Path)
    parser.add_argument("--compiler-runtime", type=Path)
    parser.add_argument("--sealed-input", type=Path)
    parser.add_argument("--input-directory", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.command == "stage":
        if args.family is None:
            require(args.rid is None and args.sealed_input is None and args.producer_prefix is None,
                    "Explicit native inputs require a closed family/RID coordinate.")
            stage(args.directory.resolve(), Path(args.vcpkg_root).resolve(), args.installed_root.resolve())
        else:
            _coordinate(args.family, args.rid)
            if args.family == "Image":
                require(args.producer_prefix is not None and args.producer_build_directory is not None
                        and args.downloads is not None and args.sealed_input is None,
                        "Image staging requires explicit producer/build/download inputs.")
                import image_runtime
                image_runtime.stage(args.directory.absolute(), args.rid,
                    image_runtime.ProducerInputs(args.producer_prefix.resolve(), args.producer_build_directory.resolve(),
                        args.installed_root.resolve(), Path(args.vcpkg_root).resolve(), args.downloads.resolve(),
                        args.compiler_runtime.resolve() if args.compiler_runtime else None), root=ROOT)
            else:
                require(args.sealed_input is not None and args.producer_prefix is None,
                        "PDF package staging consumes the actual verified sealed-input producer.")
                native_provenance.stage_pdf_runtime(args.directory.absolute(), args.rid, args.sealed_input.resolve(), ROOT)
    elif args.command == "combine":
        require(args.family is None and args.rid is None, "Composition derives exact coordinates from verified inputs.")
        combine(args.directory.absolute(), args.input_directory, args.commit or subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip())
    else:
        verify_stage(args.directory.resolve(), args.commit or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip())
