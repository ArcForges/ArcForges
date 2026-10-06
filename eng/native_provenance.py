# SPDX-License-Identifier: AGPL-3.0-only
"""Verify the reviewed native source, legal-text and compiler-runtime closure."""

from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import check_provenance as provenance

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "eng/provenance/artifact-profiles/native-win-x64-r4.json"
RECEIPT = "provenance/native-closure.json"
NOTICE = "provenance/NOTICE.txt"
VISUAL_STUDIO_LICENSE_URLS = frozenset({
    "https://visualstudio.microsoft.com/wp-content/uploads/2025/10/Visual_Studio_2026-License-Community_ENU.docx",
    "https://visualstudio.microsoft.com/wp-content/uploads/2025/10/Visual-C-V14-License-Redistributable_and_Runtime_ENU.docx",
})
VISUAL_STUDIO_LICENSE_USER_AGENT = "ArcForges/1.0 (+https://github.com/ArcForges/DesktopPlatform)"
require = provenance.require


def sha(data: bytes, normalization: str = "raw") -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n") if normalization == "lf" else data).hexdigest()


def canonical(value: dict) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def download_identity(value: str) -> None:
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password and
            not parsed.fragment and parsed.path.startswith("/") and
            not any(part in {".", ".."} for part in parsed.path.split("/")), "Invalid source download URL")


def sources(sbom: dict) -> list[dict]:
    rows = []
    for item in sbom["packages"]:
        if item["SPDXID"].startswith("SPDXRef-resource-"):
            hashes = [h["checksumValue"] for h in item["checksums"] if h["algorithm"] == "SHA512"]
            require(len(hashes) == 1, "Missing native source SHA512")
            rows.append({"url": item["downloadLocation"], "sha512": hashes[0]})
    return sorted(rows, key=lambda r: (r["url"], r["sha512"]))


def check_sources(value: dict, name: str, sbom: dict) -> None:
    component = value["components"][name]
    required = sorted(({k: r[k] for k in ("url", "sha512")} for r in component["resources"]),
                      key=lambda r: (r["url"], r["sha512"]))
    actual = sources(sbom)
    cached_helper = (name in value["cachedResourceOmissions"] and component["role"] == "build-only" and not actual)
    require(actual == required or cached_helper, "Changed native source archives: " + name +
            "; expected " + json.dumps(required, sort_keys=True) + "; observed " + json.dumps(actual, sort_keys=True))


def profile(root: Path = ROOT) -> dict:
    value = provenance.document(provenance.read(root, PROFILE))
    provenance.fields(value, "schemaVersion id authority vcpkgCommit baseline buildTools triplets components packages platformRuntime cachedResourceOmissions")
    require(value["schemaVersion"] == 1 and value["id"] == "native-win-x64-r4", "Unknown native profile")
    require(value["cachedResourceOmissions"] == [], "Unreviewed cached resource omission")
    require(value["buildTools"] == {"ownedCMake": "4.3.3", "ownedNinja": "1.13.1", "vcpkgCMake": "4.4.0", "msvcToolset": "14.51.36231"},
            "Unreviewed native build generators")
    require(set(value["triplets"]) == {"x64-windows", "x64-windows-static-md"}, "Unreviewed native triplets")
    for name, triplet in value["triplets"].items():
        provenance.fields(triplet, "path sha256 upstreamPath upstreamSha256 upstreamLicenceSha256")
        require(triplet["path"] == "eng/native/vcpkg/triplets/" + name + ".cmake" and
                triplet["upstreamPath"] == "triplets/" + name + ".cmake", "Unexpected native triplet path")
        provenance.digest(triplet["upstreamSha256"])
        provenance.digest(triplet["upstreamLicenceSha256"])
        require(sha(provenance.read(root, triplet["path"]), "lf") == triplet["sha256"], "Changed native toolset overlay")
    provenance.digest(value["vcpkgCommit"], (40,))
    authority = value["authority"]
    provenance.fields(authority, "repository commit path sections")
    require(authority["repository"] == "https://github.com/ArcForges/ArcForges-Design" and
            authority["path"] == "docs/assurance/reference-coverage-and-provenance.md" and authority["sections"] == ["3.3", "3.4"],
            "Wrong native provenance authority")
    provenance.digest(authority["commit"], (40,))
    baseline = value["baseline"]
    provenance.fields(baseline, "sourceCommit version reviewedOn recipeFiles sourceIdentityProof")
    provenance.digest(baseline["sourceCommit"], (40,))
    date.fromisoformat(provenance.text(baseline["reviewedOn"]))
    provenance.text(baseline["sourceIdentityProof"])
    provenance.text(baseline["version"])
    require(baseline["recipeFiles"] == sum(len(c["recipe"]["files"]) for c in value["components"].values()),
            "Native recipe inventory count changed")
    catalogue = {p["id"]: p for p in provenance.document(provenance.read(root, "eng/packaging/packages.json"))["packages"]
                 if p["kind"] == "native"}
    require(set(value["packages"]) == set(catalogue), "Native package profile differs from admitted catalogue")
    used = set()
    for name, package in value["packages"].items():
        provenance.fields(package, "dependencies dlls")
        provenance.strings(package["dlls"], provenance.path)
        require(package["dlls"] == sorted(package["dlls"]) and
                len({n.casefold() for n in package["dlls"]}) == len(package["dlls"]) and
                all("/" not in n and n.endswith(".dll") for n in package["dlls"]), "Invalid native DLL inventory")
        keys = []
        for dependency in package["dependencies"]:
            provenance.fields(dependency, "name triplet version features")
            require(dependency["name"] in value["components"] and
                    dependency["version"] == value["components"][dependency["name"]]["version"] and
                    dependency["triplet"] in {"x64-windows", "x64-windows-static-md"}, "Unregistered native dependency")
            provenance.strings(dependency["features"], empty=True)
            keys.append((dependency["name"], dependency["triplet"]))
            used.add(dependency["name"])
        require(len(keys) == len(set(keys)) and keys == sorted(keys), "Duplicate or unordered native dependencies")
    require(used == set(value["components"]), "Unused native component registration")
    inv = provenance.document(provenance.read(root, provenance.INVENTORY))
    for name, component in value["components"].items():
        provenance.fields(component, "record version role source recipe resources legal extras correspondingSource scope")
        require(component["role"] in {"runtime-input", "build-only"}, "Unknown native component role")
        provenance.text(component["scope"])
        provenance.text(component["version"])
        provenance.source(component["source"], "AGPL")
        require(component["record"] in inv["artifacts"], "Unregistered native component: " + name)
        record = provenance.document(provenance.read(root, provenance.STORE + component["record"] + ".json"))
        provenance.record(record, "AGPL")
        require(record["sourceRepository"] == component["source"]["repository"] and
                record["sourceCommit"] == component["source"]["commit"] and
                record["licence"]["spdx"] == component["source"]["spdx"], "Component record/source mismatch")
        expected_packages = {package for package, row in value["packages"].items()
                             if any(d["name"] == name for d in row["dependencies"])}
        require({t["package"] for t in record["artifactTargets"]} == expected_packages,
                "Component artifact target mismatch")
        for target in record["artifactTargets"]:
            require(target["profile"] == PROFILE and target["sha256"] == sha(provenance.read(root, PROFILE), "lf"),
                    "Native profile has changed without a superseding record")
            require(target["project"] == catalogue[target["package"]]["project"] and target["kind"] == "native-component-" + name,
                    "Native record binds the wrong project/material kind")
        recipe = component["recipe"]
        provenance.fields(recipe, "repository commit files licenceScope")
        provenance.repository(recipe["repository"])
        provenance.digest(recipe["commit"], (40,))
        require(bool(recipe["files"]), "Native recipe is empty")
        for path, digest in recipe["files"].items():
            provenance.path(path)
            provenance.digest(digest)
        for resource in component["resources"]:
            provenance.fields(resource, "url sha512 downloadUrl cacheName")
            provenance.digest(resource["sha512"], (128,))
            download_identity(resource["downloadUrl"])
            require(Path(resource["cacheName"]).name == resource["cacheName"], "Escaping source cache name")
        for row in component["legal"]:
            provenance.fields(row, "path sha256")
            provenance.path(row["path"])
            provenance.digest(row["sha256"])
        for row in component["extras"]:
            asset(row)
        if component["correspondingSource"] is not None:
            row = component["correspondingSource"]
            provenance.fields(row, "path url sha512 scope")
            provenance.path(row["path"])
            require(row["path"].startswith("sources/"), "Corresponding source outside sources directory")
            download_identity(row["url"])
            provenance.digest(row["sha512"], (128,))
            provenance.text(row["scope"])
    for row in value["platformRuntime"]["legal"]:
        asset(row)
    runtime = value["platformRuntime"]
    provenance.fields(runtime, "id sourceRepository sourceCommit sourceUnavailable distributionIdentity licence attribution targets disposition verification notice lifetime review files legal")
    require(runtime["sourceRepository"] is None and runtime["sourceCommit"] is None and
            runtime["sourceUnavailable"] == "Microsoft publishes these compiler-runtime redistributables as signed binaries; no corresponding public Git source identity is asserted.",
            "Compiler-runtime source identity is misleading")
    require(runtime["disposition"] == "Copy" and runtime["review"]["licensingDecision"] == "approved" and
            runtime["review"]["architectureDecision"] == "approved" and
            set(runtime["targets"]) == set(value["packages"]), "Unreviewed compiler-runtime role")
    require(runtime["licence"]["spdx"] == "LicenseRef-Microsoft-VisualCpp-Runtime-2026" and
            runtime["lifetime"]["status"] == "permanent", "Unreviewed compiler-runtime terms")
    provenance.fields(runtime["licence"], "spdx redistributionGrant systemLibraries obligations")
    for key in ("redistributionGrant", "systemLibraries", "obligations"):
        provenance.text(runtime["licence"][key])
    provenance.fields(runtime["lifetime"], "status owner removalTrigger")
    provenance.text(runtime["lifetime"]["owner"])
    require(runtime["lifetime"]["removalTrigger"] is None, "Unexpected vendor removal trigger")
    provenance.fields(runtime["review"], "licensingOwner architectureOwner reviewer reviewedOn licensingDecision architectureDecision baselineCommit rationale")
    require(runtime["review"]["licensingOwner"] == "Licensing and Provenance Owner" and
            runtime["review"]["architectureOwner"] == "Architecture Owner", "Wrong vendor review responsibility")
    for key in ("reviewer", "rationale"):
        provenance.text(runtime["review"][key])
    date.fromisoformat(provenance.text(runtime["review"]["reviewedOn"]))
    provenance.digest(runtime["review"]["baselineCommit"], (40,))
    provenance.strings(runtime["attribution"])
    provenance.text(runtime["verification"])
    provenance.text(runtime["notice"])
    provenance.fields(runtime["distributionIdentity"], "vendor release directoryVersion directory productVersion guidance distributableList")
    require(runtime["distributionIdentity"]["vendor"] == "Microsoft Corporation", "Wrong compiler-runtime vendor")
    for key, item in runtime["distributionIdentity"].items():
        provenance.text(item)
    for name, row in runtime["files"].items():
        provenance.fields(row, "sha256 productVersion fileVersion publisher")
        provenance.digest(row["sha256"])
        require(name.endswith(".dll") and name == Path(name).name, "Invalid compiler-runtime file")
        require(row["publisher"] == "Microsoft Windows Software Compatibility Publisher" and
                row["productVersion"] == runtime["distributionIdentity"]["productVersion"] and
                row["fileVersion"] == row["productVersion"], "Unreviewed compiler-runtime publisher/version")
    for package in value["packages"]:
        paths = [r["output"] for dependency in value["packages"][package]["dependencies"]
                 for r in value["components"][dependency["name"]]["extras"]] + [r["output"] for r in runtime["legal"]]
        require(len(paths) == len(set(paths)), "Colliding native legal companions")
    return value


def asset(row: dict) -> None:
    provenance.fields(row, "output url sourceSha256 sourceSha512 cacheName member memberSha256 start end encoding sha256 description")
    provenance.path(row["output"])
    require(row["output"].startswith("licenses/provenance/"), "Legal companion outside legal directory")
    download_identity(row["url"])
    require((row["sourceSha256"] is None) != (row["sourceSha512"] is None), "Ambiguous legal source digest")
    provenance.digest(row["sourceSha256"] or row["sourceSha512"], (64, 128))
    provenance.digest(row["sha256"])
    require(Path(row["cacheName"]).name == row["cacheName"], "Escaping legal cache path")
    if row["member"] is not None:
        provenance.path(row["member"])
        provenance.digest(row["memberSha256"])
    else:
        require(row["memberSha256"] is None, "Unexpected member digest")
    require(type(row["start"]) is int and type(row["end"]) is int and 0 <= row["start"] < row["end"],
            "Invalid legal-text byte range")
    require(row["encoding"] in {"raw", "utf-8", "latin-1"}, "Unknown legal-text encoding")
    provenance.text(row["description"])


def fetch(url: str, expected: str, algorithm: str, cache_name: str, cache: Path) -> Path:
    """Use only checksum-verified files; stale caches and downloads never become authority."""
    download_identity(url)
    require(Path(cache_name).name == cache_name, "Escaping download cache path")
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / cache_name

    def matches(path: Path) -> bool:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, algorithm).hexdigest() == expected

    if target.is_file():
        require(not target.is_symlink() and matches(target), "Cached source bytes differ from reviewed digest: " + cache_name)
        return target
    context = ssl.create_default_context()
    # Optional transport compatibility does not disable TLS or certificate validation.
    if os.environ.get("ARCFORGES_TLS12") == "1":
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    descriptor, temporary = tempfile.mkstemp(prefix="arcforges-source-", dir=cache)
    try:
        request = (urllib.request.Request(url, headers={"User-Agent": VISUAL_STUDIO_LICENSE_USER_AGENT})
                   if url in VISUAL_STUDIO_LICENSE_URLS else url)
        with os.fdopen(descriptor, "wb") as output, urllib.request.urlopen(request, timeout=60, context=context) as response:
            require(response.url.startswith("https://"), "Native source redirected away from HTTPS")
            shutil.copyfileobj(response, output)
        require(matches(Path(temporary)), "Downloaded source digest mismatch: " + cache_name)
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return target


def legal_bytes(row: dict, cache: Path) -> bytes:
    file = fetch(row["url"], row["sourceSha256"] or row["sourceSha512"],
                 "sha256" if row["sourceSha256"] else "sha512", row["cacheName"], cache)
    if row["member"] is not None:
        # Never extract an upstream archive onto the filesystem or follow its links.
        with tarfile.open(file) as archive:
            members = [m for m in archive.getmembers() if m.name.partition("/")[2] == row["member"]]
            require(len(members) == 1 and members[0].isfile() and members[0].size <= 8_000_000,
                    "Unexpected legal archive member")
            data = archive.extractfile(members[0]).read()
        require(sha(data) == row["memberSha256"], "Changed legal source member")
    else:
        data = file.read_bytes()
    require(row["end"] <= len(data), "Legal range exceeds source bytes")
    result = data[row["start"]:row["end"]]
    if row["encoding"] != "raw":
        result = result.decode(row["encoding"]).replace("\r\n", "\n").encode("utf-8")
    require(sha(result) == row["sha256"], "Changed legal-text transformation")
    return result


def native_notice(value: dict, package: str) -> bytes:
    rows = ["DesktopPlatform native provenance", "", "First-party ABI and wrapper source: AGPL-3.0-only.",
            "Third-party components retain their separate terms and full notices under licenses/.",
            "Build-only components identify recipes/tools; they are not bundled runtime implementations.", ""]
    for dependency in value["packages"][package]["dependencies"]:
        item = value["components"][dependency["name"]]
        src = item["source"]
        rows.extend([dependency["name"] + " " + item["version"] + " (" + item["role"] + ")",
                     src["repository"] + " @ " + src["commit"], src["spdx"], item["scope"], ""])
    rows.extend([value["platformRuntime"]["notice"], "",
                 "This software is based in part on the work of the Independent JPEG Group."
                 if any(d["name"] == "libjpeg-turbo" for d in value["packages"][package]["dependencies"]) else "",
                 ""])
    return "\n".join(rows).encode("utf-8")


def component_files(value: dict, package: str) -> dict[str, dict]:
    files = {}
    for dependency in value["packages"][package]["dependencies"]:
        name = dependency["triplet"]
        triplet = value["triplets"][name]
        files["recipes/toolchains/" + name + ".cmake"] = {"sha256": triplet["sha256"], "normalization": "lf"}
        files["recipes/toolchains/upstream-" + name + ".cmake"] = {"sha256": triplet["upstreamSha256"], "normalization": "lf"}
        files["licenses/provenance/vcpkg-LICENSE.txt"] = {"sha256": triplet["upstreamLicenceSha256"], "normalization": "lf"}
        item = value["components"][dependency["name"]]
        for row in item["legal"]:
            files[row["path"]] = {"sha256": row["sha256"], "normalization": "lf"}
        for path, digest in item["recipe"]["files"].items():
            files["recipes/" + dependency["name"] + "/" + path] = {"sha256": digest, "normalization": "lf"}
        for row in item["extras"]:
            files[row["output"]] = {"sha256": row["sha256"], "normalization": "raw"}
    for row in value["platformRuntime"]["legal"]:
        files[row["output"]] = {"sha256": row["sha256"], "normalization": "raw"}
    return files


def inspect_material(value: dict, package: str, read, names: set[str]) -> dict:
    """Independent, platform-neutral verification for stage and actual NuGet members."""
    require(package in value["packages"], "Unregistered native package")
    require(len(names) == len({n.casefold() for n in names}), "Case-colliding native members")
    for name in names:
        provenance.path(name)
    sbom = provenance.document(read("sbom.json"))
    require(sbom["buildTools"] == value["buildTools"], "Unreviewed native build tools in SBOM")
    expected = value["packages"][package]
    dependencies = sbom["buildDependencies"]
    actual = [{k: d[k] for k in ("name", "triplet", "version", "features")} for d in dependencies]
    require(actual == expected["dependencies"], "Changed native dependency/version/feature closure")
    records = []
    for dependency in dependencies:
        item = value["components"][dependency["name"]]
        require(dependency["license"] == "licenses/" + dependency["name"] + "-" + dependency["triplet"] + ".txt" and
                dependency["sbom"] == "licenses/" + dependency["name"] + "-" + dependency["triplet"] + ".spdx.json" and
                dependency["buildInfo"] == "licenses/" + dependency["name"] + "-" + dependency["triplet"] + ".abi.txt",
                "Unexpected native licence/SPDX location")
        build = [line.split(" ", 1) for line in read(dependency["buildInfo"]).decode("utf-8").splitlines() if line]
        triplet = value["triplets"][dependency["triplet"]]
        require([r[1] for r in build if r[0] == "cmake" and len(r) == 2] == [value["buildTools"]["vcpkgCMake"]] and
                [r[1] for r in build if r[0] == "triplet" and len(r) == 2] == [dependency["triplet"]],
                "Unreviewed upstream build generator/triplet: " + dependency["name"])
        identities = [r[1] for r in build if r[0] == "triplet_abi" and len(r) == 2]
        require(len(identities) == 1 and identities[0].split("-", 1)[0] == triplet["sha256"] and
                [r[1] for r in build if r[0] == "additional_file_0" and len(r) == 2] == [triplet["upstreamSha256"]],
                "Unreviewed upstream compiler selection: " + dependency["name"])
        source = provenance.document(read(dependency["sbom"]))
        check_sources(value, dependency["name"], source)
        if item["correspondingSource"] is not None:
            archive = item["correspondingSource"]
            require(dependency.get("sourceArchive") == archive["path"] and dependency.get("sourceUrl") == archive["url"],
                    "Missing or changed corresponding-source identity")
            require(hashlib.sha512(read(archive["path"])).hexdigest() == archive["sha512"], "Changed corresponding-source archive")
        records.append(item["record"])
    fixed = component_files(value, package)
    for name, row in fixed.items():
        require(name in names and sha(read(name), row["normalization"]) == row["sha256"], "Changed or missing native legal/recipe bytes: " + name)
    generated_names = {d[key] for d in dependencies for key in ("sbom", "buildInfo")}
    require({n for n in names if n.startswith(("licenses/", "recipes/"))} == set(fixed) | generated_names,
            "Unclassified native legal/recipe member")
    require({n for n in names if n.startswith("sources/")} ==
            {value["components"][d["name"]]["correspondingSource"]["path"] for d in dependencies
             if value["components"][d["name"]]["correspondingSource"] is not None}, "Unclassified native source archive")
    prefix = "runtimes/win-x64/native/"
    require(sorted(n[len(prefix):] for n in names if n.startswith(prefix) and n.endswith(".dll")) == expected["dlls"],
            "Changed native binary membership")
    runtime = value["platformRuntime"]
    crt = []
    for name in expected["dlls"]:
        if name.lower() not in runtime["files"]:
            continue
        row = runtime["files"][name.lower()]
        require(sha(read(prefix + name)) == row["sha256"], "Unapproved compiler-runtime bytes")
        crt.append({"name": name, **row})
    require(sbom["visualCppRuntime"]["files"] == crt and
            sbom["visualCppRuntime"]["record"] == runtime["id"] and
            sbom["visualCppRuntime"]["redistributableDirectoryVersion"] == runtime["distributionIdentity"]["directoryVersion"],
            "Compiler-runtime SBOM does not describe the actual reviewed files")
    require(read(NOTICE) == native_notice(value, package), "Missing native provenance attribution")
    require(read(NOTICE) in read("NOTICE.md").replace(b"\r\n", b"\n"), "Package NOTICE lost native provenance")
    return {"records": sorted(records), "platformRuntimeRecord": runtime["id"], "compilerRuntimeFiles": crt}


def seal(destination: Path, package: str, cache: Path, signatures: dict, root: Path = ROOT) -> dict:
    value = profile(root)
    for dependency in value["packages"][package]["dependencies"]:
        for row in value["components"][dependency["name"]]["extras"]:
            target = destination / row["output"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(legal_bytes(row, cache))
    for row in value["platformRuntime"]["legal"]:
        target = destination / row["output"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(legal_bytes(row, cache))
    notice = native_notice(value, package)
    (destination / NOTICE).parent.mkdir(parents=True, exist_ok=True)
    (destination / NOTICE).write_bytes(notice)
    with (destination / "NOTICE.md").open("ab") as output:
        output.write(b"\n" + notice)
    names = {p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file()}
    read = lambda path: provenance.read(destination, path)
    material = inspect_material(value, package, read, names)
    for row in material["compilerRuntimeFiles"]:
        require(signatures[row["name"].lower()] == {"sha256": row["sha256"], "productVersion": row["productVersion"],
                                                  "fileVersion": row["fileVersion"], "publisher": row["publisher"], "signature": "valid"},
                "Missing producer signature evidence")
    receipt = {"schemaVersion": 1, "sourceCommit": provenance.document(read("sbom.json"))["sourceCommit"],
               "package": package, "profile": PROFILE, "profileSha256": sha(provenance.read(root, PROFILE), "lf"),
               **material, "signatureVerification": {r["name"]: signatures[r["name"].lower()] for r in material["compilerRuntimeFiles"]},
               "files": [{"path": n, "sha256": sha(read(n))} for n in sorted(names)]}
    (destination / RECEIPT).write_bytes(canonical(receipt))
    verify(package, read, names | {RECEIPT}, root)
    return receipt


def verify(package: str, read, names: set[str], root: Path = ROOT) -> dict:
    value = profile(root)
    actual = inspect_material(value, package, read, names)
    receipt = provenance.document(read(RECEIPT))
    provenance.fields(receipt, "schemaVersion sourceCommit package profile profileSha256 records platformRuntimeRecord compilerRuntimeFiles signatureVerification files")
    require(receipt["schemaVersion"] == 1 and receipt["package"] == package and receipt["profile"] == PROFILE and
            receipt["profileSha256"] == sha(provenance.read(root, PROFILE), "lf") and
            receipt["sourceCommit"] == provenance.document(read("sbom.json"))["sourceCommit"], "Wrong native provenance receipt identity")
    require(all(receipt[k] == v for k, v in actual.items()), "Native receipt record mismatch")
    for row in actual["compilerRuntimeFiles"]:
        require(receipt["signatureVerification"].get(row["name"]) == {
            "sha256": row["sha256"], "productVersion": row["productVersion"], "fileVersion": row["fileVersion"],
            "publisher": row["publisher"], "signature": "valid"}, "Missing native producer signature receipt")
    members = {r["path"]: r["sha256"] for r in receipt["files"]}
    require(len(members) == len(receipt["files"]), "Duplicate native receipt member")
    # NuGet adds the package metadata and root README/LICENSE; the native stage is otherwise closed.
    metadata = names & {package + ".nuspec", "[Content_Types].xml", "_rels/.rels", "README.md", "LICENSE", ".signature.p7s", "build-identity.json",
                        "package/services/metadata/core-properties/nuget.psmdcp"}
    require(names - metadata - {RECEIPT} == set(members), "Native candidate membership differs from sealed producer")
    for name, digest in members.items():
        require(sha(read(name)) == digest, "Native candidate member differs from the tested producer artifact: " + name)
    return {"result": "passed", "package": package, "profileSha256": receipt["profileSha256"],
            "records": actual["records"], "members": len(names), "sourceCommit": receipt["sourceCommit"]}


def signed_runtime(path: Path) -> dict:
    """Check Windows Authenticode trust, actual signer and both fixed version fields."""
    require(os.name == "nt", "Compiler-runtime signature verification requires Windows")
    trust = ctypes.WinDLL("wintrust", use_last_error=True)
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    version = ctypes.WinDLL("version", use_last_error=True)

    class Guid(ctypes.Structure):
        _fields_ = [("data1", wintypes.DWORD), ("data2", wintypes.WORD), ("data3", wintypes.WORD), ("data4", ctypes.c_ubyte * 8)]

    class FileInfo(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("path", wintypes.LPCWSTR), ("handle", wintypes.HANDLE), ("subject", ctypes.c_void_p)]

    class TrustData(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("policy", ctypes.c_void_p), ("sip", ctypes.c_void_p),
                    ("ui", wintypes.DWORD), ("revocation", wintypes.DWORD), ("choice", wintypes.DWORD),
                    ("file", ctypes.POINTER(FileInfo)), ("action", wintypes.DWORD), ("state", wintypes.HANDLE),
                    ("url", wintypes.LPWSTR), ("flags", wintypes.DWORD), ("context", wintypes.DWORD), ("signature", ctypes.c_void_p)]

    action = Guid(0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
    file = FileInfo(ctypes.sizeof(FileInfo), str(path.resolve()), None, None)
    data = TrustData()
    data.size, data.ui, data.choice, data.file = ctypes.sizeof(TrustData), 2, 1, ctypes.pointer(file)
    # Whole-chain verification excluding the root; system trust and revocation checks remain enabled.
    data.flags, data.action = 0x80, 1
    trust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(Guid), ctypes.POINTER(TrustData)]
    trust.WinVerifyTrust.restype = wintypes.LONG
    try:
        require(trust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data)) == 0,
                "Compiler-runtime Authenticode verification failed: " + path.name)
    finally:
        data.action = 2
        trust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    store, message, cert = ctypes.c_void_p(), ctypes.c_void_p(), None
    crypt.CryptQueryObject.argtypes = [wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                     ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    crypt.CryptMsgGetParam.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    crypt.CertFindCertificateInStore.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    crypt.CertFindCertificateInStore.restype = ctypes.c_void_p
    crypt.CertGetNameStringW.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    crypt.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    crypt.CryptMsgClose.argtypes = [ctypes.c_void_p]
    crypt.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    try:
        require(crypt.CryptQueryObject(1, ctypes.c_wchar_p(str(path.resolve())), 1 << 10, 2, 0,
                                       None, None, None, ctypes.byref(store), ctypes.byref(message), None), "Cannot read native signer")
        size = wintypes.DWORD()
        require(crypt.CryptMsgGetParam(message, 7, 0, None, ctypes.byref(size)), "Missing native signer certificate")
        info = ctypes.create_string_buffer(size.value)
        require(crypt.CryptMsgGetParam(message, 7, 0, info, ctypes.byref(size)), "Invalid native signer certificate")
        cert = crypt.CertFindCertificateInStore(store, 0x10001, 0, 11 << 16, info, None)
        require(cert, "Native signer certificate not found")
        length = crypt.CertGetNameStringW(cert, 4, 0, None, None, 0)
        publisher = ctypes.create_unicode_buffer(length)
        require(length > 1 and crypt.CertGetNameStringW(cert, 4, 0, None, publisher, length), "Native publisher missing")
    finally:
        if cert:
            crypt.CertFreeCertificateContext(cert)
        if message:
            crypt.CryptMsgClose(message)
        if store:
            crypt.CertCloseStore(store, 0)
    version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    version.VerQueryValueW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)]
    dummy = wintypes.DWORD()
    size = version.GetFileVersionInfoSizeW(str(path), ctypes.byref(dummy))
    require(size > 0, "Native version resource missing")
    buffer = ctypes.create_string_buffer(size)
    require(version.GetFileVersionInfoW(str(path), 0, size, buffer), "Cannot read native version resource")
    pointer, length = ctypes.c_void_p(), wintypes.UINT()
    require(version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)) and length.value >= 52,
            "Invalid native version resource")
    words = ctypes.cast(pointer, ctypes.POINTER(wintypes.DWORD))
    require(words[0] == 0xFEEF04BD, "Invalid native fixed version signature")
    number = lambda high, low: ".".join(str(v) for v in (high >> 16, high & 0xFFFF, low >> 16, low & 0xFFFF))
    return {"sha256": sha(path.read_bytes()), "productVersion": number(words[4], words[5]),
            "fileVersion": number(words[2], words[3]), "publisher": publisher.value, "signature": "valid"}


def approve_runtime(path: Path, value: dict) -> dict:
    expected = value["platformRuntime"]["files"].get(path.name.lower())
    require(expected is not None and sha(path.read_bytes()) == expected["sha256"], "Unreviewed compiler-runtime version/file")
    actual = signed_runtime(path)
    require(actual == {**expected, "signature": "valid"}, "Compiler-runtime publisher/version mismatch")
    return actual


def pdfium_profile(root: Path = ROOT) -> dict:
    """The separate, immutable PDFium producer admission; the existing Image profile stays intact."""
    value = provenance.document(provenance.read(root, "eng/native/vcpkg/pdfium-build.v1.json"))
    require(value["schemaVersion"] == 1 and value["id"] == "pdfium-chromium-8044-win-x64-r1" and
            value["version"] == "155.0.8044.0" and value["rid"] == "win-x64", "Unknown PDFium build profile")
    require(value["configuration"] == {"pdf_enable_v8": False, "pdf_enable_xfa": False,
                                       "target_cpu": "x64", "target_os": "win"}, "Unapproved PDFium configuration")
    require(value["attestation"]["repository"] == "bblanchon/pdfium-binaries" and
            value["attestation"]["workflow"] == ".github/workflows/build-all.yml" and
            value["attestation"]["recipeCommit"] == "5453f3afc4785cbad82c05f6ceb4dabea0cb81a0",
            "Unapproved PDFium producer identity")
    for identity in (value["archive"], value["attestation"]):
        download_identity(identity["url"])
        provenance.digest(identity["sha256"])
        require(type(identity["maximumBytes"]) is int and 0 < identity["maximumBytes"] <= 8 * 1024 * 1024,
                "Invalid PDFium transfer bound")
    require(value["archive"]["url"] == "https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/8044/pdfium-win-x64.tgz" and
            value["attestation"]["url"] == "https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/8044/pdfium-attestation.json",
            "Changed PDFium source coordinate")
    for name, expected in value["files"].items():
        provenance.path(name)
        provenance.digest(expected)
    for name, expected in value["legalFiles"].items():
        require(name.startswith("third-party/pdfium/chromium-8044/"), "PDFium legal target escapes ownership")
        require(sha(provenance.read(root, name)) == expected, "Changed PDFium legal text: " + name)
    return value


def pdfium_download(identity: dict, destination: Path) -> Path:
    """One bounded trust handoff, cache by digest; retry only transient transport errors, never bad bytes."""
    if destination.exists():
        require(destination.is_file() and destination.stat().st_size <= identity["maximumBytes"],
                "PDFium cache exceeds admission bound")
        require(sha(destination.read_bytes()) == identity["sha256"], "PDFium cache digest mismatch")
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(3):
        temporary = None
        try:
            request = urllib.request.Request(identity["url"], headers={"User-Agent": "ArcForges-PDFium-producer/1.0"})
            with urllib.request.urlopen(request, timeout=60) as response, tempfile.NamedTemporaryFile(
                    dir=destination.parent, prefix=".pdfium-", delete=False) as output:
                temporary = Path(output.name)
                total = 0
                while block := response.read(64 * 1024):
                    total += len(block)
                    require(total <= identity["maximumBytes"], "PDFium transfer exceeds admission bound")
                    output.write(block)
            require(sha(temporary.read_bytes()) == identity["sha256"], "PDFium download digest mismatch")
            temporary.replace(destination)
            return destination
        except (urllib.error.URLError, TimeoutError) as error:
            transient = not isinstance(error, urllib.error.HTTPError) or error.code in {408, 429, 500, 502, 503, 504}
            if not transient or attempt == 2:
                raise
            time.sleep((0.5, 2.0)[attempt])
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    raise RuntimeError("PDFium transfer did not complete")


def verify_pdfium_prefix(prefix: Path, value: dict) -> None:
    actual = {file.relative_to(prefix).as_posix(): sha(file.read_bytes())
              for file in prefix.rglob("*") if file.is_file()}
    require(actual == value["files"], "PDFium prefix differs from the complete admitted archive")
    args = (prefix / "args.gn").read_text(encoding="utf-8")
    require("pdf_enable_v8 = false" in args and "pdf_enable_xfa = false" in args and
            'target_cpu = "x64"' in args and 'target_os = "win"' in args,
            "PDFium executable features or RID changed")


def acquire_pdfium(directory: Path, root: Path = ROOT) -> dict:
    """Fetch/verify the reviewed producer build, never a consumer-time dependency download."""
    value = pdfium_profile(root)
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    archive = pdfium_download(value["archive"], directory / "pdfium-win-x64.tgz")
    bundle = pdfium_download(value["attestation"], directory / "pdfium-attestation.json")
    # gh verifies the Sigstore certificate, signature and transparency inclusion, not just JSON fields.
    verified = subprocess.run([
        "gh", "attestation", "verify", str(archive), "--repo", value["attestation"]["repository"],
        "--bundle", str(bundle), "--deny-self-hosted-runners", "--source-digest", value["attestation"]["recipeCommit"],
        "--signer-workflow", value["attestation"]["repository"] + "/" + value["attestation"]["workflow"], "--format", "json",
    ], check=True, capture_output=True, text=True, timeout=120)
    require(bool(json.loads(verified.stdout)), "PDFium attestation verification produced no receipt")
    statement = json.loads(base64.b64decode(json.loads(bundle.read_text())["dsseEnvelope"]["payload"], validate=True))
    require(any(subject["name"] == archive.name and subject["digest"] == {"sha256": value["archive"]["sha256"]}
                for subject in statement["subject"]), "PDFium attestation lacks the admitted subject")
    require(statement["predicate"]["runDetails"]["metadata"]["invocationId"] == value["attestation"]["invocation"],
            "PDFium producer invocation changed")
    prefix = directory / "pdfium"
    if prefix.exists():
        verify_pdfium_prefix(prefix, value)
    else:
        with tempfile.TemporaryDirectory(dir=directory, prefix=".pdfium-extract-") as temporary:
            staging = Path(temporary) / "pdfium"
            staging.mkdir()
            with tarfile.open(archive, "r:gz") as tar:
                for member in tar.getmembers():
                    provenance.path(member.name.rstrip("/"))
                    require(member.isdir() or member.isfile() and member.name in value["files"],
                            "Unapproved PDFium archive member")
                    require(member.size <= value["archive"]["maximumBytes"], "PDFium member exceeds its bound")
                tar.extractall(staging, filter="data")
            verify_pdfium_prefix(staging, value)
            staging.replace(prefix)
    receipt = {"profile": value["id"], "archiveSha256": value["archive"]["sha256"],
               "attestationSha256": value["attestation"]["sha256"], "producerInvocation": value["attestation"]["invocation"],
               "recipeCommit": value["attestation"]["recipeCommit"], "rid": value["rid"],
               "version": value["version"], "cryptographicVerification": "GitHub CLI Sigstore/SLSA verification passed"}
    (directory / "pdfium-build-receipt.json").write_bytes(canonical(receipt))
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path)
    parser.add_argument("--acquire-pdfium", type=Path)
    args = parser.parse_args()
    if args.acquire_pdfium:
        print(json.dumps(acquire_pdfium(args.acquire_pdfium)))
        sys.exit(0)
    value = profile()
    results = []
    if args.stage:
        for package in value["packages"]:
            base = (args.stage / package).resolve()
            results.append(verify(package, lambda p: provenance.read(base, p),
                                  {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()}))
    print(json.dumps({"result": "passed", "components": len(value["components"]), "packages": results}))
