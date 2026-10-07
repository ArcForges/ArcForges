# SPDX-License-Identifier: AGPL-3.0-only
"""Verify the reviewed native source, legal-text and compiler-runtime closure."""

from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
from datetime import date
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
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
                 if p["kind"] == "native" and p["id"] in value["packages"]}
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
    require(value["sbom"]["path"] == "eng/native/vcpkg/pdfium-sbom.v1.json" and
            sha(provenance.read(root, value["sbom"]["path"]), "lf") == value["sbom"]["sha256"],
            "Changed PDFium aggregate bundle SBOM")
    runtime = value["compilerRuntime"]
    provenance.fields(runtime, "profile sha256 target role review")
    require(runtime["profile"] == PROFILE and runtime["sha256"] == sha(provenance.read(root, PROFILE), "lf") and
            runtime["target"] == "pdfium-production-composition-input", "Changed PDF compiler-runtime admission")
    provenance.text(runtime["role"])
    review = runtime["review"]
    provenance.fields(review, "owner reviewer reviewedOn baselineCommit decision rationale")
    require(review["owner"] == "Licensing and Provenance Owner" and review["decision"] == "approved",
            "Unreviewed PDF compiler-runtime role")
    for key in ("reviewer", "rationale"):
        provenance.text(review[key])
    provenance.digest(review["baselineCommit"], (40,))
    date.fromisoformat(provenance.text(review["reviewedOn"]))
    return value


PORTABLE_PDFIUM_ARCHIVES = {
    "linux-arm64": ("linux-arm64", "e98400ef5f005f27cfba5c14f72d464e25187298f04950de46646033cf24cef0"),
    "linux-x64": ("linux-x64", "eb142f416aed3a72fc5a02dbd5884868a16cb99dc0cf53e6bdd64afbf67b05f4"),
    "osx-arm64": ("mac-arm64", "61424884d4a7f153b808deba6437848e4400834ce30aaf95d3050da44df8f420"),
    "osx-x64": ("mac-x64", "a93d44238e05de20028446561b951d50988b849efbbe56fe40c0d376c05b45e8"),
    "win-arm64": ("win-arm64", "6c9ac0ddc69edd8a18d47b95098a5b843eaed5c5bbdcb9587a18c196457449f8"),
}


def portable_pdfium_profile(rid: str, root: Path = ROOT) -> dict:
    """Admit a complete pinned upstream SDK. Real shim/runtime production is a separate inspected handoff."""
    if rid == "win-x64":
        return pdfium_profile(root)
    require(rid in PORTABLE_PDFIUM_ARCHIVES, "Unadmitted PDFium RID")
    value = provenance.document(provenance.read(root, f"eng/native/vcpkg/pdfium-build.{rid}.v1.json"))
    provenance.fields(value, "schemaVersion id version rid archive attestation source configuration files legalFiles admission sbom inspection")
    original = pdfium_profile(root)
    coordinate, archive_digest = PORTABLE_PDFIUM_ARCHIVES[rid]
    platform, cpu = rid.split("-")
    require(value["schemaVersion"] == 2 and value["id"] == f"pdfium-chromium-8044-{rid}-r1" and
            value["rid"] == rid and value["version"] == original["version"], "Changed portable PDFium identity")
    require(value["archive"] == {"url": "https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/8044/pdfium-" + coordinate + ".tgz",
                                 "sha256": archive_digest, "maximumBytes": 8 * 1024 * 1024}, "Changed portable PDFium coordinate")
    require(value["attestation"] == original["attestation"] and value["source"] == original["source"] and value["admission"] == original["admission"],
            "Changed portable PDFium signer/source statement")
    configuration = {"pdf_enable_v8": False, "pdf_enable_xfa": False, "target_cpu": cpu,
                     "target_os": {"win": "win", "linux": "linux", "osx": "mac"}[platform]}
    require(value["configuration"] == configuration, "Changed portable PDFium executable features/RID")
    library = {"win": "bin/pdfium.dll", "linux": "lib/libpdfium.so", "osx": "lib/libpdfium.dylib"}[platform]
    expected_files = set(original["files"])
    if platform != "win":
        expected_files -= {"bin/pdfium.dll", "lib/pdfium.dll.lib"}
        expected_files.add(library)
    require(set(value["files"]) == expected_files, "Changed portable PDFium closed SDK inventory")
    for name, digest in value["files"].items():
        provenance.path(name)
        provenance.digest(digest)
    legal = {name: digest for name, digest in value["files"].items() if name == "LICENSE" or name.startswith("licenses/")}
    require(len(legal) == 15 and value["legalFiles"] == legal, "Changed portable PDFium full legal inventory")
    sbom_path = f"eng/native/vcpkg/pdfium-sbom.{rid}.v1.json"
    require(value["sbom"]["path"] == sbom_path and
            sha(provenance.read(root, sbom_path), "lf") == value["sbom"]["sha256"], "Changed portable PDFium SBOM")
    sbom = provenance.document(provenance.read(root, sbom_path))
    package = sbom["packages"][0]
    require(len(sbom["packages"]) == 1 and package["downloadLocation"] == value["archive"]["url"] and
            package["checksums"] == [{"algorithm": "SHA256", "checksumValue": archive_digest}] and
            package["licenseConcluded"] == original_license(root), "Portable PDFium SBOM identity/licence mismatch")
    require({row["fileName"]: row["checksums"] for row in sbom["files"]} ==
            {name: [{"algorithm": "SHA256", "checksumValue": digest}] for name, digest in legal.items()} and
            len(sbom["files"]) == len(legal), "Portable PDFium SBOM legal checksums mismatch")
    inspection = value["inspection"]
    provenance.fields(inspection, "owner systemPolicy format machine library linkerInput requiresActualCompilerRuntimeReceipt note")
    require(inspection["owner"] == "NAT.22" and inspection["systemPolicy"] == "eng/native/vcpkg/system-dependencies.v2.json" and
            inspection["format"] == {"win": "PE", "linux": "ELF", "osx": "Mach-O"}[platform] and
            inspection["machine"] == cpu and inspection["library"] == library and
            inspection["linkerInput"] == ("lib/pdfium.dll.lib" if platform == "win" else library) and
            inspection["requiresActualCompilerRuntimeReceipt"] is (platform == "win"), "Changed portable binary inspection contract")
    provenance.text(inspection["note"])
    return value


def original_license(root: Path) -> str:
    original = pdfium_profile(root)
    return provenance.document(provenance.read(root, original["sbom"]["path"]))["packages"][0]["licenseConcluded"]


def pdfium_download(identity: dict, destination: Path) -> Path:
    """One bounded trust handoff, cache by digest; retry only transient transport errors, never bad bytes."""
    download_identity(identity["url"])
    require(isinstance(identity["maximumBytes"], int) and 0 < identity["maximumBytes"] <= 16 * 1024 * 1024,
            "Invalid PDFium transfer bound")
    if destination.exists():
        require(not destination.is_symlink() and destination.is_file() and destination.stat().st_size <= identity["maximumBytes"],
                "PDFium cache exceeds admission bound")
        require(sha(destination.read_bytes()) == identity["sha256"], "PDFium cache digest mismatch")
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    context = ssl.create_default_context()
    if os.environ.get("ARCFORGES_TLS12") == "1":
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    operation_deadline = time.monotonic() + 180
    for attempt in range(3):
        temporary = None
        try:
            attempt_deadline = min(operation_deadline, time.monotonic() + 60)
            remaining = attempt_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("PDFium transfer deadline exceeded")
            user_agent = (VISUAL_STUDIO_LICENSE_USER_AGENT if identity["url"] in VISUAL_STUDIO_LICENSE_URLS
                          else "ArcForges-PDFium-producer/1.0")
            request = urllib.request.Request(identity["url"], headers={"User-Agent": user_agent})
            with urllib.request.urlopen(request, timeout=remaining, context=context) as response, tempfile.NamedTemporaryFile(
                    dir=destination.parent, prefix=".pdfium-", delete=False) as output:
                temporary = Path(output.name)
                download_identity(response.geturl())
                total = 0
                require(callable(getattr(response, "read1", None)), "PDFium response has no bounded progress reader")
                while True:
                    remaining = attempt_deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("PDFium transfer deadline exceeded")
                    # urllib's HTTPS response exposes the active socket through its buffered reader.
                    # Narrow its timeout before each read1, which performs at most one underlying read
                    # rather than waiting indefinitely for an entire 64KiB block to trickle in.
                    socket = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
                    if socket is not None and not socket._closed:
                        socket.settimeout(remaining)
                    block = response.read1(64 * 1024)
                    if time.monotonic() >= attempt_deadline:
                        raise TimeoutError("PDFium transfer deadline exceeded")
                    if not block:
                        break
                    total += len(block)
                    require(total <= identity["maximumBytes"], "PDFium transfer exceeds admission bound")
                    output.write(block)
            require(sha(temporary.read_bytes()) == identity["sha256"], "PDFium download digest mismatch")
            temporary.replace(destination)
            return destination
        except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLEOFError, http.client.IncompleteRead) as error:
            transient = not isinstance(error, urllib.error.HTTPError) or error.code in {408, 429, 500, 502, 503, 504}
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            if isinstance(error, urllib.error.URLError) and isinstance(error.reason, ssl.SSLCertVerificationError):
                transient = False
            delay = (0.5, 2.0)[min(attempt, 1)]
            if not transient or attempt == 2 or time.monotonic() + delay >= operation_deadline:
                raise
            time.sleep(delay)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    raise RuntimeError("PDFium transfer did not complete")


def verify_pdfium_prefix(prefix: Path, value: dict) -> None:
    require(prefix.is_dir() and not prefix.is_symlink(), "PDFium prefix is not an admitted directory")
    files = {}
    for index, file in enumerate(prefix.rglob("*")):
        require(index < len(value["files"]) * 3 + 32, "PDFium prefix inventory exceeds its bound")
        require(not file.is_symlink(), "PDFium prefix contains an unapproved symbolic link")
        if file.is_file():
            name = file.relative_to(prefix).as_posix()
            require(name in value["files"], "PDFium prefix differs from the complete admitted archive")
            require(file.stat().st_size <= 8 * 1024 * 1024, "PDFium prefix member exceeds its bound")
            files[name] = file
    require(set(files) == set(value["files"]), "PDFium prefix differs from the complete admitted archive")
    actual = {name: sha(file.read_bytes()) for name, file in files.items()}
    require(actual == value["files"], "PDFium prefix differs from the complete admitted archive")
    args = (prefix / "args.gn").read_text(encoding="utf-8")
    configuration = value["configuration"]
    require("pdf_enable_v8 = false" in args and "pdf_enable_xfa = false" in args and
            f'target_cpu = "{configuration["target_cpu"]}"' in args and f'target_os = "{configuration["target_os"]}"' in args,
            "PDFium executable features or RID changed")


def verify_pdfium_attestation(archive: Path, bundle: Path, value: dict) -> None:
    """Verify the external signer and bind the signed subject/invocation to the admitted producer."""
    # gh verifies the Sigstore certificate, signature and transparency inclusion, not just JSON fields.
    command = [
        "gh", "attestation", "verify", str(archive), "--repo", value["attestation"]["repository"],
        "--bundle", str(bundle), "--deny-self-hosted-runners", "--source-digest", value["attestation"]["recipeCommit"],
        "--signer-workflow", value["attestation"]["repository"] + "/" + value["attestation"]["workflow"], "--format", "json",
    ]
    for attempt in range(3):
        try:
            verified = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
            break
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            # Do not retry trust, signature, identity or digest failures. Only transport diagnostics
            # can justify another read-only verification attempt against the unchanged cached bytes.
            diagnostic = error.stderr or ""
            if isinstance(diagnostic, bytes):
                diagnostic = diagnostic.decode("utf-8", errors="replace")
            diagnostic = diagnostic.lower()
            transient = isinstance(error, subprocess.TimeoutExpired) or any(marker in diagnostic for marker in
                            ("http 429", "http 500", "http 502", "http 503", "http 504",
                             "connection reset", "connection timed out", "tls handshake timeout"))
            if not transient or attempt == 2:
                raise
            time.sleep((0.5, 2.0)[attempt])
    verification = json.loads(verified.stdout)
    require(isinstance(verification, list) and bool(verification), "PDFium attestation verification produced no receipt")
    statement = json.loads(base64.b64decode(json.loads(bundle.read_text())["dsseEnvelope"]["payload"], validate=True))
    require(any(subject["name"] == archive.name and subject["digest"] == {"sha256": value["archive"]["sha256"]}
                for subject in statement["subject"]), "PDFium attestation lacks the admitted subject")
    require(statement["predicate"]["runDetails"]["metadata"]["invocationId"] == value["attestation"]["invocation"],
            "PDFium producer invocation changed")


def extract_pdfium_archive(archive: Path, staging: Path, value: dict) -> None:
    expected = set(value["files"])
    directories = {parent.as_posix() for name in expected for parent in Path(name).parents
                   if parent.as_posix() != "."}
    names, files, members, total = set(), set(), [], 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            name = member.name.rstrip("/")
            provenance.path(name)
            require(name not in names and len(members) < len(expected) * 3 + 32,
                    "Duplicate or excessive PDFium archive members")
            require(member.isfile() and name in expected or member.isdir() and name in directories,
                    "Unapproved PDFium archive member")
            require(0 <= member.size <= value["archive"]["maximumBytes"], "PDFium member exceeds its bound")
            total += member.size
            require(total <= 64 * 1024 * 1024, "PDFium expanded archive exceeds its bound")
            names.add(name)
            if member.isfile(): files.add(name)
            members.append(member)
        require(files == expected, "PDFium archive file inventory changed")
        tar.extractall(staging, members=members, filter="data")


def pdfium_admission_receipt(value: dict) -> dict:
    return {"profile": value["id"], "archiveSha256": value["archive"]["sha256"],
            "attestationSha256": value["attestation"]["sha256"], "producerInvocation": value["attestation"]["invocation"],
            "recipeCommit": value["attestation"]["recipeCommit"], "rid": value["rid"], "version": value["version"],
            "cryptographicVerification": "GitHub CLI Sigstore/SLSA verification passed", "sbomSha256": value["sbom"]["sha256"]}


def verify_pdfium_admission_input(directory: Path, value: dict) -> dict:
    """Revalidate actual bounded evidence bytes and trust at the composition handoff, never a receipt assertion alone."""
    for name, identity in ((Path(urlsplit(value["archive"]["url"]).path).name, value["archive"]), ("pdfium-attestation.json", value["attestation"])):
        file = directory / name
        require(file.is_file() and not file.is_symlink() and file.stat().st_size <= identity["maximumBytes"],
                "Missing or unbounded PDF admission evidence: " + name)
        require(sha(file.read_bytes()) == identity["sha256"], "PDF admission evidence digest changed: " + name)
    receipt = directory / "pdfium-build-receipt.json"
    require(receipt.is_file() and not receipt.is_symlink() and receipt.stat().st_size <= 64 * 1024,
            "Missing or unbounded PDF admission receipt")
    expected = pdfium_admission_receipt(value)
    require(receipt.read_bytes() == canonical(expected), "PDF admission receipt is not the exact canonical closed contract")
    verify_pdfium_attestation(directory / Path(urlsplit(value["archive"]["url"]).path).name, directory / "pdfium-attestation.json", value)
    return expected


def acquire_pdfium(directory: Path, root: Path = ROOT, rid: str = "win-x64") -> dict:
    """Fetch/verify the reviewed producer build, never a consumer-time dependency download."""
    value = portable_pdfium_profile(rid, root)
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    archive = pdfium_download(value["archive"], directory / Path(urlsplit(value["archive"]["url"]).path).name)
    bundle = pdfium_download(value["attestation"], directory / "pdfium-attestation.json")
    verify_pdfium_attestation(archive, bundle, value)
    prefix = directory / "pdfium"
    if prefix.exists():
        verify_pdfium_prefix(prefix, value)
    else:
        with tempfile.TemporaryDirectory(dir=directory, prefix=".pdfium-extract-") as temporary:
            staging = Path(temporary) / "pdfium"
            staging.mkdir()
            extract_pdfium_archive(archive, staging, value)
            verify_pdfium_prefix(staging, value)
            try:
                staging.replace(prefix)
            except OSError:
                # Another verified producer may have atomically promoted the identical prefix first.
                # Check the winner rather than repeating a possibly successful write or deleting it.
                if not prefix.exists():
                    raise
                verify_pdfium_prefix(prefix, value)
    receipt = pdfium_admission_receipt(value)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, prefix=".pdfium-receipt-", delete=False) as output:
            temporary = Path(output.name)
            output.write(canonical(receipt))
        temporary.replace(directory / "pdfium-build-receipt.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return receipt


def pdfium_owned_recipe(producer, runtime_profile: dict, pdfium_directory: Path,
                        native_prefix: Path, root: Path = ROOT) -> dict:
    """Inspect the retained root producer recipe; component fixture builds cannot be sealed."""
    build_tools = producer.owned_build_tools(runtime_profile, root / "artifacts/vcpkg-installed", root)
    cache = root / "artifacts/cmake/win-x64/shim-static/CMakeCache.txt"
    values = dict(line.split("=", 1) for line in cache.read_text(encoding="utf-8").splitlines()
                  if line and not line.startswith(("#", "//")) and "=" in line)
    require(values.get("CMAKE_HOME_DIRECTORY:INTERNAL") and
            Path(values["CMAKE_HOME_DIRECTORY:INTERNAL"]).resolve() == root.resolve(),
            "PDF producer must use the owned root build, not a fixture wrapper")
    require(values.get("ARCFORGES_PDFIUM:BOOL") == "ON" and
            values.get("ARCFORGES_NATIVE_PROFILE:STRING") == "shim-static" and
            values.get("CMAKE_BUILD_TYPE:STRING") == "Release" and
            values.get("VCPKG_TARGET_TRIPLET:STRING") == "x64-windows-static-md",
            "PDF producer recipe is not the admitted production configuration")
    for key, expected in (("PDFium_DIR:PATH", pdfium_directory / "pdfium"),
                          ("CMAKE_INSTALL_PREFIX:PATH", native_prefix)):
        require(key in values and Path(values[key]).resolve() == expected.resolve(),
                "PDF producer used a different admitted prefix: " + key)
    return {"buildTools": build_tools, "cacheSha256": sha(cache.read_bytes()),
            "configuration": "Release", "nativeProfile": "shim-static",
            "triplet": "x64-windows-static-md", "pdfium": "chromium/8044"}


def verify_pdfium_staging(staging: Path, selected: dict, value: dict, receipt: dict,
                          runtime_legal: list[dict] | None = None) -> None:
    """Rebind copied bytes before promotion, refusing cache changes during the handoff."""
    expected = {"runtimes/win-x64/native/" + item["name"]: (item["sha256"], "raw", 16 * 1024 * 1024)
                for item in selected.values()}
    expected["provenance/pdfium-attestation.json"] = (value["attestation"]["sha256"], "raw",
                                                       value["attestation"]["maximumBytes"])
    expected["provenance/pdfium-sbom.v1.json"] = (value["sbom"]["sha256"], "lf", 8 * 1024 * 1024)
    expected["provenance/pdfium-build.v1.json"] = (sha(canonical(value), "lf"), "lf", 8 * 1024 * 1024)
    for name, digest in value["legalFiles"].items():
        expected["licenses/pdfium/" + Path(name).name] = (digest, "raw", 8 * 1024 * 1024)
    for legal in runtime_legal or ():
        expected[legal["output"]] = (legal["sourceSha256"], "raw", 8 * 1024 * 1024)
    for name, (digest, normalization, maximum) in expected.items():
        path = staging / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,
                "Missing or unbounded copied PDF evidence: " + name)
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        require(len(data) <= maximum and sha(data, normalization) == digest,
                "Copied PDF evidence changed during sealing: " + name)
    path = staging / "provenance/pdfium-build-receipt.json"
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 64 * 1024,
            "Missing or unbounded copied PDF admission receipt")
    with path.open("rb") as stream:
        data = stream.read(64 * 1024 + 1)
    require(data == canonical(receipt), "Copied PDF admission receipt changed during sealing")


def stage_pdfium_input(directory: Path, pdfium_directory: Path, native_prefix: Path) -> dict:
    """Seal the actual PDF binary/SDK/dependency input for NAT.25; this is not a published package."""
    import importlib.util
    import build_identity

    require(os.name == "nt", "The admitted PDFium producer requires Windows x64")
    directory = directory.resolve()
    require(not directory.exists(), "PDF composition input already exists; choose a fresh destination")
    audit = provenance.run(ROOT, "DesktopPlatform",
                           base=os.environ.get("GITHUB_SHA") if os.environ.get("GITHUB_REF", "").startswith("refs/tags/") else None)
    require(not audit["dirty"], "Commit reviewed source before producing the PDF composition input")
    value = pdfium_profile()
    verify_pdfium_prefix(pdfium_directory / "pdfium", value)
    receipt = verify_pdfium_admission_input(pdfium_directory, value)
    specification = importlib.util.spec_from_file_location("arc_pdf_native_producer", ROOT / "eng/packaging/native.py")
    require(specification is not None and specification.loader is not None, "Native PE inspector is unavailable")
    producer = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(producer)
    owned = native_prefix / "native/ArcPdfNative.dll"
    require(owned.is_file() and owned.stat().st_size <= 16 * 1024 * 1024, "Missing or unbounded PDF ABI output")
    data = owned.read_bytes()
    marker = b"ArcPdfNative;abi=1.1;backend=linked;pdfium=chromium/8044;v8=off;xfa=off;system-fonts=off"
    require(marker in data and audit["sourceCommit"].encode("ascii") in data,
            "PDF ABI output is not the source-bound admitted production build")
    exports = {"arc_pdf_" + name for name in
               ("get_abi_version", "get_build_info", "get_last_error", "open", "page_info", "text", "render", "close")}
    require(set(producer.pe(data)["exports"]) == exports, "PDF ABI export set differs from the functional contract")
    runtime_profile = profile()
    owned_recipe = pdfium_owned_recipe(producer, runtime_profile, pdfium_directory, native_prefix)
    crt = producer.vc_runtime(runtime_profile["platformRuntime"]["distributionIdentity"]["directoryVersion"])
    available = {file.name.lower(): file for file in crt.glob("*.dll")}
    available.update({"arcpdfnative.dll": owned, "pdfium.dll": pdfium_directory / "pdfium/bin/pdfium.dll"})
    pending, selected, signatures = ["arcpdfnative.dll"], {}, {}
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        require(name in available, "Missing PDF runtime dependency: " + name)
        original = available[name]
        if original.parent == crt:
            signatures[name] = approve_runtime(original, runtime_profile)
        details = producer.pe(original.read_bytes())
        selected[name] = {"name": original.name, "sha256": producer.digest(original), **details}
        pending.extend(dependency for dependency in details["imports"] if not producer.system_dependency(dependency))
    require(selected["pdfium.dll"]["sha256"] == value["files"]["bin/pdfium.dll"], "Unadmitted PDFium runtime DLL")
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix=".pdf-composition-") as temporary:
        staging = Path(temporary) / "input"
        runtime = staging / "runtimes/win-x64/native"
        runtime.mkdir(parents=True)
        for name in selected:
            shutil.copyfile(available[name], runtime / available[name].name)
        manifest = {"schemaVersion": 1, "sourceCommit": audit["sourceCommit"], "rid": "win-x64",
                    "library": "ArcPdfNative", "abi": {"major": 1, "minor": 1},
                    "files": sorted(selected.values(), key=lambda file: file["name"])}
        (runtime / "ArcPdfNative.manifest.json").write_bytes(canonical(manifest))
        for original, name in (
                (native_prefix / "lib/ArcPdfNative.lib", "sdk/win-x64/lib/ArcPdfNative.lib"),
                (ROOT / "native/arcpdf-abi/include/arc/arc_pdf_abi.h", "include/arc/arc_pdf_abi.h"),
                (ROOT / "native/shared/include/arc/arc_native_abi.h", "include/arc/arc_native_abi.h"),
                (ROOT / "eng/native/vcpkg/pdfium-build.v1.json", "provenance/pdfium-build.v1.json"),
                (ROOT / value["sbom"]["path"], "provenance/pdfium-sbom.v1.json"),
                (pdfium_directory / "pdfium-build-receipt.json", "provenance/pdfium-build-receipt.json"),
                (pdfium_directory / "pdfium-attestation.json", "provenance/pdfium-attestation.json")):
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        for name in value["legalFiles"]:
            target = staging / "licenses/pdfium" / Path(name).name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        cache = pdfium_directory / "legal-cache"
        for legal in runtime_profile["platformRuntime"]["legal"]:
            original = pdfium_download({"url": legal["url"], "sha256": legal["sourceSha256"],
                                        "maximumBytes": 8 * 1024 * 1024}, cache / legal["cacheName"])
            target = staging / legal["output"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
        (staging / "NOTICE.txt").write_bytes((
            "ArcForges PDF ABI: AGPL-3.0-only. PDFium chromium/8044 no-V8/no-XFA producer admission.\n"
            "All 15 complete PDFium/component legal texts are retained under licenses/pdfium.\n"
            "This software uses FreeType. Full attribution, FTL terms and LLVM exceptions are preserved.\n"
            "Microsoft CRT files are unmodified, hash-pinned and Authenticode-verified under the retained original grant texts.\n"
            "This source-bound composition input is not a signed/published runtime package. NAT.25 owns that delivery.\n"
        ).encode("utf-8"))
        verify_pdfium_staging(staging, selected, value, receipt, runtime_profile["platformRuntime"]["legal"])
        result = {"schemaVersion": 1, "sourceCommit": audit["sourceCommit"], "rid": "win-x64",
                  "kind": "pdfium-production-composition-input", "profile": value["id"],
                  "build": build_identity.build_identity(ROOT), "admission": receipt,
                  "ownedProducerRecipe": owned_recipe,
                  "compilerRuntimeAdmission": value["compilerRuntime"],
                  "compilerRuntimeSignatures": signatures,
                  "files": [{"path": file.relative_to(staging).as_posix(), "sha256": producer.digest(file)}
                            for file in sorted(staging.rglob("*")) if file.is_file()]}
        (staging / "pdfium-production-input.json").write_bytes(canonical(result))
        staging.replace(directory)
    return result


def _pdf_portable_recipe(build_directory, native_prefix, sdk_prefix, rid, identity, root, cancelled):
    import build_identity
    if cancelled and cancelled(): raise InterruptedError("PDF producer admission cancelled")
    build_directory, native_prefix, sdk_prefix = map(lambda path: Path(path).resolve(strict=True),
                                                    (build_directory, native_prefix, sdk_prefix))
    profile_path = "eng/provenance/artifact-profiles/pdf-runtime-producer-v1.json"
    profile_raw = provenance.read(root, profile_path)
    value = provenance.document(profile_raw)
    recipe = value["rids"][rid]
    cache_path = build_directory / "CMakeCache.txt"
    require(cache_path.is_file() and not cache_path.is_symlink() and cache_path.stat().st_size <= 1024 * 1024,
            "Missing or unbounded actual PDF producer cache")
    cache = {}
    for line in cache_path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith(("#", "//")) or "=" not in line: continue
        key, content = line.split("=", 1)
        name = key.split(":", 1)[0]
        require(name not in cache, "Ambiguous actual PDF producer cache key")
        cache[name] = content
    require(Path(cache["CMAKE_HOME_DIRECTORY"]).resolve(strict=True) == root.resolve(strict=True)
            and Path(cache["CMAKE_INSTALL_PREFIX"]).resolve(strict=True) == native_prefix
            and Path(cache["PDFium_DIR"]).resolve(strict=True) == sdk_prefix,
            "PDF compiler cache refers to a foreign source/install/SDK tree")
    engine = sdk_prefix / ("bin/pdfium.dll" if rid.startswith("win-") else "lib/libpdfium" + (".so" if rid.startswith("linux-") else ".dylib"))
    require(Path(cache["PDFium_LIBRARY"]).resolve(strict=True) == engine.resolve(strict=True)
            and Path(cache["PDFium_INCLUDE_DIR"]).resolve(strict=True) == (sdk_prefix / "include").resolve(strict=True),
            "PDF producer selected a foreign installed engine/header dependency")
    if rid.startswith("win-"):
        require(Path(cache["PDFium_IMPLIB"]).resolve(strict=True) == (sdk_prefix / "lib/pdfium.dll.lib").resolve(strict=True),
                "PDF producer selected a foreign engine import library")
    for key, expected in {"VCPKG_TARGET_TRIPLET": recipe["triplet"], "CMAKE_BUILD_TYPE": "Release",
                          "ARCFORGES_NATIVE_PROFILE": "shim-static", "ARCFORGES_NATIVE_FAMILIES": "Pdf",
                          "ARCFORGES_PDFIUM": "ON"}.items():
        require(cache.get(key) == expected, "PDF producer did not use its closed recipe: " + key)
    tools = {}
    for name, key in (("cmake", "CMAKE_COMMAND"), ("ninja", "CMAKE_MAKE_PROGRAM")):
        if cancelled and cancelled(): raise InterruptedError("PDF producer admission cancelled")
        program = Path(cache[key]).resolve(strict=True)
        require(program.is_file() and program.stat().st_size <= 256 * 1024 * 1024,
                "Invalid PDF producer tool")
        before = digest_file(program)
        # Probe only the actual retained build tool; no shell or tool installation is involved.
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen([str(program), "--version"], stdout=output, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 20
            try:
                while process.poll() is None:
                    if cancelled and cancelled(): raise InterruptedError("PDF tool probe cancelled")
                    require(time.monotonic() < deadline and output.tell() <= 8192, "Unbounded PDF tool probe")
                    time.sleep(0.02)
                require(process.returncode == 0, "PDF actual tool version probe failed")
                output.seek(0); text = output.read(8193)
                require(len(text) <= 8192, "Unbounded PDF tool version output")
            finally:
                if process.poll() is None: process.kill()
                process.wait(timeout=5)
        text = text.decode("utf-8", errors="strict").strip()
        observed = text.splitlines()[0]
        if name == "cmake": observed = observed.removeprefix("cmake version ")
        require(observed == recipe["buildTools"][name] and digest_file(program) == before,
                "PDF actual build tool version/bytes differ")
        tools[name] = {"name": name + (".exe" if rid.startswith("win-") else ""),
                       "version": observed, "sha256": before}
    compilers = {}
    for language in ("C", "CXX"):
        if cancelled and cancelled(): raise InterruptedError("PDF compiler admission cancelled")
        compiler = Path(cache["CMAKE_" + language + "_COMPILER"]).resolve(strict=True)
        require(compiler.is_file() and compiler.stat().st_size <= 256 * 1024 * 1024, "Invalid PDF actual compiler")
        if rid.startswith("win-"):
            target = "x64" if rid.endswith("x64") else "arm64"
            suffix = "/VC/Tools/MSVC/" + recipe["compiler"]["toolset"] + "/bin/Hostx64/" + target + "/cl.exe"
            require(compiler.as_posix().casefold().endswith(suffix.casefold()), "Unadmitted PDF MSVC target/toolset")
        declarations = list((build_directory / "CMakeFiles").glob("*/CMake" + language + "Compiler.cmake"))
        require(len(declarations) == 1 and declarations[0].stat().st_size <= 65536 and not declarations[0].is_symlink(),
                "Missing or unbounded actual PDF compiler declaration")
        text = declarations[0].read_text(encoding="utf-8")
        family = re.findall(r'set\(CMAKE_' + language + r'_COMPILER_ID "([^"]+)"\)', text)
        version = re.findall(r'set\(CMAKE_' + language + r'_COMPILER_VERSION "([^"]+)"\)', text)
        require(family == [recipe["compiler"]["family"]] and len(version) == 1, "Unadmitted PDF compiler family")
        compilers[language] = {"name": compiler.name, "family": family[0], "version": version[0],
                               "sha256": digest_file(compiler), "declarationSha256": digest_file(declarations[0])}
    tools["compilers"] = compilers
    generated = build_directory / "native/identity/arc_build_identity.hpp"
    require(generated.is_file() and not generated.is_symlink() and generated.stat().st_size <= 16384
            and build_identity.native_suffix(identity) in generated.read_text(encoding="utf-8"),
            "PDF producer generated identity differs from actual clean source")
    return {"producerProfileSha256": sha(profile_raw, "lf"), "cacheSha256": digest_file(cache_path),
            "configuration": "Release", "nativeProfile": "shim-static", "nativeFamilies": "Pdf",
            "triplet": recipe["triplet"], "pdfium": "chromium/8044", "tools": tools,
            "generatedIdentitySha256": digest_file(generated)}


def stage_portable_pdfium_input(directory, pdfium_directory, native_prefix, build_directory, rid,
                                compiler_runtime=None, legal_cache=None, root=ROOT, cancelled=None):
    """Seal a real owned PDF producer offline; no unavailable RID becomes a successful artifact."""
    if cancelled and cancelled(): raise InterruptedError("PDF runtime sealing cancelled")
    import build_identity
    import native as producer
    import native_binary
    check = producer._progress(cancelled)
    check()
    require(rid in PORTABLE_PDFIUM_ARCHIVES, "Historical Windows x64 input uses its preserved producer")
    sdk = portable_pdfium_profile(rid, root)
    pdfium_directory, native_prefix = Path(pdfium_directory), Path(native_prefix)
    verify_pdfium_prefix(pdfium_directory / "pdfium", sdk)
    admission = verify_pdfium_admission_input(pdfium_directory, sdk)
    audit = provenance.run(root, "DesktopPlatform")
    require(not audit["dirty"], "PDF producer requires clean admitted source")
    identity = build_identity.build_identity(root)
    recipe = _pdf_portable_recipe(build_directory, native_prefix, pdfium_directory / "pdfium", rid,
                                  identity, root, lambda: (check(), False)[1])
    own_profile = provenance.document(provenance.read(root, "eng/provenance/artifact-profiles/pdf-runtime-producer-v1.json"))
    policy, _ = _pdf_system_policy(rid, root)
    owned_name = own_profile["rids"][rid]["library"]
    engine_name = "pdfium.dll" if rid.startswith("win-") else "libpdfium" + (".so" if rid.startswith("linux-") else ".dylib")
    originals = {owned_name: native_prefix / "native" / owned_name,
                 engine_name: pdfium_directory / "pdfium" / ("bin" if rid.startswith("win-") else "lib") / engine_name}
    signatures = {}
    runtime_admission = None
    if rid.startswith("win-"):
        require(compiler_runtime is not None and legal_cache is not None, "Explicit reviewed native CRT/grant inputs are required")
        runtime_admission = own_profile["compilerRuntime"][rid]
        for name in runtime_admission["files"]:
            path = Path(compiler_runtime) / name
            require(path.is_file() and not path.is_symlink(), "Missing actual PDF native CRT")
            expected = runtime_admission["files"][name]
            actual = signed_runtime(path)
            require(actual == {**expected, "signature": "valid"}, "PDF native CRT signature/bytes/version differ")
            originals[path.name] = path
    rows, chosen, pending = [], {}, [owned_name]
    available = {(name.casefold() if rid.startswith("win-") else name): path for name, path in originals.items()}
    allowed = {name.casefold() if rid.startswith("win-") else name for name in policy["systemImports"]}
    while pending:
        check()
        name = pending.pop(); key = name.casefold() if rid.startswith("win-") else name
        if key in chosen: continue
        require(key in available, "Missing owned/transitive PDF runtime input: " + name)
        path = available[key]
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 256 * 1024 * 1024,
                "Missing, linked or unbounded PDF runtime binary")
        details = native_binary.inspect(path, rid)
        chosen[key] = path
        row = {"name": path.name, "sha256": digest_file(path), **details.as_manifest()}; rows.append(row)
        if runtime_admission and key in runtime_admission["files"]:
            signatures[key] = {**runtime_admission["files"][key], "signature": "valid"}
        for dependency in details.imports:
            bundled = dependency.removeprefix("@loader_path/").removeprefix("@rpath/")
            target = bundled.casefold() if rid.startswith("win-") else bundled
            if target in available: pending.append(bundled)
            else:
                is_api = rid.startswith("win-") and dependency.lower().endswith(".dll") and any(
                    dependency.lower().startswith(prefix) for prefix in policy.get("apiSetPrefixes", []))
                require(target in allowed or is_api, "Unadmitted PDF native dependency: " + dependency)
    require(engine_name.casefold() in chosen if rid.startswith("win-") else engine_name in chosen,
            "The actual PDF engine is missing from the produced closure")
    destination = Path(directory).absolute(); destination.parent.mkdir(parents=True, exist_ok=True)
    with producer._exclusive_stage(destination, check=check):
        require(not destination.exists(), "PDF sealed input exists; never overwrite candidate bytes")
        with tempfile.TemporaryDirectory(dir=destination.parent, prefix=".portable-pdf-") as temporary:
            staging = Path(temporary) / "input"; runtime = staging / f"runtimes/{rid}/native"; runtime.mkdir(parents=True)
            def copy(original, name, expected=None):
                check()
                original = Path(original); require(original.is_file() and not original.is_symlink(), "Missing/linked PDF producer material")
                target = staging / name; target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    checksum, size = producer._bounded_file(original, check, output)
                require(size <= 256 * 1024 * 1024 and (expected is None or checksum == expected), "PDF producer material changed/exceeded its bound")
            for row in rows: copy(chosen[row["name"].casefold() if rid.startswith("win-") else row["name"]],
                                  f"runtimes/{rid}/native/" + row["name"], row["sha256"])
            manifest = {"schemaVersion": 1, "sourceCommit": audit["sourceCommit"], "rid": rid, "library": "ArcPdfNative",
                        "abi": {"major": 1, "minor": 1}, "files": sorted(rows, key=lambda row: row["name"])}
            (runtime / "ArcPdfNative.manifest.json").write_bytes(canonical(manifest))
            for header in ("arc_pdf_abi.h", "arc_native_abi.h"):
                original = root / ("native/arcpdf-abi/include/arc/" + header if header == "arc_pdf_abi.h" else "native/shared/include/arc/" + header)
                copy(original, "include/arc/" + header, digest_file(original))
            for original, name, expected in [(root / own_profile["rids"][rid]["sdkProfilePath"], "provenance/pdfium-build.v1.json", None),
                    (root / sdk["sbom"]["path"], "provenance/pdfium-sbom.v1.json", None),
                    (pdfium_directory / "pdfium-build-receipt.json", "provenance/pdfium-build-receipt.json", sha(canonical(admission))),
                    (pdfium_directory / "pdfium-attestation.json", "provenance/pdfium-attestation.json", sdk["attestation"]["sha256"])]:
                copy(original, name, expected)
            for original, name, expected in _pdf_sdk_legal_sources(pdfium_directory, sdk): copy(original, name, expected)
            if runtime_admission:
                for legal in own_profile["runtimeLegal"]:
                    copy(Path(legal_cache) / legal["cacheName"], legal["output"], legal["sourceSha256"])
            if rid.startswith("win-"): copy(native_prefix / "lib/ArcPdfNative.lib", f"sdk/{rid}/lib/ArcPdfNative.lib")
            (staging / "NOTICE.txt").write_text("ArcPdfNative AGPL-3.0-only; full pinned PDFium legal closure retained. "
                "Native CRT original grants retained when bundled. This unsigned sealed input is not publisher authorization.\n", encoding="utf-8")
            result = {"schemaVersion": 1, "sourceCommit": audit["sourceCommit"], "rid": rid,
                      "kind": "pdfium-production-composition-input", "profile": sdk["id"], "build": identity,
                      "admission": admission, "ownedProducerRecipe": recipe, "compilerRuntimeAdmission": runtime_admission,
                      "compilerRuntimeSignatures": signatures, "files": [{"path": name, "sha256": checksum}
                          for name, checksum in sorted(producer._inventory(staging, check=check).items())]}
            (staging / "pdfium-production-input.json").write_bytes(canonical(result))
            verify_pdf_runtime_input(staging, audit["sourceCommit"], root, cancelled=lambda: (check(), False)[1])
            check()
            producer._flush_tree(staging, check=check)
            staging.replace(destination)
            producer._flush_directory(destination.parent)
    return result


def verify_pdf_runtime_input(directory: Path, source_commit: str, root: Path = ROOT, cancelled=None) -> dict:
    """Revalidate the complete sealed PDF handoff. This receipt is not publisher authentication."""
    sys.path.insert(0, str(root / "eng/packaging"))
    import native as producer
    check = producer._progress(cancelled)
    check()
    import native_binary
    import build_identity

    value = producer._read_document(directory / "pdfium-production-input.json")
    require(set(value) == {"schemaVersion", "sourceCommit", "rid", "kind", "profile", "build", "admission",
                           "ownedProducerRecipe", "compilerRuntimeAdmission", "compilerRuntimeSignatures", "files"},
            "Unknown or missing PDF composition fields")
    rid = value["rid"]
    require(rid in producer.RIDS and value["schemaVersion"] == 1 and value["sourceCommit"] == source_commit
            and value["kind"] == "pdfium-production-composition-input", "PDF composition identity mismatch")
    build_identity.validate_identity(value["build"], source_commit)
    require(not value["build"]["dirty"], "Dirty PDF producer is not admitted")
    sdk = portable_pdfium_profile(rid, root)
    require(value["profile"] == sdk["id"], "PDF composition upstream profile mismatch")
    receipt = {"profile": sdk["id"], "archiveSha256": sdk["archive"]["sha256"],
               "attestationSha256": sdk["attestation"]["sha256"], "producerInvocation": sdk["attestation"]["invocation"],
               "recipeCommit": sdk["attestation"]["recipeCommit"], "rid": rid, "version": sdk["version"],
               "cryptographicVerification": "GitHub CLI Sigstore/SLSA verification passed", "sbomSha256": sdk["sbom"]["sha256"]}
    require(value["admission"] == receipt, "PDF composition admission receipt mismatch")
    require(isinstance(value["files"], list) and 0 < len(value["files"]) <= 512, "Unbounded PDF input inventory")
    files, aliases = {}, set()
    for row in value["files"]:
        check()
        require(set(row) == {"path", "sha256"}, "Unknown PDF inventory fields")
        name = producer._relative(row["path"])
        provenance.digest(row["sha256"])
        require(name.casefold() not in aliases and name != "pdfium-production-input.json", "Duplicate PDF input path")
        aliases.add(name.casefold())
        files[name] = row["sha256"]
    actual = producer._inventory(directory, check=check)
    actual.pop("pdfium-production-input.json")
    require(actual == files, "Changed, missing or unexpected sealed PDF input bytes")
    for field, expected in (("pdfium-attestation.json", sdk["attestation"]["sha256"]),
                            ("pdfium-sbom.v1.json", sdk["sbom"]["sha256"]),
                            ("pdfium-build.v1.json", sha(canonical(sdk), "lf"))):
        path = directory / "provenance" / field
        require(path.is_file() and sha(path.read_bytes(), "lf" if field != "pdfium-attestation.json" else "raw") == expected,
                "PDF sealed upstream evidence differs: " + field)
    require((directory / "provenance/pdfium-build-receipt.json").read_bytes() == canonical(receipt),
            "PDF copied upstream receipt differs")
    for name, expected in sdk["legalFiles"].items():
        require(files.get("licenses/pdfium/" + Path(name).name) == expected, "PDF legal inventory differs from admission")
    for header in ("arc_pdf_abi.h", "arc_native_abi.h"):
        path = "native/arcpdf-abi/include/arc/" + header if header == "arc_pdf_abi.h" else "native/shared/include/arc/" + header
        require(files.get("include/arc/" + header) == sha(provenance.read(root, path)), "PDF owned header differs from source")
    manifest = producer._read_document(directory / f"runtimes/{rid}/native/ArcPdfNative.manifest.json", 1024 * 1024)
    require(set(manifest) == {"schemaVersion", "sourceCommit", "rid", "library", "abi", "files"}
            and manifest["schemaVersion"] == 1 and manifest["sourceCommit"] == source_commit and manifest["rid"] == rid
            and manifest["library"] == "ArcPdfNative" and manifest["abi"] == {"major": 1, "minor": 1},
            "PDF runtime manifest identity differs")
    require(isinstance(manifest["files"], list) and 0 < len(manifest["files"]) <= 64, "Unbounded PDF binary closure")
    names, binaries = set(), []
    expected_exports = tuple(sorted("arc_pdf_" + name for name in
        ("get_abi_version", "get_build_info", "get_last_error", "open", "page_info", "text", "render", "close")))
    owned_name = "ArcPdfNative.dll" if rid.startswith("win-") else "libArcPdfNative" + (".so" if rid.startswith("linux-") else ".dylib")
    engine_name = "pdfium.dll" if rid.startswith("win-") else "libpdfium" + (".so" if rid.startswith("linux-") else ".dylib")
    for row in manifest["files"]:
        check()
        name = producer._relative(row["name"])
        require("/" not in name and name.casefold() not in names, "Unsafe or repeated PDF binary filename")
        names.add(name.casefold())
        path = directory / f"runtimes/{rid}/native" / name
        require(files.get(path.relative_to(directory).as_posix()) == row["sha256"], "PDF binary differs from sealed inventory")
        inspected = native_binary.inspect(path, rid)
        details = inspected.as_manifest()
        require((sorted(name.lower() for name in inspected.imports) if rid.startswith("win-") else list(inspected.imports))
                == (sorted(name.lower() for name in row["imports"]) if rid.startswith("win-") else row["imports"])
                and (sorted((*inspected.exports, *inspected.data_exports, *inspected.forwarded_exports))
                     if rid.startswith("win-") and "format" not in row else list(inspected.exports)) == row["exports"]
                and row["machine"] in (details["machine"], "x64" if rid.endswith("x64") else "arm64"),
                "PDF binary metadata differs from actual inspection")
        if name == owned_name:
            require(inspected.exports == expected_exports and not inspected.forwarded_exports and not inspected.data_exports
                    and not inspected.unnamed_exports
                    and set(inspected.absolute_exports).issubset({"ARCFORGES_1.0"} if rid.startswith("linux-") else set()),
                    "PDF owned callable ABI differs")
            content = path.read_bytes()
            require(b"ArcPdfNative;abi=1.1;backend=linked;pdfium=chromium/8044;v8=off;xfa=off;system-fonts=off" in content
                    and build_identity.native_suffix(value["build"]).encode("ascii") in content, "PDF binary build/source marker differs")
        if name == engine_name:
            upstream = "bin/pdfium.dll" if rid.startswith("win-") else "lib/" + engine_name
            require(row["sha256"] == sdk["files"][upstream], "PDF engine differs from actual pinned SDK")
        binaries.append({"name": name, "sha256": row["sha256"], **details})
    require(owned_name.casefold() in names and engine_name.casefold() in names, "PDF closure omits the actual parser/engine")
    runtime_paths = {f"runtimes/{rid}/native/" + row["name"] for row in binaries}
    require({name for name in files if name.startswith("runtimes/")}
            == runtime_paths | {f"runtimes/{rid}/native/ArcPdfNative.manifest.json"}, "Unexpected PDF runtime material")
    if rid == "win-x64":
        retained = profile(root)
        require(value["compilerRuntimeAdmission"] == sdk["compilerRuntime"], "PDF compiler runtime authority differs")
        recipe = value["ownedProducerRecipe"]
        provenance.fields(recipe, "buildTools cacheSha256 configuration nativeProfile triplet pdfium")
        provenance.digest(recipe["cacheSha256"])
        require(recipe["buildTools"] == retained["buildTools"] and recipe["configuration"] == "Release"
                and recipe["nativeProfile"] == "shim-static" and recipe["triplet"] == "x64-windows-static-md"
                and recipe["pdfium"] == "chromium/8044", "PDF owned tool/recipe admission differs")
        signatures = value["compilerRuntimeSignatures"]
        used = {row["name"].lower() for row in binaries if row["name"].lower() in retained["platformRuntime"]["files"]}
        require(set(signatures) == used, "PDF CRT signature closure differs")
        for name in used:
            require(signatures[name] == {**retained["platformRuntime"]["files"][name], "signature": "valid"},
                    "PDF CRT bytes/version/publisher admission differs")
            require(next(row["sha256"] for row in binaries if row["name"].lower() == name)
                    == retained["platformRuntime"]["files"][name]["sha256"], "PDF CRT actual byte hash differs")
        for legal in retained["platformRuntime"]["legal"]:
            require(files.get(legal["output"]) == legal["sourceSha256"], "PDF CRT original redistribution grant differs")
    else:
        _pdf_owned_portable_admission(value, binaries, files, root)
    value["inspectedBinaries"] = sorted(binaries, key=lambda row: row["name"])
    return value



def _pdf_owned_portable_admission(value, binaries, files, root):
    """The owned compiler recipe and CRT are separate from the upstream SDK attestation."""
    rid = value["rid"]
    path = "eng/provenance/artifact-profiles/pdf-runtime-producer-v1.json"
    raw = provenance.read(root, path)
    profile_value = provenance.document(raw)
    require(profile_value["schemaVersion"] == 1 and profile_value["id"] == "pdf-runtime-producer-v1"
            and profile_value["family"] == "arc_pdf" and set(profile_value["rids"]) == {
                "win-x64", "win-arm64", "linux-x64", "linux-arm64", "osx-x64", "osx-arm64"},
            "Unadmitted owned PDF producer profile")
    recipe = value["ownedProducerRecipe"]
    provenance.fields(recipe, "producerProfileSha256 cacheSha256 configuration nativeProfile nativeFamilies triplet pdfium tools generatedIdentitySha256")
    require(recipe["producerProfileSha256"] == sha(raw, "lf"), "PDF owned producer authority differs")
    expected = profile_value["rids"][rid]
    for name in ("configuration", "nativeProfile", "nativeFamilies", "triplet", "pdfium"):
        require(recipe[name] == expected[name], "PDF owned recipe differs: " + name)
    for name in ("cacheSha256", "generatedIdentitySha256"): provenance.digest(recipe[name])
    tools = recipe["tools"]
    provenance.fields(tools, "cmake ninja compilers")
    for name in ("cmake", "ninja"):
        provenance.fields(tools[name], "name version sha256")
        require(tools[name]["version"] == expected["buildTools"][name]
                and isinstance(tools[name]["name"], str) and tools[name]["name"] in (name, name + ".exe"),
                "PDF actual tool identity differs")
        provenance.digest(tools[name]["sha256"])
    require(set(tools["compilers"]) == {"C", "CXX"}, "PDF compiler closure differs")
    for compiler in tools["compilers"].values():
        provenance.fields(compiler, "name family version sha256 declarationSha256")
        require(compiler["family"] == expected["compiler"]["family"] and isinstance(compiler["version"], str)
                and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", compiler["version"]), "PDF compiler family/version differs")
        require(isinstance(compiler["name"], str) and "/" not in compiler["name"] and "\\" not in compiler["name"],
                "Invalid PDF compiler identity")
        provenance.digest(compiler["sha256"]); provenance.digest(compiler["declarationSha256"])
    signatures = value["compilerRuntimeSignatures"]
    if rid.startswith("win-"):
        runtime = profile_value["compilerRuntime"][rid]
        require(value["compilerRuntimeAdmission"] == runtime, "PDF exact native CRT authority differs")
        supplied = {row["name"].lower(): row for row in binaries if row["name"].lower() in runtime["files"]}
        require(set(signatures) == set(supplied), "PDF actual CRT signature closure differs")
        for name, row in supplied.items():
            require(row["sha256"] == runtime["files"][name]["sha256"]
                    and signatures[name] == {**runtime["files"][name], "signature": "valid"},
                    "PDF exact CRT bytes/version/publisher differ")
        for legal in profile_value["runtimeLegal"]:
            require(files.get(legal["output"]) == legal["sourceSha256"], "PDF original CRT redistribution grant differs")
    else:
        require(value["compilerRuntimeAdmission"] is None and signatures == {},
                "Portable system runtime cannot invent a bundled Windows CRT admission")
    return profile_value


def _pdf_system_policy(rid, root):
    """Return exact concrete OS imports; legacy Windows admission is preserved without wildcard runtime trust."""
    path = "eng/native/vcpkg/system-dependencies.v2.json"
    if (root / path).is_file():
        value = provenance.document(provenance.read(root, path))
        require(value["schemaVersion"] == 2 and set(value["rids"]) == {
            "win-x64", "win-arm64", "linux-x64", "linux-arm64", "osx-x64", "osx-arm64"}, "Unadmitted native system policy")
        return value["rids"][rid], sha(provenance.read(root, path), "lf")
    require(rid == "win-x64", "Portable PDF production requires the delivered NAT22 system policy")
    path = "eng/native/vcpkg/system-dependencies.v1.json"
    value = provenance.document(provenance.read(root, path))
    return {"systemImports": value["windowsDlls"], "apiSetPrefixes": value["windowsApiSetPrefixes"]}, sha(provenance.read(root, path), "lf")


def _pdf_closed_imports(rows, rid, policy):
    case = (lambda name: name.lower()) if rid.startswith("win-") else (lambda name: name)
    names = {case(row["name"]) for row in rows}
    allowed = {case(name) for name in policy["systemImports"]}
    concrete = set()
    for row in rows:
        require(not row["runpaths"] or all(path in ("$ORIGIN", "@loader_path") for path in row["runpaths"]),
                "PDF native search path escapes its bundled closure")
        for dependency in row["imports"]:
            bundled = dependency.removeprefix("@loader_path/").removeprefix("@rpath/")
            if case(bundled) in names:
                require("/" not in bundled and "\\" not in bundled, "Escaped PDF dependency path")
                continue
            key = case(dependency)
            require(key in allowed or (rid.startswith("win-") and any(key.startswith(prefix) and key.endswith(".dll") for prefix in policy.get("apiSetPrefixes", []))),
                    "Unknown or escaped PDF system import: " + dependency)
            concrete.add(key)
    return sorted(concrete)


def stage_pdf_runtime(destination: Path, rid: str, sealed_input: Path, root: Path = ROOT, cancelled=None) -> dict:
    """Package a verified actual sealed input. No binary is built, invented, signed or downloaded here."""
    sys.path.insert(0, str(root / "eng/packaging"))
    import native as producer
    check = producer._progress(cancelled)
    check()
    destination = Path(destination).absolute()
    require(rid in producer.RIDS, "Unadmitted PDF runtime RID")
    require(not destination.exists(), "PDF package candidate exists; preserve tested bytes")
    source = producer._read_document(sealed_input / "pdfium-production-input.json")["sourceCommit"]
    handoff = verify_pdf_runtime_input(sealed_input, source, root, cancelled=lambda: (check(), False)[1])
    require(handoff["rid"] == rid, "PDF input has a different RID")
    import build_identity
    require(source == build_identity.git(root, "rev-parse", "HEAD"), "PDF input must match the actual packaging source cohort")
    policy, system_hash = _pdf_system_policy(rid, root)
    imports = _pdf_closed_imports(handoff["inspectedBinaries"], rid, policy)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with producer._exclusive_stage(destination, check=check):
        require(not destination.exists(), "PDF destination was concurrently published")
        with tempfile.TemporaryDirectory(prefix=".pdf-runtime-", dir=destination.parent) as temporary:
            staging = Path(temporary) / "stage"
            identifier = "ArcForges.Native.Pdf.Runtime." + rid
            package = staging / identifier
            before = producer._inventory(sealed_input, check=check)
            producer._copy_inventory(sealed_input, package, before, check)
            require(producer._inventory(package, check=check) == before, "PDF sealed bytes changed during package handoff")
            copied = verify_pdf_runtime_input(package, source, root, cancelled=lambda: (check(), False)[1])
            require(copied["inspectedBinaries"] == handoff["inspectedBinaries"], "PDF copied metadata changed")
            _prepare_pdf_runtime(package, rid, source, handoff, imports, system_hash, root)
            artifact = {"schemaVersion": 1, "sourceCommit": source, "rid": rid, "build": handoff["build"],
                        "packages": [{"id": identifier, "files": [{"path": path, "sha256": checksum}
                                     for path, checksum in sorted(producer._inventory(package, check=check).items())]}]}
            (staging / "native-artifact.json").write_bytes(canonical(artifact))
            verify_pdf_runtime_stage(staging, source, root, cancelled=lambda: (check(), False)[1])
            check()
            producer._flush_tree(staging, check=check)
            check()
            staging.replace(destination)
            producer._flush_directory(destination.parent)
    return artifact


def _prepare_pdf_runtime(package, rid, source, handoff, imports, system_hash, root):
    identifier = "ArcForges.Native.Pdf.Runtime." + rid
    runtime = package / f"runtimes/{rid}/native"
    manifest = {"schemaVersion": 1, "sourceCommit": source, "rid": rid, "library": "ArcPdfNative",
                "abi": {"major": 1, "minor": 1}, "files": handoff["inspectedBinaries"]}
    # Keep the original sealed manifest/evidence unchanged; deployed metadata is separately cross-bound.
    original = runtime / "ArcPdfNative.manifest.json"
    shutil.copyfile(original, package / "provenance/sealed-runtime-manifest.json")
    original.write_bytes(canonical(manifest))
    (package / "native-manifest.json").write_bytes(canonical(manifest))
    runtime_profile = {"schemaVersion": 1, "library": "ArcPdfNative", "rid": rid,
                       "producerProfileSha256": sha(canonical(portable_pdfium_profile(rid, root)), "lf"),
                       "systemPolicySha256": system_hash, "systemImports": imports}
    (runtime / "ArcPdfNative.profile.json").write_bytes(canonical(runtime_profile))
    sbom = {"schemaVersion": 1, "sourceCommit": source, "binaryFiles": manifest["files"],
            "buildDependencies": [{"name": "pdfium", "triplet": rid, "version": handoff["admission"]["version"],
                                   "license": "licenses/pdfium/pdfium.txt", "sbom": "provenance/pdfium-sbom.v1.json"}],
            "ownedProducerRecipe": handoff["ownedProducerRecipe"], "upstreamAdmission": handoff["admission"]}
    (package / "sbom.json").write_bytes(canonical(sbom))
    (package / "NOTICE.md").write_bytes((package / "NOTICE.txt").read_bytes())
    target = package / "buildTransitive" / (identifier + ".targets")
    target.parent.mkdir()
    target.write_bytes(_pdf_runtime_targets(identifier, rid))
    receipt = {"schemaVersion": 1, "sourceCommit": source, "rid": rid, "library": "ArcPdfNative",
               "sealedInputSha256": digest_file(package / "pdfium-production-input.json"),
               "sourceManifestSha256": digest_file(package / "provenance/sealed-runtime-manifest.json"),
               "deployedManifestSha256": digest_file(package / "native-manifest.json"),
               "runtimeProfileSha256": digest_file(runtime / "ArcPdfNative.profile.json"),
               "systemPolicySha256": system_hash}
    (package / "pdf-runtime-production.json").write_bytes(canonical(receipt))


def digest_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_pdf_runtime_stage(directory: Path, source_commit: str, root: Path = ROOT, cancelled=None) -> dict:
    sys.path.insert(0, str(root / "eng/packaging"))
    import native as producer
    check = producer._progress(cancelled)
    check()
    import build_identity
    artifact = producer._read_document(directory / "native-artifact.json")
    require(set(artifact) == {"schemaVersion", "sourceCommit", "rid", "build", "packages"}
            and artifact["schemaVersion"] == 1 and artifact["sourceCommit"] == source_commit and artifact["rid"] in producer.RIDS,
            "PDF package artifact identity mismatch")
    build_identity.validate_identity(artifact["build"], source_commit)
    require(not artifact["build"]["dirty"], "Dirty PDF package artifact")
    identifier = "ArcForges.Native.Pdf.Runtime." + artifact["rid"]
    require(len(artifact["packages"]) == 1 and artifact["packages"][0]["id"] == identifier, "PDF artifact has a mixed package closure")
    package = directory / identifier
    rows = artifact["packages"][0]["files"]
    require(isinstance(rows, list) and 0 < len(rows) <= 1024, "PDF package file bound exceeded")
    expected = {}
    for row in rows:
        check()
        require(set(row) == {"path", "sha256"}, "PDF package file metadata differs")
        name = producer._relative(row["path"])
        provenance.digest(row["sha256"])
        require(name.casefold() not in {key.casefold() for key in expected}, "Repeated PDF package file")
        expected[name] = row["sha256"]
    require(producer._inventory(package, check=check) == expected, "PDF package file bytes/closure differ")
    verify_pdf_package({"id": identifier, "rid": artifact["rid"], "library": "ArcPdfNative"},
                       lambda name: provenance.read(package, name), set(expected), source_commit, root, cancelled=lambda: (check(), False)[1])
    require(producer._inventory(directory, check=check) == {"native-artifact.json": digest_file(directory / "native-artifact.json"),
            **{identifier + "/" + name: checksum for name, checksum in expected.items()}}, "Unexpected PDF artifact material")
    return artifact


def verify_pdf_package(entry: dict, read, names: set[str], source_commit: str, root: Path = ROOT, cancelled=None) -> dict:
    """Validate packed copied bytes by reconstructing the original bounded producer handoff."""
    sys.path.insert(0, str(root / "eng/packaging"))
    import native as producer
    check = producer._progress(cancelled)
    check()
    rid = entry["rid"]
    require(rid in producer.RIDS and entry["library"] == "ArcPdfNative"
            and entry["id"] == "ArcForges.Native.Pdf.Runtime." + rid, "PDF package coordinate mismatch")
    # The original receipt inventory reconstructs exactly the immutable input;
    # deployed manifest changes are validated separately, never silently substituted.
    value = provenance.document(read("pdfium-production-input.json"))
    require(len(value.get("files", [])) <= 512, "Unbounded original PDF package receipt")
    additions = {"provenance/sealed-runtime-manifest.json", "native-manifest.json", "sbom.json", "NOTICE.md",
                 f"runtimes/{rid}/native/ArcPdfNative.profile.json", "pdf-runtime-production.json",
                 f"buildTransitive/{entry['id']}.targets"}
    require(names == {"pdfium-production-input.json", *additions, *[producer._relative(row["path"]) for row in value["files"]]},
            "Unexpected/missing PDF package material")
    with tempfile.TemporaryDirectory(prefix="arc-pdf-verify-") as temporary:
        handoff = Path(temporary)
        (handoff / "pdfium-production-input.json").write_bytes(read("pdfium-production-input.json"))
        for row in value["files"]:
            check()
            name = producer._relative(row["path"])
            require(name in names, "Missing original PDF producer material")
            content = read("provenance/sealed-runtime-manifest.json" if name == f"runtimes/{rid}/native/ArcPdfNative.manifest.json" else name)
            require(len(content) <= 512 * 1024 * 1024 and sha(content) == row["sha256"], "Changed original PDF producer material")
            path = handoff / name
            path.parent.mkdir(parents=True, exist_ok=True)
            require(not path.exists(), "Repeated reconstructed PDF producer material")
            path.write_bytes(content)
        inspected = verify_pdf_runtime_input(handoff, source_commit, root, cancelled=lambda: (check(), False)[1])
        check()
    require(read("native-manifest.json") == read(f"runtimes/{rid}/native/ArcPdfNative.manifest.json"), "PDF deployed manifest differs")
    manifest = provenance.document(read("native-manifest.json"))
    expected_manifest = {"schemaVersion": 1, "sourceCommit": source_commit, "rid": rid, "library": "ArcPdfNative",
                         "abi": {"major": 1, "minor": 1}, "files": inspected["inspectedBinaries"]}
    require(manifest == expected_manifest, "PDF deployed inspected metadata differs")
    policy, system_hash = _pdf_system_policy(rid, root)
    profile_value = {"schemaVersion": 1, "library": "ArcPdfNative", "rid": rid,
                     "producerProfileSha256": sha(canonical(portable_pdfium_profile(rid, root)), "lf"),
                     "systemPolicySha256": system_hash,
                     "systemImports": _pdf_closed_imports(inspected["inspectedBinaries"], rid, policy)}
    profile_bytes = read(f"runtimes/{rid}/native/ArcPdfNative.profile.json")
    require(profile_bytes == canonical(profile_value), "PDF runtime policy differs from immutable producer/system admission")
    receipt = provenance.document(read("pdf-runtime-production.json"))
    require(receipt == {"schemaVersion": 1, "sourceCommit": source_commit, "rid": rid, "library": "ArcPdfNative",
                       "sealedInputSha256": sha(read("pdfium-production-input.json")),
                       "sourceManifestSha256": sha(read("provenance/sealed-runtime-manifest.json")),
                       "deployedManifestSha256": sha(read("native-manifest.json")),
                       "runtimeProfileSha256": sha(profile_bytes), "systemPolicySha256": system_hash},
            "PDF runtime production cross-binding differs")
    expected_sbom = {"schemaVersion": 1, "sourceCommit": source_commit, "binaryFiles": manifest["files"],
                    "buildDependencies": [{"name": "pdfium", "triplet": rid, "version": inspected["admission"]["version"],
                                           "license": "licenses/pdfium/pdfium.txt", "sbom": "provenance/pdfium-sbom.v1.json"}],
                    "ownedProducerRecipe": inspected["ownedProducerRecipe"], "upstreamAdmission": inspected["admission"]}
    require(read("sbom.json") == canonical(expected_sbom) and read("NOTICE.md") == read("NOTICE.txt"),
            "PDF generated SBOM/notice differs from verified producer")
    require(read(f"buildTransitive/{entry['id']}.targets") == _pdf_runtime_targets(entry['id'], rid),
            "PDF generated build target differs from owned recipe")
    return manifest


def _pdf_sdk_legal_sources(pdfium_directory, sdk):
    # SDK member paths are rooted in the authenticated acquired SDK, never repo legal files.
    import native as producer
    result, names = [], set()
    for name, expected in sdk["legalFiles"].items():
        name = producer._relative(name)
        output = "licenses/pdfium/" + Path(name).name
        require(output not in names, "Colliding PDF SDK legal members")
        names.add(output)
        result.append((Path(pdfium_directory) / "pdfium" / name, output, expected))
    return result


def _pdf_runtime_targets(identifier, rid):
    return ('<Project>\n  <!-- SPDX-License-Identifier: AGPL-3.0-only -->\n'
            '  <Target Name="Require_arc_pdf_Rid" BeforeTargets="PrepareForBuild">\n'
            f'    <Error Condition="\'$(RuntimeIdentifier)\' != \'{rid}\'" Text="{identifier} requires the exact admitted RID and matching managed package version." />\n'
            '  </Target>\n</Project>\n').encode("utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--stage", type=Path)
    mode.add_argument("--acquire-pdfium", type=Path)
    mode.add_argument("--stage-pdfium-input", type=Path)
    parser.add_argument("--pdfium-directory", type=Path, default=ROOT / "artifacts/pdfium-admission")
    parser.add_argument("--native-prefix", type=Path, default=ROOT / "artifacts/stage/native/win-x64")
    parser.add_argument("--producer-build-directory", type=Path)
    parser.add_argument("--compiler-runtime", type=Path)
    parser.add_argument("--runtime-legal-cache", type=Path)
    parser.add_argument("--pdfium-rid", choices=["win-x64", *PORTABLE_PDFIUM_ARCHIVES], default="win-x64")
    args = parser.parse_args()
    if args.acquire_pdfium:
        print(json.dumps(acquire_pdfium(args.acquire_pdfium, rid=args.pdfium_rid)))
        sys.exit(0)
    if args.stage_pdfium_input:
        if args.pdfium_rid == "win-x64":
            if args.producer_build_directory or args.compiler_runtime or args.runtime_legal_cache:
                parser.error("Historical win-x64 uses its preserved exact producer inputs")
            receipt = stage_pdfium_input(args.stage_pdfium_input, args.pdfium_directory, args.native_prefix)
        else:
            if not args.producer_build_directory:
                parser.error("Portable sealing requires the actual producer build directory")
            receipt = stage_portable_pdfium_input(args.stage_pdfium_input, args.pdfium_directory,
                args.native_prefix, args.producer_build_directory, args.pdfium_rid,
                args.compiler_runtime, args.runtime_legal_cache)
        print(json.dumps({"result": "passed", "sourceCommit": receipt["sourceCommit"], "files": len(receipt["files"])}))
        sys.exit(0)
    value = profile()
    pdfium_profile()
    results = []
    if args.stage:
        for package in value["packages"]:
            base = (args.stage / package).resolve()
            results.append(verify(package, lambda p: provenance.read(base, p),
                                  {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()}))
    print(json.dumps({"result": "passed", "components": len(value["components"]), "packages": results}))
