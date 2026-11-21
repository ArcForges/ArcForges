#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Write the native cohort's SPDX 2.3 inventory before its stage is sealed."""

import argparse
import base64
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlsplit
import uuid
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eng" / "mxc"))
from stage import LICENSE, NATIVE, PACKAGE, RELEASE, SBOM, SCHEMA, SOURCE, VERSION

OUTPUT = "sbom.spdx.json"
FRAMEWORK = "net11.0"
UNKNOWN = "NOASSERTION"
DOCUMENT = "SPDXRef-DOCUMENT"
COHORT = "SPDXRef-NativeCohort"
MXC = "SPDXRef-MxcRuntime"
UPSTREAM = "DocumentRef-OfficialMxc"
AGPL = "AGPL-3.0-only"
PACKAGE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,153}")
PACKAGE_VERSION = re.compile(r"[0-9][A-Za-z0-9.+-]{0,95}")
LICENSE_EXPRESSION = re.compile(r"[A-Za-z0-9.+() -]{1,250}")


def require(value, message):
    if not value:
        raise ValueError(message)


def read(path, maximum):
    require(path.is_file() and not path.is_symlink(), f"Missing regular input: {path.name}")
    with path.open("rb") as stream:
        payload = stream.read(maximum + 1)
    require(0 < len(payload) <= maximum, f"Input size outside bound: {path.name}")
    return payload


def unique_object(pairs):
    value = {}
    for name, item in pairs:
        require(name not in value, "Duplicate input JSON member")
        value[name] = item
    return value


def json_input(path, maximum=8 * 1024 * 1024):
    return json.loads(read(path, maximum).decode("utf-8-sig"), object_pairs_hook=unique_object)


def digest(path, maximum=512 * 1024 * 1024, algorithm="sha256"):
    require(path.is_file() and not path.is_symlink(), f"Missing regular input: {path.name}")
    digest = hashlib.new(algorithm)
    seen = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(64 * 1024), b""):
            seen += len(block)
            require(seen <= maximum, f"Artifact exceeds evidence bound: {path.name}")
            digest.update(block)
    require(seen, f"Empty artifact: {path.name}")
    return digest.hexdigest()


def sha512(value):
    require(isinstance(value, str) and len(value) <= 100, "Invalid locked package hash")
    decoded = base64.b64decode(value.removeprefix("sha512-"), validate=True)
    require(len(decoded) == 64, "Wrong locked package hash length")
    return decoded.hex()


def relation(left, kind, right):
    return {"spdxElementId": left, "relationshipType": kind, "relatedSpdxElement": right}


def package(identifier, name, version, license_declared=UNKNOWN, source=UNKNOWN):
    return {"SPDXID": identifier, "name": name, "versionInfo": version,
            "downloadLocation": source, "filesAnalyzed": False,
            "licenseDeclared": license_declared, "licenseConcluded": UNKNOWN, "copyrightText": UNKNOWN}


def checksum(algorithm, value):
    return {"algorithm": algorithm, "checksumValue": value}


def declared_license(stage, name, version):
    directory = stage / "third-party" / "packages" / name.lower() / version.lower()
    matches = list(directory.glob("*.nuspec"))
    if not matches:
        return UNKNOWN, []
    require(len(matches) == 1, f"Ambiguous staged NuGet metadata: {name}")
    xml = ElementTree.fromstring(read(matches[0], 1024 * 1024))
    metadata = xml.find("./{*}metadata")
    require(metadata is not None and (metadata.findtext("{*}id") or "").casefold() == name.casefold()
            and (metadata.findtext("{*}version") or "").casefold() == version.casefold(),
            f"Staged NuGet metadata differs from the lock: {name}")
    license_ = metadata.find("{*}license")
    text = ((license_.text or "").strip() if license_ is not None and license_.get("type") == "expression" else "")
    if not LICENSE_EXPRESSION.fullmatch(text) or "licenseref-" in text.lower():
        text = UNKNOWN
    return text, [matches[0].relative_to(stage).as_posix()]


def input_package(stage, name, version, content_hash, entries):
    declared, paths = declared_license(stage, name, version)
    identifier = "SPDXRef-NuGet-" + hashlib.sha256(f"{name.lower()}\n{version}".encode()).hexdigest()[:24]
    item = package(identifier, name, version, declared)
    item["checksums"] = [checksum("SHA512", content_hash)]
    item["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                             "referenceLocator": f"pkg:nuget/{quote(name, safe='')}@{quote(version, safe='')}"}]
    item["sourceInfo"] = "Exact NuGet package from the selected RID restore graph. Native AOT symbol retention is not asserted."
    if paths:
        item["comment"] = "Staged package metadata: " + ", ".join(paths)
    item["primaryPackagePurpose"] = "LIBRARY" if entries else "OTHER"
    return item


def restore_inputs(stage, repo, role_project, lock_name, rid):
    lock = json_input(stage / lock_name)["dependencies"]
    locked = {name.casefold(): item for key in (FRAMEWORK, f"{FRAMEWORK}/{rid}")
              for name, item in lock[key].items() if item["type"] != "Project"}
    assets = json_input(repo / "src" / role_project / "obj" / "project.assets.json")
    target = assets["targets"][f"{FRAMEWORK}/{rid}"]
    require(0 < len(target) <= 512, f"Invalid restored input count: {role_project}")
    for entry, target_item in sorted(target.items()):
        if target_item["type"] != "package":
            continue
        name, _, version = entry.partition("/")
        require(PACKAGE_ID.fullmatch(name) and PACKAGE_VERSION.fullmatch(version), "Invalid NuGet package identity")
        entry_lock = locked.get(name.casefold()) or {}
        require(entry_lock.get("resolved") == version, f"Unpinned or mismatched RID input: {name}")
        content_hash = sha512(entry_lock["contentHash"])
        library = assets["libraries"][entry]
        require(library["type"] == "package" and sha512(library["sha512"]) == content_hash,
                f"Resolved NuGet content hash differs from the lock: {name}")
        runtime = any(not asset.endswith("/_._") for kind in ("runtime", "native", "runtimeTargets")
                      for asset in target_item.get(kind, ()))
        if name.casefold() in {"arcforges.build.policy", "microsoft.net.illink.tasks", "grpc.tools"} or "ilcompiler" in name.casefold():
            runtime = False
        yield input_package(stage, name, version, content_hash, runtime), runtime

    # SDK runtime-pack downloads are pinned by the restore, but do not appear in the application lock.
    # Bind the exact staged RID's actual Native AOT archive without attributing unused SDK downloads.
    expected_pack = f"Microsoft.NETCore.App.Runtime.NativeAOT.{rid}"
    downloads = assets["project"]["frameworks"][FRAMEWORK].get("downloadDependencies", [])
    selected = [entry for entry in downloads if entry["name"].casefold() == expected_pack.casefold()]
    require(len(selected) == 1, f"No exact SDK Native AOT pack restore record: {role_project}")
    version_bound = re.fullmatch(r"\[([^,]+),\s*([^\]]+)\]", selected[0]["version"])
    require(version_bound and version_bound[1] == version_bound[2] and PACKAGE_VERSION.fullmatch(version_bound[1]),
            "SDK Native AOT pack does not have an exact restored version")
    version = version_bound[1]
    name = expected_pack.lower()
    filename = f"{name}.{version.lower()}.nupkg"
    cached = next((Path(folder) / name / version.lower() / filename for folder in assets["packageFolders"]
                   if (Path(folder) / name / version.lower() / filename).is_file()), None)
    require(cached is not None, "Restored SDK Native AOT pack bytes are missing")
    content_hash = sha512(read(cached.with_name(filename + ".sha512"), 128).decode("ascii").strip())
    require(digest(cached, algorithm="sha512") == content_hash, "SDK Native AOT archive differs from restored content hash")
    item = input_package(stage, expected_pack, version, content_hash, True)
    item["sourceInfo"] = "Exact local SDK Native AOT runtime pack recorded in the selected restore. See staged .NET notices."
    yield item, True


def verify_mxc(stage, rid, supervisor):
    directory = stage / "mxc"
    manifest_path = directory / "mxc-manifest.json"
    manifest = json_input(manifest_path)
    expected = {"rid": rid, "version": VERSION, "schema": SCHEMA, "source": SOURCE,
                "packageSha256": PACKAGE, "releaseSha256": RELEASE}
    require(all(manifest.get(key) == value for key, value in expected.items()), "Wrong pinned MXC input identity")
    entries = manifest["files"]
    pinned = {**NATIVE[rid], "mxc.LICENSE.md": LICENSE, "mxc-release.spdx.json": SBOM}
    expected_names = set(pinned) | {Path(supervisor).name}
    if rid == "win-x64":
        expected_names.add("windows-signatures.json")
    files = {entry["path"]: entry["sha256"] for entry in entries}
    require(len(entries) == len(files) and files.keys() == expected_names and
            {file.name for file in directory.iterdir()} == expected_names | {manifest_path.name},
            "Unexpected MXC evidence membership")
    for name, sha in files.items():
        require(digest(directory / name) == sha and (name not in pinned or pinned[name] == sha), "Wrong pinned MXC artifact bytes")

    upstream = json_input(directory / "mxc-release.spdx.json")
    namespace = upstream["documentNamespace"]
    uri = urlsplit(namespace)
    require(upstream.get("SPDXID") == DOCUMENT and upstream.get("spdxVersion") == "SPDX-2.2"
            and uri.scheme in {"http", "https"} and uri.netloc, "Invalid upstream SPDX identity")
    external = {"externalDocumentId": UPSTREAM, "spdxDocument": namespace, "checksum": checksum("SHA256", SBOM)}
    return manifest_path, files, external


def generate(stage, rid, repo=ROOT):
    require(rid in NATIVE, "Unsupported native cohort architecture")
    info = json_input(stage / "build-info.json")
    commit = info.get("commit")
    require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit)
            and info.get("runtimeIdentifier") == rid and isinstance(info.get("dirty"), bool)
            and info.get("source") == "https://github.com/ArcForges/ArcForges", "Wrong staged source identity")
    suffix = ".exe" if rid == "win-x64" else ""
    roles = [("Node", "ArcForges.Host", "packages.lock.json", f"arcforges{suffix}"),
             ("RunSupervisor", "ArcForges.RunSupervisor", "run-supervisor.packages.lock.json", f"mxc/arcforges-run-supervisor{suffix}")]
    if suffix:
        roles.append(("NodeSupervisor", "ArcForges.Supervisor", "supervisor.packages.lock.json", "arcforges-supervisor.exe"))
    manifest_path, mxc_files, upstream = verify_mxc(stage, rid, roles[1][3])
    app = package(COHORT, f"ArcForges native {rid}", commit, AGPL, info["source"])
    notices = ["LICENSE", "THIRD_PARTY_NOTICES.md", "mxc/mxc.LICENSE.md", "mxc/mxc-release.spdx.json", manifest_path.relative_to(stage).as_posix()]
    app["sourceInfo"] = (f"Locked Native AOT cohort at source commit {commit}, SDK {info['sdk']}. "
                         + ("The source workspace had local changes." if info["dirty"] else "The source workspace was clean."))
    app["comment"] = "Staged notice/evidence SHA-256: " + "; ".join(f"{name} {digest(stage / name)}" for name in notices)

    mx_pkg = package(MXC, f"Microsoft MXC official runtime ({rid})", VERSION, "MIT", SOURCE)
    mx_pkg["comment"] = ("The official archive inventory is preserved unchanged. Upstream NOASSERTION values remain unattributed. "
                         f"The exact selected subset is bound by mxc/mxc-manifest.json: {digest(manifest_path)}.")
    packages = {COHORT: app, MXC: mx_pkg}
    relationships = [relation(DOCUMENT, "DESCRIBES", COHORT), relation(COHORT, "CONTAINS", MXC),
                     relation(MXC, "OTHER", f"{UPSTREAM}:{DOCUMENT}")]
    relationships[-1]["comment"] = "Official upstream SPDX inventory for the full x64 release archive."
    for name in sorted(NATIVE[rid]):
        artifact_id = "SPDXRef-Mxc-" + hashlib.sha256(name.encode()).hexdigest()[:24]
        artifact = package(artifact_id, name, VERSION)
        artifact["checksums"] = [checksum("SHA256", mxc_files[name])]
        artifact["packageFileName"] = f"mxc/{name}"
        packages[artifact_id] = artifact
        relationships.append(relation(MXC, "CONTAINS", artifact_id))

    for role, project, lock, path in roles:
        role_id = f"SPDXRef-{role}"
        item = package(role_id, Path(path).name, commit, AGPL, info["source"])
        item["checksums"] = [checksum("SHA256", digest(stage / path))]
        item["packageFileName"] = path
        item["comment"] = f"Locked restore inventory {lock} SHA-256 {digest(stage / lock)}."
        packages[role_id] = item
        relationships.append(relation(COHORT, "CONTAINS", role_id))
        for dependency, runtime in restore_inputs(stage, repo, project, lock, rid):
            dep_id = dependency["SPDXID"]
            previous = packages.setdefault(dep_id, dependency)
            require(previous["checksums"] == dependency["checksums"], "Inconsistent dependency bytes across native roles")
            if runtime:
                relationships.append(relation(role_id, "DEPENDS_ON", dep_id))
            else:
                relationships.append(relation(dep_id, "BUILD_DEPENDENCY_OF", role_id))

    document = {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": DOCUMENT,
        "name": app["name"], "documentNamespace": f"https://arcforges.com/spdxdocs/native/{commit}/{rid}/{uuid.uuid4()}",
        "creationInfo": {"created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "creators": ["Tool: ArcForges native packaging inventory"]},
        "externalDocumentRefs": [upstream], "packages": list(packages.values()), "relationships": relationships,
    }
    with (stage / OUTPUT).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return len(packages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--rid", choices=NATIVE, required=True)
    arguments = parser.parse_args()
    try:
        print(f"{OUTPUT}: {generate(arguments.stage.resolve(strict=True), arguments.rid)} SPDX packages")
    except (OSError, ValueError, KeyError, TypeError, ElementTree.ParseError) as error:
        parser.exit(1, f"Native SBOM refused: {error}\n")


if __name__ == "__main__":
    main()
