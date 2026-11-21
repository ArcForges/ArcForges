#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bind successful native publishing, admitted dependency locks and Node archive signing."""

import argparse
import hashlib
from pathlib import Path
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from zipfile import BadZipFile, ZipFile

sys.dont_write_bytecode = True
from signed import (ARCHIVE_NAMES, COMMIT, MAX_MANIFEST, NODE_REPO, archive_digest, envelope, host_rid,
                    json_bytes, json_object, openssl_path, read_bounded, require, seal)

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "eng/policy/dependency-admissions.json"
PROJECTS = {
    "host": ("src/ArcForges.Host", "packages.lock.json"),
    "run-supervisor": ("src/ArcForges.RunSupervisor", "run-supervisor.packages.lock.json"),
    "supervisor": ("src/ArcForges.Supervisor", "supervisor.packages.lock.json"),
}
CONTRACTS = "ArcForges/Contracts"
DESKTOP = "ArcForges/DesktopPlatform"
PACKAGE_PATH = re.compile(r"[a-z0-9_.-]+/[a-z0-9_.+-]+")
MAX_JSON = 32 * 1024 * 1024


def read_json(path):
    return json_object(read_bounded(path, MAX_JSON))


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def git(repo, *args):
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1")
    result = subprocess.run(["git", "-C", str(repo), *args], env=environment, capture_output=True,
                            text=True, encoding="utf-8", timeout=30)
    require(result.returncode == 0, f"Git did not verify {args[0]}")
    return result.stdout.strip()


def canonical_repo(url):
    for prefix in ("https://github.com/", "git@github.com:", "ssh://git@github.com/"):
        if url.startswith(prefix):
            return url[len(prefix):].removesuffix(".git")
    return None


def source_identity():
    require(canonical_repo(git(REPO, "remote", "get-url", "origin")) == NODE_REPO, "Unexpected Node producer origin")
    require(not git(REPO, "status", "--porcelain", "--untracked-files=all"), "Signed native publishing requires a clean Node worktree")
    commit = git(REPO, "rev-parse", "--verify", "HEAD^{commit}")
    tree = git(REPO, "rev-parse", "--verify", f"{commit}^{{tree}}")
    require(COMMIT.fullmatch(commit) and COMMIT.fullmatch(tree), "Invalid Node producer Git identity")
    return {"repo": NODE_REPO, "commit": commit, "tree": tree}


def main_ancestry(repo, expected_repo, commits):
    require(repo is not None and canonical_repo(git(repo, "remote", "get-url", "origin")) == expected_repo,
            f"Expected the reviewed {expected_repo} origin")
    main = git(repo, "rev-parse", "--verify", "refs/remotes/origin/main^{commit}")
    require(COMMIT.fullmatch(main), f"Invalid {expected_repo} origin/main identity")
    for commit in sorted(commits):
        require(COMMIT.fullmatch(commit), "Invalid first-party publishing commit")
        git(repo, "merge-base", "--is-ancestor", commit, main)
    return main


def roles(rid):
    return tuple(PROJECTS) if rid == "win-x64" else ("host", "run-supervisor")


def product_publish_root(rid):
    return REPO / "artifacts" / "publish" / rid


def output_inventory(root):
    require(root.is_dir() and not root.is_symlink() and not root.is_junction(), "Missing real native publish directory")
    inventory = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink() and not path.is_junction(), "Links are not admitted native outputs")
        if path.is_dir():
            continue
        require(path.is_file(), "Unexpected native publish output")
        inventory[path.relative_to(root).as_posix()] = digest(path)
    require(inventory, "Missing native publish outputs")
    return inventory


def assets_path(role):
    return REPO / PROJECTS[role][0] / "obj/project.assets.json"


def sdk_version():
    selected = read_json(REPO / "global.json")["sdk"]["version"]
    actual = subprocess.run(["dotnet", "--version"], cwd=REPO, capture_output=True, text=True, timeout=30, check=True).stdout.strip()
    require(selected == actual, "Native publish SDK does not match global.json")
    return actual


def publish_record(rid):
    sources = source_identity()
    require(host_rid() == rid, "A signed build receipt requires the selected native x64 host")
    root = product_publish_root(rid)
    return {
        "schema": 1, "rid": rid, "source": sources, "sdk": sdk_version(),
        "components": {
            role: {"files": output_inventory(root / role), "assetsSha256": digest(assets_path(role))}
            for role in roles(rid)
        },
    }


def write_publish_record(rid, expected):
    record = publish_record(rid)
    require(record["source"]["commit"] == expected, "Node HEAD changed during native publishing")
    with (product_publish_root(rid) / "distribution-build.json").open("xb") as output:
        output.write(json_bytes(record))


def verify_stage_publish(stage, rid, record):
    inventory = record["components"]
    for name, expected in inventory["host"]["files"].items():
        if Path(name).parts[0].casefold().endswith((".pdb", ".dbg", ".dsym")):
            continue
        require(digest(stage / name) == expected, "Staged Node binary/host output does not match the native publish")
    windows = rid == "win-x64"
    run = "arcforges-run-supervisor.exe" if windows else "arcforges-run-supervisor"
    require(digest(stage / "mxc" / run) == inventory["run-supervisor"]["files"][run],
            "Staged Run supervisor does not match the native publish")
    if windows:
        sibling = "arcforges-supervisor.exe"
        require(digest(stage / sibling) == inventory["supervisor"]["files"][sibling],
                "Staged Windows supervisor does not match the native publish")


def lock_records(role, stage, rid):
    project, target = PROJECTS[role]
    source = REPO / project / "packages.lock.json"
    require(digest(source) == digest(stage / target), "Staged dependency lock does not match the source")
    scopes = read_json(source)["dependencies"]
    locked = {}
    for scope in ("net11.0", f"net11.0/{rid}"):
        for package, row in scopes.get(scope, {}).items():
            if row["type"] == "Project":
                continue
            key = (package.casefold(), row["resolved"].casefold())
            require(key not in locked or locked[key] == row["contentHash"], "Conflicting restored dependency identity")
            locked[key] = row["contentHash"]
    require(locked, "No pinned dependencies in the native lock")
    return locked


def check_denied(identity, denied):
    package, version = identity
    require(identity not in denied and not (package.startswith("arcforges.contracts.") and version == "1.0.0-ci.350.1"),
            "A rolled-back first-party package is present in the native closure")


def verified_nuget(directory, package, version, locked_hash, checked):
    archive = directory / f"{package}.{version.casefold()}.nupkg"
    identifier = (archive, locked_hash)
    if identifier in checked:
        return checked[identifier]
    environment = dict(os.environ, DOTNET_CLI_UI_LANGUAGE="en-US", NUGET_CERT_REVOCATION_MODE="offline")
    archive_sha = digest(archive)
    result = subprocess.run(["dotnet", "nuget", "verify", "--verbosity", "detailed", str(archive)], cwd=REPO,
                            env=environment, capture_output=True, text=True, encoding="utf-8", timeout=60)
    hashes = re.findall(r"(?m)^Content hash: ([A-Za-z0-9+/]{86}==)\s*$", result.stdout)
    require(result.returncode == 0 and hashes == [locked_hash],
            f"NuGet did not verify the locked publication {package} {version}")
    with ZipFile(archive) as publisher:
        members = {}
        for item in publisher.infolist():
            name = item.filename.casefold()
            if name in {f"{package}.nuspec", "build-identity.json"}:
                require(name not in members and not item.is_dir() and item.file_size <= 128 * 1024,
                        "Invalid first-party package provenance member")
                members[name] = publisher.read(item)
    require(digest(archive) == archive_sha, "NuGet archive changed while verifying its publication")
    nuspec = members[f"{package}.nuspec"]
    checked[identifier] = json_object(members["build-identity.json"]), nuspec, archive_sha
    return checked[identifier]


def first_party(role, locked, direct, denied, checked):
    assets = read_json(assets_path(role))
    evidence = []
    verified = set()
    for name, row in assets["libraries"].items():
        if row["type"] != "package":
            continue
        package, version = name.split("/")
        lowered = package.casefold()
        key = (lowered, version.casefold())
        check_denied(key, denied)
        if not lowered.startswith("arcforges."):
            continue
        require(key in locked and locked[key] == row["sha512"] and PACKAGE_PATH.fullmatch(row["path"]),
                "A first-party dependency differs from its committed native lock")
        directory = next((Path(root) / row["path"] for root in assets["packageFolders"]
                          if (Path(root) / row["path"]).is_dir()), None)
        require(directory is not None, "Missing first-party locked NuGet package")
        manifest, nuspec, archive_sha = verified_nuget(directory, lowered, version, locked[key], checked)
        producer = "ArcForges/" + manifest["owner"]
        repository_field = ET.fromstring(nuspec)
        metadata = repository_field.find("{*}metadata")
        repository = metadata.find("{*}repository")
        build = manifest["build"]
        commit = build["sourceCommit"]
        require(manifest["schema"] == "arcforges.build-identity.v1" and manifest["artifact"]["id"].casefold() == lowered
                and manifest["artifact"]["version"] == version and build["kind"] == "ci" and build["dirty"] is False
                and producer in {CONTRACTS, DESKTOP} and canonical_repo(repository.get("url")) == producer
                and repository.get("commit") == commit and COMMIT.fullmatch(commit),
                "Could not bind the first-party publishing commit to the restored package")
        if key in direct:
            # The flat-container nuspec used by some existing admissions omits
            # the UTF-8 BOM present in the package member. The verified lock
            # hash above always binds the original member bytes.
            nuspec_hashes = {hashlib.sha256(raw).hexdigest() for raw in (nuspec, nuspec.removeprefix(b"\xef\xbb\xbf"))}
            require(direct[key]["sourceCommit"] == commit and direct[key]["contentHash"] == locked[key]
                    and direct[key]["nuspecSha256"] in nuspec_hashes,
                    f"Restored {package} publication differs from the dependency admission")
        evidence.append({"id": package, "version": version, "contentHash": locked[key], "repo": producer,
                         "commit": commit, "nupkgSha256": archive_sha})
        verified.add(key)
    require({key for key in locked if key[0].startswith("arcforges.")} <= verified,
            "A committed first-party dependency was missing from the verified native restore")
    return sorted(evidence, key=lambda row: (row["id"].casefold(), row["version"]))


def prepared_evidence(args):
    record = read_json(product_publish_root(args.rid) / "distribution-build.json")
    require(record == publish_record(args.rid), "Native publish receipt is stale or does not match the actual output bytes")
    verify_stage_publish(args.stage, args.rid, record)
    policy = read_json(POLICY)
    denied = {(row["id"].casefold(), row["version"].casefold()) for row in policy["neverAdmit"]}
    direct = {(row["id"].casefold(), row["version"].casefold()): row for row in policy["packages"]}
    closure = {}
    checked = {}
    for role in roles(args.rid):
        locked = lock_records(role, args.stage, args.rid)
        for identity in locked:
            check_denied(identity, denied)
        closure[role] = first_party(role, locked, direct, denied, checked)
    mains = {}
    if args.qualification == "main":
        mains[NODE_REPO] = main_ancestry(REPO, NODE_REPO, [record["source"]["commit"]])
        for producer, repo in ((CONTRACTS, args.contracts_repo), (DESKTOP, args.desktop_platform_repo)):
            commits = {row["commit"] for dependency in closure.values() for row in dependency if row["repo"] == producer}
            require(commits, "Missing expected first-party dependency lineage")
            mains[producer] = main_ancestry(repo, producer, commits)
    return {
        "schema": 1, "source": record["source"], "sdk": record["sdk"], "rid": args.rid,
        "qualification": args.qualification, "mainRefs": mains, "closures": closure,
        "sbom": {"sha256": digest(args.stage / "sbom.spdx.json"),
                 "generatorSha256": digest(REPO / "packaging/native/sbom.py")},
        "lockfiles": {PROJECTS[role][1]: digest(args.stage / PROJECTS[role][1]) for role in roles(args.rid)},
        "nativeBuild": record,
    }


def prepare_stage(args):
    from sbom import generate

    generate(args.stage, args.rid, repo=REPO)
    record = prepared_evidence(args)
    info = read_json(args.stage / "build-info.json")
    require(info["commit"] == record["source"]["commit"] and info["sdk"] == record["sdk"]
            and info["runtimeIdentifier"] == args.rid and info["dirty"] is False, "Incorrect signed build information")
    info.update(tree=record["source"]["tree"], distribution="signed-mxc-cohort", qualification=args.qualification)
    (args.stage / "build-info.json").write_bytes(json_bytes(info))
    (args.stage / "dependency-admission.json").write_bytes(POLICY.read_bytes())
    (args.stage / "dependency-evidence.json").write_bytes(json_bytes(record))


def sign_archive(args):
    sys.path.insert(0, str(REPO / "packaging/mxc"))
    from verify_install import extract, protect_install_root, verify

    require(host_rid() == args.rid and ARCHIVE_NAMES[args.rid] == args.archive.name, "Wrong native archive for signing")
    require(not args.signing_key.resolve(strict=True).is_relative_to(REPO),
            "The signing key must be kept outside the Node checkout")
    evidence_names = {
        "buildInfoSha256": "build-info.json",
        "sbomSha256": "sbom.spdx.json",
        "dependencyAdmissionSha256": "dependency-admission.json",
        "dependencyEvidenceSha256": "dependency-evidence.json",
    }
    record = prepared_evidence(args)
    require(read_json(args.stage / "dependency-evidence.json") == record
            and digest(args.stage / "dependency-admission.json") == digest(POLICY),
            "The staged dependency evidence changed while sealing")
    with tempfile.TemporaryDirectory(prefix="arcforges-pre-sign-") as directory:
        root = Path(directory)
        protect_install_root(root)
        with tempfile.TemporaryFile(dir=root) as snapshot:
            archive = archive_digest(args.archive, copy=snapshot)
            snapshot.seek(0)
            extract(args.archive, args.rid, root, source=snapshot)
        verify(root, args.rid, record["source"]["commit"], distribution="signed-mxc-cohort")
        verify_stage_publish(root, args.rid, record["nativeBuild"])
        require(digest(root / "sbom.spdx.json") == record["sbom"]["sha256"],
                "The archived SBOM differs from the admitted inventory")
        require(all(digest(root / name) == digest(args.stage / name) for name in evidence_names.values()),
                "The archived evidence differs from the verified staging")
        require(all(digest(root / name) == sha for name, sha in record["lockfiles"].items()),
                "The archived native locks differ from the admitted staging")
        manifest = {"schema": 1, "kind": "node", "rid": args.rid, "archive": archive,
                    "producers": [record["source"]], "qualification": record["qualification"],
                    **{field: digest(root / name) for field, name in evidence_names.items()}}
    envelope(args.archive, args.rid, json_bytes(manifest), commit=record["source"]["commit"],
             tree=record["source"]["tree"], allow_candidate=True)
    seal(args.archive, openssl_path(args.openssl), args.signing_key, args.trusted_key, manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("source")
    publish = commands.add_parser("record-publish")
    publish.add_argument("--rid", choices=ARCHIVE_NAMES, required=True)
    publish.add_argument("--commit", required=True)
    prepare = commands.add_parser("prepare-stage")
    signing = commands.add_parser("sign-archive")
    for command in (prepare, signing):
        command.add_argument("--rid", choices=ARCHIVE_NAMES, required=True)
        command.add_argument("--stage", type=Path, required=True)
        command.add_argument("--qualification", choices=("candidate", "main"), required=True)
        command.add_argument("--contracts-repo", type=Path)
        command.add_argument("--desktop-platform-repo", type=Path)
    signing.add_argument("--archive", type=Path, required=True)
    signing.add_argument("--signing-key", type=Path, required=True)
    signing.add_argument("--trusted-key", type=Path, required=True)
    signing.add_argument("--openssl", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "source":
            print(source_identity()["commit"])
        elif args.command == "record-publish":
            write_publish_record(args.rid, args.commit)
        elif args.command == "prepare-stage":
            prepare_stage(args)
        else:
            sign_archive(args)
    except (AttributeError, BadZipFile, KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError, ET.ParseError) as error:
        parser.exit(1, f"Node distribution: {error}\n")


if __name__ == "__main__":
    main()
