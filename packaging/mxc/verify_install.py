#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify and optionally retain a fresh extraction of an x64 Node/MXC archive."""

import argparse
import json
import ntpath
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eng" / "mxc"))
from stage import LICENSE, NATIVE, PACKAGE, RELEASE, SBOM, SCHEMA, SOURCE, VERSION
from stage import digest, is_x64_image, require, run_supervisor_name


def member_path(name):
    name = name.removeprefix("./").rstrip("/")
    parts = name.split("/")
    require(all(part and part not in (".", "..") and part == part.rstrip(" .")
                and not any(char in part for char in '\\:<>"|?*')
                and not any(ord(char) < 32 for char in part)
                and not ntpath.isreserved(part) for part in parts),
            f"Invalid archive member path: {name!r}")
    return Path(*parts)


def copy_member(root, seen, name, kind, stream=None, mode=0):
    path = member_path(name)
    key = path.as_posix().casefold()
    require(key not in seen, f"Duplicate archive member: {name}")
    seen.add(key)
    target = root / path
    if kind == "directory":
        target.mkdir(parents=True, exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        with stream, target.open("xb") as output:
            shutil.copyfileobj(stream, output)
        if os.name == "posix":
            target.chmod(0o600 | (mode & 0o100))


def extract(archive, rid, root):
    seen = set()
    if rid == "win-x64":
        require(archive.name.endswith(".zip"), "The Windows archive must be a ZIP")
        with zipfile.ZipFile(archive) as package:
            for item in package.infolist():
                kind = (item.external_attr >> 16) & 0o170000
                require(kind in (0, 0o040000, 0o100000), f"Unexpected ZIP member type: {item.filename}")
                if item.is_dir():
                    copy_member(root, seen, item.filename, "directory")
                else:
                    copy_member(root, seen, item.filename, "file", package.open(item))
    else:
        require(archive.name.endswith(".tar.gz"), "The Linux archive must be a tar.gz")
        with tarfile.open(archive, "r:gz") as package:
            for item in package:
                if item.name in (".", "./") and item.isdir():
                    continue
                require(item.isfile() or item.isdir(), f"Unexpected tar member type: {item.name}")
                relative = item.name.removeprefix("./").rstrip("/")
                if relative == "mxc" or relative.startswith("mxc/"):
                    require(item.mode & 0o7022 == 0, f"Unprotected MXC tar member: {item.name}")
                if item.isdir():
                    copy_member(root, seen, item.name, "directory")
                else:
                    copy_member(root, seen, item.name, "file", package.extractfile(item), item.mode)


def unique_object(pairs):
    result = dict(pairs)
    require(len(pairs) == len(result), "Unexpected duplicate JSON property")
    return result


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object)


def verify(root, rid, commit):
    info = read_json(root / "build-info.json")
    require(info["runtimeIdentifier"] == rid, "Build information does not match the requested RID")
    if commit is not None:
        require(info["commit"] == commit, "The package was built from a different commit")
    files = read_json(root / "digests.json")["files"]
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()} - {"digests.json"}
    require(files.keys() == actual, "Version digest manifest does not match the extracted archive membership")
    for name in sorted(actual):
        require(digest(root / name) == files[name], f"Package file digest mismatch: {name}")

    windows = rid == "win-x64"
    host = "arcforges.exe" if windows else "arcforges"
    legacy = {"arcforges-supervisor.exe", "supervisor.packages.lock.json"} if windows else {
        "packaging/linux/arcforges-node.service", "packaging/linux/arcforges-guard.service", "packaging/linux/arcforges.slice",
    }
    require(({host, "packages.lock.json", "run-supervisor.packages.lock.json", "LICENSE", "THIRD_PARTY_NOTICES.md"}
             | legacy) <= actual, "Required Node/CLI distribution files are missing")

    mxc = root / "mxc"
    manifest = read_json(mxc / "mxc-manifest.json")
    identity = {"rid": rid, "version": VERSION, "schema": SCHEMA, "source": SOURCE,
                "packageSha256": PACKAGE, "releaseSha256": RELEASE}
    require(all(manifest[key] == value for key, value in identity.items()), "Wrong MXC runtime identity")
    members = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    supervisor = run_supervisor_name(rid)
    pinned = {**NATIVE[rid], "mxc.LICENSE.md": LICENSE, "mxc-release.spdx.json": SBOM}
    expected = set(pinned) | {supervisor}
    if windows:
        expected.add("windows-signatures.json")
    require(members.keys() == expected and len(manifest["files"]) == len(members), "Unexpected MXC manifest membership")
    require({name for name in actual if name.startswith("mxc/")} == {f"mxc/{name}" for name in expected | {"mxc-manifest.json"}},
            "Unexpected installed MXC files")
    for name, sha in members.items():
        require(files[f"mxc/{name}"] == sha and (name not in pinned or pinned[name] == sha), f"MXC file digest mismatch: {name}")
    for path in (root / host, mxc / supervisor):
        require(is_x64_image(path.read_bytes(), rid), f"Incorrect native image architecture: {path.name}")
        if os.name == "posix" and not windows:
            require(path.stat().st_mode & 0o100, f"Installed binary is not executable: {path.name}")
    if windows:
        signatures = read_json(mxc / "windows-signatures.json")
        require(len(signatures) == len(NATIVE[rid]) and {row["file"] for row in signatures} == NATIVE[rid].keys()
                and all(row["status"] == "Valid" and "O=Microsoft Corporation" in row["subject"] for row in signatures),
                "Missing official Microsoft Authenticode verification receipt")
    return {"rid": rid, "commit": info["commit"], "files": len(actual), "mxcManifestSha256": files["mxc/mxc-manifest.json"]}


def protect_install_root(root):
    if os.name != "nt":
        return
    # Python's Windows mode 0700 grants OWNER RIGHTS. Use the concrete
    # installing identity so the archive's inherited ACL agrees with Node trust.
    script = r"""$ErrorActionPreference = 'Stop'
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$security = [System.Security.AccessControl.DirectorySecurity]::new()
$security.SetOwner($owner)
$security.SetAccessRuleProtection($true, $false)
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($owner, 'FullControl',
  'ContainerInherit,ObjectInherit', 'None', 'Allow')
$security.AddAccessRule($rule)
[System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.DirectoryInfo]::new($env:AFV2_MXC_INSTALL_ROOT), $security)
"""
    env = dict(os.environ, AFV2_MXC_INSTALL_ROOT=str(root))
    subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script], env=env, check=True)


def verify_extraction(archive, rid, root, commit):
    protect_install_root(root)
    extract(archive, rid, root)
    return verify(root, rid, commit)


def check(args):
    archive = args.archive.resolve(strict=True)
    sha = digest(archive)
    require(Path(f"{archive}.sha256").read_text(encoding="ascii").splitlines() == [f"{sha}  {archive.name}"],
            "Archive SHA-256 sidecar does not match")
    if args.output is None:
        if os.name == "nt":
            local_data = os.environ.get("LOCALAPPDATA")
            parent = (Path(local_data) if local_data else Path.home() / "AppData" / "Local") / "Temp"
        else:
            parent = Path.home()
        with tempfile.TemporaryDirectory(prefix="verified MXC 安装 ", dir=parent) as directory:
            result = verify_extraction(archive, args.rid, Path(directory), args.commit)
    else:
        root = args.output.absolute()
        root.mkdir(mode=0o700)
        result = verify_extraction(archive, args.rid, root, args.commit)
        result["installRoot"] = str(root)
    print(json.dumps({**result, "archiveSha256": sha}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rid", choices=NATIVE, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--commit", help="expected package source commit")
    parser.add_argument("--output", type=Path, help="retain the verified extraction in a fresh trusted directory")
    try:
        check(parser.parse_args())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError) as error:
        parser.exit(1, f"Package verification failed: {error}\n")


if __name__ == "__main__":
    main()
