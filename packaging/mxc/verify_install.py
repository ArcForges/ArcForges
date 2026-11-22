#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify and optionally retain a fresh extraction of an x64 Node/MXC archive."""

import argparse
import ctypes
import json
import mmap
import ntpath
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "native"))
from signed import archive_digest, authenticate, openssl_path, read_bounded

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eng" / "mxc"))
from stage import LICENSE, NATIVE, PACKAGE, RELEASE, SBOM, SCHEMA, SOURCE, VERSION
from stage import digest, is_x64_image, require, run_supervisor_name

MAX_MEMBERS = 1024
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024
MAX_ZIP_CENTRAL_BYTES = 1024 * 1024
COPY_BYTES = 1024 * 1024
ZIP_FOOTER = struct.Struct("<4s4H2IH")
ZIP_CENTRAL = struct.Struct("<4s6H3I5H2I")
ZIP_LOCAL = struct.Struct("<4s5H3I2H")
ZIP_EXTRA = struct.Struct("<HH")
ZIP_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


class Expansion:
    def __init__(self):
        self.members = 0
        self.total = 0

    def admit(self, size):
        require(0 <= size <= MAX_MEMBER_BYTES, "Archive member exceeds the size limit")
        self.members += 1
        self.total += size
        require(self.members <= MAX_MEMBERS, "Archive exceeds the member count limit")
        require(self.total <= MAX_EXPANDED_BYTES, "Archive exceeds the expanded size limit")


def check_zip_extra(data):
    offset = 0
    while offset < len(data):
        require(len(data) - offset >= ZIP_EXTRA.size, "Invalid ZIP extra field")
        field, size = ZIP_EXTRA.unpack_from(data, offset)
        require(field != 0x0001, "ZIP64 metadata is not supported")
        offset += ZIP_EXTRA.size + size
        require(offset <= len(data), "Invalid ZIP extra field")


def check_zip_directory(source, expansion):
    # Native packaging produces a single, ordinary ZIP without comments or
    # ZIP64. Refuse an oversized directory before ZipFile reads its entries.
    archive_size = source.seek(0, os.SEEK_END)
    require(archive_size >= ZIP_FOOTER.size, "Invalid ZIP footer")
    footer_offset = archive_size - ZIP_FOOTER.size
    if footer_offset >= 20:
        source.seek(footer_offset - 20)
        require(source.read(4) != b"PK\x06\x07", "ZIP64 locator is not supported")
    source.seek(footer_offset)
    end, disk, central_disk, local_count, count, size, offset, comment = ZIP_FOOTER.unpack(source.read(ZIP_FOOTER.size))
    require(count != 0xffff and local_count != 0xffff and size != 0xffffffff and offset != 0xffffffff,
            "ZIP64 directory is not supported")
    require(end == b"PK\x05\x06" and disk == central_disk == comment == 0
            and count == local_count and offset + size == footer_offset, "Unsupported ZIP layout")
    require(count <= MAX_MEMBERS and size <= MAX_ZIP_CENTRAL_BYTES, "ZIP directory exceeds the limit")
    source.seek(offset)
    directory = source.read(size)
    position = 0
    for _ in range(count):
        require(len(directory) - position >= ZIP_CENTRAL.size, "Incomplete ZIP directory entry")
        entry = ZIP_CENTRAL.unpack_from(directory, position)
        marker, _, version, flags, method = entry[:5]
        compressed, expanded, name_size, extra_size, comment_size, member_disk = entry[8:14]
        local_offset = entry[-1]
        require(marker == b"PK\x01\x02" and member_disk == 0, "Invalid ZIP directory entry")
        require(method in ZIP_METHODS, "Unsupported ZIP compression method")
        require(version < 45 and 0xffffffff not in (compressed, expanded, local_offset), "ZIP64 entry is not supported")
        expansion.admit(expanded)
        extra_start = position + ZIP_CENTRAL.size + name_size
        position = extra_start + extra_size + comment_size
        require(position <= len(directory), "Incomplete ZIP directory entry")
        check_zip_extra(directory[extra_start:extra_start + extra_size])

        require(local_offset + ZIP_LOCAL.size <= offset, "ZIP local header lies outside member data")
        source.seek(local_offset)
        local = ZIP_LOCAL.unpack(source.read(ZIP_LOCAL.size))
        local_marker, local_version, local_flags, local_method = local[:4]
        local_compressed, local_expanded, local_name, local_extra = local[7:]
        require(local_marker == b"PK\x03\x04" and local_flags == flags and local_method == method,
                "ZIP local header differs from its directory")
        require(local_version < 45 and 0xffffffff not in (local_compressed, local_expanded),
                "ZIP64 local header is not supported")
        data_offset = local_offset + ZIP_LOCAL.size + local_name
        require(data_offset + local_extra + compressed <= offset, "ZIP member data lies outside its archive")
        source.seek(data_offset)
        check_zip_extra(source.read(local_extra))
    require(position == len(directory), "ZIP directory has unexpected records")
    source.seek(0)
    return count


def bounded_tar_info(expansion):
    class BoundedTarInfo(tarfile.TarInfo):
        waiting_for_name_target = False

        def _proc_member(self, archive):
            # TarFile consumes GNU extension payloads before returning a
            # logical entry. Charge these raw headers before that processing.
            expansion.admit(self.size)
            cls = type(self)
            if self.type == tarfile.GNUTYPE_LONGNAME:
                require(not cls.waiting_for_name_target and 0 < self.size <= 4096, "Invalid GNU tar path extension")
                cls.waiting_for_name_target = True
            else:
                require(self.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE),
                        "Unsupported signed tar member metadata")
                cls.waiting_for_name_target = False
            return super()._proc_member(archive)

    return BoundedTarInfo


def member_path(name):
    name = name.removeprefix("./").rstrip("/")
    parts = name.split("/")
    require(all(part and part not in (".", "..") and part == part.rstrip(" .")
                and not any(char in part for char in '\\:<>"|?*')
                and not any(ord(char) < 32 for char in part)
                and not ntpath.isreserved(part) for part in parts),
            f"Invalid archive member path: {name!r}")
    return Path(*parts)


def copy_member(root, seen, name, kind, stream=None, mode=0, size=0):
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
            remaining = size
            while remaining:
                chunk = stream.read(min(remaining, COPY_BYTES))
                require(0 < len(chunk) <= remaining, "Archive member differs from its declared size")
                output.write(chunk)
                remaining -= len(chunk)
            require(not stream.read(1), "Archive member differs from its declared size")
        if os.name == "posix":
            target.chmod(0o600 | (mode & 0o100))


def extract(archive, rid, root, *, source):
    seen = set()
    expansion = Expansion()
    if rid == "win-x64":
        require(archive.name.endswith(".zip"), "The Windows archive must be a ZIP")
        expected = check_zip_directory(source, expansion)
        with zipfile.ZipFile(source) as package:
            require(len(package.infolist()) == expected, "ZIP member count differs from its directory")
            for item in package.infolist():
                kind = (item.external_attr >> 16) & 0o170000
                require(kind in (0, 0o040000, 0o100000), f"Unexpected ZIP member type: {item.filename}")
                if item.is_dir():
                    require(item.file_size == 0, "Directory has unexpected archive bytes")
                    copy_member(root, seen, item.filename, "directory")
                else:
                    copy_member(root, seen, item.filename, "file", package.open(item), size=item.file_size)
    else:
        require(archive.name.endswith(".tar.gz"), "The Linux archive must be a tar.gz")
        with tarfile.open(name=str(archive), mode="r:gz", fileobj=source, tarinfo=bounded_tar_info(expansion)) as package:
            for item in package:
                require(not item.isdir() or item.size == 0, "Directory has unexpected archive bytes")
                if item.name in (".", "./") and item.isdir():
                    continue
                require(item.isfile() or item.isdir(), f"Unexpected tar member type: {item.name}")
                relative = item.name.removeprefix("./").rstrip("/")
                if relative == "mxc" or relative.startswith("mxc/"):
                    require(item.mode & 0o7022 == 0, f"Unprotected MXC tar member: {item.name}")
                if item.isdir():
                    copy_member(root, seen, item.name, "directory")
                else:
                    copy_member(root, seen, item.name, "file", package.extractfile(item), item.mode, size=item.size)


def unique_object(pairs):
    result = dict(pairs)
    require(len(pairs) == len(result), "Unexpected duplicate JSON property")
    return result


def read_json(path):
    with path.open("rb") as source:
        raw = source.read(MAX_METADATA_BYTES + 1)
    require(len(raw) <= MAX_METADATA_BYTES, "Package JSON exceeds the metadata limit")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object)


def verify(root, rid, commit, *, distribution):
    info = read_json(root / "build-info.json")
    require(info.get("distribution") == distribution, "Package build information does not match the selected authentication")
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
    platform_files = {"arcforges-supervisor.exe", "supervisor.packages.lock.json"} if windows else {
        "packaging/linux/arcforges-node.service",
    }
    require(({host, "packages.lock.json", "run-supervisor.packages.lock.json", "LICENSE", "THIRD_PARTY_NOTICES.md"}
             | platform_files) <= actual, "Required Node/CLI distribution files are missing")

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
    images = [root / host, mxc / supervisor]
    if windows:
        images.append(root / "arcforges-supervisor.exe")
    for path in images:
        with path.open("rb") as binary:
            require(os.fstat(binary.fileno()).st_size >= 64, f"Incorrect native image architecture: {path.name}")
            with mmap.mmap(binary.fileno(), 0, access=mmap.ACCESS_READ) as image:
                require(is_x64_image(image, rid), f"Incorrect native image architecture: {path.name}")
        if os.name == "posix" and not windows:
            require(path.stat().st_mode & 0o100, f"Installed binary is not executable: {path.name}")
    if windows:
        signatures = read_json(mxc / "windows-signatures.json")
        require(len(signatures) == len(NATIVE[rid]) and {row["file"] for row in signatures} == NATIVE[rid].keys()
                and all(row["status"] == "Valid" and "O=Microsoft Corporation" in row["subject"] for row in signatures),
                "Missing official Microsoft Authenticode verification receipt")
    return {"rid": rid, "commit": info["commit"], "files": len(actual), "mxcManifestSha256": files["mxc/mxc-manifest.json"]}


def protect_install_root(root, powershell=None):
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
    subprocess.run([str(powershell) if powershell is not None else "pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
                   env=env, timeout=30, check=True)


def installation_temp_parent():
    if os.name == "nt":
        local_data = os.environ.get("LOCALAPPDATA")
        return (Path(local_data) if local_data else Path.home() / "AppData" / "Local") / "Temp"
    return Path.home()


def expose_installation(staged, output):
    if os.name == "nt":
        os.rename(staged, output)
        return
    # Linux rename must not replace a directory created after verification.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(staged), -100, os.fsencode(output), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), output)


def check_signed(args):
    archive = args.archive.absolute()
    manifest = authenticate(archive, args.rid, args.trusted_key, openssl_path(args.openssl),
                            commit=args.commit, tree=args.tree, allow_candidate=args.allow_candidate,
                            admitted_archive_sha256=args.admitted_archive_sha256)
    producer = manifest["producers"][0]
    output = args.output.absolute() if args.output is not None else None
    parent = output.parent if output is not None else installation_temp_parent()
    with tempfile.TemporaryDirectory(prefix="verified signed MXC 安装 ", dir=parent) as directory:
        staging = Path(directory)
        protect_install_root(staging, args.powershell)
        with tempfile.TemporaryFile(dir=staging) as snapshot:
            observed = archive_digest(archive, copy=snapshot, length=manifest["archive"]["length"])
            require(observed == manifest["archive"], "Signed archive length or digest does not match")
            snapshot.seek(0)
            root = staging / "cohort"
            root.mkdir(mode=0o700)
            extract(archive, args.rid, root, source=snapshot)
        result = verify(root, args.rid, producer["commit"], distribution="signed-mxc-cohort")
        evidence = {
            "build-info.json": "buildInfoSha256",
            "sbom.spdx.json": "sbomSha256",
            "dependency-admission.json": "dependencyAdmissionSha256",
            "dependency-evidence.json": "dependencyEvidenceSha256",
        }
        require(all(digest(root / name) == manifest[field] for name, field in evidence.items()),
                "Signed Node evidence digest does not match")
        provenance = read_json(root / "dependency-evidence.json")
        require(provenance["sbom"]["sha256"] == manifest["sbomSha256"]
                and provenance["source"] == producer and provenance["qualification"] == manifest["qualification"],
                "Signed Node dependency evidence does not match")
        info = read_json(root / "build-info.json")
        require(info.get("tree") == producer["tree"] and info.get("dirty") is False
                and info.get("qualification") == manifest["qualification"], "Signed build producer does not match")
        result.update(archiveSha256=observed["sha256"], authentication="ed25519", tree=producer["tree"],
                      qualification=manifest["qualification"])
        if output is not None:
            protect_install_root(root, args.powershell)
            expose_installation(root, output)
            result["installRoot"] = str(output)
    return result


def check_unsigned(args):
    archive = args.archive.resolve(strict=True)
    require(args.allow_unsigned_preview and not args.allow_candidate and args.tree is None
            and args.admitted_archive_sha256 is None
            and not any(os.path.lexists(f"{args.archive}{extension}") or os.path.lexists(f"{archive}{extension}")
                        for extension in (".manifest.json", ".manifest.sig")),
            "Supply the separately trusted public key for a signed distribution or explicitly allow an unsigned preview")
    sidecar = read_bounded(Path(f"{archive}.sha256"), 4096).decode("ascii").splitlines()
    output = args.output.absolute() if args.output is not None else None
    parent = output.parent if output is not None else installation_temp_parent()
    with tempfile.TemporaryDirectory(prefix="verified MXC 安装 ", dir=parent) as directory:
        staging = Path(directory)
        protect_install_root(staging)
        with tempfile.TemporaryFile(dir=staging) as snapshot:
            observed = archive_digest(archive, copy=snapshot)
            sha = observed["sha256"]
            require(sidecar == [f"{sha}  {archive.name}"], "Archive SHA-256 sidecar does not match")
            snapshot.seek(0)
            root = staging / "cohort"
            root.mkdir(mode=0o700)
            extract(archive, args.rid, root, source=snapshot)
        result = verify(root, args.rid, args.commit, distribution="unsigned-development-preview")
        if output is not None:
            protect_install_root(root)
            expose_installation(root, output)
            result["installRoot"] = str(output)
    return {**result, "archiveSha256": sha, "authentication": "unsigned-development-preview"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rid", choices=NATIVE, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--commit", help="expected package source commit")
    parser.add_argument("--tree", help="expected signed package source tree")
    trust = parser.add_mutually_exclusive_group()
    trust.add_argument("--trusted-key", type=Path, help="separately trusted Ed25519 PEM public key")
    trust.add_argument("--allow-unsigned-preview", action="store_true", help="verify an unsigned development preview")
    parser.add_argument("--allow-candidate", action="store_true", help="allow a signed test candidate")
    parser.add_argument("--admitted-archive-sha256", help="independently admitted archive digest, required for main")
    parser.add_argument("--openssl", type=Path, help="explicit trusted OpenSSL executable")
    parser.add_argument("--powershell", type=Path, help="explicit trusted PowerShell executable for Windows install protection")
    parser.add_argument("--output", type=Path, help="retain the verified extraction in a fresh trusted directory")
    try:
        args = parser.parse_args()
        require(args.powershell is None or (os.name == "nt" and args.powershell.is_absolute() and args.trusted_key is not None),
                "Windows PowerShell selection requires an absolute executable for a signed installation")
        result = check_signed(args) if args.trusted_key is not None else check_unsigned(args)
        print(json.dumps(result), flush=True)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError) as error:
        parser.exit(1, f"Package verification failed: {error}\n")


if __name__ == "__main__":
    main()
