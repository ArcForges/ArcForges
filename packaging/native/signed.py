#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Authenticate the exact bytes of a detached ArcForges distribution envelope."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

MAX_MANIFEST = 64 * 1024
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_KEY = 8192
SIGNATURE_SIZE = 64
ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
NODE_REPO = "ArcForges/ArcForges"
ARCHIVE_NAMES = {"win-x64": "arcforges-win-x64.zip", "linux-x64": "arcforges-linux-x64.tar.gz"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    result = dict(pairs)
    require(len(pairs) == len(result), "Unexpected duplicate JSON property")
    return result


def json_object(raw):
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    require(isinstance(document, dict), "Expected a UTF-8 JSON object")
    return document


def json_bytes(document):
    return (json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def regular_input(path):
    require(stat.S_ISREG(path.lstat().st_mode), "Expected a regular input file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    source = os.fdopen(os.open(path, flags), "rb")
    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
        source.close()
        raise ValueError("Expected a regular input file")
    return source


def read_bounded(path, maximum):
    with regular_input(path) as source:
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum, "Distribution input exceeds its size limit")
    return raw


def host_rid():
    if sys.platform == "win32":
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.WORD)]
        kernel.IsWow64Process2.restype = wintypes.BOOL
        process = wintypes.WORD()
        native = wintypes.WORD()
        require(kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(native)),
                "Could not identify the native Windows architecture")
        return "win-x64" if native.value == 0x8664 and process.value == 0 else None
    return "linux-x64" if sys.platform.startswith("linux") and os.uname().machine == "x86_64" else None


def openssl_path(value):
    if value is not None:
        return value.resolve(strict=True)
    if sys.platform == "win32":
        return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "usr" / "bin" / "openssl.exe"
    return Path("/usr/bin/openssl")


def openssl(executable, *arguments, input_bytes=None):
    result = subprocess.run([str(executable), *map(str, arguments)],
                            input=b"" if input_bytes is None else input_bytes, capture_output=True, timeout=30,
                            check=False)
    require(result.returncode == 0, "OpenSSL rejected the Ed25519 distribution operation")
    return result.stdout


def public_key(executable, path):
    supplied = read_bounded(path, MAX_KEY)
    require(supplied.startswith(b"-----BEGIN PUBLIC KEY-----"), "Requires a trusted PEM SubjectPublicKeyInfo key")
    der = openssl(executable, "pkey", "-pubin", "-inform", "PEM", "-pubout", "-outform", "DER", input_bytes=supplied)
    require(der.startswith(ED25519_SPKI) and len(der) == len(ED25519_SPKI) + 32,
            "Distribution trust key must be Ed25519")
    return der


def verify_signature(executable, trust_key, raw, signature):
    require(0 < len(raw) <= MAX_MANIFEST and len(signature) == SIGNATURE_SIZE, "Invalid detached manifest or signature size")
    with tempfile.TemporaryDirectory(prefix="arcforges-signature-") as directory:
        root = Path(directory)
        (root / "key.der").write_bytes(trust_key)
        (root / "manifest").write_bytes(raw)
        (root / "signature").write_bytes(signature)
        openssl(executable, "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", root / "key.der",
                "-in", root / "manifest", "-sigfile", root / "signature")


def envelope(archive, rid, raw, *, commit, tree, allow_candidate):
    manifest = json_object(raw)
    require(type(manifest.get("schema")) is int and manifest["schema"] == 1 and manifest.get("kind") == "node",
            "Expected the ArcForges Node distribution envelope")
    require(manifest.get("rid") == rid and ARCHIVE_NAMES.get(rid) == archive.name,
            "Signed distribution RID or archive name does not match")
    qualification = manifest.get("qualification")
    require(qualification == "main" or (qualification == "candidate" and allow_candidate),
            "Candidate distribution requires explicit admission")
    info = manifest.get("archive")
    require(isinstance(info, dict) and set(info) == {"name", "length", "sha256"} and info["name"] == archive.name
            and type(info["length"]) is int and 0 < info["length"] <= MAX_ARCHIVE
            and isinstance(info["sha256"], str) and SHA256.fullmatch(info["sha256"]), "Invalid signed archive identity")
    producers = manifest.get("producers")
    require(isinstance(producers, list) and len(producers) == 1 and isinstance(producers[0], dict),
            "Expected exactly one signed Node producer")
    producer = producers[0]
    require(set(producer) == {"repo", "commit", "tree"} and producer["repo"] == NODE_REPO
            and all(isinstance(producer[key], str) and COMMIT.fullmatch(producer[key]) for key in ("commit", "tree")),
            "Invalid signed Node producer")
    require(commit is None or commit == producer["commit"], "Signed distribution source commit does not match")
    require(tree is None or tree == producer["tree"], "Signed distribution source tree does not match")
    for name in ("buildInfoSha256", "sbomSha256", "dependencyAdmissionSha256", "dependencyEvidenceSha256"):
        require(isinstance(manifest.get(name), str) and SHA256.fullmatch(manifest[name]), "Missing signed Node evidence")
    return manifest


def authenticate(archive, rid, key, executable, *, commit=None, tree=None, allow_candidate=False):
    require(host_rid() == rid, "The signed distribution requires the matching native x64 host")
    raw = read_bounded(Path(f"{archive}.manifest.json"), MAX_MANIFEST)
    signature = read_bounded(Path(f"{archive}.manifest.sig"), SIGNATURE_SIZE)
    trust = public_key(executable, key)
    verify_signature(executable, trust, raw, signature)
    return envelope(archive, rid, raw, commit=commit, tree=tree, allow_candidate=allow_candidate)


def archive_digest(archive, *, copy=None, length=MAX_ARCHIVE):
    digest = hashlib.sha256()
    read = 0
    with regular_input(archive) as source:
        while chunk := source.read(min(1024 * 1024, length - read + 1)):
            read += len(chunk)
            require(read <= length, "Distribution archive exceeds its allowed length")
            digest.update(chunk)
            if copy is not None:
                copy.write(chunk)
    return {"name": archive.name, "length": read, "sha256": digest.hexdigest()}


def seal(archive, executable, private_key, trusted_key, manifest):
    trusted = public_key(executable, trusted_key)
    raw = json_bytes(manifest)
    with tempfile.TemporaryDirectory(prefix="arcforges-signing-input-") as directory:
        manifest_file = Path(directory) / "manifest"
        manifest_file.write_bytes(raw)
        signature = openssl(executable, "pkeyutl", "-sign", "-rawin", "-inkey", private_key.resolve(strict=True),
                            "-in", manifest_file)
    verify_signature(executable, trusted, raw, signature)
    signature_file = Path(f"{archive}.manifest.sig")
    with signature_file.open("xb") as result:
        result.write(signature)
    try:
        with Path(f"{archive}.manifest.json").open("xb") as result:
            result.write(raw)
    except OSError:
        signature_file.unlink()
        raise
