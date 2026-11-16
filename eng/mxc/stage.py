#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Stage the bounded AFV2-MXC-01 probe from exact, independently downloaded artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

VERSION = "1.0.1"
SOURCE = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
PACKAGE = "d47b1f70c3fcaaed1705a0c3872807e2878fe8c1b778c0dd9eb9325bf421a672"
RELEASE = "0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9"
LICENSE = "d9a1b1e30d633d5732ea18e3cba9538d293ebc53e1a9e4e96ab739e0c5c4f1cb"
SBOM = "c759a523c07772c869e14c5afc0a69a1bcd178d656aab368982ca4f5a3b2e1bb"
NATIVE = {
    "win-x64": {
        "mxc_ffi.dll": "bd45522f06dc9cc8001dcd5d7320bc2bf303fb08a39bf10f3404bd9a8001812c",
        "plm.exe": "beffc9c9ab974ca9e7455089fd8ecb36eb8c92811ddd1705db91370a689692c3",
        "wslcsdk.dll": "8d4d55d4283fb32a5909b57e78b576d01363d7b28bb9b2595115e80faf61db5b",
        "wxc-wslc-daemon.exe": "84f61c1bc13abde8da1c3f2ff100e6d59368ecaabdbfeca939e6fdb696202d0c",
        "wxc-exec.exe": "090f5d1f7bb93104ab08dcd4e8034ef954aeefcdaf6658dde5f7dff4cfc12f3a",
    },
    "linux-x64": {"libmxc_ffi.so": "18a1cba8f2980af79570141c4eec9cd3982872162ae6b63634d45862913002bc"},
}


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked(data, expected, name):
    require(hashlib.sha256(data).hexdigest() == expected, "Artifact mismatch: " + name)
    return data


def signatures(directory, names):
    require(os.name == "nt", "Windows staging requires actual Windows Authenticode verification")
    # Paths travel in an environment value, never in interpolated shell code.
    env = os.environ.copy()
    env["AFV2_MXC_SIGNATURE_INPUT"] = json.dumps([str(directory / name) for name in names])
    script = r"""$ErrorActionPreference='Stop'; $items=@(ConvertFrom-Json $env:AFV2_MXC_SIGNATURE_INPUT | ForEach-Object {
      $s=Get-AuthenticodeSignature -LiteralPath $_
      [pscustomobject]@{file=[IO.Path]::GetFileName($_);status=$s.Status.ToString();subject=$s.SignerCertificate.Subject;thumbprint=$s.SignerCertificate.Thumbprint}
    }); ConvertTo-Json -Depth 4 -InputObject $items"""
    result = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script], env=env, text=True, capture_output=True, check=True)
    receipt = json.loads(result.stdout)
    require(len(receipt) == len(names) and all(x["status"] == "Valid" and "O=Microsoft Corporation" in x["subject"] for x in receipt), "Official Windows unit signature verification failed")
    return receipt


def stage(args):
    require(digest(args.package) == PACKAGE, "NuGet package digest mismatch")
    require(digest(args.release) == RELEASE, "Official release ZIP digest mismatch")
    output = args.output.resolve()
    require(not output.exists(), "Output already exists; use a fresh private staging path")
    publish = args.publish.resolve()
    executable = "arcforges-mxc-probe" + (".exe" if args.rid == "win-x64" else "")
    symbols = {executable + ".dbg", "arcforges-mxc-probe.dbg", "arcforges-mxc-probe.pdb"}
    allowed = {executable} | symbols | set(NATIVE[args.rid])
    require(all(x.is_file() and not x.is_symlink() and x.name in allowed for x in publish.iterdir()), "Unexpected publish output; do not ship stale or unreviewed files")
    own = publish / executable
    require(own.is_file() and own.read_bytes()[:2 if args.rid == "win-x64" else 4] == (b"MZ" if args.rid == "win-x64" else b"\x7fELF"), "Native AOT executable missing/invalid")
    payload = {executable: own.read_bytes()}
    for name in sorted(symbols):
        if (publish / name).is_file():
            payload[name] = (publish / name).read_bytes()
    with zipfile.ZipFile(args.package) as package, zipfile.ZipFile(args.release) as release:
        payload["mxc.LICENSE.md"] = checked(package.read("LICENSE.md"), LICENSE, "MIT license")
        payload["mxc-release.spdx.json"] = checked(release.read("x64/_manifest/spdx_2.2/manifest.spdx.json"), SBOM, "upstream SPDX")
        require(release.read("x64/_manifest/spdx_2.2/manifest.spdx.json.sha256").decode().strip().lower() == SBOM, "Bundled SPDX digest mismatch")
        for name, expected in NATIVE[args.rid].items():
            data = checked(release.read("x64/" + name), expected, name)
            if name != "wxc-exec.exe":
                checked(package.read("runtimes/" + args.rid + "/native/" + name), expected, "NuGet " + name)
                require((publish / name).is_file() and digest(publish / name) == expected, "Publish native unit is missing/incoherent: " + name)
            payload[name] = data
    output.mkdir(parents=True)
    for name, data in payload.items():
        (output / name).write_bytes(data)
    if args.rid == "linux-x64":
        (output / executable).chmod(0o755)
    else:
        receipt = signatures(output, list(NATIVE[args.rid]))
        (output / "windows-signatures.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    files = [{"path": x.name, "sha256": digest(x)} for x in sorted(output.iterdir())]
    manifest = {"version": VERSION, "schema": "1.0.0", "rid": args.rid, "source": SOURCE,
                "packageSha256": PACKAGE, "releaseSha256": RELEASE, "files": files,
                "purpose": "isolated admission experiment; not a product package",
                "license": "MIT LICENSE.md from exact official package; upstream supplies no additional third-party notice",
                "sbom": "unchanged official SPDX inventory; NOASSERTION is not an independent license assertion"}
    (output / "mxc-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"stage": str(output), "manifestSha256": digest(output / "mxc-manifest.json"), "files": len(files), "rid": args.rid}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rid", required=True, choices=NATIVE)
    for name in ("package", "release", "publish", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    stage(parser.parse_args())


if __name__ == "__main__":
    main()
