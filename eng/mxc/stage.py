#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Stage the MXC admission probe or the shipped Run supervisor with the pinned official runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

REPOSITORY = Path(__file__).resolve().parents[2]
VERSION = "1.0.1"
SCHEMA = "1.0.0"
SOURCE = "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2"
PACKAGE = "d47b1f70c3fcaaed1705a0c3872807e2878fe8c1b778c0dd9eb9325bf421a672"
RELEASE = "0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9"
RELEASE_NAME = "mxc-release-binaries.zip"
RELEASE_URL = f"https://github.com/microsoft/mxc/releases/download/v{VERSION}/{RELEASE_NAME}"
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
SUPERVISOR_PROJECT_SYMBOLS = {
    "ArcForges.Node.Platform.Linux.pdb",
    "ArcForges.Node.Platform.pdb",
    "ArcForges.Node.Platform.Windows.pdb",
    "ArcForges.RunSupervisor.Protocol.pdb",
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


def run_supervisor_name(rid):
    return "arcforges-run-supervisor.exe" if rid == "win-x64" else "arcforges-run-supervisor"


def is_x64_image(data, rid):
    if rid == "win-x64":
        if len(data) < 64 or data[:2] != b"MZ":
            return False
        pe = int.from_bytes(data[0x3c:0x40], "little")
        return pe >= 64 and data[pe:pe + 6] == b"PE\x00\x00\x64\x86"
    return len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01" and data[18:20] == b"\x3e\x00"


def restored_package():
    assets_path = REPOSITORY / "src" / "ArcForges.RunSupervisor" / "obj" / "project.assets.json"
    require(assets_path.is_file(), "Run supervisor restore is missing; run the locked solution restore before packaging")
    assets = json.loads(assets_path.read_text(encoding="utf-8"))
    library = assets["libraries"].get(f"Microsoft.Mxc.Sdk/{VERSION}")
    require(library is not None and library["type"] == "package", f"Run supervisor restore must include Microsoft.Mxc.Sdk {VERSION}")
    for folder in assets["packageFolders"]:
        package = Path(folder) / library["path"] / f"microsoft.mxc.sdk.{VERSION}.nupkg"
        if package.is_file():
            return package
    raise ValueError("Exact restored Microsoft.Mxc.Sdk nupkg is missing; pass --package with the pinned file")


def cached_release():
    configured = os.environ.get("ARCFORGES_MXC_RELEASE_ZIP")
    if configured:
        release = Path(configured)
    else:
        release = REPOSITORY / "artifacts" / "mxc" / "official" / RELEASE_NAME
    require(release.is_file(), f"Pinned MXC release ZIP missing at {release}. Supply --release or ARCFORGES_MXC_RELEASE_ZIP with {RELEASE_URL}")
    return release


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
    product = args.component == "run-supervisor"
    package_path = args.package or restored_package()
    release_path = args.release or cached_release()
    require(digest(package_path) == PACKAGE, "NuGet package digest mismatch")
    require(digest(release_path) == RELEASE, "Official release ZIP digest mismatch")
    if product:
        require(not args.publish.is_symlink() and not args.publish.is_junction(), "Run supervisor publish path must be a directory, not a link")
        require(not args.output.is_symlink() and not args.output.is_junction(), "Output must be a fresh private directory, not a link")
    output = args.output.resolve()
    require(not output.exists(), "Output already exists; use a fresh private staging path")
    publish = args.publish.resolve()
    executable = run_supervisor_name(args.rid) if product else "arcforges-mxc-probe" + (".exe" if args.rid == "win-x64" else "")
    stem = executable.removesuffix(".exe")
    symbols = {executable + ".dbg", stem + ".dbg", stem + ".pdb"}
    if product:
        # AOT publish may also emit symbols for the linked platform and protocol projects.
        symbols.update(SUPERVISOR_PROJECT_SYMBOLS)
    allowed = {executable} | symbols | set(NATIVE[args.rid])
    require(all(x.is_file() and not x.is_symlink() and not x.is_junction() and x.name in allowed for x in publish.iterdir()),
            "Unexpected publish output; do not ship stale or unreviewed files")
    own = publish / executable
    require(own.is_file(), "Native AOT executable missing/invalid")
    image = own.read_bytes()
    if product:
        require(is_x64_image(image, args.rid), f"Run supervisor is not a native x64 image for {args.rid}")
    else:
        magic = b"MZ" if args.rid == "win-x64" else b"\x7fELF"
        require(image.startswith(magic), "Native AOT executable missing/invalid")
    payload = {executable: image}
    if not product:
        for name in sorted(symbols):
            if (publish / name).is_file():
                payload[name] = (publish / name).read_bytes()
    with zipfile.ZipFile(package_path) as package, zipfile.ZipFile(release_path) as release:
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
        if product:
            output.chmod(0o755)
            for name in payload:
                (output / name).chmod(0o644)
        (output / executable).chmod(0o755)
    else:
        receipt = signatures(output, list(NATIVE[args.rid]))
        (output / "windows-signatures.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    files = [{"path": x.name, "sha256": digest(x)} for x in sorted(output.iterdir())]
    manifest = {"version": VERSION, "schema": SCHEMA, "rid": args.rid, "source": SOURCE,
                "packageSha256": PACKAGE, "releaseSha256": RELEASE, "files": files,
                "purpose": "protected Run supervisor and pinned official MXC runtime" if product else "isolated admission experiment; not a product package",
                "license": "MIT LICENSE.md from exact official package; upstream supplies no additional third-party notice",
                "sbom": "unchanged official SPDX inventory; NOASSERTION is not an independent license assertion"}
    manifest_path = output / "mxc-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if product and args.rid == "linux-x64":
        manifest_path.chmod(0o644)
    print(json.dumps({"stage": str(output), "manifestSha256": digest(manifest_path), "files": len(files), "rid": args.rid}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rid", required=True, choices=NATIVE)
    parser.add_argument("--component", choices=("probe", "run-supervisor"), default="probe")
    parser.add_argument("--package", type=Path)
    parser.add_argument("--release", type=Path)
    for name in ("publish", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    if args.component == "probe" and (args.package is None or args.release is None):
        parser.error("probe staging requires --package and --release")
    try:
        stage(args)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        parser.exit(1, f"MXC staging failed: {error}\n")


if __name__ == "__main__":
    main()
