# Packaging the pinned Run supervisor

The x64 Node/CLI archives include the Native AOT `arcforges-run-supervisor`
and the pinned official Microsoft MXC 1.0.1 files under `mxc/`. Both packagers
read the SDK archive from the Run supervisor's locked NuGet restore and check
the publish output against the official, SHA-256-pinned release. Windows
checks the Microsoft Authenticode signatures before sealing the archive.
The installed SDK, schema, artifact hashes and license/SBOM identities are
recorded in `mxc/mxc-manifest.json`. The ARM64 builds retain the V1 layout.

Place the [official release ZIP](https://github.com/microsoft/mxc/releases/download/v1.0.1/mxc-release-binaries.zip)
at `artifacts/mxc/official/mxc-release-binaries.zip`, or set the build-time
`ARCFORGES_MXC_RELEASE_ZIP` to its absolute path. Either packager can also
take the ZIP as an explicit argument. The same archive and member checks
apply to every input path.

```powershell
./eng/publish.ps1 -RuntimeIdentifier win-x64
./eng/package.ps1 -RuntimeIdentifier win-x64 -MxcReleaseZip <official-zip>
```

```sh
python eng/verify_linux.py publish host,run-supervisor,bench testload
python eng/verify_linux.py package --mxc-release-zip <official-zip>
```

To retain an independently verified extraction, run the following with a new
output directory under a trusted parent. The designated-host package tests
use a fresh directory below `%LOCALAPPDATA%/Temp` on Windows or the owner's
home directory on Linux. The extractor protects each new root before writing
the package files. Omit `--output` for a temporary extraction.

```text
python packaging/mxc/verify_install.py --rid <x64-rid> --archive <archive> --commit <commit> --output <fresh-install>
```
