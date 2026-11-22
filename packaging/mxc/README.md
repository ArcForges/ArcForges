# Packaging the pinned Run supervisor

The x64 Node/CLI archives include the Native AOT `arcforges-run-supervisor`
and the pinned official Microsoft MXC 1.0.1 files under `mxc/`. Both packagers
read the SDK archive from the Run supervisor's locked NuGet restore and check
the publish output against the official, SHA-256-pinned release. Windows
checks the Microsoft Authenticode signatures before sealing the archive.
The installed SDK, schema, artifact hashes and license/SBOM identities are
recorded in `mxc/mxc-manifest.json`. Signed MXC distributions use the
qualified Windows and Linux x64 cohorts.

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
python packaging/mxc/verify_install.py --allow-unsigned-preview --rid <x64-rid> --archive <archive> --commit <commit> --output <fresh-install>
```

## Build and verify a signed Node distribution

The commands above produce an unsigned development preview. Signed packaging
uses a clean checkout, a complete native Release publish with the pinned .NET
SDK, locked dependency restores and the pinned MXC files described above.
Provide the existing Ed25519 signing key in PEM and the separately trusted
public key in PEM SubjectPublicKeyInfo format. Keep the signing key outside the
checkout and package. The installed verification tool uses OpenSSL 3 with
Ed25519 support. Its default paths are `C:\Program Files\Git\usr\bin\openssl.exe`
on Windows and `/usr/bin/openssl` on Linux. An operator can supply an explicit
trusted executable with `-OpenSsl` or `--openssl`.

```powershell
dotnet restore ArcForges.slnx --locked-mode
./eng/publish.ps1 -RuntimeIdentifier win-x64 -Component host,supervisor,run-supervisor -NoRestore -RecordDistribution
./eng/package.ps1 -RuntimeIdentifier win-x64 -SigningKey <private-pem> -TrustedKey <public-pem> -Qualification main -ContractsRepo <contracts-repo> -DesktopPlatformRepo <desktop-platform-repo>
```

```sh
dotnet restore ArcForges.slnx --locked-mode
python eng/verify_linux.py publish --record-distribution host,run-supervisor
python eng/verify_linux.py package --signing-key <private-pem> --trusted-key <public-pem> --qualification main --contracts-repo <contracts-repo> --desktop-platform-repo <desktop-platform-repo>
```

For `main` qualification, fetch the canonical Node, Contracts and
DesktopPlatform repositories before packaging. The packager checks the
Node commit and the locked first-party publishing commits against the actual
local `origin/main` histories. It verifies the restored signed NuGet packages
with the pinned SDK, compares their content hashes to the committed locks
and checks the source dependency admission, including the denied versions.
The archive contains the signed cohort's SPDX SBOM, native build receipt
and dependency proof. For a temporary signed test build, select
`candidate` and use the corresponding independently supplied test public key.

The archive, its `.manifest.json` and its raw 64-byte `.manifest.sig`
are written together under a fresh signed package directory. The signature
covers the exact UTF-8 manifest bytes, which bind the archive filename,
length and SHA-256, Node source commit/tree, qualification, and evidence
digests. Supply the trust key from the operator's trusted distribution
configuration when downloading and installing the cohort. For a signed
`main` install, separately obtain its exact approved archive SHA-256 from
the release's admission record. The packager seals the cohort for that
review and the operator performs the installation separately.

```text
python packaging/mxc/verify_install.py --rid <x64-rid> --archive <archive> --trusted-key <public-pem> --admitted-archive-sha256 <approved-sha256> --commit <commit> --tree <tree> --output <fresh-install>
```

Use `--allow-candidate` for a signed test candidate when the release admission
record does not apply. The verifier
authenticates the envelope and checks the archive bytes before opening
archive members, and it checks the binaries and pinned MXC components
before making the new installation directory available. The parent directory
must already exist and be trusted by the operator. This command prepares
an installed directory for a fresh launch.

## Update an installed Node

Run the `update` command from an independently authenticated installed cohort
that includes the updater. Obtain the replacement archive and its detached
signature, the Ed25519 public key, and the exact archive, commit, and tree
identities through the release admission process. The updater uses the fixed
installer bundled with that installed cohort. Provide absolute paths to trusted
Python and OpenSSL executables, plus PowerShell on Windows. These tools are used
for archive preparation. Ordinary Node startup and Run supervision use the
native executables.

```text
arcforges update apply --archive <archive> --trusted-key <public-pem> --archive-sha256 <approved-sha256> --commit <commit> --tree <tree> --python <python-executable> --openssl <openssl-executable>
```

On Windows append `--powershell <powershell-executable>`. When adopting an
independently admitted prior cohort, also supply `--previous-archive`,
`--previous-archive-sha256`, `--previous-commit`, and `--previous-tree` together.
When its original admission uses a different public key, also supply
`--previous-trusted-key <previous-public-pem>`.
The updater verifies and retains the exact prior installation. Before adopting
a predecessor that lacks the durable update protocol, establish its managed
selection and confirm that its existing platform service runs from it. The
Linux systemd user unit must use the managed `app/current` selection. The
Windows managed holder and startup registration resolve to the admitted
version directory. Portable installations can use the independently
authenticated offline migration and a fresh managed installation.

`arcforges update status --json` reports the selected version and saved update
checkpoint. An original service can still accept Run requests in
`PreparingPredecessor` until it is stopped and its managed startup is guarded.
Stop any Run that remains active through the original service, then use
`arcforges update resume`. Use `arcforges update rollback` to restart the
authenticated compatible predecessor. Rollback requires a complete Run drain
and the original compatible reader floor. To prepare a verified offline restore, run
`arcforges update restore --destination <fresh-absolute-directory>`. The
receipt identifies the isolated store and authority files that were restored.
The active Node data directory and its selection remain in place. Private
Sandbox contents stored outside the backup require a separately verified copy.
