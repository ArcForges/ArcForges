# MXC 1.0.1 admission probe (AFV2-MXC-01)

This isolated development tool implements MXC-AOT-01. It does not add MXC to
the Node/CLI, qualify the Windows ConPTY or Linux cgroup combinations, install
host prerequisites, or produce a product distribution. Only native win-x64
and linux-x64 are candidates; other RIDs are unqualified.

The pin is Microsoft.Mxc.Sdk **1.0.1**, schema **1.0.0**, upstream source
`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`. A newer upstream release does not
change this reviewed pin. Independently download on each designated host:

- [NuGet package](https://api.nuget.org/v3-flatcontainer/microsoft.mxc.sdk/1.0.1/microsoft.mxc.sdk.1.0.1.nupkg), SHA256 `d47b1f70c3fcaaed1705a0c3872807e2878fe8c1b778c0dd9eb9325bf421a672`.
- [Official ZIP](https://github.com/microsoft/mxc/releases/download/v1.0.1/mxc-release-binaries.zip), SHA256 `0e832239454ba7fcd338ff56218a287eef4c0a01c1484084b869f55feff8abe9`.

`stage.py` checks those digests, every selected native member, coherent NuGet
and published native files, exact output membership, and the upstream SPDX
digest. It requires a new output directory and never repairs/deletes an
existing installation. Windows staging verifies actual Authenticode `Valid`
and Microsoft Corporation on all five selected native files. Keep that
same-host receipt. Linux uses only the official `libmxc_ffi.so`; Windows keeps
the entire four-file NuGet native unit and unchanged ZIP `wxc-exec.exe`.
Optional WSLC files are preserved as packaged sidecars, not exercised backends.

The exact package supplies MIT `LICENSE.md` (retained as `mxc.LICENSE.md`). The
official source/package supplies no additional third-party notice. The exact
release's unchanged SPDX 2.2 inventory is retained as `mxc-release.spdx.json`;
its `NOASSERTION` entries are not independent license assertions. This is the
supplied upstream distribution evidence, not a new claim about every inventory
package or the later product distribution task.

Publish on the actual target OS using the repository's installed toolchain:

```text
dotnet restore tools/ArcForges.MxcProbe/ArcForges.MxcProbe.csproj --locked-mode -r <rid>
dotnet publish tools/ArcForges.MxcProbe/ArcForges.MxcProbe.csproj -c Release -r <rid> --no-restore -o <new-publish-directory> -warnaserror -tl:off -clp:Summary;ForceNoAlign -p:TrimmerSingleWarn=false
python eng/mxc/stage.py --rid <rid> --package <nupkg> --release <zip> --publish <publish-directory> --output <new-private-install-with-spaces-and-Unicode>
<install>/arcforges-mxc-probe[.exe] --manifest <install>/mxc-manifest.json --work <new-fixture-with-spaces-and-Unicode> --report <outside-install>/report.json
```

Use the existing native tool selector on Linux and the existing VS developer
environment on Windows, as for `eng/publish.ps1`. Require zero build, trim and
AOT warnings. The executable runs without a .NET SDK/JIT. Do not set
`MXC_FFI_DIR`, `MXC_FORCE_TIER`, or native loader overrides. The probe rejects
them and validates the complete private installation **before** calling any
SDK/native function. Evidence and mutable fixture files stay outside it.

Public native version/support/backend discovery is real. Linux selects typed
V1 Bubblewrap, default-denied egress/ingress, and `Telemetry.Enabled=false` for
each invocation. It executes distinct pipe/stdout/stderr, real PTY (`test -t`),
and kill/wait cases, checking the returned PID is absent after native wait.
The host must already support user namespaces and Bubblewrap; no helper is
installed and no networking/firewall/sysctl is changed. Network-enabled
profiles and stronger resource/terminal cases belong to AFV2-MXC-03.

Windows uses real SDK discovery and the unchanged signed official executor,
an absolute application path, private schema JSON, empty child PATH,
`fallback.allowDaclMutation=false`, nonempty private-control deny, and an
owner-only control directory outside grants. The small **nonterminal** launcher
creates the executor suspended, uses an exact stdio handle allowlist, assigns
and reads back an owned kill-on-close Job before resume, waits the process
handle, and requires zero active Job processes. The official executor's exit
is labelled `official_executor`; its payload marker is supplementary and is
not proof of isolation or a trusted payload start identity. ConPTY/profile
composition remains AFV2-MXC-02; no terminal claim is made here.

Reports contain phase timings and process/resource cleanup observations.
Record same-host cold/warm startup and idle observations with their context;
these are bounded experiment measurements, not product performance promises.
Run noninteractively in the intended service context and preserve the actual
identity/resource scope. No Center/account/subscription is used. The synthetic
secret in request environment must not occur in logs or executor argv; the
only executor arguments are `--config` and the private policy path. Never use
real credentials in these fixtures.

For negative cases, make separate owned staging copies, remove one required
native file or change the recorded version/schema, then invoke the same
executable with new work/report paths. Require nonzero, `stageVerified=false`,
empty cases, and no fixture directory. Also add an unexpected file and try
`MXC_FFI_DIR`; both must reject before workload. Preserve each report and the
unchanged valid installation. Never modify a shared runtime or count a
deliberately invalid stage as a native success.
