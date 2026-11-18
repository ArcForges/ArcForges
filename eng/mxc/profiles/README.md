# Official MXC profile qualification

AFV2-MXC-04 admits the scoped Windows local and Linux Bubblewrap profiles using the original native composition receipts. The checked-in JSON files record the qualified identities and the scope of the native observations.

| Profile | Qualification | Scope |
| --- | --- | --- |
| [Windows ProcessContainer](windows-process-executor-v1.qualification.json) | 60/60 on DEKU at Node `da7f5bfcfe49` | Official executor, BaseContainer, ConPTY, outer Job, local policy and recovery. The composed default-deny observation is bounded to the calibrated host-loopback TCP peer. Explicit external selected TCP/UDP remains unverified. |
| [Linux Bubblewrap](linux-bubblewrap-sdk-v1.qualification.json) | 72/72 on H-22 at Node `50e602a83ece` | Official SDK, Bubblewrap, delegated systemd/cgroup v2 and PTY with the exercised filesystem, resource, recovery and network policies. Selected egress covers literal IPv4 TCP/UDP. The test observed DNS denial. |

A qualification record binds the official 1.0.1 cohort and schema 1.0.0, exact platform identity, required host prerequisites, and original probe evidence. The probe executable and stage manifest hashes identify historical evidence. The current trusted runtime must independently validate its protected installation and file identities. The C# admission policy pins the qualified record bytes. A changed cohort requires new composed evidence and a new pin. Update evidence and admission together when qualifying a new revision.

A capability's support and native observation are separate fields. Requests requiring unsupported constraints refuse before payload launch. Windows external selected egress keeps the explicit supported rule when the request permits unverified behavior. Native rejection still applies. Native diagnostics establish whether required prerequisites and cleanup are available for a specific attempt. A missing prerequisite or unmatched qualification refuses the profile without a weaker fallback.

## Windows composed profile experiment (AFV2-MXC-02)

This directory documents the bounded `windows-process-executor-v1` experiment.
It does not switch the Node runtime or retire its existing execution/data guards.
Use the admitted Microsoft.Mxc.Sdk 1.0.1, schema 1.0.0 and unchanged official
Windows native unit described in [the staging instructions](../README.md).

Publish the probe with the selected .NET/VS toolchain, then create a **new**
private stage using `eng/mxc/stage.py`. The additional native entry point is:

```text
<stage>/arcforges-mxc-probe.exe --windows-profile --manifest <stage>/mxc-manifest.json --work <fresh-owned-workspace> --report <fresh-outside-stage-report.json> --source <exact-source-sha> --design <design-baseline-sha> --plan <plan-baseline-sha>
```

The default native Windows entry point qualifies the wrapper using 60 local
cases. It verifies the embedded source identity, stage members, exact case set,
and native cleanup. Wrapper success exits 0 with `wrapperQualificationPassed=true`
and `externalNetworkStatus=unverified`. Append `--external` to select the strict
68-case profile. That profile exits 0 with `qualificationPassed=true` after
validating the original external network cases and composed workload.
The Design and Plan SHAs identify the coordinator's selected baselines.
Exit 1 records failure or incomplete qualification. A targeted invocation
uses the manifest, work and report arguments plus `--only <group>`. Successful
diagnostic slices exit 2 with partial qualification.
No compiler success or pipe output substitutes for actual console APIs, composed
resource enforcement or owner-loss evidence. See [the detailed profile](windows-process-executor-v1.md).

The explicit CLI profile permits Win32k initialization (`ui.disable:false`) and
retains `clipboard:none` and `injection:false`. Disabling Win32k made the Native
AOT fixture fail in the Windows loader with `0xc0000142` before entering managed
code. A same-policy bounded comparison established this startup dependency; it
was not a terminal qualification. This profile makes no GUI product claim.
Filesystem grants/private-control denial, no DACL fallback, clean environment,
network rules and resource controls are independent and remain enforced.

Windows probe roles set process-local error-mode flags to return critical startup
and crash failures instead of displaying interactive error dialogs. Children
inherit the mode; no machine/registry/network/security setting changes. Original
exit codes and failure results remain failures. The contained fixture's emitted
JSON and terminal bytes are untrusted, including deliberately forged errors.

Private owner configs contain short-lived authentication material. Never export
those files, terminal transcripts or complete owner protocol messages to public
records. Shared reports contain allowlisted outcomes, identities, counts and
hashes. A cleanup error is distinct from a primary execution error; unresolved
ownership retains its evidence and cannot become a success or deletion proof.

Only test-owned paths/scopes may be cleaned, after native emptiness is established.
The detached owner is an experimental same-user background process; it is not an
SCM service or an already delivered product RunSupervisor. Its external holder is
a test guardian, distinct from the simulated reconnecting Node/client.

## Admission regression and native refusals

Run `python eng/mxc/profiles/tests/run.py --stage <original-verified-stage>` on each native host. The runner compiles the production admission classes with the selected .NET SDK and reads the measured OS and native artifact identities from the host and the protected original stage. It exercises missing and mismatched evidence, reduced assurance and an actual absent prerequisite path in a fresh private fixture. The evaluation runs without starting an MXC workload. The original composed runs supply the native execution and cleanup evidence.
