# Windows composed profile experiment (AFV2-MXC-02)

This directory documents the bounded `windows-process-executor-v1` experiment.
It does not switch the Node runtime or retire its existing execution/data guards.
Use the admitted Microsoft.Mxc.Sdk 1.0.1, schema 1.0.0 and unchanged official
Windows native unit described in [the staging instructions](../README.md).

Publish the probe with the selected .NET/VS toolchain, then create a **new**
private stage using `eng/mxc/stage.py`. The additional native entry point is:

```text
<stage>/arcforges-mxc-probe.exe --windows-profile --manifest <stage>/mxc-manifest.json --work <fresh-owned-workspace> --report <fresh-outside-stage-report.json> --source <exact-source-sha> --design <design-baseline-sha> --plan <plan-baseline-sha>
```

The full profile verifies its embedded source identity, stage members and exact
required case set before it can return exit0 with `QualificationPassed=true`.
Every required case must pass with its applicable native cleanup confirmed.
The Design/Plan SHA fields identify the coordinator's explicit baselines; the
probe does not claim to fetch or verify remote Git state itself. Exit1 preserves
failure or incomplete qualification. A targeted invocation uses the original
manifest/work/report arguments plus `--only <group>`; it always remains partial
and returns2 for successful diagnostic cases, never full qualification.
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
