# Windows composed-profile experiment

This is the AFV2-MXC-02 native experiment, not an admitted product runtime. Keep the existing product executors and data/recovery guards. Use the official cohort selected by `eng/mxc/stage.py`; every invocation verifies its manifest before execution.

Run the published probe on the designated native Windows host to qualify the wrapper:

```powershell
& './artifacts/mxc-02/install/arcforges-mxc-probe.exe' --windows-profile --manifest './artifacts/mxc-02/install/mxc-manifest.json' --work './artifacts/mxc-02/fresh-run' --report './artifacts/mxc-02/fresh-report.json' --source '<exact-source-sha>' --design '<design-baseline-sha>' --plan '<plan-baseline-sha>'
```

The default run executes 60 cases on this workstation. It collects 59 local cases and a combined run that verifies native terminal resize and replay, file access with persistence, live Job limits, owner reconnection, and cleanup. The combined run attempts TCP to a calibrated host-loopback listener while the resource fixture is active. The official executor uses default-deny egress without exceptions, denied ingress and denied host loopback. The local listener independently records its unchanged counters. The case receipt includes the applied policy hash, and its private observation identifies the host-loopback scope and counters.

The wrapper receipt records the first and subsequent native executor launches from `console-info` and `line-editing`. Their timings run from the start of executor launch through resume, including pre-resume Job checks, with the host cache in its existing state. The combined run records admission-to-console-ready timing separately. Its private observation also measures elapsed time and the owner's output-byte cursor delta between the replay reads around detach and reconnect.

Wrapper success exits 0 with `status=wrapper_passed`, `wrapperQualificationPassed=true` and `externalNetworkStatus=unverified`. The strict external profile runs when the command above ends in `--external`. It executes the original 68 cases and exits 0 with `qualificationPassed=true` and `externalNetworkStatus=verified` after all native outcomes, applicable cleanup, and stage and source identities are confirmed. The external status records whether that complete qualification exists. Each executed case records its actual outcome.

Use the verified stage and fresh workspace and report paths. For a targeted diagnosis, replace the source, design and plan arguments with `--only` and one of `local`, `terminal`, `resource`, `policy`, `network`, `lifecycle`, `combined`, or `cli`.

`--only local` includes the terminal, resource, policy, CLI and lifecycle groups and six host-loopback and inbound network cases. The `network` selection runs the six local cases followed by the seven external network cases. The `combined` selection runs the two external combined cases. Diagnostic slices report partial qualification and exit 2 when the selected cases pass. Any run with an experiment or setup failure exits 1. The receipt retains completed groups after a later failure.

## Diagnostics and cleanup

Implement diagnostics with the operation, including setup before the first case. The report preserves the primary failure, original cause/native code, bounded stage details and separate cleanup/evidence failures. Diagnose those facts before changing code or rerunning a failed operation. Private per-case records contain native Job/identity observations, owner transitions, policy hashes and terminal traces. Workload events remain untrusted fixture observations; stdout cannot establish backend state, exit provenance or cleanup.

Never publish the private owner configuration or capability keys. Public evidence should name the exact source/stage/report hashes and relevant bounded observations. Intentionally supplied arguments visible to the trusted local owner are permitted by the Plan's local-process boundary.

Loader failures return their real status without a desktop error dialog through a process-local error mode. This changes no system setting. The explicit UI policy allows Win32k for the Native AOT console fixture while retaining the configured clipboard/injection restrictions. The background owner is detached from a parent console and creates a separate workload ConPTY. Do not replace exact native-empty checks with a root-exit assumption.

The driver records its identity and immediate inherited Job context before
creating experimental Jobs. Inherited membership alone is not a rejection:
the cases must prove real suspended assignment, owned Job limits, descendants
and cleanup. Failed context queries cannot establish full qualification.
The immediate Job snapshot does not enumerate all external ancestors, and
an unknown ancestor CPU cap does not prove an exact whole-machine CPU share.
The event log marks when checks finish before publication. The process exit
and final receipt record the result after write, flush and close. A publication
failure retains a uniquely named pending file for diagnosis.

## Optional external network diagnosis

Current native result (2026-11-18): `network-resume-01` passed only8/13.
HostLoopback allow also allowed the five intended fine-egress deny cases;
matching replies and independent peer counters confirmed actual communication.
This local candidate therefore cannot qualify selected egress or the combined
profile. Preserve the failed receipt; do not repeat this setup expecting a
different policy result. The optional external profile uses a separate H22
network stack for fine-egress effects and uses SSH for peer control.

Before running the external profile, independently fetch the exact published commit
from GitHub on H22 into `/home/sammiller/arcforges/ArcForges/.worktree/mxc02-peer-<40-character-source-sha>`.
The trusted driver executes its committed `tools/ArcForges.MxcProbe/Windows/network_peer.py`
using the installed Python through `ssh netcup`. The source commit and script
hash must match the published driver's identity. No script body is transferred
through command arguments. The peer has bounded lifetime, independent receive
counters, explicit close acknowledgement and EOF cleanup. TCP and UDP share a
numeric port; another live TCP port and a nonmatching allow CIDR distinguish
the separate rule dimensions. SSH is not a payload data tunnel. No address,
host network, proxy or security setting is changed.

Fine-egress experiments keep host loopback denied. No-allow, wrong-IP,
wrong-port and wrong-protocol cases must fail against the calibrated live peer;
exact selectedTCP/UDP must succeed. The separate host-loopback and inbound
cases retain local controlled sockets to exercise those specific capabilities.
If policies cannot compose, qualification fails; there is no broader-policy
retry or inferred pass.

The default IPv4 calibration used the virtual interface and delivered no request
to the peer. An existing IPv6 route was then tried with exact `/128` policies,
but TCP connection establishment timed out before a payload ran. Both failures
remain original evidence; a route's existence is not a reachability pass.

The current IPv4 fixture selects the designated host's already observed physical
interface17 through `IP_UNICAST_IF` on each outgoing test socket. Calibration,
actual workload and combined scenarios share the same setting/readback; there is
no global route/proxy change, interface scan or fallback. Real socket endpoints
and peer counters still determine effects. The exact external `/32` rules and
separate local loopback/inbound policies remain unchanged. This fixture does not
claim that the earlier default paths passed or imply domain-name semantics.

The same controlled external peer implementation is used by both bounded combined scenarios. Actual memory
pressure and children must be ready before network/filesystem operations, with
external ordering/Job identity evidence. A successful set of old diagnostic
slices is not one same-head full qualification. Preserve historical remote-peer
calibration failures as earlier results; the retired H06 data-path prerequisite
is not a current requirement. Consult the Plan handoff for exact source/reports
and the current qualification result.
