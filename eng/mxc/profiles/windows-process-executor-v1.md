# Windows composed-profile experiment

This is the AFV2-MXC-02 native experiment, not an admitted product runtime. Keep the existing product executors and data/recovery guards. Use the official cohort selected by `eng/mxc/stage.py`; every invocation verifies its manifest before execution.

Run the published probe on the designated native Windows host:

```powershell
& './artifacts/mxc-02/install/arcforges-mxc-probe.exe' --windows-profile --manifest './artifacts/mxc-02/install/mxc-manifest.json' --work './artifacts/mxc-02/fresh-run' --report './artifacts/mxc-02/fresh-report.json' --source '<exact-source-sha>' --design '<design-baseline-sha>' --plan '<plan-baseline-sha>'
```

The stage, workspace and report above are examples: use the actual verified stage and new workspace/report paths. Existing evidence must not be overwritten. For a targeted diagnosis, omit the source/design/plan arguments and append `--only terminal`, `resource`, `policy`, `network`, `lifecycle`, `combined`, or `cli`. These selections always remain partial. Exit 2 means the executed slice passed while qualification remains partial; exit 1 means an experiment or its setup failed. Neither grants product admission. Full exit0 requires the exact required case set, all native outcomes and applicable cleanup, and unchanged verified stage/source identities; the later product-admission task remains separate.

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
Final receipts are published only after successful write, flush and close;
failed publication retains a uniquely named pending file for diagnosis.

## Controlled network peer

Current native result (2026-11-18): `network-resume-01` passed only8/13.
HostLoopback allow also allowed the five intended fine-egress deny cases;
matching replies and independent peer counters confirmed actual communication.
This local candidate therefore cannot qualify selected egress or the combined
profile. Preserve the failed receipt; do not repeat this setup expecting a
different policy result. The original WIN04/06 controlled-endpoint requirement
therefore uses the separate H22 network stack for fine-egress effects. SSH is
only the host execution/control transport; it does not add an acceptance or
owner-approval requirement.

Before running the exact published candidate, independently fetch that commit
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

The same controlled external peer implementation is used by both bounded combined scenarios. Actual memory
pressure and children must be ready before network/filesystem operations, with
external ordering/Job identity evidence. A successful set of old diagnostic
slices is not one same-head full qualification. Preserve historical remote-peer
calibration failures as earlier results; the retired H06 data-path prerequisite
is not a current requirement. Consult the Plan handoff for exact source/reports
and the current qualification result.
