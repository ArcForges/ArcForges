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

## Controlled network peer

The trusted driver owns real TCP/UDP sockets on127.0.0.1, outside the workload
ProcessContainer, with bounded calibration, independent receive counters and
cleanup. TCP and UDP share a numeric port to distinguish protocol permissions;
another live TCP port and a nonmatching allow CIDR test separate rule dimensions.
No SSH data tunnel, cross-host data probe, address installation or host
network/proxy/security setting change is used.

For local egress experiments the policy explicitly allows host loopback while
keeping default egress denied. That capability alone is not evidence of selected
egress enforcement: no-allow, wrong-IP, wrong-port and wrong-protocol cases must
still fail against a calibrated live peer; exact selectedTCP/UDP must succeed.
Separate host-loopback-deny cases retain the independent capability boundary,
and inbound cases remain separately reported. If these policies cannot compose,
qualification fails; there is no broader-policy retry or inferred pass.

The same local peer is used by both bounded combined scenarios. Actual memory
pressure and children must be ready before network/filesystem operations, with
external ordering/Job identity evidence. A successful set of old diagnostic
slices is not one same-head full qualification. Preserve historical remote-peer
calibration failures as earlier results; the retired H06 data-path prerequisite
is not a current requirement. Consult the Plan handoff for exact source/reports
and the current qualification result.
