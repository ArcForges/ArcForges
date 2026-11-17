# Windows composed-profile experiment

This is the AFV2-MXC-02 native experiment, not an admitted product runtime. Keep the existing product executors and data/recovery guards. Use the official cohort selected by `eng/mxc/stage.py`; every invocation verifies its manifest before execution.

Run the published probe on the designated native Windows host:

```powershell
& './artifacts/mxc-02/install/arcforges-mxc-probe.exe' --windows-profile --manifest './artifacts/mxc-02/install/mxc-manifest.json' --work './artifacts/mxc-02/fresh-run' --report './artifacts/mxc-02/fresh-report.json'
```

The stage, workspace and report above are examples: use the actual verified stage and new workspace/report paths. Existing evidence must not be overwritten. For a targeted diagnosis, append `--only terminal`, `resource`, `policy`, `network`, `lifecycle`, `combined`, or `cli`. These selections always remain partial. Exit 2 means the executed slice passed while qualification remains partial; exit 1 means an experiment or its setup failed. Neither grants product admission.

## Diagnostics and cleanup

Implement diagnostics with the operation, including setup before the first case. The report preserves the primary failure, original cause/native code, bounded stage details and separate cleanup/evidence failures. Diagnose those facts before changing code or rerunning a failed operation. Private per-case records contain native Job/identity observations, owner transitions, policy hashes and terminal traces. Workload events remain untrusted fixture observations; stdout cannot establish backend state, exit provenance or cleanup.

Never publish the private owner configuration or capability keys. Public evidence should name the exact source/stage/report hashes and relevant bounded observations. Intentionally supplied arguments visible to the trusted local owner are permitted by the Plan's local-process boundary.

Loader failures return their real status without a desktop error dialog through a process-local error mode. This changes no system setting. The explicit UI policy allows Win32k for the Native AOT console fixture while retaining the configured clipboard/injection restrictions. The background owner is detached from a parent console and creates a separate workload ConPTY. Do not replace exact native-empty checks with a root-exit assumption.

## Controlled network peer

The trusted driver uses the existing native OpenSSH client and `ssh netcup` to control a bounded test peer on designated H-22. The installed Python and read-only iproute2 queries locate its unique default-route interface and assigned global IPv4; SSH's control address may be loopback and is not the data address. TCP/UDP test data travels directly to the owned listeners, not through an SSH tunnel. The payload receives no SSH credentials. Peer protocol/source identity, external receive counts and acknowledged cleanup remain distinct from payload observations.

Do not install helpers or modify firewall, routing or proxy settings. The peer has a hard lifetime and EOF cleanup. A failed ordinary-host calibration means the data-path prerequisite is unproven; it is not evidence that MXC denied a payload which never ran. Preserve the precise phase, original error and before/after external counts.

Current author evidence includes passing terminal/resource scenarios, policy slice 10 (12 cases), lifecycle slice 11 (14 cases), real named IPC/build fixtures and the default-deny combination. Full qualification is still incomplete: Windows-to-H-22 data-path calibration has not reached the peer, although the same peer's native H-22 TCP/UDP self-check passes. Consult the current Plan ledger/handoff for exact revisions, original failures and the next step. No formal merge status or full-profile pass is implied by these partial results.
