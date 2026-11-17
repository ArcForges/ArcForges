# Linux Bubblewrap qualification experiments

AFV2-MXC-03 develops the five native Linux protocols in Design
`docs/verification/mxc-experiments.md`. This is an experimental probe, not the
Node runtime or a qualified product profile. A successful diagnostic slice
does not establish the full terminal/resource/filesystem/network/recovery
combination. Keep every original failed report and its event log.

Use the designated native H-22 host, through the owner's existing `ssh netcup`.
Push the source first; the host independently fetches that exact GitHub SHA into
an isolated worktree. Code delivery needs no additional Windows-to-VPS TCP test
channel. No root, WSL, host network/proxy/firewall changes, user-manager restart,
or alternate host is part of this procedure.

Reuse the admitted official Microsoft.Mxc.Sdk 1.0.1 and native release from the
MXC-01 instructions in [../README.md](../README.md). Publish with the existing
Linux native toolchain and stage with the unchanged `eng/mxc/stage.py`; do not
use a private native build or native-library override. Use fresh paths for each
publish, immutable stage, mutable fixture and report. The report parent and the
fixture parent must exist and have no symlink ancestors.

```text
<stage>/arcforges-mxc-probe --linux-profile --manifest <stage>/mxc-manifest.json --work <new-private-fixture> --report <new-report.json> --only terminal
```

The diagnostic groups are `terminal`, `policy`, `network`, and `resource`.
Exit 2 means a diagnostic slice passed with independently confirmed cleanup;
it is deliberately not a full qualification success. Exit 1 means a failure or
unresolved cleanup. Read the report and its `.events.jsonl` companion together.
`qualificationPassed` stays false until the required full combination is
implemented and proven. The initial implementation is still under development;
no native result is implied by these invocation examples.

The driver creates a unique `arcforges-mxc03-<RunId>.service`. systemd installs
CPU, memory, swap and process limits before executing the fixed trusted owner.
The owner validates its immutable stage and actual scope/limits, then waits for
the outside driver's identity/readback acknowledgement before invoking the
official Bubblewrap SDK. No payload PID is moved into a cgroup after starting.
The fixed owner launcher clears the manager's ambient environment without
reading it; it uses only the existing selected helper paths.

Each first operation records a bounded phase, identity, outcome and native or
SDK error code. Owner setup errors have a private bootstrap stderr file even
before its JSONL logger opens. Original failures and cleanup failures are
separate. Diagnose the actual failed phase before modifying code or retrying.
Untrusted fixture JSONL and terminal bytes are supplementary observations;
they cannot establish ownership, resource enforcement or successful cleanup.

The trusted control directory and its logs are outside every workload grant.
Keep ordinary logs free of credentials and raw sensitive arguments/environment.
Use only synthetic test inputs. Do not publish whole private control records.
The designated host's trusted owner may inspect its own process metadata under
the accepted local process boundary.

When a scope cannot be proven empty, preserve the exact service invocation,
boot/process identity, held cgroup identity, diagnostic files and unresolved
cleanup result. Do not delete its fixture, call it successful, or clean up a
similarly named foreign service. The unchanged repository host verification
profile and independent final-head review remain separate merge requirements.
