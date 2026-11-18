# Linux Bubblewrap qualification experiments

AFV2-MXC-03 develops the five native Linux protocols in Design
`docs/verification/mxc-experiments.md`. AFV2-MXC-04 uses the [scoped native
qualification record](linux-bubblewrap-sdk-v1.qualification.json) for profile
admission. A successful diagnostic slice
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

The diagnostic groups are `admission`, `terminal`, `policy`, `network`, `resource`,
and `lifecycle`.
Exit 2 means a diagnostic slice passed with independently confirmed cleanup;
it is deliberately not a full qualification success. Exit 1 means a failure or
unresolved cleanup. Read the report and its `.events.jsonl` companion together.
`qualificationPassed` stays false for every diagnostic invocation. These command
examples do not imply a native result.

Run the complete profile with fresh paths and exact baseline commits:

```text
<stage>/arcforges-mxc-probe --linux-profile --manifest <stage>/mxc-manifest.json --work <new-private-fixture> --report <new-full-report.json> --source <40-character-Node-commit> --design <40-character-Design-commit> --plan <40-character-Plan-commit>
```

The full driver executes all six groups sequentially against the same verified
stage, including the lifecycle group's combined terminal/filesystem/network/
resource scenario. It stops at the first failed group or unresolved cleanup.
Exit 0 requires every group to pass and every owned scope to be confirmed empty;
exit 1 leaves the profile partial. A full receipt binds the executable's embedded
source commit, executable and official stage hashes, actual kernel release and
version, boot identity, supplied Design/Plan baselines and every child receipt /
event-log hash. The source label must match the AOT executable's SDK-embedded
`SourceRevisionId`; the clean stage needs no Git executable or checkout. Design
and Plan commits are the coordinator's explicit invocation baselines, not a
claim that the probe independently fetched those repositories. Each slice keeps
its original report, owner evidence and cleanup results beneath the private
fixture root. Failed groups and groups not run remain visible in the full receipt.

The full receipt is native experiment evidence. It does not replace independent
review, required host statuses or the AFV2-MXC-04 product admission decision.

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
