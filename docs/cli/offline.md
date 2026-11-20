<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Offline CLI

These commands use the current user's local Node over the authenticated Unix
socket or Windows named pipe. Local Sandbox and Run operations work without an
account, enrollment or network connection. Remote grants are the exception.
They manage access for an existing enrollment.

This guide covers the offline CLI. See [Owned Sandbox data](data.md) for
usage, file listings, imports and exports. The filesystem delivery tasks
cover Sandbox deletion, and
CENTER-02 covers Center connection commands. The Plan records native
verification, merge and release status. [Design and command map](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/06-local-node-cli.md) ·
[Delivery plan](https://github.com/ArcForges/Plan).

## Start and inspect the local Node

```sh
arcforges node start
arcforges node status --json
arcforges doctor
```

`node start` uses the installed local service bootstrap when the Node is absent,
waits for readiness and reports the V2 handshake. A running Node is reused.
`node status` combines its actual service state with the handshake.
`doctor` also reads the Node resource budget. With `--sandbox` it reads that
Sandbox's identity, revision, profile and capabilities. Status and diagnostics
leave the service stopped when it is absent.

Read capability states and their evidence with the selected profile in mind.
An unverified capability has no measured guarantee for that request and host.
Core refuses a Start before executing the program when a required constraint
cannot be applied.

## Configure a Sandbox

Save this Linux example as `sandbox.json`. It uses the official Bubblewrap
profile, an owned work directory, denied ingress and egress, and resource
throttling. For Windows use the Windows profile pair in the table.

```json
{
  "profileId": "linux-bubblewrap-sdk-v1",
  "profileVersion": "linux-bubblewrap-sdk-v1",
  "network": {
    "egress": "NETWORK_MODE_DENY",
    "ingress": "NETWORK_MODE_DENY",
    "hostLoopback": false
  },
  "resources": {
    "pressureAction": "PRESSURE_ACTION_THROTTLE"
  }
}
```

| Platform | `profileId` | `profileVersion` |
| --- | --- | --- |
| Windows | `windows-process-executor-v1` | `win-wrapper-local-v1` |
| Linux | `linux-bubblewrap-sdk-v1` | `linux-bubblewrap-sdk-v1` |

Files passed to `--file` use UTF-8 protobuf JSON. Sandbox create, configure and
repair read a complete `SandboxConfig`. Resource set reads a `ResourcePolicy`,
and grant set reads a `RemoteGrant`. Input files use protobuf field and enum
names, such as `profileId` and `NETWORK_MODE_DENY`. Opaque IDs on the command line
and in CLI output use 26-character base32 text. An `Id` field inside an input
file uses protobuf JSON for its bytes, for example `{"value":"<base64>"}`.
Treat original configuration files containing environment values as private.
The CLI redacts those values in Sandbox output. [V2 message definitions](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/contracts/proto/arcforges/sandbox/v2/platform.proto).

```sh
arcforges sandbox create build --file sandbox.json --json
arcforges sandbox list --json
arcforges sandbox inspect "$SANDBOX_ID" --json
arcforges doctor --sandbox "$SANDBOX_ID"
```

Set the variables in these examples from the IDs and revisions printed by the
CLI. The revision protects the change against a concurrent update.

```sh
arcforges sandbox configure "$SANDBOX_ID" --file sandbox.json --expected-revision "$REVISION"
arcforges sandbox rename "$SANDBOX_ID" 'Build tools' --expected-revision "$REVISION"
arcforges sandbox repair "$SANDBOX_ID" --file sandbox.json --expected-revision "$REVISION"
```

Read the current revision before each new change. Rename reads the matching
configuration for an ordinary request. Repair revalidates a Sandbox in
`ERROR` under the local owner and exact owned-root guards.

## Start and stop a Run

Place the executable and every argument after `--`. Your shell handles the
outer quoting and the CLI passes the resulting arguments as a list. Select a
shell explicitly when you want it to interpret a script. `--cwd` selects a
Sandbox-relative working directory. Keep the program in the foreground if its
Run needs to stay alive.

Linux example with one argument containing a space:

```sh
arcforges run start "$SANDBOX_ID" --terminal off -- /usr/bin/dash -c 'printf "%s\n" "$1"' _ 'two words'
```

Windows PowerShell example:

```powershell
arcforges run start $env:SANDBOX_ID --terminal off --json -- "$env:WINDIR\System32\cmd.exe" /d /c "echo two words"
```

| `--terminal` | Requested mode |
| --- | --- |
| `auto` | Select interactive mode when stdin and stdout are terminals and the Sandbox reports qualified terminal support. Otherwise use pipes. |
| `on` | Request the interactive terminal explicitly. A foreground writer requires a native local input and output terminal. Core can refuse an unsupported Sandbox combination. |
| `off` | Request separate pipes. |

By default, `run start` prints the accepted Run and command identities on stderr
and attaches in the foreground. The selected terminal or pipes carry program
output. Use `--detach` to return the receipt and leave the Run under Node
management, or `--json` for a machine-readable receipt on stdout. An accepted
receipt can arrive while the Run is still starting.

Run inspection shows the redacted command summary, bound Sandbox revision and
profile, verified limits, and observed exit provenance. See the [terminal
guide](terminal.md) for reattaching, releasing a lease, reading logs and
understanding a foreground exit code.

```sh
arcforges run list --sandbox "$SANDBOX_ID"
arcforges run inspect "$RUN_ID" --json
arcforges run stop "$RUN_ID" --json
```

`run stop` sends a durable Stop and observes its original operation. A later
read can report verified boundary cleanup. The default `node stop` stops the
Node service and leaves Runs under their existing supervisors.
`node stop --stop-runs` stops and checks the Run IDs found in its inventory
before requesting service shutdown. Concurrent Starts can remain active across
that interval. When the service accepted shutdown but its completion could
not be observed before the deadline, the CLI preserves the accepted receipt.

## Resources and grants

```sh
arcforges resources show
arcforges resources show --scope run --id "$RUN_ID" --json
arcforges resources watch --scope sandbox --id "$SANDBOX_ID" --interval 5s --json
arcforges resources set --scope node --file resources.json --expected-revision "$REVISION"
```

Resource scope is `node`, `sandbox` or `run`. Provide an ID for the latter two.
The default for show and watch is `node`. Watch emits fresh snapshots, one JSON
object per line on stdout with `--json`. Use `--once` for the initial sample.
Inspect the reported freshness, memory kind, requested policy, applied value
and OS readback separately. A missing measured field means its value is
unavailable. A resource policy file can look like this:

```json
{
  "cpuMaxMillicores": 1000,
  "pressureAction": "PRESSURE_ACTION_THROTTLE"
}
```

When an approved enrollment already exists, inspect and manage its grants from
the local Node. Grant updates and revocation require the current revision.
A grant update also requires `grantId` in its JSON file. Set accepts locally
issued active grants.

```sh
arcforges grant list --json
arcforges grant list --sandbox "$SANDBOX_ID"
arcforges grant set --file grant.json
arcforges grant set --file grant.json --expected-revision "$REVISION"
arcforges grant revoke "$GRANT_ID" --expected-revision "$REVISION"
```

## Receipts and uncertain outcomes

The human and JSON receipt forms show the same outcome. Receipt data goes to
stdout. Human mutation diagnostics include the original command ID and owner
epoch on stderr. In JSON these are `commandId` and `ownerEpoch` in the result
document. The CLI also reports `expectedRevision` when present and the literal
`terminal` selection for a Start. Save the original request and these fields.

When a mutation times out or its connection closes, look up the original
operation. The CLI sends each mutation once. Operation inspection reads the
specified command and epoch without executing anything or selecting the current
epoch on the caller's behalf.

```sh
arcforges operation inspect "$COMMAND_ID" --owner-epoch "$OWNER_EPOCH" --json
```

Check `operation.state`, `operation.effect` and `operation.responseCompacted`.
A retained compacted receipt still records the original identity and effect.
A retired epoch cannot authorize a new effect. Report the code the Node
returns, and keep the original IDs for reconciliation.

An explicit exact replay uses both `--command-id` and `--owner-epoch` with the
same request. For Start use the original `--expected-revision` and the reported
literal `--terminal on` or `--terminal off`, plus the original arguments and
working-directory option. For a rename replay supply `--file` with the complete
configuration used in the original rename, the original display name and
revision. Keep the original file because Sandbox inspection redacts environment
values. Use operation inspection to read the receipt.

These codes cover CLI query and receipt results. A [foreground Run](terminal.md#foreground-exit-status)
can return an observed payload or executor code, including values that overlap
this table.

| Exit | CLI outcome |
| --- | --- |
| `0` | The query succeeded or the reported mutation was accepted or succeeded |
| `2` | Invalid arguments or object unavailable to the request |
| `3` | Revision or identity conflict, busy managed scope, or compacted replay |
| `4` | Authentication or authorization refusal |
| `5` | Unsupported combination or unavailable terminal |
| `6` | Resource refusal |
| `7` | Local Node unavailable or stopping |
| `8` | Uncertain effect or another command failure |
