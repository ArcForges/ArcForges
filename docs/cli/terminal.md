<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Run terminals and output

Use the [offline CLI guide](offline.md) to configure a Sandbox and start a Run.

## Attach to a Run

```sh
arcforges run attach "$RUN_ID"
arcforges run attach "$RUN_ID" --read-only
arcforges run attach "$RUN_ID" --takeover
arcforges run attach "$RUN_ID" --offset "$TERMINAL_BYTE_OFFSET"
```

A foreground `run start` attaches as a writer after acceptance. Use `--detach`
or `--json` on Start when you only need a receipt. Keep the Run ID from the
receipt or foreground status for a later attach. If the accepted Start outlasts
the CLI's readiness wait, inspect or attach to that same Run.

One attachment holds the writer lease at a time. A writer can send input and,
in interactive mode, forward the local window dimensions. A read-only
attachment follows output without input or resize authority. Use `--takeover`
to explicitly revoke the previous writer's lease. A normal writer request
reports `busy` when that lease is held. Takeover and read-only options are
mutually exclusive. Attach relays program output. Use `run logs --json` for
machine-readable output.

Use a separate local terminal for takeover if the previous attachment is on
the same console or TTY. An attachment that needs the same native terminal
mode or input ownership reports `busy` while the local holder is active.

Resume interactive output from a saved `nextOffset` from
`run logs --json --stream terminal`. If retention has passed that offset, the
attachment reports the GAP on stderr and continues from the first retained
byte. Use per-stream offsets with `run logs` for piped Runs.

The CLI reports the Run ID, lease ID and `writer` or `observer` on stderr
unless `--quiet` is set. It renews the lease on the same Node connection.
Connection loss, owner replacement or takeover can end the original
attachment. When an input or resize acknowledgment is uncertain, the CLI
stops forwarding on that attachment. A new attachment leaves the old frame's
effect unknown. Operation inspection covers durable requests such as Start and
Stop. Terminal input has transient acknowledgments.

## Detach, interrupt and close input

While using an interactive writer, press **Ctrl+]**, then **d** to release the
lease. Press **Ctrl+]** twice to send one literal Ctrl+]. Use
`--no-detach-escape` on `run start` or `run attach` to send the sequence
literally. **Ctrl+C** goes to the Run's terminal as input so its foreground
application can handle the interrupt using the native terminal.

From a second shell on the same machine and under the same local user, pass
the exact Run and lease IDs printed by the active attachment.

```sh
arcforges run detach "$RUN_ID" --lease "$LEASE_ID"
```

The original attachment receives this request over its same-user local relay
and releases the lease over its own Node connection. A successful detach
leaves the Run under Node management. If the attachment has already ended or
the acknowledgment is lost, the command reports the observed refusal or
uncertainty. Use `run stop "$RUN_ID"` to request a whole-Run stop.

In pipe mode, EOF on the local input issues one explicit close of the Run's
stdin. The CLI continues displaying output. Local Ctrl+C in pipe mode or in
a read-only attachment interrupts the CLI and releases its lease. An orderly
local interruption returns `130` after release. Detach or connection loss
leaves stdin open unless an explicit EOF was already sent. The CLI restores
its local terminal modes during orderly shutdown. If a blocked Windows
console prevents confirmation of mode restoration, the attachment reports
that uncertainty.

## Read retained output

```sh
arcforges run logs "$RUN_ID"
arcforges run logs "$RUN_ID" --follow --stream terminal
arcforges run logs "$RUN_ID" --stream stdout --offset 4096 >next-output.bin
arcforges run logs "$RUN_ID" --stream stderr --offset 4096 --json
```

Logs are read-only. An interactive Run has one `terminal` stream, displayed on
stdout. A piped Run has independent `stdout` and `stderr` streams, sent to the
corresponding local streams. By default, reading piped output opens both
streams at byte offset zero. Use `--stream stdout` or `--stream stderr`
with a nonzero `--offset` to identify the cursor's stream. With `--json`, each
output, gap or final-status frame is a JSON line on stdout. The chunk data is
base64. The top-level `stream` identifies which cursor the frame belongs to.
Diagnostics go to stderr.

A live read without `--follow` uses a two-second receive window per stream.
If the Run hasn't returned its final state by then, stderr reports the stream
and next byte offset. Treat that result as a partial read and use the reported
offset with the same stream to continue. `--follow` keeps reading until the
output settles or the command is interrupted or times out. The terminal
transcript contains retained bytes, so use the application's redraw command
if a reattached full-screen display is incomplete.

On Windows, the local renderer suppresses the two standalone Win32 input
mode sequences that the pinned inner ConPTY emits, `ESC[?9001h` and
`ESC[?9001l`. Redirected output and retained logs preserve the original bytes.

A `GAP` diagnostic gives the requested and earliest retained offsets. The CLI
continues from that retained offset for the same Run epoch and reports an
epoch change as lost continuity. Track each piped stream's offset
independently. To separate piped stderr bytes from CLI diagnostics, read
`--stream stderr --json` and decode the chunk data.

## Foreground exit status

The foreground CLI returns a representable nonzero code from a confirmed
payload exit or a directly observed official executor exit after the Node
verifies the Run's boundary is empty. A successful zero also requires confirmed
payload start and a known applied effect. The foreground CLI reports
uncertainty with exit `8` when trusted exit evidence is unavailable. A successful
local detach and a Start receipt describe their own operation. Inspect the Run
for its exit.

The fixed MXC 1.0.1 profiles record the official executor's exit code and
verified boundary cleanup. Their executor observation leaves payload start
unconfirmed, so an observed executor zero currently gives a foreground
status of `8`. Inspect shows that raw zero and its origin.

```sh
arcforges run inspect "$RUN_ID" --json
```

Read the exit source alongside the raw code, payload start evidence,
termination reason and verified boundary status. An executor code identifies
the executor's observed outcome.
