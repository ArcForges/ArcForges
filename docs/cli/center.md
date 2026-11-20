<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Center connection

The `center` commands use the current user's local Node over its authenticated
IPC connection. A Center enrollment is optional. Local Sandbox and Run commands
remain available after the link goes offline or is disabled.

| Command | Result |
| --- | --- |
| `arcforges center status` | Read the desired link setting, local enrollment and observed channel state. |
| `arcforges center connect <origin> --mode <mode> [--flow <kind>]` | Enable the link with a matching credential or begin a bounded sign-in flow. |
| `arcforges center flow <flow-id>` | Read the current state and display details of an existing flow. |
| `arcforges center cancel <flow-id>` | Cancel an existing pending flow. |
| `arcforges center disconnect` | Disable the link and cancel any pending flow. The protected credential is retained. |
| `arcforges center signout` | Disable the link, end local credential authority and request remote enrollment revocation. |

Supply the exact Center HTTPS origin and select `official` or `self_hosted`.
A matching protected enrollment re-enables the link without starting a sign-in
flow. A new sign-in uses `browser` by default. Use `--flow device_code` to
choose device-code sign-in.
When `connect` creates a flow, use the returned `flowId` with `center
flow` to see the current state. A new `connect` makes one bounded flow read and
still reports its receipt and `flowId` when that read is unavailable. An exact
replay returns the receipt and any retained `flowId`. Read the flow separately
to see current display details.

Compare the pending flow's Node key fingerprint with the approval page. If the
page asks for the last group, enter the final four hexadecimal characters shown
by the local flow. JSON displays the field as `flow.nodeKeyFingerprint` while
the flow is pending and unexpired. The verification URI, user code and
fingerprint are transient display values and stay out of durable receipts.

The connection state and observed channel state are independent of local Run
state. After sign-out check `connection.remoteRevocation` for `confirmed` or
`unknown`. A remote result can remain unresolved after local authority has
ended.

With `--json`, each command prints one result document. Mutations report the
original `commandId` and `ownerEpoch`. Inspect a receipt and retain those IDs
if the client loses its reply.

```sh
arcforges operation inspect "$COMMAND_ID" --owner-epoch "$OWNER_EPOCH" --json
```

Replay only the original request with both `--command-id` and `--owner-epoch`.
For `connect`, use the original origin, mode and flow kind. Omitting `--flow`
sends the same request as `--flow browser`.
