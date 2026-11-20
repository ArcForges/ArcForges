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
Use `--flow browser` or `--flow device_code` to select the kind for a new
sign-in. When `connect` creates a flow, use the returned `flowId` with `center
flow` to see the current state. `connect` makes one bounded flow read and still
reports its receipt and `flowId` when that read is unavailable. The flow may
display a transient verification URI or user code. Those values do not appear in
the durable operation receipt.

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
For `connect`, include the original origin, mode and any selected flow kind.
