<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# ArcForges.Contracts.LocalRpc

Strongly typed StreamJsonRpc RPC contracts, data transfer objects, proxy groups, and System.Text.Json / PolyType serialization contexts for same-machine product-to-product and product-to-hub IPC (Step 02.01).

## Scope & Contents

- **`ILocalHubControlRpc`** (`Hub/ILocalHubControlRpc.cs`): The local coordination RPC interface managing registration, lease heartbeats, provider discovery, routing, and tool action approval requests.
- **Product V1 RPC Interfaces** (`Products/`):
  - `IArcNotesRpcV1` (23 methods): Documents, blocks, tags, properties, selection, import, export, and context.
  - `IArcScopeRpcV1` (27 methods): Sessions, signal queries, capture control, protocol decoders, connections, live views, findings, analysis, and reports.
  - `IArcSlateRpcV1` (39 methods): Project snapshots, edit history (undo/redo/jump), checkpoints, media assets, timeline sequences, tracks, clips, trims, markers, and exports.
- **Proxy Group** (`Products/ProxyGroups.cs`): `IArcForgesProviderProxyGroup` annotated with `[JsonRpcProxyInterfaceGroup]` for compile-time generated composite proxies.
- **Connection Notices** (`Events/ConnectionNotices.cs`): Typed connection, disconnection, and provider health lifecycle notices.
- **Serialization** (`Serialization/`):
  - `LocalRpcJsonContext`: Strict `JsonSerializerContext` registering all contract DTOs and `ArcResult<T>` envelopes.
  - `LocalRpcInboundJsonContext`: Inbound tolerant `JsonSerializerContext` with unmapped member skipping.
  - `LocalRpcShapeWitness`: PolyType `[GenerateShapeFor<T>]` shape witness for StreamJsonRpc serialization without reflection.
- **Contract Manifest** (`artifacts/contracts/localrpc-contracts.v1.json`): Normative manifest cataloging all 96 methods, capabilities, risk levels (R0-R4), and operation flags.
