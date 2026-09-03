// SPDX-License-Identifier: AGPL-3.0-only

using PolyType;
using StreamJsonRpc;

namespace ArcForges.Contracts.LocalRpc;

[JsonRpcContract]
[GenerateShape(IncludeMethods = MethodShapeFlags.PublicInstance)]
[JsonRpcProxyInterfaceGroup(typeof(IArcNotesRpcV1), typeof(IArcScopeRpcV1), typeof(IArcSlateRpcV1))]
internal partial interface IArcForgesProviderProxyGroup : IArcNotesRpcV1, IArcScopeRpcV1, IArcSlateRpcV1
{
}
