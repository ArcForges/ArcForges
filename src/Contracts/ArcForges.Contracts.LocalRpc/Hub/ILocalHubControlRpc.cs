// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using PolyType;
using StreamJsonRpc;

namespace ArcForges.Contracts.LocalRpc;

[JsonRpcContract]
[GenerateShape(IncludeMethods = MethodShapeFlags.PublicInstance)]
public partial interface ILocalHubControlRpc : IDisposable
{
    ValueTask<RegisterInstanceResult> RegisterAsync(RegisterInstanceRequest request, CancellationToken cancellationToken);
    ValueTask UnregisterAsync(UnregisterInstanceRequest request, CancellationToken cancellationToken);
    ValueTask<HeartbeatResult> HeartbeatAsync(HeartbeatRequest request, CancellationToken cancellationToken);
    ValueTask<DiscoverResult> DiscoverAsync(DiscoverRequest request, CancellationToken cancellationToken);
    ValueTask<RouteResult> ResolveRouteAsync(RouteRequest request, CancellationToken cancellationToken);
    ValueTask<RequestApprovalResult> RequestApprovalAsync(RequestApprovalRequest request, CancellationToken cancellationToken);
    ValueTask<ResolveApprovalResult> ResolveApprovalAsync(ResolveApprovalRequest request, CancellationToken cancellationToken);
    event EventHandler<LeaseExpiredEventArgs>? LeaseExpired;
    event EventHandler<RouteChangedEventArgs>? RouteChanged;
}
