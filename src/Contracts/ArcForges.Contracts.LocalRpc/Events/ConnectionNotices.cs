// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace ArcForges.Contracts.LocalRpc;

public sealed partial record ConnectionEstablishedNotice
{
    public required InstanceId Instance { get; init; }
    public required ProductId Product { get; init; }
    public required string Transport { get; init; }
    public required string Endpoint { get; init; }
    public required DateTimeOffset ConnectedAtUtc { get; init; }
}

public sealed partial record ConnectionLostNotice
{
    public required InstanceId Instance { get; init; }
    public required ProductId Product { get; init; }
    public required string Reason { get; init; }
    public required DateTimeOffset DisconnectedAtUtc { get; init; }
}

public sealed partial record ProviderHealthNotice
{
    public required InstanceId Instance { get; init; }
    public required ProductId Product { get; init; }
    public required ProviderHealth Health { get; init; }
    public required DateTimeOffset ObservedAtUtc { get; init; }
}
