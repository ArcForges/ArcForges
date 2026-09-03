// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;

namespace ArcForges.Contracts.LocalRpc;

public sealed partial record RegisterInstanceRequest
{
    public required ProductId Product { get; init; }
    public required InstanceId Instance { get; init; }
    public required int ProcessId { get; init; }
    public required string Transport { get; init; } // "namedpipe" | "uds"
    public required string Endpoint { get; init; }
    public required string BuildId { get; init; }
    public required string ContractSet { get; init; }
    public required DateTimeOffset StartedAtUtc { get; init; }
    public required IReadOnlyList<CapabilityDescriptor> Capabilities { get; init; }
}

public sealed partial record RegisterInstanceResult
{
    public required bool Accepted { get; init; }
    public string? SessionToken { get; init; }
    public TimeSpan Lease { get; init; }
    public ArcError? Error { get; init; }
}

public sealed partial record UnregisterInstanceRequest
{
    public required InstanceId Instance { get; init; }
    public required string SessionToken { get; init; }
    public string? Reason { get; init; }
}

public sealed partial record HeartbeatRequest
{
    public required InstanceId Instance { get; init; }
    public required string SessionToken { get; init; }
    public required ProviderHealth Health { get; init; }
    public int ActiveTaskCount { get; init; }
    public int QueueDepth { get; init; }
    public required IReadOnlyList<DocumentId> ActiveDocuments { get; init; }
}

public sealed partial record HeartbeatResult
{
    public required bool Accepted { get; init; }
    public TimeSpan Lease { get; init; }
    public ArcError? Error { get; init; }
}

public sealed partial record DiscoverRequest
{
    public ProductId? Product { get; init; }
    public string? CapabilityId { get; init; }
}

public sealed partial record DiscoverResult
{
    public required IReadOnlyList<ProviderRecord> Providers { get; init; }
}

public sealed partial record RouteRequest
{
    public InstanceId? TargetInstance { get; init; }
    public DocumentId? Document { get; init; }
    public string? CapabilityId { get; init; }
}

public sealed partial record RouteResult
{
    public required bool Resolved { get; init; }
    public InstanceId? Instance { get; init; }
    public string? Endpoint { get; init; }
    public ArcError? Error { get; init; }
}

public sealed partial record RequestApprovalRequest
{
    public required CommandId Command { get; init; }
    public required TaskId Task { get; init; }
    public required ResourceRef TargetResource { get; init; }
    public required string ProposedEffect { get; init; }
    public required string RiskClass { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }
}

public sealed partial record RequestApprovalResult
{
    public required Guid ApprovalId { get; init; }
    public required bool Accepted { get; init; }
    public ArcError? Error { get; init; }
}

public sealed partial record ResolveApprovalRequest
{
    public required CommandId Command { get; init; }
    public required Guid ApprovalId { get; init; }
    public required ApprovalDecision Decision { get; init; }
    public Revision ExpectedRevision { get; init; }
}

public sealed partial record ResolveApprovalResult
{
    public required bool Accepted { get; init; }
    public Revision NewRevision { get; init; }
    public ArcError? Error { get; init; }
}

public sealed partial record CapabilityDescriptor
{
    public required string CapabilityId { get; init; }
    public required ProductId OwnerProduct { get; init; }
    public bool Read { get; init; }
    public bool Write { get; init; }
    public bool Destructive { get; init; }
    public bool Idempotent { get; init; }
    public bool Undoable { get; init; }
    public bool LongRunning { get; init; }
    public bool Cancellable { get; init; }
    public bool RequiresUi { get; init; }
    public string? RequiredEntitlement { get; init; }
    public string? PermissionClass { get; init; }
}

public sealed partial record ProviderRecord
{
    public required ProductId Product { get; init; }
    public required InstanceId Instance { get; init; }
    public required int ProcessId { get; init; }
    public required string Transport { get; init; }
    public required string Endpoint { get; init; }
    public required string BuildId { get; init; }
    public required string ContractSet { get; init; }
    public required ProviderHealth Health { get; init; }
    public required IReadOnlyList<CapabilityDescriptor> Capabilities { get; init; }
    public required IReadOnlyList<DocumentId> ActiveDocuments { get; init; }
}

public enum ProviderHealth
{
    Ready,
    Busy,
    Degraded,
    Draining,
}

public enum ApprovalDecision
{
    Approved,
    Denied,
    Expired,
    Invalidated,
    Canceled,
}

public sealed class LeaseExpiredEventArgs : EventArgs
{
    public required InstanceId Instance { get; init; }
}

public sealed class RouteChangedEventArgs : EventArgs
{
    public required DocumentId Document { get; init; }
    public InstanceId? NewInstance { get; init; }
}
