// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace ArcForges.Contracts.LocalRpc;

public sealed partial record ProductActivityRefDto
{
    public required Guid ActivityId { get; init; }
    public required ProductId OwnerProduct { get; init; }
    public required string Kind { get; init; }
    public required DateTimeOffset StartedAtUtc { get; init; }
}

public sealed partial record ProductActivitySnapshotDto
{
    public required Guid ActivityId { get; init; }
    public required ProductId OwnerProduct { get; init; }
    public required string Kind { get; init; }
    public required string State { get; init; }
    public double Progress { get; init; }
    public required DateTimeOffset StartedAtUtc { get; init; }
    public DateTimeOffset? FinishedAtUtc { get; init; }
    public ArtifactRef? ArtifactRef { get; init; }
    public ArcError? Error { get; init; }
}

public sealed partial record TypedAnchorDto
{
    public required string AnchorKind { get; init; }
    public required string Value { get; init; }
    public string? Context { get; init; }
    public long? SpanStart { get; init; }
    public long? SpanLength { get; init; }
}

public readonly record struct RationalDto
{
    public long Numerator { get; init; }
    public long Denominator { get; init; }

    public RationalDto(long numerator, long denominator)
    {
        if (denominator <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(denominator), "Denominator must be strictly positive.");
        }

        Numerator = numerator;
        Denominator = denominator;
    }
}

public sealed partial record LocalOutputTargetDto
{
    public required string Kind { get; init; } // "folder_token" or "save_picker_grant"
    public Guid? TokenId { get; init; }
    public string? RelativeName { get; init; }
    public Guid? GrantId { get; init; }
    public string? SuggestedName { get; init; }
}

public enum MutationStatus
{
    Succeeded,
    Accepted,
    Rejected,
    Unknown,
}
