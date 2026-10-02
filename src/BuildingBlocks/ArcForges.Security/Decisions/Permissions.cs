// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Security.Approvals;

namespace ArcForges.Security.Decisions;

public enum PermissionGrantState
{
    None = 0,

    /// <summary>The principal holds the permission.</summary>
    Granted = 1,

    /// <summary>Nothing has authorised it yet (PM-11: not granted).</summary>
    NotGranted = 2,

    /// <summary>A grant or policy forbids it (PM-11: explicitly denied), a standing prohibition.</summary>
    ExplicitlyDenied = 3,
}

/// <summary>
/// The constraints the pipeline understands and enforces. A constraint it does not understand is never ignored: it refuses, so a
/// grant can only ever be narrowed by a constraint, never widened by one the pipeline cannot read.
/// </summary>
public static class PermissionConstraints
{
    /// <summary>The permission applies to requests made through this machine's own interface only; a remote request fails it.</summary>
    public const string LocalOriginOnly = "origin.local-only";

    /// <summary>The permission applies only on the named device.</summary>
    public static string DeviceBound(DeviceId device) =>
        string.Create(CultureInfo.InvariantCulture, $"device:{device.Value:N}");
}

/// <summary>
/// An owner-issued permission fact for one principal, capability and scope with its constraints and lifetime (PM-02). It is evidence
/// read by the pipeline, never a grant the pipeline can mint, widen or extend.
/// </summary>
public sealed class PermissionGrantRecord
{
    private readonly string[] _constraints;

    public PermissionGrantRecord(
        string issuerKey,
        string principalKey,
        string capabilityKey,
        string scopeKey,
        PermissionGrantState state,
        IEnumerable<string> constraints,
        DateTimeOffset validFromUtc,
        DateTimeOffset validUntilUtc,
        string sourceGeneration)
    {
        SecurityText.Validate(issuerKey, 256, nameof(issuerKey));
        SecurityText.Validate(principalKey, 256, nameof(principalKey));
        SecurityText.Validate(capabilityKey, 256, nameof(capabilityKey));
        SecurityText.Validate(scopeKey, 256, nameof(scopeKey));
        SecurityText.Validate(sourceGeneration, 256, nameof(sourceGeneration));
        if (!Enum.IsDefined(state) || state == PermissionGrantState.None)
        {
            throw new ArgumentOutOfRangeException(nameof(state));
        }

        ArgumentNullException.ThrowIfNull(constraints);
        _constraints = [.. constraints];
        if (_constraints.Length > 64 || _constraints.Distinct(StringComparer.Ordinal).Count() != _constraints.Length)
        {
            throw new ArgumentException("Constraints are a bounded set of unique keys.", nameof(constraints));
        }

        foreach (var constraint in _constraints)
        {
            SecurityText.Validate(constraint, 256, nameof(constraints));
        }

        if (validFromUtc.Offset != TimeSpan.Zero || validUntilUtc.Offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Permission lifetimes are UTC.", nameof(validFromUtc));
        }

        if (validUntilUtc <= validFromUtc)
        {
            throw new ArgumentException("A permission lifetime is not empty.", nameof(validUntilUtc));
        }

        IssuerKey = issuerKey;
        PrincipalKey = principalKey;
        CapabilityKey = capabilityKey;
        ScopeKey = scopeKey;
        State = state;
        Constraints = Array.AsReadOnly(_constraints);
        ValidFromUtc = validFromUtc;
        ValidUntilUtc = validUntilUtc;
        SourceGeneration = sourceGeneration;
    }

    public string IssuerKey { get; }

    public string PrincipalKey { get; }

    public string CapabilityKey { get; }

    public string ScopeKey { get; }

    public PermissionGrantState State { get; }

    public IReadOnlyList<string> Constraints { get; }

    /// <summary>Inclusive start of the lifetime.</summary>
    public DateTimeOffset ValidFromUtc { get; }

    /// <summary>Exclusive end of the lifetime: at this exact instant the permission is already over.</summary>
    public DateTimeOffset ValidUntilUtc { get; }

    public string SourceGeneration { get; }
}

public enum PermissionDisposition
{
    Unknown = 0,
    Granted = 1,

    /// <summary>Not granted, expired, not yet valid, or its constraints are not met: a permission is required.</summary>
    Required = 2,

    /// <summary>Explicitly denied by a standing prohibition.</summary>
    Denied = 3,
}

/// <summary>
/// The read-only, immutable permission projection of the pipeline for one principal, capability and scope, preserving the
/// applicable constraints and lifetime. It is only a user-interface preflight: it is never a grant, a resource authorization or a
/// substitute for the owner's final validation at invocation, and it is valid only as of <see cref="ObservedAtUtc"/>.
/// </summary>
public sealed class PermissionAvailabilityEvidence
{
    internal PermissionAvailabilityEvidence(
        string principalKey,
        string capabilityKey,
        string scopeKey,
        PermissionDisposition disposition,
        DecisionReason reason,
        PermissionGrantRecord? grant,
        DateTimeOffset observedAtUtc)
    {
        PrincipalKey = principalKey;
        CapabilityKey = capabilityKey;
        ScopeKey = scopeKey;
        Disposition = disposition;
        Reason = reason;
        Constraints = grant is null ? Array.AsReadOnly(Array.Empty<string>()) : Array.AsReadOnly([.. grant.Constraints]);
        ValidFromUtc = grant?.ValidFromUtc;
        ValidUntilUtc = grant?.ValidUntilUtc;
        SourceGeneration = grant?.SourceGeneration;
        IssuerKey = grant?.IssuerKey;
        ObservedAtUtc = observedAtUtc;
    }

    public string PrincipalKey { get; }

    public string CapabilityKey { get; }

    public string ScopeKey { get; }

    public PermissionDisposition Disposition { get; }

    /// <summary>The step 6 reason behind a disposition that is not <see cref="PermissionDisposition.Granted"/>.</summary>
    public DecisionReason Reason { get; }

    /// <summary>The constraints of the grant record, empty when no record was found.</summary>
    public IReadOnlyList<string> Constraints { get; }

    public DateTimeOffset? ValidFromUtc { get; }

    public DateTimeOffset? ValidUntilUtc { get; }

    public string? SourceGeneration { get; }

    public string? IssuerKey { get; }

    /// <summary>The instant this projection was taken; it says nothing about any later instant.</summary>
    public DateTimeOffset ObservedAtUtc { get; }
}
