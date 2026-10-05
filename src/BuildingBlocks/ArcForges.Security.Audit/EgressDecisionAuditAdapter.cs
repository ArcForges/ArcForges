// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Security.Decisions;
using ArcForges.Security.Egress;

namespace ArcForges.Security.Audit;

/// <summary>
/// The projection of one PLT.41 <see cref="EgressAuditRecord"/> onto the closed egress audit event. It keeps only what the egress
/// decision actually knew and never invents a value: data class and destination class are the explicit unclassified or undetermined
/// markers when the decision refused before they were determined, the destination is absent only when it was malformed, the authority
/// is the kind, reference and grant generation of an allowed decision (none for a refusal), the effective risk is the explicit
/// not-assessed marker (the egress decision precedes risk assessment and the record carries none), and the opaque resource id and
/// revision become a content reference fingerprint. The occurrence time of the record is not used: the store stamps the event. Any
/// record that contradicts itself, names a non-canonical capability or destination, or cannot be held by the closed shape throws.
/// </summary>
internal static class EgressAuditProjection
{
    private const string HttpsScheme = "https://";

    internal static AuditEvent Project(EgressAuditRecord record, AuditSoftwareIdentity fallbackSoftwareIdentity)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(fallbackSoftwareIdentity);
        ArgumentNullException.ThrowIfNull(record.Actors);
        ArgumentNullException.ThrowIfNull(record.Resource);
        ArgumentNullException.ThrowIfNull(record.Scope);

        var allowed = record.Kind switch
        {
            EgressAuditKind.Authorized => true,
            EgressAuditKind.Refused => false,
            _ => throw new ArgumentOutOfRangeException(nameof(record), "The egress audit kind is not an audited outcome."),
        };
        CheckReason(record, allowed);

        var software = record.Actors.Actors.Count > 0
            ? new AuditSoftwareIdentity(record.Actors.Actors[^1].SoftwareIdentity)
            : fallbackSoftwareIdentity;
        if (record.Actors.Actors.Count > 0 && !StringComparer.Ordinal.Equals(record.SoftwareIdentity, software.Value))
        {
            throw new ArgumentException("The record's software identity is not the final actor's.", nameof(record));
        }

        var executor = record.Actors.Actors.Count > 0 ? record.Actors.Actors[^1].Executor : record.Actors.CallerInstance;
        if (executor != record.Executor)
        {
            throw new ArgumentException("The record's executor is not the final actor's executor.", nameof(record));
        }

        var detail = new AuditEgressDetail(
            allowed ? AuditEgressReason.Authorized : MapReason(record.Reason),
            MapDataClass(record.DataClass),
            MapDestinationClass(record.DestinationClass),
            MapDestination(record.Destination),
            allowed ? MapAuthority(record.Authority) : AuditEgressAuthorityKind.NoAuthority,
            allowed && record.AuthorityReference is not null ? new AuditReferenceText(record.AuthorityReference) : null,
            allowed && record.GrantGeneration is not null ? new AuditReferenceText(record.GrantGeneration) : null,
            AuditEgressContentReference.From(record.Resource.Id, record.Resource.Revision));
        if (!allowed && (record.Authority != EgressAuthorityKind.None || record.AuthorityReference is not null
            || record.GrantGeneration is not null || record.GrantIssuer is not null))
        {
            throw new ArgumentException("A refused decision names an authority.", nameof(record));
        }

        return new AuditEvent(
            allowed ? AuditEventType.DataEgressAuthorized : AuditEventType.DataEgressDenied,
            record.Actors,
            software,
            new AuditCapabilityId(record.CapabilityKey),
            default,
            AuditRisk.NotAssessed,
            allowed ? AuditDecision.Allowed : AuditDecision.Denied,
            AuditEgressReasons.Generic(detail.Reason, detail.AuthorityKind),
            record.Origin switch
            {
                DecisionOrigin.Local => AuditOrigin.Local,
                DecisionOrigin.Remote => AuditOrigin.Remote,
                _ => throw new ArgumentOutOfRangeException(nameof(record), "The egress origin is not an audited origin."),
            },
            record.Scope.Workspace,
            null,
            new CorrelationId(record.Correlation.Value),
            detail);
    }

    // The record's reason, code and registered code must be exactly the table's, so a forged or stale record is refused.
    private static void CheckReason(EgressAuditRecord record, bool allowed)
    {
        if (allowed)
        {
            if (record.Reason != EgressReason.None || record.ReasonCode is not null || record.RegisteredCode is not null)
            {
                throw new ArgumentException("An authorized decision names a refusal reason.", nameof(record));
            }

            return;
        }

        var info = EgressReasons.Describe(record.Reason);
        if (!StringComparer.Ordinal.Equals(record.ReasonCode, info.Code) || !StringComparer.Ordinal.Equals(record.RegisteredCode, info.RegisteredCode))
        {
            throw new ArgumentException("The refusal's codes do not match its reason.", nameof(record));
        }
    }

    private static AuditEgressReason MapReason(EgressReason reason) => reason switch
    {
        EgressReason.DestinationNotDeclared => AuditEgressReason.DestinationNotDeclared,
        EgressReason.DestinationMalformed => AuditEgressReason.DestinationMalformed,
        EgressReason.ContentUnclassified => AuditEgressReason.ContentUnclassified,
        EgressReason.SecretMaterial => AuditEgressReason.SecretMaterial,
        EgressReason.NotAllowlisted => AuditEgressReason.NotAllowlisted,
        EgressReason.AllowlistMismatch => AuditEgressReason.AllowlistMismatch,
        EgressReason.DataClassAboveAllowlist => AuditEgressReason.DataClassAboveAllowlist,
        EgressReason.AiIneligibleContent => AuditEgressReason.AiIneligibleContent,
        EgressReason.NoGrant => AuditEgressReason.NoGrant,
        EgressReason.GrantExplicitlyDenied => AuditEgressReason.GrantExplicitlyDenied,
        EgressReason.GrantMismatch => AuditEgressReason.GrantMismatch,
        EgressReason.GrantOutsideLifetime => AuditEgressReason.GrantOutsideLifetime,
        EgressReason.DataClassAboveGrant => AuditEgressReason.DataClassAboveGrant,
        EgressReason.ClassifierUnavailable => AuditEgressReason.ClassifierUnavailable,
        EgressReason.AllowlistUnavailable => AuditEgressReason.AllowlistUnavailable,
        EgressReason.GrantSourceUnavailable => AuditEgressReason.GrantSourceUnavailable,
        EgressReason.AuditUnavailable => AuditEgressReason.AuditUnavailable,
        _ => throw new ArgumentOutOfRangeException(nameof(reason), "The egress reason is not an audited reason."),
    };

    private static AuditEgressDataClass MapDataClass(EgressDataClass dataClass) => dataClass switch
    {
        EgressDataClass.None => AuditEgressDataClass.Unclassified,
        EgressDataClass.Public => AuditEgressDataClass.Public,
        EgressDataClass.Diagnostic => AuditEgressDataClass.Diagnostic,
        EgressDataClass.WorkspaceContent => AuditEgressDataClass.WorkspaceContent,
        EgressDataClass.SensitiveContent => AuditEgressDataClass.SensitiveContent,
        EgressDataClass.SecretMaterial => AuditEgressDataClass.SecretMaterial,
        _ => throw new ArgumentOutOfRangeException(nameof(dataClass), "The egress data class is not an audited class."),
    };

    private static AuditEgressDestinationClass MapDestinationClass(EgressDestinationClass destinationClass) => destinationClass switch
    {
        EgressDestinationClass.None => AuditEgressDestinationClass.Undetermined,
        EgressDestinationClass.CloudAiProvider => AuditEgressDestinationClass.CloudAiProvider,
        EgressDestinationClass.Connector => AuditEgressDestinationClass.Connector,
        EgressDestinationClass.ThirdParty => AuditEgressDestinationClass.ThirdParty,
        EgressDestinationClass.Public => AuditEgressDestinationClass.Public,
        _ => throw new ArgumentOutOfRangeException(nameof(destinationClass), "The egress destination class is not an audited class."),
    };

    private static AuditEgressAuthorityKind MapAuthority(EgressAuthorityKind authority) => authority switch
    {
        EgressAuthorityKind.UserConsent => AuditEgressAuthorityKind.UserConsent,
        EgressAuthorityKind.WorkspacePolicy => AuditEgressAuthorityKind.WorkspacePolicy,
        EgressAuthorityKind.ProductRoute => AuditEgressAuthorityKind.ProductRoute,
        _ => throw new ArgumentOutOfRangeException(nameof(authority), "An authorized decision rests on a named authority."),
    };

    // The destination must be the canonical origin PLT.41 itself produced; the audit identity is that origin without its scheme.
    private static AuditEgressDestinationId? MapDestination(string? destination)
    {
        if (destination is null)
        {
            return null;
        }

        if (!EgressDestinationIdentity.TryParse(destination, out var identity)
            || !StringComparer.Ordinal.Equals(identity.Origin, destination)
            || !destination.StartsWith(HttpsScheme, StringComparison.Ordinal))
        {
            throw new ArgumentException("The destination is not a canonical egress origin.", nameof(destination));
        }

        return new AuditEgressDestinationId(destination[HttpsScheme.Length..]);
    }
}

/// <summary>
/// Typed audit intake for egress decisions. <see cref="Record"/> projects one PLT.41 <see cref="EgressAuditRecord"/> (allowed or
/// refused) and appends it synchronously and durably, returning only after the row is committed. Any failure (an unrepresentable
/// record, wrong owner, a purged partition, a disposed or unwritable store) propagates unchanged. The adapter accepts only the
/// record; it has no generic append and no content, secret or property-bag parameter.
/// </summary>
public sealed class EgressDecisionAuditAdapter
{
    private readonly AuditStore store;
    private readonly AuditSoftwareIdentity fallbackSoftwareIdentity;

    /// <param name="store">The owner-scoped audit store.</param>
    /// <param name="fallbackSoftwareIdentity">The software identity recorded when the actor chain has no delegated actor, supplied by the composition root.</param>
    public EgressDecisionAuditAdapter(AuditStore store, AuditSoftwareIdentity fallbackSoftwareIdentity)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.fallbackSoftwareIdentity = fallbackSoftwareIdentity ?? throw new ArgumentNullException(nameof(fallbackSoftwareIdentity));
    }

    /// <summary>Durably append one egress decision before returning; throws on any failure.</summary>
    public AuditEventRecord Record(EgressAuditRecord record) => store.Append(EgressAuditProjection.Project(record, fallbackSoftwareIdentity));
}

/// <summary>
/// The audit side of the PLT.41 egress port: it implements <see cref="IEgressAuditSink"/> over <see cref="EgressDecisionAuditAdapter"/>,
/// so the real <see cref="EgressAuthority"/> writes every decision that reaches its sink into the durable audit store before it
/// releases the decision. A failure throws, and the authority then refuses an allowed transfer with
/// <see cref="EgressReason.AuditUnavailable"/>. The authority does not write that refusal to the sink, so it has no event of its own;
/// a write that timed out may land later as an Authorized event beside it, which is valid and authorizes nothing. Security never
/// references this project; the composition root passes this sink to the authority.
/// </summary>
public sealed class EgressAuditSink : IEgressAuditSink
{
    private readonly EgressDecisionAuditAdapter adapter;

    public EgressAuditSink(EgressDecisionAuditAdapter adapter)
    {
        this.adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
    }

    /// <summary>Appends the decision durably before returning; throws on any failure.</summary>
    public ValueTask WriteAsync(EgressAuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();
        _ = adapter.Record(record);
        return ValueTask.CompletedTask;
    }
}
