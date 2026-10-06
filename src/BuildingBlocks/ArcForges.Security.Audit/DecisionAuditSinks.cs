// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.Audit;

/// <summary>Production security-decision intake; return means durable commit, never authorization or proof of OS isolation.</summary>
public sealed class SecurityDecisionAuditSink(AuditStore store, AuditSoftwareIdentity fallbackSoftwareIdentity) : ISecurityAuditSink
{
    private readonly AuditStore store = store ?? throw new ArgumentNullException(nameof(store));
    private readonly AuditSoftwareIdentity fallbackSoftwareIdentity = fallbackSoftwareIdentity ?? throw new ArgumentNullException(nameof(fallbackSoftwareIdentity));

    public ValueTask WriteAsync(SecurityAuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();
        var detail = new AuditSecurityDecisionDetail(record);
        var software = record.SoftwareIdentity is { } identity ? new AuditSoftwareIdentity(identity) : fallbackSoftwareIdentity;
        var auditEvent = new AuditEvent(AuditEventType.SecurityDecision, record.Actors, software,
            new AuditCapabilityId(record.CapabilityKey), new AuditResourceReference(AuditResourceKind.Command, record.Correlation.Value),
            record.EffectiveRisk is { } risk ? AuditEnumValidation.FromRiskLevel(risk) : AuditRisk.NotAssessed,
            record.Kind == SecurityAuditKind.Refused ? AuditDecision.Denied : AuditDecision.Completed,
            record.Kind == SecurityAuditKind.Refused ? AuditDecisionReason.PolicyDenied : AuditDecisionReason.NotApplicable,
            record.Origin == DecisionOrigin.Local ? AuditOrigin.Local : AuditOrigin.Remote, record.Scope.Workspace,
            null, new CorrelationId(record.Correlation.Value), null, detail);
        _ = store.Append(auditEvent, cancellationToken);
        return ValueTask.CompletedTask;
    }
}

/// <summary>Durable result recorder composed for one authenticated actor/scope; the caller owns the shared store's lifetime.</summary>
public sealed class DecisionResultRecorder : IDecisionRecorder
{
    private readonly AuditStore store;
    private readonly ActorChain actorChain;
    private readonly AuditSoftwareIdentity softwareIdentity;
    private readonly DecisionScope scope;
    private readonly AuditOrigin origin;

    public DecisionResultRecorder(AuditStore store, ActorChain actorChain, AuditSoftwareIdentity softwareIdentity,
        DecisionScope scope, DecisionOrigin origin)
    {
        this.store = store ?? throw new ArgumentNullException(nameof(store));
        this.actorChain = actorChain ?? throw new ArgumentNullException(nameof(actorChain));
        this.softwareIdentity = softwareIdentity ?? throw new ArgumentNullException(nameof(softwareIdentity));
        this.scope = scope ?? throw new ArgumentNullException(nameof(scope));
        this.origin = origin switch
        {
            DecisionOrigin.Local => AuditOrigin.Local,
            DecisionOrigin.Remote => AuditOrigin.Remote,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        store.RequireOwner(actorChain);
        if (scope.Realm != actorChain.Owner.Realm) throw new ArgumentException("A result recorder must use the owner's validated realm.", nameof(scope));
        if (actorChain.Actors.Count != 0 && actorChain.Actors[^1].SoftwareIdentity != softwareIdentity.Value)
            throw new ArgumentException("Software identity must match the final delegated actor.", nameof(softwareIdentity));
    }

    public ValueTask RecordAsync(DecisionRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);
        cancellationToken.ThrowIfCancellationRequested();
        var detail = new AuditDecisionResultDetail(record);
        var auditEvent = new AuditEvent(AuditEventType.InvocationResult, actorChain, softwareIdentity,
            new AuditCapabilityId(record.CapabilityKey), new AuditResourceReference(AuditResourceKind.Command, record.CommandId.Value),
            AuditEnumValidation.FromRiskLevel(record.EffectiveRisk), AuditDecision.Completed, AuditDecisionReason.NotApplicable,
            origin, scope.Workspace, null, new CorrelationId(record.CommandId.Value), null, detail);
        _ = store.Append(auditEvent, cancellationToken);
        return ValueTask.CompletedTask;
    }
}
