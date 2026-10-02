// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Approvals;
using Instant = ArcForges.Foundation.Instant;

namespace ArcForges.Security.Decisions;

/// <summary>Every source and sink the pipeline consumes. All are required; there is no permissive default for any of them.</summary>
public sealed class DecisionPipelineServices
{
    public DecisionPipelineServices(
        IClock clock,
        ICapabilityCatalogue catalogue,
        IProductPolicy policy,
        IActorIdentityVerifier identity,
        IScopeAuthority scope,
        ITrustEvaluator trust,
        IPermissionSource permissions,
        IResourceAuthorizer resources,
        IDataBoundaryAuthorizer dataBoundary,
        ApprovalCoordinator approvals,
        StepUpCoordinator stepUp,
        IOwnerValidator owner,
        IDecisionRecorder recorder,
        ISecurityAuditSink audit)
    {
        Clock = clock ?? throw new ArgumentNullException(nameof(clock));
        Catalogue = catalogue ?? throw new ArgumentNullException(nameof(catalogue));
        Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        Trust = trust ?? throw new ArgumentNullException(nameof(trust));
        Permissions = permissions ?? throw new ArgumentNullException(nameof(permissions));
        Resources = resources ?? throw new ArgumentNullException(nameof(resources));
        DataBoundary = dataBoundary ?? throw new ArgumentNullException(nameof(dataBoundary));
        Approvals = approvals ?? throw new ArgumentNullException(nameof(approvals));
        StepUp = stepUp ?? throw new ArgumentNullException(nameof(stepUp));
        Owner = owner ?? throw new ArgumentNullException(nameof(owner));
        Recorder = recorder ?? throw new ArgumentNullException(nameof(recorder));
        Audit = audit ?? throw new ArgumentNullException(nameof(audit));
    }

    public IClock Clock { get; }

    public ICapabilityCatalogue Catalogue { get; }

    public IProductPolicy Policy { get; }

    public IActorIdentityVerifier Identity { get; }

    public IScopeAuthority Scope { get; }

    public ITrustEvaluator Trust { get; }

    public IPermissionSource Permissions { get; }

    public IResourceAuthorizer Resources { get; }

    public IDataBoundaryAuthorizer DataBoundary { get; }

    public ApprovalCoordinator Approvals { get; }

    public StepUpCoordinator StepUp { get; }

    public IOwnerValidator Owner { get; }

    public IDecisionRecorder Recorder { get; }

    public ISecurityAuditSink Audit { get; }
}

/// <summary>Bounds of the pipeline. Both default to values that fail closed rather than wait or trust a stale decision.</summary>
public sealed record DecisionPipelineOptions
{
    /// <summary>
    /// The longest any one source or sink may take. A step whose source does not answer in time refuses, and the source's token is
    /// cancelled. The owner's operation itself is not bounded here; it is bounded by its own cancellation.
    /// </summary>
    public TimeSpan StepTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>How long a service-side decision may wait for the owner's execution. At or after this age it is stale.</summary>
    public TimeSpan ServiceDecisionLifetime { get; init; } = TimeSpan.FromSeconds(60);
}

/// <summary>
/// The security decision pipeline: fourteen ordered steps implemented once and run by the four enforcement points. The pipeline
/// holds no mutable state, so one instance serves any number of concurrent requests. A refusal names the failing step and its
/// reason; a step that cannot decide (a source that throws, times out or answers Unknown) refuses. The only route that reaches an
/// owner operation is <see cref="ExecuteAsync{TResult}"/> or <see cref="ExecuteDecidedAsync{TResult}"/>, which create the
/// <see cref="AuthorizedExecution"/> ticket only after every decision step, the owner's last, has passed.
/// </summary>
public sealed class SecurityDecisionPipeline
{
    private readonly DecisionPipelineServices _services;
    private readonly DecisionPipelineOptions _options;
    private readonly object _issuer = new();

    public SecurityDecisionPipeline(DecisionPipelineServices services, DecisionPipelineOptions? options = null)
    {
        _services = services ?? throw new ArgumentNullException(nameof(services));
        _options = options ?? new DecisionPipelineOptions();
        if (_options.StepTimeout <= TimeSpan.Zero || _options.StepTimeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The step timeout is above zero and at most five minutes.");
        }

        if (_options.ServiceDecisionLifetime <= TimeSpan.Zero || _options.ServiceDecisionLifetime > TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The service decision lifetime is above zero and at most ten minutes.");
        }
    }

    /// <summary>
    /// Runs the steps <paramref name="point"/> owns in order and stops at the first refusal. A refusal at the transport, service or
    /// owner point is written to the audit sink; a caller-side pre-check is advisory and writes nothing. An allowed
    /// <see cref="EnforcementPoint.ServiceDecision"/> is the input of <see cref="ExecuteDecidedAsync{TResult}"/>.
    /// </summary>
    public async ValueTask<SecurityDecision> EvaluateAsync(
        EnforcementPoint point,
        DecisionRequest request,
        CancellationToken cancellationToken)
    {
        if (!Enum.IsDefined(point) || point == EnforcementPoint.None)
        {
            throw new ArgumentOutOfRangeException(nameof(point));
        }

        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var run = new Run(request);
        foreach (var step in DecisionProfiles.Raw(point))
        {
            var result = await RunStepAsync(step, run, cancellationToken).ConfigureAwait(false);
            run.Set(step, result);
            if (result.Reason != DecisionReason.None)
            {
                break;
            }
        }

        return await FinishAsync(point, run).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs the service-side decision and, when it allows, the owner's final validation, the owner's operation, the result record
    /// and the audit event. The owner's operation can be reached only through this route and
    /// <see cref="ExecuteDecidedAsync{TResult}"/>.
    /// </summary>
    public async ValueTask<SecurityExecution<TResult>> ExecuteAsync<TResult>(
        DecisionRequest request,
        OwnerOperation<TResult> owner,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(owner);
        var service = await EvaluateAsync(EnforcementPoint.ServiceDecision, request, cancellationToken).ConfigureAwait(false);
        return service.Allowed
            ? await ExecuteDecidedAsync(service, request, owner, cancellationToken).ConfigureAwait(false)
            : Refused<TResult>(service);
    }

    /// <summary>
    /// Continues from this pipeline's own allowed service-side decision for exactly this request: the owner validates last, then
    /// the owner's operation runs, then its result is recorded and audited. The decision is single use and goes stale after
    /// <see cref="DecisionPipelineOptions.ServiceDecisionLifetime"/>; one that is foreign, refused, for another request, stale or
    /// already spent is refused at step 11 and the owner operation does not run.
    /// </summary>
    public async ValueTask<SecurityExecution<TResult>> ExecuteDecidedAsync<TResult>(
        SecurityDecision serviceDecision,
        DecisionRequest request,
        OwnerOperation<TResult> owner,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(serviceDecision);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(owner);
        cancellationToken.ThrowIfCancellationRequested();
        var run = new Run(request);
        var reason = CheckServiceDecision(serviceDecision, request, run);
        if (reason == DecisionReason.None)
        {
            var validated = await OwnerStepAsync(run, serviceDecision, cancellationToken).ConfigureAwait(false);
            run.Set(DecisionStep.OwnerValidation, validated);
            reason = validated.Reason;
        }
        else
        {
            run.Set(DecisionStep.OwnerValidation, StepResult.Refuse(reason));
        }

        if (reason != DecisionReason.None)
        {
            return Refused<TResult>(await FinishAsync(EnforcementPoint.OwnerFinalValidation, run).ConfigureAwait(false));
        }

        var ticketDecision = BuildDecision(EnforcementPoint.OwnerFinalValidation, run, DecisionAuditStatus.NotDue);
        var ticket = new AuthorizedExecution(ticketDecision, request, run.Risk!);
        cancellationToken.ThrowIfCancellationRequested();
        var ownerResult = await RunOwnerAsync(owner, ticket, cancellationToken).ConfigureAwait(false);
        return await CompleteAsync(run, ownerResult).ConfigureAwait(false);
    }

    /// <summary>
    /// Projects the permission of the request's principal for its capability and scope as read-only evidence for a user-interface
    /// preflight. Nothing is consumed, granted or cached, and no other step runs.
    /// </summary>
    public async ValueTask<PermissionAvailabilityEvidence> ProjectPermissionAsync(
        DecisionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var (_, evidence) = await PermissionAsync(request, cancellationToken).ConfigureAwait(false);
        return evidence;
    }

    private static SecurityExecution<TResult> Refused<TResult>(SecurityDecision decision) => new(
        decision,
        ExecutionStatus.Refused,
        Outcome.Failure<TResult>(TypedFailure.Create(decision.RegisteredCode)),
        null,
        EffectCertainty.DidNotHappen);

    private static bool IsApprovalRequired(CapabilityDescriptor descriptor, RiskLevel effective) =>
        effective >= RiskLevel.R3
        || !descriptor.HasApproval
        || !string.Equals(descriptor.Approval, "none", StringComparison.Ordinal);

    private static EgressClass EgressOf(CapabilityDescriptor descriptor)
    {
        if (!descriptor.HasEgress)
        {
            return EgressClass.External;
        }

        return descriptor.Egress switch
        {
            "none" => EgressClass.None,
            "ownedContent" => EgressClass.Owned,
            _ => EgressClass.External,
        };
    }

    private static DateTimeOffset ToUtc(Instant instant) =>
        DateTimeOffset.FromUnixTimeSeconds(instant.UnixSeconds).AddTicks(instant.Nanoseconds / 100);

    private async ValueTask<StepResult> RunStepAsync(DecisionStep step, Run run, CancellationToken cancellationToken) => step switch
    {
        DecisionStep.CapabilityExists => await CapabilityStepAsync(run, cancellationToken).ConfigureAwait(false),
        DecisionStep.ProductPolicy => await PolicyStepAsync(run, cancellationToken).ConfigureAwait(false),
        DecisionStep.ActorIdentity => await ActorStepAsync(run, cancellationToken).ConfigureAwait(false),
        DecisionStep.ScopeValid => await ScopeStepAsync(run, cancellationToken).ConfigureAwait(false),
        DecisionStep.TrustEligible => await TrustStepAsync(run, cancellationToken).ConfigureAwait(false),
        DecisionStep.CapabilityPermission => await PermissionStepAsync(run, cancellationToken).ConfigureAwait(false),
        DecisionStep.ResourceAuthorization => await ResourceStepAsync(run, cancellationToken).ConfigureAwait(false),
        DecisionStep.DataBoundary => await DataBoundaryStepAsync(run, cancellationToken).ConfigureAwait(false),
        DecisionStep.EffectiveRisk => RiskStep(run),
        DecisionStep.ApprovalAndPresence => await ApprovalStepAsync(run, cancellationToken).ConfigureAwait(false),
        DecisionStep.OwnerValidation => await OwnerStepAsync(run, null, cancellationToken).ConfigureAwait(false),
        _ => throw new InvalidOperationException("The step is not a decision step."),
    };

    private async ValueTask<StepResult> CapabilityStepAsync(Run run, CancellationToken cancellationToken)
    {
        var request = run.Request;
        var found = await CallAsync(token => _services.Catalogue.FindAsync(request.CapabilityKey, token), cancellationToken).ConfigureAwait(false);
        if (!found.Ok)
        {
            return StepResult.Refuse(DecisionReason.S01Unavailable);
        }

        var descriptor = found.Value;
        if (descriptor is null || !descriptor.HasKey || !string.Equals(descriptor.Key, request.CapabilityKey, StringComparison.Ordinal))
        {
            return StepResult.Refuse(DecisionReason.S01CapabilityUnknown);
        }

        run.Descriptor = descriptor.Clone();
        run.Egress = EgressOf(run.Descriptor);
        return StepResult.Pass;
    }

    private async ValueTask<StepResult> PolicyStepAsync(Run run, CancellationToken cancellationToken)
    {
        var request = run.Request;
        var verdict = await CallAsync(token => _services.Policy.EvaluateAsync(request, token), cancellationToken).ConfigureAwait(false);
        if (!verdict.Ok)
        {
            return StepResult.Refuse(DecisionReason.S02Unavailable);
        }

        return verdict.Value switch
        {
            PolicyVerdict.Enabled => StepResult.Pass,
            PolicyVerdict.Disabled => StepResult.Refuse(DecisionReason.S02PolicyDisabled),
            _ => StepResult.Refuse(DecisionReason.S02PolicyUnknown),
        };
    }

    private async ValueTask<StepResult> ActorStepAsync(Run run, CancellationToken cancellationToken)
    {
        var request = run.Request;
        var session = request.Transport;
        var transport = await CallAsync(session.VerifyCurrentAsync, cancellationToken).ConfigureAwait(false);
        if (!transport.Ok)
        {
            return StepResult.Refuse(DecisionReason.S03Unavailable);
        }

        var verdict = transport.Value;
        var binding = verdict?.Binding;
        if (verdict is null || verdict.Refusal != TransportRefusal.None || binding is null
            || session.Kind == TransportKind.None || binding.Kind != session.Kind)
        {
            return StepResult.Refuse(DecisionReason.S03TransportRefused);
        }

        run.Transport = binding;
        if (binding.BoundCallerInstance is { } bound && bound != request.Actors.CallerInstance)
        {
            return StepResult.Refuse(DecisionReason.S03CallerInstanceMismatch);
        }

        var identity = await CallAsync(token => _services.Identity.VerifyAsync(request, token), cancellationToken).ConfigureAwait(false);
        if (!identity.Ok)
        {
            return StepResult.Refuse(DecisionReason.S03Unavailable);
        }

        return identity.Value switch
        {
            ActorIdentityVerdict.Authenticated => StepResult.Pass,
            ActorIdentityVerdict.Unauthenticated => StepResult.Refuse(DecisionReason.S03Unauthenticated),
            ActorIdentityVerdict.SessionExpired => StepResult.Refuse(DecisionReason.S03SessionExpired),
            _ => StepResult.Refuse(DecisionReason.S03Unavailable),
        };
    }

    private async ValueTask<StepResult> ScopeStepAsync(Run run, CancellationToken cancellationToken)
    {
        var request = run.Request;
        if (request.Scope.Realm != request.Actors.Owner.Realm)
        {
            return StepResult.Refuse(DecisionReason.S04RealmMismatch);
        }

        var verdict = await CallAsync(token => _services.Scope.ValidateAsync(request, token), cancellationToken).ConfigureAwait(false);
        if (!verdict.Ok)
        {
            return StepResult.Refuse(DecisionReason.S04Unavailable);
        }

        return verdict.Value switch
        {
            ScopeVerdict.Valid => StepResult.Pass,
            ScopeVerdict.Invalid => StepResult.Refuse(DecisionReason.S04WorkspaceInvalid),
            _ => StepResult.Refuse(DecisionReason.S04Unavailable),
        };
    }

    private async ValueTask<StepResult> TrustStepAsync(Run run, CancellationToken cancellationToken)
    {
        var request = run.Request;
        var binding = run.Transport;
        var verdict = await CallAsync(token => _services.Trust.EvaluateAsync(request, binding, token), cancellationToken).ConfigureAwait(false);
        if (!verdict.Ok)
        {
            return StepResult.Refuse(DecisionReason.S05Unavailable);
        }

        switch (verdict.Value)
        {
            case TrustVerdict.Verified:
                run.PackageVerified = true;
                return StepResult.Pass;
            case TrustVerdict.Unverified:
                run.PackageVerified = false;
                return StepResult.Pass;
            case TrustVerdict.Revoked:
                return StepResult.Refuse(DecisionReason.S05TrustRevoked);
            default:
                return StepResult.Refuse(DecisionReason.S05TrustUnknown);
        }
    }

    private async ValueTask<StepResult> PermissionStepAsync(Run run, CancellationToken cancellationToken)
    {
        var (reason, evidence) = await PermissionAsync(run.Request, cancellationToken).ConfigureAwait(false);
        run.Permission = evidence;
        return reason == DecisionReason.None ? StepResult.Pass : StepResult.Refuse(reason);
    }

    private async ValueTask<(DecisionReason Reason, PermissionAvailabilityEvidence Evidence)> PermissionAsync(
        DecisionRequest request,
        CancellationToken cancellationToken)
    {
        var principal = request.PrincipalKey;
        var scope = request.ScopeKey;
        var capability = request.CapabilityKey;
        var observed = _services.Clock.GetCurrentInstant();
        var observedUtc = ToUtc(observed);

        (DecisionReason, PermissionAvailabilityEvidence) Result(DecisionReason reason, PermissionDisposition disposition, PermissionGrantRecord? grant) =>
            (reason, new PermissionAvailabilityEvidence(principal, capability, scope, disposition, reason, grant, observedUtc));

        var found = await CallAsync(token => _services.Permissions.FindAsync(request, token), cancellationToken).ConfigureAwait(false);
        if (!found.Ok)
        {
            return Result(DecisionReason.S06Unavailable, PermissionDisposition.Unknown, null);
        }

        var grant = found.Value;
        if (grant is null)
        {
            return Result(DecisionReason.S06NotGranted, PermissionDisposition.Required, null);
        }

        if (!string.Equals(grant.PrincipalKey, principal, StringComparison.Ordinal)
            || !string.Equals(grant.CapabilityKey, capability, StringComparison.Ordinal)
            || !string.Equals(grant.ScopeKey, scope, StringComparison.Ordinal))
        {
            return Result(DecisionReason.S06GrantMismatch, PermissionDisposition.Unknown, null);
        }

        switch (grant.State)
        {
            case PermissionGrantState.ExplicitlyDenied:
                return Result(DecisionReason.S06ExplicitlyDenied, PermissionDisposition.Denied, grant);
            case PermissionGrantState.Granted:
                break;
            default:
                return Result(DecisionReason.S06NotGranted, PermissionDisposition.Required, grant);
        }

        // The lifetime is half open: valid from its start, already over at its end. Expiry is judged at use, not at issue.
        if (observed < Instant.FromDateTimeOffset(grant.ValidFromUtc) || observed >= Instant.FromDateTimeOffset(grant.ValidUntilUtc))
        {
            return Result(DecisionReason.S06OutsideLifetime, PermissionDisposition.Required, grant);
        }

        var device = PermissionConstraints.DeviceBound(request.Actors.Device);
        var understood = true;
        var met = true;
        foreach (var constraint in grant.Constraints)
        {
            if (string.Equals(constraint, PermissionConstraints.LocalOriginOnly, StringComparison.Ordinal))
            {
                met &= request.Origin == DecisionOrigin.Local;
            }
            else if (constraint.StartsWith("device:", StringComparison.Ordinal))
            {
                met &= string.Equals(constraint, device, StringComparison.Ordinal);
            }
            else
            {
                understood = false;
            }
        }

        if (!understood)
        {
            return Result(DecisionReason.S06ConstraintUnknown, PermissionDisposition.Required, grant);
        }

        return met
            ? Result(DecisionReason.None, PermissionDisposition.Granted, grant)
            : Result(DecisionReason.S06ConstraintUnmet, PermissionDisposition.Required, grant);
    }

    private async ValueTask<StepResult> ResourceStepAsync(Run run, CancellationToken cancellationToken)
    {
        var request = run.Request;
        var verdict = await CallAsync(token => _services.Resources.AuthorizeAsync(request, token), cancellationToken).ConfigureAwait(false);
        if (!verdict.Ok || verdict.Value is null)
        {
            return StepResult.Refuse(DecisionReason.S07Unavailable);
        }

        var value = verdict.Value;
        switch (value.Disposition)
        {
            case ResourceDisposition.Authorized:
                if (value.Facts is null)
                {
                    return StepResult.Refuse(DecisionReason.S07Unavailable);
                }

                run.Facts = run.Facts.MostSevere(value.Facts);
                return StepResult.Pass;
            case ResourceDisposition.Denied:
                return StepResult.Refuse(DecisionReason.S07ResourceDenied);
            default:
                return StepResult.Refuse(DecisionReason.S07Unavailable);
        }
    }

    private async ValueTask<StepResult> DataBoundaryStepAsync(Run run, CancellationToken cancellationToken)
    {
        var request = run.Request;
        var egress = run.Egress;
        var destination = request.EgressDestination;
        if (egress == EgressClass.None && destination is not null)
        {
            return StepResult.Refuse(DecisionReason.S08EgressNotDeclared);
        }

        var egressRequired = egress != EgressClass.None;
        if (egressRequired && destination is null)
        {
            return StepResult.Refuse(DecisionReason.S08EgressDestinationUnspecified);
        }

        var secretUse = request.SecretUseKey is not null;
        if (!egressRequired && !secretUse)
        {
            return StepResult.NotRequired;
        }

        if (secretUse)
        {
            var secret = await CallAsync(token => _services.DataBoundary.AuthorizeSecretUseAsync(request, token), cancellationToken).ConfigureAwait(false);
            if (!secret.Ok)
            {
                return StepResult.Refuse(DecisionReason.S08Unavailable);
            }

            switch (secret.Value)
            {
                case BoundaryVerdict.Allowed:
                    break;
                case BoundaryVerdict.Denied:
                    return StepResult.Refuse(DecisionReason.S08SecretUseDenied);
                default:
                    return StepResult.Refuse(DecisionReason.S08Unavailable);
            }
        }

        if (egressRequired)
        {
            var exact = destination!;
            var sent = await CallAsync(token => _services.DataBoundary.AuthorizeEgressAsync(request, exact, token), cancellationToken).ConfigureAwait(false);
            if (!sent.Ok)
            {
                return StepResult.Refuse(DecisionReason.S08Unavailable);
            }

            switch (sent.Value)
            {
                case BoundaryVerdict.Allowed:
                    break;
                case BoundaryVerdict.Denied:
                    return StepResult.Refuse(DecisionReason.S08EgressDenied);
                default:
                    return StepResult.Refuse(DecisionReason.S08Unavailable);
            }
        }

        return StepResult.Pass;
    }

    private static StepResult RiskStep(Run run)
    {
        var request = run.Request;
        var facts = run.Facts;
        var kinds = request.Actors.Actors.Count == 0
            ? [ActorKind.None]
            : request.Actors.Actors.Select(actor => actor.Kind).Distinct().ToArray();
        RiskAssessment? highest = null;
        try
        {
            foreach (var kind in kinds)
            {
                var assessment = RiskModel.Assess(
                    run.Descriptor!,
                    new RiskContext(
                        facts.Scope,
                        facts.Target,
                        facts.Reversibility,
                        run.Egress == EgressClass.External ? RiskEgress.External : RiskEgress.None,
                        kind,
                        request.Origin == DecisionOrigin.Remote,
                        run.PackageVerified,
                        facts.IsLargeDataVolume));
                if (highest is null || assessment.EffectiveRisk > highest.EffectiveRisk)
                {
                    highest = assessment;
                }
            }
        }
        catch (ArgumentException)
        {
            return StepResult.Refuse(DecisionReason.S09RiskUnclassifiable);
        }

        run.Risk = highest;
        return StepResult.Pass;
    }

    private async ValueTask<StepResult> ApprovalStepAsync(Run run, CancellationToken cancellationToken)
    {
        var request = run.Request;
        var effective = run.Risk!.EffectiveRisk;
        var approvalRequired = IsApprovalRequired(run.Descriptor!, effective);
        var stepUpRequired = request.SensitiveOperation != SensitiveOperation.None || effective == RiskLevel.R4;
        if (!approvalRequired && !stepUpRequired)
        {
            return StepResult.NotRequired;
        }

        if (effective == RiskLevel.R4 && request.Origin == DecisionOrigin.Remote)
        {
            // A remote request can never carry local presence (LP-02), however it was approved.
            return StepResult.Refuse(DecisionReason.S10LocalPresenceRequired);
        }

        if (approvalRequired)
        {
            var refusal = await CheckApprovalAsync(request, effective, cancellationToken).ConfigureAwait(false);
            if (refusal != DecisionReason.None)
            {
                return StepResult.Refuse(refusal);
            }
        }

        if (stepUpRequired)
        {
            var proof = request.StepUpProof;
            if (effective == RiskLevel.R4 && request.SensitiveOperation == SensitiveOperation.None)
            {
                return StepResult.Refuse(DecisionReason.S10StepUpOperationUnspecified);
            }

            if (proof is null)
            {
                return StepResult.Refuse(DecisionReason.S10StepUpRequired);
            }

            if (effective == RiskLevel.R4 && !proof.LocalPresenceConfirmed)
            {
                return StepResult.Refuse(DecisionReason.S10LocalPresenceRequired);
            }

            // The consumption is the last act of the step: a proof is spent only when every other requirement already holds.
            if (!_services.StepUp.TryConsume(proof, request.Actors.Owner, request.CommandId, request.SensitiveOperation, run.Risk!))
            {
                return StepResult.Refuse(DecisionReason.S10StepUpInvalid);
            }
        }

        return StepResult.Pass;
    }

    private async ValueTask<DecisionReason> CheckApprovalAsync(DecisionRequest request, RiskLevel effective, CancellationToken cancellationToken)
    {
        if (request.ApprovalId is not { } approvalId)
        {
            return DecisionReason.S10ApprovalRequired;
        }

        var read = await CallAsync(token => _services.Approvals.GetAsync(approvalId, token), cancellationToken).ConfigureAwait(false);
        if (!read.Ok || read.Value is null)
        {
            return DecisionReason.S10Unavailable;
        }

        if (!read.Value.TryGetValue(out var snapshot))
        {
            return read.Value.TryGetFailure(out var failure) && string.Equals(failure.Code, "perm.approval_required", StringComparison.Ordinal)
                ? DecisionReason.S10ApprovalRequired
                : DecisionReason.S10Unavailable;
        }

        switch (snapshot.State)
        {
            case ApprovalState.Approved:
                break;
            case ApprovalState.Pending:
                return DecisionReason.S10ApprovalPending;
            case ApprovalState.Expired:
                return DecisionReason.S10ApprovalExpired;
            case ApprovalState.Denied:
            case ApprovalState.Cancelled:
                return DecisionReason.S10ApprovalDenied;
            default:
                return DecisionReason.S10Unavailable;
        }

        // Every approval expires (AP-07), an approved one included; the coordinator only expires a pending request.
        if (_services.Clock.GetCurrentInstant() >= snapshot.ExpiresAt)
        {
            return DecisionReason.S10ApprovalExpired;
        }

        var decision = snapshot.Decision;
        if (decision is null || decision.Kind != ApprovalDecisionKind.Approve || decision.DecidedBy != request.Actors.Owner
            || snapshot.Owner != request.Actors.Owner || snapshot.CommandId != request.CommandId
            || !string.Equals(snapshot.OperationId, request.CapabilityKey, StringComparison.Ordinal)
            || !string.Equals(snapshot.TargetResourceId, request.Resource.Id, StringComparison.Ordinal)
            || !string.Equals(snapshot.TargetRevision, request.Resource.Revision, StringComparison.Ordinal)
            || !string.Equals(snapshot.EffectSha256, request.EffectSha256, StringComparison.Ordinal)
            || snapshot.EffectiveRisk != effective)
        {
            return DecisionReason.S10ApprovalMismatch;
        }

        return effective == RiskLevel.R4 && decision.Origin != ApprovalOrigin.Local
            ? DecisionReason.S10LocalPresenceRequired
            : DecisionReason.None;
    }

    private async ValueTask<StepResult> OwnerStepAsync(Run run, SecurityDecision? service, CancellationToken cancellationToken)
    {
        var request = run.Request;
        var validation = new OwnerValidationRequest(request, service?.Risk, service);
        var verdict = await CallAsync(token => _services.Owner.ValidateAsync(validation, token), cancellationToken).ConfigureAwait(false);
        if (!verdict.Ok)
        {
            return StepResult.Refuse(DecisionReason.S11Unavailable);
        }

        return verdict.Value switch
        {
            OwnerVerdict.Valid => StepResult.Pass,
            OwnerVerdict.Refused => StepResult.Refuse(DecisionReason.S11OwnerRefused),
            OwnerVerdict.RevisionChanged => StepResult.Refuse(DecisionReason.S11OwnerRevisionChanged),
            _ => StepResult.Refuse(DecisionReason.S11Unavailable),
        };
    }

    /// <summary>Checks a service decision without spending it, then spends it; the first failing check names the refusal.</summary>
    private DecisionReason CheckServiceDecision(SecurityDecision service, DecisionRequest request, Run run)
    {
        if (!ReferenceEquals(service.Issuer, _issuer) || service.Point != EnforcementPoint.ServiceDecision
            || !service.Allowed || !ReferenceEquals(service.Request, request))
        {
            return DecisionReason.S11ServiceDecisionInvalid;
        }

        run.AdoptServiceDecision(service);
        if (IsStale(service))
        {
            return DecisionReason.S11ServiceDecisionStale;
        }

        return service.TryConsume() ? DecisionReason.None : DecisionReason.S11ServiceDecisionInvalid;
    }

    /// <summary>
    /// A service decision is stale at or after its lifetime on whichever clock gets there first: the monotonic clock, which a
    /// wall-clock step back cannot extend, or the wall clock, which a step forward shortens.
    /// </summary>
    private bool IsStale(SecurityDecision service)
    {
        var clock = _services.Clock;
        var lifetime = _options.ServiceDecisionLifetime;
        if (clock.GetElapsedTime(service.DecidedMonotonic, clock.GetTimestamp()) >= lifetime)
        {
            return true;
        }

        var now = clock.GetCurrentInstant();
        var seconds = now.UnixSeconds - service.DecidedAt.UnixSeconds;
        var nanoseconds = (long)now.Nanoseconds - service.DecidedAt.Nanoseconds;
        var elapsedTicks = checked((seconds * TimeSpan.TicksPerSecond) + (nanoseconds / 100));
        return elapsedTicks >= lifetime.Ticks;
    }

    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "The owner's exception must become a typed failure with unknown effect; no exception text crosses the boundary.")]
    private static async ValueTask<Outcome<TResult>> RunOwnerAsync<TResult>(
        OwnerOperation<TResult> owner,
        AuthorizedExecution ticket,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await owner(ticket, cancellationToken).ConfigureAwait(false);
            return result ?? Outcome.Failure<TResult>(TypedFailure.Create("internal.unexpected"));
        }
        catch (OperationCanceledException)
        {
            return Outcome.Cancelled<TResult>(EffectCertainty.Unknown);
        }
        catch (Exception)
        {
            return Outcome.Failure<TResult>(TypedFailure.Create("internal.unexpected"));
        }
    }

    private async ValueTask<SecurityExecution<TResult>> CompleteAsync<TResult>(Run run, Outcome<TResult> ownerResult)
    {
        var request = run.Request;
        var risk = run.Risk!;
        DecisionResultKind kind;
        EffectCertainty effect;
        string? failureCode = null;
        Outcome<TResult> normalized = ownerResult;
        switch (ownerResult.Kind)
        {
            case OutcomeKind.Success:
                kind = DecisionResultKind.Success;
                effect = EffectCertainty.Happened;
                break;
            case OutcomeKind.Failure:
                kind = DecisionResultKind.Failure;
                ownerResult.TryGetFailure(out var failure);
                var known = failure is { IsKnownCode: true } ? failure : TypedFailure.Create("internal.unexpected");
                failureCode = known.Code;
                effect = known.Effect;
                normalized = ReferenceEquals(known, failure) ? ownerResult : Outcome.Failure<TResult>(known);
                break;
            default:
                kind = DecisionResultKind.Cancelled;
                effect = ownerResult.CancellationEffect;
                break;
        }

        run.Set(
            DecisionStep.Execution,
            kind == DecisionResultKind.Success ? StepResult.Pass : StepResult.Refuse(DecisionReason.S12OwnerFailed));

        var recorded = await BookkeepAsync(
            token => _services.Recorder.RecordAsync(
                new DecisionRecord(request.CommandId, request.CapabilityKey, request.Resource, risk.EffectiveRisk, kind, failureCode, effect, _services.Clock.GetCurrentInstant()),
                token)).ConfigureAwait(false);
        run.Set(DecisionStep.ResultRecording, recorded ? StepResult.Pass : StepResult.Refuse(DecisionReason.S13RecordFailed));

        var auditKind = kind switch
        {
            DecisionResultKind.Success => SecurityAuditKind.Executed,
            DecisionResultKind.Failure => SecurityAuditKind.OwnerFailed,
            _ => SecurityAuditKind.OwnerCancelled,
        };
        var audited = await BookkeepAsync(
            token => _services.Audit.WriteAsync(
                AuditRecord(
                    auditKind,
                    EnforcementPoint.OwnerFinalValidation,
                    DecisionStep.None,
                    kind == DecisionResultKind.Success ? string.Empty : DecisionReasons.Describe(DecisionReason.S12OwnerFailed).Code,
                    failureCode ?? string.Empty,
                    request,
                    risk.EffectiveRisk,
                    effect),
                token)).ConfigureAwait(false);
        run.Set(DecisionStep.AuditWrite, audited ? StepResult.Pass : StepResult.Refuse(DecisionReason.S14AuditFailed));

        var decision = BuildDecision(
            EnforcementPoint.OwnerFinalValidation,
            run,
            audited ? DecisionAuditStatus.Written : DecisionAuditStatus.Failed);
        if (!recorded || !audited)
        {
            var visible = kind == DecisionResultKind.Success
                ? Outcome.Failure<TResult>(TypedFailure.Create("internal.unexpected", effect: EffectCertainty.Happened))
                : normalized;
            return new SecurityExecution<TResult>(decision, ExecutionStatus.BookkeepingFailed, visible, normalized, effect);
        }

        var status = kind switch
        {
            DecisionResultKind.Success => ExecutionStatus.Succeeded,
            DecisionResultKind.Failure => ExecutionStatus.OwnerFailed,
            _ => ExecutionStatus.OwnerCancelled,
        };
        return new SecurityExecution<TResult>(decision, status, normalized, normalized, effect);
    }

    private async ValueTask<SecurityDecision> FinishAsync(EnforcementPoint point, Run run)
    {
        var failed = run.FirstRefusal();
        var audit = DecisionAuditStatus.NotDue;
        if (failed is { } refusal && point != EnforcementPoint.CallerPreCheck)
        {
            var info = DecisionReasons.Describe(refusal.Reason);
            var audited = await BookkeepAsync(
                token => _services.Audit.WriteAsync(
                    AuditRecord(
                        SecurityAuditKind.Refused,
                        point,
                        refusal.Step,
                        info.Code,
                        info.RegisteredCode,
                        run.Request,
                        run.Risk?.EffectiveRisk,
                        EffectCertainty.DidNotHappen),
                    token)).ConfigureAwait(false);
            run.Set(DecisionStep.AuditWrite, audited ? StepResult.Pass : StepResult.Refuse(DecisionReason.S14AuditFailed));
            audit = audited ? DecisionAuditStatus.Written : DecisionAuditStatus.Failed;
        }

        return BuildDecision(point, run, audit);
    }

    private SecurityDecision BuildDecision(EnforcementPoint point, Run run, DecisionAuditStatus audit) => new(
        _issuer,
        point,
        run.Request,
        [.. run.Outcomes],
        run.Risk,
        run.Permission,
        run.Transport,
        _services.Clock.GetCurrentInstant(),
        _services.Clock.GetTimestamp(),
        audit);

    private SecurityAuditRecord AuditRecord(
        SecurityAuditKind kind,
        EnforcementPoint point,
        DecisionStep failedStep,
        string reasonCode,
        string registeredCode,
        DecisionRequest request,
        RiskLevel? risk,
        EffectCertainty effect)
    {
        var chain = request.Actors;
        var last = chain.Actors.Count == 0 ? null : chain.Actors[^1];
        return new SecurityAuditRecord(
            kind,
            point,
            failedStep,
            reasonCode,
            registeredCode,
            _services.Clock.GetCurrentInstant(),
            chain,
            last?.Executor ?? chain.CallerInstance,
            last?.SoftwareIdentity,
            request.CapabilityKey,
            request.Resource,
            risk,
            request.Origin,
            chain.Device,
            request.Scope,
            request.CommandId,
            effect);
    }

    /// <summary>
    /// Runs a source with its token linked to the caller's and bounded by the step timeout. A source that throws, is cancelled by
    /// the timeout or does not answer in time reports failure; only the caller's own cancellation propagates.
    /// </summary>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A source that throws must refuse its step rather than escape the decision boundary; no exception text is retained.")]
    private async ValueTask<PortResult<T>> CallAsync<T>(Func<CancellationToken, ValueTask<T>> invoke, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(_options.StepTimeout);
        Task<T> task;
        try
        {
            task = invoke(linked.Token).AsTask();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return PortResult<T>.Failed;
        }

        try
        {
            return new PortResult<T>(true, await task.WaitAsync(_options.StepTimeout, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException)
        {
            await linked.CancelAsync().ConfigureAwait(false);
            _ = task.ContinueWith(static finished => _ = finished.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return PortResult<T>.Failed;
        }
        catch (Exception)
        {
            return PortResult<T>.Failed;
        }
    }

    /// <summary>
    /// Runs a result or audit sink. These writes must not be lost to the caller's cancellation after the owner already ran, so they
    /// are bounded only by the step timeout. A sink that throws or times out reports failure.
    /// </summary>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A failing sink is reported as a failed bookkeeping step, never an escaping exception that would hide an effect that already happened.")]
    private async ValueTask<bool> BookkeepAsync(Func<CancellationToken, ValueTask> write)
    {
        using var linked = new CancellationTokenSource(_options.StepTimeout);
        Task task;
        try
        {
            task = write(linked.Token).AsTask();
        }
        catch (Exception)
        {
            return false;
        }

        try
        {
            await task.WaitAsync(_options.StepTimeout).ConfigureAwait(false);
            return true;
        }
        catch (TimeoutException)
        {
            await linked.CancelAsync().ConfigureAwait(false);
            _ = task.ContinueWith(static finished => _ = finished.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private enum EgressClass
    {
        None = 0,
        Owned = 1,
        External = 2,
    }

    private readonly record struct PortResult<T>(bool Ok, T Value)
    {
        public static PortResult<T> Failed { get; } = new(false, default!);
    }

    private readonly record struct StepResult(DecisionReason Reason, bool IsNotRequired)
    {
        public static StepResult Pass { get; } = new(DecisionReason.None, false);

        public static StepResult NotRequired { get; } = new(DecisionReason.None, true);

        public static StepResult Refuse(DecisionReason reason) => new(reason, false);
    }

    private sealed class Run
    {
        public Run(DecisionRequest request)
        {
            Request = request;
            Facts = request.DeclaredFacts;
            for (var index = 0; index < Outcomes.Length; index++)
            {
                Outcomes[index] = new StepOutcome((DecisionStep)(index + 1), StepDisposition.NotRun, DecisionReason.None);
            }
        }

        public DecisionRequest Request { get; }

        public StepOutcome[] Outcomes { get; } = new StepOutcome[14];

        public CapabilityDescriptor? Descriptor { get; set; }

        public TransportBinding? Transport { get; set; }

        public bool PackageVerified { get; set; }

        public PermissionAvailabilityEvidence? Permission { get; set; }

        public RiskFacts Facts { get; set; }

        public EgressClass Egress { get; set; }

        public RiskAssessment? Risk { get; set; }

        public void Set(DecisionStep step, StepResult result) => Outcomes[(int)step - 1] = new StepOutcome(
            step,
            result.Reason != DecisionReason.None ? StepDisposition.Refused
                : result.IsNotRequired ? StepDisposition.NotRequired : StepDisposition.Passed,
            result.Reason);

        public StepOutcome? FirstRefusal()
        {
            foreach (var outcome in Outcomes)
            {
                if (outcome.Disposition == StepDisposition.Refused && outcome.Step <= DecisionStep.OwnerValidation)
                {
                    return outcome;
                }
            }

            return null;
        }

        /// <summary>Carries the earlier points' outcomes, risk, permission and transport into the owner-side decision.</summary>
        public void AdoptServiceDecision(SecurityDecision service)
        {
            for (var index = 0; index < (int)DecisionStep.OwnerValidation - 1; index++)
            {
                Outcomes[index] = service.StepArray[index];
            }

            Risk = service.Risk;
            Permission = service.Permission;
            Transport = service.Transport;
        }
    }
}
