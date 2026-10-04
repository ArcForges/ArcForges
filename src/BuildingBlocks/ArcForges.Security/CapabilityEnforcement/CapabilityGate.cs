// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Capabilities;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;
using ArcForges.Sdk.Contracts.V1;
using ArcForges.Security.Decisions;
using ArcForges.Security.Leases;
using Google.Protobuf;

namespace ArcForges.Security.CapabilityEnforcement;

/// <summary>
/// The owner's operation for one capability, written against the decision pipeline's <see cref="AuthorizedExecution"/> ticket. The
/// ticket has no public constructor, so an operation that requires it cannot be called without the pipeline having decided every step
/// up to the owner's final validation for exactly this invocation.
/// </summary>
public delegate ValueTask<Outcome<TResult>> EnforcedOwnerOperation<TArguments, TResult>(
    AuthorizedExecution ticket,
    CapabilityTarget target,
    Invocation invocation,
    TArguments arguments,
    FrozenContextSnapshot context,
    CancellationToken cancellationToken);

/// <summary>
/// Attaches the real security decision pipeline to the invocation pipeline (WP-09.07 authorize, WP-11.02). The gate supplies exactly
/// two things to <see cref="CapabilityInvocationPipeline"/> and changes nothing in it: the <see cref="CapabilityInvocationAuthorization"/>
/// step (<see cref="AuthorizeAsync"/>), which runs the service-side decision (steps 1 to 10) for the invocation, and the owner side
/// (<see cref="Enforce{TArguments, TResult}"/>), which runs the owner's final validation (step 11) last, then the owner's operation,
/// the result record (step 13) and the audit event (step 14). Resolution, availability, context freezing, the idempotency journal
/// and tracing stay in the invocation pipeline.
/// </summary>
/// <remarks>
/// A refusal carries the registered code of the failing step's reason and the owner operation never runs. Anything the gate cannot
/// establish (no evidence, a malformed identity, a decision that is missing, spent or for another invocation) refuses; the gate has
/// no permissive path. A binding whose owner operation does not come from <see cref="Enforce{TArguments, TResult}"/> is not gated at
/// the owner side because the invocation pipeline cannot be asked to refuse it: a host composition must route every binding through
/// the gate. One gate serves concurrent invocations; its only state is the admission of each invocation's own frozen context.
/// </remarks>
public sealed class CapabilityEnforcementGate
{
    private readonly SecurityDecisionPipeline _pipeline;
    private readonly ICapabilityEvidenceSource _evidence;
    private readonly ConditionalWeakTable<FrozenContextSnapshot, Admission> _admissions = [];

    public CapabilityEnforcementGate(SecurityDecisionPipeline pipeline, ICapabilityEvidenceSource evidence)
    {
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _evidence = evidence ?? throw new ArgumentNullException(nameof(evidence));
    }

    /// <summary>
    /// The authorize step of the invocation pipeline: the service-side decision of this exact invocation. Success means every step
    /// from capability existence to approval and presence allowed it; the allowed decision is held for this invocation's context
    /// until the owner side spends it. Pass this method as the pipeline's <see cref="CapabilityInvocationAuthorization"/>.
    /// </summary>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A host evidence source that fails must refuse the invocation with a typed failure; no exception text crosses the capability boundary.")]
    public async ValueTask<Outcome<bool>> AuthorizeAsync(
        CapabilityRegistration capability,
        Invocation invocation,
        CapabilityTarget target,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(invocation);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(context);
        if (!invocation.HasCapability || !string.Equals(invocation.Capability, capability.Key, StringComparison.Ordinal))
        {
            return Failure<bool>("validation.invalid_request");
        }

        CapabilityEvidence? evidence;
        try
        {
            evidence = await _evidence.DescribeAsync(capability, invocation.Clone(), target, context, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return Failure<bool>("resource.unavailable");
        }

        if (evidence is null)
        {
            return Failure<bool>("resource.unavailable");
        }

        DecisionRequest request;
        try
        {
            request = new DecisionRequest(
                evidence.Actors,
                capability.Key,
                evidence.Scope,
                new CommandId(UuidBoundary.FromWire(invocation.CommandId)),
                evidence.Resource,
                EffectDigest(capability, invocation, target),
                evidence.Origin,
                evidence.Transport,
                evidence.DeclaredFacts,
                evidence.EgressDestination,
                evidence.SecretUseKey,
                invocation.ApprovalId is null ? null : UuidBoundary.FromWire(invocation.ApprovalId),
                evidence.StepUpProof,
                evidence.SensitiveOperation,
                invocation.LeaseId is null ? null : new CapabilityLeaseId(UuidBoundary.FromWire(invocation.LeaseId)));
        }
        catch (ArgumentException)
        {
            return Failure<bool>("validation.invalid_request");
        }

        var decision = await _pipeline.EvaluateAsync(EnforcementPoint.ServiceDecision, request, cancellationToken).ConfigureAwait(false);
        if (decision.Allowed)
        {
            _admissions.AddOrUpdate(context, new Admission(decision, request));
        }

        return decision.ToAuthorizationOutcome();
    }

    /// <summary>
    /// Wraps the owner's operation for the invocation pipeline's binding. When it runs it spends the admission that
    /// <see cref="AuthorizeAsync"/> issued for this invocation's own context (one use, same capability and command), then has the
    /// pipeline run the owner's final validation, the operation, the result record and the audit event. The returned outcome is the
    /// owner's own on success and a typed failure with a registered code otherwise.
    /// </summary>
    public CapabilityOwnerOperation<TArguments, TResult> Enforce<TArguments, TResult>(EnforcedOwnerOperation<TArguments, TResult> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        return (target, invocation, arguments, context, cancellationToken) =>
            RunAsync(operation, target, invocation, arguments, context, cancellationToken);
    }

    private static Outcome<T> Failure<T>(string code) => Outcome.Failure<T>(TypedFailure.Create(code));

    /// <summary>The canonical uppercase SHA-256 of what is being asked: capability, exact target instance, arguments and precondition.</summary>
    private static string EffectDigest(CapabilityRegistration capability, Invocation invocation, CapabilityTarget target)
    {
        var stable = invocation.Clone();
        stable.InvocationId = null;
        stable.Context = null;
        stable.ApprovalId = null;
        stable.LeaseId = null;
        using var buffer = new MemoryStream();
        using (var writer = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(capability.Key);
            writer.Write(target.Identity.Installation.App.ProductId);
            writer.Write(target.Identity.Installation.DeviceId.Value.ToByteArray());
            writer.Write(target.Identity.Installation.InstallationId.Value.ToByteArray());
            writer.Write(target.Identity.InstanceId.Value.ToByteArray());
            writer.Write(target.Identity.Epoch);
            var bytes = stable.ToByteArray();
            writer.Write(bytes.Length);
            writer.Write(bytes);
        }

        return Convert.ToHexString(SHA256.HashData(buffer.ToArray()));
    }

    private async ValueTask<Outcome<TResult>> RunAsync<TArguments, TResult>(
        EnforcedOwnerOperation<TArguments, TResult> operation,
        CapabilityTarget target,
        Invocation invocation,
        TArguments arguments,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken)
    {
        if (!_admissions.TryGetValue(context, out var admission) || !admission.Matches(invocation) || !admission.TryTake())
        {
            return Failure<TResult>("perm.capability_denied");
        }

        var execution = await _pipeline.ExecuteDecidedAsync(
            admission.Decision,
            admission.Request,
            (ticket, token) => operation(ticket, target, invocation, arguments, context, token),
            cancellationToken).ConfigureAwait(false);
        return execution.Result;
    }

    private sealed class Admission(SecurityDecision decision, DecisionRequest request)
    {
        private int _taken;

        internal SecurityDecision Decision { get; } = decision;

        internal DecisionRequest Request { get; } = request;

        internal bool Matches(Invocation invocation) =>
            invocation.HasCapability
            && string.Equals(invocation.Capability, Request.CapabilityKey, StringComparison.Ordinal)
            && Request.CommandId.ToWire().Equals(invocation.CommandId);

        internal bool TryTake() => Interlocked.CompareExchange(ref _taken, 1, 0) == 0;
    }
}
