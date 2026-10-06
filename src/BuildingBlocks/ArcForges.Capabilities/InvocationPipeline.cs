// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.PublicApi.V1;
using ArcForges.Foundation.Errors;
using ArcForges.Sdk.Contracts.V1;
using Google.Protobuf;

namespace ArcForges.Capabilities;

/// <summary>The closed meaning of a successful typed owner result's version.</summary>
[SuppressMessage("Usage", "CA1008:Enums should have zero value", Justification = "The zero value is invalid and rejected; NonVersioned is an explicit payload-free local result arm.")]
public enum InvocationResultVersionKind
{
    Invalid = 0,
    Revision = 1,
    NativeContentRev = 2,
    NonVersioned = 3,
}

/// <summary>
/// A local result-version union. NonVersioned has no payload; absence is never encoded as a zero
/// revision, an expected precondition, or a new wire field.
/// </summary>
public sealed class InvocationResultVersion
{
    private readonly Revision? _revision;
    private readonly NativeContentRev? _nativeContentRev;

    private InvocationResultVersion(InvocationResultVersionKind kind, Revision? revision, NativeContentRev? nativeContentRev)
    {
        Kind = kind;
        _revision = revision?.Clone();
        _nativeContentRev = nativeContentRev?.Clone();
    }

    public InvocationResultVersionKind Kind { get; }
    public Revision? Revision => _revision?.Clone();
    public NativeContentRev? NativeContentRev => _nativeContentRev?.Clone();

    public static InvocationResultVersion FromRevision(Revision revision)
    {
        ArgumentNullException.ThrowIfNull(revision);
        if (!revision.HasValue || revision.Value <= 0)
        {
            throw new ArgumentException("A versioned success must carry the owner's explicit committed revision.", nameof(revision));
        }

        return new InvocationResultVersion(InvocationResultVersionKind.Revision, revision, null);
    }

    public static InvocationResultVersion FromNativeContentRev(NativeContentRev revision)
    {
        ArgumentNullException.ThrowIfNull(revision);
        if (!revision.HasValue || revision.Value == 0)
        {
            throw new ArgumentException("A native-versioned success must carry the owner's explicit native content revision.", nameof(revision));
        }

        return new InvocationResultVersion(InvocationResultVersionKind.NativeContentRev, null, revision);
    }

    public static InvocationResultVersion NonVersioned() =>
        new(InvocationResultVersionKind.NonVersioned, null, null);
}

/// <summary>A validated generic response plus its exact typed-owner version meaning.</summary>
public sealed class CapabilityInvocationValue
{
    private readonly CapabilityResult _result;

    internal CapabilityInvocationValue(CapabilityResult result, InvocationResultVersion version)
    {
        _result = result.Clone();
        Version = version;
    }

    public CapabilityResult Result => _result.Clone();
    public InvocationResultVersion Version { get; }
}

/// <summary>The immutable local result persisted and replayed for one command identity.</summary>
public sealed class InvocationOutcome
{
    private readonly CapabilityInvocationValue? _value;
    private readonly TypedFailure? _failure;

    private InvocationOutcome(OutcomeKind kind, CapabilityInvocationValue? value, TypedFailure? failure, EffectCertainty effect)
    {
        Kind = kind;
        _value = value;
        _failure = failure;
        CancellationEffect = effect;
    }

    public OutcomeKind Kind { get; }
    public CapabilityInvocationValue? Value => _value is null ? null : new CapabilityInvocationValue(_value.Result, _value.Version);
    public TypedFailure? Failure => _failure;
    public EffectCertainty CancellationEffect { get; }

    public static InvocationOutcome Success(CapabilityInvocationValue value) =>
        new(OutcomeKind.Success, value ?? throw new ArgumentNullException(nameof(value)), null, EffectCertainty.Unspecified);

    public static InvocationOutcome FailureResult(TypedFailure failure) =>
        new(OutcomeKind.Failure, null,
            failure is null ? throw new ArgumentNullException(nameof(failure)) : failure.IsKnownCode
                ? failure : TypedFailure.Create("internal.unexpected"),
            EffectCertainty.Unspecified);

    public static InvocationOutcome Cancelled(EffectCertainty effect)
    {
        if (effect is not (EffectCertainty.DidNotHappen or EffectCertainty.Happened or EffectCertainty.Unknown))
        {
            throw new ArgumentOutOfRangeException(nameof(effect));
        }
        return new InvocationOutcome(OutcomeKind.Cancelled, null, null, effect);
    }
}

/// <summary>Receives a typed operation request decoded from generated CapabilityArguments.</summary>
public delegate Outcome<TArguments> CapabilityArgumentsDecoder<TArguments>(CapabilityArguments arguments);

/// <summary>Encodes one typed owner result into its already-authored generated result schema.</summary>
public delegate Outcome<CapabilityResult> CapabilityResultEncoder<in TResult>(TResult result);

/// <summary>Invokes one operation-specific typed owner binding; the generated Invocation is forwarded unchanged.</summary>
public delegate ValueTask<Outcome<TResult>> CapabilityOwnerOperation<TArguments, TResult>(
    CapabilityTarget target,
    Invocation invocation,
    TArguments arguments,
    FrozenContextSnapshot context,
    CancellationToken cancellationToken);

/// <summary>Checks current authorization after availability and context freezing, on every new command.</summary>
public delegate ValueTask<Outcome<bool>> CapabilityInvocationAuthorization(
    CapabilityRegistration capability,
    Invocation invocation,
    CapabilityTarget target,
    FrozenContextSnapshot context,
    CancellationToken cancellationToken);

/// <summary>Typed adapter for exactly one catalogue registration.</summary>
public sealed class CapabilityInvocationBinding<TArguments, TResult> : CapabilityInvocationBinding
{
    private readonly CapabilityArgumentsDecoder<TArguments> _decode;
    private readonly CapabilityOwnerOperation<TArguments, TResult> _invoke;
    private readonly CapabilityResultEncoder<TResult> _encode;
    private readonly Func<TResult, InvocationResultVersion> _version;

    public CapabilityInvocationBinding(
        CapabilityRegistry registry,
        string capabilityKey,
        InvocationResultVersionKind resultVersionKind,
        CapabilityArgumentsDecoder<TArguments> decode,
        CapabilityOwnerOperation<TArguments, TResult> invoke,
        CapabilityResultEncoder<TResult> encode,
        Func<TResult, InvocationResultVersion> version)
        : base(registry, capabilityKey, resultVersionKind)
    {
        _decode = decode ?? throw new ArgumentNullException(nameof(decode));
        _invoke = invoke ?? throw new ArgumentNullException(nameof(invoke));
        _encode = encode ?? throw new ArgumentNullException(nameof(encode));
        _version = version ?? throw new ArgumentNullException(nameof(version));
    }

    internal override async ValueTask<Outcome<CapabilityInvocationValue>> InvokeAsync(
        Invocation invocation,
        CapabilityTarget target,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken)
    {
        var arguments = invocation.Arguments;
        if (arguments is null || !arguments.HasSchemaId || arguments.Value is null ||
            !string.Equals(arguments.SchemaId, Registration.SnapshotDescriptor().RequestSchema, StringComparison.Ordinal))
        {
            return Failure<CapabilityInvocationValue>("validation.invalid_request");
        }

        var decoded = _decode(arguments.Clone());
        if (!decoded.TryGetValue(out var request))
        {
            return Propagate<CapabilityInvocationValue, TArguments>(decoded);
        }

        var response = await _invoke(target, invocation.Clone(), request!, context, cancellationToken).ConfigureAwait(false);
        if (!response.TryGetValue(out var typedResult) || typedResult is null)
        {
            return Propagate<CapabilityInvocationValue, TResult>(response);
        }

        var encoded = _encode(typedResult);
        if (!encoded.TryGetValue(out var result) || result is null)
        {
            return Propagate<CapabilityInvocationValue, CapabilityResult>(encoded);
        }

        return RestoreResult(result, _version(typedResult));
    }

    private static Outcome<TDestination> Propagate<TDestination, TSource>(Outcome<TSource> source) => source.Kind switch
    {
        OutcomeKind.Failure when source.TryGetFailure(out var failure) && failure is not null && failure.IsKnownCode =>
            Outcome.Failure<TDestination>(failure),
        OutcomeKind.Failure => Failure<TDestination>("internal.unexpected"),
        OutcomeKind.Cancelled => Outcome.Cancelled<TDestination>(source.CancellationEffect),
        _ => Failure<TDestination>("internal.unexpected"),
    };

    private static Outcome<T> Failure<T>(string code) => Outcome.Failure<T>(TypedFailure.Create(code));
}

/// <summary>Non-inheritable binding base; business operation adapters remain operation-typed.</summary>
public abstract class CapabilityInvocationBinding
{
    protected CapabilityInvocationBinding(CapabilityRegistry registry, string capabilityKey, InvocationResultVersionKind resultVersionKind)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentException.ThrowIfNullOrWhiteSpace(capabilityKey);
        if (!Enum.IsDefined(resultVersionKind) || resultVersionKind == InvocationResultVersionKind.Invalid)
        {
            throw new ArgumentOutOfRangeException(nameof(resultVersionKind));
        }

        Registration = registry.Find(capabilityKey)
            ?? throw new ArgumentException("An invocation binding must name an exact registered capability.", nameof(capabilityKey));
        ResultVersionKind = resultVersionKind;
    }

    public string CapabilityKey => Registration.Key;
    public InvocationResultVersionKind ResultVersionKind { get; }

    /// <summary>
    /// Restore a previously committed result against this exact current binding. This validates the same response schema,
    /// structured value, output budget and owner-version meaning as dispatch, clones the result, calls no owner and grants no
    /// authorization. The invocation pipeline still checks current authorization before replaying the host's stored outcome.
    /// </summary>
    public Outcome<CapabilityInvocationValue> RestoreResult(CapabilityResult result, InvocationResultVersion version)
    {
        var descriptor = Registration.SnapshotDescriptor();
        if (result is null || !result.HasSchemaId ||
            !string.Equals(result.SchemaId, descriptor.ResponseSchema, StringComparison.Ordinal) ||
            result.Value is null || result.Value.ValueCase == StructuredValue.ValueOneofCase.None ||
            (ulong)result.CalculateSize() > descriptor.Limits.MaxOutputBytes ||
            version is null || version.Kind != ResultVersionKind ||
            version.Kind == InvocationResultVersionKind.Revision && version.Revision is not { HasValue: true, Value: > 0 } ||
            version.Kind == InvocationResultVersionKind.NativeContentRev && version.NativeContentRev is not { HasValue: true, Value: > 0 } ||
            version.Kind == InvocationResultVersionKind.NonVersioned &&
            (version.Revision is not null || version.NativeContentRev is not null))
        {
            return Outcome.Failure<CapabilityInvocationValue>(TypedFailure.Create("internal.unexpected"));
        }

        return Outcome.Success(new CapabilityInvocationValue(result, version));
    }

    internal CapabilityRegistration Registration { get; }
    internal abstract ValueTask<Outcome<CapabilityInvocationValue>> InvokeAsync(
        Invocation invocation,
        CapabilityTarget target,
        FrozenContextSnapshot context,
        CancellationToken cancellationToken);
}

public enum InvocationRecordClaimKind
{
    None = 0,
    Execute = 1,
    Replay = 2,
}

/// <summary>Atomic command claim returned by the host-owned record store.</summary>
public sealed class InvocationRecordClaim
{
    private InvocationRecordClaim(InvocationRecordClaimKind kind, Guid reservationId, InvocationOutcome? replay)
    {
        Kind = kind;
        ReservationId = reservationId;
        ReplayOutcome = replay;
    }

    public InvocationRecordClaimKind Kind { get; }
    public Guid ReservationId { get; }
    public InvocationOutcome? ReplayOutcome { get; }

    public static InvocationRecordClaim ForExecution(Guid reservationId) => reservationId == Guid.Empty
        ? throw new ArgumentException("A non-empty record reservation is required.", nameof(reservationId))
        : new InvocationRecordClaim(InvocationRecordClaimKind.Execute, reservationId, null);

    public static InvocationRecordClaim ForReplay(InvocationOutcome outcome) =>
        new(InvocationRecordClaimKind.Replay, Guid.Empty, outcome ?? throw new ArgumentNullException(nameof(outcome)));
}

/// <summary>
/// Host-owned atomic idempotency journal. Begin must reserve a new command, reject a reused command
/// with a different invocation fingerprint, or return the previously recorded typed outcome.
/// </summary>
public interface IInvocationRecordStore
{
    ValueTask<Outcome<InvocationRecordClaim>> BeginAsync(Id commandId, ByteString requestFingerprint, CancellationToken cancellationToken);
    ValueTask<Outcome<InvocationOutcome>> CompleteAsync(InvocationRecordClaim claim, InvocationOutcome outcome, CancellationToken cancellationToken);
}

public enum InvocationTracePhase
{
    None = 0,
    Started = 1,
    Completed = 2,
}

/// <summary>Privacy-bounded trace projection; arguments, actor data and context payloads are not copied.</summary>
public sealed class InvocationTraceRecord
{
    private readonly Id? _invocationId;
    private readonly Id? _commandId;

    internal InvocationTraceRecord(
        InvocationTracePhase phase,
        Invocation? invocation,
        InstanceIdentity? target,
        InvocationOutcome? outcome,
        string? canonicalCapabilityKey)
    {
        Phase = phase;
        _invocationId = CopyTraceId(invocation?.InvocationId);
        _commandId = CopyTraceId(invocation?.CommandId);
        CapabilityKey = canonicalCapabilityKey is { Length: > 0 and <= 256 } ? canonicalCapabilityKey : null;
        Target = target;
        OutcomeKind = outcome?.Kind;
        FailureCode = outcome?.Failure?.Code;
        ResultVersionKind = outcome?.Value?.Version.Kind;
    }

    private static Id? CopyTraceId(Id? value) => value is { HasValue: true } && value.Value.Length == 16
        ? value.Clone()
        : null;

    public InvocationTracePhase Phase { get; }
    public Id? InvocationId => _invocationId?.Clone();
    public Id? CommandId => _commandId?.Clone();
    public string? CapabilityKey { get; }
    public InstanceIdentity? Target { get; }
    public OutcomeKind? OutcomeKind { get; }
    public string? FailureCode { get; }
    public InvocationResultVersionKind? ResultVersionKind { get; }
}

/// <summary>Records invocations without retaining mutable generated request instances.</summary>
public interface IInvocationTraceSink
{
    ValueTask<Outcome<bool>> WriteAsync(InvocationTraceRecord record, CancellationToken cancellationToken);
}

/// <summary>
/// The only capability dispatch route: resolve, availability, context snapshot, authorization,
/// typed owner dispatch, output validation, idempotent record, and trace.
/// </summary>
public sealed class CapabilityInvocationPipeline
{
    private readonly CapabilityRegistry _registry;
    private readonly ICapabilityProvider _availability;
    private readonly CapabilityInvocationAuthorization _authorize;
    private readonly IInvocationRecordStore _records;
    private readonly IInvocationTraceSink _trace;
    private readonly ContextSnapshotBudget _contextBudget;
    private readonly Dictionary<string, CapabilityInvocationBinding> _bindings;

    public CapabilityInvocationPipeline(
        CapabilityRegistry registry,
        ICapabilityProvider availability,
        IEnumerable<CapabilityInvocationBinding> bindings,
        CapabilityInvocationAuthorization authorize,
        IInvocationRecordStore records,
        IInvocationTraceSink trace,
        ContextSnapshotBudget? contextBudget = null)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _availability = availability ?? throw new ArgumentNullException(nameof(availability));
        ArgumentNullException.ThrowIfNull(bindings);
        _authorize = authorize ?? throw new ArgumentNullException(nameof(authorize));
        _records = records ?? throw new ArgumentNullException(nameof(records));
        _trace = trace ?? throw new ArgumentNullException(nameof(trace));
        _contextBudget = contextBudget ?? ContextSnapshotBudget.Default;
        _bindings = new Dictionary<string, CapabilityInvocationBinding>(StringComparer.Ordinal);
        foreach (var binding in bindings)
        {
            ArgumentNullException.ThrowIfNull(binding);
            var canonical = _registry.Find(binding.CapabilityKey);
            if (canonical is null || !canonical.Descriptor.Equals(binding.Registration.Descriptor))
            {
                throw new ArgumentException("Invocation bindings must match the immutable catalogue descriptor.", nameof(bindings));
            }

            if (!_bindings.TryAdd(binding.CapabilityKey, binding))
            {
                throw new ArgumentException("A capability can have only one typed invocation binding.", nameof(bindings));
            }
        }
    }

    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "No owner or infrastructure exception may escape the capability boundary; failures map to the registered closed internal error.")]
    public async ValueTask<InvocationOutcome> InvokeAsync(
        Invocation? invocation,
        ActionKey? actionKey,
        FrozenContextSnapshot? availabilityContext,
        IReadOnlyList<CapabilityTarget> targets,
        IReadOnlyList<IContextProvider> contextProviders,
        InstanceIdentity? capturedTarget = null,
        InstanceIdentity? explicitlySelectedTarget = null,
        CancellationToken cancellationToken = default)
    {
        Invocation? request;
        InvocationOutcome? preflightOutcome = null;
        if (invocation is null)
        {
            request = null;
        }
        else
        {
            try
            {
                var capability = invocation.HasCapability ? _registry.Find(invocation.Capability) : null;
                var candidateDescriptor = capability?.Descriptor;
                var inputLimit = candidateDescriptor is { Limits.HasMaxInputBytes: true }
                    ? candidateDescriptor.Limits.MaxInputBytes
                    : _registry.Registrations.Max(item => item.Descriptor.Limits.MaxInputBytes);
                if ((ulong)invocation.CalculateSize() > inputLimit)
                {
                    request = invocation;
                    preflightOutcome = InvocationOutcome.FailureResult(TypedFailure.Create("entitlement.request_too_large"));
                }
                else if (!invocation.HasCapability || !invocation.Arguments.HasSchemaId)
                {
                    request = invocation;
                    preflightOutcome = InvocationOutcome.FailureResult(TypedFailure.Create("validation.invalid_request"));
                }
                else
                {
                    request = invocation.Clone();
                }
            }
            catch (Exception)
            {
                request = null;
                preflightOutcome = InvocationOutcome.FailureResult(TypedFailure.Create("validation.invalid_request"));
            }
        }

        var traceCapabilityKey = request is null ? null : CanonicalTraceCapabilityKey(request);
        var started = await WriteTraceAsync(new(InvocationTracePhase.Started, request, null, null, traceCapabilityKey)).ConfigureAwait(false);
        if (!started)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("internal.unexpected"));
        }

        CapabilityTarget? selectedTarget = null;
        InvocationOutcome outcome;
        try
        {
            outcome = preflightOutcome ?? await ExecuteAsync(request, actionKey, availabilityContext, targets, contextProviders,
                capturedTarget, explicitlySelectedTarget, target => selectedTarget = target, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            outcome = InvocationOutcome.Cancelled(EffectCertainty.Unknown);
        }
        catch
        {
            outcome = InvocationOutcome.FailureResult(TypedFailure.Create("internal.unexpected"));
        }

        _ = await WriteTraceAsync(new(InvocationTracePhase.Completed, request, selectedTarget?.Identity, outcome, traceCapabilityKey)).ConfigureAwait(false);
        return outcome;
    }

    private string? CanonicalTraceCapabilityKey(Invocation invocation)
    {
        if (!invocation.HasCapability || invocation.Capability.Length is 0 or > 256 ||
            string.IsNullOrWhiteSpace(invocation.Capability))
        {
            return null;
        }

        return _registry.Find(invocation.Capability)?.Key;
    }

    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "No owner or infrastructure exception may escape the capability boundary; owner dispatch failures map to the registered closed internal error.")]
    private async ValueTask<InvocationOutcome> ExecuteAsync(
        Invocation? invocation,
        ActionKey? actionKey,
        FrozenContextSnapshot? availabilityContext,
        IReadOnlyList<CapabilityTarget> targets,
        IReadOnlyList<IContextProvider> contextProviders,
        InstanceIdentity? capturedTarget,
        InstanceIdentity? explicitlySelectedTarget,
        Action<CapabilityTarget> selected,
        CancellationToken cancellationToken)
    {
        if (invocation is null || actionKey is null || availabilityContext is null || targets is null || contextProviders is null ||
            !invocation.HasCapability || string.IsNullOrWhiteSpace(invocation.Capability) ||
            invocation.Context is null || invocation.Arguments is null ||
            !invocation.Arguments.HasSchemaId || invocation.Arguments.Value is null)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("validation.invalid_request"));
        }

        try
        {
            _ = Foundation.Execution.InvocationId.FromWire(invocation.InvocationId);
            _ = Foundation.Execution.InvocationId.FromWire(invocation.CommandId);
        }
        catch (ArgumentException)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("validation.invalid_request"));
        }

        var capability = _registry.Find(invocation.Capability);
        if (capability is null || !_bindings.TryGetValue(invocation.Capability, out var binding))
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create(capability is null
                ? "validation.invalid_request" : "dependency.unavailable"));
        }

        var descriptor = capability.Descriptor;
        if (!descriptor.Limits.HasMaxInputBytes || (ulong)invocation.CalculateSize() > descriptor.Limits.MaxInputBytes)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("entitlement.request_too_large"));
        }

        if (!string.Equals(invocation.Arguments.SchemaId, descriptor.RequestSchema, StringComparison.Ordinal))
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("validation.invalid_request"));
        }

        if (!_availability.IsBoundToCapability(actionKey, invocation.Capability))
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("validation.invalid_request"));
        }

        var resolution = CapabilitySelector.Select(_registry, invocation.Capability, targets, capturedTarget, explicitlySelectedTarget);
        if (!resolution.IsSelected)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create(InvocationFailureMap.FromSelection(resolution.Reason)));
        }

        var target = resolution.Target!;
        selected(target);
        if (availabilityContext.Owner != target.Identity)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("validation.invalid_request"));
        }

        var available = await _availability.EvaluateAvailabilityAsync(actionKey, availabilityContext, cancellationToken).ConfigureAwait(false);
        if (!TryRead(available, out AvailabilityResult availability, out var availabilityFailure))
        {
            return availabilityFailure!;
        }

        if (!Enum.IsDefined(availability) || availability != AvailabilityResult.Available)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create(InvocationFailureMap.FromAvailability(availability)));
        }

        if (!descriptor.Limits.HasMaxContextItems)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("internal.unexpected"));
        }

        var contextBudget = new ContextSnapshotBudget(
            Math.Min(_contextBudget.MaxItems, descriptor.Limits.MaxContextItems),
            (uint)Math.Min((ulong)_contextBudget.MaxBytes, descriptor.Limits.MaxInputBytes));
        FrozenContextSnapshot frozen;
        try
        {
            frozen = await FrozenContextSnapshot.FreezeAsync(contextProviders, target.Identity, contextBudget, cancellationToken).ConfigureAwait(false);
        }
        catch (ContextScopeMismatchException)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("perm.capability_denied"));
        }
        catch (ContextBudgetExceededException)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("entitlement.request_too_large"));
        }

        var authorized = await _authorize(capability, invocation.Clone(), target, frozen, cancellationToken).ConfigureAwait(false);
        if (!TryRead(authorized, out bool isAuthorized, out var authorizationFailure))
        {
            return authorizationFailure!;
        }

        if (!isAuthorized)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("perm.capability_denied"));
        }

        // Authorization and fresh owner-scoped context are evaluated on every invocation, including
        // same-command retries. Only after those checks can the idempotency journal replay a result.
        var fingerprint = CreateRequestFingerprint(invocation, actionKey, target.Identity, frozen, descriptor, binding.ResultVersionKind);
        var begin = await _records.BeginAsync(invocation.CommandId.Clone(), fingerprint, cancellationToken).ConfigureAwait(false);
        if (!TryRead(begin, out InvocationRecordClaim? claim, out var beginFailure))
        {
            return beginFailure!;
        }

        if (claim!.Kind == InvocationRecordClaimKind.Replay)
        {
            return SanitizeRecordedOutcome(claim.ReplayOutcome);
        }

        if (claim.Kind != InvocationRecordClaimKind.Execute || claim.ReservationId == Guid.Empty)
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("internal.unexpected"));
        }

        InvocationOutcome dispatchOutcome;
        try
        {
            var invoked = await binding.InvokeAsync(invocation.Clone(), target, frozen, cancellationToken).ConfigureAwait(false);
            dispatchOutcome = TryRead(invoked, out CapabilityInvocationValue? value, out var invocationFailure)
                ? InvocationOutcome.Success(value!)
                : invocationFailure!;
        }
        catch (OperationCanceledException)
        {
            dispatchOutcome = InvocationOutcome.Cancelled(EffectCertainty.Unknown);
        }
        catch (Exception)
        {
            dispatchOutcome = InvocationOutcome.FailureResult(TypedFailure.Create("internal.unexpected"));
        }

        return await CommitAsync(claim, dispatchOutcome).ConfigureAwait(false);
    }

    private async ValueTask<InvocationOutcome> CommitAsync(InvocationRecordClaim claim, InvocationOutcome outcome)
    {
        var completed = await _records.CompleteAsync(claim, outcome, CancellationToken.None).ConfigureAwait(false);
        return TryRead(completed, out InvocationOutcome? recorded, out var failure)
            ? recorded!
            : failure!;
    }

    private static ByteString CreateRequestFingerprint(
        Invocation invocation,
        ActionKey actionKey,
        InstanceIdentity target,
        FrozenContextSnapshot context,
        CapabilityDescriptor descriptor,
        InvocationResultVersionKind resultVersionKind)
    {
        using var buffer = new MemoryStream();
        using (var writer = new BinaryWriter(buffer, Encoding.UTF8, leaveOpen: true))
        {
            // InvocationId identifies this trace attempt; CommandId is the idempotency key.
            // A retry may have a fresh InvocationId while retaining the same semantic command.
            var retryStableRequest = invocation.Clone();
            retryStableRequest.InvocationId = new Id();
            var requestBytes = retryStableRequest.ToByteArray();
            writer.Write(requestBytes.Length);
            writer.Write(requestBytes);
            writer.Write(actionKey.Value);
            writer.Write(target.Installation.App.ProductId);
            writer.Write(target.Installation.DeviceId.Value.ToByteArray());
            writer.Write(target.Installation.InstallationId.Value.ToByteArray());
            writer.Write(target.InstanceId.Value.ToByteArray());
            writer.Write(target.Epoch);
            var descriptorBytes = descriptor.ToByteArray();
            writer.Write(descriptorBytes.Length);
            writer.Write(descriptorBytes);
            writer.Write((int)resultVersionKind);
            foreach (var item in context.Items)
            {
                var itemBytes = item.Deserialize().ToByteArray();
                writer.Write(item.TypeName);
                writer.Write(itemBytes.Length);
                writer.Write(itemBytes);
            }
        }

        return ByteString.CopyFrom(SHA256.HashData(buffer.ToArray()));
    }

    private static InvocationOutcome SanitizeRecordedOutcome(InvocationOutcome? outcome)
    {
        if (outcome is null || !Enum.IsDefined(outcome.Kind))
        {
            return InvocationOutcome.FailureResult(TypedFailure.Create("internal.unexpected"));
        }

        return outcome.Kind switch
        {
            OutcomeKind.Success when outcome.Value is not null => outcome,
            OutcomeKind.Failure when outcome.Failure is { IsKnownCode: true } => outcome,
            OutcomeKind.Cancelled when Enum.IsDefined(outcome.CancellationEffect) && outcome.CancellationEffect is not EffectCertainty.Unspecified => outcome,
            _ => InvocationOutcome.FailureResult(TypedFailure.Create("internal.unexpected")),
        };
    }

    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A broken trace sink must fail closed before owner invocation and cannot destabilize the dispatch boundary.")]
    private async ValueTask<bool> WriteTraceAsync(InvocationTraceRecord record)
    {
        try
        {
            var write = await _trace.WriteAsync(record, CancellationToken.None).ConfigureAwait(false);
            return write.Kind == OutcomeKind.Success && write.TryGetValue(out var accepted) && accepted;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryRead<T>(Outcome<T>? result, out T value, out InvocationOutcome? failure)
    {
        value = default!;
        failure = null;
        if (result is null)
        {
            failure = InvocationOutcome.FailureResult(TypedFailure.Create("internal.unexpected"));
            return false;
        }

        if (result.TryGetValue(out var resultValue))
        {
            if (resultValue is null)
            {
                failure = InvocationOutcome.FailureResult(TypedFailure.Create("internal.unexpected"));
                return false;
            }

            value = resultValue;
            return true;
        }

        if (result.TryGetFailure(out var typedFailure))
        {
            failure = InvocationOutcome.FailureResult(typedFailure.IsKnownCode
                ? typedFailure : TypedFailure.Create("internal.unexpected"));
            return false;
        }

        failure = InvocationOutcome.Cancelled(result.CancellationEffect);
        return false;
    }
}

/// <summary>Exhaustive mapping from resolution/availability failures to registered semantic errors.</summary>
public static class InvocationFailureMap
{
    public static string FromSelection(CapabilitySelectionReason reason) => reason switch
    {
        CapabilitySelectionReason.None => "internal.unexpected",
        CapabilitySelectionReason.CapabilityNotRegistered => "validation.invalid_request",
        CapabilitySelectionReason.TargetUnavailable => "dependency.unavailable",
        CapabilitySelectionReason.IncompatibleVersion => "validation.unsupported_version",
        CapabilitySelectionReason.NotReady => "dependency.unavailable",
        CapabilitySelectionReason.AmbiguousTarget => "validation.invalid_request",
        CapabilitySelectionReason.DescriptorMismatch => "validation.invalid_request",
        CapabilitySelectionReason.RetargetingDenied => "perm.capability_denied",
        CapabilitySelectionReason.WrongOwner => "perm.capability_denied",
        CapabilitySelectionReason.CloudServiceNotLocalTarget => "dependency.unavailable",
        _ => "internal.unexpected",
    };

    public static string FromAvailability(AvailabilityResult result) => result switch
    {
        AvailabilityResult.Available => "internal.unexpected",
        AvailabilityResult.NotApplicableToContext => "validation.invalid_request",
        AvailabilityResult.AppNotInstalled => "state.not_found",
        AvailabilityResult.AppNotRunning => "state.gone",
        AvailabilityResult.IncompatibleVersion => "validation.unsupported_version",
        AvailabilityResult.PermissionRequired => "perm.capability_denied",
        AvailabilityResult.EntitlementRequired => "entitlement.not_entitled",
        AvailabilityResult.PolicyDisabled => "perm.capability_denied",
        AvailabilityResult.TemporarilyUnavailable => "dependency.unavailable",
        _ => "internal.unexpected",
    };
}
