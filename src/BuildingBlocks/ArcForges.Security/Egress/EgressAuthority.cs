// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using ArcForges.Security.Decisions;

namespace ArcForges.Security.Egress;

/// <summary>Bounds of the egress authority. The default fails closed rather than waiting for a source.</summary>
public sealed record EgressAuthorityOptions
{
    /// <summary>The longest any one source or the audit sink may take. A source that does not answer in time refuses the transfer.</summary>
    public TimeSpan StepTimeout { get; init; } = TimeSpan.FromSeconds(15);
}

/// <summary>
/// The egress decision: every outbound data transfer is its own authorization, distinct from the read access that let the caller see
/// the data. A transfer is allowed only when the exact destination is named in the scope's allowlist, the content's class does not
/// exceed what the allowlist and the principal's own egress grant admit, an AI destination receives only AI-eligible content, and the
/// decision is durable in the audit sink. Everything else refuses with a typed reason; a source that cannot answer refuses.
/// </summary>
/// <remarks>
/// The authority holds no mutable state, so one instance serves concurrent requests. It never consults the capability permission or
/// any read grant: read access is not an input, so it cannot change a result. It re-decides on every call, so a revocation or an
/// expiry is seen at the next transfer.
/// </remarks>
public sealed class EgressAuthority
{
    /// <summary>The most grant records one source answer may carry; more is treated as a failing source.</summary>
    public const int MaximumGrantRecords = 64;

    private readonly IClock _clock;
    private readonly IEgressContentClassifier _classifier;
    private readonly IEgressAllowlist _allowlist;
    private readonly IEgressGrantSource _grants;
    private readonly IEgressAuditSink _audit;
    private readonly TimeSpan _timeout;

    public EgressAuthority(
        IClock clock,
        IEgressContentClassifier classifier,
        IEgressAllowlist allowlist,
        IEgressGrantSource grants,
        IEgressAuditSink audit,
        EgressAuthorityOptions? options = null)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _classifier = classifier ?? throw new ArgumentNullException(nameof(classifier));
        _allowlist = allowlist ?? throw new ArgumentNullException(nameof(allowlist));
        _grants = grants ?? throw new ArgumentNullException(nameof(grants));
        _audit = audit ?? throw new ArgumentNullException(nameof(audit));
        _timeout = (options ?? new EgressAuthorityOptions()).StepTimeout;
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(options), "The step timeout is above zero and at most five minutes.");
        }
    }

    /// <summary>
    /// Decides one transfer of the request's data to <paramref name="destination"/> and writes the decision to the audit sink before
    /// it returns. The destination must be the one the invocation declared. Only the caller's own cancellation propagates.
    /// </summary>
    public async ValueTask<EgressDecision> DecideAsync(DecisionRequest request, string destination, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(destination);
        cancellationToken.ThrowIfCancellationRequested();
        var verdict = await EvaluateAsync(request, destination, cancellationToken).ConfigureAwait(false);
        return await ReleaseAsync(request, verdict).ConfigureAwait(false);
    }

    /// <summary>
    /// Decides a transfer made inside an authorized execution and, only when it is allowed and audited, calls the owner's send
    /// operation with the <see cref="AuthorizedEgress"/> ticket. The decision is made again for every transfer. A refusal returns a
    /// typed failure with a registered code and the operation is never called. The operation's own exceptions propagate unchanged.
    /// </summary>
    public async ValueTask<EgressTransfer<TResult>> TransferAsync<TResult>(
        AuthorizedExecution ticket,
        string destination,
        EgressOperation<TResult> operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(operation);
        var decision = await DecideAsync(ticket.Request, destination, cancellationToken).ConfigureAwait(false);
        if (!decision.Allowed)
        {
            return new EgressTransfer<TResult>(
                decision,
                Outcome.Failure<TResult>(TypedFailure.Create(EgressReasons.Describe(decision.Reason).RegisteredCode)),
                operationRan: false);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var result = await operation(new AuthorizedEgress(decision), cancellationToken).ConfigureAwait(false);
        return new EgressTransfer<TResult>(decision, result, operationRan: true);
    }

    private async ValueTask<Verdict> EvaluateAsync(DecisionRequest request, string destination, CancellationToken cancellationToken)
    {
        if (!EgressDestinationIdentity.TryParse(destination, out var identity))
        {
            return Verdict.Refuse(EgressReason.DestinationMalformed);
        }

        if (!EgressDestinationIdentity.TryParse(request.EgressDestination, out var declared) || !declared.Equals(identity))
        {
            return Verdict.Refuse(EgressReason.DestinationNotDeclared, identity);
        }

        var classified = await CallAsync(token => _classifier.ClassifyAsync(request, identity, token), cancellationToken).ConfigureAwait(false);
        if (!classified.Ok)
        {
            return Verdict.Refuse(EgressReason.ClassifierUnavailable, identity);
        }

        var facts = classified.Value;
        if (facts is null || !Enum.IsDefined(facts.DataClass) || facts.DataClass == EgressDataClass.None)
        {
            return Verdict.Refuse(EgressReason.ContentUnclassified, identity);
        }

        if (facts.DataClass == EgressDataClass.SecretMaterial)
        {
            return Verdict.Refuse(EgressReason.SecretMaterial, identity, dataClass: facts.DataClass, aiEligible: facts.AiEligible);
        }

        var listed = await CallAsync(token => _allowlist.FindAsync(request.ScopeKey, identity, token), cancellationToken).ConfigureAwait(false);
        if (!listed.Ok)
        {
            return Verdict.Refuse(EgressReason.AllowlistUnavailable, identity, dataClass: facts.DataClass, aiEligible: facts.AiEligible);
        }

        var entry = listed.Value;
        if (entry is null)
        {
            return Verdict.Refuse(EgressReason.NotAllowlisted, identity, dataClass: facts.DataClass, aiEligible: facts.AiEligible);
        }

        if (!string.Equals(entry.ScopeKey, request.ScopeKey, StringComparison.Ordinal) || !entry.Destination.Equals(identity))
        {
            return Verdict.Refuse(EgressReason.AllowlistMismatch, identity, dataClass: facts.DataClass, aiEligible: facts.AiEligible);
        }

        Verdict Refused(EgressReason reason) => Verdict.Refuse(
            reason, identity, entry.DestinationClass, facts.DataClass, facts.AiEligible, allowlistGeneration: entry.SourceGeneration);

        if (facts.DataClass > entry.MaxDataClass)
        {
            return Refused(EgressReason.DataClassAboveAllowlist);
        }

        if (entry.DestinationClass == EgressDestinationClass.CloudAiProvider && !facts.AiEligible)
        {
            return Refused(EgressReason.AiIneligibleContent);
        }

        var found = await CallAsync(token => _grants.FindAsync(request, identity, token), cancellationToken).ConfigureAwait(false);
        // The instant is read after the source answered, so a slow source cannot make an expired grant look current.
        var now = _clock.GetCurrentInstant();
        var snapshot = found.Ok ? Snapshot(found.Value) : null;
        if (snapshot is null)
        {
            return Refused(EgressReason.GrantSourceUnavailable);
        }

        // Everything below reads this one private copy, so a source that hands out a live list cannot change it between checks.
        var records = snapshot;
        var principal = request.PrincipalKey;
        var matching = records
            .Where(record => string.Equals(record.PrincipalKey, principal, StringComparison.Ordinal)
                && string.Equals(record.CapabilityKey, request.CapabilityKey, StringComparison.Ordinal)
                && string.Equals(record.ScopeKey, request.ScopeKey, StringComparison.Ordinal)
                && record.Destination.Equals(identity))
            .ToArray();
        if (matching.Length == 0)
        {
            return Refused(records.Length == 0 ? EgressReason.NoGrant : EgressReason.GrantMismatch);
        }

        if (matching.Any(static record => record.State == EgressGrantState.Denied))
        {
            return Refused(EgressReason.GrantExplicitlyDenied);
        }

        // The lifetime is half open: valid from its start, already over at its end. Expiry is judged at use, not at issue.
        var current = matching
            .Where(record => record.State == EgressGrantState.Granted
                && now >= Instant.FromDateTimeOffset(record.ValidFromUtc)
                && now < Instant.FromDateTimeOffset(record.ValidUntilUtc))
            .ToArray();
        if (current.Length == 0)
        {
            return Refused(EgressReason.GrantOutsideLifetime);
        }

        var admitting = current
            .Where(record => facts.DataClass <= record.MaxDataClass)
            .OrderByDescending(static record => record.ValidUntilUtc)
            .ThenBy(static record => record.IssuerKey, StringComparer.Ordinal)
            .ToArray();
        if (admitting.Length == 0)
        {
            return Refused(EgressReason.DataClassAboveGrant);
        }

        var grant = admitting[0];
        return Verdict.Allow(identity, entry.DestinationClass, facts.DataClass, facts.AiEligible, grant, entry.SourceGeneration, now);
    }

    private async ValueTask<EgressDecision> ReleaseAsync(DecisionRequest request, Verdict verdict)
    {
        var occurred = verdict.DecidedAt ?? _clock.GetCurrentInstant();
        var record = Audit(request, verdict, occurred);
        var written = await BookkeepAsync(token => _audit.WriteAsync(record, token)).ConfigureAwait(false);
        if (verdict.Reason == EgressReason.None && !written)
        {
            // An allowed decision that cannot be made durable is not released: no egress is authorized without its audit event.
            var refused = Verdict.Refuse(
                EgressReason.AuditUnavailable, verdict.Destination, verdict.DestinationClass, verdict.DataClass, verdict.AiEligible, verdict.AllowlistGeneration);
            return Decision(refused, Audit(request, refused, occurred));
        }

        return Decision(verdict, record);
    }

    /// <summary>Copies the source's answer once, bounded. Returns null for no answer, too many records, a null record or a list that fails while read.</summary>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A list that throws while it is read is a failing source and refuses the transfer.")]
    private static EgressGrantRecord[]? Snapshot(IReadOnlyList<EgressGrantRecord>? source)
    {
        if (source is null)
        {
            return null;
        }

        try
        {
            var copy = source.Take(MaximumGrantRecords + 1).ToArray();
            return copy.Length > MaximumGrantRecords || copy.Any(static record => record is null) ? null : copy;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static EgressDecision Decision(Verdict verdict, EgressAuditRecord audit) => new(
        verdict.Reason,
        verdict.Destination,
        verdict.DestinationClass,
        verdict.DataClass,
        verdict.Grant?.Authority ?? EgressAuthorityKind.None,
        verdict.Grant?.AuthorityReference,
        audit);

    private static EgressAuditRecord Audit(DecisionRequest request, Verdict verdict, Instant occurred)
    {
        var chain = request.Actors;
        var last = chain.Actors.Count == 0 ? null : chain.Actors[^1];
        var allowed = verdict.Reason == EgressReason.None;
        var info = allowed ? null : EgressReasons.Describe(verdict.Reason);
        return new EgressAuditRecord(
            allowed ? EgressAuditKind.Authorized : EgressAuditKind.Refused,
            verdict.Reason,
            info?.Code,
            info?.RegisteredCode,
            occurred,
            chain,
            last?.Executor ?? chain.CallerInstance,
            last?.SoftwareIdentity,
            request.CapabilityKey,
            request.Resource,
            request.Scope,
            request.Origin,
            chain.Device,
            request.CommandId,
            verdict.Destination?.Origin,
            verdict.DestinationClass,
            verdict.DataClass,
            verdict.AiEligible,
            verdict.Grant?.Authority ?? EgressAuthorityKind.None,
            verdict.Grant?.AuthorityReference,
            verdict.Grant?.IssuerKey,
            verdict.Grant?.SourceGeneration,
            verdict.AllowlistGeneration);
    }

    /// <summary>
    /// Runs a source with its token linked to the caller's and bounded by the step timeout. A source that throws, is cancelled by the
    /// timeout or does not answer in time reports failure; only the caller's own cancellation propagates.
    /// </summary>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A source that throws must refuse the transfer rather than escape the decision boundary; no exception text is retained.")]
    private async ValueTask<PortResult<T>> CallAsync<T>(Func<CancellationToken, ValueTask<T>> invoke, CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(_timeout);
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
            return new PortResult<T>(true, await task.WaitAsync(_timeout, cancellationToken).ConfigureAwait(false));
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
    /// Runs the audit write. The write is not cancelled by the caller's cancellation, so a decision that was reached is recorded, and
    /// it is bounded only by the step timeout. A sink that throws or times out reports failure.
    /// </summary>
    [SuppressMessage("Usage", "CA1031:Do not catch general exception types", Justification = "A failing sink is reported as an unwritten audit event, never an escaping exception.")]
    private async ValueTask<bool> BookkeepAsync(Func<CancellationToken, ValueTask> write)
    {
        using var linked = new CancellationTokenSource(_timeout);
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
            await task.WaitAsync(_timeout).ConfigureAwait(false);
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

    private readonly record struct PortResult<T>(bool Ok, T Value)
    {
        public static PortResult<T> Failed { get; } = new(false, default!);
    }

    private sealed record Verdict(
        EgressReason Reason,
        EgressDestinationIdentity? Destination,
        EgressDestinationClass DestinationClass,
        EgressDataClass DataClass,
        bool AiEligible,
        EgressGrantRecord? Grant,
        string? AllowlistGeneration,
        Instant? DecidedAt)
    {
        public static Verdict Refuse(
            EgressReason reason,
            EgressDestinationIdentity? destination = null,
            EgressDestinationClass destinationClass = EgressDestinationClass.None,
            EgressDataClass dataClass = EgressDataClass.None,
            bool aiEligible = false,
            string? allowlistGeneration = null) =>
            new(reason, destination, destinationClass, dataClass, aiEligible, null, allowlistGeneration, null);

        public static Verdict Allow(
            EgressDestinationIdentity destination,
            EgressDestinationClass destinationClass,
            EgressDataClass dataClass,
            bool aiEligible,
            EgressGrantRecord grant,
            string allowlistGeneration,
            Instant decidedAt) =>
            new(EgressReason.None, destination, destinationClass, dataClass, aiEligible, grant, allowlistGeneration, decidedAt);
    }
}

/// <summary>
/// Puts the egress authority behind the pipeline's data-boundary port (step 8). Egress decisions come only from the authority; the
/// secret-use authorization comes only from the host's own authorizer, whose egress answer is never consulted. A secret-use authorizer
/// therefore cannot allow an egress, and an egress decision never allows a secret use.
/// </summary>
public sealed class EgressDataBoundary : IDataBoundaryAuthorizer
{
    private readonly EgressAuthority _egress;
    private readonly IDataBoundaryAuthorizer _secretUse;

    public EgressDataBoundary(EgressAuthority egress, IDataBoundaryAuthorizer secretUse)
    {
        _egress = egress ?? throw new ArgumentNullException(nameof(egress));
        _secretUse = secretUse ?? throw new ArgumentNullException(nameof(secretUse));
    }

    public ValueTask<BoundaryVerdict> AuthorizeSecretUseAsync(DecisionRequest request, CancellationToken cancellationToken) =>
        _secretUse.AuthorizeSecretUseAsync(request, cancellationToken);

    public async ValueTask<BoundaryVerdict> AuthorizeEgressAsync(DecisionRequest request, string destination, CancellationToken cancellationToken)
    {
        var decision = await _egress.DecideAsync(request, destination, cancellationToken).ConfigureAwait(false);
        return decision.ToBoundaryVerdict();
    }
}
