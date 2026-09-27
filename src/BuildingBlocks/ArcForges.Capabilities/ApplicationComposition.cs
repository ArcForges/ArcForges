// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;

namespace ArcForges.Capabilities;

/// <summary>A typed explicit registration owned by exactly one composition. It carries no global discovery key.</summary>
public sealed class ApplicationHandler<TOwner, TRequest, TResult> where TOwner : class
{
    internal ApplicationHandler(ApplicationComposition<TOwner> composition,
        Func<TOwner, TRequest, CancellationToken, ValueTask<Outcome<TResult>>> operation)
    {
        Composition = composition;
        Operation = operation;
    }

    internal ApplicationComposition<TOwner> Composition { get; }
    internal Func<TOwner, TRequest, CancellationToken, ValueTask<Outcome<TResult>>> Operation { get; }
}

/// <summary>Explicit per-process composition; no global store, product lookup, peer discovery or fallback target.</summary>
public sealed class ApplicationComposition<TOwner> where TOwner : class
{
    private readonly object _gate = new();
    private readonly TOwner _owner;
    private bool _stopped;

    private ApplicationComposition(InstanceIdentity identity, Func<InstanceIdentity, TOwner> createOwner)
    {
        Identity = identity;
        _owner = createOwner(identity) ?? throw new ArgumentException("The owning composition must be present.", nameof(createOwner));
    }

    public InstanceIdentity Identity { get; }

    /// <summary>Starts a new process identity. The host retains installation state and supplies its new authoritative epoch.</summary>
    public static ApplicationComposition<TOwner> Start(InstallationIdentity installation, ulong epoch,
        Func<InstanceIdentity, TOwner> createOwner)
    {
        ArgumentNullException.ThrowIfNull(createOwner);
        var identity = new InstanceIdentity(installation, IdentityGeneration.NewInstance(), epoch);
        return new ApplicationComposition<TOwner>(identity, createOwner);
    }

    public ApplicationHandler<TOwner, TRequest, TResult> Bind<TRequest, TResult>(
        Func<TOwner, TRequest, CancellationToken, ValueTask<Outcome<TResult>>> operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        lock (_gate)
        {
            if (_stopped)
            {
                throw new InvalidOperationException("A stopped composition cannot register handlers.");
            }

            return new ApplicationHandler<TOwner, TRequest, TResult>(this, operation);
        }
    }

    /// <summary>Refuses missing, foreign or stale targets before calling the explicitly bound owner handler.</summary>
    public ValueTask<Outcome<TResult>> DispatchAsync<TRequest, TResult>(ApplicationHandler<TOwner, TRequest, TResult> handler,
        InstanceIdentity? target, TRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handler);
        lock (_gate)
        {
            string? refusal = target is null ? "validation.invalid_request"
                : !ReferenceEquals(handler.Composition, this) || target.Installation != Identity.Installation ? "perm.capability_denied"
                : _stopped || target.InstanceId != Identity.InstanceId || target.Epoch != Identity.Epoch ? "state.gone"
                : null;
            if (refusal is not null)
            {
                return ValueTask.FromResult(Outcome.Failure<TResult>(TypedFailure.Create(refusal)));
            }

            cancellationToken.ThrowIfCancellationRequested();
            // Admission is serialized with Stop. Work already admitted may finish and retains its own effect semantics.
            return handler.Operation(_owner, request, cancellationToken);
        }
    }

    /// <summary>Fences future admission without erasing installation state or claiming rollback of admitted effects.</summary>
    public void Stop()
    {
        lock (_gate)
        {
            _stopped = true;
        }
    }
}
