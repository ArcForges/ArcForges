// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Capabilities;
using ArcForges.Foundation.Errors;

namespace ArcForges.Contributions;

/// <summary>A typed handler bound to exactly one application composition.</summary>
public sealed class ContributionRegistration<TOwner, TRequest, TResult> where TOwner : class
{
    private readonly ApplicationComposition<TOwner> composition;
    private readonly ApplicationHandler<TOwner, TRequest, TResult> handler;

    internal ContributionRegistration(ApplicationComposition<TOwner> composition,
        ApplicationHandler<TOwner, TRequest, TResult> handler,
        ContributionDefinition definition,
        ContributionPersistenceResult persistenceResult)
    {
        this.composition = composition;
        this.handler = handler;
        Definition = definition;
        PersistenceResult = persistenceResult;
    }

    public ContributionDefinition Definition { get; }
    public ContributionPersistenceResult PersistenceResult { get; }

    /// <summary>Dispatches only through the captured owner composition; target fencing stays with PLT.17.</summary>
    public ValueTask<Outcome<TResult>> DispatchAsync(InstanceIdentity? target, TRequest request,
        CancellationToken cancellationToken = default) =>
        composition.DispatchAsync(handler, target, request, cancellationToken);
}
