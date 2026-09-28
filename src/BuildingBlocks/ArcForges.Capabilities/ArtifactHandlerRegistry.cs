// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;

namespace ArcForges.Capabilities;

/// <summary>Closed artifact operations an admitted in-process owner handler may declare.</summary>
public enum ArtifactAction
{
    None = 0,
    Open = 1,
    Preview = 2,
    Import = 3,
    Convert = 4,
    Edit = 5,
}

/// <summary>Checks the owning product's current permission before one artifact action.</summary>
public delegate ValueTask<Outcome<bool>> ArtifactPermissionCheck(ArtifactRef reference, ArtifactAction action, CancellationToken cancellationToken);

/// <summary>Invokes one explicitly registered owner handler after permission is re-checked.</summary>
public delegate ValueTask<Outcome<TAccess>> ArtifactHandlerAccess<TAccess>(ArtifactRef reference, ArtifactAction action, CancellationToken cancellationToken);

/// <summary>
/// An explicit in-process catalog of admitted handlers for one owning application. It routes only
/// to registrations supplied by that owner, prefers the requested handler when it supports the
/// operation, then orders by descending descriptor priority and ordinal handler ID. It never
/// discovers or launches another product.
/// </summary>
public sealed class ArtifactHandlerRegistry<TAccess>
{
    private readonly object _gate = new();
    private readonly Dictionary<string, List<Handler>> _handlers = [];
    private readonly string _ownerAppId;

    /// <summary>Binds this registry to one application's artifact handlers.</summary>
    public ArtifactHandlerRegistry(AppIdentity owner)
    {
        ArgumentNullException.ThrowIfNull(owner);
        _ownerAppId = owner.ProductId;
    }

    /// <summary>Registers one handler for an owner-namespaced artifact kind and its closed actions.</summary>
    public void Register(string artifactKind, string handlerId, int priority,
        IEnumerable<ArtifactAction> actions, ArtifactPermissionCheck authorize, ArtifactHandlerAccess<TAccess> handle)
    {
        ArgumentNullException.ThrowIfNull(actions);
        ArgumentNullException.ThrowIfNull(authorize);
        ArgumentNullException.ThrowIfNull(handle);
        if (!ResourceReferenceValidation.IsNamespacedKind(_ownerAppId, artifactKind))
        {
            throw new ArgumentException("The artifact kind must be namespaced by its owning application.", nameof(artifactKind));
        }

        if (!ResourceReferenceValidation.IsValidHandlerId(handlerId))
        {
            throw new ArgumentException("A bounded canonical handler ID is required.", nameof(handlerId));
        }

        var actionSet = actions.ToHashSet();
        if (actionSet.Count == 0 || actionSet.Any(action => !IsValidAction(action)))
        {
            throw new ArgumentException("At least one known artifact action is required.", nameof(actions));
        }

        lock (_gate)
        {
            if (!_handlers.TryGetValue(artifactKind, out var handlers))
            {
                handlers = [];
                _handlers.Add(artifactKind, handlers);
            }

            if (handlers.Any(existing => string.Equals(existing.HandlerId, handlerId, StringComparison.Ordinal)))
            {
                throw new InvalidOperationException("A handler ID can be registered only once per owner artifact kind.");
            }

            handlers.Add(new Handler(handlerId, priority, actionSet, authorize, handle));
        }
    }

    /// <summary>Dispatches to the preferred compatible handler or the deterministic priority winner.</summary>
    public ValueTask<Outcome<TAccess>> DispatchAsync(ArtifactRef? reference, ArtifactAction action,
        string? preferredHandlerId = null, CancellationToken cancellationToken = default)
    {
        var snapshot = reference?.Clone();
        if (!IsValidAction(action) ||
            preferredHandlerId is not null && !ResourceReferenceValidation.IsValidHandlerId(preferredHandlerId) ||
            !ResourceReferenceValidation.TryGetArtifactOwner(snapshot, out var ownerAppId))
        {
            return ValueTask.FromResult(Failure<TAccess>("validation.invalid_request"));
        }

        if (!string.Equals(ownerAppId, _ownerAppId, StringComparison.Ordinal))
        {
            return ValueTask.FromResult(Failure<TAccess>("resource.unavailable"));
        }

        snapshot!.Resource?.ClearDisplayHint();
        Handler? selected;
        lock (_gate)
        {
            selected = _handlers.TryGetValue(snapshot!.Kind, out var registered)
                ? registered
                    .Where(handler => handler.Actions.Contains(action))
                    .OrderBy(handler => preferredHandlerId is not null && string.Equals(handler.HandlerId, preferredHandlerId, StringComparison.Ordinal) ? 0 : 1)
                    .ThenByDescending(handler => handler.Priority)
                    .ThenBy(handler => handler.HandlerId, StringComparer.Ordinal)
                    .FirstOrDefault()
                : null;
        }

        return selected is null
            ? ValueTask.FromResult(Failure<TAccess>("resource.unavailable"))
            : DispatchSelectedAsync(selected, snapshot, action, cancellationToken);
    }

    private static async ValueTask<Outcome<TAccess>> DispatchSelectedAsync(Handler handler, ArtifactRef snapshot,
        ArtifactAction action, CancellationToken cancellationToken)
    {
        var permission = await handler.Authorize(snapshot.Clone(), action, cancellationToken).ConfigureAwait(false);
        var refusal = PermissionRefusal(permission, out var allowed);
        if (refusal is not null) return refusal;
        if (!allowed) return Failure<TAccess>("perm.resource_denied");

        return await handler.Handle(snapshot.Clone(), action, cancellationToken).ConfigureAwait(false)
            ?? Failure<TAccess>("internal.unexpected");
    }

    private static Outcome<TAccess>? PermissionRefusal(Outcome<bool>? permission, out bool allowed)
    {
        allowed = false;
        if (permission is null) return Failure<TAccess>("internal.unexpected");
        if (permission.TryGetFailure(out var failure)) return Outcome.Failure<TAccess>(failure);
        if (permission.Kind == OutcomeKind.Cancelled) return Outcome.Cancelled<TAccess>(permission.CancellationEffect);
        if (!permission.TryGetValue(out allowed)) return Failure<TAccess>("internal.unexpected");
        return null;
    }

    private static Outcome<T> Failure<T>(string code) => Outcome.Failure<T>(TypedFailure.Create(code));

    private static bool IsValidAction(ArtifactAction action) => action is not ArtifactAction.None && Enum.IsDefined(action);

    private sealed record Handler(string HandlerId, int Priority, HashSet<ArtifactAction> Actions,
        ArtifactPermissionCheck Authorize, ArtifactHandlerAccess<TAccess> Handle);
}
