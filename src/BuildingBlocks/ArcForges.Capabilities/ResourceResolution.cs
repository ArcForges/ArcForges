// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;

namespace ArcForges.Capabilities;

/// <summary>Re-evaluates the owning product's current permission for one floating resource access.</summary>
public delegate ValueTask<Outcome<bool>> FloatingResourceAuthorizationCheck(ResourceRef reference, CancellationToken cancellationToken);

/// <summary>Re-evaluates the owning product's current permission for one pinned resource access.</summary>
public delegate ValueTask<Outcome<bool>> PinnedResourceAuthorizationCheck(ResourceVersionRef reference, CancellationToken cancellationToken);

/// <summary>Opens the owner's current version of a floating resource after permission is checked.</summary>
public delegate ValueTask<Outcome<TAccess>> FloatingResourceAccess<TAccess>(ResourceRef reference, CancellationToken cancellationToken);

/// <summary>Opens the exact revision of a pinned resource after permission is checked.</summary>
public delegate ValueTask<Outcome<TAccess>> PinnedResourceAccess<TAccess>(ResourceVersionRef reference, CancellationToken cancellationToken);

/// <summary>
/// Per-application in-process registrations for resolving stable resource references. The registry
/// contains no location data, discovers no products, and calls the owning application's permission
/// check on every dereference before asking that owner to resolve content.
/// </summary>
public sealed class ResourceResolutionRegistry<TAccess>
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Handler> _handlers = [];
    private readonly string _ownerAppId;

    /// <summary>Binds this registry to one application composition.</summary>
    public ResourceResolutionRegistry(AppIdentity owner)
    {
        ArgumentNullException.ThrowIfNull(owner);
        _ownerAppId = owner.ProductId;
    }

    /// <summary>Registers one owner and namespaced resource kind exactly once.</summary>
    public void Register(string resourceKind,
        FloatingResourceAuthorizationCheck authorizeFloating,
        FloatingResourceAccess<TAccess> openFloating,
        PinnedResourceAuthorizationCheck authorizePinned,
        PinnedResourceAccess<TAccess> openPinned)
    {
        ArgumentNullException.ThrowIfNull(authorizeFloating);
        ArgumentNullException.ThrowIfNull(openFloating);
        ArgumentNullException.ThrowIfNull(authorizePinned);
        ArgumentNullException.ThrowIfNull(openPinned);
        if (!ResourceReferenceValidation.IsNamespacedKind(_ownerAppId, resourceKind))
        {
            throw new ArgumentException("The resource kind must be namespaced by its owning application.", nameof(resourceKind));
        }

        lock (_gate)
        {
            if (!_handlers.TryAdd(resourceKind, new Handler(authorizeFloating, openFloating, authorizePinned, openPinned)))
            {
                throw new InvalidOperationException("An owner can register a resource kind only once.");
            }
        }
    }

    /// <summary>Resolves the current version; this overload never accepts or infers a pinned revision.</summary>
    public ValueTask<Outcome<TAccess>> ResolveCurrentAsync(ResourceRef? reference, CancellationToken cancellationToken = default)
    {
        var snapshot = reference?.Clone();
        if (!ResourceReferenceValidation.TryGetOwner(snapshot, out var ownerAppId))
        {
            return ValueTask.FromResult(Failure<TAccess>("validation.invalid_request"));
        }

        if (!string.Equals(ownerAppId, _ownerAppId, StringComparison.Ordinal))
        {
            return ValueTask.FromResult(Failure<TAccess>("resource.unavailable"));
        }

        snapshot!.ClearDisplayHint();
        if (!TryGetHandler(snapshot!.ResourceKind, out var handler))
        {
            return ValueTask.FromResult(Failure<TAccess>("resource.unavailable"));
        }

        return ResolveCurrentCoreAsync(handler, snapshot, cancellationToken);
    }

    /// <summary>Resolves only the explicit cloud/native revision carried by a pinned reference.</summary>
    public ValueTask<Outcome<TAccess>> ResolvePinnedAsync(ResourceVersionRef? reference, CancellationToken cancellationToken = default)
    {
        var snapshot = reference?.Clone();
        if (!ResourceReferenceValidation.TryGetOwner(snapshot, out var ownerAppId))
        {
            return ValueTask.FromResult(Failure<TAccess>("validation.invalid_request"));
        }

        if (!string.Equals(ownerAppId, _ownerAppId, StringComparison.Ordinal))
        {
            return ValueTask.FromResult(Failure<TAccess>("resource.unavailable"));
        }

        snapshot!.Resource.ClearDisplayHint();
        if (!TryGetHandler(snapshot!.Resource.ResourceKind, out var handler))
        {
            return ValueTask.FromResult(Failure<TAccess>("resource.unavailable"));
        }

        return ResolvePinnedCoreAsync(handler, snapshot, cancellationToken);
    }

    private bool TryGetHandler(string kind, out Handler handler)
    {
        lock (_gate)
        {
            return _handlers.TryGetValue(kind, out handler!);
        }
    }

    private static async ValueTask<Outcome<TAccess>> ResolveCurrentCoreAsync(Handler handler, ResourceRef snapshot,
        CancellationToken cancellationToken)
    {
        var permission = await handler.AuthorizeFloating(snapshot.Clone(), cancellationToken).ConfigureAwait(false);
        var refusal = PermissionRefusal(permission, out var allowed);
        if (refusal is not null) return refusal;
        if (!allowed) return Failure<TAccess>("perm.resource_denied");

        return await handler.OpenFloating(snapshot.Clone(), cancellationToken).ConfigureAwait(false)
            ?? Failure<TAccess>("internal.unexpected");
    }

    private static async ValueTask<Outcome<TAccess>> ResolvePinnedCoreAsync(Handler handler, ResourceVersionRef snapshot,
        CancellationToken cancellationToken)
    {
        var permission = await handler.AuthorizePinned(snapshot.Clone(), cancellationToken).ConfigureAwait(false);
        var refusal = PermissionRefusal(permission, out var allowed);
        if (refusal is not null) return refusal;
        if (!allowed) return Failure<TAccess>("perm.resource_denied");

        return await handler.OpenPinned(snapshot.Clone(), cancellationToken).ConfigureAwait(false)
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

    private sealed record Handler(
        FloatingResourceAuthorizationCheck AuthorizeFloating,
        FloatingResourceAccess<TAccess> OpenFloating,
        PinnedResourceAuthorizationCheck AuthorizePinned,
        PinnedResourceAccess<TAccess> OpenPinned);
}

internal static class ResourceReferenceValidation
{
    public static bool TryGetOwner(ResourceRef? reference, out string ownerAppId)
    {
        ownerAppId = string.Empty;
        if (reference is null || !IsProductId(reference.OwnerAppId) ||
            !IsNamespacedKind(reference.OwnerAppId, reference.ResourceKind) ||
            !HasId(reference.RealmId) || !HasId(reference.ResourceId) ||
            reference.WorkspaceId is not null && !HasId(reference.WorkspaceId) ||
            reference.HoldingDeviceId is not null && !HasId(reference.HoldingDeviceId) ||
            !reference.HasAvailability || reference.Availability is ResourceAvailability.Unspecified || !Enum.IsDefined(reference.Availability) ||
            reference.HasDisplayHint && reference.DisplayHint.Length > 256)
        {
            return false;
        }

        ownerAppId = reference.OwnerAppId;
        return true;
    }

    public static bool TryGetOwner(ResourceVersionRef? reference, out string ownerAppId)
    {
        ownerAppId = string.Empty;
        if (reference is null || !TryGetOwner(reference.Resource, out ownerAppId) ||
            reference.RevisionCase == ResourceVersionRef.RevisionOneofCase.None ||
            !reference.HasContentHash || !IsSha256(reference.ContentHash, present: true))
        {
            return false;
        }

        try
        {
            switch (reference.RevisionCase)
            {
                case ResourceVersionRef.RevisionOneofCase.Cloud:
                    _ = CloudRevision.FromWire(reference.Cloud);
                    break;
                case ResourceVersionRef.RevisionOneofCase.Native:
                    _ = NativeRevision.FromWire(reference.Native);
                    break;
                default:
                    return false;
            }

            if (reference.Blob is not null)
            {
                _ = BlobId.FromWire(reference.Blob.BlobId);
                if (!reference.Blob.HasContentHash || !IsSha256(reference.Blob.ContentHash, present: true) ||
                    !string.Equals(reference.ContentHash, reference.Blob.ContentHash, StringComparison.Ordinal))
                {
                    return false;
                }
            }
        }
        catch (ArgumentException)
        {
            return false;
        }

        return true;
    }

    public static bool TryGetArtifactOwner(ArtifactRef? reference, out string ownerAppId)
    {
        ownerAppId = string.Empty;
        if (reference is null || !HasId(reference.ArtifactId) ||
            !IsNamespacedKindOwner(reference.Kind, out var owner) ||
            reference.Owner is null || !IsNamespacedKind(owner, reference.Owner.Kind) || !HasId(reference.Owner.Id) ||
            reference.Actor is null || !HasId(reference.Actor.Initiator) || !HasId(reference.Actor.Owner) ||
            reference.CreatedAt is null || !reference.CreatedAt.HasUnixSeconds || !reference.CreatedAt.HasNanos ||
            !reference.HasAvailability || string.IsNullOrWhiteSpace(reference.Availability))
        {
            return false;
        }

        try
        {
            _ = WireValues.ReadInstant(reference.CreatedAt);
        }
        catch (ArgumentException)
        {
            return false;
        }

        if (reference.Resource is not null && !TryGetOwner(reference.Resource, out _))
        {
            return false;
        }

        ownerAppId = owner;
        return true;
    }

    public static bool IsNamespacedKind(string ownerAppId, string? kind) =>
        IsProductId(ownerAppId) && IsNamespacedKindOwner(kind, out var kindOwner) &&
        string.Equals(ownerAppId, kindOwner, StringComparison.Ordinal);

    public static bool IsValidHandlerId(string? value) =>
        value is { Length: >= 1 and <= 128 } && IsKindSuffix(value);

    private static bool IsNamespacedKindOwner(string? kind, out string ownerAppId)
    {
        ownerAppId = string.Empty;
        if (string.IsNullOrEmpty(kind) || kind.Length > 128) return false;
        int separator = kind.IndexOf('.', StringComparison.Ordinal);
        if (separator <= 0 || separator == kind.Length - 1) return false;
        var owner = kind[..separator];
        if (!IsProductId(owner) || !IsKindSuffix(kind[(separator + 1)..])) return false;
        ownerAppId = owner;
        return true;
    }

    private static bool IsProductId(string? value) =>
        value is { Length: >= 1 and <= 64 } && IsLowerAlpha(value[0]) &&
        value.All(character => IsLowerAlpha(character) || character is >= '0' and <= '9' or '-');

    private static bool IsKindSuffix(string value)
    {
        bool segmentHasCharacter = false;
        bool needsCharacter = false;
        foreach (char character in value)
        {
            if (IsLowerAlpha(character) || character is >= '0' and <= '9')
            {
                segmentHasCharacter = true;
                needsCharacter = false;
            }
            else if ((character is '-' or '.') && segmentHasCharacter && !needsCharacter)
            {
                needsCharacter = true;
                if (character == '.') segmentHasCharacter = false;
            }
            else
            {
                return false;
            }
        }

        return segmentHasCharacter && !needsCharacter;
    }

    private static bool IsLowerAlpha(char value) => value is >= 'a' and <= 'z';

    private static bool IsSha256(string? value, bool present)
    {
        if (!present) return true;
        if (value is not { Length: 64 }) return false;
        return value.All(character => character is >= 'a' and <= 'f' or >= '0' and <= '9');
    }

    private static bool HasId(Id? value)
    {
        try
        {
            _ = UuidBoundary.FromWire(value!);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
