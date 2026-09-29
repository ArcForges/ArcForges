// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;

namespace ArcForges.Capabilities;

/// <summary>A validated, still-untrusted intent addressed only to the owning application.</summary>
public sealed class OwnAppDeepLinkIntent
{
    private readonly bool _isUntrusted;

    internal OwnAppDeepLinkIntent(AppIdentity owner, string routeId, string targetId)
    {
        Owner = owner;
        RouteId = routeId;
        TargetId = targetId;
        _isUntrusted = true;
    }

    public AppIdentity Owner { get; }
    public string RouteId { get; }
    public string TargetId { get; }

    /// <summary>Deep-link input never carries authorization, even after structural validation.</summary>
    public bool IsUntrusted => _isUntrusted;
}

/// <summary>In-process route handler. It may navigate to an intent but must use normal owner checks for access/effects.</summary>
public delegate ValueTask<Outcome<TAccess>> OwnAppDeepLinkHandler<TAccess>(OwnAppDeepLinkIntent intent,
    CancellationToken cancellationToken);

/// <summary>
/// Routes artifact opens and canonical local deep links only to handlers registered by this application.
/// It never discovers, launches, or falls through to another product.
/// </summary>
public sealed class OwnAppNavigationRouter<TAccess>
{
    private const int MaximumLinkLength = 2048;
    private readonly object _gate = new();
    private readonly Dictionary<string, OwnAppDeepLinkHandler<TAccess>> _routes = new(StringComparer.Ordinal);
    private readonly AppIdentity _owner;
    private readonly ArtifactHandlerRegistry<TAccess> _artifacts;

    public OwnAppNavigationRouter(AppIdentity owner, ArtifactHandlerRegistry<TAccess> artifacts)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(artifacts);
        _owner = owner;
        _artifacts = artifacts;
    }

    /// <summary>Registers one exact logical route in this process; route registration never launches a product.</summary>
    public void RegisterRoute(string routeId, OwnAppDeepLinkHandler<TAccess> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        if (!IsRouteId(routeId))
        {
            throw new ArgumentException("A bounded canonical route ID is required.", nameof(routeId));
        }

        lock (_gate)
        {
            if (!_routes.TryAdd(routeId, handler))
            {
                throw new InvalidOperationException("A route can be registered only once per application.");
            }
        }
    }

    /// <summary>Uses the existing artifact-owner registry, including its access-time permission check.</summary>
    public ValueTask<Outcome<TAccess>> OpenArtifactAsync(ArtifactRef? reference, ArtifactAction action,
        string? preferredHandlerId = null, CancellationToken cancellationToken = default)
    {
        if (ResourceReferenceValidation.TryGetArtifactOwner(reference, out var artifactOwner) &&
            !string.Equals(artifactOwner, _owner.ProductId, StringComparison.Ordinal))
        {
            return ValueTask.FromResult(Failure("resource.unavailable"));
        }

        return _artifacts.DispatchAsync(reference, action, preferredHandlerId, cancellationToken);
    }

    /// <summary>
    /// Validates an untrusted arcforges:// link and invokes only the exact route registered by this owner.
    /// Query strings, fragments, user information, ports, encoded path bytes and non-owner hosts refuse.
    /// </summary>
    public async ValueTask<Outcome<TAccess>> HandleDeepLinkAsync(string? address,
        CancellationToken cancellationToken = default)
    {
        if (!TryParse(address, out var intent, out var foreignOwner))
        {
            return Failure("validation.invalid_request");
        }

        if (foreignOwner)
        {
            return Failure("resource.unavailable");
        }

        OwnAppDeepLinkHandler<TAccess>? handler;
        lock (_gate)
        {
            _routes.TryGetValue(intent!.RouteId, out handler);
        }

        if (handler is null)
        {
            return Failure("resource.unavailable");
        }

        return await handler(intent!, cancellationToken).ConfigureAwait(false)
            ?? Failure("internal.unexpected");
    }

    private bool TryParse(string? address, out OwnAppDeepLinkIntent? intent, out bool foreignOwner)
    {
        intent = null;
        foreignOwner = false;
        if (string.IsNullOrEmpty(address) || address.Length > MaximumLinkLength ||
            address.Any(char.IsWhiteSpace) || address.Any(char.IsControl) ||
            address.Contains('\\', StringComparison.Ordinal) ||
            address.Contains('%', StringComparison.Ordinal) || address.Contains('@', StringComparison.Ordinal) ||
            address.Contains('?', StringComparison.Ordinal) || address.Contains('#', StringComparison.Ordinal) ||
            address.Contains("/../", StringComparison.Ordinal) || address.EndsWith("/..", StringComparison.Ordinal) ||
            address.Contains("/./", StringComparison.Ordinal) || address.EndsWith("/.", StringComparison.Ordinal) ||
            !Uri.TryCreate(address, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, "arcforges", StringComparison.OrdinalIgnoreCase) ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.Port != -1 ||
            uri.HostNameType != UriHostNameType.Dns)
        {
            return false;
        }

        if (!string.Equals(uri.IdnHost, _owner.ProductId, StringComparison.Ordinal))
        {
            foreignOwner = true;
            return true;
        }

        var path = uri.AbsolutePath;
        var segments = path.StartsWith('/')
            ? path[1..].Split('/', StringSplitOptions.None)
            : Array.Empty<string>();
        if (segments.Length != 2 || !IsRouteId(segments[0]) || !IsTargetId(segments[1]))
        {
            return false;
        }

        intent = new OwnAppDeepLinkIntent(_owner, segments[0], segments[1]);
        return true;
    }

    private static bool IsRouteId(string? value) => value is { Length: >= 1 and <= 64 } &&
        value[0] is >= 'a' and <= 'z' && value.All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '.');

    private static bool IsTargetId(string? value) => value is { Length: >= 1 and <= 128 } &&
        value is not "." and not ".." && value.All(character =>
            character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '-' or '_' or '.' or ':');

    private static Outcome<TAccess> Failure(string code) => Outcome.Failure<TAccess>(TypedFailure.Create(code));
}
