// SPDX-License-Identifier: AGPL-3.0-only
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace ArcForges.LocalRpc;

/// <summary>
/// One generated service a child declares: its full protobuf name, the contract majors it serves and the capabilities it offers.
/// The parent writes this from what it knows statically about the child it launches (its signed inventory), never from anything the
/// child sends over the wire and never by looking for an installed product. The type names no contract: the owner passes the
/// generated service's name.
/// </summary>
public sealed class LocalRpcServiceDeclaration
{
    /// <summary>Most contract majors one service declares.</summary>
    public const int MaximumMajors = 8;

    /// <summary>Most capabilities one service declares.</summary>
    public const int MaximumCapabilities = 32;

    /// <summary>Longest service name or capability name.</summary>
    public const int MaximumNameLength = 128;

    /// <summary>Creates a declaration. Majors and capabilities are copied; duplicates collapse; major 0 is not a version.</summary>
    /// <param name="serviceName">The full protobuf service name, for example <c>arcforges.local.sandbox.v1.ContentSandboxService</c>.</param>
    /// <param name="contractMajors">The contract majors the child serves, one to <see cref="MaximumMajors"/>.</param>
    /// <param name="capabilities">The capability names the child offers for this service, at most <see cref="MaximumCapabilities"/>.</param>
    public LocalRpcServiceDeclaration(string serviceName, IEnumerable<uint> contractMajors, IEnumerable<string>? capabilities = null)
    {
        ArgumentNullException.ThrowIfNull(serviceName);
        ArgumentNullException.ThrowIfNull(contractMajors);
        if (serviceName.Length > MaximumNameLength || !LocalRpcServerBuilder.IsProtoName(serviceName))
        {
            throw new ArgumentException("A service name is a protobuf service name of at most 128 characters.", nameof(serviceName));
        }

        var majors = contractMajors.Take(MaximumMajors + 1).ToArray();
        if (majors.Length is 0 or > MaximumMajors || majors.Contains(0u))
        {
            throw new ArgumentException("A service declares one to eight contract majors, none of them 0.", nameof(contractMajors));
        }

        var names = (capabilities ?? []).Take(MaximumCapabilities + 1).ToArray();
        if (names.Length > MaximumCapabilities || names.Any(name => !IsCapabilityName(name)))
        {
            throw new ArgumentException("A service declares at most 32 capabilities, each a valid capability name.", nameof(capabilities));
        }

        ServiceName = serviceName;
        ContractMajors = Array.AsReadOnly(majors.Distinct().Order().ToArray());
        Capabilities = Array.AsReadOnly(names.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());
    }

    /// <summary>The full protobuf service name.</summary>
    public string ServiceName { get; }

    /// <summary>The contract majors the child serves, ascending.</summary>
    public IReadOnlyList<uint> ContractMajors { get; }

    /// <summary>The capabilities the child offers for this service, in ordinal order.</summary>
    public IReadOnlyList<string> Capabilities { get; }

    /// <summary>A capability name: 1-128 ASCII letters, digits, '.', '_', '-' or ':', starting with a letter. It is compared exactly, case included.</summary>
    internal static bool IsCapabilityName(string? name)
    {
        if (name is null || name.Length is 0 or > MaximumNameLength || !char.IsAsciiLetter(name[0]))
        {
            return false;
        }

        return name.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-' or ':');
    }

    internal bool Serves(uint major) => ContractMajors.Contains(major);

    internal bool Offers(string capability) => Capabilities.Contains(capability, StringComparer.Ordinal);
}

/// <summary>
/// The closed set of generated services one kind of child exposes. A server that serves a child (<see cref="LocalRpcServerBuilder.RequireDeclaredServices"/>)
/// serves exactly these, and the router resolves nothing else for the child.
/// </summary>
public sealed class LocalRpcChildDeclaration
{
    /// <summary>Most services one child declares.</summary>
    public const int MaximumServices = 16;

    /// <summary>Creates a declaration. Each service name appears once.</summary>
    public LocalRpcChildDeclaration(LocalRpcChildKind childKind, IEnumerable<LocalRpcServiceDeclaration> services)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (childKind == LocalRpcChildKind.None || !Enum.IsDefined(childKind))
        {
            throw new ArgumentOutOfRangeException(nameof(childKind), childKind, "A declaration is for one child kind.");
        }

        var list = services.Take(MaximumServices + 1).ToArray();
        if (list.Length is 0 or > MaximumServices || list.Any(service => service is null))
        {
            throw new ArgumentException("A child declares one to sixteen services.", nameof(services));
        }

        if (list.Select(service => service.ServiceName).Distinct(StringComparer.Ordinal).Count() != list.Length)
        {
            throw new ArgumentException("A service is declared once.", nameof(services));
        }

        ChildKind = childKind;
        Services = Array.AsReadOnly(list.OrderBy(service => service.ServiceName, StringComparer.Ordinal).ToArray());
    }

    /// <summary>The child kind the declaration is for.</summary>
    public LocalRpcChildKind ChildKind { get; }

    /// <summary>The declared services, ordered by name.</summary>
    public IReadOnlyList<LocalRpcServiceDeclaration> Services { get; }

    internal LocalRpcServiceDeclaration? Find(string serviceName)
    {
        foreach (var service in Services)
        {
            if (string.Equals(service.ServiceName, serviceName, StringComparison.Ordinal))
            {
                return service;
            }
        }

        return null;
    }
}

/// <summary>Why the router did not resolve a service. <see cref="None"/> is the only resolving value. These are the parent's own diagnostics.</summary>
public enum LocalRpcRouteRefusal
{
    /// <summary>Resolved.</summary>
    None = 0,

    /// <summary>The request is malformed: a slot or service that is not a valid name, a capability that is not a capability name, too many capabilities.</summary>
    InvalidRequest,

    /// <summary>No child was added to the router under this slot. Nothing else is searched: not another slot, not another child kind, not an installed product.</summary>
    UnknownChild,

    /// <summary>The child was added but has not registered yet.</summary>
    ChildNotRegistered,

    /// <summary>The child's registration is over (lease passed, launch superseded or revoked, process gone, disposed). It is never revived: the owner relaunches and adds the new registration.</summary>
    ChildEnded,

    /// <summary>The child did not declare this service. No other child is consulted, whatever it declares.</summary>
    ServiceNotDeclared,

    /// <summary>The child does not serve the requested contract major of the service.</summary>
    VersionUnsupported,

    /// <summary>The child does not offer one of the required capabilities for the service.</summary>
    CapabilityUnsupported,
}

/// <summary>A request to resolve one declared service of one explicitly launched child.</summary>
/// <param name="Slot">The slot the child was launched in (<see cref="LocalRpcLaunchAuthority.Launch"/>).</param>
/// <param name="Service">The full protobuf service name.</param>
/// <param name="ContractMajor">The contract major the caller was built against.</param>
/// <param name="RequiredCapabilities">The capability names the caller needs the child to offer, or none.</param>
public sealed record LocalRpcRouteRequest(string Slot, string Service, uint ContractMajor, IReadOnlyList<string>? RequiredCapabilities = null);

/// <summary>
/// A resolved route: one live child, one declared service, one contract major and the capabilities that were required and found. It is a
/// fact at the moment of resolution; <see cref="CreateGuard"/> keeps a channel to it honest for as long as it is used.
/// </summary>
public sealed class LocalRpcResolvedRoute
{
    private readonly LocalRpcRegistration _registration;

    internal LocalRpcResolvedRoute(LocalRpcRegistration registration, LocalRpcServiceDeclaration service, uint contractMajor, IReadOnlyList<string> capabilities)
    {
        _registration = registration;
        var descriptor = registration.Launch.Descriptor;
        Slot = descriptor.Slot;
        Epoch = descriptor.Epoch;
        LaunchId = descriptor.LaunchId;
        ChildKind = descriptor.Identity.ChildKind;
        ServiceName = service.ServiceName;
        ContractMajor = contractMajor;
        Capabilities = capabilities;
    }

    /// <summary>The slot of the child.</summary>
    public string Slot { get; }

    /// <summary>The launch epoch of the child this route was resolved to.</summary>
    public ulong Epoch { get; }

    /// <summary>The launch of the child this route was resolved to.</summary>
    public Guid LaunchId { get; }

    /// <summary>The kind of the child.</summary>
    public LocalRpcChildKind ChildKind { get; }

    /// <summary>The one service this route is for.</summary>
    public string ServiceName { get; }

    /// <summary>The contract major that was requested and is served.</summary>
    public uint ContractMajor { get; }

    /// <summary>The capabilities that were required and are offered, in the order requested.</summary>
    public IReadOnlyList<string> Capabilities { get; }

    /// <summary>
    /// An interceptor for the channel to this child. It refuses, before the wire and before anything dispatches, every call to a service
    /// other than <see cref="ServiceName"/> (<see cref="LocalRpcRefusalReason.UnroutedService"/>), and every call once the child's
    /// registration is no longer live (<see cref="LocalRpcRefusalReason.RouteNotLive"/>): a route to the old epoch of a relaunched
    /// slot, or to a child whose lease passed, calls nothing. It does not map methods to capabilities; the capability check is the resolution.
    /// </summary>
    public Interceptor CreateGuard() => new LocalRpcRouteGuard(this);

    internal LocalRpcRegistrationRefusal CheckLive() => _registration.CheckLive();
}

/// <summary>
/// The parent's static routing table. It knows only the children that were added to it explicitly, each under the slot its launch
/// fixed, with the generated services that child declared. <see cref="TryResolve"/> answers for one slot, one service, one contract
/// major and the capabilities required, and for nothing else: it never searches other slots, never picks a child by service name, never
/// consults the operating system, a registry, a path or an installed product, and a refusal never falls back to anything. Resolving
/// touches nothing: it does not extend a lease, count as a call or change a registration.
/// </summary>
public sealed class LocalRpcRouter
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _children = new(StringComparer.Ordinal);

    /// <summary>
    /// Adds one launched child with the services it declares. The declaration's kind must be the launch's kind. A slot holds one child:
    /// adding to a slot whose earlier registration has not ended is refused, and a registration that has ended is replaced (the relaunch
    /// of a slot revokes the earlier launch at once, so its registration is over by then).
    /// </summary>
    public void Add(LocalRpcRegistration registration, LocalRpcChildDeclaration declaration)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(declaration);
        var descriptor = registration.Launch.Descriptor;
        if (descriptor.Identity.ChildKind != declaration.ChildKind)
        {
            throw new ArgumentException("The declaration is for another child kind than the launch.", nameof(declaration));
        }

        if (registration.State == LocalRpcRegistrationState.Ended)
        {
            throw new InvalidOperationException("A registration that has ended is never routed to.");
        }

        lock (_gate)
        {
            if (_children.TryGetValue(descriptor.Slot, out var existing) && existing.Registration.State != LocalRpcRegistrationState.Ended)
            {
                throw new InvalidOperationException("A slot holds one child; the earlier registration of this slot has not ended.");
            }

            _children[descriptor.Slot] = new Entry(registration, declaration);
        }
    }

    /// <summary>
    /// Resolves one declared service of the child in one slot. Checks run in a fixed order and the first failure is the answer:
    /// request, child known, child registered and live, service declared, contract major served, capabilities offered.
    /// </summary>
    public LocalRpcRouteRefusal TryResolve(LocalRpcRouteRequest request, out LocalRpcResolvedRoute? route)
    {
        ArgumentNullException.ThrowIfNull(request);
        route = null;
        if (!IsValid(request))
        {
            return LocalRpcRouteRefusal.InvalidRequest;
        }

        Entry entry;
        lock (_gate)
        {
            if (!_children.TryGetValue(request.Slot, out entry!))
            {
                return LocalRpcRouteRefusal.UnknownChild;
            }
        }

        var live = entry.Registration.CheckLive();
        if (live != LocalRpcRegistrationRefusal.None)
        {
            return live == LocalRpcRegistrationRefusal.NotRegistered ? LocalRpcRouteRefusal.ChildNotRegistered : LocalRpcRouteRefusal.ChildEnded;
        }

        if (entry.Declaration.Find(request.Service) is not { } service)
        {
            return LocalRpcRouteRefusal.ServiceNotDeclared;
        }

        if (!service.Serves(request.ContractMajor))
        {
            return LocalRpcRouteRefusal.VersionUnsupported;
        }

        var required = request.RequiredCapabilities ?? [];
        if (required.Any(capability => !service.Offers(capability)))
        {
            return LocalRpcRouteRefusal.CapabilityUnsupported;
        }

        route = new LocalRpcResolvedRoute(entry.Registration, service, request.ContractMajor, required.ToArray());
        return LocalRpcRouteRefusal.None;
    }

    private static bool IsValid(LocalRpcRouteRequest request)
    {
        if (request.Slot is not { Length: > 0 and <= LocalRpcLaunchIdentity.MaximumTokenLength } || request.Service is not { Length: > 0 and <= LocalRpcServiceDeclaration.MaximumNameLength }
            || !LocalRpcServerBuilder.IsProtoName(request.Service))
        {
            return false;
        }

        var required = request.RequiredCapabilities;
        return required is null
            || (required.Count <= LocalRpcServiceDeclaration.MaximumCapabilities && required.All(LocalRpcServiceDeclaration.IsCapabilityName));
    }

    private sealed record Entry(LocalRpcRegistration Registration, LocalRpcChildDeclaration Declaration);
}

/// <summary>The interceptor of <see cref="LocalRpcResolvedRoute.CreateGuard"/>. A refused call throws an <see cref="RpcException"/> before the call is made.</summary>
internal sealed class LocalRpcRouteGuard(LocalRpcResolvedRoute route) : Interceptor
{
    public override TResponse BlockingUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        BlockingUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        Check(context.Method);
        return continuation(request, context);
    }

    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        Check(context.Method);
        return continuation(request, context);
    }

    public override AsyncServerStreamingCall<TResponse> AsyncServerStreamingCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncServerStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        Check(context.Method);
        return continuation(request, context);
    }

    public override AsyncClientStreamingCall<TRequest, TResponse> AsyncClientStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncClientStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        Check(context.Method);
        return continuation(context);
    }

    public override AsyncDuplexStreamingCall<TRequest, TResponse> AsyncDuplexStreamingCall<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncDuplexStreamingCallContinuation<TRequest, TResponse> continuation)
    {
        Check(context.Method);
        return continuation(context);
    }

    private void Check(IMethod method)
    {
        if (!string.Equals(method.ServiceName, route.ServiceName, StringComparison.Ordinal))
        {
            throw Refuse(LocalRpcRefusalReason.UnroutedService, "The call is not routed to this child.");
        }

        if (route.CheckLive() != LocalRpcRegistrationRefusal.None)
        {
            throw Refuse(LocalRpcRefusalReason.RouteNotLive, "The child is no longer registered.");
        }
    }

    private static RpcException Refuse(LocalRpcRefusalReason reason, string message) =>
        new(
            new Status(LocalRpcRefusal.StatusOf(reason), message),
            new Metadata
            {
                { LocalRpcRefusal.ReasonTrailer, LocalRpcRefusal.NameOf(reason) },
                { LocalRpcRefusal.DispatchedTrailer, "0" },
            });
}
