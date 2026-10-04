// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation.Errors;
using ArcForges.Contracts.Foundation.V1;

namespace ArcForges.Assistant.Abstractions;

/// <summary>Opaque typed token; both its descriptor and owning registry are fixed at registration time.</summary>
public sealed class AssistantActionRegistration<TRequest, TResult>
{
    internal AssistantActionRegistration(AssistantActionRegistry registry, string operationId, AssistantActionDescriptor descriptor)
    {
        Registry = registry;
        OperationId = operationId;
        Descriptor = descriptor;
    }

    internal AssistantActionRegistry Registry { get; }
    internal string OperationId { get; }
    public AssistantHostIdentity Owner => Registry.Owner;
    public AssistantActionDescriptor Descriptor { get; }
}

/// <summary>
/// Per-composition action registry. It has no global key, reflection dispatch, or universal request/result
/// envelope: callers retain a registration token with its exact generic request and result types.
/// </summary>
public sealed class AssistantActionRegistry : IHostActions
{
    private readonly object _gate = new();
    private readonly Dictionary<string, IActionBinding> _bindings = new(StringComparer.Ordinal);
    private readonly HashSet<string> _allowedOperationIds;
    private readonly HashSet<string> _allowedCapabilities;
    private bool _sealed;

    public AssistantActionRegistry(AssistantHostIdentity owner, IEnumerable<string> allowedOperationIds,
        IEnumerable<string> allowedCapabilities)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(allowedOperationIds);
        ArgumentNullException.ThrowIfNull(allowedCapabilities);
        Owner = owner;
        _allowedOperationIds = new HashSet<string>(allowedOperationIds, StringComparer.Ordinal);
        _allowedCapabilities = new HashSet<string>(allowedCapabilities, StringComparer.Ordinal);
        if (_allowedOperationIds.Any(static id => string.IsNullOrWhiteSpace(id)) ||
            _allowedCapabilities.Any(static id => string.IsNullOrWhiteSpace(id)))
        {
            throw new ArgumentException("The action allowlist cannot contain empty identifiers.");
        }
    }

    public AssistantHostIdentity Owner { get; }

    public AssistantActionRegistration<TRequest, TResult> Register<TRequest, TResult>(AssistantActionDescriptor descriptor,
        Func<TRequest, CancellationToken, ValueTask<Outcome<TResult>>> handler,
        Func<FrozenHostContext?, ActionAvailability> availability)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(availability);
        if (!_allowedOperationIds.Contains(descriptor.OperationId))
        {
            throw new ArgumentException("The operation is not in this product's explicit action allowlist.", nameof(descriptor));
        }

        if (descriptor.RequiredCapabilities.Any(capability => !_allowedCapabilities.Contains(capability)))
        {
            throw new ArgumentException("The operation requests a capability outside this product's explicit allowlist.", nameof(descriptor));
        }

        string operationId = descriptor.OperationId;
        var binding = new ActionBinding<TRequest, TResult>(descriptor, handler, availability);
        lock (_gate)
        {
            if (_sealed)
            {
                throw new InvalidOperationException("A sealed assistant composition cannot register another action.");
            }

            if (!_bindings.TryAdd(operationId, binding))
            {
                throw new ArgumentException("An operation can be registered only once in one composition.", nameof(descriptor));
            }
        }

        return new AssistantActionRegistration<TRequest, TResult>(this, operationId, binding.Descriptor);
    }

    public Outcome<ActionAvailability> GetAvailability(string operationId, FrozenHostContext? context = null)
    {
        if (string.IsNullOrWhiteSpace(operationId))
        {
            return Outcome.Failure<ActionAvailability>(TypedFailure.Create("validation.invalid_request"));
        }

        if (context is not null && context.Owner != Owner)
        {
            return Outcome.Failure<ActionAvailability>(TypedFailure.Create("perm.capability_denied"));
        }

        IActionBinding? binding;
        lock (_gate)
        {
            _bindings.TryGetValue(operationId, out binding);
        }

        return binding is null
            ? Outcome.Failure<ActionAvailability>(TypedFailure.Create("state.not_found"))
            : Outcome.Success(binding.GetAvailability(context));
    }

    public ValueTask<Outcome<TResult>> InvokeAsync<TRequest, TResult>(AssistantActionRegistration<TRequest, TResult> registration,
        AssistantHostIdentity target, TRequest request, FrozenHostContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(target);
        if (!ReferenceEquals(registration.Registry, this) || target != Owner || registration.Owner != Owner)
        {
            return ValueTask.FromResult(Outcome.Failure<TResult>(TypedFailure.Create("perm.capability_denied")));
        }

        if (context is not null && context.Owner != Owner)
        {
            return ValueTask.FromResult(Outcome.Failure<TResult>(TypedFailure.Create("perm.capability_denied")));
        }

        IActionBinding? binding;
        lock (_gate)
        {
            _bindings.TryGetValue(registration.OperationId, out binding);
        }

        if (binding is not ActionBinding<TRequest, TResult> typedBinding)
        {
            return ValueTask.FromResult(Outcome.Failure<TResult>(TypedFailure.Create("perm.capability_denied")));
        }

        if (cancellationToken.IsCancellationRequested)
        {
            // Cancelled before the owner handler was called: no effect has happened.
            return ValueTask.FromResult(Outcome.Cancelled<TResult>(EffectCertainty.DidNotHappen));
        }

        if (!typedBinding.GetAvailability(context).IsAvailable)
        {
            return ValueTask.FromResult(Outcome.Failure<TResult>(TypedFailure.Create("perm.capability_denied")));
        }

        return typedBinding.InvokeAsync(request, cancellationToken);
    }

    internal void Seal()
    {
        lock (_gate)
        {
            _sealed = true;
        }
    }

    private interface IActionBinding
    {
        AssistantActionDescriptor Descriptor { get; }
        ActionAvailability GetAvailability(FrozenHostContext? context);
    }

    private sealed class ActionBinding<TRequest, TResult>(AssistantActionDescriptor descriptor,
        Func<TRequest, CancellationToken, ValueTask<Outcome<TResult>>> handler,
        Func<FrozenHostContext?, ActionAvailability> availability) : IActionBinding
    {
        public AssistantActionDescriptor Descriptor { get; } = descriptor;

        public ActionAvailability GetAvailability(FrozenHostContext? context)
        {
            var result = availability(context);
            return result ?? throw new InvalidOperationException("An action availability handler must return a value.");
        }

        public ValueTask<Outcome<TResult>> InvokeAsync(TRequest request, CancellationToken cancellationToken)
            => handler(request, cancellationToken);
    }
}
