// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Application.Abstractions;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;

namespace ArcForges.Assistant.Abstractions;

/// <summary>Every host capability is explicitly bound to one live product installation and instance.</summary>
public interface IAssistantHostPort
{
    AssistantHostIdentity Owner { get; }
}

public interface IHostContext : IAssistantHostPort
{
    IReadOnlyList<HostContextSelection> DescribeSelection();

    ValueTask<Outcome<FrozenHostContext>> FreezeAsync(IReadOnlyCollection<ContextSelectionId> selectionIds,
        AssistantContextBudget budget, CancellationToken cancellationToken = default);
}

public interface IHostActions : IAssistantHostPort
{
    AssistantActionRegistration<TRequest, TResult> Register<TRequest, TResult>(AssistantActionDescriptor descriptor,
        Func<TRequest, CancellationToken, ValueTask<Outcome<TResult>>> handler,
        Func<FrozenHostContext?, ActionAvailability> availability);

    Outcome<ActionAvailability> GetAvailability(string operationId, FrozenHostContext? context = null);

    ValueTask<Outcome<TResult>> InvokeAsync<TRequest, TResult>(AssistantActionRegistration<TRequest, TResult> registration,
        AssistantHostIdentity target, TRequest request, FrozenHostContext? context = null,
        CancellationToken cancellationToken = default);
}

public interface IHostResources : IAssistantHostPort
{
    Outcome<ResolvedHostResource> Resolve(AssistantResourceReference reference);

    ValueTask<Outcome<Stream>> OpenReadAsync(HostResourceReadGrant grant, HostByteRange range,
        CancellationToken cancellationToken = default);

    Outcome<HostPreview> Present(AssistantResourceReference reference, HostPreviewMode previewMode);

    ValueTask<Outcome<HostSaveReceipt>> SaveAsAsync(AssistantResourceReference reference, HostFileGrant destination,
        CancellationToken cancellationToken = default);
}

public interface IHostNavigation : IAssistantHostPort
{
    Outcome<bool> OpenOwnedResource(AssistantResourceReference reference, string? anchor = null);
    Outcome<bool> RequestPanel(AssistantPresentationMode presentation, AssistantWindowId window);
    Outcome<bool> ShowAttention(AssistantAttentionRequest attention);
}

public enum HostBusyKind
{
    None = 0,
    Idle = 1,
    LocalWork = 2,
    AwaitingRemote = 3,
    NeedsUserDecision = 4,
}

public sealed record HostBusyState(HostBusyKind Kind, int ActiveLocalOperations, string? MessageKey = null);

public interface IHostLifecycle : IApplicationLifecycle, IAssistantHostPort
{
    HostBusyState GetBusyState();

    ValueTask<Outcome<AssistantShutdownSummary>> PrepareShutdownAsync(CancellationToken cancellationToken = default);

    ValueTask<Outcome<AssistantProfileId>> OnProfileChangingAsync(AssistantProfileId nextProfile,
        CancellationToken cancellationToken = default);

    void OnResumed();
}

public interface IHostDispatcher : IAssistantHostPort
{
    ValueTask InvokeAsync(Action callback, CancellationToken cancellationToken = default);
}

public sealed record AssistantSecretHandle
{
    public AssistantSecretHandle(AssistantHostIdentity owner, Guid handleId)
    {
        ArgumentNullException.ThrowIfNull(owner);
        if (handleId == Guid.Empty)
        {
            throw new ArgumentException("A secret handle requires a non-empty identity.", nameof(handleId));
        }

        Owner = owner;
        HandleId = handleId;
    }

    public AssistantHostIdentity Owner { get; }
    public Guid HandleId { get; }
}

public interface IHostSecureStorage : IAssistantHostPort
{
    ValueTask<Outcome<AssistantSecretHandle>> GetOrCreateHandleAsync(string purpose,
        CancellationToken cancellationToken = default);

    ValueTask<Outcome<bool>> DeleteAsync(AssistantSecretHandle handle,
        CancellationToken cancellationToken = default);
}

public interface IHostFilePicker : IAssistantHostPort
{
    ValueTask<Outcome<HostFileGrant>> RequestReadAsync(CancellationToken cancellationToken = default);
    ValueTask<Outcome<HostFileGrant>> RequestWriteAsync(string suggestedName,
        CancellationToken cancellationToken = default);
}

public interface IHostClipboard : IAssistantHostPort
{
    ValueTask<Outcome<bool>> CopyTextAsync(string text, CancellationToken cancellationToken = default);
    ValueTask<Outcome<string>> ReadTextAfterUserGestureAsync(CancellationToken cancellationToken = default);
}

public interface IHostEnvironment : IAssistantHostPort
{
    string Locale { get; }
    HostThemeMode Theme { get; }
    HostAccessibilityPreferences Accessibility { get; }
}

public interface IHostPlatformServices : IAssistantHostPort
{
    IClock Clock { get; }
    IHostDispatcher Dispatcher { get; }
    IHostSecureStorage SecureStorage { get; }
    IHostFilePicker FilePicker { get; }
    IHostClipboard Clipboard { get; }
    IHostEnvironment Environment { get; }
    bool DiagnosticsConsent { get; }
}

/// <summary>The one immutable storage scope supplied by the product composition for an active profile.</summary>
public interface IAssistantStoreScope
{
    AssistantStorePartition Partition { get; }
}

public interface IAssistantSessionFactory : IAssistantHostPort
{
    IAssistantSession Create(AssistantHostOptions options, AssistantHostServices services);
}

public interface IAssistantSession : IAsyncDisposable
{
    AssistantHostIdentity Identity { get; }
    AssistantHostOptions Options { get; }
    AssistantHostServices Services { get; }
    AssistantProfileId CurrentProfile { get; }

    Outcome<AssistantSurfaceHandle> OpenSurface(AssistantSurfaceRequest request);

    ValueTask<Outcome<AssistantConversationId>> CreateConversationAsync(AssistantHistoryMode historyMode,
        CancellationToken cancellationToken = default);

    ValueTask<Outcome<AssistantConversationId>> OpenConversationAsync(AssistantConversationId conversation,
        CancellationToken cancellationToken = default);

    ValueTask<Outcome<FrozenHostContext>> AttachContextAsync(IReadOnlyCollection<ContextSelectionId> selectionIds,
        AssistantContextBudget budget, CancellationToken cancellationToken = default);

    IAsyncEnumerable<AssistantAttention> ObserveAttentionAsync(CancellationToken cancellationToken = default);

    ValueTask<Outcome<AssistantProfileId>> SwitchProfileAsync(AssistantProfileId profile,
        CancellationToken cancellationToken = default);

    ValueTask<Outcome<AssistantShutdownSummary>> PrepareShutdownAsync(CancellationToken cancellationToken = default);
}

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

        cancellationToken.ThrowIfCancellationRequested();
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
