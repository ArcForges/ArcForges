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

/// <summary>Busy state with a consistent local-operation count; running local work is never reported as idle.</summary>
public sealed record HostBusyState
{
    public HostBusyState(HostBusyKind kind, int activeLocalOperations, string? messageKey = null)
    {
        if (!Enum.IsDefined(kind) || kind == HostBusyKind.None)
        {
            throw new ArgumentOutOfRangeException(nameof(kind), "A known busy kind is required.");
        }

        ArgumentOutOfRangeException.ThrowIfNegative(activeLocalOperations);
        if (kind == HostBusyKind.LocalWork && activeLocalOperations == 0 ||
            kind != HostBusyKind.LocalWork && activeLocalOperations != 0)
        {
            throw new ArgumentException("The local operation count must agree with the busy kind.", nameof(activeLocalOperations));
        }

        Kind = kind;
        ActiveLocalOperations = activeLocalOperations;
        MessageKey = messageKey is null ? null : HostKeys.Require(messageKey, nameof(messageKey));
    }

    public HostBusyKind Kind { get; }
    public int ActiveLocalOperations { get; }
    public string? MessageKey { get; }
}

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
