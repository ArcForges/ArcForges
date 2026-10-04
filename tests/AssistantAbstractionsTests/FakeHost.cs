// SPDX-License-Identifier: AGPL-3.0-only
#pragma warning disable CA2007 // Test code has no synchronization context to preserve.
#pragma warning disable CA1859 // Tests deliberately use the port interfaces to exercise their contracts.
#pragma warning disable CA2000 // Sessions and hosts here are in-memory test doubles that own no resources.
using ArcForges.Assistant.Abstractions;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation;
using ArcForges.Foundation.Errors;
using Google.Protobuf;

namespace AssistantAbstractionsTests;

/// <summary>
/// Test-only stand-in for the external product host. It implements every host port with the owner checks a real
/// product must perform, so the tests can exercise the port signatures; it is never part of a composition root
/// or package.
/// </summary>
internal sealed class FakeHost :
    IHostContext, IHostResources, IHostNavigation, IHostLifecycle, IHostPlatformServices,
    IHostDispatcher, IHostSecureStorage, IHostFilePicker, IHostClipboard, IHostEnvironment, IAssistantStoreScope
{
    private readonly Dictionary<ContextSelectionId, HostContextSelection> _selections = [];
    private readonly Dictionary<string, byte[]> _content = [];
    private readonly Dictionary<Guid, AssistantResourceReference> _issuedReads = [];
    private readonly HashSet<Guid> _secrets = [];
    private readonly HashSet<Guid> _writeGrants = [];
    private string _clipboard = string.Empty;

    public FakeHost(AssistantHostIdentity owner, AssistantStorePartition partition,
        IHostDispatcher? dispatcher = null, IHostSecureStorage? secureStorage = null,
        IHostFilePicker? filePicker = null, IHostClipboard? clipboard = null, IHostEnvironment? environment = null)
    {
        Owner = owner;
        Partition = partition;
        Dispatcher = dispatcher ?? this;
        SecureStorage = secureStorage ?? this;
        FilePicker = filePicker ?? this;
        Clipboard = clipboard ?? this;
        Environment = environment ?? this;
    }

    public static FakeHost For(AssistantHostIdentity owner, AssistantProfileId? profile = null)
        => new(owner, new AssistantStorePartition(owner.Installation, profile ?? TestData.Profile));

    public AssistantHostIdentity Owner { get; }
    public AssistantStorePartition Partition { get; }
    public IClock Clock { get; } = ArcForges.Foundation.Clock.System;
    public IHostDispatcher Dispatcher { get; }
    public IHostSecureStorage SecureStorage { get; }
    public IHostFilePicker FilePicker { get; }
    public IHostClipboard Clipboard { get; }
    public IHostEnvironment Environment { get; }
    public bool DiagnosticsConsent { get; set; }
    public string Locale => "en-US";
    public HostThemeMode Theme => HostThemeMode.System;
    public HostAccessibilityPreferences Accessibility { get; } = new(false, false, 1.0);
    public CancellationToken Stopping => CancellationToken.None;
    public int ActiveLocalOperations { get; set; }
    public List<string> Navigated { get; } = [];
    public int Resumed { get; private set; }
    public AssistantProfileId? ChangingTo { get; private set; }

    public HostContextSelection AddSelection(HostContextSelection selection)
    {
        _selections.Add(selection.Id, selection);
        return selection;
    }

    public AssistantResourceReference AddContent(AssistantResourceReference reference, byte[] content)
    {
        _content[Key(reference)] = content;
        return reference;
    }

    public IReadOnlyList<HostContextSelection> DescribeSelection() => [.. _selections.Values];

    public ValueTask<Outcome<FrozenHostContext>> FreezeAsync(IReadOnlyCollection<ContextSelectionId> selectionIds,
        AssistantContextBudget budget, CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return ValueTask.FromResult(Outcome.Cancelled<FrozenHostContext>(EffectCertainty.DidNotHappen));
        }

        List<HostContextSelection> included = [];
        List<ContextSelectionId> excluded = [];
        ulong bytes = 0;
        foreach (var id in selectionIds)
        {
            if (!_selections.TryGetValue(id, out var selection))
            {
                return ValueTask.FromResult(Outcome.Failure<FrozenHostContext>(TypedFailure.Create("state.not_found")));
            }

            if (included.Count >= budget.MaximumItems || selection.EstimatedBytes > budget.MaximumBytes - bytes)
            {
                excluded.Add(id);
                continue;
            }

            bytes += selection.EstimatedBytes;
            included.Add(selection);
        }

        return ValueTask.FromResult(Outcome.Success(new FrozenHostContext(Owner, budget, included, excluded)));
    }

    public Outcome<ResolvedHostResource> Resolve(AssistantResourceReference reference)
    {
        if (!reference.IsOwnedBy(Owner.Product))
        {
            return Outcome.Failure<ResolvedHostResource>(TypedFailure.Create("perm.resource_denied"));
        }

        if (!_content.ContainsKey(Key(reference)))
        {
            return Outcome.Failure<ResolvedHostResource>(TypedFailure.Create("state.not_found"));
        }

        var grant = new HostResourceReadGrant(Owner, Guid.NewGuid(), reference);
        _issuedReads[grant.GrantId] = reference;
        return Outcome.Success(new ResolvedHostResource(reference, grant, "resource.available"));
    }

    public ValueTask<Outcome<Stream>> OpenReadAsync(HostResourceReadGrant grant, HostByteRange range,
        CancellationToken cancellationToken = default)
    {
        if (grant.Owner != Owner || !_issuedReads.TryGetValue(grant.GrantId, out var issued) ||
            !issued.ToWire().Equals(grant.Resource.ToWire()))
        {
            return ValueTask.FromResult(Outcome.Failure<Stream>(TypedFailure.Create("perm.resource_denied")));
        }

        byte[] bytes = _content[Key(issued)];
        if (range.Offset > bytes.Length)
        {
            return ValueTask.FromResult(Outcome.Failure<Stream>(TypedFailure.Create("validation.invalid_request")));
        }

        int length = (int)Math.Min(range.Length ?? long.MaxValue, bytes.Length - range.Offset);
        return ValueTask.FromResult(Outcome.Success<Stream>(
            new MemoryStream(bytes, (int)range.Offset, length, writable: false)));
    }

    public Outcome<HostPreview> Present(AssistantResourceReference reference, HostPreviewMode previewMode)
        => !reference.IsOwnedBy(Owner.Product) || !_content.ContainsKey(Key(reference))
            ? Outcome.Failure<HostPreview>(TypedFailure.Create("resource.unavailable"))
            : Outcome.Success(new HostPreview(reference, previewMode, "preview.capture"));

    public ValueTask<Outcome<HostSaveReceipt>> SaveAsAsync(AssistantResourceReference reference,
        HostFileGrant destination, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(destination.Owner != Owner || !destination.CanWrite || !_writeGrants.Contains(destination.GrantId)
            ? Outcome.Failure<HostSaveReceipt>(TypedFailure.Create("perm.resource_denied"))
            : Outcome.Success(new HostSaveReceipt(destination.GrantId, reference)));

    public Outcome<bool> OpenOwnedResource(AssistantResourceReference reference, string? anchor = null)
    {
        if (!reference.IsOwnedBy(Owner.Product))
        {
            return Outcome.Failure<bool>(TypedFailure.Create("perm.resource_denied"));
        }

        bool known = _content.ContainsKey(Key(reference));
        if (known)
        {
            Navigated.Add(Key(reference) + "#" + anchor);
        }

        return Outcome.Success(known);
    }

    public Outcome<bool> RequestPanel(AssistantPresentationMode presentation, AssistantWindowId window)
    {
        Navigated.Add("panel:" + presentation + ":" + window.Value);
        return Outcome.Success(true);
    }

    public Outcome<bool> ShowAttention(AssistantAttentionRequest attention)
    {
        Navigated.Add("attention:" + attention.AttentionId);
        return Outcome.Success(true);
    }

    public HostBusyState GetBusyState() => ActiveLocalOperations > 0
        ? new HostBusyState(HostBusyKind.LocalWork, ActiveLocalOperations, "busy.local")
        : new HostBusyState(HostBusyKind.Idle, 0);

    public ValueTask<Outcome<AssistantShutdownSummary>> PrepareShutdownAsync(CancellationToken cancellationToken = default)
        => ValueTask.FromResult(Outcome.Success(ActiveLocalOperations == 0
            ? new AssistantShutdownSummary(true, 0, [])
            : new AssistantShutdownSummary(false, ActiveLocalOperations, ["shutdown.local_work"])));

    public ValueTask<Outcome<AssistantProfileId>> OnProfileChangingAsync(AssistantProfileId nextProfile,
        CancellationToken cancellationToken = default)
    {
        if (ActiveLocalOperations > 0)
        {
            return ValueTask.FromResult(Outcome.Failure<AssistantProfileId>(TypedFailure.Create("state.invalid_transition")));
        }

        ChangingTo = nextProfile;
        return ValueTask.FromResult(Outcome.Success(nextProfile));
    }

    public void OnResumed() => Resumed++;

    public ValueTask<Outcome<bool>> RequestStopAsync(CancellationToken cancellationToken)
        => ValueTask.FromResult(cancellationToken.IsCancellationRequested
            ? Outcome.Cancelled<bool>(EffectCertainty.DidNotHappen)
            : Outcome.Success(true));

    public async ValueTask InvokeAsync(Action callback, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Task.Yield();
        callback();
    }

    public ValueTask<Outcome<AssistantSecretHandle>> GetOrCreateHandleAsync(string purpose,
        CancellationToken cancellationToken = default)
    {
        var handle = new AssistantSecretHandle(Owner, Guid.NewGuid());
        _secrets.Add(handle.HandleId);
        return ValueTask.FromResult(Outcome.Success(handle));
    }

    public ValueTask<Outcome<bool>> DeleteAsync(AssistantSecretHandle handle, CancellationToken cancellationToken = default)
        => ValueTask.FromResult(handle.Owner != Owner
            ? Outcome.Failure<bool>(TypedFailure.Create("perm.capability_denied"))
            : Outcome.Success(_secrets.Remove(handle.HandleId)));

    public ValueTask<Outcome<HostFileGrant>> RequestReadAsync(CancellationToken cancellationToken = default)
        => ValueTask.FromResult(Outcome.Success(new HostFileGrant(Owner, Guid.NewGuid(), canRead: true, canWrite: false)));

    public ValueTask<Outcome<HostFileGrant>> RequestWriteAsync(string suggestedName,
        CancellationToken cancellationToken = default)
    {
        var grant = new HostFileGrant(Owner, Guid.NewGuid(), canRead: false, canWrite: true);
        _writeGrants.Add(grant.GrantId);
        return ValueTask.FromResult(Outcome.Success(grant));
    }

    public ValueTask<Outcome<bool>> CopyTextAsync(string text, CancellationToken cancellationToken = default)
    {
        _clipboard = text;
        return ValueTask.FromResult(Outcome.Success(true));
    }

    public ValueTask<Outcome<string>> ReadTextAfterUserGestureAsync(CancellationToken cancellationToken = default)
        => ValueTask.FromResult(Outcome.Success(_clipboard));

    private static string Key(AssistantResourceReference reference)
        => Convert.ToHexStringLower(reference.ToWire().ToByteArray());
}

/// <summary>Session stand-in produced by the explicit factory; it forwards to the injected ports only.</summary>
internal sealed class FakeSession(AssistantHostOptions options, AssistantHostServices services) : IAssistantSession
{
    public AssistantHostIdentity Identity => Options.Identity;
    public AssistantHostOptions Options { get; } = options;
    public AssistantHostServices Services { get; } = services;
    public AssistantProfileId CurrentProfile { get; private set; } = options.InitialProfile;
    public bool Disposed { get; private set; }
    public List<AssistantSurfaceRequest> Surfaces { get; } = [];

    public Outcome<AssistantSurfaceHandle> OpenSurface(AssistantSurfaceRequest request)
    {
        if (!Options.Supports(request.Mode))
        {
            return Outcome.Failure<AssistantSurfaceHandle>(TypedFailure.Create("validation.invalid_request"));
        }

        Surfaces.Add(request);
        return Outcome.Success(new AssistantSurfaceHandle(request.Mode, request.Window, request.Conversation));
    }

    public ValueTask<Outcome<AssistantConversationId>> CreateConversationAsync(AssistantHistoryMode historyMode,
        CancellationToken cancellationToken = default)
        => ValueTask.FromResult(Outcome.Success(AssistantConversationId.New()));

    public ValueTask<Outcome<AssistantConversationId>> OpenConversationAsync(AssistantConversationId conversation,
        CancellationToken cancellationToken = default)
        => ValueTask.FromResult(Outcome.Success(conversation));

    public ValueTask<Outcome<FrozenHostContext>> AttachContextAsync(IReadOnlyCollection<ContextSelectionId> selectionIds,
        AssistantContextBudget budget, CancellationToken cancellationToken = default)
        => Services.Context.FreezeAsync(selectionIds, budget, cancellationToken);

    public async IAsyncEnumerable<AssistantAttention> ObserveAttentionAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await Task.Yield();
        yield return new AssistantAttention("attention.sample", "attention.sample.message", DateTimeOffset.UnixEpoch);
    }

    public async ValueTask<Outcome<AssistantProfileId>> SwitchProfileAsync(AssistantProfileId profile,
        CancellationToken cancellationToken = default)
    {
        var allowed = await Services.Lifecycle.OnProfileChangingAsync(profile, cancellationToken);
        if (allowed.TryGetValue(out var next))
        {
            CurrentProfile = next;
        }

        return allowed;
    }

    public ValueTask<Outcome<AssistantShutdownSummary>> PrepareShutdownAsync(CancellationToken cancellationToken = default)
        => Services.Lifecycle.PrepareShutdownAsync(cancellationToken);

    public ValueTask DisposeAsync()
    {
        Disposed = true;
        return ValueTask.CompletedTask;
    }
}

/// <summary>A session whose advertised identity, options, services or profile can be forged individually.</summary>
internal sealed class ForgedSession(FakeSession inner, AssistantHostIdentity? identity = null,
    AssistantHostOptions? options = null, AssistantHostServices? services = null, AssistantProfileId? profile = null)
    : IAssistantSession
{
    public AssistantHostIdentity Identity => identity ?? inner.Identity;
    public AssistantHostOptions Options => options ?? inner.Options;
    public AssistantHostServices Services => services ?? inner.Services;
    public AssistantProfileId CurrentProfile => profile ?? inner.CurrentProfile;

    public Outcome<AssistantSurfaceHandle> OpenSurface(AssistantSurfaceRequest request) => inner.OpenSurface(request);

    public ValueTask<Outcome<AssistantConversationId>> CreateConversationAsync(AssistantHistoryMode historyMode,
        CancellationToken cancellationToken = default) => inner.CreateConversationAsync(historyMode, cancellationToken);

    public ValueTask<Outcome<AssistantConversationId>> OpenConversationAsync(AssistantConversationId conversation,
        CancellationToken cancellationToken = default) => inner.OpenConversationAsync(conversation, cancellationToken);

    public ValueTask<Outcome<FrozenHostContext>> AttachContextAsync(IReadOnlyCollection<ContextSelectionId> selectionIds,
        AssistantContextBudget budget, CancellationToken cancellationToken = default)
        => inner.AttachContextAsync(selectionIds, budget, cancellationToken);

    public IAsyncEnumerable<AssistantAttention> ObserveAttentionAsync(CancellationToken cancellationToken = default)
        => inner.ObserveAttentionAsync(cancellationToken);

    public ValueTask<Outcome<AssistantProfileId>> SwitchProfileAsync(AssistantProfileId profile,
        CancellationToken cancellationToken = default) => inner.SwitchProfileAsync(profile, cancellationToken);

    public ValueTask<Outcome<AssistantShutdownSummary>> PrepareShutdownAsync(CancellationToken cancellationToken = default)
        => inner.PrepareShutdownAsync(cancellationToken);

    public ValueTask DisposeAsync() => inner.DisposeAsync();
}

internal sealed class FakeSessionFactory(AssistantHostIdentity owner,
    Func<AssistantHostOptions, AssistantHostServices, IAssistantSession>? create = null) : IAssistantSessionFactory
{
    public AssistantHostIdentity Owner { get; } = owner;
    public int Calls { get; private set; }

    public IAssistantSession Create(AssistantHostOptions options, AssistantHostServices services)
    {
        Calls++;
        return create is null ? new FakeSession(options, services) : create(options, services);
    }
}

internal static class Composition
{
    public static AssistantHostServices Services(FakeHost host, IHostActions actions, IAssistantSessionFactory? factory = null,
        IHostPlatformServices? platform = null, IAssistantStoreScope? store = null)
        => new(host.Owner, host, actions, host, host, host, platform ?? host, store ?? host,
            factory ?? new FakeSessionFactory(host.Owner));
}
