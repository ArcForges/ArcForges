// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using ArcForges.Application.Abstractions;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Foundation.Errors;

namespace ArcForges.Assistant.Abstractions;

/// <summary>What a product host knows about its Cloud connection. It is information only; nothing local waits on it.</summary>
public enum AssistantRemoteState
{
    None = 0,
    Available = 1,
    Unavailable = 2,
}

/// <summary>Optional host view of Cloud reachability. A composition without Cloud supplies no link.</summary>
public interface IAssistantRemoteLink : IAssistantHostPort
{
    AssistantRemoteState State { get; }
}

/// <summary>The result of launching an application composition.</summary>
public sealed record AssistantLaunchReport
{
    public AssistantLaunchReport(IEnumerable<AssistantDraft> recoveredDrafts, AssistantRemoteState remote,
        TypedFailure? recoveryFailure)
    {
        ArgumentNullException.ThrowIfNull(recoveredDrafts);
        if (!Enum.IsDefined(remote) || remote == AssistantRemoteState.None)
        {
            throw new ArgumentOutOfRangeException(nameof(remote), "A known remote state is required.");
        }

        RecoveredDrafts = [.. recoveredDrafts];
        Remote = remote;
        RecoveryFailure = recoveryFailure;
    }

    /// <summary>Drafts found durable from an earlier run, each claimable by exactly one new view.</summary>
    public IReadOnlyList<AssistantDraft> RecoveredDrafts { get; }

    public AssistantRemoteState Remote { get; }

    /// <summary>Set when stored drafts could not be read; the application still launched and nothing was deleted.</summary>
    public TypedFailure? RecoveryFailure { get; }
}

public enum AssistantWorkKind
{
    None = 0,
    Local = 1,
    Remote = 2,
}

/// <summary>
/// Registration of running work so shutdown can be honest about it. Disposing the handle ends the registration;
/// it never cancels or completes the work itself, and a window closing never disposes a handle.
/// </summary>
public sealed class AssistantWorkHandle : IDisposable
{
    private readonly AssistantLifecycle _owner;
    private int _disposed;

    internal AssistantWorkHandle(AssistantLifecycle owner, AssistantWorkKind kind, string key,
        Func<CancellationToken, ValueTask<bool>>? checkpoint)
    {
        _owner = owner;
        Kind = kind;
        Key = key;
        Checkpoint = checkpoint;
    }

    public AssistantWorkKind Kind { get; }
    public string Key { get; }

    /// <summary>Signalled when the application is stopping; local work observes it to stop writing.</summary>
    public CancellationToken Stopping => _owner.Stopping;

    internal Func<CancellationToken, ValueTask<bool>>? Checkpoint { get; }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _owner.EndWork(this);
        }
    }
}

/// <summary>
/// One window's view of the assistant: its own draft, its own cancellation scope. Closing a view saves its draft,
/// cancels only view-bound work and leaves the session, every other view, local work and Cloud work untouched.
/// </summary>
public sealed class AssistantView : IAsyncDisposable
{
    private readonly AssistantLifecycle _owner;
    [SuppressMessage("Usage", "CA2213:Disposable fields should be disposed", Justification = "The gate never allocates a wait handle and a retained view must still save after it closes.")]
    private readonly SemaphoreSlim _saveGate = new(1, 1);
    private readonly CancellationTokenSource _stoppingSource = new();
    private readonly CancellationToken _stopping;
    private readonly object _gate = new();
    private AssistantDraft _stored;
    private string _text;
    private int _closed;

    internal AssistantView(AssistantLifecycle owner, AssistantWindowId window, AssistantDraft stored)
    {
        _owner = owner;
        Window = window;
        _stored = stored;
        _text = stored.Text;
        _stopping = _stoppingSource.Token;
    }

    public AssistantWindowId Window { get; }

    /// <summary>Cancelled when this view closes; subscriptions and view-bound calls observe it.</summary>
    public CancellationToken ViewStopping => _stopping;

    public AssistantDraftId DraftId
    {
        get
        {
            lock (_gate)
            {
                return _stored.Id;
            }
        }
    }

    /// <summary>The text currently in the editor, saved or not.</summary>
    public string Text
    {
        get
        {
            lock (_gate)
            {
                return _text;
            }
        }
    }

    /// <summary>The last durable revision of this view's draft (revision 0 when nothing is stored yet).</summary>
    public AssistantDraft StoredDraft
    {
        get
        {
            lock (_gate)
            {
                return _stored;
            }
        }
    }

    public bool HasUnsavedEdits
    {
        get
        {
            lock (_gate)
            {
                return !string.Equals(_text, _stored.Text, StringComparison.Ordinal);
            }
        }
    }

    /// <summary>Replaces the editor text in memory. It is durable only after <see cref="CheckpointAsync"/> succeeds.</summary>
    public Outcome<bool> Edit(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length > AssistantDraft.MaximumTextLength)
        {
            return Outcome.Failure<bool>(TypedFailure.Create("validation.invalid_request"));
        }

        lock (_gate)
        {
            if (Volatile.Read(ref _closed) != 0)
            {
                return Outcome.Failure<bool>(TypedFailure.Create("state.gone"));
            }

            _text = text;
        }

        return Outcome.Success(true);
    }

    /// <summary>Makes the current text durable. Failure keeps the text and the previous durable revision.</summary>
    public ValueTask<Outcome<AssistantDraft>> CheckpointAsync(CancellationToken cancellationToken = default)
        => Volatile.Read(ref _closed) != 0
            ? ValueTask.FromResult(Outcome.Failure<AssistantDraft>(TypedFailure.Create("state.gone")))
            : CheckpointCoreAsync(cancellationToken);

    /// <summary>Deletes the stored draft and starts a fresh empty one; an unconfirmed deletion changes nothing.</summary>
    public async ValueTask<Outcome<bool>> DiscardDraftAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _closed) != 0)
        {
            return Outcome.Failure<bool>(TypedFailure.Create("state.gone"));
        }

        if (!await TryEnterAsync(cancellationToken).ConfigureAwait(false))
        {
            return Outcome.Cancelled<bool>(EffectCertainty.DidNotHappen);
        }

        try
        {
            AssistantDraft stored = StoredDraft;
            if (stored.Revision > 0)
            {
                var removed = await _owner.CallStoreAsync(
                    token => _owner.DraftStore.DiscardAsync(stored.Id, stored.Revision, token), cancellationToken)
                    .ConfigureAwait(false);
                if (!removed.TryGetValue(out _))
                {
                    return removed;
                }
            }

            lock (_gate)
            {
                _stored = new AssistantDraft(AssistantDraftId.New(), Window, stored.Conversation, 0, string.Empty);
                _text = string.Empty;
            }

            return Outcome.Success(true);
        }
        finally
        {
            _saveGate.Release();
        }
    }

    /// <summary>Idempotent and non-throwing: saves unsaved text, then cancels view-bound work and detaches.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }

        CancelViewScope();
        _stoppingSource.Dispose();
        _owner.Detach(this);
        await CheckpointCoreAsync(CancellationToken.None).ConfigureAwait(false);
        if (HasUnsavedEdits)
        {
            _owner.Retain(this);
        }
    }

    internal async ValueTask<Outcome<AssistantDraft>> CheckpointCoreAsync(CancellationToken cancellationToken)
    {
        if (!await TryEnterAsync(cancellationToken).ConfigureAwait(false))
        {
            return Outcome.Cancelled<AssistantDraft>(EffectCertainty.DidNotHappen);
        }

        try
        {
            string text;
            AssistantDraft stored;
            lock (_gate)
            {
                text = _text;
                stored = _stored;
            }

            if (string.Equals(text, stored.Text, StringComparison.Ordinal))
            {
                return Outcome.Success(stored);
            }

            AssistantDraft next = stored.Successor(Window, text);
            var result = await _owner.CallStoreAsync(
                token => _owner.DraftStore.SaveAsync(next, stored.Revision, token), cancellationToken)
                .ConfigureAwait(false);
            if (!result.TryGetValue(out var saved))
            {
                return result;
            }

            if (saved is null || saved.Id != next.Id || saved.Revision != next.Revision ||
                !string.Equals(saved.Text, next.Text, StringComparison.Ordinal))
            {
                // A store that acknowledges something other than what was asked is not trusted as durable.
                return Outcome.Failure<AssistantDraft>(TypedFailure.Create("internal.unexpected"));
            }

            lock (_gate)
            {
                _stored = saved;
            }

            return Outcome.Success(saved);
        }
        finally
        {
            _saveGate.Release();
        }
    }

    private async ValueTask<bool> TryEnterAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _saveGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "A throwing view-scope callback must not stop the view from closing or the draft from being saved.")]
    private void CancelViewScope()
    {
        try
        {
            _stoppingSource.Cancel();
        }
        catch (Exception)
        {
            // Callback failures are the subscriber's; closing continues.
        }
    }
}

/// <summary>
/// The reusable product-host lifecycle for one application composition. It is the <see cref="IHostLifecycle"/>
/// supplied to <see cref="AssistantHostServices"/>, owns the one session, and separates three lifetimes: views
/// (windows) open and close independently, the session and services live for the application, and canonical data
/// is never touched here. Launching and saving never consult Cloud. Shutdown reports local work and unsaved
/// drafts as refusals, treats Cloud-only work as continuing, and an application crash leaves every durable draft
/// recoverable on the next launch. It holds no process-wide state, so two applications stay independent.
/// </summary>
public sealed class AssistantLifecycle : IHostLifecycle, IAsyncDisposable
{
    /// <summary>The most views one application composition keeps open at once.</summary>
    public const int MaximumOpenViews = 64;

    private const int NotLaunched = 0;
    private const int Launching = 1;
    private const int Launched = 2;
    private const int Disposed = 3;

    private static readonly TimeSpan DefaultOperationTimeout = TimeSpan.FromSeconds(10);

    private readonly IAssistantRemoteLink? _remote;
    private readonly TimeSpan _operationTimeout;
    private readonly object _gate = new();
    [SuppressMessage("Usage", "CA2213:Disposable fields should be disposed", Justification = "The gate never allocates a wait handle; the stopping source is cancelled on close and must stay readable by late callers.")]
    private readonly SemaphoreSlim _shutdownGate = new(1, 1);
    [SuppressMessage("Usage", "CA2213:Disposable fields should be disposed", Justification = "The stopping source is cancelled on close and its token stays readable by late callers.")]
    private readonly CancellationTokenSource _stopping = new();
    private readonly Dictionary<AssistantWindowId, AssistantView> _views = [];
    private readonly List<AssistantView> _retained = [];
    private readonly List<AssistantWorkHandle> _work = [];
    private readonly Dictionary<AssistantDraftId, AssistantDraft> _unclaimed = [];
    private readonly List<TypedFailure> _shutdownFailures = [];
    private int _state;
    private int _remoteState = (int)AssistantRemoteState.Unavailable;
    private int _resumed;

    public AssistantLifecycle(AssistantHostIdentity owner, IAssistantDraftStore draftStore,
        IAssistantRemoteLink? remote = null, TimeSpan? operationTimeout = null)
    {
        ArgumentNullException.ThrowIfNull(owner);
        ArgumentNullException.ThrowIfNull(draftStore);
        if (draftStore.Owner != owner)
        {
            throw new ArgumentException("The draft store belongs to a different application instance.", nameof(draftStore));
        }

        if (draftStore.Partition.Installation != owner.Installation)
        {
            throw new ArgumentException("The draft store partition belongs to a different product installation.", nameof(draftStore));
        }

        if (remote is not null && remote.Owner != owner)
        {
            throw new ArgumentException("The remote link belongs to a different application instance.", nameof(remote));
        }

        if (operationTimeout is { } timeout && (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(5)))
        {
            throw new ArgumentOutOfRangeException(nameof(operationTimeout), "A positive bounded timeout is required.");
        }

        Owner = owner;
        DraftStore = draftStore;
        _remote = remote;
        _operationTimeout = operationTimeout ?? DefaultOperationTimeout;
    }

    public AssistantHostIdentity Owner { get; }

    /// <summary>Cancelled once shutdown is accepted or the lifecycle is disposed.</summary>
    public CancellationToken Stopping => _stopping.Token;

    /// <summary>The one session of this composition, available after a successful launch.</summary>
    public IAssistantSession? Session { get; private set; }

    /// <summary>The last observed Cloud state; updated at launch and on resume. Never consulted to save.</summary>
    public AssistantRemoteState RemoteState => (AssistantRemoteState)Volatile.Read(ref _remoteState);

    /// <summary>Draft revisions that could not be made durable when the application closed.</summary>
    public IReadOnlyList<AssistantDraftId> UnsavedDrafts
    {
        get
        {
            lock (_gate)
            {
                return [.. _views.Values.Concat(_retained).Where(view => view.HasUnsavedEdits).Select(view => view.DraftId)];
            }
        }
    }

    /// <summary>Failures met while closing (a session that did not dispose cleanly, for example).</summary>
    public IReadOnlyList<TypedFailure> ShutdownFailures
    {
        get
        {
            lock (_gate)
            {
                return [.. _shutdownFailures];
            }
        }
    }

    internal IAssistantDraftStore DraftStore { get; }

    /// <summary>
    /// Creates the session, recovers durable drafts and records Cloud reachability. A draft recovery failure
    /// does not fail the launch, and an unreachable or throwing Cloud link never does either.
    /// </summary>
    public async ValueTask<Outcome<AssistantLaunchReport>> LaunchAsync(AssistantHostOptions options,
        AssistantHostServices services, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(services);
        if (options.Identity != Owner || services.Owner != Owner)
        {
            throw new ArgumentException("The options and services must belong to this lifecycle's application instance.");
        }

        if (!ReferenceEquals(services.Lifecycle, this))
        {
            throw new ArgumentException("The services must use this lifecycle as their lifecycle port.", nameof(services));
        }

        if (DraftStore.Partition != services.Store.Partition)
        {
            throw new ArgumentException("The draft store must serve the services' profile partition.", nameof(services));
        }

        int previous = Interlocked.CompareExchange(ref _state, Launching, NotLaunched);
        if (previous != NotLaunched)
        {
            throw new InvalidOperationException(previous == Disposed
                ? "A disposed lifecycle cannot launch."
                : "One application composition launches once.");
        }

        try
        {
            var recovery = await CallStoreAsync(DraftStore.RecoverAsync, cancellationToken).ConfigureAwait(false);
            if (recovery.Kind == OutcomeKind.Cancelled && cancellationToken.IsCancellationRequested)
            {
                Volatile.Write(ref _state, NotLaunched);
                return Outcome.Cancelled<AssistantLaunchReport>(EffectCertainty.DidNotHappen);
            }

            ImmutableArray<AssistantDraft> recovered = [];
            TypedFailure? recoveryFailure = null;
            if (recovery.TryGetValue(out var drafts) && drafts is not null)
            {
                recovered = [.. drafts.Where(draft => draft is not null && draft.Revision > 0)
                    .GroupBy(draft => draft.Id).Select(group => group.MaxBy(draft => draft.Revision)!)];
            }
            else if (recovery.TryGetFailure(out var failure))
            {
                recoveryFailure = failure;
            }
            else
            {
                recoveryFailure = TypedFailure.Create("internal.unexpected");
            }

            Session = AssistantHost.Create(options, services);
            lock (_gate)
            {
                foreach (var draft in recovered)
                {
                    _unclaimed[draft.Id] = draft;
                }
            }

            RefreshRemote();
            Volatile.Write(ref _state, Launched);
            return Outcome.Success(new AssistantLaunchReport(recovered, RemoteState, recoveryFailure));
        }
        catch
        {
            Session = null;
            Volatile.Write(ref _state, NotLaunched);
            throw;
        }
    }

    /// <summary>
    /// Opens one window's view with its own draft, or resumes a recovered draft. A window that is already open,
    /// an unknown or already claimed draft, and a lifecycle that is not running are refused.
    /// </summary>
    public Outcome<AssistantView> OpenView(AssistantWindowId window, AssistantDraftId? resume = null,
        AssistantConversationId? conversation = null)
    {
        if (window.Value == Guid.Empty)
        {
            throw new ArgumentException("A window identity is required.", nameof(window));
        }

        int state = Volatile.Read(ref _state);
        if (state == Disposed || _stopping.IsCancellationRequested)
        {
            return Outcome.Failure<AssistantView>(TypedFailure.Create("state.gone"));
        }

        if (state != Launched)
        {
            return Outcome.Failure<AssistantView>(TypedFailure.Create("state.invalid_transition"));
        }

        lock (_gate)
        {
            if (_views.ContainsKey(window))
            {
                return Outcome.Failure<AssistantView>(TypedFailure.Create("conflict.duplicate_identifier"));
            }

            if (_views.Count >= MaximumOpenViews)
            {
                return Outcome.Failure<AssistantView>(TypedFailure.Create("capacity.busy"));
            }

            AssistantDraft stored;
            if (resume is { } draftId)
            {
                if (!_unclaimed.Remove(draftId, out stored!))
                {
                    return Outcome.Failure<AssistantView>(TypedFailure.Create("state.not_found"));
                }
            }
            else
            {
                stored = new AssistantDraft(AssistantDraftId.New(), window, conversation, 0, string.Empty);
            }

            var view = new AssistantView(this, window, stored);
            _views.Add(window, view);
            return Outcome.Success(view);
        }
    }

    /// <summary>Registers local work. <paramref name="checkpoint"/> returns true when its state is durable.</summary>
    public Outcome<AssistantWorkHandle> BeginLocalWork(string workKey,
        Func<CancellationToken, ValueTask<bool>>? checkpoint = null)
        => Begin(AssistantWorkKind.Local, workKey, checkpoint);

    /// <summary>Registers Cloud or remote work. It is reported but never blocks quitting and is never cancelled here.</summary>
    public Outcome<AssistantWorkHandle> BeginRemoteWork(string workKey)
        => Begin(AssistantWorkKind.Remote, workKey, null);

    public HostBusyState GetBusyState()
    {
        int local;
        int remote;
        lock (_gate)
        {
            local = _work.Count(work => work.Kind == AssistantWorkKind.Local) + DirtyViews().Length;
            remote = _work.Count(work => work.Kind == AssistantWorkKind.Remote);
        }

        if (local > 0)
        {
            return new HostBusyState(HostBusyKind.LocalWork, local, "busy.local_work");
        }

        return remote > 0
            ? new HostBusyState(HostBusyKind.AwaitingRemote, 0, "busy.awaiting_remote")
            : new HostBusyState(HostBusyKind.Idle, 0);
    }

    /// <summary>
    /// Saves every unsaved draft and asks each piece of local work to checkpoint. Anything that cannot be made
    /// durable is a stated refusal; nothing is discarded and nothing is forced. Remote work does not block.
    /// </summary>
    public async ValueTask<Outcome<AssistantShutdownSummary>> PrepareShutdownAsync(
        CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return Outcome.Cancelled<AssistantShutdownSummary>(EffectCertainty.DidNotHappen);
        }

        try
        {
            await _shutdownGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Outcome.Cancelled<AssistantShutdownSummary>(EffectCertainty.DidNotHappen);
        }

        try
        {
            var (unresolvedWork, unsavedDrafts) = await FlushAsync(cancellationToken).ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested)
            {
                return Outcome.Cancelled<AssistantShutdownSummary>(EffectCertainty.Unknown);
            }

            List<string> reasons = [];
            if (unresolvedWork > 0)
            {
                reasons.Add("shutdown.local_work");
            }

            if (unsavedDrafts > 0)
            {
                reasons.Add("shutdown.unsaved_draft");
            }

            int active = unresolvedWork + unsavedDrafts;
            return Outcome.Success(new AssistantShutdownSummary(active == 0, active, reasons));
        }
        finally
        {
            _shutdownGate.Release();
        }
    }

    /// <summary>A profile switch is allowed only when no draft or local work of the current profile would be lost.</summary>
    public async ValueTask<Outcome<AssistantProfileId>> OnProfileChangingAsync(AssistantProfileId nextProfile,
        CancellationToken cancellationToken = default)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return Outcome.Cancelled<AssistantProfileId>(EffectCertainty.DidNotHappen);
        }

        var summary = await PrepareShutdownAsync(cancellationToken).ConfigureAwait(false);
        if (!summary.TryGetValue(out var result))
        {
            return summary.TryGetFailure(out var failure)
                ? Outcome.Failure<AssistantProfileId>(failure)
                : Outcome.Cancelled<AssistantProfileId>(summary.CancellationEffect);
        }

        return result.CanClose
            ? Outcome.Success(nextProfile)
            : Outcome.Failure<AssistantProfileId>(TypedFailure.Create("conflict.local_changes_pending"));
    }

    /// <summary>The host woke from sleep: Cloud reachability is observed again, nothing else changes.</summary>
    public void OnResumed()
    {
        Interlocked.Increment(ref _resumed);
        RefreshRemote();
    }

    /// <summary>The number of times the host reported a resume.</summary>
    public int ResumeCount => Volatile.Read(ref _resumed);

    /// <summary>
    /// Accepts a stop only when shutdown would lose nothing: true means stopping was signalled, false means the
    /// stated refusals stand and the application keeps running.
    /// </summary>
    public async ValueTask<Outcome<bool>> RequestStopAsync(CancellationToken cancellationToken)
    {
        var summary = await PrepareShutdownAsync(cancellationToken).ConfigureAwait(false);
        if (!summary.TryGetValue(out var result))
        {
            return summary.TryGetFailure(out var failure)
                ? Outcome.Failure<bool>(failure)
                : Outcome.Cancelled<bool>(summary.CancellationEffect);
        }

        if (!result.CanClose)
        {
            return Outcome.Success(false);
        }

        Signal();
        return Outcome.Success(true);
    }

    /// <summary>
    /// Closes every view independently (each saves its draft), signals stopping, then disposes the session once.
    /// It never throws; what could not be saved or disposed is reported through the lifecycle's properties.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        int previous = Interlocked.Exchange(ref _state, Disposed);
        if (previous == Disposed)
        {
            return;
        }

        AssistantView[] views;
        lock (_gate)
        {
            views = [.. _views.Values];
        }

        foreach (var view in views)
        {
            await view.DisposeAsync().ConfigureAwait(false);
        }

        await FlushRetainedAsync().ConfigureAwait(false);
        Signal();
        var session = Session;
        if (session is not null)
        {
            await DisposeSessionAsync(session).ConfigureAwait(false);
        }
    }

    internal async ValueTask<Outcome<T>> CallStoreAsync<T>(Func<CancellationToken, ValueTask<Outcome<T>>> call,
        CancellationToken cancellationToken)
    {
        using var scope = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        scope.CancelAfter(_operationTimeout);
        try
        {
            var result = await call(scope.Token).ConfigureAwait(false);
            return result ?? Outcome.Failure<T>(TypedFailure.Create("internal.unexpected"));
        }
        catch (OperationCanceledException)
        {
            // A save may have completed before the cancellation was observed, so the effect is not known.
            return cancellationToken.IsCancellationRequested
                ? Outcome.Cancelled<T>(EffectCertainty.Unknown)
                : Outcome.Failure<T>(TypedFailure.Create("dependency.timeout"));
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return Outcome.Failure<T>(TypedFailure.Create("internal.unexpected"));
        }
    }

    internal void Detach(AssistantView view)
    {
        lock (_gate)
        {
            if (_views.TryGetValue(view.Window, out var current) && ReferenceEquals(current, view))
            {
                _views.Remove(view.Window);
            }
        }
    }

    internal void Retain(AssistantView view)
    {
        lock (_gate)
        {
            if (!_retained.Contains(view))
            {
                _retained.Add(view);
            }
        }
    }

    internal void EndWork(AssistantWorkHandle handle)
    {
        lock (_gate)
        {
            _work.Remove(handle);
        }
    }

    private Outcome<AssistantWorkHandle> Begin(AssistantWorkKind kind, string workKey,
        Func<CancellationToken, ValueTask<bool>>? checkpoint)
    {
        string key = HostKeys.Require(workKey, nameof(workKey));
        int state = Volatile.Read(ref _state);
        if (state == Disposed || _stopping.IsCancellationRequested)
        {
            return Outcome.Failure<AssistantWorkHandle>(TypedFailure.Create("state.gone"));
        }

        var handle = new AssistantWorkHandle(this, kind, key, checkpoint);
        lock (_gate)
        {
            _work.Add(handle);
        }

        return Outcome.Success(handle);
    }

    private AssistantView[] DirtyViews()
    {
        // Callers hold _gate.
        return [.. _views.Values.Concat(_retained).Distinct().Where(view => view.HasUnsavedEdits)];
    }

    private async ValueTask<(int UnresolvedWork, int UnsavedDrafts)> FlushAsync(CancellationToken cancellationToken)
    {
        AssistantView[] dirty;
        AssistantWorkHandle[] work;
        lock (_gate)
        {
            _retained.RemoveAll(view => !view.HasUnsavedEdits);
            dirty = DirtyViews();
            work = [.. _work.Where(handle => handle.Kind == AssistantWorkKind.Local)];
        }

        foreach (var view in dirty)
        {
            await view.CheckpointCoreAsync(cancellationToken).ConfigureAwait(false);
        }

        int unresolved = 0;
        foreach (var handle in work)
        {
            if (handle.Checkpoint is null || !await RunCheckpointAsync(handle.Checkpoint, cancellationToken).ConfigureAwait(false))
            {
                unresolved++;
            }
        }

        lock (_gate)
        {
            return (unresolved, DirtyViews().Length);
        }
    }

    private async ValueTask FlushRetainedAsync()
    {
        AssistantView[] retained;
        lock (_gate)
        {
            retained = [.. _retained];
        }

        foreach (var view in retained)
        {
            await view.CheckpointCoreAsync(CancellationToken.None).ConfigureAwait(false);
        }

        lock (_gate)
        {
            _retained.RemoveAll(view => !view.HasUnsavedEdits);
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "A throwing or hanging checkpoint is an unresolved piece of local work, never a successful save.")]
    private async ValueTask<bool> RunCheckpointAsync(Func<CancellationToken, ValueTask<bool>> checkpoint,
        CancellationToken cancellationToken)
    {
        using var scope = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        scope.CancelAfter(_operationTimeout);
        try
        {
            return await checkpoint(scope.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return false;
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "A broken Cloud link must not stop launch, save or resume; it is reported as unavailable.")]
    private void RefreshRemote()
    {
        AssistantRemoteState state = AssistantRemoteState.Unavailable;
        if (_remote is not null)
        {
            try
            {
                var observed = _remote.State;
                if (Enum.IsDefined(observed) && observed != AssistantRemoteState.None)
                {
                    state = observed;
                }
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                state = AssistantRemoteState.Unavailable;
            }
        }

        Volatile.Write(ref _remoteState, (int)state);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "A session that fails to dispose is recorded; the application is already closing and the other lifetimes have been released.")]
    private async ValueTask DisposeSessionAsync(IAssistantSession session)
    {
        try
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            lock (_gate)
            {
                _shutdownFailures.Add(TypedFailure.Create("internal.unexpected"));
            }
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "A throwing stopping callback must not prevent the session from being released.")]
    private void Signal()
    {
        try
        {
            _stopping.Cancel();
        }
        catch (Exception)
        {
            // Callback failures belong to the subscriber.
        }
    }
}
