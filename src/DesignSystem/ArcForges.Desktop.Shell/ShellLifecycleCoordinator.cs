// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Resources;

namespace ArcForges.Desktop.Shell;

public sealed class ShellActivationRequest
{
    public ShellActivationRequest(Guid requestId, ShellActivationKind kind, string? target = null)
    {
        if (requestId == Guid.Empty)
        {
            throw new ArgumentException("An activation request requires a stable non-empty id.", nameof(requestId));
        }

        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        string? safeTarget = target?.Trim();
        if (safeTarget is { Length: > 512 } || safeTarget?.Any(char.IsControl) == true)
        {
            throw new ArgumentException("An activation target must be bounded and contain no control characters.", nameof(target));
        }

        RequestId = requestId;
        Kind = kind;
        Target = string.IsNullOrEmpty(safeTarget) ? null : safeTarget;
    }

    public Guid RequestId { get; }

    public ShellActivationKind Kind { get; }

    public string? Target { get; }

    internal bool HasSamePayload(ShellActivationRequest other) =>
        Kind == other.Kind && string.Equals(Target, other.Target, StringComparison.Ordinal);
}

public enum ShellActivationKind
{
    Activate,
    OpenTarget,
}

public enum ShellActivationRouteDisposition
{
    Forwarded,
    AlreadyForwarded,
    IdentityConflict,
    CapacityReached,
}

public sealed class ShellShutdownState
{
    public ShellShutdownState(long generation, int activeWorkCount, int unsavedItemCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(generation);
        ArgumentOutOfRangeException.ThrowIfNegative(activeWorkCount);
        ArgumentOutOfRangeException.ThrowIfNegative(unsavedItemCount);

        Generation = generation;
        ActiveWorkCount = activeWorkCount;
        UnsavedItemCount = unsavedItemCount;
    }

    /// <summary>
    /// Gets the host-owned work-state revision. The host must advance it whenever the active or unsaved work set changes,
    /// even when the corresponding item counts stay the same.
    /// </summary>
    public long Generation { get; }

    public int ActiveWorkCount { get; }

    public int UnsavedItemCount { get; }
}

public enum ShellShutdownDecision
{
    KeepWorking,
    WaitForSafePointAndQuit,
    SaveThenQuit,
}

public enum ShellShutdownDisposition
{
    KeptOpen,
    ReconfirmationRequired,
    Stopped,
}

public sealed class ShellShutdownPrompt
{
    internal ShellShutdownPrompt(long generation, string consequences, IReadOnlyList<ShellShutdownDecision> decisions)
    {
        Generation = generation;
        Consequences = consequences;
        Decisions = decisions;
    }

    public long Generation { get; }

    public string Consequences { get; }

    public IReadOnlyList<ShellShutdownDecision> Decisions { get; }
}

public sealed class ShellShutdownExecutionResult
{
    internal ShellShutdownExecutionResult(
        ShellShutdownDisposition disposition,
        ShellShutdownPrompt? reconfirmationPrompt = null)
    {
        Disposition = disposition;
        ReconfirmationPrompt = reconfirmationPrompt;
    }

    public ShellShutdownDisposition Disposition { get; }

    public ShellShutdownPrompt? ReconfirmationPrompt { get; }
}

public sealed class ShellStartupMeasurement
{
    internal ShellStartupMeasurement(TimeSpan workspaceReadyAfter, TimeSpan backgroundStartedAfter, TimeSpan budget)
    {
        WorkspaceReadyAfter = workspaceReadyAfter;
        BackgroundStartedAfter = backgroundStartedAfter;
        Budget = budget;
    }

    public TimeSpan WorkspaceReadyAfter { get; }

    public TimeSpan BackgroundStartedAfter { get; }

    public TimeSpan Budget { get; }

    public bool BackgroundStartedAfterWorkspaceReady => BackgroundStartedAfter >= WorkspaceReadyAfter;

    public bool WithinConfiguredBudget => WorkspaceReadyAfter <= Budget;
}

/// <summary>Host-owned operations invoked by the framework-neutral lifecycle coordinator.</summary>
public sealed class ShellLifecycleOperations
{
    public ShellLifecycleOperations(
        Func<CancellationToken, ValueTask<bool>> makeWorkspaceUsableAsync,
        Func<CancellationToken, ValueTask> startBackgroundWorkAsync,
        Func<ShellActivationRequest, CancellationToken, ValueTask> forwardActivationToPrimaryAsync,
        Func<CancellationToken, ValueTask<ShellShutdownState>> captureShutdownStateAsync,
        Func<CancellationToken, ValueTask> stopAcceptingWritesAsync,
        Func<CancellationToken, ValueTask> resumeAcceptingWritesAsync,
        Func<CancellationToken, ValueTask> reachSafePointsAsync,
        Func<ShellShutdownState, CancellationToken, ValueTask> saveUnsavedWorkAsync,
        Func<CancellationToken, ValueTask> flushWritesAsync,
        Func<CancellationToken, ValueTask> disconnectServicesAsync,
        Func<CancellationToken, ValueTask> drainWorkAsync,
        Func<CancellationToken, ValueTask> stopNativeRuntimeAsync)
    {
        MakeWorkspaceUsableAsync = makeWorkspaceUsableAsync ?? throw new ArgumentNullException(nameof(makeWorkspaceUsableAsync));
        StartBackgroundWorkAsync = startBackgroundWorkAsync ?? throw new ArgumentNullException(nameof(startBackgroundWorkAsync));
        ForwardActivationToPrimaryAsync = forwardActivationToPrimaryAsync ?? throw new ArgumentNullException(nameof(forwardActivationToPrimaryAsync));
        CaptureShutdownStateAsync = captureShutdownStateAsync ?? throw new ArgumentNullException(nameof(captureShutdownStateAsync));
        StopAcceptingWritesAsync = stopAcceptingWritesAsync ?? throw new ArgumentNullException(nameof(stopAcceptingWritesAsync));
        ResumeAcceptingWritesAsync = resumeAcceptingWritesAsync ?? throw new ArgumentNullException(nameof(resumeAcceptingWritesAsync));
        ReachSafePointsAsync = reachSafePointsAsync ?? throw new ArgumentNullException(nameof(reachSafePointsAsync));
        SaveUnsavedWorkAsync = saveUnsavedWorkAsync ?? throw new ArgumentNullException(nameof(saveUnsavedWorkAsync));
        FlushWritesAsync = flushWritesAsync ?? throw new ArgumentNullException(nameof(flushWritesAsync));
        DisconnectServicesAsync = disconnectServicesAsync ?? throw new ArgumentNullException(nameof(disconnectServicesAsync));
        DrainWorkAsync = drainWorkAsync ?? throw new ArgumentNullException(nameof(drainWorkAsync));
        StopNativeRuntimeAsync = stopNativeRuntimeAsync ?? throw new ArgumentNullException(nameof(stopNativeRuntimeAsync));
    }

    public Func<CancellationToken, ValueTask<bool>> MakeWorkspaceUsableAsync { get; }

    public Func<CancellationToken, ValueTask> StartBackgroundWorkAsync { get; }

    public Func<ShellActivationRequest, CancellationToken, ValueTask> ForwardActivationToPrimaryAsync { get; }

    public Func<CancellationToken, ValueTask<ShellShutdownState>> CaptureShutdownStateAsync { get; }

    public Func<CancellationToken, ValueTask> StopAcceptingWritesAsync { get; }

    public Func<CancellationToken, ValueTask> ResumeAcceptingWritesAsync { get; }

    public Func<CancellationToken, ValueTask> ReachSafePointsAsync { get; }

    public Func<ShellShutdownState, CancellationToken, ValueTask> SaveUnsavedWorkAsync { get; }

    public Func<CancellationToken, ValueTask> FlushWritesAsync { get; }

    public Func<CancellationToken, ValueTask> DisconnectServicesAsync { get; }

    public Func<CancellationToken, ValueTask> DrainWorkAsync { get; }

    public Func<CancellationToken, ValueTask> StopNativeRuntimeAsync { get; }
}

/// <summary>
/// Coordinates host-provided startup, activation routing, and safe shutdown without owning product or OS-specific services.
/// </summary>
public sealed class ShellLifecycleCoordinator
{
    private const int MaximumRememberedActivations = 4096;

    private static readonly ResourceManager LifecycleStrings = new(
        "ArcForges.Desktop.Shell.Errors.ErrorPresentationStrings",
        typeof(ShellLifecycleCoordinator).Assembly);

    private readonly ShellLifecycleOperations _operations;
    private readonly TimeSpan _startupBudget;
    private readonly object _lifecycleQueueGate = new();
    private readonly object _activationGate = new();
    private readonly Dictionary<Guid, RoutedActivation> _activations = [];
    private readonly Queue<Guid> _completedActivations = new();
    private Task _lifecycleQueueTail = Task.CompletedTask;
    private ShellStartupMeasurement? _startupMeasurement;
    private bool _stopped;
    private bool _faulted;

    public ShellLifecycleCoordinator(ShellLifecycleOperations operations, TimeSpan startupBudget)
    {
        _operations = operations ?? throw new ArgumentNullException(nameof(operations));
        if (startupBudget <= TimeSpan.Zero || startupBudget > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentOutOfRangeException(nameof(startupBudget));
        }

        _startupBudget = startupBudget;
    }

    /// <summary>Establishes the usable local workspace before starting any background work and returns task-local timing.</summary>
    public async ValueTask<ShellStartupMeasurement> RunStartupAsync(CancellationToken cancellationToken)
    {
        using LifecycleLease lifecycleLease = await EnterLifecycleAsync(cancellationToken).ConfigureAwait(false);
        if (_stopped || _faulted)
        {
            throw new InvalidOperationException("Startup cannot run after shutdown completed or the lifecycle has faulted.");
        }

        if (_startupMeasurement is not null)
        {
            return _startupMeasurement;
        }

        var stopwatch = Stopwatch.StartNew();
        bool workspaceUsable = await _operations.MakeWorkspaceUsableAsync(cancellationToken).ConfigureAwait(false);
        if (!workspaceUsable)
        {
            throw new InvalidOperationException("Background work cannot start before the local workspace is usable.");
        }

        TimeSpan workspaceReadyAfter = stopwatch.Elapsed;
        try
        {
            await _operations.StartBackgroundWorkAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // The host operation may have partially started work. Do not replay it or permit shutdown to
            // race an unknown background state; the owner must replace this coordinator after recovery.
            _faulted = true;
            throw;
        }

        var measurement = new ShellStartupMeasurement(workspaceReadyAfter, stopwatch.Elapsed, _startupBudget);
        _startupMeasurement = measurement;
        return measurement;
    }

    /// <summary>
    /// Forwards one immutable secondary-launch request to the host's primary-instance transport at most once.
    /// The transport must preserve RequestId as its idempotency key across process boundaries. Duplicate suppression
    /// covers the most recent 4096 completed requests and every in-flight request.
    /// </summary>
    public async ValueTask<ShellActivationRouteDisposition> RouteActivationAsync(
        ShellActivationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        Task<bool> completion;
        TaskCompletionSource<bool>? owner = null;
        lock (_activationGate)
        {
            if (_activations.TryGetValue(request.RequestId, out RoutedActivation? existing))
            {
                if (!request.HasSamePayload(existing.Request))
                {
                    return ShellActivationRouteDisposition.IdentityConflict;
                }

                completion = existing.Completion;
            }
            else
            {
                // Completed requests are only remembered for duplicate suppression and are evicted oldest-first,
                // so a long-lived primary keeps accepting launches. Only in-flight forwards count toward capacity.
                if (_activations.Count - _completedActivations.Count >= MaximumRememberedActivations)
                {
                    return ShellActivationRouteDisposition.CapacityReached;
                }

                owner = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                completion = owner.Task;
                _activations.Add(request.RequestId, new RoutedActivation(request, completion));
            }
        }

        if (owner is not null)
        {
            try
            {
                await _operations.ForwardActivationToPrimaryAsync(request, cancellationToken).ConfigureAwait(false);
                lock (_activationGate)
                {
                    _completedActivations.Enqueue(request.RequestId);
                    while (_completedActivations.Count > MaximumRememberedActivations)
                    {
                        _activations.Remove(_completedActivations.Dequeue());
                    }
                }

                owner.TrySetResult(true);
                return ShellActivationRouteDisposition.Forwarded;
            }
            catch (Exception exception)
            {
                lock (_activationGate)
                {
                    if (_activations.TryGetValue(request.RequestId, out RoutedActivation? current) &&
                        ReferenceEquals(current.Completion, completion))
                    {
                        _activations.Remove(request.RequestId);
                    }
                }

                owner.TrySetException(exception);
                await completion.ConfigureAwait(false);
                throw;
            }
        }

        await completion.WaitAsync(cancellationToken).ConfigureAwait(false);
        return ShellActivationRouteDisposition.AlreadyForwarded;
    }

    /// <summary>Creates a consequence summary and the decisions allowed for the supplied work snapshot.</summary>
    public static ShellShutdownPrompt CreateShutdownPrompt(ShellShutdownState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        // Each combination is one complete localisable sentence set; nothing is assembled from fragments.
        string consequences = (state.ActiveWorkCount > 0, state.UnsavedItemCount > 0) switch
        {
            (true, true) => Format("lifecycle.shutdown.consequence.active_and_unsaved", state.ActiveWorkCount, state.UnsavedItemCount),
            (true, false) => Format("lifecycle.shutdown.consequence.active", state.ActiveWorkCount),
            (false, true) => Format("lifecycle.shutdown.consequence.unsaved", state.UnsavedItemCount),
            _ => Format("lifecycle.shutdown.consequence.none"),
        };

        ShellShutdownDecision quitDecision = state.UnsavedItemCount > 0
            ? ShellShutdownDecision.SaveThenQuit
            : ShellShutdownDecision.WaitForSafePointAndQuit;
        return new ShellShutdownPrompt(
            state.Generation,
            consequences,
            Array.AsReadOnly([ShellShutdownDecision.KeepWorking, quitDecision]));
    }

    /// <summary>Revalidates the prompt snapshot, then stops writes, reaches safe points, saves, flushes, disconnects and drains.</summary>
    public async ValueTask<ShellShutdownExecutionResult> ExecuteShutdownAsync(
        ShellShutdownState promptedState,
        ShellShutdownDecision decision,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(promptedState);
        if (!Enum.IsDefined(decision))
        {
            throw new ArgumentOutOfRangeException(nameof(decision));
        }

        using LifecycleLease lifecycleLease = await EnterLifecycleAsync(cancellationToken).ConfigureAwait(false);
        if (_stopped)
        {
            return new ShellShutdownExecutionResult(ShellShutdownDisposition.Stopped);
        }

        if (_faulted)
        {
            throw new InvalidOperationException("The lifecycle cannot shut down again after an earlier operation faulted.");
        }

        ShellShutdownState current = await _operations.CaptureShutdownStateAsync(cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidOperationException("The shutdown state provider returned no state.");
        if (!SameState(promptedState, current))
        {
            return Reconfirm(current);
        }

        if (!CreateShutdownPrompt(current).Decisions.Contains(decision))
        {
            return Reconfirm(current);
        }

        if (decision == ShellShutdownDecision.KeepWorking)
        {
            return new ShellShutdownExecutionResult(ShellShutdownDisposition.KeptOpen);
        }

        bool writesStopped = false;
        bool disconnectStarted = false;
        try
        {
            writesStopped = true;
            await _operations.StopAcceptingWritesAsync(cancellationToken).ConfigureAwait(false);
            await _operations.ReachSafePointsAsync(cancellationToken).ConfigureAwait(false);

            ShellShutdownState settled = await _operations.CaptureShutdownStateAsync(cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException("The shutdown state provider returned no state.");
            if (settled.ActiveWorkCount > 0 ||
                (settled.UnsavedItemCount > 0 && decision != ShellShutdownDecision.SaveThenQuit))
            {
                writesStopped = false;
                try
                {
                    await _operations.ResumeAcceptingWritesAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                    _faulted = true;
                    throw;
                }

                return Reconfirm(settled);
            }

            if (settled.UnsavedItemCount > 0)
            {
                await _operations.SaveUnsavedWorkAsync(settled, cancellationToken).ConfigureAwait(false);
                settled = await _operations.CaptureShutdownStateAsync(cancellationToken).ConfigureAwait(false)
                    ?? throw new InvalidOperationException("The shutdown state provider returned no state.");
                if (settled.ActiveWorkCount > 0 || settled.UnsavedItemCount > 0)
                {
                    writesStopped = false;
                    try
                    {
                        await _operations.ResumeAcceptingWritesAsync(CancellationToken.None).ConfigureAwait(false);
                    }
                    catch
                    {
                        _faulted = true;
                        throw;
                    }

                    return Reconfirm(settled);
                }
            }

            await _operations.FlushWritesAsync(cancellationToken).ConfigureAwait(false);
            disconnectStarted = true;
            await _operations.DisconnectServicesAsync(cancellationToken).ConfigureAwait(false);
            await _operations.DrainWorkAsync(cancellationToken).ConfigureAwait(false);
            await _operations.StopNativeRuntimeAsync(cancellationToken).ConfigureAwait(false);
            writesStopped = false;
            _stopped = true;
            return new ShellShutdownExecutionResult(ShellShutdownDisposition.Stopped);
        }
        catch (Exception exception)
        {
            if (writesStopped && !disconnectStarted)
            {
                writesStopped = false;
                try
                {
                    await _operations.ResumeAcceptingWritesAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception resumeFailure)
                {
                    _faulted = true;
                    throw new AggregateException("Shutdown failed and write acceptance could not be restored.", exception, resumeFailure);
                }
            }
            else if (disconnectStarted)
            {
                // Services are no longer available, so neither startup nor another shutdown attempt can
                // safely replay the partially completed teardown.
                _faulted = true;
            }

            throw;
        }
    }

    private async ValueTask<LifecycleLease> EnterLifecycleAsync(CancellationToken cancellationToken)
    {
        Task previous;
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_lifecycleQueueGate)
        {
            previous = _lifecycleQueueTail;
            _lifecycleQueueTail = release.Task;
        }

        try
        {
            await previous.WaitAsync(cancellationToken).ConfigureAwait(false);
            return new LifecycleLease(release);
        }
        catch
        {
            _ = ReleaseAfterAsync(previous, release);
            throw;
        }
    }

    private static string Format(string key, params object[] arguments)
    {
        string template = LifecycleStrings.GetString(key, CultureInfo.CurrentUICulture)
            ?? throw new InvalidOperationException("The shutdown prompt resources are unavailable.");
        return string.Format(CultureInfo.CurrentCulture, template, arguments);
    }

    private static async Task ReleaseAfterAsync(Task previous, TaskCompletionSource release)
    {
        await previous.ConfigureAwait(false);
        release.TrySetResult();
    }

    private static bool SameState(ShellShutdownState left, ShellShutdownState right) =>
        left.Generation == right.Generation &&
        left.ActiveWorkCount == right.ActiveWorkCount &&
        left.UnsavedItemCount == right.UnsavedItemCount;

    private static ShellShutdownExecutionResult Reconfirm(ShellShutdownState state) =>
        new(ShellShutdownDisposition.ReconfirmationRequired, CreateShutdownPrompt(state));

    private sealed class LifecycleLease(TaskCompletionSource release) : IDisposable
    {
        private TaskCompletionSource? _release = release;

        public void Dispose() => Interlocked.Exchange(ref _release, null)?.TrySetResult();
    }

    private sealed record RoutedActivation(ShellActivationRequest Request, Task<bool> Completion);
}
