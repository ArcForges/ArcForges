// SPDX-License-Identifier: AGPL-3.0-only
#pragma warning disable CA2007 // Test code has no synchronization context to preserve.
#pragma warning disable xUnit1051 // These tests deliberately exercise the default (no token) and explicit-cancellation paths.
#pragma warning disable CA2000 // Test doubles here own no unmanaged resources.
#pragma warning disable CA1859 // Tests deliberately use the port interfaces to exercise their contracts.
using ArcForges.Assistant.Abstractions;
using ArcForges.Foundation.Errors;
using A = Xunit.Assert;

namespace AssistantAbstractionsTests;

/// <summary>
/// Regression tests for the review probes: non-cooperative hangs, a view that is still saving while shutdown looks,
/// disposal racing launch, and later use of the lifecycle after disposal.
/// </summary>
public sealed class LifecycleHardeningTests : IDisposable
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(20);
    private readonly ScratchDirectory _scratch = new();

    public void Dispose() => _scratch.Dispose();

    private string Root => _scratch.Path;

    private static T Value<T>(Outcome<T> outcome) => LifecycleTests.Value(outcome);

    private async Task<LifecycleApp> LaunchedAsync(TimeSpan? timeout = null)
    {
        var app = new LifecycleApp(Root, timeout: timeout);
        await app.LaunchAsync();
        return app;
    }

    [Xunit.Fact]
    public async Task AStoreThatIgnoresItsTokenCannotHangACheckpointOrDisposal()
    {
        var app = await LaunchedAsync(TimeSpan.FromMilliseconds(200));
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("stuck"));
        app.Store.AfterTemporaryWritten = _ => new TaskCompletionSource().Task;

        A.Equal("dependency.timeout", LifecycleTests.Code(await view.CheckpointAsync().AsTask().WaitAsync(Bound)));
        await app.Lifecycle.DisposeAsync().AsTask().WaitAsync(Bound);

        A.Equal(1, app.Session!.DisposeCalls);
        A.Equal([view.DraftId], app.Lifecycle.UnsavedDrafts);
    }

    [Xunit.Fact]
    public async Task ACheckpointThatIgnoresItsTokenIsARefusalAndLaterCallsAreNotBlocked()
    {
        var app = await LaunchedAsync(TimeSpan.FromMilliseconds(200));
        using var stuck = Value(app.Lifecycle.BeginLocalWork("stuck", _ => new ValueTask<bool>(new TaskCompletionSource<bool>().Task)));

        var first = Value(await app.Lifecycle.PrepareShutdownAsync().AsTask().WaitAsync(Bound));
        var second = Value(await app.Lifecycle.PrepareShutdownAsync().AsTask().WaitAsync(Bound));

        A.False(first.CanClose);
        A.False(second.CanClose);
        A.False(Value(await app.Lifecycle.RequestStopAsync(CancellationToken.None).AsTask().WaitAsync(Bound)));
    }

    [Xunit.Fact]
    public async Task ARecoveryThatIgnoresItsTokenCannotHangLaunch()
    {
        var app = new LifecycleApp(Root, timeout: TimeSpan.FromMilliseconds(200));
        app.Store.BeforeRecover = _ => new TaskCompletionSource().Task;

        var launched = await app.Lifecycle.LaunchAsync(app.Options, app.Services).AsTask().WaitAsync(Bound);

        A.Equal("dependency.timeout", Value(launched).RecoveryFailure!.Code);
        A.NotNull(app.Lifecycle.Session);
    }

    [Xunit.Fact]
    public async Task AViewStillSavingOnCloseIsVisibleToShutdownAndDisposalWaitsForIt()
    {
        var app = await LaunchedAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("closing"));
        var release = new TaskCompletionSource();
        app.Store.AfterTemporaryWritten = _ => release.Task;

        var closing = view.DisposeAsync().AsTask();
        await Task.Delay(100);
        A.False(closing.IsCompleted);

        // While the close is still saving, the draft is neither lost to the bookkeeping nor reported as safe.
        A.Equal([view.DraftId], app.Lifecycle.UnsavedDrafts);
        A.Equal(HostBusyKind.LocalWork, app.Lifecycle.GetBusyState().Kind);

        var disposal = app.Lifecycle.DisposeAsync().AsTask();
        await Task.Delay(100);
        A.False(disposal.IsCompleted);
        A.Equal(0, app.Session!.DisposeCalls);

        release.SetResult();
        await closing.WaitAsync(Bound);
        await disposal.WaitAsync(Bound);
        A.Equal("closing", app.Store.Stored(view.DraftId)!.Text);
        A.Equal(1, app.Session.DisposeCalls);
        A.Empty(app.Lifecycle.UnsavedDrafts);
    }

    [Xunit.Fact]
    public async Task ShutdownPreparedDuringAFailingCloseRefusesUntilTheDraftIsSaved()
    {
        var app = await LaunchedAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("closing"));
        app.Store.SaveFault = new IOException("disk full");

        await view.DisposeAsync();
        var refused = Value(await app.Lifecycle.PrepareShutdownAsync());
        A.False(refused.CanClose);
        A.False(Value(await app.Lifecycle.RequestStopAsync(CancellationToken.None)));
        A.False(app.Lifecycle.Stopping.IsCancellationRequested);
    }

    [Xunit.Fact]
    public async Task DisposalDuringLaunchIsTerminalAndTheSessionCreatedByThatLaunchIsReleasedOnce()
    {
        var app = new LifecycleApp(Root);
        var release = new TaskCompletionSource();
        app.Store.BeforeRecover = _ => release.Task;

        var launching = app.Lifecycle.LaunchAsync(app.Options, app.Services).AsTask();
        await Task.Delay(100);
        await app.Lifecycle.DisposeAsync();
        release.SetResult();
        var outcome = await launching.WaitAsync(Bound);

        A.Equal("state.gone", LifecycleTests.Code(outcome));
        A.Null(app.Lifecycle.Session);
        A.Equal(1, app.Factory.Calls);
        A.Equal(1, app.Session!.DisposeCalls);
        A.Equal("state.gone", LifecycleTests.Code(app.Lifecycle.OpenView(AssistantWindowId.New())));
        await app.Lifecycle.DisposeAsync();
        A.Equal(1, app.Session.DisposeCalls);
        A.Throws<InvalidOperationException>(() => app.Lifecycle.LaunchAsync(app.Options, app.Services).AsTask().GetAwaiter().GetResult());
    }

    [Xunit.Fact]
    public async Task NothingCanBeRegisteredAfterDisposal()
    {
        var app = await LaunchedAsync();
        await app.Lifecycle.DisposeAsync();

        A.Equal("state.gone", LifecycleTests.Code(app.Lifecycle.OpenView(AssistantWindowId.New())));
        A.Equal("state.gone", LifecycleTests.Code(app.Lifecycle.BeginLocalWork("late")));
        A.Equal("state.gone", LifecycleTests.Code(app.Lifecycle.BeginRemoteWork("late")));
    }
}
