// SPDX-License-Identifier: AGPL-3.0-only
#pragma warning disable CA2007 // Test code has no synchronization context to preserve.
#pragma warning disable xUnit1051 // These tests deliberately exercise the default (no token) and explicit-cancellation paths.
#pragma warning disable CA1849 // The test store and log use synchronous durable writes like a simple real store.
#pragma warning disable CA2000 // Test doubles here own no unmanaged resources.
#pragma warning disable CA1859 // Tests deliberately use the port interfaces to exercise their contracts.
using ArcForges.Assistant.Abstractions;
using ArcForges.Foundation.Errors;
using A = Xunit.Assert;

namespace AssistantAbstractionsTests;

/// <summary>Honest shutdown, profile switching, work registration and orderly disposal.</summary>
public sealed class LifecycleShutdownTests : IDisposable
{
    private readonly ScratchDirectory _scratch = new();

    public void Dispose() => _scratch.Dispose();

    private string Root => _scratch.Path;

    private static string Code<T>(Outcome<T> outcome) => LifecycleTests.Code(outcome);

    private static T Value<T>(Outcome<T> outcome) => LifecycleTests.Value(outcome);

    private async Task<LifecycleApp> LaunchedAsync(TimeSpan? timeout = null)
    {
        var app = new LifecycleApp(Root, timeout: timeout);
        await app.LaunchAsync();
        return app;
    }

    [Xunit.Fact]
    public async Task AnIdleApplicationMayCloseAndSavesUnsavedDraftsOnTheWay()
    {
        var app = await LaunchedAsync();
        A.Equal(HostBusyKind.Idle, app.Lifecycle.GetBusyState().Kind);
        A.True(Value(await app.Lifecycle.PrepareShutdownAsync()).CanClose);

        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("typed but not saved"));
        A.Equal(HostBusyKind.LocalWork, app.Lifecycle.GetBusyState().Kind);

        var summary = Value(await app.Lifecycle.PrepareShutdownAsync());

        A.True(summary.CanClose);
        A.Equal(0, summary.ActiveLocalOperations);
        A.Equal("typed but not saved", app.Store.Stored(view.DraftId)!.Text);
        A.False(view.HasUnsavedEdits);
    }

    [Xunit.Fact]
    public async Task LocalWorkIsCheckpointedOrExplicitlyRefused()
    {
        var app = await LaunchedAsync(TimeSpan.FromMilliseconds(200));
        using var unsaved = Value(app.Lifecycle.BeginLocalWork("import.running"));
        var summary = Value(await app.Lifecycle.PrepareShutdownAsync());
        A.False(summary.CanClose);
        A.Equal(1, summary.ActiveLocalOperations);
        A.Equal(["shutdown.local_work"], summary.RefusalMessageKeys);

        int checkpoints = 0;
        using var checkpointed = Value(app.Lifecycle.BeginLocalWork("export.running", _ =>
        {
            checkpoints++;
            return ValueTask.FromResult(true);
        }));
        unsaved.Dispose();
        A.True(Value(await app.Lifecycle.PrepareShutdownAsync()).CanClose);
        A.Equal(1, checkpoints);

        // The work is still running, so the application is still busy until it ends.
        A.Equal(HostBusyKind.LocalWork, app.Lifecycle.GetBusyState().Kind);
        checkpointed.Dispose();
        checkpointed.Dispose();
        A.Equal(HostBusyKind.Idle, app.Lifecycle.GetBusyState().Kind);
    }

    [Xunit.Fact]
    public async Task AFailingThrowingOrHangingCheckpointIsARefusalNeverASuccess()
    {
        var app = await LaunchedAsync(TimeSpan.FromMilliseconds(200));
        using var refuses = Value(app.Lifecycle.BeginLocalWork("a", _ => ValueTask.FromResult(false)));
        using var throws = Value(app.Lifecycle.BeginLocalWork("b", _ => throw new InvalidOperationException("no")));
        using var hangs = Value(app.Lifecycle.BeginLocalWork("c", async token =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return true;
        }));

        var summary = Value(await app.Lifecycle.PrepareShutdownAsync());

        A.False(summary.CanClose);
        A.Equal(3, summary.ActiveLocalOperations);
    }

    [Xunit.Fact]
    public async Task CloudOnlyWorkContinuesAndNeverBlocksQuitting()
    {
        var app = await LaunchedAsync();
        using var remote = Value(app.Lifecycle.BeginRemoteWork("cloud.run"));

        var busy = app.Lifecycle.GetBusyState();
        A.Equal(HostBusyKind.AwaitingRemote, busy.Kind);
        A.Equal(0, busy.ActiveLocalOperations);
        A.True(Value(await app.Lifecycle.PrepareShutdownAsync()).CanClose);
        A.True(Value(await app.Lifecycle.RequestStopAsync(CancellationToken.None)));
        A.True(app.Lifecycle.Stopping.IsCancellationRequested);
        // Accepting a stop neither cancels nor unregisters the Cloud work; it is only reported.
        A.Equal(HostBusyKind.AwaitingRemote, app.Lifecycle.GetBusyState().Kind);
    }

    [Xunit.Fact]
    public async Task ShutdownPreparationIsCancellableWithoutForcingAnything()
    {
        var app = await LaunchedAsync();
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var before = await app.Lifecycle.PrepareShutdownAsync(cancelled.Token);
        A.Equal(OutcomeKind.Cancelled, before.Kind);
        A.Equal(ArcForges.Contracts.Foundation.V1.EffectCertainty.DidNotHappen, before.CancellationEffect);

        using var hang = Value(app.Lifecycle.BeginLocalWork("slow", async token =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return true;
        }));
        using var during = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var interrupted = await app.Lifecycle.PrepareShutdownAsync(during.Token);
        A.Equal(OutcomeKind.Cancelled, interrupted.Kind);
        A.Equal(ArcForges.Contracts.Foundation.V1.EffectCertainty.Unknown, interrupted.CancellationEffect);
        A.False(app.Lifecycle.Stopping.IsCancellationRequested);

        var stop = await app.Lifecycle.RequestStopAsync(cancelled.Token);
        A.Equal(OutcomeKind.Cancelled, stop.Kind);
        var profile = await app.Lifecycle.OnProfileChangingAsync(AssistantProfileId.New(), cancelled.Token);
        A.Equal(OutcomeKind.Cancelled, profile.Kind);
    }

    [Xunit.Fact]
    public async Task AStopRequestIsRefusedWhileWorkIsUnresolvedAndAcceptedAfterwards()
    {
        var app = await LaunchedAsync(TimeSpan.FromMilliseconds(200));
        using var work = Value(app.Lifecycle.BeginLocalWork("render"));

        A.False(Value(await app.Lifecycle.RequestStopAsync(CancellationToken.None)));
        A.False(app.Lifecycle.Stopping.IsCancellationRequested);

        work.Dispose();
        A.True(Value(await app.Lifecycle.RequestStopAsync(CancellationToken.None)));
        A.True(app.Lifecycle.Stopping.IsCancellationRequested);
        A.Equal("state.gone", Code(app.Lifecycle.BeginLocalWork("late")));
        A.Equal("state.gone", Code(app.Lifecycle.BeginRemoteWork("late")));
        A.Equal("state.gone", Code(app.Lifecycle.OpenView(AssistantWindowId.New())));
        A.Throws<ArgumentException>(() => app.Lifecycle.BeginLocalWork(" "));
        A.Throws<ArgumentException>(() => app.Lifecycle.BeginRemoteWork(new string('k', 161)));
    }

    [Xunit.Fact]
    public async Task AProfileSwitchIsAllowedOnlyWhenNothingOfTheCurrentProfileWouldBeLost()
    {
        var app = await LaunchedAsync(TimeSpan.FromMilliseconds(200));
        var next = AssistantProfileId.New();
        A.Equal(next, Value(await app.Lifecycle.OnProfileChangingAsync(next)));

        using var work = Value(app.Lifecycle.BeginLocalWork("sync"));
        A.Equal("conflict.local_changes_pending", Code(await app.Lifecycle.OnProfileChangingAsync(next)));
        work.Dispose();

        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("draft of the old profile"));
        app.Store.SaveFault = new IOException("disk full");
        A.Equal("conflict.local_changes_pending", Code(await app.Lifecycle.OnProfileChangingAsync(next)));
        A.Equal("draft of the old profile", view.Text);

        // The same switch saves the draft first when the store is healthy.
        app.Store.SaveFault = null;
        A.Equal(next, Value(await app.Lifecycle.OnProfileChangingAsync(next)));
        A.Equal("draft of the old profile", app.Store.Stored(view.DraftId)!.Text);
    }

    [Xunit.Fact]
    public async Task DisposalClosesEveryViewIndependentlyThenReleasesTheSessionOnce()
    {
        var app = await LaunchedAsync();
        var first = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        var second = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        var third = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(first.Edit("one"));
        Value(second.Edit("two"));
        Value(third.Edit("three"));
        first.ViewStopping.Register(() => app.Events.Add("view.first.closed"));
        second.ViewStopping.Register(() => app.Events.Add("view.second.closed"));

        await app.Lifecycle.DisposeAsync();
        await app.Lifecycle.DisposeAsync();

        A.True(app.Events.IndexOf("view.first.closed") >= 0 && app.Events.IndexOf("view.second.closed") >= 0);
        A.True(app.Events.IndexOf("session.disposed") > app.Events.IndexOf("view.second.closed"));
        A.Equal(1, app.Session!.DisposeCalls);
        A.Equal("session.disposed", app.Events[^1]);
        A.True(app.Lifecycle.Stopping.IsCancellationRequested);
        A.Equal(["one", "two", "three"], new[] { first, second, third }.Select(view => app.Store.Stored(view.DraftId)!.Text));
        A.Empty(app.Lifecycle.UnsavedDrafts);
        A.Empty(app.Lifecycle.ShutdownFailures);
    }

    [Xunit.Fact]
    public async Task DisposalReportsDraftsItCouldNotSaveAndASessionThatFailedToDispose()
    {
        var app = await LaunchedAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        var healthy = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("lost"));
        Value(healthy.Edit("saved"));
        app.Session!.ThrowOnDispose = true;
        app.Store.SaveFault = new IOException("disk full");

        await app.Lifecycle.DisposeAsync();

        A.Equal(2, app.Lifecycle.UnsavedDrafts.Count);
        A.Equal("internal.unexpected", A.Single(app.Lifecycle.ShutdownFailures).Code);
        A.Equal(1, app.Session.DisposeCalls);
    }

    [Xunit.Fact]
    public async Task AViewThatFailedToSaveEarlierIsSavedByDisposalOnceTheStoreRecovers()
    {
        var app = await LaunchedAsync();
        var failing = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        var other = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(failing.Edit("a"));
        Value(other.Edit("b"));
        app.Store.SaveFault = new IOException("first only");
        await failing.DisposeAsync();
        A.Contains(failing.DraftId, app.Lifecycle.UnsavedDrafts);
        app.Store.SaveFault = null;

        await app.Lifecycle.DisposeAsync();

        A.Equal("b", app.Store.Stored(other.DraftId)!.Text);
        A.Equal("a", app.Store.Stored(failing.DraftId)!.Text);
        A.Empty(app.Lifecycle.UnsavedDrafts);
    }
}
