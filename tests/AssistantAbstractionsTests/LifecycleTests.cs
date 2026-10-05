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

/// <summary>Launch, Cloud independence, views and drafts, using the real lifecycle over a real file-backed draft store.</summary>
public sealed class LifecycleTests : IDisposable
{
    private readonly ScratchDirectory _scratch = new();

    public void Dispose() => _scratch.Dispose();

    private string Root => _scratch.Path;

    internal static string Code<T>(Outcome<T> outcome)
    {
        A.True(outcome.TryGetFailure(out var failure), "a failure was expected");
        return failure.Code;
    }

    internal static T Value<T>(Outcome<T> outcome)
    {
        A.True(outcome.TryGetValue(out var value), "a success was expected");
        return value;
    }

    private static string Text(AssistantDraft draft) => draft.Text;

    // ---- Launch and save without Cloud --------------------------------------------------------------------

    [Xunit.Fact]
    public async Task LaunchAndSaveWorkWithCloudUnavailableAndNoAssistantViewOpen()
    {
        var app = new LifecycleApp(Root);
        app.Remote!.Throws = true;

        var report = await app.LaunchAsync();

        A.Equal(AssistantRemoteState.Unavailable, report.Remote);
        A.Equal(AssistantRemoteState.Unavailable, app.Lifecycle.RemoteState);
        A.NotNull(app.Lifecycle.Session);
        A.Empty(report.RecoveredDrafts);
        A.Null(report.RecoveryFailure);
        A.Equal(HostBusyKind.Idle, app.Lifecycle.GetBusyState().Kind);
        int reads = app.Remote.Reads;

        // Open, edit and save, then close the view: the session and the saved draft outlive it, and no save looked at Cloud.
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("measure the span"));
        var saved = Value(await view.CheckpointAsync());
        await view.DisposeAsync();
        A.Equal("measure the span", app.Store.Stored(saved.Id)!.Text);
        A.Equal(reads, app.Remote.Reads);
        A.False(app.Session!.Disposed);
        A.True((await app.Lifecycle.PrepareShutdownAsync()).TryGetValue(out var summary) && summary.CanClose);
        await app.Lifecycle.DisposeAsync();
    }

    [Xunit.Fact]
    public async Task LaunchWithoutALinkReportsUnavailableAndResumeObservesCloudAgain()
    {
        var offline = new LifecycleApp(Root, remote: false);
        A.Equal(AssistantRemoteState.Unavailable, (await offline.LaunchAsync()).Remote);

        var online = new LifecycleApp(Root, AssistantProductIdentity.Companion);
        online.Remote!.Observed = AssistantRemoteState.Unavailable;
        A.Equal(AssistantRemoteState.Unavailable, (await online.LaunchAsync()).Remote);
        online.Remote.Observed = AssistantRemoteState.Available;
        online.Lifecycle.OnResumed();
        A.Equal(AssistantRemoteState.Available, online.Lifecycle.RemoteState);
        A.Equal(1, online.Lifecycle.ResumeCount);
        online.Remote.Throws = true;
        online.Lifecycle.OnResumed();
        A.Equal(AssistantRemoteState.Unavailable, online.Lifecycle.RemoteState);
        online.Remote.Throws = false;
        online.Remote.Observed = AssistantRemoteState.None;
        online.Lifecycle.OnResumed();
        A.Equal(AssistantRemoteState.Unavailable, online.Lifecycle.RemoteState);
    }

    [Xunit.Fact]
    public async Task LaunchSurvivesAnUnreadableDraftStoreAndDeletesNothing()
    {
        var first = new LifecycleApp(Root);
        await first.LaunchAsync();
        var view = Value(first.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("keep me"));
        var saved = Value(await view.CheckpointAsync());

        var second = first.Restart(Root);
        second.Store.RecoverFault = new IOException("disk read error");
        var report = await second.LaunchAsync();

        A.Equal("internal.unexpected", report.RecoveryFailure!.Code);
        A.Empty(report.RecoveredDrafts);
        A.NotNull(second.Lifecycle.Session);
        A.NotNull(second.Store.Stored(saved.Id));
    }

    [Xunit.Fact]
    public async Task ARecoveryThatHangsTimesOutWithoutFailingTheLaunch()
    {
        var app = new LifecycleApp(Root, timeout: TimeSpan.FromMilliseconds(150));
        app.Store.BeforeRecover = token => Task.Delay(Timeout.Infinite, token);

        var report = await app.LaunchAsync();

        A.Equal("dependency.timeout", report.RecoveryFailure!.Code);
        A.NotNull(app.Lifecycle.Session);
    }

    [Xunit.Fact]
    public async Task ACancelledLaunchCreatesNoSessionAndCanBeRetried()
    {
        var app = new LifecycleApp(Root);
        app.Store.BeforeRecover = token => Task.Delay(Timeout.Infinite, token);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        var cancelled = await app.Lifecycle.LaunchAsync(app.Options, app.Services, cancel.Token);

        A.Equal(OutcomeKind.Cancelled, cancelled.Kind);
        A.Equal(ArcForges.Contracts.Foundation.V1.EffectCertainty.DidNotHappen, EffectCertaintyOf(cancelled));
        A.Null(app.Lifecycle.Session);
        A.Equal(0, app.Factory.Calls);

        app.Store.BeforeRecover = null;
        await app.LaunchAsync();
        A.NotNull(app.Lifecycle.Session);
    }

    private static ArcForges.Contracts.Foundation.V1.EffectCertainty EffectCertaintyOf<T>(Outcome<T> outcome)
        => outcome.CancellationEffect;

    [Xunit.Fact]
    public async Task ACorruptedStoredDraftIsSkippedAndKeptWhileOthersRecover()
    {
        var first = new LifecycleApp(Root);
        await first.LaunchAsync();
        var good = Value(first.Lifecycle.OpenView(AssistantWindowId.New()));
        var bad = Value(first.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(good.Edit("good"));
        Value(bad.Edit("bad"));
        Value(await good.CheckpointAsync());
        var badSaved = Value(await bad.CheckpointAsync());
        first.Store.Corrupt(badSaved.Id);

        var second = first.Restart(Root);
        var report = await second.LaunchAsync();

        A.Equal(["good"], report.RecoveredDrafts.Select(Text));
        A.Equal(1, second.Store.SkippedFiles);
        A.True(File.Exists(Path.Combine(second.Store.Directory, badSaved.Id.Value.ToString("N") + ".draft")));
    }

    [Xunit.Fact]
    public async Task LaunchRefusesForeignWiringSecondLaunchAndDisposedLifecycle()
    {
        var app = new LifecycleApp(Root);

        // Services that do not use this lifecycle as their lifecycle port.
        var otherLifecycle = new AssistantLifecycle(app.Identity, app.Store);
        A.Throws<ArgumentException>(() => otherLifecycle.LaunchAsync(app.Options, app.Services).AsTask().GetAwaiter().GetResult());

        // A draft store for another profile partition of the same installation.
        var otherPartition = new FileDraftStore(app.Identity,
            new AssistantStorePartition(app.Identity.Installation, TestData.OtherProfile), Path.Combine(Root, "other"));
        var wrongStore = new AssistantLifecycle(app.Identity, otherPartition);
        var wrongServices = new AssistantHostServices(app.Identity, app.Host, TestData.Registry(app.Identity), app.Host,
            app.Host, wrongStore, app.Host, app.Host, new FakeSessionFactory(app.Identity));
        A.Throws<ArgumentException>(() => wrongStore.LaunchAsync(app.Options, wrongServices).AsTask().GetAwaiter().GetResult());

        // Options of another application instance.
        var foreign = TestData.Options(TestData.Host(TestData.Installed(AssistantProductIdentity.Companion), 3));
        A.Throws<ArgumentException>(() => app.Lifecycle.LaunchAsync(foreign, app.Services).AsTask().GetAwaiter().GetResult());
        A.Throws<ArgumentNullException>(() => app.Lifecycle.LaunchAsync(null!, app.Services).AsTask().GetAwaiter().GetResult());

        await app.LaunchAsync();
        A.Throws<InvalidOperationException>(() => app.Lifecycle.LaunchAsync(app.Options, app.Services).AsTask().GetAwaiter().GetResult());

        var disposed = new LifecycleApp(Path.Combine(Root, "disposed"));
        await disposed.Lifecycle.DisposeAsync();
        A.Throws<InvalidOperationException>(() => disposed.Lifecycle.LaunchAsync(disposed.Options, disposed.Services).AsTask().GetAwaiter().GetResult());
    }

    [Xunit.Fact]
    public async Task AFailedSessionCreationLeavesTheLifecycleLaunchable()
    {
        var app = new LifecycleApp(Root);
        int calls = 0;
        var factory = new FakeSessionFactory(app.Identity, (options, services) =>
            ++calls == 1 ? throw new InvalidOperationException("boom") : new FakeSession(options, services));
        var services = new AssistantHostServices(app.Identity, app.Host, TestData.Registry(app.Identity), app.Host,
            app.Host, app.Lifecycle, app.Host, app.Host, factory);

        A.Throws<InvalidOperationException>(() => app.Lifecycle.LaunchAsync(app.Options, services).AsTask().GetAwaiter().GetResult());
        A.Null(app.Lifecycle.Session);
        A.Equal(OutcomeKind.Failure, app.Lifecycle.OpenView(AssistantWindowId.New()).Kind);

        A.True((await app.Lifecycle.LaunchAsync(app.Options, services)).TryGetValue(out _));
        A.NotNull(app.Lifecycle.Session);
    }

    [Xunit.Fact]
    public void ConstructionRefusesForeignPortsAndUnboundedTimeouts()
    {
        var app = new LifecycleApp(Root);
        var other = TestData.Host(TestData.Installed(AssistantProductIdentity.Companion), 5);
        var otherHost = FakeHost.For(other);
        var otherStore = new FileDraftStore(other, otherHost.Partition, Path.Combine(Root, "x"));

        A.Throws<ArgumentException>(() => new AssistantLifecycle(app.Identity, otherStore));
        var wrongPartition = new FileDraftStore(app.Identity, otherHost.Partition, Path.Combine(Root, "y"));
        A.Throws<ArgumentException>(() => new AssistantLifecycle(app.Identity, wrongPartition));
        A.Throws<ArgumentException>(() => new AssistantLifecycle(app.Identity, app.Store, new FakeRemoteLink(other)));
        A.Throws<ArgumentOutOfRangeException>(() => new AssistantLifecycle(app.Identity, app.Store, null, TimeSpan.Zero));
        A.Throws<ArgumentOutOfRangeException>(() => new AssistantLifecycle(app.Identity, app.Store, null, TimeSpan.FromHours(1)));
        A.Throws<ArgumentNullException>(() => new AssistantLifecycle(null!, app.Store));
        A.Throws<ArgumentNullException>(() => new AssistantLifecycle(app.Identity, null!));
    }

    // ---- Views and drafts ---------------------------------------------------------------------------------

    [Xunit.Fact]
    public async Task TwoWindowsKeepDifferentDraftsAndSaveThemIndependently()
    {
        var app = new LifecycleApp(Root);
        await app.LaunchAsync();
        var first = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        var second = Value(app.Lifecycle.OpenView(AssistantWindowId.New(), conversation: AssistantConversationId.New()));

        A.NotEqual(first.DraftId, second.DraftId);
        Value(first.Edit("first window draft"));
        Value(second.Edit("second window draft"));
        A.True(first.HasUnsavedEdits);
        var savedFirst = Value(await first.CheckpointAsync());

        // Saving one window's draft neither saves nor changes the other's.
        A.True(second.HasUnsavedEdits);
        A.Null(app.Store.Stored(second.DraftId));
        A.Equal("first window draft", app.Store.Stored(first.DraftId)!.Text);
        A.Equal(1, savedFirst.Revision);

        Value(first.Edit("first window draft v2"));
        var savedSecond = Value(await second.CheckpointAsync());
        A.Equal("second window draft", savedSecond.Text);
        A.NotNull(savedSecond.Conversation);
        A.Equal("first window draft", app.Store.Stored(first.DraftId)!.Text);
        A.Equal("first window draft v2", first.Text);

        // An unchanged draft does not write again.
        int writes = app.Store.SaveCalls;
        Value(await second.CheckpointAsync());
        A.Equal(writes, app.Store.SaveCalls);
    }

    [Xunit.Fact]
    public async Task ClosingOneViewSavesItsDraftAndLeavesSessionOtherViewsAndWorkRunning()
    {
        var app = new LifecycleApp(Root);
        await app.LaunchAsync();
        var closing = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        var staying = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        using var local = Value(app.Lifecycle.BeginLocalWork("export.running"));
        using var remote = Value(app.Lifecycle.BeginRemoteWork("cloud.task"));
        Value(closing.Edit("unsaved on close"));
        Value(staying.Edit("still typing"));

        await closing.DisposeAsync();

        A.True(closing.ViewStopping.IsCancellationRequested);
        A.False(staying.ViewStopping.IsCancellationRequested);
        A.Equal("unsaved on close", app.Store.Stored(closing.DraftId)!.Text);
        A.Equal("still typing", staying.Text);
        A.True(staying.HasUnsavedEdits);
        A.False(app.Session!.Disposed);
        A.False(app.Lifecycle.Stopping.IsCancellationRequested);
        A.False(local.Stopping.IsCancellationRequested);
        A.Equal(AssistantWorkKind.Remote, remote.Kind);
        A.Equal(HostBusyKind.LocalWork, app.Lifecycle.GetBusyState().Kind);
        A.Equal(2, app.Lifecycle.GetBusyState().ActiveLocalOperations);

        // The closed view refuses further use; closing twice is harmless; the window can be reopened.
        A.Equal("state.gone", Code(closing.Edit("late")));
        A.Equal("state.gone", Code(await closing.CheckpointAsync()));
        A.Equal("state.gone", Code(await closing.DiscardDraftAsync()));
        await closing.DisposeAsync();
        A.True(app.Lifecycle.OpenView(closing.Window).TryGetValue(out _));
    }

    [Xunit.Fact]
    public async Task OpeningAViewIsRefusedForDuplicateUnknownEarlyLateAndExcessiveRequests()
    {
        var app = new LifecycleApp(Root);
        var window = AssistantWindowId.New();
        A.Equal("state.invalid_transition", Code(app.Lifecycle.OpenView(window)));
        A.Throws<ArgumentException>(() => app.Lifecycle.OpenView(default));
        await app.LaunchAsync();

        var view = Value(app.Lifecycle.OpenView(window));
        A.Equal("conflict.duplicate_identifier", Code(app.Lifecycle.OpenView(window)));
        A.Equal("state.not_found", Code(app.Lifecycle.OpenView(AssistantWindowId.New(), AssistantDraftId.New())));
        A.Equal("state.not_found", Code(app.Lifecycle.OpenView(AssistantWindowId.New(), view.DraftId)));

        for (int index = 1; index < AssistantLifecycle.MaximumOpenViews; index++)
        {
            Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        }

        A.Equal("capacity.busy", Code(app.Lifecycle.OpenView(AssistantWindowId.New())));
        await app.Lifecycle.DisposeAsync();
        A.Equal("state.gone", Code(app.Lifecycle.OpenView(AssistantWindowId.New())));
    }

    [Xunit.Fact]
    public async Task EditIsBoundedAndNeverDurableUntilCheckpointed()
    {
        var app = new LifecycleApp(Root);
        await app.LaunchAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));

        A.Throws<ArgumentNullException>(() => view.Edit(null!));
        A.Equal("validation.invalid_request", Code(view.Edit(new string('x', AssistantDraft.MaximumTextLength + 1))));
        Value(view.Edit(new string('x', AssistantDraft.MaximumTextLength)));
        A.True(view.HasUnsavedEdits);
        A.Null(app.Store.Stored(view.DraftId));
        Value(view.Edit(string.Empty));
        A.False(view.HasUnsavedEdits);
        A.Equal(0, view.StoredDraft.Revision);
    }

    [Xunit.Fact]
    public async Task AFailedSaveKeepsTheTextAndThePreviousDurableRevision()
    {
        var app = new LifecycleApp(Root);
        await app.LaunchAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("one"));
        Value(await view.CheckpointAsync());

        Value(view.Edit("two"));
        app.Store.SaveFault = new IOException("disk full");
        A.Equal("internal.unexpected", Code(await view.CheckpointAsync()));
        A.Equal("two", view.Text);
        A.True(view.HasUnsavedEdits);
        A.Equal("one", app.Store.Stored(view.DraftId)!.Text);
        A.Equal(1, view.StoredDraft.Revision);

        app.Store.SaveFault = null;
        A.Equal(2, Value(await view.CheckpointAsync()).Revision);
        A.False(view.HasUnsavedEdits);
    }

    [Xunit.Fact]
    public async Task ARevisionConflictFromAnotherWriterIsReportedAndKeepsTheEdit()
    {
        var app = new LifecycleApp(Root);
        await app.LaunchAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("mine"));
        var saved = Value(await view.CheckpointAsync());

        // Another process wrote revision 2 of the same draft.
        Value(await app.Store.SaveAsync(new AssistantDraft(saved.Id, saved.Window, null, 2, "theirs"), 1));
        Value(view.Edit("mine, edited"));

        A.Equal("conflict.revision_mismatch", Code(await view.CheckpointAsync()));
        A.True(view.HasUnsavedEdits);
        A.Equal("theirs", app.Store.Stored(saved.Id)!.Text);
    }

    [Xunit.Fact]
    public async Task AStoreThatAcknowledgesOtherContentIsNotTrustedAsDurable()
    {
        var app = new LifecycleApp(Root);
        await app.LaunchAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("asked"));
        app.Store.Tamper = draft => new AssistantDraft(draft.Id, draft.Window, null, draft.Revision, "different");

        A.Equal("internal.unexpected", Code(await view.CheckpointAsync()));
        A.True(view.HasUnsavedEdits);
        A.Equal(0, view.StoredDraft.Revision);

        // A different draft identity is not trusted either (a fresh view, since the store did write the first one).
        var other = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(other.Edit("asked too"));
        app.Store.Tamper = draft => new AssistantDraft(AssistantDraftId.New(), draft.Window, null, draft.Revision, draft.Text);
        A.Equal("internal.unexpected", Code(await other.CheckpointAsync()));
        A.True(other.HasUnsavedEdits);
    }

    [Xunit.Fact]
    public async Task ASlowOrCancelledSaveLeavesTheViewDirtyAndThePreviousRevisionIntact()
    {
        var app = new LifecycleApp(Root, timeout: TimeSpan.FromMilliseconds(200));
        await app.LaunchAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("one"));
        Value(await view.CheckpointAsync());
        Value(view.Edit("two"));
        app.Store.AfterTemporaryWritten = token => Task.Delay(Timeout.Infinite, token);

        A.Equal("dependency.timeout", Code(await view.CheckpointAsync()));
        A.Equal("one", app.Store.Stored(view.DraftId)!.Text);
        A.True(view.HasUnsavedEdits);

        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        var cancelled = await view.CheckpointAsync(cancel.Token);
        A.Equal(OutcomeKind.Cancelled, cancelled.Kind);
        A.Equal(ArcForges.Contracts.Foundation.V1.EffectCertainty.Unknown, cancelled.CancellationEffect);

        using var already = new CancellationTokenSource();
        await already.CancelAsync();
        var beforeStart = await view.CheckpointAsync(already.Token);
        A.Equal(OutcomeKind.Cancelled, beforeStart.Kind);
    }

    [Xunit.Fact]
    public async Task DiscardingADraftRemovesItAndStartsAFreshOne()
    {
        var app = new LifecycleApp(Root);
        await app.LaunchAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));

        // Nothing stored yet: only the editor is reset.
        Value(view.Edit("scratch"));
        var original = view.DraftId;
        A.True(Value(await view.DiscardDraftAsync()));
        A.Equal(string.Empty, view.Text);
        A.NotEqual(original, view.DraftId);

        Value(view.Edit("kept"));
        var saved = Value(await view.CheckpointAsync());
        app.Store.SaveFault = null;
        A.True(Value(await view.DiscardDraftAsync()));
        A.Null(app.Store.Stored(saved.Id));
        A.NotEqual(saved.Id, view.DraftId);
        A.Equal(0, view.StoredDraft.Revision);
    }

    [Xunit.Fact]
    public async Task AnUnconfirmedDiscardChangesNothing()
    {
        var app = new LifecycleApp(Root);
        await app.LaunchAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("kept"));
        var saved = Value(await view.CheckpointAsync());
        Value(await app.Store.SaveAsync(new AssistantDraft(saved.Id, saved.Window, null, 2, "newer"), 1));

        A.Equal("conflict.revision_mismatch", Code(await view.DiscardDraftAsync()));
        A.Equal("kept", view.Text);
        A.Equal(saved.Id, view.DraftId);
        A.NotNull(app.Store.Stored(saved.Id));
    }

    [Xunit.Fact]
    public async Task AViewThatCannotSaveOnCloseIsRetainedAndShutdownRefusesUntilItSaves()
    {
        var app = new LifecycleApp(Root);
        await app.LaunchAsync();
        var view = Value(app.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("precious"));
        app.Store.SaveFault = new IOException("disk full");

        await view.DisposeAsync();

        A.Equal([view.DraftId], app.Lifecycle.UnsavedDrafts);
        A.Equal(HostBusyKind.LocalWork, app.Lifecycle.GetBusyState().Kind);
        var refused = Value(await app.Lifecycle.PrepareShutdownAsync());
        A.False(refused.CanClose);
        A.Equal(["shutdown.unsaved_draft"], refused.RefusalMessageKeys);
        A.Equal(1, refused.ActiveLocalOperations);

        app.Store.SaveFault = null;
        var allowed = Value(await app.Lifecycle.PrepareShutdownAsync());
        A.True(allowed.CanClose);
        A.Empty(app.Lifecycle.UnsavedDrafts);
        A.Equal("precious", app.Store.Stored(view.DraftId)!.Text);
    }
}
