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

/// <summary>
/// Independent application crash. A crash is simulated in-process: the application's objects are abandoned without
/// disposal (and a write is left half done), then a new instance starts over the same data directory. No operating
/// system process is killed here.
/// </summary>
public sealed class CrashRecoveryTests : IDisposable
{
    private readonly ScratchDirectory _scratch = new();

    public void Dispose() => _scratch.Dispose();

    private string Root => _scratch.Path;

    private static T Value<T>(Outcome<T> outcome) => LifecycleTests.Value(outcome);

    [Xunit.Fact]
    public async Task AnApplicationCrashLosesNoCommittedDataAndRecoversEveryDurableDraft()
    {
        var crashed = new LifecycleApp(Root);
        await crashed.LaunchAsync();
        crashed.Canonical.Commit("conversation-1/turn-1");
        crashed.Canonical.Stage("conversation-1/turn-2-not-acknowledged");

        var alpha = Value(crashed.Lifecycle.OpenView(AssistantWindowId.New()));
        var beta = Value(crashed.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(alpha.Edit("alpha"));
        Value(await alpha.CheckpointAsync());
        Value(alpha.Edit("alpha, edited but never saved"));
        Value(beta.Edit("beta"));
        Value(await beta.CheckpointAsync());
        var gamma = Value(crashed.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(gamma.Edit("gamma, never saved"));

        // beta's next save is interrupted after its temporary file is complete and before it replaces revision 1.
        Value(beta.Edit("beta, interrupted"));
        var never = new TaskCompletionSource();
        crashed.Store.AfterTemporaryWritten = _ => never.Task;
        var interrupted = beta.CheckpointAsync().AsTask();
        A.False(interrupted.IsCompleted);
        // The process dies here: nothing is disposed, flushed or completed.

        var restarted = crashed.Restart(Root);
        var report = await restarted.LaunchAsync();

        // Committed data is exactly the acknowledged commits; the staged one is absent and nothing is torn.
        A.Equal(["conversation-1/turn-1"], restarted.Canonical.Durable());
        // Each draft returns at its last durable revision; unsaved and interrupted edits are not invented.
        A.Equal(["alpha", "beta"], report.RecoveredDrafts.Select(draft => draft.Text).Order(StringComparer.Ordinal));
        A.All(report.RecoveredDrafts, draft => A.Equal(1, draft.Revision));
        A.NotEmpty(restarted.Store.TemporaryFiles());
        A.Null(report.RecoveryFailure);

        // Two windows resume two different drafts; each draft can be claimed once.
        var windowOne = AssistantWindowId.New();
        var windowTwo = AssistantWindowId.New();
        var resumeAlpha = report.RecoveredDrafts.Single(draft => draft.Text == "alpha");
        var resumeBeta = report.RecoveredDrafts.Single(draft => draft.Text == "beta");
        var viewOne = Value(restarted.Lifecycle.OpenView(windowOne, resumeAlpha.Id));
        var viewTwo = Value(restarted.Lifecycle.OpenView(windowTwo, resumeBeta.Id));
        A.Equal("alpha", viewOne.Text);
        A.Equal("beta", viewTwo.Text);
        A.Equal("state.not_found", LifecycleTests.Code(restarted.Lifecycle.OpenView(AssistantWindowId.New(), resumeAlpha.Id)));

        Value(viewOne.Edit("alpha, continued"));
        var saved = Value(await viewOne.CheckpointAsync());
        A.Equal(2, saved.Revision);
        A.Equal(windowOne, saved.Window);
        A.Equal("beta", restarted.Store.Stored(resumeBeta.Id)!.Text);
        A.True(Value(await restarted.Lifecycle.PrepareShutdownAsync()).CanClose);
        await restarted.Lifecycle.DisposeAsync();
        A.Equal("alpha, continued", restarted.Store.Stored(resumeAlpha.Id)!.Text);
    }

    [Xunit.Fact]
    public async Task OneApplicationCrashingLeavesTheOtherProductFullyUsableAndItsDataUntouched()
    {
        var arcScope = new LifecycleApp(Root);
        var companion = new LifecycleApp(Root, AssistantProductIdentity.Companion);
        await arcScope.LaunchAsync();
        await companion.LaunchAsync();
        A.NotEqual(arcScope.Store.Directory, companion.Store.Directory);

        var companionView = Value(companion.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(companionView.Edit("companion draft"));
        Value(await companionView.CheckpointAsync());
        companion.Canonical.Commit("companion/turn-1");
        var arcView = Value(arcScope.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(arcView.Edit("arcscope draft"));
        Value(await arcView.CheckpointAsync());

        // ArcScope hangs mid-save and dies; its objects are abandoned.
        Value(arcView.Edit("arcscope, interrupted"));
        arcScope.Store.AfterTemporaryWritten = _ => new TaskCompletionSource().Task;
        _ = arcView.CheckpointAsync().AsTask();

        // Companion keeps working: edits, saves, new windows, shutdown.
        Value(companionView.Edit("companion draft, later"));
        A.Equal(2, Value(await companionView.CheckpointAsync()).Revision);
        var another = Value(companion.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(another.Edit("second companion window"));
        A.True(Value(await companion.Lifecycle.PrepareShutdownAsync()).CanClose);
        A.False(companion.Lifecycle.Stopping.IsCancellationRequested);
        A.Equal(["companion/turn-1"], companion.Canonical.Durable());

        // ArcScope restarts and sees only its own draft; Companion's data is not visible to it or changed by it.
        var restarted = arcScope.Restart(Root);
        var report = await restarted.LaunchAsync();
        A.Equal(["arcscope draft"], report.RecoveredDrafts.Select(draft => draft.Text));
        A.Equal("companion draft, later", companion.Store.Stored(companionView.DraftId)!.Text);
        A.Empty(restarted.Canonical.Durable());
    }

    [Xunit.Fact]
    public async Task ADraftStoreOfAnotherProductOrInstallationCannotBeComposed()
    {
        var arcScope = new LifecycleApp(Root);
        var companion = new LifecycleApp(Root, AssistantProductIdentity.Companion);

        A.Throws<ArgumentException>(() => new AssistantLifecycle(arcScope.Identity, companion.Store));
        var secondInstallation = new LifecycleApp(Root, instance: 9, epoch: 3);
        // A different instance of the same installation is a different application instance: refused too.
        A.Throws<ArgumentException>(() => new AssistantLifecycle(arcScope.Identity, secondInstallation.Store));
        await Task.CompletedTask;
    }

    [Xunit.Fact]
    public async Task ADraftSavedByAnEarlierRunIsNotOverwrittenByARunWithStaleKnowledge()
    {
        var first = new LifecycleApp(Root);
        await first.LaunchAsync();
        var view = Value(first.Lifecycle.OpenView(AssistantWindowId.New()));
        Value(view.Edit("v1"));
        var saved = Value(await view.CheckpointAsync());

        // The crashed instance's view continues in a restarted instance and writes revision 2.
        var second = first.Restart(Root);
        var report = await second.LaunchAsync();
        var resumed = Value(second.Lifecycle.OpenView(AssistantWindowId.New(), report.RecoveredDrafts.Single().Id));
        Value(resumed.Edit("v2 from the new instance"));
        Value(await resumed.CheckpointAsync());

        // The stale view of the old instance (a zombie still alive) cannot overwrite it.
        Value(view.Edit("v2 from the zombie"));
        A.Equal("conflict.revision_mismatch", LifecycleTests.Code(await view.CheckpointAsync()));
        A.Equal("v2 from the new instance", second.Store.Stored(saved.Id)!.Text);
    }
}
