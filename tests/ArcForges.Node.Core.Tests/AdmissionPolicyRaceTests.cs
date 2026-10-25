// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real admission cannot commit a decision from a policy that was replaced while the pass was reading its input.</summary>
public sealed class AdmissionPolicyRaceTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory(Timeout = 180_000)]
    [InlineData(ParallelismScope.Global)]
    [InlineData(ParallelismScope.Session)]
    [Trait("env", "windows-real")]
    public async Task ACommittedLimitInvalidatesAnOlderAdmissionSnapshotOnWindows(ParallelismScope scope)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Windows job platform.");
        await PolicyRaceAsync(scope);
    }

    [Theory(Timeout = 180_000)]
    [InlineData(ParallelismScope.Global)]
    [InlineData(ParallelismScope.Session)]
    [Trait("env", "linux-real")]
    public async Task ACommittedLimitInvalidatesAnOlderAdmissionSnapshotOnLinux(ParallelismScope scope)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux transient units.");
        Sched.RequirePlatform();
        await PolicyRaceAsync(scope);
    }

    private static async Task PolicyRaceAsync(ParallelismScope scope)
    {
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        await Sched.WidenAsync(channel);
        byte[] session = [];
        node.Runtime.Store.Write(transaction => session = Sched.SeedSession(transaction));
        var execution = node.Runtime.Execution!;
        var captured = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseOld = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var nextPass = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseNext = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        execution.BeforeAdmissionRead = async () =>
        {
            switch (Interlocked.Increment(ref calls))
            {
                case 1:
                    captured.TrySetResult();
                    await releaseOld.Task;
                    break;
                case 2:
                    nextPass.TrySetResult();
                    await releaseNext.Task;
                    break;
            }
        };

        var releaseWork = Path.Combine(node.Root, "release.flag");
        var submitted = new List<Id>();
        try
        {
            execution.PolicyChanged();
            await captured.Task.WaitAsync(Tasks.Bound, Ct);
            await Sched.SetParallelismAsync(channel, scope, scope == ParallelismScope.Session ? ArcForges.Client.IdText.Format(session) : string.Empty,
                ParallelismMode.Disabled);

            TaskSpec Work(string name) => Sched.Hold(node, Path.Combine(node.Root, name + ".txt"), 120_000, "--until-file", releaseWork);
            async Task<Id> SubmitAsync(string name) => scope == ParallelismScope.Session
                ? await Sched.SubmitAsSessionAsync(node, Work(name), session)
                : await Tasks.SubmitAsync(channel, Work(name));
            var first = await SubmitAsync("first");
            submitted.Add(first);
            var second = await SubmitAsync("second");
            submitted.Add(second);

            // The old pass now sees work submitted after the new limit committed. Hold its successor so any admission here is
            // unambiguously the stale pass's decision, rather than racing the next pass or an OS start.
            releaseOld.TrySetResult();
            await nextPass.Task.WaitAsync(Tasks.Bound, Ct);
            Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, first)).State);
            Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, second)).State);

            releaseNext.TrySetResult();
            await Tasks.RunningAsync(channel, first);
            await Sched.ExplainedAsync(channel, second, scope == ParallelismScope.Global ? "global_limit" : "pool_limit");
            Assert.Equal(TaskState.Queued, (await Tasks.GetAsync(channel, second)).State);
            await File.WriteAllTextAsync(releaseWork, "release", Ct);
            Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, first)).State);
            Assert.Equal(TaskState.Succeeded, (await Tasks.WaitAsync(channel, second)).State);
            Assert.False(Sched.Overlap(Sched.Window(Path.Combine(node.Root, "first.txt")), Sched.Window(Path.Combine(node.Root, "second.txt"))),
                "The new limit must serialize work admitted after its commit.");
        }
        finally
        {
            execution.BeforeAdmissionRead = null;
            releaseOld.TrySetResult();
            releaseNext.TrySetResult();
            await File.WriteAllTextAsync(releaseWork, "release", Ct);
            foreach (var task in submitted)
            {
                await Tasks.WaitAsync(channel, task);
            }
        }
    }
}
