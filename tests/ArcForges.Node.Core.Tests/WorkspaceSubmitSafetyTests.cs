// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Scheduling;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Real SQLite and handler paths. The routed fixture supplies a test link and clock, not center signatures or a real center.
/// </summary>
[Trait("feature", "workspace-submit-safety")]
public sealed class WorkspaceSubmitSafetyTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact(Timeout = 120_000)]
    public async Task RealRetryMatchingDoesNotHoldTheUnrelatedSqliteWriter()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        await using var script = await node.ChannelAsync();
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var changed = await Sched.ChangePolicyAsync(human, policy =>
        {
            policy.RetrySafety ??= new RetrySafetyPolicy();
            for (var index = 0; index < 512; index++)
            {
                policy.RetrySafety.Rules.Add(new RetrySafetyRule { Pattern = "[ab]+z", SideEffect = SideEffectClass.Pure });
            }
        });
        Assert.Null(changed.Error);
        var execution = node.Runtime.Execution!;
        Assert.Equal(512, execution.Settings.RetrySafetyRules.Count);
        var firstRealMatch = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var release = new ManualResetEventSlim();
        execution.AfterRetryMatchForTests = index =>
        {
            if (index == 0)
            {
                firstRealMatch.TrySetResult();
                if (!release.Wait(TimeSpan.FromSeconds(10)))
                {
                    throw new TimeoutException("the unrelated writer did not finish");
                }
            }
        };

        // A legal 1 MiB argument vector, with no final z. All 512 real patterns are evaluated.
        var executable = Tasks.TestLoad;
        var largeArgument = new string('a', 1024 * 1024 - System.Text.Encoding.UTF8.GetByteCount(executable));
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, executable, largeArgument) };
        var pending = script.Tasks.SubmitTaskAsync(request, deadline: DateTime.UtcNow.AddSeconds(90), cancellationToken: Ct).ResponseAsync;
        try
        {
            await firstRealMatch.Task.WaitAsync(TimeSpan.FromSeconds(20), Ct);
            // Actual second writer transaction commits while a real match operation is paused between rules.
            await Task.Run(() => node.Runtime.Store.Write(transaction => transaction.Execute("""
                INSERT INTO node_setting (name, value_json, updated_at, rev)
                VALUES ('ctr06-writer-probe', 'true', $now, 0);
                """, ("$now", transaction.NowMicroseconds))), Ct).WaitAsync(TimeSpan.FromSeconds(5), Ct);
            Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar(
                "SELECT count(*) FROM node_setting WHERE name = 'ctr06-writer-probe';")));
        }
        finally
        {
            release.Set();
        }

        var response = await pending.WaitAsync(TimeSpan.FromSeconds(60), Ct);
        execution.AfterRetryMatchForTests = null;
        Assert.Null(response.Error);
        Assert.Equal(EffectCertainty.Happened, response.Value.Receipt.Effect);
        var selected = node.Runtime.Store.Read(reader => reader.Scalar("SELECT side_effect FROM task WHERE task_id=$id;",
            ("$id", response.Value.TaskId.Value.ToByteArray())));
        Assert.Equal((long)SideEffectClass.Unknown, selected);
    }

    [Theory(Timeout = 120_000)]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RoutedExpiryOrDroppedLinkImmediatelyBeforeInsertRollsBackTheTaskAndReceipt(bool expire)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var clock = new OffsetClock();
        await using var node = InProcessNode.Create();
        node.Clock = clock;
        await node.StartAsync();
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = Tasks.Meta(), All = true }, cancellationToken: Ct)).Error);
        var routed = new RoutedCalls(node);
        var request = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = Tasks.Argv(node.Root, Tasks.TestLoad, "hold", "--hold-ms", "100") };
        request.Spec.Environment.Set["VISIBLE_NAME"] = "test value";
        var observed = false;
        node.Runtime.Execution!.BeforeSubmitEffectForTests = () =>
        {
            observed = true;
            if (expire)
            {
                clock.SetOffset(TimeSpan.FromMinutes(4));
            }
            else
            {
                routed.Link.Reset(usableFor: 0);
            }
        };

        var (answer, _) = await routed.SubmitAsync(RoutedCalls.Session(), request);
        node.Runtime.Execution.BeforeSubmitEffectForTests = null;
        clock.SetOffset(TimeSpan.Zero);
        routed.Link.Reset();
        Assert.True(observed, "the real dispatcher passed its earlier check and reached the insertion boundary");
        if (expire)
        {
            Assert.Equal((RoutedOutcome.Expired, "expired"), (answer!.Outcome, answer.Error?.Code));
        }
        else
        {
            Assert.Null(answer);
        }

        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM env_snapshot;")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id=$id;", ("$id", request.Meta.CommandId.Value.ToByteArray()))));

        // Positive control exercises the same real dispatch path with a usable link and unexpired clock.
        var control = new TaskServiceSubmitTaskRequest { Meta = Tasks.Meta(), Spec = request.Spec.Clone() };
        var (accepted, response) = await routed.SubmitAsync(RoutedCalls.Session(), control);
        Assert.Equal(RoutedOutcome.Executed, accepted!.Outcome);
        Assert.Null(response!.Error);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
    }

    private sealed class OffsetClock : TimeProvider
    {
        private long _offsetTicks;

        public override DateTimeOffset GetUtcNow() => TimeProvider.System.GetUtcNow().AddTicks(Interlocked.Read(ref _offsetTicks));

        public void SetOffset(TimeSpan offset) => Interlocked.Exchange(ref _offsetTicks, offset.Ticks);
    }
}
