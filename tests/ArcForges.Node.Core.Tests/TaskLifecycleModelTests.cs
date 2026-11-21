// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using ArcForges.Tests;
using CsCheck;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The SM-TASK and SM-ATTEMPT transitions of retained legacy records, tested through the real Node and event journal.
/// </summary>
public sealed class TaskLifecycleModelTests
{
    /// <summary>SM-TASK (machines.json): the allowed (from, to) pairs.</summary>
    private static readonly HashSet<(TaskState, TaskState)> TaskTransitions = Pairs(
        ([TaskState.WaitingDependency], TaskState.Queued),
        ([TaskState.WaitingDependency], TaskState.Cancelled),
        ([TaskState.Queued], TaskState.Running),
        ([TaskState.Queued], TaskState.Placing),
        ([TaskState.Placing], TaskState.Running),
        ([TaskState.Placing], TaskState.Queued),
        ([TaskState.Running], TaskState.Paused),
        ([TaskState.Paused], TaskState.Running),
        ([TaskState.Running], TaskState.Succeeded),
        ([TaskState.Running], TaskState.RetryWait),
        ([TaskState.RetryWait], TaskState.Queued),
        ([TaskState.Running], TaskState.Failed),
        ([TaskState.Running], TaskState.Lost),
        ([TaskState.Queued, TaskState.Placing, TaskState.Running, TaskState.Paused, TaskState.RetryWait], TaskState.Cancelled),
        ([TaskState.Failed, TaskState.Cancelled, TaskState.Lost], TaskState.Queued));

    /// <summary>SM-ATTEMPT (machines.json): the allowed (from, to) pairs.</summary>
    private static readonly HashSet<(AttemptState, AttemptState)> AttemptTransitions = Pairs(
        ([AttemptState.Created], AttemptState.Transferring),
        ([AttemptState.Created], AttemptState.Starting),
        ([AttemptState.Transferring], AttemptState.Starting),
        ([AttemptState.Starting], AttemptState.Running),
        ([AttemptState.Starting], AttemptState.Finished),
        ([AttemptState.Running], AttemptState.Pausing),
        ([AttemptState.Pausing], AttemptState.Paused),
        ([AttemptState.Paused], AttemptState.Running),
        ([AttemptState.Running, AttemptState.Pausing, AttemptState.Paused], AttemptState.Stopping),

        // A cancel or preemption while the attempt is being launched: STOPPING is persisted, so a node restart continues the stop.
        ([AttemptState.Starting], AttemptState.Stopping),
        ([AttemptState.Starting, AttemptState.Running, AttemptState.Pausing, AttemptState.Paused], AttemptState.Finalizing),
        ([AttemptState.Stopping], AttemptState.Finalizing),
        ([AttemptState.Created], AttemptState.Finalizing),
        ([AttemptState.Finalizing], AttemptState.Finished),
        // The broad recovery edge is guarded by its LOST/UNKNOWN trigger below, never a normal-finish shortcut.
        ([AttemptState.Created, AttemptState.Transferring, AttemptState.Starting, AttemptState.Running, AttemptState.Pausing, AttemptState.Paused,
            AttemptState.Stopping, AttemptState.Finalizing], AttemptState.Finished));

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>One operation of a sequence; indexes pick an existing task modulo the number of tasks.</summary>
    private abstract record Operation;

    private sealed record Submit : Operation;
    private sealed record Cancel(int Index) : Operation;
    private sealed record Retry(int Index) : Operation;

    private static readonly Gen<Operation> AnyOperation = Gen.Frequency(
        (2, Gen.Const((Operation)new Submit())),
        (4, Gen.Int[0, 7].Select(index => (Operation)new Cancel(index))),
        (4, Gen.Int[0, 7].Select(index => (Operation)new Retry(index))));

    [Fact(Timeout = 600_000)]
    public async Task RetainedTaskStatesFollowTheStateMachineAndTheModel()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await AnyOperation.Array[3, 9].SampleAsync(operations => RunAsync([new Cancel(0), .. operations]), iter: PropertyRuns.Iter(4), threads: 1,
            print: operations => string.Join(", ", operations.Select(operation => operation.ToString())));
    }

    [Fact(Timeout = 120_000)]
    public async Task ARecoveredStartingAttemptEmitsItsOriginalStateAndFinalizingBeforeTheResult()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var node = InProcessNode.Create();
        var (taskId, attemptId) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Starting);
        var files = Tasks.Files(node, attemptId);
        Directory.CreateDirectory(files.Directory);
        HelperFiles.WriteAtomically(files.ExitPath, new ExitRecord
        {
            AttemptId = IdText.Format(attemptId),
            RecordedAt = node.Clock.GetUtcNow().ToString("O", CultureInfo.InvariantCulture),
        }.ToJson());

        await node.StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var task = await Tasks.WaitAsync(channel, taskId);
        Assert.Equal(TaskState.Succeeded, task.State);
        Assert.Equal(attemptId, task.CurrentAttempt.AttemptId);
        Assert.Equal(TerminationReason.Exited, task.CurrentAttempt.Result.TerminationReason);
        Assert.Equal(EffectCertainty.Happened, task.CurrentAttempt.Result.Effect);
        Assert.True(task.CurrentAttempt.Result.HasExitCode);
        Assert.Equal(0, task.CurrentAttempt.Result.ExitCode);
        var journal = node.Runtime.Journal;
        var generationStart = new EventCursor(journal.Generation, journal.GenerationStart - 1).ToString();
        var events = await EventsSinceAsync(channel, generationStart);
        var changes = events.Where(item => item.Attempt is not null).Select(item => item.Attempt).ToArray();
        Assert.NotEmpty(changes);
        Assert.Equal(AttemptState.Starting, changes[0].Attempt.State);
        Assert.False(changes[0].HasPreviousState, "Recovery must preserve the recorded STARTING phase.");
        var finalizing = Assert.Single(changes, change => change.Attempt.State == AttemptState.Finalizing);
        Assert.Null(finalizing.Attempt.Result);
        Assert.Equal(AttemptState.Finalizing, changes[^1].PreviousState);
        Assert.Equal(AttemptState.Finished, changes[^1].Attempt.State);
        AssertStateMachines(events, [new ManagedTask { TaskId = taskId, State = TaskState.Running, Revision = new() }]);
    }

    [Theory]
    [InlineData(AttemptState.Running, TerminationReason.Exited, EffectCertainty.Happened, false)]
    [InlineData(AttemptState.Stopping, TerminationReason.Cancelled, EffectCertainty.Happened, false)]
    [InlineData(AttemptState.Starting, TerminationReason.SpawnFailed, EffectCertainty.Happened, false)]
    [InlineData(AttemptState.Starting, TerminationReason.SpawnFailed, EffectCertainty.DidNotHappen, true)]
    [InlineData(AttemptState.Starting, TerminationReason.PolicyDenied, EffectCertainty.DidNotHappen, true)]
    [InlineData(AttemptState.Running, TerminationReason.Lost, EffectCertainty.Happened, false)]
    [InlineData(AttemptState.Running, TerminationReason.Lost, EffectCertainty.Unknown, true)]
    [InlineData(AttemptState.Finalizing, TerminationReason.Exited, EffectCertainty.Happened, true)]
    public void FinishedEdgesRequireTheirDeclaredTriggerAndEffect(AttemptState previous, TerminationReason reason, EffectCertainty effect, bool allowed) =>
        Assert.Equal(allowed, FinishedTrigger(previous, reason, effect));

    [Theory]
    [InlineData(AttemptState.Running, TerminationReason.Cancelled, EffectCertainty.Happened, false)]
    [InlineData(AttemptState.Stopping, TerminationReason.Cancelled, EffectCertainty.Happened, true)]
    [InlineData(AttemptState.Stopping, TerminationReason.Cancelled, EffectCertainty.Unknown, false)]
    [InlineData(AttemptState.Running, TerminationReason.Lost, EffectCertainty.Unknown, true)]
    [InlineData(AttemptState.Stopping, TerminationReason.Lost, EffectCertainty.Unknown, true)]
    [InlineData(AttemptState.Running, TerminationReason.Lost, EffectCertainty.Happened, false)]
    [InlineData(AttemptState.Finalizing, TerminationReason.Exited, EffectCertainty.Happened, false)]
    [InlineData(AttemptState.Starting, TerminationReason.SpawnFailed, EffectCertainty.DidNotHappen, false)]
    public void AdoptedFinishedEdgesRequireTheAdoptionTriggerAndEffect(AttemptState previous, TerminationReason reason, EffectCertainty effect, bool allowed) =>
        Assert.Equal(allowed, FinishedTrigger(previous, reason, effect, AttemptKind.Adopted));

    private static bool FinishedTrigger(AttemptState previous, TerminationReason reason, EffectCertainty effect, AttemptKind kind = AttemptKind.Local) =>
        kind == AttemptKind.Adopted
            ? (previous == AttemptState.Stopping && reason == TerminationReason.Cancelled && effect == EffectCertainty.Happened)
                || (previous is AttemptState.Running or AttemptState.Stopping && reason == TerminationReason.Lost && effect == EffectCertainty.Unknown)
            : ManagedFinishedTrigger(previous, reason, effect);

    private static bool ManagedFinishedTrigger(AttemptState previous, TerminationReason reason, EffectCertainty effect) =>
        previous is AttemptState.Finalizing or AttemptState.Finished
        || (reason == TerminationReason.Lost && effect == EffectCertainty.Unknown)
        || (previous == AttemptState.Starting && reason is TerminationReason.SpawnFailed or TerminationReason.PolicyDenied && effect == EffectCertainty.DidNotHappen);

    private static async Task RunAsync(Operation[] operations)
    {
        var model = new List<Modelled>();
        await using var node = InProcessNode.Create(seed: transaction =>
        {
            var owner = new ActorRef { Origin = Origin.Human };
            model.Add(new Modelled(LegacyTaskHistoryFixture.SeedQueued(transaction, owner), TaskState.Queued, 0));
            model.Add(new Modelled(LegacyTaskHistoryFixture.SeedQueued(transaction, owner), TaskState.Queued, 0));
        });
        var (succeeded, _) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished);
        var (lost, lostAttempt) = LegacyTaskHistoryFixture.Seed(node, AttemptState.Finished, stateReason: "container_missing");
        // This model starts after the old node settled the lost attempt. It needs no native scope to recover.
        using (var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = BootIdentity.Read(), Clock = node.Clock }))
        {
            store.Write(transaction =>
            {
                transaction.Execute("UPDATE task SET state = $lost WHERE task_id = $id;",
                    ("$lost", (int)TaskState.Lost), ("$id", lost.Value.ToByteArray()));
                transaction.Execute("UPDATE attempt SET termination_reason = $lost, effect = $unknown, exit_code = NULL WHERE attempt_id = $id;",
                    ("$lost", (int)TerminationReason.Lost), ("$unknown", (int)EffectCertainty.Unknown), ("$id", lostAttempt.Value.ToByteArray()));
            }, CommitDurability.Full);
        }

        model.Add(new Modelled(succeeded, TaskState.Succeeded, 1));
        model.Add(new Modelled(lost, TaskState.Lost, 1));
        await node.StartAsync();
        try
        {
            await RunAsync(node, operations, model);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            throw new InvalidOperationException(exception.Message + Environment.NewLine + Diagnose(node), exception);
        }
    }

    private static async Task RunAsync(InProcessNode node, Operation[] operations, List<Modelled> model)
    {
        await using var channel = await node.ChannelAsync(helloAsHuman: true);
        var cursor = await StartCursorAsync(channel);
        await AssertModelAsync(channel, model);
        var baseline = await Task.WhenAll(model.Select(task => Tasks.GetAsync(channel, task.Id)));
        var historicalLoss = Assert.Single(baseline, task => task.State == TaskState.Lost).CurrentAttempt;
        Assert.Equal(AttemptState.Finished, historicalLoss.State);
        Assert.Equal((TerminationReason.Lost, EffectCertainty.Unknown), (historicalLoss.Result.TerminationReason, historicalLoss.Result.Effect));
        Assert.False(historicalLoss.Result.HasExitCode);
        foreach (var operation in operations)
        {
            switch (operation)
            {
                case Submit:
                    var submitted = await Tasks.SubmitRawAsync(channel, Tasks.Argv(node.Root, Path.Combine(node.Root, "fixture-never-starts")));
                    Assert.Null(submitted.Value);
                    AssertLegacyAdmissionRefused(submitted.Error);
                    break;
                case Cancel cancel:
                    var index = cancel.Index % model.Count;
                    var target = model[index];
                    var expected = target.State == TaskState.Queued ? TaskState.Cancelled : target.State;
                    var cancelled = await CancelAsync(channel, target.Id);
                    Assert.Null(cancelled.Error);
                    Assert.Equal(expected, cancelled.Value.State);
                    model[index] = target with { State = expected };
                    break;
                case Retry retry:
                    var response = await channel.Tasks.RetryTaskAsync(new TaskServiceRetryTaskRequest
                    {
                        Meta = Tasks.Meta(),
                        TaskId = model[retry.Index % model.Count].Id,
                    }, cancellationToken: Ct);
                    Assert.Null(response.Value);
                    AssertLegacyAdmissionRefused(response.Error);
                    break;
            }

            await AssertModelAsync(channel, model);
            Assert.Equal((long)model.Count, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task;")));
            Assert.Equal((long)model.Sum(task => task.Attempts), node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM attempt;")));
        }

        var events = await EventsSinceAsync(channel, cursor);
        Assert.DoesNotContain(events, item => item.Attempt is not null);
        AssertStateMachines(events, baseline);
        Assert.Equal(historicalLoss, (await Tasks.GetAsync(channel, historicalLoss.TaskId)).CurrentAttempt);
    }

    private static void AssertLegacyAdmissionRefused(ArcError error)
    {
        Assert.Equal("operation_failed", error.Code);
        Assert.Equal("LEGACY_DRAIN", error.Details.State.State);
        Assert.Equal("legacy_task_outcome_unavailable", error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
    }

    /// <summary>The node's execution log and each attempt's files (exit record, launch record), for a failure message.</summary>
    private static string Diagnose(InProcessNode node)
    {
        var text = new System.Text.StringBuilder();
        var log = Path.Combine(node.DataRoot, "logs", "node", "node.log");
        if (File.Exists(log))
        {
            text.AppendLine("node log (execution):");
            foreach (var line in Tasks.ReadShared(log).Split('\n').Where(line => line.Contains("\"execution.", StringComparison.Ordinal)).TakeLast(40))
            {
                text.AppendLine("  " + line.TrimEnd());
            }
        }

        foreach (var attempt in InProcessNode.AttemptNames(node.Runtime.Store))
        {
            var files = new ArcForges.Node.Platform.AttemptFiles(node.DataRoot, attempt);
            text.AppendLine(System.Globalization.CultureInfo.InvariantCulture, $"attempt {attempt}: exit {Tasks.ReadShared(files.ExitPath).Trim()}; launch {Tasks.ReadShared(files.LaunchPath).Trim()}");
        }

        return text.ToString();
    }

    private sealed record Modelled(Id Id, TaskState State, int Attempts);

    private static async Task AssertModelAsync(NodeChannel channel, List<Modelled> model)
    {
        foreach (var task in model)
        {
            var actual = await Tasks.GetAsync(channel, task.Id);
            Assert.Equal((task.State, (uint)task.Attempts), (actual.State, actual.AttemptCount));
        }
    }

    private static async Task<TaskServiceCancelTaskResponse> CancelAsync(NodeChannel channel, Id id) =>
        await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "model" }, cancellationToken: Ct);

    internal static async Task<string> StartCursorAsync(NodeChannel channel)
    {
        using var call = channel.Events.Subscribe(new NodeEventServiceSubscribeRequest { Topics = { EventTopic.Tasks } }, cancellationToken: Ct);
        while (await call.ResponseStream.MoveNext(Ct))
        {
            if (call.ResponseStream.Current.FrameCase == NodeEventServiceSubscribeFrame.FrameOneofCase.SnapshotComplete)
            {
                return call.ResponseStream.Current.Position.Cursor;
            }
        }

        throw new InvalidOperationException("The subscription ended before its snapshot completed.");
    }

    internal static async Task<List<NodeEvent>> EventsSinceAsync(NodeChannel channel, string cursor)
    {
        var events = new List<NodeEvent>();
        while (true)
        {
            var page = await channel.Events.ListEventsAsync(new NodeEventServiceListEventsRequest { Topics = { EventTopic.Tasks }, Cursor = cursor, Limit = 1000 },
                deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: Ct);
            Assert.Null(page.Error);
            Assert.False(page.Value.ResetRequired, "The journal no longer holds the sequence's events.");
            if (page.Value.Events.Count == 0)
            {
                return events;
            }

            events.AddRange(page.Value.Events);
            cursor = page.Value.Position.Cursor;
        }
    }

    internal static void AssertStateMachines(List<NodeEvent> events, IReadOnlyList<ManagedTask>? baseline = null)
    {
        Assert.Equal(events.Select(item => item.Seq).Order(), events.Select(item => item.Seq));
        Assert.Equal(events.Count, events.Select(item => item.Seq).Distinct().Count());
        var tasks = new Dictionary<string, (TaskState State, long Revision)>(StringComparer.Ordinal);
        var attempts = new Dictionary<string, (AttemptState State, long Revision)>(StringComparer.Ordinal);
        foreach (var task in baseline ?? [])
        {
            tasks.Add(IdText.Format(task.TaskId), (task.State, task.Revision.Value));
            if (task.CurrentAttempt is { } attempt)
            {
                attempts.Add(IdText.Format(attempt.AttemptId), (attempt.State, attempt.Revision.Value));
            }
        }

        foreach (var item in events)
        {
            if (item.Task is { } changed)
            {
                var key = IdText.Format(changed.Task.TaskId);
                var adopted = changed.Task.CurrentAttempt?.Kind == AttemptKind.Adopted;
                Check(tasks, key, changed.HasPreviousState ? changed.PreviousState : (TaskState?)null, changed.Task.State, changed.Task.Revision.Value,
                    adopted ? Pairs(([TaskState.Running], TaskState.Cancelled), ([TaskState.Running], TaskState.Lost)) : TaskTransitions,
                    adopted ? [TaskState.Running] : [TaskState.Queued, TaskState.WaitingDependency], $"task {key} (seq {item.Seq})");
            }
            else if (item.Attempt is { } attempt)
            {
                var key = IdText.Format(attempt.Attempt.AttemptId);
                if (attempt.Attempt.State == AttemptState.Finished)
                {
                    Assert.NotNull(attempt.Attempt.Result);
                    Assert.True(attempt.HasPreviousState && FinishedTrigger(attempt.PreviousState, attempt.Attempt.Result.TerminationReason, attempt.Attempt.Result.Effect, attempt.Attempt.Kind),
                        $"attempt {key} (seq {item.Seq}): {attempt.PreviousState} -> FINISHED has no matching trigger/effect: {attempt.Attempt.Result}");
                }

                var adopted = attempt.Attempt.Kind == AttemptKind.Adopted;
                Check(attempts, key, attempt.HasPreviousState ? attempt.PreviousState : (AttemptState?)null, attempt.Attempt.State, attempt.Attempt.Revision.Value,
                    adopted ? Pairs(([AttemptState.Running], AttemptState.Stopping), ([AttemptState.Running, AttemptState.Stopping], AttemptState.Finished)) : AttemptTransitions,
                    adopted ? [AttemptState.Running] : [AttemptState.Created, AttemptState.Starting], $"attempt {key} (seq {item.Seq})");
            }
        }
    }

    /// <summary>One reported state: allowed from the last reported one, its revision not older; the first one is initial.</summary>
    private static void Check<TState>(Dictionary<string, (TState State, long Revision)> seen, string key, TState? previous, TState state, long revision,
        HashSet<(TState, TState)> allowed, TState[] initial, string what)
        where TState : struct, Enum
    {
        if (seen.TryGetValue(key, out var last))
        {
            Assert.True(revision >= last.Revision, $"{what}: revision {revision} after {last.Revision} (events out of order).");
            if (previous is { } reported)
            {
                Assert.True(EqualityComparer<TState>.Default.Equals(reported, last.State), $"{what}: reports {reported} -> {state}, but the stream last reported {last.State}.");
            }

            Assert.True(EqualityComparer<TState>.Default.Equals(last.State, state) || allowed.Contains((last.State, state)),
                $"{what}: {last.State} -> {state} is not a transition of the state machine.");
        }
        else
        {
            Assert.True(initial.Contains(state) && previous is null, $"{what}: first reported in {state}.");
        }

        seen[key] = (state, revision);
    }

    private static HashSet<(TState, TState)> Pairs<TState>(params (TState[] From, TState To)[] transitions) =>
        [.. transitions.SelectMany(transition => transition.From.Select(from => (from, transition.To)))];
}
