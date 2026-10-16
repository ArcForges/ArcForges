// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Tests;
using CsCheck;
using Grpc.Core;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// The task and attempt lifecycles, model-based against a real node in the test process with real attempts (Windows jobs and holders, or
/// Linux units): generated sequences of submissions (exiting 0, exiting non-zero, or running until cancelled), cancels (also at once,
/// while the attempt is still being created) and manual retries. After each operation the node agrees with a small model (state and
/// attempt count; a refused retry changes nothing, a cancel of a finished task changes nothing), and the TASKS event stream obeys the
/// state machines of ArcForges-Design <c>state-machines/machines.json</c>: every reported change is a transition SM-TASK or SM-ATTEMPT
/// allows (or no state change), its previous state is the state the stream reported last, the first state of a task or attempt is an
/// initial one, and per task and attempt the revision never goes back in sequence order (an event may repeat a revision: a task view
/// also changes with its attempt).
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

        // Not in machines.json (an open Design question): a cancel while the attempt is being launched moves it from STARTING to STOPPING,
        // which persists the cancel across a node restart (the recovery continues a STOPPING attempt's stop).
        ([AttemptState.Starting], AttemptState.Stopping),
        ([AttemptState.Running], AttemptState.Finalizing),
        ([AttemptState.Stopping], AttemptState.Finalizing),
        ([AttemptState.Created], AttemptState.Finalizing),
        ([AttemptState.Finalizing], AttemptState.Finished),
        ([AttemptState.Created, AttemptState.Transferring, AttemptState.Starting, AttemptState.Running, AttemptState.Pausing, AttemptState.Paused,
            AttemptState.Stopping, AttemptState.Finalizing], AttemptState.Finished));

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>One operation of a sequence; indexes pick an existing task modulo the number of tasks.</summary>
    private abstract record Operation;

    private sealed record SubmitExiting(int Code) : Operation;

    private sealed record SubmitRunning : Operation;

    private sealed record SubmitAndCancelAtOnce : Operation;

    private sealed record Cancel(int Index) : Operation;

    private sealed record Retry(int Index) : Operation;

    private static readonly Gen<Operation> AnyOperation = Gen.Frequency(
        (3, Gen.Int[0, 3].Select(code => (Operation)new SubmitExiting(code == 3 ? 0 : code))),
        (2, Gen.Const((Operation)new SubmitRunning())),
        (1, Gen.Const((Operation)new SubmitAndCancelAtOnce())),
        (3, Gen.Int[0, 7].Select(index => (Operation)new Cancel(index))),
        (3, Gen.Int[0, 7].Select(index => (Operation)new Retry(index))));

    [Fact(Timeout = 600_000)]
    public async Task TaskAndAttemptStatesFollowTheStateMachinesAndTheModel()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
        {
            Assert.SkipWhen(ArcForges.Tests.SystemdTestEnvironment.SkipReason is not null, ArcForges.Tests.SystemdTestEnvironment.SkipReason ?? string.Empty);
        }

        await AnyOperation.Array[3, 9].SampleAsync(RunAsync, iter: PropertyRuns.Iter(4), threads: 1,
            print: operations => string.Join(", ", operations.Select(operation => operation.ToString())));
    }

    private static async Task RunAsync(Operation[] operations)
    {
        await using var node = await InProcessNode.Create().StartAsync();
        try
        {
            await RunAsync(node, operations);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // What the node recorded about its attempts, for a failure that only load reproduces.
            throw new InvalidOperationException(exception.Message + Environment.NewLine + Diagnose(node), exception);
        }
    }

    private static async Task RunAsync(InProcessNode node, Operation[] operations)
    {
        await using var channel = await node.ChannelAsync();
        var cursor = await StartCursorAsync(channel);
        var model = new List<Modelled>();
        foreach (var operation in operations)
        {
            switch (operation)
            {
                case SubmitExiting submit:
                    model.Add(await RunToEndAsync(channel, new Modelled(await Tasks.SubmitAsync(channel, Exiting(node, submit.Code)), submit.Code)));
                    break;
                case SubmitRunning:
                    var running = new Modelled(await Tasks.SubmitAsync(channel, Running(node, model.Count)), null);
                    await Tasks.RunningAsync(channel, running.Id);
                    model.Add(running with { State = TaskState.Running, Attempts = 1 });
                    break;
                case SubmitAndCancelAtOnce:
                    // Cancelled while queued or while its attempt is being created: no attempt, or one that never reaches the workload's end.
                    var cancelled = new Modelled(await Tasks.SubmitAsync(channel, Running(node, model.Count)), null);
                    Assert.Null((await CancelAsync(channel, cancelled.Id)).Error);
                    var ended = await Tasks.WaitAsync(channel, cancelled.Id);
                    Assert.True(ended.State == TaskState.Cancelled, $"Cancelled at once, the task ended {ended.State}: {ended.CurrentAttempt?.Result}");
                    model.Add(cancelled with { State = TaskState.Cancelled, Attempts = (int)ended.AttemptCount });
                    break;
                case Cancel cancel when model.Count > 0:
                    var target = model[cancel.Index % model.Count];
                    Assert.Null((await CancelAsync(channel, target.Id)).Error);
                    if (target.State == TaskState.Running)
                    {
                        Assert.Equal(TaskState.Cancelled, (await Tasks.WaitAsync(channel, target.Id)).State);
                        model[model.IndexOf(target)] = target with { State = TaskState.Cancelled };
                    }

                    break;
                case Retry retry when model.Count > 0:
                    var retried = model[retry.Index % model.Count];
                    var response = await channel.Tasks.RetryTaskAsync(new TaskServiceRetryTaskRequest { Meta = Tasks.Meta(), TaskId = retried.Id }, cancellationToken: Ct);
                    if (retried.State is TaskState.Failed or TaskState.Cancelled)
                    {
                        Assert.Null(response.Error);
                        var again = retried with { State = TaskState.Queued, Attempts = retried.Attempts + 1 };
                        if (retried.Code is null)
                        {
                            await Tasks.RunningAsync(channel, again.Id);
                            again = again with { State = TaskState.Running };
                        }
                        else
                        {
                            again = await RunToEndAsync(channel, again);
                        }

                        model[model.IndexOf(retried)] = again;
                    }
                    else
                    {
                        // SUCCEEDED and RUNNING tasks cannot be retried (SM-TASK); the refusal changes nothing.
                        Assert.Equal("invalid_state", response.Error?.Code);
                    }

                    break;
            }

            await AssertModelAsync(channel, model);
        }

        foreach (var task in model.Where(task => task.State == TaskState.Running))
        {
            await CancelAsync(channel, task.Id);
            await Tasks.WaitAsync(channel, task.Id);
        }

        AssertStateMachines(await EventsSinceAsync(channel, cursor));
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

    /// <summary>What the model knows of a task: its workload (an exit code, or null for one that runs until cancelled), state and attempts.</summary>
    private sealed record Modelled(Id Id, int? Code, TaskState State = TaskState.Queued, int Attempts = 0);

    private static async Task<Modelled> RunToEndAsync(NodeChannel channel, Modelled task)
    {
        var ended = await Tasks.WaitAsync(channel, task.Id);
        var expected = task.Code == 0 ? TaskState.Succeeded : TaskState.Failed;
        Assert.Equal(expected, ended.State);
        Assert.Equal(task.Code, ended.CurrentAttempt.Result.ExitCode);
        return task with { State = expected, Attempts = task.Attempts == 0 ? 1 : task.Attempts };
    }

    private static async Task AssertModelAsync(NodeChannel channel, List<Modelled> model)
    {
        foreach (var task in model)
        {
            var actual = await Tasks.GetAsync(channel, task.Id);
            Assert.Equal((task.State, (uint)task.Attempts), (actual.State, actual.AttemptCount));
        }
    }

    private static TaskSpec Exiting(InProcessNode node, int code) => OperatingSystem.IsWindows()
        ? Tasks.Argv(node.Root, Tasks.Cmd, "/d", "/c", "exit " + code.ToString(System.Globalization.CultureInfo.InvariantCulture))
        : Tasks.Argv(node.Root, "/bin/sh", "-c", "exit " + code.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private static TaskSpec Running(InProcessNode node, int index) => OperatingSystem.IsWindows()
        ? Tasks.Argv(node.Root, Tasks.TestLoad, "signal", "--hold-ms", "120000", "--marker", Path.Combine(node.Root, "running-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".txt"))
        : Tasks.Argv(node.Root, "/bin/sleep", "120");

    private static async Task<TaskServiceCancelTaskResponse> CancelAsync(NodeChannel channel, Id id) =>
        await channel.Tasks.CancelTaskAsync(new TaskServiceCancelTaskRequest { Meta = Tasks.Meta(), TaskId = id, Reason = "model" }, cancellationToken: Ct);

    private static async Task<string> StartCursorAsync(NodeChannel channel)
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

    private static async Task<List<NodeEvent>> EventsSinceAsync(NodeChannel channel, string cursor)
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

    private static void AssertStateMachines(List<NodeEvent> events)
    {
        Assert.Equal(events.Select(item => item.Seq).Order(), events.Select(item => item.Seq));
        Assert.Equal(events.Count, events.Select(item => item.Seq).Distinct().Count());
        var tasks = new Dictionary<string, (TaskState State, long Revision)>(StringComparer.Ordinal);
        var attempts = new Dictionary<string, (AttemptState State, long Revision)>(StringComparer.Ordinal);
        foreach (var item in events)
        {
            if (item.Task is { } changed)
            {
                var key = IdText.Format(changed.Task.TaskId);
                Check(tasks, key, changed.HasPreviousState ? changed.PreviousState : (TaskState?)null, changed.Task.State, changed.Task.Revision.Value, TaskTransitions,
                    [TaskState.Queued, TaskState.WaitingDependency], $"task {key} (seq {item.Seq})");
            }
            else if (item.Attempt is { } attempt)
            {
                var key = IdText.Format(attempt.Attempt.AttemptId);
                Check(attempts, key, attempt.HasPreviousState ? attempt.PreviousState : (AttemptState?)null, attempt.Attempt.State, attempt.Attempt.Revision.Value, AttemptTransitions,
                    [AttemptState.Created, AttemptState.Starting], $"attempt {key} (seq {item.Seq})");
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
            Assert.True(initial.Contains(state) || (previous is { } reported && allowed.Contains((reported, state))), $"{what}: first reported in {state}.");
        }

        seen[key] = (state, revision);
    }

    private static HashSet<(TState, TState)> Pairs<TState>(params (TState[] From, TState To)[] transitions) =>
        [.. transitions.SelectMany(transition => transition.From.Select(from => (from, transition.To)))];
}
