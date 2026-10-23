// SPDX-License-Identifier: AGPL-3.0-only
using System.CommandLine;
using System.Globalization;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges tasks ...</c> (experience/cli.md C-01): list, show, wait, attach, logs, cancel, retry, priority, pause, resume, pin, unpin, purge and attempts.
/// IDs accept the full base32 ID or a unique prefix of at least 6 characters. <c>tasks wait</c> prints the output of a finished task
/// (default the last 4 KiB) and exits with its exit code, or 9 when the target was not reached before <c>--timeout</c> (the global
/// option is the wait's timeout here). <c>timeline</c> belongs to a later task.
/// </summary>
internal static class TaskCommands
{
    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var tasks = new Command("tasks", "List, inspect, wait for and control tasks");
        tasks.Subcommands.Add(List(factory));
        tasks.Subcommands.Add(Show(factory));
        tasks.Subcommands.Add(Wait(factory));
        tasks.Subcommands.Add(Attach(factory));
        tasks.Subcommands.Add(Logs(factory));
        tasks.Subcommands.Add(Cancel(factory));
        tasks.Subcommands.Add(Retry(factory));
        tasks.Subcommands.Add(SetPriority(factory));
        tasks.Subcommands.Add(Pause(factory, pause: true));
        tasks.Subcommands.Add(Pause(factory, pause: false));
        tasks.Subcommands.Add(Pin(factory, pinned: true));
        tasks.Subcommands.Add(Pin(factory, pinned: false));
        tasks.Subcommands.Add(Purge(factory));
        tasks.Subcommands.Add(Attempts(factory));
        return tasks;
    }

    /// <summary>
    /// Waits for a task (<c>WaitTask</c> in calls of at most 55 s) until <paramref name="target"/> or <paramref name="budget"/>; a finished
    /// task's output is printed (<paramref name="output"/>: tail, all or none) and its exit code returned; 9 when not reached.
    /// </summary>
    public static async Task<int> WaitAsync(Cli cli, NodeSession session, Id taskId, WaitTarget target, TimeSpan budget, string output,
        CancellationToken cancellationToken)
    {
        var started = TimeProvider.System.GetTimestamp();
        while (true)
        {
            var remaining = budget - TimeProvider.System.GetElapsedTime(started);
            var waitMs = (ulong)Math.Clamp(remaining.TotalMilliseconds, 0, 55_000);
            var request = new TaskServiceWaitTaskRequest { Meta = Cli.Meta(), TaskId = taskId, Target = target, WaitMs = waitMs };
            var response = await cli.CallAsync("WaitTask", request.Meta, () => session.Channel.Tasks.WaitTaskAsync(request,
                deadline: DateTime.UtcNow.AddMilliseconds(waitMs + 5_000), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            var task = response.Value.Task;
            if (response.Value.Reached)
            {
                if (target != WaitTarget.Terminal)
                {
                    if (cli.Output.Json)
                    {
                        cli.Output.Document(task);
                    }
                    else
                    {
                        cli.Output.Line(TaskText.Word(task.State));
                    }

                    return ExitCodes.Success;
                }

                if (cli.Output.Json)
                {
                    cli.Output.Document(task);
                }
                else
                {
                    await PrintOutputAsync(cli, session, task, output, cancellationToken).ConfigureAwait(false);
                }

                return TaskText.ExitCode(task.CurrentAttempt?.Result, cli.Output);
            }

            if (TimeProvider.System.GetElapsedTime(started) >= budget)
            {
                var position = task.Queue is { HasPosition: true } queue ? $", queue position {queue.Position}" : string.Empty;
                cli.Output.Error.WriteLine($"arcforges: task {IdText.Format(taskId)} is {TaskText.Word(task.State)}{position}; the wait ended before it reached {target.ToString().ToUpperInvariant()}");
                if (cli.Output.Json)
                {
                    cli.Output.Document(task);
                }

                return TaskText.WaitNotReached;
            }
        }
    }

    private static Command List(Func<ParseResult, Cli> factory)
    {
        var state = new Option<string[]>("--state") { Description = "Only tasks in this state (repeatable)", HelpName = "s" };
        state.AcceptOnlyFromAmong([.. TaskText.States.Keys]);
        var pool = new Option<string?>("--pool") { Description = "Only tasks of this pool", HelpName = "p" };
        var label = new Option<string[]>("--label") { Description = "Only tasks with this label (repeatable)", HelpName = "k=v" };
        var since = new Option<string?>("--since") { Description = "Only tasks created within this period (for example 2h)", HelpName = "dur" };
        var limit = new Option<int?>("--limit") { Description = "At most this many tasks (1..500; default 100)", HelpName = "n" };
        var command = new Command("list", "List tasks, newest first") { state, pool, label, since, limit };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var filter = new TaskFilter();
            filter.States.Add((result.GetValue(state) ?? []).Select(name => TaskText.States[name]).Distinct());
            if (result.GetValue(pool) is { } poolName)
            {
                filter.Pool = poolName;
            }

            foreach (var pair in result.GetValue(label) ?? [])
            {
                var equals = pair.IndexOf('=', StringComparison.Ordinal);
                if (equals <= 0)
                {
                    throw new UsageException($"--label: '{pair}' is not k=v.");
                }

                filter.Labels[pair[..equals]] = pair[(equals + 1)..];
            }

            if (result.GetValue(since) is { } sinceText)
            {
                filter.CreatedAfter = ProtoTime.ToInstant(DateTimeOffset.UtcNow - (Durations.TryParse(sinceText, out var period)
                    ? period
                    : throw new UsageException($"--since: '{sinceText}' is not a duration.")));
            }

            var request = new TaskServiceListTasksRequest { Meta = Cli.Meta(), Filter = filter };
            if (result.GetValue(limit) is { } count)
            {
                request.Page = new PageRequest { Limit = count };
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var response = await cli.CallAsync("ListTasks", request.Meta, () => session.Channel.Tasks.ListTasksAsync(request,
                deadline: cli.Deadline(TaskText.Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            if (response.Value.Tasks.Count == 0)
            {
                cli.Output.Line("No tasks.");
                return ExitCodes.Success;
            }

            cli.Output.Table(["ID", "STATE", "EXIT", "POOL", "CREATED", "COMMAND"],
                [.. response.Value.Tasks.Select(task => (IReadOnlyList<string>)[IdText.Format(task.TaskId), TaskText.Word(task.State), Exit(task),
                    task.Pool, CliOutput.When(task.CreatedAt), task.Title])]);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Show(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var full = new Option<bool>("--full") { Description = "Include the stored specification (secret-shaped values are omitted)" };
        var command = new Command("show", "Show one task") { id, full };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            var request = new TaskServiceGetTaskRequest { Meta = Cli.Meta(), TaskId = taskId, Detail = result.GetValue(full) ? TaskDetail.Full : TaskDetail.Summary };
            var response = await cli.CallAsync("GetTask", request.Meta, () => session.Channel.Tasks.GetTaskAsync(request,
                deadline: cli.Deadline(TaskText.Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            var task = response.Value.Task;
            var rows = new List<(string Key, string Value)>
            {
                ("task", IdText.Format(task.TaskId)),
                ("state", TaskText.Word(task.State) + (task.HasStateReason ? $" ({task.StateReason})" : string.Empty)),
                ("title", task.Title),
                ("command", task.CommandSummary),
                ("pool", task.Pool),
                ("priority", task.EffectivePriority.ToString().ToUpperInvariant()),
                ("side effect", task.SideEffect.ToString().ToUpperInvariant() + " (" + task.SideEffectSource.ToString().ToLowerInvariant() + ")"),
                ("created", CliOutput.When(task.CreatedAt)),
                ("started", CliOutput.When(task.StartedAt)),
                ("finished", CliOutput.When(task.FinishedAt)),
                ("attempts", task.AttemptCount.ToString(CultureInfo.InvariantCulture)),
                ("pinned", task.Pinned ? "yes" : "no"),
            };
            if (task.Queue is { } queue)
            {
                rows.Add(("queue", $"position {queue.Position} ({queue.BlockingReason})"));
            }

            if (task.CurrentAttempt is { } attempt)
            {
                rows.Add(("attempt", $"{IdText.Format(attempt.AttemptId)} #{attempt.Number} {attempt.State.ToString().ToUpperInvariant()}" + (attempt.NodeGap ? " (node gap)" : string.Empty)));
                if (attempt.Result is { } attemptResult)
                {
                    rows.Add(("result", TaskText.Word(attemptResult.TerminationReason) + (attemptResult.HasExitCode ? $", exit {attemptResult.ExitCode}" : string.Empty)
                        + (attempt.HasLimitEnforcedBy ? $", stopped by {attempt.LimitEnforcedBy}" : string.Empty)));
                    if (attemptResult.HasDetail && attemptResult.Detail.Length > 0)
                    {
                        rows.Add(("detail", attemptResult.Detail));
                    }
                }

                if (attempt.Usage is { } usage)
                {
                    rows.Add(("usage", $"cpu {usage.CpuTimeMs} ms, peak commit {TaskText.Bytes(usage.MemPeakBytes)}"));
                }
            }

            foreach (var (key, value) in task.Labels)
            {
                rows.Add(("label " + key, value));
            }

            cli.Output.KeyValues(rows);
            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Wait(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var target = new Option<string?>("--for") { Description = "terminal (default), started or ready", HelpName = "target" };
        target.AcceptOnlyFromAmong("terminal", "started", "ready");
        var output = new Option<string?>("--output") { Description = "tail (default: the last 4 KiB), all or none", HelpName = "what" };
        output.AcceptOnlyFromAmong("tail", "all", "none");
        var command = new Command("wait", "Wait for a task; print its output and exit with its exit code (9 when the wait ends first)") { id, target, output };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            var waitTarget = result.GetValue(target) switch
            {
                "started" => WaitTarget.Started,
                "ready" => WaitTarget.Ready,
                _ => WaitTarget.Terminal,
            };
            return await WaitAsync(cli, session, taskId, waitTarget, cli.Timeout ?? TimeSpan.FromDays(30), result.GetValue(output) ?? "tail", cancellationToken)
                .ConfigureAwait(false);
        });
        return command;
    }

    private static Command Attach(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var fromStart = new Option<bool>("--from-start") { Description = "Mirror the output from the beginning" };
        var command = new Command("attach", "Mirror a task's output until it finishes (detaching never stops it)") { id, fromStart };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            return taskId is null
                ? exit
                : await RunCommand.AttachAsync(cli, session, taskId, forwardStdin: false, handoffAt: null, result.GetValue(fromStart), cancellationToken).ConfigureAwait(false);
        });
        return command;
    }

    private static Command Logs(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var attemptNumber = new Option<int?>("--attempt") { Description = "The attempt number (default: the current attempt)", HelpName = "n" };
        var stream = new Option<string?>("--stream") { Description = "stdout, stderr or merged (default)", HelpName = "s" };
        stream.AcceptOnlyFromAmong("stdout", "stderr", "merged");
        var follow = new Option<bool>("--follow") { Description = "Keep printing new output until the attempt finishes" };
        var tail = new Option<int?>("--tail") { Description = "Only the last n lines", HelpName = "n" };
        var command = new Command("logs", "Print a task's captured output") { id, attemptNumber, stream, follow, tail };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            var list = new TaskServiceListAttemptsRequest { Meta = Cli.Meta(), TaskId = taskId };
            var attempts = await cli.CallAsync("ListAttempts", list.Meta, () => session.Channel.Tasks.ListAttemptsAsync(list,
                deadline: cli.Deadline(TaskText.Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (attempts.Error is { } error)
            {
                return cli.Output.Fail(error, list.Meta.CorrelationId);
            }

            var attempt = result.GetValue(attemptNumber) is { } number
                ? attempts.Value.Attempts.FirstOrDefault(item => item.Number == number)
                : attempts.Value.Attempts.LastOrDefault();
            if (attempt is null)
            {
                cli.Output.Error.WriteLine("error: the task has no such attempt (STATE/not_found)");
                return ExitCodes.NotFound;
            }

            var which = result.GetValue(stream) switch
            {
                "stdout" => OutputStream.Stdout,
                "stderr" => OutputStream.Stderr,
                _ => OutputStream.Merged,
            };
            using var mirror = new TaskText.Mirror();
            ulong offset = 0;
            if (result.GetValue(tail) is { } lines)
            {
                offset = await TailOffsetAsync(cli, session, attempt.AttemptId, which, lines, cancellationToken).ConfigureAwait(false);
            }

            if (result.GetValue(follow))
            {
                var watch = new TaskServiceWatchTaskOutputRequest { Meta = Cli.Meta(), AttemptId = attempt.AttemptId, Stream = which, FromOffset = offset };
                using var call = session.Channel.Tasks.WatchTaskOutput(watch, cancellationToken: cancellationToken);
                while (await call.ResponseStream.MoveNext(cancellationToken).ConfigureAwait(false))
                {
                    var frame = call.ResponseStream.Current;
                    if (frame.FrameCase == TaskServiceWatchTaskOutputFrame.FrameOneofCase.Output)
                    {
                        mirror.Write(frame.Output.Stream, frame.Output.Data.Span);
                    }
                    else if (frame.FrameCase == TaskServiceWatchTaskOutputFrame.FrameOneofCase.Error)
                    {
                        return cli.Output.Fail(frame.Error, null);
                    }
                    else if (frame.FrameCase == TaskServiceWatchTaskOutputFrame.FrameOneofCase.Result)
                    {
                        break;
                    }
                }

                return ExitCodes.Success;
            }

            while (true)
            {
                var read = new TaskServiceReadTaskOutputRequest { Meta = Cli.Meta(), AttemptId = attempt.AttemptId, Stream = which, FromOffset = offset, MaxBytes = 1024 * 1024 };
                var response = await cli.CallAsync("ReadTaskOutput", read.Meta, () => session.Channel.Tasks.ReadTaskOutputAsync(read,
                    deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken)).ConfigureAwait(false);
                if (response.Error is { } readError)
                {
                    return cli.Output.Fail(readError, read.Meta.CorrelationId);
                }

                Mirror(mirror, response.Value);
                if (response.Value.Data.Length == 0 || response.Value.NextOffset == offset)
                {
                    return ExitCodes.Success;
                }

                offset = response.Value.NextOffset;
            }
        });
        return command;
    }

    private static Command Cancel(Func<ParseResult, Cli> factory)
    {
        var ids = new Argument<string[]>("id") { Arity = ArgumentArity.OneOrMore, Description = "Task IDs or unique prefixes" };
        var reason = new Option<string?>("--reason") { Description = "Why (recorded)" };
        var grace = new Option<string?>("--grace") { Description = "The grace period before the forced phase (0s..300s; default the task's)", HelpName = "dur" };
        var command = new Command("cancel", "Cancel queued or running tasks (graceful phase, grace period, then forced)") { ids, reason, grace };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var worst = ExitCodes.Success;
            foreach (var text in result.GetValue(ids) ?? [])
            {
                var (taskId, exit) = await TaskText.ResolveAsync(cli, session, text, cancellationToken).ConfigureAwait(false);
                if (taskId is null)
                {
                    worst = Math.Max(worst, exit);
                    continue;
                }

                var request = new TaskServiceCancelTaskRequest { Meta = Cli.Meta(), TaskId = taskId };
                if (result.GetValue(reason) is { } why)
                {
                    request.Reason = why;
                }

                if (result.GetValue(grace) is { } graceText)
                {
                    request.GraceMs = graceText is "0" or "0s" ? 0
                        : Durations.TryParse(graceText, out var period) ? (ulong)period.TotalMilliseconds : throw new UsageException($"--grace: '{graceText}' is not a duration.");
                }

                var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
                var response = await cli.MutateAsync("CancelTask", request.Meta.CommandId, action, r => session.Channel.Tasks.CancelTaskAsync(r,
                    deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
                if (response.Error is { } error)
                {
                    worst = Math.Max(worst, cli.Output.Fail(error, request.Meta.CorrelationId));
                    continue;
                }

                if (cli.Output.Json)
                {
                    cli.Output.JsonLine(response.Value);
                }
                else
                {
                    cli.Output.Line($"{IdText.Format(taskId)} {TaskText.Word(response.Value.State)}" + (response.Value.State == TaskState.Running ? " (stopping)" : string.Empty));
                }
            }

            return worst;
        });
        return command;
    }

    private static Command SetPriority(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var priority = new Argument<string?>("class") { Description = "interactive, high, normal, low or background", Arity = ArgumentArity.ZeroOrOne };
        priority.AcceptOnlyFromAmong("interactive", "high", "normal", "low", "background");
        var pool = new Option<string?>("--pool") { Description = "Move the waiting task to this pool", HelpName = "p" };
        var command = new Command("priority", "Change a waiting task's priority class or pool") { id, priority, pool };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var className = result.GetValue(priority);
            var poolName = result.GetValue(pool);
            if (className is null && poolName is null)
            {
                throw new UsageException("give a class, --pool, or both.");
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            var request = new TaskServiceSetTaskPriorityRequest { Meta = Cli.Meta(), TaskId = taskId };
            if (className is not null)
            {
                request.Priority = Enum.Parse<Priority>(className, ignoreCase: true);
            }

            if (poolName is not null)
            {
                request.Pool = poolName;
            }

            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("SetTaskPriority", request.Meta.CommandId, action, r => session.Channel.Tasks.SetTaskPriorityAsync(r,
                deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, null);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
            }
            else
            {
                cli.Output.Line($"{IdText.Format(taskId)} queued at position {response.Value.Queue?.Position ?? 0}");
            }

            return ExitCodes.Success;
        });
        return command;
    }
    private static Command Pause(Func<ParseResult, Cli> factory, bool pause)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var command = new Command(pause ? "pause" : "resume", pause ? "Freeze a running pausable task (Linux)" : "Thaw a paused task") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            if (pause && OperatingSystem.IsWindows())
            {
                cli.Output.Error.WriteLine("error: pause is not supported on Windows (STATE/pause_unsupported)");
                return ExitCodes.Failed;
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            ArcError? error;
            TaskState state;
            Google.Protobuf.IMessage? value;
            if (pause)
            {
                var request = new TaskServicePauseTaskRequest { Meta = Cli.Meta(), TaskId = taskId };
                var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
                var response = await cli.MutateAsync("PauseTask", request.Meta.CommandId, action, r => session.Channel.Tasks.PauseTaskAsync(r,
                    deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
                (error, state, value) = (response.Error, response.Value?.State ?? TaskState.Unspecified, response.Value);
            }
            else
            {
                var request = new TaskServiceResumeTaskRequest { Meta = Cli.Meta(), TaskId = taskId };
                var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
                var response = await cli.MutateAsync("ResumeTask", request.Meta.CommandId, action, r => session.Channel.Tasks.ResumeTaskAsync(r,
                    deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
                (error, state, value) = (response.Error, response.Value?.State ?? TaskState.Unspecified, response.Value);
            }

            if (error is not null)
            {
                return cli.Output.Fail(error, null);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(value!);
            }
            else
            {
                cli.Output.Line($"{IdText.Format(taskId)} {TaskText.Word(state)}");
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Retry(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var mem = new Option<string?>("--mem") { Description = "A larger memory grant for the new attempt (for example 4GiB)", HelpName = "size" };
        var command = new Command("retry", "Start a new attempt of a failed, cancelled or lost task") { id, mem };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            var request = new TaskServiceRetryTaskRequest { Meta = Cli.Meta(), TaskId = taskId };
            if (result.GetValue(mem) is { } size)
            {
                var bytes = RunCommand.Size(size, "--mem");
                request.OverrideDemand = new ResourceDemand { MemExpectedBytes = bytes, MemCeilingBytes = bytes };
            }
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("RetryTask", request.Meta.CommandId, action, r => session.Channel.Tasks.RetryTaskAsync(r,
                deadline: cli.Deadline(TaskText.Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            foreach (var warning in response.Value.Warnings)
            {
                cli.Output.Error.WriteLine("warning: " + warning);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
            }
            else
            {
                cli.Output.Line($"{IdText.Format(taskId)} {TaskText.Word(response.Value.State)}");
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Pin(Func<ParseResult, Cli> factory, bool pinned)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var command = new Command(pinned ? "pin" : "unpin", pinned ? "Keep a task's records and output past retention" : "Let retention apply again") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            var request = new TaskServicePinTaskRequest { Meta = Cli.Meta(), TaskId = taskId, Pinned = pinned };
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("PinTask", request.Meta.CommandId, action, r => session.Channel.Tasks.PinTaskAsync(r,
                deadline: cli.Deadline(TaskText.Unary), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
            }
            else
            {
                cli.Output.Line($"{IdText.Format(taskId)} {(pinned ? "pinned" : "unpinned")}");
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Purge(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var command = new Command("purge", "Delete a finished task's output and detailed records (HUMAN only)") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            if (!cli.Yes && !Console.IsInputRedirected)
            {
                cli.Output.Error.Write($"Delete the output and detailed records of task {IdText.Format(taskId)}? [y/N] ");
                if (!string.Equals(Console.ReadLine()?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                {
                    cli.Output.Error.WriteLine("Nothing was deleted.");
                    return ExitCodes.Failed;
                }
            }

            var request = new TaskServicePurgeTaskRecordRequest { Meta = Cli.Meta(), TaskId = taskId };
            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var response = await cli.MutateAsync("PurgeTaskRecord", request.Meta.CommandId, action, r => session.Channel.Tasks.PurgeTaskRecordAsync(r,
                deadline: cli.Deadline(TimeSpan.FromSeconds(30)), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
            }
            else
            {
                cli.Output.Line($"{IdText.Format(taskId)} purged");
            }

            return ExitCodes.Success;
        });
        return command;
    }

    private static Command Attempts(Func<ParseResult, Cli> factory)
    {
        var id = new Argument<string>("id") { Description = "The task ID or a unique prefix (at least 6 characters)" };
        var command = new Command("attempts", "List a task's attempts, oldest first") { id };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            var (taskId, exit) = await TaskText.ResolveAsync(cli, session, result.GetValue(id)!, cancellationToken).ConfigureAwait(false);
            if (taskId is null)
            {
                return exit;
            }

            var request = new TaskServiceListAttemptsRequest { Meta = Cli.Meta(), TaskId = taskId };
            var response = await cli.CallAsync("ListAttempts", request.Meta, () => session.Channel.Tasks.ListAttemptsAsync(request,
                deadline: cli.Deadline(TaskText.Unary), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is { } error)
            {
                return cli.Output.Fail(error, request.Meta.CorrelationId);
            }

            if (cli.Output.Json)
            {
                cli.Output.Document(response.Value);
                return ExitCodes.Success;
            }

            cli.Output.Table(["#", "ATTEMPT", "STATE", "RESULT", "EXIT", "STARTED", "FINISHED"],
                [.. response.Value.Attempts.Select(attempt => (IReadOnlyList<string>)[attempt.Number.ToString(CultureInfo.InvariantCulture),
                    IdText.Format(attempt.AttemptId), attempt.State.ToString().ToUpperInvariant(),
                    attempt.Result is { } attemptResult ? TaskText.Word(attemptResult.TerminationReason) : "-",
                    attempt.Result is { HasExitCode: true } withCode ? withCode.ExitCode.ToString(CultureInfo.InvariantCulture) : "-",
                    CliOutput.When(attempt.StartedAt), CliOutput.When(attempt.FinishedAt)])]);
            return ExitCodes.Success;
        });
        return command;
    }

    private static async Task PrintOutputAsync(Cli cli, NodeSession session, ManagedTask task, string output, CancellationToken cancellationToken)
    {
        if (output == "none" || task.CurrentAttempt is not { } attempt)
        {
            return;
        }

        using var mirror = new TaskText.Mirror();
        ulong offset = 0;
        if (output == "tail")
        {
            var meta = Cli.Meta();
            var end = await cli.CallAsync("ReadTaskOutput", meta, () => session.Channel.Tasks.ReadTaskOutputAsync(new TaskServiceReadTaskOutputRequest
            {
                Meta = meta,
                AttemptId = attempt.AttemptId,
                Stream = OutputStream.Merged,
                FromOffset = ulong.MaxValue / 2,
                MaxBytes = 1,
            }, deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken)).ConfigureAwait(false);
            offset = (end.Value?.NextOffset ?? 0) > 4096 ? end.Value!.NextOffset - 4096 : 0;
        }

        while (true)
        {
            var read = new TaskServiceReadTaskOutputRequest { Meta = Cli.Meta(), AttemptId = attempt.AttemptId, Stream = OutputStream.Merged, FromOffset = offset, MaxBytes = 1024 * 1024 };
            var response = await cli.CallAsync("ReadTaskOutput", read.Meta, () => session.Channel.Tasks.ReadTaskOutputAsync(read,
                deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Value is null || response.Value.Data.Length == 0)
            {
                return;
            }

            Mirror(mirror, response.Value);
            offset = response.Value.NextOffset;
        }
    }

    /// <summary>Writes a read's bytes to stdout and stderr in index order.</summary>
    private static void Mirror(TaskText.Mirror mirror, TaskServiceReadTaskOutputValue value)
    {
        var data = value.Data.Span;
        var position = 0;
        foreach (var record in value.Index)
        {
            var length = (int)Math.Min(record.Length, (uint)(data.Length - position));
            mirror.Write(record.Stream, data.Slice(position, length));
            position += length;
        }

        if (position < data.Length)
        {
            mirror.Write(OutputStream.Stdout, data[position..]);
        }
    }

    private static async Task<ulong> TailOffsetAsync(Cli cli, NodeSession session, Id attemptId, OutputStream stream, int lines, CancellationToken cancellationToken)
    {
        // Reads back from the end in 64 KiB steps until enough line breaks were seen.
        var endResponse = await session.Channel.Tasks.ReadTaskOutputAsync(new TaskServiceReadTaskOutputRequest
        {
            Meta = Cli.Meta(),
            AttemptId = attemptId,
            Stream = stream,
            FromOffset = ulong.MaxValue / 2,
            MaxBytes = 1,
        }, deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken).ConfigureAwait(false);
        var end = endResponse.Value?.NextOffset ?? 0;
        var from = end;
        var seen = 0;
        while (from > 0)
        {
            var start = from > 65_536 ? from - 65_536 : 0;
            var chunk = await session.Channel.Tasks.ReadTaskOutputAsync(new TaskServiceReadTaskOutputRequest
            {
                Meta = Cli.Meta(),
                AttemptId = attemptId,
                Stream = stream,
                FromOffset = start,
                MaxBytes = (uint)(from - start),
            }, deadline: cli.Deadline(TimeSpan.FromSeconds(10)), cancellationToken: cancellationToken).ConfigureAwait(false);
            var bytes = chunk.Value is { } value ? value.Data.Span : [];
            for (var index = bytes.Length - 1; index >= 0; index--)
            {
                // A line break that ends the output does not start a line.
                if (bytes[index] == (byte)'\n' && start + (ulong)index + 1 < end && ++seen == lines)
                {
                    return start + (ulong)index + 1;
                }
            }

            from = start;
        }

        return 0;
    }

    private static string Exit(ManagedTask task) =>
        task.CurrentAttempt?.Result is { HasExitCode: true } result ? result.ExitCode.ToString(CultureInfo.InvariantCulture)
        : task.CurrentAttempt?.Result is { HasSignal: true, Signal: > 0 } signalled ? "SIG" + signalled.Signal.ToString(CultureInfo.InvariantCulture)
        : task.CurrentAttempt?.Result is { } other ? TaskText.Word(other.TerminationReason)
        : "-";
}
