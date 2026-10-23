// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections;
using System.CommandLine;
using System.Globalization;
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.CommandLine;

/// <summary>
/// <c>arcforges run [run options] -- &lt;program&gt; [args...]</c> and <c>run --shell &lt;kind&gt; -- "&lt;script&gt;"</c> (experience/cli.md
/// C-01; architecture 04 section 5): <c>SubmitTask</c>, then <c>AttachTask</c> (attached by default) or <c>WaitTask</c>. Attached, the
/// task's stdout and stderr are mirrored byte-exactly to the CLI's, and the CLI exits with the task's exit code (126 spawn failed, 127
/// program not found, 125 not started, 75 node unreachable; on Windows a termination exits 1 with a message). <c>Ctrl+C</c> once sends
/// <c>CancelTask</c>; a second <c>Ctrl+C</c> detaches and leaves the task running. With <c>--client-timeout</c> the run hands off before
/// the AI client's timeout: <c>ReleaseCallerBinding</c>, the task ID with the wait and cancel commands on stderr, exit 124 (AD-0006
/// section 7). The global <c>--timeout</c> is the task's wall-clock timeout here. Dependencies (<c>--depends-on</c>), keys
/// (<c>--exclusive</c>, <c>--shared</c>, <c>--exclusive-workspace</c>) and service readiness (<c>--ready-regex</c>, <c>--ready-port</c>,
/// <c>--ready-file</c>) are passed to the scheduler (03 section 4; 04 section 8); placement on peers is not offered by this build.
/// </summary>
internal static class RunCommand
{
    /// <summary>routing.handoff_margin_ms (default 15 s).</summary>
    public static readonly TimeSpan HandoffMargin = TimeSpan.FromSeconds(15);

    /// <summary>
    /// When <c>run --client-timeout</c> hands off: the caller's timeout minus <see cref="HandoffMargin"/>, counted from this process's
    /// start (the caller started its timer when it started the CLI), as a UTC time.
    /// </summary>
    public static DateTime HandoffAt(TimeSpan clientTimeout)
    {
        DateTime started;
        try
        {
            using var self = System.Diagnostics.Process.GetCurrentProcess();
            started = self.StartTime.ToUniversalTime();
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
        {
            started = DateTime.UtcNow;
        }

        return started + (clientTimeout > HandoffMargin ? clientTimeout - HandoffMargin : TimeSpan.Zero);
    }

    private static readonly TimeSpan ReconnectBudget = TimeSpan.FromSeconds(60);

    public static Command Build(Func<ParseResult, Cli> factory)
    {
        var program = new Argument<string[]>("command") { Arity = ArgumentArity.OneOrMore, Description = "The program and its arguments (after --), or the script with --shell" };
        var cwd = new Option<string?>("--cwd") { Description = "Working directory (default: the current directory)", HelpName = "dir" };
        var pool = new Option<string?>("--pool") { Description = "Pool (default 'default')", HelpName = "p" };
        var priority = new Option<string?>("--priority") { Description = "interactive, high, normal, low or background", HelpName = "class" };
        priority.AcceptOnlyFromAmong("interactive", "high", "normal", "low", "background");
        var cpuLimit = new Option<string?>("--cpu-limit-time") { Description = "CPU-time limit (for example 10m)", HelpName = "dur" };
        var env = new Option<string[]>("--env") { Description = "Set a variable (repeatable)", HelpName = "K=V" };
        var inherit = new Option<string?>("--env-inherit") { Description = "caller (default), node or none", HelpName = "mode" };
        inherit.AcceptOnlyFromAmong("caller", "node", "none");
        var unset = new Option<string[]>("--unset") { Description = "Remove an inherited variable (repeatable)", HelpName = "K" };
        var stdin = new Option<string?>("--stdin") { Description = "none (default), file:<path> or stream", HelpName = "mode" };
        var label = new Option<string[]>("--label") { Description = "A label (repeatable)", HelpName = "k=v" };
        var title = new Option<string?>("--title") { Description = "Title shown in UIs" };
        var kind = new Option<string?>("--kind") { Description = "command (default) or service", HelpName = "kind" };
        kind.AcceptOnlyFromAmong("command", "service");
        var sideEffect = new Option<string?>("--side-effect") { Description = "pure, idempotent, side-effecting or unknown (default)", HelpName = "class" };
        sideEffect.AcceptOnlyFromAmong("pure", "idempotent", "side-effecting", "unknown");
        var retries = new Option<int?>("--retries") { Description = "Retries for asserted classes (0..4)", HelpName = "n" };
        var placement = new Option<string?>("--placement") { Description = "local (LAN placement arrives with its task)", HelpName = "where" };
        placement.AcceptOnlyFromAmong("local");
        var clientTimeout = new Option<string?>("--client-timeout") { Description = "Hand off before an AI client's tool timeout (exit 124)", HelpName = "dur" };
        var join = new Option<bool>("--join-existing") { Description = "Join an identical task of the same session that has not started" };
        var cpu = new Option<string?>("--cpu") { Description = "Expected CPU in cores (for example 2 or 1.5)", HelpName = "cores" };
        var mem = new Option<string?>("--mem") { Description = "Expected memory (for example 512MiB)", HelpName = "size" };
        var memMax = new Option<string?>("--mem-max") { Description = "Memory ceiling (for example 4GiB)", HelpName = "size" };
        var require = new Option<string?>("--require-enforcement") { Description = "Refuse unless enforced: cpu,memory,pids", HelpName = "list" };
        var detach = new Option<bool>("--detach") { Description = "Submit and print the task ID without attaching" };
        var wait = new Option<string?>("--wait") { Description = "With --detach: wait up to this long for the task to finish", HelpName = "dur" };
        var sessionOption = new Option<string?>("--session") { Description = "The agent session (sessions arrive with their task)", HelpName = "id" };
        var agent = new Option<string?>("--agent") { Description = "The agent ID within the session", HelpName = "id" };
        var shell = new Option<string?>("--shell") { Description = "Run a script with bash, sh, pwsh, powershell or cmd", HelpName = "kind" };
        shell.AcceptOnlyFromAmong("bash", "sh", "pwsh", "powershell", "cmd", "system");
        var dependsOn = new Option<string[]>("--depends-on") { Description = "Start after a task (repeatable): <id>[:succeeded|finished|ready]", HelpName = "id[:condition]" };
        var exclusive = new Option<string[]>("--exclusive") { Description = "An exclusive key (repeatable): ws:<w>[/<dir>][:<purpose>], tool:<name>:<scope>, name:<text>", HelpName = "key" };
        var shared = new Option<string[]>("--shared") { Description = "A shared (reader) key (repeatable)", HelpName = "key" };
        var exclusiveWorkspace = new Option<bool>("--exclusive-workspace")
        {
            Description = "Take the workspace key ws:<workspace> exclusively (access EXCLUSIVE): tasks holding keys of the workspace wait; commands without keys may still run beside it",
        };
        var readyRegex = new Option<string?>("--ready-regex") { Description = "Service: ready when a line of output matches", HelpName = "regex" };
        var readyPort = new Option<int?>("--ready-port") { Description = "Service: ready when it listens on this localhost TCP port", HelpName = "port" };
        var readyFile = new Option<string?>("--ready-file") { Description = "Service: ready when this file exists", HelpName = "path" };
        var readyTimeout = new Option<string?>("--ready-timeout") { Description = "Service: how long to wait for readiness (default 120s)", HelpName = "dur" };
        var command = new Command("run", "Run a command under the node and mirror its output")
        {
            program, cwd, pool, priority, cpuLimit, env, inherit, unset, stdin, label, title, kind, sideEffect, retries, placement, clientTimeout, join,
            cpu, mem, memMax, require, detach, wait, sessionOption, agent, shell, dependsOn, exclusive, shared, exclusiveWorkspace, readyRegex, readyPort, readyFile,
            readyTimeout,
        };
        Actions.Set(command, factory, async (cli, result, cancellationToken) =>
        {
            var spec = new TaskSpec
            {
                WorkingDirectory = Path.GetFullPath(result.GetValue(cwd) ?? Directory.GetCurrentDirectory()),
                Environment = Environment(result.GetValue(inherit), result.GetValue(env) ?? [], result.GetValue(unset) ?? []),
            };
            var tokens = result.GetValue(program) ?? [];
            if (result.GetValue(shell) is { } shellName)
            {
                spec.Command = new CommandSpec { Shell = new ShellCommand { Kind = ShellKindOf(shellName), Script = string.Join(' ', tokens) } };
            }
            else
            {
                var argv = new ArgvCommand();
                argv.Argv.Add(tokens);
                spec.Command = new CommandSpec { Argv = argv };
            }

            var stdinMode = result.GetValue(stdin) ?? "none";
            spec.Stdin = stdinMode switch
            {
                "none" => new StdinSpec { Mode = StdinMode.None },
                "stream" => new StdinSpec { Mode = StdinMode.Stream },
                _ when stdinMode.StartsWith("file:", StringComparison.Ordinal) => new StdinSpec { Mode = StdinMode.File, FilePath = Path.GetFullPath(stdinMode[5..]) },
                _ => throw new UsageException("--stdin: none, file:<path> or stream."),
            };
            if (cli.Timeout is { } timeout)
            {
                spec.TimeoutMs = (ulong)timeout.TotalMilliseconds;
            }

            if (result.GetValue(cpuLimit) is { } limit)
            {
                spec.CpuTimeLimitMs = (ulong)Duration(limit, "--cpu-limit-time").TotalMilliseconds;
            }

            if (result.GetValue(pool) is { } poolName)
            {
                spec.Pool = poolName;
            }

            if (result.GetValue(priority) is { } priorityName)
            {
                spec.Priority = Enum.Parse<Priority>(priorityName, ignoreCase: true);
            }

            foreach (var pair in result.GetValue(label) ?? [])
            {
                var (key, value) = Pair(pair, "--label");
                spec.Labels[key] = value;
            }

            if (result.GetValue(title) is { } titleText)
            {
                spec.Title = titleText;
            }

            if (result.GetValue(kind) == "service")
            {
                spec.Kind = TaskKind.Service;
            }

            var readiness = new ReadinessCondition();
            if (result.GetValue(readyRegex) is { } regex)
            {
                readiness.OutputRegex = regex;
            }

            if (result.GetValue(readyPort) is { } port)
            {
                readiness.TcpListenPort = port is >= 1 and <= 65_535 ? (uint)port : throw new UsageException("--ready-port: 1..65535.");
            }

            if (result.GetValue(readyFile) is { } readyPath)
            {
                readiness.FileExists = Path.GetFullPath(readyPath);
            }

            if ((result.GetValue(readyRegex) is not null ? 1 : 0) + (result.GetValue(readyPort) is not null ? 1 : 0) + (result.GetValue(readyFile) is not null ? 1 : 0) > 1)
            {
                throw new UsageException("give one of --ready-regex, --ready-port and --ready-file.");
            }

            if (result.GetValue(readyTimeout) is { } readyText)
            {
                readiness.ReadinessTimeoutMs = (ulong)Duration(readyText, "--ready-timeout").TotalMilliseconds;
            }

            if (readiness.ConditionCase != ReadinessCondition.ConditionOneofCase.None || readiness.HasReadinessTimeoutMs)
            {
                spec.Kind = TaskKind.Service;
                spec.Readiness = readiness;
            }

            var exclusiveKeys = result.GetValue(exclusive) ?? [];
            var sharedKeys = result.GetValue(shared) ?? [];
            if (exclusiveKeys.Length > 0 || sharedKeys.Length > 0 || result.GetValue(exclusiveWorkspace))
            {
                spec.Concurrency = new ConcurrencySpec();
                spec.Concurrency.ExclusiveKeys.Add(exclusiveKeys);
                spec.Concurrency.SharedKeys.Add(sharedKeys);
                if (result.GetValue(exclusiveWorkspace))
                {
                    spec.Concurrency.Access = WorkspaceAccess.Exclusive;
                }
            }

            if (result.GetValue(sideEffect) is { } effect)
            {
                spec.SideEffect = effect switch
                {
                    "pure" => SideEffectClass.Pure,
                    "idempotent" => SideEffectClass.Idempotent,
                    "side-effecting" => SideEffectClass.SideEffecting,
                    _ => SideEffectClass.Unknown,
                };
            }

            if (result.GetValue(retries) is { } count)
            {
                spec.Retry = count is >= 0 and <= 4 ? new RetrySpec { MaxAttempts = (uint)count + 1 } : throw new UsageException("--retries: 0..4.");
            }

            spec.Resources = Resources(result.GetValue(cpu), result.GetValue(mem), result.GetValue(memMax), result.GetValue(require));
            // The caller's timeout counts from the CLI's start, so connecting, an auto-start and the submission use part of it.
            DateTime? handoff = result.GetValue(clientTimeout) is { } clientText ? HandoffAt(Duration(clientText, "--client-timeout")) : null;
            var request = new TaskServiceSubmitTaskRequest
            {
                Meta = Cli.Meta(),
                Spec = spec,
                CancelWhenCallerGone = handoff is not null,
                JoinExisting = result.GetValue(join),
            };
            if (result.GetValue(sessionOption) is { } sessionText)
            {
                request.SessionId = IdText.TryParse(sessionText, out var sessionId)
                    ? new Id { Value = ByteString.CopyFrom(sessionId) }
                    : throw new UsageException($"--session: '{sessionText}' is not an ID.");
            }

            if (result.GetValue(agent) is { } agentId)
            {
                request.AgentId = agentId;
            }

            var waitFor = result.GetValue(wait) is { } waitText ? Duration(waitText, "--wait") : (TimeSpan?)null;
            if (waitFor is not null && !result.GetValue(detach))
            {
                throw new UsageException("--wait needs --detach.");
            }

            await using var session = await cli.ConnectAsync(autoStart: true, cancellationToken).ConfigureAwait(false);
            foreach (var dependency in result.GetValue(dependsOn) ?? [])
            {
                var colon = dependency.LastIndexOf(':');
                var (idText, conditionText) = colon > 0 ? (dependency[..colon], dependency[(colon + 1)..]) : (dependency, "succeeded");
                var condition = conditionText.ToLowerInvariant() switch
                {
                    "succeeded" => DependencyCondition.Succeeded,
                    "finished" => DependencyCondition.Finished,
                    "ready" => DependencyCondition.Ready,
                    _ => throw new UsageException($"--depends-on: '{conditionText}' is not succeeded, finished or ready."),
                };
                var (dependencyId, exit) = await TaskText.ResolveAsync(cli, session, idText, cancellationToken).ConfigureAwait(false);
                if (dependencyId is null)
                {
                    return exit;
                }

                spec.DependsOn.Add(new Dependency { TaskId = dependencyId, Condition = condition });
            }

            var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
            var submitted = await cli.MutateAsync("SubmitTask", request.Meta.CommandId, action, r => session.Channel.Tasks.SubmitTaskAsync(r,
                deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
            if (submitted.Error is { } error)
            {
                return TaskText.Refused(error, request.Meta.CorrelationId, cli.Output);
            }

            var taskId = submitted.Value.TaskId;
            foreach (var warning in submitted.Value.Warnings)
            {
                cli.Output.Trace("warning: " + warning);
            }

            cli.Output.Trace($"submitted task {IdText.Format(taskId)} ({TaskText.Word(submitted.Value.State)})");
            if (result.GetValue(detach))
            {
                if (cli.Output.Json && waitFor is null)
                {
                    cli.Output.Document(submitted.Value);
                }
                else if (!cli.Output.Json)
                {
                    cli.Output.Essential(IdText.Format(taskId));
                }

                return waitFor is { } budget
                    ? await TaskCommands.WaitAsync(cli, session, taskId, WaitTarget.Terminal, budget, "none", cancellationToken).ConfigureAwait(false)
                    : ExitCodes.Success;
            }

            return await AttachAsync(cli, session, taskId, stdinMode == "stream", handoff, fromStart: true, cancellationToken).ConfigureAwait(false);
        });
        return command;
    }

    /// <summary>
    /// Attaches to a task (<c>run</c> and <c>tasks attach</c>): mirrors its output byte-exactly, forwards stdin when granted, reconnects
    /// after a lost connection with the offsets already written, handles Ctrl+C (cancel, then detach) and the client-timeout hand-off,
    /// and returns the exit code of its result.
    /// </summary>
    public static async Task<int> AttachAsync(Cli cli, NodeSession session, Id taskId, bool forwardStdin, DateTime? handoffAt, bool fromStart,
        CancellationToken cancellationToken)
    {
        using var mirror = new TaskText.Mirror();
        using var interrupts = new Interrupts();
        var text = IdText.Format(taskId);
        long stdoutSeen = 0;
        long stderrSeen = 0;
        if (!fromStart)
        {
            (stdoutSeen, stderrSeen) = await CurrentEndsAsync(session, taskId, cancellationToken).ConfigureAwait(false);
        }

        string? attempt = null;
        Task? stdinPump = null;
        var lastFailure = (long?)null;
        var channel = session.Channel;
        NodeSession? reconnected = null;
        using var detached = new CancellationTokenSource();
        var handoff = handoffAt is { } at
            ? Task.Delay(at > DateTime.UtcNow ? at - DateTime.UtcNow : TimeSpan.Zero, detached.Token)
            : Task.Delay(Timeout.Infinite, detached.Token);
        try
        {
            while (true)
            {
                using var call = channel.Tasks.AttachTask(new TaskServiceAttachTaskRequest
                {
                    Meta = Cli.Meta(),
                    TaskId = taskId,
                    StdoutFromOffset = (ulong)stdoutSeen,
                    StderrFromOffset = (ulong)stderrSeen,
                    WantStdin = forwardStdin && stdinPump is null,
                }, cancellationToken: detached.Token);
                var reader = call.ResponseStream;
                Task<bool>? next = null;
                try
                {
                    while (true)
                    {
                        // One read is pending at a time; an interrupt leaves it pending for the next round.
                        next ??= reader.MoveNext(detached.Token);
                        var finished = await Task.WhenAny(next, handoff, interrupts.Next).ConfigureAwait(false);
                        if (finished == handoff)
                        {
                            return await HandOffAsync(cli, channel, taskId, cancellationToken).ConfigureAwait(false);
                        }

                        if (finished == interrupts.Next)
                        {
                            interrupts.Reset();
                            if (interrupts.Count == 1)
                            {
                                cli.Output.Error.WriteLine($"arcforges: cancelling task {text} (Ctrl+C again to detach)");
                                await CancelAsync(cli, channel, taskId, cancellationToken).ConfigureAwait(false);
                                continue;
                            }

                            cli.Output.Error.WriteLine($"arcforges: detached; task {text} keeps running ('arcforges tasks attach {text}')");
                            return 130;
                        }

                        var more = await next.ConfigureAwait(false);
                        next = null;
                        if (!more)
                        {
                            break;
                        }

                        lastFailure = null;
                        var frame = reader.Current;
                        switch (frame.FrameCase)
                        {
                            case TaskServiceAttachTaskFrame.FrameOneofCase.Started:
                                if (frame.Started.StdinGranted && stdinPump is null)
                                {
                                    stdinPump = PumpStdinAsync(cli, channel, taskId, frame.Started.AttachId, detached.Token);
                                }

                                break;
                            case TaskServiceAttachTaskFrame.FrameOneofCase.Output:
                                var chunk = frame.Output;
                                var chunkAttempt = IdText.Format(chunk.AttemptId);
                                if (attempt is not null && chunkAttempt != attempt)
                                {
                                    stdoutSeen = 0;
                                    stderrSeen = 0;
                                }

                                attempt = chunkAttempt;
                                ref var seen = ref chunk.Stream == OutputStream.Stderr ? ref stderrSeen : ref stdoutSeen;
                                var offset = (long)chunk.Offset;
                                var end = offset + chunk.Data.Length;
                                if (end > seen)
                                {
                                    var skip = (int)Math.Max(0, seen - offset);
                                    mirror.Write(chunk.Stream, chunk.Data.Span[skip..]);
                                    seen = end;
                                }

                                break;
                            case TaskServiceAttachTaskFrame.FrameOneofCase.Result:
                                return TaskText.ExitCode(frame.Result, cli.Output);
                            case TaskServiceAttachTaskFrame.FrameOneofCase.Error:
                                return cli.Output.Fail(frame.Error, null);
                        }
                    }
                }
                catch (RpcException exception) when (exception.StatusCode is StatusCode.Unavailable or StatusCode.Internal or StatusCode.ResourceExhausted
                    or StatusCode.Unknown or StatusCode.Aborted)
                {
                    cli.Output.Trace($"attach interrupted ({exception.StatusCode}); reconnecting");
                }

                // The stream ended without a result (the node restarted): attach again from what was written (detaching never affects the task).
                lastFailure ??= TimeProvider.System.GetTimestamp();
                if (TimeProvider.System.GetElapsedTime(lastFailure.Value) > ReconnectBudget)
                {
                    cli.Output.Error.WriteLine($"arcforges: lost the node; task {text} keeps running ('arcforges tasks attach {text}')");
                    return ExitCodes.NodeUnreachable;
                }

                await Task.Delay(500, cancellationToken).ConfigureAwait(false);
                if (reconnected is not null)
                {
                    await reconnected.DisposeAsync().ConfigureAwait(false);
                }

                try
                {
                    reconnected = await NodeClient.WaitForReadyAsync(new NodeConnectOptions { Kind = ClientKind.Cli, TestMode = cli.TestMode, ReadinessTimeout = TimeSpan.FromSeconds(5) },
                        cancellationToken).ConfigureAwait(false);
                    channel = reconnected.Channel;
                }
                catch (NodeUnavailableException)
                {
                    reconnected = null;
                }
            }
        }
        finally
        {
            await detached.CancelAsync().ConfigureAwait(false);
            if (stdinPump is not null)
            {
                await Task.WhenAny(stdinPump, Task.Delay(500, CancellationToken.None)).ConfigureAwait(false);
            }

            if (reconnected is not null)
            {
                await reconnected.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static async Task<int> HandOffAsync(Cli cli, NodeChannel channel, Id taskId, CancellationToken cancellationToken)
    {
        var text = IdText.Format(taskId);
        var response = await channel.Tasks.ReleaseCallerBindingAsync(new TaskServiceReleaseCallerBindingRequest
        {
            Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            TaskId = taskId,
        }, deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: cancellationToken).ConfigureAwait(false);
        if (response.Error is { } error)
        {
            return cli.Output.Fail(error, null);
        }

        if (TaskText.IsTerminal(response.Value.State))
        {
            // It finished at the last moment: the attach that follows prints its output and exit code.
            var attempt = await channel.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = Cli.Meta(), TaskId = taskId },
                deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: cancellationToken).ConfigureAwait(false);
            if (attempt.Value?.Task.CurrentAttempt?.Result is { } result)
            {
                return TaskText.ExitCode(result, cli.Output);
            }
        }

        cli.Output.Error.WriteLine($"arcforges: task {text} continues after the client's timeout ({TaskText.Word(response.Value.State)}).");
        cli.Output.Error.WriteLine($"arcforges: wait for it: arcforges tasks wait {text}");
        cli.Output.Error.WriteLine($"arcforges: cancel it: arcforges tasks cancel {text}");
        return TaskText.HandedOff;
    }

    private static async Task CancelAsync(Cli cli, NodeChannel channel, Id taskId, CancellationToken cancellationToken)
    {
        var request = new TaskServiceCancelTaskRequest { Meta = Cli.Meta(), TaskId = taskId, Reason = "interrupted (Ctrl+C)" };
        var action = CommandIds.Begin(request, r => r.Meta, (r, m) => r.Meta = m);
        var response = await cli.MutateAsync("CancelTask", request.Meta.CommandId, action, r => channel.Tasks.CancelTaskAsync(r,
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: cancellationToken), cancellationToken).ConfigureAwait(false);
        if (response.Error is { } error)
        {
            cli.Output.Fail(error, request.Meta.CorrelationId);
        }
    }

    private static async Task PumpStdinAsync(Cli cli, NodeChannel channel, Id taskId, Id attachId, CancellationToken cancellationToken)
    {
        try
        {
            await using var input = Console.OpenStandardInput();
            var buffer = new byte[64 * 1024];
            ulong offset = 0;
            while (true)
            {
                var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                var response = await channel.Tasks.WriteTaskInputAsync(new TaskServiceWriteTaskInputRequest
                {
                    Meta = Cli.Meta(),
                    TaskId = taskId,
                    AttachId = attachId,
                    Offset = offset,
                    Data = ByteString.CopyFrom(buffer, 0, read),
                }, deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: cancellationToken).ConfigureAwait(false);
                if (response.Error is not null)
                {
                    cli.Output.Trace("stdin: " + Messages.For(response.Error));
                    return;
                }

                offset = response.Value.AcceptedThrough;
            }

            await channel.Tasks.CloseTaskInputAsync(new TaskServiceCloseTaskInputRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                TaskId = taskId,
                AttachId = attachId,
            }, deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or RpcException or IOException)
        {
            // Detaching ends forwarding; the task sees end-of-file when its pipe closes.
        }
    }

    private static async Task<(long Stdout, long Stderr)> CurrentEndsAsync(NodeSession session, Id taskId, CancellationToken cancellationToken)
    {
        var task = await session.Channel.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = Cli.Meta(), TaskId = taskId },
            deadline: DateTime.UtcNow.AddSeconds(5), cancellationToken: cancellationToken).ConfigureAwait(false);
        if (task.Value?.Task.CurrentAttempt is not { } attempt)
        {
            return (0, 0);
        }

        async Task<long> End(OutputStream stream)
        {
            var read = await session.Channel.Tasks.ReadTaskOutputAsync(new TaskServiceReadTaskOutputRequest
            {
                Meta = Cli.Meta(),
                AttemptId = attempt.AttemptId,
                Stream = stream,
                FromOffset = ulong.MaxValue / 2,
                MaxBytes = 1,
            }, deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: cancellationToken).ConfigureAwait(false);
            return (long)(read.Value?.NextOffset ?? 0);
        }

        return (await End(OutputStream.Stdout).ConfigureAwait(false), await End(OutputStream.Stderr).ConfigureAwait(false));
    }

    private static EnvironmentSpec Environment(string? inherit, string[] set, string[] unset)
    {
        var spec = new EnvironmentSpec
        {
            Inherit = inherit switch
            {
                "node" => EnvironmentInherit.Node,
                "none" => EnvironmentInherit.None,
                _ => EnvironmentInherit.Caller,
            },
        };
        if (spec.Inherit == EnvironmentInherit.Caller)
        {
            foreach (DictionaryEntry entry in System.Environment.GetEnvironmentVariables())
            {
                if (entry.Key is string name && name.Length > 0 && !name.Contains('=', StringComparison.Ordinal))
                {
                    spec.CallerEnvironment[name] = entry.Value as string ?? string.Empty;
                }
            }
        }

        foreach (var pair in set)
        {
            var (name, value) = Pair(pair, "--env");
            spec.Set[name] = value;
        }

        spec.Unset.Add(unset);
        return spec;
    }

    private static ResourceSpec? Resources(string? cpu, string? mem, string? memMax, string? require)
    {
        if (cpu is null && mem is null && memMax is null && require is null)
        {
            return null;
        }

        var resources = new ResourceSpec();
        if (cpu is not null || mem is not null || memMax is not null)
        {
            resources.Hint = new ResourceDemand();
            if (cpu is not null)
            {
                resources.Hint.CpuMillicores = double.TryParse(cpu, NumberStyles.Float, CultureInfo.InvariantCulture, out var cores) && cores > 0
                    ? (uint)Math.Round(cores * 1000)
                    : throw new UsageException($"--cpu: '{cpu}' is not a number of cores.");
            }

            if (mem is not null)
            {
                resources.Hint.MemExpectedBytes = Size(mem, "--mem");
            }

            if (memMax is not null)
            {
                resources.Hint.MemCeilingBytes = Size(memMax, "--mem-max");
            }
        }

        foreach (var name in (require ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            resources.RequireEnforcement.Add(name.ToLowerInvariant() switch
            {
                "cpu" => EnforcedResource.Cpu,
                "memory" => EnforcedResource.Memory,
                "pids" => EnforcedResource.Pids,
                _ => throw new UsageException($"--require-enforcement: '{name}' is not cpu, memory or pids."),
            });
        }

        return resources;
    }

    /// <summary>Parses a size (<c>512MiB</c>, <c>4GiB</c>, <c>1048576</c>).</summary>
    public static ulong Size(string text, string option)
    {
        var units = new (string Suffix, ulong Factor)[] { ("TiB", 1UL << 40), ("GiB", 1UL << 30), ("MiB", 1UL << 20), ("KiB", 1UL << 10), ("B", 1) };
        foreach (var (suffix, factor) in units)
        {
            if (text.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                && double.TryParse(text[..^suffix.Length], NumberStyles.Float, CultureInfo.InvariantCulture, out var amount) && amount > 0)
            {
                return (ulong)(amount * factor);
            }
        }

        return ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var bytes) && bytes > 0
            ? bytes
            : throw new UsageException($"{option}: '{text}' is not a size (512MiB, 4GiB).");
    }

    private static TimeSpan Duration(string text, string option) =>
        Durations.TryParse(text, out var duration) ? duration : throw new UsageException($"{option}: '{text}' is not a duration (90s, 5m, 2h, 1d).");

    private static (string Key, string Value) Pair(string text, string option)
    {
        var equals = text.IndexOf('=', StringComparison.Ordinal);
        return equals > 0 ? (text[..equals], text[(equals + 1)..]) : throw new UsageException($"{option}: '{text}' is not NAME=VALUE.");
    }

    private static ShellKind ShellKindOf(string name) => name switch
    {
        "bash" => ShellKind.Bash,
        "sh" => ShellKind.Sh,
        "pwsh" => ShellKind.Pwsh,
        "powershell" => ShellKind.Powershell,
        "cmd" => ShellKind.Cmd,
        _ => ShellKind.SystemDefault,
    };

    /// <summary>Counts Ctrl+C presses without letting them end the CLI (the first cancels the task, the second detaches).</summary>
    private sealed class Interrupts : IDisposable
    {
        private readonly PosixSignalRegistration? _registration;
        private TaskCompletionSource _next = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _count;

        public Interrupts()
        {
            try
            {
                _registration = PosixSignalRegistration.Create(PosixSignal.SIGINT, context =>
                {
                    context.Cancel = true;
                    Interlocked.Increment(ref _count);
                    Volatile.Read(ref _next).TrySetResult();
                });
            }
            catch (PlatformNotSupportedException)
            {
                _registration = null;
            }
        }

        public int Count => Volatile.Read(ref _count);

        public Task Next => Volatile.Read(ref _next).Task;

        public void Reset() => Interlocked.Exchange(ref _next, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));

        public void Dispose() => _registration?.Dispose();
    }
}
