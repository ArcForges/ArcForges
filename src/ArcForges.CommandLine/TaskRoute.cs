// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.CommandLine;

/// <summary>One command's local diagnostic or center-routed task destination.</summary>
internal sealed class TaskRoute(Cli cli, NodeSession session, Id nodeId, bool local)
{
    private static readonly TimeSpan RetryBudget = TimeSpan.FromMinutes(2);
    private const int MaximumRetries = 5;
    private readonly FleetService.FleetServiceClient _fleet = new(session.Channel.CallInvoker);

    public bool Local { get; } = local;

    public Id NodeId { get; } = nodeId;

    /// <summary>Resolves a canonical UUID directly, an exact node name through the center, or this node by default.</summary>
    public static async Task<(TaskRoute? Route, int Exit)> ResolveAsync(Cli cli, NodeSession session, string? selection, bool local,
        CancellationToken cancellationToken)
    {
        if (local && selection is not null)
        {
            return (null, cli.Output.Usage("--local cannot be combined with --node."));
        }

        var own = session.Hello.Node?.Node?.NodeId;
        if (own?.Value.Length != 16)
        {
            cli.Output.Error.WriteLine("error: the local node did not identify itself.");
            return (null, ExitCodes.Failed);
        }

        if (local || selection is null)
        {
            return (new TaskRoute(cli, session, own.Clone(), local), ExitCodes.Success);
        }

        if (Guid.TryParseExact(selection, "D", out var uuid))
        {
            if (uuid == Guid.Empty)
            {
                return (null, cli.Output.Usage("--node: the all-zero node ID is invalid."));
            }

            return (new TaskRoute(cli, session, new Id { Value = ByteString.CopyFrom(uuid.ToByteArray(bigEndian: true)) }, false), ExitCodes.Success);
        }

        var fleet = new FleetService.FleetServiceClient(session.Channel.CallInvoker);
        var request = new FleetServiceListNodesRequest { Meta = Cli.Meta() };
        var response = await fleet.ListNodesAsync(request, deadline: DateTime.UtcNow.AddSeconds(20), cancellationToken: cancellationToken).ConfigureAwait(false);
        if (response.Error is { } error)
        {
            return (null, Fail(cli, error, request.Meta.CorrelationId));
        }

        if (response.Value is null)
        {
            return (null, Fail(cli, Internal(), request.Meta.CorrelationId));
        }

        var matches = response.Value.Nodes.Where(node => string.Equals(node.Name, selection, StringComparison.Ordinal)).ToList();
        if (matches.Count == 1 && matches[0].NodeId?.Value.Length == 16)
        {
            return (new TaskRoute(cli, session, matches[0].NodeId.Clone(), false), ExitCodes.Success);
        }

        var names = response.Value.Nodes.Take(20).Select(node => Messages.Plain(node.Name) + " (" + FormatNode(node.NodeId) + ")");
        var detail = matches.Count == 0 ? "no node has that exact name; available: " + string.Join(", ", names)
            : "the node name is ambiguous; select its UUID";
        return (null, cli.Output.Usage("--node: " + detail));
    }

    /// <summary>Prints a routed refusal without ever claiming an uncertain mutation did not happen.</summary>
    public static int Fail(Cli cli, ArcError error, Id? correlation, Id? commandId = null, bool submission = false)
    {
        if (error.Code is "not_signed_in" or "cloud_unreachable" && error.Effect == EffectCertainty.DidNotHappen)
        {
            var state = error.Code == "not_signed_in" ? "the node is not signed in" : "the center or the node channel is unavailable";
            if (cli.Output.Json)
            {
                cli.Output.Fail(error, correlation);
            }

            cli.Output.Error.WriteLine("arcforges: " + state + "; use 'arcforges run --local' for HUMAN diagnostics");
            return ExitCodes.NotFound;
        }

        if (error.Code == "invalid_state" && error.Details?.State?.Reason == "replay_window_passed")
        {
            cli.Output.Fail(error, correlation);
            var task = error.Details.State.Resource?.Id;
            cli.Output.Error.WriteLine("arcforges: the command may have run; inspect the named task"
                + (task is null ? string.Empty : " " + IdText.Format(task)) + CommandText(commandId));
            return ExitCodes.Failed;
        }

        if (error.Code == "node_unreachable" && error.Details?.State?.Reason == "replay_digest_differs")
        {
            cli.Output.Fail(error, correlation);
            cli.Output.Error.WriteLine("arcforges: the replayed result differs; report this defect and do not submit a new command" + CommandText(commandId));
            return ExitCodes.Failed;
        }

        if (error.Code == "command_id_reused")
        {
            var conflict = cli.Output.Fail(error, correlation);
            cli.Output.Error.WriteLine("arcforges: command ID reuse is a defect; an earlier attempt may have run" + CommandText(commandId));
            return conflict;
        }

        if (error.Effect == EffectCertainty.Unknown)
        {
            cli.Output.Fail(error, correlation);
            if (commandId is not null)
            {
                cli.Output.Error.WriteLine("arcforges: the command may have run; do not submit a new command" + CommandText(commandId));
            }

            return ExitCodes.Failed;
        }

        var exit = cli.Output.Fail(error, correlation);
        if (error.Code == "node_offline" && error.Effect == EffectCertainty.DidNotHappen)
        {
            return ExitCodes.NodeUnreachable;
        }

        return submission ? error.Code == "program_not_found" ? TaskText.ProgramNotFound : TaskText.NotStarted : exit;
    }

    private static string CommandText(Id? commandId) => commandId is null ? string.Empty : " (command " + IdText.Format(commandId) + ")";

    private static string FormatNode(Id? id) => id?.Value.Length == 16 ? new Guid(id.Value.Span, bigEndian: true).ToString("D") : "unknown";

    public async Task<TaskServiceGetTaskResponse> GetAsync(TaskServiceGetTaskRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (Local)
        {
            return await session.Channel.Tasks.GetTaskAsync(request, deadline: cli.Deadline(TimeSpan.FromSeconds(20)), cancellationToken: cancellationToken).ResponseAsync
                .ConfigureAwait(false);
        }

        var bytes = request.ToByteString();
        var routed = new FleetServiceGetNodeTaskRequest { Meta = request.Meta?.Clone() ?? Cli.Meta(), NodeId = NodeId.Clone(), Request = bytes };
        return await ReadAsync(
            (deadline, token) => _fleet.GetNodeTaskAsync(routed, deadline: deadline, cancellationToken: token).ResponseAsync,
            answer => answer.Error, answer => answer.Value?.Response, TaskServiceGetTaskResponse.Parser,
            answer => answer.Error is not null || answer.Value is not null,
            error => new TaskServiceGetTaskResponse { Meta = Meta(request.Meta), Error = error }, TimeSpan.FromSeconds(20), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<TaskServiceListTasksResponse> ListAsync(TaskServiceListTasksRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (Local)
        {
            return await session.Channel.Tasks.ListTasksAsync(request, deadline: cli.Deadline(TimeSpan.FromSeconds(20)), cancellationToken: cancellationToken).ResponseAsync
                .ConfigureAwait(false);
        }

        var bytes = request.ToByteString();
        var routed = new FleetServiceListNodeTasksRequest { Meta = request.Meta?.Clone() ?? Cli.Meta(), NodeId = NodeId.Clone(), Request = bytes };
        return await ReadAsync(
            (deadline, token) => _fleet.ListNodeTasksAsync(routed, deadline: deadline, cancellationToken: token).ResponseAsync,
            answer => answer.Error, answer => answer.Value?.Response, TaskServiceListTasksResponse.Parser,
            answer => answer.Error is not null || answer.Value is not null,
            error => new TaskServiceListTasksResponse { Meta = Meta(request.Meta), Error = error }, TimeSpan.FromSeconds(20), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<TaskServiceWaitTaskResponse> WaitAsync(TaskServiceWaitTaskRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (Local)
        {
            return await session.Channel.Tasks.WaitTaskAsync(request, deadline: cli.Deadline(TimeSpan.FromSeconds(60)), cancellationToken: cancellationToken).ResponseAsync
                .ConfigureAwait(false);
        }

        var bytes = request.ToByteString();
        var routed = new FleetServiceWaitNodeTaskRequest { Meta = request.Meta?.Clone() ?? Cli.Meta(), NodeId = NodeId.Clone(), Request = bytes };
        return await ReadAsync(
            (deadline, token) => _fleet.WaitNodeTaskAsync(routed, deadline: deadline, cancellationToken: token).ResponseAsync,
            answer => answer.Error, answer => answer.Value?.Response, TaskServiceWaitTaskResponse.Parser,
            answer => answer.Error is not null || answer.Value is not null,
            error => new TaskServiceWaitTaskResponse { Meta = Meta(request.Meta), Error = error }, TimeSpan.FromSeconds(60), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<TaskServiceReadTaskOutputResponse> ReadAsync(TaskServiceReadTaskOutputRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (Local)
        {
            return await session.Channel.Tasks.ReadTaskOutputAsync(request, deadline: cli.Deadline(TimeSpan.FromSeconds(35)), cancellationToken: cancellationToken).ResponseAsync
                .ConfigureAwait(false);
        }

        var bytes = request.ToByteString();
        var routed = new FleetServiceReadNodeTaskOutputRequest { Meta = request.Meta?.Clone() ?? Cli.Meta(), NodeId = NodeId.Clone(), Request = bytes };
        return await ReadAsync(
            (deadline, token) => _fleet.ReadNodeTaskOutputAsync(routed, deadline: deadline, cancellationToken: token).ResponseAsync,
            answer => answer.Error, answer => answer.Value?.Response, TaskServiceReadTaskOutputResponse.Parser,
            answer => answer.Error is not null || answer.Value is not null,
            error => new TaskServiceReadTaskOutputResponse { Meta = Meta(request.Meta), Error = error }, TimeSpan.FromSeconds(35), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<TaskServiceSubmitTaskResponse> SubmitAsync(TaskServiceSubmitTaskRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (Local)
        {
            return await session.Channel.Tasks.SubmitTaskAsync(request, deadline: cli.Deadline(TimeSpan.FromSeconds(25)), cancellationToken: cancellationToken).ResponseAsync
                .ConfigureAwait(false);
        }

        var bytes = request.ToByteString();
        var routed = new FleetServiceSubmitNodeTaskRequest { Meta = request.Meta?.Clone() ?? Cli.Meta(), NodeId = NodeId.Clone(), Request = bytes };
        return await MutationAsync(
            (deadline, token) => _fleet.SubmitNodeTaskAsync(routed, deadline: deadline, cancellationToken: token).ResponseAsync,
            answer => answer.Error, answer => answer.Value?.Response, TaskServiceSubmitTaskResponse.Parser,
            answer => answer.Error is not null || answer.Value is not null, answer => answer.Error,
            error => new TaskServiceSubmitTaskResponse { Meta = Meta(request.Meta), Error = error }, request.Meta!.CommandId, TimeSpan.FromSeconds(25), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<TaskServiceCancelTaskResponse> CancelAsync(TaskServiceCancelTaskRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (Local)
        {
            return await session.Channel.Tasks.CancelTaskAsync(request, deadline: cli.Deadline(TimeSpan.FromSeconds(25)), cancellationToken: cancellationToken).ResponseAsync
                .ConfigureAwait(false);
        }

        var bytes = request.ToByteString();
        var routed = new FleetServiceCancelNodeTaskRequest { Meta = request.Meta?.Clone() ?? Cli.Meta(), NodeId = NodeId.Clone(), Request = bytes };
        return await MutationAsync(
            (deadline, token) => _fleet.CancelNodeTaskAsync(routed, deadline: deadline, cancellationToken: token).ResponseAsync,
            answer => answer.Error, answer => answer.Value?.Response, TaskServiceCancelTaskResponse.Parser,
            answer => answer.Error is not null || answer.Value is not null, answer => answer.Error,
            error => new TaskServiceCancelTaskResponse { Meta = Meta(request.Meta), Error = error }, request.Meta!.CommandId, TimeSpan.FromSeconds(25), cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Follows the current attempt by its merged output offset until the task ends.</summary>
    public async Task<int> FollowAsync(Id taskId, DateTime? handoffAt, CancellationToken cancellationToken)
    {
        using var mirror = new TaskText.Mirror();
        using var interrupts = new RunCommand.Interrupts();
        using var stopped = new CancellationTokenSource();
        var text = IdText.Format(taskId);
        var handoff = handoffAt is { } at
            ? Task.Delay(at > DateTime.UtcNow ? at - DateTime.UtcNow : TimeSpan.Zero, stopped.Token)
            : Task.Delay(Timeout.Infinite, stopped.Token);
        Task? cancellation = null;
        long? failureAt = null;
        var pause = TimeSpan.FromMilliseconds(250);
        Id? attempt = null;
        ulong offset = 0;

        async Task CancelTaskAsync()
        {
            try
            {
                var request = new TaskServiceCancelTaskRequest { Meta = Cli.Meta(), TaskId = taskId, Reason = "interrupted (Ctrl+C)" };
                var action = CommandIds.Begin(request, item => item.Meta, (item, meta) => item.Meta = meta);
                var result = await CancelAsync(action.RequestForAttempt(), stopped.Token).ConfigureAwait(false);
                if (result.Error is { } error)
                {
                    Fail(cli, error, request.Meta.CorrelationId, request.Meta.CommandId);
                }
            }
            catch (Exception exception) when (exception is OperationCanceledException or RpcException)
            {
                cli.Output.Trace("cancel request interrupted");
            }
        }

        async Task<(T? Value, int? Exit)> AwaitOperationAsync<T>(Task<T> operation)
            where T : class
        {
            while (true)
            {
                var completed = await Task.WhenAny(operation, interrupts.Next, handoff).ConfigureAwait(false);
                if (completed == operation)
                {
                    return (await operation.ConfigureAwait(false), null);
                }

                if (completed == handoff)
                {
                    await stopped.CancelAsync().ConfigureAwait(false);
                    try
                    {
                        await operation.ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is OperationCanceledException or RpcException)
                    {
                    }

                    cli.Output.Error.WriteLine($"arcforges: task {text} continues after the client's timeout.");
                    cli.Output.Error.WriteLine($"arcforges: wait for it: arcforges tasks wait {text} --node {FormatNode(NodeId)}");
                    cli.Output.Error.WriteLine($"arcforges: cancel it: arcforges tasks cancel {text} --node {FormatNode(NodeId)}");
                    return (null, TaskText.HandedOff);
                }

                interrupts.Reset();
                if (interrupts.Count == 1)
                {
                    cli.Output.Error.WriteLine($"arcforges: cancelling task {text} (Ctrl+C again to detach)");
                    cancellation ??= CancelTaskAsync();
                    continue;
                }

                await stopped.CancelAsync().ConfigureAwait(false);
                try
                {
                    await operation.ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is OperationCanceledException or RpcException)
                {
                }

                cli.Output.Error.WriteLine($"arcforges: detached; task {text} keeps running ('arcforges tasks wait {text} --node {FormatNode(NodeId)}')");
                return (null, 130);
            }
        }

        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var transient = false;
                try
                {
                    var get = new TaskServiceGetTaskRequest { Meta = Cli.Meta(), TaskId = taskId, Detail = TaskDetail.Summary };
                    var (answer, exit) = await AwaitOperationAsync(GetAsync(get, stopped.Token)).ConfigureAwait(false);
                    if (exit is { } done)
                    {
                        return done;
                    }

                    if (answer!.Error is { } error)
                    {
                        if (!TransientRead(error))
                        {
                            return Fail(cli, error, get.Meta.CorrelationId);
                        }

                        transient = true;
                    }
                    else if (answer.Value?.Task is { } task)
                    {
                        if (task.CurrentAttempt?.AttemptId is { } current)
                        {
                            if (attempt is null || !attempt.Equals(current))
                            {
                                attempt = current.Clone();
                                offset = 0;
                            }

                            var read = new TaskServiceReadTaskOutputRequest
                            {
                                Meta = Cli.Meta(),
                                AttemptId = attempt,
                                Stream = OutputStream.Merged,
                                FromOffset = offset,
                                MaxBytes = 262_144,
                                WaitMs = TaskText.IsTerminal(task.State) ? 0U : (uint)pause.TotalMilliseconds,
                            };
                            var (output, readExit) = await AwaitOperationAsync(ReadAsync(read, stopped.Token)).ConfigureAwait(false);
                            if (readExit is { } completed)
                            {
                                return completed;
                            }

                            if (output!.Error is { } readError)
                            {
                                if (!TransientRead(readError))
                                {
                                    return Fail(cli, readError, read.Meta.CorrelationId);
                                }

                                transient = true;
                            }
                            else if (output.Value is { } value)
                            {
                                if (value.NextOffset < offset || !value.TruncatedByRetention && value.NextOffset - offset != (ulong)value.Data.Length)
                                {
                                    return Fail(cli, Internal(), read.Meta.CorrelationId);
                                }

                                if (value.TruncatedByRetention)
                                {
                                    cli.Output.Error.WriteLine("arcforges: earlier output was removed by retention");
                                }

                                TaskCommands.Mirror(mirror, value);
                                offset = value.NextOffset;
                                failureAt = null;
                                if (value.Eof && TaskText.IsTerminal(task.State))
                                {
                                    return TaskText.ExitCode(task.CurrentAttempt.Result, cli.Output);
                                }

                                if (value.Data.Length > 0)
                                {
                                    pause = TimeSpan.FromMilliseconds(250);
                                    continue;
                                }

                                if (TaskText.IsTerminal(task.State))
                                {
                                    return TaskText.ExitCode(task.CurrentAttempt.Result, cli.Output);
                                }
                            }
                        }
                        else if (TaskText.IsTerminal(task.State))
                        {
                            return TaskText.ExitCode(null, cli.Output);
                        }
                        else
                        {
                            failureAt = null;
                        }
                    }
                    else
                    {
                        return Fail(cli, Internal(), get.Meta.CorrelationId);
                    }
                }
                catch (RpcException exception) when (exception.StatusCode is StatusCode.Unavailable or StatusCode.DeadlineExceeded)
                {
                    transient = true;
                }

                if (transient)
                {
                    failureAt ??= Stopwatch.GetTimestamp();
                    if (Stopwatch.GetElapsedTime(failureAt.Value) >= TimeSpan.FromMinutes(2))
                    {
                        cli.Output.Error.WriteLine($"arcforges: the center is unavailable; task {text} may still be running (output offset {offset})");
                        return ExitCodes.Failed;
                    }
                }
                else
                {
                    failureAt = null;
                }

                await Task.Delay(pause, cancellationToken).ConfigureAwait(false);
                pause = TimeSpan.FromMilliseconds(Math.Min(2000, pause.TotalMilliseconds * 2));
            }
        }
        finally
        {
            await stopped.CancelAsync().ConfigureAwait(false);
            if (cancellation is not null)
            {
                await cancellation.ConfigureAwait(false);
            }
        }
    }

    private static bool TransientRead(ArcError error) => error.Code is "cloud_unreachable" or "node_unreachable" or "node_offline";

    private static async Task<TInner> ReadAsync<TOuter, TInner>(Func<DateTime, CancellationToken, Task<TOuter>> send,
        Func<TOuter, ArcError?> errorOf, Func<TOuter, ByteString?> payloadOf, MessageParser<TInner> parser, Func<TInner, bool> hasOutcome,
        Func<ArcError, TInner> fail, TimeSpan deadline, CancellationToken cancellationToken)
        where TInner : class, IMessage<TInner>
    {
        var answer = await send(DateTime.UtcNow + deadline, cancellationToken).ConfigureAwait(false);
        return Decode(answer, errorOf, payloadOf, parser, hasOutcome, fail);
    }

    private async Task<TInner> MutationAsync<TOuter, TInner>(Func<DateTime, CancellationToken, Task<TOuter>> send,
        Func<TOuter, ArcError?> errorOf, Func<TOuter, ByteString?> payloadOf, MessageParser<TInner> parser, Func<TInner, bool> hasOutcome,
        Func<TInner, ArcError?> innerErrorOf, Func<ArcError, TInner> fail, Id command, TimeSpan deadline, CancellationToken cancellationToken)
        where TInner : class, IMessage<TInner>
    {
        var started = Stopwatch.GetTimestamp();
        var backoff = new LocalRpc.LocalRpcBackoff(TimeSpan.FromMilliseconds(250), TimeSpan.FromSeconds(2));
        var uncertain = false;
        var waitedForApproval = false;
        for (var retries = 0; ; retries++)
        {
            var remaining = RetryBudget - Stopwatch.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero)
            {
                return fail(Uncertain());
            }

            ArcError? error;
            try
            {
                var answer = await send(DateTime.UtcNow + (remaining < deadline ? remaining : deadline), cancellationToken).ConfigureAwait(false);
                error = errorOf(answer);
                if (error is null)
                {
                    var decoded = Decode(answer, errorOf, payloadOf, parser, hasOutcome, fail);
                    error = innerErrorOf(decoded);
                    if (error is null)
                    {
                        return decoded;
                    }
                }
            }
            catch (RpcException exception) when (!cancellationToken.IsCancellationRequested && exception.StatusCode is StatusCode.Unavailable or StatusCode.DeadlineExceeded)
            {
                uncertain = true;
                error = Uncertain();
            }

            if (!waitedForApproval && error.Code == "approval_required" && cli.WaitApproval is { } approvalWait
                && error.Details?.State?.Resource?.Id is { } approvalId
                && session.Hello.Node?.Node?.NodeId is { } own && own.Equals(NodeId))
            {
                waitedForApproval = true;
                if (await cli.AwaitDecisionAsync(session, approvalId, approvalWait, cancellationToken).ConfigureAwait(false))
                {
                    // Approval on this node ran the captured original request. Ask the center for that same command's outcome.
                    started = Stopwatch.GetTimestamp();
                    continue;
                }
            }

            // These refusals must stay intact even if an earlier attempt was uncertain: replay_window_passed may name the recorded task,
            // and command_id_reused is an actionable defect. Neither authorizes a fresh command ID.
            if (error.Code == "command_id_reused" || error.Code == "invalid_state" && error.Details?.State?.Reason == "replay_window_passed")
            {
                return fail(error);
            }

            uncertain |= error.Effect == EffectCertainty.Unknown;
            var retryable = error.Retry?.Mode is RetryMode.SameCommand or RetryMode.AfterTime &&
                (error.Code == "node_unreachable" || error.Code == "operation_failed" && error.Details?.State?.Reason == "command_in_progress");
            if (!retryable || retries >= MaximumRetries)
            {
                return fail(uncertain && error.Effect == EffectCertainty.DidNotHappen ? Uncertain() : error);
            }

            var wait = backoff.Next(retries + 1);
            if (error.Retry?.Mode == RetryMode.AfterTime && ProtoTime.ToDateTimeOffset(error.Retry.RetryAt) is { } retryAt)
            {
                var advised = retryAt - DateTimeOffset.UtcNow;
                if (advised > wait)
                {
                    wait = advised;
                }
            }

            remaining = RetryBudget - Stopwatch.GetElapsedTime(started);
            if (wait >= remaining)
            {
                return fail(uncertain ? Uncertain() : error);
            }

            cli.Output.Trace("retrying the same routed command " + IdText.Format(command));
            await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
        }
    }

    private static TInner Decode<TOuter, TInner>(TOuter answer, Func<TOuter, ArcError?> errorOf, Func<TOuter, ByteString?> payloadOf,
        MessageParser<TInner> parser, Func<TInner, bool> hasOutcome, Func<ArcError, TInner> fail)
        where TInner : class, IMessage<TInner>
    {
        if (errorOf(answer) is { } error)
        {
            return fail(error);
        }

        var payload = payloadOf(answer);
        if (payload is null || payload.IsEmpty)
        {
            return fail(Internal());
        }

        try
        {
            var response = parser.ParseFrom(payload);
            return hasOutcome(response) ? response : fail(Internal());
        }
        catch (InvalidProtocolBufferException)
        {
            return fail(Internal());
        }
    }

    private static ResponseMeta Meta(RequestMeta? request)
    {
        var result = new ResponseMeta();
        if (request?.CorrelationId is { } id)
        {
            result.CorrelationId = id.Clone();
        }

        return result;
    }

    private static ArcError Internal() => new()
    {
        Category = ErrorCategory.Internal,
        Code = "internal",
        MessageKey = "error.internal.internal",
        Effect = EffectCertainty.Unknown,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
    };

    private ArcError Uncertain() => new()
    {
        Category = ErrorCategory.State,
        Code = "node_unreachable",
        MessageKey = "error.state.node_unreachable",
        Effect = EffectCertainty.Unknown,
        Retry = new RetryAdvice { Mode = RetryMode.SameCommand },
        Details = new ErrorDetails { State = new StateFailure { State = "node", Reason = "channel_closed", Resource = new AggregateRef { Kind = "node", Id = NodeId.Clone() } } },
    };
}
