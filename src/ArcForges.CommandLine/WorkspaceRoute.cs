// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using Grpc.Core;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.CommandLine;

/// <summary>Transitional V1 workspace commands use the original typed center route.</summary>
internal sealed class WorkspaceRoute(Cli cli, NodeSession session, Id nodeId, TimeSpan? unaryTimeout)
{
    private static readonly TimeSpan RetryBudget = TimeSpan.FromMinutes(2);
    private const int MaximumRetries = 5;
    private readonly FleetService.FleetServiceClient _fleet = new(session.Channel.CallInvoker);

    private Id NodeId { get; } = nodeId;

    /// <summary>Resolves an exact node name or UUID, defaulting to this node through the center.</summary>
    internal static async Task<(WorkspaceRoute? Route, int Exit)> ResolveAsync(Cli cli, NodeSession session, string? selection,
        CancellationToken cancellationToken)
    {
        var own = session.Hello.Node?.Node?.NodeId;
        if (own?.Value.Length != 16)
        {
            cli.Output.Error.WriteLine("error: the local node did not identify itself.");
            return (null, ExitCodes.Failed);
        }

        if (selection is null)
        {
            return (new WorkspaceRoute(cli, session, own.Clone(), cli.Timeout), ExitCodes.Success);
        }

        if (Guid.TryParseExact(selection, "D", out var uuid))
        {
            if (uuid == Guid.Empty)
            {
                return (null, cli.Output.Usage("--node: the all-zero node ID is invalid."));
            }

            return (new WorkspaceRoute(cli, session, new Id { Value = ByteString.CopyFrom(uuid.ToByteArray(bigEndian: true)) },
                cli.Timeout), ExitCodes.Success);
        }

        var fleet = new FleetService.FleetServiceClient(session.Channel.CallInvoker);
        var request = new FleetServiceListNodesRequest { Meta = Cli.Meta() };
        var response = await fleet.ListNodesAsync(request, deadline: cli.Deadline(TimeSpan.FromSeconds(20)),
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (response.Error is { } error)
        {
            return (null, Fail(cli, error, request.Meta.CorrelationId));
        }

        if (response.Value is null)
        {
            return (null, Fail(cli, MalformedResponse(), request.Meta.CorrelationId));
        }

        var matches = response.Value.Nodes.Where(node => string.Equals(node.Name, selection, StringComparison.Ordinal)).ToList();
        if (matches.Count == 1 && matches[0].NodeId?.Value.Length == 16)
        {
            return (new WorkspaceRoute(cli, session, matches[0].NodeId.Clone(), cli.Timeout), ExitCodes.Success);
        }

        var names = response.Value.Nodes.Take(20).Select(node => Messages.Plain(node.Name) + " (" + FormatNode(node.NodeId) + ")");
        var detail = matches.Count == 0 ? "no node has that exact name; available: " + string.Join(", ", names)
            : "the node name is ambiguous; select its UUID";
        return (null, cli.Output.Usage("--node: " + detail));
    }

    /// <summary>Prints the original workspace refusal and preserves uncertainty diagnostics.</summary>
    internal static int Fail(Cli cli, ArcError error, Id? correlation, Id? commandId = null)
    {
        if (error.Code is "not_signed_in" or "cloud_unreachable" && error.Effect == EffectCertainty.DidNotHappen)
        {
            var state = error.Code == "not_signed_in" ? "the node is not signed in" : "the center or the node channel is unavailable";
            if (cli.Output.Json)
            {
                cli.Output.Fail(error, correlation);
            }

            cli.Output.Error.WriteLine("arcforges: " + state + "; connect the center and retry this workspace operation");
            return ExitCodes.NotFound;
        }

        if (error.Code == "invalid_state" && error.Details?.State?.Reason == "replay_window_passed")
        {
            cli.Output.Fail(error, correlation);
            cli.Output.Error.WriteLine("arcforges: the command may have run; inspect workspace registration before taking further action" + CommandText(commandId));
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
                WarnUncertain(cli, commandId);
            }

            return ExitCodes.Failed;
        }

        var exit = cli.Output.Fail(error, correlation);
        return error.Code == "node_offline" && error.Effect == EffectCertainty.DidNotHappen ? ExitCodes.NodeUnreachable : exit;
    }

    private static void WarnUncertain(Cli cli, Id commandId) =>
        cli.Output.Error.WriteLine("arcforges: the command may have run; do not submit a new command" + CommandText(commandId));

    private static string CommandText(Id? commandId) => commandId is null ? string.Empty : " (command " + IdText.Format(commandId) + ")";

    private static string FormatNode(Id? id) => id?.Value.Length == 16 ? new Guid(id.Value.Span, bigEndian: true).ToString("D") : "unknown";

    public async Task<WorkspaceServiceUnregisterWorkspaceResponse> UnregisterWorkspaceAsync(WorkspaceServiceUnregisterWorkspaceRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var routed = new FleetServiceUnregisterNodeWorkspaceRequest { Meta = request.Meta?.Clone() ?? Cli.Meta(), NodeId = NodeId.Clone(), Request = request.ToByteString() };
        return await MutationAsync(
            (deadline, token) => _fleet.UnregisterNodeWorkspaceAsync(routed, deadline: deadline, cancellationToken: token).ResponseAsync,
            answer => answer.Error, answer => answer.Value?.Response, WorkspaceServiceUnregisterWorkspaceResponse.Parser,
            answer => NodeShapes.IsValid(answer), answer => answer.Error,
            error => new WorkspaceServiceUnregisterWorkspaceResponse { Meta = Meta(request.Meta), Error = error }, request.Meta!.CommandId, TimeSpan.FromSeconds(20), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<WorkspaceServiceListWorkspacesResponse> ListWorkspacesAsync(WorkspaceServiceListWorkspacesRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var routed = new FleetServiceListNodeWorkspacesRequest { Meta = request.Meta?.Clone() ?? Cli.Meta(), NodeId = NodeId.Clone(), Request = request.ToByteString() };
        return await ReadAsync(
            (deadline, token) => _fleet.ListNodeWorkspacesAsync(routed, deadline: deadline, cancellationToken: token).ResponseAsync,
            answer => answer.Error, answer => answer.Value?.Response, WorkspaceServiceListWorkspacesResponse.Parser,
            answer => NodeShapes.IsValid(answer),
            error => new WorkspaceServiceListWorkspacesResponse { Meta = Meta(request.Meta), Error = error }, TimeSpan.FromSeconds(20), cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<WorkspaceServiceGetWorkspaceResponse> GetWorkspaceAsync(WorkspaceServiceGetWorkspaceRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var routed = new FleetServiceGetNodeWorkspaceRequest { Meta = request.Meta?.Clone() ?? Cli.Meta(), NodeId = NodeId.Clone(), Request = request.ToByteString() };
        return await ReadAsync(
            (deadline, token) => _fleet.GetNodeWorkspaceAsync(routed, deadline: deadline, cancellationToken: token).ResponseAsync,
            answer => answer.Error, answer => answer.Value?.Response, WorkspaceServiceGetWorkspaceResponse.Parser,
            answer => NodeShapes.IsValid(answer),
            error => new WorkspaceServiceGetWorkspaceResponse { Meta = Meta(request.Meta), Error = error }, TimeSpan.FromSeconds(20), cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<TInner> ReadAsync<TOuter, TInner>(Func<DateTime, CancellationToken, Task<TOuter>> send,
        Func<TOuter, ArcError?> errorOf, Func<TOuter, ByteString?> payloadOf, MessageParser<TInner> parser, Func<TInner, bool> hasOutcome,
        Func<ArcError, TInner> fail, TimeSpan deadline, CancellationToken cancellationToken)
        where TInner : class, IMessage<TInner>
    {
        var answer = await send(DateTime.UtcNow + (unaryTimeout ?? deadline), cancellationToken).ConfigureAwait(false);
        return Decode(answer, errorOf, payloadOf, parser, hasOutcome, fail);
    }

    private async Task<TInner> MutationAsync<TOuter, TInner>(Func<DateTime, CancellationToken, Task<TOuter>> send,
        Func<TOuter, ArcError?> errorOf, Func<TOuter, ByteString?> payloadOf, MessageParser<TInner> parser, Func<TInner, bool> hasOutcome,
        Func<TInner, ArcError?> innerErrorOf, Func<ArcError, TInner> fail, Id command, TimeSpan deadline, CancellationToken cancellationToken)
        where TInner : class, IMessage<TInner>
    {
        // The server's CLI-session binding is valid only on the hello-checked local connection; never silently rebind after it is lost.
        using var connection = session.PinConnection();
        if (connection is null)
        {
            return fail(LocalConnectionChanged());
        }

        var started = Stopwatch.GetTimestamp();
        var backoff = new LocalRpc.LocalRpcBackoff(TimeSpan.FromMilliseconds(250), TimeSpan.FromSeconds(2));
        const int inFlight = 1;
        const int previousUnknown = 2;
        const int pendingApproval = 4;
        var uncertain = false;
        var risk = 0;
        var warned = 0;
        var waitedForApproval = false;
        void WarnIfUncertain()
        {
            if (Volatile.Read(ref risk) != 0 && Interlocked.Exchange(ref warned, 1) == 0)
            {
                WarnUncertain(cli, command);
            }
        }

        // Keep a bounded signal handler while the routed workspace mutation may still take effect.
        using var interrupts = new MutationInterrupts(WarnIfUncertain, cancellationToken);
        cancellationToken = interrupts.Token;
        try
        {
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
                    var unary = unaryTimeout ?? deadline;
                    var attemptBudget = MutationAttemptBudget(Stopwatch.GetElapsedTime(started), unary);
                    if (attemptBudget <= TimeSpan.Zero)
                    {
                        return fail(Uncertain());
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    Interlocked.Or(ref risk, inFlight);
                    var answer = await send(DateTime.UtcNow + attemptBudget, cancellationToken).ConfigureAwait(false);
                    error = errorOf(answer);
                    if (error is null)
                    {
                        var decoded = Decode(answer, errorOf, payloadOf, parser, hasOutcome, fail);
                        error = innerErrorOf(decoded);
                        if (error is null)
                        {
                            Interlocked.Exchange(ref risk, 0);
                            return decoded;
                        }
                    }

                    // A known refusal removes the in-flight uncertainty, except when a prior attempt is unknown or an approval can run later.
                    if (error.Effect == EffectCertainty.Unknown)
                    {
                        Interlocked.Or(ref risk, previousUnknown);
                    }
                    if (error.Code == "approval_required")
                    {
                        Interlocked.Or(ref risk, pendingApproval);
                    }
                    Interlocked.And(ref risk, ~inFlight);
                }
                catch (RpcException exception) when (!cancellationToken.IsCancellationRequested && exception.StatusCode is StatusCode.Unavailable or StatusCode.DeadlineExceeded)
                {
                    Interlocked.Or(ref risk, previousUnknown);
                    Interlocked.And(ref risk, ~inFlight);
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

                // These refusals must stay intact even if an earlier attempt was uncertain: replay_window_passed may name the recorded workspace,
                // and command_id_reused is an actionable defect. Neither authorizes a fresh command ID.
                if (error.Code == "command_id_reused" || error.Code == "invalid_state" && error.Details?.State?.Reason == "replay_window_passed")
                {
                    return fail(error);
                }

                uncertain |= error.Effect == EffectCertainty.Unknown;
                var retryable = error.Retry?.Mode is RetryMode.SameCommand or RetryMode.AfterTime &&
                    (error.Code == "node_unreachable" || error.Code == "operation_failed" && error.Details?.State?.Reason == "command_in_progress"
                        || uncertain && error.Code == "cloud_unreachable" && error.Effect == EffectCertainty.DidNotHappen);
                if (!retryable || retries >= MaximumRetries)
                {
                    return fail(uncertain && error.Effect == EffectCertainty.DidNotHappen ? Uncertain() : error);
                }

                // Do not spend the five mutation attempts while this node reconnects. Status reads and their waits use the same total budget;
                // the server checks the original center/installation binding again before each actual relay send.
                if (uncertain && !await AwaitOwnRelayAsync(started, cancellationToken).ConfigureAwait(false))
                {
                    return fail(Uncertain());
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
        catch (Exception exception) when (exception is OperationCanceledException or RpcException)
        {
            WarnIfUncertain();
            if (interrupts.Interrupted)
            {
                // A signal during this window used to exit 130; retain it even if the RPC reports Cancelled rather than throwing OCE.
                throw new OperationCanceledException("The routed mutation was interrupted.", exception, cancellationToken);
            }

            throw;
        }
    }

    /// <summary>Intercepts signals only while a routed mutation has no final result; normal attach/detach handlers resume on disposal.</summary>
    private sealed class MutationInterrupts : IDisposable
    {
        private readonly CancellationTokenSource _stop;
        private readonly List<PosixSignalRegistration> _registrations = [];
        private int _interrupted;

        public MutationInterrupts(Action warning, CancellationToken parent)
        {
            _stop = CancellationTokenSource.CreateLinkedTokenSource(parent);
            foreach (var signal in new[] { PosixSignal.SIGINT, PosixSignal.SIGTERM })
            {
                try
                {
                    _registrations.Add(PosixSignalRegistration.Create(signal, context =>
                    {
                        context.Cancel = true;
                        Interlocked.Exchange(ref _interrupted, 1);
                        try
                        {
                            warning();
                        }
                        finally
                        {
                            _stop.Cancel();
                        }
                    }));
                }
                catch (PlatformNotSupportedException)
                {
                }
            }
        }

        public bool Interrupted => Volatile.Read(ref _interrupted) != 0;

        public CancellationToken Token => _stop.Token;

        public void Dispose()
        {
            foreach (var registration in _registrations)
            {
                registration.Dispose();
            }
            _stop.Dispose();
        }
    }

    private async Task<bool> AwaitOwnRelayAsync(long started, CancellationToken cancellationToken)
    {
        while (true)
        {
            var remaining = RetryBudget - Stopwatch.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero)
            {
                return false;
            }

            var unary = unaryTimeout ?? TimeSpan.FromSeconds(5);
            var limit = remaining < unary ? remaining : unary;
            AccountServiceGetAccountStatusResponse response;
            try
            {
                response = await session.Channel.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest { Meta = Cli.Meta() },
                    deadline: DateTime.UtcNow + limit, cancellationToken: cancellationToken).ResponseAsync.ConfigureAwait(false);
            }
            catch (RpcException exception) when (!cancellationToken.IsCancellationRequested
                && exception.StatusCode is StatusCode.Unavailable or StatusCode.DeadlineExceeded)
            {
                // In particular, a lost local connection cannot be replaced while this mutation remains uncertain.
                return false;
            }

            if (response.Error is not null || response.Value?.Status is not { } status || !status.HasSignedIn || !status.SignedIn
                || !status.HasCloudLinkEnabled || !status.CloudLinkEnabled || !status.HasRelay)
            {
                return false;
            }

            if (status.Relay == RelayState.Connected)
            {
                return true;
            }

            if (status.Relay is not (RelayState.Connecting or RelayState.Backoff))
            {
                return false;
            }

            remaining = RetryBudget - Stopwatch.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero)
            {
                return false;
            }

            var pause = remaining < TimeSpan.FromSeconds(1) ? remaining : TimeSpan.FromSeconds(1);
            await Task.Delay(pause, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Caps a blocked mutation attempt by both its unary deadline and what remains of the two-minute retry budget.</summary>
    private static TimeSpan MutationAttemptBudget(TimeSpan elapsed, TimeSpan unary)
    {
        var remaining = RetryBudget - elapsed;
        return remaining <= TimeSpan.Zero ? TimeSpan.Zero : remaining < unary ? remaining : unary;
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
            return fail(MalformedResponse());
        }

        try
        {
            var response = parser.ParseFrom(payload);
            return hasOutcome(response) ? response : fail(MalformedResponse());
        }
        catch (InvalidProtocolBufferException)
        {
            return fail(MalformedResponse());
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

    private static ArcError LocalConnectionChanged() => new()
    {
        Category = ErrorCategory.State,
        Code = "invalid_state",
        MessageKey = "error.state.invalid_state",
        Effect = EffectCertainty.DidNotHappen,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = CommandIds.New(),
        Details = new ErrorDetails { State = new StateFailure { State = "local_connection", Reason = "session_changed" } },
    };

    internal static ArcError MalformedResponse() => new()
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
