// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.CommandLine;

/// <summary>The parsed global options and the services every command uses.</summary>
public sealed class Cli
{
    /// <summary>The transport retries of a mutation with the same command ID (experience/cli.md section 4).</summary>
    public const int MaxRetries = 3;

    internal Cli(CliOutput output, bool testMode, TimeSpan? timeout, bool yes)
    {
        Output = output;
        TestMode = testMode;
        Timeout = timeout;
        Yes = yes;
    }

    /// <summary>The output.</summary>
    public CliOutput Output { get; }

    /// <summary><c>--test-mode</c>: the <c>ARCFORGES_*</c> test hooks apply.</summary>
    public bool TestMode { get; }

    /// <summary><c>--timeout</c>: the client deadline of unary calls.</summary>
    public TimeSpan? Timeout { get; }

    /// <summary><c>--yes</c>.</summary>
    public bool Yes { get; }

    /// <summary><c>--wait-approval</c>: how long a mutation that needs an approval waits for its decision (cli.md section 5).</summary>
    public TimeSpan? WaitApproval { get; init; }

    /// <summary>The session of the command's last connection (the approval wait reads the approval through it).</summary>
    private NodeSession? Session { get; set; }

    /// <summary>Connects to the node, starting it when <paramref name="autoStart"/> is set and it is absent (02 section 3).</summary>
    public async Task<NodeSession> ConnectAsync(bool autoStart, CancellationToken cancellationToken)
    {
        var session = await NodeClient.ConnectAsync(new NodeConnectOptions { Kind = ClientKind.Cli, TestMode = TestMode, AutoStart = autoStart }, cancellationToken)
            .ConfigureAwait(false);
        Session = session;
        return session;
    }

    /// <summary>The deadline of a unary call: <c>--timeout</c>, or the method's own.</summary>
    public DateTime Deadline(TimeSpan methodDeadline) => DateTime.UtcNow + (Timeout ?? methodDeadline);

    /// <summary>A request meta with a new correlation ID.</summary>
    public static RequestMeta Meta() => new() { CorrelationId = CommandIds.New() };

    /// <summary>Runs a read call, tracing it with <c>--verbose</c>.</summary>
    public async Task<TResponse> CallAsync<TResponse>(string method, RequestMeta meta, Func<AsyncUnaryCall<TResponse>> call)
    {
        ArgumentNullException.ThrowIfNull(call);
        var watch = Stopwatch.StartNew();
        var response = await call().ResponseAsync.ConfigureAwait(false);
        Output.Trace($"{method} {watch.Elapsed.TotalMilliseconds:0.0} ms (correlation {IdText.Format(meta?.CorrelationId)})");
        return response;
    }

    /// <summary>
    /// Runs a mutation: the same command ID and the same request bytes on every attempt, with up to three retries of transport
    /// failures after a jittered backoff (experience/cli.md section 4), so the node executes it at most once.
    /// </summary>
    public async Task<TResponse> MutateAsync<TRequest, TResponse>(string method, Id commandId, UserAction<TRequest> action, Func<TRequest, AsyncUnaryCall<TResponse>> call,
        CancellationToken cancellationToken)
        where TRequest : IMessage<TRequest>
        where TResponse : IMessage
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(call);
        var backoff = new LocalRpc.LocalRpcBackoff(TimeSpan.FromMilliseconds(200), TimeSpan.FromSeconds(2));
        for (var attempt = 1; ; attempt++)
        {
            var watch = Stopwatch.StartNew();
            try
            {
                var response = await call(action.RequestForAttempt()).ResponseAsync.ConfigureAwait(false);
                Output.Trace($"{method} {watch.Elapsed.TotalMilliseconds:0.0} ms, attempt {attempt} (command {IdText.Format(commandId)})");
                if (WaitApproval is { } wait && Session is { } session && ErrorOf(response) is { Code: "approval_required" } required
                    && required.Details?.State?.Resource?.Id is { } approvalId
                    && await AwaitDecisionAsync(session, approvalId, wait, cancellationToken).ConfigureAwait(false))
                {
                    // 11 section 1: the approved request ran under this command ID; resending it returns the executed outcome (or the refusal).
                    response = await call(action.RequestForAttempt()).ResponseAsync.ConfigureAwait(false);
                    Output.Trace($"{method} resent after the approval's decision (command {IdText.Format(commandId)})");
                }

                return response;
            }
            catch (RpcException exception) when (exception.StatusCode == StatusCode.Unavailable && attempt <= MaxRetries)
            {
                Output.Trace($"{method} attempt {attempt} failed in transport ({exception.Status.Detail}); retrying with the same command ID");
                await Task.Delay(backoff.Next(attempt), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// The <c>error</c> of a node response without knowing its type: every response has <c>meta = 1</c> and the <c>outcome</c> oneof with
    /// <c>value = 2</c> and <c>error = 3</c> (contracts README section 4).
    /// </summary>
    internal static ArcError? ErrorOf(IMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        var input = new CodedInputStream(response.ToByteArray());
        while (input.ReadTag() is var tag and not 0)
        {
            if (WireFormat.GetTagFieldNumber(tag) == 3 && WireFormat.GetTagWireType(tag) == WireFormat.WireType.LengthDelimited)
            {
                var error = new ArcError();
                input.ReadMessage(error);
                return error;
            }

            input.SkipLastField();
        }

        return null;
    }

    /// <summary>
    /// Waits up to <paramref name="wait"/> for the approval's decision (cli.md section 5, <c>--wait-approval</c>), polling <c>GetApproval</c>
    /// every second. True when it was decided (executed, failed, denied, expired or withdrawn): the request is then sent again.
    /// </summary>
    private async Task<bool> AwaitDecisionAsync(NodeSession session, Id approvalId, TimeSpan wait, CancellationToken cancellationToken)
    {
        Output.Error.WriteLine($"Waiting for approval {IdText.Format(approvalId)} (approve in ArcForges Desktop or with 'arcforges approvals approve {IdText.Format(approvalId)}')");
        var until = DateTime.UtcNow + wait;
        while (DateTime.UtcNow < until)
        {
            var request = new ApprovalServiceGetApprovalRequest { Meta = Meta(), ApprovalId = approvalId };
            var response = await CallAsync("GetApproval", request.Meta, () => session.Channel.Approvals.GetApprovalAsync(request, deadline: Deadline(TimeSpan.FromSeconds(5)),
                cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (response.Error is not null || response.Value.Approval.State is not (ApprovalState.Pending or ApprovalState.Approved))
            {
                return true;
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    /// <summary>Runs a command body and maps connection and transport failures to the exit codes of section 3.</summary>
    public async Task<int> GuardAsync(Func<Task<int>> body)
    {
        ArgumentNullException.ThrowIfNull(body);
        try
        {
            return await body().ConfigureAwait(false);
        }
        catch (NodeUnavailableException exception)
        {
            return Output.Fail(exception);
        }
        catch (RpcException exception) when (exception.StatusCode is StatusCode.Unavailable)
        {
            return Output.Fail(new NodeUnavailableException(NodeUnavailableReason.NotReady,
                "the node closed the connection (" + exception.Status.Detail + ")", "check 'arcforges node health'"));
        }
        catch (RpcException exception) when (exception.StatusCode is StatusCode.DeadlineExceeded)
        {
            Output.Error.WriteLine("error: the node did not answer before the deadline" + (LocalRpc.LocalRpcRefusal.TryRead(exception, out var refusal) ? $" ({refusal})" : string.Empty));
            return ExitCodes.Failed;
        }
        catch (RpcException exception)
        {
            Output.Error.WriteLine($"error: the call failed ({exception.StatusCode}: {exception.Status.Detail})");
            return ExitCodes.Failed;
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
    }

}
