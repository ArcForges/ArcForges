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

    /// <summary>Connects to the node, starting it when <paramref name="autoStart"/> is set and it is absent (02 section 3).</summary>
    public Task<NodeSession> ConnectAsync(bool autoStart, CancellationToken cancellationToken) =>
        NodeClient.ConnectAsync(new NodeConnectOptions { Kind = ClientKind.Cli, TestMode = TestMode, AutoStart = autoStart }, cancellationToken);

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
                return response;
            }
            catch (RpcException exception) when (exception.StatusCode == StatusCode.Unavailable && attempt <= MaxRetries)
            {
                Output.Trace($"{method} attempt {attempt} failed in transport ({exception.Status.Detail}); retrying with the same command ID");
                await Task.Delay(backoff.Next(attempt), cancellationToken).ConfigureAwait(false);
            }
        }
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
