// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using Grpc.Core;

namespace ArcForges.Client;

/// <summary>The endpoint a client will use and where it came from (architecture 02 section 3).</summary>
/// <param name="Endpoint">The pipe or socket.</param>
/// <param name="Source"><c>ARCFORGES_ENDPOINT</c>, <c>endpoint.json</c> or <c>default</c>.</param>
/// <param name="DataRoot">The data root that was resolved.</param>
public sealed record ResolvedEndpoint(LocalRpcEndpoint Endpoint, string Source, string DataRoot);

/// <summary><c>NodeEndpointResolver</c> (architecture 12 section 1): the endpoint override, the descriptor, or the default.</summary>
public static class NodeEndpointResolver
{
    /// <summary>
    /// Resolves the endpoint: <c>ARCFORGES_ENDPOINT</c> (test mode only); otherwise <c>run/endpoint.json</c> when its process is
    /// alive and started at the recorded time; otherwise the default per-user pipe or socket.
    /// </summary>
    public static ResolvedEndpoint Resolve(bool testMode)
    {
        var dataRoot = NodeLocations.ResolveDataRoot(testMode);
        if (NodeLocations.EndpointOverride(testMode) is not null)
        {
            return new ResolvedEndpoint(NodeLocations.Endpoint(testMode, dataRoot), NodeLocations.EndpointVariable, dataRoot);
        }

        var descriptor = EndpointDescriptor.TryRead(NodeLocations.EndpointDescriptorFile(dataRoot));
        if (descriptor is not null && descriptor.ProcessIsAlive())
        {
            try
            {
                var endpoint = OperatingSystem.IsWindows()
                    ? LocalRpcEndpoint.NamedPipe(descriptor.Endpoint)
                    : LocalRpcEndpoint.UnixDomainSocket(descriptor.Endpoint);
                return new ResolvedEndpoint(endpoint, "endpoint.json", dataRoot);
            }
            catch (ArgumentException)
            {
                // A descriptor naming an invalid endpoint is ignored; the default applies.
            }
        }

        return new ResolvedEndpoint(NodeLocations.Endpoint(testMode, dataRoot), "default", dataRoot);
    }
}

/// <summary>Why a client could not reach a ready node.</summary>
public enum NodeUnavailableReason
{
    /// <summary>The node is not running and auto-start was not requested.</summary>
    NotRunning = 1,

    /// <summary>Auto-start was refused (CI job or a sandbox job without breakaway).</summary>
    AutoStartRefused = 2,

    /// <summary>Auto-start failed (supervisor or unit missing, or the OS refused).</summary>
    AutoStartFailed = 3,

    /// <summary>The node was started (or is starting) but did not become ready in time.</summary>
    NotReady = 4,

    /// <summary>The node stayed busy (no free pipe instance, or a full socket backlog) for the whole retry budget.</summary>
    Busy = 5,

    /// <summary>The endpoint is not this user's, or the node refused the connection.</summary>
    AccessDenied = 6,

    /// <summary>The node refused the client's contract major version (<c>VALIDATION/incompatible_version</c>).</summary>
    Incompatible = 7,
}

/// <summary>A client could not reach a ready node; <see cref="Guidance"/> says what the user can do.</summary>
public sealed class NodeUnavailableException : Exception
{
    /// <summary>Creates the exception.</summary>
    public NodeUnavailableException(NodeUnavailableReason reason, string message, string guidance, ArcError? error = null, Exception? innerException = null)
        : base(message, innerException)
    {
        Reason = reason;
        Guidance = guidance;
        Error = error;
    }

    /// <summary>Creates the exception.</summary>
    public NodeUnavailableException()
        : this(NodeUnavailableReason.NotRunning, "The node is not reachable.", string.Empty)
    {
    }

    /// <summary>Creates the exception.</summary>
    public NodeUnavailableException(string message)
        : this(NodeUnavailableReason.NotRunning, message, string.Empty)
    {
    }

    /// <summary>Creates the exception.</summary>
    public NodeUnavailableException(string message, Exception innerException)
        : this(NodeUnavailableReason.NotRunning, message, string.Empty, null, innerException)
    {
    }

    /// <summary>Why.</summary>
    public NodeUnavailableReason Reason { get; }

    /// <summary>What the user can do.</summary>
    public string Guidance { get; }

    /// <summary>The node's error, when it answered with one (for example <c>VALIDATION/incompatible_version</c>).</summary>
    public ArcError? Error { get; }

    /// <summary>The connection state this failure leaves a long-lived client in.</summary>
    public ConnectionState State => Reason switch
    {
        NodeUnavailableReason.AccessDenied => ConnectionState.AccessDenied,
        NodeUnavailableReason.Incompatible => ConnectionState.Incompatible,
        _ => ConnectionState.NodeStopped,
    };
}

/// <summary>How a client connects.</summary>
public sealed record NodeConnectOptions
{
    /// <summary>The client kind reported in the hello.</summary>
    public ClientKind Kind { get; init; } = ClientKind.Cli;

    /// <summary>Honour the <c>ARCFORGES_*</c> test hooks and pass <c>--test-mode</c> to what auto-start launches.</summary>
    public bool TestMode { get; init; }

    /// <summary>Start the node when it is absent (02 section 3).</summary>
    public bool AutoStart { get; init; } = true;

    /// <summary>How long to wait for a started node to become ready: 5 s for the CLI, 15 s for the Desktop and the MCP adapter.</summary>
    public TimeSpan ReadinessTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>How long to keep retrying a busy endpoint (bounded backoff; a busy node is never auto-started).</summary>
    public TimeSpan BusyRetryBudget { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>The deadline of one hello call (node.proto: 5 s).</summary>
    public TimeSpan HelloDeadline { get; init; } = TimeSpan.FromSeconds(5);
}

/// <summary>A connected, hello-checked session with the node.</summary>
public sealed class NodeSession : IAsyncDisposable
{
    internal NodeSession(NodeChannel channel, ResolvedEndpoint endpoint, NodeServiceHelloValue hello, AutoStartResult? autoStart)
    {
        Channel = channel;
        Endpoint = endpoint;
        Hello = hello;
        AutoStart = autoStart;
    }

    /// <summary>The channel.</summary>
    public NodeChannel Channel { get; }

    /// <summary>The resolved endpoint.</summary>
    public ResolvedEndpoint Endpoint { get; }

    /// <summary>The node's hello answer (node information, assigned origin, warnings).</summary>
    public NodeServiceHelloValue Hello { get; }

    /// <summary>What auto-start did, or <see langword="null"/> when the node was already running.</summary>
    public AutoStartResult? AutoStart { get; }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => Channel.DisposeAsync();
}

/// <summary>
/// Connects to the node and performs the client hello (architecture 02 section 3, 12 section 1). A node that is not running is
/// started (when allowed) and awaited; a busy endpoint (no free pipe instance, or <c>EAGAIN</c> from a full socket backlog) is
/// retried with bounded backoff and never treated as "not running".
/// </summary>
public static class NodeClient
{
    private const string StartGuidance = "start it with 'arcforges node run --background' or the Desktop";

    /// <summary>Connects; throws <see cref="NodeUnavailableException"/> when no ready node can be reached.</summary>
    public static async Task<NodeSession> ConnectAsync(NodeConnectOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var hello = ClientProcess.Hello(options.Kind);
        var endpoint = NodeEndpointResolver.Resolve(options.TestMode);
        var channel = NodeChannel.Create(endpoint.Endpoint);
        try
        {
            var first = await ConnectWithRetriesAsync(channel, hello, options, startedAt: null, cancellationToken).ConfigureAwait(false);
            if (first.Value is { } value)
            {
                return new NodeSession(channel, endpoint, value, null);
            }

            // The node is not running.
            if (!options.AutoStart)
            {
                throw new NodeUnavailableException(NodeUnavailableReason.NotRunning, "node not running", StartGuidance);
            }

            var start = NodeAutoStart.Start(options.TestMode);
            switch (start.Outcome)
            {
                case AutoStartOutcome.RefusedInCi:
                case AutoStartOutcome.RefusedInSandbox:
                    throw new NodeUnavailableException(NodeUnavailableReason.AutoStartRefused,
                        $"node not running; auto-start is refused here ({start.Detail})", StartGuidance);
                case AutoStartOutcome.Failed:
                    throw new NodeUnavailableException(NodeUnavailableReason.AutoStartFailed,
                        $"node not running; it could not be started ({start.Detail})", "run 'arcforges node run' in a terminal");
            }

            await channel.DisposeAsync().ConfigureAwait(false);
            endpoint = NodeEndpointResolver.Resolve(options.TestMode);
            channel = NodeChannel.Create(endpoint.Endpoint);
            var started = await ConnectWithRetriesAsync(channel, hello, options, startedAt: TimeProvider.System.GetTimestamp(), cancellationToken)
                .ConfigureAwait(false);
            return new NodeSession(channel, endpoint, started.Value!, start);
        }
        catch
        {
            await channel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Waits until a node is ready, without starting one (<c>arcforges node wait-ready</c>, and after <c>node run --background</c>):
    /// it answers its hello in READY or DEGRADED. The node listens from startup step 7 and reports readiness at step 9 (02 section 2),
    /// so a hello answered in STARTING or RECOVERING is retried, as is every failure except a refusal, until
    /// <see cref="NodeConnectOptions.ReadinessTimeout"/>.
    /// </summary>
    public static async Task<NodeSession> WaitForReadyAsync(NodeConnectOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var hello = ClientProcess.Hello(options.Kind);
        var started = TimeProvider.System.GetTimestamp();
        while (true)
        {
            var endpoint = NodeEndpointResolver.Resolve(options.TestMode);
            var channel = NodeChannel.Create(endpoint.Endpoint);
            try
            {
                // Re-resolve each second: the node writes its endpoint descriptor once it listens.
                var remaining = options.ReadinessTimeout - TimeProvider.System.GetElapsedTime(started);
                var slice = options with { ReadinessTimeout = remaining < TimeSpan.FromSeconds(1) ? remaining : TimeSpan.FromSeconds(1) };
                var ready = await ConnectWithRetriesAsync(channel, hello, slice, TimeProvider.System.GetTimestamp(), cancellationToken).ConfigureAwait(false);
                if (ready.Value!.Node.State is NodeLifecycleState.Starting or NodeLifecycleState.Recovering)
                {
                    throw new NodeUnavailableException(NodeUnavailableReason.NotReady, $"the node is {ready.Value.Node.State.ToString().ToLowerInvariant()}",
                        "check 'arcforges node health' or the node log in <data root>/logs/node");
                }

                return new NodeSession(channel, endpoint, ready.Value!, null);
            }
            catch (NodeUnavailableException exception) when (exception.Reason == NodeUnavailableReason.NotReady)
            {
                await channel.DisposeAsync().ConfigureAwait(false);
                if (TimeProvider.System.GetElapsedTime(started) >= options.ReadinessTimeout)
                {
                    throw new NodeUnavailableException(NodeUnavailableReason.NotReady,
                        $"no node became ready within {options.ReadinessTimeout.TotalSeconds:0} s", exception.Guidance, exception.Error, exception);
                }

                // A node that answered while starting or recovering is asked again shortly, not at once.
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await channel.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }

    /// <summary>
    /// Says hello until the node answers. Without <paramref name="startedAt"/> a "not running" result is returned at once (the
    /// caller decides on auto-start); with it, every failure except a refusal is retried until the readiness timeout.
    /// </summary>
    private static async Task<HelloAttempt> ConnectWithRetriesAsync(NodeChannel channel, ClientHello hello, NodeConnectOptions options,
        long? startedAt, CancellationToken cancellationToken)
    {
        var busySince = (long?)null;
        var drops = 0;
        var attempt = 0;
        var backoff = new LocalRpcBackoff(TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(500));
        while (true)
        {
            attempt++;
            var result = await HelloOnceAsync(channel, hello, options.HelloDeadline, cancellationToken).ConfigureAwait(false);
            switch (result.Kind)
            {
                case HelloKind.Ready:
                    return result;
                case HelloKind.Incompatible:
                    throw new NodeUnavailableException(NodeUnavailableReason.Incompatible,
                        "the node's contract version is incompatible with this client",
                        "install matching ArcForges versions of the client and the node", result.Error);
                case HelloKind.AccessDenied:
                    throw new NodeUnavailableException(NodeUnavailableReason.AccessDenied, result.Detail,
                        "the node accepts only processes of its own user; run the client as that user");
                case HelloKind.NotRunning when startedAt is null:
                    return result;
                case HelloKind.Busy:
                    busySince ??= TimeProvider.System.GetTimestamp();
                    if (TimeProvider.System.GetElapsedTime(busySince.Value) > options.BusyRetryBudget && startedAt is null)
                    {
                        throw new NodeUnavailableException(NodeUnavailableReason.Busy,
                            $"the node is busy and accepted no connection within {options.BusyRetryBudget.TotalSeconds:0} s ({result.Detail})",
                            "retry later; the node is running");
                    }

                    break;
                case HelloKind.Dropped:
                    if (++drops >= 3)
                    {
                        throw new NodeUnavailableException(NodeUnavailableReason.AccessDenied,
                            "the node closed the connection without answering",
                            "the node accepts only processes of its own user that it can identify (on Windows an elevated client of a non-elevated node is refused)");
                    }

                    break;
            }

            if (startedAt is { } since && TimeProvider.System.GetElapsedTime(since) > options.ReadinessTimeout)
            {
                throw new NodeUnavailableException(NodeUnavailableReason.NotReady,
                    $"the node did not become ready within {options.ReadinessTimeout.TotalSeconds:0} s ({result.Detail})",
                    "check 'arcforges node health' or the node log in <data root>/logs/node");
            }

            var wait = result.Kind == HelloKind.Stopping ? TimeSpan.FromSeconds(2) : backoff.Next(Math.Min(attempt, 8));
            await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<HelloAttempt> HelloOnceAsync(NodeChannel channel, ClientHello hello, TimeSpan deadline, CancellationToken cancellationToken)
    {
        try
        {
            var response = await channel.Node.HelloAsync(new NodeServiceHelloRequest { Hello = hello },
                deadline: DateTime.UtcNow + deadline, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (response.OutcomeCase == NodeServiceHelloResponse.OutcomeOneofCase.Value)
            {
                return new HelloAttempt(HelloKind.Ready, "ready", response.Value, null);
            }

            return response.Error.Code switch
            {
                "incompatible_version" => new HelloAttempt(HelloKind.Incompatible, "incompatible", null, response.Error),
                "node_stopping" => new HelloAttempt(HelloKind.Stopping, "the node is stopping", null, response.Error),
                _ => throw new NodeUnavailableException(NodeUnavailableReason.NotReady,
                    $"the node refused the hello ({response.Error.Category}/{response.Error.Code})", "check 'arcforges node health'", response.Error),
            };
        }
        catch (RpcException exception) when (exception.StatusCode != StatusCode.Cancelled || !cancellationToken.IsCancellationRequested)
        {
            if (channel.LastFailure is { } failure)
            {
                return failure.Failure switch
                {
                    EndpointFailure.Busy => new HelloAttempt(HelloKind.Busy, failure.Message, null, null),
                    EndpointFailure.AccessDenied => new HelloAttempt(HelloKind.AccessDenied, failure.Message, null, null),
                    _ => new HelloAttempt(HelloKind.NotRunning, failure.Message, null, null),
                };
            }

            return exception.StatusCode == StatusCode.DeadlineExceeded
                ? new HelloAttempt(HelloKind.Busy, "the hello timed out", null, null)
                : new HelloAttempt(HelloKind.Dropped, $"the connection closed ({exception.StatusCode})", null, null);
        }
    }

    private enum HelloKind
    {
        Ready,
        NotRunning,
        Busy,
        Dropped,
        AccessDenied,
        Incompatible,
        Stopping,
    }

    private sealed record HelloAttempt(HelloKind Kind, string Detail, NodeServiceHelloValue? Value, ArcError? Error);
}
