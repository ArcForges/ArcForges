// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using V1 = ArcForges.Contracts.Node.V1;
using V2 = ArcForges.Contracts.Sandbox.V2;

namespace ArcForges.CommandLine;

internal sealed class V2CliSession : IAsyncDisposable
{
    private readonly NodeSession _session;

    private V2CliSession(NodeSession session)
    {
        _session = session;
        var invoker = session.Channel.CallInvoker;
        Node = new V2.NodeService.NodeServiceClient(invoker);
        Sandboxes = new V2.SandboxService.SandboxServiceClient(invoker);
        Runs = new V2.RunService.RunServiceClient(invoker);
        Resources = new V2.ResourceService.ResourceServiceClient(invoker);
        Data = new V2.DataService.DataServiceClient(invoker);
    }

    internal V2.NodeService.NodeServiceClient Node { get; }
    internal V2.SandboxService.SandboxServiceClient Sandboxes { get; }
    internal V2.RunService.RunServiceClient Runs { get; }
    internal V2.ResourceService.ResourceServiceClient Resources { get; }
    internal V2.DataService.DataServiceClient Data { get; }
    internal V1.NodeInfo LocalNode => _session.Hello.Node;
    internal V1.NodeService.NodeServiceClient Lifecycle => _session.Channel.Node;

    internal static async Task<V2CliSession> OpenAsync(Cli cli, CancellationToken cancellationToken, bool autoStart = true)
    {
        ArgumentNullException.ThrowIfNull(cli);
        var session = await cli.ConnectAsync(autoStart, cancellationToken).ConfigureAwait(false);
        return new V2CliSession(session);
    }

    internal static async Task<V2CliSession> WaitForReadyAsync(Cli cli, CancellationToken ct)
    {
        var session = await NodeClient.WaitForReadyAsync(new NodeConnectOptions
        {
            Kind = V1.ClientKind.Cli,
            TestMode = cli.TestMode,
            AutoStart = false,
            ReadinessTimeout = cli.Timeout ?? TimeSpan.FromSeconds(15),
        }, ct).ConfigureAwait(false);
        return new V2CliSession(session);
    }

    internal async Task<V2.NodeServiceHandshakeResponse> HandshakeAsync(DateTime deadline, CancellationToken ct)
    {
        using var call = Node.HandshakeAsync(new V2.NodeServiceHandshakeRequest { Meta = Cli.Meta() },
            deadline: deadline, cancellationToken: ct);
        return await call.ResponseAsync.ConfigureAwait(false);
    }

    internal IDisposable PinConnection() => _session.PinConnection()
        ?? throw new NodeUnavailableException(NodeUnavailableReason.NotReady, "The local Node connection changed.", string.Empty);

    public ValueTask DisposeAsync() => _session.DisposeAsync();
}
