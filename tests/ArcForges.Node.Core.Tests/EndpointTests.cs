// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using ArcForges.Client;
using ArcForges.LocalRpc;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// How the client classifies the operating system's answers on the node's real endpoint (02 section 3; AF-DP-01 follow-up): a
/// missing endpoint is "not running" (auto-start may follow), a full Linux accept backlog (<c>EAGAIN</c>) is "busy" (retried with
/// bounded backoff, never auto-started).
/// </summary>
[Collection(SerialNodeTests.Name)]
public sealed class EndpointTests
{
    [Fact(Timeout = 60_000)]
    public async Task AMissingEndpointIsNotRunning()
    {
        var ct = TestContext.Current.CancellationToken;
        var endpoint = OperatingSystem.IsWindows()
            ? LocalRpcEndpoint.NamedPipe("af-missing-" + Guid.NewGuid().ToString("N")[..12])
            : LocalRpcEndpoint.UnixDomainSocket(Path.Combine("/tmp", "af-missing-" + Guid.NewGuid().ToString("N")[..12], "node.sock"));

        var failure = await Assert.ThrowsAsync<EndpointConnectException>(async () => await NodeConnector.OpenAsync(endpoint, ct));

        Assert.Equal(EndpointFailure.NotRunning, failure.Failure);
    }

    [Fact(Timeout = 60_000)]
    public async Task AStoppedNodesStaleSocketIsNotRunning()
    {
        var ct = TestContext.Current.CancellationToken;
        Assert.SkipWhen(OperatingSystem.IsWindows(), "A socket file left behind is the Linux case (a pipe disappears with its server).");
        await using var node = await InProcessNode.Create().StartAsync();
        Assert.Equal(0, await node.StopAsync());

        // The stopped node removed its socket; a crashed one leaves the file, which refuses connections (ECONNREFUSED).
        using (var stale = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified))
        {
            stale.Bind(new UnixDomainSocketEndPoint(node.Endpoint.Address));
        }

        var failure = await Assert.ThrowsAsync<EndpointConnectException>(async () => await NodeConnector.OpenAsync(node.Endpoint, ct));
        Assert.Equal(EndpointFailure.NotRunning, failure.Failure);
    }

    [Fact(Timeout = 60_000)]
    [Trait("env", "linux-real")]
    public async Task OnLinuxAFullAcceptBacklogIsBusyNotNotRunning()
    {
        var ct = TestContext.Current.CancellationToken;
        Assert.SkipWhen(OperatingSystem.IsWindows(), "EAGAIN from a full Unix socket backlog.");
        await using var node = await InProcessNode.Create().StartAsync();
        var classified = new List<EndpointFailure>();
        for (var round = 0; round < 50 && !classified.Contains(EndpointFailure.Busy); round++)
        {
            var held = new List<Socket>();
            try
            {
                // A burst faster than the node accepts fills the backlog (16): the next connect fails at once with EAGAIN.
                while (held.Count < 300)
                {
                    var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified) { Blocking = false };
                    try
                    {
                        socket.Connect(new UnixDomainSocketEndPoint(node.Endpoint.Address));
                        held.Add(socket);
                    }
                    catch (SocketException exception) when (exception.SocketErrorCode == SocketError.WouldBlock)
                    {
                        socket.Dispose();
                        break;
                    }
                }

                try
                {
                    await using var stream = await NodeConnector.OpenAsync(node.Endpoint, ct);
                }
                catch (EndpointConnectException exception)
                {
                    classified.Add(exception.Failure);
                }
            }
            finally
            {
                held.ForEach(socket => socket.Dispose());
            }
        }

        Assert.Contains(EndpointFailure.Busy, classified);
        Assert.DoesNotContain(EndpointFailure.NotRunning, classified);
        Assert.DoesNotContain(EndpointFailure.AccessDenied, classified);
    }
}
