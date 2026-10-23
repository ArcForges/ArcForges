// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;

namespace ArcForges.Client;

/// <summary>
/// The LocalRpc client channel to one node endpoint (architecture 12 section 1 <c>NodeChannel</c>): one HTTP/2 connection over
/// the verified pipe or socket, with the generated <see cref="NodeService"/>, <see cref="NodeEventService"/>, <see cref="TaskService"/> and
/// <see cref="ResourceService"/> clients. It
/// records how its last connection attempt ended, so a failed call can be classified (not running, busy, refused).
/// </summary>
public sealed class NodeChannel : IAsyncDisposable
{
    private readonly LocalRpcClientChannel _channel;
    private int _connected;
    private EndpointConnectException? _lastFailure;

    private NodeChannel(LocalRpcEndpoint endpoint)
    {
        Endpoint = endpoint;
        _channel = LocalRpcClientChannel.CreateFromStreams(OpenAsync);
        Node = new NodeService.NodeServiceClient(_channel.CallInvoker);
        Events = new NodeEventService.NodeEventServiceClient(_channel.CallInvoker);
        Tasks = new TaskService.TaskServiceClient(_channel.CallInvoker);
        Resources = new ResourceService.ResourceServiceClient(_channel.CallInvoker);
    }

    /// <summary>The endpoint.</summary>
    public LocalRpcEndpoint Endpoint { get; }

    /// <summary>The generated NodeService client.</summary>
    public NodeService.NodeServiceClient Node { get; }

    /// <summary>The generated NodeEventService client.</summary>
    public NodeEventService.NodeEventServiceClient Events { get; }

    /// <summary>The generated TaskService client.</summary>
    public TaskService.TaskServiceClient Tasks { get; }

    /// <summary>The generated ResourceService client.</summary>
    public ResourceService.ResourceServiceClient Resources { get; }

    /// <summary>True once an operating-system connection to the endpoint was opened.</summary>
    public bool EverConnected => Volatile.Read(ref _connected) != 0;

    /// <summary>The classified failure of the last connection attempt, or <see langword="null"/> when it succeeded or none failed.</summary>
    public EndpointConnectException? LastFailure => Volatile.Read(ref _lastFailure);

    /// <summary>Creates a channel; nothing connects until the first call.</summary>
    public static NodeChannel Create(LocalRpcEndpoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        return new NodeChannel(endpoint);
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => _channel.DisposeAsync();

    private async ValueTask<Stream> OpenAsync(CancellationToken cancellationToken)
    {
        try
        {
            var stream = await NodeConnector.OpenAsync(Endpoint, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _lastFailure, null);
            Volatile.Write(ref _connected, 1);
            return stream;
        }
        catch (EndpointConnectException exception)
        {
            Volatile.Write(ref _lastFailure, exception);
            throw;
        }
    }
}
