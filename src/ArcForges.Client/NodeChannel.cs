// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using Grpc.Core;

namespace ArcForges.Client;

/// <summary>
/// The LocalRpc client channel to one node endpoint (architecture 12 section 1 <c>NodeChannel</c>): one HTTP/2 connection over
/// the verified pipe or socket, with the generated <see cref="NodeService"/>, <see cref="NodeEventService"/>, <see cref="TaskService"/>,
/// <see cref="ResourceService"/>, <see cref="QueueService"/>, <see cref="PolicyService"/> and <see cref="ApprovalService"/> clients. It
/// records how its last connection attempt ended, so a failed call can be classified (not running, busy, refused).
/// </summary>
public sealed class NodeChannel : IAsyncDisposable
{
    private readonly LocalRpcClientChannel _channel;
    private readonly Lock _connectionGate = new();
    private int _connectionGeneration;
    private int _connectionPins;
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
        Queue = new QueueService.QueueServiceClient(_channel.CallInvoker);
        Policy = new PolicyService.PolicyServiceClient(_channel.CallInvoker);
        Approvals = new ApprovalService.ApprovalServiceClient(_channel.CallInvoker);
        Account = new AccountService.AccountServiceClient(_channel.CallInvoker);
    }

    /// <summary>The call invoker for additional services served on this same authenticated local connection.</summary>
    public CallInvoker CallInvoker => _channel.CallInvoker;

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

    /// <summary>The generated QueueService client.</summary>
    public QueueService.QueueServiceClient Queue { get; }

    /// <summary>The generated PolicyService client.</summary>
    public PolicyService.PolicyServiceClient Policy { get; }

    /// <summary>The generated ApprovalService client.</summary>
    public ApprovalService.ApprovalServiceClient Approvals { get; }

    /// <summary>The generated AccountService client (AF-CTR-04: account status and sign-out; sign-in arrives with part N2).</summary>
    public AccountService.AccountServiceClient Account { get; }

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

    // A mutation retry must stay on the hello-checked connection whose node-side session retains its center binding.
    internal int ConnectionGeneration => Volatile.Read(ref _connectionGeneration);

    internal IDisposable? PinConnection(int expectedGeneration)
    {
        lock (_connectionGate)
        {
            if (expectedGeneration == 0 || _connectionGeneration != expectedGeneration)
            {
                return null;
            }

            _connectionPins++;
            return new ConnectionPin(this);
        }
    }

    private sealed class ConnectionPin(NodeChannel channel) : IDisposable
    {
        private NodeChannel? _channel = channel;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _channel, null) is not { } owner)
            {
                return;
            }

            lock (owner._connectionGate)
            {
                owner._connectionPins--;
            }
        }
    }

    private async ValueTask<Stream> OpenAsync(CancellationToken cancellationToken)
    {
        try
        {
            lock (_connectionGate)
            {
                if (_connectionPins != 0)
                {
                    throw new IOException("The node connection is pinned by an unresolved mutation.");
                }
            }

            var stream = await NodeConnector.OpenAsync(Endpoint, cancellationToken).ConfigureAwait(false);
            lock (_connectionGate)
            {
                // A pin may have been acquired while the OS connection was opening.
                if (_connectionPins != 0)
                {
                    stream.Dispose();
                    throw new IOException("The node connection is pinned by an unresolved mutation.");
                }

                Volatile.Write(ref _lastFailure, null);
                Volatile.Write(ref _connected, 1);
                Volatile.Write(ref _connectionGeneration, _connectionGeneration + 1);
                return stream;
            }
        }
        catch (EndpointConnectException exception)
        {
            Volatile.Write(ref _lastFailure, exception);
            throw;
        }
    }
}
