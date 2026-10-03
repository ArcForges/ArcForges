// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.LocalRpc.Platform.V1;
using Google.Protobuf;
using Grpc.Core;

namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// The test stand-in for an owner's durable store: it survives the death of a helper (a helper and its receipt table are
/// created anew, the store is not), so the tests can ask it what really happened, the way an owner reconciles. In memory by default;
/// given a directory it is one file per command, which a helper in another process and the parent both see.
/// </summary>
internal sealed class OwnerStore(string? directory = null)
{
    private readonly ConcurrentDictionary<Guid, int> _commits = new();
    private readonly object _files = new();

    /// <summary>Commits across every command.</summary>
    internal int Total
    {
        get
        {
            if (directory is null)
            {
                return _commits.Values.Sum();
            }

            lock (_files)
            {
                return Directory.EnumerateFiles(directory, "*.committed").Sum(path => File.ReadAllLines(path).Length);
            }
        }
    }

    internal int Commits(Guid commandId)
    {
        if (directory is null)
        {
            return _commits.TryGetValue(commandId, out var count) ? count : 0;
        }

        lock (_files)
        {
            var path = FileOf(commandId);
            return File.Exists(path) ? File.ReadAllLines(path).Length : 0;
        }
    }

    internal void Commit(Guid commandId)
    {
        if (directory is null)
        {
            _ = _commits.AddOrUpdate(commandId, 1, (_, count) => count + 1);
            return;
        }

        lock (_files)
        {
            File.AppendAllText(FileOf(commandId), "committed" + Environment.NewLine);
        }
    }

    private string FileOf(Guid commandId) => Path.Combine(directory!, commandId.ToString("N") + ".committed");
}

/// <summary>
/// A hand-written, test-only unary service shaped like generated code. The pinned Platform contract has no cancel or health
/// method (<c>CancelSession</c> is in the Sandbox contract, which this repository does not admit), so the cancel wire used under
/// saturation is this one. It proves how a declared control method uses the reserved slots and reaches the receipt table,
/// never the contract of a real service.
/// </summary>
internal static class CommandProbe
{
    internal const string ServiceName = "arcforges.test.commands.v1.CommandProbe";

    private static readonly Marshaller<byte[]> Bytes = Marshallers.Create(value => value, value => value);

    internal static readonly Method<byte[], byte[]> Cancel = new(MethodType.Unary, ServiceName, "Cancel", Bytes, Bytes);

    internal static readonly Method<byte[], byte[]> Health = new(MethodType.Unary, ServiceName, "Health", Bytes, Bytes);

    public static void BindService(ServiceBinderBase binder, CommandProbeBase? service)
    {
        ArgumentNullException.ThrowIfNull(binder);
        binder.AddMethod(Cancel, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Cancel));
        binder.AddMethod(Health, service is null ? null : new UnaryServerMethod<byte[], byte[]>(service.Health));
    }

    [BindServiceMethod(typeof(CommandProbe), nameof(BindService))]
    internal abstract class CommandProbeBase
    {
        public virtual Task<byte[]> Cancel(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));

        public virtual Task<byte[]> Health(byte[] request, ServerCallContext context) => throw new RpcException(new Status(StatusCode.Unimplemented, string.Empty));
    }
}

/// <summary>The probe's behavior: cancel a command by id through the receipt table and report the effect as one byte.</summary>
internal sealed class CommandProbeService(LocalRpcCommandReceipts receipts) : CommandProbe.CommandProbeBase
{
    private int _cancels;

    internal int Cancels => Volatile.Read(ref _cancels);

    public override async Task<byte[]> Cancel(byte[] request, ServerCallContext context)
    {
        _ = Interlocked.Increment(ref _cancels);
        var report = await receipts.CancelAsync(new Guid(request), context.CancellationToken).ConfigureAwait(false);
        return [(byte)report.Effect];
    }

    public override Task<byte[]> Health(byte[] request, ServerCallContext context) => Task.FromResult(new byte[] { 1 });
}

/// <summary>
/// A test double of the generated <c>ConnectorBrokerService</c>, which is a real contract with real idempotency classes (<c>GetConnection</c>
/// is a query, <c>BeginConnection</c> create-with-client-id, <c>CompleteConnection</c> non-idempotent and reconciled by a read after a lost response).
/// <c>CompleteConnection</c> and <c>BeginConnection</c> run their effect through the helper's receipt table and commit into the owner store.
/// </summary>
internal sealed class BrokerDouble(OwnerStore store, LocalRpcCommandReceipts receipts) : ConnectorBrokerService.ConnectorBrokerServiceBase
{
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource> _beforeCommit = new();
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource> _reachedBeforeCommit = new();
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource> _afterCommit = new();
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource> _reachedAfterCommit = new();
    private int _dispatched;
    private int _effectsStarted;

    /// <summary>Whether a command parks before its commit point until <see cref="ReleaseBeforeCommit"/>.</summary>
    internal bool ParkBeforeCommit { get; set; }

    /// <summary>Whether a command parks after its commit point (the response is ready but not sent) until <see cref="ReleaseAfterCommit"/>.</summary>
    internal bool ParkAfterCommit { get; set; }

    /// <summary>Called with <c>before</c> or <c>after</c> and the command id when an effect reaches its parking point (a helper process reports it on its output).</summary>
    internal Action<string, Guid>? OnReached { get; set; }

    internal int Dispatched => Volatile.Read(ref _dispatched);

    internal int EffectsStarted => Volatile.Read(ref _effectsStarted);

    internal static Guid IdOf(RequestMeta meta) => new(meta.CommandId.Value.Span);

    internal static byte[] DigestOf(Guid flow, string proof) =>
        LocalRpcCommand.DigestOf([.. flow.ToByteArray(), .. Encoding.UTF8.GetBytes(proof)]);

    internal static ConnectorBrokerServiceCompleteConnectionRequest Complete(Guid commandId, string proof = "receipt") => new()
    {
        Meta = new RequestMeta { CommandId = NewId(commandId), CorrelationId = NewId(Guid.NewGuid()) },
        FlowId = NewId(commandId),
        Proof = new ConnectorProof { CallbackReceipt = proof },
    };

    internal static ConnectorBrokerServiceBeginConnectionRequest Begin(Guid commandId, string name = "left") => new()
    {
        Meta = new RequestMeta { CommandId = NewId(commandId), CorrelationId = NewId(Guid.NewGuid()) },
        ConnectionId = NewId(commandId),
        DefinitionId = "definition",
        Name = name,
    };

    internal static ConnectorBrokerServiceGetConnectionRequest Get(Guid connectionId) => new()
    {
        Meta = new RequestMeta { CommandId = NewId(Guid.NewGuid()), CorrelationId = NewId(Guid.NewGuid()) },
        ConnectionId = NewId(connectionId),
    };

    internal static Id NewId(Guid value) => new() { Value = ByteString.CopyFrom(value.ToByteArray()) };

    internal static LocalRpcEffect Interpret(ConnectorBrokerServiceCompleteConnectionResponse response) =>
        response.OutcomeCase == ConnectorBrokerServiceCompleteConnectionResponse.OutcomeOneofCase.Error
            ? response.Error.Effect switch
            {
                EffectCertainty.DidNotHappen => LocalRpcEffect.DidNotHappen,
                EffectCertainty.Happened => LocalRpcEffect.Happened,
                _ => LocalRpcEffect.Unknown,
            }
            : LocalRpcEffect.Happened;

    internal Task WhenReachedBeforeCommit(Guid id) => Gate(_reachedBeforeCommit, id).Task;

    internal Task WhenReachedAfterCommit(Guid id) => Gate(_reachedAfterCommit, id).Task;

    internal void ReleaseBeforeCommit(Guid id) => Gate(_beforeCommit, id).TrySetResult();

    internal void ReleaseAfterCommit(Guid id) => Gate(_afterCommit, id).TrySetResult();

    public override async Task<ConnectorBrokerServiceCompleteConnectionResponse> CompleteConnection(
        ConnectorBrokerServiceCompleteConnectionRequest request,
        ServerCallContext context)
    {
        _ = Interlocked.Increment(ref _dispatched);
        var id = IdOf(request.Meta);
        var flow = new Guid(request.FlowId.Value.Span);
        return await receipts.ExecuteAsync(
            id,
            DigestOf(flow, request.Proof.CallbackReceipt),
            async effect =>
            {
                _ = Interlocked.Increment(ref _effectsStarted);
                await ParkAsync("before", _reachedBeforeCommit, _beforeCommit, id, ParkBeforeCommit, effect.CancellationToken).ConfigureAwait(false);
                effect.Commit();
                store.Commit(id);
                await ParkAsync("after", _reachedAfterCommit, _afterCommit, id, ParkAfterCommit, effect.CancellationToken).ConfigureAwait(false);
                return new ConnectorBrokerServiceCompleteConnectionResponse
                {
                    Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
                    Value = new ConnectorBrokerServiceCompleteConnectionValue
                    {
                        Connection = new ConnectorConnection { ConnectionId = NewId(flow), State = "connected" },
                    },
                };
            },
            response => response.CalculateSize(),
            context.CancellationToken).ConfigureAwait(false);
    }

    public override async Task<ConnectorBrokerServiceBeginConnectionResponse> BeginConnection(
        ConnectorBrokerServiceBeginConnectionRequest request,
        ServerCallContext context)
    {
        _ = Interlocked.Increment(ref _dispatched);
        var id = IdOf(request.Meta);
        return await receipts.ExecuteAsync(
            id,
            LocalRpcCommand.DigestOf(Encoding.UTF8.GetBytes(request.ConnectionId.Value.ToBase64() + request.Name)),
            async effect =>
            {
                _ = Interlocked.Increment(ref _effectsStarted);
                await ParkAsync("before", _reachedBeforeCommit, _beforeCommit, id, ParkBeforeCommit, effect.CancellationToken).ConfigureAwait(false);
                effect.Commit();
                store.Commit(id);
                await ParkAsync("after", _reachedAfterCommit, _afterCommit, id, ParkAfterCommit, effect.CancellationToken).ConfigureAwait(false);
                return new ConnectorBrokerServiceBeginConnectionResponse
                {
                    Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
                    Value = new ConnectorBrokerServiceBeginConnectionValue { Challenge = new ConnectorChallenge { FlowId = NewId(id) } },
                };
            },
            response => response.CalculateSize(),
            context.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>The contract's own read: a connection is connected once the command with the same id committed.</summary>
    public override Task<ConnectorBrokerServiceGetConnectionResponse> GetConnection(
        ConnectorBrokerServiceGetConnectionRequest request,
        ServerCallContext context)
    {
        var id = new Guid(request.ConnectionId.Value.Span);
        return Task.FromResult(new ConnectorBrokerServiceGetConnectionResponse
        {
            Meta = new ResponseMeta { CorrelationId = request.Meta.CorrelationId },
            Value = new ConnectorBrokerServiceGetConnectionValue
            {
                Connection = new ConnectorConnection
                {
                    ConnectionId = request.ConnectionId,
                    State = store.Commits(id) > 0 ? "connected" : "absent",
                },
            },
        });
    }

    private async Task ParkAsync(
        string point,
        ConcurrentDictionary<Guid, TaskCompletionSource> reached,
        ConcurrentDictionary<Guid, TaskCompletionSource> release,
        Guid id,
        bool park,
        CancellationToken token)
    {
        _ = Gate(reached, id).TrySetResult();
        OnReached?.Invoke(point, id);
        if (park)
        {
            await Gate(release, id).Task.WaitAsync(token).ConfigureAwait(false);
        }
    }

    private static TaskCompletionSource Gate(ConcurrentDictionary<Guid, TaskCompletionSource> gates, Guid id) =>
        gates.GetOrAdd(id, _ => new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously));
}

/// <summary>
/// One helper launch: a server over supplied in-memory streams that serves the broker double, the cancel probe and the generated
/// bootstrap service, with the four control operations declared the way an owner declares them, plus the helper's receipt table.
/// <see cref="Kill"/> ends it the way a crash would: every stream drops, the server stops and the receipt table is lost.
/// </summary>
internal sealed class CommandHarness : IAsyncDisposable
{
    private static int _epoch;

    private readonly ConcurrentBag<Stream> _serverStreams = [];
    private int _killed;

    private CommandHarness(
        LocalRpcStreamSupplier supplier,
        LocalRpcServer server,
        LocalRpcCommandReceipts receipts,
        BrokerDouble broker,
        CommandProbeService probe,
        RecordingBootstrapService bootstrap,
        LocalRpcPeerGeneration generation)
    {
        Supplier = supplier;
        Server = server;
        Receipts = receipts;
        Broker = broker;
        Probe = probe;
        Bootstrap = bootstrap;
        Generation = generation;
    }

    internal LocalRpcStreamSupplier Supplier { get; }

    internal LocalRpcServer Server { get; }

    internal LocalRpcCommandReceipts Receipts { get; }

    internal BrokerDouble Broker { get; }

    internal CommandProbeService Probe { get; }

    internal RecordingBootstrapService Bootstrap { get; }

    internal LocalRpcPeerGeneration Generation { get; }

    internal int Connects { get; private set; }

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the receipt table passes to the harness, which disposes it when the helper is killed.")]
    internal static async Task<CommandHarness> StartAsync(
        OwnerStore store,
        LocalRpcLimits? limits = null,
        LocalRpcCommandReceiptOptions? receiptOptions = null,
        bool cancelIsControl = true,
        CancellationToken cancellationToken = default)
    {
        var supplier = new LocalRpcStreamSupplier();
        var receipts = new LocalRpcCommandReceipts(receiptOptions);
        var broker = new BrokerDouble(store, receipts);
        var probe = new CommandProbeService(receipts);
        var bootstrap = new RecordingBootstrapService();
        var builder = LocalRpcServer.CreateBuilder(supplier)
            .AddService(broker)
            .AddService(probe)
            .AddService(bootstrap)
            .RegisterControl(LocalRpcControlOperation.Bootstrap, LocalBootstrapService.Descriptor.FullName, "Challenge")
            .RegisterControl(LocalRpcControlOperation.Bootstrap, LocalBootstrapService.Descriptor.FullName, "Confirm")
            .RegisterControl(LocalRpcControlOperation.LeaseRenewal, LocalBootstrapService.Descriptor.FullName, "Renew")
            .RegisterControl(LocalRpcControlOperation.Health, CommandProbe.Health);
        if (cancelIsControl)
        {
            builder.RegisterControl(LocalRpcControlOperation.Cancellation, CommandProbe.Cancel);
        }

        builder.Limits = limits ?? new LocalRpcLimits { ShutdownTimeout = TimeSpan.FromMilliseconds(100) };
        var server = builder.Build();
        await server.StartAsync(cancellationToken).ConfigureAwait(false);
        var generation = new LocalRpcPeerGeneration(Guid.NewGuid(), (ulong)Interlocked.Increment(ref _epoch));
        return new CommandHarness(supplier, server, receipts, broker, probe, bootstrap, generation);
    }

    /// <summary>Supplies a fresh connected pair to the server and returns the client end.</summary>
    internal Stream NewClientStream()
    {
        var (client, server) = InMemoryDuplexStream.CreatePair();
        if (!Supplier.TrySupply(server))
        {
            server.Dispose();
            client.Dispose();
            throw new InvalidOperationException("The supplier refused a stream.");
        }

        _serverStreams.Add(server);
        Connects++;
        return client;
    }

    internal LocalRpcClientChannel NewChannel(LocalRpcLimits? limits = null) =>
        LocalRpcClientChannel.CreateFromStreams(_ => ValueTask.FromResult(NewClientStream()), limits);

    /// <summary>Every connection drops without a goodbye, the helper and its receipt table stay alive.</summary>
    internal async Task DropConnections()
    {
        foreach (var stream in _serverStreams)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>The helper process dies: every stream drops without a goodbye and the receipt table, with everything in memory, is gone.</summary>
    internal async Task Kill()
    {
        if (Interlocked.Exchange(ref _killed, 1) != 0)
        {
            return;
        }

        Supplier.Complete();
        foreach (var stream in _serverStreams)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }

        await Receipts.DisposeAsync().ConfigureAwait(false);
        await Server.DisposeAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync() => await Kill().ConfigureAwait(false);
}

/// <summary>Parent-side helpers: send the broker double's commands through a channel and the executor.</summary>
internal static class CommandClient
{
    internal static readonly string CompleteOperation = ConnectorBrokerService.Descriptor.FullName + "/CompleteConnection";

    internal static readonly string BeginOperation = ConnectorBrokerService.Descriptor.FullName + "/BeginConnection";

    internal static TimeSpan Deadline { get; } = TimeSpan.FromSeconds(20);

    internal static LocalRpcCommand CompleteCommand(Guid id, LocalRpcIdempotency idempotency = LocalRpcIdempotency.NonIdempotent, bool replay = false, string proof = "receipt") =>
        new(id, CompleteOperation, BrokerDouble.DigestOf(id, proof), idempotency, replay);

    internal static Task<LocalRpcCommandOutcome<ConnectorBrokerServiceCompleteConnectionResponse>> CompleteAsync(
        LocalRpcCommandExecutor executor,
        LocalRpcClientChannel channel,
        LocalRpcPeerGeneration generation,
        LocalRpcCommand command,
        string proof = "receipt",
        CancellationToken cancellationToken = default)
    {
        var client = new ConnectorBrokerService.ConnectorBrokerServiceClient(channel.CallInvoker);
        var request = BrokerDouble.Complete(command.CommandId, proof);
        return executor.ExecuteAsync(
            command,
            generation,
            (_, token) => client.CompleteConnectionAsync(request, new CallOptions(deadline: DateTime.UtcNow + Deadline, cancellationToken: token)).ResponseAsync,
            BrokerDouble.Interpret,
            cancellationToken);
    }

    internal static Task<LocalRpcCommandOutcome<ConnectorBrokerServiceBeginConnectionResponse>> BeginAsync(
        LocalRpcCommandExecutor executor,
        LocalRpcClientChannel channel,
        LocalRpcPeerGeneration generation,
        Guid id,
        bool replay,
        CancellationToken cancellationToken = default)
    {
        var client = new ConnectorBrokerService.ConnectorBrokerServiceClient(channel.CallInvoker);
        var request = BrokerDouble.Begin(id);
        var command = new LocalRpcCommand(
            id,
            BeginOperation,
            LocalRpcCommand.DigestOf(Encoding.UTF8.GetBytes(request.ConnectionId.Value.ToBase64() + request.Name)),
            LocalRpcIdempotency.DuplicateSafe,
            replay);
        return executor.ExecuteAsync<ConnectorBrokerServiceBeginConnectionResponse>(
            command,
            generation,
            (_, token) => client.BeginConnectionAsync(request, new CallOptions(deadline: DateTime.UtcNow + Deadline, cancellationToken: token)).ResponseAsync,
            null,
            cancellationToken);
    }

    /// <summary>The contract's own read, used the way an owner reconciles a lost response: connected means the command's effect happened.</summary>
    internal static async ValueTask<LocalRpcEffect> ReconcileThroughReadAsync(LocalRpcClientChannel channel, Guid id, CancellationToken cancellationToken)
    {
        var client = new ConnectorBrokerService.ConnectorBrokerServiceClient(channel.CallInvoker);
        var response = await client.GetConnectionAsync(BrokerDouble.Get(id), new CallOptions(deadline: DateTime.UtcNow + Deadline, cancellationToken: cancellationToken)).ResponseAsync.ConfigureAwait(false);
        return response.Value.Connection.State == "connected" ? LocalRpcEffect.Happened : LocalRpcEffect.DidNotHappen;
    }

    /// <summary>The cancel wire: one control call through the probe, returning the effect the helper reports.</summary>
    internal static async Task<LocalRpcEffect> CancelThroughProbeAsync(LocalRpcClientChannel channel, Guid id, CancellationToken cancellationToken)
    {
        var reply = await channel.CallInvoker.AsyncUnaryCall(
            CommandProbe.Cancel,
            null,
            new CallOptions(deadline: DateTime.UtcNow + Deadline, cancellationToken: cancellationToken),
            id.ToByteArray()).ResponseAsync.ConfigureAwait(false);
        return (LocalRpcEffect)reply[0];
    }
}
