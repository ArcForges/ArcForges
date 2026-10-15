// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// A real node in the test process: <see cref="NodeHost.RunAsync"/> with its own <c>node.json</c>, data root and endpoint (a unique
/// named pipe, or a socket in a fresh owner-only directory), served by the real LocalRpc service mode and reached through the real
/// client library. Disposing stops it through the host's shutdown, deletes its node data key from the OS secret store and its files.
/// </summary>
internal sealed class InProcessNode : IAsyncDisposable
{
    private CancellationTokenSource _stop = new();
    private TaskCompletionSource<NodeRuntime> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task<int>? _run;

    private InProcessNode(string root, int streamBuffer)
    {
        Root = root;
        DataRoot = Path.Combine(root, "data");
        ConfigPath = Path.Combine(root, "config", "node.json");
        StreamBuffer = streamBuffer;
        var name = "af-test-" + Guid.NewGuid().ToString("N")[..12];
        Endpoint = OperatingSystem.IsWindows()
            ? LocalRpcEndpoint.NamedPipe(name)
            : LocalRpcEndpoint.UnixDomainSocket(Path.Combine("/tmp", name, "node.sock"));
    }

    public string Root { get; }

    public string DataRoot { get; }

    public string ConfigPath { get; }

    public int StreamBuffer { get; }

    public LocalRpcEndpoint Endpoint { get; }

    public NodeRuntime Runtime => _ready.Task.Result;

    public Task<int> Exit => _run ?? Task.FromResult(-1);

    /// <summary>Creates the node's files; <paramref name="seed"/> may write store rows before the node opens the store.</summary>
    public static InProcessNode Create(int streamBuffer = 2048, Action<StoreTransaction>? seed = null)
    {
        var root = Directory.CreateTempSubdirectory("arcforges-node-tests-").FullName;
        var node = new InProcessNode(root, streamBuffer);
        Directory.CreateDirectory(Path.GetDirectoryName(node.ConfigPath)!);
        File.WriteAllText(node.ConfigPath, "{ \"dataRoot\": " + JsonSerializer.Serialize(node.DataRoot) + " }");
        if (seed is not null)
        {
            using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "seed" });
            store.Write(seed);
        }

        return node;
    }

    public static SecretStoreSelection SecretStore(string dataRoot) => OperatingSystem.IsWindows()
        ? OsSecretStore.SelectForCurrentPlatform(dataRoot)
        : OsSecretStore.SelectForCurrentPlatform(dataRoot, new SecretServiceOptions
        {
            BusAddress = "unix:path=" + Path.Combine(dataRoot, "run", "no-session-bus"),
            CallTimeout = TimeSpan.FromSeconds(2),
        });

    /// <summary>Starts the node (again, after a stop: a restart with the same files and endpoint) and waits until it serves.</summary>
    public async Task<InProcessNode> StartAsync()
    {
        if (_run is { IsCompleted: false })
        {
            throw new InvalidOperationException("The node is running.");
        }

        if (_run is not null)
        {
            _stop.Dispose();
            _stop = new CancellationTokenSource();
            _ready = new TaskCompletionSource<NodeRuntime>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        var options = new NodeHostOptions
        {
            ConfigPath = ConfigPath,
            Endpoint = Endpoint,
            StreamBuffer = StreamBuffer,
            Ready = runtime => _ready.TrySetResult(runtime),
            SecretStore = SecretStore,
            Output = TextWriter.Null,
            Error = TextWriter.Null,
        };
        var stop = _stop.Token;
        _run = Task.Run(() => NodeHost.RunAsync(options, stop));
        var first = await Task.WhenAny(_ready.Task, _run, Task.Delay(TimeSpan.FromSeconds(30))).ConfigureAwait(false);
        if (first != _ready.Task)
        {
            throw new InvalidOperationException(_run.IsCompleted ? $"The node exited with {_run.Result} before it was ready." : "The node was not ready within 30 s.");
        }

        return this;
    }

    /// <summary>Stops the node through its shutdown sequence and returns its exit code.</summary>
    public async Task<int> StopAsync()
    {
        if (_run is null)
        {
            return -1;
        }

        await _stop.CancelAsync().ConfigureAwait(false);
        return await _run.WaitAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);
    }

    /// <summary>A connected session (the real client: endpoint, hello and all).</summary>
    public async Task<NodeChannel> ChannelAsync(bool helloAsHuman = false)
    {
        var channel = NodeChannel.Create(Endpoint);
        var hello = ClientProcess.Hello(ClientKind.Cli);
        hello.InteractiveTerminal = helloAsHuman;
        hello.CiMarkers.Clear();
        var response = await channel.Node.HelloAsync(new NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow.AddSeconds(10));
        if (response.Error is { } error)
        {
            await channel.DisposeAsync();
            throw new InvalidOperationException($"Hello failed: {error.Category}/{error.Code}");
        }

        return channel;
    }

    public static RequestMeta Command() => new() { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() };

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_run is { IsCompleted: false })
            {
                await StopAsync();
            }
        }
        finally
        {
            _stop.Dispose();
            SqliteConnection.ClearAllPools();
            if (File.Exists(StorePaths.Database(DataRoot)))
            {
                using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = DataRoot, BootIdentity = "cleanup" });
                using var keys = new NodeDataKeyRing(store, SecretStore(DataRoot));
                keys.DeleteKeys();
            }

            SqliteConnection.ClearAllPools();
            Directory.Delete(Root, recursive: true);
            if (!OperatingSystem.IsWindows() && Directory.Exists(Path.GetDirectoryName(Endpoint.Address)))
            {
                Directory.Delete(Path.GetDirectoryName(Endpoint.Address)!, recursive: true);
            }
        }
    }

    /// <summary>Inserts a job row (jobs have no producers in this build; their runners arrive with later tasks).</summary>
    public static byte[] SeedJob(StoreTransaction transaction, JobKind kind, JobState state, long createdAt)
    {
        var id = StoreIds.NewUuid7(transaction.Clock);
        transaction.Execute(
            """
            INSERT INTO job (job_id, kind, state, progress_percent, requested_by, created_at, finished_at, rev)
            VALUES ($id, $kind, $state, 0, $actor, $created, $finished, 0);
            """,
            ("$id", id),
            ("$kind", (int)kind),
            ("$state", (int)state),
            ("$actor", new ActorRef { Origin = Origin.Human }.ToByteArray()),
            ("$created", createdAt),
            ("$finished", state is JobState.Pending or JobState.Running ? null : createdAt + 1000));
        return id;
    }

    /// <summary>Inserts a notification row.</summary>
    public static byte[] SeedNotification(StoreTransaction transaction, string title, long createdAt)
    {
        var id = StoreIds.NewUuid7(transaction.Clock);
        transaction.Execute(
            "INSERT INTO notification (notification_id, kind, severity, title, body, created_at) VALUES ($id, 'node', 1, $title, 'body', $created);",
            ("$id", id),
            ("$title", title),
            ("$created", createdAt));
        return id;
    }
}
