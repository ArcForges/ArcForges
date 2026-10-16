// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Execution;
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

    private readonly HashSet<int> _childrenBefore = OperatingSystem.IsWindows() ? ExecutionCleanup.Children() : [];

    private InProcessNode(string root, int streamBuffer, ILaunchStepProvider? steps)
    {
        Steps = steps;
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

    /// <summary>Launch and end steps the node's attempts get (synthetic steps in tests).</summary>
    public ILaunchStepProvider? Steps { get; }

    /// <summary>
    /// The lifecycle state a started node reaches: READY with the Windows job platform, and on Linux with a user manager that delegates
    /// cpu, memory and pids; DEGRADED (observe only) otherwise (a hosted runner without a user manager).
    /// </summary>
    public static NodeLifecycleState ExpectedState => OperatingSystem.IsWindows() || ArcForges.Tests.SystemdTestEnvironment.FullyEnforced
        ? NodeLifecycleState.Ready
        : NodeLifecycleState.Degraded;

    /// <summary>Linux: the user manager's address (an absent one runs the node observe-only).</summary>
    public string? SystemdAddress { get; set; }

    /// <summary>Linux: the controllers treated as delegated (simulated missing delegation).</summary>
    public IReadOnlyCollection<string>? LinuxControllers { get; set; }

    /// <summary>The node's own slice on Linux (16 section 4).</summary>
    public string Slice { get; } = ArcForges.Tests.SystemdTestEnvironment.NewSlice();

    /// <summary>The <c>arcforges</c> executable whose helper roles the node starts: <c>ARCFORGES_HOST_PATH</c> or the build next to the tests.</summary>
    public static string HelperExecutable => Environment.GetEnvironmentVariable("ARCFORGES_HOST_PATH") is { Length: > 0 } configured
        ? configured
        : Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "arcforges.exe" : "arcforges");

    public LocalRpcEndpoint Endpoint { get; }

    public NodeRuntime Runtime => _ready.Task.Result;

    public Task<int> Exit => _run ?? Task.FromResult(-1);

    /// <summary>Creates the node's files; <paramref name="seed"/> may write store rows before the node opens the store.</summary>
    public static InProcessNode Create(int streamBuffer = 2048, Action<StoreTransaction>? seed = null, ILaunchStepProvider? steps = null)
    {
        var root = Directory.CreateTempSubdirectory("arcforges-node-tests-").FullName;
        var node = new InProcessNode(root, streamBuffer, steps);
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
            HelperExecutable = HelperExecutable,
            LaunchSteps = Steps,
            LinuxSlice = Slice,
            SystemdAddress = SystemdAddress,
            LinuxControllers = LinuxControllers,
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
        var leftovers = new List<string>();
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
                if (OperatingSystem.IsWindows())
                {
                    // Attempts outlive a stopped node under their holders; the fixture ends them and fails on anything left (16 section 4).
                    leftovers = ExecutionCleanup.Run(store, _childrenBefore);
                }
                else
                {
                    // Attempts outlive a stopped node as transient units: the fixture stops the node's units and slice and fails on anything left.
                    leftovers = ArcForges.Tests.SystemdTestEnvironment.Cleanup(Slice, AttemptNames(store));
                }

                using var keys = new NodeDataKeyRing(store, SecretStore(DataRoot));
                keys.DeleteKeys();
            }

            SqliteConnection.ClearAllPools();
            for (var tries = 0; ; tries++)
            {
                try
                {
                    Directory.Delete(Root, recursive: true);
                    break;
                }
                catch (Exception exception) when ((exception is IOException or UnauthorizedAccessException) && tries < 50)
                {
                    // Holders that just exited may still close their files.
                    await Task.Delay(100);
                }
            }

            if (!OperatingSystem.IsWindows() && Directory.Exists(Path.GetDirectoryName(Endpoint.Address)))
            {
                Directory.Delete(Path.GetDirectoryName(Endpoint.Address)!, recursive: true);
            }
        }

        Assert.True(leftovers.Count == 0, "Processes were left running after the test: " + string.Join(", ", leftovers));
    }

    /// <summary>The attempts of the store (their unit names on Linux).</summary>
    public static List<string> AttemptNames(NodeStore store) => store.Read(reader =>
    {
        var names = new List<string>();
        using var command = reader.CreateCommand("SELECT attempt_id FROM attempt;");
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            names.Add(IdText.Format((byte[])rows.GetValue(0)));
        }

        return names;
    });

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
