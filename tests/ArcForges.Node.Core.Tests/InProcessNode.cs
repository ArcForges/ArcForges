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
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// A real node in the test process: <see cref="NodeHost.RunAsync"/> with its own <c>node.json</c>, data root and endpoint (a unique
/// named pipe, or a socket in a fresh owner-only directory), served by the real LocalRpc service mode and reached through the real
/// client library. Its node data key lives in an isolated in-memory secret store (16-testing-strategy section 2), one per node, so
/// restarts keep it and the real OS secret store is never reached. Disposing stops it through the host's shutdown, deletes its node
/// data key, verifies that every recorded key is absent from the isolated store and that nothing else is left there (a leak is reported
/// by name, as a leftover), and removes its files.
/// </summary>
internal sealed class InProcessNode : IAsyncDisposable
{
    private CancellationTokenSource _stop = new();
    private TaskCompletionSource<NodeRuntime> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task<int>? _run;

    private InProcessNode(string root, int streamBuffer, ILaunchStepProvider? steps, ArcForges.Node.Core.Scheduling.IToolConcurrency? tools = null)
    {
        Steps = steps;
        Tools = tools;
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

    /// <summary>The tool-level concurrency hook (a synthetic adapter in tests).</summary>
    public ArcForges.Node.Core.Scheduling.IToolConcurrency? Tools { get; }

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

    /// <summary>The version directory whose digests the node verifies after startup (default: the directory of the helper executable).</summary>
    public string? VersionDirectory { get; set; }

    /// <summary>Awaited before the version check's mismatch finding is committed (the node's test seam; a test holds or fails the commit).</summary>
    public Func<Task>? VersionFindingCommitting { get; set; }

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
    public static InProcessNode Create(int streamBuffer = 2048, Action<StoreTransaction>? seed = null, ILaunchStepProvider? steps = null, string? parent = null,
        ArcForges.Node.Core.Scheduling.IToolConcurrency? tools = null)
    {
        var root = parent is null
            ? Directory.CreateTempSubdirectory("arcforges-node-tests-").FullName
            : Directory.CreateDirectory(Path.Combine(parent, "arcforges-node-tests-" + Guid.NewGuid().ToString("N")[..12])).FullName;
        var node = new InProcessNode(root, streamBuffer, steps, tools);
        Directory.CreateDirectory(Path.GetDirectoryName(node.ConfigPath)!);
        File.WriteAllText(node.ConfigPath, "{ \"dataRoot\": " + JsonSerializer.Serialize(node.DataRoot) + " }");
        if (seed is not null)
        {
            using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "seed" });
            store.Write(seed);
        }

        return node;
    }

    /// <summary>The node's isolated secret store (in memory, kept across restarts of this node).</summary>
    public ArcForges.Tests.IsolatedSecretStore Secrets { get; } = new();

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
            SecretStore = _ => Secrets.Selection,
            Output = TextWriter.Null,
            Error = TextWriter.Null,
            HelperExecutable = HelperExecutable,
            LaunchSteps = Steps,
            ToolConcurrency = Tools,
            LinuxSlice = Slice,
            SystemdAddress = SystemdAddress,
            LinuxControllers = LinuxControllers,
            VersionDirectory = VersionDirectory,
            VersionFindingCommitting = VersionFindingCommitting,
        };
        var stop = _stop.Token;
        var firstStart = _run is null;
        _run = Task.Run(() => NodeHost.RunAsync(options, stop));
        var first = await Task.WhenAny(_ready.Task, _run, Task.Delay(TimeSpan.FromSeconds(30))).ConfigureAwait(false);
        if (first != _ready.Task)
        {
            var message = _run.IsCompleted ? $"The node exited with {_run.Result} before it was ready." : "The node was not ready within 30 s.";
            if (firstStart)
            {
                // The test never gets the node to dispose (Create().StartAsync() failed): remove what it created already.
                try
                {
                    await DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    message += " Cleanup: " + exception.Message;
                }
            }

            throw new InvalidOperationException(message);
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

    /// <summary>
    /// A connected session (the real client: endpoint, hello and all). A refused hello fails as the client library's connector fails it,
    /// with <see cref="NodeUnavailableException"/> (a stopping node is not ready yet), so a reconnecting stream cache retries it.
    /// </summary>
    public async Task<NodeChannel> ChannelAsync(bool helloAsHuman = false, ClientKind kind = ClientKind.Cli)
    {
        var channel = NodeChannel.Create(Endpoint);
        var hello = ClientProcess.Hello(kind);
        hello.InteractiveTerminal = helloAsHuman;
        hello.CiMarkers.Clear();
        var response = await channel.Node.HelloAsync(new NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow.AddSeconds(10));
        if (response.Error is { } error)
        {
            await channel.DisposeAsync();
            throw new NodeUnavailableException(NodeUnavailableReason.NotReady, $"Hello failed: {error.Category}/{error.Code}", "the test node refused the hello", error);
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
            List<string> remaining = [];
            SqliteConnection.ClearAllPools();
            if (File.Exists(StorePaths.Database(DataRoot)))
            {
                using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = DataRoot, BootIdentity = "cleanup" });
                if (OperatingSystem.IsWindows())
                {
                    // Attempts outlive a stopped node under their holders; the fixture ends them and fails on anything left (16 section 4).
                    leftovers = ExecutionCleanup.Run(store);
                }
                else
                {
                    // Attempts outlive a stopped node as transient units: the fixture stops the node's units and slice and fails on anything left.
                    leftovers = ArcForges.Tests.SystemdTestEnvironment.Cleanup(Slice, AttemptNames(store));
                }

                using var keys = new NodeDataKeyRing(store, Secrets.Selection);
                var names = keys.Keys().Select(key => NodeDataKeyRing.TargetName(store.Metadata.NodeId.Span, key.KeyId)).ToList();
                keys.DeleteKeys();

                // Test verification of the cleanup (never a production read-back): every recorded key is absent, nothing else is left.
                remaining = Secrets.Remaining(names);
                leftovers.AddRange(remaining.Select(name => "node data key " + name + " still in the isolated secret store after its delete"));
            }

            leftovers.AddRange(Secrets.TakeLeaks(remaining));
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
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    leftovers.Add($"files under {Root} ({exception.Message} Processes working in it: {string.Join(", ", ProcessesWorkingIn(Root))})");
                    break;
                }
            }

            if (!OperatingSystem.IsWindows() && Directory.Exists(Path.GetDirectoryName(Endpoint.Address)))
            {
                Directory.Delete(Path.GetDirectoryName(Endpoint.Address)!, recursive: true);
            }
        }

        ArcForges.Tests.Leftovers.Report(leftovers);
    }

    /// <summary>The processes whose working directory is <paramref name="directory"/> or below it (they keep it from being deleted).</summary>
    private static List<string> ProcessesWorkingIn(string directory) =>
        [.. System.Diagnostics.Process.GetProcesses().Select(process =>
        {
            using (process)
            {
                return ArcForges.Tests.ProcessInspection.CurrentDirectory(process.Id) is { } cwd && cwd.StartsWith(directory, StringComparison.OrdinalIgnoreCase)
                    ? $"{process.ProcessName} ({process.Id}, in {cwd})"
                    : null;
            }
        }).OfType<string>()];

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
