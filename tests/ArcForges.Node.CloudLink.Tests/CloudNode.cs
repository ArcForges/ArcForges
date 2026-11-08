// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Tests;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// A real node in the test process (<see cref="NodeHost.RunAsync"/>) with its own <c>node.json</c>, data root and endpoint, reached through
/// the real client library over the real LocalRpc endpoint (a named pipe or a Unix socket). Its secrets live in the isolated in-memory
/// store and its node key in the file-backed store of its data root (16-testing-strategy section 2); its center is a FakeCenter.
/// </summary>
internal sealed class CloudNode : IAsyncDisposable
{
    private CancellationTokenSource _stop = new();
    private TaskCompletionSource<NodeRuntime> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task<int>? _run;

    private CloudNode(string root)
    {
        Root = root;
        DataRoot = Path.Combine(root, "data");
        ConfigPath = Path.Combine(root, "config", "node.json");
        var name = "af-cl-" + Guid.NewGuid().ToString("N")[..12];
        Endpoint = OperatingSystem.IsWindows()
            ? LocalRpcEndpoint.NamedPipe(name)
            : LocalRpcEndpoint.UnixDomainSocket(Path.Combine("/tmp", name, "node.sock"));
    }

    public string Root { get; }

    public string DataRoot { get; }

    public string ConfigPath { get; }

    /// <summary>
    /// Whether the node admits local SCRIPT submissions (AD-0021 section 5; CTR5-NODE-14: the node's own tests): true by default here, false
    /// for the tests of the local bound itself (a node that is not test-mode-allowed).
    /// </summary>
    public bool AllowLocalScriptSubmit { get; set; } = true;

    /// <summary>Opt in to isolated test-mode image verification for a literal CLI PTY acceptance test.</summary>
    public bool TestMode { get; set; }

    /// <summary>The wall clock for this node (the real clock unless a test supplies a controllable one).</summary>
    public TimeProvider Clock { get; set; } = TimeProvider.System;

    /// <summary>Wraps the real routed dispatcher for fault injection in an in-process test.</summary>
    public Func<IRoutedDispatcher, IRoutedDispatcher>? WrapRoutedDispatcher { get; set; }

    public LocalRpcEndpoint Endpoint { get; }

    /// <summary>The <c>arcforges</c> executable whose helper roles the node starts: <c>ARCFORGES_HOST_PATH</c> or the build next to the tests.</summary>
    public static string HelperExecutable => Environment.GetEnvironmentVariable("ARCFORGES_HOST_PATH") is { Length: > 0 } configured
        ? configured
        : Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "arcforges.exe" : "arcforges");

    /// <summary><c>arcforges-testload</c> next to the tests, or <c>ARCFORGES_TESTLOAD_PATH</c>.</summary>
    public static string TestLoad => Environment.GetEnvironmentVariable("ARCFORGES_TESTLOAD_PATH") is { Length: > 0 } configured
        ? configured
        : Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? "arcforges-testload.exe" : "arcforges-testload");

    public string Slice { get; } = SystemdTestEnvironment.NewSlice();

    public IsolatedSecretStore Secrets { get; } = new();

    /// <summary>The sign-in flows' browser (the allowed ScriptedBrowser; the node never starts a real one in these tests).</summary>
    public ScriptedBrowser Browser { get; } = new();

    public NodeRuntime Runtime => _ready.Task.Result;

    public CloudLinkService Cloud => (CloudLinkService)Runtime.CloudLink;

    /// <summary>Creates the node's files with <paramref name="centerUrl"/> as its <c>node.json</c> center (or none).</summary>
    public static CloudNode Create(string? centerUrl)
    {
        var node = new CloudNode(Directory.CreateTempSubdirectory("arcforges-cloudnode-").FullName);
        Directory.CreateDirectory(Path.GetDirectoryName(node.ConfigPath)!);
        File.WriteAllText(node.ConfigPath, "{ \"dataRoot\": " + JsonSerializer.Serialize(node.DataRoot)
            + (centerUrl is null ? string.Empty : ", \"centerUrl\": " + JsonSerializer.Serialize(centerUrl)) + " }");
        return node;
    }

    public async Task<CloudNode> StartAsync()
    {
        if (_run is not null)
        {
            _stop.Dispose();
            _stop = new CancellationTokenSource();
            _ready = new TaskCompletionSource<NodeRuntime>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        var options = new NodeHostOptions
        {
            ConfigPath = ConfigPath,
            TestMode = TestMode,
            Clock = Clock,
            WrapRoutedDispatcher = WrapRoutedDispatcher,
            Endpoint = Endpoint,

            // AD-0021 section 5 (Plan decision Q8): the node's own tests submit through local SCRIPT connections (CTR5-NODE-14); never an AGENT.
            AllowLocalScriptSubmit = AllowLocalScriptSubmit,
            Ready = runtime => _ready.TrySetResult(runtime),
            SecretStore = _ => Secrets.Selection,
            NodeKeys = NodeKeyStores.ForTestDataRoot,
            Opener = Browser,
            Output = TextWriter.Null,
            Error = TextWriter.Null,
            LinuxSlice = Slice,
            IsolatedFromMachineLoad = true,

            // AF-CTR-05 N2b: routed runs execute (RoutedNodeTests), with the helper roles of the arcforges executable built next to the tests.
            HelperExecutable = HelperExecutable,
        };
        var stop = _stop.Token;
        _run = Task.Run(() => NodeHost.RunAsync(options, stop));
        var first = await Task.WhenAny(_ready.Task, _run, Task.Delay(TimeSpan.FromSeconds(30)));
        if (first != _ready.Task)
        {
            throw new InvalidOperationException(_run.IsCompleted ? $"The node exited with {_run.Result}." : "The node was not ready within 30 s.");
        }

        return this;
    }

    public async Task<int> StopAsync()
    {
        if (_run is null)
        {
            return -1;
        }

        await _stop.CancelAsync();
        return await _run.WaitAsync(TimeSpan.FromSeconds(30));
    }

    /// <summary>A connected session as HUMAN (verified image, interactive), SCRIPT, or AGENT (the MCP adapter kind).</summary>
    public async Task<NodeChannel> ChannelAsync(Origin origin)
    {
        var channel = NodeChannel.Create(Endpoint);
        var hello = ClientProcess.Hello(origin == Origin.Agent ? ClientKind.McpAdapter : ClientKind.Cli);
        hello.InteractiveTerminal = origin == Origin.Human;
        hello.CiMarkers.Clear();
        var response = await channel.Node.HelloAsync(new NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow.AddSeconds(10));
        Assert.Null(response.Error);
        Assert.Equal(origin, response.Value.AssignedOrigin);
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
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (OperatingSystem.IsLinux())
            {
                leftovers.AddRange(SystemdTestEnvironment.Cleanup(Slice, []));
            }

            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                leftovers.Add("files under " + Root + ": " + exception.Message);
            }

            if (!OperatingSystem.IsWindows() && Directory.Exists(Path.GetDirectoryName(Endpoint.Address)))
            {
                Directory.Delete(Path.GetDirectoryName(Endpoint.Address)!, recursive: true);
            }
        }

        Leftovers.Report(leftovers);
    }
}
