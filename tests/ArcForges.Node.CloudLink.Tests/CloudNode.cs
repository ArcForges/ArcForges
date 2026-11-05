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

    public LocalRpcEndpoint Endpoint { get; }

    public string Slice { get; } = SystemdTestEnvironment.NewSlice();

    public IsolatedSecretStore Secrets { get; } = new();

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
            Endpoint = Endpoint,
            Ready = runtime => _ready.TrySetResult(runtime),
            SecretStore = _ => Secrets.Selection,
            NodeKeys = NodeKeyStores.ForTestDataRoot,
            Output = TextWriter.Null,
            Error = TextWriter.Null,
            LinuxSlice = Slice,
            IsolatedFromMachineLoad = true,
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
