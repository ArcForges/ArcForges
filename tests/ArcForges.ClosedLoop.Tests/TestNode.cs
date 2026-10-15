// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;
using Microsoft.Data.Sqlite;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>Closed-loop tests run one after another: the leftover-process check counts every node and supervisor of the binaries under test.</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SerialProcessTests
{
    public const string Name = "processes";
}

/// <summary>One run of a CLI or node process.</summary>
internal sealed record ProcessRun(int ExitCode, string Output, string Error)
{
    public JsonElement Json() => JsonDocument.Parse(Output).RootElement.Clone();

    public override string ToString() => $"exit {ExitCode}; stdout: {Output}; stderr: {Error}";
}

/// <summary>
/// An isolated node environment for real processes: its own <c>node.json</c> (through <c>ARCFORGES_CONFIG_DIR</c>), data root and
/// endpoint (<c>ARCFORGES_ENDPOINT</c>), passed to every <c>arcforges</c> process it starts with <c>--test-mode</c>. The child
/// environment has no CI markers (unless a test adds them), and on Linux a session bus address that does not exist, so the node data
/// key uses the owner-only file fallback under the data root instead of the user's keyring. Disposing stops the node, deletes its data
/// key from the OS secret store, removes the files, and fails when any <c>arcforges</c> or <c>arcforges-supervisor</c> process started
/// from the binaries under test during the test is still running (16-testing-strategy section 4).
/// </summary>
internal sealed class TestNode : IAsyncDisposable
{
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(60);
    private readonly DateTime _created = DateTime.Now.AddSeconds(-1);
    private readonly List<Process> _children = [];

    private TestNode(string root)
    {
        Root = root;
        ConfigDirectory = Path.Combine(root, "config");
        DataRoot = Path.Combine(root, "data");
        var name = "af-cl-" + Guid.NewGuid().ToString("N")[..12];
        Endpoint = OperatingSystem.IsWindows() ? name : Path.Combine("/tmp", name, "node.sock");
        Environment[NodeLocations.ConfigDirectoryVariable] = ConfigDirectory;
        Environment[NodeLocations.EndpointVariable] = Endpoint;
        foreach (var marker in ClientProcess.CiVariables)
        {
            Environment[marker] = null;
        }

        if (!OperatingSystem.IsWindows())
        {
            Environment["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + Path.Combine(root, "no-session-bus");
        }
    }

    /// <summary>The <c>arcforges</c> binary under test: <c>ARCFORGES_HOST_PATH</c> or the JIT build next to the tests.</summary>
    public static string Host { get; } = Binary("ARCFORGES_HOST_PATH", "arcforges");

    public string Root { get; }

    public string ConfigDirectory { get; }

    public string DataRoot { get; }

    public string Endpoint { get; }

    /// <summary>The child processes' environment changes (null removes a variable).</summary>
    public Dictionary<string, string?> Environment { get; } = new(StringComparer.Ordinal);

    public string NodeLog => Path.Combine(DataRoot, "logs", "node", "node.log");

    public string SupervisorLog => Path.Combine(DataRoot, "logs", "supervisor", "supervisor.log");

    public static TestNode Create()
    {
        var root = Directory.CreateTempSubdirectory("arcforges-closed-loop-").FullName;
        var node = new TestNode(root);
        Directory.CreateDirectory(node.ConfigDirectory);
        File.WriteAllText(Path.Combine(node.ConfigDirectory, "node.json"), "{ \"dataRoot\": " + JsonSerializer.Serialize(node.DataRoot) + " }");
        return node;
    }

    /// <summary>Runs <c>arcforges &lt;args&gt; --test-mode</c> to completion (bounded).</summary>
    public async Task<ProcessRun> CliAsync(params string[] args)
    {
        using var process = Start(Host, [.. args, NodeLocations.TestModeOption]);
        return await CompleteAsync(process, ProcessTimeout);
    }

    /// <summary>Starts <c>arcforges node run --test-mode</c> as a child of the test and waits until it answers.</summary>
    public async Task<Process> StartNodeAsync()
    {
        var process = Start(Host, ["node", "run", NodeLocations.TestModeOption]);
        _children.Add(process);
        await WaitReadyAsync(process);
        return process;
    }

    /// <summary>Starts a process with the environment's variables; it is tracked and killed at the end if it still runs.</summary>
    public Process Start(string executable, IEnumerable<string> arguments)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        foreach (var (name, value) in Environment)
        {
            if (value is null)
            {
                start.Environment.Remove(name);
            }
            else
            {
                start.Environment[name] = value;
            }
        }

        var process = Process.Start(start) ?? throw new InvalidOperationException($"{executable} did not start.");
        process.StandardInput.Close();
        _children.Add(process);
        return process;
    }

    /// <summary>Waits until <c>node wait-ready</c> succeeds (the node answers its hello).</summary>
    public async Task WaitReadyAsync(Process? node = null)
    {
        var run = await CliAsync("node", "wait-ready", "--timeout", "30s");
        Assert.True(run.ExitCode == 0, $"The node did not become ready: {run}" + (node is { HasExited: true } ? $" (node exited {node.ExitCode})" : string.Empty));
    }

    /// <summary>The node's endpoint descriptor, or null.</summary>
    public EndpointDescriptor? Descriptor() => EndpointDescriptor.TryRead(NodeLocations.EndpointDescriptorFile(DataRoot));

    /// <summary>The PID of the running node, from its descriptor.</summary>
    public int NodePid() => Descriptor() is { } descriptor && descriptor.ProcessIsAlive()
        ? descriptor.ProcessId
        : throw new InvalidOperationException("No node is running.");

    /// <summary>Waits for an asynchronous <paramref name="condition"/> (bounded).</summary>
    public static async Task WaitAsync(Func<Task<bool>> condition, TimeSpan timeout, string what)
    {
        var started = TimeProvider.System.GetTimestamp();
        while (!await condition())
        {
            Assert.True(TimeProvider.System.GetElapsedTime(started) < timeout, $"Timed out after {timeout.TotalSeconds:0} s waiting for {what}.");
            await Task.Delay(100);
        }
    }

    /// <summary>Waits for <paramref name="condition"/> (bounded).</summary>
    public static async Task WaitAsync(Func<bool> condition, TimeSpan timeout, string what)
    {
        var started = TimeProvider.System.GetTimestamp();
        while (!condition())
        {
            Assert.True(TimeProvider.System.GetElapsedTime(started) < timeout, $"Timed out after {timeout.TotalSeconds:0} s waiting for {what}.");
            await Task.Delay(50);
        }
    }

    public static async Task<ProcessRun> CompleteAsync(Process process, TimeSpan timeout)
    {
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var deadline = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException($"{process.StartInfo.FileName} {string.Join(' ', process.StartInfo.ArgumentList)} did not exit within {timeout.TotalSeconds:0} s.");
        }

        return new ProcessRun(process.ExitCode, await output, await error);
    }

    /// <summary>Running processes of the binaries under test started since this environment was created.</summary>
    public List<Process> LiveProcesses()
    {
        var binaries = new[] { Host, Path.Combine(Path.GetDirectoryName(Host)!, OperatingSystem.IsWindows() ? "arcforges-supervisor.exe" : "arcforges-supervisor") }
            .Select(path => Path.GetFullPath(path)).ToHashSet(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        var live = new List<Process>();
        foreach (var process in Process.GetProcessesByName("arcforges").Concat(Process.GetProcessesByName("arcforges-supervisor")))
        {
            try
            {
                if (!process.HasExited && process.MainModule?.FileName is { } file && binaries.Contains(Path.GetFullPath(file)) && process.StartTime >= _created)
                {
                    live.Add(process);
                    continue;
                }
            }
            catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Exited meanwhile, or not ours to inspect.
            }

            process.Dispose();
        }

        return live;
    }

    public async ValueTask DisposeAsync()
    {
        var leftovers = new List<string>();
        try
        {
            if (Descriptor() is { } descriptor && descriptor.ProcessIsAlive())
            {
                await CliAsync("node", "stop", "--timeout", "15s");
            }

            // Supervisors exit once their node stopped; give them a moment.
            await WaitAsync(() => LiveProcesses().Count == 0, TimeSpan.FromSeconds(15), "the node and supervisor processes to exit").ContinueWith(_ => { }, TaskScheduler.Default);
            foreach (var process in LiveProcesses())
            {
                leftovers.Add($"{process.ProcessName} (pid {process.Id})");
                process.Kill(entireProcessTree: true);
                process.WaitForExit(TimeSpan.FromSeconds(10));
                process.Dispose();
            }
        }
        finally
        {
            foreach (var child in _children)
            {
                try
                {
                    if (!child.HasExited)
                    {
                        child.Kill(entireProcessTree: true);
                        child.WaitForExit(TimeSpan.FromSeconds(10));
                    }
                }
                catch (InvalidOperationException)
                {
                    // Already disposed by the test (a completed CLI run).
                }

                child.Dispose();
            }

            DeleteDataKeys();
            SqliteConnection.ClearAllPools();
            Directory.Delete(Root, recursive: true);
            if (!OperatingSystem.IsWindows() && Directory.Exists(Path.GetDirectoryName(Endpoint)))
            {
                Directory.Delete(Path.GetDirectoryName(Endpoint)!, recursive: true);
            }
        }

        Assert.True(leftovers.Count == 0, "Processes were left running after the test: " + string.Join(", ", leftovers));
    }

    private void DeleteDataKeys()
    {
        if (!File.Exists(StorePaths.Database(DataRoot)))
        {
            return;
        }

        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = DataRoot, BootIdentity = "cleanup" });
        var selection = OperatingSystem.IsWindows()
            ? OsSecretStore.SelectForCurrentPlatform(DataRoot)
            : OsSecretStore.SelectForCurrentPlatform(DataRoot, new SecretServiceOptions { BusAddress = Environment["DBUS_SESSION_BUS_ADDRESS"], CallTimeout = TimeSpan.FromSeconds(2) });
        using var keys = new NodeDataKeyRing(store, selection);
        keys.DeleteKeys();
    }

    private static string Binary(string variable, string name)
    {
        var configured = System.Environment.GetEnvironmentVariable(variable);
        if (!string.IsNullOrEmpty(configured))
        {
            return Path.IsPathFullyQualified(configured) && File.Exists(configured)
                ? configured
                : throw new FileNotFoundException($"{variable} must be the absolute path of an existing {name} executable.", configured);
        }

        var path = Path.Combine(AppContext.BaseDirectory, OperatingSystem.IsWindows() ? name + ".exe" : name);
        return File.Exists(path) ? path : throw new FileNotFoundException($"{name} is missing next to the tests.", path);
    }

    /// <summary>Reads a log's JSON Lines records with the given event name.</summary>
    public static List<JsonElement> LogEvents(string log, string name)
    {
        var events = new List<JsonElement>();
        if (!File.Exists(log))
        {
            return events;
        }

        using var stream = new FileStream(log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (reader.ReadLine() is { } line)
        {
            using var document = JsonDocument.Parse(line);
            if (document.RootElement.GetProperty("event").GetString() == name)
            {
                events.Add(document.RootElement.Clone());
            }
        }

        return events;
    }

    public static string Text(int value) => value.ToString(CultureInfo.InvariantCulture);
}
