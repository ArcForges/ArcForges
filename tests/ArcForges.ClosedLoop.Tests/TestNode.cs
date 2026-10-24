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


/// <summary>One run of a CLI or node process.</summary>
internal sealed record ProcessRun(int ExitCode, string Output, string Error)
{
    public JsonElement Json() => JsonDocument.Parse(Output).RootElement.Clone();

    public override string ToString() => $"exit {ExitCode}; stdout: {Output}; stderr: {Error}";
}

/// <summary>
/// An isolated node environment for real processes: its own <c>node.json</c> (through <c>ARCFORGES_CONFIG_DIR</c>), data root and
/// endpoint (<c>ARCFORGES_ENDPOINT</c>), passed to every <c>arcforges</c> process it starts with <c>--test-mode</c> (<see cref="Start"/>
/// refuses to start the node, CLI or supervisor binaries without it). Under <c>--test-mode</c> the node keeps its node data key in the
/// file-backed isolated secret store of its data root and never selects an OS-wide secret store (02-node-service section 4); the child
/// environment never carries the OS secret-store tier's opt-in <c>ARCFORGES_OS_SECRET_STORE_TESTS</c>, which alone would lift that
/// rule. It has no CI markers (unless a test adds them), and on Linux a session bus address that does not exist. Disposing stops the
/// node, deletes its data key, verifies that every recorded key is absent from the data root's isolated store and that nothing else
/// is left there (a leak is reported by name), removes the files, and fails when any <c>arcforges</c> or <c>arcforges-supervisor</c>
/// process started from the binaries under test during the test is still running (16-testing-strategy section 4).
/// </summary>
internal sealed class TestNode : IAsyncDisposable
{
    private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(60);
    private readonly DateTime _created = DateTime.Now.AddSeconds(-1);
    private readonly HashSet<string> _uninspectable = [];
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

        // A stray tier opt-in in the test process must never reach a test node (16-testing-strategy section 1, guard item 1).
        Environment[OsSecretStoreGuard.OptInVariable] = null;

        // The --test-mode hook of 11 section 1's client-kind verification: this test process may present the Desktop kind, so a test acts as
        // the HUMAN approver (HumanChannelAsync); its CLI processes stay SCRIPT callers (no terminal).
        Environment["ARCFORGES_TEST_CLIENT_IMAGES"] = System.Environment.ProcessPath;

        if (!OperatingSystem.IsWindows())
        {
            Environment["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + Path.Combine(root, "no-session-bus");

            // 16 section 4: each test node gets its own slice.
            Environment["ARCFORGES_SLICE"] = Slice;

            // A JIT process the test kills would leave the runtime's diagnostic sockets in /tmp.
            Environment["DOTNET_EnableDiagnostics"] = "0";
        }
    }

    /// <summary>The node's slice on Linux (<c>arcforges-test-&lt;id&gt;.slice</c>).</summary>
    public string Slice { get; } = ArcForges.Tests.SystemdTestEnvironment.NewSlice();

    /// <summary>Test units this environment installed in the runtime unit directory (stopped and removed at the end).</summary>
    public List<string> Units { get; } = [];

    /// <summary>
    /// Installs a user unit for this test only, in <c>$XDG_RUNTIME_DIR/systemd/user</c> (cleared at logout; nothing is enabled); the unit is
    /// stopped and removed when the environment is disposed. <paramref name="name"/> must be new: the manager loads a unit it has not
    /// loaded yet from the unit directories on its first use, so no daemon-reload is needed (a reload stalls the manager for every test
    /// running beside this one).
    /// </summary>
    public string InstallUnit(string name, string content)
    {
        var directory = Path.Combine(System.Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR")!, "systemd", "user");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, name), content);
        Units.Add(name);
        return name;
    }

    /// <summary>The <c>Environment=</c> lines that give a unit this environment's variables (and the JIT build its runtime).</summary>
    public string UnitEnvironment()
    {
        var variables = Environment.Where(pair => pair.Value is not null).Select(pair => (pair.Key, Value: pair.Value!)).ToList();
        if (System.Environment.GetEnvironmentVariable("DOTNET_ROOT") is { Length: > 0 } dotnetRoot)
        {
            variables.Add(("DOTNET_ROOT", dotnetRoot));
        }

        return string.Join("\n", variables.Select(pair => $"Environment=\"{pair.Key}={pair.Value}\""));
    }

    /// <summary>
    /// A connection of this test process presenting the Desktop kind, which the test node verifies (<c>ARCFORGES_TEST_CLIENT_IMAGES</c>), so its
    /// origin is HUMAN: the approver of approval round trips (11 section 1).
    /// </summary>
    public async Task<NodeChannel> HumanChannelAsync()
    {
        var channel = NodeChannel.Create(OperatingSystem.IsWindows() ? ArcForges.LocalRpc.LocalRpcEndpoint.NamedPipe(Endpoint)
            : ArcForges.LocalRpc.LocalRpcEndpoint.UnixDomainSocket(Endpoint));
        var hello = ClientProcess.Hello(ArcForges.Contracts.Node.V1.ClientKind.Desktop);
        hello.CiMarkers.Clear();
        var answer = await channel.Node.HelloAsync(new ArcForges.Contracts.Node.V1.NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow.AddSeconds(10));
        Assert.True(answer.Value?.AssignedOrigin == ArcForges.Contracts.Node.V1.Origin.Human, $"the test channel is not HUMAN: {answer}");
        return channel;
    }

    /// <summary>Approves the first PENDING approval as a HUMAN once one appears (bounded), and returns it after its execution.</summary>
    public static async Task<ArcForges.Contracts.Node.V1.Approval> ApproveNextAsync(NodeChannel human, TimeSpan bound)
    {
        ArgumentNullException.ThrowIfNull(human);
        ArcForges.Contracts.Node.V1.Approval? pending = null;
        await WaitAsync(async () =>
        {
            var list = await human.Approvals.ListApprovalsAsync(new ArcForges.Contracts.Node.V1.ApprovalServiceListApprovalsRequest
            {
                Meta = new ArcForges.Contracts.Foundation.V1.RequestMeta { CorrelationId = CommandIds.New() },
                States = { ArcForges.Contracts.Node.V1.ApprovalState.Pending },
            }, deadline: DateTime.UtcNow.AddSeconds(10));
            pending = list.Value?.Approvals.FirstOrDefault();
            return pending is not null;
        }, bound, "a pending approval");
        var decided = await human.Approvals.DecideApprovalAsync(new ArcForges.Contracts.Node.V1.ApprovalServiceDecideApprovalRequest
        {
            Meta = new ArcForges.Contracts.Foundation.V1.RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
            ApprovalId = pending!.ApprovalId,
            Decision = ArcForges.Contracts.Node.V1.ApprovalDecisionKind.Approve,
        }, deadline: DateTime.UtcNow.AddSeconds(20));
        Assert.True(decided.Error is null, $"DecideApproval: {decided.Error}");
        return decided.Value.Approval;
    }

    /// <summary>The <c>arcforges</c> binary under test: <c>ARCFORGES_HOST_PATH</c> or the JIT build next to the tests.</summary>
    public static string Host { get; } = Binary("ARCFORGES_HOST_PATH", "arcforges");

    /// <summary>The <c>arcforges-testload</c> workload: <c>ARCFORGES_TESTLOAD_PATH</c> or the build next to the tests.</summary>
    public static string TestLoad { get; } = Binary("ARCFORGES_TESTLOAD_PATH", "arcforges-testload");

    /// <summary>
    /// A disk-backed parent for nodes whose attempts write files that must not land on tmpfs: the directory above the test binaries, because
    /// the binaries' own directory is the node's installation, which the Linux unit hardening makes read-only for attempts (AD-0007 section 8).
    /// </summary>
    public static string DiskParent { get; } = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory))!;

    /// <summary>The <c>arcforges</c> that <see cref="StartNodeAsync"/> runs as the node: <see cref="Host"/>, or a copy in a version directory.</summary>
    public string NodeExecutable { get; set; } = Host;

    public string Root { get; }

    public string ConfigDirectory { get; }

    public string DataRoot { get; }

    public string Endpoint { get; }

    /// <summary>The child processes' environment changes (null removes a variable).</summary>
    public Dictionary<string, string?> Environment { get; } = new(StringComparer.Ordinal);

    public string NodeLog => Path.Combine(DataRoot, "logs", "node", "node.log");

    public string SupervisorLog => Path.Combine(DataRoot, "logs", "supervisor", "supervisor.log");

    public static TestNode Create(string? parent = null)
    {
        var root = parent is null
            ? Directory.CreateTempSubdirectory("arcforges-closed-loop-").FullName
            : Directory.CreateDirectory(Path.Combine(parent, "arcforges-closed-loop-" + Guid.NewGuid().ToString("N")[..12])).FullName;
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

    /// <summary>
    /// Runs <c>arcforges --test-mode &lt;args&gt;</c> (the option before the arguments, so <c>run -- program</c> works) to completion and returns
    /// the exact bytes of its streams.
    /// </summary>
    public async Task<(int ExitCode, byte[] Stdout, byte[] Stderr)> CliBytesAsync(TimeSpan timeout, params string[] args)
    {
        using var process = Start(Host, [NodeLocations.TestModeOption, .. args]);
        return await BytesAsync(process, timeout);
    }

    /// <summary>Collects a started process's streams as bytes until it exits (bounded).</summary>
    public static async Task<(int ExitCode, byte[] Stdout, byte[] Stderr)> BytesAsync(Process process, TimeSpan timeout)
    {
        using var stdout = new MemoryStream();
        using var stderr = new MemoryStream();
        var copyOut = process.StandardOutput.BaseStream.CopyToAsync(stdout);
        var copyErr = process.StandardError.BaseStream.CopyToAsync(stderr);
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

        await Task.WhenAll(copyOut, copyErr);
        return (process.ExitCode, stdout.ToArray(), stderr.ToArray());
    }

    /// <summary>Writes policy revision 2 with <paramref name="change"/> applied (before the node first starts; PolicyService is AF-SCHED-01's).</summary>
    public void SeedPolicy(Action<ArcForges.Contracts.Node.V1.PolicyDocument> change)
    {
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = DataRoot, BootIdentity = "seed" });
        store.Write(transaction =>
        {
            var document = ArcForges.Node.Store.Policy.PolicyDocuments.Current(transaction).Document.Clone();
            change(document);
            transaction.Execute("UPDATE policy_document SET is_current = 0 WHERE is_current = 1;");
            transaction.Execute(
                """
                INSERT INTO policy_document (revision, document, digest, created_at, actor, comment, approval_id, is_current)
                VALUES (2, $document, $digest, $now, $actor, 'test policy', NULL, 1);
                """,
                ("$document", Google.Protobuf.MessageExtensions.ToByteArray(document)),
                ("$digest", ArcForges.Node.Store.Policy.PolicyDocuments.Digest(document)),
                ("$now", transaction.NowMicroseconds),
                ("$actor", Google.Protobuf.MessageExtensions.ToByteArray(new ArcForges.Contracts.Node.V1.ActorRef { Origin = ArcForges.Contracts.Node.V1.Origin.Human })));
        });
        SqliteConnection.ClearAllPools();
    }

    /// <summary>Starts <c>arcforges node run --test-mode</c> as a child of the test and waits until it answers.</summary>
    public async Task<Process> StartNodeAsync()
    {
        var process = Start(NodeExecutable, ["node", "run", NodeLocations.TestModeOption]);
        _children.Add(process);
        await WaitReadyAsync(process);
        return process;
    }

    /// <summary>
    /// Starts a process with the environment's variables; it is tracked and killed at the end if it still runs. The node, CLI and
    /// supervisor binaries start only with <c>--test-mode</c> (16-testing-strategy section 1: a test never starts a node without it),
    /// and the tier opt-in is removed even if a test put it back into <see cref="Environment"/>.
    /// </summary>
    public Process Start(string executable, IEnumerable<string> arguments)
    {
        var argumentList = arguments.ToList();
        var binary = Path.GetFileNameWithoutExtension(executable);
        if (binary is "arcforges" or "arcforges-supervisor" && !argumentList.Contains(NodeLocations.TestModeOption, StringComparer.Ordinal))
        {
            throw new InvalidOperationException($"{executable} must be started with {NodeLocations.TestModeOption} in a test.");
        }

        arguments = argumentList;
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

        start.Environment.Remove(OsSecretStoreGuard.OptInVariable);
        var process = Process.Start(start) ?? throw new InvalidOperationException($"{executable} did not start.");
        process.StandardInput.Close();
        _children.Add(process);
        return process;
    }

    /// <summary>Waits until <c>node wait-ready</c> succeeds (the node answers its hello).</summary>
    public async Task WaitReadyAsync(Process? node = null)
    {
        var run = await CliAsync("node", "wait-ready", "--timeout", "30s");
        Assert.True(run.ExitCode == 0, $"The node did not become ready: {run}" + (node is { HasExited: true } ? $" (node exited {node.ExitCode})" : string.Empty)
            + Diagnostics());
    }

    /// <summary>Runs <c>node stop --verbose</c> (its transport attempts on stderr) and fails with <see cref="Diagnostics"/> unless it exits 0.</summary>
    public async Task<ProcessRun> StopNodeAsync()
    {
        var run = await CliAsync("node", "stop", "--verbose");
        Assert.True(run.ExitCode == 0, run + Diagnostics());
        return run;
    }

    /// <summary>
    /// What a failed CLI call against this environment's node needs next to it: the descriptor's process and whether it is alive, the
    /// supervisor log and the end of the node log.
    /// </summary>
    public string Diagnostics()
    {
        var descriptor = Descriptor();
        var process = descriptor is null ? "no endpoint descriptor" : $"descriptor pid {descriptor.ProcessId}, alive {descriptor.ProcessIsAlive()}";
        static string Tail(string path, int lines) => string.Join('\n', ReadShared(path).Split('\n').TakeLast(lines));
        return $"\n--- {process}\n--- supervisor log:\n{Tail(SupervisorLog, 60)}\n--- node log (last 40 lines):\n{Tail(NodeLog, 40)}";
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

    /// <summary>
    /// How long after its start a node with the hang fault <paramref name="fault"/> (<c>name=seconds</c>, ExecutionFaults) would have
    /// stopped renewing its heartbeat: the fault's delay; for a hung probe, the probe timeout (5 s) and up to three missed probes one second
    /// apart; and two heartbeat intervals (1 s each).
    /// </summary>
    public static TimeSpan FaultHorizon(string fault, int seconds) =>
        TimeSpan.FromSeconds(seconds + (fault == "hang-probe-after" ? 8 : 0) + 2);

    /// <summary>
    /// Waits until the node heartbeat (<c>run/node-heartbeat</c>) changes once <paramref name="horizon"/> has passed on
    /// <paramref name="since"/>: a condition that proves the node still renews it, instead of a fixed wait. Bounded by 30 s past the horizon.
    /// </summary>
    public async Task WaitHeartbeatChangeAsync(Stopwatch since, TimeSpan horizon)
    {
        var path = ArcForges.Node.Platform.AttemptFiles.HeartbeatPath(DataRoot);
        var seen = ReadShared(path);
        await WaitAsync(() =>
        {
            var current = ReadShared(path);
            var changed = current.Length > 0 && current != seen;
            seen = current;
            return changed && since.Elapsed > horizon;
        }, horizon + TimeSpan.FromSeconds(30), $"the heartbeat to change more than {horizon.TotalSeconds:0} s after the start");
    }

    /// <summary>A file another process replaces or writes, or an empty string while it is missing.</summary>
    public static string ReadShared(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            return reader.ReadToEnd();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
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

    /// <summary>
    /// Running processes of the binaries under test started since this environment was created that belong to it: they carry its
    /// endpoint in their environment (every node, supervisor, holder and helper it started inherits it), or on Linux run in its slice
    /// (the helpers of its attempt units). Tests run in parallel, so the processes of another environment are never counted. A running
    /// process whose environment cannot be read is neither counted nor dropped: the last scan remembers it and the fixture reports it.
    /// </summary>
    public List<Process> LiveProcesses()
    {
        var binaries = new[] { Host, NodeExecutable, Path.Combine(Path.GetDirectoryName(Host)!, OperatingSystem.IsWindows() ? "arcforges-supervisor.exe" : "arcforges-supervisor") }
            .Select(path => Path.GetFullPath(path)).ToHashSet(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        var live = new List<Process>();
        lock (_uninspectable)
        {
            // Only the last scan counts: a process may be briefly uninspectable while it starts or exits.
            _uninspectable.Clear();
        }

        foreach (var process in Process.GetProcessesByName("arcforges").Concat(Process.GetProcessesByName("arcforges-supervisor")))
        {
            try
            {
                if (!process.HasExited && process.MainModule?.FileName is { } file && binaries.Contains(Path.GetFullPath(file)) && process.StartTime >= _created)
                {
                    switch (Owns(process.Id))
                    {
                        case true:
                            live.Add(process);
                            continue;
                        case null when !process.HasExited && !ArcForges.Tests.ProcessInspection.IsZombie(process.Id):
                            lock (_uninspectable)
                            {
                                _uninspectable.Add($"{process.ProcessName} (pid {process.Id}, started {process.StartTime:O}): its environment cannot be read, so it may belong to this test");
                            }

                            break;
                    }
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

    /// <summary>True when the process belongs to this environment, false when it does not, null when that cannot be told.</summary>
    private bool? Owns(int pid)
    {
        if (!OperatingSystem.IsWindows() && ProcessCgroup(pid) is { } cgroup && cgroup.Contains("/" + Slice + "/", StringComparison.Ordinal))
        {
            return true;
        }

        return ArcForges.Tests.ProcessInspection.TryEnvironmentValue(pid, NodeLocations.EndpointVariable, out var endpoint) ? endpoint == Endpoint : null;
    }

    private static string? ProcessCgroup(int pid)
    {
        try
        {
            return File.ReadAllText($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/cgroup");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
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

            // Attempts outlive a stopped node under their holders: end them, release the holders, and count what was left (16 section 4).
            if (OperatingSystem.IsWindows())
            {
                leftovers.AddRange(EndAttempts());
            }
            else
            {
                // Attempts outlive a stopped node as transient units: stop this node's units, its slice and the test units, and count what was left.
                foreach (var unit in Units)
                {
                    ArcForges.Tests.SystemdTestEnvironment.Systemctl("stop", unit);
                }

                leftovers.AddRange(ArcForges.Tests.SystemdTestEnvironment.Cleanup(Slice, AttemptNames(), Units));
                var unitDirectory = Path.Combine(System.Environment.GetEnvironmentVariable("XDG_RUNTIME_DIR") ?? "/nonexistent", "systemd", "user");
                foreach (var unit in Units)
                {
                    File.Delete(Path.Combine(unitDirectory, unit));
                }

                // No daemon-reload (see InstallUnit): a stopped unit whose file is gone is unloaded once it is not failed.
                foreach (var unit in Units)
                {
                    ArcForges.Tests.SystemdTestEnvironment.Systemctl("reset-failed", unit);
                }
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

            lock (_uninspectable)
            {
                // Not killed: it may be another test's.
                leftovers.AddRange(_uninspectable);
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

            leftovers.AddRange(DeleteDataKeys());
            SqliteConnection.ClearAllPools();
            Directory.Delete(Root, recursive: true);
            if (!OperatingSystem.IsWindows() && Directory.Exists(Path.GetDirectoryName(Endpoint)))
            {
                Directory.Delete(Path.GetDirectoryName(Endpoint)!, recursive: true);
            }
        }

        ArcForges.Tests.Leftovers.Report(leftovers);
    }

    /// <summary>The attempts of this node's store.</summary>
    public List<string> AttemptNames()
    {
        if (!File.Exists(StorePaths.Database(DataRoot)))
        {
            return [];
        }

        List<string> names;
        using (var store = NodeStore.Open(new NodeStoreOptions { DataRoot = DataRoot, BootIdentity = "cleanup" }))
        {
            names = store.Read(reader =>
            {
                var list = new List<string>();
                using var command = reader.CreateCommand("SELECT attempt_id FROM attempt;");
                using var rows = command.ExecuteReader();
                while (rows.Read())
                {
                    list.Add(IdText.Format((byte[])rows.GetValue(0)));
                }

                return list;
            });
        }

        SqliteConnection.ClearAllPools();
        return names;
    }

    /// <summary>Terminates every attempt job of this node by name and sets its ack event; returns the attempts that still ran.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private List<string> EndAttempts()
    {
        var running = new List<string>();
        if (!File.Exists(StorePaths.Database(DataRoot)))
        {
            return running;
        }

        string node;
        List<string> attempts;
        using (var store = NodeStore.Open(new NodeStoreOptions { DataRoot = DataRoot, BootIdentity = "cleanup" }))
        {
            node = IdText.Format(store.Metadata.NodeId.Span);
            attempts = store.Read(reader =>
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
        }

        SqliteConnection.ClearAllPools();
        foreach (var attempt in attempts)
        {
            using var job = ArcForges.Node.Platform.Windows.JobObject.Open(ArcForges.Node.Platform.Windows.WindowsExecutionPlatform.JobName(node, attempt));
            if (job is not null && job.Accounting().ActiveProcesses > 0)
            {
                running.Add($"attempt {attempt}");
                job.Terminate(1);
            }
        }

        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromSeconds(15))
        {
            var open = 0;
            foreach (var attempt in attempts)
            {
                if (EventWaitHandle.TryOpenExisting(ArcForges.Node.Platform.Windows.WindowsExecutionPlatform.AckName(node, attempt), out var ack))
                {
                    using (ack)
                    {
                        ack.Set();
                    }

                    open++;
                }
            }

            if (open == 0)
            {
                break;
            }

            Thread.Sleep(100);
        }

        return running;
    }

    /// <summary>
    /// Deletes the node data keys the store records from the data root's isolated secret store (where every test node keeps them), then
    /// verifies that each is absent and nothing else is left there; returns what is left, by name (test verification).
    /// </summary>
    private List<string> DeleteDataKeys()
    {
        if (!File.Exists(StorePaths.Database(DataRoot)))
        {
            return [];
        }

        var secrets = NodeSecretStores.ForTestDataRoot(DataRoot);
        var files = (TestDataRootSecretStore)secrets.Store;
        List<string> names;
        using (var store = NodeStore.Open(new NodeStoreOptions { DataRoot = DataRoot, BootIdentity = "cleanup" }))
        using (var keys = new NodeDataKeyRing(store, secrets))
        {
            names = [.. keys.Keys().Select(key => NodeDataKeyRing.TargetName(store.Metadata.NodeId.Span, key.KeyId))];
            keys.DeleteKeys();
        }

        var remaining = names.Where(name => files.Read(name) is not null).ToList();
        return [.. remaining.Select(name => "node data key " + name + " still in the isolated secret store after its delete"),
            .. files.Names().Except(remaining, StringComparer.Ordinal).Select(name => "isolated secret store entry " + name)];
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
