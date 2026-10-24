// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Api;

/// <summary>The exit codes of <c>arcforges node run</c> (experience/cli.md section 3).</summary>
public static class NodeExitCodes
{
    /// <summary>Stopped normally.</summary>
    public const int Success = 0;

    /// <summary>A fatal startup error (configuration, store, endpoint).</summary>
    public const int Failure = 1;

    /// <summary>Another node instance runs for this user (ALREADY_RUNNING).</summary>
    public const int AlreadyRunning = 3;
}

/// <summary>How <c>arcforges node run</c> runs.</summary>
public sealed record NodeHostOptions
{
    /// <summary>Honour the <c>ARCFORGES_*</c> test hooks (endpoint, configuration directory).</summary>
    public bool TestMode { get; init; }

    /// <summary>Started by the systemd user unit (<c>--systemd</c>); readiness and watchdog go to <c>NOTIFY_SOCKET</c> either way.</summary>
    public bool Systemd { get; init; }

    /// <summary>Where the node prints the endpoint of an instance that is already running.</summary>
    public TextWriter Output { get; init; } = Console.Out;

    /// <summary>Where the node prints fatal startup errors.</summary>
    public TextWriter Error { get; init; } = Console.Error;

    /// <summary>The crash recovery hooks run while RECOVERING (02 section 2 step 5).</summary>
    public IReadOnlyList<INodeRecoveryParticipant> Recovery { get; init; } = [];

    /// <summary>The node clock.</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>The <c>node.json</c> to use instead of the platform location (component tests run several nodes in one process).</summary>
    public string? ConfigPath { get; init; }

    /// <summary>The endpoint to listen on instead of the per-user one (component tests); it also names the instance.</summary>
    public LocalRpcEndpoint? Endpoint { get; init; }

    /// <summary>The per-subscriber event buffer (02 section 1: 2,048).</summary>
    public int StreamBuffer { get; init; } = 2048;

    /// <summary>Called once the node is READY or DEGRADED and serving (component tests wait for it).</summary>
    public Action<NodeRuntime>? Ready { get; init; }

    /// <summary>
    /// The secret store of the node data key for a data root. Null (the executable): <see cref="NodeSecretStores.ForNode(string, bool)"/>,
    /// the OS secret store in production and, with <see cref="TestMode"/>, the file-backed isolated store of the test data root unless
    /// the OS secret-store tier's opt-in is set (02-node-service section 4). Every in-process test node sets it to an isolated backend
    /// (16-testing-strategy section 2; ArcForges.Repository.Tests checks this).
    /// </summary>
    internal Func<string, NodeSecretStore>? SecretStore { get; init; }

    /// <summary>
    /// The <c>arcforges</c> executable whose helper roles (<c>node exec-wrap</c>, <c>node signal</c>) the node starts: by default the
    /// executable beside this one (04 section 3: helpers are invoked by path); component tests name the host built next to them.
    /// </summary>
    public string? HelperExecutable { get; init; }

    /// <summary>
    /// The version directory the node runs from, whose <c>digests.json</c> the node verifies after startup (AD-0007 section 8): by default
    /// the directory of <see cref="HelperExecutable"/>, else of this executable; component tests name a temporary one.
    /// </summary>
    public string? VersionDirectory { get; init; }

    /// <summary>Launch and end steps of attempts (toolchain adapters; tests supply synthetic steps).</summary>
    public ILaunchStepProvider? LaunchSteps { get; init; }

    /// <summary>The tool-level concurrency hook of the adapters (03 section 5.3; synthetic adapters in tests).</summary>
    public ArcForges.Node.Core.Scheduling.IToolConcurrency? ToolConcurrency { get; init; }

    /// <summary>Linux: the root slice (component tests give each node its own; default <c>arcforges.slice</c>, or the test hook in test mode).</summary>
    public string? LinuxSlice { get; init; }

    /// <summary>Linux: the user manager's D-Bus address (component tests may name an absent one; default the user bus, else the manager's private socket).</summary>
    public string? SystemdAddress { get; init; }

    /// <summary>Linux: the controllers treated as delegated (component tests simulate a manager without a controller; default as read).</summary>
    public IReadOnlyCollection<string>? LinuxControllers { get; init; }
}

/// <summary>
/// <c>arcforges node run</c>: the node's startup sequence, service and shutdown (architecture 02 section 2):
/// <list type="number">
/// <item>Resolve <c>node.json</c> and the data root (created owner-only).</item>
/// <item>Single instance: the named mutex (Windows) or <c>flock</c> on <c>node.lock</c> (Linux); exit 3 with the endpoint when held.</item>
/// <item>Open the store (backup and forward migrations), <c>quick_check</c> after an unclean shutdown.</item>
/// <item>Compare the boot identity.</item>
/// <item>Recovery hooks (RECOVERING).</item>
/// <item>Capabilities.</item>
/// <item>The LocalRpc service endpoint, then <c>run/endpoint.json</c> written atomically.</item>
/// <item>Housekeeping and the node data key load (outside the writer lock).</item>
/// <item>READY or DEGRADED journaled; <c>READY=1</c> to systemd; the Windows ready event set.</item>
/// </list>
/// Shutdown (StopNode, SIGTERM/SIGINT, or a fatal error) journals STOPPING, answers new calls <c>STATE/node_stopping</c>, stops the
/// listener, drains the command processor, checkpoints the WAL, removes the endpoint descriptor, writes the clean-shutdown marker and
/// exits 0, within 10 s.
/// </summary>
public static class NodeHost
{
    /// <summary>The shutdown budget (02 section 2).</summary>
    public static readonly TimeSpan ShutdownBudget = TimeSpan.FromSeconds(10);

    private static readonly TimeSpan HousekeepingInterval = TimeSpan.FromMinutes(10);

    /// <summary>How long after READY the version directory check starts (AD-0007 section 8: off the startup path).</summary>
    private static readonly TimeSpan VersionCheckDelay = TimeSpan.FromSeconds(5);

    /// <summary>Runs the node until it is stopped; returns the process exit code.</summary>
    public static async Task<int> RunAsync(NodeHostOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        var clock = options.Clock;
        string configPath;
        NodeConfigurationFile configuration;
        string dataRoot;
        try
        {
            configPath = options.ConfigPath ?? NodeLocations.ConfigFile(options.TestMode);
            configuration = NodeConfiguration.Read(configPath);
            dataRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuration.DataRoot ?? NodeLocations.DefaultDataRoot()));
            StorePaths.CreatePrivateDirectory(dataRoot);
            StorePaths.CreatePrivateDirectory(NodeLocations.RunDirectory(dataRoot));
            StorePaths.CreatePrivateDirectory(Path.Combine(dataRoot, "logs", "node"));
        }
        catch (Exception exception) when (exception is NodeConfigurationException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            await options.Error.WriteLineAsync($"arcforges: the node cannot start: {exception.Message}").ConfigureAwait(false);
            return NodeExitCodes.Failure;
        }

        var instanceKey = options.Endpoint is { } explicitEndpoint ? NodeLocations.InstanceKeyFor(explicitEndpoint.Address) : NodeLocations.InstanceKey(options.TestMode);
        var endpoint = options.Endpoint ?? NodeLocations.Endpoint(options.TestMode, dataRoot);
        using var instance = SingleInstance.TryAcquire(instanceKey, dataRoot);
        if (instance is null)
        {
            var running = EndpointDescriptor.TryRead(NodeLocations.EndpointDescriptorFile(dataRoot));
            var address = running is not null && running.ProcessIsAlive() ? running.Endpoint : endpoint.Address;
            await options.Output.WriteLineAsync(address).ConfigureAwait(false);
            await options.Error.WriteLineAsync($"arcforges: the node is already running (endpoint {address})").ConfigureAwait(false);
            return NodeExitCodes.AlreadyRunning;
        }

        using var log = new NodeLog(Path.Combine(dataRoot, "logs", "node"), NodeConfiguration.ParseLogLevel(configuration.LogLevel), clock);
        log.Info("node.starting", new LogField("pid", Environment.ProcessId), new LogField("version", NodeContract.ProductVersion),
            new LogField("testMode", options.TestMode), new LogField("systemd", options.Systemd),
            new LogField("osStoresDenied", ArcForges.Security.Secrets.OsSecretStoreGuard.IsDenied));
        var faults = ExecutionFaults.FromEnvironment(options.TestMode, dataRoot);
        if (faults.Take("slow-startup") is { } slow)
        {
            // Fault injection (test mode): a long store migration before the first heartbeat.
            log.Warning("node.fault.slow_startup", new LogField("delayMs", (long)slow.TotalMilliseconds));
            await Task.Delay(slow, cancellationToken).ConfigureAwait(false);
        }
        using var notifier = SystemdNotifier.FromEnvironment();
        using var ready = OperatingSystem.IsWindows() ? WindowsReadyEvent.Create(instanceKey) : null;

        NodeStore store;
        try
        {
            store = NodeStore.Open(new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = BootIdentity.Read(), Clock = clock });
        }
        catch (Exception exception) when (exception is StoreIncompatibleException or Microsoft.Data.Sqlite.SqliteException or IOException
            or UnauthorizedAccessException)
        {
            log.Error("node.store.failed", exception);
            await options.Error.WriteLineAsync($"arcforges: the node store cannot be opened: {exception.Message}").ConfigureAwait(false);
            return NodeExitCodes.Failure;
        }

        try
        {
            return await ServeAsync(options, store, log, notifier, ready, configPath, dataRoot, endpoint, faults, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Records the clean-shutdown marker and closes the writer.
            store.Dispose();
        }
    }

    private static async Task<int> ServeAsync(NodeHostOptions options, NodeStore store, NodeLog log, SystemdNotifier notifier, WindowsReadyEvent? ready,
        string configPath, string dataRoot, LocalRpcEndpoint endpoint, ExecutionFaults faults, CancellationToken cancellationToken)
    {
        var clock = options.Clock;
        var metadata = store.Metadata;
        var unclean = !metadata.PreviousShutdownClean;
        var bootChanged = !string.Equals(metadata.PreviousBootIdentity, metadata.BootIdentity, StringComparison.Ordinal);
        var integrity = unclean ? StoreRecovery.QuickCheck(store) : null;
        var recovery = new RecoveryReport(unclean, bootChanged, integrity, store.Opening);
        if (integrity is not null && integrity != "ok")
        {
            log.Error("node.store.corrupt", new LogField("quickCheck", NodeLog.OneLine(integrity)));
            await options.Error.WriteLineAsync($"arcforges: the node store failed its integrity check: {NodeLog.OneLine(integrity)}").ConfigureAwait(false);
            return NodeExitCodes.Failure;
        }

        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        var processor = new CommandProcessor(store, journal, hub);
        var settings = new NodeSettingsManager(configPath, dataRoot, log);

        // The node data key loads at startup, outside the writer (secret-store I/O must never run under the writer lock).
        var keys = new NodeDataKeyRing(store, options.SecretStore?.Invoke(dataRoot) ?? NodeSecretStores.ForNode(dataRoot, options.TestMode));
        var keyLoad = Task.Run(() =>
        {
            var keyId = keys.Prepare(out var reason);
            if (keyId is null)
            {
                log.Warning("node.data_key.unavailable", new LogField("backend", keys.Backend), new LogField("reason", NodeLog.OneLine(reason)));
            }
            else
            {
                log.Info("node.data_key.loaded", new LogField("keyId", keyId), new LogField("backend", keys.Backend), new LogField("protection", keys.Protection),
                    new LogField("isolated", keys.Isolated));
            }
        }, CancellationToken.None);

        // 02 section 2 step 6: the platform layer creates or re-opens the root container and verifies enforcement with a probe.
        var platform = StartPlatform(options, store, log);
        var capabilities = platform is null ? NodeCapabilities.Evaluate(clock) : NodeCapabilities.FromPlatform(platform, clock);
        if (OperatingSystem.IsLinux())
        {
            // An in-memory data root: captured output and temporary files count against the attempts' memory (no swap to reclaim into).
            var inMemory = NodeCapabilities.AddDataRootFact(capabilities, dataRoot);
            foreach (var (path, kind) in inMemory)
            {
                log.Warning("node.data_root_in_memory", new LogField("path", path), new LogField("filesystem", kind));
            }
        }

        using var heartbeat = new NodeHeartbeatWriter(dataRoot, log, clock);
        if (notifier.WatchdogInterval is { } watchdogInterval)
        {
            // 13 section 3.4: WatchdogSec=30, pinged with each heartbeat renewal from the enforcement loop (06 section 5).
            heartbeat.Renewed = () => notifier.Notify("WATCHDOG=1");
            log.Info("node.watchdog", new LogField("intervalMs", (long)watchdogInterval.TotalMilliseconds));
        }
        var execution = new ExecutionSupervisor(new ExecutionOptions
        {
            Store = store,
            Processor = processor,
            Log = log,
            Clock = clock,
            DataRoot = dataRoot,
            Platform = platform,
            Secrets = new TaskSecrets(store, keys),
            KeysReady = keyLoad,
            Steps = options.LaunchSteps,
            Tools = options.ToolConcurrency,
            Faults = faults,
            Heartbeat = heartbeat,
            Unenforced = platform is not null && !NodeCapabilities.FullyEnforced(capabilities),
            Sampler = CreateSampler(),
        });
        using var node = new NodeRuntime(store, journal, hub, processor, log, settings, dataRoot, endpoint.Address, clock, recovery, capabilities)
        {
            Execution = execution,
        };
        var versionDirectory = options.VersionDirectory
            ?? (options.HelperExecutable is { } helperPath ? Path.GetDirectoryName(Path.GetFullPath(helperPath)) : null)
            ?? AppContext.BaseDirectory;
        node.SetFact(VersionIntegrity.FactName, VersionIntegrity.InitialFact(versionDirectory));

        // The capability report's root_* facts follow the root limits the scheduler applies from the measured budgets (03 section 5.1).
        execution.RootLimitsApplied = _ => node.Reevaluate();
        using var stopSignals = RegisterSignals(node);
        using var external = cancellationToken.Register(() => node.RequestStop("cancelled"));
        LocalRpcServer? server = null;
        using var housekeeping = new PeriodicTimer(HousekeepingInterval);
        Task housekeepingLoop = Task.CompletedTask;
        Task versionCheck = Task.CompletedTask;
        using var loops = new CancellationTokenSource();
        try
        {
            await processor.ExecuteAsync(context =>
            {
                context.Emit(EventTopic.Node, new NodeEvent { Node = node.Status("starting") });
                return 0;
            }).ConfigureAwait(false);
            await node.TransitionAsync(NodeLifecycleState.Recovering, unclean ? "unclean_shutdown" : "store_opened").ConfigureAwait(false);
            if (store.Opening.TransientRetries > 0)
            {
                log.Warning("store.open.retried", new LogField("retries", store.Opening.TransientRetries),
                    new LogField("extendedCode", store.Opening.LastTransientCode ?? 0));
            }

            log.Info("node.recovering", new LogField("uncleanShutdown", unclean), new LogField("bootChanged", bootChanged),
                new LogField("storeCreated", store.Opening.Created), new LogField("migratedFrom", store.Opening.MigratedFrom ?? 0),
                new LogField("generation", journal.Generation));
            foreach (var participant in options.Recovery.Prepend(execution))
            {
                await participant.RecoverAsync(recovery, processor, node.Stopping).ConfigureAwait(false);
                log.Info("node.recovery.done", new LogField("participant", participant.Name));
            }

            var sessions = new ClientSessions
            {
                Opened = session => execution.CallerConnected(new CallerKey(session.Peer.ProcessId, session.Peer.ProcessStartTime.UtcTicks)),
                Closed = session => execution.CallerDisconnected(new CallerKey(session.Peer.ProcessId, session.Peer.ProcessStartTime.UtcTicks)),
            };
            server = NodeApiServer.Build(endpoint, node, sessions, options.StreamBuffer, ClientImages.ForNode(ClientImages.TestHookApplies(options.TestMode, endpoint.Address, configPath, dataRoot)));
            try
            {
                await server.StartAsync(node.Stopping).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException or UnauthorizedAccessException)
            {
                log.Error("node.endpoint.failed", exception);
                await options.Error.WriteLineAsync($"arcforges: the node endpoint {endpoint.Address} cannot be opened: {exception.Message}").ConfigureAwait(false);
                return NodeExitCodes.Failure;
            }

            new EndpointDescriptor
            {
                Endpoint = endpoint.Address,
                Transport = endpoint.Transport == LocalRpcTransport.NamedPipe ? "named-pipe" : "unix-socket",
                NodeId = IdText.Format(node.NodeId.Span),
                ProcessId = Environment.ProcessId,
                ProcessStartUnixMs = EndpointDescriptor.CurrentProcessStartUnixMs(),
                StartedAt = node.StartedAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture),
                ContractMajor = NodeContract.Major,
                ContractMinor = NodeContract.Minor,
                Version = NodeContract.ProductVersion,
            }.Write(NodeLocations.EndpointDescriptorFile(dataRoot));

            if (faults.Take("slow-ready") is { } slowReady)
            {
                // Fault injection (test mode): the node listens and answers hellos in RECOVERING, but is not READY yet.
                log.Warning("node.fault.slow_ready", new LogField("delayMs", (long)slowReady.TotalMilliseconds));
                await Task.Delay(slowReady, cancellationToken).ConfigureAwait(false);
            }

            housekeepingLoop = HousekeepAsync(node, keys, housekeeping, loops.Token);
            if (OperatingSystem.IsLinux() && platform is ArcForges.Node.Platform.Linux.LinuxExecutionPlatform { UnitMode: true } linux)
            {
                // 06 section 5: arcforges-guard.service guards the attempt units while the node is down; started when installed.
                var guardUnit = LinuxTestHooks.Value(options.TestMode, LinuxTestHooks.GuardUnit) ?? LinuxTestHooks.DefaultGuardUnit;
                log.Info("node.guard_unit", new LogField("unit", guardUnit), new LogField("state", linux.EnsureGuard(guardUnit)));
            }

            var enforced = NodeCapabilities.FullyEnforced(node.Capabilities);
            await node.TransitionAsync(enforced ? NodeLifecycleState.Ready : NodeLifecycleState.Degraded,
                enforced ? "ready" : NodeCapabilities.DegradedReason).ConfigureAwait(false);
            execution.Start();
            if (node.ResumeApprovals is { } resume)
            {
                // 11 section 1: an approval the previous run approved but did not execute runs now, under its original command ID.
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await resume().ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException)
                    {
                        log.Warning("node.approvals.resume_failed", new LogField("errorType", exception.GetType().Name));
                    }
                }, CancellationToken.None);
            }

            notifier.Notify("READY=1\nSTATUS=ArcForges node " + node.Lifecycle.State.ToString().ToLowerInvariant());
            ready?.Set();
            options.Ready?.Invoke(node);
            log.Info("node.ready", new LogField("state", node.Lifecycle.State), new LogField("endpoint", endpoint.Address),
                new LogField("transport", endpoint.Transport), new LogField("platform", platform?.Name ?? "none"),
                new LogField("heartbeatInstance", heartbeat.Instance));

            // AD-0007 section 8: the version directory is made read-only and verified against its digests off the startup path.
            versionCheck = CheckVersionAsync(node, versionDirectory, loops.Token);

            try
            {
                await Task.Delay(Timeout.Infinite, node.Stopping).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            return await ShutdownAsync(node, server, ready, notifier, processor, dataRoot, loops, [housekeepingLoop, keyLoad, versionCheck]).ConfigureAwait(false);
        }
        finally
        {
            if (server is not null)
            {
                await server.DisposeAsync().ConfigureAwait(false);
            }

            await execution.DisposeAsync().ConfigureAwait(false);
            platform?.Dispose();
            keys.Dispose();
            await processor.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task<int> ShutdownAsync(NodeRuntime node, LocalRpcServer server, WindowsReadyEvent? ready, SystemdNotifier notifier,
        CommandProcessor processor, string dataRoot, CancellationTokenSource loops, Task[] background)
    {
        var started = node.Clock.GetTimestamp();
        using var overrun = new Timer(_ =>
        {
            node.Log.Error("node.shutdown.overrun", new LogField("budgetMs", (long)ShutdownBudget.TotalMilliseconds));
            Environment.Exit(NodeExitCodes.Success);
        }, null, ShutdownBudget + TimeSpan.FromSeconds(2), Timeout.InfiniteTimeSpan);
        if (!node.Lifecycle.IsStopping)
        {
            try
            {
                await node.TransitionAsync(NodeLifecycleState.Stopping, node.StopReason ?? "stop").ConfigureAwait(false);
            }
            catch (InvalidLifecycleTransitionException)
            {
            }
        }

        ready?.Reset();
        notifier.Notify("STOPPING=1");
        node.Log.Info("node.stopping", new LogField("reason", node.StopReason ?? "stop"));
        using (var budget = new CancellationTokenSource(ShutdownBudget / 2))
        {
            try
            {
                await server.StopAsync(budget.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        await loops.CancelAsync().ConfigureAwait(false);
        await Task.WhenAny(Task.WhenAll(background), Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false);

        // Running attempts stay with their holders (their guards take over the disk limits); kill_with_node attempts end here.
        if (node.Execution is { } execution)
        {
            await execution.StopAsync().ConfigureAwait(false);
        }

        await processor.DisposeAsync().ConfigureAwait(false);
        node.Store.Checkpoint();
        var descriptorPath = NodeLocations.EndpointDescriptorFile(dataRoot);
        if (EndpointDescriptor.TryRead(descriptorPath) is { } descriptor && descriptor.ProcessId == Environment.ProcessId)
        {
            await DeleteDescriptorAsync(node.Log, descriptorPath).ConfigureAwait(false);
        }

        node.Log.Info("node.stopped", new LogField("shutdownMs", (long)node.Clock.GetElapsedTime(started).TotalMilliseconds));
        return NodeExitCodes.Success;
    }

    /// <summary>
    /// Deletes the node's endpoint descriptor. Another process may hold it open without delete sharing for a moment (a scanner, an
    /// older client); after a bounded retry the descriptor stays and the shutdown goes on: clients ignore a descriptor whose process
    /// is gone (02 section 3 step 2) and the next node replaces it.
    /// </summary>
    private static async Task DeleteDescriptorAsync(NodeLog log, string path)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Delete(path);
                return;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                if (attempt == 10)
                {
                    log.Warning("node.descriptor.delete_failed", new LogField("errorType", exception.GetType().Name), new LogField("attempts", attempt));
                    return;
                }
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100)).ConfigureAwait(false);
        }
    }

    private static async Task HousekeepAsync(NodeRuntime node, NodeDataKeyRing keys, PeriodicTimer timer, CancellationToken cancellationToken)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    // Approvals past their TTL expire; decided approvals (90 days) and audit entries (1 year) are pruned (node-store.md).
                    var removed = await node.Processor.ExecuteAsync(context =>
                        EventJournal.Prune(context.Transaction) + Notifications.Prune(context.Transaction) + Jobs.Prune(context.Transaction)
                        + Approvals.Expire(context) + Approvals.Prune(context.Transaction) + AuditLog.Prune(context.Transaction)).ConfigureAwait(false);
                    var commands = node.Store.Commands.PurgeExpired();

                    // Sealed secret values past storage.secret_retention_hours (04 section 2) and kept temporary directories of failed attempts.
                    var secrets = new TaskSecrets(node.Store, keys).PurgeDue();
                    var temporary = node.Execution?.RemoveExpiredTemp() ?? 0;
                    node.Log.Debug("node.housekeeping", new LogField("rowsRemoved", removed + commands), new LogField("secretsPurged", secrets),
                        new LogField("tmpRemoved", temporary));
                }
                catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException)
                {
                    node.Log.Warning("node.housekeeping.failed", new LogField("errorType", exception.GetType().Name));
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>The observation sources of 03 section 1 (independent of enforcement: an observe-only node still observes).</summary>
    private static IResourceSampler? CreateSampler()
    {
        if (OperatingSystem.IsWindows())
        {
            return new ArcForges.Node.Platform.Windows.WindowsResourceSampler();
        }

        return OperatingSystem.IsLinux() ? new ArcForges.Node.Platform.Linux.LinuxResourceSampler() : null;
    }

    /// <summary>
    /// Makes the version directory read-only and verifies it against its <c>digests.json</c> on a background thread of below-normal priority
    /// (AD-0007 section 8), <see cref="VersionCheckDelay"/> after the node is ready, so the first clients' exchanges never compete with it;
    /// then reports the fact <c>version_integrity</c>; a mismatch raises the tamper finding ENFORCEMENT_DEGRADED (11 section 1) with the
    /// paths. Without a manifest nothing runs (the fact stays "not checked").
    /// </summary>
    private static async Task CheckVersionAsync(NodeRuntime node, string directory, CancellationToken cancellationToken)
    {
        if (!VersionIntegrity.HasManifest(directory))
        {
            return;
        }

        try
        {
            await Task.Delay(VersionCheckDelay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        var checkedReport = new TaskCompletionSource<VersionIntegrityReport?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                checkedReport.TrySetResult(VersionIntegrity.Check(directory, cancellationToken));
            }
            catch (OperationCanceledException)
            {
                checkedReport.TrySetResult(null);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                node.Log.Warning("node.version_integrity.failed", new LogField("errorType", exception.GetType().Name));
                checkedReport.TrySetResult(null);
            }
        })
        {
            IsBackground = true,
            Name = "ArcForges version integrity",
            Priority = ThreadPriority.BelowNormal,
        };
        thread.Start();
        await RecordVersionCheckAsync(node, directory, checkedReport.Task).ConfigureAwait(false);
    }

    private static async Task RecordVersionCheckAsync(NodeRuntime node, string directory, Task<VersionIntegrityReport?> check)
    {
        if (await check.ConfigureAwait(false) is not { } report)
        {
            return;
        }

        node.SetFact(VersionIntegrity.FactName, report.Fact);
        if (report.Mismatches == 0)
        {
            node.Log.Info("node.version_integrity.verified", new LogField("directory", directory), new LogField("madeReadOnly", report.MadeReadOnly),
                new LogField("notReadOnly", report.NotReadOnly.Count));
            return;
        }

        node.Log.Warning("node.version_integrity.mismatch", new LogField("directory", directory), new LogField("missing", report.Missing.Count),
            new LogField("changed", report.Changed.Count), new LogField("unlisted", report.Unlisted.Count), new LogField("links", report.Links.Count),
            new LogField("hardLinks", report.HardLinks.Count), new LogField("invalid", report.Invalid.Count), new LogField("manifest", report.Problem ?? "ok"));
        static string Paths(IReadOnlyList<string> paths) => paths.Count == 0 ? "-" : NodeLog.OneLine(string.Join(", ", paths.Take(50))) + (paths.Count > 50 ? $" (+{paths.Count - 50} more)" : string.Empty);
        try
        {
            await node.Processor.ExecuteAsync(context =>
            {
                ExecutionFindings.Raise(context, FindingKind.EnforcementDegraded, Severity.Error, "node", node.NodeId.Span,
                    "The installed version's files do not match their digests",
                    $"{report.Mismatches} entries in the version directory {directory} are missing, changed, links, hard links, invalid or not listed in its digests.json (AD-0007 section 8). "
                    + "The files may have been modified after installation; reinstall or repair this version.",
                    [("directory", directory), ("missing", Paths(report.Missing)), ("changed", Paths(report.Changed)), ("unlisted", Paths(report.Unlisted)),
                     ("links", Paths(report.Links)), ("hard_links", Paths(report.HardLinks)), ("invalid", Paths(report.Invalid)),
                     ("manifest", report.Problem ?? "ok")]);
                return 0;
            }).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or ObjectDisposedException)
        {
            node.Log.Warning("node.version_integrity.finding_failed", new LogField("errorType", exception.GetType().Name));
        }
    }

    private static IExecutionPlatform? StartPlatform(NodeHostOptions options, NodeStore store, NodeLog log)
    {
        if (OperatingSystem.IsLinux())
        {
            return StartLinuxPlatform(options, store, log);
        }

        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        var helper = options.HelperExecutable ?? Path.Combine(AppContext.BaseDirectory, "arcforges.exe");
        var platform = new ArcForges.Node.Platform.Windows.WindowsExecutionPlatform();
        try
        {
            var settings = new ExecutionSettings(store.Policies.Current().Document, platform.Capacity.LogicalProcessors, platform.Capacity.PhysicalMemoryBytes);
            var limits = settings.RootLimits();
            platform.Start(IdText.Format(store.Metadata.NodeId.Span), limits, helper);
            log.Info("node.platform.started", new LogField("platform", platform.Name), new LogField("rootJob", platform.RootJobName),
                new LogField("rootCpuRate", limits.CpuRate), new LogField("rootCommitLimit", limits.CommitLimitBytes), new LogField("helper", helper));
            return platform;
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            log.Error("node.platform.failed", exception);
            platform.Dispose();
            return null;
        }
    }

    /// <summary>
    /// The Linux platform (AD-0005 Linux): transient units of the user manager in the slice, or plain child processes without a user
    /// manager (observe only). Test mode takes the slice, the manager's address and simulated delegation from <see cref="LinuxTestHooks"/>.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("linux")]
    private static ArcForges.Node.Platform.Linux.LinuxExecutionPlatform StartLinuxPlatform(NodeHostOptions options, NodeStore store, NodeLog log)
    {
        var helper = options.HelperExecutable ?? Path.Combine(AppContext.BaseDirectory, "arcforges");
        var controllers = LinuxTestHooks.Value(options.TestMode, LinuxTestHooks.Controllers);
        var platform = new ArcForges.Node.Platform.Linux.LinuxExecutionPlatform(new ArcForges.Node.Platform.Linux.LinuxPlatformOptions
        {
            Slice = options.LinuxSlice ?? LinuxTestHooks.Value(options.TestMode, LinuxTestHooks.Slice) ?? ArcForges.Node.Platform.Linux.LinuxExecutionPlatform.DefaultSlice,
            ManagerAddress = options.SystemdAddress ?? LinuxTestHooks.Value(options.TestMode, LinuxTestHooks.ManagerAddress),
            DelegatedControllers = options.LinuxControllers ?? controllers?.Split(' ', StringSplitOptions.RemoveEmptyEntries),

            // AD-0007 section 8: attempt units must not reach the node store or the data root's secret stores (where the hardening applies).
            ProtectedPaths = [Path.GetDirectoryName(store.DatabasePath)!, Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(store.DatabasePath)!)!, "run", "secrets"),
                Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(store.DatabasePath)!)!, "run", "test-secrets")],
        });
        var settings = new ExecutionSettings(store.Policies.Current().Document, platform.Capacity.LogicalProcessors, platform.Capacity.PhysicalMemoryBytes);
        var limits = settings.RootLimits();
        platform.Start(IdText.Format(store.Metadata.NodeId.Span), limits, helper);
        log.Info("node.platform.started", new LogField("platform", platform.Name), new LogField("slice", platform.Slice),
            new LogField("unitMode", platform.UnitMode), new LogField("managerUnavailable", platform.ManagerUnavailableReason ?? "-"),
            new LogField("controllers", string.Join(' ', platform.Controllers.Order(StringComparer.Ordinal))), new LogField("rootCpuRate", limits.CpuRate),
            new LogField("rootMemoryMax", limits.HardMemoryBytes), new LogField("rootSwapMax", limits.SwapAllowanceBytes), new LogField("helper", helper));
        foreach (var cgroup in platform.ReleasedFreezes)
        {
            log.Warning("node.platform.freeze_released", new LogField("cgroup", cgroup));
        }

        return platform;
    }

    private static Registrations RegisterSignals(NodeRuntime node)
    {
        var registrations = new List<PosixSignalRegistration>();
        foreach (var signal in (PosixSignal[])[PosixSignal.SIGTERM, PosixSignal.SIGINT, PosixSignal.SIGHUP, PosixSignal.SIGQUIT])
        {
            try
            {
                registrations.Add(PosixSignalRegistration.Create(signal, context =>
                {
                    context.Cancel = true;
                    node.RequestStop(signal.ToString());
                }));
            }
            catch (PlatformNotSupportedException)
            {
            }
        }

        return new Registrations(registrations);
    }

    private sealed class Registrations(List<PosixSignalRegistration> registrations) : IDisposable
    {
        public void Dispose()
        {
            foreach (var registration in registrations)
            {
                registration.Dispose();
            }
        }
    }
}
