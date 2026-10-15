// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;

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
    /// Selects the OS secret store of the node data key for a data root (default <c>OsSecretStore.SelectForCurrentPlatform</c>;
    /// component tests on Linux select the owner-only file fallback so the user's keyring is never touched).
    /// </summary>
    public Func<string, SecretStoreSelection> SecretStore { get; init; } = dataRoot => OsSecretStore.SelectForCurrentPlatform(dataRoot);
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
            new LogField("testMode", options.TestMode), new LogField("systemd", options.Systemd));
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
            return await ServeAsync(options, store, log, notifier, ready, configPath, dataRoot, endpoint, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Records the clean-shutdown marker and closes the writer.
            store.Dispose();
        }
    }

    private static async Task<int> ServeAsync(NodeHostOptions options, NodeStore store, NodeLog log, SystemdNotifier notifier, WindowsReadyEvent? ready,
        string configPath, string dataRoot, LocalRpcEndpoint endpoint, CancellationToken cancellationToken)
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
        using var node = new NodeRuntime(store, journal, hub, processor, log, settings, dataRoot, endpoint.Address, clock, recovery, NodeCapabilities.Evaluate(clock));
        using var stopSignals = RegisterSignals(node);
        using var external = cancellationToken.Register(() => node.RequestStop("cancelled"));
        LocalRpcServer? server = null;
        NodeDataKeyRing? keys = null;
        Task keyLoad = Task.CompletedTask;
        using var housekeeping = new PeriodicTimer(HousekeepingInterval);
        Task housekeepingLoop = Task.CompletedTask;
        Task watchdogLoop = Task.CompletedTask;
        using var loops = new CancellationTokenSource();
        try
        {
            await processor.ExecuteAsync(context =>
            {
                context.Emit(EventTopic.Node, new NodeEvent { Node = node.Status("starting") });
                return 0;
            }).ConfigureAwait(false);
            await node.TransitionAsync(NodeLifecycleState.Recovering, unclean ? "unclean_shutdown" : "store_opened").ConfigureAwait(false);
            log.Info("node.recovering", new LogField("uncleanShutdown", unclean), new LogField("bootChanged", bootChanged),
                new LogField("storeCreated", store.Opening.Created), new LogField("migratedFrom", store.Opening.MigratedFrom ?? 0),
                new LogField("generation", journal.Generation));
            foreach (var participant in options.Recovery)
            {
                await participant.RecoverAsync(recovery, processor, node.Stopping).ConfigureAwait(false);
                log.Info("node.recovery.done", new LogField("participant", participant.Name));
            }

            var sessions = new ClientSessions();
            server = NodeApiServer.Build(endpoint, node, sessions, options.StreamBuffer);
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

            housekeepingLoop = HousekeepAsync(node, housekeeping, loops.Token);
            if (notifier.WatchdogInterval is { } watchdog)
            {
                watchdogLoop = WatchdogAsync(notifier, watchdog, loops.Token);
            }

            var enforced = NodeCapabilities.FullyEnforced(node.Capabilities);
            await node.TransitionAsync(enforced ? NodeLifecycleState.Ready : NodeLifecycleState.Degraded,
                enforced ? "ready" : NodeCapabilities.DegradedReason).ConfigureAwait(false);
            notifier.Notify("READY=1\nSTATUS=ArcForges node " + node.Lifecycle.State.ToString().ToLowerInvariant());
            ready?.Set();
            options.Ready?.Invoke(node);
            log.Info("node.ready", new LogField("state", node.Lifecycle.State), new LogField("endpoint", endpoint.Address),
                new LogField("transport", endpoint.Transport));

            keys = new NodeDataKeyRing(store, options.SecretStore(dataRoot));
            var ring = keys;
            keyLoad = Task.Run(() =>
            {
                var keyId = ring.Prepare(out var reason);
                if (keyId is null)
                {
                    log.Warning("node.data_key.unavailable", new LogField("backend", ring.Backend), new LogField("reason", NodeLog.OneLine(reason)));
                }
                else
                {
                    log.Info("node.data_key.loaded", new LogField("keyId", keyId), new LogField("backend", ring.Backend),
                        new LogField("protection", ring.Protection));
                }
            }, CancellationToken.None);

            try
            {
                await Task.Delay(Timeout.Infinite, node.Stopping).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            return await ShutdownAsync(node, server, ready, notifier, processor, dataRoot, loops, [housekeepingLoop, watchdogLoop, keyLoad]).ConfigureAwait(false);
        }
        finally
        {
            if (server is not null)
            {
                await server.DisposeAsync().ConfigureAwait(false);
            }

            keys?.Dispose();
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
        await processor.DisposeAsync().ConfigureAwait(false);
        node.Store.Checkpoint();
        var descriptorPath = NodeLocations.EndpointDescriptorFile(dataRoot);
        if (EndpointDescriptor.TryRead(descriptorPath) is { } descriptor && descriptor.ProcessId == Environment.ProcessId)
        {
            File.Delete(descriptorPath);
        }

        node.Log.Info("node.stopped", new LogField("shutdownMs", (long)node.Clock.GetElapsedTime(started).TotalMilliseconds));
        return NodeExitCodes.Success;
    }

    private static async Task HousekeepAsync(NodeRuntime node, PeriodicTimer timer, CancellationToken cancellationToken)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    var removed = await node.Processor.ExecuteAsync(context =>
                        EventJournal.Prune(context.Transaction) + Notifications.Prune(context.Transaction) + Jobs.Prune(context.Transaction)).ConfigureAwait(false);
                    var commands = node.Store.Commands.PurgeExpired();
                    node.Log.Debug("node.housekeeping", new LogField("rowsRemoved", removed + commands));
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

    private static async Task WatchdogAsync(SystemdNotifier notifier, TimeSpan interval, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval / 3);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                notifier.Notify("WATCHDOG=1");
            }
        }
        catch (OperationCanceledException)
        {
        }
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
