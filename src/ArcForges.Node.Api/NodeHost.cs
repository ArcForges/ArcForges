// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.LocalRpc;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Sandboxes;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.Node.Store;
using V2 = ArcForges.Contracts.Sandbox.V2;

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
    /// Test seam, set only by in-process component tests: awaited after the API listens in RECOVERING, before readiness.
    /// A test can hold this startup boundary while using the real RPC endpoint; it must release the hold when the node stops.
    /// </summary>
    internal Func<NodeRuntime, Task>? BeforeReady { get; init; }

    /// <summary>
    /// The secret store of the node data key for a data root. Null (the executable): <see cref="NodeSecretStores.ForNode(string, bool)"/>,
    /// the OS secret store in production and, with <see cref="TestMode"/>, the file-backed isolated store of the test data root unless
    /// the OS secret-store tier's opt-in is set (02-node-service section 4). Every in-process test node sets it to an isolated backend
    /// (16-testing-strategy section 2; ArcForges.Repository.Tests checks this).
    /// </summary>
    internal Func<string, NodeSecretStore>? SecretStore { get; init; }

    // A native test may point at its protected official fixture installation.
    internal string? SandboxMxcInstallationRoot { get; init; }

    /// <summary>
    /// The node key store for a data root (AF-CTR-04). Null (the executable): <see cref="NodeKeyStores.ForNode(string, bool)"/>, a CNG user
    /// key on Windows in production, else an owner-only file; with <see cref="TestMode"/> the file-backed key of the test data root. Every
    /// in-process test node sets it to the file-backed store (ArcForges.Repository.Tests checks this).
    /// </summary>
    internal Func<string, NodeKeyStore>? NodeKeys { get; init; }

    /// <summary>The sign-in flows' browser opener (tests give the allowed ScriptedBrowser); by default the system browser, none under test mode.</summary>
    internal IBrowserOpener? Opener { get; init; }

    /// <summary>
    /// The version directory the node runs from, whose <c>digests.json</c> the node verifies after startup (AD-0007 section 8): by default
    /// the application directory; component tests name a temporary one.
    /// </summary>
    public string? VersionDirectory { get; init; }

    /// <summary>
    /// Test seam (component tests): awaited after the version check found a mismatch and before its finding is committed, inside the
    /// commit's failure handling, so a test can hold the commit (as a commit queued behind other writes waits) or fail it.
    /// </summary>
    internal Func<Task>? VersionFindingCommitting { get; init; }
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

    /// <summary>How long past <see cref="ShutdownBudget"/> the shutdown may run before the process exits anyway (node.shutdown.overrun).</summary>
    public static readonly TimeSpan OverrunGrace = TimeSpan.FromSeconds(2);

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
        LinuxSandboxDeletionAuthority? linuxDeletionAuthority;
        SingleInstance? protectedInstance = null;
        string instanceKey;
        LocalRpcEndpoint endpoint;
        try
        {
            configPath = options.ConfigPath ?? NodeLocations.ConfigFile(options.TestMode);
            configuration = NodeConfiguration.Read(configPath);
            dataRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuration.DataRoot ?? NodeLocations.DefaultDataRoot()));
            linuxDeletionAuthority = OperatingSystem.IsLinux() ? LinuxSandboxDeletionAuthority.OpenIfProvisioned(dataRoot) : null;
            instanceKey = options.Endpoint is { } explicitEndpoint
                ? NodeLocations.InstanceKeyFor(explicitEndpoint.Address) : NodeLocations.InstanceKey(options.TestMode);
            endpoint = options.Endpoint ?? NodeLocations.Endpoint(options.TestMode, dataRoot);
            if (OperatingSystem.IsLinux() && linuxDeletionAuthority is not null)
            {
                protectedInstance = SingleInstance.TryAcquire(linuxDeletionAuthority);
                if (protectedInstance is not null)
                {
                    linuxDeletionAuthority.InitializeOrVerifyStore();
                }
            }

            if (linuxDeletionAuthority is null || protectedInstance is not null)
            {
                StorePaths.CreatePrivateDirectory(dataRoot);
                StorePaths.CreatePrivateDirectory(NodeLocations.RunDirectory(dataRoot));
                StorePaths.CreatePrivateDirectory(Path.Combine(dataRoot, "logs", "node"));
            }
        }
        catch (Exception exception) when (exception is NodeConfigurationException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            protectedInstance?.Dispose();
            await options.Error.WriteLineAsync($"arcforges: the node cannot start: {exception.Message}".AsMemory(), cancellationToken).ConfigureAwait(false);
            return NodeExitCodes.Failure;
        }

        using var instance = linuxDeletionAuthority is null ? SingleInstance.TryAcquire(instanceKey, dataRoot) : protectedInstance;
        if (instance is null)
        {
            var running = EndpointDescriptor.TryRead(NodeLocations.EndpointDescriptorFile(dataRoot));
            var address = running is not null && running.ProcessIsAlive() ? running.Endpoint : endpoint.Address;
            await options.Output.WriteLineAsync(address.AsMemory(), cancellationToken).ConfigureAwait(false);
            await options.Error.WriteLineAsync($"arcforges: the node is already running (endpoint {address})".AsMemory(), cancellationToken).ConfigureAwait(false);
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
            DurableCommandStore.VerifyRestorePublication(dataRoot);
            store = NodeStore.OpenForV2Runtime(new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = BootIdentity.Read(), Clock = clock });
        }
        catch (DurableStoreMaintenanceException)
        {
            return await RefuseUnreconciledAuthorityAsync(options, log, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is StoreIncompatibleException or Microsoft.Data.Sqlite.SqliteException or IOException
            or UnauthorizedAccessException)
        {
            log.Error("node.store.failed", exception);
            await options.Error.WriteLineAsync($"arcforges: the node store cannot be opened: {exception.Message}".AsMemory(), cancellationToken).ConfigureAwait(false);
            return NodeExitCodes.Failure;
        }

        try
        {
            return await ServeAsync(options, store, log, notifier, ready, configPath, dataRoot, endpoint, faults, linuxDeletionAuthority,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Records the clean-shutdown marker and closes the writer.
            store.Dispose();
        }
    }

    private static async Task<int> RefuseUnreconciledAuthorityAsync(NodeHostOptions options, NodeLog log, CancellationToken cancellationToken)
    {
        log.Warning("node.store.maintenance", new LogField("reason", "owner_authority_reconciliation_required"));
        await options.Error.WriteLineAsync(
            "arcforges: owner_authority_reconciliation_required. Reconcile the original owner history before starting the node.".AsMemory(),
            cancellationToken).ConfigureAwait(false);
        return NodeExitCodes.Failure;
    }

    private static async Task<int> ServeAsync(NodeHostOptions options, NodeStore store, NodeLog log, SystemdNotifier notifier, WindowsReadyEvent? ready,
        string configPath, string dataRoot, LocalRpcEndpoint endpoint, ExecutionFaults faults, LinuxSandboxDeletionAuthority? linuxDeletionAuthority,
        CancellationToken cancellationToken)
    {
        var protectedStorage = linuxDeletionAuthority is not null;
        using var protectedEndpoint = OperatingSystem.IsLinux() && endpoint.Transport == LocalRpcTransport.UnixDomainSocket
            ? new SandboxProtectedEndpoint(endpoint.Address) : null;
        var clock = options.Clock;
        var metadata = store.Metadata;
        var unclean = !metadata.PreviousShutdownClean;
        var bootChanged = !string.Equals(metadata.PreviousBootIdentity, metadata.BootIdentity, StringComparison.Ordinal);
        var integrity = unclean ? StoreRecovery.QuickCheck(store) : null;
        var recovery = new RecoveryReport(unclean, bootChanged, integrity, store.Opening);
        if (integrity is not null && integrity != "ok")
        {
            log.Error("node.store.corrupt", new LogField("quickCheck", NodeLog.OneLine(integrity)));
            await options.Error.WriteLineAsync($"arcforges: the node store failed its integrity check: {NodeLog.OneLine(integrity)}".AsMemory(), cancellationToken).ConfigureAwait(false);
            return NodeExitCodes.Failure;
        }

        var journal = EventJournal.Open(store);
        var hub = new StreamHub();
        var processor = new CommandProcessor(store, journal, hub);
        var testCenter = CloudLinkTestHooks.Center(options.TestMode, Environment.GetEnvironmentVariable(CloudLinkTestHooks.CenterUrl));
        var settings = new NodeSettingsManager(configPath, dataRoot, log) { TestMode = options.TestMode, CenterOverride = testCenter };

        // The node data key loads at startup, outside the writer (secret-store I/O must never run under the writer lock).
        var secretStore = options.SecretStore?.Invoke(dataRoot) ?? NodeSecretStores.ForNode(dataRoot, options.TestMode);
        var sandboxes = CreateSandboxManager(store, dataRoot, secretStore, clock, log, journal.Generation,
            options.TestMode ? options.SandboxMxcInstallationRoot : null, protectedEndpoint, faults, linuxDeletionAuthority);
        try
        {
            if (sandboxes is not null)
            {
                sandboxes.VerifyExistingAuthority();
            }
            else if (store.Read(reader => Equals(reader.Scalar("SELECT EXISTS(SELECT 1 FROM owner_epoch);"), 1L)))
            {
                throw new DurableStoreMaintenanceException();
            }
        }
        catch (Exception error) when (error is DurableStoreMaintenanceException or IOException or UnauthorizedAccessException
            or Microsoft.Data.Sqlite.SqliteException or FormatException or System.Security.Cryptography.CryptographicException
            or SandboxPrivateRootException)
        {
            sandboxes?.Dispose();
            await processor.DisposeAsync().ConfigureAwait(false);
            return await RefuseUnreconciledAuthorityAsync(options, log, cancellationToken).ConfigureAwait(false);
        }

        var capabilities = NodeCapabilities.Evaluate(clock);
        if (OperatingSystem.IsLinux())
        {
            // Report when a Node-owned path is backed by memory.
            var inMemory = NodeCapabilities.AddDataRootFact(capabilities, dataRoot);
            foreach (var (path, kind) in inMemory)
            {
                log.Warning("node.data_root_in_memory", new LogField("path", path), new LogField("filesystem", kind));
            }
        }

        using var heartbeat = new NodeHeartbeatWriter(dataRoot, log, clock);
        if (notifier.WatchdogInterval is { } watchdogInterval)
        {
            // Systemd receives watchdog notifications from the Node heartbeat.
            heartbeat.Renewed = () => notifier.Notify("WATCHDOG=1");
            log.Info("node.watchdog", new LogField("intervalMs", (long)watchdogInterval.TotalMilliseconds));
        }
        var sampler = CreateSampler();
        using var node = new NodeRuntime(store, journal, hub, processor, log, settings, dataRoot, endpoint.Address, clock, recovery, capabilities)
        {
            Sandboxes = sandboxes,
        };

        var routed = protectedStorage ? null : new RoutedDispatcher(node);
        var versionDirectory = options.VersionDirectory ?? AppContext.BaseDirectory;
        node.SetFact(VersionIntegrity.FactName, VersionIntegrity.InitialFact(versionDirectory));

        // 02 section 2 step 8, the cloud link (AF-CTR-04): the node credential in the same secret store as the data key, the node key from
        // its composition root; state changes are journaled on topic ACCOUNT.
        var cloud = routed is null ? null : new CloudLinkService(new CloudLinkOptions
        {
            DataRoot = dataRoot,
            NodeId = node.NodeId,
            Secrets = secretStore,
            Keys = options.NodeKeys?.Invoke(dataRoot) ?? NodeKeyStores.ForNode(dataRoot, options.TestMode),
            Center = settings.Center,
            ConfigureCenter = center => processor.ExecuteAsync(_ => settings.Update(null, LogLevel.Unspecified, null, center.Url).Error),
            ChannelEnabled = true,
            V2Snapshot = () => DescribeV2Channel(sandboxes),
            V2EnrollmentChanged = enrollment => ObserveV2Enrollment(sandboxes, enrollment),
            V2ControlDispatch = routed.DispatchV2Async,
            V2StreamDataDispatch = routed.DispatchV2StreamDataAsync,
            Log = log,
            Clock = clock,
            NodeInfo = () => store.Read(reader => DescribeNode(node, reader)),
            Publish = publication => processor.ExecuteAsync(context =>
            {
                context.Emit(EventTopic.Account, new NodeEvent { Account = publication.Status });
                if (publication.Notice is { } notice)
                {
                    Notifications.Add(context, notice.Kind, Severity.Warning, notice.Title, notice.Body);
                }

                return 0;
            }),
            ConnectLog = CloudLinkTestHooks.Connections(options.TestMode, Environment.GetEnvironmentVariable(CloudLinkTestHooks.ConnectLog)),
            RefreshInterval = CloudLinkTestHooks.Refresh(options.TestMode, Environment.GetEnvironmentVariable(CloudLinkTestHooks.RefreshSeconds)),
            Opener = options.Opener
                ?? new BrowserOpener(options.TestMode, CloudLinkTestHooks.Browser(options.TestMode, Environment.GetEnvironmentVariable(CloudLinkTestHooks.BrowserFile))),

            Version = NodeContract.ProductVersion,
        });
        await using var cloudScope = cloud;
        using var centerControl = cloud is null ? null : new CenterControlServiceHandler(node, cloud);
        if (cloud is not null)
        {
            node.CloudLink = cloud;
            if (testCenter is not null)
            {
                log.Info("node.test_center", new LogField("center", testCenter.Url));
            }
        }

        using var stopSignals = RegisterSignals(node);
        using var external = cancellationToken.Register(() => node.RequestStop("cancelled"));
        LocalRpcServer? server = null;
        IAsyncDisposable? sandboxResources = null;
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
            foreach (var participant in options.Recovery)
            {
                await participant.RecoverAsync(recovery, processor, node.Stopping).ConfigureAwait(false);
                log.Info("node.recovery.done", new LogField("participant", participant.Name));
            }

            if (node.Sandboxes is { } recoveredSandboxes)
            {
                await recoveredSandboxes.RecoverRunsAsync(recovery, node.Stopping).ConfigureAwait(false);
                log.Info("node.recovery.done", new LogField("participant", "sandbox_runs"));
                centerControl?.RecoverAccepted(store, recoveredSandboxes);
                recoveredSandboxes.ReconcileDeletionReceipts();
                recoveredSandboxes.StartDataRecovery();
                sandboxResources = recoveredSandboxes.StartResourceSampling(sampler as IHostResourceSource, log);
            }

            var sessions = new ClientSessions();
            server = NodeApiServer.Build(endpoint, node, sessions, options.StreamBuffer, ClientImages.ForNode(ClientImages.TestHookApplies(options.TestMode, endpoint.Address, configPath, dataRoot)),
                cloud, centerControl, protectedStorage);
            try
            {
                await server.StartAsync(node.Stopping).ConfigureAwait(false);
                if (protectedEndpoint?.TryBind() == false)
                {
                    log.Warning("sandbox.node_endpoint.unavailable", new LogField("reason", "node_endpoint_identity_unavailable"));
                }
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException or UnauthorizedAccessException)
            {
                log.Error("node.endpoint.failed", exception);
                await options.Error.WriteLineAsync($"arcforges: the node endpoint {endpoint.Address} cannot be opened: {exception.Message}".AsMemory(), cancellationToken).ConfigureAwait(false);
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

            if (options.BeforeReady is { } beforeReady)
            {
                await beforeReady(node).ConfigureAwait(false);
            }

            housekeepingLoop = HousekeepAsync(node, housekeeping, loops.Token);
            if (cloud is not null)
            {
                await cloud.StartAsync().ConfigureAwait(false);
                centerControl!.MarkLinkLoaded();
            }
            var available = node.Sandboxes is not null;
            await node.TransitionAsync(available ? NodeLifecycleState.Ready : NodeLifecycleState.Degraded,
                available ? "ready" : "sandbox_store_unavailable").ConfigureAwait(false);
            heartbeat.Start();
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
                new LogField("transport", endpoint.Transport),
                new LogField("heartbeatInstance", heartbeat.Instance));

            // AD-0007 section 8: the version directory is made read-only and verified against its digests off the startup path.
            versionCheck = CheckVersionAsync(node, versionDirectory, options.VersionFindingCommitting, loops.Token);

            try
            {
                await Task.Delay(Timeout.Infinite, node.Stopping).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            return await ShutdownAsync(node, server, ready, notifier, processor, dataRoot, loops, [housekeepingLoop, versionCheck], cloud).ConfigureAwait(false);
        }
        finally
        {
            if (server is not null)
            {
                await server.DisposeAsync().ConfigureAwait(false);
            }

            if (sandboxResources is not null)
            {
                await sandboxResources.DisposeAsync().ConfigureAwait(false);
            }

            await processor.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static async Task<int> ShutdownAsync(NodeRuntime node, LocalRpcServer server, WindowsReadyEvent? ready, SystemdNotifier notifier,
        CommandProcessor processor, string dataRoot, CancellationTokenSource loops, Task[] background, CloudLinkService? cloud)
    {
        var started = node.Clock.GetTimestamp();

        // Review B N-9 of PR #72: the cloud link's stop is bounded from the shutdown's start, not from its turn below. No refresh or report
        // starts from now on; a center call in flight runs to its answer or its own 10 s deadline and its rotation is stored; at the budget
        // a call still running is cancelled (it fails closed). The link's DisposeAsync below then flushes (CTR4-NODE-05) within one more
        // second, so it has ended by budget + 1 s (CloudLinkService.FlushReserve), before the force exit at budget + 2 s (OverrunGrace).
        if (cloud is not null)
        {
            cloud.BeginStop(ShutdownBudget);
        }

        using var overrun = new Timer(_ =>
        {
            node.Log.Error("node.shutdown.overrun", new LogField("budgetMs", (long)ShutdownBudget.TotalMilliseconds));
            Environment.Exit(NodeExitCodes.Success);
        }, null, ShutdownBudget + OverrunGrace, Timeout.InfiniteTimeSpan);
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
        using var backgroundWait = new CancellationTokenSource();
        await Task.WhenAny(Task.WhenAll(background), Task.Delay(TimeSpan.FromSeconds(2), backgroundWait.Token)).ConfigureAwait(false);
        await backgroundWait.CancelAsync().ConfigureAwait(false);

        // The cloud link stops within the bound begun above and flushes a rotated credential whose write failed (AF-CTR-04 CTR4-NODE-05).
        if (cloud is not null)
        {
            await cloud.DisposeAsync().ConfigureAwait(false);
        }

        node.Sandboxes?.StopDeletionWorkers();
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

    private static async Task HousekeepAsync(NodeRuntime node, PeriodicTimer timer, CancellationToken cancellationToken)
    {
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    var removed = await node.Processor.ExecuteAsync(context =>
                        EventJournal.Prune(context.Transaction) + Notifications.Prune(context.Transaction) + Jobs.Prune(context.Transaction)
                        + Approvals.Expire(context, NodeServiceHandler.UpdateSettingsMethod)
                        + Approvals.Prune(context.Transaction, NodeServiceHandler.UpdateSettingsMethod)
                        + AuditLog.Prune(context.Transaction), CommitDurability.Full).ConfigureAwait(false);
                    node.Log.Debug("node.housekeeping", new LogField("rowsRemoved", removed));
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

    /// <summary>The node as it describes itself to its center (fleet.proto <c>EnrollingNodeInfo</c>; AF-CTR-04 CTR4-NODE-09).</summary>
    private static EnrollingNodeInfo DescribeNode(NodeRuntime node, StoreReader reader)
    {
        var info = node.Info(reader).Node;
        return new EnrollingNodeInfo
        {
            NodeId = info.NodeId,
            Name = info.Name,
            Os = info.Os,
            Arch = info.Arch,
            Version = NodeContract.ProductVersion,
            Role = info.Role == NodeRole.Host ? NodeRole.Host : NodeRole.Unspecified,
        };
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
    private static async Task CheckVersionAsync(NodeRuntime node, string directory, Func<Task>? findingCommitting, CancellationToken cancellationToken)
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
        await RecordVersionCheckAsync(node, directory, checkedReport.Task, findingCommitting).ConfigureAwait(false);
    }

    /// <summary>
    /// Publishes the check's result. A mismatch's ENFORCEMENT_DEGRADED finding is committed before the fact reports the mismatch, so a
    /// client that reads <c>mismatch: n files</c> also reads the finding with its paths; the fact is published even when the commit fails.
    /// </summary>
    private static async Task RecordVersionCheckAsync(NodeRuntime node, string directory, Task<VersionIntegrityReport?> check, Func<Task>? findingCommitting)
    {
        if (await check.ConfigureAwait(false) is not { } report)
        {
            return;
        }

        if (report.Mismatches == 0)
        {
            node.SetFact(VersionIntegrity.FactName, report.Fact);
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
            if (findingCommitting is not null)
            {
                await findingCommitting().ConfigureAwait(false);
            }

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
        finally
        {
            // After the finding's commit, never before it; and always, so a failed commit never loses the fact.
            node.SetFact(VersionIntegrity.FactName, report.Fact);
        }
    }

    private static V2ChannelSnapshot? DescribeV2Channel(SandboxManager? manager)
    {
        byte platform = OperatingSystem.IsWindows() ? (byte)1 : OperatingSystem.IsLinux() ? (byte)2 : (byte)0;
        var handshake = manager?.Handshake(new V2.NodeServiceHandshakeRequest(), CancellationToken.None).Value;
        if (platform == 0 || handshake?.OwnerEpoch?.Value.Length != 16 || string.IsNullOrEmpty(handshake.NodeEpoch))
            return null;

        var qualified = handshake.Capabilities.Any(capability => capability.Key == "mxc.profile" &&
            capability.State == V2.CapabilityState.Available && !string.IsNullOrEmpty(capability.EvidenceId));
        IReadOnlyList<string> profiles = !qualified ? [] : platform == 1
            ? ["windows-process-executor-v1", "win-wrapper-local-v1"] : ["linux-bubblewrap-sdk-v1"];
        return new(handshake.OwnerEpoch.Value.Memory, handshake.NodeEpoch, platform, profiles);
    }

    private static void ObserveV2Enrollment(SandboxManager? manager, V2ChannelEnrollment? enrollment)
    {
        if (manager is null)
            return;

        if (enrollment is not { Center.Scheme: "https" } active)
        {
            manager.UpdateRemoteEnrollment(null);
            return;
        }

        var (authority, channel) = RoutedDispatcher.V2Authority(manager, active);
        manager.UpdateRemoteEnrollment(authority, channel);
    }

    private static SandboxManager? CreateSandboxManager(NodeStore store, string dataRoot, NodeSecretStore secrets, TimeProvider clock, NodeLog log,
        ulong journalGeneration, string? installationRoot, SandboxProtectedEndpoint? protectedEndpoint, ExecutionFaults faults,
        LinuxSandboxDeletionAuthority? linuxDeletionAuthority)
    {
        try
        {
            if (SandboxLocalOwner.Current() is { } owner)
            {
                return new SandboxManager(store, dataRoot, owner, secrets, clock,
                    journalGeneration.ToString(CultureInfo.InvariantCulture), installationRoot, protectedEndpoint, linuxDeletionAuthority)
                {
                    RunLauncher = OperatingSystem.IsWindows() ? new WindowsRunLauncher()
                        : OperatingSystem.IsLinux() ? new LinuxRunLauncher() : null,
                    RunFaults = faults,
                    RunDiagnostic = (id, phase, native) => log.Info("run.owner", new LogField("run", id),
                        new LogField("phase", phase), new LogField("native", native)),
                    DeletionLog = log,
                };
            }

            log.Warning("sandbox.store.unavailable", new LogField("reason", "local_owner_unavailable"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or DurableStoreMaintenanceException or Microsoft.Data.Sqlite.SqliteException
            or System.Security.Cryptography.CryptographicException)
        {
            // Only the type is logged because a native or protected-store error may contain private material.
            log.Warning("sandbox.store.unavailable", new LogField("reason", exception.GetType().Name));
        }

        return null;
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
