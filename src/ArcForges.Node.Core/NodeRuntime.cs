// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Events;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core;

/// <summary>The running node's subsystems and identity, shared by the API layer (architecture 02 section 1).</summary>
public sealed class NodeRuntime : IDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private CapabilityReport _capabilities;
    private long _rpcCalls;

    /// <summary>Assembles the runtime once the store is open and the journal began its generation.</summary>
    public NodeRuntime(NodeStore store, EventJournal journal, StreamHub hub, CommandProcessor processor, NodeLog log,
        NodeSettingsManager settings, string dataRoot, string endpoint, TimeProvider clock, RecoveryReport recovery, CapabilityReport capabilities)
    {
        Store = store;
        Journal = journal;
        Hub = hub;
        Processor = processor;
        Log = log;
        Settings = settings;
        DataRoot = dataRoot;
        Endpoint = endpoint;
        Clock = clock;
        Recovery = recovery;
        _capabilities = capabilities;
        StartedAt = clock.GetUtcNow();
    }

    /// <summary>The store.</summary>
    public NodeStore Store { get; }

    /// <summary>The event journal.</summary>
    public EventJournal Journal { get; }

    /// <summary>The stream hub.</summary>
    public StreamHub Hub { get; }

    /// <summary>The command processor (the single writer).</summary>
    public CommandProcessor Processor { get; }

    /// <summary>The lifecycle (SM-NODE).</summary>
    public NodeLifecycle Lifecycle { get; } = new();

    /// <summary>The structured log.</summary>
    public NodeLog Log { get; }

    /// <summary>The node.json settings.</summary>
    public NodeSettingsManager Settings { get; }

    /// <summary>The data root.</summary>
    public string DataRoot { get; }

    /// <summary>The endpoint address (pipe name or socket path).</summary>
    public string Endpoint { get; }

    /// <summary>The node clock.</summary>
    public TimeProvider Clock { get; }

    /// <summary>What startup found about the previous run.</summary>
    public RecoveryReport Recovery { get; }

    /// <summary>When the node began serving.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>Cancelled when a stop was requested (StopNode, a signal, or a fatal error).</summary>
    public CancellationToken Stopping => _stop.Token;

    /// <summary>Why the stop was requested.</summary>
    public string? StopReason { get; private set; }

    /// <summary>The current capability report.</summary>
    public CapabilityReport Capabilities => Volatile.Read(ref _capabilities);

    /// <summary>API calls handled since start.</summary>
    public long RpcCalls => Interlocked.Read(ref _rpcCalls);

    /// <summary>The node ID (16 bytes).</summary>
    public ReadOnlyMemory<byte> NodeId => Store.Metadata.NodeId;

    /// <summary>The execution supervisor (set by the host before the API listens).</summary>
    public Execution.ExecutionSupervisor? Execution { get; set; }

    /// <summary>A snapshot of the API server's counters (set by the API layer).</summary>
    public Func<IReadOnlyList<HealthMetric>>? ServerMetrics { get; set; }

    /// <summary>Counts one API call.</summary>
    public void CountCall() => Interlocked.Increment(ref _rpcCalls);

    /// <summary>Requests a stop; the first reason wins.</summary>
    public void RequestStop(string reason)
    {
        if (StopReason is null)
        {
            StopReason = reason;
        }

        _stop.Cancel();
    }

    /// <summary>Releases the stop token.</summary>
    public void Dispose() => _stop.Dispose();

    /// <summary>Re-runs the capability evaluation (<c>GetCapabilities</c> with <c>reevaluate</c>).</summary>
    public CapabilityReport Reevaluate()
    {
        var report = Execution?.Platform is { } platform ? NodeCapabilities.FromPlatform(platform, Clock) : NodeCapabilities.Evaluate(Clock);
        if (OperatingSystem.IsLinux())
        {
            NodeCapabilities.AddDataRootFact(report, DataRoot);
        }

        Volatile.Write(ref _capabilities, report);
        return report;
    }

    /// <summary>Moves the lifecycle and journals the change on topic NODE (through the command processor).</summary>
    public Task TransitionAsync(NodeLifecycleState to, string reason) => Processor.ExecuteAsync(context =>
    {
        Lifecycle.MoveTo(to, reason);
        context.Emit(EventTopic.Node, new NodeEvent { Node = Status(reason) });
        return 0;
    });

    /// <summary>The node's current status as journaled on topic NODE.</summary>
    public NodeStatusChanged Status(string? reason = null) => new()
    {
        State = Lifecycle.State,
        Reason = reason ?? Lifecycle.Reason,
        Capabilities = Capabilities,
    };

    /// <summary>The node's information (<c>GetNodeInfo</c>, the hello answer and <c>RenameNode</c>).</summary>
    public NodeInfo Info(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var info = new NodeInfo
        {
            Node = new NodeRef
            {
                NodeId = new Id { Value = ByteString.CopyFrom(NodeId.Span) },
                Name = NodeName.Get(reader),
                Role = Store.Metadata.Role,
                Os = OperatingSystem.IsWindows() ? OsFamily.Windows : OsFamily.Linux,
                Arch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64
                    ? CpuArchitecture.Arm64
                    : CpuArchitecture.X64,
            },
            Version = NodeContract.ProductVersion,
            ContractMajor = NodeContract.Major,
            ContractMinor = NodeContract.Minor,
            DataRoot = DataRoot,
            Endpoint = Endpoint,
            StartedAt = ProtoTime.ToInstant(StartedAt),
            StoreBytes = StoreBytes(),
            Capabilities = Capabilities,
            AccountLinked = false,
            LanEnabled = false,
            Edition = Edition.Free,
            State = Lifecycle.State,
        };
        return info;
    }

    /// <summary>The store's size on disk (database and write-ahead log).</summary>
    public ulong StoreBytes()
    {
        ulong total = 0;
        foreach (var suffix in (string[])["", "-wal", "-shm"])
        {
            var file = new FileInfo(Store.DatabasePath + suffix);
            if (file.Exists)
            {
                total += (ulong)file.Length;
            }
        }

        return total;
    }
}
