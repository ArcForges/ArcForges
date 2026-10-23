// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Resources;

/// <summary>
/// The ResourceService answers (resources.proto; 03 sections 1, 2, 7 and 9): the snapshot, the classified process list and the stored
/// samples, with the validation of each request. The API layer only maps calls to these.
/// </summary>
public static class ResourceViews
{
    /// <summary>The default and bounds of <c>WatchResources.interval_ms</c>.</summary>
    public const int DefaultIntervalMs = 5_000;

    /// <summary>The default number of processes of <c>ListProcesses</c>.</summary>
    public const int DefaultTopN = 50;

    /// <summary>The default number of points of <c>GetSamples</c>.</summary>
    public const int DefaultMaxPoints = 1_000;

    /// <summary>The longest sample range (30 days, the machine samples' retention).</summary>
    public static readonly TimeSpan MaxRange = TimeSpan.FromDays(30);

    /// <summary>The range of machine and managed samples when the request gives none.</summary>
    public static readonly TimeSpan DefaultRange = TimeSpan.FromHours(1);

    /// <summary>The snapshot fields that come from the monitor's state alone (the journaled RESOURCES event of a level change).</summary>
    public static ResourceSnapshot Snapshot(ResourceState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        var snapshot = new ResourceSnapshot
        {
            At = ProtoTime.ToInstant(state.At),
            CapacityCpuMillicores = Cpu(state.CapacityCpu),
            CapacityMemBytes = Bytes(state.CapacityMemory),
            ReserveCpuMillicores = Cpu(state.ReserveCpu),
            ReserveMemBytes = Bytes(state.ReserveMemory),
            UnmanagedCpuMillicores = Cpu(state.UnmanagedCpu),
            UnmanagedMemBytes = Bytes(state.UnmanagedMemory),
            BudgetCpuMillicores = Cpu(state.BudgetCpu),
            BudgetMemBytes = Bytes(state.BudgetMemory),
            Managed = new ResourceUsage
            {
                CpuMillicores = Cpu(state.ManagedCpu),
                CpuTimeMs = Bytes(state.ManagedCpuTimeMs),
                MemBytes = Bytes(state.ManagedMemory),
                MemPeakBytes = Bytes(state.ManagedPeak),
                ProcessCount = (uint)Math.Clamp(state.ManagedProcesses, 0, uint.MaxValue),
                IoReadBytes = Bytes(state.ManagedIoRead),
                IoWriteBytes = Bytes(state.ManagedIoWrite),
            },
            NodeSelf = new ResourceUsage
            {
                CpuMillicores = Cpu(state.NodeCpu),
                CpuTimeMs = Bytes(state.NodeCpuTimeMs),
                MemBytes = Bytes(state.NodeMemory),
            },
            AvailableMemBytes = Bytes(state.AvailableMemory),
            Pressure = state.Pressure,
            PressureDetail = state.Stall is { } stall
                ? new PressureDetail
                {
                    CpuSomeAvg10 = stall.CpuSome,
                    MemorySomeAvg10 = stall.MemorySome,
                    MemoryFullAvg10 = stall.MemoryFull,
                    IoSomeAvg10 = stall.IoSome,
                    Available = true,
                }
                : new PressureDetail { Available = false },
            RunningAttempts = (uint)state.RunningAttempts,
        };
        return snapshot;
    }

    /// <summary>
    /// The full snapshot of <c>GetResourceSnapshot</c> and <c>WatchResources</c>: the monitor's state, the capability report, the volumes of
    /// the managed roots and of the running attempts' working directories with their disk pressure levels, and the queued tasks. Null
    /// before the monitor's first evaluation.
    /// </summary>
    public static ResourceSnapshot? Snapshot(NodeRuntime node)
    {
        ArgumentNullException.ThrowIfNull(node);
        if (node.Execution is not { Resources: { Current: { } state } } execution)
        {
            return null;
        }

        var snapshot = Snapshot(state);
        snapshot.Capabilities = node.Capabilities;
        snapshot.QueuedTasks = Convert.ToUInt32(node.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE state = $queued;",
            ("$queued", (int)TaskState.Queued))), CultureInfo.InvariantCulture);
        snapshot.Volumes.Add(Volumes(node.DataRoot, execution.RunningAttempts.Select(attempt => attempt.WorkingDirectory).OfType<string>(), execution.Settings));
        return snapshot;
    }

    /// <summary>
    /// The volumes holding <paramref name="dataRoot"/> (the managed roots) and <paramref name="workingDirectories"/>, with their free space
    /// and disk pressure level (06 section 5). A volume that cannot be read is left out.
    /// </summary>
    public static List<VolumeUsage> Volumes(string dataRoot, IEnumerable<string> workingDirectories, ExecutionSettings settings)
    {
        ArgumentNullException.ThrowIfNull(dataRoot);
        ArgumentNullException.ThrowIfNull(workingDirectories);
        ArgumentNullException.ThrowIfNull(settings);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        DriveInfo[] drives;
        try
        {
            drives = DriveInfo.GetDrives();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return [];
        }

        var volumes = new Dictionary<string, (DriveInfo Drive, List<string> Roots)>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var (path, managed) in workingDirectories.Select(path => (path, false)).Prepend((dataRoot, true)))
        {
            var full = Path.GetFullPath(path);
            var drive = drives.Where(candidate => Contains(candidate.RootDirectory.FullName, full, comparison))
                .MaxBy(candidate => candidate.RootDirectory.FullName.Length);
            if (drive is null)
            {
                continue;
            }

            if (!volumes.TryGetValue(drive.RootDirectory.FullName, out var entry))
            {
                entry = (drive, []);
                volumes[drive.RootDirectory.FullName] = entry;
            }

            if (managed)
            {
                entry.Roots.Add(full);
            }
        }

        var result = new List<VolumeUsage>();
        foreach (var (mount, (drive, roots)) in volumes)
        {
            try
            {
                var volume = new VolumeUsage
                {
                    Mount = mount,
                    TotalBytes = (ulong)drive.TotalSize,
                    FreeBytes = (ulong)drive.AvailableFreeSpace,
                    Level = settings.DiskLevel(drive.TotalSize, drive.AvailableFreeSpace),
                };
                volume.ManagedRoots.Add(roots);
                result.Add(volume);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
            }
        }

        return result;
    }

    /// <summary>Validates <c>WatchResources</c>; returns the interval.</summary>
    public static ArcError? Validate(ResourceServiceWatchResourcesRequest request, out TimeSpan interval)
    {
        ArgumentNullException.ThrowIfNull(request);
        interval = TimeSpan.FromMilliseconds(request.HasIntervalMs ? request.IntervalMs : DefaultIntervalMs);
        return request.HasIntervalMs && request.IntervalMs is < 1_000 or > 60_000 ? NodeErrors.InvalidArgument("interval_ms: 1,000..60,000") : null;
    }

    /// <summary>The classified processes of <c>ListProcesses</c> (03 section 9), or a validation error.</summary>
    public static (List<ProcessView>? Processes, ArcError? Error) Processes(NodeRuntime node, ProcessFilter? filter)
    {
        ArgumentNullException.ThrowIfNull(node);
        filter ??= new ProcessFilter();
        if (filter.HasTopN && filter.TopN is < 1 or > 500)
        {
            return (null, NodeErrors.InvalidArgument("filter.top_n: 1..500"));
        }

        if (filter.Labels.Any(label => label == ProcessLabel.Unspecified || !Enum.IsDefined(label)))
        {
            return (null, NodeErrors.InvalidArgument("filter.labels: defined labels"));
        }

        if (filter.TaskId is { } task && task.Value.Length != 16)
        {
            return (null, NodeErrors.InvalidArgument("filter.task_id: a 16-byte ID"));
        }

        if (filter.SessionId is { } session && session.Value.Length != 16)
        {
            return (null, NodeErrors.InvalidArgument("filter.session_id: a 16-byte ID"));
        }

        if (node.Execution?.Resources is not { } monitor)
        {
            return ([], null);
        }

        // Sessions and their agent roots belong to AF-AI-01: no process is attributed to a session yet, so a session filter matches none.
        if (filter.SessionId is not null)
        {
            return ([], null);
        }

        // Detailed before the order is taken, so the order follows the memory figure each view shows (on Linux the private resident
        // memory of /proc/<pid>/status, not the table's resident set).
        var labels = filter.Labels.ToHashSet();
        var processes = monitor.Processes()
            .Where(process => labels.Count == 0 || labels.Contains(process.Label))
            .Where(process => filter.TaskId is null || (process.Owner is { } owner && owner.TaskId.AsSpan().SequenceEqual(filter.TaskId.Value.Span)))
            .Select(process => process with { Process = monitor.Detail(process.Process) })
            .OrderByDescending(process => process.CpuMillicores ?? 0)
            .ThenByDescending(process => process.Process.MemoryBytes)
            .Take(filter.HasTopN ? (int)filter.TopN : DefaultTopN)
            .ToList();
        return ([.. processes.Select(View)], null);
    }

    /// <summary>A classified process as the contract's view.</summary>
    public static ProcessView View(ClassifiedProcess process)
    {
        ArgumentNullException.ThrowIfNull(process);
        var sample = process.Process;
        var view = new ProcessView
        {
            Process = new ProcessIdentity
            {
                Pid = (uint)sample.Pid,
                StartTime = ProtoTime.ToInstant(sample.StartTime),
                ImageName = sample.Image,
            },
            ParentPid = (uint)Math.Max(0, sample.ParentPid),
            Label = process.Label,
            Usage = new ResourceUsage
            {
                CpuTimeMs = (ulong)Math.Max(0, sample.CpuTimeMs),
                MemBytes = (ulong)Math.Max(0, sample.MemoryBytes),
                ProcessCount = 1,
            },
            Executable = sample.Executable ?? sample.Image,
            CrossesVmBoundary = process.Owner?.CrossesVmBoundary == true,
        };
        if (process.CpuMillicores is { } cpu)
        {
            view.Usage.CpuMillicores = Cpu(cpu);
        }

        if (sample.IoReadBytes is { } read)
        {
            view.Usage.IoReadBytes = (ulong)Math.Max(0, read);
        }

        if (sample.IoWriteBytes is { } written)
        {
            view.Usage.IoWriteBytes = (ulong)Math.Max(0, written);
        }

        if (process.Owner is { } owner)
        {
            view.TaskId = new Id { Value = ByteString.CopyFrom(owner.TaskId) };
            view.AttemptId = new Id { Value = ByteString.CopyFrom(owner.AttemptId) };
        }

        return view;
    }

    /// <summary>The stored samples of <c>GetSamples</c> (03 section 1 retention), or a validation or not-found error.</summary>
    public static (ResourceServiceGetSamplesValue? Value, ArcError? Error) Samples(NodeRuntime node, ResourceServiceGetSamplesRequest request)
    {
        ArgumentNullException.ThrowIfNull(node);
        ArgumentNullException.ThrowIfNull(request);
        if (!request.HasScope || request.Scope == SampleScope.Unspecified || !Enum.IsDefined(request.Scope))
        {
            return (null, NodeErrors.InvalidArgument("scope: required"));
        }

        var attempt = request.Scope == SampleScope.Attempt;
        if (attempt && (request.AttemptId is null || request.AttemptId.Value.Length != 16))
        {
            return (null, NodeErrors.InvalidArgument("attempt_id: required for the ATTEMPT scope"));
        }

        if (!attempt && request.AttemptId is not null)
        {
            return (null, NodeErrors.InvalidArgument("attempt_id: ATTEMPT scope only"));
        }

        if (request.HasMaxPoints && request.MaxPoints is < 10 or > 10_000)
        {
            return (null, NodeErrors.InvalidArgument("max_points: 10..10,000"));
        }

        var now = node.Clock.GetUtcNow();
        var until = ProtoTime.ToDateTimeOffset(request.Range?.Until) ?? now;
        DateTimeOffset from;
        byte[] subject;
        if (attempt)
        {
            subject = request.AttemptId!.Value.ToByteArray();
            var created = node.Store.Read(reader => reader.Scalar("SELECT created_at FROM attempt WHERE attempt_id = $id;", ("$id", subject))) as long?;
            if (created is null)
            {
                return (null, NodeErrors.NotFound("attempt", subject));
            }

            from = ProtoTime.ToDateTimeOffset(request.Range?.From) ?? StoreTime.FromMicroseconds(created.Value);
        }
        else
        {
            subject = node.NodeId.ToArray();
            from = ProtoTime.ToDateTimeOffset(request.Range?.From) ?? until - DefaultRange;
        }

        if (until < from)
        {
            return (null, NodeErrors.InvalidArgument("range: until before from"));
        }

        if (request.Range?.From is not null && until - from > MaxRange)
        {
            return (null, NodeErrors.InvalidArgument("range: <= 30 days"));
        }

        var maxPoints = request.HasMaxPoints ? (int)request.MaxPoints : DefaultMaxPoints;
        var pending = node.Execution?.Resources?.Pending();
        var (samples, resolution) = node.Store.Read(reader => ResourceSamples.Read(reader, request.Scope, subject, StoreTime.ToMicroseconds(from),
            StoreTime.ToMicroseconds(until), maxPoints, pending));
        var value = new ResourceServiceGetSamplesValue();
        value.Samples.Add(samples);
        if (resolution > 0)
        {
            value.ResolutionMs = (ulong)resolution;
        }

        return (value, null);
    }

    /// <summary>True when <paramref name="path"/> is <paramref name="mount"/> or inside it (<c>/home</c> holds <c>/home/a</c>, not <c>/homework</c>).</summary>
    private static bool Contains(string mount, string path, StringComparison comparison) =>
        path.StartsWith(mount, comparison)
        && (path.Length == mount.Length || Path.EndsInDirectorySeparator(mount) || path[mount.Length] == Path.DirectorySeparatorChar
            || path[mount.Length] == Path.AltDirectorySeparatorChar);

    private static uint Cpu(long millicores) => (uint)Math.Clamp(millicores, 0, uint.MaxValue);

    private static ulong Bytes(long bytes) => (ulong)Math.Max(0, bytes);
}
