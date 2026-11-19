// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Platform;
using ArcForges.Node.Store.Policy;
using Microsoft.Data.Sqlite;
using V1 = ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Resources;

internal sealed record RunResourceTarget(string RunId, string SandboxId, string Epoch, IRunResourceSource? Source);

internal sealed record RunResourceInventory(long CatalogueRevision, RunResourceTarget[] Targets);

internal sealed record RunResourceMeasurement(RunResourceTarget Target, RunResourceObservation? Reading, long? CpuMillicores);

internal sealed record SandboxResourceFrame(long Timestamp, long? LastCompleteTimestamp, long? CatalogueRevision, uint? RunIntervalMs,
    ResourceSnapshot Host, IReadOnlyDictionary<string, RunResourceMeasurement> Runs)
{
    internal bool Stale => LastCompleteTimestamp is not { } time || Stopwatch.GetElapsedTime(time) >= TimeSpan.FromSeconds(3);
}

/// <summary>Collects the host and its active V2 Run scopes without holding the Sandbox mutation lock during native reads.</summary>
internal sealed class SandboxResourceMonitor : IAsyncDisposable
{
    private const long GiB = 1L << 30;
    private readonly TimeProvider _clock;
    private readonly IHostResourceSource _host;
    private readonly Func<RunResourceInventory?> _inventory;
    private readonly Func<StoredPolicy> _policy;
    private readonly NodeLog _log;
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource _firstBudget = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task _loop;
    private readonly AsymmetricSmoother _cpu = new();
    private readonly AsymmetricSmoother _memory = new();
    private readonly long[] _timing = new long[16];
    private PressureEvaluator? _pressure;
    private HostResourceObservation? _hostBaseline;
    private ulong _sequence;
    private long? _lastComplete;
    private int _timingCount;
    private int _activeRunSamples;
    private bool? _lastAvailability;
    private long? _lastPolicyRevision;
    private SandboxResourceFrame? _latest;

    internal SandboxResourceMonitor(TimeProvider clock, IHostResourceSource host, Func<RunResourceInventory?> inventory,
        Func<StoredPolicy> policy, NodeLog log)
    {
        _clock = clock;
        _host = host;
        _inventory = inventory;
        _policy = policy;
        _log = log;
        _loop = Task.Run(SampleLoopAsync);
    }

    internal string Epoch { get; } = Guid.NewGuid().ToString("N");

    internal SandboxResourceFrame? Latest => Volatile.Read(ref _latest);

    internal bool NeedsInitialBudget => !_firstBudget.Task.IsCompleted;

    internal void WaitForInitialBudget(CancellationToken cancellationToken)
    {
        try
        {
            _firstBudget.Task.WaitAsync(TimeSpan.FromSeconds(3), cancellationToken).GetAwaiter().GetResult();
        }
        catch (TimeoutException)
        {
            // Admission validates freshness and presence after leaving this bounded startup wait.
        }
    }

    private async Task SampleLoopAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        var cancellation = _stop.Token;
        try
        {
            do
            {
                Sample();
            } while (await timer.WaitForNextTickAsync(cancellation).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
        }
    }

    private void Sample()
    {
        long timestamp = Stopwatch.GetTimestamp();
        var previous = Latest;
        var priorHost = _hostBaseline;
        var host = ReadHost();
        var stored = ReadPolicy();
        var inventory = _inventory();
        var targets = inventory?.Targets ?? [];
        var runs = new Dictionary<string, RunResourceMeasurement>(targets.Length, StringComparer.Ordinal);
        var runInterval = previous is null ? TimeSpan.Zero : Stopwatch.GetElapsedTime(previous.Timestamp, timestamp);
        foreach (var target in targets)
        {
            var read = ReadRun(target.Source);
            RunResourceMeasurement? old = null;
            if (previous is not null && previous.Runs.TryGetValue(target.RunId, out var last)
                && last.Target.Epoch == target.Epoch && ReferenceEquals(last.Target.Source, target.Source))
            {
                old = last;
            }

            long? rate = ResourceBudgetMath.CpuRateMillicores(AsLong(old?.Reading?.CumulativeCpuUsec),
                AsLong(read?.CumulativeCpuUsec), runInterval);
            runs.Add(target.RunId, new(target, read, rate));
        }

        long? nativeTime = host?.MonotonicTimestamp;
        var hostInterval = nativeTime is { } time && priorHost?.MonotonicTimestamp is { } oldTime && time > oldTime
            ? Stopwatch.GetElapsedTime(oldTime, time) : TimeSpan.Zero;
        if (host is null || nativeTime != priorHost?.MonotonicTimestamp)
        {
            _hostBaseline = host;
        }

        var snapshot = new ResourceSnapshot
        {
            ScopeKind = "node",
            SampledAt = ProtoTime.ToInstant(_clock.GetUtcNow()),
            SampleEpoch = Epoch,
            SampleSequence = ++_sequence,
            MemoryKind = "resident_estimate",
            Pressure = "unknown",
        };
        if (Milliseconds(hostInterval) is uint hostIntervalMs)
        {
            snapshot.SampleIntervalMs = hostIntervalMs;
        }

        var managed = runs.Values;
        long? managedCpu = inventory is null ? null : Sum(managed, run => run.CpuMillicores);
        long? managedResident = inventory is null ? null : Sum(managed, run => AsLong(run.Reading?.ResidentBytes));
        long? hostCpu = ResourceBudgetMath.CpuRateMillicores(AsLong(priorHost?.CpuBusyUsec), AsLong(host?.CpuBusyUsec), hostInterval);
        long? nodeCpu = ResourceBudgetMath.CpuRateMillicores(AsLong(priorHost?.NodeCpuUsec), AsLong(host?.NodeCpuUsec), hostInterval);
        long? nodeResident = AsLong(host?.NodeResidentBytes);
        long? capacityCpu = host?.CpuCapacityMillicores;
        long? capacityMem = AsLong(host?.PhysicalTotalBytes);
        long? availableMem = AsLong(host?.PhysicalAvailableBytes);
        long? usedMem = capacityMem is > 0 && availableMem is >= 0 && availableMem <= capacityMem ? capacityMem - availableMem : null;

        if (capacityCpu is > 0 and <= uint.MaxValue) snapshot.HostCpuMillicores = (uint)capacityCpu.Value;
        if (capacityMem is > 0) snapshot.HostMemoryBytes = (ulong)capacityMem.Value;
        if (managedCpu is >= 0 and <= uint.MaxValue) snapshot.ManagedCpuMillicores = (uint)managedCpu.Value;
        if (managedResident is >= 0) snapshot.ManagedMemoryBytes = (ulong)managedResident.Value;
        if (nodeCpu is >= 0 and <= uint.MaxValue) snapshot.NodeCpuMillicores = (uint)nodeCpu.Value;
        if (nodeResident is >= 0) snapshot.NodeMemoryBytes = (ulong)nodeResident.Value;
        if (inventory is not null && Sum(managed, run => run.Reading?.ProcessCount) is >= 0 and <= uint.MaxValue and var processCount)
            snapshot.ProcessCount = (uint)processCount;
        SetPressureFacts(snapshot, host?.PsiCpuSome, host?.PsiMemorySome, host?.PsiMemoryFull);

        if (stored is not null)
        {
            PopulateBudget(snapshot, stored, host, capacityCpu, capacityMem, availableMem, usedMem, hostCpu,
                managedCpu, nodeCpu, managedResident, nodeResident, timestamp);
        }
        else
        {
            _pressure = null;
        }

        var complete = nativeTime.HasValue && capacityCpu > 0 && usedMem.HasValue && snapshot.HasBudgetCpuMillicores
            && snapshot.HasBudgetMemoryBytes;
        if (complete)
        {
            _lastComplete = nativeTime;
        }

        var frame = new SandboxResourceFrame(timestamp, _lastComplete, inventory?.CatalogueRevision, Milliseconds(runInterval), snapshot, runs);
        snapshot.Stale = frame.Stale;
        Volatile.Write(ref _latest, frame);
        if (complete)
        {
            _firstBudget.TrySetResult();
        }

        if (_lastAvailability != !snapshot.Stale)
        {
            _lastAvailability = !snapshot.Stale;
            _log.Info("sandbox.resources.availability", new LogField("authoritative", !snapshot.Stale));
        }

        RecordTiming(timestamp, targets.Length > 0);
    }

    private void PopulateBudget(ResourceSnapshot snapshot, StoredPolicy stored, HostResourceObservation? host,
        long? capacityCpu, long? capacityMem, long? availableMem, long? usedMem, long? hostCpu,
        long? managedCpu, long? nodeCpu, long? managedResident, long? nodeResident, long timestamp)
    {
        var policy = stored.Document.Resources ?? new V1.ResourcePolicy();
        snapshot.PolicyRevision = new Revision { Value = stored.Revision };
        if (_lastPolicyRevision != stored.Revision)
        {
            _lastPolicyRevision = stored.Revision;
            _pressure = null;
        }

        long? reserveCpu = capacityCpu is > 0 ? HostReserve(capacityCpu.Value,
            policy.HasReserveCpuFixedMillicores ? policy.ReserveCpuFixedMillicores : 1000,
            policy.HasReserveCpuFraction ? policy.ReserveCpuFraction : 0.1) : null;
        long? reserveMemory = capacityMem is > 0 ? HostReserve(capacityMem.Value,
            policy.HasReserveMemFixedBytes ? (long)Math.Min(policy.ReserveMemFixedBytes, long.MaxValue) : 2 * GiB,
            policy.HasReserveMemFraction ? policy.ReserveMemFraction : 0.1) : null;
        if (reserveCpu is >= 0 and <= uint.MaxValue) snapshot.ReservedCpuMillicores = (uint)reserveCpu.Value;
        if (reserveMemory is >= 0) snapshot.ReservedMemoryBytes = (ulong)reserveMemory.Value;

        var alphaUp = policy.HasSmoothingAlphaUp && policy.SmoothingAlphaUp is >= 0.05 and <= 1 ? policy.SmoothingAlphaUp : 0.5;
        var alphaDown = policy.HasSmoothingAlphaDown && policy.SmoothingAlphaDown is >= 0.01 and <= 1 ? policy.SmoothingAlphaDown : 0.1;
        var unmanagedCpu = ResourceBudgetMath.UnmanagedUsage(hostCpu, managedCpu, nodeCpu);
        var unmanagedMemory = ResourceBudgetMath.UnmanagedUsage(usedMem, managedResident, nodeResident);
        var smoothedCpu = unmanagedCpu is long cpu ? (long?)_cpu.Update(cpu, alphaUp, alphaDown) : null;
        var smoothedMemory = unmanagedMemory is long memory ? (long?)_memory.Update(memory, alphaUp, alphaDown) : null;
        if (smoothedCpu is >= 0 and <= uint.MaxValue) snapshot.UnmanagedCpuMillicores = (uint)smoothedCpu.Value;
        if (smoothedMemory is >= 0) snapshot.UnmanagedMemoryBytes = (ulong)smoothedMemory.Value;
        if (ResourceBudgetMath.CpuBudget(capacityCpu, reserveCpu, smoothedCpu,
            policy.HasMinManagedCpuMillicores ? policy.MinManagedCpuMillicores : 1000) is >= 0 and <= uint.MaxValue and var cpuBudget)
            snapshot.BudgetCpuMillicores = (uint)cpuBudget;
        if (ResourceBudgetMath.MemoryBudget(capacityMem, reserveMemory, smoothedMemory) is >= 0 and var memoryBudget)
            snapshot.BudgetMemoryBytes = (ulong)memoryBudget;

        if (capacityCpu is > 0 && capacityMem is > 0 && usedMem.HasValue && smoothedCpu.HasValue
            && host is not null && (OperatingSystem.IsWindows() || host.OomKills.HasValue))
        {
            var pressure = policy.Pressure ?? new V1.PressureThresholds();
            var limits = new PressureLimits(Fraction(pressure.TightAvailableFraction, 0.10),
                Fraction(pressure.PressureAvailableFraction, 0.05), Fraction(pressure.CriticalAvailableFraction, 0.02),
                pressure.HasMemoryPsiSomeAvg10 ? pressure.MemoryPsiSomeAvg10 : 20, false, false);
            _pressure ??= new PressureEvaluator();
            var level = _pressure.Evaluate(Stopwatch.GetElapsedTime(0, timestamp),
                new(availableMem!.Value, capacityMem.Value, capacityCpu.Value, smoothedCpu.Value,
                    host.PsiMemorySome, AsLong(host.OomKills) ?? 0), limits);
            snapshot.Pressure = level.ToString().ToLowerInvariant();
        }
        else
        {
            _pressure = null;
        }
    }

    private HostResourceObservation? ReadHost()
    {
        try { return _host.ObserveHostResources(); }
        catch (Exception failure) when (IsObservationFailure(failure)) { return null; }
    }

    private static RunResourceObservation? ReadRun(IRunResourceSource? source)
    {
        try { return source?.ObserveRunResources(); }
        catch (Exception failure) when (IsObservationFailure(failure)) { return null; }
    }

    private StoredPolicy? ReadPolicy()
    {
        try
        {
            var policy = _policy();
            return CryptographicOperations.FixedTimeEquals(policy.Digest.Span, PolicyDocuments.Digest(policy.Document)) ? policy : null;
        }
        catch (Exception failure) when (IsObservationFailure(failure) || failure is SqliteException)
        {
            return null;
        }
    }

    private void RecordTiming(long timestamp, bool active)
    {
        _timing[_timingCount++] = Stopwatch.GetElapsedTime(timestamp).Ticks / 10;
        if (active) _activeRunSamples++;
        if (_timingCount < _timing.Length) return;
        Array.Sort(_timing);
        _log.Info("sandbox.resources.sample_timing", new LogField("count", (long)_timing.Length),
            new LogField("activeRunSamples", (long)_activeRunSamples), new LogField("p50Usec", _timing[(_timing.Length - 1) / 2]),
            new LogField("p95Usec", _timing[^1]));
        _timingCount = 0;
        _activeRunSamples = 0;
    }

    private static bool IsObservationFailure(Exception failure) =>
        failure is IOException or UnauthorizedAccessException or InvalidOperationException or Win32Exception;

    private static double Fraction(double value, double fallback) => value is > 0 and <= 1 ? value : fallback;

    private static long HostReserve(long capacity, long fixedAmount, double fraction)
    {
        // Keep the legacy configured fixed-plus-fraction rule, with the V2 capacity clamp.
        if (fixedAmount >= capacity || fixedAmount + fraction * capacity >= capacity)
            return capacity;
        return ResourceBudgetMath.NormalizeReserve(capacity, ResourceBudgetMath.ResolveReserve(capacity, fixedAmount, fraction));
    }

    internal static long? AsLong(ulong? value) => value is <= long.MaxValue ? (long)value.Value : null;

    private static uint? Milliseconds(TimeSpan interval) =>
        interval.TotalMilliseconds >= 1 ? (uint)Math.Min(interval.TotalMilliseconds, uint.MaxValue) : null;

    internal static long? Sum(IEnumerable<RunResourceMeasurement> runs, Func<RunResourceMeasurement, long?> field)
    {
        long total = 0;
        foreach (var run in runs)
        {
            var value = field(run);
            if (value is not >= 0 || value > long.MaxValue - total) return null;
            total += value.Value;
        }

        return total;
    }

    internal static void SetPressureFacts(ResourceSnapshot snapshot, double? cpu, double? memorySome, double? memoryFull)
    {
        if (cpu is >= 0 and <= 100) snapshot.PsiCpuSome = cpu.Value;
        if (memorySome is >= 0 and <= 100) snapshot.PsiMemorySome = memorySome.Value;
        if (memoryFull is >= 0 and <= 100) snapshot.PsiMemoryFull = memoryFull.Value;
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        try { await _loop.ConfigureAwait(false); }
        finally { _stop.Dispose(); }
    }
}
