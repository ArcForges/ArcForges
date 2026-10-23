// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Globalization;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Resources;

/// <summary>The resource state the monitor computed at one evaluation (03 sections 1, 2 and 7). Memory in bytes, CPU in millicores.</summary>
public sealed record ResourceState
{
    /// <summary>When it was computed.</summary>
    public required DateTimeOffset At { get; init; }

    /// <summary><c>C_cpu</c>.</summary>
    public required long CapacityCpu { get; init; }

    /// <summary><c>C_mem</c>.</summary>
    public required long CapacityMemory { get; init; }

    /// <summary><c>R_cpu</c>.</summary>
    public required long ReserveCpu { get; init; }

    /// <summary><c>R_mem</c>.</summary>
    public required long ReserveMemory { get; init; }

    /// <summary>The machine's CPU use over the last interval.</summary>
    public long TotalCpu { get; init; }

    /// <summary>Available memory.</summary>
    public long AvailableMemory { get; init; }

    /// <summary><c>used_mem = C_mem - available_mem</c>.</summary>
    public long UsedMemory { get; init; }

    /// <summary>Committed memory (Windows commit total; Linux <c>Committed_AS</c>).</summary>
    public long CommitBytes { get; init; }

    /// <summary>The CPU use of managed work (every attempt container).</summary>
    public long ManagedCpu { get; init; }

    /// <summary>The resident memory of managed work without reclaimable cache.</summary>
    public long ManagedMemory { get; init; }

    /// <summary>The processor time of the running attempts so far.</summary>
    public long ManagedCpuTimeMs { get; init; }

    /// <summary>The sum of the running attempts' <c>peak_observed</c>.</summary>
    public long ManagedPeak { get; init; }

    /// <summary>Processes in attempt containers.</summary>
    public long ManagedProcesses { get; init; }

    /// <summary>Bytes the running attempts read so far.</summary>
    public long ManagedIoRead { get; init; }

    /// <summary>Bytes the running attempts wrote so far.</summary>
    public long ManagedIoWrite { get; init; }

    /// <summary>The node's own CPU use.</summary>
    public long NodeCpu { get; init; }

    /// <summary>The node's own processor time so far.</summary>
    public long NodeCpuTimeMs { get; init; }

    /// <summary>The node's own private resident memory (with its helper processes).</summary>
    public long NodeMemory { get; init; }

    /// <summary>The smoothed <c>U_cpu</c>.</summary>
    public long UnmanagedCpu { get; init; }

    /// <summary>The smoothed <c>U_mem</c>.</summary>
    public long UnmanagedMemory { get; init; }

    /// <summary><c>B_cpu</c>.</summary>
    public long BudgetCpu { get; init; }

    /// <summary><c>B_mem</c>.</summary>
    public long BudgetMemory { get; init; }

    /// <summary>The pressure level in force.</summary>
    public PressureLevel Pressure { get; init; } = PressureLevel.Normal;

    /// <summary>Why the current raw level holds.</summary>
    public string PressureTrigger { get; init; } = string.Empty;

    /// <summary>The raw level of this evaluation: the level whose condition holds now, before persistence.</summary>
    public PressureLevel RawPressure { get; init; } = PressureLevel.Normal;

    /// <summary>True when available memory is below the Critical threshold at this evaluation.</summary>
    public bool MemoryCritical { get; init; }

    /// <summary>The OOM kills newly observed machine-wide at this evaluation (Linux; 0 on Windows).</summary>
    public long NewOomKills { get; init; }

    /// <summary>Linux pressure stall information.</summary>
    public PressureStall? Stall { get; init; }

    /// <summary>Running attempts.</summary>
    public int RunningAttempts { get; init; }
}

/// <summary>
/// A pressure action hook (03 section 7): called on the monitor's thread after every evaluation with the level in force. The execution
/// supervisor stops preemptible attempts at Critical; admission (Tight: only INTERACTIVE) and the Pressure-level freeze or requeue join
/// with the scheduler (AF-SCHED-01) through the same hook.
/// </summary>
public interface IPressureResponse
{
    /// <summary>Responds to the level in force (<paramref name="previous"/> differs on a change).</summary>
    void Respond(PressureLevel level, PressureLevel previous, ResourceState state);
}

/// <summary>A process of the process table with its label, owner and CPU rate (<c>ListProcesses</c>).</summary>
/// <param name="Process">The process.</param>
/// <param name="Label">Its label.</param>
/// <param name="Owner">The attempt it belongs to or escaped from.</param>
/// <param name="CpuMillicores">Its CPU rate since the previous table, when known.</param>
public sealed record ClassifiedProcess(ProcessSample Process, ProcessLabel Label, ProcessOwner? Owner, long? CpuMillicores);

/// <summary>
/// The resource monitor (03 sections 1, 2, 3 and 7; R-RES-001, R-RES-003, R-RES-009, R-RES-014). Every second it samples the machine
/// and every running attempt's container, computes managed and unmanaged use, smooths <c>U</c> asymmetrically, derives the budgets, keeps
/// each attempt's <c>peak_observed</c> and evaluates the pressure level (journaled on topic RESOURCES with a notification and a
/// <c>MEMORY_PRESSURE</c> finding at Pressure and above, then handed to the pressure hooks). Every 5 s it takes the machine and managed
/// samples. While attempts run it reads the process table every 5 s and stores the buffered rows (with the 1 s attempt samples) every 5 s;
/// an idle node does both every 30 s. Every 10 min it downsamples (<see cref="ResourceSamples"/>).
/// It runs on its own thread, so a slow sampler never delays the enforcement loop.
/// </summary>
public sealed class ResourceMonitor : IDisposable
{
    /// <summary>The evaluation interval (03 section 1: 1 s internal).</summary>
    public static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(1);

    /// <summary>The process table and the stored machine samples (03 section 1: 5 s).</summary>
    public static readonly TimeSpan ProcessInterval = TimeSpan.FromSeconds(5);

    /// <summary>How often an idle node stores its buffered machine samples.</summary>
    public static readonly TimeSpan IdleFlushInterval = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How often an idle node (no running attempt) reads the process table (the adaptive interval of the task's idle-CPU risk): at idle
    /// the table only refreshes the node's own memory and the stored process count, and <c>ListProcesses</c> reads its own table at the
    /// call; while attempts run it is read every 5 s (and every second where an attempt's memory is summed from it).
    /// </summary>
    public static readonly TimeSpan IdleProcessInterval = TimeSpan.FromSeconds(30);

    /// <summary>How often the samples are downsampled.</summary>
    public static readonly TimeSpan HousekeepingInterval = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The scheduling tolerance of the interval checks: evaluations run every second but never exactly a second apart, so "5 s since" is
    /// five evaluations within half an interval.
    /// </summary>
    private static readonly TimeSpan Tolerance = TimeSpan.FromMilliseconds(500);

    /// <summary>The most buffered sample rows kept while the store cannot take them.</summary>
    private const int MaxPending = 50_000;

    private readonly IResourceSampler _sampler;
    private readonly ExecutionSupervisor _execution;
    private readonly CommandProcessor _processor;
    private readonly NodeLog _log;
    private readonly TimeProvider _clock;
    private readonly byte[] _nodeId;
    private readonly string? _nodeImage;
    private readonly CancellationTokenSource _stop = new();
    private readonly PressureEvaluator _pressure = new();
    private readonly AsymmetricSmoother _unmanagedCpu = new();
    private readonly AsymmetricSmoother _unmanagedMemory = new();
    private readonly List<SampleRow> _pending = [];
    private readonly Lock _gate = new();
    private readonly List<IPressureResponse> _responses = [];
    private readonly long _started;
    private Thread? _thread;
    private ResourceState? _state;
    private MachineSample? _lastMachine;
    private MachineSample? _persistedMachine;
    private long _lastSelfCpuMs = -1;
    private long _lastSelfAt;
    private long _nodeMemory;
    private IReadOnlyList<ProcessSample> _table = [];
    private Dictionary<int, ProcessSample> _tableByPid = [];
    private Dictionary<int, ProcessSample> _previousTable = [];
    private long _tableAt = long.MinValue;
    private long _previousTableAt = long.MinValue;
    private long _persistAt;
    private long _flushedAt;
    private long _housekeptAt;
    private long _windowPeakUsed;
    private long _windowPeakManaged;
    private double _windowManagedCpuMs;
    private int _failures;

    /// <summary>Creates the monitor (not started).</summary>
    public ResourceMonitor(IResourceSampler sampler, ExecutionSupervisor execution, NodeStore store, CommandProcessor processor, NodeLog log, TimeProvider clock)
    {
        _sampler = sampler ?? throw new ArgumentNullException(nameof(sampler));
        _execution = execution ?? throw new ArgumentNullException(nameof(execution));
        ArgumentNullException.ThrowIfNull(store);
        _processor = processor ?? throw new ArgumentNullException(nameof(processor));
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _nodeId = store.Metadata.NodeId.ToArray();
        _started = clock.GetTimestamp();
        _persistAt = _started;
        _flushedAt = _started;
        _housekeptAt = _started;
        using var self = System.Diagnostics.Process.GetCurrentProcess();
        _nodeImage = OperatingSystem.IsWindows() ? self.ProcessName + ".exe" : self.ProcessName;
    }

    /// <summary>The sampler.</summary>
    public IResourceSampler Sampler => _sampler;

    /// <summary>The last computed state, or <see langword="null"/> before the first evaluation.</summary>
    public ResourceState? Current => Volatile.Read(ref _state);

    /// <summary>Pulsed after every evaluation.</summary>
    public AsyncPulse Sampled { get; } = new();

    /// <summary>Adds a pressure hook.</summary>
    public void AddResponse(IPressureResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        lock (_gate)
        {
            _responses.Add(response);
        }
    }

    /// <summary>Starts sampling.</summary>
    public void Start()
    {
        _thread = new Thread(Loop) { IsBackground = true, Name = "arcforges-resources" };
        _thread.Start();
    }

    /// <summary>Stops sampling and stores the buffered samples.</summary>
    public async Task StopAsync()
    {
        if (!_stop.IsCancellationRequested)
        {
            await _stop.CancelAsync().ConfigureAwait(false);
        }

        _thread?.Join(TimeSpan.FromSeconds(2));
        try
        {
            await FlushAsync().ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or ObjectDisposedException
            or InvalidOperationException)
        {
            _log.Warning("resources.flush.failed", new LogField("errorType", exception.GetType().Name));
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _stop.Cancel();
        _thread?.Join(TimeSpan.FromSeconds(2));
        _stop.Dispose();
    }

    /// <summary>The sample rows not yet stored (merged into <c>GetSamples</c> so a running attempt's newest samples are visible).</summary>
    public List<SampleRow> Pending()
    {
        lock (_gate)
        {
            return [.. _pending];
        }
    }

    /// <summary>
    /// The process table now, classified (<c>ListProcesses</c>): container membership is read from every running attempt at the call, so a
    /// process the attempt just started is never shown as unmanaged; CPU rates are against the monitor's last table.
    /// </summary>
    public List<ClassifiedProcess> Processes()
    {
        var table = _sampler.Processes();
        Dictionary<int, ProcessSample> previous;
        long previousAt;
        lock (_gate)
        {
            previous = _tableByPid;
            previousAt = _tableAt;
        }

        var now = _clock.GetTimestamp();
        var context = Context();
        var result = new List<ClassifiedProcess>(table.Count);
        foreach (var process in table)
        {
            var (label, owner) = ProcessClassifier.Classify(process, context);
            result.Add(new ClassifiedProcess(process, label, owner, Rate(process, previous, previousAt, now)));
        }

        return result;
    }

    /// <summary>The detail of a process (private resident memory and I/O where the table does not carry them).</summary>
    public ProcessSample Detail(ProcessSample process) => _sampler.Detail(process);

    // ---------------------------------------------------------------------------------------------------------------------- loop

    private void Loop()
    {
        var next = _clock.GetTimestamp();
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                Tick();
                _failures = 0;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException
                or FormatException or OverflowException or ObjectDisposedException or Microsoft.Data.Sqlite.SqliteException)
            {
                // Logged on the first failure and then every minute, so a persistent failure cannot flood the log.
                if (_failures++ % 60 == 0)
                {
                    _log.Warning("resources.sample.failed", new LogField("errorType", exception.GetType().Name),
                        new LogField("error", NodeLog.OneLine(exception.Message)), new LogField("failures", _failures));
                }
            }

            next += (long)(SampleInterval.TotalSeconds * _clock.TimestampFrequency);
            var wait = _clock.GetElapsedTime(_clock.GetTimestamp(), next);
            if (wait <= TimeSpan.Zero)
            {
                // Behind (a slow sample or a suspended machine): the next evaluation starts now, on a new schedule.
                next = _clock.GetTimestamp();
                continue;
            }

            _stop.Token.WaitHandle.WaitOne(wait);
        }
    }

    private void Tick()
    {
        var settings = _execution.Settings;
        var now = _clock.GetTimestamp();
        var at = _clock.GetUtcNow();
        var micros = StoreTime.ToMicroseconds(at);
        var machine = _sampler.Machine();
        var attempts = _execution.RunningAttempts.Where(attempt => attempt.Handle is not null && !attempt.Finalizing).ToList();

        // The process table: every 5 s while attempts run (every second while an attempt's memory is summed from it, Windows), every 30 s idle.
        var tableInterval = attempts.Count > 0 ? ProcessInterval : IdleProcessInterval;
        if (Due(_tableAt, now, tableInterval) || attempts.Any(attempt => attempt.Handle!.UsageNeedsProcessTable))
        {
            RefreshTable(now);
        }

        long managedCpu = 0, managedMemory = 0, managedCpuTime = 0, managedPeak = 0, managedProcesses = 0, managedRead = 0, managedWrite = 0;
        var managedCpuUnknown = false;
        var rows = new List<SampleRow>(attempts.Count + 2);
        foreach (var attempt in attempts)
        {
            AttemptUsage usage;
            try
            {
                usage = attempt.Handle!.Usage(_tableByPid);
            }
            catch (Exception exception) when (exception is Win32Exception or IOException or InvalidOperationException or ObjectDisposedException
                or UnauthorizedAccessException)
            {
                continue;
            }

            long rate = 0;
            if (attempt.LastUsage is { } last)
            {
                var elapsed = _clock.GetElapsedTime(last.Timestamp, now).TotalMilliseconds;
                var work = Math.Max(0, usage.CpuTimeMs - last.CpuTimeMs);
                rate = elapsed > 0 ? (long)(work * 1000 / elapsed) : 0;
                _windowManagedCpuMs += work;
            }
            else if (_lastSelfCpuMs >= 0 && attempt.StartedTimestamp is { } started && started > _lastSelfAt)
            {
                // An attempt that started since the previous sample: its CPU so far ran in this window, which the machine's total counts;
                // a rate of 0 would count it as unmanaged and drop B_cpu (and the root's CPU cap that follows it) for the smoother's decay.
                var elapsed = _clock.GetElapsedTime(_lastSelfAt, now).TotalMilliseconds;
                var work = Math.Max(0, usage.CpuTimeMs);
                rate = elapsed > 0 ? (long)(work * 1000 / elapsed) : 0;
                _windowManagedCpuMs += work;
            }
            else if (_lastSelfCpuMs >= 0)
            {
                // An attempt adopted since the previous sample (recovered after a node restart): its container's CPU at that sample is
                // unknown, so its share of this window is too; U_cpu keeps its previous value for this window instead of counting the
                // attempt's CPU as unmanaged.
                managedCpuUnknown = true;
            }

            attempt.LastUsage = (usage.CpuTimeMs, now);
            attempt.Usage = usage;
            attempt.CpuMillicores = rate;
            var peak = attempt.Observe(usage.MemoryBytes);
            managedCpu += rate;
            managedMemory += usage.MemoryBytes;
            managedCpuTime += usage.CpuTimeMs;
            managedPeak += peak;
            managedProcesses += usage.Pids.Count;
            managedRead += usage.IoReadBytes;
            managedWrite += usage.IoWriteBytes;
            rows.Add(new SampleRow(SampleScope.Attempt, attempt.AttemptId, micros, 1000, rate, usage.CpuTimeMs, usage.MemoryBytes, peak, usage.Pids.Count,
                usage.IoReadBytes, usage.IoWriteBytes));
            if (!attempt.CrossingReported && attempt.Handle!.CrossesVmBoundary)
            {
                attempt.CrossingReported = true;
                _log.Info("resources.crosses_vm_boundary", new LogField("attempt", attempt.Name),
                    new LogField("detail", "the attempt ran a launcher into a virtual machine; the processes it starts there are outside its container"));
            }
        }

        // The node's own use (the CPU rate every second; the memory with the table).
        var selfCpu = (long)Environment.CpuUsage.TotalTime.TotalMilliseconds;
        long nodeCpu = 0;
        if (_lastSelfCpuMs >= 0)
        {
            var elapsed = _clock.GetElapsedTime(_lastSelfAt, now).TotalMilliseconds;
            nodeCpu = elapsed > 0 ? Math.Max(0, (long)((selfCpu - _lastSelfCpuMs) * 1000 / elapsed)) : 0;
        }

        _lastSelfCpuMs = selfCpu;
        _lastSelfAt = now;

        var capacityCpu = settings.CapacityCpu;
        var capacityMemory = settings.CapacityMemory;
        long totalCpu = 0;
        if (_lastMachine is { } previous && machine.CpuTotalMs > previous.CpuTotalMs)
        {
            totalCpu = (long)Math.Round((double)(machine.CpuBusyMs - previous.CpuBusyMs) / (machine.CpuTotalMs - previous.CpuTotalMs) * capacityCpu);
        }

        var used = Math.Max(0, capacityMemory - machine.AvailableMemoryBytes);
        var unmanagedMemory = (long)_unmanagedMemory.Update(Math.Max(0, used - managedMemory - _nodeMemory), settings.AlphaUp, settings.AlphaDown);
        var unmanagedCpu = _lastMachine is null || managedCpuUnknown
            ? (long)(_unmanagedCpu.Value ?? 0)
            : (long)_unmanagedCpu.Update(Math.Max(0, totalCpu - managedCpu - nodeCpu), settings.AlphaUp, settings.AlphaDown);
        _lastMachine = machine;
        var (budgetCpu, budgetMemory) = settings.Budgets(unmanagedCpu, unmanagedMemory);

        var before = _pressure.Level;
        var level = _pressure.Evaluate(_clock.GetElapsedTime(_started, now),
            new PressureInputs(machine.AvailableMemoryBytes, capacityMemory, capacityCpu, unmanagedCpu, machine.Pressure?.MemorySome, machine.OomKills),
            settings.Pressure);
        var state = new ResourceState
        {
            At = at,
            CapacityCpu = capacityCpu,
            CapacityMemory = capacityMemory,
            ReserveCpu = settings.ReserveCpu,
            ReserveMemory = settings.ReserveMemory,
            TotalCpu = totalCpu,
            AvailableMemory = machine.AvailableMemoryBytes,
            UsedMemory = used,
            CommitBytes = machine.CommitBytes,
            ManagedCpu = managedCpu,
            ManagedMemory = managedMemory,
            ManagedCpuTimeMs = managedCpuTime,
            ManagedPeak = managedPeak,
            ManagedProcesses = managedProcesses,
            ManagedIoRead = managedRead,
            ManagedIoWrite = managedWrite,
            NodeCpu = nodeCpu,
            NodeCpuTimeMs = selfCpu,
            NodeMemory = _nodeMemory,
            UnmanagedCpu = unmanagedCpu,
            UnmanagedMemory = unmanagedMemory,
            BudgetCpu = budgetCpu,
            BudgetMemory = budgetMemory,
            Pressure = level,
            PressureTrigger = _pressure.Trigger,
            RawPressure = _pressure.Raw,
            MemoryCritical = _pressure.MemoryCritical,
            NewOomKills = _pressure.NewOomKills,
            Stall = machine.Pressure,
            RunningAttempts = attempts.Count,
        };
        Volatile.Write(ref _state, state);
        if (level != before)
        {
            Journal(before, level, state);
        }

        List<IPressureResponse> responses;
        lock (_gate)
        {
            responses = [.. _responses];
        }

        foreach (var response in responses)
        {
            response.Respond(level, before, state);
        }

        // The stored machine and managed samples (5 s): the mean CPU rate over the whole interval (the machine's from its busy and total
        // time, the managed work's from the processor time its attempts used in it), and the highest 1 s memory of it.
        _windowPeakUsed = Math.Max(_windowPeakUsed, used);
        _windowPeakManaged = Math.Max(_windowPeakManaged, managedMemory);
        var persist = Due(_persistAt, now, ProcessInterval);
        if (persist)
        {
            var window = _persistedMachine ?? machine;
            var windowCpu = machine.CpuTotalMs > window.CpuTotalMs
                ? (long)Math.Round((double)(machine.CpuBusyMs - window.CpuBusyMs) / (machine.CpuTotalMs - window.CpuTotalMs) * capacityCpu)
                : totalCpu;
            var (machineRead, machineWrite) = _sampler.MachineIoFromProcesses
                ? (_table.Sum(process => process.IoReadBytes ?? 0), _table.Sum(process => process.IoWriteBytes ?? 0))
                : (machine.IoReadBytes, machine.IoWriteBytes);
            rows.Add(new SampleRow(SampleScope.Machine, _nodeId, micros, 5000, windowCpu, machine.CpuBusyMs, used, _windowPeakUsed, _table.Count,
                machineRead, machineWrite));
            var windowMs = _clock.GetElapsedTime(_persistAt, now).TotalMilliseconds;
            var managedWindowCpu = windowMs > 0 ? (long)Math.Round(_windowManagedCpuMs * 1000 / windowMs) : managedCpu;
            rows.Add(new SampleRow(SampleScope.Managed, _nodeId, micros, 5000, managedWindowCpu, managedCpuTime, managedMemory, _windowPeakManaged,
                managedProcesses, managedRead, managedWrite));
            _persistedMachine = machine;
            _windowPeakUsed = 0;
            _windowPeakManaged = 0;
            _windowManagedCpuMs = 0;
        }

        lock (_gate)
        {
            _pending.AddRange(rows);
            if (_pending.Count > MaxPending)
            {
                _pending.RemoveRange(0, _pending.Count - MaxPending);
            }
        }

        if (persist)
        {
            // While attempts run, their samples and accounted memory are stored every 5 s; an idle node stores its machine samples every
            // 30 s (GetSamples merges the rows not yet stored, so none is missing from an answer).
            _persistAt = now;
            if (attempts.Count > 0 || Due(_flushedAt, now, IdleFlushInterval))
            {
                _flushedAt = now;
                _ = FlushAsync(attempts.Select(attempt => (attempt.AttemptId, attempt.PeakObserved)).ToList());
            }
        }

        if (Due(_housekeptAt, now, HousekeepingInterval))
        {
            _housekeptAt = now;
            _ = HousekeepAsync();
        }

        Sampled.Pulse();
    }

    private void RefreshTable(long now)
    {
        var table = _sampler.Processes();
        var byPid = new Dictionary<int, ProcessSample>(table.Count);
        foreach (var process in table)
        {
            byPid[process.Pid] = process;
        }

        // The node's own memory: its process (detailed) and its helper processes (the Windows holders run the same executable).
        long memory = 0;
        foreach (var process in table)
        {
            if (process.Pid == Environment.ProcessId)
            {
                memory += _sampler.Detail(process).MemoryBytes;
            }
            else if (process.ParentPid == Environment.ProcessId && string.Equals(process.Image, _nodeImage, StringComparison.OrdinalIgnoreCase))
            {
                memory += process.MemoryBytes;
            }
        }

        lock (_gate)
        {
            if (Due(_previousTableAt, now, ProcessInterval))
            {
                // The rate base for ListProcesses moves once it is 5 s old (whether the table refreshes every second or every 5 s), so a rate
                // always spans one to a few seconds and never reaches back to a base taken long before.
                _previousTable = _tableByPid;
                _previousTableAt = _tableAt;
            }

            _table = table;
            _tableByPid = byPid;
            _tableAt = now;
        }

        _nodeMemory = memory;
    }

    /// <summary>True when <paramref name="interval"/> (within the tolerance) passed since <paramref name="since"/>, or it never ran.</summary>
    private bool Due(long since, long now, TimeSpan interval) => since == long.MinValue || _clock.GetElapsedTime(since, now) >= interval - Tolerance;

    private ProcessContext Context()
    {
        var managed = new Dictionary<int, ProcessOwner>();
        var escaped = new List<(int, DateTimeOffset, ProcessOwner)>();
        foreach (var attempt in _execution.RunningAttempts)
        {
            if (attempt.Handle is not { } handle)
            {
                continue;
            }

            var owner = new ProcessOwner(attempt.AttemptId, attempt.TaskId, handle.CrossesVmBoundary);
            IReadOnlyList<int> pids;
            try
            {
                pids = handle.Usage(null).Pids;
            }
            catch (Exception exception) when (exception is Win32Exception or IOException or InvalidOperationException or ObjectDisposedException
                or UnauthorizedAccessException)
            {
                pids = attempt.Usage?.Pids ?? [];
            }

            foreach (var pid in pids)
            {
                managed[pid] = owner;
            }

            foreach (var known in attempt.KnownEscaped.Keys)
            {
                escaped.Add((known.Pid, new DateTimeOffset(known.StartTicks, TimeSpan.Zero), owner));
            }
        }

        var adopted = new Dictionary<int, ProcessOwner>();
        foreach (var adoption in _execution.Adoptions.Tracked)
        {
            try
            {
                foreach (var pid in adoption.Container.Processes())
                {
                    adopted[pid] = new ProcessOwner(adoption.AttemptId, adoption.TaskId, false);
                }
            }
            catch (Exception exception) when (exception is Win32Exception or IOException or InvalidOperationException or ObjectDisposedException)
            {
                _log.Debug("resources.adopted.read_failed", new LogField("errorType", exception.GetType().Name));
            }
        }

        return new ProcessContext
        {
            NodePid = Environment.ProcessId,
            NodeImage = _nodeImage,
            Managed = managed,
            Adopted = adopted,
            Escaped = escaped,
            IsVmWorker = _sampler.IsVmWorker,
        };
    }

    private long? Rate(ProcessSample process, Dictionary<int, ProcessSample> previous, long previousAt, long now)
    {
        // Against the newest table at least a second old: the monitor's current one, else the one before it.
        if (previousAt == long.MinValue || _clock.GetElapsedTime(previousAt, now) < TimeSpan.FromSeconds(1))
        {
            lock (_gate)
            {
                previous = _previousTable;
                previousAt = _previousTableAt;
            }
        }

        if (previousAt != long.MinValue && previous.TryGetValue(process.Pid, out var before)
            && Math.Abs((before.StartTime - process.StartTime).TotalMilliseconds) <= 10)
        {
            var elapsed = _clock.GetElapsedTime(previousAt, now).TotalMilliseconds;
            return elapsed <= 0 ? null : Math.Max(0, (long)((process.CpuTimeMs - before.CpuTimeMs) * 1000 / elapsed));
        }

        // A process the previous table did not have started after it: all of its processor time is from its own lifetime, which is no
        // longer than the time since that table (Linux start times are only as precise as the boot time's whole second).
        var age = (_clock.GetUtcNow() - process.StartTime).TotalMilliseconds;
        if (previousAt != long.MinValue)
        {
            age = Math.Min(age, _clock.GetElapsedTime(previousAt, now).TotalMilliseconds);
        }

        return age >= 500 ? Math.Max(0, (long)(process.CpuTimeMs * 1000 / age)) : null;
    }

    // ------------------------------------------------------------------------------------------------------------------- storage

    private async Task FlushAsync(List<(byte[] AttemptId, long Peak)>? peaks = null)
    {
        List<SampleRow> rows;
        lock (_gate)
        {
            rows = [.. _pending];
            _pending.Clear();
        }

        if (rows.Count == 0 && (peaks is null || peaks.Count == 0))
        {
            return;
        }

        try
        {
            await _processor.ExecuteAsync(context =>
            {
                ResourceSamples.Insert(context.Transaction, rows);
                foreach (var (attemptId, peak) in peaks ?? [])
                {
                    // accounted_mem_bytes = max(mem_expected, peak_observed), never decreasing while the attempt runs (03 section 3).
                    context.Transaction.Execute(
                        "UPDATE attempt SET accounted_mem_bytes = max(accounted_mem_bytes, $peak) WHERE attempt_id = $id AND state BETWEEN 1 AND 8;",
                        ("$peak", peak), ("$id", attemptId));
                }

                return 0;
            }).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or ObjectDisposedException
            or InvalidOperationException)
        {
            // Kept for the next flush (bounded): samples are observations, never a reason to fail the node.
            lock (_gate)
            {
                _pending.InsertRange(0, rows);
                if (_pending.Count > MaxPending)
                {
                    _pending.RemoveRange(0, _pending.Count - MaxPending);
                }
            }

            _log.Warning("resources.flush.failed", new LogField("errorType", exception.GetType().Name), new LogField("rows", rows.Count));
        }
    }

    private async Task HousekeepAsync()
    {
        try
        {
            var removed = await _processor.ExecuteAsync(context => ResourceSamples.Housekeep(context.Transaction)).ConfigureAwait(false);
            _log.Debug("resources.housekeeping", new LogField("rowsRemoved", removed));
        }
        catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or ObjectDisposedException
            or InvalidOperationException)
        {
            _log.Warning("resources.housekeeping.failed", new LogField("errorType", exception.GetType().Name));
        }
    }

    /// <summary>
    /// Journals a level change (03 section 7: every action is journaled with its trigger and evidence): the snapshot on topic RESOURCES,
    /// and at Pressure and above a notification and a <c>MEMORY_PRESSURE</c> finding (07 section 3) with the numbers.
    /// </summary>
    private void Journal(PressureLevel previous, PressureLevel level, ResourceState state)
    {
        var evidence = new List<(string Name, string Value)>
        {
            ("level", Word(level)),
            ("previous", Word(previous)),
            ("trigger", state.PressureTrigger),
            ("available_bytes", state.AvailableMemory.ToString(CultureInfo.InvariantCulture)),
            ("capacity_bytes", state.CapacityMemory.ToString(CultureInfo.InvariantCulture)),
            ("unmanaged_mem_bytes", state.UnmanagedMemory.ToString(CultureInfo.InvariantCulture)),
            ("unmanaged_cpu_millicores", state.UnmanagedCpu.ToString(CultureInfo.InvariantCulture)),
        };
        if (state.Stall is { } stall)
        {
            evidence.Add(("memory_some_avg10", stall.MemorySome.ToString("0.##", CultureInfo.InvariantCulture)));
        }

        _log.Info("resources.pressure", new LogField("level", level), new LogField("previous", previous), new LogField("trigger", state.PressureTrigger),
            new LogField("availableBytes", state.AvailableMemory), new LogField("capacityBytes", state.CapacityMemory));
        var snapshot = ResourceViews.Snapshot(state);
        _ = JournalAsync(context =>
        {
            context.Emit(EventTopic.Resources, new NodeEvent { Resources = snapshot });
            if (level >= PressureLevel.Pressure)
            {
                var severity = level == PressureLevel.Critical ? Severity.Error : Severity.Warning;
                var title = level == PressureLevel.Critical ? "Critical memory pressure" : "Memory pressure";
                var body = string.Create(CultureInfo.InvariantCulture,
                    $"{state.AvailableMemory / (1024 * 1024)} MiB of {state.CapacityMemory / (1024 * 1024)} MiB available ({state.PressureTrigger}).");
                ExecutionFindings.Raise(context, FindingKind.MemoryPressure, severity, "node", _nodeId, title,
                    level == PressureLevel.Critical
                        ? "Memory is critically low. Preemptible attempts are stopped one at a time from the lowest priority up, only while available memory stays below the Critical threshold (or once per observed OOM kill), each after the previous one has exited; non-preemptible work is never stopped for it (03 section 7)."
                        : "Memory is low. Admissions are restricted and the configured pressure actions apply (03 section 7).",
                    evidence);
                Notifications.Add(context, "finding", severity, title, body);
            }
            else if (previous >= PressureLevel.Pressure)
            {
                Notifications.Add(context, "node", Severity.Info, "Memory pressure eased",
                    string.Create(CultureInfo.InvariantCulture, $"The pressure level is {Word(level)} ({state.PressureTrigger})."));
            }

            return 0;
        });
    }

    private async Task JournalAsync(Func<CommandContext, int> command)
    {
        try
        {
            await _processor.ExecuteAsync(command).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is CommandQueueFullException or Microsoft.Data.Sqlite.SqliteException or ObjectDisposedException
            or InvalidOperationException)
        {
            _log.Warning("resources.journal.failed", new LogField("errorType", exception.GetType().Name));
        }
    }

    private static string Word(PressureLevel level) => level.ToString().ToUpperInvariant();
}
