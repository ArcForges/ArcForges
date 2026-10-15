// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Client;
using ArcForges.Node.Platform;

namespace ArcForges.Node.Core.Execution;

/// <summary>
/// A probe the heartbeat depends on (06 section 5): the cache store's in-memory request to its own request loop (AF-CACHE-01 registers
/// it). A probe that does not answer within 5 s is a miss; three misses in a row stop the renewals, so a hung store also leads to a
/// restart, while a disk stall under load does not.
/// </summary>
public interface IHeartbeatProbe
{
    /// <summary>The probe's name for the log.</summary>
    string Name { get; }

    /// <summary>Answers the in-memory probe.</summary>
    Task ProbeAsync(CancellationToken cancellationToken);
}

/// <summary>A monitor whose cycles the heartbeat requires (the output tailer here; the temporary-directory pass and the low-space check join with AF-STOR-01).</summary>
public sealed class HeartbeatMonitor
{
    private long _lastCycle = long.MinValue;

    internal HeartbeatMonitor(string name, TimeSpan staleAfter)
    {
        Name = name;
        StaleAfter = staleAfter;
    }

    /// <summary>The monitor's name.</summary>
    public string Name { get; }

    /// <summary>How long after its last cycle the monitor counts as hung.</summary>
    public TimeSpan StaleAfter { get; }

    /// <summary>True once the monitor completed a cycle.</summary>
    public bool Started => Volatile.Read(ref _lastCycle) != long.MinValue;

    /// <summary>Records a completed cycle.</summary>
    public void Completed() => Volatile.Write(ref _lastCycle, Stopwatch.GetTimestamp());

    /// <summary>True when the monitor completed a cycle recently.</summary>
    public bool Fresh => Started && Stopwatch.GetElapsedTime(Volatile.Read(ref _lastCycle)) <= StaleAfter;
}

/// <summary>
/// The node heartbeat <c>run/node-heartbeat</c> (02 section 2; 06 section 5): renewed every second from the enforcement loop with the
/// node instance's ID and an increasing sequence, but only once recovery is done, each monitor has completed a cycle (and none is
/// hung), and while every registered probe answers (three misses in a row stop the renewals). Attempt guards take over when it goes
/// stale; the Windows supervisor restarts a node whose heartbeat stalls for 30 s.
/// </summary>
public sealed class NodeHeartbeatWriter : IDisposable
{
    /// <summary>The renewal interval.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(1);

    /// <summary>The probe timeout.</summary>
    public static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Consecutive misses that stop the renewals.</summary>
    public const int MissesToStop = 3;

    private readonly string _path;
    private readonly NodeLog _log;
    private readonly TimeProvider _clock;
    private readonly List<HeartbeatMonitor> _monitors = [];
    private readonly List<IHeartbeatProbe> _probes = [];
    private readonly CancellationTokenSource _stop = new();
    private readonly Lock _gate = new();
    private Task _probeLoop = Task.CompletedTask;
    private int _misses;
    private long _sequence;
    private long _lastRenewal = long.MinValue;
    private string? _blockedBy;
    private int _disposed;

    /// <summary>Creates the writer for <paramref name="dataRoot"/>.</summary>
    public NodeHeartbeatWriter(string dataRoot, NodeLog log, TimeProvider clock)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        _path = AttemptFiles.HeartbeatPath(dataRoot);
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        Instance = IdText.Format(Guid.CreateVersion7().ToByteArray(bigEndian: true));
    }

    /// <summary>This node instance's ID.</summary>
    public string Instance { get; }

    /// <summary>The last sequence written.</summary>
    public long Sequence => Interlocked.Read(ref _sequence);

    /// <summary>Set once recovery is done (02 section 2 step 5).</summary>
    public bool RecoveryDone { get; set; }

    /// <summary>Consecutive probe misses.</summary>
    public int Misses => Volatile.Read(ref _misses);

    /// <summary>Registers a monitor the heartbeat requires.</summary>
    public HeartbeatMonitor AddMonitor(string name, TimeSpan staleAfter)
    {
        var monitor = new HeartbeatMonitor(name, staleAfter);
        lock (_gate)
        {
            _monitors.Add(monitor);
        }

        return monitor;
    }

    /// <summary>Registers a probe (the cache store's, AF-CACHE-01).</summary>
    public void AddProbe(IHeartbeatProbe probe)
    {
        ArgumentNullException.ThrowIfNull(probe);
        lock (_gate)
        {
            _probes.Add(probe);
        }
    }

    /// <summary>Starts the probe loop (every second).</summary>
    public void Start() => _probeLoop = Task.Run(ProbeLoopAsync);

    /// <summary>Renews the heartbeat when it is due and every condition holds; called from the enforcement loop.</summary>
    public void Tick()
    {
        if (_lastRenewal != long.MinValue && _clock.GetElapsedTime(_lastRenewal) < Interval)
        {
            return;
        }

        string? blocked = null;
        if (!RecoveryDone)
        {
            blocked = "recovery";
        }
        else
        {
            lock (_gate)
            {
                blocked = _monitors.FirstOrDefault(monitor => !monitor.Fresh)?.Name;
            }

            if (blocked is null && Misses >= MissesToStop)
            {
                blocked = "probe";
            }
        }

        if (blocked is not null)
        {
            if (!string.Equals(_blockedBy, blocked, StringComparison.Ordinal))
            {
                _blockedBy = blocked;
                _log.Warning("node.heartbeat.held", new LogField("waitingFor", blocked));
            }

            return;
        }

        if (_blockedBy is not null)
        {
            _log.Info("node.heartbeat.resumed", new LogField("after", _blockedBy));
            _blockedBy = null;
        }

        try
        {
            new NodeHeartbeat
            {
                Instance = Instance,
                Seq = Interlocked.Increment(ref _sequence),
                Pid = Environment.ProcessId,
                At = HelperFiles.Now(_clock),
            }.Write(_path);
            _lastRenewal = _clock.GetTimestamp();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A reader held the file during the rename; the next second retries.
            _log.Debug("node.heartbeat.write_failed", new LogField("errorType", exception.GetType().Name));
        }
    }

    /// <summary>Stops the probe loop.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _stop.Cancel();
        try
        {
            _probeLoop.Wait(TimeSpan.FromSeconds(2));
        }
        catch (AggregateException)
        {
        }

        _stop.Dispose();
    }

    private async Task ProbeLoopAsync()
    {
        using var timer = new PeriodicTimer(Interval);
        try
        {
            while (await timer.WaitForNextTickAsync(_stop.Token).ConfigureAwait(false))
            {
                IHeartbeatProbe[] probes;
                lock (_gate)
                {
                    probes = [.. _probes];
                }

                if (probes.Length == 0)
                {
                    continue;
                }

                var answered = true;
                foreach (var probe in probes)
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                    timeout.CancelAfter(ProbeTimeout);
                    var call = probe.ProbeAsync(timeout.Token);
                    var finished = await Task.WhenAny(call, Task.Delay(ProbeTimeout, _stop.Token)).ConfigureAwait(false);
                    if (finished != call || call.IsFaulted || call.IsCanceled)
                    {
                        answered = false;
                        _log.Warning("node.heartbeat.probe_missed", new LogField("probe", probe.Name), new LogField("misses", Misses + 1));
                        break;
                    }
                }

                if (answered)
                {
                    Volatile.Write(ref _misses, 0);
                }
                else
                {
                    Interlocked.Increment(ref _misses);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }
}
