// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Platform;
using Microsoft.Win32.SafeHandles;
using OutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.Core.Execution;

/// <summary>
/// One attempt the supervisor is responsible for: its container handle, the output tailer's position (<c>index.bin</c>), the limits
/// it enforces, the stop sequence in progress and the attached stdin writer.
/// </summary>
public sealed class RunningAttempt : IDisposable
{
    private readonly Lock _gate = new();
    private SafeFileHandle? _stdout;
    private SafeFileHandle? _stderr;
    private FileStream? _index;
    private readonly byte[] _record = new byte[OutputIndexRecord.Size];
    private readonly long[] _dropFrom = new long[2];
    private readonly long[] _lastDrop = new long[2];
    private long _peakObserved;

    internal RunningAttempt(byte[] attemptId, byte[] taskId, string name, int number, AttemptFiles files)
    {
        AttemptId = attemptId;
        TaskId = taskId;
        Name = name;
        Number = number;
        Files = files;
    }

    /// <summary>The attempt ID.</summary>
    public byte[] AttemptId { get; }

    /// <summary>The task ID.</summary>
    public byte[] TaskId { get; }

    /// <summary>The attempt's base32 name.</summary>
    public string Name { get; }

    /// <summary>The attempt number.</summary>
    public int Number { get; }

    /// <summary>The attempt's files.</summary>
    public AttemptFiles Files { get; }

    /// <summary>The container handle, once launched or re-opened.</summary>
    public IAttemptHandle? Handle { get; internal set; }

    /// <summary>Pulsed when output was indexed or the attempt changed.</summary>
    public AsyncPulse Changed { get; } = new();

    /// <summary>The attempt dies with the node.</summary>
    public bool KillWithNode { get; internal set; }

    /// <summary>Output is discarded (no files).</summary>
    public bool DiscardOutput { get; internal set; }

    /// <summary>When the root started (monotonic timestamp), for the wall-clock timeout.</summary>
    public long? StartedTimestamp { get; internal set; }

    /// <summary><c>timeout_ms</c>.</summary>
    public ulong? TimeoutMs { get; internal set; }

    /// <summary><c>cpu_time_limit_ms</c>.</summary>
    public ulong? CpuLimitMs { get; internal set; }

    /// <summary><c>cancel_grace_ms</c>.</summary>
    public TimeSpan CancelGrace { get; internal set; } = TimeSpan.FromSeconds(10);

    /// <summary><c>resources.stop_signal</c> (Linux; default SIGTERM).</summary>
    public string? StopSignal { get; internal set; }

    /// <summary>Recovered after a node restart.</summary>
    public bool NodeGap { get; internal set; }

    /// <summary>The next indexed chunk was written while the node was down.</summary>
    internal bool ApproximateNext { get; set; }

    /// <summary>Indexed bytes of stdout.</summary>
    public long StdoutIndexed { get; private set; }

    /// <summary>Indexed bytes of stderr.</summary>
    public long StderrIndexed { get; private set; }

    /// <summary>Index records written.</summary>
    public long IndexRecords { get; private set; }

    /// <summary>The captured output size.</summary>
    public long OutputBytes => StdoutIndexed + StderrIndexed;

    /// <summary>The root process has been recorded (RUNNING).</summary>
    internal bool RootRecorded { get; set; }

    /// <summary>The finalization started.</summary>
    internal bool Finalizing { get; set; }

    /// <summary>The finalization found processes left after the forced phase (TERMINATION_INCOMPLETE).</summary>
    internal bool FinalizeIncomplete { get; set; }

    /// <summary>A failed finalization is retried no earlier than this (monotonic).</summary>
    internal long? FinalizeNotBefore { get; set; }

    /// <summary>When the ancestry scan for escaped processes last ran (monotonic).</summary>
    internal long LastEscapeScan { get; set; } = long.MinValue;

    /// <summary>
    /// Escaped processes already recorded: (pid, creation ticks) with the image; the resource monitor reads them for the process labels, and
    /// the stop sequence terminates them (04 section 6 step 4).
    /// </summary>
    internal System.Collections.Concurrent.ConcurrentDictionary<(int Pid, long StartTicks), string> KnownEscaped { get; } = new();

    /// <summary>
    /// Escaped processes the stop sequence has dealt with (terminated, already gone, or another user's): (pid, creation in store
    /// microseconds). They are never touched again.
    /// </summary>
    internal System.Collections.Concurrent.ConcurrentDictionary<(int Pid, long StartMicros), bool> EscapedHandled { get; } = new();

    /// <summary>
    /// Escaped processes found but not yet recorded in the store (pid, creation ticks): a record write that could not be queued or did not
    /// commit is written again by the next scan, and finalization writes what is left with the attempt's record.
    /// </summary>
    internal System.Collections.Concurrent.ConcurrentDictionary<(int Pid, long StartTicks), EscapedProcess> UnrecordedEscaped { get; } = new();

    /// <summary>1 while a write of <see cref="UnrecordedEscaped"/> is queued (one at a time).</summary>
    internal int EscapedWriting;

    /// <summary>The escaped processes the stop sequence terminated, as <c>image (pid)</c> (04 section 6 step 4).</summary>
    internal List<string> EscapedTerminated { get; } = [];

    /// <summary>The graceful phase of the stop (the console signal or <c>KillUnit</c>, and its detail), once it was started.</summary>
    internal Task? GracefulPhase { get; set; }

    /// <summary>Why the node stops the attempt.</summary>
    internal TerminationReason? StopReason { get; set; }

    /// <summary>What the stop did (the graceful outcome, a guard's or a pressure stop's reason).</summary>
    internal string? StopDetail { get; set; }

    /// <summary>
    /// The stop's detail for the record: <see cref="StopDetail"/> and the escaped processes the stop terminated, composed when it is read,
    /// so neither part is lost to the order in which they were recorded.
    /// </summary>
    internal string? StopDetailText => EscapedTerminated.Count == 0
        ? StopDetail
        : (StopDetail is null ? string.Empty : StopDetail + "; ") + "escaped processes terminated: " + string.Join(", ", EscapedTerminated);

    /// <summary>When the graceful phase ends (monotonic).</summary>
    internal long? GraceDeadline { get; set; }

    /// <summary>The forced phase ran.</summary>
    internal bool Forced { get; set; }

    /// <summary>
    /// A forced phase ran while the attempt's start was pending, or while its re-opened handle watched a launch that may still go on: one more
    /// termination is owed to the late start, made by the start's continuation (or the handle's report) or by a verification that finds the
    /// late start in the container first (<c>ExecutionSupervisor.TerminateWhenStarted</c>, <c>TerminateEachLaunchProcess</c>).
    /// </summary>
    internal bool TerminationOwed { get; set; }

    /// <summary>
    /// A forced phase subscribed to the processes that enter the attempt's re-opened container
    /// (<c>ExecutionSupervisor.TerminateEachLaunchProcess</c>).
    /// </summary>
    internal bool LaunchProcessesWatched { get; set; }

    /// <summary>When the verification window ends (monotonic).</summary>
    internal long? VerifyDeadline { get; set; }

    /// <summary><c>NODE</c> when the node stopped it for a disk limit.</summary>
    internal string? LimitEnforcedBy { get; set; }

    /// <summary>The NOTIFY finding for the output limit was raised.</summary>
    internal bool OutputNotified { get; set; }

    /// <summary>The CPU time last read (milliseconds).</summary>
    internal long LastCpuCheck { get; set; } = long.MinValue;

    /// <summary>When the offsets were last persisted (monotonic).</summary>
    internal long LastPersist { get; set; }

    /// <summary>The attach that may write stdin.</summary>
    internal string? StdinAttach { get; set; }

    /// <summary>Stdin bytes accepted.</summary>
    internal long StdinAccepted { get; set; }

    /// <summary>Stdin was closed.</summary>
    internal bool StdinClosed { get; set; }

    /// <summary>Serializes stdin writes.</summary>
    internal Lock StdinGate { get; } = new();

    /// <summary>The task's priority (the pressure actions of 03 section 7 go from the lowest up).</summary>
    public Priority Priority { get; internal set; } = Priority.Normal;

    /// <summary>The working directory (its volume is watched, 03 section 1).</summary>
    public string? WorkingDirectory { get; internal set; }

    /// <summary><c>resources.preemptible</c>: the pressure response may stop the attempt (03 section 7).</summary>
    public bool Preemptible { get; internal set; }

    /// <summary>
    /// <c>peak_observed</c> (03 section 3): the highest sampled resident use of the container without reclaimable page cache. It only
    /// rises while the attempt runs.
    /// </summary>
    public long PeakObserved => Interlocked.Read(ref _peakObserved);

    /// <summary>The last usage sample: processor time and when it was read (monotonic), for the CPU rate.</summary>
    internal (long CpuTimeMs, long Timestamp)? LastUsage { get; set; }

    /// <summary>The last usage sample of the container.</summary>
    internal AttemptUsage? Usage { get; set; }

    /// <summary>The CPU rate of the last sample, in millicores.</summary>
    internal long CpuMillicores { get; set; }

    /// <summary>The attempt was seen crossing into a virtual machine (03 section 9); logged once.</summary>
    internal bool CrossingReported { get; set; }

    /// <summary>The task's pool (admission counts the attempt against it).</summary>
    public string Pool { get; internal set; } = "default";

    /// <summary>The task's session (base32), or <see langword="null"/>.</summary>
    public string? Session { get; internal set; }

    /// <summary>The task's workspace (base32), or <see langword="null"/>.</summary>
    public string? Workspace { get; internal set; }

    /// <summary><c>mem_expected</c> of the attempt's request.</summary>
    public long MemExpected { get; internal set; }

    /// <summary><c>mem_ceiling</c> of the attempt's request.</summary>
    public long MemCeiling { get; internal set; }

    /// <summary>The CPU grant: <c>min(cpu_demand, B_cpu)</c> at admission (03 section 4).</summary>
    public long CpuGrant { get; internal set; }

    /// <summary><c>accounted_mem = max(mem_expected, peak_observed)</c> (03 section 3).</summary>
    public long AccountedMemory => Math.Max(MemExpected, PeakObserved);

    /// <summary>A light routed command (outside pool limits).</summary>
    public bool Light { get; internal set; }

    /// <summary><c>resources.pausable</c>: the pressure response may freeze the attempt (03 section 7).</summary>
    public bool Pausable { get; internal set; }

    /// <summary>The soft memory limit the attempt was launched with (Linux <c>MemoryHigh</c>), restored when a pressure freeze ends.</summary>
    internal long MemoryHighBytes { get; set; }

    /// <summary>The keys the attempt holds (released keys are removed); guarded by the attempt's lock.</summary>
    internal List<Scheduling.HeldKey> Keys { get; } = [];

    /// <summary>The readiness condition of a SERVICE attempt, or <see langword="null"/>.</summary>
    internal Scheduling.ServiceReadiness? Readiness { get; set; }

    /// <summary>The readiness condition held (recorded <c>ready=true</c>).</summary>
    internal bool Ready { get; set; }

    /// <summary><c>readiness_timeout</c> passed without the condition.</summary>
    internal bool ReadinessTimedOut { get; set; }

    /// <summary>The attempt is frozen (PAUSED).</summary>
    internal bool Paused { get; set; }

    /// <summary>The freeze came from the Pressure level (thawed after 30 s at Normal), not from <c>PauseTask</c>.</summary>
    internal bool PausedByPressure { get; set; }

    /// <summary>A freeze or a thaw is posted and not yet done.</summary>
    internal bool PauseInFlight { get; set; }

    /// <summary>When the current pause began (monotonic), or <see cref="long.MinValue"/>.</summary>
    internal long PausedSince { get; set; } = long.MinValue;

    /// <summary>The paused time of earlier pauses (stopwatch ticks).</summary>
    internal long PausedTicks { get; set; }

    /// <summary>The time the attempt was paused, the current pause included (the wall-clock timeout does not count it).</summary>
    internal TimeSpan PausedTime(TimeProvider clock) =>
        TimeSpan.FromSeconds((double)PausedTicks / clock.TimestampFrequency) + (PausedSince == long.MinValue ? TimeSpan.Zero : clock.GetElapsedTime(PausedSince));

    /// <summary>Raises <see cref="PeakObserved"/> to <paramref name="memory"/> when it is higher; returns the peak.</summary>
    internal long Observe(long memory)
    {
        var peak = Interlocked.Read(ref _peakObserved);
        while (memory > peak)
        {
            var seen = Interlocked.CompareExchange(ref _peakObserved, memory, peak);
            if (seen == peak)
            {
                return memory;
            }

            peak = seen;
        }

        return peak;
    }

    /// <summary>Opens the output files for size reads and <c>index.bin</c> for appends, resuming after the complete records.</summary>
    internal void OpenTail()
    {
        lock (_gate)
        {
            if (DiscardOutput)
            {
                return;
            }

            var records = OutputIndexFile.Read(Files.IndexPath, 0, out var complete);
            StdoutIndexed = records.Where(record => record.Stream == OutputStreamKind.Stdout).Select(record => record.End).DefaultIfEmpty(0).Max();
            StderrIndexed = records.Where(record => record.Stream == OutputStreamKind.Stderr).Select(record => record.End).DefaultIfEmpty(0).Max();
            IndexRecords = records.Count;
            _index = new FileStream(Files.IndexPath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            _index.SetLength(complete);
            _index.Position = complete;
        }
    }

    /// <summary>
    /// One tailer read (04 section 4): appends an index record for the new bytes of each stream. Returns true when output was indexed.
    /// </summary>
    internal bool Tail(long unixNanos)
    {
        lock (_gate)
        {
            if (DiscardOutput || _index is null)
            {
                return false;
            }

            var appended = false;
            foreach (var stream in (OutputStreamKind[])[OutputStreamKind.Stdout, OutputStreamKind.Stderr])
            {
                var handle = Open(stream);
                if (handle is null)
                {
                    continue;
                }

                long length;
                try
                {
                    length = RandomAccess.GetLength(handle);
                }
                catch (IOException)
                {
                    continue;
                }

                var indexed = stream == OutputStreamKind.Stdout ? StdoutIndexed : StderrIndexed;
                while (length > indexed)
                {
                    var chunk = (uint)Math.Min(length - indexed, OutputIndexRecord.MaxLength);
                    new OutputIndexRecord(stream, indexed, chunk, unixNanos, ApproximateNext ? OutputChunkMarks.ApproximateTime : OutputChunkMarks.None).Write(_record);
                    _index.Write(_record);
                    indexed += chunk;
                    IndexRecords++;
                    appended = true;
                }

                if (stream == OutputStreamKind.Stdout)
                {
                    StdoutIndexed = indexed;
                }
                else
                {
                    StderrIndexed = indexed;
                }

                // Linux: indexed output leaves the page cache (charged to the attempt); the previous range again, now written back.
                var slot = stream == OutputStreamKind.Stdout ? 0 : 1;
                var previous = _dropFrom[slot];
                if (indexed > previous)
                {
                    Platform.PageCache.Drop(handle, _lastDrop[slot], indexed - _lastDrop[slot]);
                    _lastDrop[slot] = previous;
                    _dropFrom[slot] = indexed;
                }
            }

            if (appended)
            {
                _index.Flush();
                ApproximateNext = false;
            }

            return appended;
        }
    }

    /// <summary>Closes the tailer's files and the container handle.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            _index?.Dispose();
            _index = null;
            _stdout?.Dispose();
            _stderr?.Dispose();
            _stdout = null;
            _stderr = null;
        }

        Handle?.Dispose();
    }

    private SafeFileHandle? Open(OutputStreamKind stream)
    {
        ref var handle = ref stream == OutputStreamKind.Stdout ? ref _stdout : ref _stderr;
        if (handle is null)
        {
            try
            {
                handle = File.OpenHandle(Files.OutputPath(stream), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            }
            catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        return handle;
    }
}
