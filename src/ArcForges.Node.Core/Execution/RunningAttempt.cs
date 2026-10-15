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

    /// <summary>Escaped processes already recorded: (pid, creation ticks).</summary>
    internal HashSet<(int Pid, long StartTicks)> KnownEscaped { get; } = [];

    /// <summary>Why the node stops the attempt.</summary>
    internal TerminationReason? StopReason { get; set; }

    /// <summary>What the stop did (graceful outcome, escaped processes).</summary>
    internal string? StopDetail { get; set; }

    /// <summary>When the graceful phase ends (monotonic).</summary>
    internal long? GraceDeadline { get; set; }

    /// <summary>The forced phase ran.</summary>
    internal bool Forced { get; set; }

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
