// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Foundation;

namespace ArcForges.Observability.Desktop;

/// <summary>The library's own diagnostic events. They go to the local store only, never to telemetry.</summary>
internal enum DiagnosticEventKind
{
    ConsentGranted,
    ConsentRevoked,
    VerboseStarted,
    VerboseStopped,
    VerboseExpired,
    CrashRecorded,
    ReportGenerated,
    ReportApproved,
    ReportSent,
    ReportCancelled,
}

/// <summary>
/// The minimal, always-on local tier (observability architecture DG-02): a bounded, rotating log of reviewed
/// diagnostic entries in a host-chosen local directory. It has no upload member and does not read telemetry consent.
/// Rotation keeps it inside a size, age and count budget (quality contract DG-05). Writes are best effort: a failing
/// disk drops the entry and never fails the caller, because a diagnostic must not break the operation it describes.
/// </summary>
internal sealed class LocalDiagnosticStore : IStructuredEventSink
{
    internal const string SegmentPrefix = "diagnostics-";
    internal const string SegmentSuffix = ".jsonl";
    internal const int MaxEntriesPerRead = 1000;

    private readonly object _gate = new();
    private readonly string _directory;
    private readonly DesktopDiagnosticsOptions _options;
    private readonly IClock _clock;
    private readonly VerboseDiagnosticSession _verbose;
    private long _writeFailures;

    internal LocalDiagnosticStore(string directory, DesktopDiagnosticsOptions options, IClock clock, VerboseDiagnosticSession verbose)
    {
        _directory = directory;
        _options = options;
        _clock = clock;
        _verbose = verbose;
        lock (_gate)
        {
            // After a long idle period even the newest segment can be older than the age budget; none is kept then.
            Prune(keepSequence: null);
        }
    }

    /// <summary>How many entries were dropped because the local disk could not be written.</summary>
    internal long WriteFailures => Interlocked.Read(ref _writeFailures);

    /// <summary>
    /// Keeps a typed structured signal. Events below Information are kept only while a verbose session is active.
    /// </summary>
    public void Write(StructuredSignal signal)
    {
        ArgumentNullException.ThrowIfNull(signal);
        bool detail = signal.Level < SignalLevel.Information;
        if (detail && !_verbose.IsActive)
        {
            return;
        }

        Append(signal.OccurredAt, DiagnosticEntryFormat.NormalizeName(signal.Name), signal.Level,
            detail ? DiagnosticTier.VerboseSession : DiagnosticTier.LocalMinimal,
            DiagnosticEntryFormat.ValidateFields(signal.Properties));
    }

    internal void Record(DiagnosticEventKind kind, IEnumerable<KeyValuePair<string, object?>>? fields = null)
    {
        (string name, DiagnosticTier tier) = Describe(kind);
        Append(_clock.GetCurrentInstant().ToDateTimeOffset(), name, SignalLevel.Information, tier,
            DiagnosticEntryFormat.ValidateFields(fields ?? []));
    }

    /// <summary>
    /// The newest entries, oldest first. A line that is not a valid entry is skipped and counted. The segment list is taken
    /// under the write lock but the files are read outside it, so building a report or a view never stalls the event path; a
    /// segment removed or half-written while it is read costs entries from the view, never the writer.
    /// </summary>
    internal IReadOnlyList<LocalDiagnosticEntry> ReadRecent(int maxEntries, out int skipped)
    {
        skipped = 0;
        var newestFirst = new List<LocalDiagnosticEntry>();
        List<string> newestSegmentsFirst;
        lock (_gate)
        {
            newestSegmentsFirst = Segments().Select(segment => segment.Path).Reverse().ToList();
        }

        foreach (string path in newestSegmentsFirst)
        {
            byte[] bytes;
            try
            {
                bytes = ReadSegment(path);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            int end = bytes.Length;
            while (end > 0 && newestFirst.Count < maxEntries)
            {
                int start = end - 1;
                while (start > 0 && bytes[start - 1] != (byte)'\n')
                {
                    start--;
                }

                ReadOnlySpan<byte> line = bytes.AsSpan(start, end - start);
                end = start;
                line = line.TrimEnd((byte)'\n').TrimEnd((byte)'\r');
                if (line.IsEmpty)
                {
                    continue;
                }

                if (line.Length <= DiagnosticEntryFormat.MaxLineBytes
                    && DiagnosticEntryFormat.TryParse(line, out LocalDiagnosticEntry? entry))
                {
                    newestFirst.Add(entry!);
                }
                else
                {
                    skipped++;
                }
            }

            if (newestFirst.Count >= maxEntries)
            {
                break;
            }
        }

        newestFirst.Reverse();
        return newestFirst;
    }

    private static byte[] ReadSegment(string path)
    {
        const FileShare sharing = FileShare.ReadWrite | FileShare.Delete;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, sharing);
        var bytes = new byte[stream.Length];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private void Append(DateTimeOffset occurredAt, string name, SignalLevel level, DiagnosticTier tier, Dictionary<string, object?> fields)
    {
        byte[] line = DiagnosticEntryFormat.Serialize(occurredAt, name, level, tier, fields);
        if (line.Length > DiagnosticEntryFormat.MaxLineBytes)
        {
            return;
        }

        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(_directory);
                long sequence = CurrentSequence();
                string path = SegmentPath(sequence);
                long length = File.Exists(path) ? new FileInfo(path).Length : 0;
                if (length > 0 && length + line.Length > _options.MaximumSegmentBytes)
                {
                    sequence++;
                    path = SegmentPath(sequence);
                    Prune(keepSequence: sequence);
                }

                using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
                stream.Write(line);
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                Interlocked.Increment(ref _writeFailures);
            }
        }
    }

    private long CurrentSequence()
    {
        long highest = 0;
        foreach ((long sequence, _) in Segments())
        {
            highest = Math.Max(highest, sequence);
        }

        return highest == 0 ? 1 : highest;
    }

    private string SegmentPath(long sequence) =>
        Path.Combine(_directory, SegmentPrefix + sequence.ToString("D8", CultureInfo.InvariantCulture) + SegmentSuffix);

    private List<(long Sequence, string Path)> Segments()
    {
        var segments = new List<(long, string)>();
        if (!Directory.Exists(_directory))
        {
            return segments;
        }

        foreach (string path in Directory.EnumerateFiles(_directory, SegmentPrefix + "*" + SegmentSuffix))
        {
            string name = Path.GetFileName(path);
            string digits = name[SegmentPrefix.Length..^SegmentSuffix.Length];
            if (digits.Length == 8 && long.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out long sequence) && sequence > 0)
            {
                segments.Add((sequence, path));
            }
        }

        segments.Sort((left, right) => left.Item1.CompareTo(right.Item1));
        return segments;
    }

    /// <summary>
    /// Deletes segments beyond the count budget and segments whose newest write is older than the age budget, except the
    /// one about to be written. The age budget is therefore met per segment, not per entry.
    /// </summary>
    private void Prune(long? keepSequence)
    {
        try
        {
            DateTime oldest = _clock.GetCurrentInstant().ToDateTimeOffset().UtcDateTime - _options.MaximumAge;
            List<(long Sequence, string Path)> segments = Segments();
            int excess = segments.Count - _options.MaximumSegments + (keepSequence is { } keep && segments.All(segment => segment.Sequence != keep) ? 1 : 0);
            foreach ((long sequence, string path) in segments)
            {
                if (sequence == keepSequence)
                {
                    continue;
                }

                if (excess > 0 || File.GetLastWriteTimeUtc(path) < oldest)
                {
                    File.Delete(path);
                    excess--;
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            Interlocked.Increment(ref _writeFailures);
        }
    }

    private static (string Name, DiagnosticTier Tier) Describe(DiagnosticEventKind kind) => kind switch
    {
        DiagnosticEventKind.ConsentGranted => ("diagnostics.consent.granted", DiagnosticTier.LocalMinimal),
        DiagnosticEventKind.ConsentRevoked => ("diagnostics.consent.revoked", DiagnosticTier.LocalMinimal),
        DiagnosticEventKind.VerboseStarted => ("diagnostics.verbose.started", DiagnosticTier.VerboseSession),
        DiagnosticEventKind.VerboseStopped => ("diagnostics.verbose.stopped", DiagnosticTier.VerboseSession),
        DiagnosticEventKind.VerboseExpired => ("diagnostics.verbose.expired", DiagnosticTier.VerboseSession),
        DiagnosticEventKind.CrashRecorded => ("diagnostics.crash.recorded", DiagnosticTier.LocalMinimal),
        DiagnosticEventKind.ReportGenerated => ("diagnostics.report.generated", DiagnosticTier.UserApprovedReport),
        DiagnosticEventKind.ReportApproved => ("diagnostics.report.approved", DiagnosticTier.UserApprovedReport),
        DiagnosticEventKind.ReportSent => ("diagnostics.report.sent", DiagnosticTier.UserApprovedReport),
        DiagnosticEventKind.ReportCancelled => ("diagnostics.report.cancelled", DiagnosticTier.UserApprovedReport),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };
}
