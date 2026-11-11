// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ArcForges.Node.Core.Platform;
using Google.Protobuf;
using N = ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core.Files;

/// <summary>A query refusal with observations only for bytes actually read; never a pattern, body or match snippet.</summary>
internal sealed class WorkspaceQueryException(string reason, N.FileAuditMetadata? audit = null) : IOException(reason)
{
    internal string Reason { get; } = reason;
    internal N.FileAuditMetadata? Audit { get; } = audit;
}

/// <summary>The bounded search value and the mandatory signed-audit input for that exact scan.</summary>
internal sealed record WorkspaceSearchResult(N.FileServiceSearchFilesValue Value, N.FileAuditMetadata Audit);

internal sealed record WorkspaceDirectoryResult(N.FileServiceListDirectoryValue Value, N.FileAuditMetadata Audit);

/// <summary>
/// Queries an already authorized live workspace anchor. The application owns caller classification,
/// workspace-use leases, policy, transport metadata and durable audit. These methods never grant authority.
/// </summary>
internal sealed partial class WorkspaceFileQueries : IDisposable
{
    internal const int MaximumEntries = 10_000;
    internal const int MaximumFileBytes = 1_048_576;
    internal const ulong MaximumScanBytes = 8_388_608;
    internal const int MaximumMatches = 100;
    internal const int MaximumResponseBytes = 131_072;
    private const int ValueBudget = MaximumResponseBytes - 8192;
    private const int MaximumProblems = 32;
    private const int MaximumQueueBytes = 8_388_608;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly TimeSpan SearchBudget = TimeSpan.FromSeconds(5);
    private readonly TimeProvider _clock;

    internal WorkspaceFileQueries(TimeProvider? clock = null) => _clock = clock ?? TimeProvider.System;

    internal WorkspaceSearchResult Search(WorkspacePath root, string path, string pattern, N.FileSearchMode mode,
        int maximumMatches = MaximumMatches, ulong maximumBytes = MaximumScanBytes, CancellationToken cancellationToken = default) =>
        Search(root, path, pattern, mode, maximumMatches, maximumBytes, afterPrefixRead: null, cancellationToken);

    // Coordinates real file changes in tests. It neither substitutes data nor bypasses native opens.
    internal WorkspaceSearchResult Search(WorkspacePath root, string path, string pattern, N.FileSearchMode mode,
        int maximumMatches, ulong maximumBytes, Action<string>? afterPrefixRead, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(root);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed), this);
        _ = WorkspacePath.Components(path, allowRoot: true);
        if (maximumMatches is < 1 or > MaximumMatches || maximumBytes is < 1 or > MaximumScanBytes)
        {
            throw new WorkspaceQueryException("query_limit_invalid");
        }

        try
        {
            if (StrictUtf8.GetByteCount(pattern) is < 1 or > 1024)
            {
                throw new WorkspaceQueryException("pattern_length");
            }
        }
        catch (EncoderFallbackException)
        {
            throw new WorkspaceQueryException("pattern_invalid_utf8");
        }

        var started = _clock.GetTimestamp();
        using var workBudget = new CancellationTokenSource(SearchBudget, _clock);
        using var workCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, workBudget.Token);
        Regex? expression = null;
        if (mode == N.FileSearchMode.Regex)
        {
            try
            {
                expression = new Regex(pattern, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(100));
            }
            catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
            {
                // Regex exceptions can contain the private pattern. Do not retain them.
                throw new WorkspaceQueryException("pattern_unsupported");
            }
        }
        else if (mode != N.FileSearchMode.Literal)
        {
            throw new WorkspaceQueryException("pattern_mode");
        }

        using var scan = new SearchScan();
        WorkspaceSearchResult Finish()
        {
            CheckCancellation(scan, cancellationToken);
            return scan.Finish();
        }

        var pending = new Stack<string>();
        pending.Push(path);
        var queuedBytes = QueueCharge(path);
        while (pending.Count != 0)
        {
            CheckCancellation(scan, cancellationToken);
            if (Expired(started))
            {
                scan.Truncate("time_limit");
                break;
            }

            var current = pending.Pop();
            queuedBytes -= QueueCharge(current);
            scan.Value.VisitedEntries++;
            WorkspaceEntryMetadata metadata;
            try
            {
                metadata = root.InspectEntry(current, allowRoot: current.Length == 0);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                if (scan.Value.VisitedEntries == 1)
                {
                    throw new WorkspaceQueryException(ClosedReason(exception), scan.PartialAudit());
                }

                scan.Problem(current, ClosedReason(exception));
                scan.Value.SkippedFiles++;
                continue;
            }

            if (metadata.Kind == WorkspaceEntryType.Directory)
            {
                var remaining = MaximumEntries - checked((int)scan.Value.VisitedEntries) - pending.Count;
                if (remaining == 0)
                {
                    scan.Truncate("entry_limit");
                    continue;
                }

                WorkspaceDirectoryPage names;
                try
                {
                    names = WorkspaceDirectoryEntries.Read(root, current, remaining, workCancellation.Token);
                    var after = root.InspectEntry(current, allowRoot: current.Length == 0);
                    if (!metadata.Identity.SameObject(after.Identity) || metadata.Stamp != after.Stamp)
                    {
                        throw new WorkspacePathException("directory_changed");
                    }
                }
                catch (OperationCanceledException)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        throw new WorkspaceQueryException("query_cancelled", scan.PartialAudit());
                    }

                    scan.Truncate("time_limit");
                    return Finish();
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    scan.Problem(current, ClosedReason(exception));
                    scan.Value.SkippedFiles++;
                    continue;
                }

                if (names.Truncated)
                {
                    scan.Truncate("entry_limit");
                }

                // Reverse push retains the actual deterministic ordinal traversal in the transcript.
                for (var index = names.Names.Count - 1; index >= 0; index--)
                {
                    var child = current.Length == 0 ? names.Names[index] : current + "/" + names.Names[index];
                    try
                    {
                        _ = WorkspacePath.Components(child);
                    }
                    catch (WorkspacePathException exception)
                    {
                        scan.Problem(current, exception.Reason);
                        scan.Value.SkippedFiles++;
                        continue;
                    }

                    var charge = QueueCharge(child);
                    if (queuedBytes > MaximumQueueBytes - charge)
                    {
                        scan.Problem(child, "scan_queue_limit");
                        scan.Value.SkippedFiles++;
                        continue;
                    }

                    pending.Push(child);
                    queuedBytes += charge;
                }

                continue;
            }

            if (metadata.Kind != WorkspaceEntryType.File || metadata.Identity.Links != 1)
            {
                if (scan.Value.VisitedEntries == 1)
                {
                    throw new WorkspaceQueryException("path_link_or_special", scan.PartialAudit());
                }

                scan.Problem(current, metadata.Identity.Links != 1 ? "file_hard_link" : "path_link_or_special");
                scan.Value.SkippedFiles++;
                continue;
            }

            if (scan.Value.ScannedBytes == maximumBytes)
            {
                scan.Truncate("scan_bytes");
                break;
            }

            byte[] bytes;
            var count = 0;
            var cut = false;
            try
            {
                using var file = root.OpenRead(current);
                var opened = WorkspacePath.Identity(file);
                var initial = WorkspacePath.FileStamp(file);
                if (!metadata.Identity.SameObject(opened) || !opened.IsFile || opened.Links != 1 || initial.Size < 0)
                {
                    throw new WorkspacePathException("file_changed");
                }

                var requested = checked((int)Math.Min((ulong)MaximumFileBytes, Math.Min(maximumBytes - scan.Value.ScannedBytes, (ulong)initial.Size)));
                bytes = new byte[requested];
                try
                {
                    while (count != bytes.Length)
                    {
                        CheckCancellation(scan, cancellationToken);
                        if (Expired(started))
                        {
                            scan.Truncate("time_limit");
                            break;
                        }

                        var part = bytes.AsSpan(count, Math.Min(16_384, bytes.Length - count));
                        var read = RandomAccess.Read(file, part, count);
                        if (read == 0)
                        {
                            break;
                        }

                        count += read;
                    }
                }
                finally
                {
                    // Length is known before bytes are appended, including partial I/O and detection prefixes.
                    scan.Append(current, bytes.AsSpan(0, count));
                }

                afterPrefixRead?.Invoke(current);
                CheckCancellation(scan, cancellationToken);
                var final = WorkspacePath.Identity(file);
                var named = root.InspectEntry(current);
                if (!opened.SameObject(final) || final.Links != 1 || !final.IsFile || initial != WorkspacePath.FileStamp(file) ||
                    !opened.SameObject(named.Identity) || initial != named.Stamp)
                {
                    throw new WorkspacePathException("file_changed");
                }

                cut = (ulong)count < (ulong)initial.Size;
                if (cut)
                {
                    scan.Truncate(scan.Value.ScannedBytes == maximumBytes ? "scan_bytes" : Expired(started) ? "time_limit" : "file_bytes");
                }
            }
            catch (WorkspaceQueryException exception) when (exception.Reason == "query_cancelled")
            {
                throw new WorkspaceQueryException("query_cancelled", scan.PartialAudit());
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                scan.Problem(current, ClosedReason(exception));
                scan.Value.SkippedFiles++;
                continue;
            }

            if (bytes.AsSpan(0, count).Contains((byte)0))
            {
                scan.Problem(current, "binary_file");
                scan.Value.SkippedFiles++;
                continue;
            }

            var complete = CompleteUtf8Prefix(bytes.AsSpan(0, count), cut);
            if (complete < 0)
            {
                scan.Problem(current, "invalid_utf8");
                scan.Value.SkippedFiles++;
                continue;
            }

            var text = StrictUtf8.GetString(bytes, 0, complete);
            var scalarBytes = ScalarOffsets(text);
            var next = 0;
            try
            {
                while (next <= text.Length)
                {
                    CheckCancellation(scan, cancellationToken);
                    if (Expired(started))
                    {
                        scan.Truncate("time_limit");
                        return Finish();
                    }

                    int position;
                    int length;
                    if (expression is null)
                    {
                        position = text.IndexOf(pattern, next, StringComparison.Ordinal);
                        length = pattern.Length;
                    }
                    else
                    {
                        // Leave the configured match-timeout margin inside the whole-search work budget.
                        if (_clock.GetElapsedTime(started) >= SearchBudget - TimeSpan.FromMilliseconds(100))
                        {
                            scan.Truncate("time_limit");
                            return Finish();
                        }

                        var match = expression.Match(text, next);
                        if (!match.Success)
                        {
                            break;
                        }

                        position = match.Index;
                        length = match.Length;
                    }

                    if (position < 0)
                    {
                        break;
                    }

                    if (scalarBytes[position] < 0 || scalarBytes[position + length] < 0)
                    {
                        throw new WorkspaceQueryException("regex_scalar_boundary", scan.Audit());
                    }

                    var entry = new N.FileMatch
                    {
                        Path = current,
                        ByteOffset = checked((ulong)scalarBytes[position]),
                        ByteLength = checked((uint)(scalarBytes[position + length] - scalarBytes[position])),
                    };
                    scan.Value.Matches.Add(entry);
                    if (scan.Value.CalculateSize() > ValueBudget)
                    {
                        scan.Value.Matches.RemoveAt(scan.Value.Matches.Count - 1);
                        scan.Truncate("response_bytes");
                        return Finish();
                    }

                    if (scan.Value.Matches.Count == maximumMatches)
                    {
                        scan.Truncate("match_limit");
                        return Finish();
                    }

                    if (length == 0)
                    {
                        if (position == text.Length)
                        {
                            break;
                        }

                        _ = Rune.DecodeFromUtf16(text.AsSpan(position), out _, out var consumed);
                        next = position + consumed;
                    }
                    else
                    {
                        next = position + length;
                    }
                }
            }
            catch (RegexMatchTimeoutException)
            {
                scan.Truncate("regex_timeout");
                return Finish();
            }
        }

        return Finish();
    }

    private bool Expired(long started) => _clock.GetElapsedTime(started) >= SearchBudget;

    private static int QueueCharge(string path) => checked(64 + path.Length * 2);

    private static void CheckCancellation(SearchScan scan, CancellationToken token)
    {
        if (token.IsCancellationRequested)
        {
            throw new WorkspaceQueryException("query_cancelled", scan.PartialAudit());
        }
    }

    private static string ClosedReason(Exception exception) => exception is WorkspacePathException path ? path.Reason : "file_access_denied";

    private static int CompleteUtf8Prefix(ReadOnlySpan<byte> bytes, bool cut)
    {
        var offset = 0;
        while (offset < bytes.Length)
        {
            var status = Rune.DecodeFromUtf8(bytes[offset..], out _, out var consumed);
            if (status == OperationStatus.NeedMoreData)
            {
                return cut && bytes.Length - offset <= 3 ? offset : -1;
            }

            if (status != OperationStatus.Done)
            {
                return -1;
            }

            offset += consumed;
        }

        return offset;
    }

    private static int[] ScalarOffsets(string text)
    {
        var map = new int[text.Length + 1];
        Array.Fill(map, -1);
        var character = 0;
        var bytes = 0;
        map[0] = 0;
        while (character < text.Length)
        {
            _ = Rune.DecodeFromUtf16(text.AsSpan(character), out var rune, out var consumed);
            character += consumed;
            bytes += rune.Utf8SequenceLength;
            map[character] = bytes;
        }

        return map;
    }


    internal const int MaximumSnapshots = 64;
    internal const long MaximumSnapshotBytes = 16_777_216;
    private static readonly TimeSpan CursorLifetime = TimeSpan.FromSeconds(60);
    private readonly Lock _snapshotGate = new();
    private readonly Dictionary<string, DirectorySnapshot> _snapshots = new(StringComparer.Ordinal);
    private readonly byte[] _cursorKey = RandomNumberGenerator.GetBytes(32);
    private long _snapshotBytes;
    private bool _disposed;

    internal (int Count, long Bytes) SnapshotUsage
    {
        get
        {
            lock (_snapshotGate)
            {
                PruneSnapshots();
                return (_snapshots.Count, _snapshotBytes);
            }
        }
    }

    /// <summary>One-directory metadata pages. Caller binding must come from the authenticated application context.</summary>
    internal WorkspaceDirectoryResult ListDirectory(WorkspacePath root, ReadOnlySpan<byte> workspaceId, ReadOnlySpan<byte> callerBinding,
        string path, int pageSize = 100, string? cursor = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(root);
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed), this);
        _ = WorkspacePath.Components(path, allowRoot: true);
        if (workspaceId.Length != 16 || callerBinding.Length != 32 || pageSize is < 1 or > 128)
        {
            throw new WorkspaceQueryException("directory_arguments");
        }

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10), _clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        DirectorySnapshot snapshot;
        var start = 0;
        try
        {
            if (cursor is null)
            {
                var first = CaptureDirectory(root, path, linked.Token);
                var second = CaptureDirectory(root, path, linked.Token);
                if (!SameDirectory(first, second))
                {
                    throw new WorkspaceQueryException("directory_changed");
                }

                snapshot = new DirectorySnapshot(RandomNumberGenerator.GetBytes(16), workspaceId.ToArray(), callerBinding.ToArray(),
                    second, _clock.GetTimestamp());
                if (snapshot.Charge > MaximumSnapshotBytes)
                {
                    throw new WorkspaceQueryException("directory_snapshot_limit");
                }
            }
            else
            {
                (snapshot, start) = ReadCursor(cursor, workspaceId, callerBinding);
                DirectoryView current;
                try
                {
                    current = CaptureDirectory(root, path, linked.Token);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    throw new WorkspaceQueryException("invalid_cursor");
                }

                if (!SameDirectory(snapshot.View, current))
                {
                    throw new WorkspaceQueryException("invalid_cursor");
                }

                lock (_snapshotGate)
                {
                    PruneSnapshots();
                    if (!_snapshots.ContainsKey(Convert.ToHexString(snapshot.Id)))
                    {
                        throw new WorkspaceQueryException("invalid_cursor");
                    }
                }
            }

            linked.Token.ThrowIfCancellationRequested();
            var page = DirectoryPage(snapshot, start, pageSize);
            linked.Token.ThrowIfCancellationRequested();
            if (cursor is null && page.Value.HasNextCursor)
            {
                StoreSnapshot(snapshot);
            }

            return page;
        }
        catch (OperationCanceledException)
        {
            throw new WorkspaceQueryException(cancellationToken.IsCancellationRequested ? "query_cancelled" : "query_deadline");
        }
    }

    private static DirectoryView CaptureDirectory(WorkspacePath root, string path, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var directory = root.InspectEntry(path, allowRoot: path.Length == 0);
        if (directory.Kind != WorkspaceEntryType.Directory)
        {
            throw new WorkspaceQueryException("path_not_directory");
        }

        var names = WorkspaceDirectoryEntries.Read(root, path, MaximumEntries, cancellationToken);
        var entries = new SnapshotEntry[names.Names.Count];
        long charge = 512;
        for (var index = 0; index < entries.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = names.Names[index];
            var child = path.Length == 0 ? name : path + "/" + name;
            var metadata = root.InspectEntry(child);
            entries[index] = new SnapshotEntry(name, metadata);
            // Conservative managed-memory accounting includes record/array/token/name overhead.
            charge = checked(charge + 512 + name.Length * 2 + metadata.Identity.InstanceToken.Length * 2);
            if (charge > MaximumSnapshotBytes)
            {
                throw new WorkspaceQueryException("directory_snapshot_limit");
            }
        }

        var after = root.InspectEntry(path, allowRoot: path.Length == 0);
        if (!directory.Identity.SameObject(after.Identity) || directory.Stamp != after.Stamp)
        {
            throw new WorkspaceQueryException("directory_changed");
        }

        return new DirectoryView(directory, entries, names.Truncated, charge);
    }

    private static bool SameDirectory(DirectoryView first, DirectoryView second)
    {
        if (!first.Directory.Identity.SameObject(second.Directory.Identity) || first.Directory.Stamp != second.Directory.Stamp ||
            first.Overflow != second.Overflow || first.Entries.Length != second.Entries.Length)
        {
            return false;
        }

        for (var index = 0; index < first.Entries.Length; index++)
        {
            var a = first.Entries[index];
            var b = second.Entries[index];
            if (!a.Name.Equals(b.Name, StringComparison.Ordinal) || a.Metadata.Kind != b.Metadata.Kind || a.Metadata.Size != b.Metadata.Size ||
                !a.Metadata.Identity.SameObject(b.Metadata.Identity) || a.Metadata.Identity.Links != b.Metadata.Identity.Links ||
                a.Metadata.Stamp != b.Metadata.Stamp)
            {
                return false;
            }
        }

        return true;
    }

    private WorkspaceDirectoryResult DirectoryPage(DirectorySnapshot snapshot, int start, int pageSize)
    {
        if (start < 0 || start >= snapshot.View.Entries.Length)
        {
            // An empty first page is valid; a cursor can never address it or the position after EOF.
            if (start != 0 || snapshot.View.Entries.Length != 0)
            {
                throw new WorkspaceQueryException("invalid_cursor");
            }
        }

        var value = new N.FileServiceListDirectoryValue
        {
            Truncated = snapshot.View.Overflow,
            SnapshotEntries = checked((uint)snapshot.View.Entries.Length),
        };
        if (snapshot.View.Overflow)
        {
            value.Problems.Add(new N.FileScanProblem { Path = "", Reason = "entry_limit" });
        }

        var end = Math.Min(snapshot.View.Entries.Length, start + pageSize);
        for (var index = start; index < end; index++)
        {
            var source = snapshot.View.Entries[index];
            var entry = new N.FileDirectoryEntry { Name = source.Name, Kind = (N.FileEntryKind)source.Metadata.Kind };
            if (source.Metadata.Size is { } size)
            {
                entry.SizeBytes = size;
            }

            value.Entries.Add(entry);
        }

        while (true)
        {
            if (end < snapshot.View.Entries.Length)
            {
                value.NextCursor = WriteCursor(snapshot, end);
            }
            else
            {
                value.ClearNextCursor();
            }

            var audit = DirectoryAudit(value);
            var probe = new N.FileServiceListDirectoryResponse { Value = value, Audit = audit };
            if (probe.CalculateSize() + 8192 <= MaximumResponseBytes)
            {
                return new WorkspaceDirectoryResult(value, audit);
            }

            if (value.Entries.Count <= 1)
            {
                throw new WorkspaceQueryException("directory_response_limit");
            }

            value.Entries.RemoveAt(value.Entries.Count - 1);
            end--;
        }
    }

    private static N.FileAuditMetadata DirectoryAudit(N.FileServiceListDirectoryValue value)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        ReadOnlySpan<byte> domain = "ArcForges directory-list v1\0"u8;
        hash.AppendData(domain);
        var bytes = checked((ulong)domain.Length);
        Span<byte> frame = stackalloc byte[8];
        foreach (var entry in value.Entries)
        {
            var name = StrictUtf8.GetBytes(entry.Name);
            BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)name.Length));
            hash.AppendData(frame[..4]);
            hash.AppendData(name);
            BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)entry.Kind));
            hash.AppendData(frame[..4]);
            frame[0] = entry.HasSizeBytes ? (byte)1 : (byte)0;
            hash.AppendData(frame[..1]);
            bytes += checked((ulong)(9 + name.Length));
            if (entry.HasSizeBytes)
            {
                BinaryPrimitives.WriteUInt64BigEndian(frame, entry.SizeBytes);
                hash.AppendData(frame);
                bytes += 8;
            }
        }

        value.MetadataDigest = ByteString.CopyFrom(hash.GetHashAndReset());
        value.MetadataBytes = bytes;
        return new N.FileAuditMetadata
        {
            Observations =
            {
                new N.FileAuditObservation
                {
                    Kind = N.FileAuditKind.DirectoryMetadata,
                    SizeBytes = bytes,
                    DigestInputBytes = bytes,
                    Sha256 = value.MetadataDigest,
                    ItemCount = checked((uint)value.Entries.Count),
                },
            },
        };
    }

    private void StoreSnapshot(DirectorySnapshot snapshot)
    {
        lock (_snapshotGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            PruneSnapshots();
            while (_snapshots.Count >= MaximumSnapshots || _snapshotBytes > MaximumSnapshotBytes - snapshot.Charge)
            {
                var oldest = _snapshots.MinBy(static entry => entry.Value.Created);
                _snapshots.Remove(oldest.Key);
                _snapshotBytes -= oldest.Value.Charge;
            }

            var key = Convert.ToHexString(snapshot.Id);
            if (!_snapshots.TryAdd(key, snapshot))
            {
                throw new WorkspaceQueryException("directory_snapshot_unavailable");
            }

            _snapshotBytes += snapshot.Charge;
        }
    }

    private void PruneSnapshots()
    {
        var expired = _snapshots.Where(entry => _clock.GetElapsedTime(entry.Value.Created) >= CursorLifetime)
            .Select(static entry => entry.Key).ToArray();
        foreach (var key in expired)
        {
            _snapshotBytes -= _snapshots[key].Charge;
            _snapshots.Remove(key);
        }
    }

    private string WriteCursor(DirectorySnapshot snapshot, int position)
    {
        var bytes = new byte[53];
        bytes[0] = 1;
        snapshot.Id.CopyTo(bytes, 1);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(17, 4), checked((uint)position));
        lock (_snapshotGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            HMACSHA256.HashData(_cursorKey, bytes.AsSpan(0, 21)).CopyTo(bytes, 21);
        }

        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private (DirectorySnapshot Snapshot, int Position) ReadCursor(string cursor, ReadOnlySpan<byte> workspaceId, ReadOnlySpan<byte> callerBinding)
    {
        if (cursor.Length != 71 || cursor.Any(static c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_'))
        {
            throw new WorkspaceQueryException("invalid_cursor");
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(cursor.Replace('-', '+').Replace('_', '/') + "=");
        }
        catch (FormatException)
        {
            throw new WorkspaceQueryException("invalid_cursor");
        }

        if (bytes.Length != 53 || !Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_').Equals(cursor, StringComparison.Ordinal))
        {
            throw new WorkspaceQueryException("invalid_cursor");
        }

        lock (_snapshotGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            PruneSnapshots();
            var mac = HMACSHA256.HashData(_cursorKey, bytes.AsSpan(0, 21));
            if (bytes.Length != 53 || bytes[0] != 1 || !CryptographicOperations.FixedTimeEquals(mac, bytes.AsSpan(21)) ||
                !_snapshots.TryGetValue(Convert.ToHexString(bytes.AsSpan(1, 16)), out var snapshot) ||
                !CryptographicOperations.FixedTimeEquals(workspaceId, snapshot.Workspace) ||
                !CryptographicOperations.FixedTimeEquals(callerBinding, snapshot.Caller))
            {
                throw new WorkspaceQueryException("invalid_cursor");
            }

            var position = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(17, 4));
            if (position >= snapshot.View.Entries.Length)
            {
                throw new WorkspaceQueryException("invalid_cursor");
            }

            return (snapshot, checked((int)position));
        }
    }

    public void Dispose()
    {
        lock (_snapshotGate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            CryptographicOperations.ZeroMemory(_cursorKey);
            _snapshots.Clear();
            _snapshotBytes = 0;
        }
    }

    private sealed record SnapshotEntry(string Name, WorkspaceEntryMetadata Metadata);
    private sealed record DirectoryView(WorkspaceEntryMetadata Directory, SnapshotEntry[] Entries, bool Overflow, long Charge);
    private sealed record DirectorySnapshot(byte[] Id, byte[] Workspace, byte[] Caller, DirectoryView View, long Created)
    {
        internal long Charge => checked(View.Charge + 512);
    }

    private sealed class SearchScan : IDisposable
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private ulong _transcriptBytes = 25;
        private uint _files;

        internal SearchScan()
        {
            _hash.AppendData("ArcForges search-scan v1\0"u8);
            Value.VisitedEntries = 0;
            Value.ScannedBytes = 0;
            Value.SkippedFiles = 0;
            Value.Truncated = false;
        }

        internal N.FileServiceSearchFilesValue Value { get; } = new();

        internal void Append(string path, ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length == 0)
            {
                return;
            }

            var encoded = StrictUtf8.GetBytes(path);
            Span<byte> frame = stackalloc byte[8];
            BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)encoded.Length));
            _hash.AppendData(frame[..4]);
            _hash.AppendData(encoded);
            BinaryPrimitives.WriteUInt64BigEndian(frame, checked((ulong)bytes.Length));
            _hash.AppendData(frame);
            _hash.AppendData(bytes);
            Value.ScannedBytes += checked((ulong)bytes.Length);
            _transcriptBytes += checked((ulong)(12 + encoded.Length + bytes.Length));
            _files++;
        }

        internal void Truncate(string reason)
        {
            Value.Truncated = true;
            if (!Value.HasTruncationReason)
            {
                Value.TruncationReason = reason;
            }
        }

        internal void Problem(string path, string reason)
        {
            Truncate(reason);
            if (Value.Problems.Count == MaximumProblems)
            {
                return;
            }

            Value.Problems.Add(new N.FileScanProblem { Path = path, Reason = reason });
            if (Value.CalculateSize() > ValueBudget)
            {
                Value.Problems.RemoveAt(Value.Problems.Count - 1);
                Truncate("response_bytes");
            }
        }

        internal N.FileAuditMetadata Audit() => new()
        {
            Observations =
            {
                new N.FileAuditObservation
                {
                    Kind = N.FileAuditKind.SearchTranscript,
                    SizeBytes = Value.ScannedBytes,
                    Sha256 = ByteString.CopyFrom(_hash.GetCurrentHash()),
                    DigestInputBytes = _transcriptBytes,
                    ItemCount = _files,
                },
            },
        };

        internal N.FileAuditMetadata? PartialAudit() => Value.ScannedBytes == 0 ? null : Audit();

        internal WorkspaceSearchResult Finish()
        {
            Value.ScanDigest = ByteString.CopyFrom(_hash.GetCurrentHash());
            Value.ScanTranscriptBytes = _transcriptBytes;
            Value.ScanFileCount = _files;
            return new WorkspaceSearchResult(Value, Audit());
        }

        public void Dispose() => _hash.Dispose();
    }
}
