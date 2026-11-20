// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Sandboxes;

internal sealed partial class SandboxManager
{
    private const int DataEntryLimit = 10_000;
    private const int DataUsagePathBudget = 8 * 1024 * 1024;
    private const int DataUsageCacheLimit = 64;
    private const int DataUsageConcurrency = 2;
    private const int DataDirectoryReadConcurrency = 4;
    private const int DataCursorPayloadSize = sizeof(int) + SHA256.HashSizeInBytes;
    private const int DataCursorSize = DataCursorPayloadSize + SHA256.HashSizeInBytes;
    private static readonly string[] s_ownedDataDirectories = SandboxPrivateRoots.OwnedDataDirectoryNames
        .Order(StringComparer.Ordinal).ToArray();
    private static readonly TimeSpan s_dataReadBudget = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan s_dataUsageFreshness = TimeSpan.FromSeconds(5);
    private readonly object _dataUsageGate = new();
    private readonly Dictionary<string, DataUsageScan> _dataUsage = new(StringComparer.Ordinal);
    private int _dataUsageActive;
    private int _dataDirectoryReads;
    private bool _dataUsageStopped;

    internal DataServiceGetUsageResponse GetDataUsage(DataServiceGetUsageRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var row = ReadDataSandbox(request.SandboxId);
            var grants = FromStored(row.Config).HostGrants;
            SandboxPrivateRootLease? lease = _roots.Inspect(row.SandboxId, row.RootIdentity);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                DataUsageObservation? observed;
                lock (_dataUsageGate)
                {
                    if (_dataUsageStopped)
                        throw new DataReadException(ErrorCategory.State, "managed_use", "sandbox_data_stopping");

                    var scan = FindDataUsageScan(row);
                    observed = scan.Observation;
                    if (scan.Cancellation is null && _dataUsageActive < DataUsageConcurrency &&
                        (scan.CompletedAt == 0 || Stopwatch.GetElapsedTime(scan.CompletedAt) >= s_dataUsageFreshness))
                    {
                        var ownedLease = lease;
                        var deadline = new CancellationTokenSource(s_dataReadBudget);
                        scan.Cancellation = deadline;
                        _dataUsageActive++;
                        // A completed request cannot cancel the shared scan or prevent disposal of its held root.
                        _ = Task.Run(() => ObserveDataUsage(ownedLease, scan, deadline), CancellationToken.None);
                        lease = null;
                    }
                }

                var usage = new Usage
                {
                    ObservedAt = ProtoTime.ToInstant(observed?.ObservedAt ?? _clock.GetUtcNow()),
                    Partial = observed?.Partial ?? true,
                };
                if (observed is { } measurement)
                {
                    usage.OwnedBytes = measurement.LogicalBytes;
                    usage.FileCount = measurement.Files;
                    if (measurement.AllocatedBytes is { } allocation) usage.AllocatedBytes = allocation;
                }

                usage.ExcludedRoots.AddRange(grants.Select(grant => grant.HostPath).Distinct(StringComparer.Ordinal));
                return new() { Meta = Response(request.Meta, row.Revision), Value = new() { Usage = usage } };
            }
            finally
            {
                lease?.Dispose();
            }
        }
        catch (Exception failure) when (IsStorageFailure(failure))
        {
            return new() { Meta = Response(request.Meta), Error = DataReadFailure(request.Meta, failure) };
        }
    }

    internal DataServiceListEntriesResponse ListDataEntries(DataServiceListEntriesRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Interlocked.Increment(ref _dataDirectoryReads) > DataDirectoryReadConcurrency)
        {
            Interlocked.Decrement(ref _dataDirectoryReads);
            return new() { Meta = Response(request.Meta), Error = Error(request.Meta, ErrorCategory.State,
                "managed_use", "sandbox_data_read_busy") };
        }

        using var budget = new CancellationTokenSource(s_dataReadBudget);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, budget.Token);
        bool continuation = false;
        try
        {
            if (request.HasLimit && request.Limit is < 1 or > 200)
                throw new DataReadException(ErrorCategory.Validation, "invalid_argument", "limit_invalid");
            var limit = request.HasLimit ? checked((int)request.Limit) : 50;
            var row = ReadDataSandbox(request.SandboxId);
            var path = request.RelativeDirectory;
            ValidateDataPath(path, allowRoot: true);
            if (!ReadDataCursor(request.Cursor, out var offset, out var priorVersion))
                throw InvalidDataCursor();
            continuation = priorVersion is not null;

            using var lease = _roots.Inspect(row.SandboxId, row.RootIdentity);
            var root = lease.OwnedWorkspace;
            var observed = ReadDataDirectory(root, path, DataEntryLimit, observeAllocation: false, token: deadline.Token);
            if (observed.Truncated)
                throw new DataReadException(ErrorCategory.Validation, "path_rejected", "directory_observation_limit");

            // Bind the continuation to this owner, Sandbox generation, selected directory, and actual ordered observations.
            using var fingerprint = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            fingerprint.AppendData(Encoding.UTF8.GetBytes(FormattableString.Invariant(
                $"arcforges-data-directory-v1\0{OwnerId}\0{row.SandboxId}\0{row.RootIdentity}\0{row.RootGeneration}\0{row.Revision}")));
            fingerprint.AppendData(Convert.FromBase64String(DataFileVersion(row.SandboxId, path, observed.Directory)));
            var result = new DataServiceListEntriesValue { Page = new Page { NextCursor = "" } };
            for (int index = 0; index < observed.Entries.Count; index++)
            {
                deadline.Token.ThrowIfCancellationRequested();
                var entry = observed.Entries[index];
                var version = DataFileVersion(row.SandboxId, entry.Path, entry.Metadata);
                fingerprint.AppendData(Convert.FromBase64String(version));
                if (index >= offset && index < offset + limit)
                    result.Entries.Add(ProjectDataEntry(entry, version));
            }

            var directoryVersion = fingerprint.GetHashAndReset();
            if (priorVersion is not null && (offset >= observed.Entries.Count ||
                !CryptographicOperations.FixedTimeEquals(directoryVersion, priorVersion)))
            {
                throw InvalidDataCursor();
            }

            // No long filesystem work holds OwnershipGate or a Store transaction. Recheck their current binding before reply.
            if (_store.Read(reader => SandboxRecords.Get(reader, OwnerId, row.SandboxId)) != row)
                throw new DataReadException(ErrorCategory.Conflict, "identity_changed", "sandbox_data_binding_changed");
            using var current = _roots.Inspect(row.SandboxId, row.RootIdentity);
            var latest = InspectDataDirectory(current.OwnedWorkspace, path);
            if (!SameDataEntry(observed.Directory, latest))
                throw new WorkspacePathException("directory_changed");

            if (offset + limit < observed.Entries.Count)
                result.Page.NextCursor = WriteDataCursor(offset + limit, directoryVersion);
            deadline.Token.ThrowIfCancellationRequested();
            return new() { Meta = Response(request.Meta, row.Revision), Value = result };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && budget.IsCancellationRequested)
        {
            return new() { Meta = Response(request.Meta), Error = Error(request.Meta, ErrorCategory.Validation,
                "path_rejected", "directory_observation_limit") };
        }
        catch (WorkspacePathException failure) when (continuation &&
            failure.Reason is "directory_changed" or "path_not_directory" or "native_2" or "native_3")
        {
            var invalid = InvalidDataCursor();
            return new() { Meta = Response(request.Meta), Error = Error(request.Meta, invalid.Category, invalid.Code, invalid.Message) };
        }
        catch (Exception failure) when (IsStorageFailure(failure))
        {
            return new() { Meta = Response(request.Meta), Error = DataReadFailure(request.Meta, failure) };
        }
        finally
        {
            Interlocked.Decrement(ref _dataDirectoryReads);
        }
    }

    private StoredSandbox ReadDataSandbox(Id? id)
    {
        if (!ValidId(id)) throw new DataReadException(ErrorCategory.Validation, "invalid_argument", "sandbox_id_invalid");
        var sandboxId = ToHex(id!);
        var row = _store.Read(reader => SandboxRecords.Get(reader, OwnerId, sandboxId));
        if (row is null || row.State == StoredSandboxState.Deleted)
            throw new DataReadException(ErrorCategory.State, "not_found", "sandbox_not_visible");
        if (row.State != StoredSandboxState.Ready)
            throw new DataReadException(ErrorCategory.State, "managed_use", "sandbox_data_not_ready");
        if (row.RootRelative != SandboxPrivateRoots.RelativePath(sandboxId))
            throw new DataReadException(ErrorCategory.Conflict, "identity_changed", "private_root_identity_changed");
        return row;
    }

    private static void ValidateDataPath(string path, bool allowRoot)
    {
        var parts = WorkspacePath.Components(path, allowRoot);
        if (parts.Length != 0 && !s_ownedDataDirectories.Contains(parts[0], StringComparer.Ordinal))
            throw new WorkspacePathException("sandbox_data_path_not_owned");
    }

    // This opaque version records the selected name and exact native object health without exposing native IDs to clients.
    // It is stable across restarts. The caller must still prove authority and compare a fresh held observation before an effect.
    private static string DataFileVersion(string sandboxId, string relativePath, WorkspaceEntryMetadata entry)
    {
        using var bytes = new MemoryStream();
        using var writer = new BinaryWriter(bytes, Encoding.UTF8, leaveOpen: true);
        writer.Write("arcforges-data-file-version-v1");
        writer.Write(sandboxId);
        writer.Write(relativePath);
        writer.Write((int)entry.Kind);
        var identity = entry.Identity;
        writer.Write(identity.InstanceToken.Length);
        if (identity.InstanceToken.IsEmpty)
        {
            writer.Write(identity.Volume);
            writer.Write(identity.Low);
            writer.Write(identity.High);
        }
        else
        {
            // The native Linux instance token includes filesystem identity and generation; mount IDs can change at reboot.
            writer.Write(identity.InstanceToken.Span);
        }

        writer.Write(identity.Created);
        writer.Write(identity.CreatedNanoseconds);
        writer.Write(identity.Links);
        writer.Write(identity.Mode);
        var stamp = entry.Stamp;
        writer.Write(stamp.Size);
        writer.Write(stamp.Modification);
        writer.Write(stamp.ModificationNanoseconds);
        writer.Write(stamp.Change);
        writer.Write(stamp.ChangeNanoseconds);
        return Convert.ToBase64String(SHA256.HashData(bytes.GetBuffer().AsSpan(0, checked((int)bytes.Length))));
    }

    private static DataDirectoryObservation ReadDataDirectory(WorkspacePath root, string path, int maximum,
        bool observeAllocation, CancellationToken token)
    {
        var observation = InDataDirectory(root, path, Capture);
        if (!SameDataEntry(observation.Directory, InspectDataDirectory(root, path)))
            throw new WorkspacePathException("directory_changed");
        return observation;

        DataDirectoryObservation Capture(WorkspacePath selected)
        {
            token.ThrowIfCancellationRequested();
            var before = selected.InspectEntry("", allowRoot: true, observeAllocation: observeAllocation);
            if (before.Kind != WorkspaceEntryType.Directory) throw new WorkspacePathException("path_not_directory");

            var names = path.Length == 0
                ? new WorkspaceDirectoryPage(s_ownedDataDirectories, Truncated: false)
                : WorkspaceDirectoryEntries.Read(selected, "", maximum, token);
            var entries = new List<DataNamedEntry>(names.Names.Count);
            int bytes = 0;
            foreach (var name in names.Names)
            {
                token.ThrowIfCancellationRequested();
                var child = path.Length == 0 ? name : path + "/" + name;
                _ = WorkspacePath.Components(child);
                bytes += Encoding.UTF8.GetByteCount(child);
                if (bytes > DataUsagePathBudget) return new(before, entries, names.Names.Count, Truncated: true);
                var metadata = selected.InspectEntry(name, observeAllocation: observeAllocation);
                if (!root.IsPrivateStageFile(metadata.Identity)) entries.Add(new(child, metadata));
            }

            return new(before, entries, names.Names.Count, names.Truncated);
        }
    }

    private static WorkspaceEntryMetadata InspectDataDirectory(WorkspacePath root, string path) =>
        InDataDirectory(root, path, static selected => selected.InspectEntry("", allowRoot: true));

    // Open children relative to the selected native directory, even if its original name is replaced during enumeration.
    private static T InDataDirectory<T>(WorkspacePath root, string path, Func<WorkspacePath, T> read)
    {
        if (path.Length == 0) return read(root);
        if (OperatingSystem.IsLinux())
        {
            using var selectedLinux = root.OpenLinuxEntryDirectory(path);
            return read(selectedLinux);
        }

        if (!OperatingSystem.IsWindows()) throw new WorkspacePathException("path_enforcement_unavailable");

        // Retain and dispose only one checked chain for the selected Windows directory.
        var held = new List<WorkspacePath>();
        var selected = root;
        try
        {
            foreach (var component in WorkspacePath.Components(path))
            {
                selected = selected.OpenWindowsHeldChildRoot(component);
                held.Add(selected);
            }

            return read(selected);
        }
        finally
        {
            for (int index = held.Count - 1; index >= 0; index--) held[index].Dispose();
        }
    }

    private static bool SameDataEntry(WorkspaceEntryMetadata left, WorkspaceEntryMetadata right) =>
        left.Kind == right.Kind && left.Stamp == right.Stamp && left.Identity.SameObject(right.Identity);

    private static FileEntry ProjectDataEntry(DataNamedEntry entry, string version)
    {
        var value = new FileEntry
        {
            RelativePath = entry.Path,
            Kind = entry.Metadata.Kind switch
            {
                WorkspaceEntryType.File => "regular_file",
                WorkspaceEntryType.Directory => "directory",
                WorkspaceEntryType.Link => "symlink",
                _ => "other",
            },
            VersionToken = version,
        };
        if (entry.Metadata.Size is { } bytes) value.ByteLength = bytes;
        var stamp = entry.Metadata.Stamp;
        if (OperatingSystem.IsLinux() && stamp.ModificationNanoseconds < 1_000_000_000)
            value.ModifiedAt = new Instant { UnixSeconds = stamp.Modification, Nanos = stamp.ModificationNanoseconds };
        if (OperatingSystem.IsWindows())
        {
            try { value.ModifiedAt = ProtoTime.ToInstant(DateTimeOffset.FromFileTime(stamp.Modification)); }
            catch (ArgumentOutOfRangeException) { }
        }

        return value;
    }

    private string WriteDataCursor(int offset, ReadOnlySpan<byte> directoryVersion)
    {
        Span<byte> token = stackalloc byte[DataCursorSize];
        BinaryPrimitives.WriteInt32LittleEndian(token, offset);
        directoryVersion.CopyTo(token[sizeof(int)..DataCursorPayloadSize]);
        HMACSHA256.HashData(_cursorKey, token[..DataCursorPayloadSize], token[DataCursorPayloadSize..]);
        return Convert.ToBase64String(token);
    }

    private bool ReadDataCursor(string cursor, out int offset, out byte[]? directoryVersion)
    {
        offset = 0;
        directoryVersion = null;
        if (cursor.Length == 0) return true;
        if (cursor.Length > 128) return false;
        Span<byte> token = stackalloc byte[DataCursorSize];
        Span<byte> mac = stackalloc byte[SHA256.HashSizeInBytes];
        if (!Convert.TryFromBase64String(cursor, token, out int written) || written != token.Length) return false;
        HMACSHA256.HashData(_cursorKey, token[..DataCursorPayloadSize], mac);
        if (!CryptographicOperations.FixedTimeEquals(mac, token[DataCursorPayloadSize..])) return false;
        offset = BinaryPrimitives.ReadInt32LittleEndian(token);
        if (offset is < 1 or >= DataEntryLimit) return false;
        directoryVersion = token[sizeof(int)..DataCursorPayloadSize].ToArray();
        return true;
    }

    private static DataReadException InvalidDataCursor() =>
        new(ErrorCategory.Validation, "invalid_cursor", "sandbox_directory_cursor_changed");

    private static ArcError DataReadFailure(RequestMeta? meta, Exception failure) => failure switch
    {
        DataReadException read => Error(meta, read.Category, read.Code, read.Message),
        SandboxPrivateRootException root => Error(meta, ErrorCategory.Conflict, "identity_changed", root.Reason),
        WorkspacePathException path when path.Reason is "native_2" or "native_3" or "path_not_found" =>
            Error(meta, ErrorCategory.State, "not_found", path.Reason),
        WorkspacePathException path when path.Reason is "directory_changed" or "root_changed" or "file_changed" or "native_11" =>
            Error(meta, ErrorCategory.Conflict, "identity_changed", path.Reason),
        WorkspacePathException path when path.Reason is "file_access_denied" ||
            path.Reason == (OperatingSystem.IsWindows() ? "native_5" : "native_13") =>
            Error(meta, ErrorCategory.Authorization, "permission_denied", path.Reason),
        WorkspacePathException path => Error(meta, ErrorCategory.Validation, "path_rejected", path.Reason),
        UnauthorizedAccessException => Error(meta, ErrorCategory.Authorization, "permission_denied", "sandbox_data_access_denied"),
        _ => StorageFailure(meta),
    };

    private DataUsageScan FindDataUsageScan(StoredSandbox row)
    {
        if (_dataUsage.TryGetValue(row.SandboxId, out var existing))
        {
            if (existing.RootIdentity == row.RootIdentity && existing.RootGeneration == row.RootGeneration) return existing;
            existing.Cancellation?.Cancel();
        }
        else if (_dataUsage.Count >= DataUsageCacheLimit)
        {
            // At most DataUsageConcurrency entries are active, so one inactive entry is always available for eviction.
            var victim = _dataUsage.Where(entry => entry.Value.Cancellation is null)
                .MinBy(entry => entry.Value.CompletedAt);
            _dataUsage.Remove(victim.Key);
        }

        var scan = new DataUsageScan(row.RootIdentity, row.RootGeneration);
        _dataUsage[row.SandboxId] = scan;
        return scan;
    }

    private void ObserveDataUsage(SandboxPrivateRootLease lease, DataUsageScan scan, CancellationTokenSource deadline)
    {
        var usage = new DataUsageTotals();
        try
        {
            using (lease)
            {
                CountOwnedData(lease.OwnedWorkspace, scan, usage, deadline.Token);
            }
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or OperationCanceledException or OverflowException)
        {
            usage.Partial = true;
        }
        finally
        {
            lock (_dataUsageGate)
            {
                if (!_dataUsageStopped)
                {
                    if (usage.Observed) scan.Observation = usage.Snapshot(_clock.GetUtcNow(), usage.Partial);
                    else if (scan.Observation is { } prior) scan.Observation = prior with { Partial = true };
                }
                scan.CompletedAt = Stopwatch.GetTimestamp();
                scan.Cancellation = null;
                _dataUsageActive--;
                deadline.Dispose();
                if (_dataUsageStopped && _dataUsageActive == 0) Monitor.PulseAll(_dataUsageGate);
            }
        }
    }

    private void CountOwnedData(WorkspacePath root, DataUsageScan scan, DataUsageTotals usage, CancellationToken cancellationToken)
    {
        var pending = new Stack<DataNamedEntry>();
        foreach (var name in s_ownedDataDirectories)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                pending.Push(new(name, root.InspectEntry(name, observeAllocation: true)));
            }
            catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
            {
                usage.Partial = true;
            }
        }

        var entries = pending.Count;
        var pathBytes = 0;
        while (pending.TryPop(out var directory))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = DataEntryLimit - entries;
            if (remaining <= 0)
            {
                usage.Partial = true;
                break;
            }

            try
            {
                var observed = ReadDataDirectory(root, directory.Path, remaining, observeAllocation: true, token: cancellationToken);
                if (!SameDataEntry(directory.Metadata, observed.Directory))
                    throw new WorkspacePathException("directory_changed");

                usage.Add(observed.Directory);
                usage.Partial |= observed.Truncated;
                entries += observed.EnumeratedEntries;
                foreach (var entry in observed.Entries)
                {
                    pathBytes += Encoding.UTF8.GetByteCount(entry.Path);
                    if (pathBytes > DataUsagePathBudget)
                    {
                        usage.Partial = true;
                        return;
                    }

                    if (entry.Metadata.Kind == WorkspaceEntryType.Directory) pending.Push(entry);
                    else usage.Add(entry.Metadata);
                }

                lock (_dataUsageGate)
                {
                    if (!_dataUsageStopped) scan.Observation = usage.Snapshot(_clock.GetUtcNow(), partial: true);
                }
            }
            catch (Exception failure) when (failure is IOException or UnauthorizedAccessException)
            {
                usage.Partial = true;
            }
        }
    }

    private void StopDataUsageScans()
    {
        lock (_dataUsageGate)
        {
            _dataUsageStopped = true;
            foreach (var scan in _dataUsage.Values) scan.Cancellation?.Cancel();
            _dataUsage.Clear();
        }
    }

    private sealed class DataUsageScan(string rootIdentity, long rootGeneration)
    {
        internal string RootIdentity { get; } = rootIdentity;
        internal long RootGeneration { get; } = rootGeneration;
        internal long CompletedAt { get; set; }
        internal CancellationTokenSource? Cancellation { get; set; }
        internal DataUsageObservation? Observation { get; set; }
    }

    private sealed class DataUsageTotals
    {
        private ulong _logicalBytes;
        private ulong? _allocatedBytes = 0;
        private ulong _files;
        internal bool Observed { get; private set; }
        internal bool Partial { get; set; }

        internal void Add(WorkspaceEntryMetadata entry)
        {
            // Logical regular-file data and native allocation are counted per name, including hard links.
            // A link contributes only its own entry metadata and never the target's data or allocation.
            if (entry.Kind == WorkspaceEntryType.File)
            {
                _logicalBytes = checked(_logicalBytes + entry.Size!.Value);
                _files++;
            }

            _allocatedBytes = checked(_allocatedBytes + entry.AllocatedBytes);
            Observed = true;
        }

        internal DataUsageObservation Snapshot(DateTimeOffset now, bool partial) =>
            new(now, _logicalBytes, _allocatedBytes, _files, partial);
    }

    private readonly record struct DataUsageObservation(DateTimeOffset ObservedAt, ulong LogicalBytes, ulong? AllocatedBytes,
        ulong Files, bool Partial);
    private sealed record DataDirectoryObservation(WorkspaceEntryMetadata Directory, IReadOnlyList<DataNamedEntry> Entries,
        int EnumeratedEntries, bool Truncated);
    private readonly record struct DataNamedEntry(string Path, WorkspaceEntryMetadata Metadata);

    private sealed class DataReadException(ErrorCategory category, string code, string reason) : IOException(reason)
    {
        internal ErrorCategory Category { get; } = category;
        internal string Code { get; } = code;
    }
}
