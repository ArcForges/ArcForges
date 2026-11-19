// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.RunSupervisor.Protocol;

[SuppressMessage("Naming", "CA1711", Justification = "Identifies one stream in the Run output protocol.")]
public enum RunOutputStream
{
    Terminal = 1,
    Stdout = 2,
    Stderr = 3,
}

public sealed record RunOutputIdentity(string RunId, string Epoch, string LaunchSha256, RunTerminalMode TerminalMode);

public enum RunOutputReadStatus
{
    Chunk,
    Gap,
    Tail,
    Complete,
    Unavailable,
    InvalidCursor,
    StreamUnavailable,
}

public sealed record RunOutputReadResult(
    RunOutputReadStatus Status, string Epoch, ulong Offset, ulong EarliestOffset, ulong EndOffset, byte[]? Data, string? GapReason)
{
    public ulong NextOffset => Status == RunOutputReadStatus.Gap ? EarliestOffset : Offset + (ulong)(Data?.Length ?? 0);
}

internal sealed record RunOutputRange(RunOutputStream Stream, ulong Earliest, ulong End);

internal sealed record RunOutputSegment(ulong Id, RunOutputStream Stream, ulong Start, int Length)
{
    internal ulong End => Start + (ulong)Length;
}

internal sealed record RunOutputIndex(
    int Version, RunOutputIdentity Identity, long Limit, ulong Generation, ulong LastSegmentId, bool Complete,
    RunOutputRange[] Ranges, RunOutputSegment[] Segments);

[JsonSerializable(typeof(RunOutputIndex))]
internal sealed partial class RunOutputJson : JsonSerializerContext;

/// <summary>One native owner commits output before viewers can observe its contiguous per-stream byte ranges.</summary>
public sealed partial class RunOutputSpool : IDisposable
{
    private const string IndexLeaf = "output.index";
    private const int MaximumChunk = 65_536;
    private const int SegmentSize = 1024 * 1024;
    private const long MaximumOutput = 64L * SegmentSize;
    // At most one partial live segment per stream in addition to full segments.
    private const int MaximumSegments = 64 + 2;
    private const int MaximumIndex = 24_576;
    private static readonly RunOutputStream[] TerminalStreams = [RunOutputStream.Terminal];
    private static readonly RunOutputStream[] PipeStreams = [RunOutputStream.Stdout, RunOutputStream.Stderr];

    private readonly object gate = new();
    private readonly OutputDirectory directory;
    private readonly Dictionary<RunOutputStream, (ulong Id, FileStream File)> activeFiles = [];
    private RunOutputIndex index;
    private bool failed;
    private bool disposed;

    private RunOutputSpool(OutputDirectory directory, RunOutputIndex index)
    {
        this.directory = directory;
        this.index = index;
    }

    public static RunOutputSpool Create(RunLaunchSpec spec)
    {
        if (spec.OutputLimitBytes is < 0 or > MaximumOutput || Streams(spec.TerminalMode).Length == 0)
        {
            throw new InvalidDataException("run_output_configuration_invalid");
        }

        var directory = OutputDirectory.Open(spec.ControlDirectory);
        try
        {
            var index = new RunOutputIndex(1, new(spec.RunId, spec.Epoch, spec.LaunchSha256, spec.TerminalMode),
                (long)spec.OutputLimitBytes, 1, 0, false,
                Streams(spec.TerminalMode).Select(stream => new RunOutputRange(stream, 0, 0)).ToArray(), []);
            var spool = new RunOutputSpool(directory, index);

            // Persist the unique writer claim before publishing any state. A restart cannot adopt a
            // partial or already completed spool and manufacture continuity across owners.
            if (File.Exists(directory.PathFor(IndexLeaf)))
            {
                throw new IOException("run_output_already_initialized");
            }

            RunWire.WritePrivateNew(directory.PathFor("output.owner"), []);
            spool.Publish(index);
            return spool;
        }
        catch
        {
            directory.Dispose();
            throw;
        }
    }

    public void Append(RunOutputStream stream, ReadOnlySpan<byte> bytes)
    {
        lock (gate)
        {
            EnsureWritable();
            _ = RangeIndex(stream);
            if (index.Limit == 0)
            {
                RecordDroppedLocked(stream, (ulong)bytes.Length);
                return;
            }

            try
            {
                while (!bytes.IsEmpty)
                {
                    int accepted = AppendPart(stream, bytes);
                    bytes = bytes[accepted..];
                }
            }
            catch
            {
                failed = true;
                throw;
            }
        }
    }

    public void RecordDropped(RunOutputStream stream, ulong byteCount)
    {
        lock (gate)
        {
            EnsureWritable();
            RecordDroppedLocked(stream, byteCount);
        }
    }

    public void Complete() => _ = CompleteCore(null);

    internal bool TryComplete(Func<bool> authorizeCommit) => CompleteCore(authorizeCommit);

    private bool CompleteCore(Func<bool>? authorizeCommit)
    {
        lock (gate)
        {
            EnsureWritable();
            try
            {
                CloseActiveFiles();
                return Publish(index with { Generation = checked(index.Generation + 1), Complete = true }, authorizeCommit);
            }
            catch
            {
                failed = true;
                throw;
            }
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
            {
                return;
            }

            disposed = true;
            try
            {
                CloseActiveFiles();
            }
            finally
            {
                directory.Dispose();
            }
        }
    }

    /// <summary>Reads only via no-follow handles supplied by the owner-scoped reader.</summary>
    public static RunOutputReadResult Read(RunOutputIdentity identity, Func<string, SafeFileHandle> openTrustedRead,
        RunOutputStream stream, string? requestedEpoch, ulong offset, int maximumBytes = MaximumChunk)
    {
        if (!Streams(identity.TerminalMode).Contains(stream))
        {
            return new(RunOutputReadStatus.StreamUnavailable, identity.Epoch, offset, 0, 0, null, null);
        }

        if (maximumBytes is < 1 or > MaximumChunk)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        }

        ulong failedGeneration = 0;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            RunOutputIndex? state = null;
            try
            {
                state = ReadIndex(identity, openTrustedRead);
                if (state.Generation <= failedGeneration)
                {
                    break;
                }

                return ReadRange(state, openTrustedRead, stream, requestedEpoch, offset, maximumBytes);
            }
            catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
            {
                if (state is not null)
                {
                    // A viewer may hold an old index just as the writer evicts one of its files.
                    // Only a newer, independently validated index can supersede that failed read.
                    failedGeneration = state.Generation;
                }
            }
        }

        return new(RunOutputReadStatus.Unavailable, identity.Epoch, offset, 0, 0, null, null);
    }

    private int AppendPart(RunOutputStream stream, ReadOnlySpan<byte> bytes)
    {
        int capacity = SegmentCapacity(index.Limit);
        var currentTail = Array.FindLast(index.Segments, segment => segment.Stream == stream);
        int available = currentTail is null || currentTail.Length == capacity ? capacity : capacity - currentTail.Length;
        int length = Math.Min(Math.Min(bytes.Length, MaximumChunk), available);
        MakeRoom(length);

        int rangeIndex = RangeIndex(stream);
        var ranges = (RunOutputRange[])index.Ranges.Clone();
        var range = ranges[rangeIndex];
        var segments = index.Segments.ToList();
        int tailIndex = segments.FindLastIndex(segment => segment.Stream == stream);
        RunOutputSegment tail;
        ulong lastId = index.LastSegmentId;
        if (tailIndex < 0 || segments[tailIndex].Length == capacity)
        {
            CloseActiveFile(stream);
            lastId = checked(lastId + 1);
            tail = new(lastId, stream, range.End, 0);
            activeFiles.Add(stream, (lastId, directory.CreateSegment(SegmentLeaf(lastId))));
            tailIndex = segments.Count;
            segments.Add(tail);
        }
        else
        {
            tail = segments[tailIndex];
        }

        var active = activeFiles[stream].File;
        active.Write(bytes[..length]);
        active.Flush(flushToDisk: true);
        segments[tailIndex] = tail with { Length = tail.Length + length };
        ranges[rangeIndex] = range with { End = checked(range.End + (ulong)length) };

        Publish(index with
        {
            Generation = checked(index.Generation + 1),
            LastSegmentId = lastId,
            Ranges = ranges,
            Segments = segments.ToArray(),
        });
        return length;
    }

    private void MakeRoom(int incomingBytes)
    {
        long excess = index.Segments.Sum(segment => (long)segment.Length) + incomingBytes - index.Limit;
        if (excess <= 0)
        {
            return;
        }

        // Publish the loss before deleting whole files. If storage fails at either step, the
        // writer stops without writing more bytes or sealing this epoch.
        var ranges = (RunOutputRange[])index.Ranges.Clone();
        int count = 0;
        while (excess > 0)
        {
            var segment = index.Segments[count++];
            int range = RangeIndex(segment.Stream);
            ranges[range] = ranges[range] with { Earliest = segment.End };
            excess -= segment.Length;
        }

        var retired = index.Segments[..count];
        Publish(index with
        {
            Generation = checked(index.Generation + 1),
            Ranges = ranges,
            Segments = index.Segments[count..],
        });
        Retire(retired);
    }

    private void RecordDroppedLocked(RunOutputStream stream, ulong byteCount)
    {
        int rangeIndex = RangeIndex(stream);
        if (byteCount == 0)
        {
            return;
        }

        try
        {
            var ranges = (RunOutputRange[])index.Ranges.Clone();
            ulong end = checked(ranges[rangeIndex].End + byteCount);
            ranges[rangeIndex] = new(stream, end, end);
            var retired = index.Segments.Where(segment => segment.Stream == stream).ToArray();
            Publish(index with
            {
                Generation = checked(index.Generation + 1),
                Ranges = ranges,
                Segments = index.Segments.Where(segment => segment.Stream != stream).ToArray(),
            });
            Retire(retired);
        }
        catch
        {
            failed = true;
            throw;
        }
    }

    private void Retire(IEnumerable<RunOutputSegment> retired)
    {
        foreach (var segment in retired)
        {
            if (activeFiles.TryGetValue(segment.Stream, out var active) && active.Id == segment.Id)
            {
                CloseActiveFile(segment.Stream);
            }

            directory.DeleteSegment(SegmentLeaf(segment.Id));
        }
    }

    private bool Publish(RunOutputIndex state, Func<bool>? authorizeCommit = null)
    {
        if (!IsValid(state, index.Identity))
        {
            throw new InvalidDataException("run_output_index_invalid");
        }

        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(state, RunOutputJson.Default.RunOutputIndex);
        if (bytes.Length > MaximumIndex)
        {
            throw new InvalidDataException("run_output_index_too_large");
        }

        string temporary = directory.PathFor($".output-{Guid.NewGuid():N}.tmp");
        try
        {
            RunWire.WritePrivateNew(temporary, bytes);
            if (authorizeCommit is not null && !authorizeCommit())
            {
                return false;
            }

            directory.PublishIndex(temporary);
            index = state;
            return true;
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    private void EnsureWritable()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (failed || index.Complete)
        {
            throw new IOException("run_output_writer_closed");
        }
    }

    private int RangeIndex(RunOutputStream stream)
    {
        int indexOfStream = Array.IndexOf(Streams(index.Identity.TerminalMode), stream);
        return indexOfStream >= 0 ? indexOfStream : throw new ArgumentException("run_output_stream_unavailable", nameof(stream));
    }

    private void CloseActiveFile(RunOutputStream stream)
    {
        if (activeFiles.Remove(stream, out var file))
        {
            file.File.Dispose();
        }
    }

    private void CloseActiveFiles()
    {
        Exception? failure = null;
        foreach (var (_, file) in activeFiles.Values)
        {
            try
            {
                file.Dispose();
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                failure ??= error;
            }
        }

        activeFiles.Clear();
        if (failure is not null)
        {
            ExceptionDispatchInfo.Throw(failure);
        }
    }

    private static RunOutputReadResult ReadRange(RunOutputIndex state, Func<string, SafeFileHandle> openTrustedRead,
        RunOutputStream stream, string? requestedEpoch, ulong offset, int maximumBytes)
    {
        var range = state.Ranges[Array.IndexOf(Streams(state.Identity.TerminalMode), stream)];
        var result = new RunOutputReadResult(RunOutputReadStatus.Tail, state.Identity.Epoch, offset,
            range.Earliest, range.End, null, null);
        if (requestedEpoch is not null && !string.Equals(requestedEpoch, state.Identity.Epoch, StringComparison.Ordinal))
        {
            return result with { Status = RunOutputReadStatus.Gap, GapReason = "epoch_changed" };
        }

        if (offset < range.Earliest)
        {
            return result with { Status = RunOutputReadStatus.Gap, GapReason = "retention" };
        }

        if (offset > range.End)
        {
            return result with { Status = RunOutputReadStatus.InvalidCursor };
        }

        if (offset == range.End)
        {
            return state.Complete ? result with { Status = RunOutputReadStatus.Complete } : result;
        }

        var segment = state.Segments.First(segment => segment.Stream == stream && offset >= segment.Start && offset < segment.End);
        using var file = openTrustedRead(SegmentLeaf(segment.Id));
        if (RandomAccess.GetLength(file) < segment.Length)
        {
            throw new InvalidDataException("run_output_segment_truncated");
        }

        var bytes = new byte[(int)Math.Min((ulong)maximumBytes, segment.End - offset)];
        ReadExactly(file, bytes, (long)(offset - segment.Start));
        return result with { Status = RunOutputReadStatus.Chunk, Data = bytes };
    }

    private static RunOutputIndex ReadIndex(RunOutputIdentity identity, Func<string, SafeFileHandle> openTrustedRead)
    {
        using var file = openTrustedRead(IndexLeaf);
        long length = RandomAccess.GetLength(file);
        if (length is <= 0 or > MaximumIndex)
        {
            throw new InvalidDataException("run_output_index_size_invalid");
        }

        var bytes = new byte[(int)length];
        ReadExactly(file, bytes, 0);
        var state = JsonSerializer.Deserialize(bytes, RunOutputJson.Default.RunOutputIndex);
        return state is not null && IsValid(state, identity) ? state : throw new InvalidDataException("run_output_index_invalid");
    }

    private static void ReadExactly(SafeFileHandle file, Span<byte> bytes, long offset)
    {
        while (!bytes.IsEmpty)
        {
            int count = RandomAccess.Read(file, bytes, offset);
            if (count == 0)
            {
                throw new InvalidDataException("run_output_file_truncated");
            }

            offset += count;
            bytes = bytes[count..];
        }
    }

    private static bool IsValid(RunOutputIndex state, RunOutputIdentity identity)
    {
        var streams = Streams(identity.TerminalMode);
        if (state.Version != 1 || state.Identity != identity || state.Limit is < 0 or > MaximumOutput ||
            state.Generation == 0 || state.Ranges is null || state.Ranges.Length != streams.Length ||
            state.Segments is null || state.Segments.Length > MaximumSegments)
        {
            return false;
        }

        Span<ulong> next = stackalloc ulong[streams.Length];
        for (int i = 0; i < streams.Length; i++)
        {
            var range = state.Ranges[i];
            if (range is null || range.Stream != streams[i] || range.Earliest > range.End)
            {
                return false;
            }

            next[i] = range.Earliest;
        }

        long total = 0;
        int segmentCapacity = SegmentCapacity(state.Limit);
        ulong previousId = 0;
        foreach (var segment in state.Segments)
        {
            if (segment is null || segment.Id <= previousId || segment.Id > state.LastSegmentId ||
                segment.Length <= 0 || segment.Length > segmentCapacity ||
                segment.Start > ulong.MaxValue - (ulong)segment.Length)
            {
                return false;
            }

            int i = Array.IndexOf(streams, segment.Stream);
            if (i < 0 || segment.Start != next[i])
            {
                return false;
            }

            next[i] = segment.End;
            total += segment.Length;
            previousId = segment.Id;
        }

        for (int i = 0; i < streams.Length; i++)
        {
            if (next[i] != state.Ranges[i].End)
            {
                return false;
            }
        }

        return total <= state.Limit;
    }

    private static RunOutputStream[] Streams(RunTerminalMode mode) => mode switch
    {
        RunTerminalMode.Interactive => TerminalStreams,
        RunTerminalMode.Pipes => PipeStreams,
        _ => [],
    };

    // Small budgets still have several independently rotatable files. Losing one file
    // therefore leaves a retained tail unless that byte was itself the entire budget.
    private static int SegmentCapacity(long limit) => (int)Math.Min(SegmentSize, (limit + 7) / 8);

    private static string SegmentLeaf(ulong id) => "output-" + id.ToString("x16", CultureInfo.InvariantCulture) + ".bin";

    private sealed partial class OutputDirectory(string writePath, List<SafeFileHandle> handles) : IDisposable
    {
        public string PathFor(string leaf) => Path.Combine(writePath, leaf);

        public void PublishIndex(string temporary)
        {
            string indexPath = PathFor(IndexLeaf);
            if (OperatingSystem.IsWindows())
            {
                PublishWindowsIndex(temporary, indexPath);
            }
            else
            {
                // A final "." lets fsync open the directory beneath the held descriptor link.
                RunWire.CommitPrivateReplace(temporary, indexPath, writePath + "/.", "run_output");
            }
        }

        public FileStream CreateSegment(string leaf)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.ReadWrite | FileShare.Delete,
                Options = FileOptions.WriteThrough,
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            return new FileStream(PathFor(leaf), options);
        }

        public unsafe void DeleteSegment(string leaf)
        {
            string path = PathFor(leaf);
            if (!OperatingSystem.IsWindows())
            {
                File.Delete(path);
                return;
            }

            using var file = OpenWindows(path, 0x10000, 7, 0, 3, 0x00200000, 0); // DELETE, OPEN_REPARSE_POINT
            if (file.IsInvalid)
            {
                throw new IOException("run_output_retirement_open_failed:" + Marshal.GetLastPInvokeError());
            }

            // Unlink the visible name when this handle closes. Earlier readers can finish
            // their bounded reads using already acquired handles, as they can on Linux.
            uint deleteAndPosixSemantics = 3;
            const int fileDispositionInfoEx = 21;
            if (!SetWindowsInformation(file, fileDispositionInfoEx, (byte*)&deleteAndPosixSemantics, sizeof(uint)))
            {
                throw new IOException("run_output_retirement_failed:" + Marshal.GetLastPInvokeError());
            }
        }

        public static OutputDirectory Open(string path)
        {
            if (!Path.IsPathFullyQualified(path))
            {
                throw new IOException("run_output_directory_invalid");
            }

            string full = Path.GetFullPath(path);
            string root = Path.GetPathRoot(full) ?? throw new IOException("run_output_directory_invalid");
            string[] leaves = full[root.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
            if (leaves.Length == 0)
            {
                throw new IOException("run_output_directory_invalid");
            }

            var handles = new List<SafeFileHandle>();
            try
            {
                if (OperatingSystem.IsLinux())
                {
                    handles.Add(OpenLinuxDirectory(-100, root));
                    foreach (string leaf in leaves)
                    {
                        handles.Add(OpenLinuxDirectory(Descriptor(handles[^1]), leaf));
                    }

                    CheckLinuxOwner(handles[^1]);
                    return new("/proc/self/fd/" + Descriptor(handles[^1]).ToString(CultureInfo.InvariantCulture), handles);
                }

                if (OperatingSystem.IsWindows())
                {
                    handles.Add(OpenWindowsDirectory(root, readPermissions: false));
                    string current = root;
                    for (int i = 0; i < leaves.Length; i++)
                    {
                        current = Path.Combine(current, leaves[i]);
                        handles.Add(OpenWindowsDirectory(current, readPermissions: i == leaves.Length - 1));
                    }

                    CheckWindowsOwner(handles[^1]);
                    return new(full, handles);
                }

                throw new IOException("run_output_platform_unsupported");
            }
            catch
            {
                DisposeHandles(handles);
                throw;
            }
        }

        public void Dispose() => DisposeHandles(handles);

        private static void DisposeHandles(List<SafeFileHandle> handles)
        {
            for (int i = handles.Count - 1; i >= 0; i--)
            {
                handles[i].Dispose();
            }
        }

        private static int Descriptor(SafeFileHandle handle) => checked((int)handle.DangerousGetHandle());

        private static SafeFileHandle OpenLinuxDirectory(int parent, string name)
        {
            int fd = OpenAt(parent, name, 0x10000 | 0x20000 | 0x80000 | 0x200000); // DIRECTORY | NOFOLLOW | CLOEXEC | PATH
            return fd >= 0 ? new SafeFileHandle((nint)fd, ownsHandle: true) : throw DirectoryError();
        }

        private static unsafe void CheckLinuxOwner(SafeFileHandle handle)
        {
            const uint mask = 0x08 | 0x02; // STATX_UID | STATX_MODE
            byte* stat = stackalloc byte[256];
            if (Statx(Descriptor(handle), string.Empty, 0x1000 | 0x100, mask, stat) != 0 ||
                (*(uint*)stat & mask) != mask || *(uint*)(stat + 20) != EffectiveUserId() ||
                *(ushort*)(stat + 28) != (0x4000 | 0x1c0))
            {
                throw new UnauthorizedAccessException("run_output_directory_permissions");
            }
        }

        private static unsafe SafeFileHandle OpenWindowsDirectory(string path, bool readPermissions)
        {
            var handle = OpenWindows(path, 0x80u | (readPermissions ? 0x20000u : 0u), 3, 0, 3, 0x02200000, 0);
            if (handle.IsInvalid)
            {
                var error = DirectoryError();
                handle.Dispose();
                throw error;
            }

            uint* attributes = stackalloc uint[2];
            if (!GetWindowsInformation(handle, 9, attributes, 8) || (attributes[0] & (0x10 | 0x400)) != 0x10)
            {
                handle.Dispose();
                throw new UnauthorizedAccessException("run_output_directory_reparse_or_unreadable");
            }

            return handle;
        }

        private static unsafe void PublishWindowsIndex(string temporary, string indexPath)
        {
            // FileRenameInfoEx gives old readers their existing handle without pinning the current name.
            const uint deleteAndWrite = 0x40010000;
            const uint openReparseAndWriteThrough = 0x80200000;
            using var source = OpenWindows(temporary, deleteAndWrite, 7, 0, 3, openReparseAndWriteThrough, 0);
            if (source.IsInvalid)
            {
                throw DirectoryError();
            }

            // FILE_RENAME_INFO starts with Flags and an aligned, null RootDirectory for an absolute name.
            const uint replaceExistingAndPosixSemantics = 3;
            const int fileRenameInfoEx = 22;
            int nameOffset = (2 * sizeof(nint)) + sizeof(uint);
            int nameLength = indexPath.Length * sizeof(char);
            var info = new byte[nameOffset + nameLength];
            fixed (byte* data = info)
            {
                *(uint*)data = replaceExistingAndPosixSemantics;
                *(uint*)(data + nameOffset - sizeof(uint)) = (uint)nameLength;
                indexPath.AsSpan().CopyTo(new Span<char>(data + nameOffset, indexPath.Length));
                if (!SetWindowsInformation(source, fileRenameInfoEx, data, (uint)info.Length))
                {
                    throw new IOException("run_output_commit_failed:" +
                        Marshal.GetLastPInvokeError().ToString(CultureInfo.InvariantCulture));
                }
            }

            RandomAccess.FlushToDisk(source);
        }

        [SupportedOSPlatform("windows")]
        private static void CheckWindowsOwner(SafeFileHandle handle)
        {
            using var identity = WindowsIdentity.GetCurrent();
            var user = identity.User ?? throw new UnauthorizedAccessException("run_output_directory_permissions");
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            uint error = GetSecurityInfo(handle, 1, 5, out nint owner, out _, out nint dacl, out _, out nint descriptor);
            try
            {
                if (error != 0 || descriptor == 0 || owner == 0 || dacl == 0 || !new SecurityIdentifier(owner).Equals(user) ||
                    !GetWindowsSecurityControl(descriptor, out ushort control, out _) || (control & 0x1004) != 0x1004)
                {
                    throw new UnauthorizedAccessException("run_output_directory_permissions");
                }

                int size = unchecked((ushort)Marshal.ReadInt16(dacl, 2));
                var bytes = new byte[size];
                Marshal.Copy(dacl, bytes, 0, size);
                var acl = new RawAcl(bytes, 0);
                if (acl.Count != (user.Equals(system) ? 1 : 2))
                {
                    throw new UnauthorizedAccessException("run_output_directory_permissions");
                }

                const AceFlags inheritance = AceFlags.ContainerInherit | AceFlags.ObjectInherit;
                bool hasUser = false;
                bool hasSystem = false;
                foreach (var entry in acl)
                {
                    if (entry is not CommonAce
                        {
                            IsCallback: false, AceQualifier: AceQualifier.AccessAllowed,
                            AceFlags: inheritance, AccessMask: 0x001f01ff,
                        } ace)
                    {
                        throw new UnauthorizedAccessException("run_output_directory_permissions");
                    }

                    hasUser |= ace.SecurityIdentifier.Equals(user);
                    hasSystem |= ace.SecurityIdentifier.Equals(system);
                }

                if (!hasUser || !hasSystem)
                {
                    throw new UnauthorizedAccessException("run_output_directory_permissions");
                }
            }
            catch (ArgumentException exception)
            {
                throw new UnauthorizedAccessException("run_output_directory_permissions", exception);
            }
            finally
            {
                if (descriptor != 0)
                {
                    _ = FreeWindows(descriptor);
                }
            }
        }

        private static IOException DirectoryError() => new("run_output_directory_open_failed:" +
            Marshal.GetLastPInvokeError().ToString(CultureInfo.InvariantCulture));

        [LibraryImport("libc", EntryPoint = "openat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
        private static partial int OpenAt(int parent, string name, int flags);

        [LibraryImport("libc", EntryPoint = "statx", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
        private static unsafe partial int Statx(int directory, string path, int flags, uint mask, byte* stat);

        [LibraryImport("libc", EntryPoint = "geteuid")]
        private static partial uint EffectiveUserId();

        [LibraryImport("kernel32", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
        private static partial SafeFileHandle OpenWindows(string fileName, uint access, uint share, nint security, uint mode, uint flags, nint template);

        [LibraryImport("kernel32", EntryPoint = "GetFileInformationByHandleEx", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool GetWindowsInformation(SafeFileHandle handle, int informationClass, uint* attributes, uint size);

        [LibraryImport("kernel32", EntryPoint = "SetFileInformationByHandle", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static unsafe partial bool SetWindowsInformation(SafeFileHandle handle, int informationClass, byte* data, uint size);

        [LibraryImport("advapi32")]
        private static partial uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo, out nint owner,
            out nint group, out nint dacl, out nint sacl, out nint descriptor);

        [LibraryImport("advapi32", EntryPoint = "GetSecurityDescriptorControl")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool GetWindowsSecurityControl(nint descriptor, out ushort control, out uint revision);

        [LibraryImport("kernel32", EntryPoint = "LocalFree")]
        private static partial nint FreeWindows(nint memory);
    }
}

/// <summary>Decouples native pipe reads from storage commits for the lifetime of one Run.</summary>
public sealed class RunOutputCapture : IDisposable
{
    // A two-pipe Run can own one queued spill per stream plus the in-flight spill.
    private const int MaximumBufferedBytes = 320 * 1024;
    private const int MaximumSpillBytes = 64 * 1024;
    private const int MaximumBufferedItems = 64;

    private readonly object gate = new();
    private readonly RunOutputSpool spool;
    private readonly int byteBudget;
    private readonly int spillCapacity;
    private readonly RunTerminalMode terminalMode;
    private readonly Queue<CaptureItem> queue = new(MaximumBufferedItems + 2);
    private readonly CaptureItem?[] spills = new CaptureItem?[3];
    private readonly TaskCompletionSource completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Exception? captureFailure;
    private int bufferedBytes;
    private int bufferedItems;
    private bool accepting = true;
    private bool abandon;

    private sealed class CaptureItem(RunOutputStream stream)
    {
        public RunOutputStream Stream { get; } = stream;
        public ulong DroppedBefore { get; set; }
        public byte[]? Buffer { get; set; }
        public int Length { get; set; }
        public bool IsSpill { get; init; }
    }

    private RunOutputCapture(RunOutputSpool spool, RunLaunchSpec spec)
    {
        this.spool = spool;
        byteBudget = (int)Math.Min((ulong)MaximumBufferedBytes, spec.OutputLimitBytes);
        spillCapacity = (int)Math.Min((ulong)MaximumSpillBytes, spec.OutputLimitBytes);
        terminalMode = spec.TerminalMode;
        var worker = new Thread(Consume)
        {
            IsBackground = true,
            Name = "ArcForges Run output",
        };
        worker.Start();
    }

    public static RunOutputCapture Create(RunLaunchSpec spec)
    {
        var spool = RunOutputSpool.Create(spec);
        try
        {
            return new RunOutputCapture(spool, spec);
        }
        catch
        {
            spool.Dispose();
            throw;
        }
    }

    public void Capture(RunOutputStream stream, ReadOnlySpan<byte> bytes)
    {
        int slot = StreamSlot(stream);
        lock (gate)
        {
            if (!accepting || bytes.IsEmpty)
            {
                return;
            }

            if (spills[slot] is not null || bufferedItems == MaximumBufferedItems || bytes.Length > byteBudget - bufferedBytes)
            {
                BufferSpill(GetSpill(stream, slot), bytes);
            }
            else
            {
                queue.Enqueue(new CaptureItem(stream) { Buffer = bytes.ToArray(), Length = bytes.Length });
                bufferedBytes += bytes.Length;
                bufferedItems++;
            }

            Monitor.Pulse(gate);
        }
    }

    public void RecordDropped(RunOutputStream stream, ulong byteCount)
    {
        int slot = StreamSlot(stream);
        lock (gate)
        {
            if (accepting && byteCount > 0)
            {
                var spill = GetSpill(stream, slot);
                _ = AddLoss(spill, (ulong)spill.Length) && AddLoss(spill, byteCount);
                spill.Length = 0;
                Monitor.Pulse(gate);
            }
        }
    }

    /// <summary>Flushes the admitted output after the last native read and publishes clean EOF.</summary>
    public Task CompleteAsync()
    {
        lock (gate)
        {
            accepting = false;
            Monitor.Pulse(gate);
            return completion.Task;
        }
    }

    /// <summary>Discards queued work without waiting for any storage operation already in progress.</summary>
    public void Dispose()
    {
        lock (gate)
        {
            accepting = false;
            abandon = true;
            queue.Clear();
            Array.Clear(spills);
            Monitor.Pulse(gate);
        }
    }

    private CaptureItem GetSpill(RunOutputStream stream, int slot)
    {
        if (spills[slot] is not { } spill)
        {
            // One marker sits behind all previously admitted bytes. This stream keeps
            // its latest suffix there until the worker takes the marker in order.
            spill = new CaptureItem(stream) { IsSpill = true };
            spills[slot] = spill;
            queue.Enqueue(spill);
        }

        return spill;
    }

    private void BufferSpill(CaptureItem spill, ReadOnlySpan<byte> bytes)
    {
        int newest = Math.Min(spillCapacity, bytes.Length);
        int previous = Math.Min(spill.Length, spillCapacity - newest);
        ulong lost = (ulong)(spill.Length - previous) + (ulong)(bytes.Length - newest);
        if (!AddLoss(spill, lost) || newest == 0)
        {
            return;
        }

        var buffer = spill.Buffer ??= new byte[spillCapacity];
        buffer.AsSpan(spill.Length - previous, previous).CopyTo(buffer);
        bytes[^newest..].CopyTo(buffer.AsSpan(previous));
        spill.Length = previous + newest;
    }

    private bool AddLoss(CaptureItem item, ulong bytes)
    {
        if (ulong.MaxValue - item.DroppedBefore < bytes)
        {
            captureFailure = new InvalidDataException("run_output_offset_overflow");
            accepting = false;
            abandon = true;
            Monitor.Pulse(gate);
            return false;
        }

        item.DroppedBefore += bytes;
        return true;
    }

    private int StreamSlot(RunOutputStream stream) => (terminalMode, stream) switch
    {
        (RunTerminalMode.Interactive, RunOutputStream.Terminal) => 0,
        (RunTerminalMode.Pipes, RunOutputStream.Stdout) => 1,
        (RunTerminalMode.Pipes, RunOutputStream.Stderr) => 2,
        _ => throw new ArgumentException("run_output_stream_unavailable", nameof(stream)),
    };

    private CaptureItem? Take()
    {
        lock (gate)
        {
            while (!abandon)
            {
                if (queue.TryDequeue(out var item))
                {
                    if (item.IsSpill)
                    {
                        spills[StreamSlot(item.Stream)] = null;
                    }

                    return item;
                }

                if (!accepting)
                {
                    break;
                }

                Monitor.Wait(gate);
            }

            return null;
        }
    }

    private bool CanSeal()
    {
        lock (gate)
        {
            return !abandon;
        }
    }

    private void Consume()
    {
        Exception? failure = null;
        bool sealedOutput = false;
        try
        {
            while (Take() is { } item)
            {
                if (item.DroppedBefore > 0)
                {
                    spool.RecordDropped(item.Stream, item.DroppedBefore);
                }

                if (item.Length > 0 && CanSeal())
                {
                    spool.Append(item.Stream, item.Buffer.AsSpan(0, item.Length));
                }

                if (!item.IsSpill)
                {
                    lock (gate)
                    {
                        bufferedBytes -= item.Length;
                        bufferedItems--;
                    }
                }
            }

            // The same abort check before replacement covers a stall in preparing the final index.
            sealedOutput = CanSeal() && spool.TryComplete(CanSeal);
        }
        catch (Exception error)
        {
            failure = error;
        }
        finally
        {
            lock (gate)
            {
                accepting = false;
                queue.Clear();
                Array.Clear(spills);
                failure ??= captureFailure;
            }

            try
            {
                spool.Dispose();
            }
            catch (Exception error)
            {
                failure ??= error;
            }

            if (failure is not null)
            {
                completion.TrySetException(failure);
            }
            else if (sealedOutput)
            {
                completion.TrySetResult();
            }
            else
            {
                completion.TrySetCanceled();
            }
        }
    }
}
