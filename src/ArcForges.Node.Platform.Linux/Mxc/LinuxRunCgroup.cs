// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Linux.Mxc;

internal sealed record LinuxRunLimits(ulong CpuQuota, ulong CpuPeriod, ulong MemoryBytes, ulong SwapBytes, ulong Tasks, ulong? CpuWeight);

[SupportedOSPlatform("linux")]
internal sealed partial class LinuxRunCgroup : IDisposable
{
    private const string MountPoint = "/sys/fs/cgroup";
    private const uint RequiredMetadata = 0x1101;
    private const int CloseOnExec = 0x80000;
    private const int NonBlockingNoTerminal = 0x900;
    private const ulong CpuPeriodUsec = 100_000;
    private const ulong CpuQuotaUsecPerMillicore = CpuPeriodUsec / 1000;
    private static readonly int s_noFollow = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x8000 : 0x20000;
    private static readonly int s_directory = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x4000 : 0x10000;
    private readonly SafeFileHandle _handle;
    private readonly Lock _resources = new();
    private ulong? _lastCpuUsec;
    private ulong? _lastMemoryPeak;
    private ulong? _lastOomKills;
    private long _pressureAt = long.MinValue;
    private (double? CpuSome, double? MemorySome, double? MemoryFull) _pressure;

    private LinuxRunCgroup(string path, SafeFileHandle handle, FileMetadata metadata)
    {
        Path = path;
        _handle = handle;
        Inode = metadata.Inode;
        MountId = metadata.MountId;
    }

    internal string Path { get; }
    internal ulong Inode { get; }
    internal ulong MountId { get; }
    internal static uint UserId => EffectiveUser();

    internal static LinuxRunCgroup Open(string path)
    {
        var userId = UserId.ToString(CultureInfo.InvariantCulture);
        var prefix = "/user.slice/user-" + userId + ".slice/user@" + userId + ".service/";
        if (!path.StartsWith(prefix, StringComparison.Ordinal) || path.Length > 1024
            || path[1..].Split('/').Any(part => part is "" or "." or ".." || part.Contains('\0')))
        {
            throw new IOException("The reported cgroup is outside the local user manager.");
        }

        using var root = OpenDirectory(null, MountPoint);
        if (FileSystem(root, out var fileSystem) != 0)
        {
            throw NativeError("read cgroup filesystem");
        }

        if (fileSystem.Type != 0x63677270)
        {
            throw new IOException("The local resource mount is not cgroup v2.");
        }

        var rootMount = Metadata(root).MountId;
        SafeFileHandle? owned = null;
        try
        {
            foreach (var part in path[1..].Split('/'))
            {
                var next = OpenDirectory(owned ?? root, part);
                owned?.Dispose();
                owned = next;
                if (Metadata(next).MountId != rootMount)
                {
                    throw new IOException("The resource scope crosses the cgroup v2 mount.");
                }
            }

            var result = new LinuxRunCgroup(path, owned!, Metadata(owned!));
            owned = null;
            return result;
        }
        finally
        {
            owned?.Dispose();
        }
    }

    internal LinuxRunLimits ReadLimits()
    {
        Validate();
        var cpu = Fields(ReadControl(_handle, "cpu.max"));
        if (cpu.Length != 2)
        {
            throw new IOException("The cgroup CPU limit is invalid.");
        }

        var limits = new LinuxRunLimits(Number(cpu[0]), Number(cpu[1]), Number(ReadControl(_handle, "memory.max")),
            Number(ReadControl(_handle, "memory.swap.max")), Number(ReadControl(_handle, "pids.max")),
            Number(ReadControl(_handle, "cpu.weight")));
        Validate();
        return limits;
    }

    internal RunResourceLimitReading? ReadOwnedLimits(string boundary, int ownerPid, long ownerStart)
    {
        lock (_resources)
        {
            var retained = false;
            try
            {
                _handle.DangerousAddRef(ref retained);
                if (!HasResourceOwner(ownerPid, ownerStart))
                {
                    return null;
                }

                Span<byte> buffer = stackalloc byte[256];
                var cpu = ReadCpuLimit(ReadResource("cpu.max", buffer));
                var memory = ProcFs.Unsigned(ReadResource("memory.max", buffer));
                var processes = ProcFs.Unsigned(ReadResource("pids.max", buffer));
                var weight = ProcFs.Unsigned(ReadResource("cpu.weight", buffer));
                var swap = ProcFs.Unsigned(ReadResource("memory.swap.max", buffer));
                return HasResourceOwner(ownerPid, ownerStart)
                    ? new RunResourceLimitReading(boundary, cpu, memory, processes, weight, swap) : null;
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                return null;
            }
            finally
            {
                if (retained)
                {
                    _handle.DangerousRelease();
                }
            }
        }
    }

    internal static ulong? NormalizeRunLimit(RunResourceDimension dimension, ulong value)
    {
        var page = (ulong)Environment.SystemPageSize;
        return dimension switch
        {
            // cgroup v2's minimum quota is 1 ms per 100 ms period, i.e. ten millicores.
            RunResourceDimension.Cpu when value is >= 10 and <= uint.MaxValue => value,
            RunResourceDimension.Memory when value >= page && value <= long.MaxValue => value - value % page,
            RunResourceDimension.ProcessCount when value is > 0 and <= uint.MaxValue => value,
            RunResourceDimension.CpuWeight when value is > 0 and <= 10_000 => value,
            RunResourceDimension.Swap when value == 0 => value,
            _ => null,
        };
    }

    internal RunResourceWriteResult ApplyOwnedLimit(RunResourceDimension dimension, ulong requested, int ownerPid, long ownerStart)
    {
        if (dimension is not (RunResourceDimension.Cpu or RunResourceDimension.Memory or RunResourceDimension.CpuWeight)
            || NormalizeRunLimit(dimension, requested) is not { } value)
        {
            return new(RunResourceWriteStatus.Unsupported, Reason: "linux_limit_unavailable");
        }

        lock (_resources)
        {
            var retained = false;
            try
            {
                _handle.DangerousAddRef(ref retained);
                if (!HasResourceOwner(ownerPid, ownerStart))
                {
                    return ScopeLost();
                }

                if (dimension == RunResourceDimension.Memory)
                {
                    Span<byte> buffer = stackalloc byte[256];
                    if (ProcFs.Unsigned(ReadResource("memory.max", buffer)) is not { } current)
                    {
                        return new(RunResourceWriteStatus.Failed, Reason: "linux_memory_limit_read_unavailable");
                    }

                    // Allocation can race a below-limit memory.current sample. Lowering the live hard
                    // boundary could reclaim or OOM; no sample authorizes that effect.
                    if (value < current)
                    {
                        return new(RunResourceWriteStatus.Unsupported, Reason: "linux_live_memory_reduction_unsafe");
                    }
                }

                var (name, text) = dimension switch
                {
                    RunResourceDimension.Cpu => ("cpu.max", string.Create(CultureInfo.InvariantCulture,
                        $"{value * CpuQuotaUsecPerMillicore} {CpuPeriodUsec}")),
                    RunResourceDimension.Memory => ("memory.max", value.ToString(CultureInfo.InvariantCulture)),
                    _ => ("cpu.weight", value.ToString(CultureInfo.InvariantCulture)),
                };
                using var file = Owned(OpenAt(_handle, name, CloseOnExec | s_noFollow | NonBlockingNoTerminal | 1), "write " + name);
                var metadata = Metadata(file);
                if (metadata.MountId != MountId || (metadata.Mode & 0xf000) != 0x8000 || !HasResourceOwner(ownerPid, ownerStart))
                {
                    return ScopeLost();
                }

                WriteLimit(file, text);
                return HasResourceOwner(ownerPid, ownerStart)
                    ? new(RunResourceWriteStatus.Applied, value) : ScopeLost();
            }
            catch (ObjectDisposedException)
            {
                return ScopeLost();
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException)
            {
                if (!CanIdentifyResourceOwner(ownerPid, ownerStart))
                {
                    return ScopeLost();
                }

                string reason = error.InnerException is Win32Exception native
                    ? "linux_errno_" + native.NativeErrorCode.ToString(CultureInfo.InvariantCulture) : "linux_control_write_failed";
                return new(RunResourceWriteStatus.Failed, Reason: reason);
            }
            finally
            {
                if (retained)
                {
                    _handle.DangerousRelease();
                }
            }
        }
    }

    private static ulong? ReadCpuLimit(ReadOnlySpan<byte> text)
    {
        text = text.Trim(" \t\r\n"u8);
        var separator = text.IndexOf((byte)' ');
        if (separator < 0 || ProcFs.Unsigned(text[..separator]) is not { } quota || quota % CpuQuotaUsecPerMillicore != 0
            || ProcFs.Unsigned(text[(separator + 1)..]) != CpuPeriodUsec)
        {
            return null;
        }

        return NormalizeRunLimit(RunResourceDimension.Cpu, quota / CpuQuotaUsecPerMillicore);
    }

    private bool HasResourceOwner(int pid, long start) => HasResourceIdentity() && MatchesProcess(pid, start, Path);

    private bool CanIdentifyResourceOwner(int pid, long start)
    {
        try
        {
            return HasResourceOwner(pid, start);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            return false;
        }
    }

    private static RunResourceWriteResult ScopeLost() => new(RunResourceWriteStatus.ScopeLost, Reason: "linux_resource_scope_lost");

    private static unsafe void WriteLimit(SafeFileHandle file, string text)
    {
        Span<byte> buffer = stackalloc byte[64];
        var length = Encoding.ASCII.GetBytes(text, buffer);
        fixed (byte* data = buffer)
        {
            var count = Write(file, data, (nuint)length);
            if (count < 0)
            {
                throw NativeError("write native cgroup limit");
            }

            if (count != length)
            {
                throw new IOException("The native cgroup control accepted only a partial write.");
            }
        }
    }

    internal RunResourceObservation? ObserveResources()
    {
        lock (_resources)
        {
            var retained = false;
            try
            {
                _handle.DangerousAddRef(ref retained);
                if (!HasResourceIdentity())
                {
                    return null;
                }

                Span<byte> buffer = stackalloc byte[8192];
                var cpu = ProcFs.NumericField(ReadResource("cpu.stat", buffer), "usage_usec "u8);
                var current = ProcFs.Unsigned(ReadResource("memory.current", buffer));
                var peak = ProcFs.Unsigned(ReadResource("memory.peak", buffer));
                var inactive = ProcFs.NumericField(ReadResource("memory.stat", buffer), "inactive_file "u8);
                var oomKills = ProcFs.NumericField(ReadResource("memory.events", buffer), "oom_kill "u8);
                var count = ObserveMemberCount();
                var now = Environment.TickCount64;
                if (_pressureAt == long.MinValue || now - _pressureAt >= (long)LinuxResourceSampler.SlowInterval.TotalMilliseconds)
                {
                    var cpuSome = ProcFs.PsiAverage(ReadResource("cpu.pressure", buffer), "some avg10="u8);
                    var memory = ReadResource("memory.pressure", buffer);
                    _pressure = (cpuSome, ProcFs.PsiAverage(memory, "some avg10="u8), ProcFs.PsiAverage(memory, "full avg10="u8));
                    _pressureAt = now;
                }

                if (!HasResourceIdentity())
                {
                    return null;
                }

                return new RunResourceObservation(RunMemoryAccounting.LinuxCgroupCurrent)
                {
                    CumulativeCpuUsec = ProcFs.AcceptCumulative(cpu, ref _lastCpuUsec),
                    MemoryBytes = current,
                    PeakMemoryBytes = ProcFs.AcceptCumulative(peak < current ? null : peak, ref _lastMemoryPeak),
                    ResidentBytes = current is { } bytes && inactive is { } cache && cache <= bytes ? bytes - cache : null,
                    OomKills = ProcFs.AcceptCumulative(oomKills, ref _lastOomKills),
                    ProcessCount = count,
                    PsiCpuSome = _pressure.CpuSome,
                    PsiMemorySome = _pressure.MemorySome,
                    PsiMemoryFull = _pressure.MemoryFull,
                };
            }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                return null;
            }
            finally
            {
                if (retained)
                {
                    _handle.DangerousRelease();
                }
            }
        }
    }

    private bool HasResourceIdentity() => Validate().Links > 0 &&
        new DirectoryInfo(DescriptorPath(_handle)).LinkTarget == MountPoint + Path;

    private uint? ObserveMemberCount()
    {
        try
        {
            // pids.current includes threads. The published process count is distinct processes in the verified subtree.
            return (uint)ReadMembers().Count;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private ReadOnlySpan<byte> ReadResource(string name, Span<byte> buffer)
    {
        try
        {
            using var file = Owned(OpenAt(_handle, name, CloseOnExec | s_noFollow | NonBlockingNoTerminal), "read " + name);
            var metadata = Metadata(file);
            if (metadata.MountId != MountId || (metadata.Mode & 0xf000) != 0x8000)
            {
                return [];
            }

            var length = 0;
            while (length < buffer.Length)
            {
                var read = RandomAccess.Read(file, buffer[length..], length);
                if (read == 0)
                {
                    return buffer[..length];
                }

                length += read;
            }

            return [];
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    internal bool ContainsOnlyOwner(int pid, long start)
    {
        if (!MatchesProcess(pid, start, Path) || IsRemoved())
        {
            return false;
        }

        var members = ReadMembers();
        return members.Count == 1 && members.Contains(pid) && MatchesProcess(pid, start, Path);
    }

    internal bool TryContainsOnlyOwner(int pid, long start)
    {
        try
        {
            return ContainsOnlyOwner(pid, start);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal bool IsEmpty()
    {
        if (IsRemoved())
        {
            return true;
        }

        try
        {
            var events = ReadControl(_handle, "cgroup.events").Split('\n');
            if (!events.Contains("populated 0", StringComparer.Ordinal))
            {
                return false;
            }

            return ReadMembers().Count == 0;
        }
        catch (IOException) when (IsRemoved())
        {
            return true;
        }
    }

    internal static string BootId()
    {
        using var stream = File.OpenRead("/proc/sys/kernel/random/boot_id");
        var value = ReadText(stream, 128);
        return Guid.TryParseExact(value, "D", out _) ? value : throw new IOException("Linux boot identity is invalid.");
    }

    internal static bool MatchesProcess(int pid, long start, string path)
    {
        if (pid <= 0 || start <= 0 || ProcFs.Stat(pid) is not { State: not ('Z' or 'X') } process || process.StartTicks != start)
        {
            return false;
        }

        try
        {
            var proc = "/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/cgroup";
            using var stream = File.OpenRead(proc);
            var lines = ReadText(stream, 8192).Split('\n');
            return lines.Contains("0::" + path, StringComparer.Ordinal)
                && ProcFs.Stat(pid) is { State: not ('Z' or 'X') } confirmed && confirmed.StartTicks == start;
        }
        catch (IOException)
        {
            return false;
        }
    }

    internal static void RequireTrustedTool(string path)
    {
        using var handle = OpenTrustedFile(path, rootOnly: true, executable: true);
    }

    internal static void RequireSupervisor(string path)
    {
        using var handle = OpenTrustedFile(path, rootOnly: false, executable: true);
    }

    internal static SafeFileHandle OpenTrustedFile(string path, bool rootOnly, bool executable)
    {
        var handle = OpenDirectory(null, path, directory: false);
        try
        {
            var metadata = Metadata(handle);
            if ((metadata.Uid != 0 && (rootOnly || metadata.Uid != UserId))
                || (metadata.Mode & 0xF012) != 0x8000 || (executable && (metadata.Mode & 0x0049) == 0))
            {
                throw new IOException("The native Run artifact is not a protected file.");
            }

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static void RequirePrivateRuntime(string path)
    {
        using var handle = OpenPrivateDirectory(path);
    }

    internal static SafeFileHandle OpenPrivateDirectory(string path)
    {
        var handle = OpenDirectory(null, path);
        try
        {
            var metadata = Metadata(handle);
            if (metadata.Uid != UserId || (metadata.Mode & 0xF1FF) != 0x41C0)
            {
                throw new IOException("The native Run directory is not owner-private.");
            }

            return handle;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private HashSet<int> ReadMembers()
    {
        Validate();
        var members = new HashSet<int>();
        var directories = 0;
        Collect(_handle, members, ref directories, 0);
        Validate();
        return members;
    }

    private void Collect(SafeFileHandle handle, HashSet<int> members, ref int directories, int depth)
    {
        if (++directories > 64 || depth > 8 || Metadata(handle).MountId != MountId)
        {
            throw new IOException("The cgroup subtree cannot be observed safely.");
        }

        foreach (var token in Fields(ReadControl(handle, "cgroup.procs")))
        {
            if (!int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid <= 0)
            {
                throw new IOException("The cgroup contains an invalid process identity.");
            }

            members.Add(pid);
            if (members.Count > 4096)
            {
                throw new IOException("The cgroup process observation exceeds its bound.");
            }
        }

        foreach (var child in Directory.EnumerateDirectories(DescriptorPath(handle)))
        {
            using var subdirectory = OpenDirectory(handle, System.IO.Path.GetFileName(child));
            Collect(subdirectory, members, ref directories, depth + 1);
        }
    }

    private bool IsRemoved()
    {
        var metadata = Validate();
        if (metadata.Links == 0)
        {
            return true;
        }

        // kernfs can report its synthetic directory link count after unlink.
        // Only the exact held descriptor's deleted-dentry observation also proves removal.
        var link = new DirectoryInfo(DescriptorPath(_handle)).LinkTarget;
        Validate();
        return link == MountPoint + Path + " (deleted)";
    }

    private FileMetadata Validate()
    {
        var metadata = Metadata(_handle);
        return metadata.Inode == Inode && metadata.MountId == MountId
            ? metadata : throw new IOException("The held cgroup identity changed.");
    }

    internal static string DescriptorPath(SafeFileHandle handle) =>
        "/proc/self/fd/" + handle.DangerousGetHandle().ToInt32().ToString(CultureInfo.InvariantCulture);

    private static string ReadControl(SafeFileHandle handle, string name)
    {
        var descriptor = OpenAt(handle, name, CloseOnExec | s_noFollow);
        using var file = Owned(descriptor, "read " + name);
        using var stream = new FileStream(file, FileAccess.Read);
        return ReadText(stream, 65_536);
    }

    private static string ReadText(Stream stream, int maximum)
    {
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
        var content = ArrayPool<char>.Shared.Rent(maximum + 1);
        try
        {
            var count = reader.ReadBlock(content.AsSpan(0, maximum + 1));
            return count <= maximum ? new string(content, 0, count).Trim() : throw new IOException("A native observation exceeds its bound.");
        }
        finally
        {
            ArrayPool<char>.Shared.Return(content);
        }
    }

    private static string[] Fields(string value) => value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

    private static ulong Number(string value) => ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number)
        ? number : throw new IOException("An exact finite cgroup limit is unavailable.");

    private static SafeFileHandle OpenDirectory(SafeFileHandle? parent, string name, bool directory = true)
    {
        var flags = CloseOnExec | s_noFollow | (directory ? s_directory : 0x900); // O_NONBLOCK | O_NOCTTY for file inspection.
        var descriptor = parent is null ? OpenPath(name, flags) : OpenAt(parent, name, flags);
        return Owned(descriptor, "open native resource path");
    }

    private static SafeFileHandle Owned(int descriptor, string operation) => descriptor >= 0
        ? new SafeFileHandle(descriptor, ownsHandle: true) : throw NativeError(operation);

    private static FileMetadata Metadata(SafeFileHandle handle)
    {
        // AT_EMPTY_PATH reads the bound descriptor, including when its original path was removed.
        if (Statx(handle, "", 0x1000, RequiredMetadata | 0xC, out var metadata) != 0)
        {
            throw NativeError("inspect held resource identity");
        }

        return (metadata.Mask & (RequiredMetadata | 0xC)) == (RequiredMetadata | 0xC)
            ? metadata : throw new IOException("The native inode or mount identity is unavailable.");
    }

    private static IOException NativeError(string operation) =>
        new(operation, new Win32Exception(Marshal.GetLastPInvokeError()));

    public void Dispose() => _handle.Dispose();

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct FileMetadata
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(16)] internal uint Links;
        [FieldOffset(20)] internal uint Uid;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(144)] internal ulong MountId;
    }

    [StructLayout(LayoutKind.Explicit, Size = 120)]
    private struct FileSystemMetadata
    {
        [FieldOffset(0)] internal long Type;
    }

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenPath(string path, int flags);

    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAt(SafeFileHandle directory, string path, int flags);

    [LibraryImport("libc", EntryPoint = "write", SetLastError = true)]
    private static unsafe partial nint Write(SafeFileHandle file, byte* data, nuint count);

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Statx(SafeFileHandle handle, string path, int flags, uint mask, out FileMetadata metadata);

    [LibraryImport("libc", EntryPoint = "fstatfs", SetLastError = true)]
    private static partial int FileSystem(SafeFileHandle handle, out FileSystemMetadata metadata);

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint EffectiveUser();
}
