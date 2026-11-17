// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe.Linux;

internal sealed record LinuxScopeLimits(uint CpuMillicores, ulong MemoryBytes, uint ProcessLimit);
internal sealed record LinuxScopeIdentity(string Unit, string InvocationId, string BootId, int MainPid,
    ulong MainStartTicks, string ControlGroup, ulong CgroupInode, ulong CgroupMountId);
internal sealed record LinuxCgroupObservation(string ControlGroup, ulong Inode, ulong MountId, bool Removed,
    bool Populated, int[] ProcessIds, long CpuQuotaMicros, long CpuPeriodMicros, ulong? MemoryMaxBytes,
    ulong? PidsMax, ulong MemoryCurrentBytes, ulong PidsCurrent, Dictionary<string, ulong> CpuStat,
    Dictionary<string, ulong> MemoryEvents, Dictionary<string, ulong> PidsEvents)
{
    // A removed, held directory proves emptiness. Its counters/limits are the
    // last actual readback, explicitly not a new zero-valued measurement.
    public bool CountersAvailable => !Removed;
    public string? RemovalProof { get; init; }
    public uint? HeldLinkCount { get; init; }
}
internal sealed record LinuxScopeObservation(LinuxScopeIdentity Identity, string ActiveState, string SubState,
    string Result, int ExecMainCode, int ExecMainStatus, LinuxCgroupObservation Cgroup);

// This reader never writes cgroup.procs and never adopts a PID. Its directory
// descriptor pins the native scope even if its original name is later reused.
[SupportedOSPlatform("linux")]
internal sealed partial class LinuxCgroup : IDisposable
{
    private const int DirectoryFlags = 0x10000 | 0x20000 | 0x80000; // DIRECTORY, NOFOLLOW, CLOEXEC.
    private readonly SafeFileHandle _directory;
    private LinuxCgroupObservation? _last;
    private bool _disposed;

    internal string ControlGroup { get; }
    internal ulong Inode { get; }
    internal ulong MountId { get; }
    internal static uint UserId => GetEffectiveUserId();

    private LinuxCgroup(string controlGroup, SafeFileHandle directory, Statx metadata)
    { ControlGroup = controlGroup; _directory = directory; Inode = metadata.Inode; MountId = metadata.MountId; }

    internal static LinuxCgroup Open(string controlGroup)
    {
        if (!controlGroup.StartsWith("/user.slice/", StringComparison.Ordinal) || controlGroup.Length > 1024
            || controlGroup.Split('/').Any(x => x is "." or "..") || controlGroup.Contains('\0', StringComparison.Ordinal))
            throw new LinuxProbeException("cgroup_path_not_user_owned");
        using var root = OpenDirectory("/sys/fs/cgroup");
        if (ReadFileSystem(root, out var fileSystem) != 0) throw Error("cgroup_filesystem_identity");
        if (fileSystem.Type != 0x63677270) throw new LinuxProbeException("cgroup_v2_filesystem_required");
        var current = root;
        SafeFileHandle? owned = null;
        try
        {
            foreach (var part in controlGroup.Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                var next = OpenRelativeDirectory(current, part);
                owned?.Dispose();
                current = owned = next;
            }
            if (owned is null) throw new LinuxProbeException("cgroup_root_not_permitted");
            var metadata = Metadata(owned);
            var scope = new LinuxCgroup(controlGroup, owned, metadata);
            owned = null;
            return scope;
        }
        finally { owned?.Dispose(); }
    }

    internal LinuxCgroupObservation Read()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var metadata = ValidateIdentity();
        if (Removed(metadata, out var removalProof)) return RemovedObservation(metadata, removalProof);
        try
        {
            var events = Values(ReadText(_directory, "cgroup.events"));
            var cpu = ReadText(_directory, "cpu.max").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (cpu.Length != 2 || cpu[0] == "max") throw new LinuxProbeException("cgroup_cpu_unbounded_or_invalid");
            var processes = new HashSet<int>();
            var directories = 0;
            CollectProcesses(_directory, processes, ref directories, 0);
            var observed = new LinuxCgroupObservation(ControlGroup, Inode, MountId, false,
                Required(events, "populated") != 0, [.. processes.Order()], Number(cpu[0]), Number(cpu[1]),
                Limit(ReadText(_directory, "memory.max")), Limit(ReadText(_directory, "pids.max")),
                Unsigned(ReadText(_directory, "memory.current")), Unsigned(ReadText(_directory, "pids.current")),
                Values(ReadText(_directory, "cpu.stat")), Values(ReadText(_directory, "memory.events")), Values(ReadText(_directory, "pids.events")))
            { HeldLinkCount = metadata.LinkCount };
            ValidateIdentity();
            _last = observed;
            return observed;
        }
        catch (LinuxProbeException error) when (error.InnerException is Win32Exception)
        {
            metadata = ValidateIdentity();
            if (Removed(metadata, out removalProof)) return RemovedObservation(metadata, removalProof);
            throw;
        }
    }

    // The controller-absence experiment reads through the held native scope,
    // never through a same-named replacement or an assumed host configuration.
    internal (string Available, string Enabled, bool CpuMaxPresent) ReadControllerState()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Removed(ValidateIdentity(), out _)) throw new LinuxProbeException("controller_scope_removed");
        var available = ReadText(_directory, "cgroup.controllers");
        var enabled = ReadText(_directory, "cgroup.subtree_control");
        var descriptor = OpenAt(_directory, "cpu.max", 0x20000 | 0x80000);
        bool present;
        if (descriptor < 0)
        {
            if (Marshal.GetLastPInvokeError() != 2) throw Error("controller_cpu_max_open");
            present = false;
        }
        else { using var handle = new SafeFileHandle(descriptor, true); present = true; }
        if (Removed(ValidateIdentity(), out _)) throw new LinuxProbeException("controller_scope_removed_during_read");
        return (available, enabled, present);
    }

    internal bool EmptyProof()
    {
        if (Removed(ValidateIdentity(), out _)) return true;
        try
        {
            if (Required(Values(ReadText(_directory, "cgroup.events")), "populated") != 0) return false;
            var processes = new HashSet<int>(); var directories = 0;
            CollectProcesses(_directory, processes, ref directories, 0);
            return processes.Count == 0;
        }
        catch (LinuxProbeException error) when (error.InnerException is Win32Exception)
        {
            if (Removed(ValidateIdentity(), out _)) return true;
            throw;
        }
    }

    internal static ulong ProcessStartTicks(int pid)
    {
        var text = BoundedFile($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/stat", 8192);
        var close = text.LastIndexOf(')');
        if (close < 0) throw new LinuxProbeException("process_stat_invalid");
        var fields = text[(close + 1)..].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 20) throw new LinuxProbeException("process_stat_short");
        return Unsigned(fields[19]); // Field 22; the first field after ')' is field 3.
    }

    internal static string ProcessControlGroup(int pid)
    {
        var lines = BoundedFile($"/proc/{pid.ToString(CultureInfo.InvariantCulture)}/cgroup", 8192).Split('\n');
        var unified = lines.Where(x => x.StartsWith("0::/", StringComparison.Ordinal)).ToArray();
        if (unified.Length != 1) throw new LinuxProbeException("unified_process_cgroup_missing");
        return unified[0][3..].TrimEnd('\r');
    }

    internal static string BootId()
    {
        var value = BoundedFile("/proc/sys/kernel/random/boot_id", 128).Trim();
        return Guid.TryParseExact(value, "D", out _) ? value : throw new LinuxProbeException("boot_id_invalid");
    }

    internal static void VerifyTrustedProgram(string path)
    {
        using var file = OpenFile(path);
        var metadata = Metadata(file);
        if ((metadata.Mode & 0xF000) != 0x8000 || metadata.Uid != 0 || (metadata.Mode & 0x12) != 0)
            throw new LinuxProbeException("launcher_program_not_root_owned_regular_readonly");
    }

    internal static void VerifyPrivatePath(string path, bool directory)
    {
        using var handle = directory ? OpenDirectory(path) : OpenFile(path);
        var metadata = Metadata(handle);
        if (metadata.Uid != UserId || (metadata.Mode & 0x3F) != 0
            || (metadata.Mode & 0xF000) != (directory ? 0x4000 : 0x8000))
            throw new LinuxProbeException("owner_control_path_not_private");
        var current = Path.GetFullPath(path);
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new LinuxProbeException("owner_path_symlink_forbidden");
            current = Path.GetDirectoryName(current);
        }
    }

    private Statx ValidateIdentity()
    {
        var metadata = Metadata(_directory);
        if (metadata.Inode != Inode || metadata.MountId != MountId) throw new LinuxProbeException("held_cgroup_identity_changed");
        return metadata;
    }

    private LinuxCgroupObservation RemovedObservation(Statx metadata, string proof) => _last is { } previous
        ? previous with { Removed = true, Populated = false, ProcessIds = [], RemovalProof = proof, HeldLinkCount = metadata.LinkCount }
        : throw new LinuxProbeException("cgroup_removed_before_initial_readback");

    private bool Removed(Statx metadata, out string proof)
    {
        if (metadata.LinkCount == 0) { proof = "held_inode_nlink_zero"; return true; }
        // kernfs getattr refreshes directory nlink to subdirs + 2, even after
        // removal. ENOENT on a control file alone therefore proves nothing.
        // The kernel's deleted-dentry suffix on this exact held descriptor,
        // bracketed by mount/inode checks, proves the original scope was
        // unlinked; a same-named replacement cannot satisfy this observation.
        if (DescriptorTarget() == "/sys/fs/cgroup" + ControlGroup + " (deleted)")
        { ValidateIdentity(); proof = "held_dentry_unlinked"; return true; }
        proof = "";
        return false;
    }

    private unsafe string DescriptorTarget()
    {
        var referenced = false;
        try
        {
            _directory.DangerousAddRef(ref referenced);
            var descriptor = "/proc/self/fd/" + _directory.DangerousGetHandle().ToInt32().ToString(CultureInfo.InvariantCulture);
            Span<byte> buffer = stackalloc byte[4096];
            nint count;
            fixed (byte* bytes = buffer) count = ReadLink(descriptor, bytes, (nuint)buffer.Length);
            if (count < 0) throw Error("cgroup_held_dentry_readlink");
            if (count >= buffer.Length) throw new LinuxProbeException("cgroup_held_dentry_path_bound");
            return new UTF8Encoding(false, true).GetString(buffer[..(int)count]);
        }
        finally { if (referenced) _directory.DangerousRelease(); }
    }

    private static void CollectProcesses(SafeFileHandle directory, HashSet<int> processes, ref int directories, int depth)
    {
        if (++directories > 64 || depth > 8) throw new LinuxProbeException("owned_cgroup_subtree_bound_exceeded");
        foreach (var token in ReadText(directory, "cgroup.procs").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            if (!int.TryParse(token, NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid <= 0)
                throw new LinuxProbeException("cgroup_process_id_invalid");
            processes.Add(pid);
            if (processes.Count > 4096) throw new LinuxProbeException("cgroup_process_observation_bound_exceeded");
        }
        var descriptorPath = "/proc/self/fd/" + directory.DangerousGetHandle().ToInt32().ToString(CultureInfo.InvariantCulture);
        foreach (var child in Directory.EnumerateDirectories(descriptorPath).Take(65))
        {
            using var subdirectory = OpenRelativeDirectory(directory, Path.GetFileName(child));
            CollectProcesses(subdirectory, processes, ref directories, depth + 1);
        }
    }

    private static string ReadText(SafeFileHandle directory, string name)
    {
        var fd = OpenAt(directory, name, 0x20000 | 0x80000);
        if (fd < 0) throw Error("cgroup_read_" + name.Replace('.', '_'));
        using var handle = new SafeFileHandle(fd, true);
        using var stream = new FileStream(handle, FileAccess.Read);
        return BoundedText(stream, 65_536);
    }

    private static string BoundedFile(string path, int maximum)
    { using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); return BoundedText(file, maximum); }

    private static string BoundedText(Stream stream, int maximum)
    {
        var bytes = new byte[maximum + 1]; var offset = 0;
        while (offset < bytes.Length)
        { var read = stream.Read(bytes, offset, bytes.Length - offset); if (read == 0) break; offset += read; }
        if (offset > maximum) throw new LinuxProbeException("native_file_observation_bound_exceeded");
        return new UTF8Encoding(false, true).GetString(bytes, 0, offset).Trim();
    }

    private static Dictionary<string, ulong> Values(string text)
    {
        var result = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 2 || !result.TryAdd(fields[0], Unsigned(fields[1]))) throw new LinuxProbeException("cgroup_key_value_invalid");
        }
        return result;
    }

    private static ulong Required(Dictionary<string, ulong> values, string name) => values.TryGetValue(name, out var value) ? value : throw new LinuxProbeException("cgroup_required_counter_missing");
    private static ulong Unsigned(string value) => ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
        ? parsed : throw new LinuxProbeException("cgroup_unsigned_counter_invalid");
    private static long Number(string value) => long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
        ? parsed : throw new LinuxProbeException("cgroup_numeric_counter_invalid");
    private static ulong? Limit(string value) => value == "max" ? null : Unsigned(value);

    private static SafeFileHandle OpenDirectory(string path)
    { var fd = OpenNative(path, DirectoryFlags); if (fd < 0) throw Error("open_cgroup_directory"); return new(fd, true); }
    private static SafeFileHandle OpenRelativeDirectory(SafeFileHandle parent, string name)
    {
        if (name is "" or "." or ".." || name.Contains('/', StringComparison.Ordinal)) throw new LinuxProbeException("cgroup_child_name_invalid");
        var fd = OpenAt(parent, name, DirectoryFlags); if (fd < 0) throw Error("open_cgroup_child"); return new(fd, true);
    }
    private static SafeFileHandle OpenFile(string path)
    { var fd = OpenNative(path, 0x20000 | 0x80000); if (fd < 0) throw Error("open_native_regular_file"); return new(fd, true); }
    private static Statx Metadata(SafeFileHandle handle)
    {
        if (ReadStatx(handle, "", 0x1000, 0x7ff | 0x1000, out var metadata) != 0) throw Error("statx_held_native_identity");
        if ((metadata.Mask & (0x100 | 0x1000)) != (0x100 | 0x1000)) throw new LinuxProbeException("native_inode_mount_identity_unavailable");
        return metadata;
    }
    private static LinuxProbeException Error(string phase) => new(phase, new Win32Exception(Marshal.GetLastPInvokeError(), phase));
    public void Dispose() { if (_disposed) return; _directory.Dispose(); _disposed = true; }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(16)] internal uint LinkCount;
        [FieldOffset(20)] internal uint Uid;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(144)] internal ulong MountId;
    }
    [StructLayout(LayoutKind.Explicit, Size = 120)]
    private struct Statfs { [FieldOffset(0)] internal long Type; }
    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)] private static partial int OpenNative(string path, int flags);
    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)] private static partial int OpenAt(SafeFileHandle directory, string path, int flags);
    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)] private static partial int ReadStatx(SafeFileHandle fd, string path, int flags, uint mask, out Statx metadata);
    [LibraryImport("libc", EntryPoint = "fstatfs", SetLastError = true)] private static partial int ReadFileSystem(SafeFileHandle fd, out Statfs metadata);
    [LibraryImport("libc", EntryPoint = "readlink", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)] private static unsafe partial nint ReadLink(string path, byte* buffer, nuint size);
    [LibraryImport("libc", EntryPoint = "geteuid")] private static partial uint GetEffectiveUserId();
}
