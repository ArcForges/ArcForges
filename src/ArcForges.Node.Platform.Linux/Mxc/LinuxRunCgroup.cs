// SPDX-License-Identifier: AGPL-3.0-only
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
    private static readonly int s_noFollow = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x8000 : 0x20000;
    private static readonly int s_directory = RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? 0x4000 : 0x10000;
    private readonly SafeFileHandle _handle;

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
        var content = new char[maximum + 1];
        var count = reader.ReadBlock(content);
        return count <= maximum ? new string(content, 0, count).Trim() : throw new IOException("A native observation exceeds its bound.");
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

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int Statx(SafeFileHandle handle, string path, int flags, uint mask, out FileMetadata metadata);

    [LibraryImport("libc", EntryPoint = "fstatfs", SetLastError = true)]
    private static partial int FileSystem(SafeFileHandle handle, out FileSystemMetadata metadata);

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint EffectiveUser();
}
