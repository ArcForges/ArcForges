// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Client;

/// <summary>Preserves and temporarily unnames a drained, verified legacy installation.</summary>
public static partial class NodeUpdateInstallationCustody
{
    private const string LockName = ".node-update-install.lock";
    private const int LinuxDirectory = 0x10000 | 0x20000 | 0x80000;
    private const int LinuxRegularLock = 2 | 0x40 | 0x800 | 0x20000 | 0x80000;
    private const ushort UnixDirectory = 0x4000;
    private const ushort UnixRegular = 0x8000;

    /// <summary>Reports whether the exact verified version has been parked by the offline updater.</summary>
    public static bool IsParked(string appRoot, string archiveSha256)
    {
        var canonical = NodeVersionSelection.InstallationDirectory(appRoot, archiveSha256);
        var parked = NodeVersionSelection.ParkedDirectory(canonical);
        if (NodeVersionSelection.Attributes(canonical) is not null || NodeVersionSelection.Attributes(parked) is null)
        {
            return false;
        }

        NodeVersionSelection.RequireDirectory(parked, create: false);
        if (OperatingSystem.IsLinux())
        {
            using var exclusion = AcquireLinux(Path.GetDirectoryName(parked)!, existingOnly: true);
            int parent = Descriptor(exclusion.LinuxRoot!);
            using var directory = OpenLinux(parent, Path.GetFileName(parked), LinuxDirectory);
            using var executable = OpenLinuxExecutable(directory);
            var state = LinuxExecutableState(executable.SafeFileHandle);
            var receipt = ReadLinuxMode(parent, archiveSha256)
                ?? throw new IOException("node_update_linux_parked_mode_evidence_missing");
            RequireRecordedMode(receipt, state);
            if (ExecutablePermissions(state) != receipt.ParkedPermissions)
            {
                throw new IOException("node_update_linux_parked_executable_mode_unconfirmed");
            }
        }

        return true;
    }

    /// <summary>Finds the one physical location of a recorded previous installation.</summary>
    public static NodeUpdateInstallation ResolvePrevious(string appRoot, NodeUpdateInstallation previous)
    {
        var canonical = RequireCanonical(appRoot, previous);
        var parked = NodeVersionSelection.ParkedDirectory(canonical);
        var canonicalExists = NodeVersionSelection.Attributes(canonical) is not null;
        var parkedExists = NodeVersionSelection.Attributes(parked) is not null;
        if (canonicalExists == parkedExists)
        {
            throw new IOException("node_update_previous_installation_custody_ambiguous");
        }

        var actual = canonicalExists ? canonical : parked;
        NodeVersionSelection.RequireDirectory(actual, create: false);
        return previous with { Root = actual };
    }

    /// <summary>Moves a verified previous cohort after the caller has recorded intent and owns the inactive Node lease.</summary>
    public static void Park(string appRoot, NodeUpdateInstallation previous, bool testMode) => Move(appRoot, previous, testMode, park: true);

    /// <summary>Restores the exact previous path while the caller owns the inactive Node lease.</summary>
    public static void Restore(string appRoot, NodeUpdateInstallation previous, bool testMode) => Move(appRoot, previous, testMode, park: false);

    internal static IDisposable EnterStaging(string destination)
    {
        var parent = Path.GetDirectoryName(destination)!;
        if (!string.Equals(Path.GetFileName(parent), "versions", PathComparison))
        {
            throw new IOException("node_update_managed_installation_required");
        }

        var lease = Acquire(parent);
        try
        {
            if (NodeVersionSelection.Attributes(NodeVersionSelection.ParkedDirectory(destination)) is not null
                || OperatingSystem.IsLinux() && ReadLinuxMode(Descriptor(lease.LinuxRoot!), Path.GetFileName(destination)) is not null)
            {
                throw new IOException("node_update_previous_installation_parked_use_resume_or_rollback");
            }

            return lease;
        }
        catch
        {
            lease.Dispose();
            throw;
        }
    }

    private static void Move(string appRoot, NodeUpdateInstallation previous, bool testMode, bool park)
    {
        if (OperatingSystem.IsWindows() && testMode && NodeLocations.EndpointOverride(testMode) is null)
        {
            throw new IOException("node_update_windows_handoff_test_endpoint_required");
        }

        var canonical = RequireCanonical(appRoot, previous);
        using var exclusion = Acquire(Path.GetDirectoryName(canonical)!);
        var target = park ? NodeVersionSelection.ParkedDirectory(canonical) : canonical;
        var source = ResolvePrevious(appRoot, previous);
        if (OperatingSystem.IsLinux())
        {
            MoveLinux(exclusion, source, target, park);
            return;
        }

        NodeUpdateLauncher.RequireTrustedManifest(source);
        RequireExecutable(NodeUpdateLauncher.Executable(source.Root));
        RequireExecutable(Path.Combine(source.Root, NodeAutoStart.SupervisorFileName));
        if (string.Equals(source.Root, target, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        MoveWindows(source.Root, target, testMode);
    }

    private static void MoveWindows(string source, string target, bool testMode)
    {
        using var holder = new Mutex(initiallyOwned: false, NodeLocations.WindowsSupervisorMutexName(NodeLocations.InstanceKey(testMode)));
        if (!WaitForHolder(holder))
        {
            throw new IOException("node_update_windows_previous_holder_still_live");
        }

        try
        {
            const uint WriteThrough = 8;
            for (int attempt = 0; ; attempt++)
            {
                if (NodeVersionSelection.MoveFileEx(source, target, WriteThrough))
                {
                    return;
                }

                int error = Marshal.GetLastPInvokeError();
                if (attempt == 10 || error is not (5 or 32 or 33))
                {
                    throw new IOException("node_update_windows_previous_installation_move_refused:" + error);
                }

                Thread.Sleep(100);
            }
        }
        finally
        {
            holder.ReleaseMutex();
        }
    }

    private static void MoveLinux(InstallationLease exclusion, NodeUpdateInstallation source, string target, bool park)
    {
        int parent = Descriptor(exclusion.LinuxRoot!);
        var sourceLeaf = Path.GetFileName(source.Root);
        using var held = OpenLinux(parent, sourceLeaf, LinuxDirectory);
        var state = LinuxState(held, UnixDirectory);
        if (state.Owner != EffectiveUser() || (state.Mode & 0x12) != 0)
        {
            throw new IOException("node_update_linux_previous_installation_untrusted");
        }

        var anchored = source with { Root = FormattableString.Invariant($"/proc/self/fd/{Descriptor(held)}") };
        using var image = OpenLinuxExecutable(held);
        VerifyLinuxExecutable(anchored, image);
        var imageState = LinuxExecutableState(image.SafeFileHandle);
        var receipt = ReadLinuxMode(parent, source.ArchiveSha256);
        var sourceParked = sourceLeaf != source.ArchiveSha256;
        if (receipt is null)
        {
            if (sourceParked || !HasOriginalLinuxMode(ExecutablePermissions(imageState)))
            {
                throw new IOException("node_update_linux_parked_mode_evidence_missing");
            }

            if (!park)
            {
                return;
            }

            receipt = new LinuxExecutableMode(imageState.Inode, imageState.DeviceMajor, imageState.DeviceMinor, ExecutablePermissions(imageState));
            WriteLinuxMode(parent, source.ArchiveSha256, receipt.Value);
        }

        RequireRecordedMode(receipt.Value, imageState);
        if (park)
        {
            SetLinuxMode(image.SafeFileHandle, receipt.Value.ParkedPermissions);
        }

        if (!string.Equals(source.Root, target, StringComparison.Ordinal)
            && NodeVersionSelection.RenameAt(parent, sourceLeaf, parent, Path.GetFileName(target), 1) != 0)
        {
            throw new IOException("node_update_linux_previous_installation_move_refused:" + Marshal.GetLastPInvokeError());
        }

        SyncLinuxModeDirectory(parent);
        if (!park)
        {
            SetLinuxMode(image.SafeFileHandle, receipt.Value.OriginalPermissions);
            RemoveLinuxMode(parent, source.ArchiveSha256);
        }
    }

    private static bool WaitForHolder(Mutex holder)
    {
        try
        {
            return holder.WaitOne(TimeSpan.FromSeconds(10));
        }
        catch (AbandonedMutexException)
        {
            return true;
        }
    }

    private static InstallationLease Acquire(string parent)
    {
        NodeVersionSelection.RequireDirectory(parent, create: false);
        if (OperatingSystem.IsLinux())
        {
            return AcquireLinux(parent);
        }

        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("node_update_managed_platform_required");
        }

        var path = Path.Combine(parent, LockName);
        if (NodeVersionSelection.Attributes(path) is { } attributes && (attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException("node_update_windows_installation_lock_untrusted");
        }

        return new InstallationLease(new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None));
    }

    private static InstallationLease AcquireLinux(string parent, bool existingOnly = false)
    {
        var directory = OpenLinuxDirectory(parent);
        try
        {
            const int Create = 0x40;
            var gate = OpenLinux(Descriptor(directory), LockName, existingOnly ? LinuxRegularLock & ~Create : LinuxRegularLock, 0x180);
            try
            {
                var state = LinuxState(gate, UnixRegular);
                if (state.Owner != EffectiveUser() || state.Links != 1 || (state.Mode & 0x3f) != 0)
                {
                    throw new IOException("node_update_linux_installation_lock_untrusted");
                }

                if (Flock(Descriptor(gate), 2 | 4) != 0) // LOCK_EX | LOCK_NB
                {
                    throw new IOException("node_update_linux_installation_locked:" + Marshal.GetLastPInvokeError());
                }

                return new InstallationLease(gate, directory);
            }
            catch
            {
                gate.Dispose();
                throw;
            }
        }
        catch
        {
            directory.Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenLinuxDirectory(string absolute)
    {
        var directory = OpenLinux(-100, "/", LinuxDirectory);
        try
        {
            uint user = EffectiveUser();
            foreach (var leaf in Path.GetFullPath(absolute).Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                var next = OpenLinux(Descriptor(directory), leaf, LinuxDirectory);
                directory.Dispose();
                directory = next;
                var state = LinuxState(directory, UnixDirectory);
                if ((state.Owner != user && state.Owner != 0) ||
                    ((state.Mode & 0x12) != 0 && !(state.Owner == 0 && (state.Mode & 0x200) != 0)))
                {
                    throw new IOException("node_update_linux_installation_directory_untrusted");
                }
            }

            var final = LinuxState(directory, UnixDirectory);
            if (final.Owner != user || (final.Mode & 0x12) != 0)
            {
                throw new IOException("node_update_linux_installation_directory_untrusted");
            }

            return directory;
        }
        catch
        {
            directory.Dispose();
            throw;
        }
    }

    private static SafeFileHandle OpenLinux(int directory, string path, int flags, uint mode = 0)
    {
        int descriptor = OpenAt(directory, path, flags, mode);
        if (descriptor < 0)
        {
            throw new IOException("node_update_linux_installation_path_refused:" + Marshal.GetLastPInvokeError());
        }

        return new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
    }

    private static Statx LinuxState(SafeFileHandle handle, ushort type)
    {
        const uint IdentityFields = 0x010f;
        if (GetState(Descriptor(handle), "", 0x1000, IdentityFields, out var state) != 0
            || (state.Mask & IdentityFields) != IdentityFields || (state.Mode & 0xf000) != type)
        {
            throw new IOException("node_update_linux_installation_identity_unconfirmed");
        }

        return state;
    }

    private static int Descriptor(SafeFileHandle file) => file.DangerousGetHandle().ToInt32();

    private sealed class InstallationLease(IDisposable gate, SafeFileHandle? linuxRoot = null) : IDisposable
    {
        public SafeFileHandle? LinuxRoot { get; } = linuxRoot;

        public void Dispose()
        {
            gate.Dispose();
            LinuxRoot?.Dispose();
        }
    }

    private static StringComparison PathComparison => OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static string RequireCanonical(string appRoot, NodeUpdateInstallation previous)
    {
        var canonical = NodeVersionSelection.InstallationDirectory(appRoot, previous.ArchiveSha256);
        if (!string.Equals(canonical, previous.Root, PathComparison))
        {
            throw new IOException("node_update_previous_installation_not_canonical");
        }

        return canonical;
    }

    private static void RequireExecutable(string path)
    {
        if ((File.GetAttributes(path) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new IOException("node_update_previous_executable_untrusted");
        }
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct Statx
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(16)] public uint Links;
        [FieldOffset(20)] public uint Owner;
        [FieldOffset(28)] public ushort Mode;
        [FieldOffset(32)] public ulong Inode;
        [FieldOffset(136)] public uint DeviceMajor;
        [FieldOffset(140)] public uint DeviceMinor;
    }

    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenAt(int directory, string name, int flags, uint mode);

    [LibraryImport("libc", EntryPoint = "statx", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int GetState(int descriptor, string path, int flags, uint fields, out Statx state);

    [LibraryImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static partial int Flock(int descriptor, int operation);

    [LibraryImport("libc", EntryPoint = "geteuid")]
    private static partial uint EffectiveUser();
}
