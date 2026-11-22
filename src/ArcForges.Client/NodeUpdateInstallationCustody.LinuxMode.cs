// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Client;

public static partial class NodeUpdateInstallationCustody
{
    private const int ReadOnlyPrivate = 0x800 | 0x20000 | 0x80000; // O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC
    private const int ReceiptBytes = 60;
    private const ushort ExecuteBits = 0x49;
    private const ushort WriteBits = 0x92;

    private readonly record struct LinuxExecutableMode(ulong Inode, uint DeviceMajor, uint DeviceMinor, ushort OriginalPermissions)
    {
        // Keep the parked file read-only even when integrity verification rechecks it.
        public ushort ParkedPermissions => (ushort)(OriginalPermissions & ~(ExecuteBits | WriteBits));
    }

    /// <summary>Finishes the receipt after the resumed updater authenticates the live restored predecessor.</summary>
    public static void FinishRestoredMode(string appRoot, NodeUpdateInstallation previous)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        var canonical = RequireCanonical(appRoot, previous);
        using var exclusion = AcquireLinux(Path.GetDirectoryName(canonical)!, existingOnly: true);
        int parent = Descriptor(exclusion.LinuxRoot!);
        if (ReadLinuxMode(parent, previous.ArchiveSha256) is not { } receipt)
        {
            return;
        }

        using var directory = OpenLinux(parent, Path.GetFileName(canonical), LinuxDirectory);
        using var executable = OpenLinuxExecutable(directory);
        var anchored = previous with { Root = FormattableString.Invariant($"/proc/self/fd/{Descriptor(directory)}") };
        VerifyLinuxExecutable(anchored, executable);
        var state = LinuxExecutableState(executable.SafeFileHandle);
        RequireRecordedMode(receipt, state);
        if (ExecutablePermissions(state) != receipt.OriginalPermissions)
        {
            throw new IOException("node_update_linux_restored_executable_mode_unconfirmed");
        }

        // The live predecessor has its original mode; this only flushes the inode and retires the recorded intent.
        if (NodeVersionSelection.SyncDirectory(Descriptor(executable.SafeFileHandle)) != 0)
        {
            throw new IOException("node_update_linux_restored_executable_sync_failed:" + Marshal.GetLastPInvokeError());
        }

        SyncLinuxModeDirectory(parent);
        RemoveLinuxMode(parent, previous.ArchiveSha256);
    }

    private static FileStream OpenLinuxExecutable(SafeFileHandle directory)
    {
        var handle = OpenLinux(Descriptor(directory), "arcforges", ReadOnlyPrivate);
        try
        {
            _ = LinuxExecutableState(handle);
            return new FileStream(handle, FileAccess.Read);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static Statx LinuxExecutableState(SafeFileHandle handle)
    {
        var state = LinuxState(handle, UnixRegular);
        if (state.Owner != EffectiveUser() || state.Links != 1 || state.Inode == 0)
        {
            throw new IOException("node_update_linux_previous_executable_untrusted");
        }

        return state;
    }

    private static void VerifyLinuxExecutable(NodeUpdateInstallation cohort, FileStream held)
    {
        using var manifest = NodeUpdateLauncher.OpenTrustedManifest(cohort);
        using var parsed = JsonDocument.Parse(manifest);
        if (!parsed.RootElement.TryGetProperty("files", out var files) || !files.TryGetProperty("arcforges", out var expected)
            || expected.ValueKind != JsonValueKind.String || Convert.ToHexStringLower(SHA256.HashData(held)) != expected.GetString())
        {
            throw new IOException("node_update_linux_previous_executable_manifest_mismatch");
        }
    }

    private static ushort ExecutablePermissions(Statx state) => (ushort)(state.Mode & 0x0fff);

    private static bool HasOriginalLinuxMode(ushort permissions) =>
        (permissions & ~0x1ff) == 0 && (permissions & 0x12) == 0 && (permissions & 0x140) == 0x140;

    private static void RequireRecordedMode(LinuxExecutableMode record, Statx state)
    {
        var actual = ExecutablePermissions(state);
        if (record.Inode != state.Inode || record.DeviceMajor != state.DeviceMajor || record.DeviceMinor != state.DeviceMinor
            || (actual != record.OriginalPermissions && actual != record.ParkedPermissions))
        {
            throw new IOException("node_update_linux_parked_executable_identity_or_mode_changed");
        }
    }

    private static void SetLinuxMode(SafeFileHandle handle, ushort permissions)
    {
        int descriptor = Descriptor(handle);
        if (ExecutablePermissions(LinuxExecutableState(handle)) != permissions && ChangeMode(descriptor, permissions) != 0)
        {
            throw new IOException("node_update_linux_parked_executable_mode_refused:" + Marshal.GetLastPInvokeError());
        }

        if (NodeVersionSelection.SyncDirectory(descriptor) != 0 || ExecutablePermissions(LinuxExecutableState(handle)) != permissions)
        {
            throw new IOException("node_update_linux_parked_executable_mode_unconfirmed");
        }
    }

    private static string LinuxModeLeaf(string archiveSha256) => NodeVersionSelection.ParkedName(archiveSha256) + ".mode";

    private static LinuxExecutableMode? ReadLinuxMode(int directory, string archiveSha256)
    {
        int descriptor = OpenAt(directory, LinuxModeLeaf(archiveSha256), ReadOnlyPrivate, 0);
        if (descriptor < 0)
        {
            int error = Marshal.GetLastPInvokeError();
            if (error == 2) // ENOENT
            {
                return null;
            }

            throw new IOException("node_update_linux_parked_mode_evidence_refused:" + error);
        }

        using var handle = new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
        var state = LinuxState(handle, UnixRegular);
        if (state.Owner != EffectiveUser() || state.Links != 1 || (state.Mode & 0x0e3f) != 0)
        {
            throw new IOException("node_update_linux_parked_mode_evidence_untrusted");
        }

        using var stream = new FileStream(handle, FileAccess.Read);
        Span<byte> bytes = stackalloc byte[ReceiptBytes];
        if (stream.Length != bytes.Length)
        {
            throw new IOException("node_update_linux_parked_mode_evidence_invalid");
        }

        stream.ReadExactly(bytes);
        uint mode = BinaryPrimitives.ReadUInt32LittleEndian(bytes[24..]);
        ulong inode = BinaryPrimitives.ReadUInt64LittleEndian(bytes[8..]);
        if (!bytes[..8].SequenceEqual("AFUPLNX1"u8) || !bytes[28..].SequenceEqual(Convert.FromHexString(archiveSha256))
            || mode > ushort.MaxValue || !HasOriginalLinuxMode((ushort)mode) || inode == 0)
        {
            throw new IOException("node_update_linux_parked_mode_evidence_invalid");
        }

        return new LinuxExecutableMode(inode, BinaryPrimitives.ReadUInt32LittleEndian(bytes[16..]),
            BinaryPrimitives.ReadUInt32LittleEndian(bytes[20..]), (ushort)mode);
    }

    private static void WriteLinuxMode(int directory, string archiveSha256, LinuxExecutableMode mode)
    {
        var temporary = ".update-native-mode-" + Guid.NewGuid().ToString("N") + ".partial";
        const int Exclusive = 0x80;
        using var handle = OpenLinux(directory, temporary, LinuxRegularLock | Exclusive, 0x180);
        try
        {
            Span<byte> bytes = stackalloc byte[ReceiptBytes];
            "AFUPLNX1"u8.CopyTo(bytes);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes[8..], mode.Inode);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes[16..], mode.DeviceMajor);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes[20..], mode.DeviceMinor);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes[24..], mode.OriginalPermissions);
            Convert.FromHexString(archiveSha256).CopyTo(bytes[28..]);
            using (var stream = new FileStream(handle, FileAccess.Write))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }

            if (NodeVersionSelection.RenameAt(directory, temporary, directory, LinuxModeLeaf(archiveSha256), 1) != 0)
            {
                throw new IOException("node_update_linux_parked_mode_evidence_publish_refused:" + Marshal.GetLastPInvokeError());
            }

            SyncLinuxModeDirectory(directory);
        }
        finally
        {
            _ = UnlinkAt(directory, temporary, 0);
        }
    }

    private static void RemoveLinuxMode(int directory, string archiveSha256)
    {
        if (UnlinkAt(directory, LinuxModeLeaf(archiveSha256), 0) != 0)
        {
            throw new IOException("node_update_linux_parked_mode_evidence_remove_refused:" + Marshal.GetLastPInvokeError());
        }

        SyncLinuxModeDirectory(directory);
    }

    private static void SyncLinuxModeDirectory(int directory)
    {
        if (NodeVersionSelection.SyncDirectory(directory) != 0)
        {
            throw new IOException("node_update_linux_previous_installation_sync_failed:" + Marshal.GetLastPInvokeError());
        }
    }

    [LibraryImport("libc", EntryPoint = "fchmod", SetLastError = true)]
    private static partial int ChangeMode(int descriptor, uint permissions);

    [LibraryImport("libc", EntryPoint = "unlinkat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int UnlinkAt(int directory, string path, int flags);
}
