// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

[SupportedOSPlatform("linux")]
internal static partial class LinuxFileEffectExecutor
{
    /// <summary>One exclusive creation under the original prepared parent. No pathname supplies body-write access.</summary>
    internal static int ExecuteCreation(Socket socket)
    {
        SafeFileHandle[]? handles = null;
        SafeFileHandle? target = null;
        byte[]? intended = null;
        var possibleEffect = false;
        try
        {
            using var stream = new NetworkStream(socket, ownsSocket: false);
            using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
            using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
            var binding = LinuxFileCreationBinding.Read(reader);
            using var timer = LinuxFatalDeadline.ArmAbsolute(binding.Deadline);
            using var expiryTimer = LinuxFatalDeadline.ArmRealtimeExpiry(binding.ExpiryMicroseconds, binding.Deadline);
            socket.ReceiveTimeout = 0;
            EnsureOriginalSignalIsFatal();
            handles = LinuxDescriptorTransfer.Receive(socket, 3);
            var root = handles[0];
            var parent = handles[1];
            var stage = handles[2];
            AdoptCreationLease(stage);
            WorkspaceObjectIdentity? created = null;
            void Check()
            {
                if (LinuxFatalDeadline.MonotonicNanoseconds() >= binding.Deadline)
                    throw new OperationCanceledException();
                var rootId = WorkspacePath.Identity(root);
                var parentId = WorkspacePath.Identity(parent);
                var stageId = WorkspacePath.Identity(stage);
                if (!rootId.IsDirectory || rootId.Links == 0 || !parentId.IsDirectory || parentId.Links == 0 ||
                    !stageId.IsFile || stageId.Links != (binding.DurableStage ? 1u : 0u) || (stageId.Mode & 0x3f) != 0 ||
                    rootId.Volume != parentId.Volume || rootId.High != parentId.High ||
                    rootId.Volume != stageId.Volume || rootId.High != stageId.High ||
                    !Matches(rootId, binding.RootIdentity, directory: true, anonymous: false) ||
                    !Matches(parentId, binding.ParentIdentity, directory: true, anonymous: false) ||
                    !Matches(stageId, binding.IntendedStageIdentity, directory: false, anonymous: !binding.DurableStage))
                    throw new WorkspacePathException("file_identity_changed");
                if (binding.DurableStage) WorkspacePath.CheckPrivateLinuxNamedStageSecurity(stage);
                CheckCreationLease(stage);
                if (target is not null && created is { } expected)
                {
                    var actual = WorkspacePath.Identity(target);
                    if (!actual.IsFile || actual.Links != 1 || !expected.SameObject(actual) ||
                        actual.Mode != expected.Mode || actual.Volume != rootId.Volume || actual.High != rootId.High ||
                        actual.SameObject(stageId))
                        throw new WorkspacePathException("file_identity_changed");
                    CheckCreationLease(target);
                }
            }
            Check();
            using (var desired = ReadAndHash(stage, binding.IntendedSize, binding.IntendedSha256, Check, "file_identity_changed"))
                intended = desired.Bytes.ToArray();
            writer.Write((byte)'A');
            writer.Flush();
            void Permit()
            {
                Check();
                writer.Write((byte)'P');
                writer.Flush();
                if (reader.ReadByte() != (byte)'G') throw new InvalidOperationException("The effect was not authorized.");
                Check();
            }

            Permit();
            WorkspacePath.RequireLinuxLeaseBreakTime();
            possibleEffect = true;
            var descriptor = CreateRelative(checked((int)parent.DangerousGetHandle()), binding.Name,
                2 | 64 | 128 | 0x800 | 0x20000 | 0x80000, 0x180);
            if (descriptor < 0)
            {
                if (Marshal.GetLastPInvokeError() == 17)
                {
                    possibleEffect = false;
                    writer.Write((byte)'E'); // O_EXCL/EEXIST is the sole recognized no-create result.
                    writer.Flush();
                    return 0;
                }
                throw new IOException("The exclusive creation outcome could not be established.");
            }
            target = new SafeFileHandle(descriptor, ownsHandle: true);
            var identity = WorkspacePath.Identity(target);
            if (!identity.IsFile || identity.Links != 1 || (identity.Mode & 0x3f) != 0 ||
                RandomAccess.GetLength(target) != 0)
                throw new WorkspacePathException("file_identity_changed");
            // This is our new description: install a fatal notification before granting its write lease.
            var fd = checked((int)target.DangerousGetHandle());
            if (LinuxLeaseNative.Control(fd, 10, 9) < 0 ||
                LinuxLeaseNative.Control(fd, 8, Environment.ProcessId) < 0 ||
                LinuxLeaseNative.Control(fd, 1024, 1) < 0)
                throw new WorkspacePathException("file_guard_unavailable");
            created = identity;
            Check();
            writer.Write((byte)'C');
            writer.Write(RegisteredWorkspaces.RootIdentity.Encode(identity, directory: false).Bytes);
            writer.Flush();

            for (var offset = 0; offset < intended.Length;)
            {
                Permit();
                var count = Math.Min(65_536, intended.Length - offset);
                RandomAccess.Write(target, intended.AsSpan(offset, count), offset);
                offset += count;
                Check();
            }
            Permit();
            RandomAccess.SetLength(target, intended.Length);
            Check();
            RandomAccess.FlushToDisk(target);
            Check();
            Permit();
            var marker = WorkspaceCreationMarker.TryWriteNew(target);
            Check();
            if (SyncCreationParent(checked((int)parent.DangerousGetHandle())) != 0)
                throw new IOException("The created name was not durably flushed.");
            Check();
            using var actualContent = ReadAndHash(target, binding.IntendedSize, binding.IntendedSha256, Check, "file_identity_changed");
            writer.Write((byte)'D');
            writer.Write((long)actualContent.Bytes.Length);
            writer.Write(actualContent.Sha256.Span);
            writer.Write((byte)(marker?.Length ?? 0));
            if (marker is not null) writer.Write(marker);
            writer.Flush();
            LinuxDescriptorTransfer.Send(socket, [target]);
            // Parent first adopts this exact live OFD without dropping the lease, then verifies and acknowledges.
            return reader.ReadByte() == (byte)'S' ? 0 : 2;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SocketException or
            InvalidOperationException or ArgumentException or NotSupportedException or OperationCanceledException)
        {
            if (!possibleEffect)
            {
                try { _ = socket.Send([(byte)'F', (byte)3]); }
                catch (Exception sendFailure) when (sendFailure is IOException or SocketException or ObjectDisposedException) { }
            }
            return 2;
        }
        finally
        {
            if (intended is not null) CryptographicOperations.ZeroMemory(intended);
            target?.Dispose();
            if (handles is not null)
                foreach (var handle in handles) handle.Dispose();
        }
    }

    private static void AdoptCreationLease(SafeFileHandle file)
    {
        var fd = checked((int)file.DangerousGetHandle());
        if (LinuxLeaseNative.Control(fd, 8, Environment.ProcessId) < 0 ||
            LinuxLeaseNative.Control(fd, 10, 9) < 0)
            throw new WorkspacePathException("file_guard_unavailable");
        CheckCreationLease(file);
    }

    private static void CheckCreationLease(SafeFileHandle file)
    {
        var fd = checked((int)file.DangerousGetHandle());
        if (LinuxLeaseNative.Control(fd, 9, 0) != Environment.ProcessId ||
            LinuxLeaseNative.Control(fd, 11, 0) != 9 || LinuxLeaseNative.Control(fd, 1025, 0) != 1)
            throw new WorkspacePathException("file_guard_breaking");
    }

    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int CreateRelative(int directory, string name, int flags, uint mode);

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static partial int SyncCreationParent(int descriptor);
}
