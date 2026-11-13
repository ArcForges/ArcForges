// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// The worker-side half of one existing-file effect. It receives only the exact open descriptions and a bounded
/// journal binding from its authenticated parent. Each individual target effect needs a fresh parent permission.
/// </summary>
[SupportedOSPlatform("linux")]
internal static partial class LinuxFileEffectExecutor
{
    internal static int Execute(Socket socket)
    {
        SafeFileHandle[]? handles = null;
        byte[]? intended = null;
        var possibleEffect = false;
        try
        {
            using var stream = new NetworkStream(socket, ownsSocket: false);
            using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
            using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
            var binding = LinuxFileEffectBinding.Read(reader);
            using var timer = LinuxFatalDeadline.ArmAbsolute(binding.Deadline);
            using var expiryTimer = LinuxFatalDeadline.ArmRealtimeExpiry(binding.ExpiryMicroseconds);
            // The kernel timers now bound this child's wait even while its parent is stopped or unscheduled.
            socket.ReceiveTimeout = 0;
            EnsureOriginalSignalIsFatal();
            handles = LinuxDescriptorTransfer.Receive(socket, 4);
            var root = handles[0];
            var target = handles[1];
            var original = handles[2];
            var stage = handles[3];

            // Redirect first while the previous SIGIO is still installed; only the owned child can receive a break.
            // Then install SIGKILL, read both settings back and ensure that the lease was not already breaking.
            foreach (var file in new[] { target, original, stage })
            {
                var fd = checked((int)file.DangerousGetHandle());
                if (LinuxLeaseNative.Control(fd, 8, Environment.ProcessId) < 0 ||
                    LinuxLeaseNative.Control(fd, 9, 0) != Environment.ProcessId ||
                    LinuxLeaseNative.Control(fd, 10, 9) < 0 || LinuxLeaseNative.Control(fd, 11, 0) != 9 ||
                    LinuxLeaseNative.Control(fd, 1025, 0) != 1)
                    throw new WorkspacePathException("file_guard_unavailable");
            }

            var targetMode = WorkspacePath.Identity(target).Mode;
            var preserved = LinuxPreservedMetadata.Capture(target);

            void Check()
            {
                if (LinuxFatalDeadline.MonotonicNanoseconds() >= binding.Deadline)
                    throw new OperationCanceledException();
                var rootIdentity = WorkspacePath.Identity(root);
                var targetIdentity = WorkspacePath.Identity(target);
                var originalIdentity = WorkspacePath.Identity(original);
                var stageIdentity = WorkspacePath.Identity(stage);
                if (!rootIdentity.IsDirectory || rootIdentity.Links == 0 ||
                    !targetIdentity.IsFile || targetIdentity.Links != 1 || targetIdentity.Mode != targetMode ||
                    !originalIdentity.IsFile || originalIdentity.Links != 0 || (originalIdentity.Mode & 0x3f) != 0 ||
                    !stageIdentity.IsFile || stageIdentity.Links != 0 || (stageIdentity.Mode & 0x3f) != 0 ||
                    targetIdentity.Volume != rootIdentity.Volume || targetIdentity.High != rootIdentity.High ||
                    originalIdentity.Volume != rootIdentity.Volume || originalIdentity.High != rootIdentity.High ||
                    stageIdentity.Volume != rootIdentity.Volume || stageIdentity.High != rootIdentity.High ||
                    targetIdentity.SameObject(originalIdentity) || targetIdentity.SameObject(stageIdentity) ||
                    originalIdentity.SameObject(stageIdentity) ||
                    !Matches(rootIdentity, binding.RootIdentity, directory: true, anonymous: false) ||
                    !Matches(targetIdentity, binding.TargetIdentity, directory: false, anonymous: false) ||
                    !Matches(originalIdentity, binding.OriginalStageIdentity, directory: false, anonymous: true) ||
                    !Matches(stageIdentity, binding.IntendedStageIdentity, directory: false, anonymous: true))
                    throw new WorkspacePathException("file_identity_changed");
                if (!preserved.SameAs(LinuxPreservedMetadata.Capture(target)))
                    throw new WorkspacePreservationUnavailableException();
                foreach (var file in new[] { target, original, stage })
                {
                    var fd = checked((int)file.DangerousGetHandle());
                    if (LinuxLeaseNative.Control(fd, 9, 0) != Environment.ProcessId ||
                        LinuxLeaseNative.Control(fd, 11, 0) != 9 || LinuxLeaseNative.Control(fd, 1025, 0) != 1)
                        throw new WorkspacePathException("file_guard_breaking");
                }
            }

            Check();
            using (var expected = ReadAndHash(original, binding.OriginalSize, binding.OriginalSha256, Check, "file_identity_changed"))
            using (var existing = ReadAndHash(target, binding.OriginalSize, binding.OriginalSha256, Check, "hash_mismatch"))
            using (var desired = ReadAndHash(stage, binding.IntendedSize, binding.IntendedSha256, Check, "file_identity_changed"))
            {
                intended = desired.Bytes.ToArray();
            }
            Check();
            writer.Write((byte)'A'); // Adopted exact guards and hashes, no target effect has occurred.
            writer.Flush();

            void Permit()
            {
                Check();
                writer.Write((byte)'P');
                writer.Flush();
                if (reader.ReadByte() != (byte)'G') throw new InvalidOperationException("The effect was not authorized.");
                Check();
            }

            for (var offset = 0; offset < intended.Length;)
            {
                var count = Math.Min(65_536, intended.Length - offset);
                Permit();
                possibleEffect = true;
                RandomAccess.Write(target, intended.AsSpan(offset, count), offset);
                offset += count;
                Check();
            }
            Permit();
            possibleEffect = true;
            RandomAccess.SetLength(target, intended.Length);
            Check();
            RandomAccess.FlushToDisk(target);
            Check();
            using (var actual = ReadAndHash(target, binding.IntendedSize, binding.IntendedSha256, Check, "file_identity_changed"))
            {
                Check();
                writer.Write((byte)'D');
                writer.Write((long)actual.Bytes.Length);
                writer.Write(actual.Sha256.Span);
                writer.Flush();
            }
            LinuxDescriptorTransfer.Send(socket, [target]);
            // The parent adopts the same leased OFD before acknowledging; no guard is dropped or regranted.
            return reader.ReadByte() == (byte)'S' ? 0 : 2;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SocketException or
            InvalidOperationException or ArgumentException or NotSupportedException or OperationCanceledException)
        {
            if (!possibleEffect)
            {
                var reason = exception is WorkspacePathException { Reason: "hash_mismatch" } ? (byte)1
                    : exception is WorkspacePathException { Reason: "file_identity_changed" } ? (byte)2 : (byte)3;
                try { _ = socket.Send([(byte)'F', reason]); }
                catch (Exception sendFailure) when (sendFailure is IOException or SocketException or ObjectDisposedException) { }
            }
            return 2;
        }
        finally
        {
            if (intended is not null) CryptographicOperations.ZeroMemory(intended);
            if (handles is not null)
                foreach (var handle in handles) handle.Dispose();
        }
    }

    private static WorkspaceGuardedContent ReadAndHash(SafeFileHandle file, long size, ReadOnlySpan<byte> expected, Action check,
        string changedReason)
    {
        if (RandomAccess.GetLength(file) != size) throw new WorkspacePathException(changedReason);
        var bytes = new byte[checked((int)size)];
        try
        {
            var offset = 0;
            while (offset < bytes.Length)
            {
                check();
                var read = RandomAccess.Read(file, bytes.AsSpan(offset, Math.Min(65_536, bytes.Length - offset)), offset);
                if (read <= 0) throw new WorkspacePathException(changedReason);
                offset += read;
            }
            check();
            if (RandomAccess.GetLength(file) != size) throw new WorkspacePathException(changedReason);
            var hash = SHA256.HashData(bytes);
            if (!CryptographicOperations.FixedTimeEquals(hash, expected))
                throw new WorkspacePathException(changedReason);
            return new WorkspaceGuardedContent(bytes, hash);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    private static bool Matches(WorkspaceObjectIdentity actual, byte[] expected, bool directory, bool anonymous)
    {
        var identity = anonymous ? RegisteredWorkspaces.RootIdentity.EncodeAnonymousLinux(actual)
            : RegisteredWorkspaces.RootIdentity.Encode(actual, directory);
        return identity.Platform == 2 && CryptographicOperations.FixedTimeEquals(identity.Bytes, expected);
    }

    private static void EnsureOriginalSignalIsFatal()
    {
        // Before F_SETOWN moves the first lease, ensure an intervening original SIGIO cannot remain blocked or ignored.
        if (Signal(29, 0) == -1) throw new IOException("The worker signal disposition is unavailable.");
        LinuxLeaseNative.SignalSet signals = default;
        if (LinuxLeaseNative.EmptySet(ref signals) != 0 || LinuxLeaseNative.AddSignal(ref signals, 29) != 0 ||
            LinuxLeaseNative.ThreadSignalMask(1, ref signals, 0) != 0)
            throw new IOException("The worker signal mask is unavailable.");
    }

    [LibraryImport("libc", EntryPoint = "signal", SetLastError = true)]
    private static partial nint Signal(int signal, nint handler);
}
