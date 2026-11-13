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
    /// <summary>Creates an empty private object, waits for its FULL identity binding, then writes only its held FD.</summary>
    internal static int ExecutePrivateStage(Socket socket)
    {
        SafeFileHandle[]? handles = null;
        SafeFileHandle? stage = null;
        byte[]? body = null;
        try
        {
            using var stream = new NetworkStream(socket, ownsSocket: false);
            using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
            using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
            var binding = LinuxPrivateStageBinding.Read(reader);
            using var timer = LinuxFatalDeadline.ArmAbsolute(binding.Deadline);
            using var expiryTimer = LinuxFatalDeadline.ArmRealtimeExpiry(binding.ExpiryMicroseconds);
            if (binding.WorkerIdentity.ProcessId != Environment.ProcessId ||
                binding.WorkerIdentity.Observe() != LinuxProcessObservation.Alive)
                throw new InvalidOperationException("The producer generation does not match this actual child.");
            EnsureOriginalSignalIsFatal();
            socket.ReceiveTimeout = 0;
            handles = LinuxDescriptorTransfer.Receive(socket, 2);
            var root = handles[0];
            var parent = handles[1];
            body = reader.ReadBytes(checked((int)binding.Size));
            if (body.Length != binding.Size || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(body), binding.Sha256))
                throw new InvalidDataException("The bounded private body differs from its reserved hash.");
            WorkspaceObjectIdentity? created = null;
            void Check()
            {
                if (LinuxFatalDeadline.MonotonicNanoseconds() >= binding.Deadline)
                    throw new OperationCanceledException();
                var rootId = WorkspacePath.Identity(root);
                var parentId = WorkspacePath.Identity(parent);
                if (!rootId.IsDirectory || rootId.Links == 0 || !parentId.IsDirectory || parentId.Links == 0 ||
                    rootId.Volume != parentId.Volume || rootId.High != parentId.High ||
                    !Matches(rootId, binding.RootIdentity, directory: true, anonymous: false) ||
                    !Matches(parentId, binding.ParentIdentity, directory: true, anonymous: false))
                    throw new WorkspacePathException("directory_identity_changed");
                if (stage is not null && created is { } expected)
                {
                    var actual = WorkspacePath.Identity(stage);
                    if (!actual.IsFile || actual.Links != 1 || !actual.SameObject(expected) ||
                        actual.Volume != rootId.Volume || actual.High != rootId.High)
                        throw new WorkspacePathException("file_identity_changed");
                    WorkspacePath.CheckPrivateLinuxNamedStageSecurity(stage);
                    CheckCreationLease(stage);
                }
            }
            void Permit()
            {
                Check();
                writer.Write((byte)'P');
                writer.Flush();
                if (reader.ReadByte() != (byte)'G') throw new IOException("No current private effect permission.");
                Check();
            }

            Check();
            writer.Write((byte)'A');
            writer.Flush();
            Permit(); // Empty creation itself remains bounded by both already-armed kernel timers.
            WorkspacePath.RequireLinuxLeaseBreakTime();
            var descriptor = CreateRelative(checked((int)parent.DangerousGetHandle()), binding.Name,
                2 | 64 | 128 | 0x800 | 0x20000 | 0x80000, 0x180);
            if (descriptor < 0) throw new IOException("The exclusive private stage could not be created.");
            stage = new SafeFileHandle(descriptor, ownsHandle: true);
            var actualStage = WorkspacePath.Identity(stage);
            if (!actualStage.IsFile || actualStage.Links != 1 || RandomAccess.GetLength(stage) != 0)
                throw new WorkspacePathException("file_identity_changed");
            WorkspacePath.CheckPrivateLinuxNamedStageSecurity(stage);
            var fd = checked((int)stage.DangerousGetHandle());
            if (LinuxLeaseNative.Control(fd, 10, 9) < 0 ||
                LinuxLeaseNative.Control(fd, 8, Environment.ProcessId) < 0 ||
                LinuxLeaseNative.Control(fd, 1024, 1) < 0)
                throw new WorkspacePathException("file_guard_unavailable");
            created = actualStage;
            Check();
            RandomAccess.FlushToDisk(stage);
            if (SyncCreationParent(checked((int)parent.DangerousGetHandle())) != 0)
                throw new IOException("The private empty name was not flushed.");
            Check();
            writer.Write((byte)'I');
            writer.Write(RegisteredWorkspaces.RootIdentity.Encode(actualStage, directory: false).Bytes);
            writer.Flush();
            LinuxDescriptorTransfer.Send(socket, [stage]);
            // Only the parent's completed FULL object binding can permit exposing the first private body byte.
            if (reader.ReadByte() != (byte)'B') throw new IOException("The empty stage was not durably bound.");
            Check();

            for (var offset = 0; offset < body.Length;)
            {
                Permit();
                var count = Math.Min(65_536, body.Length - offset);
                RandomAccess.Write(stage, body.AsSpan(offset, count), offset);
                offset += count;
                Check();
            }
            Permit();
            RandomAccess.FlushToDisk(stage);
            Check();
            using var result = ReadAndHash(stage, binding.Size, binding.Sha256, Check, "file_identity_changed");
            writer.Write((byte)'D');
            writer.Write((long)result.Bytes.Length);
            writer.Write(result.Sha256.Span);
            writer.Flush();
            // The parent already holds a duplicate of this same OFD. It adopts notification ownership before S.
            return reader.ReadByte() == (byte)'S' ? 0 : 2;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SocketException or
            InvalidOperationException or ArgumentException or NotSupportedException or OperationCanceledException)
        {
            return 2; // A producer failure is not a proved target-file outcome or permission to retry body IO.
        }
        finally
        {
            if (body is not null) CryptographicOperations.ZeroMemory(body);
            stage?.Dispose();
            if (handles is not null)
                foreach (var handle in handles) handle.Dispose();
        }
    }
}
