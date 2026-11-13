// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal sealed record LinuxFileMutationResult(WorkspaceGuardedMutationResult Content, WorkspaceWriteGuard Guard);

internal sealed record LinuxFileCreationResult(WorkspaceCreatedTarget Target, WorkspaceGuardedMutationResult Content,
    WorkspaceCreatedOwnership Ownership);

[SupportedOSPlatform("linux")]
internal sealed partial class LinuxFileEffectController
{
    internal LinuxFileCreationResult ExecuteCreation(LinuxFileCreationBinding binding, WorkspacePath root,
        string relativePath, WorkspaceLinuxCreationSelection selection, WorkspaceAnonymousStage intended,
        Action beforeEffect, Action? beforeCreate, Action? afterCreate, CancellationToken cancellationToken)
    {
        var socket = _socket ?? throw new InvalidOperationException("The worker channel is unavailable.");
        var peer = _peer ?? throw new InvalidOperationException("The worker peer is unavailable.");
        using var cancellation = cancellationToken.Register(static state => ((LinuxFileEffectController)state!).RequestStop(), this);
        using var stream = new NetworkStream(socket, ownsSocket: false);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        byte[]? createdIdentity = null;
        WorkspaceWriteGuard? returned = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            selection.CheckNames(null);
            writer.Write((byte)'C');
            binding.Write(writer);
            WorkspaceWriteGuard.TransferLinuxCreationSource(peer, root.RootHandle, selection.Parent,
                intended.GuardForLinuxHandoff);
            if (ReadWorkerMessage(reader) != (byte)'A') throw new IOException("The worker did not adopt its checked source.");
            intended.CheckIntact();
            intended.GuardForLinuxHandoff.CloseLocalAfterLinuxHandoff();
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var message = ReadWorkerMessage(reader);
                if (message == (byte)'P')
                {
                    beforeEffect();
                    if (createdIdentity is null) beforeCreate?.Invoke();
                    selection.CheckNames(createdIdentity);
                    cancellationToken.ThrowIfCancellationRequested();
                    Volatile.Write(ref _possibleEffect, 1);
                    writer.Write((byte)'G');
                    writer.Flush();
                    continue;
                }
                if (message == (byte)'E' && createdIdentity is null)
                {
                    var child = _child ?? throw new InvalidOperationException("The worker is unavailable.");
                    if (!child.WaitForExit(5000) || child.ExitCode != 0)
                        throw new IOException("The no-create worker did not finish cleanly.");
                    Volatile.Write(ref _possibleEffect, 0);
                    throw new WorkspaceCreateCollisionException(selection.ParentIdentity, relativePath, intended.Identity);
                }
                if (message == (byte)'C' && createdIdentity is null)
                {
                    createdIdentity = reader.ReadBytes(53);
                    if (createdIdentity.Length != 53) throw new EndOfStreamException();
                    RegisteredWorkspaces.RootIdentity.ValidateEncoding(2, createdIdentity);
                    selection.CheckNames(createdIdentity);
                    afterCreate?.Invoke();
                    continue;
                }
                if (message != (byte)'D' || createdIdentity is null) throw new IOException("The worker returned an invalid creation result.");
                var size = reader.ReadInt64();
                var hash = reader.ReadBytes(32);
                var markerLength = reader.ReadByte();
                if (size != binding.IntendedSize || hash.Length != 32 ||
                    !CryptographicOperations.FixedTimeEquals(hash, binding.IntendedSha256) || markerLength is not (0 or 32))
                    throw new InvalidDataException("The worker result differs from its prepared creation intent.");
                var marker = markerLength == 0 ? null : reader.ReadBytes(markerLength);
                if (marker is not null && marker.Length != 32) throw new EndOfStreamException();
                using var file = peer.ReceiveReturnedDescriptorOnce();
                var identity = WorkspacePath.Identity(file);
                var encoded = RegisteredWorkspaces.RootIdentity.Encode(identity, directory: false);
                if (!CryptographicOperations.FixedTimeEquals(createdIdentity, encoded.Bytes))
                    throw new WorkspacePathException("file_identity_changed");
                // Transfer ownership of the received descriptor only after successful adoption. SafeFileHandle
                // ownership is moved, rather than duplicating a fresh path or releasing/regranting the lease.
                var owned = new SafeFileHandle(file.DangerousGetHandle(), ownsHandle: true);
                file.SetHandleAsInvalid();
                try { returned = WorkspaceWriteGuard.AdoptLinuxReturnedFile(owned, peer, identity, binding.Deadline); }
                catch { owned.Dispose(); throw; }
                selection.CheckNames(createdIdentity);
                using (var actual = returned.ReadForMutation(cancellationToken))
                {
                    if (actual.Bytes.Length != size || !CryptographicOperations.FixedTimeEquals(hash, actual.Sha256.Span))
                        throw new WorkspacePathException("file_identity_changed");
                }
                if (marker is not null && !returned.MatchesOwnership(encoded, marker, size, hash,
                    () => selection.CheckNames(createdIdentity), cancellationToken))
                    throw new WorkspacePathException("file_identity_changed");
                beforeEffect();
                selection.CheckNames(createdIdentity);
                returned.CheckIntact();
                cancellationToken.ThrowIfCancellationRequested();
                writer.Write((byte)'S');
                writer.Flush();
                var completedChild = _child ?? throw new InvalidOperationException("The worker is unavailable.");
                if (!completedChild.WaitForExit(5000) || completedChild.ExitCode != 0)
                    throw new IOException("The creation worker did not finish cleanly.");
                selection.CheckNames(createdIdentity);
                returned.CheckIntact();
                var result = new LinuxFileCreationResult(new WorkspaceCreatedTarget(returned),
                    new WorkspaceGuardedMutationResult(size, hash), new WorkspaceCreatedOwnership(encoded, marker));
                returned = null;
                return result;
            }
        }
        finally { returned?.Dispose(); }
    }
}
