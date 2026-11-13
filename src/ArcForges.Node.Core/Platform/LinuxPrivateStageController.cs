// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Files;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

[SupportedOSPlatform("linux")]
internal sealed partial class LinuxFileEffectController
{
    /// <summary>
    /// Receives the actual child-created empty FD, waits for FULL privacy/identity binding, then permits bounded body
    /// effects. The child retains its fatal lease and kernel timers until the same FD is safely adopted on completion.
    /// </summary>
    internal async Task<WorkspaceEmptyNamedStage> ExecutePrivateStageAsync(LinuxPrivateStageBinding binding,
        WorkspacePath workspaceRoot, WorkspacePath stageDirectory, ReadOnlyMemory<byte> body,
        Func<SafeFileHandle, Action, Task> commitEmptyIdentity, Func<Task> beforeEachEffect, CancellationToken cancellationToken)
    {
        binding.Validate();
        ArgumentNullException.ThrowIfNull(commitEmptyIdentity);
        ArgumentNullException.ThrowIfNull(beforeEachEffect);
        if (body.Length != binding.Size || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(body.Span), binding.Sha256))
            throw new InvalidDataException("The private body differs from its bound size/hash.");
        var socket = _socket ?? throw new InvalidOperationException("The worker channel is unavailable.");
        var peer = _peer ?? throw new InvalidOperationException("The worker peer is unavailable.");
        if (peer.ProcessIdentity != binding.WorkerIdentity)
            throw new InvalidOperationException("This binding belongs to another actual worker generation.");
        peer.RequireOriginalLivePeer();
        using var cancellation = cancellationToken.Register(static state => ((LinuxFileEffectController)state!).RequestStop(), this);
        using var stream = new NetworkStream(socket, ownsSocket: false);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        SafeFileHandle? file = null;
        WorkspaceWriteGuard? adopted = null;
        byte[]? createdIdentity = null;
        var identityBound = false;
        try
        {
            void CheckDirectories()
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (LinuxFatalDeadline.MonotonicNanoseconds() >= binding.Deadline)
                    throw new OperationCanceledException(cancellationToken);
                using var root = WorkspacePath.OpenRoot(workspaceRoot.RootPath, workspaceRoot.RootIdentity);
                using var parent = WorkspacePath.OpenRoot(stageDirectory.RootPath, stageDirectory.RootIdentity);
                if (!CryptographicOperations.FixedTimeEquals(binding.RootIdentity,
                        RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(workspaceRoot.RootHandle)).Bytes) ||
                    !CryptographicOperations.FixedTimeEquals(binding.ParentIdentity,
                        RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(stageDirectory.RootHandle)).Bytes))
                    throw new WorkspacePathException("directory_identity_changed");
                if (createdIdentity is not null)
                {
                    var named = stageDirectory.InspectEntry(binding.Name);
                    if (named.Kind != WorkspaceEntryType.File || named.Identity.Links != 1 ||
                        !CryptographicOperations.FixedTimeEquals(createdIdentity,
                            RegisteredWorkspaces.RootIdentity.Encode(named.Identity, directory: false).Bytes))
                        throw new WorkspacePathException("file_identity_changed");
                }
            }
            void VerifyChildEmptyGuard()
            {
                CheckDirectories();
                peer.RequireOriginalLivePeer();
                var actualFile = file ?? throw new InvalidOperationException("The actual stage FD is unavailable.");
                var identity = WorkspacePath.Identity(actualFile);
                if (!identity.IsFile || identity.Links != 1 || createdIdentity is null ||
                    !CryptographicOperations.FixedTimeEquals(createdIdentity,
                        RegisteredWorkspaces.RootIdentity.Encode(identity, directory: false).Bytes))
                    throw new WorkspacePathException("file_identity_changed");
                WorkspacePath.CheckPrivateLinuxNamedStageSecurity(actualFile);
                var fd = checked((int)actualFile.DangerousGetHandle());
                if (LinuxLeaseNative.Control(fd, 9, 0) != binding.WorkerIdentity.ProcessId ||
                    LinuxLeaseNative.Control(fd, 11, 0) != 9 || LinuxLeaseNative.Control(fd, 1025, 0) != 1)
                    throw new WorkspacePathException("file_guard_breaking");
            }

            CheckDirectories();
            writer.Write((byte)'B');
            binding.Write(writer);
            peer.SendDescriptorsOnce([workspaceRoot.RootHandle, stageDirectory.RootHandle]);
            writer.Write(body.Span);
            writer.Flush();
            if (ReadWorkerMessage(reader) != (byte)'A') throw new IOException("The producer did not adopt its reservation.");
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var message = ReadWorkerMessage(reader);
                if (message == (byte)'P')
                {
                    await beforeEachEffect().ConfigureAwait(false);
                    CheckDirectories();
                    peer.RequireOriginalLivePeer();
                    if (file is not null)
                    {
                        if (!identityBound) throw new InvalidOperationException("Body permission preceded FULL object binding.");
                        VerifyChildEmptyGuard();
                    }
                    Volatile.Write(ref _possibleEffect, 1);
                    writer.Write((byte)'G');
                    writer.Flush();
                    continue;
                }
                if (message == (byte)'I' && file is null)
                {
                    createdIdentity = reader.ReadBytes(53);
                    if (createdIdentity.Length != 53) throw new EndOfStreamException();
                    file = peer.ReceiveReturnedDescriptorOnce();
                    VerifyChildEmptyGuard();
                    if (RandomAccess.GetLength(file) != 0) throw new InvalidDataException("The producer exposed body before FULL binding.");
                    await commitEmptyIdentity(file, VerifyChildEmptyGuard).ConfigureAwait(false);
                    VerifyChildEmptyGuard();
                    identityBound = true;
                    writer.Write((byte)'B');
                    writer.Flush();
                    continue;
                }
                if (message != (byte)'D' || file is null || !identityBound)
                    throw new IOException("The private producer returned an invalid phase.");
                var size = reader.ReadInt64();
                var hash = reader.ReadBytes(32);
                if (size != binding.Size || hash.Length != 32 || !CryptographicOperations.FixedTimeEquals(hash, binding.Sha256))
                    throw new InvalidDataException("The produced body differs from the reserved intent.");
                VerifyChildEmptyGuard();
                var actualIdentity = WorkspacePath.Identity(file);
                adopted = WorkspaceWriteGuard.AdoptLinuxReturnedFile(file, peer, actualIdentity, binding.Deadline,
                    privateStage: true, WorkspacePath.CheckPrivateLinuxNamedStageSecurity);
                file = null;
                using (var actual = adopted.ReadForMutation(cancellationToken))
                {
                    if (actual.Bytes.Length != size || !CryptographicOperations.FixedTimeEquals(hash, actual.Sha256.Span))
                        throw new WorkspacePathException("file_identity_changed");
                }
                await beforeEachEffect().ConfigureAwait(false);
                CheckDirectories();
                adopted.CheckIntact();
                peer.RequireOriginalLivePeer();
                writer.Write((byte)'S');
                writer.Flush();
                var child = _child ?? throw new InvalidOperationException("The private child is unavailable.");
                if (!child.WaitForExit(5000) || child.ExitCode != 0)
                    throw new IOException("The private stage child did not actually finish.");
                CheckDirectories();
                adopted.CheckIntact();
                var result = new WorkspaceEmptyNamedStage(binding.Name,
                    RegisteredWorkspaces.RootIdentity.Encode(actualIdentity, directory: false), adopted,
                    NamedStageDurabilityEvidence.LinuxFileAndDirectoryFsync);
                adopted = null;
                return result;
            }
        }
        finally
        {
            adopted?.Dispose();
            file?.Dispose();
        }
    }
}
