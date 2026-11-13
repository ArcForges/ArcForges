// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Files;

namespace ArcForges.Node.Core.Platform;

/// <summary>A one-use Host child for a FULL-reserved Windows private stage.</summary>
[SupportedOSPlatform("windows")]
public static class WindowsPrivateStageWorker
{
    /// <summary>Enters the private protocol without initializing Node services or opening any workspace from a pathname.</summary>
    public static int Run() => RunAsync().GetAwaiter().GetResult();

    private static async Task<int> RunAsync()
    {
        byte[]? content = null;
        try
        {
            using var startup = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var input = Console.OpenStandardInput();
            var hello = await WindowsStageChannel.ReadAsync(input, startup.Token).ConfigureAwait(false);
            if (hello.Kind != (byte)'H' || hello.Payload.Length > 256) return 2;
            using var helloReader = WindowsStageChannel.Reader(hello.Payload);
            var parentPid = helloReader.ReadInt32();
            var parentCreated = helloReader.ReadInt64();
            var length = helloReader.ReadByte();
            if (length is < 1 or > 90) return 2;
            var nameBytes = helloReader.ReadBytes(length);
            if (nameBytes.Length != length || nameBytes.Any(c => c is not (>= (byte)'a' and <= (byte)'z') and
                    not (>= (byte)'0' and <= (byte)'9') and not (byte)'-')) return 2;
            var challenge = helloReader.ReadBytes(32);
            if (challenge.Length != 32) return 2;
            WindowsStageChannel.RequireEnd(helloReader);
            using var parent = WindowsStageChannel.OpenTransferParent(parentPid);
            using var pipe = new NamedPipeClientStream(".", Encoding.ASCII.GetString(nameBytes), PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await pipe.ConnectAsync(5000, startup.Token).ConfigureAwait(false);
            WindowsStageChannel.RequireServer(pipe, parent, parentPid, parentCreated);
            await WindowsStageChannel.SendAsync(pipe, (byte)'A', challenge, startup.Token).ConfigureAwait(false);
            CryptographicOperations.ZeroMemory(challenge);
            var initialize = await WindowsStageChannel.ReadAsync(pipe, startup.Token).ConfigureAwait(false);
            if (initialize.Kind == (byte)'S' && initialize.Payload.Length == 0) return 0;
            if (initialize.Kind != (byte)'I' || initialize.Payload.Length > 2048) return 2;
            using var reader = WindowsStageChannel.Reader(initialize.Payload);
            var binding = WindowsPrivateStageBinding.Read(reader);
            using var self = Process.GetCurrentProcess();
            var identity = new WindowsOwnedStageIdentity(BootIdentity.Read(), Environment.ProcessId,
                WindowsOwnedStageProcess.CreationTimeOf(self.SafeHandle));
            if (binding.WorkerIdentity != identity) return 2;
            using var root = WindowsStageChannel.DuplicateFrom(parent, reader.ReadInt64());
            using var directory = WindowsStageChannel.DuplicateFrom(parent, reader.ReadInt64());
            WindowsStageChannel.RequireEnd(reader);
            using var budget = WindowsStageChannel.Budget(binding.Deadline, binding.ExpiryMicroseconds, CancellationToken.None);
            var token = budget.Token;
            WindowsStageChannel.RequireServer(pipe, parent, parentPid, parentCreated);
            WorkspacePath.RequireWindowsStageDirectory(root, binding.RootIdentity);
            WorkspacePath.RequireWindowsStageDirectory(directory, binding.ParentIdentity);
            using var transaction = WindowsPrivateStageTransaction.Arm(binding.Deadline, binding.ExpiryMicroseconds);
            using var file = WorkspacePath.CreateWindowsTransactionalEmptyStage(directory, binding, transaction);
            var fileIdentity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file), directory: false);
            var empty = WindowsStageChannel.Encode(writer =>
            {
                writer.Write(transaction.Id.ToByteArray());
                writer.Write(transaction.TimeoutMilliseconds);
                writer.Write(transaction.Handle.DangerousGetHandle().ToInt64());
                writer.Write(file.DangerousGetHandle().ToInt64());
                writer.Write(fileIdentity.Bytes);
            });
            await WindowsStageChannel.SendAsync(pipe, (byte)'E', empty, token).ConfigureAwait(false);
            // No body is accepted before the parent commits this actual empty identity and acknowledges the FULL write.
            await RequireGoAsync(pipe, token).ConfigureAwait(false);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long offset = 0;
            while (offset < binding.Size)
            {
                var chunk = await WindowsStageChannel.ReadAsync(pipe, token).ConfigureAwait(false);
                content = chunk.Payload;
                if (chunk.Kind != (byte)'B' || content.Length == 0 || content.Length > binding.Size - offset) return 2;
                Check();
                RandomAccess.Write(file, content, offset);
                hash.AppendData(content);
                offset += content.Length;
                CryptographicOperations.ZeroMemory(content);
                content = null;
                Check();
                await WindowsStageChannel.SendAsync(pipe, (byte)'A', ReadOnlyMemory<byte>.Empty, token).ConfigureAwait(false);
            }
            if (!CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), binding.Sha256)) return 2;
            await WindowsStageChannel.SendAsync(pipe, (byte)'F', ReadOnlyMemory<byte>.Empty, token).ConfigureAwait(false);
            await RequireGoAsync(pipe, token).ConfigureAwait(false);
            Check();
            RandomAccess.FlushToDisk(file);
            Check();
            if (RandomAccess.GetLength(file) != binding.Size) return 2;
            await WindowsStageChannel.SendAsync(pipe, (byte)'C', ReadOnlyMemory<byte>.Empty, token).ConfigureAwait(false);
            await RequireGoAsync(pipe, token).ConfigureAwait(false);
            Check();
            transaction.Commit();
            await WindowsStageChannel.SendAsync(pipe, (byte)'D', fileIdentity.Bytes, token).ConfigureAwait(false);
            var stop = await WindowsStageChannel.ReadAsync(pipe, token).ConfigureAwait(false);
            return stop.Kind == (byte)'S' && stop.Payload.Length == 0 ? 0 : 2;

            void Check()
            {
                token.ThrowIfCancellationRequested();
                WindowsStageChannel.RequireServer(pipe, parent, parentPid, parentCreated);
                WorkspacePath.RequireWindowsStageDirectory(root, binding.RootIdentity);
                WorkspacePath.CheckWindowsTransactionalStage(file, directory, binding, transaction);
                if (!CryptographicOperations.FixedTimeEquals(
                        RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file), directory: false).Bytes, fileIdentity.Bytes))
                    throw new WorkspacePathException("file_identity_changed");
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            // Never log a binding, body, pipe secret or workspace path through this private role.
            return 2;
        }
        finally { if (content is not null) CryptographicOperations.ZeroMemory(content); }
    }

    private static async Task RequireGoAsync(Stream pipe, CancellationToken token)
    {
        var message = await WindowsStageChannel.ReadAsync(pipe, token).ConfigureAwait(false);
        if (message.Kind != (byte)'G' || message.Payload.Length != 0)
            throw new InvalidDataException("The private stage permission is invalid.");
    }
}
