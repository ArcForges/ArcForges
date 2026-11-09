// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Files;

/// <summary>The bounded bytes actually read from one held native file, plus their exact range and digest.</summary>
internal sealed record WorkspaceRead(ReadOnlyMemory<byte> Bytes, ulong Offset, ulong NextOffset, ulong FileSize, bool Eof, ReadOnlyMemory<byte> Sha256);

/// <summary>A closed read refusal that preserves content-free observations after partial I/O.</summary>
internal sealed class WorkspaceReadException(string reason, int observedBytes, ReadOnlyMemory<byte>? observedSha256, Exception? inner = null)
    : IOException(reason, inner)
{
    public string Reason { get; } = reason;
    public int ObservedBytes { get; } = observedBytes;
    public ReadOnlyMemory<byte>? ObservedSha256 { get; } = observedSha256;
}

/// <summary>
/// Bounded file-range I/O on an already authorized workspace anchor. This does not register a root, grant permission,
/// expose an IPC endpoint or persist an audit; the service owns those decisions and records the returned observations.
/// </summary>
internal static class WorkspaceFileReader
{
    public const int MaximumReadBytes = 65_536;

    public static WorkspaceRead Read(WorkspacePath workspace, string path, ulong offset, ulong length, CancellationToken cancellationToken = default) =>
        Read(workspace, path, offset, length, checkpoint: null, cancellationToken);

    // The callback coordinates real file changes/cancellation in component tests; production passes no callback.
    internal static WorkspaceRead Read(WorkspacePath workspace, string path, ulong offset, ulong length,
        Action<WorkspaceReadCheckpoint>? checkpoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        ArgumentOutOfRangeException.ThrowIfZero(length);
        cancellationToken.ThrowIfCancellationRequested();
        var file = workspace.OpenRead(path);
        byte[] bytes = [];
        var count = 0;
        try
        {
            var firstIdentity = WorkspacePath.Identity(file);
            if (!firstIdentity.IsFile || firstIdentity.Links != 1)
            {
                throw Failure("file_identity_changed", bytes, count);
            }

            var initialSize = checked((ulong)RandomAccess.GetLength(file));
            checkpoint?.Invoke(WorkspaceReadCheckpoint.AfterInitialSize);
            var requested = offset >= initialSize ? 0 : checked((int)Math.Min((ulong)MaximumReadBytes, Math.Min(length, initialSize - offset)));
            bytes = new byte[requested];
            while (count < bytes.Length)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    throw Failure("file_read_cancelled", bytes, count);
                }

                // Small bounded reads allow cancellation and identity changes to be observed without inventing a snapshot.
                var part = bytes.AsSpan(count, Math.Min(16_384, bytes.Length - count));
                var read = RandomAccess.Read(file, part, checked((long)(offset + (ulong)count)));
                if (read == 0)
                {
                    break;
                }

                count += read;
                checkpoint?.Invoke(WorkspaceReadCheckpoint.AfterBytesRead);
            }

            var observedSize = checked((ulong)RandomAccess.GetLength(file));
            var identity = WorkspacePath.Identity(file);
            var next = checked(offset + (ulong)count);
            // EOF goes through the same identity, size and cancellation checks as a nonempty read.
            // A concurrent truncate or growth must not yield an out-of-file range or a zero-progress continuation.
            if (!firstIdentity.SameObject(identity) || !identity.IsFile || identity.Links != 1 ||
                (count == 0 ? offset < observedSize : next > observedSize))
            {
                throw Failure("file_changed_while_reading", bytes, count);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                throw Failure("file_read_cancelled", bytes, count);
            }

            var actual = bytes.AsMemory(0, count);
            return new WorkspaceRead(actual, offset, next, observedSize, next >= observedSize, SHA256.HashData(actual.Span));
        }
        catch (WorkspaceReadException)
        {
            throw;
        }
        catch (IOException exception)
        {
            throw Failure("file_read_unavailable", bytes, count, exception);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw Failure("file_access_denied", bytes, count, exception);
        }
    }

    private static WorkspaceReadException Failure(string reason, ReadOnlySpan<byte> bytes, int count, Exception? inner = null) =>
        new(reason, count, count == 0 ? (ReadOnlyMemory<byte>?)null : SHA256.HashData(bytes[..count]), inner);
}

/// <summary>Test coordination points around actual file I/O; these do not replace filesystem behavior.</summary>
internal enum WorkspaceReadCheckpoint
{
    AfterInitialSize,
    AfterBytesRead,
}
