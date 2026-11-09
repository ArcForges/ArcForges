// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Core.Platform;

namespace ArcForges.Node.Core.Files;

/// <summary>The bounded bytes actually read from one held native file, plus their exact range and digest.</summary>
internal sealed record WorkspaceRead(ReadOnlyMemory<byte> Bytes, ulong Offset, ulong NextOffset, ulong FileSize, bool Eof, ReadOnlyMemory<byte> Sha256);

/// <summary>A closed read refusal that preserves content-free observations after partial I/O.</summary>
internal sealed class WorkspaceReadException(string reason, int observedBytes, ReadOnlyMemory<byte> observedSha256, Exception? inner = null)
    : IOException(reason, inner)
{
    public string Reason { get; } = reason;
    public int ObservedBytes { get; } = observedBytes;
    public ReadOnlyMemory<byte> ObservedSha256 { get; } = observedSha256;
}

/// <summary>
/// Bounded file-range I/O on an already authorized workspace anchor. This does not register a root, grant permission,
/// expose an IPC endpoint or persist an audit; the service owns those decisions and records the returned observations.
/// </summary>
internal static class WorkspaceFileReader
{
    public const int MaximumReadBytes = 65_536;

    public static WorkspaceRead Read(WorkspacePath workspace, string path, ulong offset, ulong length, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        ArgumentOutOfRangeException.ThrowIfZero(length);
        cancellationToken.ThrowIfCancellationRequested();
        var file = workspace.OpenRead(path);
        var firstIdentity = WorkspacePath.Identity(file);
        if (!firstIdentity.IsFile || firstIdentity.Links != 1)
        {
            throw Failure("file_identity_changed", [], 0);
        }

        var initialSize = checked((ulong)RandomAccess.GetLength(file));
        if (offset >= initialSize)
        {
            return new WorkspaceRead(ReadOnlyMemory<byte>.Empty, offset, offset, initialSize, true, SHA256.HashData(ReadOnlySpan<byte>.Empty));
        }

        var requested = checked((int)Math.Min((ulong)MaximumReadBytes, Math.Min(length, initialSize - offset)));
        var bytes = new byte[requested];
        var count = 0;
        try
        {
            while (count < bytes.Length)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    throw Failure("file_read_cancelled", bytes, count);
                }

                var read = RandomAccess.Read(file, bytes.AsSpan(count), checked((long)(offset + (ulong)count)));
                if (read == 0)
                {
                    break;
                }

                count += read;
            }

            var observedSize = checked((ulong)RandomAccess.GetLength(file));
            var identity = WorkspacePath.Identity(file);
            var next = checked(offset + (ulong)count);
            // A concurrent truncate must not yield a fabricated file size, an out-of-file range or a zero-progress continuation.
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
        new(reason, count, SHA256.HashData(bytes[..count]), inner);
}
