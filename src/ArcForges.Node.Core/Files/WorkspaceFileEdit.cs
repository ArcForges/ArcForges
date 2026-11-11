// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Node.Core.Files;

/// <summary>A bounded, non-content-bearing edit refusal; this component never writes a user file.</summary>
internal sealed class WorkspaceFileEditException(string reason) : Exception(reason)
{
    internal string Reason { get; } = reason;
}

/// <summary>One computed intended byte sequence, kept only in memory until it is staged or discarded.</summary>
internal sealed class WorkspaceFileEditResult(byte[] bytes, byte[] sha256, int replacements) : IDisposable
{
    private readonly byte[] _bytes = bytes;

    internal ReadOnlyMemory<byte> Bytes => _bytes;

    internal ReadOnlyMemory<byte> Sha256 { get; } = sha256;

    internal int Replacements { get; } = replacements;

    public void Dispose() => CryptographicOperations.ZeroMemory(_bytes);
}

/// <summary>
/// Exact UTF-8 edit planning for 06a section 3. Its input must come from a checked, guarded native file; the caller owns
/// authorization, durable staging, journal, pre-effect revalidation and the actual effect. No content is persisted here.
/// </summary>
internal static class WorkspaceFileEdit
{
    internal const int MaximumFileBytes = 4 * 1024 * 1024;
    internal const int MaximumTextBytes = 65_536;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static WorkspaceFileEditResult Plan(ReadOnlySpan<byte> original, ReadOnlySpan<byte> expectedSha256,
        string oldText, string newText, uint expectedOccurrences, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(oldText);
        ArgumentNullException.ThrowIfNull(newText);
        cancellationToken.ThrowIfCancellationRequested();
        if (original.Length > MaximumFileBytes) throw new WorkspaceFileEditException("file_existing_bytes");
        if (expectedSha256.Length != SHA256.HashSizeInBytes || oldText.Length == 0 || expectedOccurrences is < 1 or > 1000)
            throw new WorkspaceFileEditException("invalid_argument");
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(original), expectedSha256))
            throw new WorkspaceFileEditException("hash_mismatch");

        byte[] oldBytes;
        byte[] newBytes;
        try
        {
            _ = StrictUtf8.GetCharCount(original);
            if (StrictUtf8.GetByteCount(oldText) > MaximumTextBytes || StrictUtf8.GetByteCount(newText) > MaximumTextBytes)
                throw new WorkspaceFileEditException("file_edit_text_bytes");
            oldBytes = StrictUtf8.GetBytes(oldText);
            newBytes = StrictUtf8.GetBytes(newText);
        }
        catch (DecoderFallbackException)
        {
            throw new WorkspaceFileEditException("invalid_utf8");
        }
        catch (EncoderFallbackException)
        {
            throw new WorkspaceFileEditException("invalid_argument");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = 0;
            var position = 0;
            while (position <= original.Length - oldBytes.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relative = original[position..].IndexOf(oldBytes);
                if (relative < 0) break;
                count++;
                if (count > expectedOccurrences) throw new WorkspaceFileEditException("occurrence_mismatch");
                position += relative + oldBytes.Length;
            }

            if (count != expectedOccurrences) throw new WorkspaceFileEditException("occurrence_mismatch");
            var size = (long)original.Length + (long)count * (newBytes.Length - oldBytes.Length);
            if (size > MaximumFileBytes) throw new WorkspaceFileEditException("file_edit_result_bytes");

            var result = new byte[checked((int)size)];
            try
            {
                var source = 0;
                var destination = 0;
                for (var index = 0; index < count; index++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var relative = original[source..].IndexOf(oldBytes);
                    if (relative < 0) throw new InvalidOperationException("The in-memory edit plan changed unexpectedly.");
                    original.Slice(source, relative).CopyTo(result.AsSpan(destination));
                    destination += relative;
                    newBytes.CopyTo(result.AsSpan(destination));
                    destination += newBytes.Length;
                    source += relative + oldBytes.Length;
                }

                original[source..].CopyTo(result.AsSpan(destination));
                cancellationToken.ThrowIfCancellationRequested();
                return new WorkspaceFileEditResult(result, SHA256.HashData(result), count);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(result);
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(oldBytes);
            CryptographicOperations.ZeroMemory(newBytes);
        }
    }
}
