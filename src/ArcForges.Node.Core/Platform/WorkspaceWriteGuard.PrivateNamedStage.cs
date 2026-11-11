// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;

namespace ArcForges.Node.Core.Platform;

internal sealed partial class WorkspaceWriteGuard
{
    /// <summary>
    /// Writes only an empty, already registered private named object through its held handle. A caller must first
    /// commit and check the durable identity, caller, exact request and expected content; this method gives no
    /// authorization, approval or target-effect guarantee. Failure can leave partial bytes on the owned object.
    /// </summary>
    internal void WritePrivateNamedStage(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> expectedSha256,
        CancellationToken cancellationToken, Action? afterFirstWrite = null)
    {
        if (bytes.Length > MaximumExpectedBytes || expectedSha256.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), expectedSha256))
            throw new ArgumentException("The private stage bytes do not match the bounded intent.");
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (!_privateStage || _expectedLinks != 1 || _verifyPrivateSecurity is null)
                throw new InvalidOperationException("A checked private named stage is required.");
            CheckLocked();
            if (RandomAccess.GetLength(_file!) != 0)
                throw new InvalidOperationException("A nonempty private stage cannot be written again.");
            var offset = 0;
            while (offset < bytes.Length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CheckLocked();
                var count = Math.Min(65_536, bytes.Length - offset);
                RandomAccess.Write(_file!, bytes.Slice(offset, count), offset);
                offset += count;
                if (offset == count) afterFirstWrite?.Invoke();
                CheckLocked();
            }

            cancellationToken.ThrowIfCancellationRequested();
            CheckLocked();
            RandomAccess.FlushToDisk(_file!);
            CheckLocked();
            if (!MatchesExpectedContent(expectedSha256, bytes.Length, cancellationToken))
                throw new WorkspacePathException("file_identity_changed");
        }
    }
}
