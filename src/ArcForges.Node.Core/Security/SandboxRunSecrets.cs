// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;
using Tmds.DBus.Protocol;

namespace ArcForges.Node.Core.Security;

/// <summary>Resolves immutable versions of explicitly supplied, owner-local Run credentials.</summary>
internal sealed class SandboxRunSecrets(NodeSecretStore store, string dataRoot, string ownerId)
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    internal static bool IsReference(string reference)
    {
        if (reference.Length is < 37 or > 56 || !reference.StartsWith("v1:", StringComparison.Ordinal)
            || reference[35] != ':' || reference[36] == '0')
        {
            return false;
        }

        var id = reference.AsSpan(3, 32);
        foreach (var digit in id)
        {
            if (!char.IsAsciiHexDigitLower(digit))
            {
                return false;
            }
        }

        return id.ContainsAnyExcept('0')
            && ulong.TryParse(reference.AsSpan(36), NumberStyles.None, CultureInfo.InvariantCulture, out _);
    }

    internal static string Target(string dataRoot, string ownerId, string reference)
    {
        if (!IsReference(reference))
        {
            throw new ArgumentException("Invalid Run secret reference.", nameof(reference));
        }

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataRoot));
        if (OperatingSystem.IsWindows())
        {
            root = root.ToUpperInvariant();
        }

        var identity = Encoding.UTF8.GetBytes($"arcforges.sandbox-run-secret.v1\0{ownerId}\0{root}\0{reference}");
        return NodeSecretStores.TargetPrefix + Convert.ToHexString(SHA256.HashData(identity));
    }

    internal string? Resolve(string reference)
    {
        byte[]? bytes = null;
        try
        {
            bytes = store.Store.Read(Target(dataRoot, ownerId, reference));
            return bytes is { Length: > 0 and <= SecretBroker.MaximumSecretBytes } && !bytes.AsSpan().Contains((byte)0)
                ? StrictUtf8.GetString(bytes)
                : null;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or CryptographicException
            or InvalidOperationException or TimeoutException or System.ComponentModel.Win32Exception
            or DBusExceptionBase or DecoderFallbackException)
        {
            return null;
        }
        finally
        {
            if (bytes is not null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }
}
