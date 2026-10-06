// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;

namespace ArcForges.Observability.Desktop;

/// <summary>Host-owned secret adapter, normally backed by its Secrets service. Called afresh per bounded delivery attempt.</summary>
public interface IOtlpCollectorCredentials
{
    ValueTask<OtlpCollectorCredential> AcquireAsync(CancellationToken cancellationToken);
}

/// <summary>An ephemeral bearer credential. No public readable representation; disposed after transport hand-off finishes.</summary>
public sealed class OtlpCollectorCredential : IDisposable
{
    private readonly char[] _token;
    private static readonly SearchValues<char> BearerCharacters = SearchValues.Create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~+/=");
    private bool _disposed;

    public OtlpCollectorCredential(ReadOnlySpan<char> token)
    {
        if (token.Length is 0 or > 8192 || token.ContainsAnyExcept(BearerCharacters))
            throw new ArgumentException("A bounded bearer credential without whitespace is required.", nameof(token));
        _token = token.ToArray();
    }

    internal string Materialize()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new string(_token);
    }

    public override string ToString() => "OtlpCollectorCredential:[redacted]";

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Array.Clear(_token);
    }
}
