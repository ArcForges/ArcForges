// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using ArcForges.Contracts.Foundation.V1;
using Google.Protobuf;

namespace ArcForges.Client;

/// <summary>
/// UUIDv7 command IDs, one per user action (architecture 12 section 1; R-EXE-016). A retry of the same action reuses the
/// same ID and resends the same request bytes, so the node's 24-hour deduplication returns the stored outcome instead of
/// acting twice (contracts README section 6: the payload digest covers the request's wire bytes, map order included).
/// </summary>
public static class CommandIds
{
    /// <summary>A new command ID for the current instant of <paramref name="clock"/> (16 bytes, RFC 9562 byte order).</summary>
    public static Id New(TimeProvider? clock = null)
    {
        var now = (clock ?? TimeProvider.System).GetUtcNow();
        return new Id { Value = ByteString.CopyFrom(Guid.CreateVersion7(now).ToByteArray(bigEndian: true)) };
    }

    /// <summary>Prepares one user action: sets a new command ID in the request's <c>meta</c> and freezes its bytes.</summary>
    public static UserAction<TRequest> Begin<TRequest>(TRequest request, Func<TRequest, RequestMeta?> meta, Action<TRequest, RequestMeta> setMeta,
        TimeProvider? clock = null)
        where TRequest : IMessage<TRequest>
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(meta);
        ArgumentNullException.ThrowIfNull(setMeta);
        var current = meta(request) ?? new RequestMeta();
        current.CommandId = New(clock);
        setMeta(request, current);
        return new UserAction<TRequest>(request);
    }
}

/// <summary>
/// One user action's mutation: its request with a fixed command ID and the exact bytes it was first sent with. Every retry
/// sends this instance again; <see cref="RequestForAttempt"/> refuses a request that was changed after it was prepared.
/// </summary>
public sealed class UserAction<TRequest>
    where TRequest : IMessage<TRequest>
{
    private readonly byte[] _bytes;

    internal UserAction(TRequest request)
    {
        Request = request;
        _bytes = request.ToByteArray();
    }

    /// <summary>The request, with its command ID set.</summary>
    public TRequest Request { get; }

    /// <summary>How many attempts were sent.</summary>
    public int Attempts { get; private set; }

    /// <summary>The wire bytes every attempt sends.</summary>
    public ReadOnlySpan<byte> Bytes => _bytes;

    /// <summary>The request for the next attempt; it must still serialize to the bytes of the first attempt.</summary>
    public TRequest RequestForAttempt()
    {
        if (!Request.ToByteArray().AsSpan().SequenceEqual(_bytes))
        {
            throw new InvalidOperationException("A retried command must resend the identical request bytes; the request changed after it was prepared.");
        }

        Attempts++;
        return Request;
    }
}

/// <summary>Crockford base32 text of IDs (contracts README section 2: lower case in the CLI, MCP and URLs).</summary>
public static class IdText
{
    private const string Alphabet = "0123456789abcdefghjkmnpqrstvwxyz";

    /// <summary>The 26-character text of a 16-byte ID (big-endian, two leading zero bits, as in ULID).</summary>
    public static string Format(ReadOnlySpan<byte> id)
    {
        if (id.Length != 16)
        {
            return Convert.ToHexStringLower(id);
        }

        var value = new UInt128(BinaryPrimitives.ReadUInt64BigEndian(id[..8]), BinaryPrimitives.ReadUInt64BigEndian(id[8..]));
        Span<char> text = stackalloc char[26];
        for (var i = 25; i >= 0; i--)
        {
            text[i] = Alphabet[(int)(value & 31)];
            value >>= 5;
        }

        return new string(text);
    }

    /// <summary>The text of an <see cref="Id"/>, or an empty string when it is absent.</summary>
    public static string Format(Id? id) => id is null || id.Value.IsEmpty ? string.Empty : Format(id.Value.Span);

    /// <summary>Parses a full 26-character ID (case-insensitive; I and L read as 1, O as 0).</summary>
    public static bool TryParse(string? text, out byte[] id)
    {
        id = [];
        if (text is null || text.Length != 26)
        {
            return false;
        }

        UInt128 value = 0;
        for (var i = 0; i < text.Length; i++)
        {
            var digit = Digit(text[i]);
            if (digit < 0 || (i == 0 && digit > 7))
            {
                return false;
            }

            value = (value << 5) | (uint)digit;
        }

        var bytes = new byte[16];
        for (var i = 15; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }

        id = bytes;
        return true;
    }

    /// <summary>Normalizes a full ID or an ID prefix to lower-case canonical digits; false when a character is not base32.</summary>
    public static bool TryNormalizePrefix(string? text, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrEmpty(text) || text.Length > 26)
        {
            return false;
        }

        Span<char> chars = stackalloc char[text.Length];
        for (var i = 0; i < text.Length; i++)
        {
            var digit = Digit(text[i]);
            if (digit < 0)
            {
                return false;
            }

            chars[i] = Alphabet[digit];
        }

        normalized = new string(chars);
        return true;
    }

    private static int Digit(char character) => char.ToLowerInvariant(character) switch
    {
        'o' => 0,
        'i' or 'l' => 1,
        var lower => Alphabet.IndexOf(lower, StringComparison.Ordinal),
    };
}
