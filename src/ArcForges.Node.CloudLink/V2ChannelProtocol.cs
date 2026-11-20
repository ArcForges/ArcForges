// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Text;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink;

/// <summary>Current Node store identity and actually qualified capabilities.</summary>
internal sealed record V2ChannelSnapshot(ReadOnlyMemory<byte> OwnerEpoch, string NodeEpoch, byte Platform, IReadOnlyList<string> Capabilities);

/// <summary>Authenticated enrollment observed on an accepted V2 channel. Carries no credentials.</summary>
internal sealed record V2ChannelEnrollment(CenterEndpoint Center, string AccountId, string LinkedInstallationId, string EnrollmentId,
    string ProtocolEpoch, string ConnectionId, ulong HubFence, DateTimeOffset ObservedAt);

internal enum V2ChannelKind : byte
{
    Challenge = 1,
    Hello,
    Accepted,
    Heartbeat,
    Refresh,
    Close,
    ControlRequest,
    ControlResult,
}

internal readonly record struct V2ChannelFrame(V2ChannelKind Kind, ReadOnlyMemory<byte> Payload);

internal readonly record struct V2ChannelChallenge(ReadOnlyMemory<byte> Payload)
{
    public ReadOnlySpan<byte> ConnectionId => Payload.Span.Slice(32, 16);
    public ReadOnlySpan<byte> EnrollmentId => Payload.Span.Slice(48, 16);
    public ReadOnlySpan<byte> ProtocolEpoch => Payload.Span.Slice(64, 16);
    public ReadOnlySpan<byte> AccountId => Payload.Span.Slice(80, 16);
    public ulong HubFence => BinaryPrimitives.ReadUInt64BigEndian(Payload.Span[96..]);
    public long DeadlineMilliseconds => BinaryPrimitives.ReadInt64BigEndian(Payload.Span[104..]);

    public V2ChannelEnrollment Enrollment(ChannelTicket opened, DateTimeOffset observedAt) => new(opened.Center,
        Convert.ToHexStringLower(AccountId), Convert.ToHexStringLower(opened.InstallationId.Span),
        Convert.ToHexStringLower(EnrollmentId), Convert.ToHexStringLower(ProtocolEpoch),
        Convert.ToHexStringLower(ConnectionId), HubFence, observedAt);
}

internal readonly record struct V2ChannelLimits(uint MaxFrameBytes, uint HeartbeatMilliseconds, uint HeartbeatDeadlineMilliseconds);

/// <summary>
/// Private relay.v2 lifecycle frames. The WebSocket subprotocol and signature domain separate this wire from V1. The
/// credential, Node, store owner epoch, protocol epoch and live hub fence are bound to the exact hello proof bytes.
/// </summary>
internal static class V2ChannelProtocol
{
    public const string CohortCapability = "cohort-ci.481.1";
    public const string UpgradeRequired = "upgrade_required";
    public const byte Version = 2;
    public const int HeaderBytes = 10;
    private const int MaxTokenBytes = 4096;
    private const int ChallengeBytes = 112;
    private const int AcceptedBytes = 68;
    private const int SignatureBytes = RelaySignatures.SignatureLength;
    private static ReadOnlySpan<byte> HelloDomain => "ArcForges relay-hello v2\n"u8;

    public static byte[] Encode(V2ChannelKind kind, ulong sequence, ReadOnlySpan<byte> payload)
    {
        var bytes = new byte[HeaderBytes + payload.Length];
        bytes[0] = Version;
        bytes[1] = (byte)kind;
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(2), sequence);
        payload.CopyTo(bytes.AsSpan(HeaderBytes));
        return bytes;
    }

    public static bool TryDecode(ReadOnlyMemory<byte> bytes, ulong expectedSequence, out V2ChannelFrame frame, bool controlEnabled = false)
    {
        frame = default;
        var input = bytes.Span;
        if (input.Length is < HeaderBytes or > CenterChannelClient.MaxFrameBytes || input[0] != Version || expectedSequence == 0 ||
            BinaryPrimitives.ReadUInt64BigEndian(input[2..]) != expectedSequence ||
            input[1] < (byte)V2ChannelKind.Challenge ||
            input[1] > (byte)(controlEnabled ? V2ChannelKind.ControlResult : V2ChannelKind.Close))
        {
            return false;
        }

        frame = new((V2ChannelKind)input[1], bytes[HeaderBytes..]);
        return true;
    }

    public static bool TryChallenge(V2ChannelFrame frame, out V2ChannelChallenge challenge)
    {
        challenge = default;
        var payload = frame.Payload.Span;
        if (frame.Kind != V2ChannelKind.Challenge || payload.Length != ChallengeBytes ||
            payload[..32].IndexOfAnyExcept((byte)0) < 0 || !IsId(payload.Slice(32, 16)) || !IsId(payload.Slice(48, 16)) ||
            !IsId(payload.Slice(64, 16)) || !IsId(payload.Slice(80, 16)) ||
            BinaryPrimitives.ReadUInt64BigEndian(payload[96..]) is 0 or > long.MaxValue ||
            BinaryPrimitives.ReadInt64BigEndian(payload[104..]) is <= 0 or > 253402300799999L)
        {
            return false;
        }

        challenge = new(frame.Payload);
        return true;
    }

    public static bool TryAccept(V2ChannelFrame frame, V2ChannelChallenge challenge, out V2ChannelLimits limits)
    {
        limits = default;
        var payload = frame.Payload.Span;
        if (frame.Kind != V2ChannelKind.Accepted || payload.Length != AcceptedBytes || challenge.Payload.Length != ChallengeBytes ||
            !payload[..48].SequenceEqual(challenge.Payload.Span.Slice(32, 48)) ||
            BinaryPrimitives.ReadUInt64BigEndian(payload[48..]) != challenge.HubFence)
        {
            return false;
        }

        uint maxBytes = BinaryPrimitives.ReadUInt32BigEndian(payload[56..]);
        uint heartbeat = BinaryPrimitives.ReadUInt32BigEndian(payload[60..]);
        uint deadline = BinaryPrimitives.ReadUInt32BigEndian(payload[64..]);
        if (maxBytes is < 128 or > CenterChannelClient.MaxFrameBytes || heartbeat is < 100 or > 120_000 ||
            deadline <= heartbeat || deadline > 300_000)
        {
            return false;
        }

        limits = new(maxBytes, heartbeat, deadline);
        return true;
    }

    public static byte[]? Hello(ChannelTicket ticket, V2ChannelSnapshot snapshot, V2ChannelChallenge challenge, INodeKey key)
    {
        if (!IsId(ticket.NodeId.Span) || !IsId(ticket.InstallationId.Span) || !IsId(snapshot.OwnerEpoch.Span) ||
            challenge.Payload.Length != ChallengeBytes || snapshot.Platform is not (1 or 2) ||
            snapshot.NodeEpoch.Length is < 1 or > 64 || !snapshot.NodeEpoch.All(static c =>
                char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-') ||
            snapshot.Capabilities.Count >= 16 || snapshot.Capabilities.Contains(CohortCapability, StringComparer.Ordinal) ||
            !snapshot.Capabilities.All(IsCapability) ||
            snapshot.Capabilities.Distinct(StringComparer.Ordinal).Count() != snapshot.Capabilities.Count)
        {
            return null;
        }

        var capabilities = snapshot.Capabilities.Append(CohortCapability).Order(StringComparer.Ordinal).ToArray();
        int prefixLength = 48 + 1 + snapshot.NodeEpoch.Length + 2 + capabilities.Sum(static value => 1 + value.Length);
        var payload = new byte[prefixLength + SignatureBytes];
        ticket.NodeId.Span.CopyTo(payload);
        ticket.InstallationId.Span.CopyTo(payload.AsSpan(16));
        snapshot.OwnerEpoch.Span.CopyTo(payload.AsSpan(32));
        var offset = 48;
        payload[offset++] = (byte)snapshot.NodeEpoch.Length;
        offset += Encoding.ASCII.GetBytes(snapshot.NodeEpoch, payload.AsSpan(offset));
        payload[offset++] = snapshot.Platform;
        payload[offset++] = (byte)capabilities.Length;
        foreach (string capability in capabilities)
        {
            payload[offset++] = (byte)capability.Length;
            offset += Encoding.ASCII.GetBytes(capability, payload.AsSpan(offset));
        }

        var input = new byte[HelloDomain.Length + ChallengeBytes + 32 + prefixLength];
        HelloDomain.CopyTo(input);
        challenge.Payload.Span.CopyTo(input.AsSpan(HelloDomain.Length));
        RelaySignatures.Audience(ticket.Center).CopyTo(input.AsSpan(HelloDomain.Length + ChallengeBytes));
        payload.AsSpan(0, prefixLength).CopyTo(input.AsSpan(input.Length - prefixLength));
        byte[] signature = key.Sign(input);
        if (signature.Length != SignatureBytes)
        {
            return null;
        }

        signature.CopyTo(payload.AsSpan(prefixLength));
        return payload;
    }

    public static bool IsHeartbeat(V2ChannelFrame frame) => frame.Kind == V2ChannelKind.Heartbeat &&
        frame.Payload.Length == sizeof(ulong) && BinaryPrimitives.ReadUInt64BigEndian(frame.Payload.Span) is > 0 and <= 253402300799999UL;

    public static byte[]? Refresh(string token) =>
        token.Length is > 0 and <= MaxTokenBytes && token.All(static c => c is >= '!' and <= '~')
            ? Encoding.ASCII.GetBytes(token) : null;

    public static byte[] Close(uint code, string reason)
    {
        var bytes = new byte[8 + reason.Length];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, code);
        Encoding.ASCII.GetBytes(reason, bytes.AsSpan(8));
        return bytes;
    }

    public static bool TryClose(V2ChannelFrame frame, out int code, out uint? reconnectAfter, out string reason)
    {
        code = 0;
        reconnectAfter = null;
        reason = string.Empty;
        var payload = frame.Payload.Span;
        if (frame.Kind != V2ChannelKind.Close || payload.Length is < 8 or > 72 ||
            BinaryPrimitives.ReadUInt32BigEndian(payload) is < 1000 or >= 5000)
        {
            return false;
        }

        foreach (byte character in payload[8..])
        {
            if (character is not (>= (byte)'a' and <= (byte)'z' or >= (byte)'0' and <= (byte)'9' or (byte)'_' or (byte)'.' or (byte)'-'))
            {
                return false;
            }
        }

        code = (int)BinaryPrimitives.ReadUInt32BigEndian(payload);
        uint delay = BinaryPrimitives.ReadUInt32BigEndian(payload[4..]);
        if (delay > 300_000 || code != 4500 && delay != 0)
        {
            return false;
        }

        reconnectAfter = delay == 0 ? null : delay;
        reason = Encoding.ASCII.GetString(payload[8..]);
        return true;
    }

    private static bool IsId(ReadOnlySpan<byte> value) => value.Length == 16 && value.IndexOfAnyExcept((byte)0) >= 0;

    private static bool IsCapability(string value) => value.Length is >= 1 and <= 32 && char.IsAsciiLetterLower(value[0]) &&
        value.All(static c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '.' or '-');
}
