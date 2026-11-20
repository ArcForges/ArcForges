// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.Node.CloudLink;

internal enum V2ControlSelector : byte
{
    NodeGetOperation = 1,
    NodeListRemoteGrants = 2,
    NodeRevokeRemoteGrant = 3,
    SandboxCreate = 4,
    SandboxConfigure = 5,
    SandboxList = 6,
    SandboxInspect = 7,
    RunStart = 8,
    RunStop = 9,
    RunList = 10,
    RunInspect = 11,
    ResourceGetBudget = 12,
    ResourceSetPolicy = 13,
}

internal readonly record struct V2ControlRequestHeader(
    ReadOnlyMemory<byte> CallId, V2ControlSelector Selector, ReadOnlyMemory<byte> AccountId, ReadOnlyMemory<byte> ActorId,
    ReadOnlyMemory<byte> NodeId, ReadOnlyMemory<byte> EnrollmentId, ReadOnlyMemory<byte> ProtocolEpoch, ReadOnlyMemory<byte> ConnectionId,
    ReadOnlyMemory<byte> OriginalOwnerEpoch, ReadOnlyMemory<byte> CommandId, ReadOnlyMemory<byte> GrantId, ulong GrantRevision, ulong HubFence,
    long DeadlineUnixMilliseconds, ReadOnlyMemory<byte> AudienceSha256, string KeyId);

internal readonly record struct V2ControlRequest(V2ControlRequestHeader Header, ReadOnlyMemory<byte> Body,
    ReadOnlyMemory<byte> SigningInput, ReadOnlyMemory<byte> RequestBinding, ReadOnlyMemory<byte> Signature);

internal readonly record struct V2ControlResult(ReadOnlyMemory<byte> CallId, ReadOnlyMemory<byte> RequestBinding, ReadOnlyMemory<byte> Body,
    ReadOnlyMemory<byte> SigningInput, ReadOnlyMemory<byte> Signature);

/// <summary>An exact signed request body and its authenticated live channel as observed on receipt.</summary>
internal sealed record V2ControlCall(V2ControlRequest Request, V2ChannelEnrollment Enrollment, DateTimeOffset ReceivedAt, DateTimeOffset Deadline);

internal sealed class V2ControlPreparedFrame(byte[] payloadPrefix, V2ChannelKind kind, ulong sequence,
    ReadOnlyMemory<byte> signingInput, ReadOnlyMemory<byte> requestBinding)
{
    public ReadOnlyMemory<byte> SigningInput { get; } = signingInput;
    public ReadOnlyMemory<byte> RequestBinding { get; } = requestBinding;

    public byte[]? AttachSignature(ReadOnlySpan<byte> signature) =>
        sequence > 0 && AttachPayloadSignature(signature) is { } payload ? V2ChannelProtocol.Encode(kind, sequence, payload) : null;

    public byte[]? AttachPayloadSignature(ReadOnlySpan<byte> signature) =>
        signature.Length == RelaySignatures.SignatureLength ? [.. payloadPrefix, .. signature] : null;
}

/// <summary>
/// Fixed private relay.v2 control frames. Parsing checks shape, body digest and expiry. Callers must verify the signature
/// with their admitted peer key and apply live connection, grant, request and method checks before interpreting the body.
/// </summary>
internal static class V2ControlWire
{
    public const string ControlCapability = "center-control-v2";
    public const byte RequestKind = (byte)V2ChannelKind.ControlRequest;
    public const byte ResultKind = (byte)V2ChannelKind.ControlResult;

    private const int IdBytes = 16;
    private const int HashBytes = 32;
    private const int SignatureBytes = RelaySignatures.SignatureLength;
    private const int SelectorOffset = IdBytes;
    private const int AccountOffset = SelectorOffset + sizeof(byte);
    private const int ActorOffset = AccountOffset + IdBytes;
    private const int NodeOffset = ActorOffset + IdBytes;
    private const int EnrollmentOffset = NodeOffset + IdBytes;
    private const int ProtocolEpochOffset = EnrollmentOffset + IdBytes;
    private const int ConnectionOffset = ProtocolEpochOffset + IdBytes;
    private const int OwnerEpochOffset = ConnectionOffset + IdBytes;
    private const int CommandOffset = OwnerEpochOffset + IdBytes;
    private const int GrantOffset = CommandOffset + IdBytes;
    private const int GrantRevisionOffset = GrantOffset + IdBytes;
    private const int HubFenceOffset = GrantRevisionOffset + sizeof(ulong);
    private const int DeadlineOffset = HubFenceOffset + sizeof(ulong);
    private const int AudienceOffset = DeadlineOffset + sizeof(long);
    private const int RequestDigestOffset = AudienceOffset + HashBytes;
    private const int KeyLengthOffset = RequestDigestOffset + HashBytes;
    private const int KeyOffset = KeyLengthOffset + sizeof(byte);
    private const int MaxKeyBytes = 64;
    private const int MinRequestMetadataBytes = KeyOffset + 1 + sizeof(uint);

    private const int ResultBindingOffset = IdBytes;
    private const int ResultLengthOffset = ResultBindingOffset + HashBytes;
    private const int ResultDigestOffset = ResultLengthOffset + sizeof(uint);
    private const int ResultMetadataBytes = ResultDigestOffset + HashBytes;

    private static ReadOnlySpan<byte> RequestDomain => "ArcForges relay-control-request v2\n"u8;
    private static ReadOnlySpan<byte> ResultDomain => "ArcForges relay-control-result v2\n"u8;

    public static V2ControlPreparedFrame? PrepareRequest(in V2ControlRequestHeader header, ReadOnlySpan<byte> body,
        ulong sequence, uint maxFrameBytes, DateTimeOffset now)
    {
        if (!ValidRequestHeader(header, now))
        {
            return null;
        }

        int metadataLength = KeyOffset + header.KeyId.Length + sizeof(uint);
        if (sequence == 0 || !CanPrepare(maxFrameBytes, metadataLength, body.Length))
        {
            return null;
        }

        var prefix = new byte[metadataLength + body.Length];
        var metadata = prefix.AsSpan(0, metadataLength);
        header.CallId.Span.CopyTo(metadata);
        metadata[SelectorOffset] = (byte)header.Selector;
        header.AccountId.Span.CopyTo(metadata[AccountOffset..]);
        header.ActorId.Span.CopyTo(metadata[ActorOffset..]);
        header.NodeId.Span.CopyTo(metadata[NodeOffset..]);
        header.EnrollmentId.Span.CopyTo(metadata[EnrollmentOffset..]);
        header.ProtocolEpoch.Span.CopyTo(metadata[ProtocolEpochOffset..]);
        header.ConnectionId.Span.CopyTo(metadata[ConnectionOffset..]);
        header.OriginalOwnerEpoch.Span.CopyTo(metadata[OwnerEpochOffset..]);
        header.CommandId.Span.CopyTo(metadata[CommandOffset..]);
        header.GrantId.Span.CopyTo(metadata[GrantOffset..]);
        BinaryPrimitives.WriteUInt64BigEndian(metadata[GrantRevisionOffset..], header.GrantRevision);
        BinaryPrimitives.WriteUInt64BigEndian(metadata[HubFenceOffset..], header.HubFence);
        BinaryPrimitives.WriteInt64BigEndian(metadata[DeadlineOffset..], header.DeadlineUnixMilliseconds);
        header.AudienceSha256.Span.CopyTo(metadata[AudienceOffset..]);
        SHA256.HashData(body, metadata.Slice(RequestDigestOffset, HashBytes));
        metadata[KeyLengthOffset] = (byte)header.KeyId.Length;
        int keyBytes = Encoding.ASCII.GetBytes(header.KeyId, metadata[KeyOffset..]);
        BinaryPrimitives.WriteUInt32BigEndian(metadata[(KeyOffset + keyBytes)..], (uint)body.Length);
        body.CopyTo(prefix.AsSpan(metadataLength));

        var input = SigningInput(RequestDomain, metadata);
        return new(prefix, V2ChannelKind.ControlRequest, sequence, input, SHA256.HashData(input));
    }

    public static bool TryDecodeRequest(ReadOnlyMemory<byte> frame, ulong expectedSequence, uint maxFrameBytes, DateTimeOffset now,
        out V2ControlRequest request)
    {
        request = default;
        if (!TryPayload(frame, RequestKind, expectedSequence, maxFrameBytes, MinRequestMetadataBytes, out var payload))
        {
            return false;
        }

        var bytes = payload.Span;
        int keyBytes = bytes[KeyLengthOffset];
        int bodyLengthOffset = KeyOffset + keyBytes;
        int metadataLength = bodyLengthOffset + sizeof(uint);
        if (keyBytes is < 1 or > MaxKeyBytes || payload.Length <= metadataLength + SignatureBytes)
        {
            return false;
        }

        var header = new V2ControlRequestHeader(payload[..IdBytes], (V2ControlSelector)bytes[SelectorOffset],
            payload.Slice(AccountOffset, IdBytes), payload.Slice(ActorOffset, IdBytes), payload.Slice(NodeOffset, IdBytes),
            payload.Slice(EnrollmentOffset, IdBytes), payload.Slice(ProtocolEpochOffset, IdBytes), payload.Slice(ConnectionOffset, IdBytes),
            payload.Slice(OwnerEpochOffset, IdBytes), payload.Slice(CommandOffset, IdBytes), payload.Slice(GrantOffset, IdBytes),
            BinaryPrimitives.ReadUInt64BigEndian(bytes[GrantRevisionOffset..]), BinaryPrimitives.ReadUInt64BigEndian(bytes[HubFenceOffset..]),
            BinaryPrimitives.ReadInt64BigEndian(bytes[DeadlineOffset..]), payload.Slice(AudienceOffset, HashBytes),
            Encoding.ASCII.GetString(bytes.Slice(KeyOffset, keyBytes)));
        if (!ValidRequestHeader(header, now) || !TryBody(payload, metadataLength, bodyLengthOffset, RequestDigestOffset, out var body))
        {
            return false;
        }

        var input = SigningInput(RequestDomain, bytes[..metadataLength]);
        request = new(header, body, input, SHA256.HashData(input), payload[^SignatureBytes..]);
        return true;
    }

    public static V2ControlPreparedFrame? PrepareResult(ReadOnlySpan<byte> callId, ReadOnlySpan<byte> requestBinding, ReadOnlySpan<byte> body,
        ulong sequence, uint maxFrameBytes) =>
        sequence == 0 ? null : PrepareResultCore(callId, requestBinding, body, sequence, maxFrameBytes);

    /// <summary>Prepares a response whose outer sequence is written by the connected send gate.</summary>
    public static V2ControlPreparedFrame? PrepareResultPayload(ReadOnlySpan<byte> callId, ReadOnlySpan<byte> requestBinding,
        ReadOnlySpan<byte> body, uint maxFrameBytes) => PrepareResultCore(callId, requestBinding, body, 0, maxFrameBytes);

    private static V2ControlPreparedFrame? PrepareResultCore(ReadOnlySpan<byte> callId, ReadOnlySpan<byte> requestBinding,
        ReadOnlySpan<byte> body, ulong sequence, uint maxFrameBytes)
    {
        if (!IsId(callId) || requestBinding.Length != HashBytes || !CanPrepare(maxFrameBytes, ResultMetadataBytes, body.Length))
        {
            return null;
        }

        var prefix = new byte[ResultMetadataBytes + body.Length];
        var metadata = prefix.AsSpan(0, ResultMetadataBytes);
        callId.CopyTo(metadata);
        requestBinding.CopyTo(metadata[ResultBindingOffset..]);
        BinaryPrimitives.WriteUInt32BigEndian(metadata[ResultLengthOffset..], (uint)body.Length);
        SHA256.HashData(body, metadata.Slice(ResultDigestOffset, HashBytes));
        body.CopyTo(prefix.AsSpan(ResultMetadataBytes));
        return new(prefix, V2ChannelKind.ControlResult, sequence, SigningInput(ResultDomain, metadata),
            prefix.AsMemory(ResultBindingOffset, HashBytes));
    }

    public static bool TryDecodeResult(ReadOnlyMemory<byte> frame, ulong expectedSequence, uint maxFrameBytes, out V2ControlResult result)
    {
        result = default;
        if (!TryPayload(frame, ResultKind, expectedSequence, maxFrameBytes, ResultMetadataBytes, out var payload) ||
            !IsId(payload.Span[..IdBytes]) ||
            !TryBody(payload, ResultMetadataBytes, ResultLengthOffset, ResultDigestOffset, out var body))
        {
            return false;
        }

        result = new(payload[..IdBytes], payload.Slice(ResultBindingOffset, HashBytes), body,
            SigningInput(ResultDomain, payload.Span[..ResultMetadataBytes]), payload[^SignatureBytes..]);
        return true;
    }

    private static bool ValidRequestHeader(in V2ControlRequestHeader header, DateTimeOffset now) =>
        header.Selector is >= V2ControlSelector.NodeGetOperation and <= V2ControlSelector.ResourceSetPolicy &&
        IsId(header.CallId.Span) && IsId(header.AccountId.Span) && IsId(header.ActorId.Span) && IsId(header.NodeId.Span) &&
        IsId(header.EnrollmentId.Span) && IsId(header.ProtocolEpoch.Span) && IsId(header.ConnectionId.Span) &&
        IsId(header.OriginalOwnerEpoch.Span) && IsId(header.GrantId.Span) && header.CommandId.Length == IdBytes &&
        IsId(header.CommandId.Span) == RequiresCommand(header.Selector) &&
        header.GrantRevision is > 0 and <= long.MaxValue && header.HubFence is > 0 and <= long.MaxValue &&
        header.DeadlineUnixMilliseconds > 0 && header.DeadlineUnixMilliseconds > now.ToUnixTimeMilliseconds() &&
        header.AudienceSha256.Length == HashBytes && header.KeyId is { Length: >= 1 and <= MaxKeyBytes } &&
        header.KeyId.All(static c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');

    private static bool RequiresCommand(V2ControlSelector selector) =>
        selector is V2ControlSelector.NodeGetOperation or V2ControlSelector.NodeRevokeRemoteGrant or
            V2ControlSelector.SandboxCreate or V2ControlSelector.SandboxConfigure or V2ControlSelector.RunStart or
            V2ControlSelector.RunStop or V2ControlSelector.ResourceSetPolicy;

    private static bool IsId(ReadOnlySpan<byte> value) => value.Length == IdBytes && value.IndexOfAnyExcept((byte)0) >= 0;

    private static bool CanPrepare(uint maxFrameBytes, int metadataLength, int bodyLength) => bodyLength > 0 &&
        FitsFrame((long)V2ChannelProtocol.HeaderBytes + metadataLength + bodyLength + SignatureBytes, maxFrameBytes);

    private static bool FitsFrame(long frameBytes, uint maxFrameBytes) => maxFrameBytes <= CenterChannelClient.MaxFrameBytes && frameBytes <= maxFrameBytes;

    private static bool TryPayload(ReadOnlyMemory<byte> frame, byte kind, ulong sequence, uint maxFrameBytes, int minimumMetadata,
        out ReadOnlyMemory<byte> payload)
    {
        payload = default;
        if (sequence == 0 || frame.Length < V2ChannelProtocol.HeaderBytes + minimumMetadata + 1 + SignatureBytes ||
            !FitsFrame(frame.Length, maxFrameBytes) || frame.Span[0] != V2ChannelProtocol.Version || frame.Span[1] != kind ||
            BinaryPrimitives.ReadUInt64BigEndian(frame.Span[2..]) != sequence)
        {
            return false;
        }

        payload = frame[V2ChannelProtocol.HeaderBytes..];
        return true;
    }

    private static bool TryBody(ReadOnlyMemory<byte> payload, int metadataLength, int lengthOffset, int digestOffset,
        out ReadOnlyMemory<byte> body)
    {
        body = default;
        int bodyBytes = payload.Length - metadataLength - SignatureBytes;
        if (bodyBytes <= 0 || BinaryPrimitives.ReadUInt32BigEndian(payload.Span[lengthOffset..]) != (uint)bodyBytes)
        {
            return false;
        }

        var candidate = payload.Slice(metadataLength, bodyBytes);
        Span<byte> digest = stackalloc byte[HashBytes];
        SHA256.HashData(candidate.Span, digest);
        if (!CryptographicOperations.FixedTimeEquals(digest, payload.Span.Slice(digestOffset, HashBytes)))
        {
            return false;
        }

        body = candidate;
        return true;
    }

    private static byte[] SigningInput(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> metadata) => [.. domain, .. metadata];
}
