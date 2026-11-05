// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;
using Google.Protobuf;
using RelayShapes = ArcForges.Contracts.Relay.Shapes.ContractShapeValidation;

namespace ArcForges.Node.CloudLink;

/// <summary>What the node checks a call against: its live link (the record's center, account and installation) and its command key set.</summary>
internal sealed record CallBinding
{
    /// <summary>The center the node is configured with (and its credential is bound to).</summary>
    public required CenterEndpoint Center { get; init; }

    /// <summary>This node's ID (16 bytes).</summary>
    public required ReadOnlyMemory<byte> NodeId { get; init; }

    /// <summary>The link's account ID (16 bytes), or empty when the credential names none (every call is then refused).</summary>
    public required ReadOnlyMemory<byte> AccountId { get; init; }

    /// <summary>The credential's installation ID (lower-case hex), to which the key set must be bound.</summary>
    public required string InstallationId { get; init; }

    /// <summary>The key sets received at sign-in and refresh (<c>run/cloud-keys.json</c>), or <see langword="null"/>.</summary>
    public CloudKeySetFile? Keys { get; init; }
}

/// <summary>A call that passed every check of CTR5-NODE-05, recorded pending in <c>routed_call_log</c>; only now may its payload be parsed.</summary>
/// <param name="Header">The verified call header (decoded from the bytes whose signature verified).</param>
/// <param name="Payload">The exact node.v1 request bytes (never re-encoded).</param>
/// <param name="LogId">The pending row of <c>routed_call_log</c>.</param>
internal sealed record VerifiedCall(CallHeader Header, ByteString Payload, long LogId);

/// <summary>A refused frame: the failed step (closed vocabulary) and its catalogue code; <paramref name="CallId"/> is the frame's call ID when well-formed.</summary>
internal sealed record CallRefusal(string Step, string Code, Id? CallId)
{
    /// <summary><c>CATEGORY/code</c> as <c>routed_call_log.refusal_code</c> records it.</summary>
    public string LogCode => Code == RoutedRefusals.Expired ? "STATE/expired" : "AUTHENTICATION/signature_invalid";
}

/// <summary>
/// The verification of a routed call before policy (AF-CTR-05 CTR5-NODE-05; Design 11 T-11; relay.proto CallHeader and "Verifier
/// pre-conditions"), in this order, each step refusing before the next:
/// <list type="number">
/// <item>the frame's shape: exact lengths and ranges of ChannelCall and its SignedHeader (64-byte signature, the kid pattern, a header of 1 to
/// 2,048 bytes, a payload of 1 to 253,952 bytes) before any signing input is built (<c>frame_shape</c>);</item>
/// <item><c>algorithm</c> is ES256;</item>
/// <item>the kid is a command key of the set bound to this node's center and installation, valid at now plus or minus 120 s (<c>unknown_key</c>;
/// a key set of another center or installation is no key set);</item>
/// <item>ES256 P1363 low-S over the call domain string followed by the exact header bytes received (<c>signature</c>);</item>
/// <item>only then is the header decoded, and its shape checked (<c>header_shape</c>: lengths, method 1..6, the 300 s lifetime);</item>
/// <item>the header's kid, center, account, target and call ID equal the signed frame's and this link's (<c>kid_mismatch</c>,
/// <c>center_mismatch</c>, <c>account_mismatch</c>, <c>target_mismatch</c>, <c>call_id_mismatch</c>); the request size and SHA-256 equal the
/// payload's (<c>request_digest</c>);</item>
/// <item>the windows: <c>issued_at &lt;= now + 120 s</c> (<c>not_yet_valid</c>) and <c>expires_at + 120 s &gt; now</c> (<c>STATE/expired</c>);</item>
/// <item>the call ID is not already logged (<c>call_replayed</c>, also after a restart), and the pending row is written in the same step.</item>
/// </list>
/// The payload is never parsed here. Every refusal is logged in <c>routed_call_log</c> by frame digest only.
/// </summary>
internal sealed class CallVerifier(RoutedCallLog log, TimeProvider clock)
{
    /// <summary>The clock skew the node allows on every window (AD-0021 section 10).</summary>
    public static readonly TimeSpan Skew = TimeSpan.FromSeconds(120);

    /// <summary>The largest call payload (relay.proto ChannelCall.payload).</summary>
    public const int MaxPayloadBytes = 253_952;

    /// <summary>The one signature algorithm.</summary>
    public const string Algorithm = "ES256";

    /// <summary>The refusal steps, in verification order (the closed vocabulary of <c>routed_call_log.refusal_step</c>).</summary>
    public static IReadOnlyList<string> Steps { get; } =
    [
        "frame_shape", "algorithm", "unknown_key", "signature", "header_shape", "kid_mismatch", "center_mismatch", "account_mismatch",
        "target_mismatch", "call_id_mismatch", "request_digest", "not_yet_valid", "expired", RoutedCallLog.Replayed,
    ];

    /// <summary>Verifies <paramref name="call"/> (decoded from <paramref name="frame"/>, the received RelayFrame bytes) against <paramref name="binding"/>.</summary>
    public async Task<(VerifiedCall? Call, CallRefusal? Refusal)> VerifyAsync(ReadOnlyMemory<byte> frame, ChannelCall call, CallBinding binding)
    {
        ArgumentNullException.ThrowIfNull(call);
        ArgumentNullException.ThrowIfNull(binding);
        var frameSha = SHA256.HashData(frame.Span);
        var (header, refusal) = Check(call, binding);
        if (refusal is not null)
        {
            await log.RecordRefusalAsync(frameSha, refusal.Step, refusal.LogCode).ConfigureAwait(false);
            return (null, refusal);
        }

        var row = new VerifiedCallRow
        {
            FrameSha256 = frameSha,
            CallId = header!.CallId.Value.ToByteArray(),
            Kid = header.Kid,
            Method = (int)header.Method,
            Caller = header.Caller.ToByteArray(),
            CommandId = header.CommandId?.Value.ToByteArray(),
            RequestSha256 = header.RequestSha256.ToByteArray(),
            RequestSize = header.RequestSize,
        };
        if (await log.RecordVerifiedAsync(row).ConfigureAwait(false) is not { } logId)
        {
            return (null, new CallRefusal(RoutedCallLog.Replayed, RoutedRefusals.SignatureInvalid, call.CallId));
        }

        return (new VerifiedCall(header, call.Payload, logId), null);
    }

    /// <summary>True when the call's kid is absent from the key set (the channel then refreshes once before refusing; Plan PN-14).</summary>
    public static bool UnknownKid(ChannelCall call, CallBinding binding)
    {
        ArgumentNullException.ThrowIfNull(call);
        ArgumentNullException.ThrowIfNull(binding);
        return call.Header is { HasKid: true } signed && Key(binding, signed.Kid, DateTimeOffset.MinValue, any: true) is null;
    }

    /// <summary>The checks before the replay check, in order (pure; the clock is read once).</summary>
    internal (CallHeader? Header, CallRefusal? Refusal) Check(ChannelCall call, CallBinding binding)
    {
        var callId = call.CallId is { } id && RelaySignatures.ValidId(id.Value.Span) ? id : null;
        CallRefusal Refuse(string step) => new(step, step == "expired" ? RoutedRefusals.Expired : RoutedRefusals.SignatureInvalid, callId);

        // 1. Exact lengths and ranges first: no signing input is built from a field of another length.
        if (!RelayShapes.IsValid(call) || call.Payload.Length > MaxPayloadBytes)
        {
            return (null, Refuse("frame_shape"));
        }

        var signed = call.Header;
        if (signed.Algorithm != Algorithm)
        {
            return (null, Refuse("algorithm"));
        }

        var now = clock.GetUtcNow();
        if (Key(binding, signed.Kid, now, any: false) is not { } spki)
        {
            return (null, Refuse("unknown_key"));
        }

        if (!RelaySignatures.Verify(spki, RelaySignatures.CallInput(signed.Header.Span), signed.Signature.Span))
        {
            return (null, Refuse("signature"));
        }

        // Only bytes whose signature verified are decoded.
        CallHeader header;
        try
        {
            header = CallHeader.Parser.ParseFrom(signed.Header);
        }
        catch (InvalidProtocolBufferException)
        {
            return (null, Refuse("header_shape"));
        }

        if (!RelayShapes.IsValid(header))
        {
            return (null, Refuse("header_shape"));
        }

        if (header.Kid != signed.Kid)
        {
            return (null, Refuse("kid_mismatch"));
        }

        if (!header.CenterUrlSha256.Span.SequenceEqual(RelaySignatures.Audience(binding.Center)))
        {
            return (null, Refuse("center_mismatch"));
        }

        if (binding.AccountId.Length != 16 || !header.AccountId.Value.Span.SequenceEqual(binding.AccountId.Span))
        {
            return (null, Refuse("account_mismatch"));
        }

        if (!header.TargetNodeId.Value.Span.SequenceEqual(binding.NodeId.Span))
        {
            return (null, Refuse("target_mismatch"));
        }

        if (!header.CallId.Equals(call.CallId))
        {
            return (null, Refuse("call_id_mismatch"));
        }

        if (header.RequestSize != call.Payload.Length || !header.RequestSha256.Span.SequenceEqual(SHA256.HashData(call.Payload.Span)))
        {
            return (null, Refuse("request_digest"));
        }

        if (ProtoTime.ToDateTimeOffset(header.IssuedAt) is not { } issued || issued > now + Skew)
        {
            return (null, Refuse("not_yet_valid"));
        }

        if (ProtoTime.ToDateTimeOffset(header.ExpiresAt) is not { } expires || !StillValid(expires, now))
        {
            return (null, Refuse("expired"));
        }

        return (header, null);
    }

    /// <summary>The expiry window (and the re-check immediately before the effect, Plan PN-15): <c>expires_at + 120 s</c> has not passed.</summary>
    public static bool StillValid(DateTimeOffset expires, DateTimeOffset now) => expires + Skew > now;

    /// <summary>
    /// The SPKI of <paramref name="kid"/> in the command key set, when the set is bound to the binding's center and installation and the key's
    /// validity includes <paramref name="now"/> plus or minus 120 s (<paramref name="any"/>: whatever its validity).
    /// </summary>
    private static byte[]? Key(CallBinding binding, string kid, DateTimeOffset now, bool any)
    {
        if (binding.Keys is not { } keys || keys.CenterUrl != binding.Center.Url || keys.InstallationId != binding.InstallationId)
        {
            return null;
        }

        foreach (var entry in keys.CommandKeys)
        {
            if (entry.Kid != kid || entry.Key is null || (entry.Algorithm is not null && entry.Algorithm != Algorithm))
            {
                continue;
            }

            if (!any && ((entry.NotBeforeMs > 0 && DateTimeOffset.FromUnixTimeMilliseconds(entry.NotBeforeMs) > now + Skew)
                || (entry.NotAfterMs > 0 && DateTimeOffset.FromUnixTimeMilliseconds(entry.NotAfterMs) < now - Skew)))
            {
                continue;
            }

            try
            {
                return Convert.FromBase64String(entry.Key);
            }
            catch (FormatException)
            {
                return null;
            }
        }

        return null;
    }
}
