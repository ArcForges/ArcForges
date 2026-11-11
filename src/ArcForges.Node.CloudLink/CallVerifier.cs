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
/// <param name="ReceivedAt">The channel's monotonic receipt timestamp, assigned before queueing; absent only in direct in-process dispatch.</param>
internal sealed record VerifiedCall(CallHeader Header, ByteString Payload, long LogId, long? ReceivedAt = null);

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
/// <item>only then is the header decoded, and each field's length and presence checked (<c>header_shape</c>);</item>
/// <item>in the binding order of CTR5-NODE-05 (Plan E.2): the header's kid equals the signed frame's (<c>kid_mismatch</c>); the center
/// (<c>center_mismatch</c>); the target node (<c>target_mismatch</c>); the account, the caller's included (<c>account_mismatch</c>); the
/// windows: <c>issued_at &lt;= now + 120 s</c> (<c>not_yet_valid</c>), <c>expires_at + 120 s &gt; now</c> (<c>STATE/expired</c>), and at
/// most 300 s of lifetime with the deadline inside it (<c>lifetime</c>); the request size and SHA-256 (<c>request_digest</c>); the method
/// the implemented task, file and workspace methods, with command IDs exactly for mutations (<c>method</c>); the frame's call ID (<c>call_id_mismatch</c>); the contract's own
/// validator as a backstop (<c>header_shape</c>);</item>
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
        "frame_shape", "algorithm", "unknown_key", "signature", "header_shape", "kid_mismatch", "center_mismatch", "target_mismatch",
        "account_mismatch", "not_yet_valid", "expired", "lifetime", "request_digest", "method", "call_id_mismatch", RoutedCallLog.Replayed,
    ];

    /// <summary>Verifies <paramref name="call"/> (decoded from <paramref name="frame"/>, the received RelayFrame bytes) against <paramref name="binding"/>.</summary>
    /// <remarks>
    /// <paramref name="refreshKeys"/> (Plan PN-14): when the only failure so far is <c>unknown_key</c> (the frame's shape and algorithm
    /// passed), it is asked once for a refreshed binding, and the checks run again; it returns <see langword="null"/> when it refreshed nothing.
    /// </remarks>
    public async Task<(VerifiedCall? Call, CallRefusal? Refusal)> VerifyAsync(ReadOnlyMemory<byte> frame, ChannelCall call, CallBinding binding,
        Func<Task<CallBinding?>>? refreshKeys = null)
    {
        ArgumentNullException.ThrowIfNull(call);
        ArgumentNullException.ThrowIfNull(binding);
        var frameSha = SHA256.HashData(frame.Span);
        var (header, refusal) = Check(call, binding);
        if (refusal is { Step: "unknown_key" } && refreshKeys is not null && await refreshKeys().ConfigureAwait(false) is { } refreshed)
        {
            (header, refusal) = Check(call, refreshed);
        }

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

        // Only bytes whose signature verified are decoded; then each field's exact length and presence (no rule between fields yet).
        CallHeader header;
        try
        {
            header = CallHeader.Parser.ParseFrom(signed.Header);
        }
        catch (InvalidProtocolBufferException)
        {
            return (null, Refuse("header_shape"));
        }

        if (!Shaped(header))
        {
            return (null, Refuse("header_shape"));
        }

        // Then the binding order of CTR5-NODE-05 (Plan E.2): kid, center, target, account, the windows, the request, the method, the call.
        if (header.Kid != signed.Kid)
        {
            return (null, Refuse("kid_mismatch"));
        }

        if (!header.CenterUrlSha256.Span.SequenceEqual(RelaySignatures.Audience(binding.Center)))
        {
            return (null, Refuse("center_mismatch"));
        }

        if (!header.TargetNodeId.Value.Span.SequenceEqual(binding.NodeId.Span))
        {
            return (null, Refuse("target_mismatch"));
        }

        if (binding.AccountId.Length != 16 || !header.AccountId.Value.Span.SequenceEqual(binding.AccountId.Span)
            || !header.Caller.AccountId.Value.Span.SequenceEqual(binding.AccountId.Span))
        {
            return (null, Refuse("account_mismatch"));
        }

        var issued = ProtoTime.ToDateTimeOffset(header.IssuedAt)!.Value;
        var expires = ProtoTime.ToDateTimeOffset(header.ExpiresAt)!.Value;
        var deadline = ProtoTime.ToDateTimeOffset(header.Deadline)!.Value;
        if (issued > now + Skew)
        {
            return (null, Refuse("not_yet_valid"));
        }

        if (!StillValid(expires, now))
        {
            return (null, Refuse("expired"));
        }

        // AD-0021 section 10: issued_at < expires_at <= issued_at + 300 s, and issued_at < deadline <= expires_at.
        if (expires <= issued || expires - issued > MaxLifetime || deadline <= issued || deadline > expires ||
            (int)header.Method is >= 9 and <= 20 && (deadline - issued > TimeSpan.FromSeconds(15) || expires - deadline > TimeSpan.FromSeconds(30)))
        {
            return (null, Refuse("lifetime"));
        }

        if (header.RequestSize != call.Payload.Length || !header.RequestSha256.Span.SequenceEqual(SHA256.HashData(call.Payload.Span)))
        {
            return (null, Refuse("request_digest"));
        }

        var method = (int)header.Method;
        if (((method is < 1 or > 6) && method is not (9 or 12 or 13) && (method is < 17 or > 20))
            || (header.CommandId is not null) != (method is 1 or 6 or 17 or 18))
        {
            return (null, Refuse("method"));
        }

        if (!header.CallId.Equals(call.CallId))
        {
            return (null, Refuse("call_id_mismatch"));
        }

        // The contract's own validator agrees with every rule above (a backstop: a header it refuses is never verified).
        if (!RelayShapes.IsValid(header))
        {
            return (null, Refuse("header_shape"));
        }

        return (header, null);
    }

    /// <summary>The longest a call may live (AD-0021 section 10).</summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromSeconds(300);

    /// <summary>
    /// The header's fields one by one (relay.proto CallHeader, "Verifier pre-conditions"): every ID present where required, 16 bytes and
    /// not all zero; the digests 32 bytes; the kid's pattern; the size 1..253,952; the instants well-formed; the caller's own shape; the
    /// relay assertion digest exactly for a node-relayed caller. The relations of the binding order (windows, method) come after.
    /// </summary>
    private static bool Shaped(CallHeader header) =>
        ValidId(header.CallId) && header.HasKid && KidShape(header.Kid) && header.HasCenterUrlSha256 && header.CenterUrlSha256.Length == 32
        && ValidId(header.AccountId) && ValidId(header.TargetNodeId) && header.Caller is { } caller && RelayShapes.IsValid(caller)
        && (header.CommandId is null || ValidId(header.CommandId)) && header.HasMethod && header.HasRequestSha256 && header.RequestSha256.Length == 32
        && header.HasRequestSize && header.RequestSize is >= 1 and <= MaxPayloadBytes
        && ValidInstant(header.IssuedAt) && ValidInstant(header.ExpiresAt) && ValidInstant(header.Deadline)
        && header.HasRelayAssertionSha256 == (caller.Kind == ArcForges.Contracts.Node.V1.CenterCallerKind.NodeRelay)
        && (!header.HasRelayAssertionSha256 || header.RelayAssertionSha256.Length == 32);

    private static bool ValidId(Id? id) => id is not null && RelaySignatures.ValidId(id.Value.Span);

    private static bool ValidInstant(Instant? instant) => instant is not null && RelayShapes.IsValid(instant) && ProtoTime.ToDateTimeOffset(instant) is not null;

    private static bool KidShape(string kid) => kid.Length is >= 8 and <= 64 && kid.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');

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
            if (entry.Kid != kid || entry.Key is null || entry.Algorithm != Algorithm)
            {
                continue;
            }

            // Review A N-6: a key without its validity dates is not valid (fail closed); the dates are those the center delivered.
            if (!any && (entry.NotBeforeMs <= 0 || entry.NotAfterMs <= 0 || DateTimeOffset.FromUnixTimeMilliseconds(entry.NotBeforeMs) > now + Skew
                || DateTimeOffset.FromUnixTimeMilliseconds(entry.NotAfterMs) < now - Skew))
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
