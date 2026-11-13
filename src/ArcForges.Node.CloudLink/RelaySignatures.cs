// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core;

namespace ArcForges.Node.CloudLink;

/// <summary>
/// The four signatures of the node channel (AF-CTR-05; Contracts relay.proto, "Signatures of the node channel"; Design 11 section 3,
/// "Signature domain strings"; Plan decision PB-3): each is ES256 over a fixed ASCII domain string of its own followed by its signed bytes, in
/// IEEE P1363 form r||s (64 bytes, r and s in [1, n-1], low-S). No signature is valid as another kind, and a signature over the signed bytes
/// without their domain string is refused. Pure functions; every field has a fixed length and is checked before any signing input is built
/// (relay.proto, "Verifier pre-conditions"): nothing is padded, truncated or re-encoded to fit.
/// </summary>
internal static class RelaySignatures
{
    /// <summary>The routed call (center command key): <c>"ArcForges relay-call v1\n"</c>, 24 bytes.</summary>
    public const string CallDomain = "ArcForges relay-call v1\n";

    /// <summary>The routed result (node key): <c>"ArcForges relay-result v1\n"</c>, 26 bytes.</summary>
    public const string ResultDomain = "ArcForges relay-result v1\n";

    /// <summary>The channel hello proof (node key): <c>"ArcForges relay-hello v1\n"</c>, 25 bytes.</summary>
    public const string HelloDomain = "ArcForges relay-hello v1\n";

    /// <summary>The relay assertion (relaying node key): <c>"ArcForges relay-origin v1\n"</c>, 26 bytes.</summary>
    public const string OriginDomain = "ArcForges relay-origin v1\n";

    /// <summary>The hello proof's signing input: 25 + 32 + 16 + 32 + 16 + 16 bytes.</summary>
    public const int HelloInputLength = 137;

    /// <summary>The relay assertion's signing input: 26 + 32 + 16 + 16 + 1 + 16 + 1 + 32 + 16 + 16 + 32 + 12 + 12 bytes.</summary>
    public const int OriginInputLength = 228;

    /// <summary>The longest a relay assertion may live (relay.proto RelayAssertion.expires_at).</summary>
    public static readonly TimeSpan AssertionLifetime = TimeSpan.FromSeconds(120);

    /// <summary>The ES256 signature length (P1363).</summary>
    public const int SignatureLength = 64;

    private static readonly BigInteger Order = BigInteger.Parse("0FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

    private static readonly BigInteger HalfOrder = Order >> 1;

    /// <summary>The routed call's signing input: the call domain string, then the exact received header bytes (never re-encoded).</summary>
    public static byte[] CallInput(ReadOnlySpan<byte> header) => Prefixed(CallDomain, header);

    /// <summary>The routed result's signing input: the result domain string, then the exact header bytes the node transmits.</summary>
    public static byte[] ResultInput(ReadOnlySpan<byte> header) => Prefixed(ResultDomain, header);

    /// <summary>
    /// The channel hello proof's signing input (Plan decision PB-4, D0-B2): the hello domain string, the center's 32-byte nonce, the 16-byte
    /// connection ID, SHA-256 of the canonical center URL the node is configured with (never a value the center sent), the node ID and the
    /// installation ID. Each field is checked for its exact length and a non-zero ID first; <see langword="null"/> refuses.
    /// </summary>
    public static byte[]? HelloInput(ReadOnlySpan<byte> nonce, Id? connectionId, CenterEndpoint center, ReadOnlySpan<byte> nodeId, ReadOnlySpan<byte> installationId)
    {
        ArgumentNullException.ThrowIfNull(center);
        if (nonce.Length != 32 || !IdBytes(connectionId, out var connection) || !ValidId(nodeId) || !ValidId(installationId))
        {
            return null;
        }

        var input = new byte[HelloInputLength];
        var writer = new FixedWriter(input);
        writer.Ascii(HelloDomain);
        writer.Bytes(nonce);
        writer.Bytes(connection);
        writer.Bytes(Audience(center));
        writer.Bytes(nodeId);
        writer.Bytes(installationId);
        writer.End();
        return input;
    }

    /// <summary>
    /// The relay assertion's signing input (Plan addendum D0-B1, C-N2): the origin domain string followed by the canonical fields of
    /// <paramref name="assertion"/> (its signature excluded) and SHA-256 of the canonical center URL. The pre-conditions of relay.proto apply
    /// first: every ID the layout names is present, 16 bytes and not all zero (an absent target or command ID is 16 zero bytes, only where
    /// the layout allows it), every digest and nonce 32 bytes, local_origin 1..3, an implemented method, nanos 0..999,999,999, and the expiry after the
    /// issue and at most 120 s after it; <see langword="null"/> refuses.
    /// </summary>
    public static byte[]? AssertionInput(RelayAssertion assertion, CenterEndpoint center)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(center);
        var method = assertion.HasMethod ? (int)assertion.Method : 0;
        var origin = assertion.HasLocalOrigin ? (int)assertion.LocalOrigin : 0;
        if ((method is < 1 or > 9) && method is not (10 or 11 or 12 or 13 or 14 or 15 or 16) && (method is < 17 or > 20) || origin is < 1 or > 3)
        {
            return null;
        }

        var listNodes = method == (int)RoutedMethod.ListNodes;
        var commanded = method is (int)RoutedMethod.SubmitNodeTask or (int)RoutedMethod.CancelNodeTask
            or (int)RoutedMethod.WriteNodeFile or (int)RoutedMethod.EditNodeFile or (int)RoutedMethod.PlanNodeRemoval or (int)RoutedMethod.ExecuteNodeRemoval
            or (int)RoutedMethod.RegisterNodeWorkspace or (int)RoutedMethod.UnregisterNodeWorkspace;
        if (!IdBytes(assertion.RelayingNodeId, out var relaying) || !IdBytes(assertion.RelayingInstallationId, out var installation)
            || !IdBytes(assertion.LocalSessionId, out var session)
            || !OptionalId(assertion.TargetNodeId, required: !listNodes, out var target)
            || !OptionalId(assertion.CommandId, required: commanded, out var command)
            || (listNodes && assertion.TargetNodeId is not null) || (!commanded && assertion.CommandId is not null)
            || !assertion.HasRequestSha256 || assertion.RequestSha256.Length != 32 || !assertion.HasRelayNonce || assertion.RelayNonce.Length != 32
            || !Instant(assertion.IssuedAt, out var issued) || !Instant(assertion.ExpiresAt, out var expires)
            || expires <= issued || expires - issued > (BigInteger)AssertionLifetime.Ticks * 100)
        {
            return null;
        }

        var input = new byte[OriginInputLength];
        var writer = new FixedWriter(input);
        writer.Ascii(OriginDomain);
        writer.Bytes(Audience(center));
        writer.Bytes(relaying);
        writer.Bytes(installation);
        writer.Byte((byte)origin);
        writer.Bytes(session);
        writer.Byte((byte)method);
        writer.Bytes(assertion.RequestSha256.Span);
        writer.Bytes(target);
        writer.Bytes(command);
        writer.Bytes(assertion.RelayNonce.Span);
        writer.Instant(assertion.IssuedAt);
        writer.Instant(assertion.ExpiresAt);
        writer.End();
        return input;
    }

    /// <summary>SHA-256 of the canonical center URL the node is configured with (the audience of the hello proof and the assertion).</summary>
    public static byte[] Audience(CenterEndpoint center)
    {
        ArgumentNullException.ThrowIfNull(center);
        return SHA256.HashData(Encoding.UTF8.GetBytes(center.Url));
    }

    /// <summary>
    /// Verifies an ES256 signature over <paramref name="input"/> with the P-256 key <paramref name="spki"/> (PKIX SubjectPublicKeyInfo DER):
    /// exactly 64 bytes, r and s in [1, n-1], low-S (a high-S signature is refused before verification, CTR5-SEC-07). Any other key, an
    /// unparsable key or a DER signature is refused.
    /// </summary>
    public static bool Verify(ReadOnlySpan<byte> spki, ReadOnlySpan<byte> input, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != SignatureLength)
        {
            return false;
        }

        var r = new BigInteger(signature[..32], isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(signature[32..], isUnsigned: true, isBigEndian: true);
        if (r.IsZero || s.IsZero || r >= Order || s > HalfOrder)
        {
            return false;
        }

        using var key = ImportP256(spki);
        return key is not null && key.VerifyData(input, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>The P-256 public key of <paramref name="spki"/>, or <see langword="null"/> (another curve, another algorithm, trailing bytes).</summary>
    public static ECDsa? ImportP256(ReadOnlySpan<byte> spki)
    {
        var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(spki, out var read);
            if (read == spki.Length && key.KeySize == 256 && key.ExportParameters(includePrivateParameters: false).Curve.Oid?.Value == "1.2.840.10045.3.1.7")
            {
                return key;
            }
        }
        catch (CryptographicException)
        {
        }

        key.Dispose();
        return null;
    }

    /// <summary>True for a valid ID value: 16 bytes, not all zero.</summary>
    public static bool ValidId(ReadOnlySpan<byte> value) => value.Length == 16 && value.IndexOfAnyExcept((byte)0) >= 0;

    private static bool IdBytes(Id? id, out ReadOnlySpan<byte> value)
    {
        value = id is { } present ? present.Value.Span : default;
        return id is not null && ValidId(value);
    }

    private static bool OptionalId(Id? id, bool required, out ReadOnlySpan<byte> value)
    {
        if (id is null)
        {
            value = new byte[16];
            return !required;
        }

        return IdBytes(id, out value);
    }

    private static bool Instant(Instant? instant, out BigInteger nanos)
    {
        nanos = default;
        if (instant is null || instant.Nanos > 999_999_999)
        {
            return false;
        }

        nanos = (BigInteger)instant.UnixSeconds * 1_000_000_000 + instant.Nanos;
        return true;
    }

    private static byte[] Prefixed(string domain, ReadOnlySpan<byte> bytes)
    {
        var input = new byte[domain.Length + bytes.Length];
        Encoding.ASCII.GetBytes(domain, input);
        bytes.CopyTo(input.AsSpan(domain.Length));
        return input;
    }

    /// <summary>Writes fixed-length fields into an exact-size buffer; <see cref="End"/> checks every byte was written.</summary>
    private ref struct FixedWriter(Span<byte> target)
    {
        private readonly Span<byte> _target = target;
        private int _at;

        public void Ascii(string value) => _at += Encoding.ASCII.GetBytes(value, _target[_at..]);

        public void Bytes(ReadOnlySpan<byte> value)
        {
            value.CopyTo(_target[_at..]);
            _at += value.Length;
        }

        public void Byte(byte value) => _target[_at++] = value;

        public void Instant(Instant value)
        {
            BinaryPrimitives.WriteInt64BigEndian(_target[_at..], value.UnixSeconds);
            BinaryPrimitives.WriteUInt32BigEndian(_target[(_at + 8)..], value.Nanos);
            _at += 12;
        }

        public readonly void End()
        {
            if (_at != _target.Length)
            {
                throw new InvalidOperationException("A relay signing input has a fixed length.");
            }
        }
    }
}

/// <summary>
/// The relay-assertion signing API of the relaying node (Plan addendum D0-B1; part N1 provides it, part N3's local proxy uses it): a
/// <see cref="RelayAssertion"/> over a center-sent relay nonce of the node's open channel, signed with the node key under the relay-origin
/// domain string. The caller's origin is the node's own classification of its local caller (HUMAN, SCRIPT or AGENT; never REMOTE).
/// </summary>
internal static class RelayAssertions
{
    /// <summary>
    /// Builds and signs the assertion; <see langword="null"/> when its fields do not have the exact layout (relay.proto pre-conditions).
    /// The expiry is the earlier of <paramref name="lifetime"/> (at most 120 s) after <paramref name="now"/> and the nonce's own expiry.
    /// </summary>
    public static RelayAssertion? Sign(INodeKey key, CenterEndpoint center, RelayAssertionFields fields, RelayNonce nonce, DateTimeOffset now, TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(nonce);
        var span = lifetime is { } asked && asked < RelaySignatures.AssertionLifetime ? asked : RelaySignatures.AssertionLifetime;
        var expires = now + span;
        if (ProtoTime.ToDateTimeOffset(nonce.ExpiresAt) is { } nonceExpires && nonceExpires < expires)
        {
            expires = nonceExpires;
        }

        if (fields.LocalOrigin is not (Origin.Human or Origin.Script or Origin.Agent))
        {
            return null;
        }

        var assertion = new RelayAssertion
        {
            RelayingNodeId = fields.RelayingNodeId,
            RelayingInstallationId = fields.RelayingInstallationId,
            LocalOrigin = fields.LocalOrigin,
            LocalSessionId = fields.LocalSessionId,
            Method = fields.Method,
            RequestSha256 = Google.Protobuf.ByteString.CopyFrom(fields.RequestSha256.Span),
            RelayNonce = nonce.Nonce,
            IssuedAt = ProtoTime.ToInstant(now),
            ExpiresAt = ProtoTime.ToInstant(expires),
        };
        if (fields.TargetNodeId is { } target)
        {
            assertion.TargetNodeId = target;
        }

        if (fields.CommandId is { } command)
        {
            assertion.CommandId = command;
        }

        if (RelaySignatures.AssertionInput(assertion, center) is not { } input)
        {
            return null;
        }

        assertion.Signature = Google.Protobuf.ByteString.CopyFrom(key.Sign(input));
        return assertion;
    }
}

/// <summary>The caller-dependent fields of a relay assertion (the relaying node fills its own IDs from its link).</summary>
internal sealed record RelayAssertionFields
{
    /// <summary>The relaying node (this node).</summary>
    public required Id RelayingNodeId { get; init; }

    /// <summary>The installation of the relaying node's credential.</summary>
    public required Id RelayingInstallationId { get; init; }

    /// <summary>The local caller's origin class.</summary>
    public required Origin LocalOrigin { get; init; }

    /// <summary>The local caller's client session at this node.</summary>
    public required Id LocalSessionId { get; init; }

    /// <summary>The routed method (existing tasks, implemented file reads/status or workspace 17..20).</summary>
    public required RoutedMethod Method { get; init; }

    /// <summary>SHA-256 of the request bytes (relay.proto RelayAssertion.request_sha256).</summary>
    public required ReadOnlyMemory<byte> RequestSha256 { get; init; }

    /// <summary>The target node; absent for LIST_NODES only.</summary>
    public Id? TargetNodeId { get; init; }

    /// <summary>The command ID of a routed mutation; absent on reads.</summary>
    public Id? CommandId { get; init; }
}
