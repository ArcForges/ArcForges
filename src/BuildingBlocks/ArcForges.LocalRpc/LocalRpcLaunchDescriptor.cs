// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.LocalRpc;

/// <summary>Why a launch claim or connection was not authorized. <see cref="None"/> is the only accepting value.</summary>
public enum LocalRpcLaunchRefusal
{
    /// <summary>Authorized.</summary>
    None = 0,

    /// <summary>The parent has never launched this slot.</summary>
    UnknownSlot,

    /// <summary>A newer launch of the slot exists; the older descriptor never authorizes again.</summary>
    StaleEpoch,

    /// <summary>The claim names a launch or an epoch this parent never issued.</summary>
    UnknownLaunch,

    /// <summary>The launch was revoked, superseded or disposed.</summary>
    Revoked,

    /// <summary>The bootstrap window passed before the child bootstrapped.</summary>
    Expired,

    /// <summary>The descriptor was issued by another process, or its issuing process is not running.</summary>
    ParentMismatch,

    /// <summary>The presented nonce is not this launch's nonce.</summary>
    NonceMismatch,

    /// <summary>The presented child kind, build id or build digest differs from the launch.</summary>
    BuildMismatch,

    /// <summary>The presented protocol version or contract-set digest differs from the launch.</summary>
    ProtocolMismatch,

    /// <summary>A bound child process is no longer running.</summary>
    ChildGone,
}

/// <summary>
/// What the parent fixes about the child it launches: which kind, which build, which protocol. The same value is
/// expected from the child; a claim whose identity differs is refused.
/// </summary>
public sealed class LocalRpcLaunchIdentity
{
    /// <summary>Length of a SHA-256 digest.</summary>
    public const int DigestLength = 32;

    /// <summary>Longest build id or slot name.</summary>
    public const int MaximumTokenLength = 64;

    /// <summary>Creates a launch identity. Digests are copied.</summary>
    public LocalRpcLaunchIdentity(
        LocalRpcChildKind childKind,
        string buildId,
        ReadOnlySpan<byte> buildDigest,
        uint protocolVersion,
        ReadOnlySpan<byte> contractSetDigest)
    {
        if (!Enum.IsDefined(childKind) || childKind == LocalRpcChildKind.None)
        {
            throw new ArgumentOutOfRangeException(nameof(childKind), "A launch names one child kind.");
        }

        if (protocolVersion == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(protocolVersion), "A protocol version is at least 1.");
        }

        if (buildDigest.Length != DigestLength || contractSetDigest.Length != DigestLength)
        {
            throw new ArgumentException("Digests are 32 bytes (SHA-256).");
        }

        ChildKind = childKind;
        BuildId = LaunchTokens.Validate(buildId, nameof(buildId));
        BuildDigest = buildDigest.ToArray();
        ProtocolVersion = protocolVersion;
        ContractSetDigest = contractSetDigest.ToArray();
    }

    /// <summary>The kind of child.</summary>
    public LocalRpcChildKind ChildKind { get; }

    /// <summary>The build identifier the child must present.</summary>
    public string BuildId { get; }

    /// <summary>The SHA-256 build digest the child must present.</summary>
    public ReadOnlyMemory<byte> BuildDigest { get; }

    /// <summary>The private protocol version.</summary>
    public uint ProtocolVersion { get; }

    /// <summary>The SHA-256 digest of the generated contract set the child was built against.</summary>
    public ReadOnlyMemory<byte> ContractSetDigest { get; }

    internal bool SameBuild(LocalRpcLaunchIdentity other) =>
        ChildKind == other.ChildKind
        && string.Equals(BuildId, other.BuildId, StringComparison.Ordinal)
        && CryptographicOperations.FixedTimeEquals(BuildDigest.Span, other.BuildDigest.Span);

    internal bool SameProtocol(LocalRpcLaunchIdentity other) =>
        ProtocolVersion == other.ProtocolVersion
        && CryptographicOperations.FixedTimeEquals(ContractSetDigest.Span, other.ContractSetDigest.Span);
}

/// <summary>What a child presents to prove which launch it was started for. A claim authorizes nothing by itself.</summary>
public sealed class LocalRpcLaunchClaim
{
    /// <summary>Creates a claim. The nonce is copied.</summary>
    public LocalRpcLaunchClaim(
        Guid launchId,
        string slot,
        ulong epoch,
        ReadOnlySpan<byte> nonce,
        LocalRpcLaunchIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (nonce.Length != LocalRpcLaunchDescriptor.NonceLength)
        {
            throw new ArgumentException("A launch nonce is 32 bytes.", nameof(nonce));
        }

        LaunchId = launchId;
        Slot = LaunchTokens.Validate(slot, nameof(slot));
        Epoch = epoch;
        Nonce = nonce.ToArray();
        Identity = identity;
    }

    /// <summary>The launch the child believes it belongs to.</summary>
    public Guid LaunchId { get; }

    /// <summary>The launch slot.</summary>
    public string Slot { get; }

    /// <summary>The launch epoch.</summary>
    public ulong Epoch { get; }

    /// <summary>The launch nonce.</summary>
    public ReadOnlyMemory<byte> Nonce { get; }

    /// <summary>The child kind, build and protocol the child reports.</summary>
    public LocalRpcLaunchIdentity Identity { get; }
}

/// <summary>
/// The parent's immutable record of one launch: endpoint, parent process, child kind/build/protocol, a random nonce
/// and the launch epoch. It carries no secret. The parent hands it to the child inside a private bootstrap resource
/// (never argv, environment or a file) and checks every claim made from it against its own copy.
/// </summary>
public sealed class LocalRpcLaunchDescriptor
{
    /// <summary>Length of the launch nonce.</summary>
    public const int NonceLength = 32;

    /// <summary>Length of the one-use launch secret that follows the descriptor in a bootstrap resource.</summary>
    public const int SecretLength = 32;

    internal const ushort FormatVersion = 1;
    private static readonly byte[] Magic = "AFLD"u8.ToArray();

    internal LocalRpcLaunchDescriptor(
        Guid launchId,
        string slot,
        ulong epoch,
        LocalRpcEndpoint? endpoint,
        LocalRpcProcessIdentity parent,
        LocalRpcLaunchIdentity identity,
        ReadOnlySpan<byte> nonce,
        DateTimeOffset issuedAtUtc,
        DateTimeOffset bootstrapDeadlineUtc)
    {
        if (launchId == Guid.Empty || epoch == 0 || parent.ProcessId <= 0 || nonce.Length != NonceLength
            || bootstrapDeadlineUtc <= issuedAtUtc)
        {
            throw new ArgumentException("A launch descriptor has an id, an epoch of at least 1, a parent process, a 32-byte nonce and a deadline after its issue time.");
        }

        LaunchId = launchId;
        Slot = LaunchTokens.Validate(slot, nameof(slot));
        Epoch = epoch;
        Endpoint = endpoint;
        Parent = parent;
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        Nonce = nonce.ToArray();
        IssuedAtUtc = issuedAtUtc.ToUniversalTime();
        BootstrapDeadlineUtc = bootstrapDeadlineUtc.ToUniversalTime();
    }

    /// <summary>The unique id of this launch.</summary>
    public Guid LaunchId { get; }

    /// <summary>The launch slot: one logical child whose relaunches have increasing epochs.</summary>
    public string Slot { get; }

    /// <summary>The launch epoch within the slot, from 1; a newer epoch makes every older descriptor stale.</summary>
    public ulong Epoch { get; }

    /// <summary>The private endpoint the child connects to, or null when the launcher supplies already-connected streams.</summary>
    public LocalRpcEndpoint? Endpoint { get; }

    /// <summary>The parent process that issued the launch.</summary>
    public LocalRpcProcessIdentity Parent { get; }

    /// <summary>The child kind, build and protocol the parent expects.</summary>
    public LocalRpcLaunchIdentity Identity { get; }

    /// <summary>The random launch nonce.</summary>
    public ReadOnlyMemory<byte> Nonce { get; }

    /// <summary>When the parent issued the launch.</summary>
    public DateTimeOffset IssuedAtUtc { get; }

    /// <summary>The time after which an unbootstrapped launch no longer authorizes anything.</summary>
    public DateTimeOffset BootstrapDeadlineUtc { get; }

    /// <summary>The claim a child makes from this descriptor.</summary>
    public LocalRpcLaunchClaim ToClaim() => new(LaunchId, Slot, Epoch, Nonce.Span, Identity);

    /// <summary>Encodes the descriptor in its canonical, versioned binary form.</summary>
    public byte[] Encode()
    {
        var slot = Encoding.ASCII.GetBytes(Slot);
        var build = Encoding.ASCII.GetBytes(Identity.BuildId);
        var address = Endpoint is null ? [] : Encoding.UTF8.GetBytes(Endpoint.Address);
        var buffer = new byte[Magic.Length + 2 + 16 + 8 + 4 + 8 + 8 + 8 + 1 + 4 + 1 + slot.Length + 1 + build.Length
            + (2 * LocalRpcLaunchIdentity.DigestLength) + NonceLength + 1 + 2 + address.Length];
        var writer = Cursor.ForWrite(buffer);
        writer.Write(Magic);
        writer.WriteU16(FormatVersion);
        writer.Write(LaunchId.ToByteArray(bigEndian: true));
        writer.WriteU64(Epoch);
        writer.WriteU32(unchecked((uint)Parent.ProcessId));
        writer.WriteU64(unchecked((ulong)Parent.StartTimeUtcTicks));
        writer.WriteU64(unchecked((ulong)IssuedAtUtc.UtcTicks));
        writer.WriteU64(unchecked((ulong)BootstrapDeadlineUtc.UtcTicks));
        writer.WriteU8((byte)Identity.ChildKind);
        writer.WriteU32(Identity.ProtocolVersion);
        writer.WriteU8((byte)slot.Length);
        writer.Write(slot);
        writer.WriteU8((byte)build.Length);
        writer.Write(build);
        writer.Write(Identity.BuildDigest.Span);
        writer.Write(Identity.ContractSetDigest.Span);
        writer.Write(Nonce.Span);
        writer.WriteU8(Endpoint is null ? (byte)LocalRpcTransport.None : (byte)Endpoint.Transport);
        writer.WriteU16(checked((ushort)address.Length));
        writer.Write(address);
        return buffer;
    }

    /// <summary>Decodes a descriptor. Anything but the exact canonical form is refused.</summary>
    public static LocalRpcLaunchDescriptor Decode(ReadOnlySpan<byte> encoded)
    {
        var descriptor = Parse(encoded, out var consumed);
        if (consumed != encoded.Length)
        {
            throw new FormatException("A launch descriptor has trailing bytes.");
        }

        return descriptor;
    }

    /// <summary>
    /// Decodes a bootstrap resource: the descriptor followed by exactly the 32-byte one-use launch secret, which is
    /// copied to <paramref name="secret"/>.
    /// </summary>
    public static LocalRpcLaunchDescriptor DecodeBootstrapResource(ReadOnlySpan<byte> resource, Span<byte> secret)
    {
        if (secret.Length != SecretLength)
        {
            throw new ArgumentException("The secret destination is 32 bytes.", nameof(secret));
        }

        var descriptor = Parse(resource, out var consumed);
        if (resource.Length - consumed != SecretLength)
        {
            throw new FormatException("A bootstrap resource is a descriptor followed by exactly a 32-byte secret.");
        }

        resource[consumed..].CopyTo(secret);
        return descriptor;
    }

    private static LocalRpcLaunchDescriptor Parse(ReadOnlySpan<byte> encoded, out int consumed)
    {
        try
        {
            var reader = Cursor.ForRead(encoded);
            if (!reader.Read(Magic.Length).SequenceEqual(Magic) || reader.ReadU16() != FormatVersion)
            {
                throw new FormatException("Not a version 1 launch descriptor.");
            }

            var launchId = new Guid(reader.Read(16), bigEndian: true);
            var epoch = reader.ReadU64();
            var parent = new LocalRpcProcessIdentity(unchecked((int)reader.ReadU32()), unchecked((long)reader.ReadU64()));
            var issued = FromTicks(reader.ReadU64());
            var deadline = FromTicks(reader.ReadU64());
            var kind = (LocalRpcChildKind)reader.ReadU8();
            var protocol = reader.ReadU32();
            var slot = Encoding.ASCII.GetString(reader.Read(reader.ReadU8()));
            var build = Encoding.ASCII.GetString(reader.Read(reader.ReadU8()));
            var buildDigest = reader.Read(LocalRpcLaunchIdentity.DigestLength);
            var contractDigest = reader.Read(LocalRpcLaunchIdentity.DigestLength);
            var nonce = reader.Read(NonceLength);
            var transport = (LocalRpcTransport)reader.ReadU8();
            var address = Encoding.UTF8.GetString(reader.Read(reader.ReadU16()));
            var endpoint = transport == LocalRpcTransport.None
                ? (address.Length == 0 ? null : throw new FormatException("A descriptor without an endpoint has no address."))
                : LocalRpcEndpoint.CreateForVerification(transport, address);
            consumed = reader.Position;
            return new LocalRpcLaunchDescriptor(
                launchId, slot, epoch, endpoint, parent,
                new LocalRpcLaunchIdentity(kind, build, buildDigest, protocol, contractDigest), nonce, issued, deadline);
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException or EncoderFallbackException or DecoderFallbackException)
        {
            // Every malformed value is one error type for callers parsing a resource they were handed.
            throw new FormatException("The launch descriptor is malformed.", exception);
        }
    }

    private static DateTimeOffset FromTicks(ulong ticks)
    {
        if (ticks > (ulong)DateTime.MaxValue.Ticks)
        {
            throw new FormatException("A time is out of range.");
        }

        return new DateTimeOffset((long)ticks, TimeSpan.Zero);
    }

    private ref struct Cursor
    {
        private readonly Span<byte> _writable;
        private readonly ReadOnlySpan<byte> _readable;
        private int _position;

        private Cursor(Span<byte> writable, ReadOnlySpan<byte> readable)
        {
            _writable = writable;
            _readable = readable;
            _position = 0;
        }

        internal static Cursor ForWrite(byte[] buffer) => new(buffer, buffer);

        internal static Cursor ForRead(ReadOnlySpan<byte> buffer) => new(default, buffer);

        internal readonly int Position => _position;

        internal void Write(ReadOnlySpan<byte> value)
        {
            value.CopyTo(_writable[_position..]);
            _position += value.Length;
        }

        internal void WriteU8(byte value) => _writable[_position++] = value;

        internal void WriteU16(ushort value)
        {
            BinaryPrimitives.WriteUInt16BigEndian(_writable[_position..], value);
            _position += 2;
        }

        internal void WriteU32(uint value)
        {
            BinaryPrimitives.WriteUInt32BigEndian(_writable[_position..], value);
            _position += 4;
        }

        internal void WriteU64(ulong value)
        {
            BinaryPrimitives.WriteUInt64BigEndian(_writable[_position..], value);
            _position += 8;
        }

        internal ReadOnlySpan<byte> Read(int count)
        {
            if (count < 0 || _readable.Length - _position < count)
            {
                throw new FormatException("The launch descriptor is truncated.");
            }

            var slice = _readable.Slice(_position, count);
            _position += count;
            return slice;
        }

        internal byte ReadU8() => Read(1)[0];

        internal ushort ReadU16() => BinaryPrimitives.ReadUInt16BigEndian(Read(2));

        internal uint ReadU32() => BinaryPrimitives.ReadUInt32BigEndian(Read(4));

        internal ulong ReadU64() => BinaryPrimitives.ReadUInt64BigEndian(Read(8));
    }
}

internal static class LaunchTokens
{
    /// <summary>A slot or build id: 1-64 ASCII letters, digits, '.', '_', '-', '+', starting with a letter or digit.</summary>
    internal static string Validate(string value, string parameter)
    {
        ArgumentNullException.ThrowIfNull(value, parameter);
        if (value.Length is 0 or > LocalRpcLaunchIdentity.MaximumTokenLength || !IsAlphanumeric(value[0]))
        {
            throw new ArgumentException("A slot or build id is 1-64 characters and starts with a letter or digit.", parameter);
        }

        foreach (var character in value)
        {
            if (!IsAlphanumeric(character) && character is not ('.' or '_' or '-' or '+'))
            {
                throw new ArgumentException("A slot or build id is ASCII letters, digits, '.', '_', '-' or '+'.", parameter);
            }
        }

        return value;
    }

    private static bool IsAlphanumeric(char character) =>
        character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9';
}
