// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ArcForges.ContentSandbox.Contracts;

/// <summary>The restricted launch profile family a launch was built for. A helper refuses a frame for another family.</summary>
internal enum ContentSandboxProfileKind : byte
{
    /// <summary>Windows AppContainer with a Job Object.</summary>
    WindowsAppContainerJob = 1,

    /// <summary>Linux Landlock, seccomp and no_new_privs.</summary>
    LinuxLandlockSeccomp = 2,

    /// <summary>
    /// Reserved and wire-stable; macOS is not a supported platform. No profile of this family exists, it is never selected, and a frame carrying
    /// it is refused by the helper with the isolation-unavailable exit on every operating system.
    /// </summary>
    MacOsAppSandboxXpc = 3,
}

/// <summary>The part an inherited OS resource plays. The helper takes only the resources named here, in this closed set.</summary>
internal enum ContentSandboxHandleRole : byte
{
    /// <summary>The stream on which the helper calls the bootstrap service of the parent (the helper is the client).</summary>
    Control = 1,

    /// <summary>The stream on which the parent calls the sandbox service of the helper (the helper is the server).</summary>
    Service = 2,

    /// <summary>The read-only mapping of the immutable input.</summary>
    Input = 3,

    /// <summary>The first output slot mapping.</summary>
    Slot0 = 4,

    /// <summary>The second output slot mapping.</summary>
    Slot1 = 5,

    /// <summary>The third output slot mapping.</summary>
    Slot2 = 6,
}

/// <summary>One inherited resource: its role and the number the OS gave it in the helper (a Windows handle value or a Unix descriptor).</summary>
/// <param name="Role">The role.</param>
/// <param name="Value">The OS value in the helper process.</param>
internal readonly record struct ContentSandboxHandleEntry(ContentSandboxHandleRole Role, ulong Value);

/// <summary>
/// The one private frame a parent writes to the inherited standard input of the helper: the closed inventory of what the helper
/// inherited, the parent-minted invocation identity, the budget and the one-use launch bootstrap resource. It is read before
/// anything else, never from the command line, the environment or a file. A helper takes no resource that is not listed.
/// </summary>
internal sealed class ContentSandboxLaunchFrame : IDisposable
{
    internal const int MaxFrameBytes = 16 * 1024;
    internal const int MaxBootstrapBytes = 4096;
    private const ushort FormatVersion = 1;
    private static readonly byte[] Magic = "ARCFCS01"u8.ToArray();

    internal ContentSandboxLaunchFrame(
        ContentSandboxProfileKind profile,
        Guid invocationId,
        Guid leaseId,
        ulong generation,
        Guid inputId,
        ulong inputLength,
        byte[] inputDigest,
        IReadOnlyList<ulong> slotCapacities,
        ContentSandboxLimits limits,
        IReadOnlyList<ContentSandboxHandleEntry> handles,
        string parserProfile,
        byte[] bootstrapResource)
    {
        Profile = profile;
        InvocationId = invocationId;
        LeaseId = leaseId;
        Generation = generation;
        InputId = inputId;
        InputLength = inputLength;
        InputDigest = inputDigest;
        SlotCapacities = slotCapacities;
        Limits = limits;
        Handles = handles;
        ParserProfile = parserProfile;
        BootstrapResource = bootstrapResource;
    }

    internal ContentSandboxProfileKind Profile { get; }

    internal Guid InvocationId { get; }

    internal Guid LeaseId { get; }

    internal ulong Generation { get; }

    internal Guid InputId { get; }

    internal ulong InputLength { get; }

    internal byte[] InputDigest { get; }

    internal IReadOnlyList<ulong> SlotCapacities { get; }

    internal ContentSandboxLimits Limits { get; }

    internal IReadOnlyList<ContentSandboxHandleEntry> Handles { get; }

    internal string ParserProfile { get; }

    /// <summary>The launch descriptor followed by the one-use secret (the LocalRpc bootstrap resource). Zeroed by <see cref="Dispose"/>.</summary>
    internal byte[] BootstrapResource { get; }

    /// <summary>True for a parser-profile identifier of 1 to 64 characters from <c>[A-Za-z0-9._-]</c>.</summary>
    internal static bool IsParserProfile(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > ContentSandboxContract.MaxParserProfileLength)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!(char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-'))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The OS value of a role, if the frame lists it.</summary>
    internal bool TryGetHandle(ContentSandboxHandleRole role, out ulong value)
    {
        foreach (var entry in Handles)
        {
            if (entry.Role == role)
            {
                value = entry.Value;
                return true;
            }
        }

        value = 0;
        return false;
    }

    /// <summary>Encodes the frame, preceded by its 4-byte big-endian length.</summary>
    internal byte[] Encode()
    {
        using var body = new MemoryStream();
        body.Write(Magic);
        WriteU16(body, FormatVersion);
        body.WriteByte((byte)Profile);
        body.WriteByte(0);
        WriteGuid(body, InvocationId);
        WriteGuid(body, LeaseId);
        WriteU64(body, Generation);
        WriteGuid(body, InputId);
        WriteU64(body, InputLength);
        body.Write(InputDigest);
        body.WriteByte((byte)SlotCapacities.Count);
        foreach (var capacity in SlotCapacities)
        {
            WriteU64(body, capacity);
        }

        WriteU64(body, Limits.MaxInputBytes);
        WriteU64(body, Limits.MaxMemoryBytes);
        WriteU64(body, Limits.MaxOutputBytes);
        WriteU32(body, Limits.MaxWidth);
        WriteU32(body, Limits.MaxHeight);
        WriteU32(body, Limits.MaxItems);
        WriteU32(body, Limits.TimeoutMs);
        body.WriteByte((byte)Handles.Count);
        foreach (var entry in Handles)
        {
            body.WriteByte((byte)entry.Role);
            WriteU64(body, entry.Value);
        }

        var profile = Encoding.ASCII.GetBytes(ParserProfile);
        WriteU16(body, (ushort)profile.Length);
        body.Write(profile);
        WriteU32(body, (uint)BootstrapResource.Length);
        body.Write(BootstrapResource);
        if (body.Length > MaxFrameBytes)
        {
            throw new InvalidOperationException("The launch frame exceeds its bound.");
        }

        var frame = new byte[4 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)body.Length);
        _ = body.TryGetBuffer(out var segment);
        segment.AsSpan().CopyTo(frame.AsSpan(4));
        return frame;
    }

    /// <summary>
    /// Reads one frame from the stream: the length prefix, then exactly that many bytes. Anything malformed, truncated, oversized,
    /// with a trailing byte or outside the profile is refused with <see cref="FormatException"/>.
    /// </summary>
    internal static async ValueTask<ContentSandboxLaunchFrame> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt32BigEndian(prefix);
        if (length is 0 or > MaxFrameBytes)
        {
            throw new FormatException("The launch frame length is outside its bound.");
        }

        var body = new byte[length];
        try
        {
            await stream.ReadExactlyAsync(body, cancellationToken).ConfigureAwait(false);
            return Decode(body);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    /// <summary>Decodes a frame body (without the length prefix).</summary>
    internal static ContentSandboxLaunchFrame Decode(ReadOnlySpan<byte> body)
    {
        var cursor = new Cursor(body);
        if (!cursor.Take(Magic.Length).SequenceEqual(Magic) || cursor.U16() != FormatVersion)
        {
            throw new FormatException("The launch frame is not this version.");
        }

        var profile = (ContentSandboxProfileKind)cursor.U8();
        if (!Enum.IsDefined(profile) || cursor.U8() != 0)
        {
            throw new FormatException("The launch frame names no known profile.");
        }

        var invocation = cursor.Guid();
        var lease = cursor.Guid();
        var generation = cursor.U64();
        var inputId = cursor.Guid();
        var inputLength = cursor.U64();
        var digest = cursor.Take(32).ToArray();
        var slotCount = cursor.U8();
        if (slotCount is 0 or > ContentSandboxContract.MaxSlots)
        {
            throw new FormatException("The launch frame names an unsupported number of slots.");
        }

        var capacities = new ulong[slotCount];
        for (var index = 0; index < slotCount; index++)
        {
            capacities[index] = cursor.U64();
            if (capacities[index] is 0 || capacities[index] > (ulong)ContentSandboxContract.MaxSlotBytes)
            {
                throw new FormatException("A slot capacity is outside its bound.");
            }
        }

        var limits = new ContentSandboxLimits
        {
            MaxInputBytes = cursor.U64(),
            MaxMemoryBytes = cursor.U64(),
            MaxOutputBytes = cursor.U64(),
            MaxWidth = cursor.U32(),
            MaxHeight = cursor.U32(),
            MaxItems = cursor.U32(),
            TimeoutMs = cursor.U32(),
        };
        var handleCount = cursor.U8();
        if (handleCount != 3 + slotCount)
        {
            throw new FormatException("The launch frame inventory is not the closed set.");
        }

        var handles = new ContentSandboxHandleEntry[handleCount];
        var seen = new HashSet<ContentSandboxHandleRole>();
        for (var index = 0; index < handleCount; index++)
        {
            var role = (ContentSandboxHandleRole)cursor.U8();
            var value = cursor.U64();
            if (!Enum.IsDefined(role) || !seen.Add(role) || value == 0)
            {
                throw new FormatException("The launch frame inventory repeats or invents a resource.");
            }

            handles[index] = new ContentSandboxHandleEntry(role, value);
        }

        foreach (var required in new[] { ContentSandboxHandleRole.Control, ContentSandboxHandleRole.Service, ContentSandboxHandleRole.Input })
        {
            if (!seen.Contains(required))
            {
                throw new FormatException("The launch frame inventory lacks a required resource.");
            }
        }

        for (var index = 0; index < slotCount; index++)
        {
            if (!seen.Contains((ContentSandboxHandleRole)((int)ContentSandboxHandleRole.Slot0 + index)))
            {
                throw new FormatException("The launch frame inventory lacks a slot.");
            }
        }

        var profileLength = cursor.U16();
        var parserProfile = Encoding.ASCII.GetString(cursor.Take(profileLength));
        var bootstrapLength = cursor.U32();
        if (bootstrapLength is 0 or > MaxBootstrapBytes)
        {
            throw new FormatException("The bootstrap resource is outside its bound.");
        }

        var bootstrap = cursor.Take((int)bootstrapLength).ToArray();
        if (!cursor.AtEnd)
        {
            CryptographicOperations.ZeroMemory(bootstrap);
            throw new FormatException("The launch frame has trailing bytes.");
        }

        if (invocation == Guid.Empty || lease == Guid.Empty || inputId == Guid.Empty || generation == 0
            || inputLength is 0 || inputLength > limits.MaxInputBytes || !limits.IsWithinProfile() || !IsParserProfile(parserProfile))
        {
            CryptographicOperations.ZeroMemory(bootstrap);
            throw new FormatException("The launch frame carries a value outside the profile.");
        }

        return new ContentSandboxLaunchFrame(profile, invocation, lease, generation, inputId, inputLength, digest, capacities, limits, handles, parserProfile, bootstrap);
    }

    /// <summary>Zeroes the bootstrap resource (which holds the one-use secret).</summary>
    public void Dispose() => CryptographicOperations.ZeroMemory(BootstrapResource);

    private static void WriteU16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteU32(Stream stream, uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteU64(Stream stream, ulong value)
    {
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void WriteGuid(Stream stream, Guid value)
    {
        Span<byte> bytes = stackalloc byte[16];
        _ = value.TryWriteBytes(bytes, bigEndian: true, out _);
        stream.Write(bytes);
    }

    private ref struct Cursor(ReadOnlySpan<byte> buffer)
    {
        private readonly ReadOnlySpan<byte> _buffer = buffer;
        private int _position;

        internal readonly bool AtEnd => _position == _buffer.Length;

        internal ReadOnlySpan<byte> Take(int count)
        {
            if (count < 0 || count > _buffer.Length - _position)
            {
                throw new FormatException("The launch frame is truncated.");
            }

            var slice = _buffer.Slice(_position, count);
            _position += count;
            return slice;
        }

        internal byte U8() => Take(1)[0];

        internal ushort U16() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));

        internal uint U32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));

        internal ulong U64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8));

        internal Guid Guid() => new(Take(16), bigEndian: true);
    }
}
