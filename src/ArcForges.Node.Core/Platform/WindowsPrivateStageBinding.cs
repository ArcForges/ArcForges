// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Platform;

/// <summary>One FULL-reserved private producer; its metadata alone grants no filesystem authority.</summary>
[SupportedOSPlatform("windows")]
internal sealed record WindowsPrivateStageBinding(byte[] CommandId, byte[] ProducerNonce, byte[] WorkerNonce,
    byte[] RequestSha256, byte[] CallerDigest, byte[] WorkspaceId, byte[] CorrelationId, int Slot,
    byte[] RootIdentity, byte[] ParentIdentity, string Name, long Size, byte[] Sha256, long Deadline, long ExpiryMicroseconds,
    WindowsOwnedStageIdentity WorkerIdentity)
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal void Validate()
    {
        StoreIds.Validate(CommandId, nameof(CommandId));
        StoreIds.Validate(WorkspaceId, nameof(WorkspaceId));
        StoreIds.Validate(CorrelationId, nameof(CorrelationId));
        if (ProducerNonce.Length != 16 || WorkerNonce.Length != 16 || RequestSha256.Length != 32 ||
            CallerDigest.Length != 32 || Slot is not (1 or 2) || RootIdentity.Length != 33 || ParentIdentity.Length != 33 ||
            Name != ".arcforges-stage-" + Convert.ToHexStringLower(CommandId) + "-" +
                Slot.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
            Size is < 0 or > 4_194_304 || Sha256.Length != 32 || Deadline <= 0 || ExpiryMicroseconds <= 0)
            throw new InvalidDataException("The Windows private producer binding is invalid.");
        if (WorkerIdentity.ProcessId <= 0 || WorkerIdentity.CreationTime <= 0 ||
            !WorkerIdentity.BootIdentity.StartsWith("windows:", StringComparison.Ordinal) || Utf8.GetByteCount(WorkerIdentity.BootIdentity) > 512)
            throw new InvalidDataException("The Windows producer generation is invalid.");
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(1, RootIdentity);
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(1, ParentIdentity);
    }

    internal void Write(BinaryWriter writer)
    {
        Validate();
        writer.Write((byte)1);
        writer.Write(CommandId);
        writer.Write(ProducerNonce);
        writer.Write(WorkerNonce);
        writer.Write(RequestSha256);
        writer.Write(CallerDigest);
        writer.Write(WorkspaceId);
        writer.Write(CorrelationId);
        writer.Write(checked((byte)Slot));
        writer.Write(RootIdentity);
        writer.Write(ParentIdentity);
        var name = Utf8.GetBytes(Name);
        writer.Write(checked((ushort)name.Length));
        writer.Write(name);
        writer.Write(Size);
        writer.Write(Sha256);
        writer.Write(Deadline);
        writer.Write(ExpiryMicroseconds);
        var boot = Utf8.GetBytes(WorkerIdentity.BootIdentity);
        writer.Write(checked((ushort)boot.Length));
        writer.Write(boot);
        writer.Write(WorkerIdentity.ProcessId);
        writer.Write(WorkerIdentity.CreationTime);
        writer.Flush();
    }

    internal byte[] Digest()
    {
        using var memory = new MemoryStream();
        memory.Write("ArcForges Windows private producer v1\0"u8);
        using var writer = new BinaryWriter(memory, Utf8, leaveOpen: true);
        Write(writer);
        return SHA256.HashData(memory.GetBuffer().AsSpan(0, checked((int)memory.Length)));
    }

    internal static WindowsPrivateStageBinding Read(BinaryReader reader)
    {
        if (reader.ReadByte() != 1) throw new InvalidDataException("Unknown Windows private producer protocol.");
        var command = ReadExactly(reader, 16);
        var producer = ReadExactly(reader, 16);
        var worker = ReadExactly(reader, 16);
        var request = ReadExactly(reader, 32);
        var caller = ReadExactly(reader, 32);
        var workspace = ReadExactly(reader, 16);
        var correlation = ReadExactly(reader, 16);
        var slot = reader.ReadByte();
        var root = ReadExactly(reader, 33);
        var parent = ReadExactly(reader, 33);
        var length = reader.ReadUInt16();
        if (length is < 1 or > 255) throw new InvalidDataException("Invalid Windows private producer name.");
        var name = Utf8.GetString(ReadExactly(reader, length));
        var size = reader.ReadInt64();
        var hash = ReadExactly(reader, 32);
        var deadline = reader.ReadInt64();
        var expiry = reader.ReadInt64();
        var bootLength = reader.ReadUInt16();
        if (bootLength is < 1 or > 512) throw new InvalidDataException("Invalid Windows producer boot identity.");
        var boot = Utf8.GetString(ReadExactly(reader, bootLength));
        var generation = new WindowsOwnedStageIdentity(boot, reader.ReadInt32(), reader.ReadInt64());
        var result = new WindowsPrivateStageBinding(command, producer, worker, request, caller, workspace, correlation,
            slot, root, parent, name, size, hash, deadline, expiry, generation);
        result.Validate();
        return result;
    }

    private static byte[] ReadExactly(BinaryReader reader, int count)
    {
        var bytes = reader.ReadBytes(count);
        return bytes.Length == count ? bytes : throw new EndOfStreamException("The Windows private producer binding ended early.");
    }
}
