// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Text;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// One private named stage production, not a target operation. The coordinator must FULL-bind the exact producer,
// empty-object reservation and challenge-sealed child before sending descriptors or granting the first private effect.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed record LinuxPrivateStageBinding(byte[] CommandId, byte[] ProducerNonce, byte[] WorkerNonce,
    byte[] RequestSha256, byte[] CallerDigest, byte[] WorkspaceId, byte[] CorrelationId, int Slot,
    byte[] RootIdentity, byte[] ParentIdentity, string Name, long Size, byte[] Sha256, long Deadline, long ExpiryMicroseconds)
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

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
        writer.Flush();
    }

    internal static LinuxPrivateStageBinding Read(BinaryReader reader)
    {
        if (reader.ReadByte() != 1) throw new InvalidDataException("Unknown private stage protocol.");
        var command = ReadExactly(reader, 16);
        var producer = ReadExactly(reader, 16);
        var worker = ReadExactly(reader, 16);
        var request = ReadExactly(reader, 32);
        var caller = ReadExactly(reader, 32);
        var workspace = ReadExactly(reader, 16);
        var correlation = ReadExactly(reader, 16);
        var slot = reader.ReadByte();
        var root = ReadExactly(reader, 53);
        var parent = ReadExactly(reader, 53);
        var length = reader.ReadUInt16();
        if (length is < 1 or > 255) throw new InvalidDataException("Invalid private stage name.");
        var name = Utf8.GetString(ReadExactly(reader, length));
        var result = new LinuxPrivateStageBinding(command, producer, worker, request, caller, workspace, correlation,
            slot, root, parent, name, reader.ReadInt64(), ReadExactly(reader, 32), reader.ReadInt64(), reader.ReadInt64());
        result.Validate();
        return result;
    }

    internal void Validate()
    {
        if (CommandId.Length != 16 || CommandId.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            ProducerNonce.Length != 16 || WorkerNonce.Length != 16 || RequestSha256.Length != 32 ||
            CallerDigest.Length != 32 || WorkspaceId.Length != 16 || CorrelationId.Length != 16 || Slot is not (1 or 2) ||
            RootIdentity.Length != 53 || ParentIdentity.Length != 53 || RootIdentity[0] != 1 || ParentIdentity[0] != 1 ||
            Name != ".arcforges-stage-" + Convert.ToHexStringLower(CommandId) + "-" + Slot.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
            Size is < 0 or > 4_194_304 || Sha256.Length != 32 || Deadline <= 0 || ExpiryMicroseconds <= 0)
            throw new InvalidDataException("The private stage binding is invalid.");
    }

    private static byte[] ReadExactly(BinaryReader reader, int count)
    {
        var result = reader.ReadBytes(count);
        return result.Length == count ? result : throw new EndOfStreamException("The private stage binding ended early.");
    }
}
