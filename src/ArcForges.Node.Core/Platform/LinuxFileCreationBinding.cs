// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using Google.Protobuf;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// One prepared expected-absent Linux creation. This private worker payload is not caller authority; its owner must
/// first FULL-bind the exact journal, caller, workspace, stage, live child and original execution/expiry bounds.
/// It has no invented existing target or preimage and contains no file body.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed record LinuxFileCreationBinding(
    byte[] CommandId, byte[] RequestDigest, byte[] CallerDigest, byte[] WorkspaceId, byte[] CorrelationId,
    byte[] RootIdentity, byte[] ParentIdentity, byte[] IntendedStageIdentity, string Name, bool DurableStage,
    long IntendedSize, byte[] IntendedSha256, long Deadline, long ExpiryMicroseconds)
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static LinuxFileCreationBinding FromPrepared(FileJournalIntent intent, ReadOnlySpan<byte> transmitted,
        long deadline, long expiryMicroseconds)
    {
        FileMutationJournal.ValidateIntent(intent, transmitted);
        return FromIntent(intent, SHA256.HashData(transmitted), durableStage: false, deadline, expiryMicroseconds);
    }

    /// <summary>
    /// An approved command retains its exact transmitted digest, not its old content-bearing request. The FULL
    /// coordinator must independently read and bind the current APPROVED record; no request is reserialized here.
    /// </summary>
    internal static LinuxFileCreationBinding FromApproved(PrivateStageApprovedPlan plan, long deadline,
        long expiryMicroseconds)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (!plan.Active) throw new InvalidOperationException("The approved stage reservation is inactive.");
        return FromIntent(plan.Intent, plan.RequestSha256, durableStage: true, deadline, expiryMicroseconds);
    }

    private static LinuxFileCreationBinding FromIntent(FileJournalIntent intent, ReadOnlySpan<byte> requestDigest,
        bool durableStage, long deadline, long expiryMicroseconds)
    {
        ArgumentNullException.ThrowIfNull(intent);
        if (intent.Kind != FileOperationKind.Write || intent.IdentityPlatform != 2 ||
            intent.TargetIdentity is not null || intent.OriginalSize is not null || intent.OriginalSha256 is not null ||
            intent.OriginalStageIdentity is not null)
            throw new InvalidOperationException("Only a prepared expected-absent Linux write can use this worker.");
        var remaining = deadline - LinuxFatalDeadline.MonotonicNanoseconds();
        if (remaining is <= 0 or > 10_000_000_000)
            throw new InvalidOperationException("The original monotonic deadline is unavailable.");
        var names = WorkspacePath.Components(intent.RelativePath);
        var result = new LinuxFileCreationBinding(intent.CommandId.ToArray(), requestDigest.ToArray(),
            SHA256.HashData(FileMutationJournal.Sanitize(intent.Caller).ToByteArray()), intent.WorkspaceId.ToArray(),
            intent.CorrelationId.ToArray(), intent.RootIdentity.ToArray(), intent.ParentIdentity.ToArray(),
            intent.IntendedStageIdentity.ToArray(), names[^1], durableStage, intent.IntendedSize,
            intent.IntendedSha256.ToArray(), deadline, expiryMicroseconds);
        result.Validate();
        return result;
    }

    internal void Write(BinaryWriter writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        Validate();
        var name = Utf8.GetBytes(Name);
        writer.Write((byte)1);
        writer.Write(CommandId);
        writer.Write(RequestDigest);
        writer.Write(CallerDigest);
        writer.Write(WorkspaceId);
        writer.Write(CorrelationId);
        writer.Write(RootIdentity);
        writer.Write(ParentIdentity);
        writer.Write(IntendedStageIdentity);
        writer.Write(DurableStage ? (byte)1 : (byte)0);
        writer.Write(checked((ushort)name.Length));
        writer.Write(name);
        writer.Write(IntendedSize);
        writer.Write(IntendedSha256);
        writer.Write(Deadline);
        writer.Write(ExpiryMicroseconds);
        writer.Flush();
    }

    internal static LinuxFileCreationBinding Read(BinaryReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if (reader.ReadByte() != 1) throw new InvalidDataException("Unsupported creation binding.");
        var command = ReadExactly(reader, 16);
        var request = ReadExactly(reader, 32);
        var caller = ReadExactly(reader, 32);
        var workspace = ReadExactly(reader, 16);
        var correlation = ReadExactly(reader, 16);
        var root = ReadExactly(reader, 53);
        var parent = ReadExactly(reader, 53);
        var stage = ReadExactly(reader, 53);
        var durable = reader.ReadByte();
        if (durable > 1) throw new InvalidDataException("Invalid creation stage kind.");
        var length = reader.ReadUInt16();
        if (length is < 1 or > 4096) throw new InvalidDataException("Invalid creation name length.");
        var name = Utf8.GetString(ReadExactly(reader, length));
        var result = new LinuxFileCreationBinding(command, request, caller, workspace, correlation, root, parent, stage,
            name, durable != 0, reader.ReadInt64(), ReadExactly(reader, 32), reader.ReadInt64(), reader.ReadInt64());
        result.Validate();
        return result;
    }

    private void Validate()
    {
        if (CommandId.Length != 16 || CommandId.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            WorkspaceId.Length != 16 || WorkspaceId.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
            CorrelationId.Length != 16 || RequestDigest.Length != 32 || CallerDigest.Length != 32 ||
            RootIdentity.Length != 53 || ParentIdentity.Length != 53 || IntendedStageIdentity.Length != 53 ||
            RootIdentity[0] != 1 || ParentIdentity[0] != 1 || IntendedStageIdentity[0] != 1 ||
            IntendedSize is < 0 or > 196_608 || IntendedSha256.Length != 32 || Deadline <= 0 ||
            ExpiryMicroseconds <= 0 || Utf8.GetByteCount(Name) is < 1 or > 4096 ||
            WorkspacePath.Components(Name).Length != 1)
            throw new InvalidDataException("Invalid creation binding.");
    }

    private static byte[] ReadExactly(BinaryReader reader, int length)
    {
        var bytes = reader.ReadBytes(length);
        return bytes.Length == length ? bytes : throw new EndOfStreamException("The creation binding ended early.");
    }
}
