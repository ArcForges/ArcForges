// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using Google.Protobuf;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// Bounded, content-free description of a single journaled Linux effect. This is sent only over the authenticated
/// parent/child channel after FULL registration. It is not a caller-provided command or authority by itself.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed record LinuxFileEffectBinding(
    FileOperationKind Kind, byte[] CommandId, byte[] RequestDigest, byte[] CallerDigest,
    byte[] RootIdentity, byte[] ParentIdentity, byte[] TargetIdentity, byte[] OriginalStageIdentity,
    byte[] IntendedStageIdentity, long OriginalSize, byte[] OriginalSha256, long IntendedSize,
    byte[] IntendedSha256, long Deadline, long ExpiryMicroseconds, bool DurableStages = false)
{
    internal static LinuxFileEffectBinding FromPrepared(FileJournalIntent intent, ReadOnlySpan<byte> raw, long deadline, long expiryMicroseconds)
    {
        FileMutationJournal.ValidateIntent(intent, raw);
        return FromIntent(intent, SHA256.HashData(raw), deadline, expiryMicroseconds, durableStages: false);
    }

    internal static LinuxFileEffectBinding FromApproved(PrivateStageApprovedPlan plan, long deadline, long expiryMicroseconds)
    {
        if (!plan.Active) throw new InvalidOperationException("The approved stage reservation is inactive.");
        return FromIntent(plan.Intent, plan.RequestSha256, deadline, expiryMicroseconds, durableStages: true);
    }

    private static LinuxFileEffectBinding FromIntent(FileJournalIntent intent, byte[] requestDigest, long deadline,
        long expiryMicroseconds, bool durableStages)
    {
        if (intent.IdentityPlatform != 2 || intent.TargetIdentity is null || intent.OriginalStageIdentity is null ||
            intent.OriginalSize is null || intent.OriginalSha256 is null)
            throw new InvalidOperationException("Only a prepared existing Linux target can use this worker.");
        var remaining = deadline - LinuxFatalDeadline.MonotonicNanoseconds();
        if (remaining is <= 0 or > 10_000_000_000)
            throw new InvalidOperationException("The original monotonic deadline is unavailable.");
        return new LinuxFileEffectBinding(intent.Kind, intent.CommandId.ToArray(), requestDigest.ToArray(),
            SHA256.HashData(FileMutationJournal.Sanitize(intent.Caller).ToByteArray()),
            intent.RootIdentity.ToArray(), intent.ParentIdentity.ToArray(), intent.TargetIdentity.ToArray(),
            intent.OriginalStageIdentity.ToArray(), intent.IntendedStageIdentity.ToArray(), intent.OriginalSize.Value,
            intent.OriginalSha256.ToArray(), intent.IntendedSize, intent.IntendedSha256.ToArray(), deadline, expiryMicroseconds, durableStages);
    }

    internal void Write(BinaryWriter writer)
    {
        Validate();
        writer.Write((byte)2);
        writer.Write(DurableStages ? (byte)1 : (byte)0);
        writer.Write((byte)Kind);
        writer.Write(CommandId);
        writer.Write(RequestDigest);
        writer.Write(CallerDigest);
        writer.Write(RootIdentity);
        writer.Write(ParentIdentity);
        writer.Write(TargetIdentity);
        writer.Write(OriginalStageIdentity);
        writer.Write(IntendedStageIdentity);
        writer.Write(OriginalSize);
        writer.Write(OriginalSha256);
        writer.Write(IntendedSize);
        writer.Write(IntendedSha256);
        writer.Write(Deadline);
        writer.Write(ExpiryMicroseconds);
        writer.Flush();
    }

    internal static LinuxFileEffectBinding Read(BinaryReader reader)
    {
        var version = reader.ReadByte();
        if (version is not (1 or 2)) throw new InvalidDataException("Unsupported worker binding.");
        var stageKind = version == 2 ? reader.ReadByte() : (byte)0;
        if (stageKind > 1) throw new InvalidDataException("Unknown stage storage kind.");
        var result = new LinuxFileEffectBinding((FileOperationKind)reader.ReadByte(), ReadExactly(reader, 16),
            ReadExactly(reader, 32), ReadExactly(reader, 32), ReadExactly(reader, 53), ReadExactly(reader, 53),
            ReadExactly(reader, 53), ReadExactly(reader, 53), ReadExactly(reader, 53), reader.ReadInt64(),
            ReadExactly(reader, 32), reader.ReadInt64(), ReadExactly(reader, 32), reader.ReadInt64(), reader.ReadInt64(), stageKind == 1);
        result.Validate();
        return result;
    }

    private void Validate()
    {
        if (Kind is not (FileOperationKind.Write or FileOperationKind.Edit) || CommandId.Length != 16 ||
            CommandId.AsSpan().IndexOfAnyExcept((byte)0) < 0 || RequestDigest.Length != 32 || CallerDigest.Length != 32 ||
            RootIdentity.Length != 53 || ParentIdentity.Length != 53 || TargetIdentity.Length != 53 ||
            OriginalStageIdentity.Length != 53 || IntendedStageIdentity.Length != 53 ||
            RootIdentity[0] != 1 || ParentIdentity[0] != 1 || TargetIdentity[0] != 1 ||
            OriginalStageIdentity[0] != 1 || IntendedStageIdentity[0] != 1 ||
            OriginalSize is < 0 or > 4_194_304 || IntendedSize is < 0 or > 4_194_304 ||
            OriginalSha256.Length != 32 || IntendedSha256.Length != 32 || ExpiryMicroseconds <= 0)
            throw new InvalidDataException("Invalid worker binding.");
    }

    private static byte[] ReadExactly(BinaryReader reader, int count)
    {
        var bytes = reader.ReadBytes(count);
        return bytes.Length == count ? bytes : throw new EndOfStreamException("The worker binding ended early.");
    }
}
