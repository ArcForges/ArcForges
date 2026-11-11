// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using FleetShapes = ArcForges.Contracts.Fleet.Shapes.ContractShapeValidation;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal static partial class RoutedFileResponseValidation
{
    internal static bool Directory(FleetServiceListNodeDirectoryResponse response, Id target, FileServiceListDirectoryRequest request)
    {
        var pathOnly = new FileServiceReadFileRequest { Path = request.Path?.Clone() };
        if (!FleetShapes.IsValid(response))
        {
            return false;
        }

        if (response.Error is { } outer)
        {
            return CanonicalLimits(outer) && ReadLimitMatches(outer, pathOnly);
        }

        if (response.Value is not { HasResponse: true } value || value.NodeId is not { Value.Length: 16 } nodeId ||
            !nodeId.Value.Span.SequenceEqual(target.Value.Span) || value.Response.Length is < 1 or > 131_072)
        {
            return false;
        }

        FileServiceListDirectoryResponse inner;
        try
        {
            inner = FileServiceListDirectoryResponse.Parser.ParseFrom(value.Response);
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }

        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, request.Meta, inner.Error))
        {
            return false;
        }

        if (inner.Error is { } error)
        {
            var cursorError = error.Category == ErrorCategory.Validation && error.Code == "invalid_cursor" && NodeShapes.IsValid(error) &&
                error.Effect == EffectCertainty.DidNotHappen && error.Retry is { Mode: RetryMode.Never, RetryAt: null };
            return (cursorError || ReadError(error)) && 
                CanonicalLimits(error) && ReadLimitMatches(error, pathOnly) && inner.Audit is null;
        }

        if (inner.Value is not { } page || !NodeShapes.IsValid(request) || request.Meta?.CommandId is not null ||
            request.HasPageSize && request.PageSize is < 1 or > 128 ||
            page.Entries.Count > (request.HasPageSize ? request.PageSize : 100) ||
            page.SnapshotEntries > 10_000 || page.SnapshotEntries < page.Entries.Count ||
            inner.Audit is not { Observations.Count: 1 })
        {
            return false;
        }

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        ReadOnlySpan<byte> domain = "ArcForges directory-list v1\0"u8;
        hash.AppendData(domain);
        ulong bytes = (ulong)domain.Length;
        Span<byte> frame = stackalloc byte[8];
        string? previous = null;
        foreach (var entry in page.Entries)
        {
            if (previous is not null && string.CompareOrdinal(previous, entry.Name) >= 0)
            {
                return false;
            }

            previous = entry.Name;
            byte[] name;
            try
            {
                name = StrictUtf8.GetBytes(entry.Name);
            }
            catch (System.Text.EncoderFallbackException)
            {
                return false;
            }

            BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)name.Length));
            hash.AppendData(frame[..4]);
            hash.AppendData(name);
            BinaryPrimitives.WriteUInt32BigEndian(frame, checked((uint)entry.Kind));
            hash.AppendData(frame[..4]);
            frame[0] = entry.HasSizeBytes ? (byte)1 : (byte)0;
            hash.AppendData(frame[..1]);
            bytes += checked((ulong)(9 + name.Length));
            if (entry.HasSizeBytes)
            {
                BinaryPrimitives.WriteUInt64BigEndian(frame, entry.SizeBytes);
                hash.AppendData(frame);
                bytes += 8;
            }
        }

        var digest = hash.GetHashAndReset();
        var observation = inner.Audit.Observations[0];
        return page.MetadataBytes == bytes && CryptographicOperations.FixedTimeEquals(page.MetadataDigest.Span, digest) &&
            observation.Kind == FileAuditKind.DirectoryMetadata && observation.HasSizeBytes && observation.SizeBytes == bytes &&
            observation.HasDigestInputBytes && observation.DigestInputBytes == bytes && observation.HasItemCount &&
            observation.ItemCount == page.Entries.Count && CryptographicOperations.FixedTimeEquals(observation.Sha256.Span, digest);
    }
}
