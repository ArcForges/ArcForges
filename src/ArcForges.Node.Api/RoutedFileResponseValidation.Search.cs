// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using Google.Protobuf;
using FleetShapes = ArcForges.Contracts.Fleet.Shapes.ContractShapeValidation;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Api;

internal static partial class RoutedFileResponseValidation
{
    internal static bool Search(FleetServiceSearchNodeFilesResponse response, Id target, FileServiceSearchFilesRequest request)
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

        FileServiceSearchFilesResponse inner;
        try
        {
            inner = FileServiceSearchFilesResponse.Parser.ParseFrom(value.Response);
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }

        if (!NodeShapes.IsValid(inner) || !FileMetaMatches(inner.Meta, request.Meta, inner.Error) || !ValidSearchAudit(inner.Audit, request))
        {
            return false;
        }

        if (inner.Error is { } error)
        {
            return ReadError(error) && CanonicalLimits(error) && ReadLimitMatches(error, pathOnly) &&
                (error.Details?.State?.Reason != "pattern: regex_scalar_boundary" || inner.Audit is { Observations.Count: 1 } &&
                    inner.Audit.Observations[0].SizeBytes > 0);
        }

        if (inner.Value is not { } result || !NodeShapes.IsValid(request) || request.Meta?.CommandId is not null ||
            request.Path is not { HasPath: true } path || request.HasMaxMatches && request.MaxMatches is < 1 or > 100 ||
            request.HasMaxScanBytes && request.MaxScanBytes is < 1 or > 8_388_608 ||
            result.VisitedEntries > 10_000 || result.ScannedBytes > (request.HasMaxScanBytes ? request.MaxScanBytes : 8_388_608UL) ||
            result.Matches.Count > (request.HasMaxMatches ? request.MaxMatches : 100) || result.ScanFileCount > result.VisitedEntries ||
            result.Truncated != result.HasTruncationReason || !result.Truncated && result.Problems.Count != 0 ||
            inner.Audit is not { Observations.Count: 1 })
        {
            return false;
        }

        var observation = inner.Audit.Observations[0];
        if (observation.SizeBytes != result.ScannedBytes || observation.DigestInputBytes != result.ScanTranscriptBytes ||
            observation.ItemCount != result.ScanFileCount || !CryptographicOperations.FixedTimeEquals(observation.Sha256.Span, result.ScanDigest.Span))
        {
            return false;
        }

        int literalBytes;
        try
        {
            literalBytes = request.Mode == FileSearchMode.Literal ? StrictUtf8.GetByteCount(request.Pattern) : 0;
        }
        catch (System.Text.EncoderFallbackException)
        {
            return false;
        }

        var ends = new Dictionary<string, ulong>(StringComparer.Ordinal);
        ulong required = 0;
        foreach (var match in result.Matches)
        {
            try
            {
                _ = WorkspacePath.Components(match.Path);
            }
            catch (WorkspacePathException)
            {
                return false;
            }

            if (path.Path.Length != 0 && !match.Path.Equals(path.Path, StringComparison.Ordinal) &&
                !match.Path.StartsWith(path.Path + "/", StringComparison.Ordinal) ||
                match.ByteOffset > 1_048_576 || match.ByteLength > 1_048_576 - match.ByteOffset ||
                match.ByteOffset > result.ScannedBytes || match.ByteLength > result.ScannedBytes - match.ByteOffset ||
                request.Mode == FileSearchMode.Literal && match.ByteLength != literalBytes)
            {
                return false;
            }

            var end = match.ByteOffset + match.ByteLength;
            ends.TryGetValue(match.Path, out var previous);
            if (end > previous)
            {
                var increment = end - previous;
                if (increment > result.ScannedBytes - required)
                {
                    return false;
                }

                required += increment;
                ends[match.Path] = end;
            }
        }

        return ends.Count <= result.ScanFileCount;
    }

    private static bool ValidSearchAudit(FileAuditMetadata? audit, FileServiceSearchFilesRequest request)
    {
        if (audit is null)
        {
            return true;
        }

        if (audit.Observations.Count != 1 || audit.Observations[0] is not
            { Kind: FileAuditKind.SearchTranscript, HasSizeBytes: true, HasDigestInputBytes: true, HasItemCount: true, Sha256.Length: 32 } item ||
            item.SizeBytes > (request.HasMaxScanBytes ? request.MaxScanBytes : 8_388_608UL) || item.ItemCount > 10_000 ||
            (item.SizeBytes == 0) != (item.ItemCount == 0) ||
            item.DigestInputBytes < 25UL + item.SizeBytes + 12UL * item.ItemCount ||
            item.DigestInputBytes > 25UL + item.SizeBytes + 4108UL * item.ItemCount)
        {
            return false;
        }

        return item.SizeBytes != 0 || item.ItemCount == 0 && item.DigestInputBytes == 25 &&
            CryptographicOperations.FixedTimeEquals(item.Sha256.Span, SHA256.HashData("ArcForges search-scan v1\0"u8));
    }
}
