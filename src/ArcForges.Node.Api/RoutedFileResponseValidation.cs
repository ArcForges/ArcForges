// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using Google.Protobuf;
using FleetShapes = ArcForges.Contracts.Fleet.Shapes.ContractShapeValidation;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;
using WireDecimal = ArcForges.Contracts.Foundation.V1.Decimal;

namespace ArcForges.Node.Api;

/// <summary>Checks a center reply against the original file read without rewriting its inner bytes.</summary>
internal static partial class RoutedFileResponseValidation
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static bool Read(FleetServiceReadNodeFileResponse response, Id target, FileServiceReadFileRequest request)
    {
        if (!FleetShapes.IsValid(response))
        {
            return false;
        }

        if (response.Error is { } outer)
        {
            return CanonicalLimits(outer) && ReadLimitMatches(outer, request);
        }

        if (response.Value is not { HasResponse: true } value || value.NodeId is not { Value.Length: 16 } nodeId ||
            !nodeId.Value.Span.SequenceEqual(target.Value.Span) || value.Response.Length is < 1 or > 1_040_384)
        {
            return false;
        }

        FileServiceReadFileResponse inner;
        try
        {
            inner = FileServiceReadFileResponse.Parser.ParseFrom(value.Response);
        }
        catch (InvalidProtocolBufferException)
        {
            return false;
        }

        if (!NodeShapes.IsValid(inner))
        {
            return false;
        }

        if (inner.Error is { } error)
        {
            return ReadError(error) && CanonicalLimits(error) && ReadLimitMatches(error, request) && ValidReadAudit(inner.Audit);
        }

        if (inner.Value is not { } read || !request.HasOffset || !request.HasLength || request.Length == 0 ||
            read.Offset != request.Offset || (ulong)read.Data.Length > Math.Min(request.Length, 65_536UL) ||
            read.Offset > ulong.MaxValue - (ulong)read.Data.Length || read.NextOffset != read.Offset + (ulong)read.Data.Length ||
            (read.Offset >= read.FileSize
                ? read.Data.Length != 0 || !read.Eof
                : read.Data.Length == 0 || read.NextOffset > read.FileSize || read.Eof != (read.NextOffset == read.FileSize)))
        {
            return false;
        }

        var hash = SHA256.HashData(read.Data.Span);
        if (!CryptographicOperations.FixedTimeEquals(hash, read.Sha256.Span) || !ValidReadAudit(inner.Audit) ||
            inner.Audit is not { Observations.Count: 1 })
        {
            return false;
        }

        var observation = inner.Audit.Observations[0];
        return observation.SizeBytes == (ulong)read.Data.Length &&
            CryptographicOperations.FixedTimeEquals(hash, observation.Sha256.Span);
    }

    /// <summary>
    /// Applies canonicalDecimal independently of the published 450.1 validator, which accepts trailing fractional zeroes.
    /// Each present maximum and available value must be canonical before the surrounding result may be accepted.
    /// </summary>
    internal static bool CanonicalLimits(ArcError error)
    {
        if (error.Details?.Limit is not { } limit)
        {
            return error.Code != "too_large";
        }

        return (limit.Maximum is null || CanonicalDecimal(limit.Maximum)) &&
            (limit.Available is null || CanonicalDecimal(limit.Available)) &&
            (error.Code != "too_large" || limit.Maximum is not null);
    }

    internal static bool CanonicalDecimal(WireDecimal value)
    {
        if (!value.HasValue || value.Value.Length == 0)
        {
            return false;
        }

        var text = value.Value.AsSpan();
        var negative = text[0] == '-';
        if (negative)
        {
            text = text[1..];
        }

        if (text.IsEmpty)
        {
            return false;
        }

        var dot = text.IndexOf('.');
        var integer = dot < 0 ? text : text[..dot];
        var fraction = dot < 0 ? ReadOnlySpan<char>.Empty : text[(dot + 1)..];
        if (integer.IsEmpty || integer.Length > 1 && integer[0] == '0' ||
            dot >= 0 && (fraction.IsEmpty || fraction.Length > 9 || fraction[^1] == '0' || fraction.Contains('.')))
        {
            return false;
        }

        var significant = 0;
        var seenNonzero = false;
        foreach (var character in text)
        {
            if (character == '.')
            {
                continue;
            }

            if (character is < '0' or > '9')
            {
                return false;
            }

            seenNonzero |= character != '0';
            if (seenNonzero)
            {
                significant++;
            }
        }

        return significant <= 28 && (!negative || seenNonzero);
    }

    private static bool ReadLimitMatches(ArcError error, FileServiceReadFileRequest request)
    {
        if (error.Category != ErrorCategory.Resource || error.Code != "too_large")
        {
            return true;
        }

        var limit = error.Details?.Limit;
        if (limit?.Maximum?.Value != "4096" || !Token(limit.LimitName) || request.Path is not { HasPath: true } path ||
            limit.LimitName is "workspace_root_path_bytes" or "file_write_bytes" or "file_edit_text_bytes" or
                "file_existing_bytes" or "file_edit_result_bytes" or "removal_descendants" or "removal_total_bytes")
        {
            return false;
        }

        try
        {
            return StrictUtf8.GetByteCount(path.Path) > 4096;
        }
        catch (EncoderFallbackException)
        {
            return false;
        }
    }

    private static bool ReadError(ArcError error)
    {
        if (!NodeShapes.IsValid(error) || error.Retry is null || error.Effect != EffectCertainty.DidNotHappen)
        {
            return false;
        }

        var category = error.Category;
        var code = error.Code;
        if (category == ErrorCategory.Resource && code == "overloaded")
        {
            return error.Retry.Mode == RetryMode.AfterTime && error.Retry.RetryAt is not null;
        }

        if (category == ErrorCategory.Internal && code == "internal")
        {
            return error.Retry.Mode == RetryMode.AfterTime && error.Retry.RetryAt is not null;
        }

        if (error.Retry.Mode != RetryMode.Never || error.Retry.RetryAt is not null)
        {
            return false;
        }

        if (category == ErrorCategory.Resource && code == "too_large")
        {
            return true;
        }

        var state = error.Details?.State;
        if (state is null || !Token(state.State) || !Reason(state.Reason))
        {
            return false;
        }

        return (category, code) switch
        {
            (ErrorCategory.Validation, "invalid_argument") => state.Reason.Contains(": ", StringComparison.Ordinal),
            (ErrorCategory.Validation, "path_not_found") or (ErrorCategory.Authorization, "permission_denied") => true,
            (ErrorCategory.Conflict, "file_changed") => state.State == "file" &&
                state.Reason is "workspace_root_changed" or "workspace_path_conflict" or "workspace_identity_conflict" or
                    "workspace_registration_changed" or "legacy_snapshot_changed" or "file_identity_changed" or
                    "directory_identity_changed" or "directory_changed" or "root_changed" or "file_changed_while_reading" or
                    "parent_identity_changed",
            (ErrorCategory.State, "file_access_denied") => state.State == "file" &&
                state.Reason is "file_access_denied" or "file_hard_link" or "file_metadata_unavailable" or "path_link_or_special" or
                    "mount_crossing" or "canonical_path_unavailable" or "case_semantics_unavailable" or "directory_entry_invalid" or
                    "directory_enumeration_failed" or "directory_enumeration_unavailable" or "file_guard_unavailable" or
                    "path_enforcement_unavailable" or "identity_filesystem_unavailable" or "identity_handle_unavailable" or
                    "identity_unavailable" or "identity_unavailable_or_reparse" or "procfs_unavailable" or "root_not_supported",
            _ => false,
        };
    }

    private static bool ValidReadAudit(FileAuditMetadata? audit)
    {
        if (audit is null)
        {
            return true;
        }

        if (audit.Observations.Count > 1)
        {
            return false;
        }

        return audit.Observations.Count == 0 ||
            audit.Observations[0] is { Kind: FileAuditKind.ReadBytes, HasSizeBytes: true, HasDigestInputBytes: true, Sha256.Length: 32 } item &&
            item.SizeBytes <= 65_536 && item.DigestInputBytes == item.SizeBytes;
    }

    private static bool FileMetaMatches(ResponseMeta? meta, RequestMeta? request, ArcError? error)
    {
        static bool Valid(Id? id) => id is { Value.Length: 16 } && id.Value.Span.IndexOfAnyExcept((byte)0) >= 0;
        var expected = request?.CorrelationId;
        if (meta is not null && (!Valid(meta.CorrelationId) || Valid(expected) && !meta.CorrelationId!.Equals(expected)))
        {
            return false;
        }

        return error is null || Valid(error.CorrelationId) && (!Valid(expected) || error.CorrelationId!.Equals(expected)) &&
            (meta is null || error.CorrelationId!.Equals(meta.CorrelationId));
    }

    private static bool Token(string value) =>
        value.Length is >= 1 and <= 128 && value.All(static c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '/' or '-');

    private static bool Reason(string value) =>
        value.Length is >= 1 and <= 256 && value.All(static c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '/' or '-' or ' ');
}
