// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// Content-free settlement for checked file effects. The effect coordinator must independently prove authorization,
/// native identity, guard, flush, final rehash and name revalidation. These methods do not perform a filesystem effect.
/// </summary>
internal static partial class FileMutationJournal
{
    /// <summary>
    /// Settles a verified effect and its audit in the same FULL transaction. Only fixed result metadata is serialized;
    /// the original request is checked in memory and is never stored. Do not call until the same held handle has been
    /// flushed, rehashed and the required identities have been revalidated.
    /// </summary>
    internal static byte[] CompleteVerifiedEffect(StoreTransaction transaction, ReadOnlySpan<byte> commandId,
        ReadOnlySpan<byte> transmitted, long resultingSize, ReadOnlySpan<byte> resultingSha256, uint? replacements,
        WorkspaceCreatedOwnership? createdOwnership = null, FileCreationOwnership.UpdateProof? ownershipUpdate = null)
    {
        RequireFull(transaction);
        StoreIds.Validate(commandId, nameof(commandId));
        var row = ReadRow(transaction, commandId) ?? throw new InvalidOperationException("The file intent is missing.");
        if (row.State != FileOperationState.Prepared || row.Outcome is not null ||
            transmitted.Length is < 1 or > MaximumRequestBytes ||
            !CryptographicOperations.FixedTimeEquals(row.RequestSha256, SHA256.HashData(transmitted)) ||
            resultingSize != row.IntendedSize || resultingSha256.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(row.IntendedSha256, resultingSha256))
            throw new InvalidOperationException("The observed result does not match the prepared file intent.");

        if (row.Kind == FileOperationKind.Write)
        {
            if (replacements is not null)
                throw new ArgumentException("A write has no replacement count.", nameof(replacements));
        }
        else
        {
            var request = FileServiceEditFileRequest.Parser.ParseFrom(transmitted.ToArray());
            if (!NodeShapes.IsValid(request) || !request.HasExpectedOccurrences ||
                replacements is null or < 1 or > 1000 || replacements.Value != request.ExpectedOccurrences)
                throw new ArgumentException("The replacement count must match the original edit request.", nameof(replacements));
        }

        if (createdOwnership is not null && (row.Kind != FileOperationKind.Write || !row.ExpectedAbsent || ownershipUpdate is not null) ||
            ownershipUpdate is not null && row.ExpectedAbsent)
            throw new InvalidOperationException("Creation and update evidence do not match the file intent.");
        return CompleteCheckedEffect(transaction, row, resultingSize, resultingSha256, replacements, createdOwnership, ownershipUpdate);
    }

    private static byte[] CompleteCheckedEffect(StoreTransaction transaction, JournalRow row, long resultingSize,
        ReadOnlySpan<byte> resultingSha256, uint? replacements, WorkspaceCreatedOwnership? createdOwnership = null,
        FileCreationOwnership.UpdateProof? ownershipUpdate = null)
    {
        var result = new FileMutationResult
        {
            CommandId = new Id { Value = ByteString.CopyFrom(row.CommandId) },
            SizeBytes = checked((ulong)resultingSize),
            Sha256 = ByteString.CopyFrom(resultingSha256),
        };
        if (replacements is not null) result.Replacements = replacements.Value;
        var audit = new FileAuditMetadata
        {
            Observations =
            {
                new FileAuditObservation
                {
                    Kind = FileAuditKind.WrittenBytes,
                    SizeBytes = checked((ulong)resultingSize),
                    DigestInputBytes = checked((ulong)resultingSize),
                    Sha256 = ByteString.CopyFrom(resultingSha256),
                },
            },
        };
        var meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) } };
        byte[] outcome;
        if (row.Kind == FileOperationKind.Write)
        {
            var response = new FileServiceWriteFileResponse
            {
                Meta = meta,
                Value = new FileServiceWriteFileValue { Result = result },
                Audit = audit,
            };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid write settlement.");
            outcome = response.ToByteArray();
        }
        else
        {
            var response = new FileServiceEditFileResponse
            {
                Meta = meta,
                Value = new FileServiceEditFileValue { Result = result },
                Audit = audit,
            };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid edit settlement.");
            outcome = response.ToByteArray();
        }

        if (transaction.Execute("""
            UPDATE file_operation_journal SET phase = 2, held = 0, updated_at = max(updated_at, $now)
            WHERE command_id = $id AND phase = 1 AND held = 1 AND acknowledged = 0;
            """, ("$now", transaction.NowMicroseconds), ("$id", row.CommandId)) != 1)
            throw new InvalidOperationException("The file intent changed during settlement.");
        CommandDeduplication.Complete(transaction, row.CommandId, outcome);
        // A controlled update retains evidence only if the same caller, old marker/ID/hash and the final
        // marker/ID/hash were observed on the guarded object. Any unverified or foreign write invalidates it.
        var objectGeneration = FileCreationOwnership.InvalidateAffected(transaction, row.CommandId, createdOwnership);
        var retained = ownershipUpdate is not null && objectGeneration is not null &&
            FileCreationOwnership.Advance(transaction, ownershipUpdate, row.CommandId, row.WorkspaceId, row.Path,
                row.Caller, resultingSize, resultingSha256, objectGeneration.Value);
        if (!retained) FileCreationOwnership.ForgetPath(transaction, row.WorkspaceId, row.Path);
        if (createdOwnership?.Marker is not null)
            FileCreationOwnership.RecordCompleted(transaction, row.CommandId, createdOwnership, resultingSize, resultingSha256);
        // A terminal named stage remains retained and charged, but no longer holds the workspace open.
        if (PrivateStageRegistry.HasSchema(transaction))
            transaction.Execute("UPDATE file_private_stage_reservation SET active = 0 WHERE command_id = $id AND active = 1;",
                ("$id", row.CommandId));
        AuditLog.AppendFileWorkspace(transaction, Actor(row), row.Kind == FileOperationKind.Write
            ? "file.write FileService.WriteFile" : "file.edit FileService.EditFile",
            row.WorkspaceId, null, row.Path, PermissionDecision.Allow, "completed", audit);
        return outcome;
    }

    /// <summary>
    /// Makes an unresolved effect UNKNOWN without performing or retrying it. The original correlation and exact
    /// content-free response are committed together with the hold and audit. The caller still owns stage disposition.
    /// </summary>
    internal static byte[] MarkUnknown(StoreTransaction transaction, ReadOnlySpan<byte> commandId)
    {
        RequireFull(transaction);
        StoreIds.Validate(commandId, nameof(commandId));
        var row = ReadRow(transaction, commandId) ?? throw new InvalidOperationException("The file intent is missing.");
        if (row.State != FileOperationState.Prepared || row.Outcome is not null)
            throw new InvalidOperationException("Only an unresolved file intent can become UNKNOWN.");
        var outcome = UnknownOutcome(row);
        if (transaction.Execute("""
            UPDATE file_operation_journal SET phase = 3, updated_at = max(updated_at, $now)
            WHERE command_id = $id AND phase = 1 AND held = 1 AND acknowledged = 0;
            """, ("$now", transaction.NowMicroseconds), ("$id", row.CommandId)) != 1)
            throw new InvalidOperationException("The file intent changed during recovery.");
        _ = FileCreationOwnership.InvalidateAffected(transaction, row.CommandId, created: null);
        FileCreationOwnership.ForgetPath(transaction, row.WorkspaceId, row.Path);
        CommandDeduplication.Complete(transaction, row.CommandId, outcome);
        AuditLog.AppendFileWorkspace(transaction, Actor(row), "file.recovery FileService.GetFileOperation",
            row.WorkspaceId, null, row.Path, PermissionDecision.Allow, "recovered: file_outcome_unknown", null);
        return outcome;
    }

    /// <summary>Returns the stored bytes only after the original caller, method and exact raw request match.</summary>
    internal static byte[]? Replay(StoreReader reader, FileOperationKind kind, ReadOnlySpan<byte> commandId,
        CenterCaller caller, ReadOnlySpan<byte> transmitted)
    {
        if (FindExisting(reader, kind, commandId, caller, transmitted) != FileJournalPreparation.Existing)
            return null;
        var row = ReadRow(reader, commandId);
        if (row is null) return PrivateStageTerminal.Replay(reader, kind, commandId, caller, transmitted);
        if (row.State == FileOperationState.Completed) _ = CompletedResult(row);
        else if (row.State == FileOperationState.Unknown) EnsureUnknownOutcome(row);
        else if (row.Outcome is not null) throw new InvalidDataException("A prepared journal has an outcome.");
        return row.Outcome?.ToArray();
    }

    private static ActorRef Actor(JournalRow row) => new()
    {
        Origin = Origin.Remote,
        CenterCaller = row.Caller,
        RemoteCommandId = new Id { Value = ByteString.CopyFrom(row.CommandId) },
    };

    private static ArcError UnknownError(JournalRow row) => new()
    {
        Category = ErrorCategory.Execution,
        Code = "operation_failed",
        MessageKey = "error.execution.operation_failed",
        Effect = EffectCertainty.Unknown,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) },
        Details = new ErrorDetails { State = new StateFailure { State = "file", Reason = "file_outcome_unknown" } },
    };

    private static byte[] UnknownOutcome(JournalRow row)
    {
        var meta = new ResponseMeta { CorrelationId = new Id { Value = ByteString.CopyFrom(row.Correlation) } };
        var error = UnknownError(row);
        if (row.Kind == FileOperationKind.Write)
        {
            var response = new FileServiceWriteFileResponse { Meta = meta, Error = error };
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid UNKNOWN write settlement.");
            return response.ToByteArray();
        }
        var edit = new FileServiceEditFileResponse { Meta = meta, Error = error };
        if (!NodeShapes.IsValid(edit)) throw new InvalidDataException("Invalid UNKNOWN edit settlement.");
        return edit.ToByteArray();
    }

    private static void EnsureUnknownOutcome(JournalRow row)
    {
        var expected = UnknownOutcome(row);
        if (row.Outcome is null || !CryptographicOperations.FixedTimeEquals(row.Outcome, expected))
            throw new InvalidDataException("The recorded uncertain outcome does not match its journal.");
    }

    private static (FileMutationResult? Mutation, ArcError? Error) CompletedResult(JournalRow row)
    {
        if (row.Outcome is null) throw new InvalidDataException("A completed file operation has no outcome.");
        FileMutationResult? result;
        ResponseMeta? meta;
        ArcError? error;
        FileAuditMetadata? audit;
        if (row.Kind == FileOperationKind.Write)
        {
            var response = FileServiceWriteFileResponse.Parser.ParseFrom(row.Outcome);
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid completed write outcome.");
            result = response.Value?.Result;
            meta = response.Meta;
            error = response.Error;
            audit = response.Audit;
            if (result?.HasReplacements == true) throw new InvalidDataException("A write cannot report replacements.");
        }
        else
        {
            var response = FileServiceEditFileResponse.Parser.ParseFrom(row.Outcome);
            if (!NodeShapes.IsValid(response)) throw new InvalidDataException("Invalid completed edit outcome.");
            result = response.Value?.Result;
            meta = response.Meta;
            error = response.Error;
            audit = response.Audit;
            if (result is not null && (!result.HasReplacements || result.Replacements is < 1 or > 1000))
                throw new InvalidDataException("An edit needs its actual replacement count.");
        }
        if (meta?.CorrelationId?.Value.Span.SequenceEqual(row.Correlation) != true)
            throw new InvalidDataException("The completed outcome correlation does not match its journal.");
        if (error is not null)
        {
            if (result is not null || audit is not null) throw new InvalidDataException("Invalid known file refusal.");
            return (null, ReadKnownFileRefusal(row, error));
        }
        if (result?.CommandId?.Value.Span.SequenceEqual(row.CommandId) != true ||
            !result.HasSizeBytes || result.SizeBytes != (ulong)row.IntendedSize ||
            !result.HasSha256 || !CryptographicOperations.FixedTimeEquals(result.Sha256.Span, row.IntendedSha256))
            throw new InvalidDataException("The completed outcome does not match its file intent.");
        return (result.Clone(), null);
    }
}
