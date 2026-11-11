// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Files;

/// <summary>
/// Content-free approval binding for an already durable named stage. This component does not itself establish a
/// routed caller, execute an approval or change a target. The caller retains the verified root and target guards.
/// </summary>
internal static class PrivateStageApproval
{
    internal static (StoredApproval? Approval, bool Created, ArcError? Error) Raise(CommandContext context,
        FileJournalIntent intent, ReadOnlySpan<byte> transmitted, ActorRef requester, WorkspacePath root,
        WorkspaceWriteGuard? target, TimeSpan ttl, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(requester);
        ArgumentNullException.ThrowIfNull(root);
        var transaction = context.Transaction;
        if (transaction.Durability != CommitDurability.Full || ttl <= TimeSpan.Zero ||
            ttl.TotalMicroseconds > long.MaxValue - transaction.NowMicroseconds)
            throw new InvalidOperationException("File approvals require a bounded FULL transaction.");
        FileMutationJournal.ValidateIntent(intent, transmitted);
        if (requester.Origin != Origin.Remote || requester.CenterCaller is null ||
            !CenterRouting.SameFileCaller(requester.CenterCaller, intent.Caller) ||
            requester.RemoteCommandId?.Value.Span.SequenceEqual(intent.CommandId) != true)
            throw new ArgumentException("The original verified requester must own the command.", nameof(requester));
        cancellationToken.ThrowIfCancellationRequested();
        var digest = SHA256.HashData(transmitted);
        var method = intent.Kind == FileOperationKind.Write ? "FileService.WriteFile" : "FileService.EditFile";
        using (var select = transaction.CreateCommand("""
            SELECT r.kind, r.workspace_id, r.correlation_id, r.relative_path, r.expected_absent, r.expected_sha256,
                   r.request_sha256, r.caller, w.platform, w.native_identity
            FROM file_private_stage_reservation r
            JOIN workspace_root_identity w ON w.workspace_id = r.workspace_id AND w.released_at IS NULL
            WHERE r.command_id = $id AND r.active = 1;
            """))
        {
            select.Parameters.AddWithValue("$id", intent.CommandId);
            using var row = select.ExecuteReader();
            if (!row.Read() || row.GetInt32(0) != (int)intent.Kind ||
                !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(1), intent.WorkspaceId) ||
                !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(2), intent.CorrelationId) ||
                row.GetString(3) != intent.RelativePath || (row.GetInt32(4) != 0) != (intent.TargetIdentity is null) ||
                (intent.OriginalSha256 is null ? !row.IsDBNull(5) : row.IsDBNull(5) ||
                    !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(5), intent.OriginalSha256)) ||
                !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(6), digest) ||
                !CenterRouting.SameFileCaller(CenterCaller.Parser.ParseFrom((byte[])row.GetValue(7)), intent.Caller) ||
                row.GetInt32(8) != intent.IdentityPlatform ||
                !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(9), intent.RootIdentity))
                throw new InvalidOperationException("The durable stage reservation does not match the file intent.");
        }

        CheckTarget(intent, root, target, cancellationToken);
        using var intended = PrivateStageRegistry.ReopenReadyStage(transaction, intent.CommandId, 2, intent.Caller, digest, cancellationToken);
        CheckStage(intended, intent.IdentityPlatform, intent.IntendedStageIdentity, intent.IntendedSize, intent.IntendedSha256, cancellationToken);
        if (target is not null && intended.Guard.ObjectIdentity.SameObject(target.ObjectIdentity))
            throw new WorkspacePathException("file_identity_changed");
        using var original = intent.TargetIdentity is null ? null :
            PrivateStageRegistry.ReopenReadyStage(transaction, intent.CommandId, 1, intent.Caller, digest, cancellationToken);
        if (original is not null)
        {
            CheckStage(original, intent.IdentityPlatform, intent.OriginalStageIdentity!, intent.OriginalSize!.Value,
                intent.OriginalSha256!, cancellationToken);
            if (original.Guard.ObjectIdentity.SameObject(intended.Guard.ObjectIdentity) ||
                target is not null && original.Guard.ObjectIdentity.SameObject(target.ObjectIdentity))
                throw new WorkspacePathException("file_identity_changed");
            if (intent.Kind == FileOperationKind.Edit)
            {
                var editRequest = FileServiceEditFileRequest.Parser.ParseFrom(transmitted.ToArray());
                using var source = original.Guard.ReadForMutation(cancellationToken);
                using var edit = WorkspaceFileEdit.Plan(source.Bytes.Span, intent.OriginalSha256!, editRequest.OldText,
                    editRequest.NewText, editRequest.ExpectedOccurrences, cancellationToken);
                if (edit.Bytes.Length != intent.IntendedSize ||
                    !CryptographicOperations.FixedTimeEquals(edit.Sha256.Span, intent.IntendedSha256))
                    throw new InvalidOperationException("The staged edit does not match the transmitted edit.");
            }
        }

        // Recheck the live held target after potentially expensive stage hashing, before committing an approval.
        CheckTarget(intent, root, target, cancellationToken);
        var existing = Approvals.ByCommand(transaction, intent.CommandId);
        if (existing is not null)
        {
            if (!BindingMatches(transaction, intent, existing.Id) || existing.View.Operation != method ||
                !CryptographicOperations.FixedTimeEquals(existing.RequestDigest, digest) ||
                !CenterRouting.SameFileCaller(existing.View.Requester?.CenterCaller, intent.Caller))
                return (null, false, StoreErrors.CommandIdReused());
            return (existing, false, null);
        }

        var reference = new byte[17];
        reference[0] = 1; // Versioned command reference, not a serialized file request.
        intent.CommandId.CopyTo(reference, 1);
        var stableRequester = new ActorRef
        {
            Origin = Origin.Remote,
            ClientKind = requester.ClientKind,
            CenterCaller = intent.Caller.Clone(),
            RemoteCommandId = new Id { Value = ByteString.CopyFrom(intent.CommandId) },
        };
        var capture = new ApprovalCapture
        {
            Operation = method,
            MatrixOperation = PermissionMatrix.FileWrite,
            Summary = intent.Kind == FileOperationKind.Write ? "Write a registered workspace file" : "Edit a registered workspace file",
            Details = Describe(intent, digest),
            Risk = RiskClass.High,
            Requester = stableRequester,
            CommandId = intent.CommandId.ToArray(),
            Request = reference,
            RequestDigest = digest,
            TargetKind = "workspace",
            TargetId = intent.WorkspaceId.ToArray(),
        };
        var result = Approvals.Raise(context, capture, ttl);
        if (result.Error is not null || !result.Created || result.Approval is null)
            throw new InvalidOperationException("The private file approval could not be recorded.");
        transaction.Execute("""
            INSERT INTO file_private_approval_binding
              (command_id, approval_id, identity_platform, root_identity, parent_identity, target_identity)
            VALUES ($id, $approval, $platform, $root, $parent, $target);
            """, ("$id", intent.CommandId), ("$approval", result.Approval.Id), ("$platform", intent.IdentityPlatform),
            ("$root", intent.RootIdentity), ("$parent", intent.ParentIdentity), ("$target", intent.TargetIdentity));
        return result;
    }

    // Approvals persist at most 500 UTF-16 units per detail and 32 details. A valid workspace path can be longer:
    // split it at surrogate-safe boundaries so a HUMAN can reconstruct the complete target, without storing content.
    internal static IReadOnlyList<KeyValue> Describe(FileJournalIntent intent, ReadOnlySpan<byte> requestHash)
    {
        var details = new List<KeyValue> { new() { Name = "workspace_id", Value = IdText.Format(intent.WorkspaceId) } };
        var path = intent.RelativePath;
        for (var offset = 0; offset < path.Length;)
        {
            var count = Math.Min(400, path.Length - offset);
            if (offset + count < path.Length && char.IsHighSurrogate(path[offset + count - 1])) count--;
            details.Add(new KeyValue
            {
                Name = "target_path_" + details.Count.ToString("D2", System.Globalization.CultureInfo.InvariantCulture),
                Value = path.Substring(offset, count)
            });
            offset += count;
        }
        details.Add(new KeyValue { Name = "request_sha256", Value = Convert.ToHexStringLower(requestHash) });
        details.Add(new KeyValue { Name = "intended_sha256", Value = Convert.ToHexStringLower(intent.IntendedSha256) });
        details.Add(new KeyValue { Name = "intended_bytes", Value = intent.IntendedSize.ToString(System.Globalization.CultureInfo.InvariantCulture) });
        if (details.Count > 32) throw new ArgumentException("The approval target is too long.", nameof(intent));
        return details;
    }

    internal static void CheckStage(RecoveredPrivateStage stage, int platform, byte[] expectedIdentity,
        long size, byte[] expectedHash, CancellationToken cancellationToken)
    {
        var actual = RegisteredWorkspaces.RootIdentity.Encode(stage.Guard.ObjectIdentity, directory: false);
        if (actual.Platform != platform || !CryptographicOperations.FixedTimeEquals(actual.Bytes, expectedIdentity) ||
            !stage.Guard.MatchesExpectedContent(expectedHash, size, cancellationToken))
            throw new WorkspacePathException("file_identity_changed");
    }

    internal static void CheckTarget(FileJournalIntent intent, WorkspacePath root, WorkspaceWriteGuard? target, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var actualRoot = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var slash = intent.RelativePath.LastIndexOf('/');
        var parent = root.OpenDirectory(slash < 0 ? "" : intent.RelativePath[..slash]);
        var actualParent = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(parent));
        if (actualRoot.Platform != intent.IdentityPlatform || actualParent.Platform != intent.IdentityPlatform ||
            !CryptographicOperations.FixedTimeEquals(actualRoot.Bytes, intent.RootIdentity) ||
            !CryptographicOperations.FixedTimeEquals(actualParent.Bytes, intent.ParentIdentity))
            throw new WorkspacePathException("file_identity_changed");
        using var namedRoot = WorkspacePath.OpenRoot(root.RootPath, root.RootIdentity);
        if (intent.TargetIdentity is null)
        {
            if (target is not null) throw new InvalidOperationException("An absent target cannot have a guard.");
            try
            {
                _ = root.InspectEntry(intent.RelativePath);
                throw new WorkspacePathException("file_identity_changed");
            }
            catch (WorkspacePathException missing) when (missing.Reason == "native_2") { }
            return;
        }

        if (target is null || intent.OriginalSha256 is null || intent.OriginalSize is null)
            throw new InvalidOperationException("The existing target's held guard is required.");
        target.CheckIntact();
        var actualTarget = RegisteredWorkspaces.RootIdentity.Encode(target.ObjectIdentity, directory: false);
        var named = root.InspectEntry(intent.RelativePath);
        if (actualTarget.Platform != intent.IdentityPlatform ||
            !CryptographicOperations.FixedTimeEquals(actualTarget.Bytes, intent.TargetIdentity) ||
            named.Kind != WorkspaceEntryType.File || !target.ObjectIdentity.SameObject(named.Identity) || named.Identity.Links != 1 ||
            !target.MatchesExpectedContent(intent.OriginalSha256, intent.OriginalSize, token))
            throw new WorkspacePathException("file_identity_changed");
        target.CheckIntact();
    }

    private static bool BindingMatches(StoreReader reader, FileJournalIntent intent, byte[] approvalId)
    {
        using var command = reader.CreateCommand("""
            SELECT approval_id, identity_platform, root_identity, parent_identity, target_identity
            FROM file_private_approval_binding WHERE command_id = $id;
            """);
        command.Parameters.AddWithValue("$id", intent.CommandId);
        using var row = command.ExecuteReader();
        return row.Read() && CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(0), approvalId) &&
            row.GetInt32(1) == intent.IdentityPlatform &&
            CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(2), intent.RootIdentity) &&
            CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(3), intent.ParentIdentity) &&
            (intent.TargetIdentity is null ? row.IsDBNull(4) : !row.IsDBNull(4) &&
                CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(4), intent.TargetIdentity));
    }
}
