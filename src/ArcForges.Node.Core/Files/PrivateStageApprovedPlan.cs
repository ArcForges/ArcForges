// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Files;

/// <summary>The already captured, content-free facts for a local HUMAN-approved file operation.</summary>
internal sealed record PrivateStageApprovedPlan(byte[] ApprovalId, FileJournalIntent Intent, byte[] RequestSha256,
    long ApprovalExpiresAt, uint? ExpectedOccurrences, bool Active);

internal static class PrivateStageApprovedPlans
{
    /// <summary>
    /// Reads a real APPROVED record and its immutable reservation/binding. A caller must still check validation time,
    /// current policy, native objects and journal immediately before an effect; no original channel is assumed live.
    /// </summary>
    internal static PrivateStageApprovedPlan? Read(StoreReader reader, ReadOnlySpan<byte> approvalId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        StoreIds.Validate(approvalId, nameof(approvalId));
        var approval = Approvals.Get(reader, approvalId);
        if (approval is null || approval.State != ApprovalState.Approved) return null;
        if (approval.Request.Length != 17 || approval.Request[0] != 1 || approval.RequestDigest.Length != 32)
            throw new InvalidDataException("The file approval reference is invalid.");
        var id = approval.Request.AsSpan(1, 16).ToArray();
        if (approval.View.Requester is not { Origin: Origin.Remote, CenterCaller: { } approvedCaller, RemoteCommandId: { } remote } ||
            !remote.Value.Span.SequenceEqual(id) || CenterRouting.Shape(approvedCaller) is not null)
            throw new InvalidDataException("The file approval requester is invalid.");
        using var command = reader.CreateCommand("""
            SELECT r.kind, r.workspace_id, r.correlation_id, r.relative_path, r.expected_absent, r.expected_sha256,
                   r.expected_occurrences, r.request_sha256, r.caller, b.identity_platform, b.root_identity,
                   b.parent_identity, b.target_identity, a.expires_at, d.method, d.payload_digest, d.origin,
                   o2.phase, o2.identity_platform, o2.native_identity, o2.expected_size, o2.expected_sha256,
                   o1.phase, o1.identity_platform, o1.native_identity, o1.expected_size, o1.expected_sha256, r.active
            FROM file_private_approval_binding b
            JOIN file_private_stage_reservation r ON r.command_id = b.command_id
            JOIN approval a ON a.approval_id = b.approval_id AND a.command_id = b.command_id
            JOIN command_dedup d ON d.command_id = b.command_id
            JOIN file_private_stage_object o2 ON o2.command_id = b.command_id AND o2.slot = 2
            LEFT JOIN file_private_stage_object o1 ON o1.command_id = b.command_id AND o1.slot = 1
            WHERE b.approval_id = $approval AND b.command_id = $id;
            """);
        command.Parameters.AddWithValue("$approval", approvalId.ToArray());
        command.Parameters.AddWithValue("$id", id);
        using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        var kind = (FileOperationKind)row.GetInt32(0);
        var expectedMethod = kind == FileOperationKind.Write ? "FileService.WriteFile" :
            kind == FileOperationKind.Edit ? "FileService.EditFile" : throw new InvalidDataException("Unknown file approval kind.");
        var caller = CenterCaller.Parser.ParseFrom((byte[])row.GetValue(8));
        var digest = (byte[])row.GetValue(7);
        var platform = row.GetInt32(9);
        var root = (byte[])row.GetValue(10);
        var parent = (byte[])row.GetValue(11);
        var absent = row.GetInt32(4) != 0;
        var target = row.IsDBNull(12) ? null : (byte[])row.GetValue(12);
        var originalHash = row.IsDBNull(5) ? null : (byte[])row.GetValue(5);
        var occurrences = row.IsDBNull(6) ? (uint?)null : checked((uint)row.GetInt64(6));
        if (approval.View.Operation != expectedMethod || row.GetString(14) != "arcforges.node.v1." + expectedMethod.Replace('.', '/') ||
            row.GetInt32(16) != (int)Origin.Remote || digest.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(digest, approval.RequestDigest) ||
            !CryptographicOperations.FixedTimeEquals(digest, (byte[])row.GetValue(15)) ||
            !CenterRouting.SameFileCaller(caller, approvedCaller) || absent != (target is null) ||
            row.GetInt32(17) != 3 || row.IsDBNull(18) || row.GetInt32(18) != platform || row.IsDBNull(19) ||
            row.GetInt64(20) is < 0 or > 4 * 1024 * 1024 || ((byte[])row.GetValue(21)).Length != 32 ||
            (kind == FileOperationKind.Write ? occurrences is not null : occurrences is not (>= 1 and <= 1000)))
            throw new InvalidDataException("The file approval binding is invalid.");
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, root);
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, parent);
        if (target is not null) RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, target);
        var intendedId = (byte[])row.GetValue(19);
        RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, intendedId);
        long? originalSize = null;
        byte[]? originalId = null;
        if (absent)
        {
            if (!row.IsDBNull(22) || originalHash is not null || kind != FileOperationKind.Write)
                throw new InvalidDataException("An absent target has unexpected stage metadata.");
        }
        else
        {
            if (row.IsDBNull(22) || row.GetInt32(22) != 3 || row.IsDBNull(23) || row.GetInt32(23) != platform ||
                row.IsDBNull(24) || row.IsDBNull(25) || row.IsDBNull(26) || originalHash is not { Length: 32 } ||
                !CryptographicOperations.FixedTimeEquals(originalHash, (byte[])row.GetValue(26)))
                throw new InvalidDataException("The preimage stage is invalid.");
            originalId = (byte[])row.GetValue(24);
            RegisteredWorkspaces.RootIdentity.ValidateEncoding(platform, originalId);
            originalSize = row.GetInt64(25);
            if (originalSize is < 0 or > 4 * 1024 * 1024) throw new InvalidDataException("The preimage size is invalid.");
        }
        var intent = new FileJournalIntent(kind, id, (byte[])row.GetValue(2), caller, (byte[])row.GetValue(1), row.GetString(3),
            platform, root, parent, target, originalSize, originalHash, originalId, row.GetInt64(20),
            (byte[])row.GetValue(21), intendedId);
        return new PrivateStageApprovedPlan(approvalId.ToArray(), intent, digest, row.GetInt64(13), occurrences, row.GetInt32(27) != 0);
    }
}
