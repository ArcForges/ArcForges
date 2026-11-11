// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Files;

/// <summary>Metadata for one intended private stage; the file bytes never enter SQLite.</summary>
internal sealed record PrivateStageSpec(int Slot, string AbsolutePath, long ExpectedSize, byte[] ExpectedSha256);

internal enum PrivateStageReservationResult { Reserved, Existing, Conflict, Capacity }

/// <summary>
/// Durable capacity and opened-object identities for future named approval stages. This is not an approval or stage
/// producer: binding an empty object establishes FileService exclusion only. A producer must separately establish
/// restricted ownership/ACL, continuous native exclusion, exact-byte rehash, durable flushing and safe disposition.
/// </summary>
internal static partial class PrivateStageRegistry
{
    private const int MaximumRequestBytes = 245_760;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static (int Mutations, long Bytes) Usage(StoreReader reader) => FileStageCapacity.Durable(reader);

    internal static bool HasWorkspaceHold(StoreReader reader, ReadOnlySpan<byte> workspaceId)
    {
        ArgumentNullException.ThrowIfNull(reader);
        return HasSchema(reader) && reader.Scalar("""
            SELECT 1 FROM file_private_stage_reservation WHERE workspace_id = $id AND active = 1 LIMIT 1;
            """, ("$id", workspaceId.ToArray())) is not null;
    }

    // A small transaction-local snapshot avoids a SQLite lookup for each visited file. A larger registry is never
    // truncated: callers switch to an indexed lookup by the native identity of every opened candidate instead.
    internal static IReadOnlyList<RegisteredWorkspaces.RootIdentity>? TryLoadIdentitiesForUse(StoreReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if (!HasSchema(reader)) return [];
        var result = new List<RegisteredWorkspaces.RootIdentity>();
        using var command = reader.CreateCommand("""
            SELECT identity_platform, native_identity FROM file_private_stage_object
            WHERE native_identity IS NOT NULL ORDER BY command_id, slot LIMIT 129;
            """);
        using var row = command.ExecuteReader();
        while (row.Read())
        {
            if (result.Count == 128) return null;
            if (row.IsDBNull(0) || row.IsDBNull(1)) throw new InvalidDataException("Private stage identity registry is invalid.");
            var identity = new RegisteredWorkspaces.RootIdentity(row.GetInt32(0), (byte[])row.GetValue(1));
            RegisteredWorkspaces.RootIdentity.ValidateEncoding(identity.Platform, identity.Bytes);
            result.Add(identity);
        }
        return result;
    }

    // Existing small-registry callers may ask for a complete snapshot; never silently omit a retained object.
    internal static IReadOnlyList<RegisteredWorkspaces.RootIdentity> LoadIdentities(StoreReader reader) =>
        TryLoadIdentitiesForUse(reader) ?? throw new InvalidDataException("The private stage registry needs indexed protection.");

    internal static bool ContainsIdentity(StoreReader reader, WorkspaceObjectIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(reader);
        if (!identity.IsFile || !HasSchema(reader)) return false;
        // A newly added hard link does not change the identity of the protected native file.
        var encoded = RegisteredWorkspaces.RootIdentity.Encode(identity with { Links = 1 }, directory: false);
        return reader.Scalar("""
            SELECT 1 FROM file_private_stage_object WHERE identity_platform = $platform AND native_identity = $identity LIMIT 1;
            """, ("$platform", encoded.Platform), ("$identity", encoded.Bytes)) is not null;
    }

    /// <summary>
    /// Reserves a command and bounded stage capacity in a FULL transaction. Callers must provide the exact transmitted
    /// bytes, verified center caller and both current in-process and durable budget; no content is stored.
    /// </summary>
    internal static PrivateStageReservationResult Reserve(StoreTransaction transaction, FileStageBudget transientBudget,
        FileOperationKind kind, ReadOnlySpan<byte> commandId, ReadOnlySpan<byte> workspaceId, ReadOnlySpan<byte> correlationId, CenterCaller caller,
        ReadOnlySpan<byte> transmitted, IReadOnlyList<PrivateStageSpec> stages)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(transientBudget);
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(stages);
        StoreIds.Validate(commandId, nameof(commandId));
        StoreIds.Validate(workspaceId, nameof(workspaceId));
        StoreIds.Validate(correlationId, nameof(correlationId));
        if (commandId.IndexOfAnyExcept((byte)0) < 0 || workspaceId.IndexOfAnyExcept((byte)0) < 0 ||
            correlationId.IndexOfAnyExcept((byte)0) < 0 ||
            kind is not (FileOperationKind.Write or FileOperationKind.Edit) || CenterRouting.Shape(caller) is not null ||
            transmitted.Length is < 1 or > MaximumRequestBytes || stages.Count is < 1 or > 2 ||
            stages.Select(item => item.Slot).Distinct().Count() != stages.Count)
            throw new ArgumentException("A verified file request and bounded private stages are required.");
        long bytes = 0;
        foreach (var stage in stages)
        {
            if (stage.Slot is not (1 or 2) || !Path.IsPathFullyQualified(stage.AbsolutePath) ||
                stage.AbsolutePath.Contains('\0') || StrictUtf8.GetByteCount(stage.AbsolutePath) is < 1 or > 4096 ||
                stage.ExpectedSize is < 0 or > FileStageBudget.MaximumFileBytes || stage.ExpectedSha256.Length != 32)
                throw new ArgumentException("A private stage descriptor is invalid.", nameof(stages));
            bytes = checked(bytes + stage.ExpectedSize);
        }

        var facts = RequestBindsStages(kind, commandId, workspaceId, correlationId, transmitted, stages)
            ?? throw new ArgumentException("The stage metadata does not bind the actual file request.", nameof(stages));
        var digest = SHA256.HashData(transmitted);
        var method = kind == FileOperationKind.Write
            ? "arcforges.node.v1.FileService/WriteFile" : "arcforges.node.v1.FileService/EditFile";
        using (var select = transaction.CreateCommand("""
            SELECT s.workspace_id, s.request_sha256, s.caller, d.method, s.kind, s.correlation_id,
                   s.relative_path, s.expected_absent, s.expected_sha256, s.expected_occurrences
            FROM file_private_stage_reservation s JOIN command_dedup d ON d.command_id = s.command_id
            WHERE s.command_id = $id;
            """))
        {
            select.Parameters.AddWithValue("$id", commandId.ToArray());
            using var row = select.ExecuteReader();
            if (row.Read())
            {
                var previous = CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2));
                var correlation = (byte[])row.GetValue(5);
                var sameExpected = facts.ExpectedSha256 is null ? row.IsDBNull(8) :
                    !row.IsDBNull(8) && CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(8), facts.ExpectedSha256);
                var sameOccurrences = facts.ExpectedOccurrences is null ? row.IsDBNull(9) :
                    !row.IsDBNull(9) && row.GetInt64(9) == facts.ExpectedOccurrences.Value;
                return row.GetString(3) == method && row.GetInt32(4) == (int)kind &&
                    ((byte[])row.GetValue(0)).AsSpan().SequenceEqual(workspaceId) &&
                    CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(1), digest) &&
                    correlation.Length == 16 && correlation.AsSpan().IndexOfAnyExcept((byte)0) >= 0 &&
                    (!facts.HasCorrelation || correlation.AsSpan().SequenceEqual(correlationId)) &&
                    row.GetString(6) == facts.Path && (row.GetInt32(7) != 0) == facts.ExpectedAbsent &&
                    sameExpected && sameOccurrences && CenterRouting.SameFileCaller(previous, caller)
                    ? PrivateStageReservationResult.Existing : PrivateStageReservationResult.Conflict;
            }
        }

        if (transaction.Scalar("""
            SELECT 1 FROM workspace WHERE workspace_id = $id AND kind = 1 AND state = 2 AND removed_at IS NULL;
            """, ("$id", workspaceId.ToArray())) is null)
            throw new InvalidOperationException("The registered workspace is unavailable.");
        // An anonymous lease or an earlier journal for this command cannot be reinterpreted as a new named stage.
        if (transientBudget.HasCommand(commandId) || transaction.Scalar(
            "SELECT 1 FROM command_dedup WHERE command_id = $id;", ("$id", commandId.ToArray())) is not null)
            return PrivateStageReservationResult.Conflict;
        var combined = transientBudget.CombinedUsage(transaction);
        if (combined.Active >= FileStageBudget.MaximumMutations || combined.Bytes > FileStageBudget.MaximumBytes ||
            bytes > FileStageBudget.MaximumBytes - combined.Bytes)
            return PrivateStageReservationResult.Capacity;
        var decision = CommandDeduplication.Begin(transaction, commandId, method, digest, Origin.Remote);
        if (decision.Status != DedupStatus.Execute) return PrivateStageReservationResult.Conflict;

        transaction.Execute("""
            INSERT INTO file_private_stage_reservation
              (command_id, workspace_id, kind, correlation_id, relative_path, expected_absent, expected_sha256,
               expected_occurrences, request_sha256, caller, reserved_bytes, created_at)
            VALUES ($id, $workspace, $kind, $correlation, $path, $absent, $expected, $occurrences, $digest, $caller, $bytes, $now);
            """, ("$id", commandId.ToArray()), ("$workspace", workspaceId.ToArray()), ("$kind", (int)kind),
            ("$correlation", correlationId.ToArray()), ("$path", facts.Path), ("$absent", facts.ExpectedAbsent ? 1 : 0),
            ("$expected", facts.ExpectedSha256), ("$occurrences", facts.ExpectedOccurrences is { } count ? (long)count : null),
            ("$digest", digest), ("$caller", Sanitize(caller).ToByteArray()), ("$bytes", bytes), ("$now", transaction.NowMicroseconds));
        foreach (var stage in stages)
            transaction.Execute("""
                INSERT INTO file_private_stage_object (command_id, slot, stage_path, expected_size, expected_sha256)
                VALUES ($id, $slot, $path, $size, $digest);
                """, ("$id", commandId.ToArray()), ("$slot", stage.Slot), ("$path", stage.AbsolutePath),
                ("$size", stage.ExpectedSize), ("$digest", stage.ExpectedSha256));
        return PrivateStageReservationResult.Reserved;
    }

    /// <summary>
    /// Binds a still-empty held object to its already durable reservation. This permits query exclusion, not writing
    /// stage bytes: a producer must independently prove private security and native exclusion before doing so.
    /// </summary>
    internal static void BindEmptyForProtection(StoreTransaction transaction, ReadOnlySpan<byte> commandId, int slot,
        WorkspacePath workspaceRoot, WorkspacePath stageDirectory, string name, WorkspaceWriteGuard held,
        CancellationToken cancellationToken)
    {
        RequireFull(transaction);
        ArgumentNullException.ThrowIfNull(workspaceRoot);
        ArgumentNullException.ThrowIfNull(stageDirectory);
        ArgumentNullException.ThrowIfNull(held);
        var components = WorkspacePath.Components(name);
        if (components.Length != 1 || slot is not (1 or 2)) throw new ArgumentException("A direct stage name is required.", nameof(name));
        cancellationToken.ThrowIfCancellationRequested();
        held.CheckIntact();
        if (held.ObserveLength(cancellationToken) != 0) throw new InvalidOperationException("A stage must be empty before registration.");
        var actual = held.ObjectIdentity;
        var root = workspaceRoot.RootIdentity;
        if (!actual.IsFile || actual.Links != 1 || actual.Volume != root.Volume ||
            OperatingSystem.IsLinux() && actual.High != root.High ||
            stageDirectory.RootIdentity.Volume != root.Volume ||
            OperatingSystem.IsLinux() && stageDirectory.RootIdentity.High != root.High)
            throw new InvalidOperationException("The held stage is not on the registered volume.");
        using var recheckedDirectory = WorkspacePath.OpenRoot(stageDirectory.RootPath, stageDirectory.RootIdentity);
        var named = stageDirectory.InspectEntry(name);
        if (named.Kind != WorkspaceEntryType.File || !named.Identity.SameObject(actual) || named.Identity.Links != 1)
            throw new InvalidOperationException("The stage name no longer identifies the held object.");
        var workspace = RegisteredWorkspaces.RootIdentity.Encode(root);
        var stage = RegisteredWorkspaces.RootIdentity.Encode(actual, directory: false);
        var parent = RegisteredWorkspaces.RootIdentity.Encode(stageDirectory.RootIdentity);
        if (parent.Platform != stage.Platform) throw new InvalidOperationException("The stage directory is on another platform.");
        using var command = transaction.CreateCommand("""
            SELECT o.stage_path, o.identity_platform, o.native_identity, w.platform, w.native_identity
            FROM file_private_stage_object o
            JOIN file_private_stage_reservation r ON r.command_id = o.command_id
            JOIN workspace_root_identity w ON w.workspace_id = r.workspace_id AND w.released_at IS NULL
            WHERE o.command_id = $id AND o.slot = $slot AND r.active = 1;
            """);
        command.Parameters.AddWithValue("$id", commandId.ToArray());
        command.Parameters.AddWithValue("$slot", slot);
        using (var row = command.ExecuteReader())
        {
            if (!row.Read() || !row.IsDBNull(1) || !row.IsDBNull(2) || row.GetInt32(3) != workspace.Platform ||
                !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(4), workspace.Bytes) ||
                !string.Equals(row.GetString(0), Path.Combine(stageDirectory.RootPath, name),
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidOperationException("The stage reservation or registered root does not match.");
        }
        held.CheckIntact();
        cancellationToken.ThrowIfCancellationRequested();
        if (transaction.Execute("""
            UPDATE file_private_stage_object SET phase = 2, identity_platform = $platform, native_identity = $identity,
                                                 parent_identity = $parent
            WHERE command_id = $id AND slot = $slot AND phase = 1 AND native_identity IS NULL AND parent_identity IS NULL;
            """, ("$platform", stage.Platform), ("$identity", stage.Bytes), ("$parent", parent.Bytes),
            ("$id", commandId.ToArray()), ("$slot", slot)) != 1)
            throw new InvalidOperationException("The stage identity was already bound.");
    }

    /// <summary>
    /// After the empty identity was committed, writes and rehashes that exact held stage and commits READY with FULL
    /// durability. This is a separate store operation and must not be nested in another writer transaction. Neither
    /// READY nor this method grants approval or performs a target effect; failures retain the prior identity and bytes.
    /// </summary>
    internal static void WriteBoundStage(NodeStore store, ReadOnlySpan<byte> commandId, int slot, CenterCaller caller,
        ReadOnlySpan<byte> transmitted, WorkspaceEmptyNamedStage stage, ReadOnlySpan<byte> content,
        CancellationToken cancellationToken, Action? afterFirstWrite = null)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(stage);
        StoreIds.Validate(commandId, nameof(commandId));
        if (slot is not (1 or 2) || CenterRouting.Shape(caller) is not null || transmitted.Length is < 1 or > MaximumRequestBytes ||
            content.Length > FileStageBudget.MaximumFileBytes)
            throw new ArgumentException("A verified request and bounded stage are required.");
        cancellationToken.ThrowIfCancellationRequested();
        if (stage.DurabilityEvidence is not (NamedStageDurabilityEvidence.LinuxFileAndDirectoryFsync or
            NamedStageDurabilityEvidence.WindowsNtfsWriteThroughAndFileFlush))
            throw new WorkspacePathException("file_guard_unavailable");

        // Bind immutable snapshots to the exact persisted facts; clear in-memory copies containing request/body bytes.
        var id = commandId.ToArray();
        var request = transmitted.ToArray();
        var body = content.ToArray();
        var stableCaller = Sanitize(caller);
        try
        {
            var requestHash = SHA256.HashData(request);
            var contentHash = SHA256.HashData(body);
            store.Write(transaction =>
            {
                RequireFull(transaction);
                cancellationToken.ThrowIfCancellationRequested();
                stage.Guard.CheckIntact();
                var actual = RegisteredWorkspaces.RootIdentity.Encode(stage.Guard.ObjectIdentity, directory: false);
                using (var query = transaction.CreateCommand("""
                    SELECT o.phase, o.stage_path, o.identity_platform, o.native_identity, o.expected_size, o.expected_sha256,
                           r.request_sha256, r.caller
                    FROM file_private_stage_object o JOIN file_private_stage_reservation r ON r.command_id = o.command_id
                    WHERE o.command_id = $id AND o.slot = $slot AND r.active = 1;
                    """))
                {
                    query.Parameters.AddWithValue("$id", id);
                    query.Parameters.AddWithValue("$slot", slot);
                    using var row = query.ExecuteReader();
                    if (!row.Read() || row.GetInt32(0) != 2 || row.IsDBNull(2) || row.IsDBNull(3) ||
                        row.GetInt32(2) != actual.Platform || actual.Platform != stage.Identity.Platform ||
                        !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(3), actual.Bytes) ||
                        !CryptographicOperations.FixedTimeEquals(actual.Bytes, stage.Identity.Bytes) ||
                        !string.Equals(Path.GetFileName(row.GetString(1)), stage.Name,
                            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) ||
                        row.GetInt64(4) != body.Length ||
                        !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(5), contentHash) ||
                        !CryptographicOperations.FixedTimeEquals((byte[])row.GetValue(6), requestHash) ||
                        !CenterRouting.SameFileCaller(CenterCaller.Parser.ParseFrom((byte[])row.GetValue(7)), stableCaller))
                        throw new InvalidOperationException("The committed private stage does not bind this request and object.");
                }

                // The checked object ID was committed by a previous FULL transaction before any body is exposed.
                stage.Guard.WritePrivateNamedStage(body, contentHash, cancellationToken, afterFirstWrite);
                cancellationToken.ThrowIfCancellationRequested();
                stage.Guard.CheckIntact();
                if (transaction.Execute("""
                    UPDATE file_private_stage_object SET phase = 3
                    WHERE command_id = $id AND slot = $slot AND phase = 2;
                    """, ("$id", id), ("$slot", slot)) != 1)
                    throw new InvalidOperationException("The private stage could not become ready.");
            }, CommitDurability.Full);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(request);
            CryptographicOperations.ZeroMemory(body);
        }
    }

    private sealed record StageFacts(string Path, bool ExpectedAbsent, byte[]? ExpectedSha256,
        uint? ExpectedOccurrences, bool HasCorrelation);

    private static StageFacts? RequestBindsStages(FileOperationKind kind, ReadOnlySpan<byte> commandId,
        ReadOnlySpan<byte> workspaceId, ReadOnlySpan<byte> correlationId, ReadOnlySpan<byte> transmitted,
        IReadOnlyList<PrivateStageSpec> stages)
    {
        var intended = stages.SingleOrDefault(item => item.Slot == 2);
        var original = stages.SingleOrDefault(item => item.Slot == 1);
        if (intended is null) return null;
        try
        {
            if (kind == FileOperationKind.Write)
            {
                var request = FileServiceWriteFileRequest.Parser.ParseFrom(transmitted.ToArray());
                if (!NodeShapes.IsValid(request) || request.Meta?.CommandId?.Value.Span.SequenceEqual(commandId) != true ||
                    request.Meta.CorrelationId is { } correlation && !correlation.Value.Span.SequenceEqual(correlationId) ||
                    request.Path?.WorkspaceId?.Value.Span.SequenceEqual(workspaceId) != true || !request.Path.HasPath ||
                    !request.HasData || intended.ExpectedSize != request.Data.Length ||
                    !CryptographicOperations.FixedTimeEquals(intended.ExpectedSha256, SHA256.HashData(request.Data.Span)))
                    return null;
                _ = WorkspacePath.Components(request.Path.Path);
                if (request.HasExpectedAbsent && request.ExpectedAbsent && original is null)
                    return new StageFacts(request.Path.Path, true, null, null, request.Meta.CorrelationId is not null);
                return request.HasExpectedSha256 && original is not null && request.ExpectedSha256.Length == 32 &&
                    CryptographicOperations.FixedTimeEquals(original.ExpectedSha256, request.ExpectedSha256.Span)
                    ? new StageFacts(request.Path.Path, false, request.ExpectedSha256.ToByteArray(), null, request.Meta.CorrelationId is not null)
                    : null;
            }
            var edit = FileServiceEditFileRequest.Parser.ParseFrom(transmitted.ToArray());
            if (!NodeShapes.IsValid(edit) || edit.Meta?.CommandId?.Value.Span.SequenceEqual(commandId) != true ||
                edit.Meta.CorrelationId is { } editCorrelation && !editCorrelation.Value.Span.SequenceEqual(correlationId) ||
                edit.Path?.WorkspaceId?.Value.Span.SequenceEqual(workspaceId) != true || !edit.Path.HasPath ||
                !edit.HasExpectedSha256 || edit.ExpectedSha256.Length != 32 || !edit.HasExpectedOccurrences || original is null ||
                !CryptographicOperations.FixedTimeEquals(original.ExpectedSha256, edit.ExpectedSha256.Span))
                return null;
            _ = WorkspacePath.Components(edit.Path.Path);
            return new StageFacts(edit.Path.Path, false, edit.ExpectedSha256.ToByteArray(), edit.ExpectedOccurrences,
                edit.Meta.CorrelationId is not null);
        }
        catch (Exception exception) when (exception is InvalidProtocolBufferException or WorkspacePathException or EncoderFallbackException)
        {
            return null;
        }
    }

    internal static bool HasSchema(StoreReader reader)
    {
        var value = reader.Scalar("SELECT schema_version FROM store_meta WHERE singleton = 1;");
        if (value is not long version || version < 1) throw new InvalidDataException("Store schema metadata is unavailable.");
        return version >= 8;
    }

    private static void RequireFull(StoreTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        if (transaction.Durability != CommitDurability.Full || !HasSchema(transaction))
            throw new InvalidOperationException("Private stage metadata requires the current schema and synchronous=FULL.");
    }

    private static CenterCaller Sanitize(CenterCaller caller)
    {
        static Id? Copy(Id? id) => id is null ? null : new Id { Value = ByteString.CopyFrom(id.Value.Span) };
        var result = new CenterCaller { Kind = caller.Kind, AccountId = Copy(caller.AccountId) };
        if (caller.Kind == CenterCallerKind.AccountSession)
        {
            result.UserId = Copy(caller.UserId);
            result.SessionId = Copy(caller.SessionId);
        }
        else
        {
            result.RelayingNodeId = Copy(caller.RelayingNodeId);
            result.LocalOrigin = caller.LocalOrigin;
            result.LocalSessionId = Copy(caller.LocalSessionId);
        }
        return result;
    }
}
