// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Store;

internal enum StoredRemoteGrantScope
{
    Sandbox,
    Provision,
}

internal enum StoredRemoteGrantState
{
    Active = 1,
    Revoked = 2,
    Expired = 3,
}

internal sealed record StoredRemoteGrant(
    string GrantId,
    string OwnerId,
    string EnrollmentId,
    StoredRemoteGrantScope Scope,
    string? SandboxId,
    string? ParentGrantId,
    long? ParentGrantRevision,
    long Revision,
    StoredRemoteGrantState State,
    string PolicyJson,
    string RevocationAnchorCommandId,
    long? TemplateRevision,
    string? CreationTemplateJson,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt);

internal sealed record StoredGrantExpiration(string GrantId, string EnrollmentId, long Revision);

/// <summary>Owner-scoped grants in the existing schema 16 tables.</summary>
internal static class RemoteGrantRecords
{
    private const string Visible = """
        json_extract(g.policy_json,'$.version')=1 AND json_extract(g.policy_json,'$.ownerId')=$owner
        AND (g.scope_kind='provision' OR EXISTS(
            SELECT 1 FROM sandbox AS owned WHERE owned.sandbox_id=g.sandbox_id AND owned.owner_id=$owner
        ))
        """;

    private const string Filter = """
         AND ($sandbox IS NULL OR g.sandbox_id=$sandbox)
         AND ($enrollment IS NULL OR g.enrollment_id=$enrollment)
        """;

    private const string Select = """
        SELECT g.grant_id, g.enrollment_id, g.scope_kind, g.sandbox_id, g.parent_grant_id, g.revision, g.state,
               json_extract(g.policy_json,'$.policy'), json_extract(g.policy_json,'$.revocationAnchorCommandId'),
               json_extract(g.policy_json,'$.parentGrantRevision'), g.template_revision, g.creation_template_json,
               g.created_local_utc, g.expires_utc, g.revoked_utc
        FROM remote_grant AS g WHERE
        """ + " " + Visible;

    internal static StoredRemoteGrant? Get(StoreReader reader, string ownerId, string grantId)
    {
        using var command = reader.CreateCommand(Select + " AND g.grant_id=$id;");
        StoreReader.Bind(command, [("$owner", ownerId), ("$id", grantId)]);
        using var row = command.ExecuteReader();
        return row.Read() ? Read(row, ownerId) : null;
    }

    internal static IReadOnlyList<StoredRemoteGrant> List(StoreReader reader, string ownerId, string? sandboxId,
        string? enrollmentId, string? afterGrantId, int limit)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);
        using var command = reader.CreateCommand(Select + Filter + """
             AND ($after IS NULL OR g.grant_id>$after) ORDER BY g.grant_id LIMIT $limit;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$sandbox", sandboxId), ("$enrollment", enrollmentId),
            ("$after", afterGrantId), ("$limit", limit)]);
        using var rows = command.ExecuteReader();
        var result = new List<StoredRemoteGrant>();
        while (rows.Read())
        {
            result.Add(Read(rows, ownerId));
        }

        return result;
    }

    /// <summary>Every creation and state change advances the matching owner's filtered catalog.</summary>
    internal static long ListVersion(StoreReader reader, string ownerId, string? sandboxId, string? enrollmentId) =>
        (long)reader.Scalar("SELECT coalesce(sum(g.revision),0) FROM remote_grant AS g WHERE " + Visible + Filter,
            ("$owner", ownerId), ("$sandbox", sandboxId), ("$enrollment", enrollmentId))!;

    internal static bool IsActiveRevision(StoreReader reader, string ownerId, string grantId, long revision, DateTimeOffset now) =>
        Equals(reader.Scalar("SELECT EXISTS(SELECT 1 FROM remote_grant AS g WHERE " + Visible + """
             AND g.grant_id=$id AND g.revision=$revision AND g.state=1 AND (g.expires_utc IS NULL OR g.expires_utc>$now));
            """, ("$owner", ownerId), ("$id", grantId), ("$revision", revision), ("$now", FormatTime(now))), 1L);

    internal static bool Exists(StoreReader reader, string grantId) =>
        Equals(reader.Scalar("SELECT EXISTS(SELECT 1 FROM remote_grant WHERE grant_id=$id);", ("$id", grantId)), 1L);

    internal static bool MatchesProvisionSettlement(StoreReader reader, string ownerId, string sandboxId, string commandId,
        DurableProvisionBinding binding, bool succeeded)
    {
        using var command = reader.CreateCommand("""
            SELECT count(*), coalesce(sum(CASE
                WHEN g.grant_id=$child AND g.parent_grant_id=$parent
                 AND json_extract(g.policy_json,'$.parentGrantRevision')=$parentRevision
                 AND g.revision=1 AND g.state=1 AND s.state=2 THEN 1 ELSE 0 END),0)
            FROM remote_grant AS g JOIN sandbox AS s ON s.sandbox_id=g.sandbox_id WHERE
            """ + " " + Visible + """
             AND g.scope_kind='sandbox' AND g.sandbox_id=$sandbox
             AND json_extract(g.policy_json,'$.revocationAnchorCommandId')=$command;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$sandbox", sandboxId), ("$command", commandId),
            ("$child", binding.DerivedGrantId), ("$parent", binding.ParentGrantId), ("$parentRevision", binding.ParentGrantRevision)]);
        using var row = command.ExecuteReader();
        return row.Read() && (succeeded ? row.GetInt64(0) == 1 && row.GetInt64(1) == 1 : row.GetInt64(0) == 0);
    }

    internal static bool HasActiveDerivedGrant(StoreReader reader, string ownerId, string sandboxId, string commandId,
        string parentGrantId, long parentGrantRevision, DateTimeOffset now) =>
        Equals(reader.Scalar("""
            SELECT EXISTS(
                SELECT 1 FROM remote_grant AS g JOIN remote_grant AS p ON p.grant_id=g.parent_grant_id
                JOIN sandbox AS s ON s.sandbox_id=g.sandbox_id
                WHERE
            """ + " " + Visible + """
                 AND g.scope_kind='sandbox' AND g.sandbox_id=$sandbox AND g.state=1 AND s.state=2
                 AND json_extract(g.policy_json,'$.revocationAnchorCommandId')=$command
                 AND json_extract(g.policy_json,'$.parentGrantRevision')=$parentRevision
                 AND p.grant_id=$parent AND p.scope_kind='provision' AND p.state=1
                 AND p.revision=$parentRevision AND p.enrollment_id=g.enrollment_id
                 AND json_extract(p.policy_json,'$.version')=1 AND json_extract(p.policy_json,'$.ownerId')=$owner
                 AND (g.expires_utc IS NULL OR g.expires_utc>$now) AND (p.expires_utc IS NULL OR p.expires_utc>$now)
            );
            """, ("$owner", ownerId), ("$sandbox", sandboxId), ("$command", commandId), ("$parent", parentGrantId),
            ("$parentRevision", parentGrantRevision), ("$now", FormatTime(now))), 1L);

    // Capacity follows the settled state. An elapsed wall-clock TTL alone cannot
    // release authority's safety slot, since an unobserved clock can move backward.
    internal static long CountActive(StoreReader reader, string ownerId) =>
        (long)reader.Scalar("SELECT count(*) FROM remote_grant AS g WHERE " + Visible + """
             AND g.state=1;
            """, ("$owner", ownerId))!;

    internal static IReadOnlyList<StoredGrantExpiration> DueExpirations(StoreReader reader, string ownerId, DateTimeOffset now)
    {
        using var command = reader.CreateCommand("""
            SELECT g.grant_id,g.enrollment_id,g.revision FROM remote_grant AS g WHERE
            """ + " " + Visible + """
             AND g.state=1 AND g.expires_utc IS NOT NULL AND g.expires_utc<=$now ORDER BY g.grant_id;
            """);
        StoreReader.Bind(command, [("$owner", ownerId), ("$now", FormatTime(now))]);
        using var rows = command.ExecuteReader();
        var due = new List<StoredGrantExpiration>();
        while (rows.Read())
        {
            due.Add(new(rows.GetString(0), rows.GetString(1), rows.GetInt64(2)));
        }

        return due;
    }

    internal static void ObserveExpiration(StoreTransaction transaction, string ownerId, StoredGrantExpiration due, DateTimeOffset observedAt)
    {
        RequireFull(transaction);
        long revision = checked(due.Revision + 1);
        string observed = FormatTime(observedAt);
        int changed = transaction.Execute("""
            UPDATE remote_grant AS g SET state=3,revision=$next WHERE
            """ + " " + Visible + """
             AND g.grant_id=$id AND g.enrollment_id=$enrollment AND g.revision=$revision AND g.state=1
             AND g.expires_utc IS NOT NULL AND g.expires_utc<=$now;
            """, ("$owner", ownerId), ("$id", due.GrantId), ("$enrollment", due.EnrollmentId), ("$revision", due.Revision),
            ("$next", revision), ("$now", observed));
        if (changed != 1)
        {
            throw new InvalidOperationException("The observed grant expiry changed before its fenced settlement.");
        }

        transaction.Execute("""
            INSERT INTO audit(actor_id,origin,command_id,method,aggregate_id,effect_certainty,reason_code,created_utc,metadata_json)
            VALUES('node','system',NULL,'RemoteGrant.Expire',$grant,2,'grant_expired',$now,
                json_object('ownerId',$owner,'enrollmentId',$enrollment,'revision',$revision));
            """, ("$grant", due.GrantId), ("$now", observed), ("$owner", ownerId), ("$enrollment", due.EnrollmentId),
            ("$revision", revision));
    }

    internal static int Insert(StoreTransaction transaction, StoredRemoteGrant grant)
    {
        RequireFull(transaction);
        Validate(grant);
        if (grant.Revision != 1)
        {
            throw new ArgumentException("A new remote grant starts at revision one.", nameof(grant));
        }

        // Child insertion is performed after READY is written in the same FULL transaction. The
        // parent must still authorize this exact derivation, including its admitted revision.
        return transaction.Execute("""
            INSERT INTO remote_grant(grant_id,sandbox_id,scope_kind,parent_grant_id,template_revision,
                creation_template_json,enrollment_id,revision,state,policy_json,created_local_utc,expires_utc,revoked_utc)
            SELECT $id,$sandbox,$scope,$parent,$templateRevision,$template,$enrollment,$revision,1,
                json_object('version',1,'ownerId',$owner,'revocationAnchorCommandId',$anchor,
                    'parentGrantRevision',$parentRevision,'policy',json($policy)),
                $created,$expires,NULL
            WHERE NOT EXISTS(SELECT 1 FROM remote_grant WHERE grant_id=$id)
              AND ($expires IS NULL OR $expires>$now)
              AND ($scope='provision' OR EXISTS(
                SELECT 1 FROM sandbox WHERE sandbox_id=$sandbox AND owner_id=$owner AND state=2))
              AND ($parent IS NULL OR EXISTS(
                SELECT 1 FROM remote_grant AS p
                WHERE p.grant_id=$parent AND p.scope_kind='provision' AND p.parent_grant_id IS NULL AND p.state=1
                  AND json_extract(p.policy_json,'$.version')=1 AND json_extract(p.policy_json,'$.ownerId')=$owner
                  AND p.enrollment_id=$enrollment AND p.revision=$parentRevision
                  AND (p.expires_utc IS NULL OR ($expires IS NOT NULL AND $expires<=p.expires_utc AND p.expires_utc>$now))
              ));
            """, Parameters(grant, grant.CreatedAt));
    }

    internal static int Replace(StoreTransaction transaction, StoredRemoteGrant grant, long expectedRevision,
        DateTimeOffset? authorizedAt = null)
    {
        RequireFull(transaction);
        Validate(grant);
        ValidateExpected(expectedRevision);
        if (grant.Revision != expectedRevision + 1)
        {
            throw new ArgumentException("A remote grant replacement advances one revision.", nameof(grant));
        }

        using var command = transaction.CreateCommand("""
            UPDATE remote_grant AS g
            SET revision=$revision, template_revision=$templateRevision, creation_template_json=$template, expires_utc=$expires,
                policy_json=json_object('version',1,'ownerId',$owner,'revocationAnchorCommandId',$anchor,
                    'parentGrantRevision',$parentRevision,'policy',json($policy))
            WHERE
            """ + " " + Visible + """
             AND g.grant_id=$id AND g.revision=$expected AND g.state=1
             AND (g.expires_utc IS NULL OR g.expires_utc>$now) AND ($expires IS NULL OR $expires>$now)
             AND g.scope_kind=$scope AND g.sandbox_id IS $sandbox AND g.parent_grant_id IS $parent
             AND g.enrollment_id=$enrollment AND g.created_local_utc=$created
             AND json_extract(g.policy_json,'$.revocationAnchorCommandId')=$anchor
             AND json_extract(g.policy_json,'$.parentGrantRevision') IS $parentRevision
             AND ((g.template_revision IS $templateRevision AND g.creation_template_json IS $template)
                OR (g.scope_kind='provision' AND $templateRevision=g.template_revision+1))
             AND ($parent IS NULL OR EXISTS(
                SELECT 1 FROM remote_grant AS p
                WHERE p.grant_id=$parent AND p.scope_kind='provision' AND p.parent_grant_id IS NULL AND p.state=1
                  AND json_extract(p.policy_json,'$.version')=1 AND json_extract(p.policy_json,'$.ownerId')=$owner
                  AND p.enrollment_id=$enrollment AND p.revision>=$parentRevision
                  AND (p.expires_utc IS NULL OR ($expires IS NOT NULL AND $expires<=p.expires_utc AND p.expires_utc>$now))
             ));
            """);
        StoreReader.Bind(command, Parameters(grant, authorizedAt ?? transaction.Clock.GetUtcNow()));
        StoreReader.Bind(command, [("$expected", expectedRevision)]);
        return command.ExecuteNonQuery();
    }

    internal static int Revoke(StoreTransaction transaction, string ownerId, string grantId, long expectedRevision,
        DateTimeOffset now, string? enrollmentId = null)
    {
        RequireFull(transaction);
        ValidateExpected(expectedRevision);
        return transaction.Execute("""
            UPDATE remote_grant AS g SET state=2, revoked_utc=$now, revision=revision+1 WHERE
            """ + " " + Visible + """
             AND g.grant_id=$id AND g.revision=$expected AND g.state=1 AND (g.expires_utc IS NULL OR g.expires_utc>$now)
             AND ($enrollment IS NULL OR g.enrollment_id=$enrollment);
            """, ("$owner", ownerId), ("$id", grantId), ("$expected", expectedRevision), ("$now", FormatTime(now)),
            ("$enrollment", enrollmentId));
    }

    internal static int AppendAudit(StoreTransaction transaction, string ownerId, string actorId, string origin,
        string commandId, string method, string grantId, string enrollmentId, string correlationId, long revision,
        int effect, string reason, DateTimeOffset now)
    {
        RequireFull(transaction);
        if (!Identity(ownerId) || !Identity(actorId) || origin is not ("local" or "remote")
            || !IsId(commandId) || !IsId(grantId) || !IsId(enrollmentId) || !IsId(correlationId)
            || !Code(method) || !Code(reason) || revision <= 0 || effect is < 1 or > 3)
        {
            throw new ArgumentException("The remote grant audit must contain bounded identities and reason codes.", nameof(reason));
        }

        return transaction.Execute("""
            INSERT INTO audit(actor_id,origin,command_id,method,aggregate_id,effect_certainty,reason_code,created_utc,metadata_json)
            VALUES($actor,$origin,$command,$method,$id,$effect,$reason,$now,
                json_object('ownerId',$owner,'enrollmentId',$enrollment,'correlationId',$correlation,'revision',$revision));
            """, ("$actor", actorId), ("$origin", origin), ("$command", commandId), ("$method", method),
            ("$id", grantId), ("$effect", effect), ("$reason", reason), ("$now", FormatTime(now)), ("$owner", ownerId),
            ("$enrollment", enrollmentId), ("$correlation", correlationId), ("$revision", revision));
    }

    private static (string Name, object? Value)[] Parameters(StoredRemoteGrant grant, DateTimeOffset now) =>
        [("$id", grant.GrantId), ("$owner", grant.OwnerId), ("$enrollment", grant.EnrollmentId),
         ("$scope", grant.Scope == StoredRemoteGrantScope.Sandbox ? "sandbox" : "provision"), ("$sandbox", grant.SandboxId),
         ("$parent", grant.ParentGrantId), ("$parentRevision", grant.ParentGrantRevision), ("$revision", grant.Revision),
         ("$policy", grant.PolicyJson), ("$anchor", grant.RevocationAnchorCommandId),
         ("$templateRevision", grant.TemplateRevision), ("$template", grant.CreationTemplateJson),
         ("$created", FormatTime(grant.CreatedAt)), ("$expires", grant.ExpiresAt is { } expires ? FormatTime(expires) : null),
         ("$now", FormatTime(now))];

    private static StoredRemoteGrant Read(SqliteDataReader row, string ownerId)
    {
        var scope = row.GetString(2) switch
        {
            "sandbox" => StoredRemoteGrantScope.Sandbox,
            "provision" => StoredRemoteGrantScope.Provision,
            _ => throw new InvalidDataException("The stored grant scope is invalid."),
        };

        if (row.IsDBNull(7) || row.IsDBNull(8))
        {
            throw new InvalidDataException("The stored grant authority is incomplete.");
        }

        return new(row.GetString(0), ownerId, row.GetString(1), scope, StringOrNull(row, 3), StringOrNull(row, 4),
            LongOrNull(row, 9), row.GetInt64(5), (StoredRemoteGrantState)row.GetInt32(6), row.GetString(7), row.GetString(8),
            LongOrNull(row, 10), StringOrNull(row, 11), ParseTime(row.GetString(12)),
            row.IsDBNull(13) ? null : ParseTime(row.GetString(13)), row.IsDBNull(14) ? null : ParseTime(row.GetString(14)));
    }

    private static void Validate(StoredRemoteGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        bool validScope = grant.Scope switch
        {
            StoredRemoteGrantScope.Provision => grant is
            {
                SandboxId: null, ParentGrantId: null, ParentGrantRevision: null,
                TemplateRevision: > 0, CreationTemplateJson: not null
            },
            StoredRemoteGrantScope.Sandbox => IsId(grant.SandboxId) && grant.TemplateRevision is null && grant.CreationTemplateJson is null
                && (grant.ParentGrantId is null ? grant.ParentGrantRevision is null
                    : IsId(grant.ParentGrantId) && grant.ParentGrantRevision is > 0 && grant.ParentGrantId != grant.GrantId),
            _ => false,
        };
        if (!validScope || !IsId(grant.GrantId) || !IsId(grant.EnrollmentId) || !IsId(grant.RevocationAnchorCommandId)
            || !Identity(grant.OwnerId) || grant.Revision <= 0 || grant.State != StoredRemoteGrantState.Active
            || grant.RevokedAt is not null || grant.ExpiresAt is { } expiration && expiration <= grant.CreatedAt)
        {
            throw new ArgumentException("The remote grant identity, revision, or scope is invalid.", nameof(grant));
        }

        RequireObject(grant.PolicyJson);
        if (grant.CreationTemplateJson is { } template)
        {
            RequireObject(template);
        }
    }

    private static void RequireObject(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (json.Length > 1_048_576)
        {
            throw new ArgumentException("The grant policy exceeds the contract bound.", nameof(json));
        }

        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("The grant policy must be a JSON object.", nameof(json));
        }
    }

    private static void RequireFull(StoreTransaction transaction)
    {
        if (transaction.Durability != CommitDurability.Full)
        {
            throw new InvalidOperationException("Remote grant changes require a FULL transaction.");
        }
    }

    private static void ValidateExpected(long sequence)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sequence);
        ArgumentOutOfRangeException.ThrowIfEqual(sequence, long.MaxValue);
    }

    private static bool IsId(string? id) => id is { Length: 32 } && id.All(char.IsAsciiHexDigitLower);

    private static bool Identity(string? id) => id is { Length: > 0 and <= 256 } && !id.Any(char.IsControl);

    private static bool Code(string? value) => value is { Length: > 0 and <= 80 }
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-');

    private static string? StringOrNull(SqliteDataReader row, int index) => row.IsDBNull(index) ? null : row.GetString(index);

    private static long? LongOrNull(SqliteDataReader row, int index) => row.IsDBNull(index) ? null : row.GetInt64(index);

    private static string FormatTime(DateTimeOffset value) => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTime(string value) =>
        DateTimeOffset.ParseExact(value, "O", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
}
