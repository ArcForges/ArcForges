// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Api;

/// <summary>Reads bounded persistent workspace metadata without assuming that a recorded root is available.</summary>
internal static class WorkspaceCatalog
{
    private const string Columns = """
        workspace_id, kind, state, name, root_path, repository_identity, base_workspace_id, base_ref, owner,
        origin_node_id, routing_mode, concurrency_mode, remote_slot, leased_by_attempt_id, created_at, last_used_at
        """;

    internal sealed record Page(long Revision, IReadOnlyList<Workspace> Records, bool More);

    internal static Page ReadPage(StoreReader reader, int limit, byte kinds, byte[]? after)
    {
        var revision = reader.Scalar("SELECT revision FROM workspace_inventory_revision WHERE singleton = 1;") is long value
            ? value : throw new InvalidDataException("Workspace inventory revision is unavailable.");
        using var command = reader.CreateCommand("SELECT " + Columns + " " + """
            FROM workspace WHERE removed_at IS NULL AND ((1 << (kind - 1)) & $kinds) <> 0
              AND ($after IS NULL OR workspace_id > $after) ORDER BY workspace_id LIMIT $limit;
            """);
        command.Parameters.AddWithValue("$kinds", kinds);
        command.Parameters.AddWithValue("$after", (object?)after ?? DBNull.Value);
        command.Parameters.AddWithValue("$limit", checked(limit + 1));
        using var rows = command.ExecuteReader();
        var workspaces = new List<Workspace>(limit + 1);
        while (rows.Read())
        {
            workspaces.Add(Project(rows));
        }

        var more = workspaces.Count > limit;
        if (more)
        {
            workspaces.RemoveAt(workspaces.Count - 1);
        }

        return new Page(revision, workspaces, more);
    }

    internal static Workspace? Get(StoreReader reader, byte[] id)
    {
        using var command = reader.CreateCommand("SELECT " + Columns + " FROM workspace WHERE workspace_id = $id AND removed_at IS NULL;");
        command.Parameters.AddWithValue("$id", id);
        using var row = command.ExecuteReader();
        return row.Read() ? Project(row) : null;
    }

    private static Workspace Project(SqliteDataReader row)
    {
        var workspace = new Workspace
        {
            WorkspaceId = new Id { Value = ByteString.CopyFrom((byte[])row.GetValue(0)) },
            Kind = (WorkspaceKind)row.GetInt32(1),
            State = (WorkspaceState)row.GetInt32(2),
            Name = row.GetString(3),
            RootPath = row.GetString(4),
            CreatedAt = ArcForges.Client.ProtoTime.ToInstant(StoreTime.FromMicroseconds(row.GetInt64(14))),
            LastUsedAt = ArcForges.Client.ProtoTime.ToInstant(StoreTime.FromMicroseconds(row.GetInt64(15))),
        };
        if (!row.IsDBNull(5)) workspace.RepositoryIdentity = row.GetString(5);
        if (!row.IsDBNull(6)) workspace.BaseWorkspaceId = new Id { Value = ByteString.CopyFrom((byte[])row.GetValue(6)) };
        if (!row.IsDBNull(7)) workspace.BaseRef = row.GetString(7);
        if (!row.IsDBNull(8)) workspace.Owner = ActorRef.Parser.ParseFrom((byte[])row.GetValue(8));
        if (!row.IsDBNull(9)) workspace.OriginNodeId = new Id { Value = ByteString.CopyFrom((byte[])row.GetValue(9)) };
        if (row.GetInt32(10) != 0) workspace.RoutingMode = (RoutingMode)row.GetInt32(10);
        if (row.GetInt32(11) != 0) workspace.ConcurrencyMode = (WorkspaceConcurrency)row.GetInt32(11);
        if (!row.IsDBNull(12)) workspace.RemoteSlot = checked((uint)row.GetInt64(12));
        if (!row.IsDBNull(13)) workspace.LeasedByAttemptId = new Id { Value = ByteString.CopyFrom((byte[])row.GetValue(13)) };
        return workspace;
    }
}
