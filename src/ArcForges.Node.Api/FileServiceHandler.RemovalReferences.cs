// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    /// <summary>Observes only ArcForges-managed references while admission and the writer are coordinated.</summary>
    private bool RemovalManagedUsesClear(StoreReader reader, RemovalEffectLease lease, CancellationToken token)
    {
        var target = lease.Target;
        var targetPath = Path.Combine(lease.Root.RootPath, lease.Source.Replace('/', Path.DirectorySeparatorChar));
        var targetAncestors = RemovalAncestors(Path.GetDirectoryName(targetPath), token);
        bool Related(string? path, bool requireDirectory = false, int? expectedPlatform = null, byte[]? expectedIdentity = null)
        {
            token.ThrowIfCancellationRequested();
            if (string.IsNullOrEmpty(path) || !Path.IsPathFullyQualified(path))
                throw new WorkspaceRemovalPlanException("file_access_denied");
            try
            {
                var selected = Path.TrimEndingDirectorySeparator(path);
                var parentPath = Path.GetDirectoryName(selected);
                WorkspaceEntryMetadata? final;
                List<WorkspaceObjectIdentity> ancestors;
                if (parentPath is null)
                {
                    using var root = WorkspacePath.OpenRoot(selected);
                    final = root.InspectEntry("", allowRoot: true);
                    ancestors = [];
                }
                else
                {
                    using var parent = WorkspacePath.OpenRoot(parentPath);
                    ancestors = RemovalAncestors(parentPath, token);
                    try { final = parent.InspectEntry(Path.GetFileName(selected)); }
                    catch (WorkspacePathException failure) when (!requireDirectory && failure.Reason is "native_2" or "native_3")
                    { final = null; }
                }
                if (requireDirectory && final?.Kind != WorkspaceEntryType.Directory)
                    throw new WorkspaceRemovalPlanException("file_access_denied");
                if (expectedPlatform is not null)
                {
                    if (final is null || expectedIdentity is null) throw new WorkspaceRemovalPlanException("file_access_denied");
                    var encoded = RegisteredWorkspaces.RootIdentity.Encode(final.Value.Identity, directory: final.Value.Kind == WorkspaceEntryType.Directory);
                    if (encoded.Platform != expectedPlatform || !encoded.Bytes.AsSpan().SequenceEqual(expectedIdentity))
                        throw new WorkspaceRemovalPlanException("file_access_denied");
                }
                return final is { } entry &&
                    (entry.Identity.SameObject(target) || entry.Kind == WorkspaceEntryType.Directory &&
                        targetAncestors.Any(ancestor => ancestor.SameObject(entry.Identity))) ||
                    target.IsDirectory && ancestors.Any(ancestor => ancestor.SameObject(target));
            }
            catch (Exception failure) when (failure is WorkspacePathException or UnauthorizedAccessException or ArgumentException)
            {
                throw new WorkspaceRemovalPlanException("file_access_denied", failure);
            }
        }

        // Persistent node I/O is an in-scope use too, not just scheduled task records.
        foreach (var path in new[] { Path.Combine(node.DataRoot, "store"), Path.Combine(node.DataRoot, "logs") })
            if (Directory.Exists(path) && Related(path, requireDirectory: true)) return false;
        var lockPath = Path.Combine(node.DataRoot, "node.lock");
        if (File.Exists(lockPath) && Related(lockPath)) return false;

        using (var select = reader.CreateCommand("""
            SELECT t.spec, t.state, w.root_path, i.platform, i.native_identity, t.workspace_id
            FROM task t LEFT JOIN workspace w ON w.workspace_id = t.workspace_id
            LEFT JOIN workspace_root_identity i ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE t.state BETWEEN 1 AND 6;
            """))
        using (var rows = select.ExecuteReader())
        {
            while (rows.Read())
            {
                token.ThrowIfCancellationRequested();
                TaskSpec spec;
                try { spec = TaskSpec.Parser.ParseFrom((byte[])rows.GetValue(0)); }
                catch (InvalidProtocolBufferException failure) { throw new WorkspaceRemovalPlanException("file_access_denied", failure); }
                var workspaceKnown = !rows.IsDBNull(5);
                if (workspaceKnown && Related(rows.IsDBNull(2) ? null : rows.GetString(2), true,
                        rows.IsDBNull(3) ? null : rows.GetInt32(3), rows.IsDBNull(4) ? null : (byte[])rows.GetValue(4)) ||
                    Related(spec.HasWorkingDirectory ? spec.WorkingDirectory : null, requireDirectory: true))
                    return false;
                if (spec.Stdin is { Mode: StdinMode.File } stdin && Related(stdin.HasFilePath ? stdin.FilePath : null) ||
                    spec.Readiness is { ConditionCase: ReadinessCondition.ConditionOneofCase.FileExists } readiness && Related(readiness.FileExists) ||
                    spec.Command?.Shell is { HasShellPath: true } shell && Related(shell.ShellPath) ||
                    spec.Command?.Argv is { Argv.Count: > 0 } argv && Path.IsPathFullyQualified(argv.Argv[0]) && Related(argv.Argv[0]))
                    return false;
                // A running arbitrary program's unrelated cwd is not proof of all its access.
                // A queued unrelated task is held at admission until this short cleanup ends.
                if (!workspaceKnown || rows.GetInt32(1) is >= 4 and <= 6)
                    throw new WorkspaceRemovalPlanException("file_access_denied");
            }
        }
        using (var select = reader.CreateCommand("""
            SELECT s.cwd, w.root_path, i.platform, i.native_identity, s.workspace_id FROM session s
            LEFT JOIN workspace w ON w.workspace_id = s.workspace_id
            LEFT JOIN workspace_root_identity i ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE s.state IN (1,2) OR EXISTS(SELECT 1 FROM session_subagent a WHERE a.session_id = s.session_id AND a.stopped_at IS NULL);
            """))
        using (var rows = select.ExecuteReader())
        {
            while (rows.Read())
            {
                if (rows.IsDBNull(0) && rows.IsDBNull(4)) throw new WorkspaceRemovalPlanException("file_access_denied");
                if (!rows.IsDBNull(0) && Related(rows.GetString(0), requireDirectory: true) ||
                    !rows.IsDBNull(4) && Related(rows.IsDBNull(1) ? null : rows.GetString(1), true,
                        rows.IsDBNull(2) ? null : rows.GetInt32(2), rows.IsDBNull(3) ? null : (byte[])rows.GetValue(3)))
                    return false;
            }
        }
        using (var select = reader.CreateCommand("""
            SELECT path FROM cache_instance WHERE maintenance_lease_holder IS NOT NULL
            UNION ALL SELECT w.root_path FROM workspace w WHERE w.leased_by_attempt_id IS NOT NULL OR EXISTS
                (SELECT 1 FROM remote_attempt r WHERE r.remote_workspace_id = w.workspace_id AND r.released_at IS NULL);
            """))
        using (var rows = select.ExecuteReader())
            while (rows.Read()) if (Related(rows.IsDBNull(0) ? null : rows.GetString(0), requireDirectory: true)) return false;
        using (var select = reader.CreateCommand("""
            SELECT r.path, m.relative_path FROM managed_directory m LEFT JOIN root_location r ON r.root_class = m.root_class
            WHERE m.pinned = 1 AND m.state <> 5;
            """))
        using (var rows = select.ExecuteReader())
        {
            while (rows.Read())
            {
                if (rows.IsDBNull(0)) throw new WorkspaceRemovalPlanException("file_access_denied");
                var components = WorkspacePath.Components(rows.GetString(1), allowRoot: true);
                var path = components.Length == 0 ? rows.GetString(0) : Path.Combine(rows.GetString(0), Path.Combine(components));
                if (Related(path, requireDirectory: true)) return false;
            }
        }
        return true;
    }

    private static List<WorkspaceObjectIdentity> RemovalAncestors(string? path, CancellationToken token)
    {
        var result = new List<WorkspaceObjectIdentity>();
        while (path is not null)
        {
            token.ThrowIfCancellationRequested();
            using var opened = WorkspacePath.OpenRoot(path);
            result.Add(opened.RootIdentity);
            path = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(path));
        }
        return result;
    }
}
