// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Files;

/// <summary>The observed relationship to managed-directory records, independent of caller ownership.</summary>
internal enum AttemptDirectoryTracking
{
    Tracked,
    Untracked,
    Unknown,
}

/// <summary>
/// Read-only native-identity matching for the directory rows observed in one store transaction.
/// Missing roots and unobservable rows remain unknown. This observation grants no cleanup authority.
/// </summary>
internal static class AttemptDirectoryTrackingObservation
{
    internal static IReadOnlyDictionary<string, AttemptDirectoryTracking> Read(StoreReader reader,
        WorkspaceRemovalSnapshot snapshot, Action checkBudget)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(checkBudget);
        var candidates = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var entry in snapshot.Entries.Where(entry => entry.Kind == WorkspaceEntryType.Directory))
        {
            var key = Key(entry.NativeIdentity);
            if (key is null) throw new WorkspaceRemovalPlanException("identity_unavailable");
            candidates.Add(entry.Path, key);
        }

        var matched = new HashSet<string>(StringComparer.Ordinal);
        var roots = new Dictionary<string, WorkspacePath>(StringComparer.Ordinal);
        var incomplete = false;
        try
        {
            using var command = reader.CreateCommand("""
                SELECT m.root_class, m.relative_path, r.path
                FROM managed_directory m
                LEFT JOIN root_location r ON r.root_class = m.root_class
                WHERE m.state <> 5;
                """);
            using var rows = command.ExecuteReader();
            while (rows.Read())
            {
                checkBudget();
                var rootClass = rows.GetString(0);
                if (rows.IsDBNull(2) || rows.GetString(2).Length == 0)
                {
                    incomplete = true;
                    continue;
                }

                if (!roots.TryGetValue(rootClass, out var root))
                {
                    try
                    {
                        root = WorkspacePath.OpenRoot(rows.GetString(2));
                        roots.Add(rootClass, root);
                    }
                    catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
                    {
                        // The required root itself was not established; this cannot prove an absent record.
                        incomplete = true;
                        continue;
                    }
                }

                try
                {
                    var metadata = root.InspectEntry(rows.GetString(1), allowRoot: true);
                    if (metadata.Kind != WorkspaceEntryType.Directory) continue;
                    var key = Key(RegisteredWorkspaces.RootIdentity.Encode(metadata.Identity));
                    if (key is null) incomplete = true;
                    else matched.Add(key);
                }
                catch (WorkspacePathException error) when (error.Reason is "native_2" or "native_3" or "native_20")
                {
                    // Only an entry under the successfully opened required root is known to be absent.
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    // A record whose object cannot be observed cannot prove absence of another matching row.
                    incomplete = true;
                }
            }
        }
        finally
        {
            foreach (var root in roots.Values) root.Dispose();
        }

        checkBudget();
        return candidates.ToDictionary(pair => pair.Key,
            pair => matched.Contains(pair.Value) ? AttemptDirectoryTracking.Tracked :
                incomplete ? AttemptDirectoryTracking.Unknown : AttemptDirectoryTracking.Untracked,
            StringComparer.Ordinal);
    }

    private static string? Key(RegisteredWorkspaces.RootIdentity identity)
    {
        var key = FileCreationOwnership.StableKey(identity.Platform, identity.Bytes);
        return key is null ? null : identity.Platform.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + Convert.ToHexString(key);
    }
}
