// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Execution;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Api;

internal sealed partial class FileServiceHandler
{
    private enum AttemptReferenceState { Unrelated, InUse, Unknown }

    private static AttemptReferenceState QualifyAttemptReferences(StoreReader reader, WorkspacePath temporaryRoot,
        WorkspacePath attemptRoot, Action checkBudget)
    {
        // A checked declared path is evidence of a relationship, not an external-use or cleanup-effect guard.
        var targetIdentity = attemptRoot.RootIdentity;
        var targetAncestors = temporaryRoot.WindowsRootAncestors();
        var observations = new Dictionary<string, (RegisteredWorkspaces.RootIdentity? Identity, bool Overlaps, WorkspaceEntryType? Kind)>(StringComparer.Ordinal);
        var incomplete = false;

        bool Overlaps(string? path, bool boundWorkspace = false, int? expectedPlatform = null, byte[]? expectedIdentity = null, bool requireDirectory = false)
        {
            checkBudget();
            if (string.IsNullOrEmpty(path))
            {
                incomplete = true;
                return false;
            }

            if (!observations.TryGetValue(path, out var observation))
            {
                try
                {
                    var observed = WorkspacePath.ObserveWindowsReference(path);
                    var identity = observed.Final is { Kind: WorkspaceEntryType.Directory } final
                        ? RegisteredWorkspaces.RootIdentity.Encode(final.Identity) : null;
                    observation = (identity, observed.OverlapsDirectory(targetIdentity, targetAncestors), observed.Final?.Kind);
                    observations.Add(path, observation);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    // This is an actual failed native observation, rather than an absent association index.
                    throw new WorkspaceRemovalPlanException("identity_unavailable", exception);
                }
            }

            // cwd, managed directories and cache roots require a directory; a stale file at that name does
            // not establish an unrelated directory association. Other structured references may be files.
            if (observation.Kind is not (WorkspaceEntryType.File or WorkspaceEntryType.Directory) ||
                (requireDirectory || boundWorkspace) && observation.Kind != WorkspaceEntryType.Directory)
            {
                incomplete = true;
                return false;
            }
            if (boundWorkspace && (expectedPlatform is null || expectedIdentity is null || observation.Identity is null ||
                expectedPlatform != observation.Identity.Platform ||
                !CryptographicOperations.FixedTimeEquals(expectedIdentity, observation.Identity.Bytes)))
            {
                incomplete = true;
                return false;
            }
            return observation.Overlaps;
        }

        using (var sessions = reader.CreateCommand("""
            SELECT s.cwd, w.root_path, i.platform, i.native_identity, s.workspace_id FROM session s
            LEFT JOIN workspace w ON w.workspace_id = s.workspace_id
            LEFT JOIN workspace_root_identity i ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE s.state IN (1, 2) OR EXISTS
                (SELECT 1 FROM session_subagent a WHERE a.session_id = s.session_id AND a.stopped_at IS NULL);
            """))
        using (var rows = sessions.ExecuteReader())
        {
            while (rows.Read())
            {
                checkBudget();
                var hasCwd = !rows.IsDBNull(0) && rows.GetString(0).Length != 0;
                var hasWorkspace = !rows.IsDBNull(4);
                if (!hasCwd && !hasWorkspace) incomplete = true;
                if (hasCwd && Overlaps(rows.GetString(0), requireDirectory: true) ||
                    hasWorkspace && Overlaps(rows.IsDBNull(1) ? null : rows.GetString(1), true,
                        rows.IsDBNull(2) ? null : rows.GetInt32(2), rows.IsDBNull(3) ? null : (byte[])rows.GetValue(3)))
                    return AttemptReferenceState.InUse;
            }
        }

        using (var tasks = reader.CreateCommand("""
            SELECT t.spec, w.root_path, i.platform, i.native_identity, t.workspace_id, t.env_digest,
                   t.current_attempt_id, t.attempt_count,
                   EXISTS(SELECT 1 FROM task_secret s WHERE s.task_id = t.task_id) FROM task t
            LEFT JOIN workspace w ON w.workspace_id = t.workspace_id
            LEFT JOIN workspace_root_identity i ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE t.state BETWEEN 1 AND 6;
            """))
        using (var rows = tasks.ExecuteReader())
        {
            while (rows.Read())
            {
                checkBudget();
                TaskSpec spec;
                try { spec = TaskSpec.Parser.ParseFrom((byte[])rows.GetValue(0)); }
                catch (InvalidProtocolBufferException) { incomplete = true; continue; }
                if (Overlaps(spec.HasWorkingDirectory ? spec.WorkingDirectory : null, requireDirectory: true) ||
                    !rows.IsDBNull(4) && Overlaps(rows.IsDBNull(1) ? null : rows.GetString(1), true,
                        rows.IsDBNull(2) ? null : rows.GetInt32(2), rows.IsDBNull(3) ? null : (byte[])rows.GetValue(3)))
                    return AttemptReferenceState.InUse;
                if (spec.Stdin is { Mode: StdinMode.File } stdin && Overlaps(stdin.HasFilePath ? stdin.FilePath : null) ||
                    spec.Readiness is { ConditionCase: ReadinessCondition.ConditionOneofCase.FileExists } readiness && Overlaps(readiness.FileExists) ||
                    spec.Command?.Shell is { HasShellPath: true } shell && Overlaps(shell.ShellPath))
                    return AttemptReferenceState.InUse;

                // Use the product's actual Windows lookup rules and stored caller snapshot, without exposing any
                // environment or command bytes. This current resolution cannot attest a running process's past
                // lookup, nor exclude arbitrary shell/argv access, so absence still remains Unknown below.
                try
                {
                    var snapshot = rows.IsDBNull(5) ? null : EnvSnapshots.Get(reader, (byte[])rows.GetValue(5));
                    // Do not reconstruct a past launch or guess values removed by secret redaction. Resolving
                    // fresh queued work uses exactly the stored public inputs and the real platform algorithm.
                    var lookupKnown = rows.IsDBNull(6) && rows.GetInt32(7) == 0 && rows.GetInt32(8) == 0 &&
                        (spec.Environment?.Inherit != EnvironmentInherit.Caller || snapshot is not null &&
                         CryptographicOperations.FixedTimeEquals(EnvSnapshots.Digest(snapshot), (byte[])rows.GetValue(5)));
                    if (lookupKnown)
                    {
                        var restored = SubmittedEnvironment.Restore(spec, snapshot, secrets: null);
                        var environment = ExecutionSupervisor.ValidationEnvironment(restored, StringComparer.OrdinalIgnoreCase);
                        string? executable = null;
                        if (spec.Command?.Argv is { Argv.Count: > 0 } argv && spec.HasWorkingDirectory)
                            executable = WindowsProgramResolver.Resolve(argv.Argv[0], spec.WorkingDirectory, environment);
                        else if (spec.Command?.Shell is { } selectedShell)
                            executable = selectedShell.HasShellPath ? selectedShell.ShellPath :
                                WindowsCommands.FindShell(selectedShell.Kind, environment);
                        if (executable is not null && Overlaps(executable)) return AttemptReferenceState.InUse;
                    }
                }
                catch (Exception error) when (error is InvalidDataException or ArgumentException)
                {
                    // Missing/malformed lookup facts do not establish absence, and are never a guessed holder.
                }

                // cwd, a workspace and the declared paths do not confine an arbitrary executable or script.
                // There is no complete external-access index for such activity in this implementation.
                incomplete = true;
            }
        }

        using (var references = reader.CreateCommand("""
            SELECT path, NULL, NULL, 0 FROM cache_instance WHERE maintenance_lease_holder IS NOT NULL
            UNION ALL
            SELECT w.root_path, i.platform, i.native_identity, 1 FROM workspace w
            LEFT JOIN workspace_root_identity i ON i.workspace_id = w.workspace_id AND i.released_at IS NULL
            WHERE w.leased_by_attempt_id IS NOT NULL OR EXISTS
                (SELECT 1 FROM remote_attempt r WHERE r.remote_workspace_id = w.workspace_id AND r.released_at IS NULL);
            """))
        using (var rows = references.ExecuteReader())
        {
            while (rows.Read())
                if (Overlaps(rows.IsDBNull(0) ? null : rows.GetString(0), rows.GetInt32(3) != 0,
                    rows.IsDBNull(1) ? null : rows.GetInt32(1), rows.IsDBNull(2) ? null : (byte[])rows.GetValue(2), requireDirectory: true))
                    return AttemptReferenceState.InUse;
        }

        using (var pinned = reader.CreateCommand("""
            SELECT r.path, m.relative_path FROM managed_directory m
            LEFT JOIN root_location r ON r.root_class = m.root_class
            WHERE m.pinned = 1 AND m.state <> 5;
            """))
        using (var rows = pinned.ExecuteReader())
        {
            while (rows.Read())
            {
                checkBudget();
                if (rows.IsDBNull(0) || rows.GetString(0).Length == 0)
                {
                    incomplete = true;
                    continue;
                }
                try
                {
                    var components = WorkspacePath.Components(rows.GetString(1), allowRoot: true);
                    var candidate = components.Length == 0 ? rows.GetString(0) :
                        Path.Combine(rows.GetString(0), string.Join(Path.DirectorySeparatorChar, components));
                    if (Overlaps(candidate, requireDirectory: true)) return AttemptReferenceState.InUse;
                }
                catch (WorkspacePathException exception)
                {
                    throw new WorkspaceRemovalPlanException("identity_unavailable", exception);
                }
            }
        }
        checkBudget();
        return incomplete ? AttemptReferenceState.Unknown : AttemptReferenceState.Unrelated;
    }

}
