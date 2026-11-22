// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store;

internal sealed record NativeUpdateStoreFloor(int Schema, int MinimumReader);

public sealed partial class NodeStore
{
    internal static NativeUpdateStoreFloor InspectNativeUpdateFloor(string dataRoot, bool onlineObservation = false, bool requireDrained = false,
        NativeUpdateCheckpoint? expectedBindings = null, string? ownerEpoch = null, NativeUpdateAuthority? previousAuthority = null)
    {
        DurableCommandStore.VerifyRestorePublication(dataRoot);
        SQLitePCL.Batteries_V2.Init();
        ContractionPaths.RequireOwnedDirectory(dataRoot);
        string database = StorePaths.Database(dataRoot);
        ContractionPaths.RequireOwnedDirectory(Path.GetDirectoryName(database)!);
        if (!HasFileEntry(database))
            throw new StoreIncompatibleException("native_update_existing_store_required");

        var identity = ContractionPaths.NamedRegularIdentity(database);
        var existing = InspectRuntimeStore(database, StoreMigrations.Released, allowWindowsSharing: onlineObservation, requireStableCopy: onlineObservation, requireDrained: requireDrained,
            expectedBindings: expectedBindings, updateOwnerEpoch: ownerEpoch, previousAuthority: previousAuthority);
        if (existing is null || identity != ContractionPaths.NamedRegularIdentity(database))
            throw new StoreIncompatibleException("native_update_store_identity_unconfirmed");
        return new(existing.SchemaVersion, existing.MinReaderVersion);
    }

    // Restore uses the separate authenticated MIG-02 flow, which checks the latest epoch and effect history.
    // The binaries' update selector never publishes an older snapshot over the live store.
    internal static NativeUpdateCheckpoint CaptureNativeUpdateBackup(string dataRoot, string owner, string bootIdentity,
        NativeUpdateAuthority authority, Guid operationId, int candidateReader, bool compatibleSupervisors, bool testMode,
        string? candidateSupervisorProtocol = null)
    {
        var floor = InspectNativeUpdateFloor(dataRoot, requireDrained: !compatibleSupervisors);
        NativeUpdateGate.RequireCompatibleReader(floor.Schema, floor.MinimumReader, candidateReader);
        if (floor.Schema != authority.PreviousSchema || floor.MinimumReader != authority.PreviousMinimumReader ||
            floor.Schema != StoreMigrations.SupportedSchemaVersion)
            throw new StoreIncompatibleException("native_update_store_requires_prepared_offline_migration");

        string backupRoot = Path.Combine(Path.GetDirectoryName(dataRoot)!,
            $".{Path.GetFileName(dataRoot)}.update-backup-{operationId:N}-{Guid.NewGuid():N}");
        using var store = OpenForV2Runtime(new NodeStoreOptions { DataRoot = dataRoot, BootIdentity = bootIdentity });
        if (!Convert.ToHexStringLower(store.Metadata.NodeId.Span).Equals(authority.NodeId, StringComparison.Ordinal) ||
            !DurableCommandStore.HasExistingAuthority(store, owner))
            throw new DurableStoreMaintenanceException();
        using var commands = new DurableCommandStore(store, owner, NodeSecretStores.ForNode(dataRoot, testMode), existingOnly: true);
        if (!Convert.ToHexStringLower(commands.OwnerEpoch.Span).Equals(authority.OwnerEpoch, StringComparison.Ordinal) ||
            commands.MaintenanceRequired)
            throw new DurableStoreMaintenanceException();

        var retainedRuns = store.Read(reader =>
        {
            var runs = RunRecords.ListNonterminal(reader, owner);
            if (runs.Count > 80)
                throw new StoreIncompatibleException("native_update_supervisor_checkpoint_capacity");
            return runs.Select(run => ReadOriginalRun(reader, owner, run)).ToArray();
        });

        var backupSecrets = NodeSecretStores.ForNode(backupRoot, testMode);
        commands.CreateBackup(backupRoot, backupSecrets, createPrivateRoot: true);
        return new(floor.Schema, floor.MinimumReader, candidateReader, HashUpdateBackupManifest(backupRoot), backupRoot, retainedRuns, candidateSupervisorProtocol);
    }

    private static NativeUpdateRetainedRun ReadOriginalRun(StoreReader reader, string owner, StoredRun run)
    {
        var recovery = RunRecoveryRecords.Read(reader, owner, run);
        var supervisor = RunRecords.GetSupervisor(reader, owner, run.RunId);
        if (recovery is not { PrepareStarted: true } || supervisor is null || supervisor.ControlEpoch != run.Epoch)
            throw new StoreIncompatibleException("native_update_original_run_binding_unconfirmed");

        string[] tuple = [supervisor.InstanceId, supervisor.BootId, supervisor.ProcessId.ToString(CultureInfo.InvariantCulture),
            supervisor.CreationIdentity, supervisor.Endpoint, supervisor.BoundaryIdentity, supervisor.BackendId, supervisor.Cohort,
            supervisor.ControlEpoch, recovery.BootId, recovery.SupervisorPath, recovery.SupervisorSha256, recovery.InstallationRoot];
        if (tuple.Any(value => string.IsNullOrEmpty(value) || value.Contains('\0')))
            throw new StoreIncompatibleException("native_update_original_run_binding_invalid");
        string binding = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\0', tuple))));
        return new(run.RunId, run.Epoch, run.LaunchSha256, binding, recovery.Generation);
    }

    private static void VerifyNativeUpdateSourceAuthority(SqliteConnection connection, NativeUpdateAuthority authority)
    {
        var reader = new StoreReader(connection, null, TimeProvider.System);
        if (reader.Scalar("SELECT node_id FROM store_meta WHERE singleton=1;") is not byte[] { Length: 16 } nodeId ||
            Convert.ToHexStringLower(nodeId) != authority.NodeId ||
            !Equals(reader.Scalar("SELECT count(*) FROM owner_epoch WHERE owner_epoch=$epoch AND state='ACTIVE';",
                ("$epoch", Convert.FromHexString(authority.OwnerEpoch))), 1L))
            throw new DurableStoreMaintenanceException();
    }

    private static void VerifyNativeUpdateRunBindings(SqliteConnection connection, NativeUpdateCheckpoint checkpoint, string ownerEpoch)
    {
        var reader = new StoreReader(connection, null, TimeProvider.System);
        string owner = reader.Scalar("SELECT owner_id FROM owner_epoch WHERE owner_epoch=$epoch AND state='ACTIVE';",
            ("$epoch", Convert.FromHexString(ownerEpoch))) as string
            ?? throw new DurableStoreMaintenanceException();

        foreach (var expected in checkpoint.RetainedRuns ?? [])
        {
            var run = RunRecords.Get(reader, owner, expected.RunId);
            if (run is null || run.Epoch != expected.Epoch || run.LaunchSha256 != expected.LaunchSha256)
                throw new StoreIncompatibleException("native_update_retained_run_identity_changed");

            if (run.State is StoredRunState.Exited or StoredRunState.Failed)
            {
                if (run.EndedAt is null || string.IsNullOrWhiteSpace(run.TerminationReason))
                    throw new StoreIncompatibleException("native_update_retained_run_completion_unconfirmed");
                continue;
            }

            var current = ReadOriginalRun(reader, owner, run);
            if (run.State == StoredRunState.RecoveryRequired || current.RecoveryGeneration <= expected.RecoveryGeneration
                || current.BindingSha256 != expected.BindingSha256)
                throw new StoreIncompatibleException("native_update_original_native_boundary_unconfirmed");
        }
    }

    private static string HashUpdateBackupManifest(string root)
    {
        ContractionPaths.RequireOwnedDirectory(root);
        using var manifest = ContractionPaths.OpenRegularRead(Path.Combine(root, "v2-backup.manifest"));
        if (manifest.Length is < 33 or > 1048576)
            throw new StoreIncompatibleException("native_update_backup_unconfirmed");
        return Convert.ToHexStringLower(SHA256.HashData(manifest));
    }
}
