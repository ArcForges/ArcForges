// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store;

internal sealed record NativeUpdateStoreFloor(int Schema, int MinimumReader);

public sealed partial class NodeStore
{
    internal static NativeUpdateStoreFloor InspectNativeUpdateFloor(string dataRoot, bool onlineObservation = false)
    {
        DurableCommandStore.VerifyRestorePublication(dataRoot);
        ContractionPaths.RequireOwnedDirectory(dataRoot);
        string database = StorePaths.Database(dataRoot);
        ContractionPaths.RequireOwnedDirectory(Path.GetDirectoryName(database)!);
        if (!HasFileEntry(database))
            throw new StoreIncompatibleException("native_update_existing_store_required");

        var identity = ContractionPaths.NamedRegularIdentity(database);
        var existing = InspectRuntimeStore(database, StoreMigrations.Released, allowWindowsSharing: onlineObservation);
        if (existing is null || identity != ContractionPaths.NamedRegularIdentity(database))
            throw new StoreIncompatibleException("native_update_store_identity_unconfirmed");
        return new(existing.SchemaVersion, existing.MinReaderVersion);
    }

    // Restore uses the separate authenticated MIG-02 flow, which checks the latest epoch and effect history.
    // The binaries' update selector never publishes an older snapshot over the live store.
    internal static NativeUpdateCheckpoint CaptureNativeUpdateBackup(string dataRoot, string owner, string bootIdentity,
        NativeUpdateAuthority authority, Guid operationId, int candidateReader, bool compatibleSupervisors, bool testMode)
    {
        var floor = InspectNativeUpdateFloor(dataRoot);
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

        var retainedRuns = store.Read(reader => RunRecords.ListNonterminal(reader, owner)).Select(run => run.RunId).ToArray();
        if (!compatibleSupervisors && retainedRuns.Length != 0)
            throw new StoreIncompatibleException("native_update_supervisor_drain_required");
        if (retainedRuns.Length > 512)
            throw new StoreIncompatibleException("native_update_supervisor_checkpoint_capacity");

        var backupSecrets = NodeSecretStores.ForNode(backupRoot, testMode);
        commands.CreateBackup(backupRoot, backupSecrets, createPrivateRoot: true);
        return new(floor.Schema, floor.MinimumReader, candidateReader, HashUpdateBackupManifest(backupRoot), backupRoot, retainedRuns);
    }

    internal static void VerifyNativeUpdateBackup(NativeUpdateCheckpoint checkpoint)
    {
        if (checkpoint.BackupRoot is null ||
            !HashUpdateBackupManifest(checkpoint.BackupRoot).Equals(checkpoint.BackupManifestSha256, StringComparison.Ordinal))
            throw new StoreIncompatibleException("native_update_backup_unconfirmed");
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
