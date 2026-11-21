// SPDX-License-Identifier: AGPL-3.0-only

namespace ArcForges.Node.Store.Migrations;

/// <summary>Builds a detached expanded store and its authenticated backup from a held schema-15 input.</summary>
internal static class PreparedNodeMigration
{
    internal static void Prepare(NodeContractionScope source, string expandedRoot, string backupRoot, bool testMode)
    {
        source.ValidatePreparationRoot(expandedRoot);
        source.ValidatePreparationRoot(backupRoot);
        ContractionPaths.RequireSeparateRoots(source.DataRoot, backupRoot, expandedRoot, allowMissingBackup: true);
        string owner = NodeContractionScope.CurrentPreparationOwner();
        source.CopySchema15To(expandedRoot);

        using var expanded = NodeStore.Open(new NodeStoreOptions
        {
            DataRoot = expandedRoot,
            BootIdentity = NodeContractionScope.ReadCurrentBootIdentity(),
        }, StoreMigrations.Expanded);
        if (expanded.Opening.MigratedFrom != 15 || expanded.Metadata.SchemaVersion != StoreMigrations.ExpandedSchemaVersion)
            throw new StoreIncompatibleException("The detached store did not expand from the original schema 15.");

        var expandedSecrets = NodeSecretStores.ForNode(expandedRoot, testMode, optIn: null);
        var backupSecrets = NodeSecretStores.ForNode(backupRoot, testMode, optIn: null);
        using var commands = new DurableCommandStore(expanded, owner, expandedSecrets);
        commands.CreateBackup(backupRoot, backupSecrets, source);
    }
}
