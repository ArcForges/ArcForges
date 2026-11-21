// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Node.Store;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

if (args.Length == 1 && args[0] is "--help" or "-h")
{
    PrintUsage();
    return 0;
}

if (args.Length is < 4 or > 5 || args[0] != "stage" || args.Length == 5 && args[4] != "--test-mode")
{
    PrintUsage();
    return 2;
}

try
{
    string source = Path.GetFullPath(args[1]);
    string backup = Path.GetFullPath(args[2]);
    string stage = Path.GetFullPath(args[3]);
    bool testMode = args.Length == 5;
    NodeSecretStores.ApplyTestModeTripwire(testMode, optIn: null);
    using var scope = NodeContractionScope.Acquire(source);
    var proof = VerifiedNodeContractionArchive.Restore(scope, Secrets(source), backup, Secrets(backup), stage, Secrets(stage));
    NodeStore.ContractVerifiedCopy(proof, TimeProvider.System);
    Console.WriteLine("Staged an authenticated Node schema 20 database.");
    Console.WriteLine(proof.StagedDatabasePath);
    return 0;

    NodeSecretStore Secrets(string root) => NodeSecretStores.ForNode(root, testMode, optIn: null);
}
catch (Exception failure) when (failure is StoreIncompatibleException or DurableStoreMaintenanceException
    or IOException or UnauthorizedAccessException or SqliteException or ArgumentException)
{
    Console.Error.WriteLine("Node contraction refused.");
    Console.Error.WriteLine(failure.Message);
    return 1;
}

static void PrintUsage()
{
    Console.WriteLine("arcforges-migrate-node stage SOURCE BACKUP STAGE [--test-mode]");
    Console.WriteLine("Stage schema contraction from an offline, expanded source and its authenticated backup.");
    Console.WriteLine("STAGE is a new private directory. The command produces a database for later cutover.");
}
