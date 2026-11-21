// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using ArcForges.Node.Store;
using ArcForges.Node.Store.Migrations;
using Microsoft.Data.Sqlite;

if (args.Length == 1 && args[0] is "--help" or "-h")
{
    PrintUsage();
    return 0;
}

if (args.Length is < 4 or > 5 || args[0] is not ("prepare" or "stage") || args.Length == 5 && args[4] != "--test-mode")
{
    PrintUsage();
    return 2;
}

try
{
    bool prepare = args[0] == "prepare";
    string source = Root(args[1]);
    string second = Root(args[2]);
    string third = Root(args[3]);
    bool testMode = args.Length == 5;
    NodeSecretStores.ApplyTestModeTripwire(testMode, optIn: null);
    using var scope = NodeContractionScope.Acquire(source, prepareSchema15: prepare);
    if (prepare)
    {
        PreparedNodeMigration.Prepare(scope, second, third, testMode);
        Console.WriteLine("Prepared a detached Node schema 19 store and an authenticated backup.");
        Console.WriteLine(second);
        Console.WriteLine(third);
        Console.WriteLine("Original native scope SHA-256 " + scope.ReceiptSha256);
        return 0;
    }

    var proof = VerifiedNodeContractionArchive.Restore(scope, Secrets(source), second, Secrets(second), third, Secrets(third));
    NodeStore.ContractVerifiedCopy(proof, TimeProvider.System);
    Console.WriteLine("Staged an authenticated Node schema 20 database.");
    Console.WriteLine(proof.StagedDatabasePath);
    return 0;

    NodeSecretStore Secrets(string root) => NodeSecretStores.ForNode(root, testMode, optIn: null);
}
catch (Exception failure) when (failure is StoreIncompatibleException or DurableStoreMaintenanceException or Win32Exception
    or IOException or UnauthorizedAccessException or SqliteException or ArgumentException)
{
    Console.Error.WriteLine("Node migration refused.");
    Console.Error.WriteLine(failure.Message);
    return 1;
}

static string Root(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

static void PrintUsage()
{
    Console.WriteLine("arcforges-migrate-node prepare SOURCE EXPANDED BACKUP [--test-mode]");
    Console.WriteLine("Copy a closed schema 15 Node to a new expanded store and create a separate authenticated backup.");
    Console.WriteLine("arcforges-migrate-node stage EXPANDED BACKUP STAGE [--test-mode]");
    Console.WriteLine("Stage schema contraction from an offline, expanded source and its authenticated backup.");
    Console.WriteLine("STAGE is a new private directory. The command produces a database for later cutover.");
}
