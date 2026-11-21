// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using ArcForges.Node.Store.Migrations;

namespace ArcForges.Node.Store.Tests;

[Collection(nameof(MigrationOwnershipFixture))]
public sealed class MigrationPrepareTests
{
    [Fact(DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [Trait("env", "windows-real")]
    [Trait("env", "linux-real")]
    public void PreparationKeepsSchema15UnchangedAndProducesAnAuthenticStagingInput()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows() || OperatingSystem.IsLinux(), "Native owner verification is required.");
        using var source = new TemporaryDataRoot();
        using var expanded = new TemporaryDataRoot();
        using var backup = new TemporaryDataRoot();
        using var staged = new TemporaryDataRoot();
        using var occupied = new TemporaryDataRoot();
        var clock = new ManualClock();
        var plan = new MigrationPlan(StoreMigrations.Expanded.Steps.Take(15));
        string boot = NodeContractionScope.ReadCurrentBootIdentity();
        byte[] originalId;
        using (var original = source.Open(clock, plan, boot))
            originalId = original.Metadata.NodeId.ToArray();

        if (OperatingSystem.IsLinux())
        {
            using var instance = DurableEpochFence.OpenPrivate(Path.Combine(source.Path, "node.lock"), FileMode.CreateNew);
        }

        string sentinel = Path.Combine(source.Path, "original-owner-data");
        File.WriteAllText(sentinel, "original fixture bytes");
        string[] originalPaths = Paths(source.Path);
        byte[] originalDatabaseHash = Hash(source.Database);
        byte[] originalSentinelHash = Hash(sentinel);
        using (var first = NodeContractionScope.Acquire(source.Path, prepareSchema15: true))
        {
            var overlapping = Assert.Throws<StoreIncompatibleException>(
                () => PreparedNodeMigration.Prepare(first, Path.Combine(source.Path, "inside"), backup.Path, testMode: true));
            Assert.Contains("contraction_roots_overlap", overlapping.Message, StringComparison.Ordinal);
            Assert.False(Directory.Exists(backup.Path));

            Directory.CreateDirectory(occupied.Path);
            var exists = Assert.Throws<StoreIncompatibleException>(
                () => PreparedNodeMigration.Prepare(first, expanded.Path, occupied.Path, testMode: true));
            Assert.Contains("preparation_output_already_exists", exists.Message, StringComparison.Ordinal);
            Assert.Empty(Directory.EnumerateFileSystemEntries(occupied.Path));
            Assert.False(Directory.Exists(expanded.Path));

            PreparedNodeMigration.Prepare(first, expanded.Path, backup.Path, testMode: true);
            first.VerifyHeld();
        }

        Assert.Equal(originalPaths, Paths(source.Path));
        Assert.Equal(originalDatabaseHash, Hash(source.Database));
        Assert.Equal(originalSentinelHash, Hash(sentinel));
        Assert.True(File.Exists(Path.Combine(backup.Path, "v2-backup.manifest")));
        Assert.Single(StoreBackups.List(expanded.Path));
        if (OperatingSystem.IsWindows())
        {
            AssertWindowsPrivate(expanded.Path);
            AssertWindowsPrivate(backup.Path);
        }

        if (OperatingSystem.IsLinux())
        {
            Assert.Equal(StorePaths.PrivateDirectoryMode, File.GetUnixFileMode(expanded.Path));
            Assert.Equal(StorePaths.PrivateDirectoryMode, File.GetUnixFileMode(backup.Path));
        }

        byte[] expandedHash = Hash(expanded.Database);
        var owner = NodeContractionScope.CurrentPreparationOwner();
        var wrongVersion = Assert.Throws<StoreIncompatibleException>(
            () => NodeContractionScope.Acquire(expanded.Path, prepareSchema15: true));
        Assert.Contains("original_schema15_required", wrongVersion.Message, StringComparison.Ordinal);
        Assert.Equal(expandedHash, Hash(expanded.Database));

        using (var offline = NodeContractionScope.Acquire(expanded.Path))
        {
            var archive = VerifiedNodeContractionArchive.Restore(offline, Secrets(expanded), backup.Path, Secrets(backup), staged.Path, Secrets(staged));
            NodeStore.ContractVerifiedCopy(archive, clock);
        }

        if (OperatingSystem.IsWindows())
            AssertWindowsPrivate(staged.Path);
        if (OperatingSystem.IsLinux())
            Assert.Equal(StorePaths.PrivateDirectoryMode, File.GetUnixFileMode(staged.Path));

        using var result = NodeStore.OpenForV2Runtime(new NodeStoreOptions { DataRoot = staged.Path, BootIdentity = boot });
        Assert.Equal(20, result.Metadata.SchemaVersion);
        Assert.Equal(originalId, result.Metadata.NodeId.ToArray());
        Assert.Equal(owner, result.Read(reader => reader.Scalar("SELECT owner_id FROM owner_epoch;")));
        Assert.Equal(0L, result.Read(reader => reader.Scalar("SELECT COUNT(*) FROM command_receipt;")));
        Assert.Equal(expandedHash, Hash(expanded.Database));
        Assert.Equal(originalDatabaseHash, Hash(source.Database));
    }

    [SupportedOSPlatform("windows")]
    private static void AssertWindowsPrivate(string path)
    {
        using var identity = WindowsIdentity.GetCurrent();
        var permissions = new DirectoryInfo(path).GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
        Assert.Equal(identity.User, permissions.GetOwner(typeof(SecurityIdentifier)));
        Assert.True(permissions.AreAccessRulesProtected);
        var rule = Assert.Single(permissions.GetAccessRules(includeExplicit: true, includeInherited: true,
            typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>());
        Assert.Equal(identity.User, rule.IdentityReference);
        Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
        Assert.Equal(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, rule.InheritanceFlags);
    }

    private static NodeSecretStore Secrets(TemporaryDataRoot root) => NodeSecretStores.ForTestDataRoot(root.Path);

    private static string[] Paths(string root) => [.. Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)
        .Select(path => Path.GetRelativePath(root, path)).Order(StringComparer.Ordinal)];

    private static byte[] Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return SHA256.HashData(stream);
    }
}
