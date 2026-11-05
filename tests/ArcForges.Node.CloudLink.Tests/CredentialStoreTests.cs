// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;
using ArcForges.Tests;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-3 (ISOLATED store, REAL files) and N1-17 (persistence and crash points; N1 decision R-1 and node-10): the credential record, the link
/// file and the key sets; where the credential lives, what start-up does with what it finds, and that nothing is deleted on an absent record
/// or a store failure.
/// </summary>
public sealed class CredentialStoreTests
{
    [Fact]
    public async Task TestCredentialRecordRoundTripsThroughTheIsolatedStore()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        var record = link.StoredRecord();
        Assert.NotNull(record);
        Assert.Equal(issued.RefreshToken, record.RefreshToken);
        Assert.Equal(issued.AccessToken, record.AccessToken);
        Assert.Equal(Convert.ToHexStringLower(link.NodeId), record.NodeId);
        Assert.Equal(link.Center.Endpoint.Url, record.CenterUrl);
        Assert.Equal(3_600_000, record.AccessLifetimeMs);
        Assert.Equal(TimeSpan.FromDays(365).TotalMilliseconds, record.FamilyLifetimeMs);
        Assert.True(record.Serialize().Length <= TestDataRootSecretStore.MaximumSecretBytes);

        // The target derives from the node ID and the center origin (no path), the NodeDataKeyRing construction with its own domain.
        var target = Assert.Single(link.Secrets.Names());
        Assert.Equal(NodeSecretStores.TargetPrefix + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            "arcforges.node-cloud-credential.v1|" + Convert.ToHexStringLower(link.NodeId) + "|" + link.Center.Endpoint.Origin))), target);

        // A restart reads it back and is signed in again.
        await link.StopAsync();
        await link.StartAsync();
        Assert.True(link.Service.AccountLinked);
        var status = link.Service.Status();
        Assert.Equal("Test Account", status.AccountDisplayName);
        Assert.Equal(link.Center.Endpoint.Url, status.CenterUrl);
    }

    [Fact]
    public async Task TheLinkFileRecordsWhereTheCredentialIsAndIsOwnerOnly()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        var file = link.Storage.ReadLink()!;
        Assert.Equal(LinkStates.SignedIn, file.State);
        Assert.Equal(link.Secrets.Backend.ToString(), file.Backend);
        Assert.True(file.Isolated);
        Assert.Equal(link.Center.Endpoint.Url, file.CenterUrl);
        var text = System.Text.Encoding.UTF8.GetString(PrivateFiles.ReadOrNull(link.Storage.LinkPath)!);
        Assert.DoesNotContain("afr1.", text, StringComparison.Ordinal);
        Assert.DoesNotContain("afa1.", text, StringComparison.Ordinal);
        Assert.DoesNotContain("afr1.", System.Text.Encoding.UTF8.GetString(PrivateFiles.ReadOrNull(link.Storage.KeysPath)!), StringComparison.Ordinal);
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(link.Storage.LinkPath));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(link.Storage.KeysPath));
        }
    }

    [Fact]
    public async Task AnIsolatedStoreIsNeverReportedAsTheOsStore()
    {
        await using var link = await LinkFixture.CreateAsync();
        link.Secrets = new IsolatedSecretStore(SecretStoreBackend.WindowsCredentialManager, SecretStoreProtection.OsSecretStore);
        await link.StartAsync();
        await link.SignInAsync();
        var status = link.Service.Status();
        Assert.False(status.CredentialInOsStore);
        Assert.Contains("isolated_test_backend", status.Warnings);
        Assert.DoesNotContain("FILE_PERMISSIONS_ONLY", status.Warnings);
    }

    [Fact]
    public async Task AnOwnerOnlyFileStoreAddsFilePermissionsOnly()
    {
        await using var link = await LinkFixture.CreateAsync();
        link.Secrets = new IsolatedSecretStore(SecretStoreBackend.OwnerOnlyFile, SecretStoreProtection.FileOwnerOnly);
        await link.StartAsync();
        await link.SignInAsync();
        Assert.Contains("FILE_PERMISSIONS_ONLY", link.Service.Status().Warnings);
        Assert.False(link.Service.Status().CredentialInOsStore);
    }

    [Theory]
    [InlineData(nameof(SecretStoreBackend.SecretService), nameof(SecretStoreBackend.OwnerOnlyFile), true)]
    [InlineData(nameof(SecretStoreBackend.OwnerOnlyFile), nameof(SecretStoreBackend.SecretService), true)]
    [InlineData(nameof(SecretStoreBackend.OwnerOnlyFile), nameof(SecretStoreBackend.OwnerOnlyFile), false)]
    public async Task ABackendChangeLeavesEverythingAsItWas(string recorded, string selected, bool isolated)
    {
        await using var link = await LinkFixture.CreateAsync();
        link.Secrets = new IsolatedSecretStore(Enum.Parse<SecretStoreBackend>(recorded), SecretStoreProtection.FileOwnerOnly);
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();
        var linkBytes = PrivateFiles.ReadOrNull(link.Storage.LinkPath)!;
        var held = link.Secrets;

        // The next start selects another backend, or the same backend but not isolated (node-10 items 1-3).
        var other = new IsolatedSecretStore(Enum.Parse<SecretStoreBackend>(selected), SecretStoreProtection.FileOwnerOnly);
        link.Secrets = other;
        var store = isolated ? other.Selection : new NodeSecretStore(other, other.Backend, other.Protection, isolated: false);
        await using var service = new CloudLinkService(Options(link, store));
        await service.StartAsync();
        Assert.False(service.AccountLinked);
        Assert.Contains("credential_backend_changed", service.Status().Warnings);
        Assert.Equal(linkBytes, PrivateFiles.ReadOrNull(link.Storage.LinkPath)!);
        Assert.Single(held.Names());
        Assert.Empty(link.Center.Calls);
    }

    [Fact]
    public async Task AnAbsentRecordBehindASignedInLinkDeletesNothing()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        await link.StopAsync();
        link.Secrets = new IsolatedSecretStore();
        await link.StartAsync();
        Assert.False(link.Service.AccountLinked);
        Assert.Contains("credential_backend_changed", link.Service.Status().Warnings);
        Assert.True(File.Exists(link.Storage.LinkPath));
        Assert.True(File.Exists(link.Storage.KeysPath));
        Assert.NotNull(link.Keys.Recorded());
    }

    [Fact]
    public async Task AStoreReadErrorIsNeverAbsentItIsReportedAndRetried()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();
        link.Secrets.Unavailable = true;
        await link.StartAsync();
        Assert.False(link.Service.AccountLinked);
        Assert.Contains("credential_store_unavailable", link.Service.Status().Warnings);
        Assert.True(File.Exists(link.Storage.LinkPath));

        // The store comes back: the loop reads it again (about a minute later) and the node is signed in.
        link.Secrets.Unavailable = false;
        Assert.NotEmpty(link.Secrets.Names());
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(3), () => link.Service.AccountLinked, "signed in again");
        Assert.DoesNotContain("credential_store_unavailable", link.Service.Status().Warnings);
    }

    [Fact]
    public async Task CredentialRecordOfAnotherNodeIdIsIgnored()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();

        // The link file says another node ID (a store reset under the same data root): signed out, nothing sent, nothing deleted.
        var file = link.Storage.ReadLink()!;
        file.NodeId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        link.Storage.WriteLink(file);
        await link.StartAsync();
        Assert.False(link.Service.AccountLinked);
        Assert.Contains("credential_for_other_node", link.Service.Status().Warnings);
        link.Clock.Advance(TimeSpan.FromHours(2));
        await Task.Delay(100, TestContext.Current.CancellationToken);
        Assert.Empty(link.Center.CallsOf("RefreshNodeSession"));
    }

    [Fact]
    public async Task TestTheCredentialIsNeverSentToAnotherCenter()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();
        await using var other = await FakeCenter.StartAsync("/other");
        link.ConfiguredCenter = other.Endpoint;
        await link.StartAsync();
        Assert.False(link.Service.AccountLinked);
        Assert.Contains("credential_for_other_center", link.Service.Status().Warnings);
        Assert.Equal(other.Endpoint.Url, link.Service.Status().CenterUrl);
        link.Clock.Advance(TimeSpan.FromHours(2));
        await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.Empty(other.Calls);
        Assert.Empty(link.Center.Calls);
        Assert.NotNull(link.StoredRecord());
    }

    [Fact]
    public async Task ACommittingLinkWithItsRecordIsCompletedOnStart()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();
        var file = link.Storage.ReadLink()!;
        file.State = LinkStates.Committing;
        link.Storage.WriteLink(file);
        await link.StartAsync();
        Assert.True(link.Service.AccountLinked);
        Assert.Equal(LinkStates.SignedIn, link.Storage.ReadLink()!.State);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task AnInterruptedEndingIsFinishedOnStart(int stepsDone)
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        await link.StopAsync();

        // A crash after "ending" was written and after 0..3 of the deletions (record, key sets, node key).
        var file = link.Storage.ReadLink()!;
        file.State = LinkStates.Ending;
        link.Storage.WriteLink(file);
        if (stepsDone >= 1)
        {
            link.Storage.DeleteRecord(file.Target);
        }

        if (stepsDone >= 2)
        {
            link.Storage.DeleteKeys();
        }

        if (stepsDone >= 3)
        {
            link.Keys.Delete();
        }

        await link.StartAsync();
        Assert.False(link.Service.AccountLinked);
        Assert.Empty(link.Secrets.Names());
        Assert.False(File.Exists(link.Storage.LinkPath));
        Assert.False(File.Exists(link.Storage.KeysPath));
        Assert.Null(link.Keys.Recorded());
    }

    [Fact]
    public async Task AnEndingWhoseRecordCannotBeDeletedStaysRecordedAndIsFinishedLater()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        link.Center.Revoke(issued.RefreshToken);
        link.Secrets.Unavailable = true;
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Service.Phase == CloudLinkPhase.SignedOut,
            "signed out");
        Assert.Equal(LinkStates.Ending, link.Storage.ReadLink()!.State);
        link.Secrets.Unavailable = false;
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(3), () => !File.Exists(link.Storage.LinkPath), "the ending finished");
        Assert.Empty(link.Secrets.Names());
    }

    [Fact]
    public void TheRecordInATestNodesFileStoreIsOwnerOnly()
    {
        // N1-3 over the store a --test-mode node selects (REAL files): the record file is 0600 in a 0700 directory on Unix.
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix file modes: on Windows the files inherit the data root's access list.");
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var root = Directory.CreateTempSubdirectory("arcforges-credential-modes-").FullName;
        try
        {
            var secrets = NodeSecretStores.ForTestDataRoot(root);
            var storage = new CloudCredentialStore(root, secrets);
            var nodeId = RandomNumberGenerator.GetBytes(16);
            var target = CloudCredentialStore.Target(nodeId, "https://center.example.test");
            storage.WriteRecord(target, new CloudCredentialRecord
            {
                NodeId = Convert.ToHexStringLower(nodeId),
                CenterUrl = "https://center.example.test/api",
                InstallationId = new string('0', 32),
                AccessToken = "afa1.access",
                RefreshToken = "afr1.refresh",
            });
            var file = Path.Combine(root, "run", "test-secrets", target);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(file));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Path.GetDirectoryName(file)!));
            Assert.Equal("afr1.refresh", storage.ReadRecord(target)!.RefreshToken);
            Assert.True(storage.DeleteRecord(target));
            Assert.False(File.Exists(file));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void TheRecordIsBoundedByTheSecretStoreLimit()
    {
        var record = new CloudCredentialRecord
        {
            NodeId = "00",
            CenterUrl = "https://c.example/" + new string('a', 2600),
            InstallationId = "00",
            AccessToken = "afa1.x",
            RefreshToken = "afr1.y",
        };
        Assert.Throws<InvalidOperationException>(record.Serialize);
        Assert.Null(CloudCredentialRecord.Parse("not json"u8));
    }

    private static CloudLinkOptions Options(LinkFixture link, NodeSecretStore store) => new()
    {
        DataRoot = link.DataRoot,
        NodeId = link.NodeId,
        Secrets = store,
        Keys = link.Keys,
        Center = () => link.ConfiguredCenter,
        Log = link.Log,
        Clock = link.Clock,
        NodeInfo = () => new ArcForges.Contracts.Fleet.V1.EnrollingNodeInfo(),
        Publish = _ => Task.CompletedTask,
    };
}
