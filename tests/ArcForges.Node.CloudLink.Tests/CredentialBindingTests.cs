// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using ArcForges.Security.Secrets;
using ArcForges.Tests;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// N1-6, N1-7 and N1-17 (CTR4-SEC-19; N1 decisions R-1 and G-1; the interim review's FX-1..FX-4 with the reviewers' probes S1-S4 ported):
/// the credential is bound to its own center for every call, a center change ends every credential of the old center, and an ending is
/// finished only where the record lives and only once every deletion succeeded. MOCKED center (FakeCenter) and time (manual clock),
/// ISOLATED store, REAL files.
/// </summary>
public sealed class CredentialBindingTests
{
    private const string Refresh = "RefreshNodeSession";
    private const string Report = "ReportNodeInfo";

    [Fact]
    public async Task ACenterConfiguredWhileSignedInReceivesNothingAndTheCredentialIsHeldForItsOwnCenter()
    {
        // Probe S1: node.json names another center while the node is signed in (a hand edit, a same-user process).
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        await Eventually.TrueAsync(() => link.Center.CallsOf(Report).Count == 1, "the first report");
        await using var other = await FakeCenter.StartAsync("/other");
        link.ConfiguredCenter = other.Endpoint;
        link.NodeName = "renamed";
        link.Service.NodeInfoChanged();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(70),
            () => link.Service.Status().Warnings.Contains("credential_for_other_center"), "the credential held for its own center");
        link.Clock.Advance(TimeSpan.FromHours(3));
        await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.Empty(other.Calls);
        Assert.Empty(link.Center.CallsOf(Refresh));
        Assert.Single(link.Center.CallsOf(Report));
        Assert.False(link.Service.AccountLinked);
        Assert.Equal(issued.RefreshToken, link.StoredRecord()!.RefreshToken);
        Assert.True(link.Center.IsLive(issued.RefreshToken));
    }

    [Fact]
    public async Task ASignOutUnderAnotherConfiguredCenterSendsNothingAndStillEndsLocally()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await Eventually.TrueAsync(() => link.Center.CallsOf(Report).Count == 1, "the first report");
        await using var other = await FakeCenter.StartAsync("/other");
        link.ConfiguredCenter = other.Endpoint;
        using (await link.Service.EnterAsync(CancellationToken.None))
        {
            Assert.Equal(SignOutResult.RemoteUnconfirmed, await link.Service.SignOutHeldAsync(revokeRemote: true));
        }

        Assert.Empty(other.Calls);
        Assert.Empty(link.Center.CallsOf("SignOutNode"));
        Assert.Empty(link.Secrets.Names());
        Assert.False(File.Exists(link.Storage.LinkPath));
    }

    [Fact]
    public async Task ARejectedCredentialEndsOnACenterChangeAndTheNewCenterReceivesNothing()
    {
        // Probe S2: a credential held as center_rejected_credential (phase SignedOut, which UpdateNodeSettings allows to change the center).
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        await Eventually.TrueAsync(() => link.Center.CallsOf(Report).Count == 1, "the first report");
        link.Center.Script(Refresh, new FakeFault.Refusal(Arc(ErrorCategory.Authentication, "unauthenticated")));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45),
            () => link.Service.Status().Warnings.Contains("center_rejected_credential"), "the rejection");
        Assert.Equal(CloudLinkPhase.SignedOut, link.Service.Phase);
        Assert.NotNull(link.Keys.Recorded());
        Assert.True(File.Exists(link.Storage.KeysPath));

        await using var other = await FakeCenter.StartAsync("/other");
        link.ConfiguredCenter = other.Endpoint;
        await link.Service.CenterChangedAsync();
        Assert.Equal("center_changed", link.Service.LastError);
        Assert.Empty(link.Secrets.Names());
        Assert.False(File.Exists(link.Storage.LinkPath));
        Assert.False(File.Exists(link.Storage.KeysPath));
        Assert.Null(link.Keys.Recorded());
        Assert.Empty(Directory.GetFiles(link.KeyFiles.Directory));
        link.Clock.Advance(TimeSpan.FromHours(3));
        await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.Empty(other.Calls);
        Assert.Single(link.Center.CallsOf(Refresh));
    }

    [Fact]
    public async Task ACenterChangeWithoutACredentialDeletesTheOldCentersKeySetsAndKey()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        link.Storage.WriteKeys(new CloudKeySetFile { CenterUrl = link.Center.Endpoint.Url, InstallationId = new string('0', 32) });
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        link.ConfiguredCenter = CenterEndpoint.Parse("https://other.example.test");
        await link.Service.CenterChangedAsync();
        Assert.False(File.Exists(link.Storage.KeysPath));
        Assert.Null(link.Keys.Recorded());
        Assert.Empty(Directory.GetFiles(link.KeyFiles.Directory));
    }

    [Fact]
    public async Task ACenterChangeBackToTheCredentialsOwnCenterSignsItInAgain()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();
        link.ConfiguredCenter = CenterEndpoint.Parse("https://other.example.test");
        await link.StartAsync();
        Assert.Contains("credential_for_other_center", link.Service.Status().Warnings);
        link.ConfiguredCenter = link.Center.Endpoint;
        await link.Service.CenterChangedAsync();
        Assert.True(link.Service.AccountLinked);
        Assert.DoesNotContain("credential_for_other_center", link.Service.Status().Warnings);
    }

    [Fact]
    public async Task AnInterruptedEndingIsNeverFinishedInAnotherBackendAndResumesInItsOwn()
    {
        // Probe S3: the ending was written while the Secret Service held the record; the next start selects the owner-only file store.
        await using var link = await LinkFixture.CreateAsync();
        link.Secrets = new IsolatedSecretStore(SecretStoreBackend.SecretService, SecretStoreProtection.OsSecretStore);
        var held = link.Secrets;
        await link.StartAsync();
        await link.SignInAsync();
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        await link.StopAsync();
        var file = link.Storage.ReadLink()!;
        file.State = LinkStates.Ending;
        link.Storage.WriteLink(file);

        link.Secrets = new IsolatedSecretStore(SecretStoreBackend.OwnerOnlyFile, SecretStoreProtection.FileOwnerOnly);
        await link.StartAsync();
        Assert.Contains("credential_backend_changed", link.Service.Status().Warnings);
        Assert.Equal(LinkStates.Ending, link.Storage.ReadLink()!.State);
        Assert.Single(held.Names());
        Assert.NotNull(link.Keys.Recorded());
        using (await link.Service.EnterAsync(CancellationToken.None))
        {
            Assert.Equal(SignOutResult.NotSignedIn, await link.Service.SignOutHeldAsync(revokeRemote: false));
        }

        Assert.True(File.Exists(link.Storage.LinkPath));
        Assert.Single(held.Names());

        await link.StopAsync();
        link.Secrets = held;
        await link.StartAsync();
        Assert.Empty(held.Names());
        Assert.False(File.Exists(link.Storage.LinkPath));
        Assert.Null(link.Keys.Recorded());
    }

    [Fact]
    public async Task ANodeKeyThatCannotBeDeletedKeepsTheEndingRecordedUntilItIs()
    {
        await using var link = await LinkFixture.CreateAsync();
        var keys = new FailingDeletes(link.KeyFiles);
        link.Keys = new NodeKeyStore(link.DataRoot, keys);
        await link.StartAsync();
        var issued = await link.SignInAsync();
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        await Eventually.TrueAsync(() => link.Center.CallsOf(Report).Count == 1, "the first report");
        keys.Fail = true;
        link.Center.Revoke(issued.RefreshToken);
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Service.Phase == CloudLinkPhase.SignedOut,
            "signed out");
        Assert.Equal(LinkStates.Ending, link.Storage.ReadLink()!.State);
        Assert.Contains("credential_store_unavailable", link.Service.Status().Warnings);
        Assert.NotNull(link.Keys.Recorded());
        Assert.Single(Directory.GetFiles(link.KeyFiles.Directory));
        Assert.Empty(link.Secrets.Names());

        // The loop retries the ending every minute; once the key store answers it completes.
        keys.Fail = false;
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(3), () => !File.Exists(link.Storage.LinkPath), "the ending finished");
        Assert.Null(link.Keys.Recorded());
        Assert.Empty(Directory.GetFiles(link.KeyFiles.Directory));
        Assert.DoesNotContain("credential_store_unavailable", link.Service.Status().Warnings);
    }

    [Fact]
    public async Task AKeyInAReadOnlyDirectoryKeepsTheEndingAndARestartFinishesIt()
    {
        // Probe S4: run/node-key made read-only (0500), then a revocation; after a restart with the directory writable the ending resumes.
        Assert.SkipWhen(OperatingSystem.IsWindows(), "Unix file modes: a read-only directory does not stop a deletion on Windows; "
            + "ANodeKeyThatCannotBeDeletedKeepsTheEndingRecordedUntilItIs covers the same rule on every system.");
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        await Eventually.TrueAsync(() => link.Center.CallsOf(Report).Count == 1, "the first report");
        var directory = link.KeyFiles.Directory;
        File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            link.Center.Revoke(issued.RefreshToken);
            await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Service.Phase == CloudLinkPhase.SignedOut,
                "signed out");
            Assert.Single(Directory.GetFiles(directory));
            Assert.True(File.Exists(link.Storage.LinkPath));
            Assert.Equal(LinkStates.Ending, link.Storage.ReadLink()!.State);
            await link.StopAsync();
        }
        finally
        {
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        await link.StartAsync();
        Assert.Empty(Directory.GetFiles(directory));
        Assert.False(File.Exists(link.Storage.LinkPath));
        Assert.Null(link.Keys.Recorded());
        Assert.True(string.IsNullOrEmpty(link.Service.Status().NodeKeyFingerprint));
    }

    [Fact]
    public async Task ACommittingLinkWithoutItsRecordIsSignedOutAndItsFilesRemoved()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        using (link.Keys.Create(link.NodeId, link.Center.Endpoint.Origin, link.Clock))
        {
        }

        await link.StopAsync();
        var file = link.Storage.ReadLink()!;
        file.State = LinkStates.Committing;
        link.Storage.WriteLink(file);
        link.Storage.DeleteRecord(file.Target);
        await link.StartAsync();
        Assert.False(link.Service.AccountLinked);
        Assert.DoesNotContain(link.Service.Status().Warnings, warning => warning != "isolated_test_backend");
        Assert.False(File.Exists(link.Storage.LinkPath));
        Assert.False(File.Exists(link.Storage.KeysPath));
        Assert.Null(link.Keys.Recorded());
    }

    [Fact]
    public async Task ALinkFileNamingAnotherEntryNeverDeletesIt()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();
        var foreign = NodeSecretStores.TargetPrefix + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("another entry")));
        link.Secrets.Write(foreign, [1, 2, 3]);
        var file = link.Storage.ReadLink()!;
        file.State = LinkStates.Ending;
        file.Target = foreign;
        link.Storage.WriteLink(file);
        await link.StartAsync();
        Assert.Contains(foreign, link.Secrets.Names());
        Assert.Equal(2, link.Secrets.Names().Count);
        Assert.True(File.Exists(link.Storage.LinkPath));
        Assert.Contains("credential_store_unavailable", link.Service.Status().Warnings);
    }

    [Fact]
    public async Task AnUnparsableLinkFileIsAnErrorStateAndNothingIsDeleted()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await link.StopAsync();
        File.WriteAllText(link.Storage.LinkPath, "{ not a link file");
        await link.StartAsync();
        Assert.False(link.Service.AccountLinked);
        Assert.Contains("credential_store_unavailable", link.Service.Status().Warnings);
        Assert.True(File.Exists(link.Storage.KeysPath));
        Assert.Single(link.Secrets.Names());
        using (await link.Service.EnterAsync(CancellationToken.None))
        {
            Assert.Equal(SignOutResult.NotSignedIn, await link.Service.SignOutHeldAsync(revokeRemote: false));
        }

        Assert.Single(link.Secrets.Names());
    }

    [Fact]
    public async Task AdoptingNeverReplacesTheLinkOfAnotherCredential()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        await using var other = await FakeCenter.StartAsync("/other");
        await Assert.ThrowsAsync<InvalidOperationException>(() => link.Service.AdoptAsync(other.Issue(link.NodeId), other.Endpoint));
        Assert.True(link.Service.AccountLinked);
        Assert.Equal(issued.RefreshToken, link.StoredRecord()!.RefreshToken);
        Assert.Equal(link.Center.Endpoint.Url, link.Storage.ReadLink()!.CenterUrl);
    }

    [Fact]
    public async Task AnInvalidNodeJsonNeitherBreaksTheStatusNorSendsAnythingUntilItIsFixed()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        await Eventually.TrueAsync(() => link.Center.CallsOf(Report).Count == 1, "the first report");
        link.CenterFailure = new NodeConfigurationException("node.json: not a configuration file");
        Assert.Equal(link.Center.Endpoint.Url, link.Service.Status().CenterUrl);
        link.Clock.Advance(TimeSpan.FromMinutes(70));
        await Eventually.TrueAsync(() => link.Service.Idle, "the loop waits");
        link.Clock.Advance(TimeSpan.FromMinutes(5));
        await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.Empty(link.Center.CallsOf(Refresh));
        Assert.NotNull(link.Service.Status());

        link.CenterFailure = null;
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(5), () => link.Center.CallsOf(Refresh).Count == 1, "the refresh");
        Assert.True(link.Service.AccountLinked);
    }

    [Fact]
    public async Task ADependencyUnavailableAfterACommittedRefreshIsReportedAsALostReply()
    {
        // The hosted Worker answers dependency.unavailable also after the request reached the center (proto finding 5).
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        var issued = await link.SignInAsync();
        link.Center.Script(Refresh, new FakeFault.ReplacedReply(14, "dependency.unavailable"));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(45), () => link.Service.Phase == CloudLinkPhase.SignedOut,
            "the reuse refused");
        Assert.Equal("refresh_reply_lost", link.Service.LastError);
        Assert.False(link.Center.IsLive(issued.RefreshToken));
    }

    [Fact]
    public async Task ANodeClockAheadNeverRetriesARateLimitedRefreshInALoop()
    {
        await using var link = await LinkFixture.CreateAsync();
        await link.StartAsync();
        await link.SignInAsync();
        var limited = Arc(ErrorCategory.Resource, "rate_limited");
        limited.Retry = new RetryAdvice { Mode = RetryMode.AfterTime, RetryAt = ProtoTime.ToInstant(link.Clock.GetUtcNow() + TimeSpan.FromMinutes(45)) };
        for (var i = 0; i < 100; i++)
        {
            link.Center.Script(Refresh, new FakeFault.Refusal(limited));
        }

        // The node's wall clock jumps an hour ahead: retry_at is already past by its clock.
        link.Clock.SetWall(link.Clock.GetUtcNow() + TimeSpan.FromHours(1));
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(45), () => link.Center.CallsOf(Refresh).Count == 1, "the first refresh");
        var first = link.Clock.GetTimestamp();
        await Eventually.AdvanceUntilAsync(link, TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(11),
            () => link.Clock.GetElapsedTime(first) >= TimeSpan.FromMinutes(10), "ten minutes");
        Assert.InRange(link.Center.CallsOf(Refresh).Count, 2, 12);
    }

    private static ArcError Arc(ErrorCategory category, string code) => new()
    {
        Code = code,
        Category = category,
        MessageKey = "error." + category.ToString().ToLowerInvariant() + "." + code,
        Retry = new RetryAdvice { Mode = RetryMode.Never },
        Effect = EffectCertainty.DidNotHappen,
    };

    /// <summary>The file-backed key backend whose deletions fail while <see cref="Fail"/> is set (a locked key store).</summary>
    private sealed class FailingDeletes(FileNodeKeyBackend inner) : INodeKeyBackend
    {
        public bool Fail { get; set; }

        public string Kind => inner.Kind;

        public INodeKey? Open(string name) => inner.Open(name);

        public INodeKey Create(string name) => inner.Create(name);

        public bool Delete(string name) => Fail ? throw new IOException("The key store is locked.") : inner.Delete(name);

        public IReadOnlyList<string> Names() => inner.Names();
    }
}
