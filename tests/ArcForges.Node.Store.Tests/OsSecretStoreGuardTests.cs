// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Security.Secrets;
using ArcForges.Tests;
using ArcForges.Tests.SecretStoreTier;

namespace ArcForges.Node.Store.Tests;

/// <summary>
/// The negative tests of the OS secret-store test guard (ArcForges-Design 16-testing-strategy section 1, item 4) in a routine test
/// process, which sets the tripwire switch (tests/Directory.Build.props) and carries no opt-in: every path to a real OS secret store is
/// refused before any OS call. The paths are the tier's fixture, a direct adapter call and the node's production composition root
/// (refused by the tripwire), and the composition root with <c>--test-mode</c> (which never selects an OS store; the closed-loop
/// <c>TestModeSecretStoreTests</c> shows it in a real node process). eng/test.ps1 and eng/test.sh start this project's
/// <see cref="ThisRoutineTestProcessDeniesTheOsStoresThroughItsRuntimeConfiguration"/> with the opt-in already set and show that it is
/// removed (ArcForges.Tools.Tests). Each refused call is chosen so that it makes no OS call even if the tripwire were missing (a
/// construction, a selection that only constructs, or a TCP bus address on which no Secret Service listens), so these tests can only
/// fail by assertion, never by reaching a store.
/// </summary>
public sealed class OsSecretStoreGuardTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("arcforges-guard-").FullName;

    public OsSecretStoreGuardTests()
    {
        // The precondition of every test here, checked before anything else: no opt-in in this routine process and the tripwire on. It
        // fails before any adapter is touched, so a stray value can never turn these tests into real-store calls.
        Assert.Null(Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable));
        Assert.True(OsSecretStoreGuard.IsDenied);
    }

    public static bool OnWindows => OperatingSystem.IsWindows();

    public static bool OnLinux => OperatingSystem.IsLinux();

    private string DataRoot => Path.Combine(_root, "data");

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void ThisRoutineTestProcessDeniesTheOsStoresThroughItsRuntimeConfiguration()
    {
        Assert.True(AppContext.TryGetSwitch(OsSecretStoreGuard.DenyOsStoresSwitch, out var deny));
        Assert.True(deny);
        var refusal = Assert.Throws<OsSecretStoreDeniedException>(() => OsSecretStoreGuard.ThrowIfDenied("the Windows Credential Manager"));
        Assert.Contains(OsSecretStoreGuard.OptInVariable + "=1", refusal.Message, StringComparison.Ordinal);
        if (OperatingSystem.IsWindows())
        {
            // The adapter's constructor makes no OS call; the tripwire refuses it.
            Assert.Throws<OsSecretStoreDeniedException>(CredentialManager);
        }
    }

    [Fact(Skip = "The Windows Credential Manager adapter exists only on Windows.", SkipUnless = nameof(OnWindows))]
    [SupportedOSPlatform("windows")]
    public void ADirectAdapterCallAndTheProductionSelectionAreRefusedBeforeAnyOsCall()
    {
        Assert.Throws<OsSecretStoreDeniedException>(CredentialManager);
        Assert.Throws<OsSecretStoreDeniedException>(() => OsSecretStore.SelectForCurrentPlatform(DataRoot));
        Assert.Throws<OsSecretStoreDeniedException>(() => OsSecretStore.CreateForCurrentPlatform());

        // The node's production composition root (no --test-mode) is refused the same way; it never falls back to another backend.
        Assert.Throws<OsSecretStoreDeniedException>(() => NodeSecretStores.ForNode(DataRoot, testMode: false));
        Assert.False(Directory.Exists(DataRoot));
    }

    [Fact(Skip = "The Secret Service adapter is selected only on Linux.", SkipUnless = nameof(OnLinux))]
    public void TheLinuxSelectionOfANonOwnedBusIsRefusedAndNeverFallsBackToTheFileStore()
    {
        // A TCP address is in the tripwire's scope (it cannot be shown to be test-owned); no Secret Service listens on this local port, so
        // an unguarded selection could not reach a store either and would only fail the assertion.
        var options = new SecretServiceOptions { BusAddress = "tcp:host=127.0.0.1,port=1", CallTimeout = TimeSpan.FromSeconds(2) };
        Assert.Throws<OsSecretStoreDeniedException>(() => OsSecretStore.SelectForCurrentPlatform(DataRoot, options));
        Assert.False(Directory.Exists(Path.Combine(DataRoot, "run")));
    }

    [Fact]
    public void ATestModeNodeWithoutTheOptInNeverSelectsAnOsStore()
    {
        var selected = NodeSecretStores.ForNode(DataRoot, testMode: true);

        Assert.True(selected.Isolated);
        var files = Assert.IsType<TestDataRootSecretStore>(selected.Store);
        Assert.Equal(Path.Combine(DataRoot, "run", TestDataRootSecretStore.DirectoryName), files.Directory);
        Assert.Equal(NodeSecretStores.TestBackend, selected.Backend);
        Assert.Equal(NodeSecretStores.TestProtection, selected.Protection);
        Assert.False(Directory.Exists(DataRoot));
    }

    [Theory]
    [InlineData(true, null, false)]
    [InlineData(true, "", false)]
    [InlineData(true, "0", false)]
    [InlineData(true, "true", false)]
    [InlineData(true, " 1", false)]
    [InlineData(true, "1", true)]
    [InlineData(false, null, true)]
    public void TheTestModeRuleSelectsAnOsStoreOnlyInProductionOrWithTheExactOptIn(bool testMode, string? optIn, bool osStore) =>
        Assert.Equal(osStore, NodeSecretStores.UsesOsSecretStore(testMode, optIn));

    [Fact]
    public void ATestModeProcessSetsTheTripwireUnlessTheExactOptInIsSetAndProductionNever()
    {
        // Only the decision is varied; setting the switch again in this test process (where it is already set) changes nothing.
        Assert.False(NodeSecretStores.ApplyTestModeTripwire(testMode: false, optIn: null));
        Assert.False(NodeSecretStores.ApplyTestModeTripwire(testMode: true, optIn: "1"));
        Assert.True(NodeSecretStores.ApplyTestModeTripwire(testMode: true, optIn: null));
        Assert.True(NodeSecretStores.ApplyTestModeTripwire(testMode: true, optIn: "true"));
        Assert.True(AppContext.TryGetSwitch(OsSecretStoreGuard.DenyOsStoresSwitch, out var deny) && deny);
        Assert.True(OsSecretStoreGuard.IsDenied);
    }

    [Fact]
    public void TheTiersFixtureRefusesWithoutTheOptInBeforeAnyCall()
    {
        var backend = new IsolatedSecretStore();
        var tier = new OsSecretStoreTier();
        try
        {
            Assert.False(OsSecretStoreTier.OptedIn);
            Assert.False(OsSecretStoreTier.WindowsTier);
            Assert.ThrowsAny<InvalidOperationException>(() => tier.NewEntry(backend));
            var name = OsSecretStoreTier.EntryName(tier.RunId, 1);
            Assert.ThrowsAny<InvalidOperationException>(() => tier.NewEntry(name, backend));
            Assert.False(tier.IsListed(name));
            Assert.ThrowsAny<InvalidOperationException>(() => tier.Call("read " + name, () => backend.Read(name)));
            Assert.Equal(0, tier.Calls);
        }
        finally
        {
            tier.Dispose();
        }

        Assert.Equal((0, 0, 0), (backend.Writes, backend.Reads, backend.Deletes));
        Assert.False(File.Exists(tier.NameList));
    }

    [SupportedOSPlatform("windows")]
    private static void CredentialManager() => _ = new WindowsCredentialManagerSecretStore();
}
