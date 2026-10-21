// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Security.Secrets;

namespace ArcForges.Node.Store;

/// <summary>
/// The node's reviewed composition root for OS-wide secret stores (16-testing-strategy section 1, guard item 3; 02-node-service
/// section 4). It is the only production source that names DesktopPlatform's OS secret-store selection
/// (<c>ArcForges.Repository.Tests</c> checks this):
/// <list type="bullet">
/// <item>Without <c>--test-mode</c> (production): DesktopPlatform's <c>SelectForCurrentPlatform</c>, unchanged (AD-0011 section 4).</item>
/// <item>With <c>--test-mode</c>: never an OS-wide secret store unless <c>ARCFORGES_OS_SECRET_STORE_TESTS=1</c> (the OS secret-store
/// tier's single opt-in) is set; otherwise the file-backed isolated store under the test data root
/// (<see cref="TestDataRootSecretStore"/>), which keeps restart and retry tests' keys.</item>
/// </list>
/// Every secret the node holds in the OS secret store takes its store from here. Today that is the node data key; the node
/// credential, the LAN link tokens and the CNG node key (AF-LAN-01) are not
/// delivered yet. <em>Note (2026-10-18):</em> when they are, they take their store from <see cref="ForNode(string, bool)"/> (the CNG
/// node key a file-backed key in the test data root under the same rule), so <c>--test-mode</c> keeps them in the test data root too.
/// </summary>
internal static class NodeSecretStores
{
    /// <summary>The prefix of every canonical secret-store target.</summary>
    public const string TargetPrefix = "ArcForges.Secrets.v1.";

    /// <summary>Why a test backend is not the OS secret store (reported as the fallback reason where the platform reports one).</summary>
    public const string TestBackendReason = "isolated test backend (--test-mode or a test): no OS-wide secret store is used";

    /// <summary>
    /// The backend the isolated test backends report: what the node's selection reports on this platform for a test node (Windows
    /// Credential Manager; on Linux the owner-only file store, as test nodes never reach the user's session bus). Recording the same
    /// label keeps everything above the adapter (key versions per backend, logs) as in production (16 section 2).
    /// </summary>
    public static SecretStoreBackend TestBackend => OperatingSystem.IsWindows() ? SecretStoreBackend.WindowsCredentialManager : SecretStoreBackend.OwnerOnlyFile;

    /// <summary>The protection the isolated test backends report, matching <see cref="TestBackend"/>.</summary>
    public static SecretStoreProtection TestProtection => OperatingSystem.IsWindows() ? SecretStoreProtection.OsSecretStore : SecretStoreProtection.FileOwnerOnly;

    /// <summary>The node's secret store for its data root, following the <c>--test-mode</c> rule (see the type).</summary>
    public static NodeSecretStore ForNode(string dataRoot, bool testMode) =>
        ForNode(dataRoot, testMode, Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable));

    /// <summary>As <see cref="ForNode(string, bool)"/> with the opt-in's value given.</summary>
    internal static NodeSecretStore ForNode(string dataRoot, bool testMode, string? optIn) => UsesOsSecretStore(testMode, optIn)
        ? NodeSecretStore.FromSelection(OsSecretStore.SelectForCurrentPlatform(dataRoot))
        : ForTestDataRoot(dataRoot);

    /// <summary>
    /// The decision of the <c>--test-mode</c> rule: production (no test mode) uses the OS secret store; a test-mode node only with the
    /// exact opt-in <c>1</c>, as DesktopPlatform's tripwire decides.
    /// </summary>
    public static bool UsesOsSecretStore(bool testMode, string? optIn) => !testMode || optIn == "1";

    /// <summary>
    /// The runtime tripwire for a process started with <c>--test-mode</c> (16-testing-strategy section 1, item 2): unless the tier's
    /// exact opt-in is set, sets the AppContext switch <c>ArcForges.Security.Secrets.DenyOsStores</c> in this process, so a test node,
    /// CLI or helper also refuses the user's OS secret stores before any OS call, as every test process does. Without test mode
    /// (production) nothing is set. Returns whether the switch was set.
    /// </summary>
    public static bool ApplyTestModeTripwire(bool testMode) =>
        ApplyTestModeTripwire(testMode, Environment.GetEnvironmentVariable(OsSecretStoreGuard.OptInVariable));

    /// <summary>As <see cref="ApplyTestModeTripwire(bool)"/> with the opt-in's value given.</summary>
    internal static bool ApplyTestModeTripwire(bool testMode, string? optIn)
    {
        if (UsesOsSecretStore(testMode, optIn))
        {
            return false;
        }

        AppContext.SetSwitch(OsSecretStoreGuard.DenyOsStoresSwitch, true);
        return true;
    }

    /// <summary>The file-backed isolated store under <paramref name="dataRoot"/>, with the test labels.</summary>
    public static NodeSecretStore ForTestDataRoot(string dataRoot) =>
        new(new TestDataRootSecretStore(dataRoot), TestBackend, TestProtection, OperatingSystem.IsWindows() ? null : TestBackendReason, isolated: true);

    /// <summary>A canonical target: <c>ArcForges.Secrets.v1.</c> and 64 uppercase hexadecimal digits (also a safe file name).</summary>
    public static void ValidateTarget(string opaqueTarget)
    {
        ArgumentNullException.ThrowIfNull(opaqueTarget);
        if (opaqueTarget.Length != TargetPrefix.Length + 64 || !opaqueTarget.StartsWith(TargetPrefix, StringComparison.Ordinal)
            || !opaqueTarget.AsSpan(TargetPrefix.Length).ContainsOnlyUpperHex())
        {
            throw new ArgumentException("A secret-store target is 'ArcForges.Secrets.v1.' and 64 uppercase hexadecimal digits.", nameof(opaqueTarget));
        }
    }

    private static bool ContainsOnlyUpperHex(this ReadOnlySpan<char> text)
    {
        foreach (var character in text)
        {
            if (character is not ((>= '0' and <= '9') or (>= 'A' and <= 'F')))
            {
                return false;
            }
        }

        return true;
    }
}
