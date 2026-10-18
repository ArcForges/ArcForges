// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Supervisor;

/// <summary>
/// <c>arcforges-supervisor.exe [--test-mode]</c>: started at logon from the HKCU Run key (13 section 3.1) or by a client's auto-start
/// (02 section 3). It runs <c>arcforges.exe node run</c> beside it and restarts the node after a crash. A second supervisor of the
/// same user exits at once.
/// </summary>
internal static class Program
{
    /// <summary>The AppContext switch of DesktopPlatform's OsSecretStoreGuard that denies the real OS secret stores.</summary>
    internal const string DenyOsStoresSwitch = "ArcForges.Security.Secrets.DenyOsStores";

    /// <summary>The OS secret-store tier's single opt-in.</summary>
    internal const string OsSecretStoreOptIn = "ARCFORGES_OS_SECRET_STORE_TESTS";

    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            return 1;
        }

        var testMode = args.Contains(SupervisorLocations.TestModeOption, StringComparer.Ordinal);
        if (testMode && Environment.GetEnvironmentVariable(OsSecretStoreOptIn) != "1")
        {
            // The OS secret-store tripwire of a --test-mode process (16-testing-strategy section 1, item 2), as the arcforges host sets
            // it; production is unaffected. The names are DesktopPlatform's OsSecretStoreGuard constants (the supervisor references no
            // Security.Secrets package; ArcForges.Repository.Tests checks that the literals match the host's).
            AppContext.SetSwitch(DenyOsStoresSwitch, true);
        }

        return new NodeSupervisor(SupervisorLocations.Resolve(testMode), TimeProvider.System).Run();
    }
}
