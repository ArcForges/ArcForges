// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Supervisor;

/// <summary>
/// <c>arcforges-supervisor.exe [--test-mode]</c>: started at logon from the HKCU Run key (13 section 3.1) or by a client's auto-start
/// (02 section 3). It runs <c>arcforges.exe node run</c> beside it and restarts the node after a crash. A second supervisor of the
/// same user exits at once.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            return 1;
        }

        var testMode = args.Contains(SupervisorLocations.TestModeOption, StringComparer.Ordinal);
        return new NodeSupervisor(SupervisorLocations.Resolve(testMode), TimeProvider.System).Run();
    }
}
