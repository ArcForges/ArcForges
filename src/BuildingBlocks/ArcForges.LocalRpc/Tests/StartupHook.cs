// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;

/// <summary>The startup-hook entry the runtime calls (by this exact name) before the entry point when the hook names this assembly.</summary>
[SuppressMessage("Design", "CA1050", Justification = "The runtime requires the startup hook type to be in the global namespace.")]
internal static class StartupHook
{
    public static void Initialize() => ArcForges.LocalRpc.Tests.LaunchHelperProcess.RunWhenAHelper();
}
