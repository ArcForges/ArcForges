// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.ContentSandbox.Contracts;

namespace ArcForges.ContentSandbox.Broker.Linux;

/// <summary>The data of the Linux launch: where each inherited resource lands in the child, and the whole environment the child receives.</summary>
internal static class LinuxLaunchPlan
{
    /// <summary>The fixed child-side numbers: the plan every launch follows.</summary>
    internal static IReadOnlyList<(ContentSandboxHandleRole Role, int Target)> TargetPlan(int slotCount)
    {
        var plan = new List<(ContentSandboxHandleRole, int)>
        {
            (ContentSandboxHandleRole.Control, 3),
            (ContentSandboxHandleRole.Service, 4),
            (ContentSandboxHandleRole.Input, 5),
        };
        for (var index = 0; index < slotCount; index++)
        {
            plan.Add(((ContentSandboxHandleRole)((int)ContentSandboxHandleRole.Slot0 + index), 6 + index));
        }

        return plan;
    }

    /// <summary>The whole environment of the helper: a GC heap bound and nothing else. No home, no path, no inherited secret.</summary>
    internal static IReadOnlyList<string> Environment(ContentSandboxLimits limits) =>
    [
        "DOTNET_gcServer=0",
        "DOTNET_GCHeapHardLimit=" + limits.MaxMemoryBytes.ToString("x", CultureInfo.InvariantCulture),
    ];
}
