// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core;

/// <summary>
/// The node's capability report (architecture 02 section 2 step 6; 03 section 8). The enforcement platform layer (Windows jobs,
/// Linux cgroups through the user manager, and its self-test) belongs to the execution and resource-control tasks; until it is part
/// of the build, every enforcement capability is reported as OBSERVE_ONLY with that reason, and the node is DEGRADED (SM-NODE:
/// RECOVERING -> DEGRADED when a capability is missing). The platform facts are read from the running system.
/// </summary>
public static class NodeCapabilities
{
    /// <summary>The reason recorded for every enforcement capability of this build.</summary>
    public const string NotInBuild = "the enforcement platform layer is not part of this build";

    /// <summary>The lifecycle reason of the DEGRADED state this report leads to.</summary>
    public const string DegradedReason = "capabilities_observe_only";

    /// <summary>Evaluates the report now.</summary>
    public static CapabilityReport Evaluate(TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        var report = new CapabilityReport
        {
            Cpu = CpuControl.ObserveOnly,
            CpuReason = NotInBuild,
            Memory = MemoryControl.ObserveOnly,
            MemoryReason = NotInBuild,
            Pids = ProcessCountControl.ObserveOnly,
            PidsReason = NotInBuild,
            Io = IoControl.ObserveOnly,
            IoReason = NotInBuild,
            EvaluatedAt = ProtoTime.ToInstant(clock.GetUtcNow()),
        };
        report.PlatformFacts.Add(Fact("os", RuntimeInformation.OSDescription));
        report.PlatformFacts.Add(Fact("arch", RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant()));
        report.PlatformFacts.Add(Fact("runtime", RuntimeInformation.FrameworkDescription));
        if (OperatingSystem.IsLinux())
        {
            report.PlatformFacts.Add(Fact("cgroup_v2", File.Exists("/sys/fs/cgroup/cgroup.controllers") ? "present" : "absent"));
            report.PlatformFacts.Add(Fact("systemd_user_manager", NodeAutoStart.UserManagerAvailable() ? "running" : "absent"));
        }

        return report;
    }

    /// <summary>True when every enforcement capability is enforced (READY rather than DEGRADED).</summary>
    public static bool FullyEnforced(CapabilityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return report.Cpu is CpuControl.EnforcedShareAndCap or CpuControl.EnforcedShare
            && report.Memory is MemoryControl.EnforcedSoftAndHard or MemoryControl.EnforcedCommit
            && report.Pids == ProcessCountControl.Enforced;
    }

    private static KeyValue Fact(string name, string value) => new() { Name = name, Value = value };
}
