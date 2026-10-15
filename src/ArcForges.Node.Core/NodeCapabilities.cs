// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core;

/// <summary>
/// The node's capability report (architecture 02 section 2 step 6; 03 section 8). On Windows the execution platform (job objects,
/// AF-EXEC-01) reports its capabilities after its self-test (<see cref="FromPlatform"/>). Where this build has no execution platform
/// (Linux until AF-EXEC-02), every enforcement capability is reported as OBSERVE_ONLY with that reason, and the node is DEGRADED
/// (SM-NODE: RECOVERING -> DEGRADED when a capability is missing). The platform facts are read from the running system.
/// </summary>
public static class NodeCapabilities
{
    /// <summary>The reason recorded for every enforcement capability where the build has no execution platform.</summary>
    public const string NotInBuild = "the enforcement platform layer for this operating system is not part of this build";

    /// <summary>The report of a started execution platform, stamped with the evaluation time.</summary>
    public static CapabilityReport FromPlatform(ArcForges.Node.Platform.IExecutionPlatform platform, TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(platform);
        ArgumentNullException.ThrowIfNull(clock);
        var report = platform.Evaluate();
        report.EvaluatedAt = ProtoTime.ToInstant(clock.GetUtcNow());
        return report;
    }

    /// <summary>The first missing capability's reason, or <see langword="null"/> when every capability is enforced.</summary>
    public static string? MissingReason(CapabilityReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.Cpu is not (CpuControl.EnforcedShareAndCap or CpuControl.EnforcedShare))
        {
            return report.CpuReason;
        }

        if (report.Memory is not (MemoryControl.EnforcedSoftAndHard or MemoryControl.EnforcedCommit))
        {
            return report.MemoryReason;
        }

        return report.Pids == ProcessCountControl.Enforced ? null : report.PidsReason;
    }

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
