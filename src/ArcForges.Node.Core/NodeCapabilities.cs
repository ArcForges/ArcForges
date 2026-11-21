// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using ArcForges.Client;
using ArcForges.Contracts.Node.V1;

namespace ArcForges.Node.Core;

/// <summary>
/// Baseline Node capability diagnostics and platform facts. Sandbox Run profiles report their own MXC readiness.
/// </summary>
public static class NodeCapabilities
{
    /// <summary>The reason recorded for the retired Node-wide enforcement capability fields.</summary>
    public const string NotInBuild = "legacy Node-wide enforcement has been retired; see Sandbox Run readiness";

    /// <summary>The first missing capability's reason in the Node-wide diagnostic report.</summary>
    public static string? MissingReason(CapabilityReport report) => MissingReason(report, OperatingSystem.IsWindows());

    /// <summary>The first missing capability's reason under the readiness rule of the Windows job platform or of the other platforms.</summary>
    public static string? MissingReason(CapabilityReport report, bool windowsJobs)
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

        return windowsJobs || report.Pids == ProcessCountControl.Enforced ? null : report.PidsReason;
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
            Adopt = AdoptSupport.Unsupported,
            AdoptReason = "legacy process adoption has been retired",
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

    /// <summary>True when the Node-wide diagnostic report describes fully enforced resource control.</summary>
    public static bool FullyEnforced(CapabilityReport report) => FullyEnforced(report, OperatingSystem.IsWindows());

    /// <summary>
    /// The readiness rule, platform-explicit (SM-NODE: RECOVERING to DEGRADED when "some capability missing"). Every platform needs cpu
    /// and memory enforced. Other platforms (Linux cgroups) also need <c>pids</c> enforced, as before this task. The Windows job platform
    /// does not: no policy field sets a job active-process limit in this build, so it reports <c>pids</c> OBSERVE_ONLY (counted by job
    /// accounting) and that alone does not degrade it. Whether the state machine means this is a Design clarification (PR body).
    /// <c>io</c> never degrades a node (I/O limits are a privileged option).
    /// </summary>
    public static bool FullyEnforced(CapabilityReport report, bool windowsJobs)
    {
        ArgumentNullException.ThrowIfNull(report);
        return report.Cpu is CpuControl.EnforcedShareAndCap or CpuControl.EnforcedShare
            && report.Memory is MemoryControl.EnforcedSoftAndHard or MemoryControl.EnforcedCommit
            && (windowsJobs || report.Pids == ProcessCountControl.Enforced);
    }

    /// <summary>
    /// Linux: adds the fact <c>data_root_filesystem</c> (<c>disk</c>, or the in-memory file systems under the data root and why that
    /// matters) and returns the in-memory (path, kind) pairs; see <see cref="Platform.MemoryFileSystems"/>.
    /// </summary>
    public static List<(string Path, string Kind)> AddDataRootFact(CapabilityReport report, string dataRoot)
    {
        ArgumentNullException.ThrowIfNull(report);
        var inMemory = Platform.MemoryFileSystems.UnderDataRoot(dataRoot);
        report.PlatformFacts.Add(Fact("data_root_filesystem", inMemory.Count == 0
            ? "disk"
            : string.Join(", ", inMemory.Select(item => $"{item.Kind} ({item.Path})"))
                + ": in memory, so captured output and temporary files count against each attempt's memory limits"));
        return inMemory;
    }

    private static KeyValue Fact(string name, string value) => new() { Name = name, Value = value };
}
