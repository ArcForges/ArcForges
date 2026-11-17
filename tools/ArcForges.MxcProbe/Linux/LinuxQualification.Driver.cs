// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;

namespace ArcForges.MxcProbe.Linux;

internal static partial class LinuxQualification
{
    internal static async Task<int> RunAsync(string[] args)
    {
        var report = new LinuxQualificationReport { RunId = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture) };
        LinuxEvidence? log = null;
        LinuxServiceScope? scope = null;
        string? reportPath = null;
        string phase = "arguments";
        try
        {
            if (!OperatingSystem.IsLinux()) throw new LinuxProbeException("linux_host_required");
            Require(args.Length == 8 && args[0] == "--manifest" && args[2] == "--work"
                && args[4] == "--report" && args[6] == "--only", "linux_profile_arguments");
            string group = args[7];
            Require(group is "terminal" or "policy" or "network" or "resource" or "lifecycle", "linux_diagnostic_group_invalid");
            reportPath = Path.GetFullPath(args[5]);
            string manifest = Path.GetFullPath(args[1]);
            string stage = Path.GetDirectoryName(manifest)!;
            string work = Path.GetFullPath(args[3]);
            Require(!IsWithin(reportPath, stage) && !IsWithin(work, stage) && !IsWithin(reportPath, work), "mutable_path_in_stage");
            Require(!File.Exists(reportPath) && !Directory.Exists(reportPath)
                && !File.Exists(work) && !Directory.Exists(work), "fresh_evidence_paths_required");
            ValidateAncestors(Path.GetDirectoryName(reportPath)!);
            ValidateAncestors(Path.GetDirectoryName(work)!);
            log = new LinuxEvidence(reportPath + ".events.jsonl", report.RunId);
            phase = "stage_validation";
            log.Phase(phase, "begin");
            Program.ValidateStage(manifest);
            log.Phase(phase, "verified");
            phase = "workspace_prepare";
            log.Phase(phase, "begin");
            Directory.CreateDirectory(work, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            string control = Path.Combine(work, "control");
            string data = Path.Combine(work, "sandbox");
            Directory.CreateDirectory(control, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.CreateDirectory(data, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            if (group is "resource" or "lifecycle")
            {
                phase = group + "_cases";
                log.Phase(phase, "begin");
                var resource = group == "resource"
                    ? await LinuxResourceCases.RunAsync(manifest, data, control, log).ConfigureAwait(false)
                    : await LinuxLifecycleCases.RunAsync(manifest, data, control, log).ConfigureAwait(false);
                report.Cases = resource.Cases;
                report.CleanupConfirmed = resource.CleanupConfirmed;
                report.DiagnosticSlicePassed = report.Cases.Count > 0 && report.Cases.All(x => x.Passed);
                log.Phase(phase, report.DiagnosticSlicePassed ? "slice_passed" : "slice_failed");
            }
            else
            {
                string unit = "arcforges-mxc03-" + report.RunId + ".service";
                var config = new LinuxOwnerConfiguration(report.RunId, manifest, data, control,
                    Path.Combine(control, "ready.json"), Path.Combine(control, "continue"),
                    Path.Combine(control, "owner-report.json"), Path.Combine(control, "owner-events.jsonl"),
                    unit, group, 512L * 1024 * 1024, 128, 50_000);
                string configPath = Path.Combine(control, "owner-config.json");
                phase = "owner_config_write";
                log.Phase(phase, "begin");
                WriteJson(configPath, config, LinuxQualificationJson.Default.LinuxOwnerConfiguration);
                phase = "service_start";
                log.Phase(phase, "begin");
                scope = await LinuxServiceScope.StartAsync(stage, configPath, unit,
                    new LinuxScopeLimits(500, 512UL * 1024 * 1024, 128), log).ConfigureAwait(false);
                phase = "owner_ready";
                log.Phase(phase, "begin");
                await WaitForFileAsync(config.ReadyPath, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
                var ready = ReadJson(config.ReadyPath, LinuxQualificationJson.Default.LinuxOwnerReady);
                Require(ready.ProcessId == scope.Identity.MainPid && ready.BootId == scope.Identity.BootId
                    && ready.StartTicks == scope.Identity.MainStartTicks.ToString(CultureInfo.InvariantCulture)
                    && ready.ControlGroup == scope.Identity.ControlGroup, "owner_service_identity_mismatch");
                var observed = await scope.ObserveAsync().ConfigureAwait(false);
                Require(!observed.Cgroup.Removed && observed.Cgroup.CpuQuotaMicros == 50_000
                    && observed.Cgroup.CpuPeriodMicros == 100_000
                    && observed.Cgroup.MemoryMaxBytes == 512UL * 1024 * 1024
                    && observed.Cgroup.PidsMax == 128, "driver_limits_readback_mismatch");
                report.Owner = ready;
                using (var permit = new FileStream(config.ContinuePath + ".pending", FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                {
                    permit.Write(System.Text.Encoding.ASCII.GetBytes(report.RunId));
                    permit.Flush(flushToDisk: true);
                }
                File.Move(config.ContinuePath + ".pending", config.ContinuePath, overwrite: false);
                log.Phase(phase, "admitted", new(StringComparer.Ordinal)
                {
                    ["invocationId"] = scope.Identity.InvocationId,
                    ["unit"] = unit,
                    ["mainPid"] = ready.ProcessId.ToString(CultureInfo.InvariantCulture)
                });
                phase = "owner_completion";
                log.Phase(phase, "begin");
                await WaitForFileAsync(config.ReportPath, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
                var ownerReport = ReadJson(config.ReportPath, LinuxQualificationJson.Default.LinuxQualificationReport);
                Require(ownerReport.RunId == report.RunId && ownerReport.Owner == ready, "owner_report_identity_mismatch");
                report.Cases = ownerReport.Cases;
                report.DiagnosticSlicePassed = ownerReport.DiagnosticSlicePassed;
                report.FailurePhase = ownerReport.FailurePhase;
                report.FailureType = ownerReport.FailureType;
                log.Phase(phase, report.DiagnosticSlicePassed ? "slice_passed" : "slice_failed");
            }
        }
        catch (Exception ex)
        {
            report.FailurePhase = phase;
            report.FailureType = ex.GetType().Name;
            report.DiagnosticSlicePassed = false;
            if (log is not null) log.Failure(phase, ex);
            else EarlyFailure(report.RunId, phase, ex);
        }
        finally
        {
            if (scope is not null)
            {
                try
                {
                    var stopped = await scope.StopAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
                    report.CleanupConfirmed = !stopped.Cgroup.Populated && stopped.Cgroup.ProcessIds.Length == 0;
                    Require(report.CleanupConfirmed, "driver_cgroup_not_empty");
                    await scope.DisposeAsync().ConfigureAwait(false);
                    log!.Phase("service_cleanup", "confirmed_empty");
                }
                catch (Exception ex)
                {
                    report.CleanupConfirmed = false;
                    report.DiagnosticSlicePassed = false;
                    log!.Failure("service_cleanup", ex, cleanup: true);
                }
            }
            if (reportPath is not null && log is not null)
            {
                try { WriteJson(reportPath, report, LinuxQualificationJson.Default.LinuxQualificationReport); }
                catch (Exception ex)
                {
                    report.DiagnosticSlicePassed = false;
                    log.Failure("driver_report_write", ex, cleanup: true);
                }
            }
            log?.Dispose();
        }
        Console.WriteLine(JsonSerializer.Serialize(report, LinuxQualificationJson.Default.LinuxQualificationReport));
        // A diagnostic slice never establishes the full five-protocol composition.
        return report.DiagnosticSlicePassed && report.CleanupConfirmed ? 2 : 1;
    }

    private static bool IsWithin(string path, string root) => path == root
        || path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.Ordinal);

    private static void ValidateAncestors(string path)
    {
        for (var dir = new DirectoryInfo(path); dir is not null; dir = dir.Parent)
            Require(dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) == 0, "evidence_parent_invalid");
    }
}
