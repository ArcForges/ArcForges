// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.MxcProbe.Linux;

internal static partial class LinuxQualification
{
    internal static async Task<int> RunAsync(string[] args)
    {
        if (args.Length != 8 || args[6] != "--only")
            return await RunFullAsync(args).ConfigureAwait(false);
        var report = new LinuxQualificationReport { RunId = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture) };
        LinuxEvidence? log = null;
        LinuxServiceScope? scope = null;
        string? reportPath = null;
        string phase = "arguments";
        try
        {
            if (!OperatingSystem.IsLinux()) throw new LinuxProbeException("linux_host_required");
            report.Kernel = ReadKernelRelease();
            Require(args.Length == 8 && args[0] == "--manifest" && args[2] == "--work"
                && args[4] == "--report" && args[6] == "--only", "linux_profile_arguments");
            string group = args[7];
            Require(group is "admission" or "terminal" or "policy" or "network" or "resource" or "lifecycle", "linux_diagnostic_group_invalid");
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

    private static async Task<int> RunFullAsync(string[] args)
    {
        string[] groups = ["admission", "terminal", "policy", "network", "resource", "lifecycle"];
        var report = new LinuxFullQualificationReport
        {
            RunId = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture),
            StartedUtc = DateTimeOffset.UtcNow,
            NotRunGroups = [.. groups],
        };
        LinuxEvidence? log = null;
        string? reportPath = null;
        bool unfinishedSlice = false;
        string phase = "full_arguments";
        try
        {
            if (!OperatingSystem.IsLinux()) throw new LinuxProbeException("linux_host_required");
            Require(args.Length == 12 && args[0] == "--manifest" && args[2] == "--work"
                && args[4] == "--report" && args[6] == "--source" && args[8] == "--design"
                && args[10] == "--plan", "linux_full_profile_arguments");
            Require(IsCommit(args[7]) && IsCommit(args[9]) && IsCommit(args[11]), "full_exact_commits_required");
            report.SourceCommit = args[7].ToLowerInvariant();
            report.DesignCommit = args[9].ToLowerInvariant();
            report.PlanCommit = args[11].ToLowerInvariant();
            reportPath = Path.GetFullPath(args[5]);
            string manifestPath = Path.GetFullPath(args[1]);
            string stage = Path.GetDirectoryName(manifestPath)!;
            string work = Path.GetFullPath(args[3]);
            Require(!IsWithin(reportPath, stage) && !IsWithin(work, stage) && !IsWithin(reportPath, work), "mutable_path_in_stage");
            Require(!File.Exists(reportPath) && !Directory.Exists(reportPath)
                && !File.Exists(work) && !Directory.Exists(work), "fresh_evidence_paths_required");
            ValidateAncestors(Path.GetDirectoryName(reportPath)!);
            ValidateAncestors(Path.GetDirectoryName(work)!);
            log = new LinuxEvidence(reportPath + ".events.jsonl", report.RunId);
            phase = "full_stage_identity";
            log.Phase(phase, "begin");
            Program.ValidateStage(manifestPath);
            var manifest = ReadJson(manifestPath, ProbeJson.Default.StageManifest);
            report.ArtifactVersion = manifest.Version;
            report.ArtifactSchema = manifest.Schema;
            report.NativeSourceCommit = manifest.Source;
            report.PackageSha256 = manifest.PackageSha256;
            report.ReleaseSha256 = manifest.ReleaseSha256;
            report.StageFiles = manifest.Files;
            report.ManifestSha256 = FileHash(manifestPath);
            report.ExecutableSha256 = FileHash(Environment.ProcessPath!);
            report.ExecutableInformationalVersion = typeof(LinuxQualification).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "";
            // The SDK embeds SourceRevisionId in this attribute. A caller label
            // alone cannot establish which source produced the AOT executable.
            Require(report.ExecutableInformationalVersion.EndsWith("+" + report.SourceCommit, StringComparison.Ordinal),
                "full_executable_source_commit_mismatch");
            report.HostFacts = new(StringComparer.Ordinal)
            {
                ["host"] = Environment.MachineName,
                ["kernelRelease"] = ReadKernelRelease(),
                ["kernelVersion"] = File.ReadAllText("/proc/sys/kernel/version").Trim(),
                ["bootId"] = File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim(),
                ["osDescription"] = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                ["osArchitecture"] = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
                ["processArchitecture"] = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString(),
                ["rid"] = System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier,
                ["driverCgroup"] = File.ReadAllText("/proc/self/cgroup").Trim(),
            };
            log.Phase(phase, "verified", new(StringComparer.Ordinal)
            {
                ["sourceCommit"] = report.SourceCommit,
                ["designCommit"] = report.DesignCommit,
                ["planCommit"] = report.PlanCommit,
                ["manifestSha256"] = report.ManifestSha256,
                ["executableSha256"] = report.ExecutableSha256,
                ["kernelRelease"] = report.HostFacts["kernelRelease"],
            });
            Directory.CreateDirectory(work, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            foreach (string group in groups)
            {
                phase = "full_" + group;
                log.Phase(phase, "begin");
                // Inputs remain the same immutable official cohort for every
                // native slice; resource-sensitive slices run sequentially.
                Require(FileHash(manifestPath) == report.ManifestSha256
                    && FileHash(Environment.ProcessPath!) == report.ExecutableSha256, "full_stage_identity_changed");
                string childReportPath = Path.Combine(work, group + ".json");
                var watch = Stopwatch.StartNew();
                unfinishedSlice = true;
                int exitCode = await RunAsync(["--manifest", manifestPath, "--work", Path.Combine(work, group),
                    "--report", childReportPath, "--only", group]).ConfigureAwait(false);
                var child = ReadJson(childReportPath, LinuxQualificationJson.Default.LinuxQualificationReport);
                Require(child.Profile == report.Profile && IsRunId(child.RunId)
                    && child.Host == Environment.MachineName && child.Kernel == report.HostFacts["kernelRelease"]
                    && !child.QualificationPassed, "full_slice_identity_mismatch");
                bool passed = exitCode == 2 && child.DiagnosticSlicePassed && child.CleanupConfirmed
                    && child.FailurePhase is null && child.Cases.Count > 0 && child.Cases.All(item => item.Passed);
                report.Slices.Add(new LinuxQualificationSlice(group, Path.GetFileName(childReportPath),
                    FileHash(childReportPath), FileHash(childReportPath + ".events.jsonl"), child.RunId,
                    exitCode, watch.Elapsed.TotalMilliseconds, passed, child.CleanupConfirmed, child.Owner, child.Cases));
                unfinishedSlice = false;
                report.NotRunGroups.Remove(group);
                log.Phase(phase, passed ? "passed" : "failed", new(StringComparer.Ordinal)
                {
                    ["sliceRunId"] = child.RunId,
                    ["exitCode"] = exitCode.ToString(CultureInfo.InvariantCulture),
                    ["reportSha256"] = report.Slices[^1].ReportSha256,
                    ["eventsSha256"] = report.Slices[^1].EventsSha256,
                    ["cleanupConfirmed"] = child.CleanupConfirmed.ToString(CultureInfo.InvariantCulture),
                });
                Require(passed, "full_required_slice_failed");
            }
            Require(FileHash(manifestPath) == report.ManifestSha256
                && FileHash(Environment.ProcessPath!) == report.ExecutableSha256, "full_stage_identity_changed");
            report.CleanupConfirmed = report.Slices.Count == groups.Length && report.Slices.All(slice => slice.CleanupConfirmed);
            report.QualificationPassed = report.CleanupConfirmed && report.NotRunGroups.Count == 0
                && report.Slices.All(slice => slice.Passed);
            report.State = report.QualificationPassed ? "passed" : "partial";
            log.Phase("full_combination", report.QualificationPassed ? "passed" : "failed");
        }
        catch (Exception exception)
        {
            report.FailurePhase = phase;
            report.FailureType = exception.GetType().Name;
            report.QualificationPassed = false;
            report.State = "partial";
            // This is only the observed cleanup of slices actually run. An
            // absent/unfinished slice can never turn the full result into pass.
            report.CleanupConfirmed = !unfinishedSlice && report.Slices.Count > 0 && report.Slices.All(slice => slice.CleanupConfirmed);
            if (log is not null) log.Failure(phase, exception);
            else EarlyFailure(report.RunId, phase, exception);
        }
        finally
        {
            report.FinishedUtc = DateTimeOffset.UtcNow;
            if (reportPath is not null && log is not null)
            {
                try { WriteJson(reportPath, report, LinuxFullQualificationJson.Default.LinuxFullQualificationReport); }
                catch (Exception exception)
                {
                    report.QualificationPassed = false;
                    report.State = "partial";
                    log.Failure("full_report_write", exception, cleanup: true);
                }
            }
            log?.Dispose();
        }
        Console.WriteLine(JsonSerializer.Serialize(report, LinuxFullQualificationJson.Default.LinuxFullQualificationReport));
        return report.QualificationPassed ? 0 : 1;
    }

    private static string ReadKernelRelease() => File.ReadAllText("/proc/sys/kernel/osrelease").Trim();

    private static string FileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static bool IsCommit(string value) => value.Length == 40 && value.All(char.IsAsciiHexDigit);
    private static bool IsRunId(string value) => value.Length == 32 && value.All(char.IsAsciiHexDigit);

    private static bool IsWithin(string path, string root) => path == root
        || path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.Ordinal);

    private static void ValidateAncestors(string path)
    {
        for (var dir = new DirectoryInfo(path); dir is not null; dir = dir.Parent)
            Require(dir.Exists && (dir.Attributes & FileAttributes.ReparsePoint) == 0, "evidence_parent_invalid");
    }
}

internal sealed record LinuxQualificationSlice(string Group, string ReportFile, string ReportSha256, string EventsSha256,
    string RunId, int ExitCode, double ElapsedMs, bool Passed, bool CleanupConfirmed, LinuxOwnerReady? Owner,
    List<LinuxCaseResult> Cases);

internal sealed class LinuxFullQualificationReport
{
    public string Profile { get; set; } = "linux-bubblewrap-sdk-v1";
    public string RunId { get; set; } = "";
    public string State { get; set; } = "partial";
    public bool QualificationPassed { get; set; }
    public bool CleanupConfirmed { get; set; }
    public DateTimeOffset StartedUtc { get; set; }
    public DateTimeOffset FinishedUtc { get; set; }
    public string? FailurePhase { get; set; }
    public string? FailureType { get; set; }
    public string SourceCommit { get; set; } = "";
    public string DesignCommit { get; set; } = "";
    public string PlanCommit { get; set; } = "";
    public string ExecutableInformationalVersion { get; set; } = "";
    public string ExecutableSha256 { get; set; } = "";
    public string ManifestSha256 { get; set; } = "";
    public string ArtifactVersion { get; set; } = "";
    public string ArtifactSchema { get; set; } = "";
    public string NativeSourceCommit { get; set; } = "";
    public string PackageSha256 { get; set; } = "";
    public string ReleaseSha256 { get; set; } = "";
    public StageMember[] StageFiles { get; set; } = [];
    public Dictionary<string, string> HostFacts { get; set; } = new(StringComparer.Ordinal);
    public List<string> NotRunGroups { get; set; } = [];
    public List<LinuxQualificationSlice> Slices { get; set; } = [];
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(LinuxFullQualificationReport))]
internal sealed partial class LinuxFullQualificationJson : JsonSerializerContext;
