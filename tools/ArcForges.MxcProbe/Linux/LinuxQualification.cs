// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.MxcProbe.Linux;

internal sealed record LinuxOwnerConfiguration(string RunId, string Manifest, string Work, string Control,
    string ReadyPath, string ContinuePath, string ReportPath, string LogPath, string UnitName,
    string Group, long MemoryMax, int TasksMax, int CpuQuotaMicros);

internal sealed record LinuxOwnerReady(int ProcessId, string BootId, string StartTicks, string ControlGroup,
    string CpuMax, string MemoryMax, string PidsMax);

internal sealed class LinuxQualificationReport
{
    public string Profile { get; set; } = "linux-bubblewrap-sdk-v1";
    public string RunId { get; set; } = "";
    public string Host { get; set; } = Environment.MachineName;
    public string Kernel { get; set; } = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
    public bool QualificationPassed { get; set; }
    public bool DiagnosticSlicePassed { get; set; }
    public string State { get; set; } = "partial";
    public string? FailurePhase { get; set; }
    public string? FailureType { get; set; }
    public bool CleanupConfirmed { get; set; }
    public LinuxOwnerReady? Owner { get; set; }
    public List<LinuxCaseResult> Cases { get; set; } = [];
}

internal static partial class LinuxQualification
{
    internal static async Task<int> RunOwnerAsync(string configPath)
    {
        LinuxEvidence? log = null;
        LinuxOwnerConfiguration? config = null;
        var report = new LinuxQualificationReport();
        string phase = "owner_config";
        try
        {
            if (!OperatingSystem.IsLinux()) throw new LinuxProbeException("linux_host_required");
            var candidate = ReadJson(configPath, LinuxQualificationJson.Default.LinuxOwnerConfiguration);
            Require(Path.GetDirectoryName(Path.GetFullPath(configPath)) == candidate.Control, "owner_control_location");
            Require(candidate.RunId.Length == 32 && candidate.RunId.All(char.IsAsciiHexDigit)
                && candidate.UnitName == "arcforges-mxc03-" + candidate.RunId + ".service", "owner_identity_shape");
            Require(candidate.ReadyPath == Path.Combine(candidate.Control, "ready.json")
                && candidate.ContinuePath == Path.Combine(candidate.Control, "continue")
                && candidate.ReportPath == Path.Combine(candidate.Control, "owner-report.json")
                && candidate.LogPath == Path.Combine(candidate.Control, "owner-events.jsonl"), "owner_evidence_paths");
            config = candidate;
            report.RunId = config.RunId;
            log = new LinuxEvidence(config.LogPath, config.RunId);
            phase = "owner_stage";
            log.Phase(phase, "begin");
            Program.ValidateStage(config.Manifest);
            phase = "owner_preexecution_scope";
            log.Phase(phase, "begin");
            var ready = ReadOwnerScope(config);
            report.Owner = ready;
            WriteJson(config.ReadyPath, ready, LinuxQualificationJson.Default.LinuxOwnerReady);
            log.Phase(phase, "verified", new(StringComparer.Ordinal)
            {
                ["cpuMax"] = ready.CpuMax,
                ["memoryMax"] = ready.MemoryMax,
                ["pidsMax"] = ready.PidsMax,
                ["startTicks"] = ready.StartTicks,
                ["unit"] = config.UnitName
            });
            phase = "owner_wait_for_admission";
            log.Phase(phase, "begin");
            await WaitForFileAsync(config.ContinuePath, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            Require(File.ReadAllText(config.ContinuePath) == config.RunId, "owner_admission_identity");
            // Re-read immediately before the SDK. The driver also verifies the exact service identity.
            Require(ReadOwnerScope(config) == ready, "owner_scope_changed_before_sdk");
            phase = "owner_cases";
            log.Phase(phase, "begin");
            if (config.Group == "terminal")
                report.Cases = await LinuxTerminalCases.RunAsync(Environment.ProcessPath!, config.Work, config.Control, log).ConfigureAwait(false);
            else if (config.Group == "policy")
                report.Cases = await LinuxPolicyCases.RunAsync(AppContext.BaseDirectory, config.Work, config.Control, log).ConfigureAwait(false);
            else if (config.Group == "network")
                report.Cases = await LinuxNetworkCases.RunAsync(config, log).ConfigureAwait(false);
            else if (config.Group.StartsWith("resource_", StringComparison.Ordinal))
                report.Cases = await LinuxResourceCases.RunOwnerAsync(config, log).ConfigureAwait(false);
            else if (config.Group.StartsWith("lifecycle_", StringComparison.Ordinal))
                report.Cases = await LinuxOwnerChannel.RunOwnerAsync(config, log).ConfigureAwait(false);
            else
                throw new LinuxProbeException("owner_group_unsupported");
            report.DiagnosticSlicePassed = report.Cases.Count > 0 && report.Cases.All(x => x.Passed);
            // Outer cgroup drain belongs to the independent driver after this owner exits.
            log.Phase(phase, report.DiagnosticSlicePassed ? "slice_passed" : "slice_failed");
        }
        catch (Exception ex)
        {
            report.DiagnosticSlicePassed = false;
            report.FailurePhase = phase;
            report.FailureType = ex.GetType().Name;
            if (log is not null) log.Failure(phase, ex);
            else EarlyFailure(report.RunId, phase, ex);
        }
        finally
        {
            if (config is not null)
            {
                try { WriteJson(config.ReportPath, report, LinuxQualificationJson.Default.LinuxQualificationReport); }
                catch (Exception ex)
                {
                    if (log is not null) log.Failure("owner_report_write", ex, cleanup: true);
                    else EarlyFailure(report.RunId, "owner_report_write", ex);
                    report.DiagnosticSlicePassed = false;
                }
            }
            log?.Dispose();
        }
        return report.DiagnosticSlicePassed ? 0 : 1;
    }

    private static LinuxOwnerReady ReadOwnerScope(LinuxOwnerConfiguration config)
    {
        string[] lines = File.ReadAllLines("/proc/self/cgroup");
        Require(lines.Length == 1 && lines[0].StartsWith("0::/", StringComparison.Ordinal), "owner_cgroup_v2_required");
        string group = lines[0][3..];
        Require(group.EndsWith("/" + config.UnitName, StringComparison.Ordinal), "owner_not_in_expected_service");
        string root = "/sys/fs/cgroup" + group;
        string cpu = File.ReadAllText(Path.Combine(root, "cpu.max")).Trim();
        string memory = File.ReadAllText(Path.Combine(root, "memory.max")).Trim();
        string pids = File.ReadAllText(Path.Combine(root, "pids.max")).Trim();
        Require(cpu == config.CpuQuotaMicros.ToString(CultureInfo.InvariantCulture) + " 100000"
            && memory == config.MemoryMax.ToString(CultureInfo.InvariantCulture)
            && pids == config.TasksMax.ToString(CultureInfo.InvariantCulture), "owner_limits_readback_mismatch");
        string stat = File.ReadAllText("/proc/self/stat");
        int end = stat.LastIndexOf(')');
        Require(end > 0, "owner_process_identity_invalid");
        string[] fields = stat[(end + 2)..].Split(' ');
        Require(fields.Length > 19, "owner_process_identity_short");
        return new LinuxOwnerReady(Environment.ProcessId, File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim(),
            fields[19], group, cpu, memory, pids);
    }

    internal static async Task WaitForFileAsync(string path, TimeSpan deadline)
    {
        var watch = Stopwatch.StartNew();
        while (!File.Exists(path))
        {
            if (watch.Elapsed >= deadline) throw new LinuxProbeException("owner_handshake_timeout");
            await Task.Delay(50).ConfigureAwait(false);
        }
        Require(new FileInfo(path).Length <= 1024 * 1024 && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0,
            "owner_handshake_file_invalid");
    }

    internal static T ReadJson<T>(string path, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type)
    {
        Require(new FileInfo(path).Length <= 1024 * 1024 && (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0,
            "control_file_invalid");
        return JsonSerializer.Deserialize(File.ReadAllBytes(path), type) ?? throw new LinuxProbeException("control_json_null");
    }

    internal static void WriteJson<T>(string path, T value, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.Read };
        if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        string temporary = path + "." + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture) + ".pending";
        using (var stream = new FileStream(temporary, options))
        {
            JsonSerializer.Serialize(stream, value, type);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, path, overwrite: false);
    }

    private static void Require(bool condition, string code)
    {
        if (!condition) throw new LinuxProbeException(code);
    }

    private static void EarlyFailure(string runId, string phase, Exception ex)
        => Console.Error.WriteLine("linux_probe_failed:run=" + runId + ":phase=" + phase
            + ":type=" + ex.GetType().Name + ":hresult=" + ex.HResult.ToString("X8", CultureInfo.InvariantCulture)
            + (ex is LinuxProbeException probe ? ":code=" + probe.Code : ""));
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(LinuxOwnerConfiguration))]
[JsonSerializable(typeof(LinuxOwnerReady))]
[JsonSerializable(typeof(LinuxQualificationReport))]
internal sealed partial class LinuxQualificationJson : JsonSerializerContext;
