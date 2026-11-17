// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.MxcProbe;

// This slice records owned Job enforcement. Ancestor-chain qualification,
// guardian loss and owner recovery remain separate WIN-03/WIN-05 cases.
[SupportedOSPlatform("windows")]
internal static class WindowsResourceCases
{
    private const ulong MiB = 1024UL * 1024;
    private static readonly ConPtyLimits Ordinary = new(5000, 512 * MiB, 16);

    internal static async Task<List<WindowsQualificationCase>> RunAsync(string stage, string work)
    {
        var cases = new List<WindowsQualificationCase>();
        // One busy thread targets roughly a quarter logical CPU under the cap.
        // The recorded processor count is a host observation, not a guarantee
        // that an inherited ancestor allocation or host contention is absent.
        var lowRate = (uint)Math.Clamp(2500 / Environment.ProcessorCount, 1, 10_000);
        var low = new WindowsResourceEvidence { Scenario = "cpu-cap", LogicalProcessors = Environment.ProcessorCount };
        cases.Add(await RunAsync("resource-cpu-capped", stage, work, ["load", "5000", "0", "0"], low, async (session, capture) =>
        {
            _ = await capture.WaitForEventAsync("load-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            var sample = await MeasureAsync(session, capture, low, "capped", TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            var allowance = sample.ElapsedMs / 1000 * Environment.ProcessorCount * lowRate / 10_000;
            low.CpuCeilingSeconds = allowance;
            // A broad scheduling/accounting margin, not a product performance
            // target: a full unconstrained busy CPU must exceed this envelope.
            Require(sample.CpuSeconds > 0 && sample.CpuSeconds <= allowance * 1.5 + 0.2, "cpu_cap_accounting_above_envelope");
        }, new(lowRate, Ordinary.MemoryBytes, Ordinary.ProcessLimit)).ConfigureAwait(false));
        if (cases[^1].UnresolvedCleanupOwner is not null) return cases;

        var high = new WindowsResourceEvidence { Scenario = "cpu-control", LogicalProcessors = Environment.ProcessorCount };
        cases.Add(await RunAsync("resource-cpu-control", stage, work, ["load", "5000", "0", "0"], high, async (session, capture) =>
        {
            _ = await capture.WaitForEventAsync("load-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            var sample = await MeasureAsync(session, capture, high, "uncapped", TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            Require(low.Windows.Count == 1 && low.Windows[0].CpuSeconds > 0, "cpu_capped_control_missing");
            var limited = low.Windows[0];
            var lowUsage = limited.CpuSeconds / (limited.ElapsedMs / 1000);
            var highUsage = sample.CpuSeconds / (sample.ElapsedMs / 1000);
            high.ControlCpuRatio = highUsage / lowUsage;
            Require(highUsage > lowUsage * 1.5, "cpu_comparison_not_proven_under_actual_contention");
        }, new(10_000, Ordinary.MemoryBytes, Ordinary.ProcessLimit)).ConfigureAwait(false));
        if (cases[^1].UnresolvedCleanupOwner is not null) return cases;

        var memory = new WindowsResourceEvidence { Scenario = "native-commit-refusal" };
        cases.Add(await RunAsync("resource-memory-cap", stage, work, ["commit", "256", "1500"], memory, async (session, capture) =>
        {
            var ready = await capture.WaitForEventAsync("commit-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            var committed = ready.GetProperty("committedBytes").GetUInt64();
            var failure = ready.GetProperty("failedCode").GetInt32();
            memory.CommittedBytes = committed;
            memory.NativeFailureCode = failure;
            Require(failure is 8 or 1455 or 1816 && committed is > 0 and < 256 * MiB, "native_commit_refusal_missing");
            var observed = Record(session, memory, "commit-held");
            Require(observed.Limits.MemoryBytes == 96 * MiB && observed.PeakMemoryBytes >= committed,
                "native_commit_job_accounting_missing");
            // Successful pages are retained and touched, while a subsequent
            // 4MiB native commit was rejected. A GC heap-limit message alone
            // cannot satisfy this case. The native peak may include a refused
            // charge, so it is recorded rather than treated as current commit.
            Require(observed.PeakMemoryBytes >= 80 * MiB, "native_commit_did_not_approach_job_limit");
            _ = await MeasureAsync(session, capture, memory, "commit-retained", TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
        }, new(5000, 96 * MiB, 16), expectedExit: 72).ConfigureAwait(false));
        if (cases[^1].UnresolvedCleanupOwner is not null) return cases;

        var burst = new WindowsResourceEvidence { Scenario = "process-burst-control" };
        cases.Add(await RunAsync("resource-process-control", stage, work, ["load", "4000", "0", "4"], burst, async (session, capture) =>
        {
            _ = await capture.WaitForEventAsync("load-ready", TimeSpan.FromSeconds(5), item => item.GetProperty("childrenCreated").GetInt32() == 4).ConfigureAwait(false);
            var observed = Record(session, burst, "burst-live");
            Require(observed.ActiveProcesses >= 6 && observed.ProcessIds.Length >= 6 && observed.TotalProcesses >= 6,
                "real_burst_descendants_not_observed");
            Require(observed.ProcessIds.Contains(session.ProcessId) && observed.ActiveProcesses <= observed.Limits.ProcessLimit,
                "burst_job_membership_inconsistent");
            _ = await MeasureAsync(session, capture, burst, "burst-accounted", TimeSpan.FromMilliseconds(500)).ConfigureAwait(false);
        }, Ordinary).ConfigureAwait(false));
        if (cases[^1].UnresolvedCleanupOwner is not null) return cases;

        var limitedBurst = new WindowsResourceEvidence { Scenario = "process-burst-refusal" };
        cases.Add(await RunAsync("resource-process-cap", stage, work, ["load", "4000", "0", "8"], limitedBurst, async (session, capture) =>
        {
            var failure = await capture.WaitForEventAsync("error", TimeSpan.FromSeconds(5), item =>
                item.GetProperty("errorType").GetString() == "Win32Exception").ConfigureAwait(false);
            limitedBurst.NativeFailureCode = failure.GetProperty("win32Code").GetInt32();
            Require(limitedBurst.NativeFailureCode == 1816, "process_burst_was_not_rejected_by_native_quota");
            var observed = Record(session, limitedBurst, "burst-refused");
            // TotalProcesses survives the short root/child exit window. The
            // unconstrained control above establishes the same burst can spawn.
            Require(observed.Limits.ProcessLimit == 4 && observed.TotalProcesses >= 4
                && observed.ActiveProcesses <= 4 && observed.ProcessIds.Length <= 4, "process_limit_native_accounting_missing");
        }, new(5000, Ordinary.MemoryBytes, 4), expectedExit: 70).ConfigureAwait(false));
        if (cases[^1].UnresolvedCleanupOwner is not null) return cases;

        var shortBurst = new WindowsResourceEvidence { Scenario = "short-lived-descendant-accounting" };
        cases.Add(await RunAsync("resource-short-lived-burst", stage, work, ["short-burst", "8"], shortBurst, async (session, capture) =>
        {
            _ = await capture.WaitForEventAsync("short-burst-ready", TimeSpan.FromSeconds(11), item =>
                item.GetProperty("count").GetInt32() == 8 && item.GetProperty("exitedCount").GetInt32() == 8).ConfigureAwait(false);
            var children = new List<uint>();
            for (var index = 0; index < 8; index++)
            {
                var expectedIndex = index;
                var child = await capture.WaitForEventAsync("short-child-exited", TimeSpan.FromSeconds(1), item =>
                    item.GetProperty("index").GetInt32() == expectedIndex).ConfigureAwait(false);
                Require(child.GetProperty("exitCode").GetInt32() == 0, "short_child_did_not_exit_zero");
                children.Add(child.GetProperty("childPid").GetUInt32());
            }
            shortBurst.ShortLivedProcessIds = children.ToArray();
            var actual = Record(session, shortBurst, "short-children-already-exited");
            // A late live-PID enumeration cannot see these children. Native
            // cumulative charges must still include executor + root + all eight.
            Require(actual.TotalProcesses >= 10 && children.All(child => !actual.ProcessIds.Contains(child))
                && actual.ProcessIds.Contains(session.ProcessId), "short_lived_children_not_in_native_cumulative_accounting");
        }, Ordinary, policyTimeoutMilliseconds: 15_000).ConfigureAwait(false));
        if (cases[^1].UnresolvedCleanupOwner is not null) return cases;

        cases.Add(await AssignmentFailureAsync(stage, work).ConfigureAwait(false));
        if (cases[^1].UnresolvedCleanupOwner is not null) return cases;

        var dynamic = new WindowsResourceEvidence { Scenario = "live-resource-update", LogicalProcessors = Environment.ProcessorCount };
        cases.Add(await RunAsync("resource-live-update", stage, work, ["load", "6000", "8", "2"], dynamic, async (session, capture) =>
        {
            _ = await capture.WaitForEventAsync("load-ready", TimeSpan.FromSeconds(5), item => item.GetProperty("childrenCreated").GetInt32() == 2).ConfigureAwait(false);
            var before = await MeasureAsync(session, capture, dynamic, "before-update", TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            var target = new ConPtyLimits(lowRate, 256 * MiB, 8);
            dynamic.RequestedUpdate = target;
            var actual = session.UpdateLimits(target);
            dynamic.Observations.Add(new("update-readback", Stopwatch.GetTimestamp(), actual));
            Require(actual.Limits == target && actual.ProcessIds.Contains(session.ProcessId) && actual.ActiveProcesses >= 4,
                "live_resource_update_readback_mismatch");
            var after = await MeasureAsync(session, capture, dynamic, "after-update", TimeSpan.FromMilliseconds(1500)).ConfigureAwait(false);
            var beforeRate = before.CpuSeconds / (before.ElapsedMs / 1000);
            var afterRate = after.CpuSeconds / (after.ElapsedMs / 1000);
            dynamic.ControlCpuRatio = beforeRate / afterRate;
            Require(afterRate > 0 && beforeRate > afterRate * 1.5, "live_cpu_update_effect_not_proven");
        }, Ordinary).ConfigureAwait(false));
        if (cases[^1].UnresolvedCleanupOwner is not null) return cases;
        cases.Add(await InvalidBeforeLaunchAsync(stage, work).ConfigureAwait(false));
        return cases;
    }

    private static async Task<WindowsQualificationCase> RunAsync(string name, string stage, string work, IReadOnlyList<string> args,
        WindowsResourceEvidence evidence, Func<ConPtySession, WindowsTerminalCapture, Task> exercise, ConPtyLimits limits,
        uint expectedExit = 0, uint policyTimeoutMilliseconds = 10_000)
    {
        evidence.InitialLimits = limits;
        var (policy, events) = BuildPolicy(stage, work, name, args, policyTimeoutMilliseconds);
        var result = await WindowsQualification.RunCaseAsync(name, stage, policy, exercise, expectedExit, limits, fixtureEventsDirectory: events).ConfigureAwait(false);
        result.Protocol = "MXC-WIN-03";
        evidence.FinalJob = result.FinalJob;
        await SaveAsync(result, evidence, Path.Combine(work, name, "private control")).ConfigureAwait(false);
        return result;
    }

    private static (WindowsPolicyArtifact Policy, string Events) BuildPolicy(string stage, string work, string name, IReadOnlyList<string> args, uint timeoutMilliseconds)
    {
        var workspace = Path.Combine(work, name, "workspace 工作区");
        var control = Path.Combine(work, name, "private control");
        var owned = new WindowsOwnedPaths(Path.Combine(workspace, "home"), Path.Combine(workspace, "config"), Path.Combine(workspace, "cache"),
            Path.Combine(workspace, "temp"), Path.Combine(workspace, "work"), Path.Combine(workspace, "data"));
        foreach (var path in new[] { owned.Home, owned.Config, owned.Cache, owned.Temp, owned.Work, owned.Data }) Directory.CreateDirectory(path);
        var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"), ["--windows-workload", .. args], owned,
            [stage, Environment.GetFolderPath(Environment.SpecialFolder.System)], [control], WindowsNetworkChoice.DenyAll);
        request.Process.Timeout = timeoutMilliseconds;
        var events = WindowsQualification.EnableFixtureEvents(request, owned.Work);
        return (WindowsPolicy.WritePrivate(control, request), events);
    }

    private static async Task<WindowsQualificationCase> AssignmentFailureAsync(string stage, string work)
    {
        const string name = "resource-native-assignment-refusal";
        var result = new WindowsQualificationCase { Name = name, Protocol = "MXC-WIN-03", PayloadStartCertainty = "NOT_STARTED" };
        var evidence = new WindowsResourceEvidence { Scenario = "full-owned-parent-assignment-refusal", InitialLimits = Ordinary };
        var control = Path.Combine(work, name, "private control");
        try
        {
            var (policy, _) = BuildPolicy(stage, work, name, ["exit", "0"], 10_000);
            result.PolicySha256 = policy.Sha256;
            var probe = await WindowsPolicyProbe.RunAsync(stage, policy.Path, Path.Combine(control, "native-probe")).ConfigureAwait(false);
            Require(probe.ExitCode == 0 && probe.JsonParsed && probe.NativeBaseContainer && probe.NeedsDaclAugmentation == false
                && probe.DenyPaths && probe.UiRestrictionsComplete, "assignment_probe_same_policy_native_refused");
            result.SamePolicyProbePassed = true;
            var actual = ConPtySession.ProbeParentAssignmentFailure(new(Path.Combine(stage, "wxc-exec.exe"), policy.Path, control, 80, 24, Ordinary));
            evidence.AssignmentFailure = actual;
            result.ExecutorProcessId = actual.CandidateProcessId;
            result.ExecutorStartUtc = actual.CandidateCreatedUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
            result.RawExecutorExit = actual.CandidateExitCode;
            result.FinalJob = actual.CandidateAfterCleanup;
            Require(actual.AssignmentRejected && actual.NativeErrorCode != 0 && !actual.CandidateResumed && !actual.WorkerResumed,
                "assignment_refusal_was_not_native_and_before_resume");
            Require(actual.ParentBeforeAssignment is { ActiveProcesses: 1, Limits.ProcessLimit: 1 } before
                && before.ProcessIds.Length == 1 && before.ProcessIds[0] == actual.WorkerProcessId,
                "assignment_test_parent_was_not_owned_and_full");
            Require(actual.CleanupCompleted && actual.ParentAfterCleanup is { ActiveProcesses: 0, ProcessIds.Length: 0 }
                && actual.CandidateAfterCleanup is { ActiveProcesses: 0, ProcessIds.Length: 0 } && actual.CandidateExitCode.HasValue,
                "assignment_refusal_cleanup_unresolved");
            result.CleanupCompleted = true;
            result.JobEmpty = true;
            result.Passed = true;
        }
        catch (Exception error)
        {
            var primary = error;
            if (error is ConPtyLaunchException launch && launch.InnerException is AggregateException combined && combined.InnerExceptions.Count >= 2)
            {
                primary = combined.InnerExceptions[0];
                result.CleanupFailure = WindowsQualification.ObserveFailure(combined.InnerExceptions[1]);
                result.UnresolvedCleanupOwner = launch.CleanupOwner;
            }
            result.PrimaryFailure = WindowsQualification.ObserveFailure(primary);
            result.FailureCode = result.PrimaryFailure.Code;
            result.FailureType = result.PrimaryFailure.Type;
            result.FailureHResult = primary.HResult;
        }
        await SaveAsync(result, evidence, control).ConfigureAwait(false);
        return result;
    }

    private static ConPtyJobObservation Record(ConPtySession session, WindowsResourceEvidence evidence, string phase)
    {
        var actual = session.ObserveJob();
        evidence.Observations.Add(new(phase, Stopwatch.GetTimestamp(), actual));
        return actual;
    }

    private static async Task<WindowsResourceWindow> MeasureAsync(ConPtySession session, WindowsTerminalCapture capture,
        WindowsResourceEvidence evidence, string phase, TimeSpan interval)
    {
        var start = Record(session, evidence, phase + "-start");
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < interval)
        {
            capture.Refresh();
            Require(session.GetExecutorExitCode() is null, "resource_measurement_ended_before_window");
            await Task.Delay(25).ConfigureAwait(false);
        }
        var end = Record(session, evidence, phase + "-end");
        var cpuTicks = end.UserTimeTicks + end.KernelTimeTicks - start.UserTimeTicks - start.KernelTimeTicks;
        Require(cpuTicks >= 0 && end.TotalProcesses >= start.TotalProcesses, "job_resource_counters_regressed");
        var window = new WindowsResourceWindow(phase, watch.Elapsed.TotalMilliseconds, TimeSpan.FromTicks(cpuTicks).TotalSeconds);
        evidence.Windows.Add(window);
        return window;
    }

    private static async Task<WindowsQualificationCase> InvalidBeforeLaunchAsync(string stage, string work)
    {
        const string name = "resource-invalid-before-launch";
        var result = new WindowsQualificationCase { Name = name, Protocol = "MXC-WIN-03", ExitSource = "supervisor", PayloadStartCertainty = "NOT_STARTED" };
        var evidence = new WindowsResourceEvidence { Scenario = "invalid-before-launch" };
        var control = Path.Combine(work, name, "private control");
        try
        {
            // Build an actual private request, so invalid limits must be the
            // rejection and cannot be hidden by an absent executable/config.
            var workspace = Path.Combine(work, name, "workspace");
            var owned = new WindowsOwnedPaths(Path.Combine(workspace, "home"), Path.Combine(workspace, "config"), Path.Combine(workspace, "cache"),
                Path.Combine(workspace, "temp"), Path.Combine(workspace, "work"), Path.Combine(workspace, "data"));
            foreach (var path in new[] { owned.Home, owned.Config, owned.Cache, owned.Temp, owned.Work, owned.Data }) Directory.CreateDirectory(path);
            var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"), ["--windows-workload", "exit", "0"], owned,
                [stage, Environment.GetFolderPath(Environment.SpecialFolder.System)], [control], WindowsNetworkChoice.DenyAll);
            var policy = WindowsPolicy.WritePrivate(control, request);
            result.PolicySha256 = policy.Sha256;
            ConPtyLimits[] invalid = [new(0, 96 * MiB, 4), new(10001, 96 * MiB, 4), new(5000, 0, 4), new(5000, 2_147_483_649, 4), new(5000, 96 * MiB, 0), new(5000, 96 * MiB, 65)];
            foreach (var limits in invalid)
            {
                var rejected = false;
                try
                {
                    await using var unexpected = ConPtySession.Start(new(Path.Combine(stage, "wxc-exec.exe"), policy.Path, control, 80, 24, limits));
                    evidence.UnexpectedExecutorProcessId = unexpected.ProcessId;
                }
                catch (ArgumentOutOfRangeException) { rejected = true; }
                Require(rejected, "invalid_resource_settings_were_not_rejected_before_launch");
                evidence.InvalidRequestsRejected++;
            }
            result.Passed = true;
            result.CleanupCompleted = true;
            result.JobEmpty = true; // No native scope was created by numeric validation.
        }
        catch (Exception error)
        {
            result.PrimaryFailure = WindowsQualification.ObserveFailure(error);
            result.FailureCode = result.PrimaryFailure.Code;
            result.FailureType = result.PrimaryFailure.Type;
            result.FailureHResult = error.HResult;
        }
        await SaveAsync(result, evidence, control).ConfigureAwait(false);
        return result;
    }

    private static async Task SaveAsync(WindowsQualificationCase result, WindowsResourceEvidence evidence, string control)
    {
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(evidence, WindowsResourceJson.Default.WindowsResourceEvidence);
            await using var output = new FileStream(Path.Combine(control, "resource-observation.json"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            await output.WriteAsync(bytes).ConfigureAwait(false);
            result.PrivateDiagnostics.Add(new("resource-observation.json", Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length));
        }
        catch (Exception error)
        {
            result.EvidenceFailure = WindowsQualification.ObserveFailure(error);
            result.Passed = false;
        }
    }

    private static void Require(bool condition, string code) { if (!condition) throw new WindowsQualificationCheckException(code); }
}

internal sealed record WindowsResourceSample(string Phase, long MonotonicTimestamp, ConPtyJobObservation Actual);
internal sealed record WindowsResourceWindow(string Phase, double ElapsedMs, double CpuSeconds);
internal sealed class WindowsResourceEvidence
{
    public string Scenario { get; set; } = "";
    public string Limitation { get; set; } = "Owned Job accounting includes executor/helper charges. Host contention and inherited ancestor budgets may prevent a comparison from proving enforcement. This is not whole WIN-03 qualification.";
    public long MonotonicFrequency { get; set; } = Stopwatch.Frequency;
    public int LogicalProcessors { get; set; }
    public ConPtyLimits? InitialLimits { get; set; }
    public ConPtyLimits? RequestedUpdate { get; set; }
    public List<WindowsResourceSample> Observations { get; set; } = [];
    public List<WindowsResourceWindow> Windows { get; set; } = [];
    public double? CpuCeilingSeconds { get; set; }
    public double? ControlCpuRatio { get; set; }
    public ulong? CommittedBytes { get; set; }
    public int? NativeFailureCode { get; set; }
    public int InvalidRequestsRejected { get; set; }
    public uint? UnexpectedExecutorProcessId { get; set; }
    public uint[] ShortLivedProcessIds { get; set; } = [];
    public ConPtyAssignmentEvidence? AssignmentFailure { get; set; }
    public ConPtyJobObservation? FinalJob { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(WindowsResourceEvidence))]
internal sealed partial class WindowsResourceJson : JsonSerializerContext;
