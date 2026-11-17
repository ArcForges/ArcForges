// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe;

internal static class WindowsQualification
{
    private static readonly Dictionary<string, string[]> RequiredCases = new(StringComparer.Ordinal)
    {
        ["MXC-WIN-01"] = ["argv-roundtrip", "reject-malformed", "reject-schema-version", "reject-missing-policy",
            "reject-invalid-environment", "reject-least-privilege", "reject-proxy-peer-without-proxy"],
        ["MXC-WIN-02"] = ["console-info", "line-editing", "raw-resize", "detached-flood", "exit-0", "exit-1", "exit-23",
            "fake-error-output", "interactive-cmd", "invalid-payload-executable", "native-invalid-image", "official-policy-timeout",
            "etx-cooperative", "etx-raw", "etx-ignore-etx"],
        ["MXC-WIN-03"] = ["resource-cpu-capped", "resource-cpu-control", "resource-memory-cap", "resource-process-control",
            "resource-process-cap", "resource-short-lived-burst", "resource-native-assignment-refusal", "resource-live-update",
            "resource-invalid-before-launch"],
        ["MXC-WIN-04"] = ["clean-environment", "known-folder-observations", "filesystem-policy", "filesystem-reparse",
            "filesystem-external-grant", "network-deny-all-tcp", "network-deny-all-udp", "network-selected-tcp", "network-selected-udp",
            "network-denied-port", "network-denied-protocol", "network-denied-address", "network-host-loopback-denied-tcp",
            "network-host-loopback-denied-udp", "network-ingress-denied-tcp",
            "network-ingress-loopback-tcp", "network-ingress-denied-udp", "network-ingress-loopback-udp",
            "cli-named-pipe-roundtrip", "cli-native-compile-link-test"],
        ["MXC-WIN-05"] = ["owner-detach-auth-lease", "owner-detached-bounded-replay", "owner-loss-native-drain", "center-observer-loss",
            "root-exit-background-child", "cleanup-record-publication-failure", "client-loss-at-prepared", "client-loss-at-scope-created",
            "client-loss-at-owner-ack", "client-loss-at-executor-created", "client-loss-at-active", "client-loss-at-cleaning",
            "client-loss-at-final", "persistent-data-first-run", "persistent-data-new-run"],
        ["MXC-WIN-06"] = ["combined-default-deny", "combined-selected-egress"],
    };

    [SupportedOSPlatform("windows")]
    internal static async Task<int> RunAsync(string[] args)
    {
        var report = new WindowsQualificationReport { StartedUtc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture), Os = Environment.OSVersion.VersionString };
        string? reportPath = null;
        FileStream? events = null;
        string phase = "arguments";
        try
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native Windows is required.");
            if (args.Length is not (8 or 12) || args[0] != "--manifest" || args[2] != "--work" || args[4] != "--report"
                || (args.Length == 8 && (args[6] != "--only" || args[7] is not ("terminal" or "resource" or "policy" or "network" or "lifecycle" or "combined" or "cli")))
                || (args.Length == 12 && (args[6] != "--source" || args[8] != "--design" || args[10] != "--plan")))
                throw new WindowsQualificationCheckException("full_exact_commits_or_diagnostic_selection_required");
            report.SelectionGroup = args.Length == 8 ? args[7] : "full";
            report.DiagnosticSelection = report.SelectionGroup != "full";
            if (!report.DiagnosticSelection)
            {
                Check(IsCommit(args[7]) && IsCommit(args[9]) && IsCommit(args[11]), "full_exact_commits_required");
                report.SourceCommit = args[7].ToLowerInvariant();
                report.DesignCommit = args[9].ToLowerInvariant();
                report.PlanCommit = args[11].ToLowerInvariant();
            }
            var manifest = Path.GetFullPath(args[1]);
            var stage = Path.GetDirectoryName(manifest)!;
            var work = Path.GetFullPath(args[3]);
            var requestedReport = Path.GetFullPath(args[5]);
            Check(!Within(work, stage) && !Within(requestedReport, stage) && !Within(requestedReport, work), "evidence_outside_stage_and_work_required");
            Check(!Directory.Exists(work) && !File.Exists(work), "fresh_workspace_required");
            Check(!File.Exists(requestedReport) && !Directory.Exists(requestedReport), "fresh_report_required");
            reportPath = requestedReport;
            Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
            events = new FileStream(reportPath + ".events.jsonl", FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
            phase = "stage_identity";
            WritePhase(events, report.RunId, phase, "begin");
            Program.ValidateStage(manifest);
            var identity = JsonSerializer.Deserialize(File.ReadAllBytes(manifest), ProbeJson.Default.StageManifest)
                ?? throw new WindowsQualificationCheckException("stage_manifest_missing");
            report.ArtifactVersion = identity.Version;
            report.ArtifactSchema = identity.Schema;
            report.ArtifactRid = identity.Rid;
            report.NativeSourceCommit = identity.Source;
            report.PackageSha256 = identity.PackageSha256;
            report.ReleaseSha256 = identity.ReleaseSha256;
            report.StageFiles = identity.Files;
            report.ManifestSha256 = FileHash(manifest);
            report.ExecutableSha256 = FileHash(Environment.ProcessPath!);
            report.ExecutableInformationalVersion = typeof(WindowsQualification).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "";
            if (!report.DiagnosticSelection)
                Check(report.ExecutableInformationalVersion.EndsWith("+" + report.SourceCommit, StringComparison.Ordinal), "full_executable_source_commit_mismatch");
            report.HostFacts = new(StringComparer.Ordinal)
            {
                ["host"] = Environment.MachineName,
                ["osDescription"] = RuntimeInformation.OSDescription,
                ["osArchitecture"] = RuntimeInformation.OSArchitecture.ToString(),
                ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                ["rid"] = RuntimeInformation.RuntimeIdentifier,
                ["logicalProcessors"] = Environment.ProcessorCount.ToString(CultureInfo.InvariantCulture),
            };
            report.StageVerified = true;
            WritePhase(events, report.RunId, phase, "verified");
            phase = "driver_job_context";
            WritePhase(events, report.RunId, phase, "begin");
            var driver = WindowsHostContext.CaptureDriverJob(report.RunId);
            report.DriverJobContext = driver;
            var job = driver.GetProperty("job");
            bool identityObserved = driver.GetProperty("processCreationFileTime").ValueKind == JsonValueKind.Number;
            bool membershipObserved = job.GetProperty("status").GetString() == "membership_observed";
            report.DriverInheritedJob = membershipObserved ? job.GetProperty("inJob").GetBoolean() : null;
            report.DriverJobContextObserved = identityObserved && membershipObserved
                && (report.DriverInheritedJob == false || job.GetProperty("extendedLimits").GetProperty("status").GetString() == "observed"
                    && job.GetProperty("uiRestrictions").GetProperty("status").GetString() == "observed"
                    && job.GetProperty("cpuRateControl").GetProperty("status").GetString() == "observed");
            report.DriverJobContextStatus = !report.DriverJobContextObserved ? "driver_job_observation_unproven"
                : report.DriverInheritedJob == true ? "immediate_job_observed_ancestors_not_enumerated" : "no_inherited_job_observed";
            var driverBytes = Encoding.UTF8.GetBytes(driver.GetRawText());
            Check(driverBytes.Length <= 16 * 1024, "driver_job_context_bound");
            string driverPath = reportPath + ".driver-context.json";
            using (var output = new FileStream(driverPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
            {
                output.Write(driverBytes);
                output.Flush(flushToDisk: true);
            }
            report.DriverJobContextFile = Path.GetFileName(driverPath);
            report.DriverJobContextSha256 = FileHash(driverPath);
            WritePhase(events, report.RunId, phase, report.DriverJobContextStatus);
            if (report.DriverInheritedJob != false || !report.DriverJobContextObserved)
            {
                report.Limitations = [.. report.Limitations, "The calling-process Job snapshot does not enumerate unknown ancestors. Each experiment verifies native assignment, limits, enforcement and cleanup through its held owned Job handles."];
            }
            Directory.CreateDirectory(work);
            if (report.DiagnosticSelection)
            {
                phase = "diagnostic_" + report.SelectionGroup;
                WritePhase(events, report.RunId, phase, "begin");
                report.Cases = report.SelectionGroup switch
                {
                    "terminal" => await RunTerminalCasesAsync(stage, work).ConfigureAwait(false),
                    "resource" => await WindowsResourceCases.RunAsync(stage, work).ConfigureAwait(false),
                    "policy" => await WindowsPolicyCases.RunAsync(stage, work).ConfigureAwait(false),
                    "network" => await WindowsNetworkCases.RunAsync(stage, work).ConfigureAwait(false),
                    "lifecycle" => await WindowsLifecycleCases.RunAsync(stage, work).ConfigureAwait(false),
                    "combined" => await WindowsCombinedCases.RunAsync(stage, work).ConfigureAwait(false),
                    "cli" => await WindowsCliCases.RunAsync(stage, work).ConfigureAwait(false),
                    _ => throw new ArgumentException("Unknown diagnostic group.")
                };
                WritePhase(events, report.RunId, phase, report.Cases.All(CaseSucceeded) ? "passed" : "failed");
            }
            else
            {
                (string Name, Func<Task<List<WindowsQualificationCase>>> Run)[] groups =
                [
                    ("terminal", () => RunTerminalCasesAsync(stage, work)),
                    ("resource", () => WindowsResourceCases.RunAsync(stage, work)),
                    ("policy", () => WindowsPolicyCases.RunAsync(stage, work)),
                    ("network", () => WindowsNetworkCases.RunAsync(stage, work)),
                    ("cli", () => WindowsCliCases.RunAsync(stage, work)),
                    ("lifecycle", () => WindowsLifecycleCases.RunAsync(stage, work)),
                    ("combined", () => WindowsCombinedCases.RunAsync(stage, work)),
                ];
                foreach (var group in groups)
                {
                    phase = "full_" + group.Name;
                    WritePhase(events, report.RunId, phase, "begin");
                    var cases = await group.Run().ConfigureAwait(false);
                    report.Cases.AddRange(cases);
                    bool passed = cases.Count > 0 && cases.All(CaseSucceeded);
                    WritePhase(events, report.RunId, phase, passed ? "passed" : "failed");
                    // Diagnose a failed slice before starting more native workloads.
                    if (!passed) break;
                }
            }
            phase = "final_stage_identity";
            WritePhase(events, report.RunId, phase, "begin");
            Program.ValidateStage(manifest);
            Check(FileHash(manifest) == report.ManifestSha256 && FileHash(Environment.ProcessPath!) == report.ExecutableSha256,
                "profile_stage_identity_changed");
            report.FinalIdentityVerified = true;
            WritePhase(events, report.RunId, phase, "verified");
        }
        catch (Exception exception)
        {
            report.FailurePhase = phase;
            report.FailureCode = FailureCode(exception);
            report.FailureType = exception.GetType().Name;
            report.FailureHResult = exception.HResult;
            report.Failure = ObserveFailure(exception);
            TryWriteFailure(events, report, phase, exception);
        }
        FinalizeReport(report);
        report.FinishedUtc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        try
        {
            if (events is not null) WritePhase(events, report.RunId, "qualification", report.QualificationPassed ? "passed" : "partial_or_failed");
        }
        catch (Exception exception) { RecordEvidenceFailure(report, exception); }
        finally
        {
            try { events?.Dispose(); }
            catch (Exception exception) { RecordEvidenceFailure(report, exception); }
        }
        try
        {
            if (reportPath is not null)
            {
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(report, WindowsQualificationJson.Default.WindowsQualificationReport);
                string pending = reportPath + "." + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture) + ".pending";
                // The final receipt exists only after its complete bytes have
                // been flushed and the stream closed successfully. Failed
                // evidence publication retains the pending file for diagnosis.
                using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
                {
                    await output.WriteAsync(bytes).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }
                File.Move(pending, reportPath, overwrite: false);
            }
        }
        catch (Exception exception) { RecordEvidenceFailure(report, exception); }
        Console.WriteLine(JsonSerializer.Serialize(report, WindowsQualificationJson.Default.WindowsQualificationReport));
        return report.QualificationPassed ? 0 : report.DiagnosticSelection && report.ExecutedCasesPassed && report.Failure is null && report.EvidenceFailure is null ? 2 : 1;
    }

    private static bool IsCommit(string value) => value.Length == 40 && value.All(char.IsAsciiHexDigit);

    private static string FileHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    private static bool CaseSucceeded(WindowsQualificationCase item)
    {
        bool scopeClosed = item.Name == "reject-missing-policy"
            ? item.ExitSource == "official_executor_config_rejection" && item.ExecutorProcessId != 0
                && item.ExecutorStartUtc is not null && item.RawExecutorExit is > 0 and < 0x80000000
            : item.JobEmpty;
        return item.Passed && item.CleanupCompleted && scopeClosed && item.UnresolvedCleanupOwner is null
            && item.PrimaryFailure is null && item.CleanupFailure is null && item.EvidenceFailure is null
            && item.DiagnosticFailure is null && item.DrainFailure is null && item.FailureCode is null;
    }

    private static void FinalizeReport(WindowsQualificationReport report)
    {
        var observed = report.Cases.GroupBy(item => item.Name, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.Ordinal);
        var expectedNames = RequiredCases.Values.SelectMany(names => names).ToHashSet(StringComparer.Ordinal);
        report.DuplicateCases = observed.Where(item => item.Value.Length != 1).Select(item => item.Key).Order(StringComparer.Ordinal).ToArray();
        report.UnexpectedCases = observed.Keys.Where(name => !expectedNames.Contains(name)).Order(StringComparer.Ordinal).ToArray();
        report.IncompleteProtocols = RequiredCases.Where(protocol => protocol.Value.Any(name =>
            !observed.TryGetValue(name, out var cases) || cases.Length != 1 || cases[0].Protocol != protocol.Key || !CaseSucceeded(cases[0])))
            .Select(protocol => protocol.Key).ToArray();
        report.ExpectedCases = expectedNames.Count;
        report.ExecutedCasesPassed = report.Cases.Count > 0 && report.Cases.All(CaseSucceeded);
        report.CleanupConfirmed = report.Cases.Count > 0 && report.Cases.All(item => item.CleanupCompleted && item.UnresolvedCleanupOwner is null && item.CleanupFailure is null);
        report.QualificationPassed = !report.DiagnosticSelection && report.StageVerified && report.FinalIdentityVerified && report.DriverJobContextObserved
            && report.Failure is null && report.EvidenceFailure is null && report.ExecutedCasesPassed && report.CleanupConfirmed
            && report.Cases.Count == report.ExpectedCases && report.IncompleteProtocols.Length == 0
            && report.DuplicateCases.Length == 0 && report.UnexpectedCases.Length == 0;
        report.Status = report.DiagnosticSelection ? "partial" : report.QualificationPassed ? "passed" : "failed";
    }

    private static void WritePhase(FileStream stream, string runId, string phase, string outcome, WindowsQualificationFailure? failure = null)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new WindowsQualificationPhase(runId, phase, outcome, DateTimeOffset.UtcNow, failure),
            WindowsQualificationJson.Default.WindowsQualificationPhase);
        Check(stream.Position + bytes.Length + 1 <= 256 * 1024, "qualification_event_bound");
        stream.Write(bytes);
        stream.WriteByte((byte)'\n');
        stream.Flush(flushToDisk: true);
    }

    private static void TryWriteFailure(FileStream? events, WindowsQualificationReport report, string phase, Exception exception)
    {
        if (events is null) return;
        try { WritePhase(events, report.RunId, phase, "failed", ObserveFailure(exception)); }
        catch (Exception evidence) { RecordEvidenceFailure(report, evidence); }
    }

    private static void RecordEvidenceFailure(WindowsQualificationReport report, Exception exception)
    {
        report.EvidenceFailure ??= ObserveFailure(exception);
        report.QualificationPassed = false;
        report.Status = report.DiagnosticSelection ? "partial" : "failed";
        Console.Error.WriteLine("windows_qualification_evidence_failed:type=" + exception.GetType().Name
            + ":hresult=" + exception.HResult.ToString("X8", CultureInfo.InvariantCulture));
    }

    [SupportedOSPlatform("windows")]
    internal static async Task<List<WindowsQualificationCase>> RunTerminalCasesAsync(string stage, string work)
    {
        var results = new List<WindowsQualificationCase>();
        var smoke = await RunCaseAsync("console-info", stage, work, ["console-info"], async (_, capture) =>
        {
            var console = capture.WaitForTerminalEventAsync("console", TimeSpan.FromSeconds(10));
            try { await console.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
            catch (TimeoutException) { await capture.RecordOwnedDiagnosticAsync("console-info-2s").ConfigureAwait(false); }
            var info = await console.ConfigureAwait(false);
            Check(info.GetProperty("inputConsole").GetBoolean() && info.GetProperty("outputConsole").GetBoolean()
                && info.GetProperty("screenInfo").GetBoolean(), "native_console_api_required");
            Check(info.GetProperty("columns").GetInt32() == 80 && info.GetProperty("rows").GetInt32() == 24, "initial_terminal_size_mismatch");
        }).ConfigureAwait(false);
        results.Add(smoke);
        if (!smoke.Passed) return results;

        results.Add(await RunCaseAsync("line-editing", stage, work, ["console", "line", "15000"], async (session, capture) =>
        {
            _ = await capture.WaitForEventAsync("console-ready", TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            // VT Backspace is DEL. Sending BS/Ctrl+H is a different input and
            // must not silently substitute a word-deletion operation here.
            await session.WriteInputAsync("ab\u007f星\r"u8.ToArray(), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            var line = await capture.WaitForEventAsync("line", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            Check(!line.GetProperty("eof").GetBoolean() && line.GetProperty("length").GetInt32() == 2
                && line.GetProperty("sha256").GetString() == Convert.ToHexStringLower(SHA256.HashData("a星"u8)), "line_editing_mismatch");
            Check(capture.Contains("AFV2 Unicode: forge 星 Ω 😀") && capture.Contains("\u001b[?1049h"), "unicode_alternate_screen_missing");
        }).ConfigureAwait(false));

        results.Add(await RunCaseAsync("raw-resize", stage, work, ["console", "raw", "15000"], async (session, capture) =>
        {
            _ = await capture.WaitForEventAsync("console-ready", TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            foreach (var size in new[] { (40, 12), (160, 50), (80, 24) })
            {
                session.Resize(size.Item1, size.Item2);
                _ = await capture.WaitForEventAsync("resize", TimeSpan.FromSeconds(3), x => x.GetProperty("columns").GetInt32() == size.Item1
                    && x.GetProperty("rows").GetInt32() == size.Item2).ConfigureAwait(false);
            }
            foreach (var size in new[] { (0, 24), (80, 0), (32768, 24), (80, 32768) })
            {
                var rejected = false;
                try { session.Resize(size.Item1, size.Item2); }
                catch (ArgumentOutOfRangeException) { rejected = true; }
                Check(rejected, "invalid_resize_not_rejected");
            }
            await session.WriteInputAsync("星"u8.ToArray(), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            _ = await capture.WaitForEventAsync("key", TimeSpan.FromSeconds(3), x => x.GetProperty("code").GetInt32() == '星').ConfigureAwait(false);
            await session.WriteInputAsync("q"u8.ToArray(), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }).ConfigureAwait(false));

        var flood = await RunCaseAsync("detached-flood", stage, work, ["flood", "2097152"], async (session, capture) =>
        {
            // The session's native drain keeps running without a replay reader.
            var identity = session.ProcessId;
            await Task.Delay(250).ConfigureAwait(false);
            var end = await capture.WaitForEventAsync("flood-finished", TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            Check(end.GetProperty("bytesWritten").GetInt32() == 2 * 1024 * 1024, "flood_incomplete");
            Check(identity == session.ProcessId, "terminal_identity_changed");
        }).ConfigureAwait(false);
        // The untrusted file event is not terminal-drain completion. Check the
        // real drained byte count after the native wait/EOF, with the same bound.
        if (flood.Passed && flood.ObservedTerminalBytes < 2 * 1024 * 1024)
        {
            flood.Passed = false;
            flood.FailureCode = "flood_incomplete";
            flood.PrimaryFailure = ObserveFailure(new WindowsQualificationCheckException("flood_incomplete"));
            flood.FailureType = flood.PrimaryFailure.Type;
            flood.FailureHResult = flood.PrimaryFailure.HResult;
        }
        results.Add(flood);

        foreach (var code in new[] { 0, 1, 23 })
            results.Add(await RunCaseAsync("exit-" + code.ToString(CultureInfo.InvariantCulture), stage, work, ["exit", code.ToString(CultureInfo.InvariantCulture)], expectedExecutorExit: (uint)code).ConfigureAwait(false));
        results.Add(await RunCaseAsync("fake-error-output", stage, work, ["fake-errors", "23"], async (_, capture) =>
        {
            await capture.WaitForTextAsync("synthetic_backend_failure", TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            await capture.WaitForTextAsync("\"exit_source\":\"payload\"", TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        }, expectedExecutorExit: 23).ConfigureAwait(false));

        results.Add(await InteractiveShellAsync(stage, work).ConfigureAwait(false));
        results.Add(await PayloadLaunchRefusalAsync(stage, work, malformedImage: false).ConfigureAwait(false));
        results.Add(await PayloadLaunchRefusalAsync(stage, work, malformedImage: true).ConfigureAwait(false));
        results.Add(await PolicyTimeoutAsync(stage, work).ConfigureAwait(false));

        foreach (var mode in new[] { "cooperative", "raw", "ignore-etx" })
        {
            var control = new WindowsTerminalControlObservation { Mode = mode, GraceMs = 3000 };
            string? eventsDirectory = null;
            var result = await RunCaseAsync("etx-" + mode, stage, work, ["console", mode, "15000"], async (session, capture) =>
            {
                eventsDirectory = capture.FixtureEventsDirectory;
                _ = await capture.WaitForEventAsync("console-ready", TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                if (mode == "cooperative")
                {
                    var child = await capture.WaitForEventAsync("child-created", TimeSpan.FromSeconds(3)).ConfigureAwait(false);
                    control.FixtureRootPid = child.GetProperty("pid").GetUInt32();
                    control.FixtureChildPid = child.GetProperty("childPid").GetUInt32();
                }
                control.BeforeEtxJob = session.ObserveJob();
                if (mode == "cooperative")
                    Check(control.FixtureRootPid != control.FixtureChildPid && control.FixtureRootPid != session.ProcessId && control.FixtureChildPid != session.ProcessId
                        && control.BeforeEtxJob.ProcessIds.Contains(control.FixtureRootPid!.Value) && control.BeforeEtxJob.ProcessIds.Contains(control.FixtureChildPid!.Value)
                        && control.BeforeEtxJob.ProcessIds.Contains(session.ProcessId), "cooperative_child_native_membership_missing");
                await session.SendEtxAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                control.EtxSent = true;
                if (mode == "cooperative")
                {
                    var grace = Stopwatch.StartNew();
                    while (grace.Elapsed < TimeSpan.FromMilliseconds(control.GraceMs))
                    {
                        control.HandlerObserved = capture.ReadFixtureEvents().Any(x => x.GetProperty("event").GetString() == "ctrl");
                        var code = session.GetExecutorExitCode();
                        if (code is not null)
                        {
                            // Read once more after the trusted exit observation
                            // so a just-flushed handler record is not missed.
                            control.HandlerObserved = capture.ReadFixtureEvents().Any(x => x.GetProperty("event").GetString() == "ctrl");
                            if (code == 0 && control.HandlerObserved) control.Outcome = "handler_graceful_exit";
                            else if (code == 0xc000013a && !control.HandlerObserved) control.Outcome = "native_ctrl_exit";
                            else throw new WindowsQualificationCheckException("unexpected_cooperative_etx_outcome");
                            control.ExitObservedWithinGrace = true;
                            return;
                        }
                        capture.Refresh();
                        await Task.Delay(10).ConfigureAwait(false);
                    }
                    control.EscalationRequested = true;
                    control.Outcome = "deadline_tree_kill_requested";
                    _ = await session.ForceStopAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                }
                else
                {
                    var key = await capture.WaitForEventAsync("key", TimeSpan.FromSeconds(3), x => x.GetProperty("etx").GetBoolean()).ConfigureAwait(false);
                    Check(key.GetProperty("ignored").GetBoolean() == (mode == "ignore-etx"), "etx_mode_mismatch");
                    Check(session.GetExecutorExitCode() is null, "etx_was_not_only_terminal_input");
                    control.RawEtxObserved = true;
                    control.EscalationRequested = true;
                    control.Outcome = "raw_terminal_input_then_tree_kill";
                    _ = await session.ForceStopAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                }
            }, expectedExecutorExit: null).ConfigureAwait(false);
            result.TerminalControl = control;
            if (result.Passed && control.Outcome == "native_ctrl_exit")
            {
                try
                {
                    control.HandlerObserved = WindowsTerminalCapture.ReadFixtureEvents(eventsDirectory!).Any(x => x.GetProperty("event").GetString() == "ctrl");
                    Check(result.RawExecutorExit == 0xc000013a && result.JobEmpty && !control.HandlerObserved, "native_ctrl_exit_final_evidence_missing");
                }
                catch (Exception exception) { FailCase(result, exception); }
            }
            results.Add(result);
        }
        return results;
    }

    [SupportedOSPlatform("windows")]
    internal static Task<WindowsQualificationCase> RunCaseAsync(string name, string stage, string work, IReadOnlyList<string> workloadArgs,
        Func<ConPtySession, WindowsTerminalCapture, Task>? exercise = null, uint? expectedExecutorExit = 0, ConPtyLimits? limits = null)
    {
        var fixture = BuildCaseRequest(stage, work, name, Path.Combine(stage, "arcforges-mxc-probe.exe"), ["--windows-workload", .. workloadArgs]);
        var policy = WindowsPolicy.WritePrivate(fixture.Control, fixture.Request);
        return RunCaseAsync(name, stage, policy, exercise, expectedExecutorExit, limits, fixture.Events);
    }

    [SupportedOSPlatform("windows")]
    private static WindowsTerminalFixture BuildCaseRequest(string stage, string work, string name, string executable, IReadOnlyList<string> args)
    {
        var root = Path.Combine(work, name);
        Directory.CreateDirectory(root);
        var fixture = Path.Combine(root, "workspace 工作区");
        var owned = new WindowsOwnedPaths(Path.Combine(fixture, "home"), Path.Combine(fixture, "config"), Path.Combine(fixture, "cache"),
            Path.Combine(fixture, "temp"), Path.Combine(fixture, "work"), Path.Combine(fixture, "data"));
        foreach (var directory in new[] { owned.Home, owned.Config, owned.Cache, owned.Temp, owned.Work, owned.Data }) Directory.CreateDirectory(directory);
        var control = Path.Combine(root, "private control");
        var request = WindowsPolicy.BuildRequest(executable, args, owned,
            [stage, Environment.GetFolderPath(Environment.SpecialFolder.System)], [control], WindowsNetworkChoice.DenyAll);
        var events = EnableFixtureEvents(request, owned.Work);
        return new(owned, control, request, events);
    }

    [SupportedOSPlatform("windows")]
    private static async Task<WindowsQualificationCase> InteractiveShellAsync(string stage, string work)
    {
        var fixture = BuildCaseRequest(stage, work, "interactive-cmd", Path.Combine(Environment.SystemDirectory, "cmd.exe"), ["/d", "/q"]);
        fixture.Request.Process.Env = [.. fixture.Request.Process.Env, "PROMPT=AFV2_MXC_PROMPT$G", "AFV2_MXC_SHELL_ECHO=AFV2_MXC_SHELL_OK"];
        var policy = WindowsPolicy.WritePrivate(fixture.Control, fixture.Request);
        var result = await RunCaseAsync("interactive-cmd", stage, policy, async (session, capture) =>
        {
            await capture.WaitForTextAsync("AFV2_MXC_PROMPT>", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            // The complete marker is absent from the input bytes. Its actual
            // appearance requires shell expansion/output, independently of how
            // ConPTY represents cursor movement or line boundaries.
            await session.WriteInputAsync("echo %AFV2_MXC_SHELL_ECHO%\r"u8.ToArray(), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            await capture.WaitForTextAsync("AFV2_MXC_SHELL_OK", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            await session.WriteInputAsync("echo AFV2_MXC_SHELL_FILE>shell-result.txt\rexit 23\r"u8.ToArray(), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        }, expectedExecutorExit: 23, fixtureEventsDirectory: fixture.Events).ConfigureAwait(false);
        if (result.Passed)
        {
            try { Check(File.ReadAllText(Path.Combine(fixture.Owned.Work, "shell-result.txt")).Trim() == "AFV2_MXC_SHELL_FILE", "interactive_shell_command_not_executed"); }
            catch (Exception exception) { FailCase(result, exception); }
        }
        result.ExpectedOutcome = "interactive_cmd_prompt_echo_and_exit_23";
        return result;
    }

    [SupportedOSPlatform("windows")]
    private static async Task<WindowsQualificationCase> PayloadLaunchRefusalAsync(string stage, string work, bool malformedImage)
    {
        var name = malformedImage ? "native-invalid-image" : "invalid-payload-executable";
        var fixture = BuildCaseRequest(stage, work, name, Path.Combine(stage, "arcforges-mxc-probe.exe"), []);
        var executable = Path.Combine(fixture.Owned.Work, malformedImage ? "malformed-owned.exe" : "missing-owned.exe");
        string? imageHash = null;
        if (malformedImage)
        {
            // A fixed owned non-PE image reaches the unchanged executor's real
            // native payload creation path; the official binary is untouched.
            byte[] invalidImage = [0x4d, 0x5a, 0, 0, 0, 0, 0, 0];
            await File.WriteAllBytesAsync(executable, invalidImage).ConfigureAwait(false);
            imageHash = Convert.ToHexStringLower(SHA256.HashData(invalidImage));
        }
        else Check(!File.Exists(executable), "missing_payload_fixture_already_exists");
        fixture.Request.Process.CommandLine = WindowsPolicy.QuoteCommandLine(executable, []);
        var policy = WindowsPolicy.WritePrivate(fixture.Control, fixture.Request);
        var result = await RunCaseAsync(name, stage, policy, expectedExecutorExit: null, fixtureEventsDirectory: fixture.Events).ConfigureAwait(false);
        if (result.Passed)
        {
            try
            {
                Check(result.RawExecutorExit is > 0 && result.JobEmpty && result.FinalJob is { ActiveProcesses: 0 }, "payload_native_creation_refusal_not_proven");
                Check(result.CapturedBytes > 0 && result.PrivateTranscriptFile is not null, "payload_launch_refusal_diagnostic_missing");
                Check(WindowsTerminalCapture.ReadFixtureEvents(fixture.Events).Length == 0, "unexpected_payload_fixture_observation");
            }
            catch (Exception exception) { FailCase(result, exception); }
        }
        result.ExpectedOutcome = malformedImage ? "official_executor_refuses_owned_invalid_image" : "official_executor_refuses_missing_payload";
        result.PayloadFixtureSha256 = imageHash;
        return result;
    }

    [SupportedOSPlatform("windows")]
    private static async Task<WindowsQualificationCase> PolicyTimeoutAsync(string stage, string work)
    {
        const uint policyMs = 1500;
        const int fixtureMs = 15000;
        var fixture = BuildCaseRequest(stage, work, "official-policy-timeout", Path.Combine(stage, "arcforges-mxc-probe.exe"), ["--windows-workload", "console", "ignore-etx", fixtureMs.ToString(CultureInfo.InvariantCulture)]);
        fixture.Request.Process.Timeout = policyMs;
        var policy = WindowsPolicy.WritePrivate(fixture.Control, fixture.Request);
        Stopwatch? naturalLifetime = null;
        var result = await RunCaseAsync("official-policy-timeout", stage, policy, async (session, capture) =>
        {
            naturalLifetime = Stopwatch.StartNew();
            _ = await capture.WaitForEventAsync("console-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            Check(session.GetExecutorExitCode() is null, "timeout_fixture_not_observed_live");
            // No input, Stop or forced termination: only the compiled official
            // policy timer may end this live console before its own deadline.
        }, expectedExecutorExit: null, fixtureEventsDirectory: fixture.Events).ConfigureAwait(false);
        result.NaturalLifetimeMs = naturalLifetime?.Elapsed.TotalMilliseconds;
        result.RequestedPolicyTimeoutMs = policyMs;
        result.FixtureOwnDeadlineMs = fixtureMs;
        result.ExpectedOutcome = "official_policy_timeout_without_manual_stop";
        if (result.Passed)
        {
            try
            {
                Check(result.RawExecutorExit is > 0 && result.JobEmpty && result.NaturalLifetimeMs is >= 1000 and < 8000, "official_policy_timeout_not_observed");
                Check(!WindowsTerminalCapture.ReadFixtureEvents(fixture.Events).Any(x => x.GetProperty("event").GetString() == "deadline"), "fixture_own_deadline_was_not_policy_timeout");
            }
            catch (Exception exception) { FailCase(result, exception); }
        }
        return result;
    }

    private static void FailCase(WindowsQualificationCase result, Exception exception)
    {
        result.Passed = false;
        result.PrimaryFailure ??= ObserveFailure(exception);
        result.FailureCode = result.PrimaryFailure.Code;
        result.FailureType = result.PrimaryFailure.Type;
        result.FailureHResult = result.PrimaryFailure.HResult;
    }

    private sealed record WindowsTerminalFixture(WindowsOwnedPaths Owned, string Control, WindowsPolicyRequest Request, string Events);

    [SupportedOSPlatform("windows")]
    internal static string EnableFixtureEvents(WindowsPolicyRequest request, string ownedWork)
    {
        var work = Path.GetFullPath(ownedWork);
        Check(Path.GetFullPath(request.Process.Cwd).Equals(work, StringComparison.OrdinalIgnoreCase), "fixture_observation_workspace_mismatch");
        // A fresh directory per Run prevents an earlier Run's PID/event file
        // from becoming an observation of a later Run in the same Sandbox.
        var directory = Path.Combine(work, "probe-observations-" + Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture));
        Directory.CreateDirectory(directory);
        const string prefix = "AFV2_MXC_OBSERVATIONS_DIR=";
        request.Process.Env = [.. request.Process.Env.Where(x => !x.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)), prefix + directory];
        return directory;
    }

    [SupportedOSPlatform("windows")]
    internal static async Task<WindowsQualificationCase> RunCaseAsync(string name, string stage, WindowsPolicyArtifact policy,
        Func<ConPtySession, WindowsTerminalCapture, Task>? exercise = null, uint? expectedExecutorExit = 0, ConPtyLimits? limits = null,
        string? fixtureEventsDirectory = null)
    {
        var result = new WindowsQualificationCase { Name = name, PolicySha256 = policy.Sha256, FixtureObservationSource = fixtureEventsDirectory is null ? "not_enabled" : "untrusted_payload_files" };
        var watch = Stopwatch.StartNew();
        ConPtySession? session = null;
        WindowsTerminalCapture? capture = null;
        try
        {
            var probe = await WindowsPolicyProbe.RunAsync(stage, policy.Path, Path.Combine(policy.ControlDirectory, "native-probe")).ConfigureAwait(false);
            Check(probe.ExitCode == 0 && probe.JsonParsed && probe.NativeBaseContainer && probe.NeedsDaclAugmentation == false
                && probe.DenyPaths && probe.UiRestrictionsComplete, "same_policy_native_probe_refused");
            result.SamePolicyProbePassed = true;
            session = ConPtySession.Start(new(Path.Combine(stage, "wxc-exec.exe"), policy.Path, policy.ControlDirectory, 80, 24,
                limits ?? new(5000, 1024UL * 1024 * 1024, 16), PrivateDiagnostics: name is "console-info" or "native-invalid-image" or "invalid-payload-executable" or "official-policy-timeout"));
            result.ExecutorProcessId = session.ProcessId;
            result.ExecutorStartUtc = session.ProcessStartTimeUtc.ToString("O", CultureInfo.InvariantCulture);
            result.InheritedJob = session.InheritedJob;
            result.SpawnMs = session.SpawnMs;
            capture = new WindowsTerminalCapture(session, policy.ControlDirectory, fixtureEventsDirectory);
            if (exercise is not null) await exercise(session, capture).ConfigureAwait(false);
            var wait = session.WaitAsync(TimeSpan.FromSeconds(25));
            while (!wait.IsCompleted) { capture.Refresh(); await Task.Delay(10).ConfigureAwait(false); }
            var exit = await wait.ConfigureAwait(false);
            capture.Refresh();
            result.RawExecutorExit = exit.RawExitCode;
            result.ExitSource = exit.ExitSource;
            result.JobEmpty = exit.JobEmpty;
            result.FinalJob = exit.Job;
            Check(exit.ExitSource == "official_executor" && exit.JobEmpty, "trusted_exit_or_cleanup_missing");
            Check(expectedExecutorExit is null || exit.RawExitCode == expectedExecutorExit, "raw_executor_exit_mismatch");
            Check(capture.DrainFailure is null, "terminal_drain_failed");
            result.Passed = true;
        }
        catch (Exception exception)
        {
            result.Passed = false;
            var primary = exception;
            if (exception is ConPtyLaunchException launch && launch.InnerException is AggregateException combined && combined.InnerExceptions.Count >= 2)
            {
                primary = combined.InnerExceptions[0];
                result.CleanupFailure = ObserveFailure(combined.InnerExceptions[1]);
                result.UnresolvedCleanupOwner = launch.CleanupOwner;
            }
            result.PrimaryFailure = ObserveFailure(primary);
            result.FailureCode = FailureCode(primary);
            result.FailureType = primary.GetType().Name;
            result.FailureHResult = primary.HResult;
        }
        finally
        {
            // Cleanup has its own outcome; it must never replace the first
            // exercise/launch failure with a later native termination error.
            if (session is not null)
            {
                if (result.PrimaryFailure is not null && capture is not null)
                {
                    var before = await capture.RecordOwnedDiagnosticAsync("before-cleanup").ConfigureAwait(false);
                    result.BeforeCleanupExecutorExit = before.ExecutorExit;
                    result.BeforeCleanupJob = before.Job;
                    result.BeforeCleanupExecutorObservationFailure = before.ExecutorObservationFailure;
                    result.BeforeCleanupJobObservationFailure = before.JobObservationFailure;
                }
                try
                {
                    await session.DisposeAsync().ConfigureAwait(false);
                    result.CleanupCompleted = true;
                }
                catch (Exception exception)
                {
                    result.CleanupFailure = ObserveFailure(exception);
                    result.UnresolvedCleanupOwner = session;
                    result.Passed = false;
                }
            }
            if (capture is not null)
            {
                try
                {
                    capture.Refresh();
                    result.ObservedTerminalBytes = capture.ObservedBytes;
                    result.CapturedBytes = capture.CapturedBytes;
                    result.CaptureTruncated = capture.CaptureTruncated;
                    result.ReplayGaps = capture.Gaps;
                    result.DrainFailure = capture.DrainFailure;
                    result.PrivateDiagnostics = capture.PrivateDiagnostics;
                    result.DiagnosticFailure = capture.DiagnosticFailure;
                    // Only this owner-private denied directory receives raw
                    // bytes. Shared JSON contains counts/hash, never the bytes.
                    var transcript = Path.Combine(policy.ControlDirectory, "terminal-output.bin");
                    await capture.WritePrivateTranscriptAsync(transcript).ConfigureAwait(false);
                    result.PrivateTranscriptFile = "terminal-output.bin";
                    result.PrivateTranscriptSha256 = capture.Sha256();
                }
                catch (Exception exception)
                {
                    result.EvidenceFailure = ObserveFailure(exception);
                    result.Passed = false;
                }
                finally { capture.Dispose(); }
            }
        }
        result.ElapsedMs = watch.Elapsed.TotalMilliseconds;
        return result;
    }

    private static bool Within(string path, string root) => path.Equals(root, StringComparison.OrdinalIgnoreCase)
        || path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    internal static void Check(bool condition, string code) { if (!condition) throw new WindowsQualificationCheckException(code); }
    internal static string FailureCode(Exception exception) => exception is WindowsQualificationCheckException check ? check.Code : "native_operation_failed";
    internal static WindowsQualificationFailure ObserveFailure(Exception exception)
    {
        var native = exception as Win32Exception ?? exception.InnerException as Win32Exception ?? exception.InnerException?.InnerException as Win32Exception;
        var message = native?.Message;
        // ConPtySession's native helper uses fixed operation strings ending in
        // " failed.". Arbitrary exception/request/OS messages are not exported.
        var operation = message is { Length: <= 160 } && message.EndsWith(" failed.", StringComparison.Ordinal)
            && message.All(x => char.IsAsciiLetterOrDigit(x) || x is ' ' or '.' or '-' or '(' or ')') ? message : null;
        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        // Only fixed diagnostic fields emitted by our controlled peer/calibrator,
        // never arbitrary exception messages, environment or payload output.
        for (Exception? current = exception; current is not null && details.Count < 48; current = current.InnerException)
        {
            foreach (System.Collections.DictionaryEntry item in current.Data)
            {
                if (item.Key is not string key || !(key.StartsWith("remotePeer", StringComparison.Ordinal) || key.StartsWith("networkCalibration", StringComparison.Ordinal))) continue;
                if (item.Value is not (string or int or long or uint or bool)) continue;
                var value = Convert.ToString(item.Value, CultureInfo.InvariantCulture);
                if (value is not null && value.Length <= 160 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.')) details.TryAdd(key, value);
            }
        }
        return new(FailureCode(exception), exception.GetType().Name, exception.HResult, native?.NativeErrorCode, operation, details.Count == 0 ? null : details, exception.InnerException?.GetType().Name);
    }
}

internal sealed class WindowsQualificationCheckException(string code, Exception? inner = null) : Exception(null, inner)
{
    internal string Code { get; } = code;
}

[SupportedOSPlatform("windows")]
internal sealed partial class WindowsTerminalCapture(ConPtySession session, string? privateControlDirectory = null, string? fixtureEventsDirectory = null) : IDisposable
{
    private const int MaximumCaptureBytes = 4 * 1024 * 1024;
    private readonly MemoryStream _captured = new();
    private long _cursor;
    internal long ObservedBytes { get; private set; }
    internal long CapturedBytes => _captured.Length;
    internal bool CaptureTruncated { get; private set; }
    internal string? DrainFailure { get; private set; }
    internal List<WindowsTerminalGap> Gaps { get; } = [];
    internal List<WindowsPrivateDiagnostic> PrivateDiagnostics { get; } = [];
    internal WindowsQualificationFailure? DiagnosticFailure { get; private set; }
    internal string? FixtureEventsDirectory { get; set; } = fixtureEventsDirectory;

    public void Dispose() => _captured.Dispose();

    internal string Sha256() => Convert.ToHexStringLower(SHA256.HashData(_captured.GetBuffer().AsSpan(0, checked((int)_captured.Length))));

    internal async Task WritePrivateTranscriptAsync(string path)
    {
        await using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        await output.WriteAsync(_captured.GetBuffer().AsMemory(0, checked((int)_captured.Length))).ConfigureAwait(false);
    }

    internal async Task<WindowsOwnedDiagnostic> RecordOwnedDiagnosticAsync(string phase)
    {
        var result = new WindowsOwnedDiagnostic { Phase = phase, AtUtc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture) };
        try { result.ExecutorExit = session.GetExecutorExitCode(); }
        catch (Exception exception) { result.ExecutorObservationFailure = WindowsQualification.ObserveFailure(exception); }
        try { result.Job = session.ObserveJob(); }
        catch (Exception exception) { result.JobObservationFailure = WindowsQualification.ObserveFailure(exception); }
        foreach (var pid in (result.Job?.ProcessIds ?? []).Take(16))
        {
            var item = new WindowsOwnedProcessDiagnostic { ProcessId = pid };
            result.Processes.Add(item);
            try
            {
                using var process = Process.GetProcessById(checked((int)pid));
                // Retain this exact OS process object before rechecking current
                // Job membership; a stale/recycled PID is not diagnostic authority.
                _ = process.SafeHandle;
                if (!session.ObserveJob().ProcessIds.Contains(pid)) { item.NoLongerOwned = true; continue; }
                var name = process.ProcessName;
                item.Name = name[..Math.Min(name.Length, 64)];
                var threads = process.Threads;
                item.ThreadsTruncated = threads.Count > 32;
                for (var index = 0; index < Math.Min(threads.Count, 32); index++)
                {
                    using var thread = threads[index];
                    var state = thread.ThreadState;
                    item.Threads.Add(new(thread.Id, state.ToString(), state == System.Diagnostics.ThreadState.Wait ? thread.WaitReason.ToString() : null));
                }
            }
            catch (Exception exception) { item.Failure = WindowsQualification.ObserveFailure(exception); }
        }
        result.ProcessesTruncated = result.Job is { } job && job.ProcessIds.Length > 16;
        try
        {
            if (privateControlDirectory is null || phase.Length > 48 || !phase.All(x => char.IsAsciiLetterOrDigit(x) || x == '-'))
                throw new InvalidOperationException("A fixed private diagnostic destination is required.");
            var bytes = JsonSerializer.SerializeToUtf8Bytes(result, WindowsQualificationJson.Default.WindowsOwnedDiagnostic);
            var filename = phase + ".json";
            await using var output = new FileStream(Path.Combine(privateControlDirectory, filename), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            await output.WriteAsync(bytes).ConfigureAwait(false);
            PrivateDiagnostics.Add(new(filename, Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length));
        }
        catch (Exception exception) { DiagnosticFailure = WindowsQualification.ObserveFailure(exception); }
        return result;
    }

    internal void Refresh()
    {
        for (var index = 0; index < 256; index++)
        {
            var read = session.ReadReplay(_cursor);
            DrainFailure = read.DrainFailure;
            ObservedBytes = read.AvailableUntil;
            if (read.GapFrom is { } from && read.GapUntil is { } until)
            {
                if (Gaps.Count < 32) Gaps.Add(new(from, until));
                CaptureTruncated = true;
            }
            var count = (int)Math.Min(read.Data.Length, MaximumCaptureBytes - _captured.Length);
            if (count != 0) _captured.Write(read.Data, 0, count);
            if (count != read.Data.Length) CaptureTruncated = true;
            _cursor = read.NextSequence;
            if (read.Data.Length == 0 || _cursor == read.AvailableUntil) return;
        }
        throw new InvalidDataException("The bounded terminal read exceeded its capacity.");
    }

    internal bool Contains(string text) { Refresh(); return Text().Contains(text, StringComparison.Ordinal); }
    private string Text() => Encoding.UTF8.GetString(_captured.GetBuffer(), 0, checked((int)_captured.Length));

    // A bounded parsing view, not a terminal emulator or a trusted state channel.
    // Conhost may insert title/cursor sequences inside an ordinary fixture JSON
    // token. Raw capture and ANSI assertions continue to use the original bytes.
    internal static string FixtureParsingView(string text)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(text.Length, MaximumCaptureBytes);
        var output = new StringBuilder(text.Length);
        for (var index = 0; index < text.Length;)
        {
            var value = text[index];
            if (value == '\u001b')
            {
                if (index + 1 == text.Length) break;
                var introducer = text[index + 1];
                if (introducer == '[') { index = SkipCsi(text, index + 2); continue; }
                if (introducer == ']') { index = SkipControlString(text, index + 2, allowBell: true); continue; }
                if (introducer is 'P' or 'X' or '^' or '_') { index = SkipControlString(text, index + 2, allowBell: false); continue; }
                var end = index + 1;
                while (end < text.Length && text[end] is >= '\u0020' and <= '\u002f') end++;
                if (end == text.Length) break;
                index = text[end] is >= '\u0030' and <= '\u007e' ? end + 1 : end;
                continue;
            }
            if (value == '\u009b') { index = SkipCsi(text, index + 1); continue; }
            if (value == '\u009d') { index = SkipControlString(text, index + 1, allowBell: true); continue; }
            if (value is '\u0090' or '\u0098' or '\u009e' or '\u009f') { index = SkipControlString(text, index + 1, allowBell: false); continue; }
            if (value is not ('\u0007' or '\u009c')) output.Append(value);
            index++;
        }
        return output.ToString();
    }

    private static int SkipCsi(string text, int cursor)
    {
        while (cursor < text.Length && text[cursor] is >= '\u0030' and <= '\u003f') cursor++;
        while (cursor < text.Length && text[cursor] is >= '\u0020' and <= '\u002f') cursor++;
        // A split/incomplete tail contributes nothing until the next full view.
        if (cursor == text.Length) return cursor;
        return text[cursor] is >= '\u0040' and <= '\u007e' ? cursor + 1 : cursor;
    }

    private static int SkipControlString(string text, int cursor, bool allowBell)
    {
        for (; cursor < text.Length; cursor++)
        {
            if ((allowBell && text[cursor] == '\u0007') || text[cursor] == '\u009c') return cursor + 1;
            if (text[cursor] == '\u001b' && cursor + 1 < text.Length && text[cursor + 1] == '\\') return cursor + 2;
        }
        return text.Length;
    }

    internal async Task WaitForTextAsync(string text, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < timeout)
        {
            if (Contains(text)) return;
            await Task.Delay(10).ConfigureAwait(false);
        }
        throw new WindowsQualificationCheckException("expected_terminal_text_missing");
    }

    internal async Task<JsonElement> WaitForEventAsync(string eventName, TimeSpan timeout, Func<JsonElement, bool>? predicate = null)
    {
        var observation = WaitForFixtureEventAsync(FixtureEventsDirectory ?? throw new WindowsQualificationCheckException("fixture_observations_not_enabled"), eventName, timeout, predicate);
        while (!observation.IsCompleted) { Refresh(); await Task.Delay(10).ConfigureAwait(false); }
        var result = await observation.ConfigureAwait(false);
        Refresh();
        return result;
    }

    internal JsonElement[] ReadFixtureEvents() =>
        ReadFixtureEvents(FixtureEventsDirectory ?? throw new WindowsQualificationCheckException("fixture_observations_not_enabled"));

    internal static async Task<JsonElement> WaitForFixtureEventAsync(string directory, string eventName, TimeSpan timeout, Func<JsonElement, bool>? predicate = null)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < timeout)
        {
            foreach (var item in ReadFixtureEvents(directory))
                if (item.GetProperty("event").GetString() == eventName && (predicate is null || predicate(item))) return item;
            await Task.Delay(10).ConfigureAwait(false);
        }
        throw new WindowsQualificationCheckException("expected_fixture_file_event_missing");
    }

    // These files are ordinary, writable payload observations. They never set
    // backend classification, payload-start certainty, owner state or cleanup.
    internal static JsonElement[] ReadFixtureEvents(string directory)
    {
        const int maximumFileBytes = 64 * 1024;
        const int maximumTotalBytes = 1024 * 1024;
        var root = Path.GetFullPath(directory);
        if (!Path.IsPathFullyQualified(directory) || root.StartsWith("\\\\", StringComparison.Ordinal)
            || (File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new WindowsQualificationCheckException("fixture_observation_directory_invalid");
        var files = Directory.EnumerateFileSystemEntries(root).Take(17).ToArray();
        if (files.Length > 16) throw new WindowsQualificationCheckException("fixture_observation_file_count_exceeded");
        var result = new List<JsonElement>();
        long total = 0;
        foreach (var file in files.Order(StringComparer.Ordinal))
        {
            var name = Path.GetFileName(file);
            var attributes = File.GetAttributes(file);
            if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 || !name.EndsWith(".jsonl", StringComparison.Ordinal)
                || !uint.TryParse(name.AsSpan(0, name.Length - 6), NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid == 0)
                throw new WindowsQualificationCheckException("fixture_observation_file_invalid");
            using var input = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if ((File.GetAttributes(input.SafeFileHandle) & FileAttributes.ReparsePoint) != 0
                || !FinalObservationPath(input.SafeFileHandle).Equals(Path.GetFullPath(file), StringComparison.OrdinalIgnoreCase))
                throw new WindowsQualificationCheckException("fixture_observation_reparse_rejected");
            var length = input.Length;
            total = checked(total + length);
            if (length > maximumFileBytes || total > maximumTotalBytes) throw new WindowsQualificationCheckException("fixture_observation_byte_limit_exceeded");
            var bytes = new byte[checked((int)length)];
            input.ReadExactly(bytes);
            // A concurrent append may end between bytes of a record; only full
            // LF-terminated records participate in this snapshot.
            var complete = Array.LastIndexOf(bytes, (byte)'\n') + 1;
            var text = new UTF8Encoding(false, true).GetString(bytes, 0, complete);
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                if (!line.StartsWith("{\"fixture\":\"windows-workload-v1\",", StringComparison.Ordinal))
                    throw new WindowsQualificationCheckException("fixture_observation_prefix_invalid");
                using var document = JsonDocument.Parse(line);
                var value = document.RootElement;
                if (value.GetProperty("pid").GetUInt32() != pid || value.GetProperty("event").ValueKind != JsonValueKind.String)
                    throw new WindowsQualificationCheckException("fixture_observation_identity_invalid");
                result.Add(value.Clone());
            }
        }
        return [.. result];
    }

    private static unsafe string FinalObservationPath(SafeFileHandle handle)
    {
        const int capacity = 32768;
        var buffer = stackalloc char[capacity];
        var length = GetFinalPathNameByHandle(handle, buffer, capacity, 0);
        if (length == 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), "Verify fixture observation file handle failed.");
        if (length >= capacity) throw new WindowsQualificationCheckException("fixture_observation_path_limit_exceeded");
        var path = new string(buffer, 0, checked((int)length));
        return path.StartsWith("\\\\?\\", StringComparison.Ordinal) ? path[4..] : path;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    private static unsafe partial uint GetFinalPathNameByHandle(SafeFileHandle handle, char* path, uint length, uint flags);

    internal async Task<JsonElement> WaitForTerminalEventAsync(string eventName, TimeSpan timeout, Func<JsonElement, bool>? predicate = null)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < timeout)
        {
            Refresh();
            var text = FixtureParsingView(Text());
            var offset = 0;
            while ((offset = text.IndexOf("{\"fixture\":\"windows-workload-v1\"", offset, StringComparison.Ordinal)) >= 0)
            {
                var end = text.IndexOf('}', offset);
                if (end < 0) break;
                try
                {
                    using var parsed = JsonDocument.Parse(text.Substring(offset, end - offset + 1));
                    var value = parsed.RootElement;
                    if (value.GetProperty("event").GetString() == eventName && (predicate is null || predicate(value))) return value.Clone();
                }
                catch (JsonException) { /* A terminal redraw may interrupt an untrusted fixture record. */ }
                offset = end + 1;
            }
            await Task.Delay(10).ConfigureAwait(false);
        }
        throw new WindowsQualificationCheckException("expected_fixture_event_missing");
    }
}

internal sealed record WindowsTerminalGap(long From, long Until);
internal sealed class WindowsTerminalControlObservation
{
    public string InputOperation { get; set; } = "terminal_input_etx";
    public string Mode { get; set; } = "";
    public bool EtxSent { get; set; }
    public string Outcome { get; set; } = "not_observed";
    public int GraceMs { get; set; }
    public bool HandlerObserved { get; set; }
    public bool RawEtxObserved { get; set; }
    public bool ExitObservedWithinGrace { get; set; }
    public bool EscalationRequested { get; set; }
    public uint? FixtureRootPid { get; set; }
    public uint? FixtureChildPid { get; set; }
    public ConPtyJobObservation? BeforeEtxJob { get; set; }
}
internal sealed record WindowsQualificationFailure(string Code, string Type, int HResult, int? NativeErrorCode, string? Operation, Dictionary<string, string>? Details = null, string? CauseType = null);
internal sealed record WindowsPrivateDiagnostic(string File, string Sha256, int Bytes);
internal sealed record WindowsThreadDiagnostic(int Id, string State, string? WaitReason);
internal sealed class WindowsOwnedProcessDiagnostic
{
    public uint ProcessId { get; set; }
    public string? Name { get; set; }
    public bool NoLongerOwned { get; set; }
    public bool ThreadsTruncated { get; set; }
    public List<WindowsThreadDiagnostic> Threads { get; set; } = [];
    public WindowsQualificationFailure? Failure { get; set; }
}
internal sealed class WindowsOwnedDiagnostic
{
    public string Phase { get; set; } = "";
    public string AtUtc { get; set; } = "";
    public uint? ExecutorExit { get; set; }
    public ConPtyJobObservation? Job { get; set; }
    public WindowsQualificationFailure? ExecutorObservationFailure { get; set; }
    public WindowsQualificationFailure? JobObservationFailure { get; set; }
    public bool ProcessesTruncated { get; set; }
    public List<WindowsOwnedProcessDiagnostic> Processes { get; set; } = [];
}
internal sealed class WindowsQualificationCase
{
    public string Name { get; set; } = "";
    public string Protocol { get; set; } = "MXC-WIN-02";
    public bool Passed { get; set; }
    public string PolicySha256 { get; set; } = "";
    public string FixtureObservationSource { get; set; } = "not_enabled";
    public bool SamePolicyProbePassed { get; set; }
    public uint ExecutorProcessId { get; set; }
    public string? ExecutorStartUtc { get; set; }
    public bool InheritedJob { get; set; }
    public uint? RawExecutorExit { get; set; }
    public string ExitSource { get; set; } = "official_executor";
    public string PayloadStartCertainty { get; set; } = "UNKNOWN";
    public string? ExpectedOutcome { get; set; }
    public string? PayloadFixtureSha256 { get; set; }
    public uint? RequestedPolicyTimeoutMs { get; set; }
    public int? FixtureOwnDeadlineMs { get; set; }
    public double? NaturalLifetimeMs { get; set; }
    public WindowsTerminalControlObservation? TerminalControl { get; set; }
    public bool JobEmpty { get; set; }
    public ConPtyJobObservation? FinalJob { get; set; }
    public double SpawnMs { get; set; }
    public double ElapsedMs { get; set; }
    public long ObservedTerminalBytes { get; set; }
    public long CapturedBytes { get; set; }
    public bool CaptureTruncated { get; set; }
    public List<WindowsTerminalGap> ReplayGaps { get; set; } = [];
    public string? DrainFailure { get; set; }
    public bool CleanupCompleted { get; set; }
    public uint? BeforeCleanupExecutorExit { get; set; }
    public ConPtyJobObservation? BeforeCleanupJob { get; set; }
    public WindowsQualificationFailure? BeforeCleanupExecutorObservationFailure { get; set; }
    public WindowsQualificationFailure? BeforeCleanupJobObservationFailure { get; set; }
    public List<WindowsPrivateDiagnostic> PrivateDiagnostics { get; set; } = [];
    public WindowsQualificationFailure? DiagnosticFailure { get; set; }
    public WindowsQualificationFailure? PrimaryFailure { get; set; }
    public WindowsQualificationFailure? CleanupFailure { get; set; }
    public WindowsQualificationFailure? EvidenceFailure { get; set; }
    public string? PrivateTranscriptFile { get; set; }
    public string? PrivateTranscriptSha256 { get; set; }
    internal ConPtySession? UnresolvedCleanupOwner { get; set; }
    public string? FailureCode { get; set; }
    public string? FailureType { get; set; }
    public int FailureHResult { get; set; }
}

internal sealed class WindowsQualificationReport
{
    public string Profile { get; set; } = "windows-process-executor-v1";
    public string ProfileRevision { get; set; } = "win01-06-cases-v1";
    public string RunId { get; set; } = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
    public string SelectionGroup { get; set; } = "full";
    public bool DiagnosticSelection { get; set; }
    public string Status { get; set; } = "partial";
    public bool QualificationPassed { get; set; }
    public bool ExecutedCasesPassed { get; set; }
    public bool CleanupConfirmed { get; set; }
    public bool StageVerified { get; set; }
    public bool FinalIdentityVerified { get; set; }
    public JsonElement? DriverJobContext { get; set; }
    public string? DriverJobContextFile { get; set; }
    public string? DriverJobContextSha256 { get; set; }
    public bool? DriverInheritedJob { get; set; }
    public bool DriverJobContextObserved { get; set; }
    public string DriverJobContextStatus { get; set; } = "not_observed";
    public string SourceCommit { get; set; } = "";
    public string DesignCommit { get; set; } = "";
    public string PlanCommit { get; set; } = "";
    public string ExecutableInformationalVersion { get; set; } = "";
    public string ExecutableSha256 { get; set; } = "";
    public string ManifestSha256 { get; set; } = "";
    public string ArtifactVersion { get; set; } = "";
    public string ArtifactSchema { get; set; } = "";
    public string ArtifactRid { get; set; } = "";
    public string NativeSourceCommit { get; set; } = "";
    public string PackageSha256 { get; set; } = "";
    public string ReleaseSha256 { get; set; } = "";
    public StageMember[] StageFiles { get; set; } = [];
    public Dictionary<string, string> HostFacts { get; set; } = new(StringComparer.Ordinal);
    public string Os { get; set; } = "";
    public string StartedUtc { get; set; } = "";
    public string FinishedUtc { get; set; } = "";
    public string[] IncompleteProtocols { get; set; } = ["MXC-WIN-01", "MXC-WIN-02", "MXC-WIN-03", "MXC-WIN-04", "MXC-WIN-05", "MXC-WIN-06"];
    public int ExpectedCases { get; set; }
    public string[] DuplicateCases { get; set; } = [];
    public string[] UnexpectedCases { get; set; } = [];
    public string[] Limitations { get; set; } = ["Lower-capability-host rejection: NOT_RUN; no designated lower-capability host is available. The deterministic official policy refusals remain required."];
    public List<WindowsQualificationCase> Cases { get; set; } = [];
    public string? FailurePhase { get; set; }
    public string? FailureCode { get; set; }
    public string? FailureType { get; set; }
    public int FailureHResult { get; set; }
    public WindowsQualificationFailure? Failure { get; set; }
    public WindowsQualificationFailure? EvidenceFailure { get; set; }
}

internal sealed record WindowsQualificationPhase(string RunId, string Phase, string Outcome, DateTimeOffset AtUtc, WindowsQualificationFailure? Failure);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(WindowsQualificationReport))]
[JsonSerializable(typeof(WindowsOwnedDiagnostic))]
[JsonSerializable(typeof(WindowsQualificationPhase))]
internal sealed partial class WindowsQualificationJson : JsonSerializerContext;
