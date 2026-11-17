// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.MxcProbe;

internal static class WindowsQualification
{
    internal static async Task<int> RunAsync(string[] args)
    {
        var report = new WindowsQualificationReport { StartedUtc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture), Os = Environment.OSVersion.VersionString };
        string? reportPath = null;
        try
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Native Windows is required.");
            if (args.Length != 6 || args[0] != "--manifest" || args[2] != "--work" || args[4] != "--report")
                throw new ArgumentException("Expected --manifest, --work and --report.");
            var manifest = Path.GetFullPath(args[1]);
            var stage = Path.GetDirectoryName(manifest)!;
            var work = Path.GetFullPath(args[3]);
            var requestedReport = Path.GetFullPath(args[5]);
            Check(!Within(work, stage) && !Within(requestedReport, stage), "evidence_outside_stage_required");
            Check(!Directory.Exists(work) && !File.Exists(work), "fresh_workspace_required");
            Check(!File.Exists(requestedReport) && !Directory.Exists(requestedReport), "fresh_report_required");
            reportPath = requestedReport;
            Program.ValidateStage(manifest);
            report.StageVerified = true;
            Directory.CreateDirectory(work);
            report.Cases = await RunTerminalCasesAsync(stage, work).ConfigureAwait(false);
            report.ExecutedCasesPassed = report.Cases.Count > 0 && report.Cases.All(x => x.Passed);
        }
        catch (Exception exception)
        {
            report.FailureCode = FailureCode(exception);
            report.FailureType = exception.GetType().Name;
            report.FailureHResult = exception.HResult;
            report.Failure = ObserveFailure(exception);
        }

        // This terminal slice alone cannot qualify the six-protocol combination.
        report.FinishedUtc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        var json = JsonSerializer.Serialize(report, WindowsQualificationJson.Default.WindowsQualificationReport);
        if (reportPath is not null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
            await using var output = new FileStream(reportPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            await output.WriteAsync(Encoding.UTF8.GetBytes(json)).ConfigureAwait(false);
        }
        Console.WriteLine(json);
        return report.ExecutedCasesPassed ? 2 : 1;
    }

    [SupportedOSPlatform("windows")]
    internal static async Task<List<WindowsQualificationCase>> RunTerminalCasesAsync(string stage, string work)
    {
        var results = new List<WindowsQualificationCase>();
        var smoke = await RunCaseAsync("console-info", stage, work, ["console-info"], async (_, capture) =>
        {
            var console = capture.WaitForEventAsync("console", TimeSpan.FromSeconds(10));
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
            await session.WriteInputAsync("ab\b星\r"u8.ToArray(), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
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

        results.Add(await RunCaseAsync("detached-flood", stage, work, ["flood", "2097152"], async (session, capture) =>
        {
            // The session's native drain keeps running without a replay reader.
            var identity = session.ProcessId;
            await Task.Delay(250).ConfigureAwait(false);
            var end = await capture.WaitForEventAsync("flood-finished", TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            Check(end.GetProperty("bytesWritten").GetInt32() == 2 * 1024 * 1024 && capture.ObservedBytes >= 2 * 1024 * 1024, "flood_incomplete");
            Check(identity == session.ProcessId, "terminal_identity_changed");
        }).ConfigureAwait(false));

        foreach (var code in new[] { 0, 1, 23 })
            results.Add(await RunCaseAsync("exit-" + code.ToString(CultureInfo.InvariantCulture), stage, work, ["exit", code.ToString(CultureInfo.InvariantCulture)], expectedExecutorExit: (uint)code).ConfigureAwait(false));
        results.Add(await RunCaseAsync("fake-error-output", stage, work, ["fake-errors", "23"], async (_, capture) =>
        {
            await capture.WaitForTextAsync("synthetic_backend_failure", TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            await capture.WaitForTextAsync("\"exit_source\":\"payload\"", TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        }, expectedExecutorExit: 23).ConfigureAwait(false));

        foreach (var mode in new[] { "cooperative", "raw", "ignore-etx" })
            results.Add(await RunCaseAsync("etx-" + mode, stage, work, ["console", mode, "15000"], async (session, capture) =>
            {
                _ = await capture.WaitForEventAsync("console-ready", TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                await session.SendEtxAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
                if (mode == "cooperative")
                {
                    _ = await capture.WaitForEventAsync("ctrl", TimeSpan.FromSeconds(3)).ConfigureAwait(false);
                }
                else
                {
                    var key = await capture.WaitForEventAsync("key", TimeSpan.FromSeconds(3), x => x.GetProperty("etx").GetBoolean()).ConfigureAwait(false);
                    Check(key.GetProperty("ignored").GetBoolean() == (mode == "ignore-etx"), "etx_mode_mismatch");
                    Check(session.GetExecutorExitCode() is null, "etx_was_not_only_terminal_input");
                    _ = await session.ForceStopAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
                }
            }, expectedExecutorExit: mode == "cooperative" ? 0U : null).ConfigureAwait(false));
        return results;
    }

    [SupportedOSPlatform("windows")]
    internal static Task<WindowsQualificationCase> RunCaseAsync(string name, string stage, string work, IReadOnlyList<string> workloadArgs,
        Func<ConPtySession, WindowsTerminalCapture, Task>? exercise = null, uint? expectedExecutorExit = 0, ConPtyLimits? limits = null)
    {
        var root = Path.Combine(work, name);
        Directory.CreateDirectory(root);
        var fixture = Path.Combine(root, "workspace 工作区");
        var owned = new WindowsOwnedPaths(Path.Combine(fixture, "home"), Path.Combine(fixture, "config"), Path.Combine(fixture, "cache"),
            Path.Combine(fixture, "temp"), Path.Combine(fixture, "work"), Path.Combine(fixture, "data"));
        foreach (var directory in new[] { owned.Home, owned.Config, owned.Cache, owned.Temp, owned.Work, owned.Data }) Directory.CreateDirectory(directory);
        var control = Path.Combine(root, "private control");
        var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"), ["--windows-workload", .. workloadArgs], owned,
            [stage, Environment.GetFolderPath(Environment.SpecialFolder.System)], [control], WindowsNetworkChoice.DenyAll);
        var policy = WindowsPolicy.WritePrivate(control, request);
        return RunCaseAsync(name, stage, policy, exercise, expectedExecutorExit, limits);
    }

    [SupportedOSPlatform("windows")]
    internal static async Task<WindowsQualificationCase> RunCaseAsync(string name, string stage, WindowsPolicyArtifact policy,
        Func<ConPtySession, WindowsTerminalCapture, Task>? exercise = null, uint? expectedExecutorExit = 0, ConPtyLimits? limits = null)
    {
        var result = new WindowsQualificationCase { Name = name, PolicySha256 = policy.Sha256 };
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
                limits ?? new(5000, 1024UL * 1024 * 1024, 16), PrivateDiagnostics: name == "console-info"));
            result.ExecutorProcessId = session.ProcessId;
            result.ExecutorStartUtc = session.ProcessStartTimeUtc.ToString("O", CultureInfo.InvariantCulture);
            result.InheritedJob = session.InheritedJob;
            result.SpawnMs = session.SpawnMs;
            capture = new WindowsTerminalCapture(session, policy.ControlDirectory);
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
    private static void Check(bool condition, string code) { if (!condition) throw new WindowsQualificationCheckException(code); }
    private static string FailureCode(Exception exception) => exception is WindowsQualificationCheckException check ? check.Code : "native_operation_failed";
    internal static WindowsQualificationFailure ObserveFailure(Exception exception)
    {
        var native = exception as Win32Exception;
        var message = native?.Message;
        // ConPtySession's native helper uses fixed operation strings ending in
        // " failed.". Arbitrary exception/request/OS messages are not exported.
        var operation = message is { Length: <= 160 } && message.EndsWith(" failed.", StringComparison.Ordinal)
            && message.All(x => char.IsAsciiLetterOrDigit(x) || x is ' ' or '.' or '-' or '(' or ')') ? message : null;
        return new(FailureCode(exception), exception.GetType().Name, exception.HResult, native?.NativeErrorCode, operation);
    }
}

internal sealed class WindowsQualificationCheckException(string code) : Exception
{
    internal string Code { get; } = code;
}

[SupportedOSPlatform("windows")]
internal sealed class WindowsTerminalCapture(ConPtySession session, string? privateControlDirectory = null) : IDisposable
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
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < timeout)
        {
            Refresh();
            var text = Text();
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
internal sealed record WindowsQualificationFailure(string Code, string Type, int HResult, int? NativeErrorCode, string? Operation);
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
    public bool SamePolicyProbePassed { get; set; }
    public uint ExecutorProcessId { get; set; }
    public string? ExecutorStartUtc { get; set; }
    public bool InheritedJob { get; set; }
    public uint? RawExecutorExit { get; set; }
    public string ExitSource { get; set; } = "official_executor";
    public string PayloadStartCertainty { get; set; } = "UNKNOWN";
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
    public string Status { get; set; } = "partial";
    public bool QualificationPassed { get; set; }
    public bool ExecutedCasesPassed { get; set; }
    public bool StageVerified { get; set; }
    public string Os { get; set; } = "";
    public string StartedUtc { get; set; } = "";
    public string FinishedUtc { get; set; } = "";
    public string[] IncompleteProtocols { get; set; } = ["MXC-WIN-01", "MXC-WIN-02", "MXC-WIN-03", "MXC-WIN-04", "MXC-WIN-05", "MXC-WIN-06"];
    public List<WindowsQualificationCase> Cases { get; set; } = [];
    public string? FailureCode { get; set; }
    public string? FailureType { get; set; }
    public int FailureHResult { get; set; }
    public WindowsQualificationFailure? Failure { get; set; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[JsonSerializable(typeof(WindowsQualificationReport))]
[JsonSerializable(typeof(WindowsOwnedDiagnostic))]
internal sealed partial class WindowsQualificationJson : JsonSerializerContext;
