// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe.Linux;

[SupportedOSPlatform("linux")]
internal static partial class LinuxTerminalCases
{
    internal static LinuxSdkSession? UnresolvedCleanupOwner { get; private set; }

    internal static async Task<List<LinuxCaseResult>> RunAsync(string executable, string sandboxData, string control, LinuxEvidence log)
    {
        var cases = new List<LinuxCaseResult>();
        async Task<bool> Add(string id, IReadOnlyList<string> args, bool terminal,
            Func<LinuxSdkSession, string, Dictionary<string, string>, Task>? exercise = null,
            int? expectedExit = 0, int timeoutMs = 15000, bool timedOut = false, int replayBytes = 262144, string? selectedExecutable = null)
        {
            cases.Add(await RunCaseAsync(id, executable, sandboxData, control, log, args, terminal, exercise,
                expectedExit, timeoutMs, timedOut, replayBytes, selectedExecutable).ConfigureAwait(false));
            return UnresolvedCleanupOwner is null;
        }

        if (!await Add("lnx02_pty_info", ["terminal-info"], true, async (_, data, facts) =>
        {
            var info = await WaitForEventAsync(data, "terminal", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            Require(info.GetProperty("stdinTty").GetBoolean() && info.GetProperty("stdoutTty").GetBoolean()
                && info.GetProperty("stderrTty").GetBoolean() && info.GetProperty("termiosOk").GetBoolean()
                && info.GetProperty("windowOk").GetBoolean(), "pty_native_terminal_required");
            Require(info.GetProperty("rows").GetInt32() == 24 && info.GetProperty("columns").GetInt32() == 80, "pty_initial_size_mismatch");
            facts["namespacePgrp"] = info.GetProperty("pgrp").GetInt32().ToString(CultureInfo.InvariantCulture);
            facts["namespaceForegroundPgrp"] = info.GetProperty("foregroundPgrp").GetInt32().ToString(CultureInfo.InvariantCulture);
            facts["foregroundAuthority"] = "dedicated_host_namespace_snapshot_required";
            facts["terminalObservation"] = "native_isatty_termios_window";
        }).ConfigureAwait(false)) return cases;
        // Avoid repeating a prerequisite failure through every terminal case.
        if (!cases[^1].Passed) return cases;

        if (!await Add("lnx02_pipe_comparison", ["terminal-info"], false, async (_, data, _) =>
        {
            var info = await WaitForEventAsync(data, "terminal", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            Require(!info.GetProperty("stdinTty").GetBoolean() && !info.GetProperty("stdoutTty").GetBoolean()
                && !info.GetProperty("stderrTty").GetBoolean(), "pipe_mode_misrepresented_as_terminal");
        }, expectedExit: 77).ConfigureAwait(false)) return cases;

        if (!await Add("lnx02_canonical_edit", ["terminal", "canonical", "10000"], true, async (session, data, ignoredFacts) =>
        {
            var info = await WaitForEventAsync(data, "terminal", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            _ = await WaitForEventAsync(data, "terminal-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            var erase = checked((byte)info.GetProperty("eraseByte").GetInt32());
            byte[] input = [.. "ab"u8.ToArray(), erase, .. "星\n"u8.ToArray()];
            await session.WriteInputAsync(input, TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            var line = await WaitForEventAsync(data, "line", TimeSpan.FromSeconds(5), item => !item.GetProperty("eof").GetBoolean()).ConfigureAwait(false);
            Require(line.GetProperty("length").GetInt32() == 2 && line.GetProperty("sha256").GetString() == Hash("a星"u8), "canonical_line_edit_mismatch");
            session.CloseInput();
            _ = await WaitForEventAsync(data, "eof", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }).ConfigureAwait(false)) return cases;

        if (!await Add("lnx02_raw_unicode_resize", ["terminal", "raw", "10000"], true, async (session, data, facts) =>
        {
            _ = await WaitForEventAsync(data, "terminal-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            foreach (var size in new[] { (12, 40), (50, 160), (24, 80) })
            {
                session.Resize(size.Item1, size.Item2);
                _ = await WaitForEventAsync(data, "resize", TimeSpan.FromSeconds(3), item => item.GetProperty("rows").GetInt32() == size.Item1
                    && item.GetProperty("columns").GetInt32() == size.Item2).ConfigureAwait(false);
            }
            foreach (var invalid in new[] { (0, 80), (24, 0), (32768, 80), (24, 32768) })
            {
                var rejected = false;
                try { session.Resize(invalid.Item1, invalid.Item2); }
                catch (ArgumentOutOfRangeException) { rejected = true; }
                Require(rejected, "invalid_pty_size_not_rejected");
            }
            await session.WriteInputAsync("星q"u8.ToArray(), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            var input = await WaitForEventAsync(data, "raw-input", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            Require(input.GetProperty("bytes").GetInt32() == 3 && input.GetProperty("sha256").GetString() == Hash("星"u8), "raw_unicode_input_mismatch");
            var exit = await session.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            var output = Encoding.UTF8.GetString(session.ReadOutput(0).Data);
            Require(exit.ExitCode == 0 && output.Contains('星') && output.Contains("\u001b[?1049h", StringComparison.Ordinal), "unicode_alternate_screen_missing");
            facts["resizesObserved"] = "3";
            facts["invalidSizesRejected"] = "4";
        }).ConfigureAwait(false)) return cases;

        if (!await Add("lnx02_canonical_eof", ["terminal", "canonical", "10000"], true, async (session, data, ignoredFacts) =>
        {
            _ = await WaitForEventAsync(data, "terminal-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            session.CloseInput();
            _ = await WaitForEventAsync(data, "eof", TimeSpan.FromSeconds(5), item => item.GetProperty("mode").GetString() == "canonical").ConfigureAwait(false);
        }).ConfigureAwait(false)) return cases;

        if (!await Add("lnx02_raw_eot_close", ["terminal", "raw", "10000"], true, async (session, data, facts) =>
        {
            _ = await WaitForEventAsync(data, "terminal-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            await session.WriteInputAsync(new byte[] { 4 }, TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            _ = await WaitForEventAsync(data, "key", TimeSpan.FromSeconds(3), item => item.GetProperty("code").GetInt32() == 4).ConfigureAwait(false);
            facts["rawEotMeaning"] = "input_byte_not_eof";
            session.CloseInput();
            try
            {
                _ = await session.WaitAsync(TimeSpan.FromMilliseconds(250)).ConfigureAwait(false);
                facts["rawCloseOutcome"] = "native_exit";
            }
            catch (TimeoutException)
            {
                facts["rawCloseOutcome"] = "raw_protocol_requires_explicit_stop";
                _ = await session.StopAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            }
        }, expectedExit: null).ConfigureAwait(false)) return cases;

        var foregroundCommand = LinuxRequestFactory.Command(executable, ["--linux-workload", "terminal", "cooperative", "10000"]);
        if (!await Add("lnx02_foreground_sigint", ["--noprofile", "--norc", "-i", "-c", foregroundCommand], true, async (session, data, facts) =>
        {
            var ready = await WaitForEventAsync(data, "terminal-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            var child = await WaitForEventAsync(data, "child-created", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            var group = LinuxCgroup.ProcessControlGroup(Environment.ProcessId);
            log.Phase("foreground_scope_open", "begin");
            using var scope = LinuxCgroup.Open(group);
            var before = ObserveTerminalMembers(scope, log, "foreground_before_etx");
            var payload = NamespaceMember(before, ready.GetProperty("pid").GetInt32());
            var foregroundChild = NamespaceMember(before, child.GetProperty("childPid").GetInt32());
            var backend = before.SingleOrDefault(member => member.HostPid == session.ProcessId)
                ?? throw new LinuxProbeException("foreground_sdk_root_not_live");
            Require(payload.TtyNumber != 0 && payload.ForegroundGroup > 0 && payload.ProcessGroup == payload.ForegroundGroup
                && foregroundChild.TtyNumber == payload.TtyNumber && foregroundChild.ProcessGroup == payload.ForegroundGroup
                && foregroundChild.ForegroundGroup == payload.ForegroundGroup, "foreground_job_not_established_in_host_namespace");
            Require(backend.ProcessGroup != payload.ForegroundGroup, "foreground_job_still_targets_bwrap_group");
            facts["foregroundSetup"] = "contained_interactive_bash_job_control";
            facts["payloadHostPid"] = payload.HostPid.ToString(CultureInfo.InvariantCulture);
            facts["childHostPid"] = foregroundChild.HostPid.ToString(CultureInfo.InvariantCulture);
            facts["hostForegroundGroup"] = payload.ForegroundGroup.ToString(CultureInfo.InvariantCulture);
            await session.WriteInputAsync(new byte[] { 3 }, TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            var signal = WaitForEventAsync(data, "signal", TimeSpan.FromSeconds(5), item => item.GetProperty("signal").GetString() == "SIGINT");
            while (!signal.IsCompleted && !session.LifetimeCompleted) await Task.Delay(5).ConfigureAwait(false);
            _ = ObserveTerminalMembers(scope, log, "foreground_after_etx");
            _ = await signal.ConfigureAwait(false);
            var completed = await session.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            Require(completed.ExitCode == 0 && !completed.TimedOut, "foreground_sigint_did_not_complete_cooperatively");
            var drained = ObserveTerminalMembers(scope, log, "foreground_after_native_drain");
            Require(!drained.Any(member => member.HostPid == payload.HostPid || member.HostPid == foregroundChild.HostPid
                || member.HostPid == session.ProcessId), "foreground_native_members_remain_after_drain");
        }, selectedExecutable: "/bin/bash").ConfigureAwait(false)) return cases;

        if (!await Add("lnx02_ignore_etx_stop", ["terminal", "ignore-etx", "10000"], true, async (session, data, facts) =>
        {
            _ = await WaitForEventAsync(data, "terminal-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            await session.WriteInputAsync(new byte[] { 3 }, TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            _ = await WaitForEventAsync(data, "key", TimeSpan.FromSeconds(3), item => item.GetProperty("etx").GetBoolean()
                && item.GetProperty("ignored").GetBoolean()).ConfigureAwait(false);
            using var client = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            var cancelled = false;
            try { _ = await session.WaitAsync(TimeSpan.FromSeconds(1), client.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { cancelled = true; }
            Require(cancelled, "ignored_etx_terminated_owner");
            var stopped = await session.StopAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            facts["forcedStopRawExit"] = stopped.ExitCode.ToString(CultureInfo.InvariantCulture);
        }, expectedExit: null).ConfigureAwait(false)) return cases;

        if (!await Add("lnx02_detached_flood", ["flood", "2097152"], true, async (session, data, facts) =>
        {
            var identity = session.ProcessId;
            // No replay client reads during the entire flood. Native drains
            // continue, with bounded retention and an explicit old-cursor gap.
            var done = await WaitForEventAsync(data, "flood-finished", TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            var exit = await session.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            var replay = session.ReadOutput(0);
            Require(done.GetProperty("bytesWritten").GetInt32() == 2097152 && exit.StdoutBytes >= 2097152,
                "large_terminal_output_incomplete");
            Require(identity == session.ProcessId && replay.GapFrom == 0 && replay.GapUntil == replay.AvailableFrom
                && replay.AvailableFrom > 0 && replay.Data.Length == 1024 && replay.FailureCode is null, "detach_replay_gap_missing");
            var end = session.ReadOutput(replay.NextSequence);
            Require(end.Data.Length == 0 && end.EndOfStream, "reattach_final_cursor_mismatch");
            facts["replayGapUntil"] = replay.AvailableFrom.ToString(CultureInfo.InvariantCulture);
        }, replayBytes: 1024).ConfigureAwait(false)) return cases;

        if (!await Add("lnx02_client_wait_cancel", ["terminal", "raw", "10000"], true, async (session, data, facts) =>
        {
            _ = await WaitForEventAsync(data, "terminal-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            using var client = new CancellationTokenSource();
            client.Cancel();
            var cancelled = false;
            try { _ = await session.WaitAsync(TimeSpan.FromSeconds(1), client.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { cancelled = true; }
            Require(cancelled, "client_wait_not_cancelled");
            var identity = session.ProcessId;
            await session.WriteInputAsync("q"u8.ToArray(), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            Require((await session.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false)).ExitCode == 0 && session.ProcessId == identity,
                "client_cancel_changed_run_lifetime");
            facts["clientCancellation"] = "observer_only_owner_retained";
        }).ConfigureAwait(false)) return cases;

        string[] vectors = ["", "space separated", "single'quote", "double\"quote", "trailing\\", "星 Ω 😀", "$(touch should-not-exist)", ";touch should-not-exist", "$HOME"];
        if (!await Add("lnx02_posix_argv", ["argv", .. vectors], false, async (_, data, _) =>
        {
            for (var index = 0; index < vectors.Length; index++)
            {
                var expected = index;
                var item = await WaitForEventAsync(data, "argv", TimeSpan.FromSeconds(5), value => value.GetProperty("index").GetInt32() == expected).ConfigureAwait(false);
                Require(item.GetProperty("sha256").GetString() == Hash(Encoding.UTF8.GetBytes(vectors[index])), "posix_argument_value_changed");
            }
            Require(!File.Exists(Path.Combine(data, "should-not-exist")), "posix_metacharacter_was_executed");
        }).ConfigureAwait(false)) return cases;

        if (!await Add("lnx02_shell_editing", ["--noprofile", "--norc", "-i"], true, async (session, _, _) =>
        {
            Require(File.Exists("/bin/bash"), "interactive_shell_unavailable");
            await session.WriteInputAsync(Encoding.UTF8.GetBytes("printf 'AFV2-SHELL-EDIT-OX\u007fK\\n'\nexit 0\n"), TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            _ = await session.WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            Require(Encoding.UTF8.GetString(session.ReadOutput(0).Data).Replace("\r", "", StringComparison.Ordinal)
                .Contains("AFV2-SHELL-EDIT-OK\n", StringComparison.Ordinal), "interactive_shell_editing_missing");
        }, selectedExecutable: "/bin/bash").ConfigureAwait(false)) return cases;

        foreach (var code in new[] { 0, 1, 23 })
            if (!await Add("lnx02_exit_" + code.ToString(CultureInfo.InvariantCulture), ["exit", code.ToString(CultureInfo.InvariantCulture)], true,
                expectedExit: code).ConfigureAwait(false)) return cases;
        if (!await Add("lnx02_fake_output", ["fake-errors", "23"], true, expectedExit: 23).ConfigureAwait(false)) return cases;
        _ = await Add("lnx02_policy_timeout", ["terminal", "raw", "10000"], true, expectedExit: null, timeoutMs: 1000, timedOut: true).ConfigureAwait(false);
        return cases;
    }

    private static async Task<LinuxCaseResult> RunCaseAsync(string id, string executable, string sandboxData, string control, LinuxEvidence log,
        IReadOnlyList<string> args, bool terminal, Func<LinuxSdkSession, string, Dictionary<string, string>, Task>? exercise,
        int? expectedExit, int timeoutMs, bool expectedTimeout, int replayBytes, string? selectedExecutable)
    {
        var facts = new Dictionary<string, string>(StringComparer.Ordinal) { ["protocol"] = "MXC-LNX-02", ["fixtureSource"] = "untrusted_payload_files", ["mode"] = terminal ? "pty" : "pipes" };
        var passed = false;
        LinuxSdkSession? session = null;
        log.Phase(id, "begin");
        try
        {
            var data = Path.Combine(sandboxData, id);
            var privateControl = Path.Combine(control, id);
            Require(!Directory.Exists(data) && !Directory.Exists(privateControl), "terminal_case_requires_fresh_directories");
            Directory.CreateDirectory(data, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.CreateDirectory(privateControl, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var request = LinuxRequestFactory.Create(selectedExecutable ?? executable,
                selectedExecutable is null ? ["--linux-workload", .. args] : args, data, privateControl, timeoutMs);
            session = LinuxSdkSession.Start(request, terminal, log, id, replayBytes: replayBytes);
            facts["sdkProcessId"] = session.ProcessId.ToString(CultureInfo.InvariantCulture);
            if (exercise is not null) await exercise(session, data, facts).ConfigureAwait(false);
            var exit = await session.WaitAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
            facts["exitSource"] = exit.ExitSource;
            facts["rawExitCode"] = exit.ExitCode.ToString(CultureInfo.InvariantCulture);
            facts["timedOut"] = exit.TimedOut.ToString();
            facts["stdoutBytes"] = exit.StdoutBytes.ToString(CultureInfo.InvariantCulture);
            facts["stderrBytes"] = exit.StderrBytes.ToString(CultureInfo.InvariantCulture);
            facts["sdkRootAbsent"] = exit.NativeProcessAbsent.ToString();
            facts["cgroupEmptyAuthority"] = "external_scope_observer_required";
            Require(exit.Drained && exit.NativeProcessAbsent && exit.TimedOut == expectedTimeout
                && (!expectedExit.HasValue || exit.ExitCode == expectedExit.Value), "terminal_native_exit_or_drain_mismatch");
            passed = true;
        }
        catch (Exception error)
        {
            log.Failure(id, error);
            facts["failureCode"] = error is LinuxProbeException probe ? probe.Code : "terminal_operation_failed";
            if (error is LinuxSdkLaunchException launch) UnresolvedCleanupOwner = launch.CleanupOwner;
        }
        finally
        {
            if (session is not null)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); facts["sdkDisposed"] = "true"; }
                catch (Exception error) { log.Failure(id, error, cleanup: true); UnresolvedCleanupOwner = session; facts["cleanupFailure"] = "sdk_owner_retained"; passed = false; }
            }
        }
        log.Phase(id, passed ? "passed" : "failed", facts);
        return new(id, passed, facts);
    }

    private static LinuxTerminalMember NamespaceMember(IReadOnlyList<LinuxTerminalMember> members, int namespacePid)
    {
        var matches = members.Where(member => member.NamespacePids.Length > 1 && member.NamespacePids[^1] == namespacePid).ToArray();
        Require(matches.Length == 1, "foreground_namespace_pid_not_uniquely_mapped");
        return matches[0];
    }

    private static List<LinuxTerminalMember> ObserveTerminalMembers(LinuxCgroup scope, LinuxEvidence log, string phase)
    {
        log.Phase(phase, "begin");
        try
        {
            var observed = scope.Read();
            Require(!observed.Removed && observed.ProcessIds.Length <= 64, "foreground_scope_identity_or_member_bound");
            var members = new List<LinuxTerminalMember>();
            foreach (var pid in observed.ProcessIds)
            {
                try
                {
                    var processGroup = LinuxCgroup.ProcessControlGroup(pid);
                    if (processGroup != scope.ControlGroup && !processGroup.StartsWith(scope.ControlGroup + "/", StringComparison.Ordinal)) continue;
                    var stat = File.ReadAllText("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/stat");
                    Require(stat.Length <= 8192, "foreground_proc_stat_bound");
                    var closing = stat.LastIndexOf(')');
                    Require(closing > 0 && closing + 2 < stat.Length, "foreground_proc_stat_invalid");
                    var fields = stat[(closing + 2)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    Require(fields.Length >= 20, "foreground_proc_stat_fields_missing");
                    var start = ulong.Parse(fields[19], CultureInfo.InvariantCulture);
                    var line = File.ReadLines("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/status")
                        .Take(128).FirstOrDefault(value => value.StartsWith("NSpid:", StringComparison.Ordinal));
                    Require(line is { Length: <= 1024 }, "foreground_namespace_pid_mapping_missing");
                    var mapped = line![6..].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)
                        .Select(value => int.Parse(value, CultureInfo.InvariantCulture)).ToArray();
                    Require(mapped.Length is > 0 and <= 16 && mapped[0] == pid, "foreground_namespace_pid_mapping_invalid");
                    // These are observation identities, never PID-only signal
                    // authority. Recheck after both proc reads to reject reuse.
                    if (LinuxCgroup.ProcessStartTicks(pid) != start || LinuxCgroup.ProcessControlGroup(pid) != processGroup) continue;
                    var member = new LinuxTerminalMember(pid, start,
                        int.Parse(fields[2], CultureInfo.InvariantCulture), int.Parse(fields[3], CultureInfo.InvariantCulture),
                        long.Parse(fields[4], CultureInfo.InvariantCulture), int.Parse(fields[5], CultureInfo.InvariantCulture), mapped);
                    members.Add(member);
                    log.Phase(phase + "_member", "observed", new()
                    {
                        ["hostPid"] = pid.ToString(CultureInfo.InvariantCulture),
                        ["startTicks"] = start.ToString(CultureInfo.InvariantCulture),
                        ["processGroup"] = member.ProcessGroup.ToString(CultureInfo.InvariantCulture),
                        ["session"] = member.Session.ToString(CultureInfo.InvariantCulture),
                        ["ttyNumber"] = member.TtyNumber.ToString(CultureInfo.InvariantCulture),
                        ["foregroundGroup"] = member.ForegroundGroup.ToString(CultureInfo.InvariantCulture),
                        ["namespacePids"] = string.Join(',', mapped.Select(value => value.ToString(CultureInfo.InvariantCulture))),
                        ["scopeInode"] = observed.Inode.ToString(CultureInfo.InvariantCulture),
                        ["scopeMountId"] = observed.MountId.ToString(CultureInfo.InvariantCulture)
                    });
                }
                catch (Exception error) when (error is FileNotFoundException or DirectoryNotFoundException)
                {
                    log.Phase(phase + "_member", "departed_during_observation", new() { ["hostPid"] = pid.ToString(CultureInfo.InvariantCulture) });
                }
            }
            return members;
        }
        catch (Exception error) { log.Failure(phase, error); throw; }
    }

    private sealed record LinuxTerminalMember(int HostPid, ulong StartTicks, int ProcessGroup, int Session,
        long TtyNumber, int ForegroundGroup, int[] NamespacePids);

    internal static async Task<JsonElement> WaitForEventAsync(string sandboxData, string eventName, TimeSpan timeout, Func<JsonElement, bool>? predicate = null)
    {
        if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(1)) throw new ArgumentOutOfRangeException(nameof(timeout));
        var clock = Stopwatch.StartNew();
        while (clock.Elapsed < timeout)
        {
            foreach (var value in ReadEventsCore(sandboxData, allowEmpty: true))
                if (value.GetProperty("event").GetString() == eventName && (predicate is null || predicate(value))) return value;
            await Task.Delay(20).ConfigureAwait(false);
        }
        throw new LinuxProbeException("fixture_event_timeout");
    }

    internal static JsonElement[] ReadEvents(string sandboxData) => ReadEventsCore(sandboxData, allowEmpty: false);

    private static JsonElement[] ReadEventsCore(string sandboxData, bool allowEmpty)
    {
        // Open the exact directory and every child with NOFOLLOW. The payload
        // can write these observations, but must not redirect this host reader
        // into an unrelated host file. Never log raw file contents.
        var descriptor = Open(Path.Combine(sandboxData, "observations"), 0x80000 | 0x20000 | 0x10000);
        if (descriptor < 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), "Open fixture observations failed.");
        using var directory = new SafeFileHandle(descriptor, ownsHandle: true);
        var names = Directory.EnumerateFiles("/proc/self/fd/" + descriptor.ToString(CultureInfo.InvariantCulture), "*.jsonl").Select(Path.GetFileName).Take(10).ToArray();
        Require(names.Length <= 9, "fixture_observation_file_bound");
        Require(allowEmpty || names.Length > 0, "fixture_observation_files_missing");
        var values = new List<JsonElement>();
        foreach (var name in names)
        {
            Require(name is not null && uint.TryParse(Path.GetFileNameWithoutExtension(name), NumberStyles.None, CultureInfo.InvariantCulture, out _), "fixture_observation_name_invalid");
            var fd = OpenAt(descriptor, name!, 0x80000 | 0x20000 | 0x800);
            if (fd < 0) throw new Win32Exception(Marshal.GetLastPInvokeError(), "Open fixture observation failed.");
            using var handle = new SafeFileHandle(fd, ownsHandle: true);
            using var stream = new FileStream(handle, FileAccess.Read);
            Require(stream.Length <= 65536, "fixture_observation_byte_bound");
            var bytes = new byte[(int)stream.Length];
            stream.ReadExactly(bytes);
            var text = Encoding.UTF8.GetString(bytes);
            var complete = text.LastIndexOf('\n');
            if (complete < 0) continue;
            foreach (var line in text[..complete].Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                using var document = JsonDocument.Parse(line, new() { MaxDepth = 8 });
                Require(document.RootElement.GetProperty("fixture").GetString() == "linux-workload-v1", "fixture_observation_schema_invalid");
                values.Add(document.RootElement.Clone());
            }
        }
        return values.ToArray();
    }

    private static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static void Require(bool condition, string code) { if (!condition) throw new LinuxProbeException(code); }
    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)] private static partial int Open(string path, int flags);
    [LibraryImport("libc", EntryPoint = "openat", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)] private static partial int OpenAt(int directory, string path, int flags);
}
