// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.MxcProbe.Linux;

// The outer coordinator and restartable Node clients never own the SDK/PTY.
// Each case has its own manager-created service, held cgroup and native owner.
[SupportedOSPlatform("linux")]
internal static class LinuxLifecycleCases
{
    private static readonly LinuxScopeLimits Limits = new(500, 512UL * 1024 * 1024, 128);
    internal static List<LinuxServiceScope> UnresolvedCleanupScopes { get; } = [];

    internal static async Task<(List<LinuxCaseResult> Cases, bool CleanupConfirmed)> RunAsync(string manifest,
        string work, string control, LinuxEvidence log)
    {
        var results = new List<LinuxCaseResult>();
        var cleanup = true;
        foreach (var boundary in new[] { "prepared", "scope_created", "owner_ack", "native_created", "active", "cleaning", "final" })
            await RunCaseAsync("reconnect_" + boundary, "terminal", context => ReconnectAsync(context, boundary)).ConfigureAwait(false);
        await RunCaseAsync("authentication_and_single_writer", "terminal", AuthenticationAsync).ConfigureAwait(false);
        await RunCaseAsync("client_and_center_loss", "terminal", ClientAndCenterLossAsync).ConfigureAwait(false);
        await RunCaseAsync("owner_loss", "terminal", OwnerLossAsync).ConfigureAwait(false);
        await RunCaseAsync("root_exit_descendants", "rootexit", RootExitAsync).ConfigureAwait(false);
        await RunCaseAsync("retained_cleanup", "terminal", RetainedCleanupAsync).ConfigureAwait(false);
        await RunCaseAsync("persistence_write", "persist_write", context => PersistenceAsync(context, write: true), "persistent-data").ConfigureAwait(false);
        await RunCaseAsync("persistence_read", "persist_read", context => PersistenceAsync(context, write: false), "persistent-data").ConfigureAwait(false);
        await RunCaseAsync("combined_default_deny", "combined_deny", context => CombinedAsync(context, selected: false)).ConfigureAwait(false);
        await RunCaseAsync("combined_selected", "combined_selected", context => CombinedAsync(context, selected: true)).ConfigureAwait(false);
        return (results, cleanup);

        async Task RunCaseAsync(string id, string scenario, Func<Context, Task> body, string? dataName = null)
        {
            if (!cleanup)
            {
                results.Add(new LinuxCaseResult("LNX05-" + id, false, new() { ["state"] = "not_run", ["reason"] = "previous_scope_cleanup_unresolved" }));
                return;
            }
            var facts = new Dictionary<string, string>(StringComparer.Ordinal) { ["scenario"] = scenario };
            Context? context = null;
            bool passed = false;
            string phase = "lifecycle_prepare";
            log.Phase(phase, "begin", new() { ["case"] = id });
            try
            {
                context = new Context(manifest, Path.Combine(work, dataName ?? id), Path.Combine(control, id), scenario, log, facts);
                if (scenario == "persist_read")
                {
                    string previous = Path.Combine(context.Data, "observations");
                    Require(File.Exists(Path.Combine(context.Data, "persistent-sentinel.txt")), "persistent_first_run_data_missing");
                    if (Directory.Exists(previous)) Directory.Move(previous, Path.Combine(context.Control, "first-run-observations"));
                }
                phase = "lifecycle_execute";
                await body(context).ConfigureAwait(false);
                passed = true;
            }
            catch (Exception error)
            {
                log.Failure(phase + "_" + id, error);
                facts["failurePhase"] = phase;
                facts["failureType"] = error.GetType().Name;
                if (error is LinuxProbeException probe) facts["failureCode"] = probe.Code;
            }
            finally
            {
                if (context is not null)
                {
                    try
                    {
                        await context.DisposeAsync().ConfigureAwait(false);
                        facts["scopeCleanup"] = "confirmed_empty";
                    }
                    catch (Exception error)
                    {
                        cleanup = false; passed = false;
                        facts["scopeCleanup"] = "unresolved";
                        log.Failure("lifecycle_cleanup_" + id, error, cleanup: true);
                    }
                }
                results.Add(new LinuxCaseResult("LNX05-" + id, passed, facts));
                log.Phase("lifecycle_case", passed ? "passed" : "failed", new() { ["case"] = id });
            }
        }
    }

    private static async Task ReconnectAsync(Context context, string boundary)
    {
        if (boundary is not "prepared") await context.StartServiceAsync(admit: boundary != "scope_created").ConfigureAwait(false);
        await using (var node = await context.StartNodeAsync(boundary, 1, owner: boundary is not ("prepared" or "scope_created")).ConfigureAwait(false))
        {
            var before = node.Ready.Snapshot;
            context.Facts["crashBoundary"] = boundary;
            context.Facts["nodePid"] = Text(node.Process.Id);
            context.Facts["nodeStartTicks"] = Text(node.StartTicks);
            if (before?.NativePid is { } native) context.Facts["nativeBeforeCrash"] = Text(native);
            await node.KillAsync().ConfigureAwait(false);
            if (boundary == "prepared") await context.StartServiceAsync(admit: true).ConfigureAwait(false);
            else if (boundary == "scope_created") await context.AdmitAsync().ConfigureAwait(false);
            await using var replacement = await context.ConnectAsync(2).ConfigureAwait(false);
            var restored = await BindAsync(replacement).ConfigureAwait(false);
            AssertOwner(context, restored.Snapshot);
            if (before?.NativePid is { } original)
                Require(restored.Snapshot.NativePid == original && restored.Snapshot.NativeStartTicks == before.NativeStartTicks,
                    "node_reconnect_changed_native_identity");
            if (restored.Snapshot.State == "prepared") _ = await replacement.RequireAsync("start").ConfigureAwait(false);
            if (restored.Snapshot.State is "prepared" or "starting") _ = await replacement.RequireAsync("activate").ConfigureAwait(false);
            if (boundary is not ("cleaning" or "final"))
            {
                _ = await replacement.RequireAsync("acquire").ConfigureAwait(false);
                _ = await replacement.RequireAsync("resize", 31, 101).ConfigureAwait(false);
                _ = await LinuxTerminalCases.WaitForEventAsync(context.Data, "resize", TimeSpan.FromSeconds(5),
                    item => item.GetProperty("rows").GetInt32() == 31 && item.GetProperty("columns").GetInt32() == 101).ConfigureAwait(false);
                var duplicateStart = await replacement.SendAsync("start").ConfigureAwait(false);
                Require(!duplicateStart.Ok && duplicateStart.Error == "start_already_consumed", "reconnect_reexecuted_start");
                _ = await replacement.RequireAsync("stop").ConfigureAwait(false);
            }
            await FinalizeAsync(context, replacement).ConfigureAwait(false);
            context.Facts["reconnectedSameOwner"] = "true";
        }
    }

    private static async Task AuthenticationAsync(Context context)
    {
        await context.StartServiceAsync().ConfigureAwait(false);
        await using var first = await context.ConnectAsync(1).ConfigureAwait(false);
        _ = await BindAsync(first).ConfigureAwait(false);
        _ = await first.RequireAsync("start").ConfigureAwait(false);
        _ = await first.RequireAsync("activate").ConfigureAwait(false);
        _ = await first.RequireAsync("acquire").ConfigureAwait(false);
        await using (var competing = await context.ConnectAsync(1).ConfigureAwait(false))
        {
            var response = await competing.SendAsync("acquire").ConfigureAwait(false);
            Require(!response.Ok && response.Error == "writer_busy", "second_terminal_writer_admitted");
        }
        var before = (await first.RequireAsync("status").ConfigureAwait(false)).Snapshot;
        await ExpectAuthenticationFailureAsync(context, context.Ready! with { OwnerStartTicks = context.Ready!.OwnerStartTicks + 1 }, context.Setup.ControllerKey).ConfigureAwait(false);
        await ExpectAuthenticationFailureAsync(context, context.Ready! with { OwnerEpoch = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture) }, context.Setup.ControllerKey).ConfigureAwait(false);
        await ExpectAuthenticationFailureAsync(context, context.Ready!, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))).ConfigureAwait(false);
        var after = (await first.RequireAsync("status").ConfigureAwait(false)).Snapshot;
        Require(after.NativePid == before.NativePid && after.NativeStartTicks == before.NativeStartTicks && after.State == "active", "authentication_failure_changed_run");
        _ = await first.RequireAsync("detach").ConfigureAwait(false);
        await using var replacement = await context.ConnectAsync(2).ConfigureAwait(false);
        _ = await BindAsync(replacement).ConfigureAwait(false);
        var stale = await first.SendAsync("stop").ConfigureAwait(false);
        Require(!stale.Ok && stale.Error == "stale_node_generation", "stale_node_mutation_admitted");
        _ = await replacement.RequireAsync("stop").ConfigureAwait(false);
        await FinalizeAsync(context, replacement).ConfigureAwait(false);
        context.Facts["authentication"] = "wrong_key_epoch_creation_identity_refused";
        context.Facts["singleWriter"] = "second_writer_refused_stale_generation_refused";
    }

    private static async Task ExpectAuthenticationFailureAsync(Context context, LinuxLifecycleReady ready, string key)
    {
        bool refused = false;
        try
        {
            await using var invalid = await LinuxOwnerChannel.Client.ConnectAsync(ready, key, 1, NewId()).ConfigureAwait(false);
            _ = await invalid.SendAsync("stop").ConfigureAwait(false);
        }
        catch (Exception error) when (error is LinuxProbeException or IOException or SocketException)
        {
            refused = true;
            context.Log.Phase("lifecycle_auth_negative", "refused", new() { ["type"] = error.GetType().Name });
        }
        Require(refused, "invalid_owner_authentication_accepted");
    }

    private static async Task ClientAndCenterLossAsync(Context context)
    {
        await context.StartServiceAsync().ConfigureAwait(false);
        await using var node = await context.StartNodeAsync("active", 1).ConfigureAwait(false);
        var original = node.Ready.Snapshot!;
        await using (var center = await context.StartNodeAsync("center", 1, observer: true).ConfigureAwait(false))
        {
            await center.KillAsync().ConfigureAwait(false);
            await context.AssertLiveNativeAsync(original).ConfigureAwait(false);
        }
        await node.KillAsync().ConfigureAwait(false);
        await context.AssertLiveNativeAsync(original).ConfigureAwait(false);
        await using var replacement = await context.ConnectAsync(2).ConfigureAwait(false);
        _ = await BindAsync(replacement).ConfigureAwait(false);
        _ = await replacement.RequireAsync("acquire").ConfigureAwait(false);
        _ = await replacement.RequireAsync("resize", 35, 107).ConfigureAwait(false);
        _ = await LinuxTerminalCases.WaitForEventAsync(context.Data, "resize", TimeSpan.FromSeconds(5),
            item => item.GetProperty("columns").GetInt32() == 107).ConfigureAwait(false);
        _ = await replacement.RequireAsync("stop").ConfigureAwait(false);
        await FinalizeAsync(context, replacement).ConfigureAwait(false);
        context.Facts["centerLoss"] = "independent_observer_process_killed_run_survived";
        context.Facts["clientLoss"] = "node_process_killed_same_native_owner_reconnected";
    }

    private static async Task OwnerLossAsync(Context context)
    {
        await context.StartServiceAsync().ConfigureAwait(false);
        await using var client = await context.ConnectAsync(1).ConfigureAwait(false);
        _ = await BindAsync(client).ConfigureAwait(false);
        _ = await client.RequireAsync("start").ConfigureAwait(false);
        var active = (await client.RequireAsync("activate").ConfigureAwait(false)).Snapshot;
        await context.AssertLiveNativeAsync(active).ConfigureAwait(false);
        await context.Scope!.KillMainAsync().ConfigureAwait(false);
        var watch = Stopwatch.StartNew();
        LinuxScopeObservation observed;
        do
        {
            observed = await context.Scope.ObserveAsync().ConfigureAwait(false);
            if (!observed.Cgroup.Populated && observed.Cgroup.ProcessIds.Length == 0) break;
            if (watch.Elapsed > TimeSpan.FromSeconds(15)) throw new LinuxProbeException("owner_loss_did_not_automatically_clean_scope");
            await Task.Delay(25).ConfigureAwait(false);
        } while (true);
        context.Facts["ownerLossCleanupMs"] = watch.Elapsed.TotalMilliseconds.ToString("F3", CultureInfo.InvariantCulture);
        context.Facts["ownerLoss"] = "main_only_killed_manager_cleaned_original_held_scope";
        context.Facts["payloadRawExit"] = "unknown_owner_lost";
        context.Facts["unitExecMainCode"] = Text(observed.ExecMainCode);
        context.Facts["unitExecMainStatus"] = Text(observed.ExecMainStatus);
    }

    private static async Task RootExitAsync(Context context)
    {
        await context.StartServiceAsync().ConfigureAwait(false);
        await using var client = await context.ConnectAsync(1).ConfigureAwait(false);
        _ = await BindAsync(client).ConfigureAwait(false);
        _ = await client.RequireAsync("start").ConfigureAwait(false);
        _ = await client.RequireAsync("activate").ConfigureAwait(false);
        var before = await context.Scope!.ObserveAsync().ConfigureAwait(false);
        Require(before.Cgroup.ProcessIds.Count(pid => pid != context.Scope.Identity.MainPid) >= 2, "background_descendant_not_independently_observed");
        var child = LinuxTerminalCases.ReadEvents(context.Data).Single(item => Event(item, "child-created"));
        context.Facts["fixtureChildNamespacePid"] = Text(child.GetProperty("childPid").GetInt32());
        int namespacePid = child.GetProperty("childPid").GetInt32();
        var matched = new List<int>();
        foreach (int pid in before.Cgroup.ProcessIds)
        {
            try
            {
                string? nspid = File.ReadLines($"/proc/{Text(pid)}/status").FirstOrDefault(line => line.StartsWith("NSpid:", StringComparison.Ordinal));
                if (nspid is null) continue;
                string[] ids = nspid[6..].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (ids.Length > 0 && int.Parse(ids[^1], CultureInfo.InvariantCulture) == namespacePid
                    && LinuxCgroup.ProcessStartTicks(pid) > 0) matched.Add(pid);
            }
            catch (IOException) { }
        }
        Require(matched.Count == 1, "background_child_not_mapped_to_held_scope_namespace_pid");
        context.Facts["backgroundChildHostPid"] = Text(matched[0]);
        context.Facts["backgroundChildStartTicks"] = Text(LinuxCgroup.ProcessStartTicks(matched[0]));
        context.Facts["membersBeforeRootExit"] = Text(before.Cgroup.ProcessIds.Length);
        var natural = await client.RequireAsync("finish_natural").ConfigureAwait(false);
        Require(natural.Snapshot.NativeExit == 0, "root_exit_was_not_natural_exit_zero");
        await FinalizeAsync(context, client).ConfigureAwait(false);
        context.Facts["rootExit"] = "native_root_and_all_descendants_absent_from_held_scope";
    }

    private static async Task RetainedCleanupAsync(Context context)
    {
        await context.StartServiceAsync().ConfigureAwait(false);
        await using var client = await context.ConnectAsync(1).ConfigureAwait(false);
        _ = await BindAsync(client).ConfigureAwait(false);
        _ = await client.RequireAsync("start").ConfigureAwait(false);
        _ = await client.RequireAsync("activate").ConfigureAwait(false);
        var attempted = await client.SendAsync("finalize").ConfigureAwait(false);
        Require(!attempted.Ok && attempted.Error == "cleanup_unresolved" && attempted.Snapshot.State == "recovery_required"
            && !attempted.Snapshot.CleanupConfirmed && !attempted.Snapshot.DataDeletionAllowed, "live_scope_misreported_final");
        var refused = await client.SendAsync("delete_candidate").ConfigureAwait(false);
        Require(!refused.Ok && File.Exists(Path.Combine(context.Data, "deletion-candidate.txt")), "unresolved_cleanup_allowed_delete");
        var live = await context.Scope!.ObserveAsync().ConfigureAwait(false);
        Require(live.Cgroup.ProcessIds.Any(pid => pid != context.Scope.Identity.MainPid), "cleanup_refusal_did_not_have_real_live_members");
        _ = await client.RequireAsync("stop").ConfigureAwait(false);
        await FinalizeAsync(context, client, quit: false).ConfigureAwait(false);
        _ = await client.RequireAsync("delete_candidate").ConfigureAwait(false);
        Require(!File.Exists(Path.Combine(context.Data, "deletion-candidate.txt")), "resolved_cleanup_fixture_delete_failed");
        _ = await client.RequireAsync("quit").ConfigureAwait(false);
        await context.VerifyFinalOwnerReportAsync().ConfigureAwait(false);
        context.Facts["retainedCleanup"] = "actual_live_scope_refused_delete_then_reconciled";
    }

    private static async Task PersistenceAsync(Context context, bool write)
    {
        await context.StartServiceAsync().ConfigureAwait(false);
        await using var client = await context.ConnectAsync(1).ConfigureAwait(false);
        _ = await BindAsync(client).ConfigureAwait(false);
        _ = await client.RequireAsync("start").ConfigureAwait(false);
        _ = await client.RequireAsync("activate").ConfigureAwait(false);
        var result = LinuxTerminalCases.ReadEvents(context.Data).Single(item => Event(item, "persistence"));
        Require(result.GetProperty("operation").GetString() == (write ? "write" : "read") && result.GetProperty("succeeded").GetBoolean(), "persistent_sandbox_fixture_failed");
        var natural = await client.RequireAsync("finish_natural").ConfigureAwait(false);
        Require(natural.Snapshot.NativeExit == 0, "persistence_run_did_not_complete_naturally");
        await FinalizeAsync(context, client).ConfigureAwait(false);
        Require(File.Exists(Path.Combine(context.Data, "persistent-sentinel.txt")), "persistent_sandbox_data_lost");
        context.Facts["persistentSandbox"] = write ? "first_run_wrote_actual_sentinel" : "second_run_read_same_actual_sentinel";
    }

    private static async Task CombinedAsync(Context context, bool selected)
    {
        await context.StartServiceAsync().ConfigureAwait(false);
        await using var node = await context.StartNodeAsync("active", 1).ConfigureAwait(false);
        var original = node.Ready.Snapshot!;
        var throughputWatch = Stopwatch.StartNew();
        _ = await LinuxTerminalCases.WaitForEventAsync(context.Data, "combined-idle-ready", TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        Require(!LinuxTerminalCases.ReadEvents(context.Data).Any(item => Event(item, "combined-work-starting")), "combined_idle_window_already_ended");
        var before = await context.Scope!.ObserveAsync().ConfigureAwait(false);
        var idleWatch = Stopwatch.StartNew();
        using var ownerProcess = Process.GetProcessById(context.Scope.Identity.MainPid);
        Require(LinuxCgroup.ProcessStartTicks(ownerProcess.Id) == context.Scope.Identity.MainStartTicks, "idle_owner_identity_changed");
        long ownerMemory = ownerProcess.WorkingSet64;
        await Task.Delay(1000).ConfigureAwait(false);
        var after = await context.Scope.ObserveAsync().ConfigureAwait(false);
        Require(!LinuxTerminalCases.ReadEvents(context.Data).Any(item => Event(item, "combined-work-starting")), "combined_work_contaminated_idle_measurement");
        context.Facts["idleWindowMs"] = idleWatch.Elapsed.TotalMilliseconds.ToString("F3", CultureInfo.InvariantCulture);
        context.Facts["idleOwnerRssBytes"] = Text(ownerMemory);
        context.Facts["idleAggregateMemoryBytes"] = Text(after.Cgroup.MemoryCurrentBytes);
        context.Facts["idleAggregateCpuMicros"] = Text(after.Cgroup.CpuStat["usage_usec"] - before.Cgroup.CpuStat["usage_usec"]);
        context.Facts["idleNativeMembers"] = Text(after.Cgroup.ProcessIds.Length);
        var memberMemory = new List<string>();
        foreach (int pid in after.Cgroup.ProcessIds)
        {
            ulong birth = LinuxCgroup.ProcessStartTicks(pid);
            using var process = Process.GetProcessById(pid);
            long rss = process.WorkingSet64;
            Require(LinuxCgroup.ProcessStartTicks(pid) == birth, "idle_member_creation_identity_changed");
            memberMemory.Add(Text(pid) + ":" + Text(birth) + ":" + Text(rss));
        }
        context.Facts["idleMemberPidStartTicksRss"] = string.Join(';', memberMemory);

        await node.KillAsync().ConfigureAwait(false);
        await context.AssertLiveNativeAsync(original).ConfigureAwait(false);
        await using var replacement = await context.ConnectAsync(2).ConfigureAwait(false);
        var rebound = await BindAsync(replacement).ConfigureAwait(false);
        Require(rebound.Snapshot.NativePid == original.NativePid && rebound.Snapshot.NativeStartTicks == original.NativeStartTicks,
            "combined_node_restart_replaced_native_owner");
        _ = await replacement.RequireAsync("acquire").ConfigureAwait(false);
        _ = await replacement.RequireAsync("resize", 37, 111).ConfigureAwait(false);
        _ = await LinuxTerminalCases.WaitForEventAsync(context.Data, "resize", TimeSpan.FromSeconds(5),
            item => item.GetProperty("rows").GetInt32() == 37 && item.GetProperty("columns").GetInt32() == 111).ConfigureAwait(false);
        _ = await LinuxTerminalCases.WaitForEventAsync(context.Data, "combined-ready", TimeSpan.FromSeconds(8)).ConfigureAwait(false);
        _ = await LinuxTerminalCases.WaitForEventAsync(context.Data, "load-ready", TimeSpan.FromSeconds(8)).ConfigureAwait(false);
        await VerifyPrivateNamespaceAsync(context).ConfigureAwait(false);
        VerifyCombinedFiles(context.Data);
        var marker = selected ? "network" : "network-observation-failed";
        var network = await LinuxTerminalCases.WaitForEventAsync(context.Data, marker, TimeSpan.FromSeconds(8)).ConfigureAwait(false);
        if (selected) Require(network.GetProperty("replyMatch").GetBoolean(), "combined_selected_reply_mismatch");
        else
        {
            var type = network.GetProperty("errorType").GetString();
            bool allowedRefusal = type == nameof(OperationCanceledException) || type == nameof(TaskCanceledException);
            if (network.TryGetProperty("socketErrorCode", out var code))
                allowedRefusal = (SocketError)code.GetInt32() is SocketError.AccessDenied or SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.TimedOut;
            Require(allowedRefusal, "combined_network_failure_not_a_policy_or_namespace_refusal");
        }
        var status = (await replacement.RequireAsync("status").ConfigureAwait(false)).Snapshot;
        context.Facts["terminalMeasurementWindowMs"] = throughputWatch.Elapsed.TotalMilliseconds.ToString("F3", CultureInfo.InvariantCulture);
        long measuredBytes = status.OutputCursor - original.OutputCursor;
        context.Facts["terminalWindowBytes"] = Text(measuredBytes);
        context.Facts["terminalBytesPerSecond"] = (measuredBytes / throughputWatch.Elapsed.TotalSeconds).ToString("F3", CultureInfo.InvariantCulture);
        Require(selected ? status.PeerTcpDelta == 1 && status.NetworkReplyMatched == true : status.PeerTcpDelta == 0, "combined_external_endpoint_effect_mismatch");
        _ = await replacement.RequireAsync("detach").ConfigureAwait(false);
        long cursor = status.OutputCursor;
        await using (var observer = await context.ConnectAsync(2, observer: true).ConfigureAwait(false))
        {
            var read = await observer.RequireAsync("read", cursor: Math.Max(0, cursor - 256)).ConfigureAwait(false);
            Require(read.Output is { Length: > 0 } && read.Snapshot.NativePid == original.NativePid, "detached_output_not_owned_by_surviving_supervisor");
        }
        _ = await replacement.RequireAsync("acquire").ConfigureAwait(false);
        var updated = await context.Scope.UpdateLimitsAsync(new LinuxScopeLimits(250, Limits.MemoryBytes, Limits.ProcessLimit)).ConfigureAwait(false);
        Require(updated.Cgroup.CpuQuotaMicros == 25_000 && updated.Cgroup.CpuPeriodMicros == 100_000, "combined_dynamic_limit_readback_failed");
        _ = await replacement.RequireAsync("resize", 29, 97).ConfigureAwait(false);
        var stopWatch = Stopwatch.StartNew();
        _ = await replacement.RequireAsync("stop").ConfigureAwait(false);
        await FinalizeAsync(context, replacement).ConfigureAwait(false);
        context.Facts["stopAndCleanupMs"] = stopWatch.Elapsed.TotalMilliseconds.ToString("F3", CultureInfo.InvariantCulture);
        context.Facts["networkMode"] = selected ? "selected_tcp_exact_address_port" : "all_deny";
        context.Facts["nodeRestart"] = "same_authenticated_sdk_and_pty_owner";
        context.Facts["outputBytesObserved"] = Text(status.OutputCursor);
        context.Facts["limitsUpdatedBeforeStop"] = "cpu_500_to_250_millicores_actual_readback";
    }

    private static void VerifyCombinedFiles(string data)
    {
        var effects = LinuxTerminalCases.ReadEvents(data).Where(item => Event(item, "filesystem")).ToArray();
        Require(effects.Length == 10, "combined_filesystem_effects_missing");
        foreach (var item in effects)
        {
            string role = item.GetProperty("role").GetString()!;
            bool expected = role == "writable" || role == "readonly" && item.GetProperty("operation").GetString() == "read";
            Require(item.GetProperty("succeeded").GetBoolean() == expected, "combined_filesystem_boundary_wrong");
            if (!expected) Require(item.GetProperty("errno").GetInt32() is 1 or 2 or 13 or 30, "combined_filesystem_error_not_a_boundary_refusal");
        }
    }

    private static async Task VerifyPrivateNamespaceAsync(Context context)
    {
        var item = LinuxTerminalCases.ReadEvents(context.Data).Single(value => Event(value, "network-namespace"));
        ulong net = item.GetProperty("netInode").GetUInt64(), pidNamespace = item.GetProperty("pidInode").GetUInt64();
        int insidePid = item.GetProperty("pid").GetInt32();
        Require(NamespaceInode(context.Scope!.Identity.MainPid, "net") != net, "combined_payload_shared_owner_network_namespace");
        var observed = await context.Scope.ObserveAsync().ConfigureAwait(false);
        var candidates = new List<int>();
        foreach (int pid in observed.Cgroup.ProcessIds)
        {
            try
            {
                string? line = File.ReadLines($"/proc/{Text(pid)}/status").FirstOrDefault(value => value.StartsWith("NSpid:", StringComparison.Ordinal));
                if (line is null) continue;
                var inside = line[6..].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (inside.Length > 0 && int.Parse(inside[^1], CultureInfo.InvariantCulture) == insidePid
                    && NamespaceInode(pid, "net") == net && NamespaceInode(pid, "pid") == pidNamespace) candidates.Add(pid);
            }
            catch (IOException) { }
        }
        Require(candidates.Count == 1, "combined_namespace_not_independently_mapped_to_scope_member");
        context.Facts["payloadHostPid"] = Text(candidates[0]);
        context.Facts["payloadHostStartTicks"] = Text(LinuxCgroup.ProcessStartTicks(candidates[0]));
        context.Facts["payloadNetworkNamespaceInode"] = Text(net);
    }

    private static ulong NamespaceInode(int pid, string name)
    {
        var target = new FileInfo($"/proc/{Text(pid)}/ns/{name}").LinkTarget ?? throw new LinuxProbeException("lifecycle_namespace_identity_missing");
        Require(target.StartsWith(name + ":[", StringComparison.Ordinal) && target.EndsWith(']') && target.Length < 64, "lifecycle_namespace_identity_invalid");
        return ulong.Parse(target.AsSpan(name.Length + 2, target.Length - name.Length - 3), NumberStyles.None, CultureInfo.InvariantCulture);
    }

    private static async Task<LinuxLifecycleResponse> BindAsync(LinuxOwnerChannel.Client client)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            var response = await client.SendAsync("bind").ConfigureAwait(false);
            if (response.Ok) return response;
            Require(response.Error == "writer_busy", response.Error ?? "node_rebind_failed");
            if (watch.Elapsed > TimeSpan.FromSeconds(3)) throw new LinuxProbeException("old_writer_connection_not_released");
            await Task.Delay(25).ConfigureAwait(false);
        } while (true);
    }

    private static async Task FinalizeAsync(Context context, LinuxOwnerChannel.Client client, bool quit = true)
    {
        var observed = await context.Scope!.ObserveAsync().ConfigureAwait(false);
        Require(!observed.Cgroup.Removed && observed.Cgroup.ProcessIds.SequenceEqual([context.Scope.Identity.MainPid]), "lifecycle_workload_helpers_not_empty");
        var result = await client.RequireAsync("finalize").ConfigureAwait(false);
        Require(result.Snapshot.CleanupConfirmed && result.Snapshot.DataDeletionAllowed && result.Snapshot.NativeProcessAbsent
            && result.Snapshot.StreamsDrained && result.Snapshot.State == "final", "lifecycle_final_without_native_drain");
        AssertOwner(context, result.Snapshot);
        context.Facts["nativeExitSource"] = result.Snapshot.ExitSource;
        context.Facts["nativeSpawnMs"] = result.Snapshot.NativeSpawnMs.ToString("F3", CultureInfo.InvariantCulture);
        context.Facts["nativeExit"] = Text(result.Snapshot.NativeExit ?? int.MinValue);
        context.Facts["payloadAndHelperCleanup"] = "held_cgroup_only_exact_owner_remained";
        if (quit)
        {
            _ = await client.RequireAsync("quit").ConfigureAwait(false);
            await context.VerifyFinalOwnerReportAsync().ConfigureAwait(false);
        }
    }

    private static void AssertOwner(Context context, LinuxLifecycleSnapshot value)
    {
        Require(value.RunId == context.RunId && value.OwnerEpoch == context.Setup.OwnerEpoch && value.OwnerPid == context.Scope!.Identity.MainPid
            && value.OwnerStartTicks == context.Scope.Identity.MainStartTicks && value.BootId == context.Scope.Identity.BootId, "lifecycle_reconnect_owner_identity_changed");
    }

    private sealed class Context : IAsyncDisposable
    {
        internal string RunId { get; } = NewId();
        internal string Data { get; }
        internal string Control { get; }
        internal LinuxLifecycleSetup Setup { get; }
        internal LinuxLifecycleReady? Ready { get; private set; }
        internal LinuxServiceScope? Scope { get; private set; }
        internal LinuxEvidence Log { get; }
        internal Dictionary<string, string> Facts { get; }
        private readonly LinuxOwnerConfiguration _owner;
        private readonly string _manifest;
        private readonly string _configPath;
        private bool _startupCleanupUnresolved;

        internal Context(string manifest, string data, string control, string scenario, LinuxEvidence log, Dictionary<string, string> facts)
        {
            _manifest = manifest; Data = data; Control = control; Log = log; Facts = facts;
            Directory.CreateDirectory(Data, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.CreateDirectory(Control, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            LinuxCgroup.VerifyPrivatePath(Control, true);
            string readonlyDirectory = Path.Combine(Path.GetDirectoryName(Data)!, Path.GetFileName(Control) + "-readonly");
            Directory.CreateDirectory(readonlyDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            string ro = Path.Combine(readonlyDirectory, "readonly.txt");
            string denied = Path.Combine(Control, "control-sentinel.txt");
            string neighbor = Path.Combine(Path.GetDirectoryName(Data)!, Path.GetFileName(Control) + "-neighbor.txt");
            string outside = Path.Combine(Path.GetDirectoryName(Control)!, Path.GetFileName(Control) + "-outside.txt");
            foreach (var path in new[] { ro, denied, neighbor, outside, Path.Combine(Data, "deletion-candidate.txt") })
            {
                if (File.Exists(path) && scenario == "persist_read") continue;
                using var file = new FileStream(path, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.Read, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite });
                file.Write("AFV2_FILE_SENTINEL\n"u8); file.Flush(true);
            }
            Setup = new(RunId, NewId(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), scenario, ro, denied, neighbor, outside);
            LinuxQualification.WriteJson(Path.Combine(Control, "channel-config.json"), Setup, LinuxLifecycleJson.Default.LinuxLifecycleSetup);
            string unit = "arcforges-mxc03-" + RunId + ".service";
            _owner = new(RunId, manifest, Data, Control, Path.Combine(Control, "ready.json"), Path.Combine(Control, "continue"),
                Path.Combine(Control, "owner-report.json"), Path.Combine(Control, "owner-events.jsonl"), unit, "lifecycle_" + scenario,
                checked((long)Limits.MemoryBytes), checked((int)Limits.ProcessLimit), 50_000);
            _configPath = Path.Combine(Control, "owner-config.json");
            LinuxQualification.WriteJson(_configPath, _owner, LinuxQualificationJson.Default.LinuxOwnerConfiguration);
            facts["runId"] = RunId; facts["ownerEpoch"] = Setup.OwnerEpoch; facts["unit"] = unit;
        }

        internal async Task StartServiceAsync(bool admit = true)
        {
            var clock = Stopwatch.StartNew();
            int unresolvedBefore = LinuxServiceScope.UnresolvedStartupScopes.Count;
            try { Scope = await LinuxServiceScope.StartAsync(Path.GetDirectoryName(_manifest)!, _configPath, _owner.UnitName, Limits, Log).ConfigureAwait(false); }
            catch { _startupCleanupUnresolved = LinuxServiceScope.UnresolvedStartupScopes.Count > unresolvedBefore; throw; }
            await LinuxQualification.WaitForFileAsync(_owner.ReadyPath, TimeSpan.FromSeconds(20)).ConfigureAwait(false);
            var ready = LinuxQualification.ReadJson(_owner.ReadyPath, LinuxQualificationJson.Default.LinuxOwnerReady);
            Require(ready.ProcessId == Scope.Identity.MainPid && ready.StartTicks == Text(Scope.Identity.MainStartTicks)
                && ready.BootId == Scope.Identity.BootId && ready.ControlGroup == Scope.Identity.ControlGroup, "lifecycle_service_ready_identity_mismatch");
            Facts["serviceReadyMs"] = clock.Elapsed.TotalMilliseconds.ToString("F3", CultureInfo.InvariantCulture);
            Facts["invocationId"] = Scope.Identity.InvocationId; Facts["ownerStartTicks"] = Text(Scope.Identity.MainStartTicks);
            if (admit) await AdmitAsync().ConfigureAwait(false);
        }

        internal async Task AdmitAsync()
        {
            using (var file = new FileStream(_owner.ContinuePath + ".pending", FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            { file.Write(Encoding.ASCII.GetBytes(RunId)); file.Flush(true); }
            File.Move(_owner.ContinuePath + ".pending", _owner.ContinuePath, overwrite: false);
            await LinuxQualification.WaitForFileAsync(Path.Combine(Control, "channel-ready.json"), TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            Ready = LinuxQualification.ReadJson(Path.Combine(Control, "channel-ready.json"), LinuxLifecycleJson.Default.LinuxLifecycleReady);
            Require(Ready.RunId == RunId && Ready.OwnerEpoch == Setup.OwnerEpoch && Ready.OwnerPid == Scope!.Identity.MainPid
                && Ready.OwnerStartTicks == Scope.Identity.MainStartTicks && Ready.BootId == Scope.Identity.BootId
                && Ready.CgroupInode == Scope.Identity.CgroupInode && Ready.CgroupMountId == Scope.Identity.CgroupMountId,
                "lifecycle_channel_ready_identity_mismatch");
        }

        internal Task<LinuxOwnerChannel.Client> ConnectAsync(long generation, bool observer = false)
            => LinuxOwnerChannel.Client.ConnectAsync(Ready ?? throw new LinuxProbeException("lifecycle_channel_not_ready"),
                observer ? Setup.ObserverKey : Setup.ControllerKey, generation, NewId(), observer);

        internal async Task VerifyFinalOwnerReportAsync()
        {
            await LinuxQualification.WaitForFileAsync(_owner.ReportPath, TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            var report = LinuxQualification.ReadJson(_owner.ReportPath, LinuxQualificationJson.Default.LinuxQualificationReport);
            Require(report.RunId == RunId && report.DiagnosticSlicePassed && report.FailurePhase is null
                && report.Owner is { } owner && owner.ProcessId == Scope!.Identity.MainPid
                && owner.StartTicks == Text(Scope.Identity.MainStartTicks) && owner.BootId == Scope.Identity.BootId,
                "lifecycle_owner_final_report_failed_or_identity_changed");
            Facts["ownerFinalReport"] = "verified_same_run_creation_identity_and_native_owner_cleanup";
        }

        internal async Task<NodeProcess> StartNodeAsync(string boundary, long generation, bool owner = true, bool observer = false)
        {
            string id = NewId();
            string path = Path.Combine(Control, "node-" + id + ".json");
            string ready = Path.Combine(Control, "node-" + id + "-ready.json");
            var configuration = new LinuxLifecycleClientConfiguration(RunId, Setup.OwnerEpoch, observer ? Setup.ObserverKey : Setup.ControllerKey,
                observer, generation, id, owner ? Ready ?? throw new LinuxProbeException("node_owner_channel_not_ready") : null,
                boundary, ready, Path.Combine(Control, "node-" + id + "-events.jsonl"));
            LinuxQualification.WriteJson(path, configuration, LinuxLifecycleJson.Default.LinuxLifecycleClientConfiguration);
            var start = new ProcessStartInfo(Path.Combine(Path.GetDirectoryName(_manifest)!, "arcforges-mxc-probe")) { UseShellExecute = false, WorkingDirectory = Control };
            start.Environment.Clear(); start.Environment["PATH"] = "/usr/bin:/bin"; start.Environment["LANG"] = "C.UTF-8"; start.Environment["LC_ALL"] = "C.UTF-8";
            start.ArgumentList.Add("--linux-node-client"); start.ArgumentList.Add(path);
            var process = Process.Start(start) ?? throw new LinuxProbeException("node_client_not_created");
            var node = new NodeProcess(process, LinuxCgroup.ProcessStartTicks(process.Id), Log);
            try
            {
                await LinuxQualification.WaitForFileAsync(ready, TimeSpan.FromSeconds(35)).ConfigureAwait(false);
                node.Ready = LinuxQualification.ReadJson(ready, LinuxLifecycleJson.Default.LinuxLifecycleClientReady);
                Require(node.Ready.ClientPid == process.Id && node.Ready.ClientStartTicks == node.StartTicks
                    && node.Ready.Boundary == boundary && !process.HasExited, "node_client_ready_identity_mismatch");
                return node;
            }
            catch { await node.DisposeAsync().ConfigureAwait(false); throw; }
        }

        internal async Task AssertLiveNativeAsync(LinuxLifecycleSnapshot original)
        {
            var observed = await Scope!.ObserveAsync().ConfigureAwait(false);
            Require(observed.Identity == Scope.Identity && observed.Cgroup.ProcessIds.Contains(Scope.Identity.MainPid)
                && original.NativePid is { } pid && observed.Cgroup.ProcessIds.Contains(checked((int)pid))
                && original.NativeStartTicks is { } ticks && LinuxCgroup.ProcessStartTicks(checked((int)pid)) == ticks,
                "client_loss_did_not_preserve_native_creation_identity");
        }

        public async ValueTask DisposeAsync()
        {
            if (Scope is null) { Require(!_startupCleanupUnresolved, "lifecycle_startup_scope_cleanup_unresolved"); return; }
            try
            {
                var stopped = await Scope.StopAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
                Require(!stopped.Cgroup.Populated && stopped.Cgroup.ProcessIds.Length == 0, "lifecycle_final_scope_not_empty");
                await Scope.DisposeAsync().ConfigureAwait(false);
            }
            catch { UnresolvedCleanupScopes.Add(Scope); throw; }
        }
    }

    private sealed class NodeProcess(Process process, ulong startTicks, LinuxEvidence log) : IAsyncDisposable
    {
        internal Process Process { get; } = process;
        internal ulong StartTicks { get; } = startTicks;
        internal LinuxLifecycleClientReady Ready { get; set; } = null!;
        internal async Task KillAsync()
        {
            if (Process.HasExited) throw new LinuxProbeException("node_exited_before_crash_injection");
            Require(LinuxCgroup.ProcessStartTicks(Process.Id) == StartTicks, "node_creation_identity_changed");
            log.Phase("node_crash", "before_kill", new() { ["pid"] = Text(Process.Id), ["startTicks"] = Text(StartTicks) });
            Process.Kill();
            await Process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            log.Phase("node_crash", "actual_process_exited", new() { ["exitCode"] = Text(Process.ExitCode) });
        }
        public async ValueTask DisposeAsync()
        {
            try { if (!Process.HasExited) await KillAsync().ConfigureAwait(false); }
            finally { Process.Dispose(); }
        }
    }

    private static bool Event(JsonElement item, string name) => item.GetProperty("event").GetString() == name;
    private static string NewId() => Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
    private static string Text<T>(T value) where T : IFormattable => value.ToString(null, CultureInfo.InvariantCulture);
    private static void Require(bool condition, string code) { if (!condition) throw new LinuxProbeException(code); }
}
