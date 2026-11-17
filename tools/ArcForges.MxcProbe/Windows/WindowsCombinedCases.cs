// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.MxcProbe;

[SupportedOSPlatform("windows")]
internal static class WindowsCombinedCases
{
    private static readonly List<WindowsOwnerHost> UnresolvedGuardians = [];

    internal static async Task<List<WindowsQualificationCase>> RunAsync(string stage, string work)
    {
        var results = new List<WindowsQualificationCase>();
        foreach (var selected in new[] { false, true })
        {
            var result = await RunOneAsync(stage, work, selected).ConfigureAwait(false);
            results.Add(result);
            if (result.CleanupFailure is not null) break;
        }
        return results;
    }

    private static async Task<WindowsQualificationCase> RunOneAsync(string stage, string work, bool selected)
    {
        var name = selected ? "combined-selected-egress" : "combined-default-deny";
        var result = new WindowsQualificationCase { Name = name, Protocol = "MXC-WIN-06", FixtureObservationSource = "bounded_untrusted_fixture_files" };
        var timer = Stopwatch.StartNew();
        var root = Path.Combine(work, name);
        Directory.CreateDirectory(root);
        var owned = new WindowsOwnedPaths(Path.Combine(root, "home"), Path.Combine(root, "config"), Path.Combine(root, "cache"),
            Path.Combine(root, "temp"), Path.Combine(root, "work"), Path.Combine(root, "data"));
        foreach (var directory in new[] { owned.Home, owned.Config, owned.Cache, owned.Temp, owned.Work, owned.Data }) Directory.CreateDirectory(directory);
        var control = Path.Combine(root, "private control");
        var readonlyDirectory = Path.Combine(root, "readonly input");
        var neighbor = Path.Combine(root, "neighbor");
        var outside = Path.Combine(root, "outside");
        foreach (var directory in new[] { readonlyDirectory, neighbor, outside }) Directory.CreateDirectory(directory);
        var writable = Path.Combine(owned.Data, "persistent.txt");
        var readonlyFile = Path.Combine(readonlyDirectory, "input.txt");
        var neighborFile = Path.Combine(neighbor, "neighbor.txt");
        var outsideFile = Path.Combine(outside, "outside.txt");
        const string initial = "AFV2_COMBINED_INITIAL\n";
        foreach (var file in new[] { writable, readonlyFile, neighborFile, outsideFile }) File.WriteAllText(file, initial);
        await using var endpoint = await WindowsNetworkEndpoint.StartControlledTcpAsync().ConfigureAwait(false);
        await endpoint.CalibrateAsync().ConfigureAwait(false);
        var beforeNetwork = endpoint.Observe();
        var request = WindowsPolicy.BuildRequest(Path.Combine(stage, "arcforges-mxc-probe.exe"),
            ["--windows-workload", "combined", "30000", "32", "2", endpoint.Address.ToString(), endpoint.Port.ToString(CultureInfo.InvariantCulture),
                writable, readonlyFile, Path.Combine(control, "request.json"), neighborFile, outsideFile],
            owned, [stage, Environment.SystemDirectory, readonlyDirectory], [control, neighbor],
            selected ? WindowsNetworkCases.SelectedEgress(endpoint) : WindowsNetworkCases.LocalDenyEgress);
        request.Process.Timeout = 45_000; // Overall combined lifetime, separate from its 4s socket attempt.
        var eventsDirectory = WindowsQualification.EnableFixtureEvents(request, owned.Work);
        WindowsOwnerHost? guardian = null;
        ProbeOwnerConfig? config = null;
        ProbeOwnerResponse? first = null;
        ConPtyJobObservation? aggregate = null;
        ConPtyJobObservation? applied = null;
        long ownerWorkingSet = 0;
        double readyMs = 0;
        double stopMs = 0;
        var aclBefore = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var aclAfter = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var idleMemory = new List<WindowsCombinedMemory>();
        double? idleWindowMs = null;
        double? idleAggregateCpuMs = null;
        double? consoleReadyMs = null;
        double? admissionToConsoleReadyMs = null;
        var rebound = false;
        var resized = false;
        var unicodeOutput = false;
        WindowsCombinedPressureOverlap? pressureOverlap = null;
        try
        {
            var admissionWatch = Stopwatch.StartNew();
            var started = await WindowsLifecycleCases.StartOwnerAsync(stage, control, request, beforeLaunch: policy =>
            {
                foreach (var path in new[] { owned.Home, owned.Config, owned.Cache, owned.Temp, owned.Work, owned.Data,
                    readonlyDirectory, neighbor, outside, writable, readonlyFile, neighborFile, outsideFile, control, policy.Path, stage })
                    aclBefore.Add(path, WindowsPolicyCases.AclHash(path));
            }).ConfigureAwait(false);
            config = started.Config;
            guardian = started.Guardian;
            result.PolicySha256 = started.Policy.Sha256;
            result.SamePolicyProbePassed = true;
            first = await WindowsLifecycleCases.AwaitStatusAsync(config, value => value.Ok && value.State == "RUNNING", TimeSpan.FromSeconds(10), result).ConfigureAwait(false);
            Require(first.ExecutorPid.HasValue && first.OwnerPid == guardian.ProcessId, "combined_owner_identity_missing");
            result.ExecutorProcessId = first.ExecutorPid.Value;
            result.ExecutorStartUtc = first.ExecutorCreatedUtc?.ToString("O", CultureInfo.InvariantCulture);
            _ = await WindowsTerminalCapture.WaitForFixtureEventAsync(eventsDirectory, "combined-idle-ready", TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            consoleReadyMs = timer.Elapsed.TotalMilliseconds;
            admissionToConsoleReadyMs = admissionWatch.Elapsed.TotalMilliseconds;
            var idleBefore = guardian.ObserveAggregate();
            Require(!WindowsTerminalCapture.ReadFixtureEvents(eventsDirectory).Any(value => value.GetProperty("event").GetString() == "combined-work-starting"),
                "combined_idle_window_already_finished");
            var idleWatch = Stopwatch.StartNew();
            foreach (var pid in idleBefore.ProcessIds)
            {
                using var process = Process.GetProcessById(checked((int)pid));
                idleMemory.Add(new(pid, process.ProcessName, process.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                    process.WorkingSet64, process.PrivateMemorySize64));
            }
            await Task.Delay(1000).ConfigureAwait(false);
            var idleAfter = guardian.ObserveAggregate();
            idleWindowMs = idleWatch.Elapsed.TotalMilliseconds;
            idleAggregateCpuMs = (idleAfter.UserTimeTicks + idleAfter.KernelTimeTicks - idleBefore.UserTimeTicks - idleBefore.KernelTimeTicks) / 10_000.0;
            Require(!WindowsTerminalCapture.ReadFixtureEvents(eventsDirectory).Any(value => value.GetProperty("event").GetString() == "combined-work-starting")
                && idleAfter.ProcessIds.Contains(guardian.ProcessId) && idleAfter.ProcessIds.Contains(first.ExecutorPid.Value), "combined_idle_window_not_preserved");
            _ = await WindowsTerminalCapture.WaitForFixtureEventAsync(eventsDirectory, "combined-ready", TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            _ = await WindowsTerminalCapture.WaitForFixtureEventAsync(eventsDirectory, "load-ready", TimeSpan.FromSeconds(5), value => value.GetProperty("childrenCreated").GetInt32() == 2).ConfigureAwait(false);
            readyMs = timer.Elapsed.TotalMilliseconds;
            aggregate = guardian.ObserveAggregate();
            Require(aggregate.ActiveProcesses >= 5 && aggregate.ProcessIds.Contains(guardian.ProcessId), "combined_aggregate_descendants_missing");
            using (var process = Process.GetProcessById(first.OwnerPid))
            {
                Require(process.StartTime.ToUniversalTime() == guardian.ProcessStartTimeUtc.UtcDateTime, "combined_owner_identity_changed");
                ownerWorkingSet = process.WorkingSet64;
            }
            var lease = await SendAsync(config, result, "acquire").ConfigureAwait(false);
            Require(lease.Ok && lease.LeaseId is not null, "combined_writer_acquire_failed");
            var size = await WindowsLifecycleCases.SendOwnerAsync(config, result, new() { Operation = "resize", Generation = config.Generation, LeaseId = lease.LeaseId, Sequence = 1, Columns = 120, Rows = 40 }).ConfigureAwait(false);
            Require(size.Ok, "combined_resize_failed");
            _ = await WindowsTerminalCapture.WaitForFixtureEventAsync(eventsDirectory, "resize", TimeSpan.FromSeconds(4), value => value.GetProperty("columns").GetInt32() == 120 && value.GetProperty("rows").GetInt32() == 40).ConfigureAwait(false);
            resized = true;
            var initialRead = await WindowsLifecycleCases.SendOwnerAsync(config, result, new() { Operation = "read", Generation = config.Generation, Cursor = 0 }, observer: true).ConfigureAwait(false);
            Require(initialRead.Ok && initialRead.Replay is not null && initialRead.Replay.DrainFailure is null, "combined_terminal_read_failed");
            unicodeOutput = Encoding.UTF8.GetString(initialRead.Replay.Data).Contains('星');
            Require(unicodeOutput, "combined_unicode_terminal_missing");
            var cursor = initialRead.Replay.NextSequence;
            var detached = await WindowsLifecycleCases.SendOwnerAsync(config, result, new() { Operation = "detach", Generation = config.Generation, LeaseId = lease.LeaseId }).ConfigureAwait(false);
            Require(detached.Ok, "combined_detach_failed");
            _ = await WindowsLifecycleCases.KillAuthenticatedClientAsync(config, control, result).ConfigureAwait(false);
            // The authenticated controller really died while this same workload,
            // pseudoconsole and native resource owner remained alive.
            var reconnect = await SendAsync(config, result, "rebind").ConfigureAwait(false);
            Require(reconnect.Ok && reconnect.Generation == config.Generation + 1 && reconnect.OwnerPid == first.OwnerPid && reconnect.ExecutorPid == first.ExecutorPid
                && reconnect.OwnerCreatedUtc == first.OwnerCreatedUtc && reconnect.ExecutorCreatedUtc == first.ExecutorCreatedUtc,
                "combined_reconnect_changed_identity");
            config = config with { Generation = reconnect.Generation };
            var recovered = await SendAsync(config, result, "status").ConfigureAwait(false);
            Require(recovered.Ok && recovered.Job?.Limits == first.Job?.Limits && recovered.Job is { ActiveProcesses: > 0 },
                "combined_recovered_limits_or_scope_changed");
            rebound = true;
            var replay = await WindowsLifecycleCases.SendOwnerAsync(config, result, new() { Operation = "read", Generation = config.Generation, Cursor = cursor }, observer: true).ConfigureAwait(false);
            Require(replay.Ok && replay.Replay is not null && replay.Replay.DrainFailure is null, "combined_replay_failed");
            result.ObservedTerminalBytes = replay.Replay.AvailableUntil;
            if (replay.Replay.GapFrom is { } from && replay.Replay.GapUntil is { } until) result.ReplayGaps.Add(new(from, until));
            var limits = new ConPtyLimits(2500, 768UL * 1024 * 1024, 12);
            var changed = await WindowsLifecycleCases.SendOwnerAsync(config, result, new() { Operation = "limits", Generation = config.Generation, Limits = limits }).ConfigureAwait(false);
            Require(changed.Ok && changed.Job?.Limits == limits && changed.Job.ActiveProcesses >= 4, "combined_limit_update_not_effective");
            applied = changed.Job;
            foreach (var role in new[] { "readonly", "control-denied", "neighbor", "outside" })
            {
                var observation = await WindowsTerminalCapture.WaitForFixtureEventAsync(eventsDirectory, "filesystem", TimeSpan.FromSeconds(2), value =>
                    value.GetProperty("role").GetString() == role && value.GetProperty("operation").GetString() == "write").ConfigureAwait(false);
                Require(!observation.GetProperty("succeeded").GetBoolean(), "combined_denied_write_succeeded");
            }
            var persisted = await WindowsTerminalCapture.WaitForFixtureEventAsync(eventsDirectory, "filesystem", TimeSpan.FromSeconds(2), value =>
                value.GetProperty("role").GetString() == "writable" && value.GetProperty("operation").GetString() == "write").ConfigureAwait(false);
            Require(persisted.GetProperty("succeeded").GetBoolean(), "combined_owned_write_failed");
            var network = await WindowsTerminalCapture.WaitForFixtureEventAsync(eventsDirectory, selected ? "network" : "network-observation-failed", TimeSpan.FromSeconds(6)).ConfigureAwait(false);
            if (selected) Require(network.GetProperty("replyMatch").GetBoolean(), "combined_network_reply_mismatch");
            else Require(network.TryGetProperty("nativeErrorCode", out var nativeError) && nativeError.GetInt32() == 10013
                || network.GetProperty("errorType").GetString() == "OperationCanceledException" && !network.GetProperty("canceled").GetBoolean(),
                "combined_network_refusal_not_observed");
            pressureOverlap = VerifyPressureOverlap(eventsDirectory, network, aggregate);
            endpoint.RequireHealthy();
            var afterNetwork = endpoint.Observe();
            Require(selected ? afterNetwork.MatchedRequests == beforeNetwork.MatchedRequests + 1 : afterNetwork.AcceptedOrReceived == beforeNetwork.AcceptedOrReceived,
                "combined_external_network_observation_mismatch");
            var stoppedAt = Stopwatch.StartNew();
            var stopped = await SendAsync(config, result, "stop").ConfigureAwait(false);
            Require(stopped.Ok && stopped.CleanupConfirmed && stopped.ExitSource == "official_executor", "combined_stop_not_confirmed");
            var final = await SendAsync(config, result, "status").ConfigureAwait(false);
            Require(final.Job is { ActiveProcesses: 0 } && final.Job.ProcessIds.Length == 0, "combined_inner_scope_not_empty");
            result.FinalJob = final.Job;
            result.RawExecutorExit = stopped.RawExitCode;
            result.JobEmpty = true;
            var shutdown = await SendAsync(config, result, "shutdown").ConfigureAwait(false);
            Require(shutdown.Ok, "combined_owner_shutdown_refused");
            _ = await guardian.WaitEmptyAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            _ = WindowsLifecycleCases.CaptureFinalOwnerEvidence(config, result);
            stopMs = stoppedAt.Elapsed.TotalMilliseconds;
            await guardian.DisposeAsync().ConfigureAwait(false);
            guardian = null;
            result.CleanupCompleted = true;
            Require(File.ReadAllText(writable).Contains("AFV2_FILE_SENTINEL", StringComparison.Ordinal), "combined_persistence_missing");
            foreach (var file in new[] { readonlyFile, neighborFile, outsideFile }) Require(File.ReadAllText(file) == initial, "combined_ungranted_file_changed");
            foreach (var item in aclBefore) aclAfter.Add(item.Key, WindowsPolicyCases.AclHash(item.Key));
            Require(aclBefore.All(item => aclAfter[item.Key] == item.Value), "combined_host_acl_changed");
            result.Passed = result.EvidenceFailure is null;
        }
        catch (Exception exception)
        {
            result.PrimaryFailure = WindowsQualification.ObserveFailure(exception);
            result.FailureCode = exception is WindowsQualificationCheckException check ? check.Code : "combined_native_operation_failed";
            result.FailureType = exception.GetType().Name;
            result.FailureHResult = exception.HResult;
        }
        finally
        {
            if (guardian is not null)
            {
                try
                {
                    await guardian.DisposeAsync().ConfigureAwait(false);
                    result.CleanupCompleted = true;
                }
                catch (Exception exception)
                {
                    UnresolvedGuardians.Add(guardian);
                    result.Passed = false;
                    result.CleanupFailure = WindowsQualification.ObserveFailure(exception) with { Code = "combined_guardian_cleanup_unresolved" };
                }
                if (result.CleanupCompleted && config is not null)
                    _ = WindowsLifecycleCases.CaptureFinalOwnerEvidence(config, result);
            }
        }
        result.ElapsedMs = timer.Elapsed.TotalMilliseconds;
        if (Directory.Exists(control))
        {
            var path = Path.Combine(control, "combined-observation.json");
            using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            using (var writer = new Utf8JsonWriter(stream, new() { Indented = true }))
            {
                writer.WriteStartObject();
                writer.WriteString("scenario", name);
                endpoint.WritePeerIdentity(writer);
                if (admissionToConsoleReadyMs.HasValue) writer.WriteNumber("admissionToConsoleReadyMs", admissionToConsoleReadyMs.Value); else writer.WriteNull("admissionToConsoleReadyMs");
                writer.WriteBoolean("sameOwnerRebound", rebound);
                writer.WriteBoolean("actualResize", resized);
                writer.WriteBoolean("unicodeTerminalOutput", unicodeOutput);
                writer.WriteStartObject("pressureOverlap");
                writer.WriteBoolean("observed", pressureOverlap is not null);
                if (pressureOverlap is not null)
                {
                    writer.WriteNumber("payloadPid", pressureOverlap.PayloadPid);
                    writer.WriteNumber("loadReadyIndex", pressureOverlap.LoadReadyIndex);
                    writer.WriteNumber("pressureReleasedIndex", pressureOverlap.PressureReleasedIndex);
                    writer.WriteNumber("networkAttemptIndex", pressureOverlap.NetworkAttemptIndex);
                    writer.WriteNumber("networkResultIndex", pressureOverlap.NetworkResultIndex);
                    writer.WriteNumber("filesystemEffects", pressureOverlap.FilesystemEffects);
                    writer.WriteString("basis", "same_fixture_process_order_with_payload_in_native_job_and_no_load_completion_at_observation");
                }
                writer.WriteEndObject();
                if (consoleReadyMs.HasValue) writer.WriteNumber("setupToConsoleReadyMs", consoleReadyMs.Value); else writer.WriteNull("setupToConsoleReadyMs");
                if (idleWindowMs.HasValue) writer.WriteNumber("idleWindowMs", idleWindowMs.Value); else writer.WriteNull("idleWindowMs");
                if (idleAggregateCpuMs.HasValue) writer.WriteNumber("idleAggregateCpuMs", idleAggregateCpuMs.Value); else writer.WriteNull("idleAggregateCpuMs");
                writer.WriteStartArray("idleOwnedProcessMemory");
                foreach (var sample in idleMemory)
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("pid", sample.Pid);
                    writer.WriteString("imageName", sample.ImageName);
                    writer.WriteString("createdUtc", sample.CreatedUtc);
                    writer.WriteNumber("residentBytes", sample.ResidentBytes);
                    writer.WriteNumber("privateBytes", sample.PrivateBytes);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
                writer.WriteStartArray("ownedAclComparisons");
                var objectIndex = 0;
                foreach (var item in aclBefore)
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("objectIndex", objectIndex++);
                    writer.WriteString("beforeSha256", item.Value);
                    if (aclAfter.TryGetValue(item.Key, out var after)) writer.WriteString("afterSha256", after); else writer.WriteNull("afterSha256");
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
                writer.WriteNumber("readyMs", readyMs);
                writer.WriteNumber("stopAndCleanupMs", stopMs);
                if (ownerWorkingSet == 0) writer.WriteNull("ownerResidentBytes"); else writer.WriteNumber("ownerResidentBytes", ownerWorkingSet);
                writer.WriteString("startupObservation", selected ? "subsequent same-host process startup; no OS cache claim" : "first combined process startup; no OS cache flush");
                if (aggregate is null) writer.WriteNull("aggregateProcessesAtReady"); else writer.WriteNumber("aggregateProcessesAtReady", aggregate.ActiveProcesses);
                if (aggregate is null) writer.WriteNull("aggregatePeakCommitBytesAtReady"); else writer.WriteNumber("aggregatePeakCommitBytesAtReady", aggregate.PeakMemoryBytes);
                if (applied is null) writer.WriteNull("updatedCpuRate"); else writer.WriteNumber("updatedCpuRate", applied.Limits.CpuRate);
                if (applied is null) writer.WriteNull("updatedMemoryBytes"); else writer.WriteNumber("updatedMemoryBytes", applied.Limits.MemoryBytes);
                if (applied is null) writer.WriteNull("updatedProcessLimit"); else writer.WriteNumber("updatedProcessLimit", applied.Limits.ProcessLimit);
                writer.WriteEndObject();
            }
            var bytes = File.ReadAllBytes(path);
            result.PrivateDiagnostics.Add(new(Path.GetFileName(path), Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length));
        }
        result.Passed &= result.EvidenceFailure is null;
        return result;
    }

    private sealed record WindowsCombinedMemory(uint Pid, string ImageName, string CreatedUtc, long ResidentBytes, long PrivateBytes);

    private sealed record WindowsCombinedPressureOverlap(uint PayloadPid, int LoadReadyIndex, int PressureReleasedIndex,
        int NetworkAttemptIndex, int NetworkResultIndex, int FilesystemEffects);

    private static WindowsCombinedPressureOverlap VerifyPressureOverlap(string eventsDirectory, JsonElement network, ConPtyJobObservation aggregate)
    {
        // Bounded fixture records establish workload ordering only. Native Job
        // membership and external endpoint counters establish the boundary.
        uint rootPid = network.GetProperty("pid").GetUInt32();
        Require(aggregate.ProcessIds.Contains(rootPid), "combined_pressure_payload_not_in_native_job");
        var events = WindowsTerminalCapture.ReadFixtureEvents(eventsDirectory)
            .Where(item => item.GetProperty("pid").GetUInt32() == rootPid).ToArray();
        int ready = Array.FindIndex(events, item => Event(item, "load-ready"));
        int release = Array.FindIndex(events, item => Event(item, "combined-pressure-ready"));
        int attempt = Array.FindIndex(events, item => Event(item, "network-attempt"));
        int completed = Array.FindIndex(events, item => Event(item, "network") || Event(item, "network-observation-failed"));
        var filesystem = events.Select((item, index) => (Item: item, Index: index))
            .Where(value => Event(value.Item, "filesystem")).ToArray();
        Require(ready >= 0 && release > ready && attempt > release && completed > attempt,
            "combined_network_did_not_run_after_pressure_ready");
        Require(events[ready].GetProperty("memoryBytesTouched").GetInt32() == 32 * 1024 * 1024
            && events[ready].GetProperty("childrenCreated").GetInt32() == 2, "combined_pressure_setup_incomplete");
        Require(filesystem.Length == 10 && filesystem.All(value => value.Index > release),
            "combined_filesystem_did_not_run_after_pressure_ready");
        Require(!events.Any(item => Event(item, "load-finished") || Event(item, "load-observation-failed")),
            "combined_pressure_ended_before_effect_observation");
        return new(rootPid, ready, release, attempt, completed, filesystem.Length);
    }

    private static bool Event(JsonElement item, string name) => item.GetProperty("event").GetString() == name;

    private static Task<ProbeOwnerResponse> SendAsync(ProbeOwnerConfig config, WindowsQualificationCase result, string operation) =>
        WindowsLifecycleCases.SendOwnerAsync(config, result, new() { Operation = operation, Generation = config.Generation });

    private static void Require([DoesNotReturnIf(false)] bool value, string code)
    {
        if (!value) throw new WindowsQualificationCheckException(code);
    }
}
