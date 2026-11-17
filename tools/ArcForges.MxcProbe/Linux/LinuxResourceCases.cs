// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.MxcProbe.Linux;

// The coordinator stays outside each bounded service. No process is moved into
// a cgroup after creation; the existing service owner admits the SDK only after
// the independent ready/identity/resource readback handshake.
[SupportedOSPlatform("linux")]
internal static class LinuxResourceCases
{
    private const ulong MiB = 1024 * 1024;
    private static readonly LinuxScopeLimits Ordinary = new(500, 512 * MiB, 128);
    internal static List<LinuxServiceScope> UnresolvedCleanupScopes { get; } = [];

    internal static async Task<(List<LinuxCaseResult> Cases, bool CleanupConfirmed)> RunAsync(string manifest, string work, string control, LinuxEvidence log)
    {
        var cases = new List<LinuxCaseResult>();
        var cleanup = true;
        ResourceSpec[] specifications =
        [
            new("resource_cpu_low", new(250, 512 * MiB, 128)),
            new("resource_cpu_control", new(1000, 512 * MiB, 128)),
            new("resource_burst", Ordinary),
            new("resource_dynamic", new(1000, 512 * MiB, 128)),
            new("resource_pids_limit", new(500, 512 * MiB, 32)),
            new("resource_memory", new(500, 96 * MiB, 128)),
            new("resource_lower_refusal", Ordinary),
            new("resource_creation_refusal", Ordinary),
            new("resource_readback_refusal", Ordinary),
        ];
        foreach (var specification in specifications)
        {
            var result = await RunOneAsync(manifest, work, control, specification, log).ConfigureAwait(false);
            cases.Add(result.Result);
            cleanup &= result.Cleanup;
            if (!result.Cleanup || !result.Result.Passed) break;
        }
        if (cases.Count >= 2 && cases[0].Passed && cases[1].Passed)
        {
            var low = Number(cases[0].Facts, "cpuUsecDelta") / Number(cases[0].Facts, "windowMs");
            var high = Number(cases[1].Facts, "cpuUsecDelta") / Number(cases[1].Facts, "windowMs");
            var compared = high > low * 1.5;
            cases.Add(new("resource_cpu_comparison", compared, new(StringComparer.Ordinal)
            {
                ["lowCpuUsecPerMs"] = low.ToString("R", CultureInfo.InvariantCulture),
                ["controlCpuUsecPerMs"] = high.ToString("R", CultureInfo.InvariantCulture),
                ["basis"] = "independent_service_cpu_stat_same_fixed_busy_fixture",
            }));
        }
        return (cases, cleanup);
    }

    internal static async Task<List<LinuxCaseResult>> RunOwnerAsync(LinuxOwnerConfiguration config, LinuxEvidence log)
    {
        var facts = new Dictionary<string, string>(StringComparer.Ordinal) { ["networkMode"] = "default_deny", ["terminal"] = "true" };
        LinuxSdkSession? session = null;
        var passed = false;
        try
        {
            string[] arguments = config.Group switch
            {
                "resource_cpu_low" or "resource_cpu_control" => ["load", "6000", "0", "0"],
                "resource_burst" => ["load", "6000", "8", "4"],
                "resource_dynamic" => ["load", "8000", "8", "2"],
                "resource_pids_limit" => ["load", "6000", "0", "8"],
                "resource_memory" => ["commit", "256", "1000"],
                _ => throw new LinuxProbeException("resource_owner_group_invalid")
            };
            var request = LinuxRequestFactory.Create(Environment.ProcessPath!, ["--linux-workload", .. arguments], config.Work, config.Control, 15_000);
            log.Phase("resource_sdk", "starting", new(StringComparer.Ordinal) { ["group"] = config.Group });
            session = LinuxSdkSession.Start(request, true, log, "resource_sdk");
            LinuxQualification.WriteJson(Path.Combine(config.Control, "resource-sdk.json"),
                new ResourceLive(config.RunId, session.ProcessId, 0, []), LinuxResourceJson.Default.ResourceLive);
            if (config.Group is "resource_cpu_low" or "resource_cpu_control" or "resource_burst" or "resource_dynamic")
            {
                int children = config.Group == "resource_burst" ? 4 : config.Group == "resource_dynamic" ? 2 : 0;
                var ready = await LinuxTerminalCases.WaitForEventAsync(config.Work, "load-ready", TimeSpan.FromSeconds(8),
                    item => item.GetProperty("childrenCreated").GetInt32() == children).ConfigureAwait(false);
                var namespacePid = ready.GetProperty("pid").GetInt32();
                var childPids = new List<int>();
                while (childPids.Count < children)
                {
                    var child = await LinuxTerminalCases.WaitForEventAsync(config.Work, "child-created", TimeSpan.FromSeconds(3),
                        item => item.GetProperty("pid").GetInt32() == namespacePid && !childPids.Contains(item.GetProperty("childPid").GetInt32())).ConfigureAwait(false);
                    childPids.Add(child.GetProperty("childPid").GetInt32());
                }
                LinuxQualification.WriteJson(Path.Combine(config.Control, "resource-live.json"),
                    new ResourceLive(config.RunId, session.ProcessId, namespacePid, [.. childPids]), LinuxResourceJson.Default.ResourceLive);
                log.Phase("resource_payload_observation", "ready", new(StringComparer.Ordinal) { ["children"] = children.ToString(CultureInfo.InvariantCulture) });
            }
            var exit = await session.WaitAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
            facts["sdkExitCode"] = exit.ExitCode.ToString(CultureInfo.InvariantCulture);
            facts["sdkExitSource"] = exit.ExitSource;
            facts["sdkTimedOut"] = exit.TimedOut.ToString(CultureInfo.InvariantCulture);
            facts["sdkNativeProcessAbsent"] = exit.NativeProcessAbsent.ToString(CultureInfo.InvariantCulture);
            Require(exit.ExitSource == "official_sdk" && exit.Drained && exit.NativeProcessAbsent && !exit.TimedOut, "resource_sdk_native_wait_incomplete");
            if (config.Group is not ("resource_memory" or "resource_pids_limit")) Require(exit.ExitCode == 0, "resource_control_payload_failed");
            // Enforcement is decided by the external cgroup observer, never by
            // this payload's writable event file or its exit code alone.
            passed = true;
        }
        catch (Exception exception)
        {
            log.Failure("resource_owner", exception);
            facts["failureType"] = exception.GetType().Name;
            if (exception is LinuxProbeException probe) facts["failureCode"] = probe.Code;
            if (exception is LinuxSdkLaunchException launch) session = launch.CleanupOwner;
        }
        finally
        {
            if (session is not null)
            {
                try { await session.DisposeAsync().ConfigureAwait(false); }
                catch (Exception exception) { passed = false; log.Failure("resource_owner_cleanup", exception, true); }
            }
        }
        return [new(config.Group, passed, facts)];
    }

    private static async Task<(LinuxCaseResult Result, bool Cleanup)> RunOneAsync(string manifest, string work, string control, ResourceSpec spec, LinuxEvidence log)
    {
        var runId = Guid.NewGuid().ToString("N", CultureInfo.InvariantCulture);
        var data = PrivateDirectory(Path.Combine(work, spec.Group));
        var privateControl = PrivateDirectory(Path.Combine(control, spec.Group));
        var unit = "arcforges-mxc03-" + runId + ".service";
        var config = new LinuxOwnerConfiguration(runId, manifest, data, privateControl,
            Path.Combine(privateControl, "ready.json"), Path.Combine(privateControl, "continue"),
            Path.Combine(privateControl, "owner-report.json"), Path.Combine(privateControl, "owner-events.jsonl"),
            unit, spec.Group is "resource_lower_refusal" or "resource_creation_refusal" or "resource_readback_refusal" ? "resource_cpu_low" : spec.Group,
            checked((long)spec.Limits.MemoryBytes), checked((int)spec.Limits.ProcessLimit), checked((int)(spec.Limits.CpuMillicores * 100)));
        var configPath = Path.Combine(privateControl, "owner-config.json");
        LinuxQualification.WriteJson(configPath, config, LinuxQualificationJson.Default.LinuxOwnerConfiguration);
        var facts = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["unit"] = unit,
            ["runId"] = runId,
            ["networkMode"] = "default_deny",
            ["coordinatorOutsideService"] = "true",
        };
        LinuxServiceScope? scope = null;
        var passed = false;
        var cleanup = true;
        int unresolvedBefore = LinuxServiceScope.UnresolvedStartupScopes.Count;
        try
        {
            log.Phase(spec.Group, "service_create", new(StringComparer.Ordinal) { ["unit"] = unit });
            scope = await LinuxServiceScope.StartAsync(Path.GetDirectoryName(manifest)!, configPath, unit, spec.Limits, log).ConfigureAwait(false);
            await LinuxQualification.WaitForFileAsync(config.ReadyPath, TimeSpan.FromSeconds(30)).ConfigureAwait(false);
            var ready = LinuxQualification.ReadJson(config.ReadyPath, LinuxQualificationJson.Default.LinuxOwnerReady);
            Require(ready.ProcessId == scope.Identity.MainPid && ready.BootId == scope.Identity.BootId
                && ready.StartTicks == scope.Identity.MainStartTicks.ToString(CultureInfo.InvariantCulture)
                && ready.ControlGroup == scope.Identity.ControlGroup, "resource_service_owner_identity_mismatch");
            var initial = await ObserveAsync(scope, log, spec.Group + "_initial").ConfigureAwait(false);
            RequireLimits(initial, spec.Limits);
            facts["invocationId"] = scope.Identity.InvocationId;
            facts["cgroupInode"] = scope.Identity.CgroupInode.ToString(CultureInfo.InvariantCulture);
            facts["cgroupMountId"] = scope.Identity.CgroupMountId.ToString(CultureInfo.InvariantCulture);
            if (spec.Group == "resource_lower_refusal")
            {
                Require(initial.Cgroup.PidsCurrent > 1, "resource_lower_refusal_usage_not_observed");
                bool refused = false;
                try { _ = await scope.UpdateLimitsAsync(spec.Limits with { ProcessLimit = 1 }).ConfigureAwait(false); }
                catch (LinuxProbeException exception) when (exception.Code == "resource_update_below_current_usage")
                { refused = true; log.Phase(spec.Group, "expected_unsafe_decrease_refused"); }
                Require(refused, "resource_unsafe_decrease_not_refused");
                RequireLimits(await ObserveAsync(scope, log, spec.Group + "_after_refusal").ConfigureAwait(false), spec.Limits);
                Require(!File.Exists(config.ContinuePath) && !File.Exists(Path.Combine(privateControl, "resource-sdk.json")), "resource_refusal_permitted_payload");
                facts["payloadAdmission"] = "not_permitted";
                passed = true;
            }
            else if (spec.Group == "resource_creation_refusal")
            {
                bool refused = false;
                try
                {
                    var unexpected = await LinuxServiceScope.StartAsync(Path.GetDirectoryName(manifest)!, configPath, unit, spec.Limits, log).ConfigureAwait(false);
                    UnresolvedCleanupScopes.Add(unexpected);
                    throw new LinuxProbeException("resource_duplicate_service_was_created");
                }
                catch (LinuxProbeException exception) when (exception.Code == "service_unit_already_exists")
                { refused = true; log.Phase(spec.Group, "expected_existing_unit_refused"); }
                var after = await ObserveAsync(scope, log, spec.Group + "_preserved_owner").ConfigureAwait(false);
                Require(refused && after.Identity == initial.Identity && after.Cgroup.ProcessIds.Contains(ready.ProcessId)
                    && !File.Exists(config.ContinuePath), "resource_existing_owner_not_preserved");
                facts["payloadAdmission"] = "not_permitted";
                passed = true;
            }
            else
            {
                if (spec.Group == "resource_readback_refusal")
                    _ = await scope.UpdateLimitsAsync(spec.Limits with { CpuMillicores = 250 }).ConfigureAwait(false);
                Permit(config);
                if (spec.Group is "resource_cpu_low" or "resource_cpu_control" or "resource_burst" or "resource_dynamic")
                {
                    var livePath = Path.Combine(privateControl, "resource-live.json");
                    await LinuxQualification.WaitForFileAsync(livePath, TimeSpan.FromSeconds(12)).ConfigureAwait(false);
                    var live = LinuxQualification.ReadJson(livePath, LinuxResourceJson.Default.ResourceLive);
                    Require(live.RunId == runId, "resource_live_identity_mismatch");
                    var active = await ObserveAsync(scope, log, spec.Group + "_active").ConfigureAwait(false);
                    Require(active.Cgroup.ProcessIds.Contains(checked((int)live.NativePid)), "resource_native_pid_not_in_service");
                    if (spec.Group is "resource_cpu_low" or "resource_cpu_control")
                        await CpuWindowAsync(scope, log, spec.Group, facts).ConfigureAwait(false);
                    if (spec.Group is "resource_burst" or "resource_dynamic")
                        VerifyMembers(live, active, privateControl, log, spec.Group);
                    if (spec.Group == "resource_dynamic")
                    {
                        var target = new LinuxScopeLimits(250, 256 * MiB, 64);
                        log.Phase(spec.Group, "update_requested");
                        var updated = await scope.UpdateLimitsAsync(target).ConfigureAwait(false);
                        RequireLimits(updated, target);
                        Require(updated.Cgroup.Populated && updated.Cgroup.ProcessIds.Contains(checked((int)live.NativePid)), "resource_update_lost_live_group");
                        await CpuWindowAsync(scope, log, spec.Group, facts).ConfigureAwait(false);
                        facts["liveUpdateReadback"] = "verified";
                    }
                }
                var completion = await MonitorCompletionAsync(scope, config, log, spec.Group).ConfigureAwait(false);
                if (spec.Group == "resource_memory")
                {
                    Require(completion.MemoryOomKill > Required(initial.Cgroup.MemoryEvents, "oom_kill") || completion.Last.Result == "oom-kill", "resource_memory_oom_enforcement_not_observed");
                    facts["enforcementAuthority"] = completion.Last.Result == "oom-kill" ? "systemd_native_oom_result" : "cgroup_memory_events_oom_kill";
                }
                else if (spec.Group == "resource_pids_limit")
                {
                    Require(completion.PidsMaxEvents > Required(initial.Cgroup.PidsEvents, "max"), "resource_pids_enforcement_not_observed");
                    facts["enforcementAuthority"] = "cgroup_pids_events_max";
                }
                else
                {
                    Require(File.Exists(config.ReportPath), "resource_owner_report_missing");
                    var owner = LinuxQualification.ReadJson(config.ReportPath, LinuxQualificationJson.Default.LinuxQualificationReport);
                    Require(owner.RunId == runId && owner.Owner == ready, "resource_owner_report_identity_mismatch");
                    if (spec.Group == "resource_readback_refusal")
                    {
                        Require(!owner.DiagnosticSlicePassed && owner.Cases.Count == 0 && owner.FailurePhase == "owner_wait_for_admission"
                            && !File.Exists(Path.Combine(privateControl, "resource-sdk.json")) && OwnerReadbackRefusal(config.LogPath), "resource_changed_scope_did_not_refuse_before_sdk");
                        facts["payloadAdmission"] = "readback_refused_before_sdk";
                    }
                    else Require(owner.DiagnosticSlicePassed, "resource_owner_cases_failed");
                }
                facts["observedOomKill"] = completion.MemoryOomKill.ToString(CultureInfo.InvariantCulture);
                facts["observedPidsMaxEvents"] = completion.PidsMaxEvents.ToString(CultureInfo.InvariantCulture);
                facts["lastCounterAvailable"] = completion.Last.Cgroup.CountersAvailable.ToString(CultureInfo.InvariantCulture);
                passed = true;
            }
        }
        catch (Exception exception)
        {
            log.Failure(spec.Group, exception);
            facts["failureType"] = exception.GetType().Name;
            if (exception is LinuxProbeException probe) facts["failureCode"] = probe.Code;
        }
        finally
        {
            if (scope is not null)
            {
                try
                {
                    var stopped = await scope.StopAsync(TimeSpan.FromSeconds(20)).ConfigureAwait(false);
                    Require(!stopped.Cgroup.Populated && stopped.Cgroup.ProcessIds.Length == 0, "resource_cleanup_not_empty");
                    facts["cleanupAuthority"] = stopped.Cgroup.Removed ? "held_cgroup_inode_removed" : "held_cgroup_events_and_processes_empty";
                    await scope.DisposeAsync().ConfigureAwait(false);
                }
                catch (Exception exception)
                {
                    cleanup = false; passed = false;
                    UnresolvedCleanupScopes.Add(scope);
                    log.Failure(spec.Group + "_cleanup", exception, true);
                }
            }
            if (LinuxServiceScope.UnresolvedStartupScopes.Count > unresolvedBefore) { cleanup = false; passed = false; }
            if (UnresolvedCleanupScopes.Count != 0) { cleanup = false; passed = false; }
        }
        facts["cleanupConfirmed"] = cleanup.ToString(CultureInfo.InvariantCulture);
        return (new(spec.Group, passed, facts), cleanup);
    }

    private static async Task CpuWindowAsync(LinuxServiceScope scope, LinuxEvidence log, string phase, Dictionary<string, string> facts)
    {
        var before = await ObserveAsync(scope, log, phase + "_window_begin").ConfigureAwait(false);
        Require(before.Cgroup.CountersAvailable, "resource_cpu_counter_unavailable");
        var watch = Stopwatch.StartNew();
        await Task.Delay(2000).ConfigureAwait(false);
        var after = await ObserveAsync(scope, log, phase + "_window_end").ConfigureAwait(false);
        Require(after.Cgroup.CountersAvailable && after.Cgroup.Populated, "resource_cpu_window_not_live");
        ulong usage = Required(after.Cgroup.CpuStat, "usage_usec") - Required(before.Cgroup.CpuStat, "usage_usec");
        ulong throttled = Required(after.Cgroup.CpuStat, "nr_throttled") - Required(before.Cgroup.CpuStat, "nr_throttled");
        var allowed = watch.Elapsed.TotalMilliseconds * 1000 * after.Cgroup.CpuQuotaMicros / after.Cgroup.CpuPeriodMicros;
        Require(usage > 0 && usage <= allowed * 1.5 + 100_000, "resource_cpu_quota_not_observed");
        if (after.Cgroup.CpuQuotaMicros <= 25_000) Require(throttled > 0, "resource_cpu_throttling_not_observed");
        facts["cpuUsecDelta"] = usage.ToString(CultureInfo.InvariantCulture);
        facts["windowMs"] = watch.Elapsed.TotalMilliseconds.ToString("R", CultureInfo.InvariantCulture);
        facts["throttledPeriodsDelta"] = throttled.ToString(CultureInfo.InvariantCulture);
    }

    private static async Task<ResourceCompletion> MonitorCompletionAsync(LinuxServiceScope scope, LinuxOwnerConfiguration config, LinuxEvidence log, string phase)
    {
        var watch = Stopwatch.StartNew();
        ulong oom = 0, pids = 0;
        LinuxScopeObservation? last = null;
        while (watch.Elapsed < TimeSpan.FromSeconds(30))
        {
            last = await ObserveAsync(scope, log, phase + "_sample").ConfigureAwait(false);
            if (last.Cgroup.CountersAvailable)
            {
                oom = Math.Max(oom, Required(last.Cgroup.MemoryEvents, "oom_kill"));
                pids = Math.Max(pids, Required(last.Cgroup.PidsEvents, "max"));
            }
            if (File.Exists(config.ReportPath) || !last.Cgroup.Populated || last.ActiveState is "inactive" or "failed") return new(last, oom, pids);
            await Task.Delay(50).ConfigureAwait(false);
        }
        throw new LinuxProbeException("resource_completion_deadline");
    }

    private static async Task<LinuxScopeObservation> ObserveAsync(LinuxServiceScope scope, LinuxEvidence log, string phase)
    {
        var observed = await scope.ObserveAsync().ConfigureAwait(false);
        var group = observed.Cgroup;
        log.Phase(phase, "native_readback", new(StringComparer.Ordinal)
        {
            ["unit"] = observed.Identity.Unit,
            ["invocationId"] = observed.Identity.InvocationId,
            ["inode"] = group.Inode.ToString(CultureInfo.InvariantCulture),
            ["removed"] = group.Removed.ToString(CultureInfo.InvariantCulture),
            ["counterAvailable"] = group.CountersAvailable.ToString(CultureInfo.InvariantCulture),
            ["populated"] = group.Populated.ToString(CultureInfo.InvariantCulture),
            ["processIds"] = string.Join(',', group.ProcessIds.Take(64)),
            ["processCount"] = group.ProcessIds.Length.ToString(CultureInfo.InvariantCulture),
            ["cpuQuota"] = group.CpuQuotaMicros.ToString(CultureInfo.InvariantCulture),
            ["cpuPeriod"] = group.CpuPeriodMicros.ToString(CultureInfo.InvariantCulture),
            ["memoryMax"] = group.MemoryMaxBytes?.ToString(CultureInfo.InvariantCulture) ?? "unbounded",
            ["memoryCurrent"] = group.MemoryCurrentBytes.ToString(CultureInfo.InvariantCulture),
            ["pidsMax"] = group.PidsMax?.ToString(CultureInfo.InvariantCulture) ?? "unbounded",
            ["pidsCurrent"] = group.PidsCurrent.ToString(CultureInfo.InvariantCulture),
            ["cpuStat"] = Pairs(group.CpuStat),
            ["memoryEvents"] = Pairs(group.MemoryEvents),
            ["pidsEvents"] = Pairs(group.PidsEvents),
            ["managerResult"] = observed.Result,
            ["mainCode"] = observed.ExecMainCode.ToString(CultureInfo.InvariantCulture),
            ["mainStatus"] = observed.ExecMainStatus.ToString(CultureInfo.InvariantCulture),
        });
        return observed;
    }

    private static void VerifyMembers(ResourceLive live, LinuxScopeObservation observed, string control, LinuxEvidence log, string phase)
    {
        var members = new List<ResourceMember>();
        foreach (var pid in observed.Cgroup.ProcessIds)
        {
            ulong start = LinuxCgroup.ProcessStartTicks(pid);
            string group = LinuxCgroup.ProcessControlGroup(pid);
            Require(group == observed.Identity.ControlGroup || group.StartsWith(observed.Identity.ControlGroup + '/', StringComparison.Ordinal), "resource_member_outside_owned_cgroup");
            string? namespaceLink = new FileInfo("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/ns/pid").LinkTarget;
            var line = File.ReadLines("/proc/" + pid.ToString(CultureInfo.InvariantCulture) + "/status").Single(x => x.StartsWith("NSpid:", StringComparison.Ordinal));
            var ids = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            Require(ids.Length >= 2 && namespaceLink is not null && start == LinuxCgroup.ProcessStartTicks(pid), "resource_member_identity_changed");
            members.Add(new(pid, start, namespaceLink!, int.Parse(ids[^1], NumberStyles.None, CultureInfo.InvariantCulture)));
        }
        int[] expected = [live.FixtureNamespacePid, .. live.ChildNamespacePids];
        Require(expected.Distinct().Count() == expected.Length && members.GroupBy(x => x.PidNamespace)
            .Any(group => expected.All(pid => group.Any(member => member.NamespacePid == pid))), "resource_fork_namespace_members_not_observed");
        LinuxQualification.WriteJson(Path.Combine(control, "resource-members.json"), members, LinuxResourceJson.Default.ListResourceMember);
        log.Phase(phase + "_members", "native_namespace_and_cgroup_verified", new(StringComparer.Ordinal) { ["fixtureChildren"] = live.ChildNamespacePids.Length.ToString(CultureInfo.InvariantCulture), ["hostMembers"] = members.Count.ToString(CultureInfo.InvariantCulture) });
    }

    private static void RequireLimits(LinuxScopeObservation observed, LinuxScopeLimits limits)
        => Require(!observed.Cgroup.Removed && observed.Cgroup.CpuQuotaMicros == limits.CpuMillicores * 100L
            && observed.Cgroup.CpuPeriodMicros == 100_000 && observed.Cgroup.MemoryMaxBytes == limits.MemoryBytes
            && observed.Cgroup.PidsMax == limits.ProcessLimit, "resource_limits_readback_mismatch");

    private static bool OwnerReadbackRefusal(string path)
    {
        LinuxCgroup.VerifyPrivatePath(path, false);
        Require(new FileInfo(path).Length <= 4 * 1024 * 1024, "resource_owner_evidence_size_bound");
        foreach (var line in File.ReadLines(path))
        {
            using var document = JsonDocument.Parse(line);
            var entry = document.RootElement;
            if (entry.GetProperty("phase").GetString() == "owner_wait_for_admission"
                && entry.GetProperty("outcome").GetString() == "failed"
                && entry.TryGetProperty("facts", out var facts) && facts.ValueKind == JsonValueKind.Object
                && facts.TryGetProperty("cause0Code", out var code) && code.GetString() == "owner_limits_readback_mismatch") return true;
        }
        return false;
    }

    private static void Permit(LinuxOwnerConfiguration config)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.Read, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite };
        using (var stream = new FileStream(config.ContinuePath + ".pending", options))
        { stream.Write(Encoding.ASCII.GetBytes(config.RunId)); stream.Flush(flushToDisk: true); }
        File.Move(config.ContinuePath + ".pending", config.ContinuePath, false);
    }

    private static string PrivateDirectory(string path)
    {
        Require(!Directory.Exists(path) && !File.Exists(path), "resource_fresh_directory_required");
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        LinuxCgroup.VerifyPrivatePath(path, true);
        return path;
    }
    private static ulong Required(Dictionary<string, ulong> values, string key) => values.TryGetValue(key, out var result) ? result : throw new LinuxProbeException("resource_required_counter_missing_" + key);
    private static string Pairs(Dictionary<string, ulong> values) => string.Join(';', values.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => x.Key + "=" + x.Value.ToString(CultureInfo.InvariantCulture)));
    private static double Number(Dictionary<string, string> values, string key) => double.Parse(values[key], NumberStyles.Float, CultureInfo.InvariantCulture);
    private static void Require(bool condition, string code) { if (!condition) throw new LinuxProbeException(code); }
    private sealed record ResourceSpec(string Group, LinuxScopeLimits Limits);
    private sealed record ResourceCompletion(LinuxScopeObservation Last, ulong MemoryOomKill, ulong PidsMaxEvents);
}

internal sealed record ResourceLive(string RunId, uint NativePid, int FixtureNamespacePid, int[] ChildNamespacePids);
internal sealed record ResourceMember(int HostPid, ulong StartTicks, string PidNamespace, int NamespacePid);
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ResourceLive))]
[JsonSerializable(typeof(List<ResourceMember>))]
internal sealed partial class LinuxResourceJson : JsonSerializerContext;
