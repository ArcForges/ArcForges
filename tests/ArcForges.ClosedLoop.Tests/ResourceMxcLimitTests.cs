// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.Node.Platform.Windows.Mxc;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    private const uint CohortCpuCap = 500;
    private const uint BusyRunCpu = 300;
    private const uint SpareRunCpu = 150;
    private const uint RaisedRunCpu = 340;
    private const uint UnsafeMixedIncreaseCpu = CohortCpuCap - SpareRunCpu;
    private const uint NodeCpuCap = 600;
    private const int CohortMemoryMiB = 384;
    private const int LiveRunMemoryMiB = 128;
    private const int RaisedBusyMemoryMiB = 160;
    private const int LiveAllocationMiB = 64;
    private const uint ProfileProcessCap = 128;
    private const string SaturationRelease = "grant-cap-release";
    private const string SaturationMarker = "grant-cap-refused.log";
    private const string SaturationReport = "grant-cap-unexpected.json";

    private static async Task VerifyInstalledResourceLimitsAsync(TestNode fixture, NodeService.NodeServiceClient node,
        SandboxService.SandboxServiceClient sandboxes, RunService.RunServiceClient runs, ResourceService.ResourceServiceClient resources,
        Id epoch, SandboxConfig profile, CancellationToken cancellation)
    {
        var config = profile.Clone();
        config.Resources.CpuMaxMillicores = CohortCpuCap;
        config.Resources.MemoryMaxBytes = ResourceBytes(CohortMemoryMiB);
        config.Resources.MaxConcurrentRuns = 3;
        var nodeBefore = await ReadInstalledBudgetAsync(resources, "node", null, cancellation);
        var setNode = await resources.SetPolicyAsync(new ResourceServiceSetPolicyRequest
        {
            Meta = Mutation(nodeBefore.PolicyRevision),
            ScopeKind = "node",
            OwnerEpoch = epoch,
            Policy = new ResourcePolicy
            {
                CpuMaxMillicores = NodeCpuCap,
                MemoryMaxBytes = ResourceBytes(512),
                PressureAction = PressureAction.Throttle,
            },
        }, deadline: Deadline, cancellationToken: cancellation);
        var nodeChange = Value(setNode.Value, setNode.Error);
        Assert.Equal(OperationState.Succeeded, nodeChange.Operation.State);
        Assert.Equal(EffectCertainty.Happened, nodeChange.Operation.Effect);
        Assert.True(nodeChange.Snapshot.PolicyRevision.Value > nodeBefore.PolicyRevision.Value);
        RequireSameResourceReceipt(nodeChange.Operation, await OperationAsync(node, epoch, nodeChange.Operation.CommandId));

        var sandbox = await CreateBudgetSandboxAsync("Native resource grant fixture");
        var working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
        Directory.CreateDirectory(working);
        var payload = CopySecurityTestLoad(working);
        var independent = await CreateBudgetSandboxAsync("Independent native grant fixture");
        var independentWork = Path.Combine(independent.DataLocation, "work", "quoted directory");
        Directory.CreateDirectory(independentWork);
        var independentPayload = CopySecurityTestLoad(independentWork);
        var keepMemory = Path.Combine(working, "grant-live-memory-release");
        var liveReport = Path.Combine(working, "grant-live-memory.json");
        var refusedMarker = Path.Combine(working, "grant-refused.log");
        var nodeRefusalMarker = Path.Combine(independentWork, "node-grant-refused.log");
        var active = new List<Id>();
        try
        {
            var cpuRun = await StartHeldAsync(Request(sandbox, BusyRunCpu, LiveRunMemoryMiB,
                [payload, "cpu", "--threads", "2", "--iterations", "20000000000"]));
            var cpuOwner = ReadSupervisor(fixture.DataRoot, cpuRun);
            using var cpuGroup = OperatingSystem.IsLinux() ? OpenResourceCgroup(cpuOwner) : null;
            var cpuBefore = await ReadEffectiveRunBudgetAsync(resources, cpuRun, BusyRunCpu, LiveRunMemoryMiB);
            RequireNativeStartupLimit(fixture.DataRoot, cpuRun, cpuOwner, cpuGroup, BusyRunCpu, LiveRunMemoryMiB);

            // This request fits by itself. The first Run's existing hard grant makes the combination too large.
            var refusedRequest = Request(sandbox, BusyRunCpu, LiveRunMemoryMiB,
                [payload, "hold", "--hold-ms", "1000", "--marker", refusedMarker]);
            await RequireRefusedStartAsync(refusedRequest, refusedMarker, "sandbox_cpu_grant_unavailable");
            Assert.Equal(cpuRun.RunId, Assert.Single(await ListAsync(runs, sandbox.SandboxId)).RunId);

            var memoryRun = await StartHeldAsync(Request(sandbox, SpareRunCpu, LiveRunMemoryMiB,
                [payload, .. MemoryRampArguments(LiveAllocationMiB, keepMemory, liveReport)]));
            var memoryOwner = ReadSupervisor(fixture.DataRoot, memoryRun);
            using var memoryGroup = OperatingSystem.IsLinux() ? OpenResourceCgroup(memoryOwner) : null;
            Assert.NotEqual(cpuOwner.Boundary, memoryOwner.Boundary);
            RequireNativeStartupLimit(fixture.DataRoot, memoryRun, memoryOwner, memoryGroup, SpareRunCpu, LiveRunMemoryMiB);
            var memoryBefore = await WaitForResourceBudgetAsync(resources, "run", memoryRun.RunId,
                sample => OperatingSystem.IsWindows() ? sample.HasPeakMemoryBytes && sample.PeakMemoryBytes >= ResourceBytes(LiveAllocationMiB)
                    : sample.HasManagedMemoryBytes && sample.ManagedMemoryBytes >= ResourceBytes(LiveAllocationMiB));
            _ = RequireEffectiveRunLimit(memoryBefore, "memory", ResourceBytes(LiveRunMemoryMiB));
            var nodeDenied = Request(independent, 200, LiveRunMemoryMiB,
                [independentPayload, "hold", "--hold-ms", "1000", "--marker", nodeRefusalMarker]);
            await RequireRefusedStartAsync(nodeDenied, nodeRefusalMarker, "node_cpu_grant_unavailable");
            Assert.Empty(await ListAsync(runs, independent.SandboxId));

            await ObserveCpuGrantUnderLoadAsync(resources, cpuRun, cpuGroup, cpuBefore, cancellation);

            var earlyIncrease = ResourceMutation(epoch, memoryRun.RunId, memoryBefore.PolicyRevision,
                new ResourcePolicy { CpuMaxMillicores = RaisedRunCpu, PressureAction = PressureAction.Throttle });
            var blocked = await resources.SetPolicyAsync(earlyIncrease, deadline: Deadline, cancellationToken: cancellation);
            Assert.Null(blocked.Value);
            Assert.NotNull(blocked.Error);
            Assert.Equal(ErrorCategory.State, blocked.Error.Category);
            Assert.Equal("busy", blocked.Error.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, blocked.Error.Effect);
            _ = await ReadEffectiveRunBudgetAsync(resources, memoryRun, SpareRunCpu, LiveRunMemoryMiB);
            if (OperatingSystem.IsLinux() && memoryGroup is not null)
            {
                Assert.Equal(SpareRunCpu * 100UL, memoryGroup.ReadLimits().CpuQuota);
            }

            var reduce = ResourceMutation(epoch, cpuRun.RunId, cpuBefore.PolicyRevision, new ResourcePolicy
            {
                CpuMaxMillicores = SpareRunCpu,
                MemoryMaxBytes = ResourceBytes(RaisedBusyMemoryMiB),
                PressureAction = PressureAction.Throttle,
            });
            var reduced = await ApplyInstalledRunPolicyAsync(resources, node, epoch, reduce, cancellation);
            var cpuAfter = await ReadEffectiveRunBudgetAsync(resources, cpuRun, SpareRunCpu, RaisedBusyMemoryMiB);
            Assert.True(cpuAfter.PolicyRevision.Value > cpuBefore.PolicyRevision.Value);
            Assert.Equal(cpuAfter.PolicyRevision, reduced.Snapshot.PolicyRevision);
            var reducedLimit = RequireEffectiveRunLimit(cpuAfter, "cpu", SpareRunCpu);
            Assert.Equal(RequireEffectiveRunLimit(cpuBefore, "cpu", BusyRunCpu).Scope, reducedLimit.Scope);
            if (OperatingSystem.IsLinux() && cpuGroup is not null)
            {
                var changed = cpuGroup.ReadLimits();
                Assert.Equal(SpareRunCpu * 100UL, changed.CpuQuota);
                Assert.Equal(ResourceBytes(RaisedBusyMemoryMiB), changed.MemoryBytes);
            }

            // Replaying a successful durable command must not reapply or advance its revision. A new stale intent must conflict.
            var repeat = await resources.SetPolicyAsync(reduce, deadline: Deadline, cancellationToken: cancellation);
            Assert.Equal(reduced.Operation, Value(repeat.Value, repeat.Error).Operation);
            var reused = reduce.Clone();
            reused.Policy.CpuMaxMillicores = SpareRunCpu + 10;
            var mismatch = await resources.SetPolicyAsync(reused, deadline: Deadline, cancellationToken: cancellation);
            Assert.Equal("command_id_reused", mismatch.Error?.Code);
            var stale = reduce.Clone();
            stale.Meta.CommandId = CommandIds.New();
            stale.Policy.CpuMaxMillicores = SpareRunCpu - 10;
            var conflicted = await resources.SetPolicyAsync(stale, deadline: Deadline, cancellationToken: cancellation);
            Assert.Null(conflicted.Value);
            var conflict = Assert.IsType<ArcError>(conflicted.Error);
            Assert.Equal(ErrorCategory.Conflict, conflict.Category);
            Assert.Equal("revision_mismatch", conflict.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, conflict.Effect);
            var revision = Assert.IsType<RevisionConflict>(conflict.Details?.Revision);
            Assert.Equal(cpuBefore.PolicyRevision, revision.Expected);
            Assert.Equal(cpuAfter.PolicyRevision, revision.Actual);
            var afterConflict = await ReadInstalledBudgetAsync(resources, "run", cpuRun.RunId, cancellation);
            Assert.Equal(cpuAfter.PolicyRevision, afterConflict.PolicyRevision);
            Assert.Equal(cpuAfter.Limits.Count, afterConflict.Limits.Count);
            foreach (var beforeLimit in cpuAfter.Limits)
            {
                var afterLimit = Assert.Single(afterConflict.Limits, limit => limit.Dimension == beforeLimit.Dimension);
                // GetBudget performs a fresh native read, which advances only the observation timestamp.
                var expected = beforeLimit.Clone();
                expected.ReadbackAt = afterLimit.ReadbackAt;
                Assert.Equal(expected, afterLimit);
                var previousReadback = ProtoTime.ToDateTimeOffset(beforeLimit.ReadbackAt);
                var currentReadback = ProtoTime.ToDateTimeOffset(afterLimit.ReadbackAt);
                Assert.Equal(previousReadback.HasValue, currentReadback.HasValue);
                if (previousReadback is { } observed) Assert.True(currentReadback >= observed);
            }

            var increase = earlyIncrease.Clone();
            increase.Meta = Mutation((await ReadEffectiveRunBudgetAsync(resources, memoryRun, SpareRunCpu, LiveRunMemoryMiB)).PolicyRevision);
            _ = await ApplyInstalledRunPolicyAsync(resources, node, epoch, increase, cancellation);
            var memoryAfter = await ReadEffectiveRunBudgetAsync(resources, memoryRun, RaisedRunCpu, LiveRunMemoryMiB);
            var raisedLimit = RequireEffectiveRunLimit(memoryAfter, "cpu", RaisedRunCpu);
            Assert.True(ProtoTime.ToDateTimeOffset(raisedLimit.AppliedAt) >= ProtoTime.ToDateTimeOffset(reducedLimit.ReadbackAt));
            Assert.True(ReadNumericLimit(reducedLimit.ReadbackValue) + ReadNumericLimit(raisedLimit.ReadbackValue) <= CohortCpuCap);
            if (OperatingSystem.IsLinux() && memoryGroup is not null)
            {
                Assert.Equal(RaisedRunCpu * 100UL, memoryGroup.ReadLimits().CpuQuota);
            }

            var unsafeDecrease = ResourceMutation(epoch, memoryRun.RunId, memoryAfter.PolicyRevision,
                new ResourcePolicy
                {
                    CpuMaxMillicores = UnsafeMixedIncreaseCpu,
                    MemoryMaxBytes = ResourceBytes(32),
                    PressureAction = PressureAction.Throttle,
                });
            var lowered = await ApplyInstalledRunPolicyAsync(resources, node, epoch, unsafeDecrease, cancellation);
            Assert.True(lowered.Snapshot.PolicyRevision.Value > memoryAfter.PolicyRevision.Value);
            var held = await ReadInstalledBudgetAsync(resources, "run", memoryRun.RunId, cancellation);
            var heldMemory = Assert.Single(held.Limits, limit => limit.Dimension == "memory");
            var originalMemory = RequireEffectiveRunLimit(memoryAfter, "memory", ResourceBytes(LiveRunMemoryMiB));
            Assert.Equal(LimitStatus.Unsupported, heldMemory.Status);
            Assert.Equal(OperatingSystem.IsWindows() ? "windows_commit_reduction_unverified" : "linux_live_memory_reduction_unsafe", heldMemory.Reason);
            Assert.Equal(ResourceBytes(32).ToString(CultureInfo.InvariantCulture), heldMemory.DesiredValue);
            Assert.Equal(originalMemory.ReadbackValue, heldMemory.ReadbackValue);
            Assert.Equal(originalMemory.AppliedValue, heldMemory.AppliedValue);
            var heldCpu = Assert.Single(held.Limits, limit => limit.Dimension == "cpu");
            Assert.Equal(LimitStatus.Failed, heldCpu.Status);
            Assert.Equal("increase_blocked_by_unconfirmed_reduction", heldCpu.Reason);
            Assert.Equal(UnsafeMixedIncreaseCpu.ToString(CultureInfo.InvariantCulture), heldCpu.DesiredValue);
            Assert.Equal(raisedLimit.ReadbackValue, heldCpu.ReadbackValue);
            Assert.Equal(raisedLimit.AppliedValue, heldCpu.AppliedValue);
            if (OperatingSystem.IsLinux() && memoryGroup is not null)
            {
                var nativeHeld = memoryGroup.ReadLimits();
                Assert.Equal(ResourceBytes(LiveRunMemoryMiB), nativeHeld.MemoryBytes);
                Assert.Equal(RaisedRunCpu * 100UL, nativeHeld.CpuQuota);
            }

            Assert.Equal(RunState.Running, (await InspectAsync(runs, memoryRun.RunId, cancellation)).State);
            Assert.Equal(RunState.Running, (await InspectAsync(runs, cpuRun.RunId, cancellation)).State);
            await File.WriteAllTextAsync(keepMemory, "release", cancellation);
            var drainedMemory = await WaitForStateAsync(fixture, runs, memoryRun.RunId, RunState.Exited, cancellation);
            Assert.True(drainedMemory.Exit.GroupEmptyVerified);
            Assert.Equal(ResourceBytes(LiveAllocationMiB), ResourceAllocationReport(liveReport));
            active.Remove(memoryRun.RunId);

            var saturation = Request(sandbox, RaisedRunCpu, LiveRunMemoryMiB, PrepareMemoryCapPayload(working, payload));
            // The synthetic allocator must reach the OS-controlled cap rather than a smaller managed heap setting.
            saturation.Environment.Add(new EnvironmentEntry { Name = "DOTNET_GCHeapHardLimit", Value = "20000000" });
            var cappedRun = await StartHeldAsync(saturation);
            var cappedOwner = ReadSupervisor(fixture.DataRoot, cappedRun);
            using var cappedGroup = OperatingSystem.IsLinux() ? OpenResourceCgroup(cappedOwner) : null;
            RequireNativeStartupLimit(fixture.DataRoot, cappedRun, cappedOwner, cappedGroup, RaisedRunCpu, LiveRunMemoryMiB);
            await TestNode.WaitAsync(() => File.Exists(Path.Combine(working, SaturationMarker)), NativeBound,
                "the native memory-capped child to refuse its fixed allocation");
            Assert.Equal("refused", Assert.Single(ReadLines(Path.Combine(working, SaturationMarker))));
            Assert.False(File.Exists(Path.Combine(working, SaturationReport)));
            ResourceSnapshot? windowsCapped = null;
            if (OperatingSystem.IsLinux() && cappedGroup is not null)
            {
                var memoryEvents = ReadLinuxCounters(cappedGroup, "memory.events");
                Assert.True(memoryEvents["oom"] > 0 || memoryEvents["oom_kill"] > 0);
                Assert.InRange(Assert.IsType<ulong>(ReadLinuxResource(cappedGroup).MemoryBytes), 1UL, ResourceBytes(LiveRunMemoryMiB));
            }
            else if (OperatingSystem.IsWindows())
            {
                windowsCapped = await WaitForResourceBudgetAsync(resources, "run", cappedRun.RunId,
                    sample => sample.HasPeakMemoryBytes && sample.PeakMemoryBytes >= ResourceBytes(96));
                Assert.InRange(windowsCapped.PeakMemoryBytes, ResourceBytes(96), ResourceBytes(LiveRunMemoryMiB));
            }

            Assert.Equal(RunState.Running, (await InspectAsync(runs, cpuRun.RunId, cancellation)).State);
            await File.WriteAllTextAsync(Path.Combine(working, SaturationRelease), "release", cancellation);
            var cappedDrain = await WaitForStateAsync(fixture, runs, cappedRun.RunId, RunState.Exited, cancellation);
            Assert.True(cappedDrain.Exit.GroupEmptyVerified);
            if (OperatingSystem.IsWindows() && windowsCapped is not null)
            {
                var evidence = ReadWindowsJobResource(fixture.DataRoot, cappedRun, cappedOwner, "windows-drained.json");
                Assert.Empty(evidence.PayloadProcessIds);
                Assert.InRange(evidence.PeakCommitBytes, windowsCapped.PeakMemoryBytes, ResourceBytes(LiveRunMemoryMiB));
            }

            active.Remove(cappedRun.RunId);
            Assert.False(File.Exists(refusedMarker));
            Assert.False(File.Exists(nodeRefusalMarker));
            TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
                $"Confirmed reduced CPU readback {reducedLimit.ReadbackValue} before increased readback {raisedLimit.ReadbackValue}; sandbox ceiling {CohortCpuCap} millicores."));
        }
        finally
        {
            File.WriteAllText(keepMemory, "release");
            File.WriteAllText(Path.Combine(working, SaturationRelease), "release");
            foreach (var owned in active)
            {
                var current = await InspectAsync(runs, owned, CancellationToken.None);
                if (current.State is RunState.Starting or RunState.Running)
                {
                    await StopAsync(runs, BuildStop(epoch, current), CancellationToken.None);
                }

                if (current.State is not (RunState.Exited or RunState.Failed))
                {
                    var stopped = await WaitForStateAsync(fixture, runs, owned, RunState.Exited, CancellationToken.None);
                    Assert.True(stopped.Exit.GroupEmptyVerified);
                }
            }
        }

        async Task<Sandbox> CreateBudgetSandboxAsync(string displayName)
        {
            var created = await sandboxes.CreateAsync(new SandboxServiceCreateRequest
            {
                Meta = Mutation(),
                OwnerEpoch = epoch,
                DisplayName = displayName,
                Config = config,
            }, deadline: Deadline, cancellationToken: cancellation);
            return Value(created.Value, created.Error).Sandbox;
        }

        RunServiceStartRequest Request(Sandbox target, uint cpu, int memoryMiB, string[] argv)
        {
            var request = BuildStart(target, epoch, argv);
            request.TerminalMode = TerminalMode.Pipes;
            request.TerminalSize = null;
            request.Environment.Clear();
            request.RequestedResources = new ResourcePolicy
            {
                CpuMaxMillicores = cpu,
                MemoryMaxBytes = ResourceBytes(memoryMiB),
                PressureAction = PressureAction.Throttle,
            };
            return request;
        }

        async Task<Run> StartHeldAsync(RunServiceStartRequest request)
        {
            var start = await runs.StartAsync(request, deadline: Deadline, cancellationToken: cancellation);
            var id = Value(start.Value, start.Error).Run.RunId;
            active.Add(id);
            return await WaitForStateAsync(fixture, runs, id, RunState.Running, cancellation);
        }

        async Task RequireRefusedStartAsync(RunServiceStartRequest request, string marker, string reason)
        {
            var refused = await runs.StartAsync(request, deadline: Deadline, cancellationToken: cancellation);
            if (refused.Value?.Run?.RunId is { } unexpected) active.Add(unexpected);
            AssertResourceRefusal(refused.Error, reason);
            Assert.Null(refused.Value);
            var rejectedReceipt = await OperationAsync(node, epoch, request.Meta.CommandId);
            Assert.Equal(OperationState.Failed, rejectedReceipt.State);
            Assert.Equal(EffectCertainty.DidNotHappen, rejectedReceipt.Effect);
            var replay = await runs.StartAsync(request, deadline: Deadline, cancellationToken: cancellation);
            if (replay.Value?.Run?.RunId is { } unexpectedReplay) active.Add(unexpectedReplay);
            Assert.Null(replay.Value);
            AssertResourceRefusal(replay.Error, reason);
            Assert.False(File.Exists(marker));
        }
    }

    private static ResourceServiceSetPolicyRequest ResourceMutation(Id epoch, Id run, Revision revision, ResourcePolicy policy) => new()
    {
        Meta = Mutation(revision),
        ScopeKind = "run",
        ScopeId = run,
        OwnerEpoch = epoch,
        Policy = policy,
    };

    private static async Task<ResourceServiceSetPolicyValue> ApplyInstalledRunPolicyAsync(ResourceService.ResourceServiceClient resources,
        NodeService.NodeServiceClient node, Id epoch, ResourceServiceSetPolicyRequest request, CancellationToken cancellation)
    {
        var response = await resources.SetPolicyAsync(request, deadline: Deadline, cancellationToken: cancellation);
        var value = Value(response.Value, response.Error);
        Assert.Equal(OperationState.Succeeded, value.Operation.State);
        Assert.Equal(EffectCertainty.Happened, value.Operation.Effect);
        Assert.Equal(request.ScopeId, value.Operation.AggregateId);
        RequireSameResourceReceipt(value.Operation, await OperationAsync(node, epoch, request.Meta.CommandId));
        return value;
    }

    private static void RequireSameResourceReceipt(Operation returned, Operation stored)
    {
        Assert.Equal((returned.CommandId, returned.OwnerEpoch, returned.Method, returned.AggregateId, returned.Revision, returned.State, returned.Effect),
            (stored.CommandId, stored.OwnerEpoch, stored.Method, stored.AggregateId, stored.Revision, stored.State, stored.Effect));
        Assert.NotNull(stored.UpdatedAt);
        Assert.False(stored.ResponseCompacted);
    }

    private static async Task<ResourceSnapshot> ReadInstalledBudgetAsync(ResourceService.ResourceServiceClient client,
        string kind, Id? id, CancellationToken cancellation)
    {
        var response = await client.GetBudgetAsync(new ResourceServiceGetBudgetRequest
        {
            Meta = Query(),
            ScopeKind = kind,
            ScopeId = id,
        }, deadline: Deadline, cancellationToken: cancellation);
        return Value(response.Value, response.Error).Snapshot;
    }

    private static async Task<ResourceSnapshot> ReadEffectiveRunBudgetAsync(ResourceService.ResourceServiceClient client,
        Run run, uint cpu, int memoryMiB)
    {
        var result = await WaitForResourceBudgetAsync(client, "run", run.RunId, sample => sample.Limits.Any(limit =>
            limit.Dimension == "cpu" && limit.Status == LimitStatus.Effective && limit.DesiredValue == cpu.ToString(CultureInfo.InvariantCulture)));
        Assert.NotNull(result.PolicyRevision);
        _ = RequireEffectiveRunLimit(result, "cpu", cpu);
        _ = RequireEffectiveRunLimit(result, "memory", ResourceBytes(memoryMiB));
        Assert.Equal("count", RequireEffectiveRunLimit(result, "pids", ProfileProcessCap).Unit);
        return result;
    }

    private static LimitState RequireEffectiveRunLimit(ResourceSnapshot snapshot, string dimension, ulong desired)
    {
        var limit = Assert.Single(snapshot.Limits, item => item.Dimension == dimension);
        Assert.Equal(LimitStatus.Effective, limit.Status);
        Assert.Equal(desired.ToString(CultureInfo.InvariantCulture), limit.DesiredValue);
        Assert.Equal(limit.AppliedValue, limit.ReadbackValue);
        Assert.True(ReadNumericLimit(limit.ReadbackValue) > 0);
        Assert.False(string.IsNullOrWhiteSpace(limit.Scope));
        Assert.NotNull(limit.DesiredRevision);
        var applied = Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(limit.AppliedAt));
        var readback = Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(limit.ReadbackAt));
        Assert.True(readback >= applied);
        if (dimension == "cpu")
        {
            Assert.Equal("millicores", limit.Unit);
            Assert.InRange(ReadNumericLimit(limit.ReadbackValue), 1UL, desired);
        }
        else
        {
            Assert.Equal(desired, ReadNumericLimit(limit.ReadbackValue));
        }

        return limit;
    }

    private static ulong ReadNumericLimit(string value) => ulong.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);

    private static void AssertResourceRefusal(ArcError? error, string reason)
    {
        Assert.NotNull(error);
        Assert.Equal(ErrorCategory.Resource, error.Category);
        Assert.Equal("budget_unavailable", error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
        Assert.Equal(reason, error.Details?.State?.Reason);
    }

    private static async Task ObserveCpuGrantUnderLoadAsync(ResourceService.ResourceServiceClient resources, Run run,
        LinuxRunCgroup? cgroup, ResourceSnapshot initial, CancellationToken cancellation)
    {
        var before = await WaitForResourceBudgetAsync(resources, "run", run.RunId,
            sample => sample.HasCumulativeCpuUsec && sample.CumulativeCpuUsec > 0);
        var nativeBefore = OperatingSystem.IsLinux() && cgroup is not null ? ReadLinuxCounters(cgroup, "cpu.stat") : null;
        var sampledAt = Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(before.SampledAt));
        await Task.Delay(TimeSpan.FromSeconds(3), cancellation);
        var after = await WaitForResourceBudgetAsync(resources, "run", run.RunId, sample => sample.HasCumulativeCpuUsec
            && sample.SampleSequence > before.SampleSequence && ProtoTime.ToDateTimeOffset(sample.SampledAt) >= sampledAt.AddSeconds(2));
        Assert.True(after.CumulativeCpuUsec > before.CumulativeCpuUsec);
        var observedAt = Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(after.SampledAt));
        var measuredMillicores = (after.CumulativeCpuUsec - before.CumulativeCpuUsec) / (observedAt - sampledAt).TotalMilliseconds;
        var effective = ReadNumericLimit(RequireEffectiveRunLimit(initial, "cpu", BusyRunCpu).ReadbackValue);
        // Account for short native accounting-period and independent observer boundary differences.
        Assert.InRange(measuredMillicores, 30, effective + 200);
        if (OperatingSystem.IsLinux() && cgroup is not null && nativeBefore is not null)
        {
            Assert.True(ReadLinuxCounters(cgroup, "cpu.stat")["nr_throttled"] > nativeBefore["nr_throttled"]);
        }

        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"Busy Run measured {measuredMillicores:F1} millicores with {effective} millicores read back."));
    }

    private static void RequireNativeStartupLimit(string root, Run run, (int Pid, string Creation, string Boundary) owner,
        LinuxRunCgroup? group, uint cpu, int memoryMiB)
    {
        if (OperatingSystem.IsLinux() && group is not null)
        {
            var limits = group.ReadLimits();
            Assert.Equal(100_000UL, limits.CpuPeriod);
            Assert.Equal(cpu * 100UL, limits.CpuQuota);
            Assert.Equal(ResourceBytes(memoryMiB), limits.MemoryBytes);
            Assert.Equal((ulong)ProfileProcessCap, limits.Tasks);
            Assert.Equal(0UL, limits.SwapBytes);
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            var control = Path.Combine(root, "control", "run-" + Hex(run.RunId));
            var path = Path.Combine(control, "windows-prepared.json");
            using var directory = WindowsMxcPathLease.Open(control, directory: true, privateObject: true);
            using var receipt = WindowsMxcPathLease.Open(path, directory: false, privateObject: true);
            using var document = JsonDocument.Parse(File.ReadAllBytes(path));
            var value = document.RootElement;
            Assert.Equal(Hex(run.RunId), value.GetProperty("runId").GetString());
            Assert.Equal(run.LaunchSha256, value.GetProperty("launchSha256").GetString());
            Assert.Equal(owner.Pid, value.GetProperty("ownerPid").GetInt32());
            Assert.Equal(owner.Creation, value.GetProperty("ownerCreationFileTime").GetInt64().ToString(CultureInfo.InvariantCulture));
            Assert.Equal(WindowsMxcProcess.CpuRate(cpu), value.GetProperty("cpuRate").GetInt32());
            Assert.Equal(ResourceBytes(memoryMiB), value.GetProperty("commitLimitBytes").GetUInt64());
            Assert.Equal(ProfileProcessCap, value.GetProperty("maxProcesses").GetUInt32());
            return;
        }

        throw new PlatformNotSupportedException();
    }

    [SupportedOSPlatform("linux")]
    private static Dictionary<string, ulong> ReadLinuxCounters(LinuxRunCgroup group, string name)
    {
        _ = group.ReadLimits(); // Validate the original held object before and after reading its kernel counters.
        var path = Path.Combine("/sys/fs/cgroup", group.Path.TrimStart('/'), name);
        var result = new Dictionary<string, ulong>(StringComparer.Ordinal);
        foreach (var line in File.ReadLines(path))
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(2, fields.Length);
            result.Add(fields[0], ReadNumericLimit(fields[1]));
        }

        _ = group.ReadLimits();
        return result;
    }

    private static string[] PrepareMemoryCapPayload(string working, string payload)
    {
        if (OperatingSystem.IsLinux())
        {
            const string script = """
                if "$1" mem-ramp --target-mb 192 --step-mb 8 --step-ms 20 --report "$2"; then
                    exit 9
                fi
                printf 'refused\n' > "$3" || exit 11
                exec "$1" hold --hold-ms 40000 --until-file "$4"
                """;
            return ["/usr/bin/dash", "-c", script, "arcforges-resource-fixture", payload,
                SaturationReport, SaturationMarker, SaturationRelease];
        }

        const string batch = """
            @echo off
            .\arcforges-testload.exe mem-ramp --target-mb 192 --step-mb 8 --step-ms 20 --report grant-cap-unexpected.json
            if not errorlevel 1 exit /b 9
            >grant-cap-refused.log echo refused
            .\arcforges-testload.exe hold --hold-ms 40000 --until-file grant-cap-release
            """;
        File.WriteAllText(Path.Combine(working, "grant-memory-cap.cmd"), batch.ReplaceLineEndings("\r\n") + "\r\n");
        return [Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/d", "/c", "grant-memory-cap.cmd"];
    }
}
