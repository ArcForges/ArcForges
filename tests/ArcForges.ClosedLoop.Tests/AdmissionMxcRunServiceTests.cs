// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform.Capabilities;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    [Fact(Timeout = 135_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task InstalledParallelStartsReserveOneSlotAndNeverQueueTheRefusedRun()
    {
        var cancellation = TestContext.Current.CancellationToken;
        cancellation.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var package = await ResourcePackage.StartAsync();
        await package.SetNodePolicyAsync(new ResourcePolicy
        {
            CpuMaxMillicores = 1000,
            MemoryMaxBytes = ResourceBytes(768),
            MaxConcurrentRuns = 1,
            PressureAction = PressureAction.Throttle,
        }, cancellation);
        var singleSlot = ScopePolicy(400);
        singleSlot.ExpectedMemoryBytes = ResourceBytes(128);
        singleSlot.MaxConcurrentRuns = 1;
        singleSlot.Weight = 1;
        var first = await package.CreateScopeAsync("Concurrent first Sandbox", singleSlot, cancellation);
        var second = await package.CreateScopeAsync("Concurrent second Sandbox", singleSlot, cancellation);
        var requests = new[]
        {
            BuildAdmissionHold(package, first, "concurrent-first", 180, 0, false),
            BuildAdmissionHold(package, second, "concurrent-second", 180, 0, false),
        };
        await WaitForResourceBudgetAsync(package.Resources, "node", null, sample => sample.Pressure == "normal"
            && sample.HasBudgetCpuMillicores && sample.BudgetCpuMillicores >= 360);

        // Distinct authenticated transports exercise simultaneous admission independently of channel scheduling.
        await using var peer = OpenChannel(package.Fixture);
        var peerRuns = new RunService.RunServiceClient(peer.CallInvoker);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var starts = new[] { LaunchAtBarrier(package.Runs, requests[0]), LaunchAtBarrier(peerRuns, requests[1]) };
        gate.SetResult();
        var replies = await Task.WhenAll(starts);
        var admitted = Assert.Single(replies, reply => reply.Value is not null);
        var refused = Assert.Single(replies, reply => reply.Error is not null);
        var winner = ReferenceEquals(replies[0], admitted) ? 0 : 1;
        var loser = 1 - winner;
        var refusedRequest = requests[loser];
        var scopes = new[] { first, second };
        var names = new[] { "concurrent-first", "concurrent-second" };
        const string reason = "node_concurrency_grant_unavailable";
        var refusal = AssertInstalledBudgetRefusal(refused, reason, refusedRequest.Meta.CorrelationId);
        var storedRefusal = await QueryAdmissionRefusalAsync(package, refusedRequest.Meta.CommandId, reason, cancellation);
        Assert.Equal(OperationState.Failed, storedRefusal.State);
        Assert.Equal(EffectCertainty.DidNotHappen, storedRefusal.Effect);

        var run = await WaitForStateAsync(package.Fixture, package.Runs, admitted.Value.Run.RunId, RunState.Running, cancellation);
        await WaitForAdmissionMarkerAsync(scopes[winner], names[winner]);
        Assert.Equal(run.RunId, Assert.Single(await ListAsync(package.Runs, scopes[winner].Sandbox.SandboxId)).RunId);
        Assert.Empty(await ListAsync(package.Runs, scopes[loser].Sandbox.SandboxId));
        Assert.False(File.Exists(AdmissionMarker(scopes[loser], names[loser])));
        var reservation = await WaitForResourceBudgetAsync(package.Resources, "run", run.RunId, sample =>
            sample.HasReservedRunMemoryBytes && sample.ReservedRunMemoryBytes >= ResourceBytes(128));
        var nodeReservation = await WaitForResourceBudgetAsync(package.Resources, "node", null, sample =>
            sample.HasReservedRunMemoryBytes && sample.ReservedRunMemoryBytes == reservation.ReservedRunMemoryBytes);
        var sandboxReservation = await WaitForResourceBudgetAsync(package.Resources, "sandbox", scopes[winner].Sandbox.SandboxId,
            sample => sample.HasReservedRunMemoryBytes && sample.ReservedRunMemoryBytes == nodeReservation.ReservedRunMemoryBytes);
        Assert.True(sandboxReservation.ReservedRunMemoryBytes >= ResourceBytes(128));

        var winnerReplay = requests[winner].Clone();
        winnerReplay.Meta.CorrelationId = CommandIds.New();
        var sameWinner = await package.StartAsync(winnerReplay, cancellation);
        Assert.Equal(winnerReplay.Meta.CorrelationId, sameWinner.Meta.CorrelationId);
        Assert.Equal(run.RunId, Value(sameWinner.Value, sameWinner.Error).Run.RunId);
        Assert.Single(ReadLines(AdmissionMarker(scopes[winner], names[winner])), line => line.StartsWith("start ", StringComparison.Ordinal));
        Assert.True((await package.DrainAsync(run.RunId, cancellation)).Exit.GroupEmptyVerified);
        await WaitForResourceBudgetAsync(package.Resources, "node", null,
            sample => sample.HasReservedRunMemoryBytes && sample.ReservedRunMemoryBytes == 0);

        await VerifyReplayedAdmissionRefusalAsync(package, refusedRequest, reason, refusal, storedRefusal, cancellation);
        Assert.Empty(await ListAsync(package.Runs, scopes[loser].Sandbox.SandboxId));
        Assert.False(File.Exists(AdmissionMarker(scopes[loser], names[loser])));

        var freshIntent = refusedRequest.Clone();
        freshIntent.Meta = Mutation(scopes[loser].Sandbox.Revision);
        var later = await package.StartRunningAsync(freshIntent, cancellation);
        await WaitForAdmissionMarkerAsync(scopes[loser], names[loser]);
        Assert.NotEqual(run.RunId, later.RunId);
        Assert.Single(ReadLines(AdmissionMarker(scopes[loser], names[loser])), line => line.StartsWith("start ", StringComparison.Ordinal));
        Assert.True((await package.DrainAsync(later.RunId, cancellation)).Exit.GroupEmptyVerified);

        await VerifyResidentContentionAsync(package, first, second, cancellation);
        await VerifyProspectiveDefaultCpuShareAsync(package, first, second, cancellation);

        async Task<RunServiceStartResponse> LaunchAtBarrier(RunService.RunServiceClient service, RunServiceStartRequest request)
        {
            await gate.Task.WaitAsync(cancellation);
            return await service.StartAsync(request, deadline: Deadline, cancellationToken: cancellation);
        }
    }

    private static async Task VerifyResidentContentionAsync(ResourcePackage package, ResourcePackageScope first,
        ResourcePackageScope second, CancellationToken cancellation)
    {
        var incumbent = await package.StartRunningAsync(BuildAdmissionHold(package, first, "resident-holder", 180, 0, false), cancellation);
        await WaitForAdmissionMarkerAsync(first, "resident-holder");
        ulong estimated = ResourceBytes(128);
        ulong measuredTarget = ResourceBytes(192);
        var baseline = await WaitForResourceBudgetAsync(package.Resources, "node", null, sample => sample.Pressure == "normal"
            && sample.HasUnmanagedMemoryBytes && sample.HasHostMemoryBytes && sample.HasReservedRunMemoryBytes
            && sample.ReservedRunMemoryBytes == estimated);
        Assert.True(baseline.HostMemoryBytes > baseline.UnmanagedMemoryBytes + measuredTarget);
        ulong reserve = baseline.HostMemoryBytes - baseline.UnmanagedMemoryBytes - measuredTarget;
        await package.SetNodePolicyAsync(new ResourcePolicy
        {
            CpuMaxMillicores = 1000,
            MemoryMaxBytes = ResourceBytes(768),
            HostReserveBytes = reserve,
            MaxConcurrentRuns = 2,
            PressureAction = PressureAction.Throttle,
        }, cancellation);

        var measured = await WaitForResourceBudgetAsync(package.Resources, "node", null, sample => sample.Pressure == "normal"
            && sample.HasReservedRunMemoryBytes && sample.ReservedRunMemoryBytes == estimated && sample.ReservedMemoryBytes == reserve
            && sample.HasBudgetMemoryBytes && sample.BudgetMemoryBytes >= ResourceBytes(144) && sample.BudgetMemoryBytes <= ResourceBytes(240));
        var blocked = BuildAdmissionHold(package, second, "resident-refused", 180, 0, false);
        Assert.Equal(estimated, blocked.RequestedResources.MemoryMaxBytes);
        _ = RequireEffectiveRunLimit(await ReadEffectiveRunBudgetAsync(package.Resources, incumbent, 180, 128), "memory", estimated);
        Assert.True(estimated * 2 > measured.BudgetMemoryBytes);
        var previousRuns = (await ListAsync(package.Runs, second.Sandbox.SandboxId)).Select(run => Hex(run.RunId)).Order(StringComparer.Ordinal).ToArray();

        // Both configured native hard caps and concurrency slots fit; the measured resident reservation is the limiting dimension.
        const string reason = "node_resident_memory_unavailable";
        var refused = AssertInstalledBudgetRefusal(await package.StartAsync(blocked, cancellation), reason, blocked.Meta.CorrelationId);
        var receipt = await QueryAdmissionRefusalAsync(package, blocked.Meta.CommandId, reason, cancellation);
        Assert.Equal(OperationState.Failed, receipt.State);
        Assert.Equal(EffectCertainty.DidNotHappen, receipt.Effect);
        var retainedBody = ReadAdmissionRefusalReceipt(package, blocked.Meta.CommandId);
        using var details = JsonDocument.Parse(retainedBody);
        var measuredRefusal = details.RootElement.GetProperty("resourceRefusal");
        Assert.Equal("node", measuredRefusal.GetProperty("scope").GetString());
        Assert.Equal("resident_memory", measuredRefusal.GetProperty("dimension").GetString());
        Assert.Equal(estimated, measuredRefusal.GetProperty("requested").GetUInt64());
        var available = measuredRefusal.GetProperty("available").GetUInt64();
        Assert.True(available < estimated);
        Assert.Equal(measured.PolicyRevision.Value, measuredRefusal.GetProperty("policyRevision").GetInt64());
        Assert.Equal(measured.SampleEpoch, measuredRefusal.GetProperty("sampleEpoch").GetString());
        Assert.True(measuredRefusal.GetProperty("sampleSequence").GetUInt64() >= measured.SampleSequence);
        Assert.True(DateTimeOffset.Parse(measuredRefusal.GetProperty("sampledUtc").GetString()!, CultureInfo.InvariantCulture)
            >= Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(measured.SampledAt)));
        Assert.Equal(previousRuns, (await ListAsync(package.Runs, second.Sandbox.SandboxId)).Select(run => Hex(run.RunId)).Order(StringComparer.Ordinal));
        Assert.False(File.Exists(AdmissionMarker(second, "resident-refused")));

        Assert.True((await package.DrainAsync(incumbent.RunId, cancellation)).Exit.GroupEmptyVerified);
        await WaitForResourceBudgetAsync(package.Resources, "node", null,
            sample => sample.HasReservedRunMemoryBytes && sample.ReservedRunMemoryBytes == 0 && sample.BudgetMemoryBytes >= estimated);
        await VerifyReplayedAdmissionRefusalAsync(package, blocked, reason, refused, receipt, cancellation);
        Assert.Equal(retainedBody, ReadAdmissionRefusalReceipt(package, blocked.Meta.CommandId));
        Assert.False(File.Exists(AdmissionMarker(second, "resident-refused")));
        var retried = blocked.Clone();
        retried.Meta = Mutation(second.Sandbox.Revision);
        var later = await package.StartRunningAsync(retried, cancellation);
        await WaitForAdmissionMarkerAsync(second, "resident-refused");
        Assert.True((await package.DrainAsync(later.RunId, cancellation)).Exit.GroupEmptyVerified);
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"Verified independent resident contention: {estimated} bytes reserved; rejected request for {estimated} bytes with {available} bytes resident budget remaining. Native hard grants are 128 MiB."));
    }

    private static string ReadAdmissionRefusalReceipt(ResourcePackage package, Id commandId)
    {
        using var database = ReadDatabase(package.Fixture.DataRoot);
        using var command = database.CreateCommand();
        command.CommandText = "SELECT response_json FROM command_receipt WHERE owner_epoch=$owner AND command_id=$command;";
        command.Parameters.AddWithValue("$owner", package.Epoch.Value.ToByteArray());
        command.Parameters.AddWithValue("$command", Hex(commandId));
        return Assert.IsType<string>(command.ExecuteScalar());
    }

    private static async Task VerifyProspectiveDefaultCpuShareAsync(ResourcePackage package, ResourcePackageScope first,
        ResourcePackageScope second, CancellationToken cancellation)
    {
        await package.SetNodePolicyAsync(new ResourcePolicy
        {
            CpuMaxMillicores = 400,
            MemoryMaxBytes = ResourceBytes(768),
            MaxConcurrentRuns = 2,
            PressureAction = PressureAction.Throttle,
        }, cancellation);
        await WaitForResourceBudgetAsync(package.Resources, "node", null, sample => sample.Pressure == "normal" && sample.BudgetCpuMillicores == 400);
        var defaultRequest = BuildAdmissionHold(package, first, "prospective-default", 400, 0, false);
        defaultRequest.RequestedResources.ClearCpuMaxMillicores();
        var incumbent = await package.StartRunningAsync(defaultRequest, cancellation);
        await WaitForAdmissionMarkerAsync(first, "prospective-default");
        var originalIdentity = ReadSupervisor(package.Fixture.DataRoot, incumbent);
        using var held = OperatingSystem.IsLinux() ? OpenResourceCgroup(originalIdentity) : null;
        RequireNativeStartupLimit(package.Fixture.DataRoot, incumbent, originalIdentity, held, 400, 128);
        var firstBudget = await ReadEffectiveRunBudgetAsync(package.Resources, incumbent, 400, 128);
        var before = RequireEffectiveRunLimit(firstBudget, "cpu", 400);
        Assert.InRange(ReadNumericLimit(before.ReadbackValue), 390UL, 400UL);

        var newcomer = await package.StartRunningAsync(BuildAdmissionHold(package, second, "prospective-explicit", 100, 0, false), cancellation);
        await WaitForAdmissionMarkerAsync(second, "prospective-explicit");
        var nextIdentity = ReadSupervisor(package.Fixture.DataRoot, newcomer);
        using var nextGroup = OperatingSystem.IsLinux() ? OpenResourceCgroup(nextIdentity) : null;
        RequireNativeStartupLimit(package.Fixture.DataRoot, newcomer, nextIdentity, nextGroup, 100, 128);
        var updatedFirst = await ReadInstalledBudgetAsync(package.Resources, "run", incumbent.RunId, cancellation);
        var after = RequireEffectiveRunLimit(updatedFirst, "cpu", 400);
        var nextBudget = await ReadEffectiveRunBudgetAsync(package.Resources, newcomer, 100, 128);
        var next = RequireEffectiveRunLimit(nextBudget, "cpu", 100);
        Assert.Equal(before.Scope, after.Scope);
        Assert.Equal(originalIdentity, ReadSupervisor(package.Fixture.DataRoot, incumbent));
        Assert.NotEqual(originalIdentity.Boundary, nextIdentity.Boundary);
        Assert.InRange(ReadNumericLimit(after.ReadbackValue), 290UL, 300UL);
        Assert.True(RequireAppliedAt(after) <= RequireAppliedAt(next));
        Assert.True(ReadNumericLimit(after.ReadbackValue) + ReadNumericLimit(next.ReadbackValue) <= 400);
        if (OperatingSystem.IsLinux() && held is not null)
        {
            Assert.Equal(30_000UL, held.ReadLimits().CpuQuota);
        }

        Assert.True((await package.DrainAsync(newcomer.RunId, cancellation)).Exit.GroupEmptyVerified);
        Assert.True((await package.DrainAsync(incumbent.RunId, cancellation)).Exit.GroupEmptyVerified);
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"Prospective Start confirmed same-scope incumbent CPU {before.ReadbackValue}m→{after.ReadbackValue}m before the independent explicit {next.ReadbackValue}m grant."));
    }

    [Fact(Timeout = 165_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task InstalledWeightedSandboxesShareReducedNativeCpuHeadroomAndRecover()
    {
        var cancellation = TestContext.Current.CancellationToken;
        cancellation.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        await using var package = await ResourcePackage.StartAsync(policy =>
        {
            policy.Resources.MinManagedCpuMillicores = 400;
            policy.Resources.SmoothingAlphaUp = 1;
            policy.Resources.SmoothingAlphaDown = 0.8;
        });

        var baseline = await WaitForResourceBudgetAsync(package.Resources, "node", null, sample =>
            sample.HasHostCpuMillicores && sample.HasUnmanagedCpuMillicores && sample.Pressure == "normal");
        uint host = baseline.HostCpuMillicores;
        uint threshold = (host + 19) / 20;
        uint perScope = Math.Max(800U, (threshold + 650) / 2);
        uint combined = 2 * perScope;
        uint initialHeadroom = combined + 450;
        uint measuredOverhead = baseline.UnmanagedCpuMillicores;
        Assert.True(host > initialHeadroom + measuredOverhead,
            $"Native CPU capacity {host}m or unmanaged baseline {measuredOverhead}m does not permit calibration for {initialHeadroom}m.");
        uint reserve = host - initialHeadroom - measuredOverhead;
        await package.SetNodePolicyAsync(new ResourcePolicy
        {
            CpuMaxMillicores = initialHeadroom,
            HostReserveMillicores = reserve,
            MemoryMaxBytes = ResourceBytes(768),
            PressureAction = PressureAction.Throttle,
        }, cancellation);
        await WaitForResourceBudgetAsync(package.Resources, "node", null, sample => sample.BudgetCpuMillicores >= combined
            && sample.ReservedCpuMillicores == reserve);

        var firstPolicy = ScopePolicy(perScope);
        firstPolicy.Weight = 1;
        var secondPolicy = ScopePolicy(perScope);
        secondPolicy.Weight = 3;
        var first = await package.CreateScopeAsync("Lower weight Sandbox", firstPolicy, cancellation);
        var second = await package.CreateScopeAsync("Higher weight Sandbox", secondPolicy, cancellation);
        var lighter = await package.StartRunningAsync(BuildAdmissionCpu(package, first, perScope), cancellation);
        var beforeSecondStart = await ReadInstalledBudgetAsync(package.Resources, "node", null, cancellation);
        var secondHeadroom = await WaitForResourceBudgetAsync(package.Resources, "node", null, sample => sample.SampleSequence > beforeSecondStart.SampleSequence
            && sample.Pressure == "normal" && sample.ReservedCpuMillicores == reserve && sample.BudgetCpuMillicores >= combined);
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"Before the second Start, host sample {secondHeadroom.SampleSequence} had {secondHeadroom.BudgetCpuMillicores}m for {combined}m of grants."));
        var heavier = await package.StartRunningAsync(BuildAdmissionCpu(package, second, perScope), cancellation);
        var lightOwner = ReadSupervisor(package.Fixture.DataRoot, lighter);
        var heavyOwner = ReadSupervisor(package.Fixture.DataRoot, heavier);
        Assert.NotEqual(lightOwner.Boundary, heavyOwner.Boundary);
        using var lightGroup = OperatingSystem.IsLinux() ? OpenResourceCgroup(lightOwner) : null;
        using var heavyGroup = OperatingSystem.IsLinux() ? OpenResourceCgroup(heavyOwner) : null;
        RequireNativeStartupLimit(package.Fixture.DataRoot, lighter, lightOwner, lightGroup, perScope, 128);
        RequireNativeStartupLimit(package.Fixture.DataRoot, heavier, heavyOwner, heavyGroup, perScope, 128);
        var lightInitial = await ReadEffectiveRunBudgetAsync(package.Resources, lighter, perScope, 128);
        var heavyInitial = await ReadEffectiveRunBudgetAsync(package.Resources, heavier, perScope, 128);
        var initialLightLimit = RequireEffectiveRunLimit(lightInitial, "cpu", perScope);
        var initialHeavyLimit = RequireEffectiveRunLimit(heavyInitial, "cpu", perScope);

        // The host-owned producer consumes only the CPU needed to cross the calibrated threshold.
        uint heldBudget = combined - threshold - 100;
        int threads = (int)Math.Clamp(((initialHeadroom - heldBudget + 999) / 1000) + 1, 2U, 4U);
        var latest = await ReadInstalledBudgetAsync(package.Resources, "node", null, cancellation);
        await WaitForResourceBudgetAsync(package.Resources, "node", null,
            sample => sample.SampleSequence > latest.SampleSequence && sample.BudgetCpuMillicores >= combined);
        var load = package.Fixture.Start(TestNode.TestLoad, ["cpu", "--threads", threads.ToString(CultureInfo.InvariantCulture),
            "--iterations", "20000000000"]);
        DateTimeOffset reducedAt;
        try
        {
            var reduced = await WaitForResourceBudgetAsync(package.Resources, "node", null, sample =>
                sample.HasBudgetCpuMillicores && sample.BudgetCpuMillicores is >= 400 && sample.BudgetCpuMillicores <= heldBudget);
            var shared = await AwaitWeightedReadbackAsync(package, lighter, heavier, heldBudget, cancellation);
            Assert.Equal(initialLightLimit.Scope, shared.Light.Scope);
            Assert.Equal(initialHeavyLimit.Scope, shared.Heavy.Scope);
            reducedAt = new[] { RequireAppliedAt(shared.Light), RequireAppliedAt(shared.Heavy) }.Max();
            if (OperatingSystem.IsLinux() && lightGroup is not null && heavyGroup is not null)
            {
                Assert.Equal(ReadNumericLimit(shared.Light.ReadbackValue) * 100, lightGroup.ReadLimits().CpuQuota);
                Assert.Equal(ReadNumericLimit(shared.Heavy.ReadbackValue) * 100, heavyGroup.ReadLimits().CpuQuota);
            }

            var latency = Stopwatch.StartNew();
            var probe = package.Fixture.Start(TestNode.TestLoad, ["cpu", "--threads", "1", "--iterations", "1000000"]);
            var responsiveness = await TestNode.CompleteAsync(probe, NativeBound);
            latency.Stop();
            Assert.Equal(0, responsiveness.ExitCode);
            await RequireWeightedRunDemandAsync(package, lighter, heavier, shared, heldBudget, cancellation);
            Assert.False(load.HasExited);
            TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
                $"Native CPU budget dropped to {reduced.BudgetCpuMillicores}m with reserve {reserve}m. Weighted readbacks were {shared.Light.ReadbackValue}m and {shared.Heavy.ReadbackValue}m; independent host probe completed in {latency.ElapsedMilliseconds}ms."));
        }
        finally
        {
            if (!load.HasExited) load.Kill();
            await load.WaitForExitAsync(CancellationToken.None).WaitAsync(NativeBound, CancellationToken.None);
        }

        await WaitForResourceBudgetAsync(package.Resources, "node", null, sample => sample.BudgetCpuMillicores >= combined);
        var restoredLight = await WaitForResourceBudgetAsync(package.Resources, "run", lighter.RunId,
            sample => CpuReadbackMatches(sample, initialLightLimit));
        var restoredHeavy = await WaitForResourceBudgetAsync(package.Resources, "run", heavier.RunId,
            sample => CpuReadbackMatches(sample, initialHeavyLimit));
        Assert.True(RequireAppliedAt(RequireEffectiveRunLimit(restoredLight, "cpu", perScope)) >= reducedAt + TimeSpan.FromSeconds(9));
        Assert.True(RequireAppliedAt(RequireEffectiveRunLimit(restoredHeavy, "cpu", perScope)) >= reducedAt + TimeSpan.FromSeconds(9));
        Assert.Equal(RunState.Running, (await InspectAsync(package.Runs, lighter.RunId, cancellation)).State);
        Assert.Equal(RunState.Running, (await InspectAsync(package.Runs, heavier.RunId, cancellation)).State);
        Assert.True((await package.DrainAsync(lighter.RunId, cancellation)).Exit.GroupEmptyVerified);
        Assert.True((await package.DrainAsync(heavier.RunId, cancellation)).Exit.GroupEmptyVerified);

        static bool CpuReadbackMatches(ResourceSnapshot snapshot, LimitState original) => snapshot.Limits.Any(limit =>
            limit.Dimension == "cpu" && limit.Status == LimitStatus.Effective && limit.ReadbackValue == original.ReadbackValue);
    }

    private static async Task<WeightedRunFrame> AwaitWeightedReadbackAsync(ResourcePackage package,
        Run lighter, Run heavier, uint latestBudget, CancellationToken cancellation)
    {
        WeightedRunFrame? reduced = null;
        await TestNode.WaitAsync(async () =>
        {
            reduced = await ReadWeightedRunFrameAsync(package, lighter, heavier, latestBudget, cancellation);
            return reduced is not null;
        }, NativeBound, "both contending Run scopes to read back weighted native CPU shares under the same host budget");
        return Assert.IsType<WeightedRunFrame>(reduced);
    }

    private static async Task<WeightedRunFrame?> ReadWeightedRunFrameAsync(ResourcePackage package, Run lighter, Run heavier,
        uint latestBudget, CancellationToken cancellation)
    {
        var light = await ReadInstalledBudgetAsync(package.Resources, "run", lighter.RunId, cancellation);
        var heavy = await ReadInstalledBudgetAsync(package.Resources, "run", heavier.RunId, cancellation);
        var host = await ReadInstalledBudgetAsync(package.Resources, "node", null, cancellation);
        if (light.Stale || heavy.Stale || host.Stale || light.SampleEpoch != heavy.SampleEpoch || light.SampleEpoch != host.SampleEpoch
            || light.SampleSequence != heavy.SampleSequence || light.SampleSequence != host.SampleSequence
            || !host.HasBudgetCpuMillicores || host.BudgetCpuMillicores > latestBudget
            || !light.HasManagedCpuMillicores || !heavy.HasManagedCpuMillicores) return null;

        var lightLimit = Assert.Single(light.Limits, entry => entry.Dimension == "cpu");
        var heavyLimit = Assert.Single(heavy.Limits, entry => entry.Dimension == "cpu");
        if (lightLimit.Status != LimitStatus.Effective || heavyLimit.Status != LimitStatus.Effective) return null;
        ulong lightReadback = ReadNumericLimit(lightLimit.ReadbackValue);
        ulong heavyReadback = ReadNumericLimit(heavyLimit.ReadbackValue);
        ulong total = lightReadback + heavyReadback;
        ulong weightedTarget = 3 * lightReadback;
        ulong weightDifference = Math.Max(heavyReadback, weightedTarget) - Math.Min(heavyReadback, weightedTarget);
        uint granularity = OperatingSystem.IsWindows() ? (host.HostCpuMillicores + 9999) / 10_000 : 1;
        if (lightReadback == 0 || weightDifference > 4 * granularity || total > host.BudgetCpuMillicores
            || light.ManagedCpuMillicores == 0 || heavy.ManagedCpuMillicores == 0) return null;
        Assert.Equal(lightLimit.AppliedValue, lightLimit.ReadbackValue);
        Assert.Equal(heavyLimit.AppliedValue, heavyLimit.ReadbackValue);
        return new(light, heavy, lightLimit, heavyLimit, host.BudgetCpuMillicores);
    }

    private static async Task RequireWeightedRunDemandAsync(ResourcePackage package, Run lighter, Run heavier,
        WeightedRunFrame shared, uint latestBudget, CancellationToken cancellation)
    {
        WeightedRunFrame? baseline = null;
        WeightedRunFrame? observed = null;
        await TestNode.WaitAsync(async () =>
        {
            var current = await ReadWeightedRunFrameAsync(package, lighter, heavier, latestBudget, cancellation);
            if (current is null || !current.LightSnapshot.HasCumulativeCpuUsec || !current.HeavySnapshot.HasCumulativeCpuUsec) return false;
            Assert.Equal(shared.Light.Scope, current.Light.Scope);
            Assert.Equal(shared.Heavy.Scope, current.Heavy.Scope);

            // The CPU counters are sampled before the controller applies limits for that frame.
            // Never use a frame from before either native grant as the start of the usage interval.
            if (ProtoTime.ToDateTimeOffset(current.LightSnapshot.SampledAt) is not { } sampledAt
                || sampledAt <= RequireAppliedAt(current.Light) || sampledAt <= RequireAppliedAt(current.Heavy)) return false;
            if (baseline is null || baseline.LightSnapshot.SampleEpoch != current.LightSnapshot.SampleEpoch
                || !SameGrant(baseline.Light, current.Light) || !SameGrant(baseline.Heavy, current.Heavy))
            {
                baseline = current;
                return false;
            }

            if (current.LightSnapshot.SampleSequence < baseline.LightSnapshot.SampleSequence + 2) return false;
            observed = current;
            return true;
        }, NativeBound, "two fresh native CPU samples under the same weighted grants");

        var start = Assert.IsType<WeightedRunFrame>(baseline);
        var end = Assert.IsType<WeightedRunFrame>(observed);
        TestContext.Current.TestOutputHelper?.WriteLine("Weighted CPU start " + DescribeFrame(start));
        TestContext.Current.TestOutputHelper?.WriteLine("Weighted CPU end " + DescribeFrame(end));
        double light = CpuDemand(start.LightSnapshot, end.LightSnapshot);
        double heavy = CpuDemand(start.HeavySnapshot, end.HeavySnapshot);
        ulong lightCap = ReadNumericLimit(start.Light.ReadbackValue);
        ulong heavyCap = ReadNumericLimit(start.Heavy.ReadbackValue);
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"Weighted CPU demand was {light:F3}m under {lightCap}m for the light Run and {heavy:F3}m under {heavyCap}m for the heavy Run."));
        Assert.InRange(light, lightCap * 0.55, lightCap + 135.0);
        Assert.InRange(heavy, heavyCap * 0.55, heavyCap + 135.0);
        Assert.True(heavy > light * 1.5, $"Sampled native CPU demand was {light:F0}m and {heavy:F0}m.");

        static bool SameGrant(LimitState before, LimitState after) => before.Scope == after.Scope
            && before.ReadbackValue == after.ReadbackValue && Equals(before.AppliedAt, after.AppliedAt)
            && Equals(before.DesiredRevision, after.DesiredRevision);

        static string DescribeFrame(WeightedRunFrame frame) => FormattableString.Invariant($"""
            epoch {frame.LightSnapshot.SampleEpoch}, sequence {frame.LightSnapshot.SampleSequence}, sampled {ProtoTime.ToDateTimeOffset(frame.LightSnapshot.SampledAt):O}, budget {frame.Budget}m
            light {frame.Light.Scope}: {frame.LightSnapshot.CumulativeCpuUsec}us at {frame.Light.ReadbackValue}m, applied {RequireAppliedAt(frame.Light):O}
            heavy {frame.Heavy.Scope}: {frame.HeavySnapshot.CumulativeCpuUsec}us at {frame.Heavy.ReadbackValue}m, applied {RequireAppliedAt(frame.Heavy):O}
            """);

        static double CpuDemand(ResourceSnapshot before, ResourceSnapshot after)
        {
            Assert.True(before.HasCumulativeCpuUsec && after.CumulativeCpuUsec > before.CumulativeCpuUsec);
            var start = Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(before.SampledAt));
            var end = Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(after.SampledAt));
            Assert.True(end > start);
            return (after.CumulativeCpuUsec - before.CumulativeCpuUsec) / (end - start).TotalMilliseconds;
        }
    }

    private sealed record WeightedRunFrame(ResourceSnapshot LightSnapshot, ResourceSnapshot HeavySnapshot,
        LimitState Light, LimitState Heavy, uint Budget);

    private static DateTimeOffset RequireAppliedAt(LimitState limit) =>
        Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(limit.AppliedAt));

    private static ResourcePolicy ScopePolicy(uint cpu) => new()
    {
        CpuMaxMillicores = cpu,
        MemoryMaxBytes = ResourceBytes(512),
        ExpectedMemoryBytes = ResourceBytes(80),
        MaxConcurrentRuns = 4,
        PressureAction = PressureAction.Throttle,
    };

    private static RunServiceStartRequest BuildAdmissionHold(ResourcePackage package, ResourcePackageScope scope,
        string marker, uint cpu, int priority, bool preemptible) => BuildAdmissionStart(package, scope, cpu, priority, preemptible,
        [scope.Payload, "hold", "--hold-ms", "110000", "--marker", AdmissionMarker(scope, marker)]);

    private static RunServiceStartRequest BuildAdmissionCpu(ResourcePackage package, ResourcePackageScope scope, uint cpu) =>
        BuildAdmissionStart(package, scope, cpu, 0, false,
            [scope.Payload, "cpu", "--threads", "2", "--iterations", "20000000000"]);

    private static RunServiceStartRequest BuildAdmissionStart(ResourcePackage package, ResourcePackageScope scope, uint cpu,
        int priority, bool preemptible, string[] argv)
    {
        var request = BuildStart(scope.Sandbox, package.Epoch, argv);
        request.TerminalMode = TerminalMode.Pipes;
        request.TerminalSize = null;
        request.Environment.Clear();
        request.RequestedResources = new ResourcePolicy
        {
            CpuMaxMillicores = cpu,
            MemoryMaxBytes = ResourceBytes(128),
            Priority = priority,
            Preemptible = preemptible,
            PressureAction = scope.Sandbox.Config.Resources.PressureAction,
        };
        return request;
    }

    private static string AdmissionMarker(ResourcePackageScope scope, string marker) => Path.Combine(scope.Working, marker + ".log");

    private static Task WaitForAdmissionMarkerAsync(ResourcePackageScope scope, string marker) => TestNode.WaitAsync(
        () => ReadLines(AdmissionMarker(scope, marker)).Any(line => line.StartsWith("ready ", StringComparison.Ordinal)), NativeBound,
        $"the {marker} payload marker");

    private static ArcError AssertInstalledBudgetRefusal(RunServiceStartResponse response, string reason, Id? correlationId = null)
    {
        Assert.Null(response.Value);
        var error = Assert.IsType<ArcError>(response.Error);
        AssertResourceRefusal(error, reason);
        if (correlationId is not null)
        {
            Assert.Equal(correlationId, response.Meta.CorrelationId);
            Assert.Equal(correlationId, error.CorrelationId);
        }
        return error;
    }

    private static async Task<Operation> QueryAdmissionRefusalAsync(ResourcePackage package, Id commandId, string reason,
        CancellationToken cancellation)
    {
        var meta = Query();
        var reply = await package.Node.GetOperationAsync(new NodeServiceGetOperationRequest
        {
            Meta = meta,
            OwnerEpoch = package.Epoch,
            CommandId = commandId,
        }, deadline: Deadline, cancellationToken: cancellation);
        var operation = Value(reply.Value, reply.Error).Operation;
        Assert.Equal(meta.CorrelationId, reply.Meta.CorrelationId);
        Assert.Equal(meta.CorrelationId, operation.Error.CorrelationId);
        AssertResourceRefusal(operation.Error, reason);
        return operation;
    }

    private static async Task VerifyReplayedAdmissionRefusalAsync(ResourcePackage package, RunServiceStartRequest original,
        string reason, ArcError refusal, Operation stored, CancellationToken cancellation)
    {
        var retry = original.Clone();
        retry.Meta.CorrelationId = CommandIds.New();
        var replay = AssertInstalledBudgetRefusal(await package.StartAsync(retry, cancellation), reason, retry.Meta.CorrelationId);
        Assert.NotEqual(refusal.CorrelationId, replay.CorrelationId);
        var expectedError = refusal.Clone();
        expectedError.CorrelationId = replay.CorrelationId.Clone();
        Assert.Equal(expectedError, replay);

        var reconciled = await QueryAdmissionRefusalAsync(package, original.Meta.CommandId, reason, cancellation);
        Assert.NotEqual(stored.Error.CorrelationId, reconciled.Error.CorrelationId);
        var expectedOperation = stored.Clone();
        expectedOperation.Error.CorrelationId = reconciled.Error.CorrelationId.Clone();
        Assert.Equal(expectedOperation, reconciled);
    }

    private sealed record ResourcePackageScope(Sandbox Sandbox, string Working, string Payload);

    private sealed class ResourcePackage(TestNode fixture, Process process, NodeChannel channel, Id epoch) : IAsyncDisposable
    {
        private readonly List<ResourcePackageScope> _scopes = [];

        internal TestNode Fixture { get; } = fixture;
        internal Id Epoch { get; } = epoch;
        internal NodeService.NodeServiceClient Node { get; } = new(channel.CallInvoker);
        internal RunService.RunServiceClient Runs { get; } = new(channel.CallInvoker);
        internal ResourceService.ResourceServiceClient Resources { get; } = new(channel.CallInvoker);

        internal static async Task<ResourcePackage> StartAsync(Action<ArcForges.Contracts.Node.V1.PolicyDocument>? seed = null)
        {
            var fixture = TestNode.Create(OperatingSystem.IsLinux() ? TestNode.DiskParent : null);
            Process? process = null;
            NodeChannel? channel = null;
            try
            {
                PrepareDataRoot(fixture.DataRoot);
                fixture.LiveMachine = true;
                if (seed is not null) fixture.SeedPolicy(seed);
                process = await fixture.StartNodeAsync();
                channel = OpenChannel(fixture);
                var handshake = await HandshakeAsync(new NodeService.NodeServiceClient(channel.CallInvoker));
                return new ResourcePackage(fixture, process, channel, handshake.OwnerEpoch);
            }
            catch
            {
                try
                {
                    if (channel is not null) await channel.DisposeAsync();
                    if (process is not null) await StopNodeAsync(fixture, process);
                }
                finally
                {
                    await fixture.DisposeAsync();
                }

                throw;
            }
        }

        internal async Task<ResourcePackageScope> CreateScopeAsync(string name, ResourcePolicy resources, CancellationToken cancellation)
        {
            bool windows = OperatingSystem.IsWindows();
            var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
            var reply = await sandboxes.CreateAsync(new SandboxServiceCreateRequest
            {
                Meta = Mutation(),
                OwnerEpoch = Epoch,
                DisplayName = name,
                Config = new SandboxConfig
                {
                    ProfileId = windows ? MxcProfileAdmission.WindowsProfileId : MxcProfileAdmission.LinuxProfileId,
                    ProfileVersion = windows ? MxcProfileAdmission.WindowsProfileRevision : MxcProfileAdmission.LinuxProfileRevision,
                    Network = new NetworkPolicy { Egress = NetworkMode.Deny, Ingress = NetworkMode.Deny, HostLoopback = false },
                    Resources = resources,
                },
            }, deadline: Deadline, cancellationToken: cancellation);
            var sandbox = Value(reply.Value, reply.Error).Sandbox;
            Assert.Equal(SandboxState.Ready, sandbox.State);
            var working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
            Directory.CreateDirectory(working);
            var scope = new ResourcePackageScope(sandbox, working, CopySecurityTestLoad(working));
            _scopes.Add(scope);
            return scope;
        }

        internal async Task SetNodePolicyAsync(ResourcePolicy policy, CancellationToken cancellation)
        {
            var before = await ReadInstalledBudgetAsync(Resources, "node", null, cancellation);
            var result = await Resources.SetPolicyAsync(new ResourceServiceSetPolicyRequest
            {
                Meta = Mutation(before.PolicyRevision),
                ScopeKind = "node",
                OwnerEpoch = Epoch,
                Policy = policy,
            }, deadline: Deadline, cancellationToken: cancellation);
            var value = Value(result.Value, result.Error);
            Assert.True(value.Snapshot.PolicyRevision.Value > before.PolicyRevision.Value);
            RequireSameResourceReceipt(value.Operation, await OperationAsync(Node, Epoch, value.Operation.CommandId));
        }

        internal async Task<RunServiceStartResponse> StartAsync(RunServiceStartRequest request, CancellationToken cancellation) =>
            await Runs.StartAsync(request, deadline: Deadline, cancellationToken: cancellation);

        internal async Task<Run> StartRunningAsync(RunServiceStartRequest request, CancellationToken cancellation)
        {
            var reply = await StartAsync(request, cancellation);
            var run = Value(reply.Value, reply.Error).Run;
            return await WaitForStateAsync(Fixture, Runs, run.RunId, RunState.Running, cancellation);
        }

        internal async Task<Run> DrainAsync(Id runId, CancellationToken cancellation)
        {
            Run? settled = null;
            await TestNode.WaitAsync(async () =>
            {
                var current = await InspectAsync(Runs, runId, cancellation);
                if (current.State is RunState.Exited or RunState.Failed)
                {
                    settled = current;
                    return true;
                }

                if (current.State is RunState.Running or RunState.Starting)
                {
                    var reply = await Runs.StopAsync(BuildStop(Epoch, current), deadline: Deadline, cancellationToken: cancellation);
                    if (reply.Error?.Code != "revision_mismatch") _ = Value(reply.Value, reply.Error);
                }

                return false;
            }, NativeBound, $"verified drain for Run {Hex(runId)}");
            var terminal = Assert.IsType<Run>(settled);
            Assert.True(terminal.Exit.GroupEmptyVerified);
            return terminal;
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!process.HasExited)
                {
                    foreach (var scope in _scopes)
                    {
                        var reply = await Runs.ListAsync(new RunServiceListRequest { Meta = Query(), SandboxId = scope.Sandbox.SandboxId }, deadline: Deadline);
                        foreach (var run in Value(reply.Value, reply.Error).Runs)
                        {
                            if (run.State is not (RunState.Exited or RunState.Failed)) await DrainAsync(run.RunId, CancellationToken.None);
                        }
                    }
                }
            }
            finally
            {
                try
                {
                    await channel.DisposeAsync();
                    await StopNodeAsync(Fixture, process);
                    RemoveFixtureOwnerKey(Fixture.DataRoot, Epoch);
                }
                finally
                {
                    await Fixture.DisposeAsync();
                }
            }
        }
    }
}
