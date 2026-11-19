// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Tests;
using V1 = ArcForges.Contracts.Node.V1;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    private const string PressureChangeEvent = "sandbox.resources.pressure";
    private const string PressureStopEvent = "sandbox.resources.pressure_stop";
    private const string CriticalAdmissionReason = "resource_pressure_critical";
    private const int PressureAllocationMiB = 2048;

    [Fact(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task InstalledPressurePersistsBeforeStoppingOneEligibleRunAndLeavesItsPeersRunning()
    {
        var cancellation = TestContext.Current.CancellationToken;
        cancellation.ThrowIfCancellationRequested();
        RequireExtractedPackage();

        var sample = ReadFreshResourceHost();
        ulong total = Assert.IsType<ulong>(sample.PhysicalTotalBytes);
        ulong baseline = Assert.IsType<ulong>(sample.PhysicalAvailableBytes);
        // Elevate only the isolated Node's thresholds. The fixed 2 GiB stimulus leaves substantial actual host headroom.
        Assert.True(baseline >= ResourceBytes(PressureAllocationMiB + 2048),
            $"Native pressure fixture requires 4096 MiB available before the bounded allocation, observed {baseline >> 20} MiB.");
        ulong critical = baseline - ResourceBytes(1536);
        var thresholds = new V1.PressureThresholds
        {
            CriticalAvailableFraction = critical / (double)total,
            PressureAvailableFraction = (critical + ResourceBytes(256)) / (double)total,
            TightAvailableFraction = (critical + ResourceBytes(512)) / (double)total,
            MemoryPsiSomeAvg10 = 99,
        };
        await using var package = await ResourcePackage.StartAsync(policy => policy.Resources.Pressure = thresholds);
        await package.SetNodePolicyAsync(new ResourcePolicy
        {
            CpuMaxMillicores = 1400,
            MemoryMaxBytes = ResourceBytes(768),
            PressureAction = PressureAction.Throttle,
        }, cancellation);
        var candidates = ScopePolicy(600);
        candidates.PressureAction = PressureAction.StopPreemptible;
        var eligible = await package.CreateScopeAsync("Pressure eligible Sandbox", candidates, cancellation);
        var protectedScope = await package.CreateScopeAsync("Pressure protected Sandbox", ScopePolicy(600), cancellation);

        var older = await package.StartRunningAsync(BuildAdmissionHold(package, eligible, "older-victim", 180, -10, true), cancellation);
        await WaitForAdmissionMarkerAsync(eligible, "older-victim");
        var victimRequest = BuildAdmissionHold(package, eligible, "newest-victim", 180, -10, true);
        var newest = await package.StartRunningAsync(victimRequest, cancellation);
        await WaitForAdmissionMarkerAsync(eligible, "newest-victim");
        var protectedRun = await package.StartRunningAsync(BuildAdmissionHold(package, protectedScope, "protected-peer", 180, 0, false), cancellation);
        await WaitForAdmissionMarkerAsync(protectedScope, "protected-peer");
        var victimOwner = ReadSupervisor(package.Fixture.DataRoot, newest);
        var protectedOwner = ReadSupervisor(package.Fixture.DataRoot, protectedRun);
        Assert.NotEqual(victimOwner.Boundary, protectedOwner.Boundary);
        using var windowsVictim = OperatingSystem.IsWindows() ? HoldWindowsResourceOwner(victimOwner) : null;
        using var windowsProtected = OperatingSystem.IsWindows() ? HoldWindowsResourceOwner(protectedOwner) : null;
        using var linuxVictim = OperatingSystem.IsLinux() ? OpenResourceCgroup(victimOwner) : null;
        using var linuxProtected = OperatingSystem.IsLinux() ? OpenResourceCgroup(protectedOwner) : null;
        var initial = await WaitForResourceBudgetAsync(package.Resources, "node", null, current => current.Pressure == "normal");
        int firstChange = TestNode.LogEvents(package.Fixture.NodeLog, PressureChangeEvent).Count;
        Assert.Empty(TestNode.LogEvents(package.Fixture.NodeLog, PressureStopEvent));

        ulong lowestAvailable;
        DateTimeOffset rawCriticalAt;
        await using (var shortPulse = new InstalledPressurePulse(package.Fixture, "short", critical))
        {
            long crossed = await shortPulse.WaitForCriticalAsync(cancellation);
            var raw = await WaitForPressureChangeAsync(package.Fixture, firstChange,
                entry => PressureState(entry, "raw") == "critical", TimeSpan.FromSeconds(3));
            Assert.NotEqual("critical", PressureState(raw, "effective"));
            rawCriticalAt = PressureEventTime(raw);
            _ = shortPulse.RequireAvailableHeadroom();
            await shortPulse.ReleaseAsync(cancellation);
            Assert.True(Stopwatch.GetElapsedTime(crossed) < TimeSpan.FromSeconds(4.5), "The brief native pulse must not span pressure persistence.");
            lowestAvailable = shortPulse.LowestAvailable;
        }

        var afterShort = await WaitForResourceBudgetAsync(package.Resources, "node", null,
            current => current.SampleSequence > initial.SampleSequence && current.Pressure == "normal");
        await WaitForPressureChangeAsync(package.Fixture, firstChange,
            entry => PressureEventTime(entry) > rawCriticalAt && PressureState(entry, "raw") == "normal"
                && PressureState(entry, "effective") == "normal", NativeBound);
        Assert.Empty(TestNode.LogEvents(package.Fixture.NodeLog, PressureStopEvent));
        Assert.Equal(RunState.Running, (await InspectAsync(package.Runs, newest.RunId, cancellation)).State);

        int sustainedChanges = TestNode.LogEvents(package.Fixture.NodeLog, PressureChangeEvent).Count;
        await using (var sustained = new InstalledPressurePulse(package.Fixture, "sustained", critical))
        {
            _ = await sustained.WaitForCriticalAsync(cancellation);
            var crossed = DateTimeOffset.UtcNow;
            TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
                $"Independent native available-memory crossing at {crossed:O}; waiting up to 3s for Node raw Critical."));
            var firstRaw = await WaitForPressureChangeAsync(package.Fixture, sustainedChanges,
                entry => PressureState(entry, "raw") == "critical", TimeSpan.FromSeconds(3));
            var detected = PressureEventTime(firstRaw) - crossed;
            TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
                $"Node first observed raw Critical at sample {PressureSampleSequence(firstRaw)}, {detected.TotalMilliseconds:F0}ms after the independent crossing."));
            Assert.True(detected <= TimeSpan.FromSeconds(3), "The first coherent Node raw Critical observation exceeded the 3s diagnostic bound.");
            Assert.NotEqual("critical", PressureState(firstRaw, "effective"));

            JsonElement decision = default;
            await TestNode.WaitAsync(async () =>
            {
                sustained.RequireAvailableHeadroom();
                var stops = TestNode.LogEvents(package.Fixture.NodeLog, PressureStopEvent);
                if (stops.Count == 0) return false;
                decision = Assert.Single(stops);
                Assert.Equal(Hex(newest.RunId), PressureState(decision, "runId"));
                return (await InspectAsync(package.Runs, newest.RunId, cancellation)).State
                    is RunState.Stopping or RunState.Draining or RunState.Exited;
            }, TimeSpan.FromSeconds(12), "one authorized native pressure stop");
            await sustained.ReleaseAsync(cancellation);
            lowestAvailable = Math.Min(lowestAvailable, sustained.LowestAvailable);
            RequirePressureDecisionTiming(package.Fixture, sustainedChanges, crossed, decision);
        }

        // The observed effective level retains Critical after the physical release. Even interactive admissions are refused.
        var refusedRequest = BuildAdmissionHold(package, protectedScope, "critical-refused", 180, 10, false);
        await WaitForResourceBudgetAsync(package.Resources, "node", null,
            current => current.SampleSequence > afterShort.SampleSequence && current.Pressure == "critical");
        var refused = AssertInstalledBudgetRefusal(await package.StartAsync(refusedRequest, cancellation), CriticalAdmissionReason);
        var receipt = await OperationAsync(package.Node, package.Epoch, refusedRequest.Meta.CommandId);
        Assert.Equal(OperationState.Failed, receipt.State);
        Assert.Equal(EffectCertainty.DidNotHappen, receipt.Effect);
        Assert.False(File.Exists(AdmissionMarker(protectedScope, "critical-refused")));

        var victim = await WaitForStateAsync(package.Fixture, package.Runs, newest.RunId, RunState.Exited, cancellation);
        Assert.True(victim.Exit.GroupEmptyVerified);
        Assert.Equal("pressure_preempted", victim.Exit.TerminationReason);
        var completedStart = await OperationAsync(package.Node, package.Epoch, victimRequest.Meta.CommandId);
        Assert.Equal(OperationState.Succeeded, completedStart.State);
        Assert.Equal(EffectCertainty.Happened, completedStart.Effect);
        Assert.Equal(newest.RunId, completedStart.AggregateId);
        if (OperatingSystem.IsWindows())
        {
            var drained = ReadWindowsJobResource(package.Fixture.DataRoot, newest, victimOwner, "windows-drained.json");
            Assert.Equal(victimOwner.Pid, Assert.Single(drained.ProcessIds));
            Assert.Empty(drained.PayloadProcessIds);
            Assert.True(drained.OutputDrainCompleted);
            Assert.NotNull(windowsVictim);
            Assert.True(windowsVictim.HasExited);
            Assert.NotNull(windowsProtected);
            Assert.False(windowsProtected.HasExited);
        }
        else if (OperatingSystem.IsLinux() && linuxVictim is not null && linuxProtected is not null)
        {
            Assert.True(linuxVictim.IsEmpty());
            Assert.False(linuxProtected.IsEmpty());
        }

        var recovered = await WaitForResourceBudgetAsync(package.Resources, "node", null,
            current => current.SampleSequence > afterShort.SampleSequence && current.Pressure == "normal");
        Assert.True(recovered.HasBudgetMemoryBytes);
        Assert.Single(TestNode.LogEvents(package.Fixture.NodeLog, PressureStopEvent));
        Assert.Equal(RunState.Running, (await InspectAsync(package.Runs, older.RunId, cancellation)).State);
        Assert.Equal(RunState.Running, (await InspectAsync(package.Runs, protectedRun.RunId, cancellation)).State);
        Assert.Equal(new[] { Hex(older.RunId), Hex(newest.RunId) }.Order(StringComparer.Ordinal),
            (await ListAsync(package.Runs, eligible.Sandbox.SandboxId)).Select(run => Hex(run.RunId)).Order(StringComparer.Ordinal));
        Assert.Equal(protectedRun.RunId, Assert.Single(await ListAsync(package.Runs, protectedScope.Sandbox.SandboxId)).RunId);
        Assert.Single(ReadLines(AdmissionMarker(eligible, "newest-victim")), line => line.StartsWith("start ", StringComparison.Ordinal));

        var replay = AssertInstalledBudgetRefusal(await package.StartAsync(refusedRequest, cancellation), CriticalAdmissionReason);
        Assert.Equal(refused.Details, replay.Details);
        Assert.False(File.Exists(AdmissionMarker(protectedScope, "critical-refused")));
        var laterIntent = refusedRequest.Clone();
        laterIntent.Meta = Mutation(protectedScope.Sandbox.Revision);
        var later = await package.StartRunningAsync(laterIntent, cancellation);
        await WaitForAdmissionMarkerAsync(protectedScope, "critical-refused");
        Assert.True((await package.DrainAsync(later.RunId, cancellation)).Exit.GroupEmptyVerified);
        Assert.True((await package.DrainAsync(older.RunId, cancellation)).Exit.GroupEmptyVerified);
        Assert.True((await package.DrainAsync(protectedRun.RunId, cancellation)).Exit.GroupEmptyVerified);
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"Native available memory bottomed at {lowestAvailable >> 20} MiB under a fixture Critical threshold of {critical >> 20} MiB. One verified pressure stop completed; both peer Runs survived."));
    }

    private static string? PressureState(JsonElement entry, string field) =>
        entry.GetProperty("fields").TryGetProperty(field, out var value) ? value.GetString() : null;

    private static DateTimeOffset PressureEventTime(JsonElement entry) =>
        DateTimeOffset.Parse(entry.GetProperty("at").GetString()!, CultureInfo.InvariantCulture);

    private static ulong PressureSampleSequence(JsonElement entry) => entry.GetProperty("fields").GetProperty("sampleSequence").GetUInt64();

    private static void RequirePressureDecisionTiming(TestNode fixture, int offset, DateTimeOffset crossed, JsonElement decision)
    {
        var stopSample = PressureSampleSequence(decision);
        var transitions = TestNode.LogEvents(fixture.NodeLog, PressureChangeEvent).Skip(offset)
            .Where(entry => PressureSampleSequence(entry) <= stopSample).ToArray();
        int effectiveIndex = Array.FindIndex(transitions, entry => PressureState(entry, "effective") == "critical");
        Assert.True(effectiveIndex >= 0, $"Stop sample {stopSample} has no matching effective Critical transition after physical crossing {crossed:O}.");

        // The raw stream records changes. A noncritical raw observation resets persistence, even if the OS observer crossed earlier.
        int rawIndex = effectiveIndex;
        while (rawIndex > 0 && PressureState(transitions[rawIndex - 1], "raw") == "critical") rawIndex--;
        var raw = transitions[rawIndex];
        var effective = transitions[effectiveIndex];
        var rawSample = PressureSampleSequence(raw);
        var effectiveSample = PressureSampleSequence(effective);
        var rawAt = PressureEventTime(raw);
        var persistence = PressureEventTime(effective) - rawAt;
        var stopReaction = PressureEventTime(decision) - rawAt;
        var details = FormattableString.Invariant(
            $"Physical crossing to contiguous raw Critical {(rawAt - crossed).TotalMilliseconds:F0}ms (sample {rawSample}), raw to effective Critical {persistence.TotalMilliseconds:F0}ms (sample {effectiveSample}), raw to Stop {stopReaction.TotalMilliseconds:F0}ms (sample {stopSample}).");
        TestContext.Current.TestOutputHelper?.WriteLine(details);
        Assert.Equal("critical", PressureState(raw, "raw"));
        Assert.Equal("critical", PressureState(effective, "raw"));
        Assert.True(rawSample < effectiveSample, details);
        Assert.True(stopSample == effectiveSample, details);
        Assert.InRange(persistence.TotalSeconds, 4.25, 6.25);
        Assert.InRange(stopReaction.TotalSeconds, 4.25, 6.25);
    }

    private static async Task<JsonElement> WaitForPressureChangeAsync(TestNode fixture, int offset,
        Func<JsonElement, bool> predicate, TimeSpan bound)
    {
        JsonElement selected = default;
        await TestNode.WaitAsync(() =>
        {
            foreach (var entry in TestNode.LogEvents(fixture.NodeLog, PressureChangeEvent).Skip(offset))
            {
                if (!predicate(entry)) continue;
                selected = entry;
                return true;
            }

            return false;
        }, bound, "the exact raw and effective native pressure transition");
        return selected;
    }

    private sealed class InstalledPressurePulse : IAsyncDisposable
    {
        private readonly Process _process;
        private readonly string _release;
        private readonly ulong _critical;

        internal InstalledPressurePulse(TestNode fixture, string phase, ulong critical)
        {
            _critical = critical;
            _release = Path.Combine(fixture.Root, $"pressure-{phase}-release");
            _process = fixture.Start(TestNode.TestLoad, ["mem-ramp", "--target-mb", PressureAllocationMiB.ToString(CultureInfo.InvariantCulture),
                "--step-mb", "64", "--step-ms", "20", "--hold-ms", "45000", "--until-file", _release]);
            Assert.NotNull(ProcessIdentity.Capture(_process.Id));
        }

        internal ulong LowestAvailable { get; private set; } = ulong.MaxValue;

        internal async Task<long> WaitForCriticalAsync(CancellationToken cancellation)
        {
            var wait = Stopwatch.StartNew();
            while (true)
            {
                cancellation.ThrowIfCancellationRequested();
                Assert.False(_process.HasExited, "The fixed allocator ended before crossing the native pressure threshold.");
                if (RequireAvailableHeadroom() < _critical) return Stopwatch.GetTimestamp();
                Assert.True(wait.Elapsed < NativeBound, $"Native available memory never crossed the calibrated {_critical >> 20} MiB threshold.");
                await Task.Delay(50, cancellation);
            }
        }

        internal ulong RequireAvailableHeadroom()
        {
            var available = Assert.IsType<ulong>(ReadFreshResourceHost().PhysicalAvailableBytes);
            LowestAvailable = Math.Min(LowestAvailable, available);
            Assert.True(available >= ResourceBytes(1536), $"The native host has only {available >> 20} MiB available; release the fixture allocator.");
            return available;
        }

        internal async Task ReleaseAsync(CancellationToken cancellation)
        {
            await File.WriteAllTextAsync(_release, "release", cancellation);
            await _process.WaitForExitAsync(cancellation).WaitAsync(NativeBound, cancellation);
            Assert.Equal(0, _process.ExitCode);
        }

        public async ValueTask DisposeAsync()
        {
            if (_process.HasExited) return;
            _process.Kill();
            await _process.WaitForExitAsync(CancellationToken.None).WaitAsync(NativeBound);
        }
    }
}
