// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Sandbox.V2;
using ArcForges.Node.Platform;
using ArcForges.Node.Platform.Linux;
using ArcForges.Node.Platform.Linux.Mxc;
using ArcForges.Node.Platform.Windows;
using ArcForges.Node.Platform.Windows.Mxc;
using ArcForges.Tests;

namespace ArcForges.ClosedLoop.Tests;

public sealed partial class MxcRunServiceTests
{
    private const int ManagedRampMiB = 80;
    private const int UnmanagedRampMiB = 128;
    private const int LinuxCacheMiB = 24;

    [Fact(Timeout = 150_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task InstalledResourcesObserveOwnedNativeScopesAndKeepHostUsageSeparate()
    {
        var cancellation = TestContext.Current.CancellationToken;
        cancellation.ThrowIfCancellationRequested();
        RequireExtractedPackage();
        // A disk-backed Linux root makes the generated file reclaimable cache instead of tmpfs shared memory.
        await using var fixture = TestNode.Create(OperatingSystem.IsLinux() ? TestNode.DiskParent : null);
        PrepareDataRoot(fixture.DataRoot);
        var startingAt = DateTimeOffset.UtcNow;
        var nodeProcess = await fixture.StartNodeAsync();
        await using var channel = OpenChannel(fixture);
        var node = new NodeService.NodeServiceClient(channel.CallInvoker);
        var sandboxes = new SandboxService.SandboxServiceClient(channel.CallInvoker);
        var runs = new RunService.RunServiceClient(channel.CallInvoker);
        var resources = new ResourceService.ResourceServiceClient(channel.CallInvoker);
        Id? ownerEpoch = null;
        Run? activeRun = null;
        Process? unmanaged = null;
        string? releaseManaged = null;
        var releaseUnmanaged = Path.Combine(fixture.Root, "resource-host-finish");
        try
        {
            ownerEpoch = (await HandshakeAsync(node)).OwnerEpoch;
            var sandbox = await CreateSandboxAsync(sandboxes, ownerEpoch);
            var baseline = await WaitForResourceBudgetAsync(resources, "node", null,
                snapshot => snapshot.HasUnmanagedMemoryBytes && snapshot.HasBudgetMemoryBytes);

            var unmanagedReport = Path.Combine(fixture.Root, "resource-host-report.json");
            unmanaged = fixture.Start(TestNode.TestLoad, MemoryRampArguments(UnmanagedRampMiB, releaseUnmanaged, unmanagedReport));
            var unmanagedIdentity = ProcessIdentity.Capture(unmanaged.Id);
            Assert.NotNull(unmanagedIdentity);
            await TestNode.WaitAsync(() =>
            {
                unmanaged.Refresh();
                return !unmanaged.HasExited && unmanaged.WorkingSet64 >= (long)ResourceBytes(UnmanagedRampMiB);
            }, NativeBound, "the independent host-owned memory load");

            var working = Path.Combine(sandbox.DataLocation, "work", "quoted directory");
            Directory.CreateDirectory(working);
            var payload = CopySecurityTestLoad(working);
            releaseManaged = Path.Combine(working, "resource-run-finish");
            var managedReport = Path.Combine(working, "resource-run-report.json");
            var linuxCache = Path.Combine(working, "resource-page-cache.txt");
            string[] ramp = [payload, .. MemoryRampArguments(ManagedRampMiB, releaseManaged, managedReport)];
            // The short-lived writer's charge belongs to the same Run as the subsequently held memory ramp.
            string[] argv = OperatingSystem.IsLinux()
                ? ["/usr/bin/dash", "-c", "\"$1\" output --bytes \"$2\" --line-bytes 4096 > \"$3\" && shift 3 && exec \"$@\"",
                    "resource-fixture", payload, ResourceBytes(LinuxCacheMiB).ToString(CultureInfo.InvariantCulture), linuxCache, .. ramp]
                : ramp;
            var request = BuildStart(sandbox, ownerEpoch, argv);
            request.TerminalMode = TerminalMode.Pipes;
            request.TerminalSize = null;
            request.Environment.Clear();
            var start = await runs.StartAsync(request, deadline: Deadline, cancellationToken: cancellation);
            activeRun = Value(start.Value, start.Error).Run;
            var running = await WaitForStateAsync(fixture, runs, activeRun.RunId, RunState.Running, cancellation);

            var nativeOwner = ReadSupervisor(fixture.DataRoot, running);
            using var windowsOwner = OperatingSystem.IsWindows() ? HoldWindowsResourceOwner(nativeOwner) : null;
            var windowsPrepared = OperatingSystem.IsWindows()
                ? ReadWindowsJobResource(fixture.DataRoot, running, nativeOwner, "windows-prepared.json") : null;
            if (windowsPrepared is { } prepared)
            {
                Assert.DoesNotContain(unmanaged.Id, prepared.ProcessIds);
            }

            using var cgroup = OperatingSystem.IsLinux() ? OpenResourceCgroup(nativeOwner) : null;
            if (OperatingSystem.IsLinux() && cgroup is not null)
            {
                Assert.False(LinuxRunCgroup.MatchesProcess(unmanaged.Id, unmanagedIdentity.Value.StartKey, cgroup.Path));
            }

            var rampBytes = ResourceBytes(ManagedRampMiB);
            var budgetRun = await WaitForResourceBudgetAsync(resources, "run", running.RunId, snapshot =>
                snapshot is { HasProcessCount: true, ProcessCount: > 0, HasCumulativeCpuUsec: true, CumulativeCpuUsec: > 0 }
                && (OperatingSystem.IsWindows() ? snapshot.HasPeakMemoryBytes && snapshot.PeakMemoryBytes >= rampBytes
                    : snapshot.HasManagedMemoryBytes && snapshot.ManagedMemoryBytes >= rampBytes));
            var budgetSandbox = await WaitForResourceBudgetAsync(resources, "sandbox", sandbox.SandboxId,
                snapshot => snapshot is { HasProcessCount: true, ProcessCount: > 0 });
            var linuxBefore = OperatingSystem.IsLinux() && cgroup is not null ? ReadLinuxResource(cgroup) : null;
            var nodeWatch = WatchResourceScopeAsync(resources, "node", null, startingAt);
            var sandboxWatch = WatchResourceScopeAsync(resources, "sandbox", sandbox.SandboxId, startingAt);
            var runWatch = WatchResourceScopeAsync(resources, "run", running.RunId, startingAt);
            await Task.WhenAll(nodeWatch, sandboxWatch, runWatch);
            var hostUsage = await nodeWatch;
            var sandboxUsage = await sandboxWatch;
            var runUsage = await runWatch;
            var linuxAfter = OperatingSystem.IsLinux() && cgroup is not null ? ReadLinuxResource(cgroup) : null;

            Assert.Equal(baseline.SampleEpoch, hostUsage.SampleEpoch);
            Assert.Equal(hostUsage.SampleEpoch, sandboxUsage.SampleEpoch);
            Assert.Equal(hostUsage.SampleEpoch, runUsage.SampleEpoch);
            Assert.Equal(sandbox.Revision, sandboxUsage.PolicyRevision);
            Assert.Equal(running.SandboxRevision, runUsage.PolicyRevision);
            Assert.True(runUsage.SampleSequence >= budgetRun.SampleSequence);
            Assert.True(sandboxUsage.SampleSequence >= budgetSandbox.SampleSequence);
            Assert.True(unmanagedIdentity.Value.IsRunning());
            Assert.Equal("resident_estimate", hostUsage.MemoryKind);
            Assert.True(hostUsage.HasHostMemoryBytes && hostUsage.HostMemoryBytes > hostUsage.BudgetMemoryBytes);
            Assert.True(hostUsage.HasBudgetMemoryBytes && hostUsage.HasReservedMemoryBytes && hostUsage.ReservedMemoryBytes > 0);
            Assert.True(hostUsage.HasHostCpuMillicores && hostUsage.HasBudgetCpuMillicores && hostUsage.HasReservedCpuMillicores);
            Assert.InRange(hostUsage.BudgetCpuMillicores, 0U, hostUsage.HostCpuMillicores);
            Assert.True(hostUsage.HasNodeMemoryBytes && hostUsage.NodeMemoryBytes > 0);
            Assert.True(hostUsage.HasNodeCpuMillicores && hostUsage.HasUnmanagedCpuMillicores);
            Assert.True(hostUsage.HasUnmanagedMemoryBytes && hostUsage.UnmanagedMemoryBytes >= ResourceBytes(UnmanagedRampMiB));
            Assert.True(hostUsage.HasManagedMemoryBytes && hostUsage.ManagedMemoryBytes >= rampBytes);

            var expectedKind = OperatingSystem.IsWindows() ? "windows_commit" : "linux_cgroup_current";
            Assert.True(runUsage.HasCumulativeCpuUsec && runUsage.CumulativeCpuUsec > 0);
            foreach (var sample in new[] { runUsage, sandboxUsage })
            {
                Assert.Equal(expectedKind, sample.MemoryKind);
                Assert.True(sample.HasProcessCount && sample.ProcessCount > 0);
                Assert.False(sample.HasUnmanagedMemoryBytes);
                Assert.Equal(OperatingSystem.IsLinux(), sample.HasManagedMemoryBytes);
                if (sample.HasManagedMemoryBytes) Assert.InRange(sample.ManagedMemoryBytes, rampBytes, DesiredMemory(running));
                if (sample.HasPeakMemoryBytes) Assert.True(sample.PeakMemoryBytes >= rampBytes);
            }

            Assert.Equal(runUsage.ProcessCount, sandboxUsage.ProcessCount);
            if (runUsage.SampleSequence == sandboxUsage.SampleSequence)
            {
                Assert.Equal(runUsage.HasManagedCpuMillicores, sandboxUsage.HasManagedCpuMillicores);
                Assert.Equal(runUsage.ManagedCpuMillicores, sandboxUsage.ManagedCpuMillicores);
                Assert.Equal(runUsage.ManagedMemoryBytes, sandboxUsage.ManagedMemoryBytes);
            }

            var hostNative = ReadFreshResourceHost();
            Assert.Equal(hostNative.PhysicalTotalBytes, hostUsage.HostMemoryBytes);
            RequirePsiProjection(hostUsage, hostNative.PsiCpuSome, hostNative.PsiMemorySome, hostNative.PsiMemoryFull);
            ReportResourceObservationTiming("native host sampler fresh reads", ReadFreshResourceHost);
            if (OperatingSystem.IsLinux() && cgroup is not null)
            {
                var before = Assert.IsType<RunResourceObservation>(linuxBefore);
                var after = Assert.IsType<RunResourceObservation>(linuxAfter);
                Assert.InRange(runUsage.CumulativeCpuUsec, before.CumulativeCpuUsec!.Value, after.CumulativeCpuUsec!.Value);
                Assert.Equal(after.ProcessCount, runUsage.ProcessCount);
                Assert.Equal(after.PeakMemoryBytes.HasValue, runUsage.HasPeakMemoryBytes);
                if (after.PeakMemoryBytes is { } peak)
                {
                    Assert.InRange(runUsage.PeakMemoryBytes, rampBytes, peak);
                }

                Assert.InRange(after.MemoryBytes!.Value, rampBytes, DesiredMemory(running));
                Assert.InRange(after.ResidentBytes!.Value, rampBytes, after.MemoryBytes.Value);
                Assert.Equal((long)ResourceBytes(LinuxCacheMiB), new FileInfo(linuxCache).Length);
                var reclaimable = after.MemoryBytes.Value - after.ResidentBytes.Value;
                Assert.True(reclaimable >= ResourceBytes(LinuxCacheMiB / 2), "The native cgroup included the generated reclaimable file cache.");
                Assert.True(runUsage.ManagedMemoryBytes > hostUsage.ManagedMemoryBytes,
                    "The Run exposes native cgroup charge and the host accounting subtracts its separate resident estimate.");
                TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
                    $"Linux scope charged {after.MemoryBytes.Value} bytes and observed {after.ResidentBytes.Value} resident bytes."));
                RequirePsiProjection(runUsage, after.PsiCpuSome, after.PsiMemorySome, after.PsiMemoryFull);
                ReportResourceObservationTiming("native held Linux Run cgroup", cgroup.ObserveResources);
            }
            else
            {
                Assert.True(runUsage.HasPeakMemoryBytes);
                Assert.True(hostNative.CommitBytes is > 0 && hostNative.CommitLimitBytes >= hostNative.CommitBytes);
                RequirePsiProjection(runUsage, null, null, null);
            }

            var wrongKind = await resources.GetBudgetAsync(new ResourceServiceGetBudgetRequest
            {
                Meta = Query(),
                ScopeKind = "sandbox",
                ScopeId = running.RunId,
            }, deadline: Deadline, cancellationToken: cancellation);
            Assert.Equal("not_found", wrongKind.Error?.Code);
            Assert.Null(wrongKind.Value);
            var malformedScope = await resources.GetBudgetAsync(new ResourceServiceGetBudgetRequest
            {
                Meta = Query(),
                ScopeKind = "node",
                ScopeId = sandbox.SandboxId,
            }, deadline: Deadline, cancellationToken: cancellation);
            Assert.Equal("invalid_argument", malformedScope.Error?.Code);
            Assert.Null(malformedScope.Value);
            using (var notVisible = resources.WatchUsage(new ResourceServiceWatchUsageRequest
            {
                Meta = Query(),
                ScopeKind = "run",
                ScopeId = CommandIds.New(),
                IntervalMs = 1000,
            }, deadline: Deadline, cancellationToken: cancellation))
            {
                Assert.True(await notVisible.ResponseStream.MoveNext(cancellation));
                Assert.Equal("not_found", notVisible.ResponseStream.Current.Error?.Code);
                Assert.Null(notVisible.ResponseStream.Current.Snapshot);
                Assert.False(await notVisible.ResponseStream.MoveNext(cancellation));
            }

            await File.WriteAllTextAsync(releaseManaged, "finish", cancellation);
            await File.WriteAllTextAsync(releaseUnmanaged, "finish", cancellation);
            var settled = await WaitForStateAsync(fixture, runs, running.RunId, RunState.Exited, cancellation);
            Assert.True(settled.Exit.GroupEmptyVerified);
            activeRun = null;
            var ended = await resources.GetBudgetAsync(new ResourceServiceGetBudgetRequest
            {
                Meta = Query(),
                ScopeKind = "run",
                ScopeId = settled.RunId,
            }, deadline: Deadline, cancellationToken: cancellation);
            Assert.True(Value(ended.Value, ended.Error).Snapshot.Stale);
            await unmanaged.WaitForExitAsync(cancellation).WaitAsync(NativeBound, cancellation);
            Assert.Equal(0, unmanaged.ExitCode);
            Assert.Equal(rampBytes, ResourceAllocationReport(managedReport));
            Assert.Equal(ResourceBytes(UnmanagedRampMiB), ResourceAllocationReport(unmanagedReport));
            if (OperatingSystem.IsWindows() && windowsPrepared is { } preparedJob)
            {
                var drained = ReadWindowsJobResource(fixture.DataRoot, running, nativeOwner, "windows-drained.json");
                // The worker writes its last accounting while it is the sole outer Job member.
                // Node verifies final aggregate drain after that exact process exits.
                Assert.Equal(nativeOwner.Pid, Assert.Single(drained.ProcessIds));
                Assert.Empty(drained.PayloadProcessIds);
                Assert.True(drained.OutputDrainCompleted);
                Assert.NotNull(windowsOwner);
                Assert.True(windowsOwner.HasExited);
                Assert.InRange(runUsage.CumulativeCpuUsec, preparedJob.CumulativeCpuUsec, drained.CumulativeCpuUsec);
                Assert.InRange(runUsage.PeakMemoryBytes, Math.Max(preparedJob.PeakCommitBytes, rampBytes), drained.PeakCommitBytes);
            }

            TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
                $"Run kind {runUsage.MemoryKind}, observed peak {runUsage.PeakMemoryBytes} bytes, cumulative CPU {runUsage.CumulativeCpuUsec} usec, processes {runUsage.ProcessCount}. Host unmanaged {hostUsage.UnmanagedMemoryBytes} bytes and Node overhead {hostUsage.NodeMemoryBytes} bytes."));
            await VerifyInstalledResourceLimitsAsync(fixture, node, sandboxes, runs, resources, ownerEpoch, sandbox.Config, cancellation);
        }
        finally
        {
            try
            {
                if (releaseManaged is not null) File.WriteAllText(releaseManaged, "finish");
                if (unmanaged is not null)
                {
                    File.WriteAllText(releaseUnmanaged, "finish");
                    await unmanaged.WaitForExitAsync(CancellationToken.None).WaitAsync(NativeBound, CancellationToken.None);
                }

                if (activeRun is not null && !nodeProcess.HasExited)
                {
                    await WaitForStateAsync(fixture, runs, activeRun.RunId, RunState.Exited, CancellationToken.None);
                }
            }
            finally
            {
                await StopNodeAsync(fixture, nodeProcess);
                if (ownerEpoch is not null) RemoveFixtureOwnerKey(fixture.DataRoot, ownerEpoch);
            }
        }
    }

    private static string[] MemoryRampArguments(int sizeMiB, string release, string report) =>
        ["mem-ramp", "--target-mb", sizeMiB.ToString(CultureInfo.InvariantCulture), "--step-mb", "16", "--hold-ms", "60000",
            "--until-file", release, "--report", report];

    private static ulong ResourceBytes(int sizeMiB) => (ulong)sizeMiB << 20;

    private static HostResourceObservation ReadFreshResourceHost()
    {
        // A fresh native observer prevents the Linux shared one-second cache from timing cached reads.
        if (OperatingSystem.IsWindows()) return new WindowsResourceSampler().ObserveHostResources();
        if (OperatingSystem.IsLinux()) return new LinuxResourceSampler().ObserveHostResources();
        throw new PlatformNotSupportedException();
    }

    private static ulong ResourceAllocationReport(string path)
    {
        using var report = JsonDocument.Parse(File.ReadAllBytes(path));
        return report.RootElement.GetProperty("results").GetProperty("allocatedBytes").GetUInt64();
    }

    private static async Task<ResourceSnapshot> WaitForResourceBudgetAsync(ResourceService.ResourceServiceClient client,
        string kind, Id? id, Func<ResourceSnapshot, bool> ready)
    {
        ResourceSnapshot? selected = null;
        await TestNode.WaitAsync(async () =>
        {
            var reply = await client.GetBudgetAsync(new ResourceServiceGetBudgetRequest { Meta = Query(), ScopeKind = kind, ScopeId = id },
                deadline: Deadline, cancellationToken: Ct);
            var current = Value(reply.Value, reply.Error).Snapshot;
            if (!current.HasStale || current.Stale || !ready(current)) return false;
            selected = current;
            return true;
        }, NativeBound, $"a fresh native {kind} resource budget");
        return Assert.IsType<ResourceSnapshot>(selected);
    }

    private static async Task<ResourceSnapshot> WatchResourceScopeAsync(ResourceService.ResourceServiceClient client,
        string kind, Id? id, DateTimeOffset startedAt)
    {
        using var call = client.WatchUsage(new ResourceServiceWatchUsageRequest
        {
            Meta = Query(),
            ScopeKind = kind,
            ScopeId = id,
            IntervalMs = 1000,
        }, deadline: Deadline, cancellationToken: Ct);
        Assert.True(await call.ResponseStream.MoveNext(Ct));
        var initial = Value(call.ResponseStream.Current.Snapshot, call.ResponseStream.Current.Error);
        AssertScope(initial);
        Assert.True(await call.ResponseStream.MoveNext(Ct));
        var next = Value(call.ResponseStream.Current.Snapshot, call.ResponseStream.Current.Error);
        var currentTime = AssertScope(next);
        Assert.Equal(initial.SampleEpoch, next.SampleEpoch);
        Assert.True(next.SampleSequence > initial.SampleSequence);
        Assert.True(currentTime >= ProtoTime.ToDateTimeOffset(initial.SampledAt));
        return next;

        DateTimeOffset AssertScope(ResourceSnapshot sample)
        {
            Assert.Equal(kind, sample.ScopeKind);
            Assert.Equal(id, sample.ScopeId);
            Assert.False(string.IsNullOrWhiteSpace(sample.SampleEpoch));
            Assert.True(sample.HasSampleSequence && sample.SampleSequence > 0);
            Assert.True(sample.HasSampleIntervalMs && sample.SampleIntervalMs > 0);
            Assert.True(sample.HasStale);
            Assert.False(sample.Stale);
            var at = Assert.IsType<DateTimeOffset>(ProtoTime.ToDateTimeOffset(sample.SampledAt));
            Assert.InRange(at, startedAt, DateTimeOffset.UtcNow);
            return at;
        }
    }

    [SupportedOSPlatform("linux")]
    private static LinuxRunCgroup OpenResourceCgroup((int Pid, string Creation, string Boundary) owner)
    {
        var boundary = owner.Boundary.Split('|');
        Assert.Equal(5, boundary.Length);
        var held = LinuxRunCgroup.Open(boundary[2]);
        try
        {
            Assert.Equal(boundary[3], held.MountId.ToString(CultureInfo.InvariantCulture));
            Assert.Equal(boundary[4], held.Inode.ToString(CultureInfo.InvariantCulture));
            Assert.True(LinuxRunCgroup.MatchesProcess(owner.Pid, long.Parse(owner.Creation, CultureInfo.InvariantCulture), held.Path));
            return held;
        }
        catch
        {
            held.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("linux")]
    private static RunResourceObservation ReadLinuxResource(LinuxRunCgroup held) => Assert.IsType<RunResourceObservation>(held.ObserveResources());

    [SupportedOSPlatform("windows")]
    private static Process HoldWindowsResourceOwner((int Pid, string Creation, string Boundary) owner)
    {
        var process = Process.GetProcessById(owner.Pid);
        try
        {
            Assert.False(process.SafeHandle.IsInvalid);
            Assert.Equal(owner.Creation, process.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture));
            return process;
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }

    [SupportedOSPlatform("windows")]
    private static WindowsJobResource ReadWindowsJobResource(string dataRoot, Run run,
        (int Pid, string Creation, string Boundary) owner, string fileName)
    {
        var control = Path.Combine(dataRoot, "control", "run-" + Hex(run.RunId));
        var path = Path.Combine(control, fileName);
        using var heldDirectory = WindowsMxcPathLease.Open(control, directory: true, privateObject: true);
        using var heldEvidence = WindowsMxcPathLease.Open(path, directory: false, privateObject: true);
        using var data = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = data.RootElement;
        Assert.Equal(Hex(run.RunId), root.GetProperty("runId").GetString());
        Assert.Equal(run.LaunchSha256, root.GetProperty("launchSha256").GetString());
        Assert.Equal(owner.Pid, root.GetProperty("ownerPid").GetInt32());
        Assert.Equal(owner.Creation, root.GetProperty("ownerCreationFileTime").GetInt64().ToString(CultureInfo.InvariantCulture));
        var job = root.GetProperty("aggregate");
        return new((job.GetProperty("userTimeTicks").GetUInt64() + job.GetProperty("kernelTimeTicks").GetUInt64()) / 10,
            job.GetProperty("peakCommitBytes").GetUInt64(), ReadJobMembers(job), ReadJobMembers(root.GetProperty("payload")),
            root.TryGetProperty("outputDrainCompleted", out var drained) && drained.GetBoolean());

        static int[] ReadJobMembers(JsonElement scope)
        {
            var members = scope.GetProperty("processIds").EnumerateArray().Select(pid => pid.GetInt32()).ToArray();
            Assert.Equal((uint)members.Length, scope.GetProperty("activeProcesses").GetUInt32());
            return members;
        }
    }

    private sealed record WindowsJobResource(ulong CumulativeCpuUsec, ulong PeakCommitBytes, int[] ProcessIds,
        int[] PayloadProcessIds, bool OutputDrainCompleted);

    private static void RequirePsiProjection(ResourceSnapshot snapshot, double? cpuSome, double? memorySome, double? memoryFull)
    {
        Check(cpuSome, snapshot.HasPsiCpuSome, snapshot.PsiCpuSome);
        Check(memorySome, snapshot.HasPsiMemorySome, snapshot.PsiMemorySome);
        Check(memoryFull, snapshot.HasPsiMemoryFull, snapshot.PsiMemoryFull);

        static void Check(double? native, bool reported, double percent)
        {
            Assert.Equal(native.HasValue, reported);
            if (reported) Assert.InRange(percent, 0, 100);
        }
    }

    private static void ReportResourceObservationTiming<T>(string source, Func<T> sample)
    {
        _ = sample();
        var elapsed = new double[25];
        for (var index = 0; index < elapsed.Length; index++)
        {
            var started = Stopwatch.GetTimestamp();
            _ = sample();
            elapsed[index] = Stopwatch.GetElapsedTime(started).TotalMicroseconds;
        }

        Array.Sort(elapsed);
        var p50 = elapsed[(int)Math.Ceiling(0.50 * elapsed.Length) - 1];
        var p95 = elapsed[(int)Math.Ceiling(0.95 * elapsed.Length) - 1];
        TestContext.Current.TestOutputHelper?.WriteLine(FormattableString.Invariant(
            $"{source}: n={elapsed.Length} p50={p50:F1} usec p95={p95:F1} usec"));
    }
}
