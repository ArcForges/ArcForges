// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.Versioning;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Tests;

namespace ArcForges.Node.Core.Tests;

/// <summary>Linux data-root observation and fresh legacy Task refusal under degraded host capabilities.</summary>
/// <remarks>
/// The original Linux Task launch and process-effect scenarios remain executable at
/// eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a (blob 156855ba70cfc6fd36d33d4c0bd82ca1b8ee1df3).
/// The shared Attempt recovery fixtures cover retained exit records without submitting a new Task.
/// </remarks>
[Trait("env", "linux-real")]
[SupportedOSPlatform("linux")]
public sealed class LinuxTaskTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RequireUnits() => Assert.SkipWhen(SystemdTestEnvironment.SkipReason is not null, SystemdTestEnvironment.SkipReason ?? string.Empty);

    [Fact(Timeout = 120_000)]
    public async Task AnInMemoryDataRootIsReportedAndADiskOneIsNot()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        // tmpfs (/dev/shm, and /tmp in WSL Debian) keeps captured output in memory charged to the attempts: a capability fact and a log
        // warning say so; a disk-backed root (the test binaries' directory) reports "disk".
        Assert.SkipUnless(OperatingSystem.IsLinux() && Directory.Exists("/dev/shm"), "Linux tmpfs.");
        Assert.Equal("tmpfs", Core.Platform.MemoryFileSystems.KindOf("/dev/shm"));
        Assert.Null(Core.Platform.MemoryFileSystems.KindOf(AppContext.BaseDirectory));
        TestContext.Current.TestOutputHelper?.WriteLine($"/tmp: {Core.Platform.MemoryFileSystems.KindOf("/tmp") ?? "disk"}");

        await using (var inMemory = await InProcessNode.Create(parent: "/dev/shm").StartAsync())
        {
            var fact = inMemory.Runtime.Capabilities.PlatformFacts.Single(item => item.Name == "data_root_filesystem").Value;
            Assert.StartsWith("tmpfs (" + inMemory.DataRoot + ")", fact, StringComparison.Ordinal);
            Assert.Contains("node.data_root_in_memory", File.ReadAllText(Path.Combine(inMemory.DataRoot, "logs", "node", "node.log")), StringComparison.Ordinal);
        }

        await using var onDisk = await InProcessNode.Create(parent: AppContext.BaseDirectory).StartAsync();
        Assert.Equal("disk", onDisk.Runtime.Capabilities.PlatformFacts.Single(item => item.Name == "data_root_filesystem").Value);
    }

    [Fact(Timeout = 120_000)]
    public async Task WithoutAUserManagerTheNodeIsDegradedAndRefusesFreshLegacyTasks()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        Assert.SkipUnless(OperatingSystem.IsLinux(), "Linux.");
        var node = InProcessNode.Create();
        node.SystemdAddress = "unix:path=" + Path.Combine(node.Root, "no-user-manager");
        await using (node)
        {
            await node.StartAsync();
            await using var channel = await node.ChannelAsync(helloAsHuman: true);
            Assert.Equal(NodeLifecycleState.Degraded, node.Runtime.Lifecycle.State);
            Assert.Equal(CpuControl.ObserveOnly, node.Runtime.Capabilities.Cpu);
            Assert.Contains("cannot be reached", node.Runtime.Capabilities.MemoryReason, StringComparison.Ordinal);
            Assert.False(node.Runtime.Capabilities.RestartSurvival);

            await AssertFreshLegacyTaskRefusedAsync(node, channel, EnforcedResource.Memory);
            await AssertFreshLegacyTaskRefusedAsync(node, channel);
        }

        var strict = InProcessNode.Create(seed: transaction => Tasks.SeedPolicy(transaction, policy => policy.Resources.AllowUnenforced = false));
        strict.SystemdAddress = "unix:path=" + Path.Combine(strict.Root, "no-user-manager");
        await using (strict)
        {
            await strict.StartAsync();
            await using var channel = await strict.ChannelAsync(helloAsHuman: true);
            await AssertFreshLegacyTaskRefusedAsync(strict, channel);
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task WithoutMemoryDelegationMemoryIsObserveOnlyAndFreshLegacyTasksAreRefused()
    {
        // A user manager whose delegation lacks the memory controller (simulated: the node treats only cpu and pids as delegated).
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        RequireUnits();
        var node = InProcessNode.Create();
        node.LinuxControllers = ["cpu", "pids"];
        await using (node)
        {
            await node.StartAsync();
            await using var channel = await node.ChannelAsync(helloAsHuman: true);
            var capabilities = node.Runtime.Capabilities;
            Assert.Equal(NodeLifecycleState.Degraded, node.Runtime.Lifecycle.State);
            Assert.Equal(CpuControl.EnforcedShareAndCap, capabilities.Cpu);
            Assert.Equal(MemoryControl.ObserveOnly, capabilities.Memory);
            Assert.Contains("no memory delegation", capabilities.MemoryReason, StringComparison.Ordinal);

            await AssertFreshLegacyTaskRefusedAsync(node, channel, EnforcedResource.Memory);
            await AssertFreshLegacyTaskRefusedAsync(node, channel, EnforcedResource.Cpu);
        }
    }

    private static async Task AssertFreshLegacyTaskRefusedAsync(InProcessNode node, NodeChannel channel, EnforcedResource? required = null)
    {
        var spec = Tasks.Argv(node.Root, Path.Combine(node.Root, "missing-legacy-fixture-program"));
        if (required is { } resource)
        {
            spec.Resources = new ResourceSpec();
            spec.Resources.RequireEnforcement.Add(resource);
        }

        var response = await Tasks.SubmitRawAsync(channel, spec);
        Assert.Null(response.Value);
        Assert.Equal("operation_failed", response.Error.Code);
        Assert.Equal("LEGACY_DRAIN", response.Error.Details.State.State);
        Assert.Equal("legacy_task_outcome_unavailable", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.Unknown, response.Error.Effect);
        Assert.Equal(RetryMode.Never, response.Error.Retry.Mode);
        node.Runtime.Store.Read(reader =>
        {
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM task;"));
            Assert.Equal(0L, reader.Scalar("SELECT count(*) FROM attempt;"));
            return 0;
        });
    }
}
