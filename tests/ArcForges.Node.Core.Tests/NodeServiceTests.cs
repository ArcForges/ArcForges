// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Store;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// NodeService against a real node in the test process (node-component layer): the hello and compatibility (R-API-007), origins,
/// idempotent mutations (R-EXE-016), settings revisions, jobs and the notification centre. Each test has its own data root and
/// endpoint.
/// </summary>
[Collection(SerialNodeTests.Name)]
public sealed class NodeServiceTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(10);

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData(true, ProcessCountControl.ObserveOnly, true)]
    [InlineData(true, ProcessCountControl.Enforced, true)]
    [InlineData(false, ProcessCountControl.ObserveOnly, false)]
    [InlineData(false, ProcessCountControl.Enforced, true)]
    public void ReadinessIsPlatformExplicitAboutProcessCounts(bool windowsJobs, ProcessCountControl pids, bool ready)
    {
        // cpu and memory enforced everywhere; pids decides only off the Windows job platform (a Linux node without pids delegation
        // stays DEGRADED).
        var report = new CapabilityReport
        {
            Cpu = CpuControl.EnforcedShareAndCap,
            Memory = MemoryControl.EnforcedSoftAndHard,
            Pids = pids,
            PidsReason = "no pids controller",
        };
        Assert.Equal(ready, NodeCapabilities.FullyEnforced(report, windowsJobs));
        Assert.Equal(ready ? null : "no pids controller", NodeCapabilities.MissingReason(report, windowsJobs));
        report.Memory = MemoryControl.ObserveOnly;
        Assert.False(NodeCapabilities.FullyEnforced(report, windowsJobs));
    }

    [Fact(Timeout = 60_000)]
    public async Task TheHelloAssignsTheOriginAndChecksTheContract()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = NodeChannel.Create(node.Endpoint);

        var human = await Hello(channel, hello => hello.InteractiveTerminal = true);
        Assert.Equal(Origin.Human, human.Value.AssignedOrigin);
        Assert.Equal(NodeContract.Major, human.Value.Node.ContractMajor);
        Assert.Equal(Origin.Script, (await Hello(channel, hello => hello.InteractiveTerminal = false)).Value.AssignedOrigin);
        Assert.Equal(Origin.Script, (await Hello(channel, hello => { hello.InteractiveTerminal = true; hello.CiMarkers.Add("CI"); })).Value.AssignedOrigin);
        Assert.Equal(Origin.Agent, (await Hello(channel, hello => hello.ClientKind = ClientKind.McpAdapter)).Value.AssignedOrigin);
        Assert.Equal(Origin.Human, (await Hello(channel, hello => hello.ClientKind = ClientKind.Desktop)).Value.AssignedOrigin);

        // R-API-007: another major is refused with a typed error; a newer minor is accepted with a warning.
        var major = await Hello(channel, hello => hello.ContractMajor = 2);
        Assert.Equal(("incompatible_version", ErrorCategory.Validation), (major.Error.Code, major.Error.Category));
        Assert.Equal("2.0", major.Error.Details.Upgrade.Received);
        var newer = await Hello(channel, hello => hello.ContractMinor = NodeContract.Minor + 1);
        Assert.Single(newer.Value.Warnings);
        Assert.Empty((await Hello(channel, hello => hello.ContractMinor = NodeContract.Minor)).Value.Warnings);
    }

    [Fact(Timeout = 60_000)]
    public async Task TheHelloIsCheckedAgainstTheConnectionsPeerProcess()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = NodeChannel.Create(node.Endpoint);

        var otherPid = await Hello(channel, hello => hello.Process.Pid += 1);
        Assert.Equal("invalid_argument", otherPid.Error.Code);
        Assert.Equal("hello.process: must be the connection's peer process", otherPid.Error.Details.State.Reason);
        var otherStart = await Hello(channel, hello => hello.Process.StartTime = ProtoTime.ToInstant(DateTimeOffset.UtcNow.AddHours(-1)));
        Assert.Equal("invalid_argument", otherStart.Error.Code);
        Assert.Equal("invalid_argument", (await Hello(channel, hello => hello.ClearClientKind())).Error.Code);
        Assert.Equal("invalid_argument", (await Hello(channel, hello => hello.ClientVersion = "one")).Error.Code);
        Assert.Equal("invalid_argument", (await Hello(channel, hello => hello.McpClientName = "x")).Error.Code);
        var missing = await channel.Node.HelloAsync(new NodeServiceHelloRequest(), deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal("hello: required", missing.Error.Details.State.Reason);
    }

    [Fact(Timeout = 60_000)]
    public async Task ARenameRunsOncePerCommandIdAndPayload()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();
        var request = new NodeServiceRenameNodeRequest { Meta = InProcessNode.Command(), Name = "build box" };

        var before = node.Runtime.Journal.Latest;
        var first = await channel.Node.RenameNodeAsync(request, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        var afterFirst = node.Runtime.Journal.Latest;
        var replay = await channel.Node.RenameNodeAsync(request, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);

        Assert.Equal("build box", first.Value.Node.Node.Name);
        Assert.Equal(before + 1, afterFirst);
        Assert.Equal(first.Value.Node.Node.Name, replay.Value.Node.Node.Name);
        Assert.Equal(afterFirst, node.Runtime.Journal.Latest);

        // The same command ID with another payload is CONFLICT/command_id_reused, and nothing changes.
        var reused = await channel.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = request.Meta, Name = "other" }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(("command_id_reused", ErrorCategory.Conflict), (reused.Error.Code, reused.Error.Category));
        var info = await channel.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest(), deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal("build box", info.Value.Node.Node.Name);

        var noCommand = await channel.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Name = "x" }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal("meta.command_id: required; a 16-byte UUIDv7", noCommand.Error.Details.State.Reason);
        var tooLong = await channel.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = InProcessNode.Command(), Name = new string('n', 65) },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal("invalid_argument", tooLong.Error.Code);
    }

    [Fact(Timeout = 60_000)]
    public async Task SettingsUpdatesCheckTheRevisionAndApplyTheLogLevel()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        await using var script = await node.ChannelAsync(helloAsHuman: false);
        var current = await script.Node.GetNodeSettingsAsync(new NodeServiceGetNodeSettingsRequest(), deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(0, current.Value.Settings.Revision.Value);
        Assert.Equal(LogLevel.Info, current.Value.Settings.LogLevel);
        Assert.Equal(node.DataRoot, current.Value.Settings.DataRoot);
        Assert.Equal(node.ConfigPath, current.Value.Settings.ConfigPath);

        var meta = InProcessNode.Command();
        meta.ExpectedRev = new Revision { Value = 0 };
        var updated = await script.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = meta, LogLevel = LogLevel.Debug },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(1, updated.Value.Settings.Revision.Value);
        Assert.False(updated.Value.RestartRequired);
        Assert.Equal(LogLevel.Debug, node.Runtime.Log.MinimumLevel);
        Assert.Contains("\"logLevel\": \"debug\"", File.ReadAllText(node.ConfigPath), StringComparison.Ordinal);

        var stale = InProcessNode.Command();
        stale.ExpectedRev = new Revision { Value = 0 };
        var conflict = await script.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = stale, LogLevel = LogLevel.Error },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal("revision_conflict", conflict.Error.Code);
        Assert.Equal(1, conflict.Error.Details.Revision.Actual.Value);

        // node.proto: telemetry_opt_in is HUMAN only.
        var denied = await script.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = InProcessNode.Command(), TelemetryOptIn = true },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(("permission_denied", ErrorCategory.Authorization), (denied.Error.Code, denied.Error.Category));
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var allowed = await human.Node.UpdateNodeSettingsAsync(new NodeServiceUpdateNodeSettingsRequest { Meta = InProcessNode.Command(), TelemetryOptIn = true },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.True(allowed.Value.Settings.TelemetryOptIn);
        Assert.Equal(2, allowed.Value.Settings.Revision.Value);
    }

    [Fact(Timeout = 60_000)]
    public async Task JobsAreListedNewestFirstByPageAndCancelledOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        byte[] pending = [], running = [], finished = [];
        var start = StoreTime.ToMicroseconds(DateTimeOffset.UtcNow);
        await using var node = await InProcessNode.Create(seed: transaction =>
        {
            finished = InProcessNode.SeedJob(transaction, JobKind.Doctor, JobState.Succeeded, start);
            running = InProcessNode.SeedJob(transaction, JobKind.StorageAnalysis, JobState.Running, start + 1);
            pending = InProcessNode.SeedJob(transaction, JobKind.RecordExport, JobState.Pending, start + 2);
        }).StartAsync();
        await using var channel = await node.ChannelAsync();

        var all = await channel.Node.ListJobsAsync(new NodeServiceListJobsRequest(), deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal([pending, running, finished], all.Value.Jobs.Select(job => job.JobId.Value.ToByteArray()));
        Assert.False(all.Value.Page.HasMore);

        var first = await channel.Node.ListJobsAsync(new NodeServiceListJobsRequest { Page = new PageRequest { Limit = 2 } }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        var second = await channel.Node.ListJobsAsync(new NodeServiceListJobsRequest { Page = new PageRequest { Limit = 2, Cursor = first.Value.Page.NextCursor } },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.True(first.Value.Page.HasMore);
        Assert.Equal([pending, running], first.Value.Jobs.Select(job => job.JobId.Value.ToByteArray()));
        Assert.Equal([finished], second.Value.Jobs.Select(job => job.JobId.Value.ToByteArray()));

        var active = await channel.Node.ListJobsAsync(new NodeServiceListJobsRequest { States = { JobState.Running, JobState.Pending } }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(2, active.Value.Jobs.Count);
        Assert.Equal("invalid_cursor", (await channel.Node.ListJobsAsync(new NodeServiceListJobsRequest { Page = new PageRequest { Cursor = "nope" } },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct)).Error.Code);
        Assert.Equal("invalid_argument", (await channel.Node.ListJobsAsync(new NodeServiceListJobsRequest { Page = new PageRequest { Limit = 501 } },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct)).Error.Code);

        var sequence = node.Runtime.Journal.Latest;
        var cancel = new NodeServiceCancelJobRequest { Meta = InProcessNode.Command(), JobId = Id(running) };
        var cancelled = await channel.Node.CancelJobAsync(cancel, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(JobState.Cancelled, cancelled.Value.Job.State);
        Assert.NotNull(cancelled.Value.Job.FinishedAt);
        Assert.Equal(sequence + 1, node.Runtime.Journal.Latest);
        Assert.Equal(JobState.Cancelled, (await channel.Node.CancelJobAsync(cancel, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct)).Value.Job.State);
        Assert.Equal(sequence + 1, node.Runtime.Journal.Latest);

        var again = await channel.Node.CancelJobAsync(new NodeServiceCancelJobRequest { Meta = InProcessNode.Command(), JobId = Id(running) }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(("invalid_state", "CANCELLED"), (again.Error.Code, again.Error.Details.State.State));
        var unknown = await channel.Node.GetJobAsync(new NodeServiceGetJobRequest { JobId = CommandIds.New() }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(("not_found", "job"), (unknown.Error.Code, unknown.Error.Details.State.Resource.Kind));
        Assert.Equal(JobKind.RecordExport, (await channel.Node.GetJobAsync(new NodeServiceGetJobRequest { JobId = Id(pending) }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct)).Value.Job.Kind);
    }

    [Fact(Timeout = 60_000)]
    public async Task NotificationsAreMarkedReadByIdOrUpToATime()
    {
        var ct = TestContext.Current.CancellationToken;
        byte[] oldest = [], middle = [], newest = [];
        var start = StoreTime.ToMicroseconds(DateTimeOffset.UtcNow.AddMinutes(-10));
        await using var node = await InProcessNode.Create(seed: transaction =>
        {
            oldest = InProcessNode.SeedNotification(transaction, "first", start);
            middle = InProcessNode.SeedNotification(transaction, "second", start + 1_000_000);
            newest = InProcessNode.SeedNotification(transaction, "third", start + 2_000_000);
        }).StartAsync();
        await using var channel = await node.ChannelAsync(helloAsHuman: true);

        var list = await channel.Node.ListNotificationsAsync(new NodeServiceListNotificationsRequest(), deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(["third", "second", "first"], list.Value.Notifications.Select(item => item.Title));
        Assert.Equal(3u, list.Value.UnreadCount);

        var sequence = node.Runtime.Journal.Latest;
        var one = await channel.Node.MarkNotificationsReadAsync(new NodeServiceMarkNotificationsReadRequest { NotificationIds = { Id(middle) } },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(2u, one.Value.UnreadCount);
        Assert.Equal(sequence + 1, node.Runtime.Journal.Latest);
        var unread = await channel.Node.ListNotificationsAsync(new NodeServiceListNotificationsRequest { UnreadOnly = true }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(["third", "first"], unread.Value.Notifications.Select(item => item.Title));

        var upTo = await channel.Node.MarkNotificationsReadAsync(new NodeServiceMarkNotificationsReadRequest
        {
            UpTo = ProtoTime.ToInstant(StoreTime.FromMicroseconds(start + 1_500_000)),
        }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(1u, upTo.Value.UnreadCount);
        Assert.Equal(sequence + 2, node.Runtime.Journal.Latest);

        // Marking read twice succeeds (natural idempotency) and journals nothing.
        Assert.Equal(1u, (await channel.Node.MarkNotificationsReadAsync(new NodeServiceMarkNotificationsReadRequest { NotificationIds = { Id(middle), Id(oldest) } },
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct)).Value.UnreadCount);
        Assert.Equal(sequence + 2, node.Runtime.Journal.Latest);
        Assert.Equal("up_to: required when notification_ids is empty", (await channel.Node.MarkNotificationsReadAsync(new NodeServiceMarkNotificationsReadRequest(),
            deadline: DateTime.UtcNow + Deadline, cancellationToken: ct)).Error.Details.State.Reason);
        Assert.NotEmpty(newest);
    }

    [Fact(Timeout = 60_000)]
    public async Task StopNodeReturnsAReceiptAndTheNodeShutsDownCleanly()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var descriptor = NodeLocations.EndpointDescriptorFile(node.DataRoot);
        Assert.True(File.Exists(descriptor));

        // A free-text reason may carry anything; it never reaches the log (R-SEC-003).
        var value = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(12));
        var reason = "token=" + value;
        await using (var channel = await node.ChannelAsync(helloAsHuman: true))
        {
            var meta = InProcessNode.Command();
            var response = await channel.Node.StopNodeAsync(new NodeServiceStopNodeRequest { Meta = meta, Reason = reason }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
            Assert.Equal(meta.CommandId, response.Value.Receipt.CommandId);
            Assert.Equal(EffectCertainty.Happened, response.Value.Receipt.Effect);
        }

        Assert.Equal(0, await node.Exit.WaitAsync(TimeSpan.FromSeconds(15), ct));
        Assert.False(File.Exists(descriptor));
        using var store = NodeStore.Open(new NodeStoreOptions { DataRoot = node.DataRoot, BootIdentity = "check" });
        Assert.True(store.Metadata.PreviousShutdownClean);
        var log = File.ReadAllText(Path.Combine(node.DataRoot, "logs", "node", "node.log"));
        Assert.Contains("\"event\":\"node.stopped\"", log, StringComparison.Ordinal);
        Assert.Contains("\"reasonLength\":" + reason.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), log, StringComparison.Ordinal);
        Assert.DoesNotContain(value, log, StringComparison.Ordinal);
    }

    [Fact(Timeout = 60_000)]
    public async Task HealthAndCapabilitiesReportTheBuildsEnforcement()
    {
        // Windows enforces through job objects (AF-EXEC-01) and is READY; Linux enforces through transient units of the user manager
        // (AF-EXEC-02) and is READY when the manager delegates cpu, memory and pids, observe-only (DEGRADED) without a user manager.
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        await using var channel = await node.ChannelAsync();

        var health = await channel.Node.GetHealthAsync(new NodeServiceGetHealthRequest(), deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        Assert.Equal(InProcessNode.ExpectedState, health.Value.State);
        Assert.Contains(health.Value.Checks, check => check.CheckId == "node.enforcement"
            && check.Status == (InProcessNode.ExpectedState == NodeLifecycleState.Ready ? CheckStatus.Pass : CheckStatus.Warn));
        Assert.Contains(health.Value.Metrics, metric => metric.Name == "rpc.peers_admitted" && metric.Value >= 1);
        var capabilities = await channel.Node.GetCapabilitiesAsync(new NodeServiceGetCapabilitiesRequest { Reevaluate = true }, deadline: DateTime.UtcNow + Deadline, cancellationToken: ct);
        var report = capabilities.Value.Capabilities;
        Assert.Contains(report.PlatformFacts, fact => fact.Name == "os");
        if (OperatingSystem.IsWindows())
        {
            Assert.Equal(CpuControl.EnforcedShareAndCap, report.Cpu);
            Assert.Equal(MemoryControl.EnforcedCommit, report.Memory);
            Assert.Equal(ProcessCountControl.ObserveOnly, report.Pids);
            Assert.Contains("no policy field", report.PidsReason, StringComparison.Ordinal);
            Assert.Equal(PauseSupport.Unsupported, report.Pause);
            Assert.Equal(KillTreeGuarantee.Guaranteed, report.KillTree);
            Assert.True(report.RestartSurvival);
            Assert.Contains(report.PlatformFacts, fact => fact.Name == "root_job");
        }
        else if (ArcForges.Tests.SystemdTestEnvironment.FullyEnforced)
        {
            Assert.Equal(CpuControl.EnforcedShareAndCap, report.Cpu);
            Assert.Equal(MemoryControl.EnforcedSoftAndHard, report.Memory);
            Assert.Equal(ProcessCountControl.Enforced, report.Pids);
            Assert.Equal(PauseSupport.Supported, report.Pause);
            Assert.Equal(KillTreeGuarantee.Guaranteed, report.KillTree);
            Assert.True(report.RestartSurvival);
            Assert.Contains(report.PlatformFacts, fact => fact.Name == "slice" && fact.Value == node.Slice);
        }
        else
        {
            Assert.Equal(CpuControl.ObserveOnly, report.Cpu);
            Assert.False(report.RestartSurvival);
        }
    }

    private static Id Id(byte[] bytes) => new() { Value = Google.Protobuf.ByteString.CopyFrom(bytes) };

    private static async Task<NodeServiceHelloResponse> Hello(NodeChannel channel, Action<ClientHello> change)
    {
        var hello = ClientProcess.Hello(ClientKind.Cli);
        hello.CiMarkers.Clear();
        change(hello);
        return await channel.Node.HelloAsync(new NodeServiceHelloRequest { Hello = hello }, deadline: DateTime.UtcNow + Deadline, cancellationToken: Ct);
    }
}

/// <summary>Node-component tests run one after another (each starts a real node; parallel runs would only add noise to timings).</summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class SerialNodeTests
{
    public const string Name = "node";
}
