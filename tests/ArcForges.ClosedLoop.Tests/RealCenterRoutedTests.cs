// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.CloudLink;
using ArcForges.Node.CloudLink.Tests;
using ArcForges.Node.Core;
using Google.Protobuf;
using Grpc.Core;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;

namespace ArcForges.ClosedLoop.Tests;

/// <summary>
/// AF-CTR-05 N2-16..20: real in-process nodes, real node channel and execution, the merged local center and PostgreSQL.
/// The browser's passkey is virtual and the future N3 proxy is represented by this test's relay client. No supervisor,
/// hosted center, Windows-to-center, owner's passkey or real step-up is claimed. Opt in only through the three E2E variables.
/// </summary>
[Trait("loop", "cloud")]
public sealed class RealCenterRoutedTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly TimeSpan ConnectedTimeout = TimeSpan.FromSeconds(90);

    [Fact(Timeout = 900_000)]
    public async Task RealNodeRoutesThroughTheMergedCenterAndRecoversFromInterruption()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var url = Environment.GetEnvironmentVariable("ARCFORGES_E2E_CENTER_URL");
        Assert.SkipUnless(!string.IsNullOrEmpty(url), "ARCFORGES_E2E_CENTER_URL is not set");
        Assert.SkipUnless(OperatingSystem.IsLinux(), "the real local center closed loop is Linux-only");
        Assert.SkipWhen(ArcForges.Tests.SystemdTestEnvironment.SkipReason is not null, ArcForges.Tests.SystemdTestEnvironment.SkipReason ?? string.Empty);
        Assert.True(CenterEndpoint.TryParse(url, out var center, out var reason), reason);
        Assert.NotEqual(CenterEndpoint.OfficialDefault, center.Url);
        Assert.True(center.Scheme == "http" && (center.Host == "localhost" || (IPAddress.TryParse(center.Host, out var address) && IPAddress.IsLoopback(address)))
            && center.PathBase.Length == 0, "the fault-injection closed loop requires an isolated loopback center");
        var directory = Environment.GetEnvironmentVariable("ARCFORGES_E2E_DIR");
        var harness = Environment.GetEnvironmentVariable("ARCFORGES_E2E_CENTER_HARNESS");
        Assert.True(!string.IsNullOrEmpty(directory) && Path.IsPathFullyQualified(directory), "ARCFORGES_E2E_DIR must be absolute");
        Assert.True(!string.IsNullOrEmpty(harness) && Path.IsPathFullyQualified(harness) && File.Exists(harness), "ARCFORGES_E2E_CENTER_HARNESS must be an existing absolute path");
        Directory.CreateDirectory(directory);
        var clock = new OffsetClock();
        var delay = new DelayResult();
        await using var target = CloudNode.Create(center.Url);
        target.Clock = clock;
        target.WrapRoutedDispatcher = inner => new DelayedDispatcher(inner, delay);
        await using var relayer = CloudNode.Create(center.Url);
        await target.StartAsync();
        await relayer.StartAsync();
        await using var human = await target.ChannelAsync(Origin.Human);
        await using var relayHuman = await relayer.ChannelAsync(Origin.Human);
        var begun = new List<string>();
        var resultsWritten = new HashSet<string>(StringComparer.Ordinal);
        var centerStopped = false;
        try
        {
            // Both devices belong to the harness's one disposable account. Only the target's own relay is used for the normal path.
            var targetFlow = await BeginAsync(target, human, center, directory, "n2b-target");
            begun.Add("n2b-target");
            await AwaitSignInAsync(human, targetFlow, "target");
            using var own = new RelayClient(target, center);
            var targetId = new Id { Value = ByteString.CopyFrom(target.Runtime.NodeId.Span) };

            // N2-16: own-node relay -> real center -> real node -> real center, including output and cancel.
            var print = Submit(target, "output", "--bytes", "2048");
            var printed = await own.SubmitAsync(targetId, Origin.Script, print);
            Assert.Null(printed.Error);
            var printId = printed.Value.TaskId;
            var ended = await WaitRoutedAsync(own, targetId, printId, WaitTarget.Terminal);
            Assert.Equal(TaskState.Succeeded, ended.State);
            var list = await own.ListAsync(targetId, Origin.Script, new TaskServiceListTasksRequest { Meta = CloudNode.Command() });
            Assert.Null(list.Error);
            Assert.Contains(list.Value.Tasks, item => item.TaskId.Equals(printId));
            var output = await own.OutputAsync(targetId, Origin.Script, new TaskServiceReadTaskOutputRequest
            {
                Meta = CloudNode.Command(),
                AttemptId = ended.CurrentAttempt.AttemptId,
                FromOffset = 1024,
                MaxBytes = 512,
            });
            Assert.Null(output.Error);
            Assert.Equal((512, 1536UL), (output.Value.Data.Length, output.Value.NextOffset));
            var holding = await own.SubmitAsync(targetId, Origin.Script, Submit(target, "hold", "--hold-ms", "120000"));
            Assert.Null(holding.Error);
            var held = holding.Value.TaskId;
            Assert.Equal(TaskState.Running, (await WaitRoutedAsync(own, targetId, held, WaitTarget.Started)).State);
            var cancel = await own.CancelAsync(targetId, Origin.Script, new TaskServiceCancelTaskRequest { Meta = CloudNode.Command(), TaskId = held });
            Assert.Null(cancel.Error);
            Assert.Equal(TaskState.Cancelled, (await WaitLocalAsync(human, held, WaitTarget.Terminal)).State);

            // B-1: the first delivery sees an injected stopping link; the real dispatcher creates the transient response
            // and the node channel signs it. The merged center must leave it non-final and route the same command again.
            var transient = Submit(target, "hold", "--hold-ms", "500");
            delay.StopOnce(transient.Meta.CommandId);
            var firstAttempt = await own.SubmitAsync(targetId, Origin.Script, transient);
            Assert.Equal(("node_stopping", EffectCertainty.DidNotHappen, RetryMode.AfterTime),
                (firstAttempt.Error?.Code, firstAttempt.Error?.Effect, firstAttempt.Error?.Retry?.Mode));
            Assert.NotNull(firstAttempt.Error!.Retry.RetryAt);
            Assert.Equal(0L, target.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", transient.Meta.CommandId.Value.ToByteArray()))));
            var retried = await own.SubmitAsync(targetId, Origin.Script, transient);
            Assert.Null(retried.Error);
            Assert.Equal(TaskState.Succeeded, (await WaitLocalAsync(human, retried.Value.TaskId, WaitTarget.Terminal)).State);
            Assert.Equal(1L, target.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", transient.Meta.CommandId.Value.ToByteArray()))));

            // N2-19: two different relayed origins share one queue and the same fixed pool capacity.
            Assert.Null((await human.Queue.SetParallelismAsync(new QueueServiceSetParallelismRequest
            {
                Meta = CloudNode.Command(),
                Scope = ParallelismScope.Global,
                Mode = ParallelismMode.Fixed,
                Fixed = 1,
            }, cancellationToken: Ct)).Error);
            Assert.Null((await human.Queue.PausePoolAsync(new QueueServicePausePoolRequest { Meta = CloudNode.Command(), All = true }, cancellationToken: Ct)).Error);
            var one = await own.SubmitAsync(targetId, Origin.Human, Submit(target, "hold", "--hold-ms", "120000"));
            var two = await own.SubmitAsync(targetId, Origin.Script, Submit(target, "hold", "--hold-ms", "120000"));
            Assert.Null(one.Error);
            Assert.Null(two.Error);
            await TestNode.WaitAsync(async () =>
            {
                var snapshot = await human.Queue.GetQueueAsync(new QueueServiceGetQueueRequest { Meta = CloudNode.Command() }, cancellationToken: Ct);
                Assert.Null(snapshot.Error);
                return snapshot.Value.Entries.Count(entry => entry.TaskId.Equals(one.Value.TaskId) || entry.TaskId.Equals(two.Value.TaskId)) == 2;
            }, TimeSpan.FromSeconds(30), "both routed tasks in the shared queue");
            var queue = await human.Queue.GetQueueAsync(new QueueServiceGetQueueRequest { Meta = CloudNode.Command() }, cancellationToken: Ct);
            Assert.Null(queue.Error);
            var entries = queue.Value.Entries.Where(entry => entry.TaskId.Equals(one.Value.TaskId) || entry.TaskId.Equals(two.Value.TaskId)).ToArray();
            Assert.Equal(2, entries.Length);
            Assert.NotEqual(entries[0].Queue.Position, entries[1].Queue.Position);
            Assert.Equal(Origin.Human, entries.Single(entry => entry.TaskId.Equals(one.Value.TaskId)).Owner.CenterCaller.LocalOrigin);
            Assert.Equal(Origin.Script, entries.Single(entry => entry.TaskId.Equals(two.Value.TaskId)).Owner.CenterCaller.LocalOrigin);
            var policy = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = CloudNode.Command() }, cancellationToken: Ct);
            Assert.Null(policy.Error);
            Assert.Contains(policy.Value.Document.Parallelism, rule => rule.Scope == ParallelismScope.Global && rule.Mode == ParallelismMode.Fixed && rule.Fixed == 1);
            Assert.True(queue.Value.Budget.GlobalMaxRunning > 0);
            Assert.All(entries, entry => Assert.Equal((100u, 64UL << 20), (entry.Request.CpuMillicores, entry.Request.MemExpectedBytes)));
            Assert.Null((await human.Queue.ResumePoolAsync(new QueueServiceResumePoolRequest { Meta = CloudNode.Command(), All = true }, cancellationToken: Ct)).Error);
            await TestNode.WaitAsync(async () => (await human.Queue.GetQueueAsync(new QueueServiceGetQueueRequest { Meta = CloudNode.Command() }, cancellationToken: Ct)).Value.Budget.GlobalRunning == 1,
                TimeSpan.FromSeconds(30), "one task registered in the shared budget");
            var runningBudget = await human.Queue.GetQueueAsync(new QueueServiceGetQueueRequest { Meta = CloudNode.Command() }, cancellationToken: Ct);
            Assert.Null(runningBudget.Error);
            Assert.Equal(1u, runningBudget.Value.Budget.GlobalRunning);
            Assert.Equal(queue.Value.Budget.GlobalMaxRunning, runningBudget.Value.Budget.GlobalMaxRunning);
            Assert.True(runningBudget.Value.Budget.AccountedMemBytes > 0);
            var states = new List<TaskState>();
            foreach (var id in new[] { one.Value.TaskId, two.Value.TaskId })
            {
                var task = await human.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = CloudNode.Command(), TaskId = id }, cancellationToken: Ct);
                Assert.Null(task.Error);
                states.Add(task.Value.Task.State);
            }

            Assert.Equal(new[] { TaskState.Queued, TaskState.Running }, states.OrderBy(state => state));
            foreach (var (id, origin) in new[] { (one.Value.TaskId, Origin.Human), (two.Value.TaskId, Origin.Script) })
            {
                var cancelled = await own.CancelAsync(targetId, origin, new TaskServiceCancelTaskRequest { Meta = CloudNode.Command(), TaskId = id });
                Assert.Null(cancelled.Error);
                Assert.Equal(TaskState.Cancelled, (await WaitLocalAsync(human, id, WaitTarget.Terminal)).State);
            }

            // node-approve handles each begin/result pair in sequence. The first result covers only the completed own-node
            // run/list/output/cancel and shared-queue stage; the target stays connected while the second case is approved.
            WriteResult(directory, "n2b-target", passed: true, "own-node routed operations and shared queue");
            resultsWritten.Add("n2b-target");
            var relayFlow = await BeginAsync(relayer, relayHuman, center, directory, "n2b-relayer");
            begun.Add("n2b-relayer");
            await AwaitSignInAsync(relayHuman, relayFlow, "relayer");
            using var other = new RelayClient(relayer, center);

            // N2-17: hold the real result after the task row commits, kill only the harness center, restart over the same PG,
            // reconnect and resend exactly the same inner bytes and command ID with a fresh assertion.
            var interrupted = Submit(target, "hold", "--hold-ms", "500");
            delay.Arm(interrupted.Meta.CommandId);
            var first = own.SubmitRawAsync(targetId, Origin.Script, interrupted);
            await delay.Held.Task.WaitAsync(TimeSpan.FromSeconds(30), Ct);
            await HarnessAsync(harness, "center-crash");
            centerStopped = true;
            delay.Release.TrySetResult();
            await TestNode.WaitAsync(async () => (await StatusAsync(human)).Relay != RelayState.Connected, ConnectedTimeout, "target observes the stopped center");
            await TestNode.WaitAsync(async () => (await StatusAsync(relayHuman)).Relay != RelayState.Connected, ConnectedTimeout, "relayer observes the stopped center");
            try
            {
                var firstAnswer = await first;
                Assert.NotNull(firstAnswer.Error);
            }
            catch (RpcException exception) when (exception.StatusCode is StatusCode.Unavailable or StatusCode.Cancelled or StatusCode.DeadlineExceeded)
            {
                // An interrupted transport is expected; neither it nor an UNKNOWN response proves the effect failed.
            }

            await HarnessAsync(harness, "center-start");
            centerStopped = false;
            await AwaitConnectedAsync(human, "target after center restart");
            await AwaitConnectedAsync(relayHuman, "relayer after center restart");
            var resumed = await own.OutputAsync(targetId, Origin.Script, new TaskServiceReadTaskOutputRequest
            {
                Meta = CloudNode.Command(),
                AttemptId = ended.CurrentAttempt.AttemptId,
                FromOffset = output.Value.NextOffset,
                MaxBytes = 512,
            });
            Assert.Null(resumed.Error);
            Assert.Equal((512, 2048UL), (resumed.Value.Data.Length, resumed.Value.NextOffset));
            var localOutput = await human.Tasks.ReadTaskOutputAsync(new TaskServiceReadTaskOutputRequest
            {
                Meta = CloudNode.Command(),
                AttemptId = ended.CurrentAttempt.AttemptId,
                FromOffset = 1024,
                MaxBytes = 1024,
            }, cancellationToken: Ct);
            Assert.Null(localOutput.Error);
            Assert.Equal(localOutput.Value.Data.ToByteArray(), output.Value.Data.Concat(resumed.Value.Data).ToArray());
            var replay = await own.SubmitAsync(targetId, Origin.Script, interrupted);
            Assert.Null(replay.Error);
            var replayId = replay.Value.TaskId;
            Assert.Equal(1L, target.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", interrupted.Meta.CommandId.Value.ToByteArray()))));
            Assert.Equal(TaskState.Succeeded, (await WaitLocalAsync(human, replayId, WaitTarget.Terminal)).State);

            // A second final replay traverses the center's ComparableReplay path. This must return the recorded node result, not replay_digest_differs.
            var finalReplay = await own.SubmitAsync(targetId, Origin.Script, interrupted);
            Assert.Null(finalReplay.Error);
            Assert.Equal(replayId, finalReplay.Value.TaskId);
            Assert.Equal(1L, target.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", interrupted.Meta.CommandId.Value.ToByteArray()))));

            // The target remains own-node-only through the preceding acceptance. Opt in cross-node only for offline and clock cases,
            // where the second node can relay while the target's channel or wall clock is faulted.
            await SetCrossNodeAsync(human);
            var off = await human.Account.SetCloudLinkAsync(new AccountServiceSetCloudLinkRequest { Meta = CloudNode.Command(), Enabled = false }, cancellationToken: Ct);
            Assert.Null(off.Error);
            await TestNode.WaitAsync(async () => (await StatusAsync(human)).Relay == RelayState.Disabled, ConnectedTimeout, "target channel disabled");
            var offline = await other.SubmitRawAsync(targetId, Origin.Script, Submit(target, "hold", "--hold-ms", "100"));
            Assert.Equal("node_offline", offline.Error?.Code);
            Assert.Equal(EffectCertainty.DidNotHappen, offline.Error!.Effect);
            Assert.Null((await human.Account.SetCloudLinkAsync(new AccountServiceSetCloudLinkRequest { Meta = CloudNode.Command(), Enabled = true }, cancellationToken: Ct)).Error);
            await AwaitConnectedAsync(human, "target after enabling link");

            // N2-20 and N2-18 share a running task: all six operations must be expired by the target's fast clock,
            // including a cancel, and the same task must then survive browser-driven revocation.
            var surviving = await own.SubmitAsync(targetId, Origin.Script, Submit(target, "hold", "--hold-ms", "45000"));
            Assert.Null(surviving.Error);
            Assert.Equal(TaskState.Running, (await WaitLocalAsync(human, surviving.Value.TaskId, WaitTarget.Started)).State);
            var expired = Submit(target, "hold", "--hold-ms", "100");
            var probes = new (RoutedMethod Method, IMessage Request, Id? Command)[]
            {
                (RoutedMethod.SubmitNodeTask, expired, expired.Meta.CommandId),
                (RoutedMethod.GetNodeTask, new TaskServiceGetTaskRequest { Meta = CloudNode.Command(), TaskId = surviving.Value.TaskId }, null),
                (RoutedMethod.ListNodeTasks, new TaskServiceListTasksRequest { Meta = CloudNode.Command() }, null),
                (RoutedMethod.WaitNodeTask, new TaskServiceWaitTaskRequest { Meta = CloudNode.Command(), TaskId = surviving.Value.TaskId, WaitMs = 1000 }, null),
                (RoutedMethod.ReadNodeTaskOutput, new TaskServiceReadTaskOutputRequest { Meta = CloudNode.Command(), AttemptId = ended.CurrentAttempt.AttemptId, MaxBytes = 1 }, null),
                CancelProbe(surviving.Value.TaskId),
            };
            clock.OffsetSeconds = 400;
            try
            {
                foreach (var (method, request, command) in probes)
                {
                    var error = await other.ErrorAsync(targetId, Origin.Script, method, request, command);
                    Assert.True(error is { Code: "expired", Effect: EffectCertainty.DidNotHappen }, method + ": expected expired before effect, got " + error?.Code);
                }

                Assert.Equal(0L, target.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM task WHERE remote_command_id = $id;", ("$id", expired.Meta.CommandId.Value.ToByteArray()))));
                var afterExpiry = await human.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = CloudNode.Command(), TaskId = surviving.Value.TaskId }, cancellationToken: Ct);
                Assert.Null(afterExpiry.Error);
                Assert.Equal(TaskState.Running, afterExpiry.Value.Task.State);
            }
            finally
            {
                clock.OffsetSeconds = 0;
            }

            // The first result already covered only the own-node phase. The second releases node-approve to revoke both devices;
            // browser cleanup and the task's continued execution are verified after it, by this test's final result.
            WriteResult(directory, "n2b-relayer", passed: true, "restart, replay, offline and expiry checks; revocation pending");
            resultsWritten.Add("n2b-relayer");

            await TestNode.WaitAsync(async () => !(await StatusAsync(human)).SignedIn, TimeSpan.FromMinutes(5), "target revoked by node-approve");
            await TestNode.WaitAsync(async () => (await StatusAsync(human)).Relay == RelayState.Disabled, ConnectedTimeout, "revoked target channel disabled");
            var stillRunning = await human.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = CloudNode.Command(), TaskId = surviving.Value.TaskId }, cancellationToken: Ct);
            Assert.Null(stillRunning.Error);
            Assert.Equal(TaskState.Running, stillRunning.Value.Task.State);
            Assert.Equal(TaskState.Succeeded, (await WaitLocalAsync(human, surviving.Value.TaskId, WaitTarget.Terminal)).State);
            await TestNode.WaitAsync(async () => !(await StatusAsync(relayHuman)).SignedIn, TimeSpan.FromMinutes(5), "relayer revoked by node-approve");
        }
        finally
        {
            delay.Release.TrySetResult();
            clock.OffsetSeconds = 0;
            if (centerStopped)
            {
                await HarnessAsync(harness, "center-start");
            }

            foreach (var name in begun.Where(name => !resultsWritten.Contains(name)))
            {
                WriteResult(directory, name, passed: false, "interrupted");
            }

            // If a failure prevented browser revocation, delete this test's credentials rather than leaving them in its isolated store.
            await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command(), RevokeRemote = false }, cancellationToken: CancellationToken.None);
            await relayHuman.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command(), RevokeRemote = false }, cancellationToken: CancellationToken.None);
        }
    }

    /// <summary>
    /// N3-10: a literal HUMAN CLI in a Linux PTY and SCRIPT CLIs use the actual node proxy, loopback center and PostgreSQL.
    /// The browser passkey and node secret store are isolated test substitutes, never hosted or owner-device proof.
    /// </summary>
    [Fact(Timeout = 600_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RealCliRoutesThroughTheLocalNodeAndCenter()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        var url = Environment.GetEnvironmentVariable("ARCFORGES_E2E_CENTER_URL");
        Assert.SkipUnless(!string.IsNullOrEmpty(url), "ARCFORGES_E2E_CENTER_URL is not set");
        Assert.SkipUnless(OperatingSystem.IsLinux() && File.Exists("/usr/bin/script"), "the real center PTY acceptance requires Linux and script");
        Assert.SkipWhen(ArcForges.Tests.SystemdTestEnvironment.SkipReason is not null, ArcForges.Tests.SystemdTestEnvironment.SkipReason ?? string.Empty);
        Assert.True(CenterEndpoint.TryParse(url, out var center, out var reason), reason);
        Assert.True(center.Scheme == "http" && (center.Host == "localhost" || (IPAddress.TryParse(center.Host, out var address) && IPAddress.IsLoopback(address)))
            && center.PathBase.Length == 0, "the isolated acceptance center must be loopback");
        var directory = Environment.GetEnvironmentVariable("ARCFORGES_E2E_DIR");
        Assert.True(!string.IsNullOrEmpty(directory) && Path.IsPathFullyQualified(directory), "ARCFORGES_E2E_DIR must be absolute");
        Directory.CreateDirectory(directory);
        await using var node = CloudNode.Create(center.Url);
        node.TestMode = true;
        node.AllowLocalScriptSubmit = false;
        // The existing isolated test-mode image hook verifies this real CLI executable as HUMAN when it has a PTY.
        // This fact is exclusive and the process environment is restored immediately after startup.
        var imageBefore = Environment.GetEnvironmentVariable(ClientImages.TestVariable);
        try
        {
            Environment.SetEnvironmentVariable(ClientImages.TestVariable, CloudNode.HelperExecutable);
            await node.StartAsync();
        }
        finally
        {
            Environment.SetEnvironmentVariable(ClientImages.TestVariable, imageBefore);
        }

        await using var human = await node.ChannelAsync(Origin.Human);
        var begun = false;
        var resultWritten = false;
        try
        {
            var flow = await BeginAsync(node, human, center, directory, "n3-cli");
            begun = true;
            await AwaitSignInAsync(human, flow, "N3 CLI node");

            var pty = await CliAsync(node, pty: true, "run", "--wait", "--env-inherit", "none", "--cwd", node.Root,
                "--title", "n3-pty-check", "--", "/bin/sh", "-c", "printf human-pty; /bin/sleep 1; exit 7");
            Assert.True(pty.ExitCode == 7, "PTY run: " + pty);
            Assert.Equal("human-pty", pty.Output);
            var localList = await human.Tasks.ListTasksAsync(new TaskServiceListTasksRequest { Meta = CloudNode.Command(), Filter = new TaskFilter() }, cancellationToken: Ct);
            Assert.Null(localList.Error);
            var ptyTask = Assert.Single(localList.Value.Tasks, task => task.Title == "n3-pty-check");
            Assert.Equal(Origin.Remote, ptyTask.Owner.Origin);
            Assert.Equal(Origin.Human, ptyTask.Owner.CenterCaller.LocalOrigin);

            var submitted = await CliAsync(node, pty: false, "run", "--detach", "--env-inherit", "none", "--cwd", node.Root,
                "--", "/bin/sh", "-c", "printf alpha; /bin/sleep 5; printf omega");
            Assert.True(submitted.ExitCode == 0, "script submission: " + submitted);
            var id = submitted.Output.Trim();
            Assert.True(IdText.TryParse(id, out _), "script submission did not return a task ID");
            var followed = await CliAsync(node, pty: false, "output", id, "--follow");
            Assert.True(followed.ExitCode == 0, "output follow: " + followed);
            Assert.Equal("alphaomega", followed.Output);
            Assert.Empty(followed.Error);
            var waited = await CliAsync(node, pty: false, "tasks", "wait", id, "--output", "all");
            Assert.True(waited.ExitCode == 0, "tasks wait: " + waited);
            Assert.Equal("alphaomega", waited.Output);
            var listed = await CliAsync(node, pty: false, "tasks");
            Assert.True(listed.ExitCode == 0, "tasks list: " + listed);
            Assert.Contains(id, listed.Output, StringComparison.Ordinal);
            var shown = await CliAsync(node, pty: false, "tasks", "show", id);
            Assert.True(shown.ExitCode == 0, "tasks show: " + shown);
            Assert.Contains(id, shown.Output, StringComparison.Ordinal);
            var info = await human.Node.GetNodeInfoAsync(new NodeServiceGetNodeInfoRequest { Meta = CloudNode.Command() }, cancellationToken: Ct);
            Assert.Null(info.Error);
            var byName = await CliAsync(node, pty: false, "tasks", "list", "--node", info.Value.Node.Node.Name);
            Assert.True(byName.ExitCode == 0, "tasks list by name: " + byName);
            Assert.Contains(id, byName.Output, StringComparison.Ordinal);
            var uuid = new Guid(node.Runtime.NodeId.Span, bigEndian: true).ToString("D");
            var byId = await CliAsync(node, pty: false, "tasks", "list", "--node", uuid);
            Assert.True(byId.ExitCode == 0, "tasks list by UUID: " + byId);
            Assert.Contains(id, byId.Output, StringComparison.Ordinal);

            // Unlike the framework-dependent testload, this system program needs no runtime variables in the deliberately empty environment.
            var holding = await CliAsync(node, pty: false, "run", "--detach", "--env-inherit", "none", "--cwd", node.Root,
                "--", "/bin/sleep", "120");
            Assert.True(holding.ExitCode == 0, "hold submission: " + holding);
            var held = holding.Output.Trim();
            Assert.True(IdText.TryParse(held, out var heldBytes), "hold submission did not return a task ID");
            var started = await CliAsync(node, pty: false, "tasks", "wait", held, "--for", "started", "--output", "none");
            Assert.True(started.ExitCode == 0, "hold start: " + started);
            var heldId = new Id { Value = ByteString.CopyFrom(heldBytes) };
            var beforeCancel = await human.Tasks.GetTaskAsync(new TaskServiceGetTaskRequest { Meta = CloudNode.Command(), TaskId = heldId }, cancellationToken: Ct);
            Assert.Null(beforeCancel.Error);
            Assert.True(beforeCancel.Value.Task.State == TaskState.Running,
                "hold was not running before cancellation; wait=" + started + "; task=" + beforeCancel.Value.Task);
            var cancelled = await CliAsync(node, pty: false, "tasks", "cancel", held);
            Assert.True(cancelled.ExitCode == 0, "hold cancellation: " + cancelled);
            var ended = await WaitLocalAsync(human, heldId, WaitTarget.Terminal);
            Assert.True(ended.State == TaskState.Cancelled, "hold did not cancel; cancel=" + cancelled + "; task=" + ended);
            Assert.Equal(Origin.Remote, ended.Owner.Origin);
            Assert.Equal(Origin.Script, ended.Owner.CenterCaller.LocalOrigin);
            WriteResult(directory, "n3-cli", passed: true, "PTY HUMAN and SCRIPT through actual proxy, center and node");
            resultWritten = true;
        }
        finally
        {
            if (begun && !resultWritten)
            {
                WriteResult(directory, "n3-cli", passed: false, "interrupted");
            }

            await human.Account.SignOutAsync(new AccountServiceSignOutRequest { Meta = CloudNode.Command(), RevokeRemote = false }, cancellationToken: CancellationToken.None);
        }
    }

    private static async Task<ProcessRun> CliAsync(CloudNode node, bool pty, params string[] args)
    {
        static string ShellQuote(string value) => "'" + value.Replace("'", "'\"'\"'", StringComparison.Ordinal) + "'";
        var start = new ProcessStartInfo(pty ? "/usr/bin/script" : CloudNode.HelperExecutable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
        };
        if (pty)
        {
            start.ArgumentList.Add("-qefc");
            start.ArgumentList.Add(string.Join(' ', new[] { CloudNode.HelperExecutable, NodeLocations.TestModeOption }.Concat(args).Select(ShellQuote)));
            start.ArgumentList.Add("/dev/null");
        }
        else
        {
            start.ArgumentList.Add(NodeLocations.TestModeOption);
            foreach (var arg in args)
            {
                start.ArgumentList.Add(arg);
            }
        }

        start.Environment[NodeLocations.EndpointVariable] = node.Endpoint.Address;
        start.Environment[NodeLocations.ConfigDirectoryVariable] = Path.GetDirectoryName(node.ConfigPath)!;
        start.Environment.Remove(ArcForges.Security.Secrets.OsSecretStoreGuard.OptInVariable);
        foreach (var name in ClientProcess.CiVariables)
        {
            start.Environment.Remove(name);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("The acceptance CLI did not start.");
        var stdout = process.StandardOutput.ReadToEndAsync(Ct);
        var stderr = process.StandardError.ReadToEndAsync(Ct);
        try
        {
            await process.WaitForExitAsync(Ct).WaitAsync(TimeSpan.FromSeconds(60), Ct);
        }
        catch (Exception exception) when (exception is TimeoutException or OperationCanceledException)
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None);
            }

            throw;
        }

        return new ProcessRun(process.ExitCode, await stdout, await stderr);
    }

    private static TaskSpec Spec(CloudNode node, params string[] args)
    {
        var argv = new ArgvCommand();
        argv.Argv.Add(CloudNode.TestLoad);
        argv.Argv.Add(args);
        return new TaskSpec
        {
            Command = new CommandSpec { Argv = argv },
            WorkingDirectory = node.Root,
            Environment = new EnvironmentSpec { Inherit = EnvironmentInherit.Node },
            Resources = new ResourceSpec { Hint = new ResourceDemand { CpuMillicores = 100, MemExpectedBytes = 64UL << 20 } },
        };
    }

    private static TaskServiceSubmitTaskRequest Submit(CloudNode node, params string[] args) => new() { Meta = CloudNode.Command(), Spec = Spec(node, args) };

    private static (RoutedMethod Method, IMessage Request, Id? Command) CancelProbe(Id task)
    {
        var request = new TaskServiceCancelTaskRequest { Meta = CloudNode.Command(), TaskId = task };
        return (RoutedMethod.CancelNodeTask, request, request.Meta.CommandId);
    }

    private static async Task<SignInFlow> BeginAsync(CloudNode node, NodeChannel human, CenterEndpoint center, string directory, string name)
    {
        var nodeName = "n2b-" + Guid.NewGuid().ToString("N")[..8];
        Assert.Null((await human.Node.RenameNodeAsync(new NodeServiceRenameNodeRequest { Meta = CloudNode.Command(), Name = nodeName }, cancellationToken: Ct)).Error);
        var response = await human.Account.BeginSignInAsync(new AccountServiceBeginSignInRequest { Meta = CloudNode.Command(), Method = SignInMethod.DeviceCode }, cancellationToken: Ct);
        Assert.Null(response.Error);
        var flow = response.Value.Flow;
        Write(directory, name + ".begin.json", new JsonObject
        {
            ["case"] = name,
            ["kind"] = "device",
            ["url"] = flow.VerificationUriComplete,
            ["fingerprint"] = flow.NodeKeyFingerprint,
            ["name"] = nodeName,
            ["os"] = "Linux",
            ["arch"] = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64 ? "Arm64" : "x64",
            ["version"] = NodeContract.ProductVersion.Split('+')[0],
            ["centerHost"] = center.Port is { } port ? center.Host + ":" + port : center.Host,
            ["decision"] = "approve",
            ["userCode"] = SignInUrls.DisplayUserCode(flow.UserCode),
        });
        return flow;
    }

    private static async Task AwaitSignInAsync(NodeChannel human, SignInFlow flow, string name)
    {
        await TestNode.WaitAsync(async () => (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Ct)).Value.Flow.State
            is not (SignInFlowState.Pending or SignInFlowState.Completing), TimeSpan.FromMinutes(5), name + " sign-in decision");
        var ended = (await human.Account.GetSignInFlowAsync(new AccountServiceGetSignInFlowRequest { FlowId = flow.FlowId }, cancellationToken: Ct)).Value.Flow;
        Assert.Equal(SignInFlowState.SignedIn, ended.State);
        await AwaitConnectedAsync(human, name + " channel");
    }

    private static async Task<AccountStatus> StatusAsync(NodeChannel channel) =>
        (await channel.Account.GetAccountStatusAsync(new AccountServiceGetAccountStatusRequest(), cancellationToken: Ct)).Value.Status;

    private static Task AwaitConnectedAsync(NodeChannel human, string name) =>
        TestNode.WaitAsync(async () => (await StatusAsync(human)).Relay == RelayState.Connected, ConnectedTimeout, name);

    private static async Task SetCrossNodeAsync(NodeChannel human)
    {
        var current = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = CloudNode.Command() }, cancellationToken: Ct);
        Assert.Null(current.Error);
        var document = current.Value.Document.Clone();
        (document.CenterRouted ??= new CenterRoutedPolicy()).RelayedFrom = RelayedFrom.Account;
        var meta = CloudNode.Command();
        meta.ExpectedRev = current.Value.Revision.Revision;
        Assert.Null((await human.Policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = meta, Document = document, Comment = "real-center negative tests" }, cancellationToken: Ct)).Error);
    }

    private static async Task<ManagedTask> WaitLocalAsync(NodeChannel human, Id task, WaitTarget target)
    {
        var response = await human.Tasks.WaitTaskAsync(new TaskServiceWaitTaskRequest { Meta = CloudNode.Command(), TaskId = task, Target = target, WaitMs = 50_000 },
            deadline: DateTime.UtcNow.AddSeconds(58), cancellationToken: Ct);
        Assert.True(response.Error is null && response.Value.Reached, "local wait: " + response.Error?.Code);
        return response.Value.Task;
    }

    private static async Task<ManagedTask> WaitRoutedAsync(RelayClient relay, Id node, Id task, WaitTarget target)
    {
        var result = await relay.WaitAsync(node, Origin.Script, new TaskServiceWaitTaskRequest { Meta = CloudNode.Command(), TaskId = task, Target = target, WaitMs = 50_000 });
        Assert.True(result.Error is null && result.Value.Reached, "routed wait: " + result.Error?.Code);
        return result.Value.Task;
    }

    private static async Task HarnessAsync(string path, string operation)
    {
        var start = new ProcessStartInfo("python3") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add(path);
        start.ArgumentList.Add(operation);
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync(Ct).WaitAsync(TimeSpan.FromSeconds(30), Ct);
        Assert.True(process.ExitCode == 0, "center harness " + operation + " failed: " + await stdout + " " + await stderr);
    }

    private static void WriteResult(string directory, string name, bool passed, string outcome) => Write(directory, name + ".result.json", new JsonObject
    {
        ["case"] = name,
        ["kind"] = "device",
        ["passed"] = passed,
        ["steps"] = new JsonArray { new JsonObject { ["name"] = "routed acceptance", ["ok"] = passed, ["outcome"] = outcome } },
        ["requests"] = new JsonArray(),
    });

    private static void Write(string directory, string name, JsonObject value)
    {
        var temporary = Path.Combine(directory, "." + name + ".tmp");
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }

        using (var file = new FileStream(temporary, options))
        using (var writer = new StreamWriter(file))
        {
            writer.Write(value.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n");
        }

        File.Move(temporary, Path.Combine(directory, name), overwrite: true);
    }

    private sealed class OffsetClock : TimeProvider
    {
        private int _offsetSeconds;
        public int OffsetSeconds { get => Volatile.Read(ref _offsetSeconds); set => Volatile.Write(ref _offsetSeconds, value); }
        public override DateTimeOffset GetUtcNow() => TimeProvider.System.GetUtcNow().AddSeconds(OffsetSeconds);
    }

    private sealed class DelayResult
    {
        private Id? _command;
        private Id? _stopCommand;
        public TaskCompletionSource Held { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Arm(Id command) => _command = command;
        public void StopOnce(Id command) => Volatile.Write(ref _stopCommand, command);
        public bool Matches(VerifiedCall call) => _command is not null && Equals(call.Header.CommandId, _command);

        public bool TakeStop(VerifiedCall call)
        {
            var command = Volatile.Read(ref _stopCommand);
            return command is not null && Equals(call.Header.CommandId, command)
                && ReferenceEquals(Interlocked.CompareExchange(ref _stopCommand, null, command), command);
        }
    }

    // Inject the stopping condition for one identified delivery, leaving usability and all other deliveries untouched.
    private sealed class StoppingLink(IRoutedLink inner) : IRoutedLink
    {
        public bool Usable => inner.Usable;
        public bool Stopping => true;
    }

    private sealed class DelayedDispatcher(IRoutedDispatcher inner, DelayResult delay) : IRoutedDispatcher
    {
        public async Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
        {
            var effectiveLink = delay.TakeStop(call) ? new StoppingLink(link) : link;
            var answer = await inner.DispatchAsync(call, effectiveLink, cancellationToken);
            if (delay.Matches(call))
            {
                delay.Held.TrySetResult();
                await delay.Release.Task.WaitAsync(cancellationToken);
            }

            return answer;
        }
    }

    private sealed class RelayClient : IDisposable
    {
        private readonly CloudNode _node;
        private readonly GrpcChannel _channel;
        private readonly FleetService.FleetServiceClient _fleet;
        private readonly Id _session = CommandIds.New();

        public RelayClient(CloudNode node, CenterEndpoint center)
        {
            _node = node;
            var web = new GrpcWebHandler(GrpcWebMode.GrpcWeb, new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });
            _channel = GrpcChannel.ForAddress(center.Origin, new GrpcChannelOptions
            {
                HttpHandler = web,
                HttpVersion = HttpVersion.Version11,
                HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact,
            });
            _fleet = new FleetService.FleetServiceClient(_channel);
        }

        private async Task<(RoutedCaller Caller, ByteString Payload, ByteString Assertion, Metadata Headers)> PrepareAsync(Id target, Origin origin, RoutedMethod method, IMessage request, Id? command)
        {
            var payload = request.ToByteString();
            var assertion = await _node.Cloud.SignRelayAssertionAsync(origin, _session, method, SHA256.HashData(payload.Span), target, command, Ct);
            Assert.NotNull(assertion);
            var file = _node.Cloud.Storage.ReadLink();
            Assert.NotNull(file);
            var credential = _node.Cloud.Storage.ReadRecord(file.Target);
            Assert.NotNull(credential);
            return (new RoutedCaller { Kind = CallerKind.NodeRelay, RelayingNodeId = new Id { Value = ByteString.CopyFrom(_node.Runtime.NodeId.Span) }, LocalOrigin = origin },
                payload, assertion.ToByteString(), new Metadata { { "authorization", "Bearer " + credential.AccessToken } });
        }

        public async Task<FleetServiceSubmitNodeTaskResponse> SubmitRawAsync(Id target, Origin origin, TaskServiceSubmitTaskRequest request)
        {
            var (caller, payload, assertion, headers) = await PrepareAsync(target, origin, RoutedMethod.SubmitNodeTask, request, request.Meta.CommandId);
            return await _fleet.SubmitNodeTaskAsync(new FleetServiceSubmitNodeTaskRequest { Meta = request.Meta.Clone(), NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion },
                headers, DateTime.UtcNow.AddSeconds(20), Ct);
        }

        public async Task<ArcError?> ErrorAsync(Id target, Origin origin, RoutedMethod method, IMessage request, Id? command)
        {
            var (caller, payload, assertion, headers) = await PrepareAsync(target, origin, method, request, command);
            var meta = command is null ? CloudNode.Command() : new RequestMeta { CommandId = command, CorrelationId = CommandIds.New() };
            var deadline = DateTime.UtcNow.AddSeconds(20);
            return method switch
            {
                RoutedMethod.SubmitNodeTask => (await _fleet.SubmitNodeTaskAsync(new FleetServiceSubmitNodeTaskRequest { Meta = meta, NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, deadline, Ct)).Error,
                RoutedMethod.GetNodeTask => (await _fleet.GetNodeTaskAsync(new FleetServiceGetNodeTaskRequest { Meta = meta, NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, deadline, Ct)).Error,
                RoutedMethod.ListNodeTasks => (await _fleet.ListNodeTasksAsync(new FleetServiceListNodeTasksRequest { Meta = meta, NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, deadline, Ct)).Error,
                RoutedMethod.WaitNodeTask => (await _fleet.WaitNodeTaskAsync(new FleetServiceWaitNodeTaskRequest { Meta = meta, NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, deadline, Ct)).Error,
                RoutedMethod.ReadNodeTaskOutput => (await _fleet.ReadNodeTaskOutputAsync(new FleetServiceReadNodeTaskOutputRequest { Meta = meta, NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, deadline, Ct)).Error,
                RoutedMethod.CancelNodeTask => (await _fleet.CancelNodeTaskAsync(new FleetServiceCancelNodeTaskRequest { Meta = meta, NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, deadline, Ct)).Error,
                _ => throw new ArgumentOutOfRangeException(nameof(method)),
            };
        }

        public async Task<TaskServiceSubmitTaskResponse> SubmitAsync(Id target, Origin origin, TaskServiceSubmitTaskRequest request)
        {
            var answer = await SubmitRawAsync(target, origin, request);
            Assert.True(answer.Error is null, "Submit center refusal: " + answer.Error?.Category + "/" + answer.Error?.Code);
            return TaskServiceSubmitTaskResponse.Parser.ParseFrom(answer.Value.Response);
        }

        public async Task<TaskServiceListTasksResponse> ListAsync(Id target, Origin origin, TaskServiceListTasksRequest request)
        {
            var (caller, payload, assertion, headers) = await PrepareAsync(target, origin, RoutedMethod.ListNodeTasks, request, null);
            var answer = await _fleet.ListNodeTasksAsync(new FleetServiceListNodeTasksRequest { Meta = CloudNode.Command(), NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, DateTime.UtcNow.AddSeconds(20), Ct);
            Assert.True(answer.Error is null, "List center refusal: " + answer.Error?.Code);
            return TaskServiceListTasksResponse.Parser.ParseFrom(answer.Value.Response);
        }

        public async Task<TaskServiceWaitTaskResponse> WaitAsync(Id target, Origin origin, TaskServiceWaitTaskRequest request)
        {
            var (caller, payload, assertion, headers) = await PrepareAsync(target, origin, RoutedMethod.WaitNodeTask, request, null);
            var answer = await _fleet.WaitNodeTaskAsync(new FleetServiceWaitNodeTaskRequest { Meta = CloudNode.Command(), NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, DateTime.UtcNow.AddSeconds(60), Ct);
            Assert.True(answer.Error is null, "Wait center refusal: " + answer.Error?.Code);
            return TaskServiceWaitTaskResponse.Parser.ParseFrom(answer.Value.Response);
        }

        public async Task<TaskServiceReadTaskOutputResponse> OutputAsync(Id target, Origin origin, TaskServiceReadTaskOutputRequest request)
        {
            var (caller, payload, assertion, headers) = await PrepareAsync(target, origin, RoutedMethod.ReadNodeTaskOutput, request, null);
            var answer = await _fleet.ReadNodeTaskOutputAsync(new FleetServiceReadNodeTaskOutputRequest { Meta = CloudNode.Command(), NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, DateTime.UtcNow.AddSeconds(20), Ct);
            Assert.True(answer.Error is null, "Output center refusal: " + answer.Error?.Code);
            return TaskServiceReadTaskOutputResponse.Parser.ParseFrom(answer.Value.Response);
        }

        public async Task<TaskServiceCancelTaskResponse> CancelAsync(Id target, Origin origin, TaskServiceCancelTaskRequest request)
        {
            var (caller, payload, assertion, headers) = await PrepareAsync(target, origin, RoutedMethod.CancelNodeTask, request, request.Meta.CommandId);
            var answer = await _fleet.CancelNodeTaskAsync(new FleetServiceCancelNodeTaskRequest { Meta = request.Meta.Clone(), NodeId = target, Caller = caller, Request = payload, RelayAssertion = assertion }, headers, DateTime.UtcNow.AddSeconds(20), Ct);
            Assert.True(answer.Error is null, "Cancel center refusal: " + answer.Error?.Code);
            return TaskServiceCancelTaskResponse.Parser.ParseFrom(answer.Value.Response);
        }

        public void Dispose() => _channel.Dispose();
    }
}
