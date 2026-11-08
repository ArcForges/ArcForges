// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Fleet.V1;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>REAL CLI process, local endpoint and node proxy; the scripted center is MOCKED and never claimed as task execution.</summary>
public sealed class RoutedCliTests
{
    [Fact(Timeout = 60000)]
    public async Task TheDefaultRunRefusesWithoutAConnectedAccount()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync(signedIn: false);
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(4, result.ExitCode);
        Assert.Empty(result.Stdout);
        Assert.Contains("not signed in", result.Stderr, StringComparison.Ordinal);
        Assert.Contains("run --local", result.Stderr, StringComparison.Ordinal);
        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task ADisconnectedOwnChannelDoesNotFallBackToLocalExecution()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await using var human = await fixture.Node.ChannelAsync(Origin.Human);
        var disabled = await human.Account.SetCloudLinkAsync(new AccountServiceSetCloudLinkRequest { Meta = CloudNode.Command(), Enabled = false },
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(disabled.Error);
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(4, result.ExitCode);
        Assert.Empty(result.Stdout);
        Assert.Contains("unavailable", result.Stderr, StringComparison.Ordinal);
        Assert.Contains("run --local", result.Stderr, StringComparison.Ordinal);
        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task ATargetOfflineWithoutAnEarlierUncertainResultExitsSeventyFive()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", Reply(new FleetServiceSubmitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.State,
                Code = "node_offline",
                MessageKey = "error.state.node_offline",
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
            },
        }));
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(75, result.ExitCode);
        Assert.Empty(result.Stdout);
        Assert.DoesNotContain("may have run", result.Stderr, StringComparison.Ordinal);
        Assert.Single(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task ExplicitWaitWithoutDurationIsAttachedAndConflictsWithDetach()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync(signedIn: false);
        var waiting = await fixture.CliAsync("run", "--wait", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(4, waiting.ExitCode);
        Assert.Contains("not signed in", waiting.Stderr, StringComparison.Ordinal);
        var conflicting = await fixture.CliAsync("run", "--detach", "--wait", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(2, conflicting.ExitCode);
        Assert.Contains("cannot be combined", conflicting.Stderr, StringComparison.Ordinal);
    }

    [Fact(Timeout = 60000)]
    public async Task APreviouslyUncertainMutationIsNotReclassifiedAsOffline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        fixture.Center.Script("SubmitNodeTask", Reply(new FleetServiceSubmitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.State,
                Code = "node_offline",
                MessageKey = "error.state.node_offline",
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
            },
        }));
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.NotEqual(0, result.ExitCode);
        Assert.NotEqual(75, result.ExitCode);
        Assert.Contains("may have run", result.Stderr, StringComparison.Ordinal);
        Assert.Equal(2, fixture.Center.CallsOf("SubmitNodeTask").Count);
    }

    [Theory(Timeout = 60000)]
    [InlineData(@"C:\target\work", @"C:\target\input.bin", @"C:\target\ready")]
    [InlineData("/target/work", "/target/input.bin", "/target/ready")]
    [InlineData(@"\\server\share\work", @"\\server\share\input.bin", @"\\server\share\ready")]
    public async Task ForeignTargetPathsAreNotInterpretedByTheCallingOs(string cwd, string stdin, string ready)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var target = CommandIds.New();
        var task = CommandIds.New();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(target, task)));
        var uuid = new Guid(target.Value.Span, bigEndian: true).ToString("D");
        var result = await fixture.CliAsync("run", "--detach", "--node", uuid, "--cwd", cwd, "--stdin", "file:" + stdin,
            "--ready-file", ready, "--env-inherit", "none", "--", "test-program");
        Assert.Equal(0, result.ExitCode);
        var outer = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("SubmitNodeTask")).Body));
        var inner = TaskServiceSubmitTaskRequest.Parser.ParseFrom(outer.Request);
        Assert.Equal(cwd, inner.Spec.WorkingDirectory);
        Assert.Equal(stdin, inner.Spec.Stdin.FilePath);
        Assert.Equal(ready, inner.Spec.Readiness.FileExists);
    }

    [Fact(Timeout = 60000)]
    public async Task ForeignTargetRequiresExplicitAbsolutePaths()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var target = CommandIds.New();
        var uuid = new Guid(target.Value.Span, bigEndian: true).ToString("D");
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(target, CommandIds.New())));
        var missing = await fixture.CliAsync("run", "--detach", "--node", uuid, "--env-inherit", "none", "--", "test-program");
        Assert.Equal(2, missing.ExitCode);
        Assert.Contains("--cwd", missing.Stderr, StringComparison.Ordinal);
        var relative = await fixture.CliAsync("run", "--detach", "--node", uuid, "--cwd", "relative", "--env-inherit", "none", "--", "test-program");
        Assert.Equal(2, relative.ExitCode);
        Assert.Contains("absolute", relative.Stderr, StringComparison.Ordinal);
        var stdin = await fixture.CliAsync("run", "--detach", "--node", uuid, "--cwd", "/target/work", "--stdin", "file:relative", "--", "test-program");
        Assert.Equal(2, stdin.ExitCode);
        Assert.Contains("--stdin", stdin.Stderr, StringComparison.Ordinal);
        var ready = await fixture.CliAsync("run", "--detach", "--node", uuid, "--cwd", "/target/work", "--ready-file", "relative", "--", "test-program");
        Assert.Equal(2, ready.ExitCode);
        Assert.Contains("--ready-file", ready.Stderr, StringComparison.Ordinal);
        Assert.Empty(fixture.Center.CallsOf("SubmitNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task ExplicitOwnNodeKeepsLocalPathDefaultsAndRelativePaths()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var uuid = new Guid(fixture.NodeId.Value.Span, bigEndian: true).ToString("D");
        var result = await fixture.CliAsync("run", "--detach", "--node", uuid, "--stdin", "file:input.bin", "--ready-file", "ready", "--", "test-program");
        Assert.Equal(0, result.ExitCode);
        var outer = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("SubmitNodeTask")).Body));
        var spec = TaskServiceSubmitTaskRequest.Parser.ParseFrom(outer.Request).Spec;
        Assert.Equal(Directory.GetCurrentDirectory(), spec.WorkingDirectory);
        Assert.Equal(Path.GetFullPath("input.bin"), spec.Stdin.FilePath);
        Assert.Equal(Path.GetFullPath("ready"), spec.Readiness.FileExists);
    }

    [Fact(Timeout = 60000)]
    public async Task JsonOutputPreservesBinaryDataIndexAndEof()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        var attempt = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, task, attempt, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue
        {
            Data = ByteString.CopyFrom([0, 255, 65]),
            NextOffset = 3,
            Eof = true,
            TruncatedByRetention = true,
            Index = { new OutputIndexRecord { Stream = OutputStream.Stdout, Offset = 0, Length = 1 }, new OutputIndexRecord { Stream = OutputStream.Stderr, Offset = 0, Length = 2 } },
        })));
        var result = await fixture.CliAsync("--json", "output", IdText.Format(task));
        Assert.Equal(0, result.ExitCode);
        using var document = System.Text.Json.JsonDocument.Parse(result.Stdout);
        var value = document.RootElement;
        Assert.Equal(new byte[] { 0, 255, 65 }, value.GetProperty("data").GetBytesFromBase64());
        Assert.Equal("3", value.GetProperty("nextOffset").GetString());
        Assert.True(value.GetProperty("eof").GetBoolean());
        Assert.True(value.GetProperty("truncatedByRetention").GetBoolean());
        Assert.Equal(2, value.GetProperty("index").GetArrayLength());
        Assert.Equal("OUTPUT_STREAM_STDOUT", value.GetProperty("index")[0].GetProperty("stream").GetString());
        Assert.Equal("OUTPUT_STREAM_STDERR", value.GetProperty("index")[1].GetProperty("stream").GetString());
        Assert.Equal("0", value.GetProperty("index")[0].GetProperty("offset").GetString());
        Assert.Equal(1U, value.GetProperty("index")[0].GetProperty("length").GetUInt32());
        Assert.Equal("0", value.GetProperty("index")[1].GetProperty("offset").GetString());
        Assert.Equal(2U, value.GetProperty("index")[1].GetProperty("length").GetUInt32());
    }

    [Fact(Timeout = 60000)]
    public async Task JsonOutputFollowUsesLinesAndPreservesOffsetsAndBothStreams()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        var attempt = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, task, attempt, TaskState.Running)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue
        {
            Data = ByteString.CopyFrom([255, 0]),
            NextOffset = 2,
            Eof = false,
            Index = { new OutputIndexRecord { Stream = OutputStream.Stdout, Offset = 0, Length = 2 } },
        })));
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, task, attempt, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue
        {
            Data = ByteString.CopyFrom([128, 66]),
            NextOffset = 4,
            Eof = true,
            Index = { new OutputIndexRecord { Stream = OutputStream.Stderr, Offset = 0, Length = 2 } },
        })));
        var result = await fixture.CliAsync("--json", "output", IdText.Format(task), "--follow");
        Assert.Equal(0, result.ExitCode);
        Assert.Empty(result.Stderr);
        var lines = result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        using var first = System.Text.Json.JsonDocument.Parse(lines[0]);
        using var last = System.Text.Json.JsonDocument.Parse(lines[1]);
        Assert.Equal(new byte[] { 255, 0 }, first.RootElement.GetProperty("data").GetBytesFromBase64());
        Assert.Equal("2", first.RootElement.GetProperty("nextOffset").GetString());
        Assert.False(first.RootElement.GetProperty("eof").GetBoolean());
        Assert.Equal("OUTPUT_STREAM_STDOUT", first.RootElement.GetProperty("index")[0].GetProperty("stream").GetString());
        Assert.Equal(new byte[] { 128, 66 }, last.RootElement.GetProperty("data").GetBytesFromBase64());
        Assert.Equal("4", last.RootElement.GetProperty("nextOffset").GetString());
        Assert.True(last.RootElement.GetProperty("eof").GetBoolean());
        Assert.Equal("OUTPUT_STREAM_STDERR", last.RootElement.GetProperty("index")[0].GetProperty("stream").GetString());
        var reads = fixture.Center.CallsOf("ReadNodeTaskOutput").Select(call => TaskServiceReadTaskOutputRequest.Parser.ParseFrom(
            FleetServiceReadNodeTaskOutputRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body)).Request).FromOffset).ToList();
        Assert.Equal([0UL, 2UL], reads);
    }

    [Fact(Timeout = 60000)]
    public async Task SentMutationTransportFailureStaysUncertain()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        fixture.Center.Script("CancelNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        var meta = CloudNode.Command();
        var inner = new TaskServiceCancelTaskRequest { Meta = meta.Clone(), TaskId = CommandIds.New() }.ToByteString();
        var error = await Assert.ThrowsAsync<Grpc.Core.RpcException>(async () => await fleet.CancelNodeTaskAsync(
            new FleetServiceCancelNodeTaskRequest { Meta = meta, NodeId = fixture.NodeId, Request = inner }, deadline: DateTime.UtcNow.AddSeconds(15),
            cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(Grpc.Core.StatusCode.Unavailable, error.StatusCode);
        Assert.Single(fixture.Center.CallsOf("CancelNodeTask"));
    }

    [Fact(Timeout = 60000)]
    public async Task DisconnectedProxyErrorHasAValidRetryContract()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await using var human = await fixture.Node.ChannelAsync(Origin.Human);
        var disabled = await human.Account.SetCloudLinkAsync(new AccountServiceSetCloudLinkRequest { Meta = CloudNode.Command(), Enabled = false },
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Null(disabled.Error);
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        var correlation = CommandIds.New();
        var response = await fleet.ListNodesAsync(new FleetServiceListNodesRequest { Meta = new RequestMeta { CorrelationId = correlation } },
            deadline: DateTime.UtcNow.AddSeconds(10), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("cloud_unreachable", response.Error.Code);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(response.Error));
        Assert.Equal(correlation, response.Error.CorrelationId);
        Assert.Equal("cloud_link", response.Error.Details.State.State);
        Assert.Equal("channel_not_connected", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.AfterTime, response.Error.Retry.Mode);
        Assert.InRange(ProtoTime.ToDateTimeOffset(response.Error.Retry.RetryAt)!.Value, DateTimeOffset.UtcNow.AddSeconds(-2), DateTimeOffset.UtcNow.AddSeconds(10));
        Assert.Empty(fixture.Center.CallsOf("ListNodes"));
    }

    [Fact(Timeout = 60000)]
    public async Task PreSendConnectionFailureReturnsAValidDidNotHappenError()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        fixture.Node.Cloud.BeforeRelayForward = async token =>
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
            stop.CancelAfter(TimeSpan.FromSeconds(3));
            try
            {
                await fixture.Center.StopAsync(stop.Token);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                // The listener is stopped before the bounded drain of its existing WebSocket completes.
            }
        };
        var meta = CloudNode.Command();
        var inner = new TaskServiceCancelTaskRequest { Meta = meta.Clone(), TaskId = CommandIds.New() }.ToByteString();
        var response = await fleet.CancelNodeTaskAsync(new FleetServiceCancelNodeTaskRequest { Meta = meta, NodeId = fixture.NodeId, Request = inner },
            deadline: DateTime.UtcNow.AddSeconds(15), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal("cloud_unreachable", response.Error.Code);
        Assert.True(ArcForges.Contracts.Node.Shapes.ContractShapeValidation.IsValid(response.Error));
        Assert.Equal(meta.CorrelationId, response.Error.CorrelationId);
        Assert.Equal("cloud_link", response.Error.Details.State.State);
        Assert.Equal("center_unreachable", response.Error.Details.State.Reason);
        Assert.Equal(EffectCertainty.DidNotHappen, response.Error.Effect);
        Assert.Equal(RetryMode.AfterTime, response.Error.Retry.Mode);
        Assert.InRange(ProtoTime.ToDateTimeOffset(response.Error.Retry.RetryAt)!.Value, DateTimeOffset.UtcNow.AddSeconds(-2), DateTimeOffset.UtcNow.AddSeconds(10));
        Assert.Empty(fixture.Center.CallsOf("CancelNodeTask"));
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RoutedListHonorsTheGlobalUnaryDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("ListNodeTasks", new FakeFault.Delay(TimeSpan.FromSeconds(5)));
        fixture.Center.Script("ListNodeTasks", Reply(new FleetServiceListNodeTasksResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodeTasksValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceListTasksResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceListTasksValue { Page = new PageState { HasMore = false } },
                }.ToByteString(),
            },
        }));
        var started = Stopwatch.StartNew();
        var result = await fixture.CliAsync("tasks", "list", "--timeout", "1s");
        Assert.NotEqual(0, result.ExitCode);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(4), "a one-second unary budget must not wait for the five-second reply");
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RoutedWaitHonorsItsRemainingTargetBudget()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        fixture.Center.Script("WaitNodeTask", new FakeFault.Delay(TimeSpan.FromSeconds(5)));
        fixture.Center.Script("WaitNodeTask", Reply(new FleetServiceWaitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceWaitNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceWaitTaskResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceWaitTaskValue { Task = new ManagedTask { TaskId = task, State = TaskState.Running }, Reached = false },
                }.ToByteString(),
            },
        }));
        var started = Stopwatch.StartNew();
        var result = await fixture.CliAsync("tasks", "wait", IdText.Format(task), "--timeout", "1s", "--output", "none");
        Assert.Equal(9, result.ExitCode);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(4), "a one-second wait budget must not wait for the five-second reply");
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task UnaryDeadlineCancelsAStalledNonceWithoutSendingTheRequest()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Channel.AnswerNonces = false;
        var started = Stopwatch.StartNew();
        var result = await fixture.CliAsync("tasks", "list", "--timeout", "1s");
        Assert.NotEqual(0, result.ExitCode);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(4), "the deadline must include the local proxy signing/nonce wait");
        Assert.Empty(fixture.Center.CallsOf("ListNodeTasks"));
        Assert.Contains(fixture.Center.Channel.Connections.SelectMany(connection => connection.Received),
            frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest);
    }

    [Fact(Timeout = 60000)]
    public async Task CallerCancellationDuringNonceWaitNeverSendsTheRequest()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Channel.AnswerNonces = false;
        await using var script = await fixture.Node.ChannelAsync(Origin.Script);
        var fleet = new FleetService.FleetServiceClient(script.CallInvoker);
        using var cancelled = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var pending = fleet.ListNodesAsync(new FleetServiceListNodesRequest { Meta = CloudNode.Command() }, cancellationToken: cancelled.Token).ResponseAsync;
        await Eventually.TrueAsync(() => fixture.Center.Channel.Connections.SelectMany(connection => connection.Received)
            .Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.RelayNonceRequest), "nonce requested");
        await cancelled.CancelAsync();
        var error = await Record.ExceptionAsync(async () => await pending);
        Assert.True(error is OperationCanceledException or Grpc.Core.RpcException { StatusCode: Grpc.Core.StatusCode.Cancelled },
            "the local caller's cancellation must propagate");
        Assert.Empty(fixture.Center.CallsOf("ListNodes"));
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RoutedNameResolutionHonorsTheGlobalUnaryDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("ListNodes", new FakeFault.Delay(TimeSpan.FromSeconds(5)));
        fixture.Center.Script("ListNodes", Reply(new FleetServiceListNodesResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodesValue { Nodes = { new FleetNode { NodeId = fixture.NodeId, Name = "build-box" } } },
        }));
        var started = Stopwatch.StartNew();
        var result = await fixture.CliAsync("tasks", "list", "--node", "build-box", "--timeout", "1s");
        Assert.NotEqual(0, result.ExitCode);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(4), "node-name resolution must honor the one-second unary deadline");
        Assert.Empty(fixture.Center.CallsOf("ListNodeTasks"));
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task TimedOutMutationRetriesTheSameBytesAndCommandWithinTheUnaryDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        fixture.Center.Script("CancelNodeTask", new FakeFault.Delay(TimeSpan.FromSeconds(5)));
        fixture.Center.Script("CancelNodeTask", Reply(new FleetServiceCancelNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceCancelNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceCancelTaskResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceCancelTaskValue { State = TaskState.Cancelled },
                }.ToByteString(),
            },
        }));
        var result = await fixture.CliAsync("tasks", "cancel", IdText.Format(task), "--timeout", "1s");
        Assert.Equal(0, result.ExitCode);
        var calls = fixture.Center.CallsOf("CancelNodeTask");
        Assert.Equal(2, calls.Count);
        var first = FleetServiceCancelNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(calls[0].Body));
        var second = FleetServiceCancelNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(calls[1].Body));
        Assert.Equal(first.Meta.CommandId, second.Meta.CommandId);
        Assert.Equal(first.Request, second.Request);
        Assert.All(calls, call => Assert.InRange(GrpcTimeout(call.GrpcTimeout), TimeSpan.Zero, TimeSpan.FromMilliseconds(1100)));
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task RunTimeoutIsTheTasksExecutionLimitNotTheUnaryDeadline()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        fixture.Center.Script("ListNodes", new FakeFault.Delay(TimeSpan.FromSeconds(2)));
        fixture.Center.Script("ListNodes", Reply(new FleetServiceListNodesResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodesValue { Nodes = { new FleetNode { NodeId = fixture.NodeId, Name = "build-box" } } },
        }));
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Delay(TimeSpan.FromSeconds(2)));
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, CommandIds.New())));
        var result = await fixture.CliAsync("run", "--detach", "--node", "build-box", "--timeout", "1s", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(0, result.ExitCode);
        Assert.True(GrpcTimeout(Assert.Single(fixture.Center.CallsOf("ListNodes")).GrpcTimeout) > TimeSpan.FromSeconds(2));
        var call = Assert.Single(fixture.Center.CallsOf("SubmitNodeTask"));
        var outer = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body));
        Assert.Equal(1000UL, TaskServiceSubmitTaskRequest.Parser.ParseFrom(outer.Request).Spec.TimeoutMs);
        Assert.True(GrpcTimeout(call.GrpcTimeout) > TimeSpan.FromSeconds(2));
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task DefaultRoutedWaitRetainsTheLongPollBudget()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var task = CommandIds.New();
        fixture.Center.Script("WaitNodeTask", new FakeFault.Delay(TimeSpan.FromSeconds(2)));
        fixture.Center.Script("WaitNodeTask", Reply(new FleetServiceWaitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceWaitNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceWaitTaskResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceWaitTaskValue
                    {
                        Reached = true,
                        Task = new ManagedTask
                        {
                            TaskId = task,
                            State = TaskState.Succeeded,
                            CurrentAttempt = new Attempt { Result = new AttemptResult { TerminationReason = TerminationReason.Exited, ExitCode = 0 } }
                        },
                    },
                }.ToByteString(),
            },
        }));
        var result = await fixture.CliAsync("tasks", "wait", IdText.Format(task), "--output", "none");
        Assert.Equal(0, result.ExitCode);
        var call = Assert.Single(fixture.Center.CallsOf("WaitNodeTask"));
        var outer = FleetServiceWaitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body));
        Assert.Equal(50_000UL, TaskServiceWaitTaskRequest.Parser.ParseFrom(outer.Request).WaitMs);
        Assert.True(GrpcTimeout(call.GrpcTimeout) > TimeSpan.FromSeconds(50));
    }

    private static TimeSpan GrpcTimeout(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            throw new InvalidOperationException("The center did not receive a gRPC timeout.");
        }

        var amount = double.Parse(text[..^1], System.Globalization.CultureInfo.InvariantCulture);
        return text[^1] switch
        {
            'H' => TimeSpan.FromHours(amount),
            'M' => TimeSpan.FromMinutes(amount),
            'S' => TimeSpan.FromSeconds(amount),
            'm' => TimeSpan.FromMilliseconds(amount),
            'u' => TimeSpan.FromMicroseconds(amount),
            'n' => TimeSpan.FromTicks((long)(amount / 100)),
            _ => throw new InvalidOperationException("Unknown gRPC timeout unit."),
        };
    }

    [Fact(Timeout = 60000)]
    public async Task ATransportRetryUsesTheSameCommandAndExactInnerBytes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, taskId)));
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(IdText.Format(taskId), result.Stdout.Trim());
        var calls = fixture.Center.CallsOf("SubmitNodeTask").Select(call => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        Assert.Equal(calls[0].Request, calls[1].Request);
        Assert.Equal(calls[0].Meta.CommandId, calls[1].Meta.CommandId);
        var first = RelayAssertion.Parser.ParseFrom(calls[0].RelayAssertion);
        var second = RelayAssertion.Parser.ParseFrom(calls[1].RelayAssertion);
        Assert.Equal(first.CommandId, second.CommandId);
        Assert.Equal(first.RequestSha256, second.RequestSha256);
        Assert.NotEqual(first.RelayNonce, second.RelayNonce);
    }

    [Fact(Timeout = 60000)]
    public async Task AReplayWindowRefusalNamesTheTaskAndNeverCreatesANewCommand()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        fixture.Center.Script("SubmitNodeTask", Reply(new FleetServiceSubmitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.State,
                Code = "invalid_state",
                MessageKey = "error.state.invalid_state",
                Effect = EffectCertainty.DidNotHappen,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Details = new ErrorDetails { State = new StateFailure { State = "task", Reason = "replay_window_passed", Resource = new AggregateRef { Kind = "task", Id = taskId } } },
            },
        }));
        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("may have run", result.Stderr, StringComparison.Ordinal);
        Assert.Contains(IdText.Format(taskId), result.Stderr, StringComparison.Ordinal);
        var calls = fixture.Center.CallsOf("SubmitNodeTask").Select(call => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        Assert.Equal(calls[0].Request, calls[1].Request);
        Assert.Equal(calls[0].Meta.CommandId, calls[1].Meta.CommandId);
        Assert.Contains(IdText.Format(calls[0].Meta.CommandId), result.Stderr, StringComparison.Ordinal);
    }

    [Fact(Timeout = 60000)]
    public async Task AttachedRunMirrorsOutputByOffsetAndReturnsTheTasksExitCode()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        var attemptId = CommandIds.New();
        fixture.Center.Script("SubmitNodeTask", Reply(SubmitResult(fixture.NodeId, taskId)));
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Running)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue
        {
            Data = ByteString.CopyFromUtf8("abXY"),
            NextOffset = 4,
            Index = { new OutputIndexRecord { Stream = OutputStream.Stdout, Length = 2 }, new OutputIndexRecord { Stream = OutputStream.Stderr, Length = 2 } },
        })));
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId, new TaskServiceReadTaskOutputValue { Data = ByteString.Empty, NextOffset = 4, Eof = true })));
        var result = await fixture.CliAsync("run", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.Equal(7, result.ExitCode);
        Assert.Equal("ab", result.Stdout);
        Assert.Equal("XY", result.Stderr);
        var calls = fixture.Center.CallsOf("ReadNodeTaskOutput").Select(call => FleetServiceReadNodeTaskOutputRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(2, calls.Count);
        var first = TaskServiceReadTaskOutputRequest.Parser.ParseFrom(calls[0].Request);
        var second = TaskServiceReadTaskOutputRequest.Parser.ParseFrom(calls[1].Request);
        Assert.Equal(0UL, first.FromOffset);
        Assert.Equal(4UL, second.FromOffset);
        Assert.Equal(attemptId, first.AttemptId);
        Assert.True(first.MaxBytes <= 262_144 && second.MaxBytes <= 262_144);
    }

    [Fact(Timeout = 60000)]
    public async Task NodeSelectionUsesExactNamesOrTheCanonicalUuid()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var selected = fixture.NodeId;
        var other = CommandIds.New();
        fixture.Center.Script("ListNodes", Reply(new FleetServiceListNodesResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodesValue
            {
                Nodes = { new FleetNode { NodeId = selected, Name = "build-box" }, new FleetNode { NodeId = other, Name = "build-box" } },
            },
        }));
        var ambiguous = await fixture.CliAsync("tasks", "list", "--node", "build-box");
        Assert.Equal(2, ambiguous.ExitCode);
        Assert.Contains("ambiguous", ambiguous.Stderr, StringComparison.Ordinal);
        Assert.Empty(fixture.Center.CallsOf("ListNodeTasks"));

        var uuid = new Guid(selected.Value.Span, bigEndian: true).ToString("D");
        fixture.Center.Script("ListNodeTasks", Reply(new FleetServiceListNodeTasksResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceListNodeTasksValue
            {
                NodeId = selected,
                Response = new TaskServiceListTasksResponse
                {
                    Meta = new ResponseMeta(),
                    Value = new TaskServiceListTasksValue { Page = new PageState { HasMore = false } },
                }.ToByteString(),
            },
        }));
        var direct = await fixture.CliAsync("tasks", "list", "--node", uuid, "--json");
        Assert.Equal(0, direct.ExitCode);
        using var json = System.Text.Json.JsonDocument.Parse(direct.Stdout);
        Assert.Equal(System.Text.Json.JsonValueKind.Object, json.RootElement.ValueKind);
        var request = FleetServiceListNodeTasksRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("ListNodeTasks")).Body));
        Assert.Equal(selected, request.NodeId);
        Assert.Single(fixture.Center.CallsOf("ListNodes"));
    }

    [Fact(Timeout = 60000)]
    public async Task OutputResumesAtTheRequestedOffset()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        var attemptId = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId,
            new TaskServiceReadTaskOutputValue { Data = ByteString.CopyFromUtf8("cd"), NextOffset = 4, Eof = true })));
        var result = await fixture.CliAsync("output", IdText.Format(taskId), "--from-offset", "2");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("cd", result.Stdout);
        var outer = FleetServiceReadNodeTaskOutputRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("ReadNodeTaskOutput")).Body));
        Assert.Equal(2UL, TaskServiceReadTaskOutputRequest.Parser.ParseFrom(outer.Request).FromOffset);
    }

    [Fact(Timeout = 60000)]
    public async Task OutputFollowKeepsAFutureOffsetWithoutReplayingEarlierBytes()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        var attemptId = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Running)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId,
            new TaskServiceReadTaskOutputValue { Data = ByteString.Empty, NextOffset = 2, Eof = false })));
        fixture.Center.Script("GetNodeTask", Reply(GetResult(fixture.NodeId, taskId, attemptId, TaskState.Succeeded)));
        fixture.Center.Script("ReadNodeTaskOutput", Reply(ReadResult(fixture.NodeId,
            new TaskServiceReadTaskOutputValue { Data = ByteString.CopyFromUtf8("xy"), NextOffset = 7, Eof = true })));
        var result = await fixture.CliAsync("output", IdText.Format(taskId), "--from-offset", "5", "--follow");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("xy", result.Stdout);
        Assert.Empty(result.Stderr);
        var offsets = fixture.Center.CallsOf("ReadNodeTaskOutput").Select(call =>
            TaskServiceReadTaskOutputRequest.Parser.ParseFrom(FleetServiceReadNodeTaskOutputRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body)).Request).FromOffset).ToList();
        Assert.Equal([5UL, 5UL], offsets);
    }

    [Fact(Timeout = 60000)]
    public async Task WaitShowAndCancelUseTheSelectedRoutedMethods()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        var attemptId = CommandIds.New();
        var task = new ManagedTask
        {
            TaskId = taskId,
            State = TaskState.Succeeded,
            Title = "safe\u001b[2Jtitle",
            CurrentAttempt = new Attempt { AttemptId = attemptId, Result = new AttemptResult { TerminationReason = TerminationReason.Exited, ExitCode = 0 } },
        };
        fixture.Center.Script("GetNodeTask", Reply(new FleetServiceGetNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceGetNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceGetTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceGetTaskValue { Task = task } }.ToByteString(),
            },
        }));
        var shown = await fixture.CliAsync("tasks", "show", IdText.Format(taskId));
        Assert.Equal(0, shown.ExitCode);
        Assert.DoesNotContain("\u001b", shown.Stdout, StringComparison.Ordinal);
        Assert.Contains("safe?[2Jtitle", shown.Stdout, StringComparison.Ordinal);

        fixture.Center.Script("WaitNodeTask", Reply(new FleetServiceWaitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceWaitNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceWaitTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceWaitTaskValue { Task = task, Reached = true } }.ToByteString(),
            },
        }));
        var waited = await fixture.CliAsync("tasks", "wait", IdText.Format(taskId), "--output", "none");
        Assert.Equal(0, waited.ExitCode);
        var wait = FleetServiceWaitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("WaitNodeTask")).Body));
        Assert.True(TaskServiceWaitTaskRequest.Parser.ParseFrom(wait.Request).WaitMs <= 50_000);

        fixture.Center.Script("CancelNodeTask", Reply(new FleetServiceCancelNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Value = new FleetServiceCancelNodeTaskValue
            {
                NodeId = fixture.NodeId,
                Response = new TaskServiceCancelTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceCancelTaskValue { State = TaskState.Cancelled } }.ToByteString(),
            },
        }));
        var cancelled = await fixture.CliAsync("tasks", "cancel", IdText.Format(taskId), "--reason", "test");
        Assert.Equal(0, cancelled.ExitCode);
        var cancel = FleetServiceCancelNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("CancelNodeTask")).Body));
        Assert.Equal(cancel.Meta.CommandId, TaskServiceCancelTaskRequest.Parser.ParseFrom(cancel.Request).Meta.CommandId);
    }

    [Fact(Timeout = 60000)]
    public async Task OversizedFullGetAndDigestMismatchAreNotReportedAsSuccess()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        var taskId = CommandIds.New();
        fixture.Center.Script("GetNodeTask", Reply(new FleetServiceGetNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.Internal,
                Code = "internal",
                MessageKey = "error.internal.internal",
                Effect = EffectCertainty.Unknown,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
            },
        }));
        var get = await fixture.CliAsync("tasks", "show", IdText.Format(taskId), "--full");
        Assert.NotEqual(0, get.ExitCode);
        Assert.Contains("INTERNAL/internal", get.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("may have run", get.Stderr, StringComparison.Ordinal);

        fixture.Center.Script("SubmitNodeTask", Reply(new FleetServiceSubmitNodeTaskResponse
        {
            Meta = new ResponseMeta(),
            Error = new ArcError
            {
                Category = ErrorCategory.State,
                Code = "node_unreachable",
                MessageKey = "error.state.node_unreachable",
                Effect = EffectCertainty.Unknown,
                Retry = new RetryAdvice { Mode = RetryMode.Never },
                Details = new ErrorDetails { State = new StateFailure { State = "node", Reason = "replay_digest_differs" } },
            },
        }));
        var submit = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.NotEqual(0, submit.ExitCode);
        Assert.Contains("defect", submit.Stderr, StringComparison.Ordinal);
        var sent = FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(Assert.Single(fixture.Center.CallsOf("SubmitNodeTask")).Body));
        Assert.Contains(IdText.Format(sent.Meta.CommandId), submit.Stderr, StringComparison.Ordinal);
    }

    [Fact(Timeout = 60000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task FiveTransportRetriesKeepOneCommandAndFinishWithAnUncertainOutcome()
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var fixture = await Fixture.StartAsync();
        for (var i = 0; i < 6; i++)
        {
            fixture.Center.Script("SubmitNodeTask", new FakeFault.Transport(14, "dependency.unavailable"));
        }

        var result = await fixture.CliAsync("run", "--detach", "--env-inherit", "none", "--", CloudNode.TestLoad, "hold", "--hold-ms", "1");
        Assert.NotEqual(0, result.ExitCode);
        Assert.NotEqual(75, result.ExitCode);
        Assert.Contains("may have run", result.Stderr, StringComparison.Ordinal);
        var calls = fixture.Center.CallsOf("SubmitNodeTask").Select(call => FleetServiceSubmitNodeTaskRequest.Parser.ParseFrom(FakeCenter.Payload(call.Body))).ToList();
        Assert.Equal(6, calls.Count);
        Assert.All(calls, call => Assert.Equal(calls[0].Request, call.Request));
        Assert.All(calls, call => Assert.Equal(calls[0].Meta.CommandId, call.Meta.CommandId));
        Assert.Contains(IdText.Format(calls[0].Meta.CommandId), result.Stderr, StringComparison.Ordinal);
    }

    private static FleetServiceSubmitNodeTaskResponse SubmitResult(Id node, Id task) => new()
    {
        Meta = new ResponseMeta(),
        Value = new FleetServiceSubmitNodeTaskValue
        {
            NodeId = node,
            Response = new TaskServiceSubmitTaskResponse { Meta = new ResponseMeta(), Value = new TaskServiceSubmitTaskValue { TaskId = task, State = TaskState.Queued } }.ToByteString(),
        },
    };

    private static FleetServiceGetNodeTaskResponse GetResult(Id node, Id task, Id attempt, TaskState state) => new()
    {
        Meta = new ResponseMeta(),
        Value = new FleetServiceGetNodeTaskValue
        {
            NodeId = node,
            Response = new TaskServiceGetTaskResponse
            {
                Meta = new ResponseMeta(),
                Value = new TaskServiceGetTaskValue
                {
                    Task = new ManagedTask
                    {
                        TaskId = task,
                        State = state,
                        CurrentAttempt = new Attempt { AttemptId = attempt, Result = new AttemptResult { TerminationReason = TerminationReason.Exited, ExitCode = 7 } },
                    },
                },
            }.ToByteString(),
        },
    };

    private static FleetServiceReadNodeTaskOutputResponse ReadResult(Id node, TaskServiceReadTaskOutputValue value) => new()
    {
        Meta = new ResponseMeta(),
        Value = new FleetServiceReadNodeTaskOutputValue
        {
            NodeId = node,
            Response = new TaskServiceReadTaskOutputResponse { Meta = new ResponseMeta(), Value = value }.ToByteString(),
        },
    };

    private static FakeFault.Raw Reply(IMessage response) => new([.. FakeCenter.DataFrame(response), .. FakeCenter.TrailerFrame(0, null)]);

    private sealed class Fixture(FakeCenter center, CloudNode node) : IAsyncDisposable
    {
        public FakeCenter Center { get; } = center;

        public CloudNode Node { get; } = node;

        public Id NodeId => new() { Value = ByteString.CopyFrom(Node.Runtime.NodeId.Span) };

        public static async Task<Fixture> StartAsync(bool signedIn = true)
        {
            var center = await FakeCenter.StartAsync();
            center.ScriptedFleet = true;
            var node = await CloudNode.Create(center.Endpoint.Url).StartAsync();
            var fixture = new Fixture(center, node);
            if (signedIn)
            {
                var id = node.Runtime.NodeId.ToArray();
                var credentials = center.Issue(id);
                using var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(id, center.Endpoint.Origin)
                    ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(id, center.Endpoint.Origin, TimeProvider.System);
                center.CommandKeys.Add(center.Channel.CommandPublicKey);
                center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
                await node.Cloud.AdoptAsync(credentials, center.Endpoint);
                await center.Channel.ProvedAsync();
                await Eventually.TrueAsync(() => node.Cloud.Status().Relay == RelayState.Connected, "the node channel is connected");
            }

            return fixture;
        }

        public async Task<(int ExitCode, string Stdout, string Stderr)> CliAsync(params string[] args)
        {
            var start = new ProcessStartInfo(CloudNode.HelperExecutable)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true,
            };
            start.ArgumentList.Add(NodeLocations.TestModeOption);
            foreach (var arg in args)
            {
                start.ArgumentList.Add(arg);
            }

            start.Environment[NodeLocations.EndpointVariable] = Node.Endpoint.Address;
            start.Environment[NodeLocations.ConfigDirectoryVariable] = Path.GetDirectoryName(Node.ConfigPath)!;
            start.Environment.Remove("ARCFORGES_OS_SECRET_STORE_TESTS");
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the test CLI.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            try
            {
                await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(40));
            }
            catch (TimeoutException)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
                throw;
            }

            return (process.ExitCode, await stdout, await stderr);
        }

        public async ValueTask DisposeAsync()
        {
            await Node.DisposeAsync();
            await Center.DisposeAsync();
        }
    }
}
