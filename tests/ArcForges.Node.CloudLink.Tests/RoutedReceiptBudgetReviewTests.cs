// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using NativeOutputIndexRecord = ArcForges.Node.Platform.OutputIndexRecord;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>
/// Signed mock-channel reads of retained tasks charge monotonic time from receipt, including verification and in-flight admission.
/// The original native workload tests remain at eaaccb8380a2bd265aaad0a67d62c8fab2a8a29a.
/// </summary>
public sealed class RoutedReceiptBudgetReviewTests
{
    private const int OutputChunkBytes = 64 * 1024;
    private const int OutputBytes = 4 * OutputChunkBytes;
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData(false, false, 0)]
    [InlineData(false, true, 8)]
    [InlineData(false, true, 12)]
    [InlineData(true, false, 0)]
    [InlineData(true, true, 8)]
    [InlineData(true, true, 12)]
    public async Task WaitAndReadChargeTimeBeforeDispatch(bool readOutput, bool delay, int elapsedSeconds)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        var clock = new AdvanceableClock();
        var hold = new HeldDispatcher();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        node.Clock = clock;
        node.WrapRoutedDispatcher = inner => new HeldDispatcherWrapper(inner, hold);
        center.Channel.Limits.MaxInFlightCalls = 1;
        await node.StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        // The issued credential includes the initial key; a later unknown call key triggers refresh.
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        var connection = await center.Channel.ProvedAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        await AllowRemoteOutputAsync(human);
        var retained = SeedRetainedAttempt(node);

        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };
        var method = readOutput ? RoutedMethod.ReadNodeTaskOutput : RoutedMethod.WaitNodeTask;
        var request = BudgetRequest(retained, readOutput);
        if (readOutput)
            await AssertRetainedOutputAsync(center, connection, node, caller, retained);

        // One signed mock call occupies the sole in-flight slot. The next frame must be received before the monotonic jump.
        var get = new TaskServiceGetTaskRequest { Meta = CloudNode.Command(), TaskId = retained.TaskId };
        var (first, _) = center.Channel.BuildCall(connection,
            new FakeCallSpec { Method = RoutedMethod.GetNodeTask, Payload = get.ToByteArray(), Caller = caller });
        hold.Arm(first.CallId);
        await connection.SendCallAsync(first);
        await hold.Entered.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
        try
        {
            var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec { Method = method, Payload = request.ToByteArray(), Caller = caller });
            clock.ObserveNextFrame();
            await connection.SendCallAsync(call);
            await clock.FrameReceived.Task.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            if (delay)
            {
                clock.Advance(TimeSpan.FromSeconds(elapsedSeconds));
            }

            hold.Release.TrySetResult();
            var result = connection.ResultOfAsync(call.CallId);
            var early = await Task.WhenAny(result, Task.Delay(delay ? TimeSpan.FromSeconds(2) : TimeSpan.FromMilliseconds(500), Ct)) == result;
            var received = await result.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            await AssertSignedReceiptAsync(node, connection, call.CallId, received.Payload);
            AssertWaitingResult(retained, readOutput, received.Payload);
            Assert.Equal(delay, early);
            Assert.Empty(node.Runtime.Execution!.RunningAttempts);
        }
        finally
        {
            hold.Release.TrySetResult();
        }
    }

    [Theory(Timeout = 180_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WaitAndReadChargeAnUnknownKeyRefresh(bool readOutput)
    {
        TestContext.Current.CancellationToken.ThrowIfCancellationRequested();
        await using var center = await FakeCenter.StartAsync();
        var clock = new AdvanceableClock();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        node.Clock = clock;
        await node.StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        // The issued credential includes the initial key; a later unknown call key triggers refresh.
        center.CommandKeys.Add(center.Channel.CommandPublicKey);
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        var connection = await center.Channel.ProvedAsync();
        await using var human = await node.ChannelAsync(Origin.Human);
        await AllowRemoteOutputAsync(human);
        var retained = SeedRetainedAttempt(node);
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Script,
            LocalSessionId = CommandIds.New(),
        };
        var request = BudgetRequest(retained, readOutput);
        var rotated = center.Channel.CommandPublicKey;
        rotated.Kid = "cmd-review-refresh";
        center.CommandKeys.Add(rotated);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        center.Script("RefreshNodeSession", new FakeFault.Hold(release));
        try
        {
            var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec
            {
                Method = readOutput ? RoutedMethod.ReadNodeTaskOutput : RoutedMethod.WaitNodeTask,
                Payload = request.ToByteArray(),
                Caller = caller,
                FrameKid = rotated.Kid,
                HeaderKid = rotated.Kid,
            });
            await connection.SendCallAsync(call);
            await Eventually.TrueAsync(() => center.CallsOf("RefreshNodeSession").Count == 1, "call is held during unknown-key refresh");
            clock.Advance(TimeSpan.FromSeconds(12));
            release.TrySetResult();
            var result = connection.ResultOfAsync(call.CallId);
            var early = await Task.WhenAny(result, Task.Delay(TimeSpan.FromSeconds(2), Ct)) == result;
            var received = await result.WaitAsync(TimeSpan.FromSeconds(15), Ct);
            await AssertSignedReceiptAsync(node, connection, call.CallId, received.Payload);
            AssertWaitingResult(retained, readOutput, received.Payload);
            Assert.True(early, "verification time must be charged before the handler starts its wait");
            Assert.Empty(node.Runtime.Execution!.RunningAttempts);
        }
        finally
        {
            release.TrySetResult();
        }
    }

    private static async Task AllowRemoteOutputAsync(NodeChannel human)
    {
        var current = await human.Policy.GetPolicyAsync(new PolicyServiceGetPolicyRequest { Meta = CloudNode.Command() }, cancellationToken: Ct);
        Assert.Null(current.Error);
        var document = current.Value.Document.Clone();
        (document.Privacy ??= new PrivacyPolicy()).RemoteOutputTail = true;
        var meta = CloudNode.Command();
        meta.ExpectedRev = current.Value.Revision.Revision;
        var changed = await human.Policy.UpdatePolicyAsync(new PolicyServiceUpdatePolicyRequest { Meta = meta, Document = document }, cancellationToken: Ct);
        Assert.Null(changed.Error);
    }

    private sealed record RetainedAttempt(Id TaskId, Id AttemptId, byte[] Output);

    private static RetainedAttempt SeedRetainedAttempt(CloudNode node)
    {
        // Seed after startup so the synthetic task is observed via SQLite and never adopted as a live process.
        var store = node.Runtime.Store;
        var taskId = CommandIds.New();
        var attemptId = CommandIds.New();
        var spec = new TaskSpec
        {
            Kind = TaskKind.Command,
            Command = new CommandSpec { Argv = new ArgvCommand { Argv = { "retained-receipt-budget-fixture" } } },
        }.ToByteArray();
        var digest = SHA256.HashData(spec);
        store.Write(transaction =>
        {
            transaction.Execute("""
                INSERT INTO task (task_id, state, kind, title, command_summary, spec, spec_digest, owner, owner_origin,
                                  pool, priority, effective_priority, side_effect, side_effect_source, command_fingerprint,
                                  command_digest, created_at, started_at, current_attempt_id, attempt_count, rev)
                VALUES ($task, $state, 1, 'retained receipt fixture', 'retained receipt fixture', $spec, $digest, $owner, 1,
                        'default', 3, 3, 4, 1, 'retained-receipt-fixture', $digest, $now, $now, $attempt, 1, 0);
                """, ("$task", taskId.Value.ToByteArray()), ("$state", (int)TaskState.Running), ("$spec", spec), ("$digest", digest),
                ("$owner", new ActorRef { Origin = Origin.Human }.ToByteArray()), ("$now", transaction.NowMicroseconds),
                ("$attempt", attemptId.Value.ToByteArray()));
            transaction.Execute("""
                INSERT INTO attempt (attempt_id, task_id, number, kind, state, executor_node_id, boot_identity,
                                     request_cpu_millicores, request_mem_expected_bytes, request_mem_ceiling_bytes, request_source,
                                     accounted_mem_bytes, created_at, started_at, rev)
                VALUES ($attempt, $task, 1, 1, $state, $node, $boot, 100, 67108864, 67108864, 1, 67108864, $now, $now, 0);
                """, ("$attempt", attemptId.Value.ToByteArray()), ("$task", taskId.Value.ToByteArray()), ("$state", (int)AttemptState.Running),
                ("$node", store.Metadata.NodeId.ToArray()), ("$boot", store.Metadata.BootIdentity), ("$now", transaction.NowMicroseconds));
            return 0;
        }, CommitDurability.Full);

        var files = new AttemptFiles(node.DataRoot, IdText.Format(attemptId));
        Directory.CreateDirectory(files.Directory);
        var output = Enumerable.Range(0, OutputBytes).Select(index => (byte)(index % 251)).ToArray();
        File.WriteAllBytes(files.StdoutPath, output);
        using (var index = File.Create(files.IndexPath))
        {
            Span<byte> record = stackalloc byte[NativeOutputIndexRecord.Size];
            for (var offset = 0; offset < output.Length; offset += OutputChunkBytes)
            {
                new NativeOutputIndexRecord(OutputStreamKind.Stdout, offset, OutputChunkBytes, 1_700_000_000_000_000_000 + offset,
                    OutputChunkMarks.None).Write(record);
                index.Write(record);
            }
        }
        return new RetainedAttempt(taskId, attemptId, output);
    }

    private static IMessage BudgetRequest(RetainedAttempt retained, bool readOutput) => readOutput
        ? new TaskServiceReadTaskOutputRequest
        {
            Meta = CloudNode.Command(),
            AttemptId = retained.AttemptId,
            FromOffset = 1_000_000,
            WaitMs = 4_000,
        }
        : new TaskServiceWaitTaskRequest
        {
            Meta = CloudNode.Command(),
            TaskId = retained.TaskId,
            Target = WaitTarget.Terminal,
            WaitMs = 4_000,
        };

    private static async Task AssertRetainedOutputAsync(FakeCenter center, FakeChannelConnection connection, CloudNode node,
        CenterCaller caller, RetainedAttempt retained)
    {
        var request = new TaskServiceReadTaskOutputRequest
        {
            Meta = CloudNode.Command(),
            AttemptId = retained.AttemptId,
            MaxBytes = OutputBytes,
        };
        var (call, _) = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.ReadNodeTaskOutput,
            Payload = request.ToByteArray(),
            Caller = caller,
        });
        await connection.SendCallAsync(call);
        var received = await connection.ResultOfAsync(call.CallId).WaitAsync(TimeSpan.FromSeconds(15), Ct);
        await AssertSignedReceiptAsync(node, connection, call.CallId, received.Payload);
        var read = TaskServiceReadTaskOutputResponse.Parser.ParseFrom(received.Payload);
        Assert.Null(read.Error);
        Assert.Equal(retained.Output, read.Value.Data.ToByteArray());
        Assert.Equal((ulong)OutputBytes, read.Value.NextOffset);
        Assert.Equal(OutputBytes / OutputChunkBytes, read.Value.Index.Count);
        Assert.False(read.Value.Eof);
    }

    private static async Task AssertSignedReceiptAsync(CloudNode node, FakeChannelConnection connection, Id call, ByteString payload)
    {
        await Eventually.TrueAsync(() => connection.VerifiedResults.Any(verified => verified.Header.CallId.Equals(call)),
            "the routed result is signed and verified");
        var header = connection.VerifiedResults.Single(verified => verified.Header.CallId.Equals(call)).Header;
        Assert.True(header.Outcome == RoutedOutcome.Executed,
            $"unexpected routed outcome {header.Outcome}: {header.Error?.Code}/{header.Error?.Details?.State?.Reason}");
        Assert.InRange(payload.Length, 1, ResultSigner.MaxPayloadBytes);
        var hash = SHA256.HashData(payload.Span);
        Assert.Equal((uint)payload.Length, header.ResponseSize);
        Assert.Equal(hash, header.ResponseSha256.ToByteArray());
        node.Runtime.Store.Read(reader =>
        {
            using var query = reader.CreateCommand("SELECT decision, response_size, response_sha256 FROM routed_call_log WHERE call_id = $call;");
            query.Parameters.AddWithValue("$call", call.Value.ToByteArray());
            using var row = query.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal((int)RoutedCallDecision.Executed, row.GetInt32(0));
            Assert.Equal(payload.Length, row.GetInt32(1));
            Assert.Equal(hash, (byte[])row.GetValue(2));
            Assert.False(row.Read());
            return 0;
        });
    }

    private static void AssertWaitingResult(RetainedAttempt retained, bool readOutput, ByteString payload)
    {
        if (readOutput)
        {
            var read = TaskServiceReadTaskOutputResponse.Parser.ParseFrom(payload);
            Assert.Null(read.Error);
            Assert.Empty(read.Value.Data);
            Assert.Empty(read.Value.Index);
            Assert.Equal((ulong)retained.Output.Length, read.Value.NextOffset);
            Assert.False(read.Value.Eof);
            return;
        }

        var waited = TaskServiceWaitTaskResponse.Parser.ParseFrom(payload);
        Assert.Null(waited.Error);
        Assert.False(waited.Value.Reached);
        Assert.Equal(retained.TaskId, waited.Value.Task.TaskId);
        Assert.Equal(TaskState.Running, waited.Value.Task.State);
        Assert.Equal(retained.AttemptId, waited.Value.Task.CurrentAttempt.AttemptId);
    }

    private sealed class HeldDispatcher
    {
        private Id? _call;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Arm(Id id) => _call = id;
        public bool Matches(VerifiedCall call) => _call is not null && _call.Equals(call.Header.CallId);
    }

    private sealed class HeldDispatcherWrapper(IRoutedDispatcher inner, HeldDispatcher held) : IRoutedDispatcher
    {
        public async Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
        {
            if (held.Matches(call))
            {
                held.Entered.TrySetResult();
                await held.Release.Task.WaitAsync(cancellationToken);
            }

            return await inner.DispatchAsync(call, link, cancellationToken);
        }
    }

    private sealed class AdvanceableClock : TimeProvider
    {
        private long _offset;
        private int _observe;
        public TaskCompletionSource FrameReceived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override long TimestampFrequency => TimeProvider.System.TimestampFrequency;
        public override DateTimeOffset GetUtcNow() => TimeProvider.System.GetUtcNow();

        public override long GetTimestamp()
        {
            var timestamp = TimeProvider.System.GetTimestamp() + Interlocked.Read(ref _offset);
            if (Volatile.Read(ref _observe) != 0 && new StackTrace().GetFrames().Any(frame =>
                frame.GetMethod()?.DeclaringType?.FullName?.Contains("ChannelLoop+<ServeAsync>", StringComparison.Ordinal) == true))
            {
                Interlocked.Exchange(ref _observe, 0);
                FrameReceived.TrySetResult();
            }

            return timestamp;
        }

        public void ObserveNextFrame() => Volatile.Write(ref _observe, 1);
        public void Advance(TimeSpan by) => Interlocked.Add(ref _offset, checked((long)(by.TotalSeconds * TimestampFrequency)));
    }
}
