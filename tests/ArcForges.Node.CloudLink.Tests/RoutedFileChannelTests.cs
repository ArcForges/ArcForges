// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real node, native file, SQLite, WebSocket and signatures; FakeCenter is only a mocked channel peer.</summary>
public sealed class RoutedFileChannelTests
{
    [Fact(Timeout = 120_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    public async Task SignedReadsAndRefusalsDifferFromTimeoutAndAuditFailureWithoutAReply()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        PausingDispatcher? gate = null;
        node.WrapRoutedDispatcher = inner => gate = new PausingDispatcher(inner);
        await node.StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            if (!center.CommandKeys.Any(existing => existing.Kid == FakeChannelPeer.Kid))
            {
                center.CommandKeys.Add(center.Channel.CommandPublicKey);
            }

            center.Channel.RegisterNodeKey(credentials.AccessToken, key.PublicKey);
            await node.Cloud.AdoptAsync(credentials, center.Endpoint);
        }

        var connection = await center.Channel.ProvedAsync();
        var caller = new CenterCaller
        {
            Kind = CenterCallerKind.NodeRelay,
            AccountId = new Id { Value = ByteString.CopyFrom(connection.AccountId) },
            RelayingNodeId = new Id { Value = ByteString.CopyFrom(nodeId) },
            LocalOrigin = Origin.Human,
            LocalSessionId = CommandIds.New(),
        };
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "signed-read-root")).FullName;
        var content = Encoding.UTF8.GetBytes("REAL_SIGNED_CHANNEL_BODY_MUST_NOT_BE_STORED_241ca");
        File.WriteAllBytes(Path.Combine(root, "payload.txt"), content);
        var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = CloudNode.Command(), Path = root, Name = "signed-read" };
        var (registerCall, _) = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.RegisterNodeWorkspace,
            Payload = register.ToByteArray(),
            Caller = caller,
            CommandId = register.Meta.CommandId,
            Lifetime = TimeSpan.FromSeconds(30),
        });
        await connection.SendCallAsync(registerCall);
        var registeredFrame = await connection.ResultOfAsync(registerCall.CallId);
        await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(registerCall.CallId)), "signed workspace registration");
        var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(registeredFrame.Payload);
        Assert.Null(registered.Error);
        var workspace = registered.Value.Workspace.WorkspaceId;
        var correlation = CommandIds.New();
        var read = new FileServiceReadFileRequest
        {
            Meta = new RequestMeta { CorrelationId = correlation },
            Path = new NodeFilePath { WorkspaceId = workspace, Path = "payload.txt" },
            Offset = 0,
            Length = (ulong)content.Length,
        };
        ChannelCall BuildRead(FileServiceReadFileRequest request) => center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.ReadNodeFile,
            Payload = request.ToByteArray(),
            Caller = caller,
            Lifetime = TimeSpan.FromSeconds(30),
        }).Call;
        async Task<(ResultHeader Header, FileServiceReadFileResponse Response)> AnswerAsync(ChannelCall call)
        {
            await connection.SendCallAsync(call);
            var result = await connection.ResultOfAsync(call.CallId);
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(x => x.Header.CallId.Equals(call.CallId)), "independently verified file result");
            return (connection.VerifiedResults.Single(x => x.Header.CallId.Equals(call.CallId)).Header,
                FileServiceReadFileResponse.Parser.ParseFrom(result.Payload));
        }

        var (successHeader, success) = await AnswerAsync(BuildRead(read));
        Assert.Equal(RoutedOutcome.Executed, successHeader.Outcome);
        Assert.Null(success.Error);
        Assert.Equal(content, success.Value.Data.ToByteArray());
        Assert.Equal(SHA256.HashData(content), success.Value.Sha256.ToByteArray());
        Assert.Equal(correlation, success.Meta.CorrelationId);
        var invalid = read.Clone();
        invalid.Path.Path = "../outside";
        var (refusalHeader, refusal) = await AnswerAsync(BuildRead(invalid));
        Assert.Equal(RoutedOutcome.Executed, refusalHeader.Outcome);
        Assert.Equal("invalid_argument", refusal.Error.Code);
        Assert.Equal(correlation, refusal.Error.CorrelationId);
        Assert.Empty(connection.UnverifiedResults);

        var handler = ((RoutedDispatcher)node.Runtime.RoutedDispatcher!).FileHandlerForTests!;

        // The native read and its audit can finish, but the independent channel result-log write can still wait behind a real writer.
        using var releaseResultLog = new ManualResetEventSlim();
        var resultLogBlocked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<int>? heldResultLog = null;
        handler.AfterNativeReadForTests = () =>
        {
            heldResultLog = node.Runtime.Processor.ExecuteAsync(_ =>
            {
                resultLogBlocked.TrySetResult();
                releaseResultLog.Wait(TimeSpan.FromSeconds(45));
                return 0;
            });
        };
        var lateLog = BuildRead(read);
        await connection.SendCallAsync(lateLog);
        try
        {
            await resultLogBlocked.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            await Task.Delay(TimeSpan.FromSeconds(11), ct);
        }
        finally
        {
            releaseResultLog.Set();
        }

        await heldResultLog!;
        await node.Runtime.Processor.ExecuteAsync(_ => 0);
        handler.AfterNativeReadForTests = null;
        await connection.SendHeartbeatAsync(12344, DateTimeOffset.UtcNow);
        await Eventually.TrueAsync(() => connection.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat && frame.Heartbeat.Seq == 12344),
            "the channel remains live after result-log queue release");
        await Task.Delay(TimeSpan.FromSeconds(1), ct);
        var lateFrames = connection.Received.Where(frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(lateLog.CallId)).ToArray();
        Assert.True(lateFrames.Length == 0, $"A file result was sent after its monotonic deadline: frames={lateFrames.Length}, payloadBytes={(lateFrames.Length == 0 ? 0 : lateFrames[0].CallResult.Payload.Length)}");

        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.AfterNativeReadForTests = () =>
        {
            entered.TrySetResult();
            release.Wait(TimeSpan.FromSeconds(30));
        };
        var timed = BuildRead(read);
        await connection.SendCallAsync(timed);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            await Task.Delay(TimeSpan.FromSeconds(11), ct);
            Assert.DoesNotContain(connection.Received, frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(timed.CallId));
        }
        finally
        {
            release.Set();
        }

        await node.Runtime.Processor.ExecuteAsync(_ => 0);
        handler.AfterNativeReadForTests = null;
        await connection.SendHeartbeatAsync(12345, DateTimeOffset.UtcNow);
        await Eventually.TrueAsync(() => connection.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat && frame.Heartbeat.Seq == 12345),
            "the real websocket remains live after the dropped call");
        Assert.DoesNotContain(connection.Received, frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(timed.CallId));
        var hash = SHA256.HashData(content);
        long TimedAudit() => (long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a
            JOIN audit_log l ON l.seq = a.audit_seq
            JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'payload.txt' AND l.decision = 3
              AND o.kind = 1 AND o.size_bytes = $bytes AND o.sha256 = $digest;
            """, ("$workspace", workspace.Value.ToByteArray()), ("$bytes", content.Length), ("$digest", hash)))!;
        long Pending(Id id) => (long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM routed_file_call_log
            WHERE call_id = $id AND decision = 5 AND response_sha256 IS NULL AND response_size IS NULL;
            """, ("$id", id.Value.ToByteArray())))!;
        Assert.Equal(1, TimedAudit());
        Assert.Equal(1, Pending(timed.CallId));
        Assert.Equal(1, Pending(lateLog.CallId));

        // The actual SQLite audit insert fails after the real read; no result is signed or sent and the verified row remains pending.
        node.Runtime.Store.Write(transaction => transaction.Execute("""
            CREATE TRIGGER test_fail_read_audit BEFORE INSERT ON file_workspace_audit
            BEGIN SELECT RAISE(ABORT, 'test_audit_failure'); END;
            """));
        var failedRead = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.AfterNativeReadForTests = () => failedRead.TrySetResult();
        var failed = BuildRead(read);
        await connection.SendCallAsync(failed);
        await failedRead.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
        await node.Runtime.Processor.ExecuteAsync(_ => 0);
        handler.AfterNativeReadForTests = null;
        await connection.SendHeartbeatAsync(12346, DateTimeOffset.UtcNow);
        await Eventually.TrueAsync(() => connection.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat && frame.Heartbeat.Seq == 12346),
            "the channel remains live after the real audit failure");
        Assert.DoesNotContain(connection.Received, frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(failed.CallId));
        Assert.Equal(1, Pending(failed.CallId));
        Assert.Equal(1, TimedAudit());
        node.Runtime.Store.Write(transaction => transaction.Execute("DROP TRIGGER test_fail_read_audit;"));
        // A signed read is verified and logged first, then the real bounded writer queue is filled before the real dispatcher runs.
        File.WriteAllText(Path.Combine(root, "queue-full.txt"), "MUST_NOT_READ_WHEN_WRITER_QUEUE_FULL_4299");
        var queueRead = read.Clone();
        queueRead.Path.Path = "queue-full.txt";
        var full = BuildRead(queueRead);
        gate!.Enabled = true;
        await connection.SendCallAsync(full);
        await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
        Assert.Equal(1, Pending(full.CallId));
        var reads = 0;
        handler.AfterNativeReadForTests = () => Interlocked.Increment(ref reads);
        using var releaseWriter = new ManualResetEventSlim();
        var writerEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            writerEntered.TrySetResult();
            releaseWriter.Wait(TimeSpan.FromSeconds(45));
            return 0;
        });
        var queued = new List<Task<int>>();
        try
        {
            await writerEntered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            for (var i = 0; i < CommandProcessor.Capacity; i++)
            {
                try
                {
                    queued.Add(node.Runtime.Processor.ExecuteAsync(_ => 0));
                }
                catch (CommandQueueFullException)
                {
                    break;
                }
            }

            Assert.Equal(CommandProcessor.Capacity, node.Runtime.Processor.Queued);
            gate.Release.TrySetResult();
            Assert.True(await gate.Completed.Task.WaitAsync(TimeSpan.FromSeconds(5), ct));
            Assert.Equal(0, Volatile.Read(ref reads));
            await connection.SendHeartbeatAsync(12347, DateTimeOffset.UtcNow);
            await Eventually.TrueAsync(() => connection.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat && frame.Heartbeat.Seq == 12347),
                "the channel remains live when the actual node writer is full");
            Assert.DoesNotContain(connection.Received, frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(full.CallId));
        }
        finally
        {
            gate.Release.TrySetResult();
            releaseWriter.Set();
            await blocker;
            await Task.WhenAll(queued);
            handler.AfterNativeReadForTests = null;
        }

        Assert.Equal(1, Pending(full.CallId));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit WHERE workspace_id = $workspace AND path = 'queue-full.txt';
            """, ("$workspace", workspace.Value.ToByteArray()))));
        foreach (var candidate in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (File.Exists(candidate))
            {
                using var stream = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var copy = new MemoryStream();
                stream.CopyTo(copy);
                Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(content));
            }
        }

        var logs = Directory.EnumerateFiles(Path.Combine(node.DataRoot, "logs", "node"), "*", SearchOption.AllDirectories).ToArray();
        Assert.NotEmpty(logs);
        foreach (var file in logs)
        {
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(content));
        }

        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        Assert.Equal(1, Pending(timed.CallId));
        Assert.Equal(1, Pending(failed.CallId));
        Assert.Equal(1, Pending(full.CallId));
        Assert.Equal(1, Pending(lateLog.CallId));
        Assert.Equal(1, TimedAudit());
    }

    private sealed class PausingDispatcher(IRoutedDispatcher inner) : IRoutedDispatcher
    {
        internal volatile bool Enabled;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Completed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
        {
            if (!Enabled || call.Header.Method != RoutedMethod.ReadNodeFile)
            {
                return await inner.DispatchAsync(call, link, cancellationToken).ConfigureAwait(false);
            }

            Entered.TrySetResult();
            await Release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var answer = await inner.DispatchAsync(call, link, cancellationToken).ConfigureAwait(false);
                Completed.TrySetResult(answer is null);
                return answer;
            }
            catch (Exception exception)
            {
                Completed.TrySetException(exception);
                throw;
            }
        }
    }
}
