// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.CloudLink;
using ArcForges.Node.Core;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.CloudLink.Tests;

/// <summary>Real node, SQLite, native filesystem and signed WebSocket; the channel peer is a mocked center.</summary>
public sealed class RoutedFileClockChannelTests
{
    [Theory(Timeout = 120_000)]
    [InlineData(1)]
    [InlineData(40)]
    public async Task ForwardJumpThenRestartAndRollbackCannotDeliverAnOldSignedMutation(int jumpDays)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        var clock = new WallStepClock();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        node.Clock = clock;
        await node.StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
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
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "clock-workspace")).FullName;
        File.WriteAllText(Path.Combine(root, "kept.txt"), "REAL_CLOCK_TEST_KEEP");
        var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = CloudNode.Command(), Path = root, Name = "clock" };
        var registerCall = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.RegisterNodeWorkspace,
            Payload = register.ToByteArray(),
            Caller = caller,
            CommandId = register.Meta.CommandId,
            Lifetime = TimeSpan.FromSeconds(30),
        }).Call;
        await connection.SendCallAsync(registerCall);
        var registered = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom((await connection.ResultOfAsync(registerCall.CallId)).Payload);
        Assert.Null(registered.Error);
        var workspace = registered.Value.Workspace.WorkspaceId.Clone();

        var unregister = new WorkspaceServiceUnregisterWorkspaceRequest { Meta = CloudNode.Command(), WorkspaceId = workspace };
        var delayed = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.UnregisterNodeWorkspace,
            Payload = unregister.ToByteArray(),
            Caller = caller,
            CommandId = unregister.Meta.CommandId,
            Lifetime = TimeSpan.FromSeconds(30),
        }).Call;
        var list = new WorkspaceServiceListWorkspacesRequest { Meta = new RequestMeta { CorrelationId = CommandIds.New() } };
        var probe = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.ListNodeWorkspaces,
            Payload = list.ToByteArray(),
            Caller = caller,
            Lifetime = TimeSpan.FromSeconds(30),
        }).Call;

        var floorBefore = (long)node.Runtime.Store.Read(reader => reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;"))!;
        var forged = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.ListNodeWorkspaces,
            Payload = list.ToByteArray(),
            Caller = caller,
            Lifetime = TimeSpan.FromSeconds(30),
            AlterSignature = bytes => { var copy = (byte[])bytes.Clone(); copy[0] ^= 1; return copy; },
        }).Call;
        clock.Offset = TimeSpan.FromDays(jumpDays);
        await connection.SendCallAsync(forged);
        _ = await connection.ResultOfAsync(forged.CallId);
        await Eventually.TrueAsync(() => connection.VerifiedResults.Any(result => result.Header.CallId.Equals(forged.CallId)), "the node signed its forged-frame refusal");
        Assert.Equal("signature_invalid", connection.VerifiedResults.Single(result => result.Header.CallId.Equals(forged.CallId)).Header.Error.Code);
        Assert.Equal(floorBefore, node.Runtime.Store.Read(reader => reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
        var unknown = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.ListNodeWorkspaces,
            Payload = list.ToByteArray(),
            Caller = caller,
            Lifetime = TimeSpan.FromSeconds(30),
            FrameKid = "cmd-unknown-0001",
        }).Call;
        await connection.SendCallAsync(unknown);
        _ = await connection.ResultOfAsync(unknown.CallId);
        await Eventually.TrueAsync(() => connection.VerifiedResults.Any(result => result.Header.CallId.Equals(unknown.CallId)), "the node signed its unknown-key refusal");
        Assert.Equal("signature_invalid", connection.VerifiedResults.Single(result => result.Header.CallId.Equals(unknown.CallId)).Header.Error.Code);
        Assert.Equal(floorBefore, node.Runtime.Store.Read(reader => reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
        var changedPayload = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.ListNodeWorkspaces,
            Payload = list.ToByteArray(),
            Caller = caller,
            Lifetime = TimeSpan.FromSeconds(30),
            AlterPayload = bytes => { var copy = (byte[])bytes.Clone(); copy[^1] ^= 1; return copy; },
        }).Call;
        await connection.SendCallAsync(changedPayload);
        _ = await connection.ResultOfAsync(changedPayload.CallId);
        await Eventually.TrueAsync(() => connection.VerifiedResults.Any(result => result.Header.CallId.Equals(changedPayload.CallId)), "the node signed its altered-payload refusal");
        var alteredError = connection.VerifiedResults.Single(result => result.Header.CallId.Equals(changedPayload.CallId)).Header.Error.Code;
        Assert.True(alteredError is "expired" or "signature_invalid");
        Assert.Equal(floorBefore, node.Runtime.Store.Read(reader => reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
        await connection.SendCallAsync(probe);
        await Eventually.TrueAsync(() => ClockRefusals(node) >= 1 || connection.Received.Any(frame =>
            frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(probe.CallId)), "a forward wall-clock decision");
        var unexpected = connection.Received.FirstOrDefault(frame =>
            frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(probe.CallId));
        if (unexpected is not null)
        {
            await Eventually.TrueAsync(() => connection.VerifiedResults.Any(result => result.Header.CallId.Equals(probe.CallId)), "the unexpected response signature");
            var header = connection.VerifiedResults.Single(result => result.Header.CallId.Equals(probe.CallId)).Header;
            Assert.Fail("unexpected verified response: " + header.Outcome + "/" + header.Error?.Code + "/" + header.Error?.Details?.State?.Reason);
        }
        Assert.True(ClockRefusals(node) >= 1);
        var futureBoundary = (long)node.Runtime.Store.Read(reader => reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;"))!;
        Assert.True(futureBoundary > StoreTime.NowMicroseconds(TimeProvider.System) + (jumpDays * 24L - 1) * 60 * 60 * 1_000_000);
        await connection.SendHeartbeatAsync(32101, DateTimeOffset.UtcNow);
        await Eventually.TrueAsync(() => connection.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat && frame.Heartbeat.Seq == 32101),
            "channel remains alive after clock refusal");
        Assert.DoesNotContain(connection.Received, frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(probe.CallId));

        clock.Offset = TimeSpan.Zero;
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        var reconnected = await center.Channel.ProvedAsync(2);
        Assert.Equal(futureBoundary, node.Runtime.Store.Read(reader => reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
        await reconnected.SendCallAsync(delayed);
        await Eventually.TrueAsync(() => ClockRefusals(node) >= 2, "the delayed signed mutation was refused after rollback and restart");
        await reconnected.SendHeartbeatAsync(32102, DateTimeOffset.UtcNow);
        await Eventually.TrueAsync(() => reconnected.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat && frame.Heartbeat.Seq == 32102),
            "the reconnected channel remains alive");
        Assert.DoesNotContain(reconnected.Received, frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(delayed.CallId));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE workspace_id = $id AND removed_at IS NULL;",
            ("$id", workspace.Value.ToByteArray()))));
        Assert.True(File.Exists(Path.Combine(root, "kept.txt")));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;",
            ("$id", unregister.Meta.CommandId.Value.ToByteArray()))));
        Assert.Empty(reconnected.UnverifiedResults);
        ct.ThrowIfCancellationRequested();
    }

    [Fact(Timeout = 120_000)]
    public async Task ClockJumpAfterVerificationIsCheckedAgainBeforeWorkspaceEffect()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var center = await FakeCenter.StartAsync();
        var clock = new WallStepClock();
        await using var node = CloudNode.Create(center.Endpoint.Url);
        node.Clock = clock;
        PausingWorkspaceDispatcher? gate = null;
        node.WrapRoutedDispatcher = inner => gate = new PausingWorkspaceDispatcher(inner);
        await node.StartAsync();
        var nodeId = node.Runtime.NodeId.ToArray();
        var credentials = center.Issue(nodeId);
        using (var key = NodeKeyStores.ForTestDataRoot(node.DataRoot).Load(nodeId, center.Endpoint.Origin)
            ?? NodeKeyStores.ForTestDataRoot(node.DataRoot).Create(nodeId, center.Endpoint.Origin, TimeProvider.System))
        {
            center.CommandKeys.Add(center.Channel.CommandPublicKey);
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
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "clock-before-effect")).FullName;
        var register = new WorkspaceServiceRegisterWorkspaceRequest { Meta = CloudNode.Command(), Path = root, Name = "clock" };
        var registration = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.RegisterNodeWorkspace,
            Payload = register.ToByteArray(),
            Caller = caller,
            CommandId = register.Meta.CommandId,
            Lifetime = TimeSpan.FromSeconds(30),
        }).Call;
        await connection.SendCallAsync(registration);
        var response = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom((await connection.ResultOfAsync(registration.CallId)).Payload);
        Assert.Null(response.Error);
        var workspace = response.Value.Workspace.WorkspaceId.Clone();
        var unregister = new WorkspaceServiceUnregisterWorkspaceRequest { Meta = CloudNode.Command(), WorkspaceId = workspace };
        var pending = center.Channel.BuildCall(connection, new FakeCallSpec
        {
            Method = RoutedMethod.UnregisterNodeWorkspace,
            Payload = unregister.ToByteArray(),
            Caller = caller,
            CommandId = unregister.Meta.CommandId,
            Lifetime = TimeSpan.FromSeconds(30),
        }).Call;
        gate!.Enabled = true;
        await connection.SendCallAsync(pending);
        await gate.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM routed_file_call_log WHERE call_id = $call AND decision = 5;
            """, ("$call", pending.CallId.Value.ToByteArray()))));
        clock.Offset = TimeSpan.FromDays(1);
        gate.Release.TrySetResult();
        Assert.True(await gate.Completed.Task.WaitAsync(TimeSpan.FromSeconds(10), ct));
        var boundary = (long)node.Runtime.Store.Read(reader => reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;"))!;
        Assert.True(boundary > StoreTime.NowMicroseconds(TimeProvider.System) + 23L * 60 * 60 * 1_000_000);
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM audit_log WHERE outcome_summary = 'refused: clock_unavailable' AND remote_command_id = $id;
            """, ("$id", unregister.Meta.CommandId.Value.ToByteArray()))));
        await connection.SendHeartbeatAsync(32103, DateTimeOffset.UtcNow);
        await Eventually.TrueAsync(() => connection.Received.Any(frame => frame.FrameCase == RelayFrame.FrameOneofCase.Heartbeat && frame.Heartbeat.Seq == 32103),
            "the channel remains live after a pre-effect clock jump");
        Assert.DoesNotContain(connection.Received, frame => frame.FrameCase == RelayFrame.FrameOneofCase.CallResult && frame.CallResult.CallId.Equals(pending.CallId));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM workspace WHERE workspace_id = $id AND removed_at IS NULL;",
            ("$id", workspace.Value.ToByteArray()))));
        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM command_dedup WHERE command_id = $id;",
            ("$id", unregister.Meta.CommandId.Value.ToByteArray()))));
        clock.Offset = TimeSpan.Zero;
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        Assert.Equal(boundary, node.Runtime.Store.Read(reader => reader.Scalar("SELECT highwater FROM routed_file_validation_time WHERE singleton = 1;")));
        Assert.Equal(1L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM routed_file_call_log WHERE call_id = $call AND decision = 5;
            """, ("$call", pending.CallId.Value.ToByteArray()))));
    }

    private sealed class PausingWorkspaceDispatcher(IRoutedDispatcher inner) : IRoutedDispatcher
    {
        internal volatile bool Enabled;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource<bool> Completed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<RoutedAnswer?> DispatchAsync(VerifiedCall call, IRoutedLink link, CancellationToken cancellationToken)
        {
            if (!Enabled || call.Header.Method != RoutedMethod.UnregisterNodeWorkspace)
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

    private static long ClockRefusals(CloudNode node) => (long)node.Runtime.Store.Read(reader =>
        reader.Scalar("SELECT count(*) FROM routed_call_log WHERE refusal_step = 'clock_unavailable' AND refusal_code = 'INTERNAL/internal';"))!;

    private sealed class WallStepClock : TimeProvider
    {
        private long _offsetTicks;

        internal TimeSpan Offset { set => Interlocked.Exchange(ref _offsetTicks, value.Ticks); }

        public override DateTimeOffset GetUtcNow() => TimeProvider.System.GetUtcNow() + TimeSpan.FromTicks(Interlocked.Read(ref _offsetTicks));

        public override long GetTimestamp() => TimeProvider.System.GetTimestamp();

        public override long TimestampFrequency => TimeProvider.System.TimestampFrequency;
    }
}
