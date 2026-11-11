// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Api;
using ArcForges.Node.Core;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Security;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;
using NodeShapes = ArcForges.Contracts.Node.Shapes.ContractShapeValidation;

namespace ArcForges.Node.Core.Tests;

/// <summary>Actual node, SQLite and native filesystem through the routed dispatcher seam. This does not claim a real center or signed channel.</summary>
public sealed class FileReadRoutedTests
{
    [Fact(Timeout = 120_000)]
    public async Task ReadUsesTheRegisteredRootAndAuditsOnlyTheExactObservedBytes()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "read-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var marker = Encoding.UTF8.GetBytes("FILE_BODY_MUST_NEVER_BE_PERSISTED_4ae833");
        var data = Enumerable.Repeat((byte)'x', 70_010).ToArray();
        marker.CopyTo(data, 0);
        File.WriteAllBytes(Path.Combine(root, "payload.bin"), data);
        var correlation = CommandIds.New();
        var request = Read(workspace.Id, "payload.bin", new RequestMeta { CorrelationId = correlation }, 0, 90_000);
        var answer = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.ReadNodeFile, request.ToByteArray());
        Assert.Equal(RoutedOutcome.Executed, answer.Answer!.Outcome);
        var response = FileServiceReadFileResponse.Parser.ParseFrom(answer.Answer.Response);
        Assert.Null(response.Error);
        Assert.True(NodeShapes.IsValid(response));
        Assert.Equal(correlation, response.Meta.CorrelationId);
        Assert.Equal(data.AsSpan(0, 65_536).ToArray(), response.Value.Data.ToByteArray());
        Assert.Equal(65_536UL, response.Value.NextOffset);
        Assert.Equal((ulong)data.Length, response.Value.FileSize);
        Assert.False(response.Value.Eof);
        var digest = SHA256.HashData(data.AsSpan(0, 65_536));
        Assert.Equal(digest, response.Value.Sha256.ToByteArray());
        var observation = Assert.Single(response.Audit.Observations);
        Assert.Equal(FileAuditKind.ReadBytes, observation.Kind);
        Assert.Equal(65_536UL, observation.SizeBytes);
        Assert.Equal(65_536UL, observation.DigestInputBytes);
        Assert.Equal(digest, observation.Sha256.ToByteArray());
        Assert.Equal(workspace.Id, answer.Answer.WorkspaceId);
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a
            JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'payload.bin' AND o.kind = 1
              AND o.size_bytes = 65536 AND o.digest_input_bytes = 65536 AND o.sha256 = $digest;
            """, ("$workspace", workspace.Id), ("$digest", digest)))! >= 1);

        // Missing metadata is valid and uses this verified call's actual ID, never an invented correlation.
        request.Meta = null;
        request.Offset = (ulong)data.Length;
        request.Length = 1;
        var missing = await calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.ReadNodeFile, request.ToByteArray());
        var eof = FileServiceReadFileResponse.Parser.ParseFrom(missing.Answer!.Response);
        Assert.Null(eof.Error);
        Assert.True(NodeShapes.IsValid(eof));
        Assert.Equal(calls.LastCallId, eof.Meta.CorrelationId);
        Assert.True(eof.Value.Eof);
        Assert.Empty(eof.Value.Data.ToByteArray());
        Assert.Equal(SHA256.HashData(ReadOnlySpan<byte>.Empty), eof.Value.Sha256.ToByteArray());

        // The published 450.1 validator accepts absent metadata but rejects a present RequestMeta without its correlation.
        request.Meta = new RequestMeta();
        Assert.False(NodeShapes.IsValid(request.Meta));
        Assert.False(NodeShapes.IsValid(request));
        var empty = await calls.CallAsync(calls.Relay(Origin.Script), RoutedMethod.ReadNodeFile, request.ToByteArray());
        var emptyResponse = FileServiceReadFileResponse.Parser.ParseFrom(empty.Answer!.Response);
        Assert.Equal("invalid_argument", emptyResponse.Error.Code);
        Assert.Equal(calls.LastCallId, emptyResponse.Meta.CorrelationId);
        Assert.Equal(calls.LastCallId, emptyResponse.Error.CorrelationId);
        Assert.True(NodeShapes.IsValid(emptyResponse));

        // A real policy change after the first check must be rechecked before the workspace usage update and file read.
        await using var human = await node.ChannelAsync(helloAsHuman: true);
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var agent = calls.Relay(Origin.Agent);
        request.Meta = new RequestMeta { CorrelationId = correlation };
        request.Offset = 0;
        request.Length = 16;
        var beforeRevision = node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT rev FROM workspace WHERE workspace_id=$id;", ("$id", workspace.Id)));
        handler.BeforeReadUseForTests = async _ =>
        {
            var changed = await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileRead,
                Origin = Origin.Agent,
                Decision = PermissionDecision.Deny,
            }));
            Assert.Null(changed.Error);
        };
        var beforeRead = await calls.CallAsync(agent, RoutedMethod.ReadNodeFile, request.ToByteArray());
        Assert.Equal(RoutedOutcome.RefusedByPolicy, beforeRead.Answer!.Outcome);
        Assert.Equal(beforeRevision, node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT rev FROM workspace WHERE workspace_id=$id;", ("$id", workspace.Id))));
        handler.BeforeReadUseForTests = null;
        Assert.Null((await Sched.ChangePolicyAsync(human, policy => policy.Permissions.Clear())).Error);

        // A competing policy update cannot commit between the actual read and its audit transaction.
        using var releaseRead = new ManualResetEventSlim();
        var afterNative = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.AfterNativeReadForTests = () =>
        {
            afterNative.TrySetResult();
            releaseRead.Wait(TimeSpan.FromSeconds(30));
        };
        var activeRead = calls.CallAsync(agent, RoutedMethod.ReadNodeFile, request.ToByteArray(), record: false);
        Task<PolicyServiceUpdatePolicyResponse>? policyUpdate = null;
        try
        {
            await afterNative.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            policyUpdate = Sched.ChangePolicyAsync(human, policy => policy.Permissions.Add(new PermissionOverride
            {
                Operation = PermissionMatrix.FileRead,
                Origin = Origin.Agent,
                Decision = PermissionDecision.Deny,
            }));
            await Tasks.WaitForAsync(() => node.Runtime.Processor.Queued >= 1, TimeSpan.FromSeconds(10), "the competing policy update to wait for the read audit");
            Assert.False(policyUpdate.IsCompleted);
        }
        finally
        {
            releaseRead.Set();
        }

        var afterRead = await activeRead;
        Assert.Equal(RoutedOutcome.Executed, afterRead.Answer!.Outcome);
        var readValue = FileServiceReadFileResponse.Parser.ParseFrom(afterRead.Answer.Response);
        Assert.Null(readValue.Error);
        Assert.Equal(data.AsSpan(0, 16).ToArray(), readValue.Value.Data.ToByteArray());
        Assert.Null((await policyUpdate!).Error);
        var prefixDigest = SHA256.HashData(data.AsSpan(0, 16));
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a
            JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            JOIN audit_log l ON l.seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'payload.bin' AND l.decision = 1
              AND o.kind = 1 AND o.size_bytes = 16 AND o.sha256 = $digest;
            """, ("$workspace", workspace.Id), ("$digest", prefixDigest)))! >= 1);
        handler.AfterNativeReadForTests = null;

        // The committed policy update denies the next AGENT call and records the attempted path without content.
        request.Meta = new RequestMeta { CorrelationId = correlation };
        var denied = await calls.CallAsync(calls.Relay(Origin.Agent), RoutedMethod.ReadNodeFile, request.ToByteArray());
        Assert.Equal(RoutedOutcome.RefusedByPolicy, denied.Answer!.Outcome);
        Assert.Equal("permission_denied", denied.Answer.Error!.Code);
        Assert.Equal(correlation, denied.Answer.Error.CorrelationId);
        Assert.True(NodeShapes.IsValid(denied.Answer.Error));
        Assert.True((long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a
            JOIN audit_log l ON l.seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'payload.bin' AND l.decision = 3;
            """, ("$workspace", workspace.Id)))! >= 1);

        // The actual SQLite database and WAL contain no selected file bytes.
        foreach (var candidate in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(candidate))
            {
                continue;
            }

            using var stream = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(marker));
        }
    }

    [Fact(Timeout = 120_000)]
    public async Task ReadRefusalsHaveThePublishedShapeAndBindTheRealCorrelation()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "errors-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        File.WriteAllBytes(Path.Combine(root, "regular"), [1, 2, 3]);
        var correlation = CommandIds.New();
        var meta = new RequestMeta { CorrelationId = correlation };

        async Task<FileServiceReadFileResponse> Invoke(FileServiceReadFileRequest request)
        {
            var call = await calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.ReadNodeFile, request.ToByteArray());
            Assert.Equal(RoutedOutcome.Executed, call.Answer!.Outcome);
            var value = FileServiceReadFileResponse.Parser.ParseFrom(call.Answer.Response);
            Assert.NotNull(value.Error);
            Assert.True(NodeShapes.IsValid(value));
            Assert.True(NodeShapes.IsValid(value.Error));
            return value;
        }

        var missing = await Invoke(Read(workspace.Id, "missing", meta, 0, 1));
        Assert.Equal("path_not_found", missing.Error.Code);
        Assert.Equal(correlation, missing.Meta.CorrelationId);
        Assert.Equal(correlation, missing.Error.CorrelationId);
        var traversal = await Invoke(Read(workspace.Id, "../outside", meta, 0, 1));
        Assert.Equal("invalid_argument", traversal.Error.Code);
        Assert.Contains(": ", traversal.Error.Details.State.Reason);
        var unknown = await Invoke(Read(CommandIds.New().Value.ToByteArray(), "regular", meta, 0, 1));
        Assert.Equal("invalid_argument", unknown.Error.Code);
        Assert.Equal("workspace_id.registered: required", unknown.Error.Details.State.Reason);

        var excessive = await Invoke(Read(workspace.Id, new string('p', 4097), meta, 0, 1));
        Assert.Equal("too_large", excessive.Error.Code);
        Assert.Equal("path_bytes", excessive.Error.Details.Limit.LimitName);
        Assert.Equal("4096", excessive.Error.Details.Limit.Maximum.Value);
        var malformed = Read(workspace.Id, "regular", new RequestMeta
        {
            CorrelationId = new Id { Value = ByteString.CopyFrom(new byte[15]) },
        }, 0, 1);
        var invalidCorrelation = await Invoke(malformed);
        Assert.Equal("invalid_argument", invalidCorrelation.Error.Code);
        Assert.Equal(calls.LastCallId, invalidCorrelation.Meta.CorrelationId);
        Assert.Equal(calls.LastCallId, invalidCorrelation.Error.CorrelationId);

        var malformedPayload = await calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.ReadNodeFile, [0xff, 0xff, 0xff]);
        Assert.Equal(RoutedOutcome.Executed, malformedPayload.Answer!.Outcome);
        var invalidPayload = FileServiceReadFileResponse.Parser.ParseFrom(malformedPayload.Answer.Response);
        Assert.Equal("invalid_argument", invalidPayload.Error.Code);
        Assert.Equal(calls.LastCallId, invalidPayload.Error.CorrelationId);
        Assert.Equal(calls.LastCallId, invalidPayload.Meta.CorrelationId);
        Assert.True(NodeShapes.IsValid(invalidPayload.Error));
    }

    [Fact(Timeout = 120_000)]
    public async Task WorkspaceErrorReplayKeepsItsOriginalPersistedCorrelation()
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var correlation = CommandIds.New();
        var meta = Tasks.Meta();
        meta.CorrelationId = correlation;
        var request = new WorkspaceServiceRegisterWorkspaceRequest
        {
            Meta = meta,
            Path = Path.Combine(node.Root, "missing-root"),
            Name = "missing",
        };
        var caller = calls.Relay(Origin.Human);
        var first = await calls.CallAsync(caller, RoutedMethod.RegisterNodeWorkspace, request.ToByteArray(), meta.CommandId);
        Assert.Equal(RoutedOutcome.Executed, first.Answer!.Outcome);
        var refusal = WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(first.Answer.Response);
        Assert.Equal("path_not_found", refusal.Error.Code);
        Assert.Equal(correlation, refusal.Meta.CorrelationId);
        Assert.Equal(correlation, refusal.Error.CorrelationId);
        Assert.True(NodeShapes.IsValid(refusal.Error));
        Assert.True(NodeShapes.IsValid(refusal));
        var repeated = await calls.CallAsync(caller, RoutedMethod.RegisterNodeWorkspace, request.ToByteArray(), meta.CommandId);
        Assert.Equal(first.Answer.Response, repeated.Answer!.Response);
        Assert.Equal(correlation, WorkspaceServiceRegisterWorkspaceResponse.Parser.ParseFrom(repeated.Answer.Response).Error.CorrelationId);
    }

    [Theory(Timeout = 90_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ReadWithAStalledAuditWriterHonorsDeadlineAndCancellationWithoutReturningTheBody(bool cancelCaller)
    {
        var ct = TestContext.Current.CancellationToken;
        ct.ThrowIfCancellationRequested();
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "budget-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var content = Encoding.UTF8.GetBytes("ACTUAL_BYTES_OBSERVED_BEFORE_AUDIT_DELAY_7c922");
        File.WriteAllBytes(Path.Combine(root, "budget.txt"), content);
        var request = Read(workspace.Id, "budget.txt", new RequestMeta { CorrelationId = CommandIds.New() }, 0, (ulong)content.Length);
        var handler = calls.Dispatcher.FileHandlerForTests!;
        using var release = new ManualResetEventSlim();
        using var callerCancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        handler.AfterNativeReadForTests = () =>
        {
            entered.TrySetResult();
            release.Wait(TimeSpan.FromSeconds(45));
        };

        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        var pending = calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.ReadNodeFile, request.ToByteArray(),
            record: false, cancellationToken: callerCancellation.Token);
        bool finishedWhileBlocked;
        TimeSpan returnedAfter;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            if (cancelCaller)
            {
                callerCancellation.Cancel();
            }

            var cutoff = Task.Delay(TimeSpan.FromSeconds(cancelCaller ? 3 : 12), ct);
            finishedWhileBlocked = await Task.WhenAny(pending, cutoff) == pending;
            returnedAfter = elapsed.Elapsed;
        }
        finally
        {
            release.Set();
        }

        bool cancelled = false;
        RoutedOutcome? outcome = null;
        int? responseBytes = null;
        try
        {
            var result = await pending.WaitAsync(TimeSpan.FromSeconds(10), ct);
            outcome = result.Answer?.Outcome;
            responseBytes = result.Answer?.Response?.Length;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            cancelled = true;
        }

        await node.Runtime.Processor.ExecuteAsync(_ => 0);
        var actual = SHA256.HashData(content);
        var (denied, allowed) = node.Runtime.Store.Read(reader =>
        {
            long Count(long decision) => (long)reader.Scalar("""
                SELECT count(*) FROM file_workspace_audit a
                JOIN audit_log l ON l.seq = a.audit_seq
                JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
                WHERE a.workspace_id = $workspace AND a.path = 'budget.txt' AND l.decision = $decision
                  AND o.kind = 1 AND o.size_bytes = $bytes AND o.sha256 = $digest;
                """, ("$workspace", workspace.Id), ("$decision", decision), ("$bytes", content.Length), ("$digest", actual))!;
            return (Count(3), Count(1));
        });
        handler.AfterNativeReadForTests = null;
        Assert.True(finishedWhileBlocked && returnedAfter < TimeSpan.FromSeconds(cancelCaller ? 3 : 12) &&
            (cancelled || outcome is null) && denied == 1 && allowed == 0,
            $"cancelCaller={cancelCaller}, finishedWhileBlocked={finishedWhileBlocked}, returnedAfter={returnedAfter}, cancelled={cancelled}, outcome={outcome}, responseBytes={responseBytes}, denied={denied}, allowed={allowed}");
    }

    [Theory(Timeout = 90_000, DisableParallelization = true)]
    [Trait("isolation", "exclusive")]
    [InlineData(false)]
    [InlineData(true)]
    public async Task QueuedReadExpiresOrCancelsWithoutLaterFileIoAndItsAuditSurvivesRestart(bool cancelCaller)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "queue-budget-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        File.WriteAllText(Path.Combine(root, "queued.txt"), "MUST_NOT_BE_READ_AFTER_QUEUE_TIMEOUT_849c");
        var request = Read(workspace.Id, "queued.txt", new RequestMeta { CorrelationId = CommandIds.New() }, 0, 64);
        var handler = calls.Dispatcher.FileHandlerForTests!;
        var reads = 0;
        handler.ReadCheckpointForTests = _ => Interlocked.Increment(ref reads);
        using var release = new ManualResetEventSlim();
        using var callerCancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            entered.TrySetResult();
            release.Wait(TimeSpan.FromSeconds(45));
            return 0;
        });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
        var elapsed = System.Diagnostics.Stopwatch.StartNew();
        var pending = calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.ReadNodeFile, request.ToByteArray(),
            record: false, cancellationToken: callerCancellation.Token);
        bool finishedWhileBlocked;
        TimeSpan returnedAfter;
        try
        {
            await Tasks.WaitForAsync(() => node.Runtime.Processor.Queued >= 1, TimeSpan.FromSeconds(10), "the file read to wait for the writer");
            if (cancelCaller)
            {
                callerCancellation.Cancel();
            }

            finishedWhileBlocked = await Task.WhenAny(pending, Task.Delay(TimeSpan.FromSeconds(cancelCaller ? 3 : 12), ct)) == pending;
            returnedAfter = elapsed.Elapsed;
        }
        finally
        {
            release.Set();
        }

        await blocker;
        var cancelled = false;
        RoutedOutcome? outcome = null;
        try
        {
            outcome = (await pending.WaitAsync(TimeSpan.FromSeconds(10), ct)).Answer?.Outcome;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            cancelled = true;
        }

        await node.Runtime.Processor.ExecuteAsync(_ => 0);
        Assert.True(finishedWhileBlocked && returnedAfter < TimeSpan.FromSeconds(cancelCaller ? 3 : 12) && (cancelled || outcome is null),
            $"cancelCaller={cancelCaller}, returnedAfter={returnedAfter}, cancelled={cancelled}, outcome={outcome}");
        Assert.Equal(0, Volatile.Read(ref reads));
        long AuditCount() => (long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a
            JOIN audit_log l ON l.seq = a.audit_seq
            LEFT JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'queued.txt' AND l.decision = 3 AND o.audit_seq IS NULL;
            """, ("$workspace", workspace.Id)))!;
        Assert.Equal(1, AuditCount());
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        Assert.Equal(1, AuditCount());
    }

    [Fact(Timeout = 90_000)]
    public async Task CancellationDuringNativeReadAuditsOnlyTheObservedPrefixAndSurvivesRestart()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "partial-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        var content = Enumerable.Range(0, 50_000).Select(i => (byte)(i % 251)).ToArray();
        File.WriteAllBytes(Path.Combine(root, "partial.bin"), content);
        var request = Read(workspace.Id, "partial.bin", new RequestMeta { CorrelationId = CommandIds.New() }, 0, (ulong)content.Length);
        var handler = calls.Dispatcher.FileHandlerForTests!;
        using var callerCancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var checkpoints = 0;
        handler.ReadCheckpointForTests = step =>
        {
            if (step == WorkspaceReadCheckpoint.AfterBytesRead)
            {
                Interlocked.Increment(ref checkpoints);
                callerCancellation.Cancel();
            }
        };
        var pending = calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.ReadNodeFile, request.ToByteArray(),
            record: false, cancellationToken: callerCancellation.Token);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5), ct));
        await node.Runtime.Processor.ExecuteAsync(_ => 0);
        Assert.Equal(1, checkpoints);
        var hash = SHA256.HashData(content.AsSpan(0, 16_384));
        long AuditCount() => (long)node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit a
            JOIN audit_log l ON l.seq = a.audit_seq
            JOIN file_workspace_audit_observation o ON o.audit_seq = a.audit_seq
            WHERE a.workspace_id = $workspace AND a.path = 'partial.bin' AND l.decision = 3
              AND o.kind = 1 AND o.size_bytes = 16384 AND o.digest_input_bytes = 16384 AND o.sha256 = $digest;
            """, ("$workspace", workspace.Id), ("$digest", hash)))!;
        Assert.Equal(1, AuditCount());
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        Assert.Equal(1, AuditCount());
    }

    [Fact(Timeout = 90_000)]
    public async Task FullWriterQueueDropsReadWithoutAnUnauditedAnswerOrFileIo()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var root = Directory.CreateDirectory(Path.Combine(node.Root, "full-queue-root")).FullName;
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(root, cancellationToken: ct);
        File.WriteAllText(Path.Combine(root, "queued.txt"), "QUEUE_FULL_MUST_NOT_READ_203f");
        var request = Read(workspace.Id, "queued.txt", new RequestMeta { CorrelationId = CommandIds.New() }, 0, 64);
        var reads = 0;
        calls.Dispatcher.FileHandlerForTests!.ReadCheckpointForTests = _ => Interlocked.Increment(ref reads);
        using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var blocker = node.Runtime.Processor.ExecuteAsync(_ =>
        {
            entered.TrySetResult();
            release.Wait(TimeSpan.FromSeconds(45));
            return 0;
        });
        var queued = new List<Task<int>>();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
            for (var i = 0; i < CommandProcessor.Capacity; i++)
            {
                queued.Add(node.Runtime.Processor.ExecuteAsync(_ => 0));
            }

            Assert.Equal(CommandProcessor.Capacity, node.Runtime.Processor.Queued);
            var answer = await calls.CallAsync(calls.Relay(Origin.Human), RoutedMethod.ReadNodeFile, request.ToByteArray(), record: false);
            Assert.Null(answer.Answer);
            Assert.Equal(0, Volatile.Read(ref reads));
        }
        finally
        {
            release.Set();
            await blocker;
            await Task.WhenAll(queued);
        }

        Assert.Equal(0L, node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM file_workspace_audit WHERE workspace_id = $workspace AND path = 'queued.txt';
            """, ("$workspace", workspace.Id))));
    }

    private static FileServiceReadFileRequest Read(byte[] workspace, string path, RequestMeta? meta, ulong offset, ulong length) => new()
    {
        Meta = meta,
        Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace) }, Path = path },
        Offset = offset,
        Length = length,
    };
}
