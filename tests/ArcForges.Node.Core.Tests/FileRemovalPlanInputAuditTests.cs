// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;
using Microsoft.Data.Sqlite;

namespace ArcForges.Node.Core.Tests;

/// <summary>
/// Test-owned native files and SQLite are real. Agent creation provenance is seeded solely to exercise
/// planning; the currently refused AGENT expected-absent API is not claimed to have created these files.
/// The dispatcher seam is not a signed channel or an actual Go Center.
/// </summary>
public sealed class FileRemovalPlanInputAuditTests
{
    private const int BlockSize = 65_536;
    private static readonly byte[] BodyMarker = "plan-input-owned-fixture-body-4c37"u8.ToArray();

    private sealed record SeededFile(string Relative, string FullPath, byte[] Block, int Repetitions,
        RegisteredWorkspaces.RootIdentity Identity, byte[] Marker, byte[] Hash);

    private sealed class Fixture(InProcessNode node, RoutedCalls calls, CenterCaller caller, byte[] workspace,
        string tree, IReadOnlyList<SeededFile> files) : IAsyncDisposable
    {
        internal InProcessNode Node { get; } = node;
        internal RoutedCalls Calls { get; set; } = calls;
        internal CenterCaller Caller { get; } = caller;
        internal byte[] Workspace { get; } = workspace;
        internal string Tree { get; } = tree;
        internal IReadOnlyList<SeededFile> Files { get; } = files;

        internal FileServicePlanRemovalRequest Request() => new()
        {
            Meta = Tasks.Meta(),
            WorkspacePath = new FilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(Workspace) }, Path = "tree" },
        };

        public async ValueTask DisposeAsync() => await Node.DisposeAsync();
    }

    private static async Task<Fixture> CreateFixture(int count, int repetitions)
    {
        var ct = TestContext.Current.CancellationToken;
        var node = await InProcessNode.Create().StartAsync();
        try
        {
            var calls = new RoutedCalls(node);
            var caller = calls.Relay(Origin.Agent);
            var rootName = Directory.CreateDirectory(Path.Combine(node.Root, "plan-input-root")).FullName;
            var tree = Directory.CreateDirectory(Path.Combine(rootName, "tree")).FullName;
            var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootName, cancellationToken: ct);
            var files = new List<SeededFile>();
            RegisteredWorkspaces.RootIdentity rootIdentity;
            using (var root = WorkspacePath.OpenRoot(rootName))
            {
                rootIdentity = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
                for (var index = 0; index < count; index++)
                {
                    var relative = $"tree/{index:D2}.bin";
                    var full = Path.Combine(tree, $"{index:D2}.bin");
                    var block = new byte[BlockSize];
                    RandomNumberGenerator.Fill(block);
                    BodyMarker.CopyTo(block, 0);
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    using var file = new FileStream(full, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
                    for (var part = 0; part < repetitions; part++)
                    {
                        file.Write(block);
                        hash.AppendData(block);
                    }
                    file.Flush(flushToDisk: true);
                    var marker = Assert.IsType<byte[]>(WorkspaceCreationMarker.TryWriteNew(file.SafeFileHandle));
                    var identity = RegisteredWorkspaces.RootIdentity.Encode(WorkspacePath.Identity(file.SafeFileHandle), directory: false);
                    files.Add(new SeededFile(relative, full, block, repetitions, identity, marker, hash.GetHashAndReset()));
                }
            }

            // This fixture metadata is synthetic; native objects, markers, bytes and SQLite writes are not mocked.
            node.Runtime.Store.Write(tx =>
            {
                foreach (var file in files)
                {
                    var key = Assert.IsType<byte[]>(FileCreationOwnership.StableKey(file.Identity.Platform, file.Identity.Bytes));
                    tx.Execute("INSERT INTO file_ownership_object_generation (object_platform, object_key, generation) VALUES ($p, $key, 0);",
                        ("$p", file.Identity.Platform), ("$key", key));
                    tx.Execute("""
                        INSERT INTO file_creation_ownership
                          (workspace_id, relative_path, caller, creation_command_id, creation_request_sha256, root_platform, root_identity,
                           object_platform, object_identity, object_key, creation_marker, last_written_size, last_written_sha256,
                           global_generation, object_generation, recorded_at)
                        VALUES ($ws, $path, $caller, $command, $request, $platform, $root, $platform, $object, $key,
                                $marker, $size, $hash, 0, 0, $now);
                        """, ("$ws", workspace.Id), ("$path", file.Relative), ("$caller", caller.ToByteArray()),
                        ("$command", CommandIds.New().Value.ToByteArray()), ("$request", SHA256.HashData("synthetic-provenance"u8)),
                        ("$platform", file.Identity.Platform), ("$root", rootIdentity.Bytes), ("$object", file.Identity.Bytes),
                        ("$key", key), ("$marker", file.Marker), ("$size", (long)BlockSize * file.Repetitions),
                        ("$hash", file.Hash), ("$now", tx.NowMicroseconds));
                }
                return 0;
            }, CommitDurability.Full);
            return new Fixture(node, calls, caller, workspace.Id, tree, files);
        }
        catch
        {
            await node.DisposeAsync();
            throw;
        }
    }

    private static byte[] ExpectedDigest(Fixture fixture, IEnumerable<string> actualOrder)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var path in actualOrder)
        {
            var file = Assert.Single(fixture.Files, item => item.Relative == path);
            for (var index = 0; index < file.Repetitions; index++) hash.AppendData(file.Block);
        }
        return hash.GetHashAndReset();
    }

    private static void CheckObservation(FileAuditMetadata? audit, ulong expectedBytes, byte[] expectedDigest)
    {
        var observation = Assert.Single(Assert.IsType<FileAuditMetadata>(audit).Observations);
        Assert.Equal(FileAuditKind.InputBytes, observation.Kind);
        Assert.Equal(expectedBytes, observation.SizeBytes);
        Assert.Equal(expectedBytes, observation.DigestInputBytes);
        Assert.False(observation.HasItemCount);
        Assert.Equal(expectedDigest, observation.Sha256.ToByteArray());
    }

    private static void CheckLastStoredObservation(Fixture fixture, string outcome, ulong expectedBytes, byte[] digest)
    {
        fixture.Node.Runtime.Store.Read(reader =>
        {
            using var sql = reader.CreateCommand("""
                SELECT o.kind, o.size_bytes, o.digest_input_bytes, o.item_count, o.sha256
                FROM audit_log a JOIN file_workspace_audit_observation o ON o.audit_seq = a.seq
                WHERE a.operation = 'cleanup.plan FileService.PlanRemoval' AND a.outcome_summary = $outcome
                ORDER BY a.seq DESC LIMIT 1;
                """);
            sql.Parameters.AddWithValue("$outcome", outcome);
            using var row = sql.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal((int)FileAuditKind.InputBytes, row.GetInt32(0));
            Assert.Equal((long)expectedBytes, row.GetInt64(1));
            Assert.Equal((long)expectedBytes, row.GetInt64(2));
            Assert.True(row.IsDBNull(3));
            Assert.Equal(digest, (byte[])row.GetValue(4));
            Assert.False(row.Read());
            return 0;
        });
    }

    private static void CheckNoBody(Fixture fixture)
    {
        foreach (var path in new[] { fixture.Node.Runtime.Store.DatabasePath, fixture.Node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(path)) continue;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(BodyMarker));
        }
    }

    [Fact(Timeout = 180_000)]
    public async Task Actual64MiBCompleteAndRepeatedReadRefusalCommitReplayWithoutAnotherRead()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await CreateFixture(count: 16, repetitions: 64);
        var handler = fixture.Calls.Dispatcher.FileHandlerForTests!;
        var order = new List<string>();
        var readCalls = 0;
        handler.AfterRemovalOwnershipReadForTests = () => readCalls++;
        handler.AfterRemovalOwnershipCheckForTests = (entry, _) =>
        {
            if (entry.Kind == WorkspaceEntryType.File) order.Add(entry.Path);
        };

        var completeRequest = fixture.Request();
        var completeBytes = completeRequest.ToByteArray();
        var complete = await fixture.Calls.CallAsync(fixture.Caller, RoutedMethod.PlanNodeRemoval, completeBytes,
            completeRequest.Meta.CommandId, cancellationToken: ct);
        var completeResponse = FileServicePlanRemovalResponse.Parser.ParseFrom(complete.Answer!.Response);
        Assert.Null(completeResponse.Error);
        Assert.Equal(67_108_864UL, completeResponse.Value.Plan.TotalBytes);
        Assert.Equal(17, completeResponse.Value.Plan.Items.Count);
        Assert.Equal(16, order.Count);
        Assert.Equal(1024, readCalls);
        var completeDigest = ExpectedDigest(fixture, order);
        CheckObservation(completeResponse.Audit, 67_108_864, completeDigest);
        CheckLastStoredObservation(fixture, "planned", 67_108_864, completeDigest);

        var exhaustedRequest = fixture.Request();
        var exhaustedBytes = exhaustedRequest.ToByteArray();
        var exhaustedId = exhaustedRequest.Meta.CommandId.Value.ToByteArray();
        order.Clear();
        readCalls = 0;
        var repeated = false;
        handler.AfterRemovalOwnershipCheckForTests = (entry, repeat) =>
        {
            if (entry.Kind != WorkspaceEntryType.File) return;
            order.Add(entry.Path);
            if (repeated) return;
            repeated = true;
            order.Add(entry.Path);
            repeat(); // the actual same checked file is read again against the shared budget
        };
        var observedFull = false;
        handler.AfterRemovalSizeRefusalForTests = transaction =>
        {
            observedFull = transaction.Durability == CommitDurability.Full && (long)transaction.Scalar("PRAGMA synchronous;")! == 2;
        };
        handler.AfterRemovalSizeCommitForTests = () => throw new SqliteException("test-owned commit return fault", 10);
        var uncertain = await fixture.Calls.CallAsync(fixture.Caller, RoutedMethod.PlanNodeRemoval, exhaustedBytes,
            exhaustedRequest.Meta.CommandId, cancellationToken: ct);
        handler.AfterRemovalSizeRefusalForTests = null;
        handler.AfterRemovalSizeCommitForTests = null;
        var unknown = FileServicePlanRemovalResponse.Parser.ParseFrom(uncertain.Answer!.Response);
        Assert.True(observedFull);
        Assert.Equal("internal", unknown.Error.Code);
        Assert.Equal(EffectCertainty.Unknown, unknown.Error.Effect);
        Assert.Equal(RetryMode.Never, unknown.Error.Retry.Mode);
        Assert.Null(unknown.Audit);
        Assert.True(repeated);
        Assert.Equal(16, order.Count);
        Assert.Equal(1024, readCalls);
        var refusalDigest = ExpectedDigest(fixture, order);
        var receipt = fixture.Node.Runtime.Store.Read(reader =>
        {
            using var sql = reader.CreateCommand("""
                SELECT d.payload_digest, d.outcome, o.caller
                FROM command_dedup d JOIN file_removal_command_owner o ON o.command_id = d.command_id
                WHERE d.command_id = $id;
                """);
            sql.Parameters.AddWithValue("$id", exhaustedId);
            using var row = sql.ExecuteReader();
            Assert.True(row.Read());
            Assert.Equal(SHA256.HashData(exhaustedBytes), (byte[])row.GetValue(0));
            Assert.Equal(fixture.Caller, CenterCaller.Parser.ParseFrom((byte[])row.GetValue(2)));
            return (byte[])row.GetValue(1);
        });
        var refused = FileServicePlanRemovalResponse.Parser.ParseFrom(receipt);
        Assert.Null(refused.Value);
        Assert.Equal(ErrorCategory.Resource, refused.Error.Category);
        Assert.Equal("too_large", refused.Error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, refused.Error.Effect);
        Assert.Equal(RetryMode.Never, refused.Error.Retry.Mode);
        Assert.Equal("removal_ownership_input_bytes", refused.Error.Details.Limit.LimitName);
        Assert.Equal("67108864", refused.Error.Details.Limit.Maximum.Value);
        CheckObservation(refused.Audit, 67_108_864, refusalDigest);
        CheckLastStoredObservation(fixture, "refused: too_large", 67_108_864, refusalDigest);
        Assert.Equal(0L, fixture.Node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM file_removal_plan WHERE command_id = $id;", ("$id", exhaustedId))));

        handler.AfterRemovalOwnershipReadForTests = () => throw new InvalidOperationException("replay unexpectedly read file content");
        var replay = await fixture.Calls.CallAsync(fixture.Caller, RoutedMethod.PlanNodeRemoval, exhaustedBytes,
            exhaustedRequest.Meta.CommandId, cancellationToken: ct);
        Assert.Equal(receipt, replay.Answer!.Response!.ToByteArray());
        var foreign = fixture.Caller.Clone();
        foreign.LocalSessionId = CommandIds.New();
        var denied = await fixture.Calls.CallAsync(foreign, RoutedMethod.PlanNodeRemoval, exhaustedBytes,
            exhaustedRequest.Meta.CommandId, cancellationToken: ct);
        Assert.Equal("command_id_reused", FileServicePlanRemovalResponse.Parser.ParseFrom(denied.Answer!.Response).Error.Code);
        Assert.Equal(0, await fixture.Node.StopAsync());
        await fixture.Node.StartAsync();
        fixture.Calls = new RoutedCalls(fixture.Node);
        fixture.Calls.Dispatcher.FileHandlerForTests!.AfterRemovalOwnershipReadForTests =
            () => throw new InvalidOperationException("restart replay unexpectedly read file content");
        var restarted = await fixture.Calls.CallAsync(fixture.Caller, RoutedMethod.PlanNodeRemoval, exhaustedBytes,
            exhaustedRequest.Meta.CommandId, cancellationToken: ct);
        Assert.Equal(receipt, restarted.Answer!.Response!.ToByteArray());
        CheckNoBody(fixture);
    }

    [Fact(Timeout = 120_000)]
    public async Task VerifiedEmptyFileOmitsContentObservation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await CreateFixture(count: 1, repetitions: 0);
        var reads = 0;
        fixture.Calls.Dispatcher.FileHandlerForTests!.AfterRemovalOwnershipReadForTests = () => reads++;
        var request = fixture.Request();
        var result = await fixture.Calls.CallAsync(fixture.Caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(),
            request.Meta.CommandId, cancellationToken: ct);
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(result.Answer!.Response);
        Assert.Null(response.Error);
        Assert.True(response.Value.Plan.Items.Single(item => item.Path == fixture.Files[0].Relative).OwnerVerified);
        Assert.Equal(0, reads);
        Assert.Null(response.Audit);
        Assert.Equal(0L, fixture.Node.Runtime.Store.Read(reader => reader.Scalar("""
            SELECT count(*) FROM audit_log a JOIN file_workspace_audit_observation o ON o.audit_seq = a.seq
            WHERE a.operation = 'cleanup.plan FileService.PlanRemoval';
            """)));
    }

    [Fact(Timeout = 120_000)]
    public async Task ChangedSecondFileReturnsAndPersistsOnlyActuallyReadPrefix()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var fixture = await CreateFixture(count: 2, repetitions: 1);
        var handler = fixture.Calls.Dispatcher.FileHandlerForTests!;
        var changed = false;
        handler.AfterRemovalOwnershipReadForTests = () =>
        {
            if (changed) return;
            changed = true;
            using var second = new FileStream(fixture.Files[1].FullPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            second.WriteByte(0x61); // real competing change to the other test-owned file after the first read
            second.Flush(flushToDisk: true);
        };
        var request = fixture.Request();
        var raw = request.ToByteArray();
        var result = await fixture.Calls.CallAsync(fixture.Caller, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId,
            cancellationToken: ct);
        var response = FileServicePlanRemovalResponse.Parser.ParseFrom(result.Answer!.Response);
        Assert.True(changed);
        Assert.Null(response.Value);
        Assert.Equal(ErrorCategory.Conflict, response.Error.Category);
        Assert.Equal("file_changed", response.Error.Code);
        Assert.Equal("planned_tree_changed", response.Error.Details.State.Reason);
        var expected = SHA256.HashData(fixture.Files[0].Block);
        CheckObservation(response.Audit, BlockSize, expected);
        CheckLastStoredObservation(fixture, "refused: file_changed", BlockSize, expected);
        Assert.Equal(0L, fixture.Node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        handler.AfterRemovalOwnershipReadForTests = () => throw new InvalidOperationException("replay unexpectedly read file content");
        var replay = await fixture.Calls.CallAsync(fixture.Caller, RoutedMethod.PlanNodeRemoval, raw, request.Meta.CommandId,
            cancellationToken: ct);
        Assert.Equal(result.Answer.Response, replay.Answer!.Response);
        CheckNoBody(fixture);
    }

    [Fact(Timeout = 120_000)]
    public async Task CancellationAfterActualReadDoesNotInventAReplyOrCommittedReceipt()
    {
        await using var fixture = await CreateFixture(count: 1, repetitions: 2);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var reads = 0;
        fixture.Calls.Dispatcher.FileHandlerForTests!.AfterRemovalOwnershipReadForTests = () =>
        {
            reads++;
            cancellation.Cancel();
        };
        var request = fixture.Request();
        var id = request.Meta.CommandId.Value.ToByteArray();
        try
        {
            var result = await fixture.Calls.CallAsync(fixture.Caller, RoutedMethod.PlanNodeRemoval, request.ToByteArray(),
                request.Meta.CommandId, cancellationToken: cancellation.Token);
            Assert.Null(result.Answer?.Response);
        }
        catch (OperationCanceledException) { }
        Assert.Equal(1, reads);
        await fixture.Node.Runtime.Processor.ExecuteAsync(_ => 0).WaitAsync(TestContext.Current.CancellationToken); // writer completed or rolled back
        Assert.Equal(0L, fixture.Node.Runtime.Store.Read(reader => reader.Scalar(
            "SELECT count(*) FROM command_dedup WHERE command_id = $id;", ("$id", id))));
        Assert.Equal(0L, fixture.Node.Runtime.Store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
        CheckNoBody(fixture);
    }
}
