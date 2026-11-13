// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Contracts.Relay.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Core.Security;
using ArcForges.Node.Store;
using Google.Protobuf;
using NodeFilePath = ArcForges.Contracts.Node.V1.FilePath;

namespace ArcForges.Node.Core.Tests;

/// <summary>Real retained native stages, SQLite journal acknowledgments and routed file privacy; caller is synthetic.</summary>
public sealed class PrivateStageRetainedCapacityTests
{
    [Fact(Timeout = 300_000)]
    public async Task ManyAcknowledgedStagesKeepBytesAndPrivacyWithoutConsumingActiveSlots()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var node = await InProcessNode.Create().StartAsync();
        var calls = new RoutedCalls(node);
        var caller = calls.Relay(Origin.Script);
        var rootPath = Directory.CreateDirectory(Path.Combine(node.Root, "retained-capacity")).FullName;
        File.WriteAllText(Path.Combine(rootPath, "visible.txt"), "ordinary-retained-capacity-positive");
        var workspace = new RegisteredWorkspaces(node.Runtime.Store).RegisterFromVerifiedHuman(rootPath, cancellationToken: ct);
        using var root = WorkspacePath.OpenRoot(rootPath);
        var rootId = RegisteredWorkspaces.RootIdentity.Encode(root.RootIdentity);
        var budget = new FileStageBudget();
        var requester = new ActorRef { Origin = Origin.Remote, CenterCaller = caller };
        var human = new ActorRef { Origin = Origin.Human, ClientKind = ClientKind.Cli };
        long bytes = 0;
        var phase = Stopwatch.StartNew();
        for (var index = 0; index < 130; index++)
        {
            ct.ThrowIfCancellationRequested();
            var body = Encoding.UTF8.GetBytes("private-retained-stage-" + index.ToString("D3", System.Globalization.CultureInfo.InvariantCulture));
            var hash = SHA256.HashData(body);
            var name = "stage-" + index.ToString("D3", System.Globalization.CultureInfo.InvariantCulture);
            var request = new FileServiceWriteFileRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "target-" + index },
                ExpectedAbsent = true,
                Data = ByteString.CopyFrom(body),
            };
            var raw = request.ToByteArray();
            var id = request.Meta.CommandId.Value.ToByteArray();
            var spec = new PrivateStageSpec(2, Path.Combine(rootPath, name), body.Length, hash);
            Assert.Equal(PrivateStageReservationResult.Reserved, node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t, budget,
                FileOperationKind.Write, id, workspace.Id, request.Meta.CorrelationId.Value.Span, caller, raw, [spec]), CommitDurability.Full));
            RegisteredWorkspaces.RootIdentity stageId;
            using (var stage = await PrivateStageProducer.CreateBoundAsync(node.Runtime.Processor, id, 2, root, root, name, ct))
            {
                stageId = stage.Identity;
                PrivateStageRegistry.WriteBoundStage(node.Runtime.Store, id, 2, caller, raw, stage, body, ct);
            }
            var intent = new FileJournalIntent(FileOperationKind.Write, id, request.Meta.CorrelationId.Value.ToByteArray(), caller,
                workspace.Id, request.Path.Path, rootId.Platform, rootId.Bytes, rootId.Bytes, null, null, null, null,
                body.Length, hash, stageId.Bytes);
            requester.RemoteCommandId = request.Meta.CommandId.Clone();
            var raised = await node.Runtime.Processor.ExecuteAsync(command => PrivateStageApproval.Raise(command, intent, raw,
                requester, root, target: null, TimeSpan.FromHours(1), ct), CommitDurability.Full);
            Assert.True(raised.Created);
            var approvalId = raised.Approval!.Id;
            await node.Runtime.Processor.ExecuteAsync(command => Approvals.Decide(command, approvalId, approve: true, human, comment: null),
                CommitDurability.Full);
            using (var recovered = node.Runtime.Store.Read(r => PrivateStageRegistry.ReopenReadyStage(r, id, 2,
                caller, SHA256.HashData(raw), ct)))
            {
                var prepared = node.Runtime.Store.Write(t => FileMutationJournal.PrepareApproved(t, approvalId, root, target: null,
                    original: null, recovered, ct), CommitDurability.Full);
                Assert.Equal(ApprovedFilePreparation.Prepared, prepared.Status);
            }
            var outcome = node.Runtime.Store.Write(t => FileMutationJournal.MarkUnknown(t, id), CommitDurability.Full);
            await node.Runtime.Processor.ExecuteAsync(command => Approvals.Executed(command, approvalId, outcome,
                Approvals.OutcomeError(outcome), PermissionMatrix.FileWrite), CommitDurability.Full);
            Assert.Equal(FileJournalAcknowledgment.Acknowledged, node.Runtime.Store.Write(t =>
                FileMutationJournal.AcknowledgeFromVerifiedHuman(t, id, SHA256.HashData(raw), human), CommitDurability.Full));
            bytes += body.Length;
            Assert.Equal((0, bytes), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        }

        TestContext.Current.TestOutputHelper?.WriteLine($"130 retained stage setup: {phase.Elapsed.TotalMilliseconds:F0} ms");
        phase.Restart();
        Assert.Equal(130L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_object WHERE phase = 3;")));
        Assert.Null(node.Runtime.Store.Read(PrivateStageRegistry.TryLoadIdentitiesForUse));
        Assert.Equal(0, await node.StopAsync());
        await node.StartAsync();
        calls = new RoutedCalls(node);
        Assert.Equal((0, bytes), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Null(node.Runtime.Store.Read(PrivateStageRegistry.TryLoadIdentitiesForUse));
        // Neither the first nor the last retained object may escape indexed privacy when Windows metadata changes.
        foreach (var name in new[] { "stage-000", "stage-129" })
        {
            if (OperatingSystem.IsWindows())
            {
                var before = root.InspectEntry(name).Identity;
                var retainedPath = Path.Combine(rootPath, name);
                File.SetCreationTimeUtc(retainedPath, File.GetCreationTimeUtc(retainedPath).AddHours(1));
                var after = root.InspectEntry(name).Identity;
                Assert.Equal(before.Volume, after.Volume);
                Assert.Equal(before.Low, after.Low);
                Assert.Equal(before.High, after.High);
                Assert.NotEqual(before.Created, after.Created);
            }
            Assert.True(node.Runtime.Store.Read(r => PrivateStageRegistry.ContainsIdentity(r, root.InspectEntry(name).Identity)));
        }
        // Verify the actual platform-specific lookup uses the existing identity index, including the Windows BLOB range.
        var observed = RegisteredWorkspaces.RootIdentity.Encode(root.InspectEntry("stage-000").Identity, directory: false);
        var indexUsed = node.Runtime.Store.Read(r =>
        {
            using var query = r.CreateCommand(OperatingSystem.IsWindows() ? """
                EXPLAIN QUERY PLAN SELECT 1 FROM file_private_stage_object
                WHERE identity_platform = 1 AND native_identity >= $lower AND native_identity <= $upper
                  AND length(native_identity) = 33 LIMIT 1;
                """ : """
                EXPLAIN QUERY PLAN SELECT 1 FROM file_private_stage_object
                WHERE identity_platform = $platform AND native_identity = $identity LIMIT 1;
                """);
            if (OperatingSystem.IsWindows())
            {
                var lower = observed.Bytes.ToArray();
                var upper = observed.Bytes.ToArray();
                lower.AsSpan(25).Clear();
                upper.AsSpan(25).Fill(byte.MaxValue);
                query.Parameters.AddWithValue("$lower", lower);
                query.Parameters.AddWithValue("$upper", upper);
            }
            else
            {
                query.Parameters.AddWithValue("$platform", observed.Platform);
                query.Parameters.AddWithValue("$identity", observed.Bytes);
            }
            using var row = query.ExecuteReader();
            return row.Read() && row.GetString(3).Contains("INDEX", StringComparison.OrdinalIgnoreCase);
        });
        Assert.True(indexUsed);
        foreach (var name in new[] { "stage-000", "stage-129" })
        {
            var read = new FileServiceReadFileRequest
            {
                Meta = new RequestMeta { CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = name },
                Offset = 0,
                Length = 128,
            };
            var result = await calls.CallAsync(caller, RoutedMethod.ReadNodeFile, read.ToByteArray());
            var response = FileServiceReadFileResponse.Parser.ParseFrom(result.Answer!.Response);
            Assert.Null(response.Value);
            Assert.NotNull(response.Error);
            var retainedPath = Path.Combine(rootPath, name);
            var retainedBody = File.ReadAllBytes(retainedPath);
            var failure = node.Runtime.Store.Write(transaction =>
            {
                using var use = new RegisteredWorkspaces(node.Runtime.Store).OpenForUse(transaction, workspace.Id, beforeUse: null, ct);
                return Assert.Throws<WorkspacePathException>(() => use.Root.OpenExistingWriteGuard(name));
            }, CommitDurability.Full);
            Assert.Equal("file_access_denied", failure.Reason);
            Assert.Equal(retainedBody, File.ReadAllBytes(retainedPath));
        }
        var search = new FileServiceSearchFilesRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "" },
            Pattern = "private-retained-stage",
            Mode = FileSearchMode.Literal,
        };
        TestContext.Current.TestOutputHelper?.WriteLine($"Restart and two retained file checks: {phase.Elapsed.TotalMilliseconds:F0} ms");
        phase.Restart();
        var searchResult = await calls.CallAsync(caller, RoutedMethod.SearchNodeFiles, search.ToByteArray());
        TestContext.Current.TestOutputHelper?.WriteLine($"130-entry routed search: {phase.Elapsed.TotalMilliseconds:F0} ms");
        var searchResponse = FileServiceSearchFilesResponse.Parser.ParseFrom(searchResult.Answer!.Response);
        Assert.Null(searchResponse.Error);
        Assert.Empty(searchResponse.Value.Matches);
        Assert.False(searchResponse.Value.Truncated);
        var list = new FileServiceListDirectoryRequest
        {
            Meta = new RequestMeta { CorrelationId = CommandIds.New() },
            Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "" },
        };
        phase.Restart();
        try
        {
            var listResult = await calls.CallAsync(caller, RoutedMethod.ListNodeDirectory, list.ToByteArray());
            var listResponse = FileServiceListDirectoryResponse.Parser.ParseFrom(listResult.Answer!.Response);
            Assert.Null(listResponse.Error);
            Assert.DoesNotContain(listResponse.Value.Entries, entry => entry.Name.StartsWith("stage-", StringComparison.Ordinal));
            Assert.Contains(listResponse.Value.Entries, entry => entry.Name == "visible.txt");
        }
        finally
        {
            TestContext.Current.TestOutputHelper?.WriteLine($"130-entry routed directory listing: {phase.Elapsed.TotalMilliseconds:F0} ms");
        }
        var marker = Encoding.UTF8.GetBytes("private-retained-stage");
        foreach (var database in new[] { node.Runtime.Store.DatabasePath, node.Runtime.Store.DatabasePath + "-wal" })
        {
            if (!File.Exists(database)) continue;
            using var stream = new FileStream(database, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var copy = new MemoryStream();
            stream.CopyTo(copy);
            Assert.Equal(-1, copy.ToArray().AsSpan().IndexOf(marker));
        }

        PrivateStageReservationResult ReserveActive(int index)
        {
            var request = new FileServiceWriteFileRequest
            {
                Meta = new RequestMeta { CommandId = CommandIds.New(), CorrelationId = CommandIds.New() },
                Path = new NodeFilePath { WorkspaceId = new Id { Value = ByteString.CopyFrom(workspace.Id) }, Path = "new-target-" + index },
                ExpectedAbsent = true,
                Data = ByteString.Empty,
            };
            var spec = new PrivateStageSpec(2, Path.Combine(rootPath, "new-stage-" + index), 0, SHA256.HashData(ReadOnlySpan<byte>.Empty));
            return node.Runtime.Store.Write(t => PrivateStageRegistry.Reserve(t, budget, FileOperationKind.Write,
                request.Meta.CommandId.Value.Span, workspace.Id, request.Meta.CorrelationId.Value.Span,
                caller, request.ToByteArray(), [spec]), CommitDurability.Full);
        }
        for (var index = 0; index < 64; index++) Assert.Equal(PrivateStageReservationResult.Reserved, ReserveActive(index));
        Assert.Equal((64, bytes), node.Runtime.Store.Read(PrivateStageRegistry.Usage));
        Assert.Equal(PrivateStageReservationResult.Capacity, ReserveActive(64));
        Assert.Equal(130L, node.Runtime.Store.Read(r => r.Scalar("SELECT count(*) FROM file_private_stage_object WHERE phase = 3;")));
    }
}
