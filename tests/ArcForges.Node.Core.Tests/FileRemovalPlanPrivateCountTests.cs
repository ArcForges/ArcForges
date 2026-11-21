// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Client;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Node.V1;
using ArcForges.Node.Core.Files;
using ArcForges.Node.Core.Platform;
using ArcForges.Node.Store;
using Google.Protobuf;

namespace ArcForges.Node.Core.Tests;

public sealed class FileRemovalPlanPrivateCountTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task HistoricalPrivateDenialAndPublicCountKeepDistinctReplayShapes(bool privateDenial) =>
        LegacyPlannerHistoryFixture.WithStoreAsync(store =>
        {
            var owner = LegacyPlannerHistoryFixture.Owner(store);
            var request = new FileServicePlanRemovalRequest
            {
                Meta = InProcessNode.Command(),
                WorkspacePath = new FilePath { WorkspaceId = CommandIds.New(), Path = "tree" },
            };
            var error = LegacyPlannerHistoryFixture.Refusal(privateDenial ? ErrorCategory.State : ErrorCategory.Resource,
                privateDenial ? "file_access_denied" : "too_large", "file_access_denied", request.Meta.CorrelationId);
            if (!privateDenial)
            {
                error.Details = new ErrorDetails
                {
                    Limit = new LimitFailure
                    {
                        LimitName = "removal_descendants",
                        Maximum = new ArcForges.Contracts.Foundation.V1.Decimal { Value = "1000" },
                    },
                };
            }

            var raw = request.ToByteArray();
            var recorded = LegacyPlannerHistoryFixture.RecordRefusal(store, request, owner, error);
            var replay = LegacyPlannerHistoryFixture.ReadRetained(store, request.Meta.CommandId, raw);
            Assert.Equal(DedupStatus.Replay, replay.Status);
            var retained = replay.Outcome!.Value;
            Assert.Equal(recorded, retained.ToArray());
            var response = FileServicePlanRemovalResponse.Parser.ParseFrom(retained.Span);
            Assert.Equal(request.Meta.CorrelationId, response.Meta.CorrelationId);
            Assert.Equal(error, response.Error);
            Assert.Null(response.Value);
            Assert.Equal(owner.ToByteArray(), Assert.IsType<byte[]>(store.Read(reader => reader.Scalar(
                "SELECT caller FROM file_removal_command_owner WHERE command_id = $id;",
                ("$id", request.Meta.CommandId.Value.ToByteArray())))));
            if (privateDenial)
            {
                Assert.Null(response.Error.Details.Limit);
            }
            else
            {
                Assert.Equal("1000", response.Error.Details.Limit.Maximum.Value);
            }

            var changed = LegacyPlannerHistoryFixture.ReadRetained(store, request.Meta.CommandId, [.. raw, 0x98, 0x06, 0x01]);
            Assert.Equal(DedupStatus.Conflict, changed.Status);
            Assert.Equal("command_id_reused", changed.Error!.Code);
            Assert.Null(changed.Outcome);
            Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM file_removal_plan;")));
            Assert.Equal(0L, store.Read(reader => reader.Scalar("SELECT count(*) FROM file_operation_journal;")));
            return Task.CompletedTask;
        });

    [Fact]
    public Task RetainedPrivateIdentityMatchesTheObjectIndependentOfLinkCount() =>
        LegacyPlannerHistoryFixture.WithStoreAsync(store =>
        {
            var owner = LegacyPlannerHistoryFixture.Owner(store);
            var body = "fixture"u8.ToArray();
            var native = OperatingSystem.IsWindows()
                ? new WorkspaceObjectIdentity(17, 29, 37, 43, 0, 1, 0x8000)
                : new WorkspaceObjectIdentity(17, 29, 37, 43, 7, 1, 0x8000, SHA256.HashData("stage"u8));
            var parent = native with
            {
                Low = 39,
                Mode = 0x4000,
                InstanceToken = OperatingSystem.IsWindows()
                ? default : SHA256.HashData("stage parent"u8)
            };
            var identity = RegisteredWorkspaces.RootIdentity.Encode(native, directory: false);
            var parentIdentity = RegisteredWorkspaces.RootIdentity.Encode(parent);
            var registered = store.Write(transaction =>
            {
                var root = Path.Combine(store.DataRoot, "workspace");
                var workspace = LegacyPlannerHistoryFixture.SeedWorkspace(transaction, root);
                var request = new FileServiceWriteFileRequest
                {
                    Meta = InProcessNode.Command(),
                    ExpectedAbsent = true,
                    Data = ByteString.CopyFrom(body),
                    Path = new FilePath { WorkspaceId = workspace, Path = "unwritten" },
                };
                var id = request.Meta.CommandId.Value.ToByteArray();
                Assert.Equal(PrivateStageReservationResult.Reserved, PrivateStageRegistry.Reserve(transaction,
                    new FileStageBudget(), FileOperationKind.Write, id, workspace.Value.Span, request.Meta.CorrelationId.Value.Span,
                    owner, request.ToByteArray(), [new PrivateStageSpec(2, Path.Combine(root, "stage"), body.Length, SHA256.HashData(body))]));
                // Existing immutable stage metadata, with the native observation supplied by the test.
                Assert.Equal(1, transaction.Execute("""
                    UPDATE file_private_stage_object SET phase = 2, identity_platform = $platform,
                      native_identity = $identity, parent_identity = $parent WHERE command_id = $id AND slot = 2;
                    """, ("$platform", identity.Platform), ("$identity", identity.Bytes), ("$parent", parentIdentity.Bytes), ("$id", id)));
                return workspace;
            }, CommitDurability.Full);

            store.Read(reader =>
            {
                Assert.Single(PrivateStageRegistry.LoadIdentities(reader));
                Assert.True(PrivateStageRegistry.HasWorkspaceHold(reader, registered.Value.Span));
                Assert.False(PrivateStageRegistry.HasWorkspaceHold(reader, CommandIds.New().Value.Span));
                Assert.True(PrivateStageRegistry.ContainsIdentity(reader, native));
                Assert.True(PrivateStageRegistry.ContainsIdentity(reader, native with { Links = 2 }));
                var foreign = native with
                {
                    Low = 41,
                    InstanceToken = OperatingSystem.IsWindows()
                    ? default : SHA256.HashData("foreign"u8)
                };
                Assert.False(PrivateStageRegistry.ContainsIdentity(reader, foreign));
                return 0;
            });
            return Task.CompletedTask;
        });
}
